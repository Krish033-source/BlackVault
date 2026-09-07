# BlackVault — Setup & Run Guide

Encrypted file vault with password + OTP (MFA), automatic threat scoring,
and delete-attempt protection: if someone tries to wipe/delete a vault
without the correct password, the encrypted file is automatically backed
up before it's lost, and the **owner** (you) gets the retrieval link on
your own recovery email. Nothing is ever hidden from the actual owner —
only from whoever doesn't have the password.

**Live Link:** https://blackvault-jm1q.onrender.com

# BlackVault — Full Documentation

This document explains what every file does, what each endpoint does, and
the exact mechanism behind every feature — so you can explain it
confidently to hackathon judges.

---

## 1. Project structure

```
blackvault/
├── main.py              -- Flask backend, all real logic lives here
├── cli.py                -- command-line client (talks to main.py over HTTP)
├── requirements.txt      -- Python dependencies
├── .env.example          -- template for your secrets (copy to .env)
├── frontend/
│   ├── index.html        -- the web UI
│   └── ui.js              -- all UI behavior / API calls
├── vault_data/            -- (auto-created) encrypted files + metadata live here
├── honeypot_files/         -- (auto-created) fake decoy files live here
├── blackvault_logs.db      -- (auto-created) SQLite audit log
├── config.json             -- (auto-created) master password hash + recovery email
└── otp_state.json          -- (auto-created) current OTP state
```

---

## 2. What each part of `main.py` does

### Encryption (`derive_key`, `fernet_key`, `encrypt_bytes`, `decrypt_bytes`)
- Your master password is run through **PBKDF2-HMAC-SHA256** with 200,000
  iterations to derive a 32-byte key. This is a standard, slow, brute-force-
  resistant key derivation function — the same family of algorithm used by
  tools like VeraCrypt.
- That derived key is used with **Fernet** (from the `cryptography` library),
  which internally uses **AES-128 in CBC mode with HMAC authentication**
  (Fernet's spec). This means: your file is encrypted AND tamper-checked —
  if even one byte of the ciphertext is altered, decryption fails loudly
  instead of silently returning corrupted data.
- `encrypt_bytes` / `decrypt_bytes` are the only two functions that touch
  your actual file content.

### Integrity hash (`compute_file_hash`)
- At lock time, we compute `SHA256(original_file_bytes)` and store it in
  the vault's metadata (`original_sha256`).
- At unlock time, after decrypting, we recompute the hash and compare —
  `integrity_verified: true/false` in the response tells you whether the
  decrypted bytes exactly match what was originally locked.

### Real OTP (`generate_and_send_otp`, `verify_and_consume_otp`)
- `/api/request_otp` generates a random 6-digit number with Python's
  `random.randint`, hashes it (SHA-256) and stores the hash + an expiry
  timestamp (5 minutes) in `otp_state.json`. The **plaintext OTP is only
  ever in the email**, never stored or logged anywhere.
- `/api/lock` calls `verify_and_consume_otp`, which checks the hash matches,
  hasn't expired, and hasn't already been used — then marks it used so it
  can't be replayed.

### Threat scoring (`compute_threat_score`, `handle_wrong_attempt`)
- Every vault's metadata tracks `failed_attempts` (integer) and `known_ips`
  (list of IPs that have successfully authenticated).
- Score formula: `min(failed_attempts, 5) * 20`, plus `+30` if the current
  request's IP isn't in `known_ips`.
- This is **fully server-tracked** — there is no client-side input that
  can influence it. An attacker cannot lie about their own attempt count.

### Honeypot (`create_honeypot_file`)
- Once `failed_attempts >= 2` on a vault, a **real file** is written to
  `honeypot_files/` with plausible-looking but fake placeholder content,
  and a one-time download token is returned. This is a genuine downloadable
  file, not just text shown on screen.

### Auto-migration (inside `handle_wrong_attempt`)
- Once the threat score crosses 60, if the vault hasn't already been
  migrated and the local encrypted file still exists:
  1. The encrypted `.bv` file is uploaded to a **private GitHub Gist**
     (`upload_to_backup`) via the real GitHub REST API
     (`POST https://api.github.com/gists`).
  2. A real email is sent to your recovery address via Gmail SMTP with
     the Gist link and step-by-step recovery instructions.
  3. The local encrypted file is destroyed with `secure_wipe()` — this
     overwrites the file with random bytes before deleting it, so it
     can't be recovered by undelete tools. The ONLY remaining copy is
     the encrypted one in your private Gist.
  4. The vault's metadata is marked `migrated: true` with the Gist's
     `raw_url` saved for later retrieval.

### Recovering a migrated file (`download_from_backup`, `/api/download_decrypted`)
- When you unlock a migrated vault with the correct password, the backend
  fetches the base64-encoded ciphertext from the Gist's raw URL, decodes
  it, decrypts it with your password, verifies the integrity hash, and
  either shows a preview or lets you download the real file.
- **Nobody can read the Gist content usefully without your master
  password** — even though GitHub Gists are technically fetchable via URL,
  what's stored there is AES ciphertext, not your real data.

### Audit log (`log_event`, hash-chained)
- Every event (setup, lock, wrong password, honeypot, migration, delete)
  is inserted into a SQLite table with a `prev_hash` / `curr_hash` chain —
  each row's hash includes the previous row's hash. If anyone tampered
  with an old log entry, every hash after it would no longer match,
  making tampering detectable (this is the same principle blockchains and
  git commit chains use).

---

## 3. API endpoints (what each one does)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/setup` | POST | One-time: set master password + recovery email |
| `/api/test_email` | POST | Sends a plain test email to confirm `.env` mail config |
| `/api/request_otp` | POST | Emails a real, single-use, 5-minute OTP |
| `/api/lock` | POST | Encrypts + stores a file (needs password + valid OTP) |
| `/api/download_encrypted/<id>` | GET | Downloads the raw ciphertext `.bv` file |
| `/api/unlock` | POST | Attempts to unlock; real password check + threat tracking |
| `/api/download_decrypted/<id>` | POST | Decrypts fully and returns the real original file |
| `/api/download_honeypot/<token>` | GET | Downloads the fake decoy file generated on a failed attempt |
| `/api/delete_attempt` | POST | Real delete (correct password) or blocked+migrated (wrong password) |
| `/api/status` | GET | Lists all vaults + the last 50 audit log entries |

---

## 4. Using the CLI (`cli.py`)

Everything the web UI does, you can also do from a terminal. Start the
server first (`python main.py` in one terminal), then in another:

```bash
python cli.py setup --password mypass123 --email you@gmail.com
python cli.py test-email
python cli.py request-otp --password mypass123
# check your inbox for the OTP, then:
python cli.py lock --file secret.txt --password mypass123 --otp 482913
python cli.py status
python cli.py unlock --vault-id abcd1234 --password mypass123
python cli.py download-decrypted --vault-id abcd1234 --password mypass123 --out recovered.txt
python cli.py delete --vault-id abcd1234 --password mypass123
```

Run `python cli.py --help` or `python cli.py <command> --help` for details
on any command.

---

