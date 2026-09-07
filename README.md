# BlackVault

**Encrypted file vault with real MFA, automatic threat scoring, and delete-attempt protection.**

If someone tries to wipe or delete a vault without the correct password, the encrypted file is automatically backed up *before* it can be lost, and the owner gets a retrieval link on their own recovery email. Nothing is ever hidden from the actual owner — only from whoever doesn't have the password.

**🌐 Live demo:** [blackvault-jm1q.onrender.com](https://blackvault-jm1q.onrender.com)

---

## Table of Contents
- [Features](#features)
- [Project Structure](#project-structure)
- [How It Works](#how-it-works)
- [Getting Started](#getting-started)
- [API Reference](#api-reference)
- [Using the CLI](#using-the-cli)
- [Using the Web Terminal](#using-the-web-terminal)
- [Security Notes](#security-notes)
- [Known Limitations](#known-limitations)
- [License](#license)

---

## Features

| Feature | Description |
|---|---|
| 🔐 **Real encryption** | AES (via Fernet) with a key derived from your master password using PBKDF2-HMAC-SHA256 (200,000 iterations) |
| 📧 **Real OTP / MFA** | A genuine, single-use, 5-minute one-time code emailed to you — required before any file can be locked |
| 🎯 **Threat scoring** | Every failed unlock/delete attempt is tracked server-side and scored; nothing client-controlled can fake it |
| 🍯 **Honeypot** | After repeated wrong passwords, a real (but fake) decoy file is generated and served to whoever's attacking |
| ☁️ **Auto-migration on attack** | Once the threat score crosses a threshold, your real encrypted file is pushed to a private GitHub Gist and wiped locally before it can be destroyed |
| ✅ **Integrity verification** | SHA-256 of the original file is checked on every unlock — you always know if the bytes match what you locked |
| 📜 **Tamper-evident audit log** | Every event is stored in a hash-chained SQLite log (same principle as git commits / blockchains) — altering old entries breaks the chain |
| 🖥️ **Two interfaces, one backend** | A full web GUI *and* an in-browser terminal (toggle between them on the same page), plus a standalone `cli.py` for pure bash usage |

---

## Project Structure

```
blackvault/
├── main.py                -- Flask backend, all real logic lives here
├── cli.py                 -- command-line client (talks to main.py directly)
├── requirements.txt       -- Python dependencies
├── .env.example           -- template for your secrets (copy to .env)
├── frontend/
│   ├── index.html         -- the web UI (GUI + terminal toggle)
│   ├── ui.js               -- GUI behavior / API calls
│   └── terminal.js         -- in-browser terminal (REPL) mode
├── vault_data/              -- (auto-created) encrypted files + metadata
├── honeypot_files/           -- (auto-created) fake decoy files
├── blackvault_logs.db         -- (auto-created) SQLite audit log
├── config.json                 -- (auto-created) master password hash + recovery email
└── otp_state.json               -- (auto-created) current OTP state
```

---

## How It Works

### Encryption
Your master password is run through **PBKDF2-HMAC-SHA256** (200,000 iterations) combined with a random per-vault salt to derive a key. That key is used with **Fernet** (from the `cryptography` library), which internally uses AES-128-CBC with HMAC authentication — your file is encrypted *and* tamper-checked. If even one byte of the ciphertext is altered, decryption fails loudly instead of silently returning corrupted data.

### Integrity Hash
At lock time, `SHA256(original_file_bytes)` is stored in the vault's metadata. At unlock time, the decrypted bytes are re-hashed and compared — the response tells you plainly whether `integrity_verified` is `true` or `false`.

### Real OTP
`/api/request_otp` generates a cryptographically random 6-digit code, hashes it, and stores the hash plus a 5-minute expiry. The plaintext code only ever exists in the email — never stored or logged. `/api/lock` verifies it, checks it hasn't expired or already been used, then marks it consumed so it can't be replayed.

### Threat Scoring
Every vault tracks `failed_attempts` and a list of `known_ips`. Score = `min(failed_attempts, 5) * 20`, +30 if the current IP hasn't authenticated successfully before. This is entirely server-tracked — nothing the client sends can influence it.

### Honeypot
Once `failed_attempts >= 2` on a vault, a real file is written to `honeypot_files/` with plausible but fake content, and served as a genuine download — not just text on screen.

### Auto-Migration on Attack
Once the threat score crosses the configured threshold, and if the vault hasn't already been migrated:
1. The encrypted `.bv` file is uploaded to a **private GitHub Gist** via the real GitHub REST API.
2. A real email goes to your recovery address with the Gist link and recovery steps.
3. The local encrypted file is **securely wiped** (overwritten with random bytes, then deleted) — the only remaining copy is the ciphertext sitting in your private Gist.
4. The vault is marked `migrated: true`.

Nobody can read the Gist usefully without your master password — what's stored there is AES ciphertext, not your real data.

### Recovering a Migrated File
Unlocking a migrated vault with the correct password fetches the ciphertext from the Gist, decrypts it, verifies the integrity hash, and lets you preview or download the real file — completely transparent to you as the owner.

### Audit Log
Every event (setup, lock, wrong password, honeypot served, migration, delete) is inserted into a SQLite table where each row's hash includes the previous row's hash. Tampering with any old entry breaks every hash after it, making tampering detectable. `/api/status` reports whether the chain is still intact.

---

## Getting Started

```bash
git clone https://github.com/Krish033-source/BlackVault.git
cd BlackVault
pip install -r requirements.txt
cp .env.example .env   # fill in your SMTP + GitHub token details
python main.py
```

Then open `http://localhost:5000` in your browser.

### Required environment variables (`.env`)

| Variable | Purpose |
|---|---|
| `MAIL_SERVER`, `MAIL_PORT` | SMTP server for sending OTP / alert emails (default: Gmail) |
| `MAIL_USERNAME`, `MAIL_PASSWORD` | Sender account — for Gmail, use an **App Password**, not your normal password |
| `MAIL_DEFAULT_SENDER` | From-address shown on outgoing emails |
| `GITHUB_TOKEN` | A GitHub personal access token with `gist` scope, for auto-backup on attack |
| `PORT` | Port to run on (default `5000`) |
| `FLASK_DEBUG` | Set to `1` only for local debugging — never in production |

---

## API Reference

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/setup` | `POST` | One-time: set master password + recovery email |
| `/api/test_email` | `POST` | Sends a plain test email to confirm `.env` mail config |
| `/api/request_otp` | `POST` | Emails a real, single-use, 5-minute OTP |
| `/api/lock` | `POST` | Encrypts + stores a file (needs password + valid OTP) |
| `/api/download_encrypted/<id>` | `GET` | Downloads the raw ciphertext `.bv` file |
| `/api/unlock` | `POST` | Attempts to unlock; real password check + threat tracking |
| `/api/download_decrypted/<id>` | `POST` | Decrypts fully and returns the real original file |
| `/api/download_honeypot/<token>` | `GET` | Downloads the fake decoy file generated on a failed attempt |
| `/api/delete_attempt` | `POST` | Real delete (correct password) or blocked + migrated (wrong password) |
| `/api/status` | `POST` | Lists all vaults + the last 50 audit log entries. **Requires `{"password": "..."}`** in the body — this endpoint is authenticated. |

---

## Using the CLI

Everything the web UI does, you can also do straight from bash — no browser, no GUI. Run it from the same folder as `main.py`:

```bash
python cli.py setup            # interactive: prompts for password (hidden input), confirms it, then asks for recovery email
python cli.py test-email
python cli.py request-otp      # prompts for master password
python cli.py lock secret.txt  # prompts for password, then the OTP you received by email
python cli.py status           # prompts for password, shows all vaults + human-readable audit log
python cli.py unlock <vault_id>
python cli.py download <vault_id> recovered.txt
python cli.py delete <vault_id>
```

Passwords are always entered via a hidden prompt (`getpass`) — they never appear on screen or in shell history.

Run `python cli.py --help` or `python cli.py <command> --help` for details on any command.

---

## Using the Web Terminal

The web UI has a **GUI / Terminal** toggle at the top of the page. Terminal mode gives you a REPL right in the browser, hitting the exact same backend as the GUI and the CLI:

```
blackvault> help
blackvault> setup
blackvault> lock
blackvault> status
```

Interactive prompts (password, OTP, email) mask sensitive input the same way the CLI does. Type `mode gui` to switch back.

---

## Security Notes

- Every vault gets its **own random salt** for key derivation — the same password never produces the same encryption key across two different vaults.
- Password comparisons use constant-time checks (`hmac.compare_digest`) to avoid timing side-channels.
- OTP codes are generated with Python's `secrets` module (CSPRNG-backed), not `random`.
- `/api/status` requires the master password — vault metadata and the audit log are not publicly readable.
- The `GITHUB_TOKEN` is read from environment variables and is not persisted to `config.json` in plaintext when sourced that way.

This project was built as a learning/hackathon project to explore real encryption, real MFA, and real attacker-response mechanics end-to-end — **it has not been professionally security-audited.** Don't use it as your only backup for anything you can't afford to lose.

---

## Known Limitations

- The OTP state is currently global to the server, not scoped per in-progress lock operation — concurrent lock attempts from different users could interfere with each other's OTPs.
- The master password itself is stored as a single SHA-256 hash without a per-install salt; this is acceptable for a single-owner personal vault but would need hardening (e.g. `bcrypt`/`argon2`) for a multi-user deployment.
- No rate-limiting at the network layer — threat scoring tracks failed attempts per vault, but there's no global IP throttling.

---

## License

MIT — do whatever you want with it, just don't blame me if you lock yourself out. 😄
