# BlackVault — Setup & Run Guide

Encrypted file vault with password + OTP (MFA), automatic threat scoring,
and delete-attempt protection: if someone tries to wipe/delete a vault
without the correct password, the encrypted file is automatically backed
up before it's lost, and the **owner** (you) gets the retrieval link on
your own recovery email. Nothing is ever hidden from the actual owner —
only from whoever doesn't have the password.

## 1. Install dependencies

```bash
cd blackvault
python -m venv venv
source venv/bin/activate      # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Configure environment

```bash
cp .env.example .env
```

Then edit `.env`:
- `MAIL_USERNAME` / `MAIL_PASSWORD` → your Gmail + a Google **App Password**
  (Google Account → Security → 2-Step Verification → App Passwords)
- `UPLOAD_API_URL` is already set to `https://file.io` (free, no signup,
  no API key needed — good for demo/hackathon). Files uploaded there
  auto-expire after 14 days by default, which is fine for a demo but
  swap it for S3/Drive later if you want permanent backups.

## 3. Run

```bash
python main.py
```

Visit **http://localhost:5000**

## 4. Demo flow for judges

1. **Setup Vault** — set a master password + your real email (you'll get
   real emails here, so use an inbox you can check live).
2. **Lock File** — upload any test file, enter the password + OTP
   (`123456` in demo mode), tick a few threat checkboxes
   (e.g. "Delete attempt", "IP changed") to push the threat score ≥ 60.
3. Watch the response: file gets encrypted, uploaded to file.io, and a
   real email lands in your inbox with the recovery link — live, during
   the demo.
4. **Unlock Vault** with the wrong password → a honeypot decoy file is
   created and the attempt is logged (visible in Status/Logs).
5. **Status / Logs** panel shows the hash-chained audit trail — good
   talking point for "tamper-evident logging."

## What each threat flag means (for your pitch)

| Flag | Points |
|---|---|
| IP changed | 40 |
| 3+ bad passwords | 30 |
| Delete attempt | 50 |
| Format attempt | 60 |
| Unauthorized copy | 25 |
| Suspicious device | 20 |

Score ≥ 60 → auto-migrate + email the owner.

## Notes on the design (for your report/judges' Q&A)

- The owner **always** knows where their backup is — it's emailed to
  the recovery email they set up themselves. This is intentional:
  a vault that hides data from its own owner isn't a security product,
  it's a liability.
- Honeypot only fires on the *wrong password* path — it never blocks
  the real owner.
- `secure_wipe()` overwrites the local file with random bytes before
  deleting it, so a deleted/migrated vault can't be recovered from the
  local disk — but the encrypted copy safely exists at the backup link.
