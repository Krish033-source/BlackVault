#!/usr/bin/env python3
"""
BlackVault CLI -- run every vault operation straight from bash, no browser,
no GUI, no separate page. This imports main.py directly and calls the exact
same functions the Flask routes use, so behaviour (encryption, honeypot,
auto-migrate, audit log) is identical to the web UI.

Usage:
    python cli.py setup
    python cli.py request-otp
    python cli.py lock <file_path>
    python cli.py unlock <vault_id>
    python cli.py download <vault_id> <output_path>
    python cli.py delete <vault_id>
    python cli.py status
    python cli.py test-email

Run these from the SAME folder as main.py (or set BLACKVAULT_DIR env var to
point at it), since it reuses main.py's DATA_DIR / config / DB paths as-is.
"""
import sys
import os
import getpass
import argparse

# Let the CLI be run from anywhere by pointing at the main.py directory.
APP_DIR = os.getenv("BLACKVAULT_DIR", os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, APP_DIR)

import main as bv  # reuses every helper function from main.py, zero duplication


def pw_prompt(label="Master password: "):
    return getpass.getpass(label).strip()


def cmd_setup(args):
    if bv.load_config()["master_password_hash"]:
        print("Vault already initialized. Delete config.json first if you really want to redo setup.")
        return
    password = pw_prompt("Set master password: ")
    confirm = pw_prompt("Confirm master password: ")
    if password != confirm:
        print("Passwords didn't match.")
        return
    if len(password) < 8:
        print("Password must be at least 8 characters.")
        return
    email = input("Recovery email: ").strip()
    if "@" not in email:
        print("That doesn't look like a valid email.")
        return
    bv.init_master(password, email)
    print("Vault initialized. Master password + recovery email saved.")


def cmd_request_otp(args):
    password = pw_prompt()
    if not bv.verify_master(password):
        print("Wrong master password.")
        return
    cfg = bv.load_config()
    ok, err = bv.generate_and_send_otp(cfg["recovery_email"])
    if ok:
        print(f"OTP sent to {cfg['recovery_email']}. Check inbox (and spam).")
    else:
        print(f"Failed to send OTP: {err}")


def cmd_lock(args):
    if not os.path.exists(args.file_path):
        print(f"File not found: {args.file_path}")
        return
    password = pw_prompt()
    if not bv.verify_master(password):
        print("Wrong master password.")
        bv.log_event("bad_password_on_lock", os.path.basename(args.file_path), ip="cli")
        return
    otp = input("Enter the OTP you received by email: ").strip()
    otp_ok, otp_err = bv.verify_and_consume_otp(otp)
    if not otp_ok:
        print(f"OTP check failed: {otp_err}")
        return

    with open(args.file_path, "rb") as f:
        raw = f.read()

    vault_id = bv.make_vault_id()
    enc_path = bv.data_path(vault_id)
    original_hash = bv.compute_file_hash(raw)
    salt = os.urandom(16)
    enc = bv.encrypt_bytes(raw, password, salt)
    with open(enc_path, "wb") as f:
        f.write(enc)

    meta = {
        "vault_id": vault_id,
        "original_name": os.path.basename(args.file_path),
        "stored_name": os.path.basename(enc_path),
        "created_at": int(__import__("time").time()),
        "migrated": False,
        "migration_html_url": "",
        "failed_attempts": 0,
        "known_ips": ["cli"],
        "last_attempt_ip": "",
        "threat_score": 0,
        "state": "locked",
        "original_sha256": original_hash,
        "salt": salt.hex()
    }
    bv.save_meta(vault_id, meta)
    bv.log_event("encrypt", f"{meta['original_name']} -> {vault_id} sha256={original_hash[:16]}...", ip="cli")

    print("File locked successfully.")
    print(f"  Vault ID : {vault_id}")
    print(f"  SHA-256  : {original_hash}")
    print(f"  Stored at: {enc_path}")
    print("  Save the Vault ID -- you need it to unlock later.")


def cmd_unlock(args):
    meta = bv.load_meta(args.vault_id)
    if not meta:
        print("Vault not found.")
        return
    password = pw_prompt()

    if not bv.verify_master(password):
        r = bv.handle_wrong_attempt(meta, args.vault_id, "unlock")
        if r["show_honeypot"]:
            print("Wrong password. A decoy file was generated (contains no real data):")
            print(f"  {os.path.join(bv.HONEYPOT_DIR, r['honeypot_filename'])}")
        else:
            print(f"Wrong password. Threat score now: {r['score']}")
        return

    known_ips = set(meta.get("known_ips", []))
    known_ips.add("cli")
    meta["known_ips"] = list(known_ips)
    meta["failed_attempts"] = 0
    meta["threat_score"] = 0
    bv.save_meta(args.vault_id, meta)
    bv.log_event("unlock_success", args.vault_id, ip="cli")

    salt = bv.get_vault_salt(meta)
    try:
        if meta.get("migrated"):
            enc = bv.download_from_backup(meta["migration_raw_url"])
        else:
            with open(bv.data_path(args.vault_id), "rb") as f:
                enc = f.read()
        dec = bv.decrypt_bytes(enc, password, salt)
    except Exception as e:
        print(f"Decrypt failed: {e}")
        return

    integrity_ok = bv.compute_file_hash(dec) == meta.get("original_sha256")
    print("Unlocked successfully.")
    print(f"  Integrity verified: {integrity_ok}")
    print("  Preview (first 500 bytes):")
    print(dec[:500].decode("utf-8", errors="ignore"))
    print("\nUse `python cli.py download <vault_id> <output_path>` to save the full file.")


def cmd_download(args):
    meta = bv.load_meta(args.vault_id)
    if not meta:
        print("Vault not found.")
        return
    password = pw_prompt()
    if not bv.verify_master(password):
        r = bv.handle_wrong_attempt(meta, args.vault_id, "download")
        if r["show_honeypot"]:
            print("Wrong password. A decoy file was generated (contains no real data):")
            print(f"  {os.path.join(bv.HONEYPOT_DIR, r['honeypot_filename'])}")
        else:
            print(f"Wrong password. Threat score now: {r['score']}")
        return

    try:
        salt = bv.get_vault_salt(meta)
        if meta.get("migrated"):
            enc = bv.download_from_backup(meta["migration_raw_url"])
        else:
            with open(bv.data_path(args.vault_id), "rb") as f:
                enc = f.read()
        dec = bv.decrypt_bytes(enc, password, salt)
    except Exception as e:
        print(f"Decrypt failed: {e}")
        return

    with open(args.output_path, "wb") as f:
        f.write(dec)
    print(f"Saved decrypted file to {args.output_path}")


def cmd_delete(args):
    meta = bv.load_meta(args.vault_id)
    if not meta:
        print("Vault not found.")
        return
    password = pw_prompt()
    if not bv.verify_master(password):
        r = bv.handle_wrong_attempt(meta, args.vault_id, "delete")
        print(f"Wrong password. Delete blocked. Threat score: {r['score']}")
        if r["show_honeypot"]:
            print(f"  Decoy file: {os.path.join(bv.HONEYPOT_DIR, r['honeypot_filename'])}")
        return

    bv.secure_wipe(bv.data_path(args.vault_id))
    meta["state"] = "deleted_by_owner"
    bv.save_meta(args.vault_id, meta)
    bv.log_event("owner_delete", args.vault_id, ip="cli")
    print("Vault deleted.")


def cmd_status(args):
    password = pw_prompt()
    if not bv.verify_master(password):
        print("Wrong master password.")
        return

    bv.init_db()
    print("\n=== VAULTS ===")
    found_any = False
    for fname in os.listdir(bv.DATA_DIR):
        if fname.endswith(".json"):
            found_any = True
            import json as _json
            with open(os.path.join(bv.DATA_DIR, fname), "r", encoding="utf-8") as f:
                m = _json.load(f)
            print(f"- {m.get('vault_id')} | {m.get('original_name')} | state={m.get('state')} "
                  f"| failed_attempts={m.get('failed_attempts')} | threat_score={m.get('threat_score')}")
    if not found_any:
        print("(no vaults yet)")

    print("\n=== AUDIT LOG (most recent first) ===")
    import sqlite3
    with sqlite3.connect(bv.LOG_DB) as conn:
        rows = conn.execute(
            "SELECT ts, event, details, ip, prev_hash, curr_hash FROM logs ORDER BY id DESC LIMIT 50"
        ).fetchall()
    if not rows:
        print("(no log entries yet)")
    for row in rows:
        entry = bv.humanize_log_row(row)
        print(f"[{entry['when']}] {entry['message']}  (ip={entry['ip']})")

    ok = bv.verify_log_chain_intact()
    print(f"\nTamper check: {'OK - log history is intact' if ok else 'FAILED - log history looks tampered with!'}")


def cmd_test_email(args):
    cfg = bv.load_config()
    if not cfg.get("recovery_email"):
        print("No recovery email set yet -- run `python cli.py setup` first.")
        return
    ok, err = bv.send_email_link(
        cfg["recovery_email"], "BlackVault Test Email",
        "This is a test email from BlackVault CLI. If you got this, your .env mail config is correct."
    )
    if ok:
        print(f"Test email sent to {cfg['recovery_email']}")
    else:
        print(f"Send failed: {err}")


def main():
    parser = argparse.ArgumentParser(description="BlackVault CLI -- operate the vault fully from bash.")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("setup", help="First-time setup: master password + recovery email").set_defaults(func=cmd_setup)
    sub.add_parser("request-otp", help="Email yourself a fresh OTP (needed before lock)").set_defaults(func=cmd_request_otp)

    p_lock = sub.add_parser("lock", help="Encrypt and store a file")
    p_lock.add_argument("file_path")
    p_lock.set_defaults(func=cmd_lock)

    p_unlock = sub.add_parser("unlock", help="Unlock a vault (shows a preview)")
    p_unlock.add_argument("vault_id")
    p_unlock.set_defaults(func=cmd_unlock)

    p_download = sub.add_parser("download", help="Decrypt and save the full original file")
    p_download.add_argument("vault_id")
    p_download.add_argument("output_path")
    p_download.set_defaults(func=cmd_download)

    p_delete = sub.add_parser("delete", help="Delete a vault (owner-authorized)")
    p_delete.add_argument("vault_id")
    p_delete.set_defaults(func=cmd_delete)

    sub.add_parser("status", help="Show all vaults + human-readable audit log").set_defaults(func=cmd_status)
    sub.add_parser("test-email", help="Send a test email to verify mail config").set_defaults(func=cmd_test_email)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
