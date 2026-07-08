"""
BlackVault CLI -- talk to your running BlackVault server (python main.py)
from the command line instead of the browser.

Run `python main.py` in one terminal first, then use this in another:

    python cli.py setup --password mypass123 --email you@gmail.com
    python cli.py test-email
    python cli.py request-otp --password mypass123
    python cli.py lock --file secret.txt --password mypass123 --otp 482913
    python cli.py unlock --vault-id abcd1234 --password mypass123
    python cli.py download-decrypted --vault-id abcd1234 --password mypass123 --out recovered.txt
    python cli.py delete --vault-id abcd1234 --password mypass123
    python cli.py status
"""
import argparse
import os
import sys
import requests

BASE_URL = https://blackvault-jm1q.onrender.com/


def pretty(resp):
    try:
        data = resp.json()
        import json
        print(json.dumps(data, indent=2))
    except Exception:
        print(f"HTTP {resp.status_code}: {resp.text[:300]}")


def cmd_setup(args):
    r = requests.post(f"{BASE_URL}/api/setup", json={"password": args.password, "email": args.email})
    pretty(r)


def cmd_test_email(args):
    r = requests.post(f"{BASE_URL}/api/test_email")
    pretty(r)


def cmd_request_otp(args):
    r = requests.post(f"{BASE_URL}/api/request_otp", json={"password": args.password})
    pretty(r)


def cmd_lock(args):
    with open(args.file, "rb") as f:
        files = {"file": (args.file, f)}
        data = {"password": args.password, "otp": args.otp}
        r = requests.post(f"{BASE_URL}/api/lock", files=files, data=data)
    pretty(r)


def cmd_unlock(args):
    r = requests.post(f"{BASE_URL}/api/unlock", json={"vault_id": args.vault_id, "password": args.password})
    pretty(r)


def cmd_download_encrypted(args):
    r = requests.get(f"{BASE_URL}/api/download_encrypted/{args.vault_id}")
    if r.status_code == 200:
        out = args.out or f"{args.vault_id}_ENCRYPTED.bv"
        with open(out, "wb") as f:
            f.write(r.content)
        print(f"Saved encrypted file to {out} ({len(r.content)} bytes)")
    else:
        pretty(r)


def cmd_download_decrypted(args):
    r = requests.post(f"{BASE_URL}/api/download_decrypted/{args.vault_id}", json={"password": args.password})
    if r.status_code == 200:
        out = args.out or "decrypted_output"
        with open(out, "wb") as f:
            f.write(r.content)
        print(f"Saved decrypted file to {out} ({len(r.content)} bytes)")
    else:
        pretty(r)


def cmd_delete(args):
    r = requests.post(f"{BASE_URL}/api/delete_attempt", json={"vault_id": args.vault_id, "password": args.password})
    pretty(r)


def cmd_status(args):
    r = requests.get(f"{BASE_URL}/api/status")
    pretty(r)


def main():
    parser = argparse.ArgumentParser(description="BlackVault command-line client")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("setup", help="Initialize the vault (once)")
    p.add_argument("--password", required=True)
    p.add_argument("--email", required=True)
    p.set_defaults(func=cmd_setup)

    p = sub.add_parser("test-email", help="Send a test email to verify your .env mail config")
    p.set_defaults(func=cmd_test_email)

    p = sub.add_parser("request-otp", help="Email yourself a real one-time OTP code")
    p.add_argument("--password", required=True)
    p.set_defaults(func=cmd_request_otp)

    p = sub.add_parser("lock", help="Encrypt and store a file")
    p.add_argument("--file", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--otp", required=True)
    p.set_defaults(func=cmd_lock)

    p = sub.add_parser("unlock", help="Attempt to unlock a vault (real threat detection applies)")
    p.add_argument("--vault-id", required=True)
    p.add_argument("--password", required=True)
    p.set_defaults(func=cmd_unlock)

    p = sub.add_parser("download-encrypted", help="Download the raw encrypted .bv file")
    p.add_argument("--vault-id", required=True)
    p.add_argument("--out")
    p.set_defaults(func=cmd_download_encrypted)

    p = sub.add_parser("download-decrypted", help="Decrypt and download the real original file")
    p.add_argument("--vault-id", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--out")
    p.set_defaults(func=cmd_download_decrypted)

    p = sub.add_parser("delete", help="Attempt to delete a vault (only succeeds for real with the correct password)")
    p.add_argument("--vault-id", required=True)
    p.add_argument("--password", required=True)
    p.set_defaults(func=cmd_delete)

    p = sub.add_parser("status", help="Show all vaults and the audit log")
    p.set_defaults(func=cmd_status)

    args = parser.parse_args()
    try:
        args.func(args)
    except requests.exceptions.ConnectionError:
        print("Could not reach the BlackVault server. Is `python main.py` running in another terminal?")
        sys.exit(1)


if __name__ == "__main__":
    main()
