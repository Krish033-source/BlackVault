from flask import Flask, request, jsonify, send_from_directory, send_file
from flask_cors import CORS
from flask_mail import Mail, Message
from cryptography.fernet import Fernet, InvalidToken
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import os, json, time, uuid, sqlite3, hashlib, base64, requests, io, random

load_dotenv()

app = Flask(__name__, static_folder="frontend", static_url_path="")
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", "587"))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "true").lower() == "true"
app.config["MAIL_USE_SSL"] = os.getenv("MAIL_USE_SSL", "false").lower() == "true"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_DEFAULT_SENDER", app.config["MAIL_USERNAME"])

mail = Mail(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "vault_data")
HONEYPOT_DIR = os.path.join(BASE_DIR, "honeypot_files")
LOG_DB = os.path.join(BASE_DIR, "blackvault_logs.db")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")
OTP_FILE = os.path.join(BASE_DIR, "otp_state.json")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(HONEYPOT_DIR, exist_ok=True)

HONEYPOT_AFTER_ATTEMPTS = 2
MIGRATE_THREAT_SCORE = 60
OTP_VALID_SECONDS = 300  # 5 minutes

# =========================================================
# DB / config helpers
# =========================================================
def init_db():
    with sqlite3.connect(LOG_DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                event TEXT NOT NULL,
                details TEXT NOT NULL,
                ip TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                curr_hash TEXT NOT NULL
            )
        """)
        conn.commit()

def default_config():
    return {
        "master_password_hash": "",
        "recovery_email": "",
        "github_token": os.getenv("GITHUB_TOKEN", "")
    }

def load_config():
    if not os.path.exists(CONFIG_FILE):
        cfg = default_config()
        save_config(cfg)
        return cfg
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    base = default_config()
    base.update(cfg)
    return base

def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or "unknown"

def log_event(event, details="", ip=None):
    init_db()
    ip = ip or "system"
    with sqlite3.connect(LOG_DB) as conn:
        row = conn.execute("SELECT curr_hash FROM logs ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = row[0] if row else "GENESIS"
        payload = f"{int(time.time())}|{event}|{details}|{ip}|{prev_hash}"
        curr_hash = sha256_text(payload)
        conn.execute(
            "INSERT INTO logs (ts, event, details, ip, prev_hash, curr_hash) VALUES (?, ?, ?, ?, ?, ?)",
            (int(time.time()), event, details, ip, prev_hash, curr_hash)
        )
        conn.commit()

# =========================================================
# Crypto helpers
# =========================================================
def derive_key(password, salt=b"blackvault_salt_v1"):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000, dklen=32)

def fernet_key(password):
    raw = hashlib.sha256(derive_key(password)).digest()
    return base64.urlsafe_b64encode(raw)

def encrypt_bytes(data, password):
    return Fernet(fernet_key(password)).encrypt(data)

def decrypt_bytes(data, password):
    return Fernet(fernet_key(password)).decrypt(data)

# =========================================================
# Vault metadata
# =========================================================
def make_vault_id():
    return uuid.uuid4().hex[:16]

def meta_path(vault_id):
    return os.path.join(DATA_DIR, f"{vault_id}.json")

def data_path(vault_id):
    return os.path.join(DATA_DIR, f"{vault_id}.bv")

def load_meta(vault_id):
    p = meta_path(vault_id)
    if not os.path.exists(p):
        return None
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)

def save_meta(vault_id, meta):
    with open(meta_path(vault_id), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

def secure_wipe(path):
    if not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass

def compute_threat_score(meta, attempt_ip):
    failed = meta.get("failed_attempts", 0)
    known_ips = set(meta.get("known_ips", []))
    score = min(failed, 5) * 20
    if attempt_ip not in known_ips:
        score += 30
    return score

def create_honeypot_file(original_name, vault_id):
    """
    Generates a REAL fake file on disk (not just a JSON text blob) that
    looks plausible but contains no real data. Returns a one-time
    download token pointing at it.
    """
    token = uuid.uuid4().hex[:16]
    safe_name = secure_filename(original_name) or "file"
    fake_path = os.path.join(HONEYPOT_DIR, f"{token}__{safe_name}")

    decoy_lines = [
        f"-- {original_name} --",
        "[This vault is currently locked / archived]",
        f"Reference: {vault_id[:8]}-XXXX-XXXX",
        "Status: ARCHIVED (no active balance / no active records)",
        "Last verified: N/A",
        "",
        "This is a placeholder file. No sensitive data is stored here.",
    ]
    with open(fake_path, "w", encoding="utf-8") as f:
        f.write("\n".join(decoy_lines) + "\n")

    return token, os.path.basename(fake_path)

def compute_file_hash(raw_bytes):
    return hashlib.sha256(raw_bytes).hexdigest()

def init_master(password, email):
    cfg = load_config()
    if cfg["master_password_hash"]:
        return False
    cfg["master_password_hash"] = sha256_text(password)
    cfg["recovery_email"] = email
    save_config(cfg)
    log_event("setup", "vault initialized", ip=client_ip())
    return True

def verify_master(password):
    cfg = load_config()
    return bool(cfg["master_password_hash"]) and sha256_text(password) == cfg["master_password_hash"]

# =========================================================
# REAL OTP -- generated fresh, emailed, single-use, expires
# =========================================================
def save_otp_state(state):
    with open(OTP_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)

def load_otp_state():
    if not os.path.exists(OTP_FILE):
        return None
    with open(OTP_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def generate_and_send_otp(to_email):
    otp = f"{random.randint(0, 999999):06d}"
    state = {"otp_hash": sha256_text(otp), "expires_at": int(time.time()) + OTP_VALID_SECONDS, "used": False}
    save_otp_state(state)
    body = f"Your BlackVault OTP is: {otp}\nIt expires in {OTP_VALID_SECONDS // 60} minutes and can be used once."
    ok, err = send_email_link(to_email, "BlackVault OTP Code", body)
    return ok, err

def verify_and_consume_otp(otp):
    state = load_otp_state()
    if not state:
        return False, "no_otp_requested"
    if state.get("used"):
        return False, "otp_already_used"
    if int(time.time()) > state.get("expires_at", 0):
        return False, "otp_expired"
    if sha256_text(otp) != state.get("otp_hash"):
        return False, "otp_incorrect"
    state["used"] = True
    save_otp_state(state)
    return True, None

# =========================================================
# Real, testable backup backend: GitHub Gist (secret gist)
# =========================================================
def upload_to_backup(file_path, vault_id):
    token = load_config().get("github_token", "")
    if not token:
        return None, "github_token_not_set"

    with open(file_path, "rb") as f:
        raw = f.read()
    encoded = base64.b64encode(raw).decode("ascii")

    payload = {
        "description": f"BlackVault encrypted backup {vault_id}",
        "public": False,
        "files": {f"{vault_id}.bv.b64": {"content": encoded}}
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    r = requests.post("https://api.github.com/gists", json=payload, headers=headers, timeout=60)
    if r.status_code not in (200, 201):
        return None, f"github_error_{r.status_code}:{r.text[:200]}"

    data = r.json()
    html_url = data.get("html_url")
    raw_url = data.get("files", {}).get(f"{vault_id}.bv.b64", {}).get("raw_url")
    if not html_url:
        return None, "no_url_in_response"
    return {"html_url": html_url, "raw_url": raw_url}, None

def download_from_backup(raw_url):
    token = load_config().get("github_token", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    r = requests.get(raw_url, headers=headers, timeout=60)
    r.raise_for_status()
    return base64.b64decode(r.text.strip())

def send_email_link(to_email, subject, body):
    if not to_email:
        return False, "recovery_email_missing"
    if not app.config["MAIL_USERNAME"] or not app.config["MAIL_PASSWORD"]:
        return False, "mail_not_configured_check_env_file"
    try:
        msg = Message(subject=subject, recipients=[to_email], body=body)
        mail.send(msg)
        return True, None
    except Exception as e:
        return False, str(e)

# =========================================================
# Shared: what happens on a wrong-password attempt
# =========================================================
def handle_wrong_attempt(meta, vault_id, action_label):
    ip = client_ip()
    meta["failed_attempts"] = meta.get("failed_attempts", 0) + 1
    meta["last_attempt_ip"] = ip
    meta["last_attempt_ts"] = int(time.time())

    score = compute_threat_score(meta, ip)
    meta["threat_score"] = score
    save_meta(vault_id, meta)
    log_event(f"bad_password_on_{action_label}", f"vault={vault_id} attempt#{meta['failed_attempts']} score={score}", ip=ip)

    migrated_now = False
    email_ok = None
    email_err = None
    migrate_err = None

    if score >= MIGRATE_THREAT_SCORE and not meta.get("migrated") and os.path.exists(data_path(vault_id)):
        enc_path = data_path(vault_id)
        result, err = upload_to_backup(enc_path, vault_id)
        if result:
            cfg = load_config()
            body = (
                f"SECURITY ALERT: repeated wrong-password attempts on your BlackVault vault.\n\n"
                f"Vault ID: {vault_id}\n"
                f"Failed attempts: {meta['failed_attempts']}\n"
                f"Last attempt IP: {ip}\n\n"
                f"Your encrypted file was backed up before it could be lost:\n{result['html_url']}\n\n"
                f"HOW TO GET YOUR REAL FILE BACK:\n"
                f"1. Open your BlackVault app (http://localhost:5000 if running locally)\n"
                f"2. Go to the Unlock section\n"
                f"3. Paste this Vault ID: {vault_id}\n"
                f"4. Enter your master password (the same one you set up with)\n"
                f"5. Click 'Download Real Decrypted File' -- BlackVault fetches the\n"
                f"   backup from the link above and decrypts it for you automatically.\n"
                f"   The backup link itself is USELESS without your password -- it's\n"
                f"   still AES-256 encrypted ciphertext.\n"
            )
            email_ok, email_err = send_email_link(cfg["recovery_email"], "BlackVault: Threat Detected - Auto Backup Created", body)
            if not email_ok:
                log_event("email_failed", email_err or "unknown", ip=ip)

            secure_wipe(enc_path)
            meta["migrated"] = True
            meta["migration_html_url"] = result["html_url"]
            meta["migration_raw_url"] = result["raw_url"]
            meta["state"] = "migrated"
            save_meta(vault_id, meta)
            log_event("auto_migrate", f"{vault_id} -> {result['html_url']} (email_sent={email_ok})", ip=ip)
            migrated_now = True
        else:
            migrate_err = err
            log_event("migrate_failed", err or "unknown", ip=ip)

    show_honeypot = meta["failed_attempts"] >= HONEYPOT_AFTER_ATTEMPTS
    honeypot_token = None
    honeypot_filename = None
    if show_honeypot:
        honeypot_token, honeypot_filename = create_honeypot_file(meta.get("original_name", "vault_file"), vault_id)
        log_event("honeypot_served", f"{vault_id} token={honeypot_token}", ip=ip)

    return {
        "score": score, "migrated_now": migrated_now, "show_honeypot": show_honeypot,
        "email_ok": email_ok, "email_err": email_err, "migrate_err": migrate_err,
        "honeypot_token": honeypot_token, "honeypot_filename": honeypot_filename
    }

# =========================================================
# Routes
# =========================================================
@app.route("/")
def home():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/ui.js")
def ui():
    return send_from_directory(app.static_folder, "ui.js")

@app.route("/api/setup", methods=["POST"])
def api_setup():
    data = request.get_json(force=True, silent=True) or {}
    password = data.get("password", "").strip()
    email = data.get("email", "").strip()
    if len(password) < 8:
        return jsonify({"ok": False, "reason": "password_too_short"}), 400
    if "@" not in email:
        return jsonify({"ok": False, "reason": "invalid_email"}), 400
    if not init_master(password, email):
        return jsonify({"ok": False, "reason": "already_initialized"}), 409
    return jsonify({"ok": True, "message": "vault_initialized"})

@app.route("/api/request_otp", methods=["POST"])
def api_request_otp():
    """
    REAL OTP: generates a random 6-digit code, emails it to the
    recovery email set at Setup. You must actually check your inbox
    and type the code you received -- it is not hardcoded anywhere.
    """
    data = request.get_json(force=True, silent=True) or {}
    password = data.get("password", "").strip()
    ip = client_ip()

    if not verify_master(password):
        log_event("otp_request_bad_password", "", ip=ip)
        return jsonify({"ok": False, "reason": "bad_master_password"}), 401

    cfg = load_config()
    ok, err = generate_and_send_otp(cfg["recovery_email"])
    if not ok:
        log_event("otp_email_failed", err or "unknown", ip=ip)
        return jsonify({
            "ok": False, "reason": "email_send_failed", "detail": err,
            "hint": "Check MAIL_USERNAME / MAIL_PASSWORD in your .env -- MAIL_PASSWORD must be a Gmail App Password, not your normal Gmail password."
        }), 500

    log_event("otp_sent", cfg["recovery_email"], ip=ip)
    return jsonify({"ok": True, "message": f"OTP sent to {cfg['recovery_email']}. Check your inbox (and spam folder)."})

@app.route("/api/lock", methods=["POST"])
def api_lock():
    file = request.files.get("file")
    password = request.form.get("password", "").strip()
    otp = request.form.get("otp", "").strip()
    ip = client_ip()

    if not file:
        return jsonify({"ok": False, "reason": "no_file"}), 400
    if not verify_master(password):
        log_event("bad_password_on_lock", file.filename, ip=ip)
        return jsonify({"ok": False, "reason": "bad_password"}), 401

    otp_ok, otp_err = verify_and_consume_otp(otp)
    if not otp_ok:
        log_event("bad_otp_on_lock", f"{file.filename}:{otp_err}", ip=ip)
        return jsonify({"ok": False, "reason": "bad_otp", "detail": otp_err}), 401

    vault_id = make_vault_id()
    enc_path = data_path(vault_id)
    raw = file.read()
    original_hash = compute_file_hash(raw)
    enc = encrypt_bytes(raw, password)
    with open(enc_path, "wb") as f:
        f.write(enc)

    meta = {
        "vault_id": vault_id,
        "original_name": file.filename,
        "stored_name": os.path.basename(enc_path),
        "created_at": int(time.time()),
        "migrated": False,
        "migration_html_url": "",
        "failed_attempts": 0,
        "known_ips": [ip],
        "last_attempt_ip": "",
        "threat_score": 0,
        "state": "locked",
        "original_sha256": original_hash
    }
    save_meta(vault_id, meta)
    log_event("encrypt", f"{file.filename} -> {vault_id} sha256={original_hash[:16]}...", ip=ip)

    return jsonify({
        "ok": True,
        "vault_id": vault_id,
        "action": "locked",
        "encrypted_download_url": f"/api/download_encrypted/{vault_id}",
        "original_sha256": original_hash,
        "message": "File encrypted and stored. Click the download link to see the actual encrypted bytes -- it will NOT open as your original file."
    })

@app.route("/api/download_encrypted/<vault_id>", methods=["GET"])
def api_download_encrypted(vault_id):
    """
    Real proof the file is encrypted: download the .bv file directly.
    Opening it in Notepad/any viewer shows scrambled bytes, not your
    original content -- that's Fernet/AES ciphertext.
    """
    meta = load_meta(vault_id)
    if not meta:
        return jsonify({"ok": False, "reason": "vault_not_found"}), 404
    path = data_path(vault_id)
    if not os.path.exists(path):
        if meta.get("migrated"):
            return jsonify({"ok": False, "reason": "already_migrated_use_backup_url", "backup_url": meta.get("migration_html_url", "")}), 410
        return jsonify({"ok": False, "reason": "data_missing"}), 404
    return send_file(path, as_attachment=True, download_name=f"{vault_id}_ENCRYPTED.bv")

@app.route("/api/download_honeypot/<token>", methods=["GET"])
def api_download_honeypot(token):
    """Serves the real fake decoy file generated when an attacker triggers the honeypot."""
    for fname in os.listdir(HONEYPOT_DIR):
        if fname.startswith(token + "__"):
            path = os.path.join(HONEYPOT_DIR, fname)
            display_name = fname.split("__", 1)[1]
            return send_file(path, as_attachment=True, download_name=display_name)
    return jsonify({"ok": False, "reason": "honeypot_not_found_or_expired"}), 404

@app.route("/api/unlock", methods=["POST"])
def api_unlock():
    data = request.get_json(force=True, silent=True) or {}
    vault_id = data.get("vault_id", "").strip()
    password = data.get("password", "").strip()
    ip = client_ip()

    meta = load_meta(vault_id)
    if not meta:
        return jsonify({"ok": False, "reason": "vault_not_found"}), 404

    if not verify_master(password):
        r = handle_wrong_attempt(meta, vault_id, "unlock")
        if r["show_honeypot"]:
            return jsonify({
                "ok": True, "honeypot": True,
                "message": "FAKE decoy file generated -- password was wrong. This is a real downloadable file, but it contains no real data.",
                "honeypot_download_url": f"/api/download_honeypot/{r['honeypot_token']}",
                "honeypot_filename": r["honeypot_filename"],
                "threat_score": r["score"], "migrated_now": r["migrated_now"],
                "email_ok": r["email_ok"], "email_err": r["email_err"], "migrate_err": r["migrate_err"]
            })
        return jsonify({
            "ok": False, "reason": "bad_password", "attempts": meta["failed_attempts"],
            "threat_score": r["score"]
        }), 403

    known_ips = set(meta.get("known_ips", []))
    known_ips.add(ip)
    meta["known_ips"] = list(known_ips)
    meta["failed_attempts"] = 0
    meta["threat_score"] = 0
    save_meta(vault_id, meta)
    log_event("unlock_success", vault_id, ip=ip)

    if meta.get("migrated"):
        try:
            enc = download_from_backup(meta["migration_raw_url"])
            dec = decrypt_bytes(enc, password)
            integrity_ok = compute_file_hash(dec) == meta.get("original_sha256")
            return jsonify({
                "ok": True, "migrated": True,
                "content_preview": dec[:500].decode("utf-8", errors="ignore"),
                "backup_url": meta["migration_html_url"],
                "decrypted_download_url": f"/api/download_decrypted/{vault_id}",
                "integrity_verified": integrity_ok
            })
        except Exception as e:
            return jsonify({
                "ok": True, "migrated": True,
                "message": "Correct password, but couldn't fetch/decrypt backup right now.",
                "backup_url": meta.get("migration_html_url", ""), "error": str(e)
            })

    path = data_path(vault_id)
    if not os.path.exists(path):
        return jsonify({"ok": False, "reason": "data_missing"}), 404

    with open(path, "rb") as f:
        dec = decrypt_bytes(f.read(), password)
    integrity_ok = compute_file_hash(dec) == meta.get("original_sha256")
    return jsonify({
        "ok": True, "migrated": False,
        "content_preview": dec[:500].decode("utf-8", errors="ignore"),
        "decrypted_download_url": f"/api/download_decrypted/{vault_id}",
        "integrity_verified": integrity_ok
    })

@app.route("/api/download_decrypted/<vault_id>", methods=["POST"])
def api_download_decrypted(vault_id):
    """Requires correct password again -- decrypts fully (not just 500-byte preview) and sends the real original file back as a download."""
    data = request.get_json(force=True, silent=True) or {}
    password = data.get("password", "").strip()

    meta = load_meta(vault_id)
    if not meta:
        return jsonify({"ok": False, "reason": "vault_not_found"}), 404
    if not verify_master(password):
        handle_wrong_attempt(meta, vault_id, "download")
        return jsonify({"ok": False, "reason": "bad_password"}), 403

    try:
        if meta.get("migrated"):
            enc = download_from_backup(meta["migration_raw_url"])
        else:
            with open(data_path(vault_id), "rb") as f:
                enc = f.read()
        dec = decrypt_bytes(enc, password)
    except Exception as e:
        return jsonify({"ok": False, "reason": "decrypt_failed", "detail": str(e)}), 500

    return send_file(
        io.BytesIO(dec), as_attachment=True,
        download_name=meta.get("original_name", "decrypted_file")
    )

@app.route("/api/delete_attempt", methods=["POST"])
def api_delete_attempt():
    data = request.get_json(force=True, silent=True) or {}
    vault_id = data.get("vault_id", "").strip()
    password = data.get("password", "").strip()
    ip = client_ip()

    meta = load_meta(vault_id)
    if not meta:
        return jsonify({"ok": False, "reason": "vault_not_found"}), 404

    if not verify_master(password):
        r = handle_wrong_attempt(meta, vault_id, "delete")
        resp = {
            "ok": True,
            "message": "delete_blocked" + ("_and_migrated" if r["migrated_now"] else ""),
            "attempts": meta["failed_attempts"], "threat_score": r["score"],
            "honeypot": r["show_honeypot"],
            "email_ok": r["email_ok"], "email_err": r["email_err"], "migrate_err": r["migrate_err"]
        }
        if r["show_honeypot"]:
            resp["honeypot_download_url"] = f"/api/download_honeypot/{r['honeypot_token']}"
            resp["honeypot_filename"] = r["honeypot_filename"]
        return jsonify(resp)

    secure_wipe(data_path(vault_id))
    meta["state"] = "deleted_by_owner"
    save_meta(vault_id, meta)
    log_event("owner_delete", vault_id, ip=ip)
    return jsonify({"ok": True, "message": "vault_deleted_by_owner"})

@app.route("/api/status", methods=["GET"])
def api_status():
    init_db()
    vaults = []
    for file in os.listdir(DATA_DIR):
        if file.endswith(".json"):
            try:
                with open(os.path.join(DATA_DIR, file), "r", encoding="utf-8") as f:
                    vaults.append(json.load(f))
            except Exception:
                pass
    logs = []
    with sqlite3.connect(LOG_DB) as conn:
        rows = conn.execute("SELECT ts, event, details, ip, prev_hash, curr_hash FROM logs ORDER BY id DESC LIMIT 50").fetchall()
        for r in rows:
            logs.append({"ts": r[0], "event": r[1], "details": r[2], "ip": r[3], "prev_hash": r[4], "curr_hash": r[5]})
    return jsonify({"ok": True, "vaults": vaults, "logs": logs})

@app.route("/api/test_email", methods=["POST"])
def api_test_email():
    """Debug helper: sends a plain test email so you can verify your .env mail config works, without touching any vault."""
    cfg = load_config()
    if not cfg.get("recovery_email"):
        return jsonify({"ok": False, "reason": "no_recovery_email_set_yet_run_setup_first"}), 400
    ok, err = send_email_link(cfg["recovery_email"], "BlackVault Test Email", "This is a test email from BlackVault. If you got this, your .env mail config is correct.")
    if not ok:
        return jsonify({"ok": False, "reason": "send_failed", "detail": err}), 500
    return jsonify({"ok": True, "message": f"Test email sent to {cfg['recovery_email']}"})

if __name__ == "__main__":
    init_db()
    if not os.path.exists(CONFIG_FILE):
        save_config(default_config())
    port = int(os.getenv("PORT", "5000"))
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
