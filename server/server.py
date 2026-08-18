import base64
import datetime as dt
import sqlite3
import hashlib
import json
import os
import secrets
import smtplib
from io import BytesIO
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    render_template_string,
    request,
    session,
    stream_with_context,
    url_for,
    send_file,
)
from cryptography.fernet import Fernet

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

LOG_CHAIN_FILE = DATA_DIR / "blockchain_logs.json"
AUTH_DEVICES_FILE = DATA_DIR / "authorized_devices.json"
FILES_TRACKER_FILE = DATA_DIR / "files.json"
SERVER_KEYS_FILE = DATA_DIR / "server_keys.json"
INTRUSION_DIR = DATA_DIR / "intrusions"
INTRUSION_DIR.mkdir(exist_ok=True)

DB_FILE = DATA_DIR / "nexus_departments.db"


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def derive_file_key(password: str) -> str:
    key_bytes = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes).decode()

def init_db():
    with get_db() as conn:
        # Tables are created if they do not exist
        pass
        
        conn.execute('''
            CREATE TABLE IF NOT EXISTS departments (
                department TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )
        ''')
        # Seed default departments if empty
        if conn.execute("SELECT COUNT(*) FROM departments").fetchone()[0] == 0:
            pw1 = hashlib.sha256('D1@2005'.encode()).hexdigest()
            pw2 = hashlib.sha256('D2@2005'.encode()).hexdigest()
            conn.execute("INSERT INTO departments (department, password_hash) VALUES ('DA', ?)", (pw1,))
            conn.execute("INSERT INTO departments (department, password_hash) VALUES ('DB', ?)", (pw2,))
            
        conn.execute('''
            CREATE TABLE IF NOT EXISTS file_auth (
                file_name TEXT PRIMARY KEY,
                department TEXT NOT NULL
            )
        ''')

init_db()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "nexus-soc-2026-secret")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Arnab@2026")
EMAIL_SENDER = "arnabjana078@gmail.com"
EMAIL_PASSWORD = "hzmqdxdebynazbks"
EMAIL_RECEIVER = "Sg2816418@gmail.com"
EMAIL_ENABLED = os.environ.get("EMAIL_ENABLED", "true").lower() == "true"
SERVER_HOST = os.environ.get("SERVER_HOST", "0.0.0.0")
SERVER_PORT = int(os.environ.get("PORT", "5050"))

clients = []
blocked_devices = set()
pending_attempts = []

# Agent session tracking — maps device_name -> session_id
# Only heartbeats with a valid session are accepted
active_sessions = {}


def _read_json(path: Path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _write_json(path: Path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _server_keys():
    keys = _read_json(SERVER_KEYS_FILE, {})
    if not keys:
        master = Fernet.generate_key().decode()
        signing = secrets.token_hex(32)
        keys = {"fernet_key": master, "signing_secret": signing}
        _write_json(SERVER_KEYS_FILE, keys)
    return keys


def _fernet():
    return Fernet(_server_keys()["fernet_key"].encode())


def _signing_secret() -> bytes:
    return _server_keys()["signing_secret"].encode()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated


def load_blockchain():
    return _read_json(LOG_CHAIN_FILE, [])


def save_blockchain(chain):
    _write_json(LOG_CHAIN_FILE, chain)


def load_authorized_devices():
    return _read_json(AUTH_DEVICES_FILE, {})


def save_authorized_devices(devices):
    _write_json(AUTH_DEVICES_FILE, devices)


def load_files():
    return _read_json(FILES_TRACKER_FILE, {})


def save_files(files):
    _write_json(FILES_TRACKER_FILE, files)


def now_str():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hash_value(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def encrypt_for_storage(raw: str) -> str:
    return _fernet().encrypt(raw.encode()).decode()


def decrypt_for_storage(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()


def calculate_block_hash(block: dict) -> str:
    payload = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


def add_block(event_type: str, data: dict):
    # Filter heartbeats at the lowest insertion point
    action = data.get("action", "")
    if "heartbeat" in action.lower():
        device = data.get("device")
        if device:
            auth = load_authorized_devices()
            if device in auth:
                auth[device]["last_seen"] = now_str()
                save_authorized_devices(auth)
        return {"index": -1, "hash": "skipped"}

    # Only log HIGH and MEDIUM severity events to the blockchain.
    # NORMAL events are silently acknowledged but not stored.
    severity = data.get("severity", "NORMAL").upper()
    if severity == "NORMAL":
        # Still update device last_seen
        device = data.get("device")
        if device:
            auth = load_authorized_devices()
            if device in auth:
                auth[device]["last_seen"] = now_str()
                save_authorized_devices(auth)
        return {"index": -1, "hash": "filtered"}

    chain = load_blockchain()
    prev_hash = chain[-1]["hash"] if chain else "0"
    block = {
        "index": len(chain),
        "timestamp": now_str(),
        "event_type": event_type,
        "data": data,
        "prev_hash": prev_hash,
    }
    block["hash"] = calculate_block_hash(block)
    chain.append(block)
    save_blockchain(chain)
    for q in clients:
        q.append(block)
    return block


def is_authorized(device: str, ip: str) -> bool:
    auth = load_authorized_devices()
    if device not in auth:
        return False
    allowed_ip = auth[device].get("ip")
    return allowed_ip == "*" or allowed_ip == ip


def classify_severity(device: str, ip: str, action: str) -> str:
    action_l = action.lower()
    if device in blocked_devices:
        return "HIGH"
    if not is_authorized(device, ip):
        return "HIGH"
    if "failed" in action_l or "unauthorized" in action_l or "intrusion" in action_l:
        return "HIGH"
    if "decrypt" in action_l:
        return "MEDIUM"
    return "NORMAL"


def save_intrusion_image(image_b64: str, device: str) -> str | None:
    if not image_b64:
        return None
    try:
        raw = base64.b64decode(image_b64)
        filename = f"{device}_{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg"
        path = INTRUSION_DIR / filename
        path.write_bytes(raw)
        return str(path)
    except Exception:
        return None


def send_email_alert(subject: str, plain: str, html: str | None = None, attachment_path: str | None = None):
    print("[EMAIL] Preparing security alert")
    missing_configs = []
    if not EMAIL_ENABLED:
        missing_configs.append("EMAIL_ENABLED is false")
    if not EMAIL_SENDER:
        missing_configs.append("EMAIL_SENDER is empty")
    if not EMAIL_PASSWORD:
        missing_configs.append("EMAIL_PASSWORD is empty")
    if not EMAIL_RECEIVER:
        missing_configs.append("EMAIL_RECEIVER is empty")
        
    if missing_configs:
        print(f"[EMAIL ERROR] Cannot send email. Missing/Invalid configs: {', '.join(missing_configs)}")
        return
        
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = EMAIL_SENDER
    msg["To"] = EMAIL_RECEIVER
    msg.attach(MIMEText(plain, "plain"))
    if html:
        msg.attach(MIMEText(html, "html"))
    if attachment_path and os.path.exists(attachment_path):
        from email.mime.image import MIMEImage
        print("[EMAIL] Attaching image")
        with open(attachment_path, "rb") as f:
            img = MIMEImage(f.read())
            img.add_header('Content-Disposition', 'attachment', filename="intruder.jpg")
            msg.attach(img)
        print("[EMAIL] Sending security email")
    else:
        print("[EMAIL] Sending security email without attachment")
        
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            try:
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            except smtplib.SMTPAuthenticationError as auth_err:
                print(f"[EMAIL ERROR] SMTP Authentication failed: {auth_err}")
                return
            
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print("[EMAIL] Security email sent successfully")
    except smtplib.SMTPException as smtp_err:
        print(f"[EMAIL ERROR] SMTP error occurred: {smtp_err}")
    except Exception as exc:
        print(f"[EMAIL ERROR] Connection/Unexpected failed -> {exc}")


def emit_security_email(severity: str, device: str, ip: str, file_name: str, action: str, attachment_path: str | None = None):
    subject = f"[{severity}] NEXUS alert | {device} | {file_name}"
    plain = (
        f"Severity: {severity}\n"
        f"Time: {now_str()}\n"
        f"Device: {device}\n"
        f"IP: {ip}\n"
        f"File: {file_name}\n"
        f"Action: {action}\n"
    )
    html = (
        "<html><body style='background:#0a0d13;color:#d9e2ec;font-family:Arial,sans-serif'>"
        f"<h2 style='color:{'#ff4466' if severity == 'HIGH' else '#ffaa00'}'>NEXUS Alert - {severity}</h2>"
        f"<p><b>Time:</b> {now_str()}</p>"
        f"<p><b>Device:</b> {device}</p>"
        f"<p><b>IP:</b> {ip}</p>"
        f"<p><b>File:</b> {file_name}</p>"
        f"<p><b>Action:</b> {action}</p>"
        "</body></html>"
    )
    send_email_alert(subject, plain, html, attachment_path)


def make_device_snapshot():
    auth = load_authorized_devices()
    return {
        "authorized": [
            {"device": d, **details} for d, details in sorted(auth.items())
        ],
        "blocked": sorted(blocked_devices),
    }


LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>NEXUS SOC Login</title>
  <style>
    :root{
      --bg:#0A0F1C;--card:#0F172A;--accent:#22D3EE;--accent-dark:#00E5FF;
      --success:#00FFA3;--danger:#FF4D6D;--text:#FFFFFF;--muted:#94A3B8;
      --border:rgba(148, 163, 184, 0.1);--input-bg:rgba(0, 0, 0, 0.3);--radius:12px;
    }
    *{box-sizing:border-box;margin:0;padding:0;}
    body{
      background:var(--bg);color:var(--text);
      font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
      font-size:14px;display:flex;align-items:center;justify-content:center;
      min-height:100vh;-webkit-font-smoothing:antialiased;
    }
    .card{
      width:100%;max-width:400px;
      background:var(--card);border:1px solid var(--border);
      border-radius:8px;padding:32px;
    }
    .header{text-align:center;margin-bottom:32px;}
    .logo{
      display:inline-flex;align-items:center;justify-content:center;
      width:48px;height:48px;border-radius:50%;background:rgba(129,140,248,.15);
      margin-bottom:12px;
    }
    .title{font-size:20px;font-weight:700;color:var(--text);margin-bottom:4px;}
    .subtitle{font-size:12px;color:var(--muted);}

    .form-group{margin-bottom:24px;}
    label{display:block;font-size:12px;font-weight:700;color:var(--text);margin-bottom:8px;}
    .input-wrap{position:relative;}
    input[type=password],input[type=text]{
      width:100%;height:44px;background:var(--input-bg);color:var(--text);
      border:1px solid var(--border);border-radius:var(--radius);
      padding:0 44px 0 12px;font-size:14px;font-family:inherit;
      transition:border-color .2s ease,box-shadow .2s ease;outline:none;
    }
    input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(129,140,248,.15);}
    input.error-field{border-color:var(--danger);}
    input.error-field:focus{box-shadow:0 0 0 3px rgba(251,113,133,.15);}

    .eye-btn{
      position:absolute;right:0;top:0;width:44px;height:44px;
      display:flex;align-items:center;justify-content:center;
      background:transparent;border:none;cursor:pointer;color:var(--accent);
    }
    .eye-btn:hover{color:var(--success);}
    .eye-btn svg{width:18px;height:18px;}

    .error-msg{font-size:12px;color:var(--danger);margin-top:6px;}

    .btn-submit{
      width:100%;height:44px;background:var(--accent);color:#fff;border:none;
      border-radius:var(--radius);font-size:14px;font-weight:700;cursor:pointer;
      transition:background .2s ease,transform .1s ease;display:flex;
      align-items:center;justify-content:center;gap:8px;font-family:inherit;
      margin-top:8px;
    }
    .btn-submit:hover{background:var(--accent-dark);}
    .btn-submit:active{transform:scale(0.98);}
    .btn-submit:disabled{opacity:.6;cursor:not-allowed;}
    .spinner{
      width:16px;height:16px;border:2px solid rgba(255,255,255,.3);
      border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite;display:none;
    }
    @keyframes spin{to{transform:rotate(360deg);}}
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="logo">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#818CF8" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <div class="title">NEXUS SOC Login</div>
      <div class="subtitle">Enter credentials to access the security console</div>
    </div>

    <form method="POST" id="loginForm">
      <div class="form-group">
        <label for="password">Admin Password</label>
        <div class="input-wrap">
          <input type="password" id="password" name="password"
                 placeholder="Enter admin password" autocomplete="current-password"
                 {% if error %}class="error-field"{% endif %} required />
          <button type="button" class="eye-btn" onclick="togglePwd()" title="Show/hide password" tabindex="-1">
            <svg id="eyeIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
          </button>
        </div>
        {% if error %}
        <div class="error-msg">{{ error }}</div>
        {% endif %}
      </div>

      <button type="submit" class="btn-submit" id="authBtn">
        <div class="spinner" id="spinner"></div>
        <span id="btnText">Authenticate</span>
      </button>
    </form>
  </div>

  <script>
    function togglePwd() {
      const inp = document.getElementById('password');
      const icon = document.getElementById('eyeIcon');
      if (inp.type === 'password') {
        inp.type = 'text';
        icon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>';
      } else {
        inp.type = 'password';
        icon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
      }
    }
    document.getElementById('loginForm').addEventListener('submit', function() {
      const btn = document.getElementById('authBtn');
      const txt = document.getElementById('btnText');
      const spin = document.getElementById('spinner');
      btn.disabled = true;
      txt.textContent = 'Authenticating...';
      spin.style.display = 'block';
    });
  </script>
</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("password", "") == ADMIN_PASSWORD:
            session["logged_in"] = True
            return redirect(url_for("home"))
        error = "Invalid password"
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@app.route("/dashboard")
@login_required
def home():
    return render_template("index.html", logs=load_blockchain())


@app.route("/stats")
@login_required
def stats():
    chain = load_blockchain()
    counts = {"HIGH": 0, "MEDIUM": 0, "NORMAL": 0}
    for block in chain:
        sev = block.get("data", {}).get("severity", "NORMAL").upper()
        counts[sev] = counts.get(sev, 0) + 1
    return jsonify(
        {
            "total": len(chain),
            "counts": counts,
            "blocked_devices": sorted(blocked_devices),
            "authorized_count": len(load_authorized_devices()),
            "pending_attempts": pending_attempts[-25:],
        }
    )


@app.route("/logs")
@login_required
def logs():
    return jsonify(load_blockchain())


@app.route("/devices")
@login_required
def devices():
    return jsonify(make_device_snapshot())


@app.route("/authorize-device", methods=["POST"])
@login_required
def authorize_device():
    data = request.get_json(silent=True) or {}
    device = (data.get("device") or "").strip()
    ip = (data.get("ip") or "").strip() or "*"
    owner = (data.get("owner") or "Server Manager").strip()
    if not device:
        return jsonify({"error": "device is required"}), 400
    auth = load_authorized_devices()
    auth[device] = {"ip": ip, "owner": owner, "authorized_at": now_str()}
    save_authorized_devices(auth)
    add_block(
        "access_management",
        {"severity": "NORMAL", "device": device, "ip": ip, "file": "-", "action": f"Device authorized by manager ({owner})"},
    )
    return jsonify({"status": "authorized", "device": device, "ip": ip})


@app.route("/revoke-device", methods=["POST"])
@login_required
def revoke_device():
    data = request.get_json(silent=True) or {}
    device = (data.get("device") or "").strip()
    auth = load_authorized_devices()
    if device not in auth:
        return jsonify({"error": "device not found"}), 404
    auth.pop(device)
    save_authorized_devices(auth)
    add_block(
        "access_management",
        {"severity": "MEDIUM", "device": device, "ip": "-", "file": "-", "action": "Device authorization revoked by manager"},
    )
    return jsonify({"status": "revoked", "device": device})


@app.route("/block-device", methods=["POST"])
@login_required
def block_device_route():
    data = request.get_json(silent=True) or {}
    device = (data.get("device") or "").strip()
    if not device:
        return jsonify({"error": "device is required"}), 400
    blocked_devices.add(device)
    add_block(
        "access_management",
        {"severity": "HIGH", "device": device, "ip": "-", "file": "-", "action": "Device blocked by manager"},
    )
    return jsonify({"status": "blocked", "device": device})


@app.route("/unblock-device", methods=["POST"])
@login_required
def unblock_device_route():
    data = request.get_json(silent=True) or {}
    device = (data.get("device") or "").strip()
    if device in blocked_devices:
        blocked_devices.discard(device)
        add_block(
            "access_management",
            {"severity": "MEDIUM", "device": device, "ip": "-", "file": "-", "action": "Device unblocked by manager"},
        )
        return jsonify({"status": "unblocked", "device": device})
    return jsonify({"error": "device not found"}), 404


@app.route("/clear", methods=["POST"])
@login_required
def clear_chain():
    save_blockchain([])
    pending_attempts.clear()
    for q in clients:
        q.append({"type": "clear"})
    return jsonify({"status": "cleared"})


@app.route("/stream")
@login_required
def stream():
    def event_stream():
        q = []
        clients.append(q)
        try:
            while True:
                if q:
                    yield "data: " + json.dumps(q.pop(0)) + "\n\n"
                else:
                    yield ": keepalive\n\n"
                import time
                time.sleep(1)
        finally:
            if q in clients:
                clients.remove(q)

    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")


@app.route("/client/enroll", methods=["POST"])
def client_enroll():
    data = request.get_json(silent=True) or {}
    device = data.get("device", "").strip()
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    auth = load_authorized_devices()
    if device not in auth:
        auth[device] = {"ip": ip, "owner": "Auto-enrolled", "authorized_at": now_str()}
        save_authorized_devices(auth)

    # Issue a session ID so the server can track active agents
    session_id = secrets.token_hex(16)
    active_sessions[device] = session_id
    print(f"[SESSION] {device} enrolled with session {session_id[:8]}...")

    return jsonify({"status": "ok", "server_time": now_str(), "session_id": session_id})


@app.route("/client/deregister", methods=["POST"])
def client_deregister():
    """Called by the agent on graceful shutdown to invalidate its session."""
    data = request.get_json(silent=True) or {}
    device = data.get("device", "").strip()
    session_id = data.get("session_id", "")

    stored = active_sessions.get(device)
    if stored and stored == session_id:
        del active_sessions[device]
        print(f"[SESSION] {device} deregistered (session {session_id[:8]}...)")
        return jsonify({"status": "deregistered"})

    return jsonify({"status": "ok", "message": "session not found or mismatch"})


@app.route("/client/request-encryption", methods=["POST"])
def request_encryption():
    data = request.get_json(silent=True) or {}
    device = data.get("device", "").strip()
    file_name = data.get("file_name", "unknown")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    
    # Authoritative extraction of department from filename
    # e.g., Test File.DA.txt
    try:
        parts = file_name.rsplit('.', 2)
        if len(parts) >= 2 and parts[-2].upper() in ("DA", "DB"):
            department = parts[-2].upper()
        else:
            return jsonify({"error": "Filename must contain a valid department marker (e.g. .DA. or .DB.)"}), 400
    except Exception:
        return jsonify({"error": "Invalid filename format"}), 400
        
        
    with get_db() as conn:
        row = conn.execute("SELECT password_hash FROM departments WHERE department=?", (department,)).fetchone()
        if not row:
            return jsonify({"error": "Department not found"}), 400
        password_hash = row[0]
        
        conn.execute('INSERT OR REPLACE INTO file_auth (file_name, department) VALUES (?, ?)', (file_name, department))
        
    key_bytes = bytes.fromhex(password_hash)
    file_key = base64.urlsafe_b64encode(key_bytes).decode()

    # Keep minimal metadata for the dashboard
    files_state = load_files()
    files_state[file_name] = {
        "file_name": file_name,
        "department": department,
        "origin_device": device,
        "created_at": now_str(),
        "status": "encrypted",
    }
    save_files(files_state)

    sev = classify_severity(device, ip, "encryption key issued")
    block = add_block(
        "encryption_request",
        {"severity": sev, "device": device, "ip": ip, "file": file_name, "action": f"Server issued encryption key for file {file_name} (Dept: {department})"},
    )
    return jsonify({"file_key": file_key, "department": department, "block": block})


@app.route("/client/request-decryption", methods=["POST"])
def request_decryption():
    if request.is_json:
        data = request.json or {}
    else:
        data = request.form or {}
        
    input_password = data.get("password") or data.get("auth_token", "")
    file_name = data.get("file_name", "unknown")
    ciphertext_b64 = data.get("ciphertext_b64")
    original_name = data.get("original_name", "decrypted_file")
    device = data.get("device", "unknown")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    image_file = None

    # Helper for failures
    def handle_failure(action_text):
        print(f"[DEBUG] Handling failure: {action_text}")
        
        # 1. Log event
        print("[DEBUG] Logging unauthorized access event to dashboard.")
        add_block("decryption_attempt", {"severity": "HIGH", "device": device, "ip": ip, "file": file_name, "action": action_text})
        
        # 2. Return 403
        print("[DEBUG] Returning 403 Forbidden to client.")
        return jsonify({"status": "fail", "message": "Unauthorized access attempt"}), 403

    print(f"[AUTH] Requested file: {file_name}")

    # 1. Extract file_department from filename
    try:
        parts = file_name.rsplit('.', 2)
        if len(parts) >= 2 and parts[-2].upper() in ("DA", "DB"):
            file_department = parts[-2].upper()
        else:
            print(f"[AUTH] File {file_name} does not contain valid department marker.")
            return handle_failure(f"Unauthorized access attempt | file: {file_name} | severity: HIGH")
    except Exception:
        print(f"[AUTH] Invalid filename format for {file_name}")
        return handle_failure(f"Unauthorized access attempt | file: {file_name} | severity: HIGH")
        
    print(f"[AUTH] File department: {file_department}")

    # 2. Verify password against file_department's hash
    print("[AUTH] Looking up department password")
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM departments WHERE department=?", (file_department,))
        dept_pwd_row = cursor.fetchone()
    
    if not dept_pwd_row:
        print(f"[AUTH] Department {file_department} not found in departments table.")
        return handle_failure(f"System error: Department {file_department} missing")
        
    expected_hash = dept_pwd_row[0]
    input_hash = hashlib.sha256(input_password.encode()).hexdigest() if input_password else ""
    
    if input_hash != expected_hash:
        print("[AUTH] Password verification failed")
        print("[AUTH] Unauthorized access detected")
        return handle_failure(f"Unauthorized access attempt | file: {file_name} | severity: HIGH")
        
    print("[AUTH] Password verification successful")
    
    print("[DEBUG] Access granted.")

    # 4. KEY GENERATION
    key_bytes = hashlib.sha256(input_password.encode()).digest()
    key = base64.urlsafe_b64encode(key_bytes).decode()

    # 5. DECRYPTION OR KEY ISSUANCE
    if ciphertext_b64:
        try:
            cipher = Fernet(key.encode())
            decrypted_data = cipher.decrypt(base64.b64decode(ciphertext_b64))
        except Exception as e:
            return jsonify({"status": "fail", "message": f"Decryption failed: {str(e)}"}), 400

        # 6a. LOGGING & RESPONSE FOR FULL FILE
        add_block("decryption_success", {"severity": "NORMAL", "device": device, "ip": ip, "file": file_name, "action": f"Decryption success | file: {file_name} | dept: {file_department} | severity: NORMAL"})
        return send_file(BytesIO(decrypted_data), as_attachment=True, download_name=original_name)
    else:
        # 6b. LOGGING & RESPONSE FOR KEY ONLY (Agent request)
        add_block("key_issued", {"severity": "NORMAL", "device": device, "ip": ip, "file": file_name, "action": f"Decryption key issued | file: {file_name} | dept: {file_department} | severity: NORMAL"})
        return jsonify({"status": "ok", "file_key": key})


@app.route("/client/log-event", methods=["POST"])
def client_log_event():
    data = request.get_json(silent=True) or {}
    device = data.get("device", "unknown")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    file_name = data.get("file", "-")
    action = data.get("action", "client event")
    severity = data.get("severity") or classify_severity(device, ip, action)

    # Session-based heartbeat filtering
    if "heartbeat" in action.lower():
        session_id = data.get("session_id", "")
        stored = active_sessions.get(device)
        if not stored or stored != session_id:
            # Silently drop heartbeats from unknown/stale sessions
            return jsonify({"status": "ok", "block": {"index": -1, "hash": "dropped"}})

    block = add_block("client_event", {"severity": severity, "device": device, "ip": ip, "file": file_name, "action": action})
    if severity == "HIGH":
        attachment_path = None
        intrusion_image_b64 = data.get("intrusion_image_b64")
        if intrusion_image_b64:
            import base64
            import datetime as dt
            try:
                timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"event_{timestamp}.jpg"
                path = INTRUSION_DIR / filename
                path.write_bytes(base64.b64decode(intrusion_image_b64))
                attachment_path = str(path)
                print(f"[EMAIL] Image attachment found: {filename}")
            except Exception as e:
                print(f"[ERROR] Failed to save b64 image: {e}")
                print("[EMAIL] No webcam image available")
        else:
            print("[EMAIL] No webcam image available")
                
        import threading
        threading.Thread(target=emit_security_email, args=("HIGH", device, ip, file_name, action, attachment_path), daemon=True).start()
    return jsonify({"status": "ok", "block": block})


@app.route("/client/log-event-batch", methods=["POST"])
def client_log_event_batch():
    data = request.get_json(silent=True) or {}
    events = data.get("events", [])
    results = []
    for evt in events:
        device = evt.get("device", "unknown")
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        file_name = evt.get("file", "-")
        action = evt.get("action", "batch event")
        severity = evt.get("severity") or classify_severity(device, ip, action)

        # Session-based heartbeat filtering for batch events
        if "heartbeat" in action.lower():
            session_id = evt.get("session_id", "")
            stored = active_sessions.get(device)
            if not stored or stored != session_id:
                results.append({"status": "dropped", "block_index": -1})
                continue

        block = add_block("client_event", {"severity": severity, "device": device, "ip": ip, "file": file_name, "action": action})
        if severity == "HIGH":
            attachment_path = None
            intrusion_image_b64 = evt.get("intrusion_image_b64")
            if intrusion_image_b64:
                import base64
                import datetime as dt
                try:
                    timestamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                    path = INTRUSION_DIR / f"event_batch_{timestamp}.jpg"
                    path.write_bytes(base64.b64decode(intrusion_image_b64))
                    attachment_path = str(path)
                except Exception as e:
                    print(f"[ERROR] Failed to save b64 image: {e}")
                    
            import threading
            threading.Thread(target=emit_security_email, args=("HIGH", device, ip, file_name, action, attachment_path), daemon=True).start()
        results.append({"status": "ok", "block_index": block["index"]})
    return jsonify({"status": "ok", "count": len(results), "results": results})


if __name__ == "__main__":
    _server_keys()
    save_blockchain(load_blockchain())
    save_authorized_devices(load_authorized_devices())
    save_files(load_files())
    print(f"[SERVER] running on http://{SERVER_HOST}:{SERVER_PORT}")
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=SERVER_HOST, port=SERVER_PORT, debug=debug_mode, use_reloader=False, threaded=True)
