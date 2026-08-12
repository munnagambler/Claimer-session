import os
import re
import json
import time
import threading
import asyncio
import secrets
import sqlite3
import datetime
import urllib.request
import urllib.parse
import collections
from flask import Flask, request, jsonify, render_template_string, Response

import logging

from pyrogram import Client, filters
from pyrogram.handlers import MessageHandler, EditedMessageHandler
from pyrogram.errors import SessionPasswordNeeded

# ══════════════════════════════════════════════════════════════
#  SUPPRESS PYROGRAM INTERNAL PEER/RESOLVE ERRORS
# ══════════════════════════════════════════════════════════════
class _SuppressPeerErrors(logging.Filter):
    _BLOCKED = (
        "Peer id invalid",
        "ID not found",
        "Task exception was never retrieved",
        "peer_id invalid",
        "resolve_peer",
        "get_peer_by_id",
        "KeyError",
    )
    def filter(self, record):
        msg = record.getMessage()
        return not any(b in msg for b in self._BLOCKED)

for _lg_name in ("pyrogram", "pyrogram.dispatcher",
                 "pyrogram.methods.advanced.resolve_peer",
                 "pyrogram.client", "asyncio"):
    _lg = logging.getLogger(_lg_name)
    _lg.addFilter(_SuppressPeerErrors())
    _lg.setLevel(logging.CRITICAL)

app = Flask(__name__)

# ══════════════════════════════════════════════════════════════
#  SECURITY LAYER 1 — X-Forwarded-For Spoof Protection
# ══════════════════════════════════════════════════════════════
def get_real_ip():
    return request.remote_addr  


# ══════════════════════════════════════════════════════════════
#  SECURITY LAYER 2 — Brute Force / DoS Rate Limiter
# ══════════════════════════════════════════════════════════════
_failed_attempts  = {}   
_request_log      = {}   
_ratelimit_lock   = threading.Lock()

FLOOD_LIMIT_PER_10S = 80   

def is_flood(ip):
    now = time.time()
    with _ratelimit_lock:
        reqs = _request_log.get(ip, [])
        reqs = [t for t in reqs if now - t < 10]
        _request_log[ip] = reqs
        if len(reqs) >= FLOOD_LIMIT_PER_10S:
            return True
        reqs.append(now)
        _request_log[ip] = reqs
        return False

def is_rate_limited(ip):
    now = time.time()
    with _ratelimit_lock:
        attempts = _failed_attempts.get(ip, [])
        attempts = [t for t in attempts if now - t < 60]
        _failed_attempts[ip] = attempts
        return len(attempts) >= 8  

def record_failed_attempt(ip):
    now = time.time()
    with _ratelimit_lock:
        _failed_attempts.setdefault(ip, []).append(now)

def clear_failed_attempts(ip):
    with _ratelimit_lock:
        _failed_attempts.pop(ip, None)


# ══════════════════════════════════════════════════════════════
#  SECURITY LAYER 3 — Admin Endpoint Hardening
# ══════════════════════════════════════════════════════════════
BLOCKED_PATHS = {
    '/admin', '/administrator', '/panel', '/cp', '/dashboard',
    '/phpmyadmin', '/mysql', '/wp-admin', '/wp-login.php',
    '/config', '/env', '/.env', '/setup', '/install',
    '/api/admin', '/console', '/manager', '/backend',
    '/xmlrpc.php', '/cgi-bin', '/shell', '/cmd',
}

@app.before_request
def security_firewall():
    ip = get_real_ip()

    if is_flood(ip):
        return "Too many requests.", 429

    raw_path = request.path.rstrip('/').lower()
    if raw_path in BLOCKED_PATHS:
        return "", 404

    for key, val in request.headers:
        if '\r' in val or '\n' in val:
            return "Bad request.", 400

    # ── MASTER ACCESS SECRET GATE ────────────────────────────
    if ACCESS_SECRET and request.path not in ('/ping',):
        token_header = request.headers.get("X-Matrix-Access", "")
        token_param  = request.args.get("_mxs", "")
        token_cookie = request.cookies.get("_mxs", "")
        if token_header != ACCESS_SECRET and token_param != ACCESS_SECRET and token_cookie != ACCESS_SECRET:
            return "", 404

    if request.path in ('/auth/phone', '/auth/code', '/auth/2fa', '/license/verify'):
        time.sleep(0.01)


# ══════════════════════════════════════════════════════════════
#  SECURITY LAYER 4 — Response Header Hardening
# ══════════════════════════════════════════════════════════════
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options']  = 'nosniff'
    response.headers['X-XSS-Protection']         = '1; mode=block'
    response.headers['Referrer-Policy']           = 'no-referrer'
    response.headers.pop('Server', None)
    return response

# ══════════════════════════════════════════════════════════════
#  CONFIG 
# ══════════════════════════════════════════════════════════════
DB_PATH       = os.environ.get("DB_PATH", "/data/licenses.db")
ADMIN_SECRET  = os.environ.get("ADMIN_SECRET", "")
SESSIONS_DIR  = os.environ.get("SESSIONS_DIR", "/data/sessions")
API_ID        = int(os.environ.get("TG_API_ID", "0"))
API_HASH      = os.environ.get("TG_API_HASH", "")

PROXIES = json.loads(os.environ.get("PROXY_LIST", "[]"))

# ── MASTER ACCESS SECRET ─────────────────────────────────────
# Set ACCESS_SECRET in HuggingFace Secrets.
# Every request must send header: X-Matrix-Access: <secret>
# OR url param: ?_mxs=<secret>  OR cookie: _mxs=<secret>
# Without it → 404. Server looks dead to scanners/bots.
ACCESS_SECRET = os.environ.get("ACCESS_SECRET", "")

os.makedirs(SESSIONS_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

with open(os.path.join(os.path.dirname(__file__), "dashboard.html"), "r", encoding="utf-8") as f:
    DASHBOARD_HTML = f.read()


# ══════════════════════════════════════════════════════════════
#  LICENSE DATABASE
# ══════════════════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT UNIQUE NOT NULL,
            device_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            active INTEGER DEFAULT 1,
            tg_api_id TEXT DEFAULT '',
            tg_api_hash TEXT DEFAULT ''
        )
    """)
    # Migration: add columns if they don't exist (for existing DBs)
    try:
        conn.execute("ALTER TABLE licenses ADD COLUMN tg_api_id TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE licenses ADD COLUMN tg_api_hash TEXT DEFAULT ''")
    except Exception:
        pass
    conn.commit()
    conn.close()

init_db()

ADMIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Matrix License Admin</title>
    <style>
        body { background: #0a0a0a; color: #fff; font-family: sans-serif; padding: 20px; max-width: 600px; margin: 0 auto; }
        input, button { width: 100%; padding: 14px; margin-bottom: 14px; border-radius: 8px; border: 1px solid #333; background: #1a1a1a; color: #fff; font-size: 15px; box-sizing: border-box; }
        button { background: #00aa55; font-weight: bold; border: none; cursor: pointer; }
        .key-box { background: #141414; border: 1px solid #00ff88; border-radius: 8px; padding: 16px; margin-top: 10px; margin-bottom: 20px; word-break: break-all; font-size: 20px; color: #00ff88; text-align: center; letter-spacing: 2px; }
        h2 { color: #00ff88; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 12px; }
        td, th { border: 1px solid #333; padding: 8px; text-align: left; word-break: break-all; }
        th { background: #111; color: #00ff88; }
        .btn-revoke { background: #d32f2f; color: #fff; padding: 6px 10px; font-size: 11px; border-radius: 4px; font-weight: bold; width: auto; margin: 0; }
    </style>
</head>
<body>
    <h2>⚡ Matrix License Generator</h2>
    <form method="POST" action="/license/generate">
      <input type="password" name="secret" placeholder="Admin Secret" required>
      <input type="text" name="device_id" placeholder="Buyer's Device ID" required>
      <input type="number" name="days" placeholder="Validity in days (1, 3, 30...)" required>
      <button type="submit">Generate License Key</button>
    </form>
    
    {% if generated_key %}
    <div class="key-box">🔑 {{ generated_key }}</div>
    <p style="text-align:center;color:#888">Valid until: {{ expires_at }}</p>
    {% endif %}
    
    <h2>All Licenses ({{ licenses|length }})</h2>
    <table>
        <tr>
            <th>Key</th>
            <th>Device ID</th>
            <th>Expires</th>
            <th>Action</th>
        </tr>
        {% for lic in licenses %}
        <tr>
          <td><b>{{ lic.license_key }}</b></td>
          <td>{{ lic.device_id[:12] }}...</td>
          <td>{{ lic.expires_at[:10] }}</td>
          <td>
            <form method="POST" action="/license/revoke" style="margin:0;" onsubmit="return confirm('Kya aap sach me is key ko block karke user ko instantly logout karna chahte hain?');">
              <input type="hidden" name="secret" value="{{ request.args.get('secret','') }}">
              <input type="hidden" name="key_to_revoke" value="{{ lic.license_key }}">
              <button type="submit" class="btn-revoke">Revoke 🗑️</button>
            </form>
          </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
"""

@app.route("/license/admin", methods=["GET"])
def license_admin_page():
    secret = request.args.get("secret", "")
    if secret != ADMIN_SECRET:
        return "🔒 Access Denied: Galat ya missing admin secret link.", 403

    conn = get_db()
    licenses = conn.execute("SELECT * FROM licenses ORDER BY id DESC").fetchall()
    conn.close()
    return render_template_string(ADMIN_PAGE, generated_key=None, expires_at=None, licenses=licenses)

@app.route("/license/generate", methods=["POST"])
def license_generate():
    secret = request.form.get("secret", "")
    if secret != ADMIN_SECRET:
        return "Wrong admin secret", 403

    device_id = request.form.get("device_id", "").strip()
    days = int(request.form.get("days", "1"))

    if not device_id:
        return "Device ID nahi diya — buyer ka Device ID paste karo", 400
    if days <= 0:
        return "Days 1 ya usse zyada hone chahiye", 400

    license_key = secrets.token_hex(8).upper()
    created_at = datetime.datetime.utcnow().isoformat()
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).isoformat()

    conn = get_db()
    conn.execute(
        "INSERT INTO licenses (license_key, device_id, created_at, expires_at, active) VALUES (?, ?, ?, ?, 1)",
        (license_key, device_id, created_at, expires_at)
    )
    conn.commit()
    licenses = conn.execute("SELECT * FROM licenses ORDER BY id DESC").fetchall()
    conn.close()

    return render_template_string(ADMIN_PAGE, generated_key=license_key, expires_at=expires_at, licenses=licenses)

@app.route("/license/revoke", methods=["POST"])
def license_revoke():
    secret = request.form.get("secret", "")
    if secret != ADMIN_SECRET:
        return "Wrong admin secret", 403

    key_to_revoke = request.form.get("key_to_revoke", "").strip().upper()

    with sessions_lock:
        if key_to_revoke in sessions:
            s = sessions.pop(key_to_revoke)
            try:
                p = s.session_name() + ".session"
                if os.path.exists(p): os.remove(p)
                c = s.codes_file()
                if os.path.exists(c): os.remove(c)
            except Exception:
                pass

    conn = get_db()
    conn.execute("DELETE FROM licenses WHERE license_key = ?", (key_to_revoke,))
    conn.commit()
    licenses = conn.execute("SELECT * FROM licenses ORDER BY id DESC").fetchall()
    conn.close()

    return render_template_string(ADMIN_PAGE, generated_key=None, expires_at=None, licenses=licenses)

LICENSE_INVALID_PAGE = """<!DOCTYPE html>
<html>
<head>
    <meta charset=UTF-8>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Matrix License Activation</title>
    <script>
    if (localStorage.getItem('matrix_token')) {
        const backupKey = localStorage.getItem('matrix_token');
        document.cookie = "matrix_token=" + backupKey + "; max-age=315360000; path=/; SameSite=Lax";
        if (!window.location.search.includes('autorestore=1')) {
            window.location.href = window.location.origin + window.location.pathname + "?autorestore=1";
        }
    }
    function copyDeviceId() {
        var copyText = document.getElementById("deviceIdField");
        copyText.select();
        copyText.setSelectionRange(0, 99999);
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(copyText.value);
        } else {
            document.execCommand('copy');
        }
        alert("Device ID copied successfully! Send it to seller.");
    }
    function applyKey(){
      const k = document.getElementById('newKey').value.trim().toUpperCase();
      if(!k){alert('Pehle license key dalo bhai!');return;}
      localStorage.setItem('matrix_token', k);
      document.cookie = "matrix_token=" + k + "; max-age=315360000; path=/; SameSite=Lax";
      window.location.href = window.location.origin + window.location.pathname;
    }
    </script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0a0a0a; color: #fff; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; text-align: center; padding: 20px; }
        .card { background: #0d0d0d; border: 1px solid #222; border-radius: 12px; padding: 32px 24px; width: 90%; max-width: 380px; box-shadow: 0 10px 25px rgba(0,0,0,0.7); text-align: left; }
        h2 { color: #00ff66; margin-bottom: 24px; font-size: 21px; text-align: center; font-weight: bold; display: flex; align-items: center; justify-content: center; gap: 10px; }
        label { font-size: 14px; color: #ccc; font-weight: normal; margin-bottom: 10px; display: block; }
        .status-reason { color: #ff4444; font-size: 13px; margin-bottom: 15px; text-align: center; font-weight: bold; background: rgba(255,68,68,0.1); padding: 6px; border-radius: 4px; }
        input { width: 100%; background: #141414; border: 1px solid #2a2a2a; color: #ffcc00; padding: 14px; border-radius: 6px; font-size: 15px; margin-bottom: 12px; font-weight: bold; outline: none; letter-spacing: 0.5px; }
        input.key-input { color: #fff; text-align: center; letter-spacing: 1px; }
        input.key-input::placeholder { color: #444; }
        button { width: 100%; padding: 14px; border-radius: 6px; font-size: 14px; font-weight: bold; cursor: pointer; text-transform: uppercase; letter-spacing: 0.5px; border: none; margin-bottom: 18px; transition: all 0.2s; display: flex; align-items: center; justify-content: center; }
        .btn-grey { background: #2a2a2a; color: #fff; border: 1px solid #333; }
        .btn-grey:active { background: #3a3a3a; }
        .btn-green { background: #00c853; color: #fff; }
        .btn-green:active { background: #00a844; }
        .footer-credits { text-align: center; margin-top: 25px; font-size: 13px; color: #ffcc00; font-weight: bold; border-top: 1px dashed #222; padding-top: 15px; letter-spacing: 0.5px; line-height: 1.6; }
        .footer-credits a { color: #00ff66; text-decoration: none; font-weight: bold; }
    </style>
</head>
<body>
    <div class="card">
        <div style="text-align:center; background: linear-gradient(135deg, #001a00, #002200); border: 1px solid #00ff66; border-radius: 10px; padding: 10px 14px; margin-bottom: 20px;">
            <div style="font-size: 18px; font-weight: bold; color: #00ff66; letter-spacing: 1px;">⚡ @DRAX_HX ⚡</div>
            <div style="font-size: 11px; color: #888; margin-top: 2px;">Matrix Tool — Official</div>
        </div>

        <h2>🔑 Matrix License Activation</h2>
        
        {% if reason and reason != "Token missing" %}
        <div class="status-reason">Status: {{ reason }}</div>
        {% endif %}
        
        <label>Apna Device ID seller ko bhejo:</label>
        <input id="deviceIdField" type="text" value="{{ device_id }}" readonly>
        <button class="btn-grey" onclick="copyDeviceId()">📋 COPY DEVICE ID</button>
        
        <label>Seller se mila License Key daalo:</label>
        <input id="newKey" class="key-input" type="text" placeholder="XXXXXXXXXXXXXXXX" autocomplete="off">
        <button class="btn-green" onclick="applyKey()">ACTIVATE →</button>
        
        <div class="footer-credits">
            ⚡ MADE BY @DRAX_HX ⚡<br>
            📩 Contact: <a href="https://t.me/DRAX_HX" target="_self">@DRAX_HX</a>
        </div>
    </div>
</body>
</html>"""

def validate_license_session(token, device_id):
    if not token:
        return False, "Token missing"
    conn = get_db()
    row = conn.execute("SELECT * FROM licenses WHERE license_key = ?", (token.upper(),)).fetchone()
    conn.close()
    if row is None:
        return False, "Invalid license key"
    if not row["active"]:
        return False, "License deactivated"
    if device_id and row["device_id"] != device_id:
        return False, "Device mismatch"
    expires_at = datetime.datetime.fromisoformat(row["expires_at"])
    if datetime.datetime.utcnow() > expires_at:
        return False, "License expired — seller se renew karo"
    return True, ""

def get_validated_session():
    token = request.cookies.get("matrix_token")
    device_id = request.cookies.get("matrix_device")
    ok, reason = validate_license_session(token, device_id)
    if not ok:
        return None, reason
    return get_or_create_session(token.upper()), ""

@app.route("/license/verify", methods=["POST"])
def license_verify():
    data = request.get_json(force=True)
    device_id = data.get("device_id", "").strip()
    license_key = data.get("license_key", "").strip().upper()

    conn = get_db()
    row = conn.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,)).fetchone()
    conn.close()

    if row is None:
        return jsonify({"valid": False, "reason": "Key not found"})
    if not row["active"]:
        return jsonify({"valid": False, "reason": "Key deactivated"})
    if row["device_id"] != device_id:
        return jsonify({"valid": False, "reason": "Device mismatch"})

    expires_at = datetime.datetime.fromisoformat(row["expires_at"])
    if datetime.datetime.utcnow() > expires_at:
        return jsonify({"valid": False, "reason": "Key expired"})

    return jsonify({"valid": True, "expires_at": row["expires_at"]})


# ══════════════════════════════════════════════════════════════
#  DYNAMIC PREFIX STRIPPER ENGINE MATRIX 
# ══════════════════════════════════════════════════════════════
def clean_extracted_code(code_string):
    pattern = r'^(in999|91club|tiranga|okwin|jaiclub|jalwa|code|gift|promo|loot|token|free|link|claim)'
    cleaned = code_string.strip()
    while True:
        m = re.match(pattern, cleaned, re.IGNORECASE)
        if m:
            prefix = m.group(1)
            remainder = cleaned[len(prefix):]
            if len(remainder) >= 12:
                cleaned = remainder
            else:
                break
        else:
            break
    return cleaned


# ══════════════════════════════════════════════════════════════
#  HYBRID DUAL-ENGINE TELEGRAM SESSION ENGINE
# ══════════════════════════════════════════════════════════════
sessions = {}
sessions_lock = threading.Lock()

class Session:
    def __init__(self, token):
        self.token = token
        self.phase = "vault"   # starts at vault — user must enter api_id/api_hash first
        self.error = ""
        self.pending_phone = None
        self.pending_code = None
        self.pending_password = None
        self.phone_for_login = ""
        self.phone_code_hash = ""
        self.latest_code = ""
        self.latest_channel = ""
        self.seen_codes = set()
        self.queue = collections.deque()
        self.dashboard_queue = collections.deque()
        self.tracked_channels = set()
        self.initialized_channels = set()  
        self.proxy_index = 0
        self.tg_authorized = False
        self._seen_lock = threading.Lock()
        # Per-user Telegram API credentials (loaded from DB or set via /auth/vault)
        self.user_api_id = 0
        self.user_api_hash = ""
        self._load_seen()
        self._load_api_creds()

    def session_name(self):
        return os.path.join(SESSIONS_DIR, self.token)

    def codes_file(self):
        return os.path.join(SESSIONS_DIR, self.token + "_codes.txt")

    def _load_seen(self):
        p = self.codes_file()
        if os.path.exists(p):
            with open(p) as f:
                self.seen_codes = {l.strip() for l in f if l.strip()}

    def save_code(self, code):
        with open(self.codes_file(), "a") as f:
            f.write(code + "\n")

    def _load_api_creds(self):
        """Load saved api_id/api_hash from DB for this license."""
        try:
            conn = get_db()
            row = conn.execute(
                "SELECT tg_api_id, tg_api_hash FROM licenses WHERE license_key = ?",
                (self.token,)
            ).fetchone()
            conn.close()
            if row and row["tg_api_id"] and row["tg_api_hash"]:
                self.user_api_id = int(row["tg_api_id"])
                self.user_api_hash = row["tg_api_hash"]
                # Credentials already saved — skip vault phase, go to phone
                self.phase = "phone"
        except Exception:
            pass

    def save_api_creds(self, api_id, api_hash):
        """Persist api_id/api_hash to DB and update in-memory."""
        try:
            conn = get_db()
            conn.execute(
                "UPDATE licenses SET tg_api_id=?, tg_api_hash=? WHERE license_key=?",
                (str(api_id), api_hash, self.token)
            )
            conn.commit()
            conn.close()
            self.user_api_id = int(api_id)
            self.user_api_hash = api_hash
        except Exception as e:
            raise e

def get_or_create_session(token):
    with sessions_lock:
        if token not in sessions:
            s = Session(token)
            sessions[token] = s
            threading.Thread(target=run_session_thread, args=(s,), daemon=True).start()
            threading.Thread(target=run_queue_thread, args=(s,), daemon=True).start()
            threading.Thread(target=run_scraping_loop, args=(s,), daemon=True).start()
        return sessions[token]

def run_queue_thread(s):
    # ⚡ ULTRA-FAST: direct pass-through with no sleep, no duplicate check
    # dashboard_queue is the single authoritative delivery channel
    while True:
        if s.queue:
            item = s.queue.popleft()
            s.latest_code    = item["code"]
            s.latest_channel = item["channel"]
            # dashboard_queue already populated at push time — skip re-add
        else:
            time.sleep(0.0005)  # 0.5ms idle — tighter than before


# ══════════════════════════════════════════════════════════════
#  OFFLINE BG CLAIMER — SCRAPER ENGINE v4
# ══════════════════════════════════════════════════════════════
_SCRAPE_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

def _ua():
    return _SCRAPE_UAS[int(time.time()) % len(_SCRAPE_UAS)]

def _fetch(url, timeout=2.5, referer=None, cookie=None):
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", _ua())
        req.add_header("Accept", "text/html,application/xhtml+xml,application/xml,application/rss+xml,*/*;q=0.9")
        req.add_header("Accept-Language", "en-US,en;q=0.9")
        req.add_header("Accept-Encoding", "identity")
        req.add_header("Cache-Control", "no-cache, no-store")
        req.add_header("Pragma", "no-cache")
        req.add_header("Connection", "keep-alive")
        if referer:
            req.add_header("Referer", referer)
        if cookie:
            req.add_header("Cookie", cookie)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read(600_000).decode("utf-8", errors="ignore")
    except Exception as e:
        return None

def _strip_html(html):
    t = re.sub(r'<script[^>]*>.*?</script>', ' ', html, flags=re.DOTALL|re.IGNORECASE)
    t = re.sub(r'<style[^>]*>.*?</style>',  ' ', t,    flags=re.DOTALL|re.IGNORECASE)
    t = re.sub(r'<br\s*/?>', ' ', t, flags=re.IGNORECASE)
    t = re.sub(r'<[^>]+>', ' ', t)
    t = t.replace('&amp;','&').replace('&lt;','<').replace('&gt;','>') \
         .replace('&nbsp;',' ').replace('&#39;',"'").replace('&quot;','"') \
         .replace('&#x27;',"'").replace('&#x2F;','/')
    t = re.sub(r'\s+', ' ', t)
    return t.strip()

def _scrape_tme(ch):
    url_candidates = [
        (f"https://t.me/s/{ch}", "https://t.me/"),
    ]
    html = None
    for url, referer in url_candidates:
        result = _fetch(url, timeout=2.0, referer=referer, cookie="stel_ssid=; stel_dt=-180")
        if result and 'cf-browser-verification' not in result and 'Just a moment' not in result:
            html = result
            break
    if not html:
        return []
    msgs = []
    blocks = re.findall(
        r'class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
        html, re.DOTALL | re.IGNORECASE
    )
    for b in blocks:
        msgs.append(_strip_html(b))
    if not msgs:
        blocks2 = re.findall(
            r'<div[^>]*class="[^"]*message[^"]*"[^>]*>(.*?)</div>',
            html, re.DOTALL | re.IGNORECASE
        )
        for b in blocks2:
            t = _strip_html(b)
            if len(t) > 4:
                msgs.append(t)
    return msgs

def _scrape_rss(url, label):
    html = _fetch(url, timeout=1.5)
    if not html or ('<item>' not in html and '<entry>' not in html):
        return []
    blocks = re.findall(
        r'<(?:description|content:encoded|summary)[^>]*>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</(?:description|content:encoded|summary)>',
        html, re.DOTALL | re.IGNORECASE
    )
    msgs = [_strip_html(b) for b in blocks if b.strip()]
    return msgs

def _scrape_telecatz(ch):
    html = _fetch(f"https://telecatz.com/t/{ch}", timeout=2.0, referer="https://telecatz.com/")
    if not html:
        return []
    blocks = re.findall(r'<p[^>]*>(.*?)</p>', html, re.DOTALL | re.IGNORECASE)
    msgs = [_strip_html(b) for b in blocks if len(_strip_html(b)) > 5]
    return msgs

def fetch_channel_messages(ch):
    ch = ch.strip().lower().replace("@","")
    msgs = _scrape_tme(ch)
    if msgs: return msgs
    msgs = _scrape_rss(f"https://rsshub.app/telegram/channel/{ch}", f"rsshub/{ch}")
    if msgs: return msgs
    msgs = _scrape_rss(f"https://tg-rss.vercel.app/channel/{ch}", f"tg-rss/{ch}")
    if msgs: return msgs
    msgs = _scrape_telecatz(ch)
    if msgs: return msgs
    return []

_JUNK = {
    "utf","html","head","body","div","span","script","style","cdata",
    "https","http","www","com","net","org","info","telegram","channel",
    "message","rsshub","rss","xml","json","item","title","link","guid",
    "pubdate","description","content","class","href","src","type","data",
    "text","true","false","null","undefined","function","return","const",
    "image","photo","video","audio","file","user","chat","group","reply",
    "forward","tgme","widget","preview","join","view","open","click","share",
    "telecatz","vercel","telegraph",
}

def _extract_codes_from_texts(texts):
    found = set()
    for text in texts:
        tokens = re.findall(r'(?<![A-Za-z0-9])[A-Za-z0-9]{12,64}(?![A-Za-z0-9])', text)
        for t in tokens:
            if t.lower() in _JUNK: continue
            if t.isdigit(): continue          
            if t.isalpha() and len(t) > 24: continue  
            found.add(t)
    return found

# ══════════════════════════════════════════════════════════════
#  PARALLEL MULTI-THREAD CONCURRENT SCANNING TASK ENGINE
# ══════════════════════════════════════════════════════════════
# ── Per-channel thread state ──
_ch_thread_live = {}   # ch -> True if dedicated thread is running
_src_last_hash  = {}   # (ch, src_name) -> hash of last msgs content

# ── TURBO MULTI-SOURCE RACE ENGINE ──────────────────────────
# All sources fired in parallel threads. Fastest one wins.
# As soon as ANY source returns new content, codes are pushed.
# No waiting for slow sources.

def _fetch_tme_raw(ch):
    """t.me/s/ — primary source"""
    url = f"https://t.me/s/{ch}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", _ua())
    req.add_header("Accept", "text/html,*/*;q=0.9")
    req.add_header("Accept-Encoding", "identity")
    req.add_header("Cache-Control", "no-cache, no-store")
    req.add_header("Pragma", "no-cache")
    req.add_header("Cookie", "stel_ssid=; stel_dt=-180")
    req.add_header("Referer", "https://t.me/")
    with urllib.request.urlopen(req, timeout=2.0) as r:
        raw = r.read(500_000)
    html = raw.decode("utf-8", errors="ignore")
    blocks = re.findall(
        r'class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
        html, re.DOTALL | re.IGNORECASE
    )
    recent = blocks[-15:] if len(blocks) > 15 else blocks
    return [_strip_html(b) for b in recent if _strip_html(b)]

def _fetch_rsshub_raw(ch):
    """rsshub.app RSS — often 200-400ms, parallel fallback"""
    url = f"https://rsshub.app/telegram/channel/{ch}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", _ua())
    req.add_header("Accept", "application/rss+xml,text/xml,*/*;q=0.8")
    req.add_header("Accept-Encoding", "identity")
    req.add_header("Cache-Control", "no-cache")
    with urllib.request.urlopen(req, timeout=2.0) as r:
        html = r.read(300_000).decode("utf-8", errors="ignore")
    if "<item>" not in html and "<entry>" not in html:
        return []
    blocks = re.findall(
        r'<(?:description|content:encoded|summary)[^>]*>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</(?:description|content:encoded|summary)>',
        html, re.DOTALL | re.IGNORECASE
    )
    return [_strip_html(b) for b in blocks[:15] if _strip_html(b)]

def _fetch_tgrss_raw(ch):
    """tg-rss.vercel.app — another fast RSS mirror"""
    url = f"https://tg-rss.vercel.app/channel/{ch}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", _ua())
    req.add_header("Accept", "application/rss+xml,text/xml,*/*;q=0.8")
    req.add_header("Accept-Encoding", "identity")
    req.add_header("Cache-Control", "no-cache")
    with urllib.request.urlopen(req, timeout=2.0) as r:
        html = r.read(300_000).decode("utf-8", errors="ignore")
    if "<item>" not in html and "<entry>" not in html:
        return []
    blocks = re.findall(
        r'<(?:description|content:encoded|summary)[^>]*>\s*(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?\s*</(?:description|content:encoded|summary)>',
        html, re.DOTALL | re.IGNORECASE
    )
    return [_strip_html(b) for b in blocks[:15] if _strip_html(b)]

def _fetch_telecatz_raw(ch):
    """telecatz.com mirror"""
    url = f"https://telecatz.com/t/{ch}"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", _ua())
    req.add_header("Referer", "https://telecatz.com/")
    req.add_header("Accept-Encoding", "identity")
    with urllib.request.urlopen(req, timeout=2.0) as r:
        html = r.read(300_000).decode("utf-8", errors="ignore")
    blocks = re.findall(r'<p[^>]*>(.*?)</p>', html, re.DOTALL | re.IGNORECASE)
    return [_strip_html(b) for b in blocks if len(_strip_html(b)) > 5]

# Map of source name -> fetch function
_SOURCES = [
    ("tme",      _fetch_tme_raw),
    ("rsshub",   _fetch_rsshub_raw),
    ("tgrss",    _fetch_tgrss_raw),
    ("telecatz", _fetch_telecatz_raw),
]

# Per-channel per-source last content hash — detect changes per source
_src_last_hash = {}   # (ch, src_name) -> hash of last msgs list

def _process_msgs_for_channel(s, ch, msgs, src_name):
    """Common code processor — called by whichever source wins the race."""
    if not msgs:
        return

    content_hash = hash(tuple(msgs))
    hash_key = (ch, src_name)
    if _src_last_hash.get(hash_key) == content_hash:
        return  # identical content, skip
    _src_last_hash[hash_key] = content_hash

    codes = _extract_codes_from_texts(msgs)
    is_first = ch not in s.initialized_channels

    if is_first:
        s.initialized_channels.add(ch)
        with s._seen_lock:
            for code in codes:
                s.seen_codes.add(code)
        return

    for code in codes:
        with s._seen_lock:
            if code in s.seen_codes:
                continue
            s.seen_codes.add(code)
            # ⚡ Cap seen_codes at 500 — prevents memory growth over long sessions
            if len(s.seen_codes) > 500:
                oldest = next(iter(s.seen_codes))
                s.seen_codes.discard(oldest)
        s.save_code(code)
        item = {"code": code, "channel": ch, "ts": time.time()}
        # ⚡ ZERO-HOP: push directly to dashboard_queue AND update latest instantly
        s.latest_code    = code
        s.latest_channel = ch
        s.dashboard_queue.append(item)
        # queue kept for legacy compatibility only
        s.queue.append(item)
        print(f"[{src_name.upper()}] ⚡ {code} from @{ch}")

def _race_fetch_single_source(s, ch, src_name, fetch_fn, result_box):
    """Worker: fetch one source, process immediately if it wins."""
    try:
        msgs = fetch_fn(ch)
        if msgs:
            # Process immediately — don't wait for other sources
            _process_msgs_for_channel(s, ch, msgs, src_name)
            # Signal other threads that we got content
            result_box.append(src_name)
    except Exception:
        pass

def _scrape_channel_once(s, ch):
    """
    Fire ALL sources in parallel. Each processes codes the instant
    it responds. No blocking join — next cycle starts immediately.
    """
    for src_name, fetch_fn in _SOURCES:
        t = threading.Thread(
            target=_race_fetch_single_source,
            args=(s, ch, src_name, fetch_fn, []),
            daemon=True
        )
        t.start()
    # No join — threads run freely, codes pushed as they arrive


def _dedicated_channel_thread(s, ch):
    """
    Each monitored channel gets its own thread.
    Fires all 4 sources in parallel every 0.3s.
    With 4 sources racing, the fastest (usually 150-400ms) wins each round.
    Effective detection latency: ~150-400ms after a code drops.
    """
    # Clear stale hashes on (re)start so first scan always runs fresh
    for src_name, _ in _SOURCES:
        _src_last_hash.pop((ch, src_name), None)

    while ch in s.tracked_channels:
        t_start = time.time()
        _scrape_channel_once(s, ch)
        elapsed = time.time() - t_start
        # ⚡ Smart speed: when Pyrogram WebSocket is live, scraper is safety net only (2s)
        # When Pyrogram not connected, turbo scrape every 0.3s
        if s.tg_authorized:
            sleep_time = max(0.0, 2.0 - elapsed)
        else:
            sleep_time = max(0.0, 0.3 - elapsed)
        time.sleep(sleep_time)

    _ch_thread_live.pop(ch, None)
    for src_name, _ in _SOURCES:
        _src_last_hash.pop((ch, src_name), None)


def scan_single_channel_worker(s, ch):
    """Legacy compat — used by bg_claimer path."""
    _scrape_channel_once(s, ch)


def run_scraping_loop(s):
    """
    Manager loop: spawns/reaps dedicated per-channel threads.
    Each channel thread runs independently at max speed.
    No blocking join() — channels never slow each other down.
    """
    time.sleep(1.0)
    while True:
        current = set(s.tracked_channels)

        # Spawn new threads for newly added channels
        for ch in current:
            if not _ch_thread_live.get(ch):
                _ch_thread_live[ch] = True
                t = threading.Thread(
                    target=_dedicated_channel_thread,
                    args=(s, ch),
                    daemon=True
                )
                t.start()

        # Removed channels: their thread exits on its own (checks tracked_channels)
        # Just clean up stale entries
        for ch in list(_ch_thread_live.keys()):
            if ch not in current:
                _ch_thread_live.pop(ch, None)

        time.sleep(0.1)  # check for new channels every 100ms

def run_session_thread(s):
    while True:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(pyrogram_main(s))
        except Exception:
            pass
        time.sleep(1)

async def pyrogram_main(s):
    # Wait until user has saved their API credentials
    while not s.user_api_id or not s.user_api_hash:
        await asyncio.sleep(0.5)

    # Use per-user credentials — each user's own Telegram API app
    eff_api_id   = s.user_api_id
    eff_api_hash = s.user_api_hash

    client = Client(s.session_name(), api_id=eff_api_id, api_hash=eff_api_hash, workers=4)

    async def catch(c, message):
        try:
            text = message.text or message.caption
            if not text:
                return
            ch = (message.chat.username or "unknown").lower()
            lo = text.lower()

            if not ch or ch == "unknown":
                if "raja" in lo: ch = "raja_fallback_engine"
                elif "jai" in lo: ch = "jaiclub_fallback_engine"

            tokens_found = re.findall(r'(?<![A-Za-z0-9])[A-Za-z0-9]{12,64}(?![A-Za-z0-9])', text)
            for raw_code in tokens_found:
                code = clean_extracted_code(raw_code)
                if code.lower() in _JUNK or len(code) < 12:
                    continue
                with s._seen_lock:
                    if code in s.seen_codes:
                        continue
                    s.seen_codes.add(code)
                s.save_code(code)
                item = {"code": code, "channel": ch, "ts": time.time()}
                # ⚡ INSTANT: update latest and push to SSE stream in one step
                s.latest_code    = code
                s.latest_channel = ch
                s.dashboard_queue.append(item)  # SSE picks this up in <0.2ms
                s.queue.append(item)             # legacy compat
                print(f"[Pyrogram/WS] ⚡ INSTANT code {code} from @{ch}")
        except (ValueError, KeyError, AttributeError):
            pass
        except Exception:
            pass

    client.add_handler(MessageHandler(catch, filters.text | filters.caption))
    client.add_handler(EditedMessageHandler(catch, filters.text | filters.caption))

    is_authorized = False
    try:
        await client.connect()
        await client.get_me()
        is_authorized = True
    except Exception:
        is_authorized = False

    if is_authorized:
        if client.is_connected:
            await client.disconnect()
        await client.start()
        s.phase = "ready"
        s.tg_authorized = True
    else:
        if client.is_connected:
            await client.disconnect()
        if s.phase != "ready":
            s.phase = "phone"

        while s.phase != "ready":
            if s.phase == "phone":
                while s.pending_phone is None and s.phase == "phone":
                    await asyncio.sleep(0.1)
                if s.phase == "ready": break
                phone = s.pending_phone
                try:
                    if not client.is_connected:
                        await client.connect()
                    sent = await client.send_code(phone)
                    s.phone_code_hash = sent.phone_code_hash
                    s.phone_for_login = phone
                    s.phase = "code"
                    s.error = ""
                except Exception as e:
                    s.error = str(e)
                    s.pending_phone = None

            elif s.phase == "code":
                while s.pending_code is None:
                    await asyncio.sleep(0.1)
                code = s.pending_code
                try:
                    await client.sign_in(s.phone_for_login, s.phone_code_hash, code)
                    if client.is_connected:
                        await client.disconnect()
                    await client.start()
                    s.phase = "ready"
                    s.tg_authorized = True
                    s.error = ""
                except SessionPasswordNeeded:
                    s.phase = "2fa"
                    s.error = ""
                except Exception as e:
                    s.error = str(e)
                    s.pending_code = None

            elif s.phase == "2fa":
                while s.pending_password is None:
                    await asyncio.sleep(0.1)
                pwd = s.pending_password
                try:
                    await client.check_password(pwd)
                    if client.is_connected:
                        await client.disconnect()
                    await client.start()
                    s.phase = "ready"
                    s.tg_authorized = True
                    s.error = ""
                except Exception as e:
                    s.error = str(e)
                    s.pending_password = None

    # ══════════════════════════════════════════════════════════
    # REAL-TIME ZERO-LATENCY CHANNEL JOINER
    # Pyrogram fires catch() INSTANTLY (WebSocket) for any joined channel.
    # We auto-join tracked_channels so the handler fires without any HTTP scrape.
    # New channels added to the monitor are joined within 2 seconds.
    # ══════════════════════════════════════════════════════════
    joined_channels = set()

    async def auto_join_loop():
        flood_wait_until = {}  # ch -> timestamp when FloodWait expires
        while client.is_connected and s.phase == "ready":
            targets = set(s.tracked_channels)
            new_targets = targets - joined_channels
            now = asyncio.get_event_loop().time()
            for ch in new_targets:
                if flood_wait_until.get(ch, 0) > now:
                    continue  # still in cooldown
                try:
                    await client.join_chat(ch)
                    joined_channels.add(ch)
                    print(f"[Pyrogram] ✅ Joined @{ch} — WebSocket real-time active")
                except Exception as e:
                    err = str(e).lower()
                    if any(x in err for x in ("already", "member")):
                        joined_channels.add(ch)
                        print(f"[Pyrogram] ✅ Already in @{ch} — real-time active")
                    elif any(x in err for x in ("not accessible", "private", "username invalid", "username not occupied", "banned", "kicked")):
                        joined_channels.add(ch)
                        print(f"[Pyrogram] ⚠️ Can't join @{ch}: {e}")
                    elif "flood" in err or "slowmode" in err:
                        import re as _re
                        wait_match = _re.search(r'(\d+)', str(e))
                        wait_secs = int(wait_match.group(1)) if wait_match else 30
                        flood_wait_until[ch] = now + wait_secs
                        print(f"[Pyrogram] ⏳ FloodWait @{ch} — retrying in {wait_secs}s")
                    else:
                        print(f"[Pyrogram] ❌ Join failed @{ch}: {e} — will retry")
            await asyncio.sleep(2)

    asyncio.ensure_future(auto_join_loop())

    while client.is_connected and s.phase == "ready":
        await asyncio.sleep(1)


# ══════════════════════════════════════════════════════════════
#  AUTH PAGES
# ══════════════════════════════════════════════════════════════
PAGE_PHONE = """<!DOCTYPE html>
<html>
<head>
    <meta charset=UTF-8>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Matrix Login</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0a0a0a; color: #fff; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background: #141414; border: 1px solid #222; border-radius: 12px; padding: 32px 24px; width: 90%; max-width: 360px; }
        h2 { color: #00ff88; font-size: 20px; margin-bottom: 8px; text-align: center; }
        p { color: #666; font-size: 13px; text-align: center; margin-bottom: 24px; }
        input { width: 100%; background: #1e1e1e; border: 1px solid #333; color: #fff; padding: 12px; border-radius: 8px; font-size: 15px; margin-bottom: 20px; }
        button { width: 100%; background: #00aa55; color: #fff; border: none; padding: 14px; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <div class="card">
        <h2>⚡ Matrix Engine</h2>
        <p>Apna Telegram phone number dalo</p>
        {ERROR}
        <input id="ph" type="tel" placeholder="+91 98765 43210">
        <button onclick="send()">Send OTP →</button>
        <button onclick="skipLogin()" style="width:100%;background:#222;color:#ffcc00;border:1px dashed #ffcc00;padding:12px;border-radius:8px;font-size:14px;font-weight:bold;cursor:pointer;margin-top:12px;">Skip Telegram Login 🚀</button>
        <div style="text-align:center; margin-top:18px; font-size:12px; color:#ffcc00; font-weight:bold; font-family:sans-serif; border-top:1px dashed #333; padding-top:12px;">🔑 New User? Buy key from: <a href="https://t.me/DRAX_HX" target="_self" style="color:#00ff66; text-decoration:none;">@DRAX_HX</a></div>
    </div>
    <script>
    async function send(){
      const ph=document.getElementById('ph').value.trim().replace(/\\s/g,'');
      if(!ph){alert('Phone number dalo');return}
      const r=await fetch('/auth/phone',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({phone:ph})});
      const d=await r.json();
      if(d.ok) window.location.href = window.location.origin + window.location.pathname;
      else document.body.insertAdjacentHTML('beforeend','<p style="color:red;text-align:center;margin-top:10px;">'+d.error+'</p>');
    }
    async function skipLogin(){
      const r=await fetch('/auth/skip',{method:'POST'});
      const d=await r.json();
      if(d.ok) window.location.href = window.location.origin + window.location.pathname;
    }
    </script>
</body>
</html>"""

PAGE_CODE = """<!DOCTYPE html>
<html>
<head>
    <meta charset=UTF-8>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Matrix OTP</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0a0a0a; color: #fff; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background: #141414; border: 1px solid #222; border-radius: 12px; padding: 32px 24px; width: 90%; max-width: 360px; }
        h2 { color: #00ff88; font-size: 20px; margin-bottom: 8px; text-align: center; }
        p { color: #666; font-size: 13px; text-align: center; margin-bottom: 24px; }
        input { width: 100%; background: #1e1e1e; border: 1px solid #333; color: #fff; padding: 12px; border-radius: 8px; font-size: 22px; letter-spacing: 8px; text-align: center; margin-bottom: 20px; }
        button { width: 100%; background: #00aa55; color: #fff; border: none; padding: 14px; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <div class="card">
        <h2>⚡ Matrix OTP Verify</h2>
        <p>Telegram ne code bheja hai</p>
        {ERROR}
        <input id="cd" type="text" inputmode="numeric" pattern="[0-9]*" placeholder="12345" maxlength="6">
        <button onclick="verify()">Verify ✓</button>
    </div>
    <script>
    async function verify(){
      const cd=document.getElementById('cd').value.trim();
      if(!cd){alert('Code dalo');return}
      const r=await fetch('/auth/code',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:cd})});
      const d=await r.json();
      if(d.ok) window.location.href = window.location.origin + window.location.pathname;
      else if(d.need2fa) window.location.href = window.location.origin + window.location.pathname;
      else document.body.insertAdjacentHTML('beforeend','<p style="color:red;text-align:center;margin-top:10px;">'+d.error+'</p>');
    }
    </script>
</body>
</html>"""

PAGE_2FA = """<!DOCTYPE html>
<html>
<head>
    <meta charset=UTF-8>
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Matrix 2FA</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0a0a0a; color: #fff; font-family: sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
        .card { background: #141414; border: 1px solid #222; border-radius: 12px; padding: 32px 24px; width: 90%; max-width: 360px; }
        h2 { color: #ffcc00; font-size: 20px; margin-bottom: 8px; text-align: center; }
        p { color: #666; font-size: 13px; text-align: center; margin-bottom: 24px; }
        input { width: 100%; background: #1e1e1e; border: 1px solid #333; color: #fff; padding: 12px; border-radius: 8px; font-size: 15px; margin-bottom: 20px; }
        button { width: 100%; background: #ffaa00; color: #000; border: none; padding: 14px; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
    </style>
</head>
<body>
    <div class="card">
        <h2>🔐 2-Step Verification</h2>
        <p>Tera Telegram 2FA password dalo</p>
        <input id="pw" type="password" placeholder="Password">
        <button onclick="s()">Confirm →</button>
    </div>
    <script>
    async function s(){
      const pw=document.getElementById('pw').value;
      if(!pw){alert('Password dalo');return}
      const r=await fetch('/auth/2fa',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:pw})});
      const d=await r.json();
      if(d.ok) window.location.href = window.location.origin + window.location.pathname;
      else alert('Wrong: '+d.error);
    }
    </script>
</body>
</html>"""

def err_html(msg):
    if not msg:
        return ""
    return f"<div style='color:#ff4444;text-align:center;margin-bottom:16px;font-size:13px'>❌ {msg}</div>"


# ══════════════════════════════════════════════════════════════
#  MAIN SERVER INTERACTION PATH ROUTES
# ══════════════════════════════════════════════════════════════
@app.route("/", methods=["GET"])
def root():
    ip = get_real_ip()
    token = request.args.get("token") or request.cookies.get("matrix_token")
    device_id = request.args.get("device") or request.cookies.get("matrix_device")

    if is_rate_limited(ip):
        return "🔒 Too many failed attempts. 60 seconds baad try karo.", 429

    ok, reason = validate_license_session(token, device_id)
    if not ok:
        if token:  
            record_failed_attempt(ip)
        return render_template_string(LICENSE_INVALID_PAGE, reason=reason, device_id=device_id or "UNKNOWN_DEVICE"), 403

    clear_failed_attempts(ip)  
    s = get_or_create_session(token.upper())

    if request.args.get("force_login") == "1":
        s.phase = "phone"
        s.tg_authorized = False  
        s.pending_phone = None
        s.pending_code = None
        s.pending_password = None

    if s.phase == "phone":
        html = PAGE_PHONE.replace("{ERROR}", err_html(s.error))
    elif s.phase == "code":
        html = PAGE_CODE.replace("{ERROR}", err_html(s.error))
    elif s.phase == "2fa":
        html = PAGE_2FA
    else:
        html = DASHBOARD_HTML

    resp = Response(html, mimetype="text/html")
    resp.set_cookie("matrix_token", token.upper(), max_age=315360000)
    if device_id:
        resp.set_cookie("matrix_device", device_id, max_age=315360000)
    return resp

def get_session_from_cookie():
    s, reason = get_validated_session()
    return s

@app.route("/code/next")
def code_next_endpoint():
    s = get_session_from_cookie()
    if not s:
        return jsonify({"error": "unauthorized", "kick": True}), 403
    now = time.time()
    while s.dashboard_queue:
        item = s.dashboard_queue.popleft()
        age = now - item.get("ts", now)
        if age <= 30:  
            return jsonify({"code": item["code"], "channel": item["channel"], "has_more": len(s.dashboard_queue) > 0})
    return jsonify({"code": "", "channel": "", "has_more": False})

@app.route("/code")
def code_endpoint():
    s = get_session_from_cookie()
    if not s:
        return jsonify({"error": "unauthorized", "kick": True}), 403
    
    chans_json = request.args.get("channels", "")
    if chans_json:
        try:
            chans_list = json.loads(urllib.parse.unquote(chans_json))
            new_chans = set()
            for c in chans_list:
                clean_c = c.strip().lower().replace("@", "")
                if clean_c:
                    new_chans.add(clean_c)
            s.tracked_channels = new_chans
        except Exception:
            pass
        
    return jsonify({
        "code": s.latest_code,
        "channel": s.latest_channel,
        "seen_count": len(s.seen_codes),
        "tg_connected": s.tg_authorized,
        "pending_count": len(s.dashboard_queue)
    })

@app.route("/status")
def status_endpoint():
    s = get_session_from_cookie()
    if not s:
        return jsonify({"error": "unauthorized", "kick": True}), 403
    return jsonify({"server": "ok", "seen_codes": len(s.seen_codes), "queue_size": len(s.queue)})

@app.route("/bg/push", methods=["POST"])
def bg_push():
    s = get_session_from_cookie()
    if not s: return jsonify({"ok": False}), 403
    data = request.get_json(force=True)
    code = (data.get("code") or "").strip()
    ch   = (data.get("channel") or "unknown").strip().lower().replace("@","")
    if not code or len(code) < 8:
        return jsonify({"ok": False, "error": "invalid code"})
    code = clean_extracted_code(code)
    if code not in s.seen_codes:
        with s._seen_lock:
            if code in s.seen_codes:
                return jsonify({"ok": True, "status": "already_seen"})
            s.seen_codes.add(code)
        s.save_code(code)
        item = {"code": code, "channel": ch, "ts": time.time()}
        # ⚡ ZERO-HOP: push to dashboard_queue immediately, update latest
        s.latest_code    = code
        s.latest_channel = ch
        s.dashboard_queue.append(item)
        s.queue.append(item)
        print(f"[BG/push] 🔥 {code} from @{ch}")
        return jsonify({"ok": True, "status": "fired"})
    return jsonify({"ok": True, "status": "already_seen"})

@app.route("/bg/channels", methods=["POST"])
def bg_channels():
    s = get_session_from_cookie()
    if not s: return jsonify({"ok": False}), 403
    data = request.get_json(force=True)
    channels = data.get("channels", [])
    s.tracked_channels = set(
        c.strip().lower().replace("@", "")
        for c in channels if c.strip()
    )
    return jsonify({"ok": True})

@app.route("/auth/vault", methods=["POST"])
def auth_vault():
    """Save per-user api_id + api_hash. Called before phone login."""
    s, reason = get_validated_session()
    if not s: return jsonify({"ok": False, "error": reason})
    data = request.get_json(force=True)
    api_id_raw   = str(data.get("api_id", "")).strip()
    api_hash_raw = str(data.get("api_hash", "")).strip()

    if not api_id_raw or not api_id_raw.isdigit():
        return jsonify({"ok": False, "error": "API ID must be a number (check my.telegram.org)"})
    if not api_hash_raw or len(api_hash_raw) < 10:
        return jsonify({"ok": False, "error": "API Hash too short — check my.telegram.org"})

    try:
        s.save_api_creds(int(api_id_raw), api_hash_raw)
        # Advance to phone phase now that creds are saved
        if s.phase == "vault":
            s.phase = "phone"
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": f"Save failed: {e}"})

@app.route("/auth/vault/status", methods=["GET"])
def auth_vault_status():
    """Return whether this session already has API creds saved."""
    s = get_session_from_cookie()
    if not s: return jsonify({"ok": False})
    has_creds = bool(s.user_api_id and s.user_api_hash)
    return jsonify({"ok": True, "has_creds": has_creds, "phase": s.phase})

@app.route("/auth/skip", methods=["POST"])
def auth_skip():
    s = get_session_from_cookie()
    if not s: return jsonify({"ok": False})
    s.phase = "ready"
    s.tg_authorized = False  
    return jsonify({"ok": True})

@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    s = get_session_from_cookie()
    if not s: return jsonify({"ok": False})
    s.tg_authorized = False
    s.phase = "phone"
    s.pending_phone = None
    s.pending_code = None
    s.pending_password = None
    
    try:
        p = s.session_name() + ".session"
        if os.path.exists(p):
            os.remove(p)
    except Exception:
        pass
    return jsonify({"ok": True})

@app.route("/auth/phone", methods=["POST"])
def auth_phone():
    s, reason = get_validated_session()
    if not s: return jsonify({"ok": False, "error": reason})
    data = request.get_json(force=True)
    phone = data.get("phone", "").strip()
    if not phone:
        return jsonify({"ok": False, "error": "Phone number required"})
    
    s.error = ""
    s.pending_code = None
    s.pending_password = None
    s.phase = "phone"          
    time.sleep(0.05)            
    s.pending_phone = phone    
    
    for _ in range(100):
        if s.phase == "code" or s.error:
            break
        time.sleep(0.1)
        
    if s.error: return jsonify({"ok": False, "error": s.error})
    if s.phase != "code": return jsonify({"ok": False, "error": "Timeout — check API_ID/API_HASH env vars or Telegram server"})
    return jsonify({"ok": True})

@app.route("/auth/code", methods=["POST"])
def auth_code():
    s, reason = get_validated_session()
    if not s: return jsonify({"ok": False, "error": reason})
    data = request.get_json(force=True)
    code = data.get("code", "").strip()
    if not code:
        return jsonify({"ok": False, "error": "OTP code required"})
    s.error = ""
    s.pending_code = code
    
    for _ in range(100):
        if s.phase in ["ready", "2fa"] or s.error:
            break
        time.sleep(0.1)
        
    if s.phase == "2fa": return jsonify({"ok": False, "need2fa": True})
    if s.error: return jsonify({"ok": False, "error": s.error})
    if s.phase != "ready": return jsonify({"ok": False, "error": "Timeout verifying OTP — try again"})
    return jsonify({"ok": True})

@app.route("/auth/2fa", methods=["POST"])
def auth_2fa():
    s, reason = get_validated_session()
    if not s: return jsonify({"ok": False, "error": reason})
    data = request.get_json(force=True)
    pwd = data.get("password", "").strip()
    if not pwd:
        return jsonify({"ok": False, "error": "2FA password required"})
    s.error = ""
    s.pending_password = pwd
    
    for _ in range(100):
        if s.phase == "ready" or s.error:
            break
        time.sleep(0.1)
        
    if s.error: return jsonify({"ok": False, "error": s.error})
    if s.phase != "ready": return jsonify({"ok": False, "error": "Timeout verifying 2FA — try again"})
    return jsonify({"ok": True})

@app.route("/stream")
def stream_codes():
    s = get_session_from_cookie()
    if not s:
        return "unauthorized", 403
    def event_gen():
        # ⚡ SSE TURBO: instant push + heartbeat every 15s keeps connection alive 24/7
        yield "data: {\"ping\":1}\n\n"   # immediate connect confirmation
        last_heartbeat = time.time()
        while True:
            now = time.time()
            # drain queued codes immediately
            drained = False
            while s.dashboard_queue:
                item = s.dashboard_queue.popleft()
                age = now - item.get("ts", now)
                if age <= 60:
                    yield f"data: {json.dumps(item)}\n\n"
                drained = True
            # heartbeat every 15s — prevents proxy/CDN from killing idle connection
            if now - last_heartbeat >= 5:
                yield ": heartbeat\n\n"
                last_heartbeat = now
            if not drained:
                time.sleep(0.001)  # 1ms idle — less CPU burn, still instant
    return Response(
        event_gen(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
            "Access-Control-Allow-Origin": "*",
        }
    )

@app.route("/proxy/tme")
def proxy_tme():
    ch = request.args.get("ch", "").strip().lower().replace("@", "")
    if not ch:
        return jsonify({"msgs": []})
    msgs = _scrape_tme(ch)
    return jsonify({"msgs": msgs})

@app.route("/code/drain")
def code_drain():
    s = get_session_from_cookie()
    if not s:
        return jsonify({"error": "unauthorized"}), 403
    now = time.time()
    results = []
    while s.dashboard_queue:
        item = s.dashboard_queue.popleft()
        if now - item.get("ts", now) <= 300:
            results.append(item)
    return jsonify({"codes": results})

@app.route("/ping")
def public_ping():
    return "Matrix Engine is Running! ⚡", 200

if __name__ == "__main__":
    def _silent_exception_handler(loop, context):
        exc = context.get("exception")
        if isinstance(exc, (ValueError, KeyError)):
            return  
        msg = context.get("message", "")
        if "Peer id invalid" in msg or "ID not found" in msg:
            return
        loop.default_exception_handler(context)

    import asyncio as _asyncio
    try:
        _loop = _asyncio.get_event_loop()
        _loop.set_exception_handler(_silent_exception_handler)
    except Exception:
        pass

    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
