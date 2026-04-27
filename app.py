from flask import Flask, request, jsonify
from datetime import datetime, timezone, timedelta
from hashlib import sha256
import os
import hmac
import sqlite3
import time
from functools import wraps
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# =========================jhtfuh
# CONFIG
# =========================

DB_FILE = "data.db"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

ADMIN_KEY = os.getenv("ADMIN_KEY", "secret123")
ADMIN_HASH = sha256(ADMIN_KEY.encode()).hexdigest()

# =========================
# RATE LIMIT
# =========================
RATE_LIMIT = {}
RATE_WINDOW = 10
RATE_MAX = 20


def rate_limiter():
    ip = request.remote_addr
    now = time.time()

    requests = RATE_LIMIT.get(ip, [])
    requests = [t for t in requests if now - t < RATE_WINDOW]

    if len(requests) >= RATE_MAX:
        return False

    requests.append(now)
    RATE_LIMIT[ip] = requests
    return True


# =========================
# DB
# =========================

def db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db()
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            device_id TEXT PRIMARY KEY,
            status TEXT,
            expires TEXT,
            banned INTEGER
        )
    """)
    conn.commit()
    conn.close()

init_db()


# =========================
# HELPERS
# =========================

def json_error(msg, code=400):
    return jsonify({"error": msg}), code


def clean_device_id(device_id):
    return str(device_id).strip().lower() if device_id else None


def parse_date(date_str):
    return datetime.strptime(date_str, DATE_FORMAT).replace(tzinfo=timezone.utc)


def require_auth():
    key = request.headers.get("Authorization")
    if not key:
        return False
    return hmac.compare_digest(
        sha256(key.encode()).hexdigest(),
        ADMIN_HASH
    )


def protected(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not rate_limiter():
            return json_error("rate limit exceeded", 429)
        if not require_auth():
            return json_error("unauthorized", 403)
        return f(*args, **kwargs)
    return wrapper


# =========================
# ADD DEVICE
# =========================
@app.route("/add", methods=["POST"])
@protected
def add_device():
    data = request.get_json(silent=True)
    if not data:
        return json_error("invalid json")

    device_id = clean_device_id(data.get("device_id"))
    if not device_id:
        return json_error("device_id required")

    # custom days support (default = 7)
    try:
        days = int(data.get("days", 7))
    except:
        return json_error("invalid days")

    # safety limits (important)
    if days < 1 or days > 365:
        return json_error("days must be 1-365")

    conn = db()
    c = conn.cursor()

    c.execute("SELECT device_id FROM users WHERE device_id=?", (device_id,))
    if c.fetchone():
        return json_error("device already exists")

    expires = (
        datetime.now(timezone.utc) + timedelta(days=days)
    ).strftime(DATE_FORMAT)

    c.execute(
        "INSERT INTO users VALUES (?, ?, ?, ?)",
        (device_id, "premium", expires, 0)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "Device added successfully",
        "days": days,
        "expires": expires
    })


# =========================
# VALIDATE
# =========================
@app.route("/validate", methods=["POST"])
def validate():
    if not rate_limiter():
        return json_error("rate limit exceeded", 429)

    data = request.get_json(silent=True)
    if not data:
        return json_error("invalid json")

    device_id = clean_device_id(data.get("device_id"))
    if not device_id:
        return json_error("device_id required")

    conn = db()
    c = conn.cursor()

    c.execute("SELECT * FROM users WHERE device_id=?", (device_id,))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({"status": "not_found"})

    now = datetime.now(timezone.utc)
    expiry = parse_date(user["expires"])

    if user["banned"]:
        return jsonify({"status": "banned"})

    if now > expiry:
        return jsonify({"status": "expired"})

    return jsonify({"status": "active"})


# =========================
# BAN / UNBAN
# =========================
@app.route("/ban", methods=["POST"])
@protected
def ban():
    data = request.get_json(silent=True)
    device_id = clean_device_id(data.get("device_id"))

    conn = db()
    c = conn.cursor()
    c.execute("UPDATE users SET banned=1 WHERE device_id=?", (device_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "banned"})


@app.route("/unban", methods=["POST"])
@protected
def unban():
    data = request.get_json(silent=True)
    device_id = clean_device_id(data.get("device_id"))

    conn = db()
    c = conn.cursor()
    c.execute("UPDATE users SET banned=0 WHERE device_id=?", (device_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "unbanned"})


# =========================
# EXTEND
# =========================
@app.route("/extend", methods=["POST"])
@protected
def extend():
    data = request.get_json(silent=True)
    device_id = clean_device_id(data.get("device_id"))
    days = int(data.get("days", 0))

    if days <= 0:
        return json_error("invalid days")

    conn = db()
    c = conn.cursor()

    c.execute("SELECT expires FROM users WHERE device_id=?", (device_id,))
    row = c.fetchone()

    if not row:
        return json_error("device not found")

    current = parse_date(row["expires"])
    new_exp = (current + timedelta(days=days)).strftime(DATE_FORMAT)

    c.execute(
        "UPDATE users SET expires=? WHERE device_id=?",
        (new_exp, device_id)
    )

    conn.commit()
    conn.close()

    return jsonify({"message": "extended"})


# =========================
# DELETE
# =========================
@app.route("/delete", methods=["POST"])
@protected
def delete():
    data = request.get_json(silent=True)
    device_id = clean_device_id(data.get("device_id"))

    conn = db()
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE device_id=?", (device_id,))
    conn.commit()
    conn.close()

    return jsonify({"message": "deleted"})


# =========================
# STATS
# =========================
@app.route("/stats", methods=["GET"])
@protected
def stats():
    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    users = c.fetchall()
    conn.close()

    now = datetime.now(timezone.utc)

    total = len(users)
    banned = expired = active = 0

    for u in users:
        expiry = parse_date(u["expires"])

        if u["banned"]:
            banned += 1
        elif now > expiry:
            expired += 1
        else:
            active += 1

    return jsonify({
        "total": total,
        "banned": banned,
        "expired": expired,
        "active": active
    })


# =========================
# USERS
# =========================
@app.route("/users", methods=["GET"])
@protected
def users():
    conn = db()
    c = conn.cursor()
    c.execute("SELECT * FROM users")
    rows = c.fetchall()
    conn.close()

    now = datetime.now(timezone.utc)

    result = []
    for u in rows:
        expiry = parse_date(u["expires"])
        days_left = max(int((expiry - now).total_seconds() / 86400), 0)

        result.append({
            "device_id": u["device_id"],
            "status": u["status"],
            "banned": bool(u["banned"]),
            "expires": u["expires"],
            "days_left": days_left
        })

    return jsonify({"users": result})


# =========================
# RUN SERVER (FIXED)
# =========================
if __name__ == "__main__":
    app.run(debug=True)