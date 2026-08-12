"""
Checkpoint — QR Attendance backend.

Run:
    pip install -r requirements.txt
    python app.py
Then open http://localhost:5000

All security-relevant decisions (token signing, expiry, replay checks,
geofence math) happen here on the server. The browser never sees the
signing secret — it only ever sees the public token fields (sid, nonce,
issued-at, expiry, signature), which is what actually makes the QR code
tamper-evident. In the previous browser-only prototype the secret lived
in client-side storage, which is fine for a demo but isn't a real
security boundary.
"""
import hashlib
import hmac
import math
import os
import secrets
import sqlite3
import threading
import time

from flask import Flask, g, jsonify, render_template, request, session

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attendance.db")
TOKEN_TTL_MS = 3000  # QR expiry, per spec: 3 seconds


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            sid TEXT PRIMARY KEY,
            course TEXT,
            faculty TEXT,
            lat REAL,
            lng REAL,
            radius REAL,
            secret TEXT,
            started_at INTEGER,
            ended_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sid TEXT,
            name TEXT,
            roll TEXT,
            time INTEGER,
            distance REAL,
            status TEXT
        );
        CREATE TABLE IF NOT EXISTS used_nonces (
            sid TEXT,
            nonce TEXT,
            PRIMARY KEY (sid, nonce)
        );
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# In-memory state for the single active classroom session.
# (A production multi-course version would key this by course/room instead
# of assuming one active session at a time — flagged in the README.)
# ---------------------------------------------------------------------------
STATE = {"active": None, "token": None}
LOCK = threading.Lock()


def sign(secret_hex, message):
    key = bytes.fromhex(secret_hex)
    return hmac.new(key, message.encode(), hashlib.sha256).hexdigest()


def haversine_meters(lat1, lng1, lat2, lng2):
    r = 6371000
    p1, p2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lng2 - lng1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(d_lambda / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def now_ms():
    return int(time.time() * 1000)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------------------
# Faculty API
# ---------------------------------------------------------------------------
@app.route("/api/faculty/login", methods=["POST"])
def faculty_login():
    data = request.get_json(force=True) or {}
    session["faculty"] = (data.get("name") or "Faculty").strip()
    session["course"] = (data.get("course") or "Untitled section").strip()
    return jsonify({"ok": True, "faculty": session["faculty"], "course": session["course"]})


@app.route("/api/session/start", methods=["POST"])
def session_start():
    data = request.get_json(force=True) or {}
    lat, lng = data.get("lat"), data.get("lng")
    radius = float(data.get("radius", 27))
    if lat is None or lng is None:
        return jsonify({"ok": False, "error": "Classroom location is required."}), 400
    if not (25 <= radius <= 30):
        radius = min(max(radius, 25), 30)

    sid = secrets.token_hex(6)
    secret = secrets.token_hex(32)
    course = session.get("course", "Untitled section")
    faculty = session.get("faculty", "Faculty")

    db = get_db()
    db.execute(
        "INSERT INTO sessions (sid, course, faculty, lat, lng, radius, secret, started_at, ended_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
        (sid, course, faculty, lat, lng, radius, secret, now_ms()),
    )
    db.commit()

    with LOCK:
        STATE["active"] = {
            "sid": sid, "lat": lat, "lng": lng, "radius": radius,
            "secret": secret, "course": course, "faculty": faculty,
        }
        STATE["token"] = None

    return jsonify({"ok": True, "sid": sid, "radius": radius})


@app.route("/api/session/end", methods=["POST"])
def session_end():
    with LOCK:
        active = STATE["active"]
        if active:
            db = get_db()
            db.execute("UPDATE sessions SET ended_at = ? WHERE sid = ?", (now_ms(), active["sid"]))
            db.commit()
        STATE["active"] = None
        STATE["token"] = None
    return jsonify({"ok": True})


@app.route("/api/session/status")
def session_status():
    with LOCK:
        active = STATE["active"]
    if not active:
        return jsonify({"active": False})
    return jsonify({
        "active": True, "sid": active["sid"], "course": active["course"],
        "faculty": active["faculty"], "radius": active["radius"],
    })


@app.route("/api/token")
def get_token():
    """Returns the current rotating token. Regenerates it lazily once the
    previous one has expired — this is the server-side 3-second rotation."""
    with LOCK:
        active = STATE["active"]
        if not active:
            return jsonify({"error": "no_active_session"}), 404
        tok = STATE["token"]
        t = now_ms()
        if not tok or t >= tok["exp"]:
            nonce = secrets.token_hex(8)
            iat, exp = t, t + TOKEN_TTL_MS
            payload = f"{active['sid']}.{nonce}.{iat}.{exp}"
            tok = {"sid": active["sid"], "n": nonce, "iat": iat, "exp": exp,
                   "sig": sign(active["secret"], payload)}
            STATE["token"] = tok
        return jsonify(tok)


# ---------------------------------------------------------------------------
# Student API
# ---------------------------------------------------------------------------
@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(force=True) or {}
    token = data.get("token") or {}
    name = (data.get("name") or "").strip()
    roll = (data.get("roll") or "").strip()
    lat, lng = data.get("lat"), data.get("lng")
    accuracy = data.get("accuracy") or 0

    if not name or not roll:
        return jsonify({"ok": False, "reason": "missing_identity",
                         "message": "Name and roll number are required."}), 400

    with LOCK:
        active = STATE["active"]

    if not active or token.get("sid") != active["sid"]:
        return jsonify({"ok": False, "reason": "no_session",
                         "message": "This code doesn't belong to an active session — it may have ended."})

    if now_ms() > token.get("exp", 0):
        return jsonify({"ok": False, "reason": "expired",
                         "message": "This code expired. The QR refreshes every 3 seconds — scan the current one."})

    expected_sig = sign(active["secret"],
                         f"{token.get('sid')}.{token.get('n')}.{token.get('iat')}.{token.get('exp')}")
    if not hmac.compare_digest(expected_sig, token.get("sig", "")):
        return jsonify({"ok": False, "reason": "bad_signature",
                         "message": "This code failed signature verification and may have been tampered with."})

    db = get_db()
    used = db.execute(
        "SELECT 1 FROM used_nonces WHERE sid = ? AND nonce = ?", (active["sid"], token.get("n"))
    ).fetchone()
    if used:
        return jsonify({"ok": False, "reason": "replay",
                         "message": "This single-use code has already been redeemed."})

    if lat is None or lng is None:
        return jsonify({"ok": False, "reason": "no_location",
                         "message": "Location is required to confirm you're in the classroom."})

    dist = haversine_meters(lat, lng, active["lat"], active["lng"])
    allowed = dist <= (active["radius"] + min(accuracy, 15))
    status = "present" if allowed else "rejected"

    db.execute("INSERT INTO used_nonces (sid, nonce) VALUES (?, ?)", (active["sid"], token.get("n")))
    db.execute(
        "INSERT INTO attendance (sid, name, roll, time, distance, status) VALUES (?, ?, ?, ?, ?, ?)",
        (active["sid"], name, roll, now_ms(), dist, status),
    )
    db.commit()

    return jsonify({
        "ok": allowed,
        "reason": None if allowed else "geofence",
        "message": "Attendance marked." if allowed else "Outside the classroom geofence.",
        "distance": dist, "radius": active["radius"],
    })


@app.route("/api/attendance")
def attendance():
    with LOCK:
        active = STATE["active"]
    if not active:
        return jsonify({"records": []})
    db = get_db()
    rows = db.execute(
        "SELECT name, roll, time, distance, status FROM attendance WHERE sid = ? ORDER BY time DESC",
        (active["sid"],),
    ).fetchall()
    return jsonify({"records": [dict(r) for r in rows]})


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
