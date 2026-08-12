# Checkpoint — QR Attendance Tracker

A working Flask + SQLite website. QR codes rotate every 3 seconds, are
HMAC-SHA256 signed and single-use, students verify with a live-face
(blink) liveness check in the browser, and check-ins are rejected if the
student's GPS position is outside a 25–30m classroom geofence.

## Run it

```bash
pip install -r requirements.txt
python app.py
```

Open **http://localhost:5000** — one browser tab as faculty, another (or
your phone, if it's on the same network) as a student.

For a phone to reach it, use your machine's LAN IP instead of localhost,
e.g. `http://192.168.1.23:5000`, and make sure port 5000 is reachable.
Camera and geolocation APIs require either `localhost` or HTTPS — over
plain HTTP on another device, most mobile browsers will block camera/GPS
access. For real deployment, put this behind HTTPS (e.g. via Caddy,
nginx + certbot, or a host that provides it for you).

## What's actually server-side now

Unlike a browser-only mockup, the parts that matter for security run on
the server, not in the student's browser:

- **Token signing** — `app.py` generates a random secret per session and
  signs each token with HMAC-SHA256. The secret never leaves the server;
  the browser only ever sees `{sid, nonce, issued-at, expiry, signature}`.
- **Expiry & replay checks** — the server checks the token against its
  own clock and a `used_nonces` table, not against anything the client
  claims.
- **Geofence math** — haversine distance is computed server-side against
  the classroom coordinates stored at session start; the radius (25–30m)
  is enforced there too.
- **Attendance records** — written to `attendance.db` (SQLite), not to
  browser storage, so they survive refreshes and are shared across every
  device hitting the API.

## What still runs in the browser

- **Live face check** (`face-api.js`): loads a small face-landmark model
  and watches for a natural blink before letting a student proceed. This
  is a reasonable academic-grade liveness signal (a static photo won't
  blink), not a certified biometric system — a browser has no way to do
  cryptographically-attested liveness on its own.
- **QR scanning** (`jsQR`): decodes the code from the device camera.
- **QR rendering** (`qrcode.js`): draws the token the server issued.

## Known limitations (things a real deployment would need)

- **One active session at a time.** The server keeps a single in-memory
  "current session" rather than one per course/room. Fine for a single
  classroom demo; a real rollout would key sessions by course and store
  active sessions in the DB instead of a module-level dict.
- **No real faculty authentication.** `/api/faculty/login` accepts any
  name — there's no password or identity check. Swap in your
  institution's SSO or a proper auth flow before using this for real.
- **No server-side identity binding for students.** A student typing in
  someone else's name/roll after passing their own liveness check would
  still be recorded under that name. A production version would tie the
  liveness check to a known student identity (e.g. a photo on file) and
  bind attendance to whoever logged in, not to free-text fields.
- **GPS accuracy varies by device.** Laptops without GPS hardware can be
  off by 100m+ (Wi-Fi/IP based positioning). The geofence check adds a
  small buffer for reported accuracy, but very inaccurate readings can
  still cause false rejections indoors — test on an actual phone.

## Files

```
app.py              Flask backend — routes, signing, validation, SQLite
templates/index.html Single-page frontend (faculty + student flows)
requirements.txt
```
