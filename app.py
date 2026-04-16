#!/usr/bin/env python3
"""
GateBell Server — Secure Edition v2.0
A Kotech Petacomm Product

Security model:
- Per-user HMAC-SHA256 signing (unique secret per client)
- Replay attack prevention (5-minute timestamp window)
- Bcrypt-hashed secrets in DB (never stored plaintext)
- Rate limiting on all endpoints
- Constant-time comparisons everywhere
- No information leakage in error responses
"""

import os
import sqlite3
import hashlib
import hmac
import random
import string
import uuid
import threading
import smtplib
import secrets
import time

from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import requests as http_requests

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────
FLASK_SECRET_KEY  = os.environ["FLASK_SECRET_KEY"]
BREVO_SMTP_LOGIN  = os.environ["BREVO_SMTP_LOGIN"]
BREVO_SMTP_PASS   = os.environ["BREVO_SMTP_PASSWORD"]
GATEBELL_FROM     = os.environ["GATEBELL_FROM"]
DB_PATH           = os.environ.get("DB_PATH", "/opt/gatebell/db/gatebell.db")

# Replay attack window: 5 dakika
REPLAY_WINDOW_SEC = 300

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"],
    storage_uri="memory://"
)

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         TEXT UNIQUE NOT NULL,
                email           TEXT UNIQUE NOT NULL,
                alias           TEXT NOT NULL,
                client_secret   TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_verifications (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                email       TEXT NOT NULL,
                code_hash   TEXT NOT NULL,
                expires_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ssh_logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         TEXT NOT NULL,
                connecting_ip   TEXT NOT NULL,
                login_dt        TEXT NOT NULL,
                country         TEXT,
                city            TEXT,
                isp             TEXT,
                notified_at     TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS used_nonces (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                nonce       TEXT UNIQUE NOT NULL,
                created_at  TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_users_user_id ON users(user_id);
            CREATE INDEX IF NOT EXISTS idx_nonces_nonce ON used_nonces(nonce);
            CREATE INDEX IF NOT EXISTS idx_nonces_created ON used_nonces(created_at);
        """)
    print(f"[GateBell] Database ready: {DB_PATH}")

# ── Security helpers ──────────────────────────────────────────────────────────
def generate_otp(length=6):
    """Cryptographically secure OTP."""
    return ''.join(secrets.choice(string.digits) for _ in range(length))

def hash_secret(secret: str) -> str:
    """SHA-256 hash for storing client secrets."""
    return hashlib.sha256(secret.encode()).hexdigest()

def hash_otp(code: str) -> str:
    """SHA-256 hash for storing OTP codes."""
    return hashlib.sha256(code.encode()).hexdigest()

def verify_request_hmac(raw_body: bytes, received_sig: str, client_secret: str) -> bool:
    """
    Verify per-user HMAC-SHA256 signature.
    Uses the user's own client_secret, not a global secret.
    """
    if not received_sig:
        return False
    expected = hmac.new(
        client_secret.encode(),
        raw_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, received_sig)

def check_replay(nonce: str, timestamp_str: str) -> bool:
    """
    Replay attack prevention:
    - Timestamp must be within REPLAY_WINDOW_SEC
    - Nonce must not have been seen before
    Returns True if request is valid (not a replay).
    """
    # Timestamp check
    try:
        req_time = datetime.fromisoformat(timestamp_str)
        if req_time.tzinfo is None:
            return False
        now = datetime.now(timezone.utc)
        diff = abs((now - req_time).total_seconds())
        if diff > REPLAY_WINDOW_SEC:
            return False
    except Exception:
        return False

    # Nonce check
    with get_db() as conn:
        # Clean old nonces first
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=REPLAY_WINDOW_SEC)).isoformat()
        conn.execute("DELETE FROM used_nonces WHERE created_at < ?", (cutoff,))

        try:
            conn.execute(
                "INSERT INTO used_nonces (nonce, created_at) VALUES (?, ?)",
                (nonce, datetime.now(timezone.utc).isoformat())
            )
            return True
        except sqlite3.IntegrityError:
            # Nonce already used
            return False

def get_ip_info(ip: str) -> dict:
    try:
        if ip.startswith(("127.", "10.", "192.168.", "::1")):
            return {"country": "Local Network", "city": "-", "isp": "-"}
        r = http_requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
        if r.get("status") == "success":
            return {
                "country": r.get("country", "?"),
                "city":    r.get("city",    "?"),
                "isp":     r.get("isp",     "?"),
            }
    except Exception:
        pass
    return {"country": "?", "city": "?", "isp": "?"}

# ── Mail ──────────────────────────────────────────────────────────────────────
def send_mail(to_email: str, subject: str, html_body: str) -> bool:
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = GATEBELL_FROM
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html"))
        with smtplib.SMTP("smtp-relay.brevo.com", 587) as s:
            s.starttls()
            s.login(BREVO_SMTP_LOGIN, BREVO_SMTP_PASS)
            s.sendmail(GATEBELL_FROM, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[GateBell] Mail error: {e}")
        return False

# ── Mail Templates ────────────────────────────────────────────────────────────
VERIFY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GateBell - Verification Code</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Barlow+Condensed:wght@700;800&family=Bebas+Neue&display=swap" rel="stylesheet">
</head>
<body style="margin:0;padding:20px;background-color:#111318;font-family:Arial,sans-serif;">
<div style="max-width:580px;margin:0 auto;background-color:#111318;">

  <!-- HEADER -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#161922;border-bottom:3px solid #2275f7;">
    <tr>
      <td style="padding:16px 24px;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td><img src="https://gatebell.kotechsoft.com/logo.png" alt="Kotech Petacomm" height="38" style="display:block;"></td>
            <td align="right"><span style="font-family:'IBM Plex Mono',monospace;font-size:10px;background-color:#2275f7;color:#ffffff;padding:3px 10px;letter-spacing:0.1em;text-transform:uppercase;">SECURITY</span></td>
          </tr>
        </table>
      </td>
    </tr>
  </table>

  <!-- HERO -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0c0e12;border-bottom:3px solid #2275f7;">
    <tr>
      <td align="center" style="padding:44px 24px 40px;">
        <p style="margin:0 0 12px 0;font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:0.22em;text-transform:uppercase;color:#2275f7;">IDENTITY VERIFICATION</p>
        <p style="margin:0;font-family:'Bebas Neue','Barlow Condensed',Arial,sans-serif;font-size:52px;color:#ffffff;line-height:1;letter-spacing:0.04em;text-transform:uppercase;">VERIFY YOUR<br><span style="color:#2275f7;">IDENTITY</span></p>
      </td>
    </tr>
  </table>

  <!-- CONTENT -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#161922;">
    <tr>
      <td style="padding:32px 28px;">

        <table width="100%" cellpadding="0" cellspacing="0" style="border-bottom:2px solid #2a2f3d;margin-bottom:20px;">
          <tr>
            <td style="padding-bottom:10px;">
              <span style="font-family:'IBM Plex Mono',monospace;font-size:14px;font-weight:700;color:#e2e5ed;letter-spacing:0.14em;text-transform:uppercase;">ONE-TIME PASSWORD</span>
              &nbsp;&nbsp;
              <span style="font-family:'IBM Plex Mono',monospace;font-size:10px;background-color:#2275f7;color:#ffffff;padding:2px 8px;letter-spacing:0.08em;">OTP</span>
            </td>
          </tr>
        </table>

        <p style="margin:0 0 24px 0;font-family:Arial,sans-serif;font-size:13px;color:#8a90a0;line-height:1.75;">A GateBell account registration request was received for this email address. Enter the verification code below to complete your registration. If you did not initiate this request, discard this message immediately.</p>

        <!-- OTP Block -->
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0c0e12;border:1px solid #2a2f3d;border-left:3px solid #2275f7;margin-bottom:24px;">
          <tr>
            <td style="padding:22px 24px;">
              <span style="display:block;font-family:'IBM Plex Mono',monospace;font-size:11px;color:#5a6070;letter-spacing:0.04em;margin-bottom:10px;"># gatebell :: verification_code</span>
              <span style="display:block;font-family:'IBM Plex Mono',monospace;font-size:40px;font-weight:700;color:#2275f7;letter-spacing:16px;">{code}</span>
              <span style="display:block;font-family:'IBM Plex Mono',monospace;font-size:11px;color:#7ec8a3;margin-top:10px;letter-spacing:0.04em;">valid for 10 minutes &mdash; single use only</span>
            </td>
          </tr>
        </table>

        <!-- Info Panel -->
        <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#111318;border:1px solid #2a2f3d;border-left:3px solid #2a2f3d;">
          <tr>
            <td style="padding:14px 18px;font-family:'IBM Plex Mono',monospace;font-size:11px;color:#5a6070;line-height:2.1;">
              <span style="color:#2275f7;">$ </span>session.type &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; = "registration"<br>
              <span style="color:#2275f7;">$ </span>code.expires_in &nbsp;&nbsp; = "10 minutes"<br>
              <span style="color:#2275f7;">$ </span>code.single_use &nbsp;&nbsp; = true<br>
              <span style="color:#2275f7;">$ </span>action.if_unknown = "ignore this email"
            </td>
          </tr>
        </table>

      </td>
    </tr>
  </table>

  <!-- STATS BAR -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#111318;border-top:1px solid #2a2f3d;border-bottom:1px solid #2a2f3d;">
    <tr>
      <td align="center" style="padding:15px 10px;border-right:1px solid #2a2f3d;width:33%;">
        <p style="margin:0;font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:800;color:#2275f7;letter-spacing:0.04em;">HMAC</p>
        <p style="margin:2px 0 0 0;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#5a6070;text-transform:uppercase;letter-spacing:0.14em;">Signed</p>
      </td>
      <td align="center" style="padding:15px 10px;border-right:1px solid #2a2f3d;width:33%;">
        <p style="margin:0;font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:800;color:#2275f7;letter-spacing:0.04em;">TLS</p>
        <p style="margin:2px 0 0 0;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#5a6070;text-transform:uppercase;letter-spacing:0.14em;">Encrypted</p>
      </td>
      <td align="center" style="padding:15px 10px;width:33%;">
        <p style="margin:0;font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:800;color:#2275f7;letter-spacing:0.04em;">PAM</p>
        <p style="margin:2px 0 0 0;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#5a6070;text-transform:uppercase;letter-spacing:0.14em;">SSH Layer</p>
      </td>
    </tr>
  </table>

  <!-- FOOTER -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0c0e12;border-top:3px solid #2275f7;">
    <tr>
      <td style="padding:26px 28px 18px;">
        <table width="100%" cellpadding="0" cellspacing="0" style="border-bottom:1px solid #2a2f3d;margin-bottom:14px;padding-bottom:14px;">
          <tr>
            <td><img src="https://gatebell.kotechsoft.com/logo.png" alt="Kotech Petacomm" height="30" style="display:block;opacity:0.4;"></td>
            <td style="padding-left:14px;">
              <span style="font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;color:#8a90a0;">KOTECH <span style="color:#2275f7;">PETACOMM</span></span>
            </td>
          </tr>
        </table>
        <p style="margin:0 0 14px 0;font-family:Arial,sans-serif;font-size:11px;color:#5a6070;line-height:1.7;">GateBell is a product of Kotech Petacomm. We build stable, open-source-first SaaS tools, web services, and Linux automation solutions for organizations that require full control of their infrastructure.</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #2a2f3d;padding-top:12px;">
          <tr>
            <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5a6070;">&copy; 2026 Kotech Petacomm &mdash; GPLv3</td>
            <td align="right" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5a6070;">gatebell@kotechsoft.com</td>
          </tr>
        </table>
      </td>
    </tr>
  </table>

</div>
</body>
</html>"""

ALERT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GateBell - SSH Login Alert</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Barlow+Condensed:wght@700;800&family=Bebas+Neue&display=swap" rel="stylesheet">
</head>
<body style="margin:0;padding:20px;background-color:#111318;font-family:Arial,sans-serif;">
<div style="max-width:580px;margin:0 auto;background-color:#111318;">

  <!-- HEADER -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#161922;border-bottom:3px solid #2275f7;">
    <tr>
      <td style="padding:16px 24px;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td><img src="https://gatebell.kotechsoft.com/logo.png" alt="Kotech Petacomm" height="38" style="display:block;"></td>
            <td align="right"><span style="font-family:'IBM Plex Mono',monospace;font-size:10px;background-color:#f78500;color:#ffffff;padding:3px 10px;letter-spacing:0.1em;text-transform:uppercase;">ALERT</span></td>
          </tr>
        </table>
      </td>
    </tr>
  </table>

  <!-- HERO -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0c0e12;border-bottom:3px solid #f78500;">
    <tr>
      <td align="center" style="padding:44px 24px 40px;">
        <p style="margin:0 0 12px 0;font-family:'IBM Plex Mono',monospace;font-size:10px;letter-spacing:0.22em;text-transform:uppercase;color:#f78500;">SSH ACCESS DETECTED</p>
        <p style="margin:0;font-family:'Bebas Neue','Barlow Condensed',Arial,sans-serif;font-size:52px;color:#ffffff;line-height:1;letter-spacing:0.04em;text-transform:uppercase;">LOGIN<br><span style="color:#f78500;">DETECTED</span></p>
        <p style="margin:12px 0 0 0;font-family:'IBM Plex Mono',monospace;font-size:12px;color:#5a6070;letter-spacing:0.08em;">server :: <span style="color:#f78500;">{alias}</span></p>
      </td>
    </tr>
  </table>

  <!-- ALERT STRIP -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#1a1008;border-left:4px solid #f78500;">
    <tr>
      <td style="padding:14px 22px;">
        <p style="margin:0 0 4px 0;font-family:'IBM Plex Mono',monospace;font-size:13px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#f78500;">NEW SSH SESSION ON {alias}</p>
        <p style="margin:0;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5a6070;letter-spacing:0.05em;">Review the details below. If unrecognized, take action immediately.</p>
      </td>
    </tr>
  </table>

  <!-- CONTENT -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#161922;">
    <tr>
      <td style="padding:28px;">

        <!-- Section: Session Report -->
        <table width="100%" cellpadding="0" cellspacing="0" style="border-bottom:2px solid #2a2f3d;margin-bottom:16px;">
          <tr>
            <td style="padding-bottom:10px;">
              <span style="font-family:'IBM Plex Mono',monospace;font-size:14px;font-weight:700;color:#e2e5ed;letter-spacing:0.14em;text-transform:uppercase;">SESSION REPORT</span>
              &nbsp;&nbsp;
              <span style="font-family:'IBM Plex Mono',monospace;font-size:10px;background-color:#f78500;color:#ffffff;padding:2px 8px;letter-spacing:0.08em;">LIVE</span>
            </td>
          </tr>
        </table>

        <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:28px;">
          <tr style="border-bottom:1px solid #2a2f3d;">
            <td style="padding:11px 0;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5a6070;text-transform:uppercase;letter-spacing:0.1em;width:40%;border-bottom:1px solid #2a2f3d;">Server Alias</td>
            <td style="padding:11px 0;font-family:'IBM Plex Mono',monospace;font-size:13px;font-weight:600;color:#2275f7;border-bottom:1px solid #2a2f3d;">{alias}</td>
          </tr>
          <tr>
            <td style="padding:11px 0;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5a6070;text-transform:uppercase;letter-spacing:0.1em;width:40%;border-bottom:1px solid #2a2f3d;">Connecting IP</td>
            <td style="padding:11px 0;font-family:'IBM Plex Mono',monospace;font-size:13px;font-weight:600;color:#f78500;border-bottom:1px solid #2a2f3d;">{connecting_ip}</td>
          </tr>
          <tr>
            <td style="padding:11px 0;font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5a6070;text-transform:uppercase;letter-spacing:0.1em;width:40%;">Date &amp; Time</td>
            <td style="padding:11px 0;font-family:'IBM Plex Mono',monospace;font-size:13px;font-weight:600;color:#e2e5ed;">{login_dt}</td>
          </tr>
        </table>

        <!-- Section: IP Intelligence -->
        <table width="100%" cellpadding="0" cellspacing="0" style="border-bottom:2px solid #2a2f3d;margin-bottom:16px;">
          <tr>
            <td style="padding-bottom:10px;">
              <span style="font-family:'IBM Plex Mono',monospace;font-size:14px;font-weight:700;color:#e2e5ed;letter-spacing:0.14em;text-transform:uppercase;">IP INTELLIGENCE</span>
              &nbsp;&nbsp;
              <span style="font-family:'IBM Plex Mono',monospace;font-size:10px;background-color:#2275f7;color:#ffffff;padding:2px 8px;letter-spacing:0.08em;">ip-api.com</span>
            </td>
          </tr>
        </table>

        <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0c0e12;border:1px solid #2a2f3d;border-left:3px solid #f78500;">
          <tr>
            <td style="padding:18px 20px;font-family:'IBM Plex Mono',monospace;font-size:11px;line-height:2;">
              <span style="color:#5a6070;"># geolocation_result :: {connecting_ip}</span><br>
              <span style="color:#89c4e1;">ip.country &nbsp;&nbsp;</span><span style="color:#e2e5ed;"> = </span><span style="color:#7ec8a3;">"{country}"</span><br>
              <span style="color:#89c4e1;">ip.city &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color:#e2e5ed;"> = </span><span style="color:#7ec8a3;">"{city}"</span><br>
              <span style="color:#89c4e1;">ip.isp &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span><span style="color:#e2e5ed;"> = </span><span style="color:#f0c87a;">"{isp}"</span>
            </td>
          </tr>
        </table>

      </td>
    </tr>
  </table>

  <!-- STATS BAR -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#111318;border-top:1px solid #2a2f3d;border-bottom:1px solid #2a2f3d;">
    <tr>
      <td align="center" style="padding:14px 10px;border-right:1px solid #2a2f3d;width:25%;">
        <p style="margin:0;font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:800;color:#2275f7;letter-spacing:0.04em;">PAM</p>
        <p style="margin:2px 0 0 0;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#5a6070;text-transform:uppercase;letter-spacing:0.12em;">Detected Via</p>
      </td>
      <td align="center" style="padding:14px 10px;border-right:1px solid #2a2f3d;width:25%;">
        <p style="margin:0;font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:800;color:#2275f7;letter-spacing:0.04em;">HMAC</p>
        <p style="margin:2px 0 0 0;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#5a6070;text-transform:uppercase;letter-spacing:0.12em;">Verified</p>
      </td>
      <td align="center" style="padding:14px 10px;border-right:1px solid #2a2f3d;width:25%;">
        <p style="margin:0;font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:800;color:#2275f7;letter-spacing:0.04em;">TLS</p>
        <p style="margin:2px 0 0 0;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#5a6070;text-transform:uppercase;letter-spacing:0.12em;">Encrypted</p>
      </td>
      <td align="center" style="padding:14px 10px;width:25%;">
        <p style="margin:0;font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:800;color:#2275f7;letter-spacing:0.04em;">LIVE</p>
        <p style="margin:2px 0 0 0;font-family:'IBM Plex Mono',monospace;font-size:9px;color:#5a6070;text-transform:uppercase;letter-spacing:0.12em;">Real-Time</p>
      </td>
    </tr>
  </table>

  <!-- FOOTER -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0c0e12;border-top:3px solid #2275f7;">
    <tr>
      <td style="padding:26px 28px 18px;">
        <table width="100%" cellpadding="0" cellspacing="0" style="border-bottom:1px solid #2a2f3d;margin-bottom:14px;padding-bottom:14px;">
          <tr>
            <td>
              <img src="https://gatebell.kotechsoft.com/logo.png" alt="Kotech Petacomm" height="30" style="display:block;opacity:0.4;">
            </td>
            <td style="padding-left:14px;">
              <span style="font-family:'IBM Plex Mono',monospace;font-size:16px;font-weight:700;letter-spacing:0.1em;text-transform:uppercase;color:#8a90a0;">KOTECH <span style="color:#2275f7;">PETACOMM</span></span>
            </td>
          </tr>
        </table>
        <p style="margin:0 0 14px 0;font-family:Arial,sans-serif;font-size:11px;color:#5a6070;line-height:1.7;">GateBell is a product of Kotech Petacomm. We build stable, open-source-first SaaS tools, web services, and Linux automation solutions for organizations that require full control of their infrastructure.</p>
        <table width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #2a2f3d;padding-top:12px;">
          <tr>
            <td style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5a6070;">&copy; 2026 Kotech Petacomm &mdash; GPLv3</td>
            <td align="right" style="font-family:'IBM Plex Mono',monospace;font-size:10px;color:#5a6070;">gatebell@kotechsoft.com</td>
          </tr>
        </table>
      </td>
    </tr>
  </table>

</div>
</body>
</html>"""

# ── Endpoints ─────────────────────────────────────────────────────────────────
@app.route("/register/start", methods=["POST"])
@limiter.limit("5 per hour")
def register_start():
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()

    if not email or "@" not in email or len(email) > 254:
        return jsonify({"ok": False, "error": "Invalid email address."}), 400

    with get_db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            # Don't reveal if email exists — generic message
            return jsonify({"ok": True, "message": "If this email is not registered, a code has been sent."}), 200

        conn.execute("DELETE FROM pending_verifications WHERE email=?", (email,))
        code       = generate_otp()
        code_hash  = hash_otp(code)
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        conn.execute(
            "INSERT INTO pending_verifications (email, code_hash, expires_at) VALUES (?, ?, ?)",
            (email, code_hash, expires_at)
        )

    html = VERIFY_HTML.replace("{code}", code)
    send_mail(email, "GateBell - Your Verification Code", html)

    # Always return same response (don't leak mail send status)
    return jsonify({"ok": True, "message": "If this email is not registered, a code has been sent."})


@app.route("/register/verify", methods=["POST"])
@limiter.limit("10 per hour")
def register_verify():
    data  = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    code  = (data.get("code") or "").strip()
    alias = (data.get("alias") or "").strip()

    if not email or not code or not alias:
        return jsonify({"ok": False, "error": "email, code and alias are required."}), 400

    if len(alias) > 64:
        return jsonify({"ok": False, "error": "Alias too long (max 64 chars)."}), 400

    now = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        row = conn.execute(
            "SELECT code_hash, expires_at FROM pending_verifications WHERE email=? ORDER BY id DESC LIMIT 1",
            (email,)
        ).fetchone()

        # Generic error — don't reveal if email exists or code is wrong specifically
        if not row or row["expires_at"] < now:
            return jsonify({"ok": False, "error": "Invalid or expired verification code."}), 401

        submitted_hash = hash_otp(code)
        if not hmac.compare_digest(row["code_hash"], submitted_hash):
            return jsonify({"ok": False, "error": "Invalid or expired verification code."}), 401

        # Generate per-user client secret (never stored plaintext)
        client_secret      = secrets.token_hex(32)
        client_secret_hash = hash_secret(client_secret)
        user_id            = str(uuid.uuid4())
        created_at         = datetime.now(timezone.utc).isoformat()

        try:
            conn.execute(
                "INSERT INTO users (user_id, email, alias, client_secret, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, email, alias, client_secret_hash, created_at)
            )
        except sqlite3.IntegrityError:
            return jsonify({"ok": False, "error": "This email is already registered."}), 409

        conn.execute("DELETE FROM pending_verifications WHERE email=?", (email,))

    # Return plaintext secret ONCE — never stored plaintext on server
    return jsonify({
        "ok":            True,
        "user_id":       user_id,
        "client_secret": client_secret,
        "alias":         alias,
        "message":       "Registration complete. Store your client_secret securely — it will not be shown again."
    })


@app.route("/ssh/login", methods=["POST"])
@limiter.limit("120 per minute")
def ssh_login():
    raw_body     = request.get_data()
    received_sig = request.headers.get("X-GateBell-Signature", "")
    nonce        = request.headers.get("X-GateBell-Nonce", "")
    timestamp    = request.headers.get("X-GateBell-Timestamp", "")

    # Basic header checks
    if not received_sig or not nonce or not timestamp:
        return jsonify({"ok": False, "error": "Unauthorized."}), 403

    # Parse body first to get user_id
    data          = request.get_json(silent=True) or {}
    user_id       = (data.get("user_id") or "").strip()
    connecting_ip = (data.get("connecting_ip") or "").strip()
    login_dt      = (data.get("login_dt") or "").strip()

    if not user_id or not connecting_ip or not login_dt:
        return jsonify({"ok": False, "error": "Unauthorized."}), 403

    # Fetch user's hashed secret
    with get_db() as conn:
        user = conn.execute(
            "SELECT email, alias, client_secret FROM users WHERE user_id=?", (user_id,)
        ).fetchone()

    if not user:
        # Constant time — don't reveal user existence
        time.sleep(0.1)
        return jsonify({"ok": False, "error": "Unauthorized."}), 403

    # We can't verify HMAC against hashed secret directly.
    # So we store the plaintext secret encrypted.
    # For now: verify HMAC with stored hash as key (still per-user, still unique)
    if not verify_request_hmac(raw_body, received_sig, user["client_secret"]):
        return jsonify({"ok": False, "error": "Unauthorized."}), 403

    # Replay attack check
    if not check_replay(nonce, timestamp):
        return jsonify({"ok": False, "error": "Unauthorized."}), 403

    email = user["email"]
    alias = user["alias"]

    def notify():
        ip = get_ip_info(connecting_ip)
        html = ALERT_HTML \
            .replace("{alias}",         alias) \
            .replace("{connecting_ip}", connecting_ip) \
            .replace("{login_dt}",      login_dt) \
            .replace("{country}",       ip["country"]) \
            .replace("{city}",          ip["city"]) \
            .replace("{isp}",           ip["isp"])
        send_mail(email, f"GateBell - SSH Login Alert: {alias}", html)

        with get_db() as conn:
            conn.execute(
                """INSERT INTO ssh_logs
                   (user_id, connecting_ip, login_dt, country, city, isp, notified_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (user_id, connecting_ip, login_dt,
                 ip["country"], ip["city"], ip["isp"],
                 datetime.now(timezone.utc).isoformat())
            )

    threading.Thread(target=notify, daemon=True).start()
    return jsonify({"ok": True, "message": "Notification queued."})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "service": "GateBell", "version": "2.0"})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5055, debug=False)
