"""
Nairobi County Gubernatorial E-Voting Prototype
=================================================
Single-file Flask application built for academic (Master's dissertation)
demonstration purposes. Implements:

  - Sybil-resistant registration (unique email + unique National ID)
  - Session-based auth with a persistent has_voted DB flag
  - Time-bound, single-use password reset tokens (printed to console)
  - AES (Fernet) encrypted ballots
  - SHA-256 hash-chained vote ledger (tamper-evident, blockchain-style)
  - Audit dashboard that re-walks the chain and reports VALID / COMPROMISED

DISCLAIMER: This is a teaching/research prototype, not a production voting
system. Real elections require far more (voter-verifiable paper trails,
distributed trust, formal security audits, threat modelling for coercion
and receipt-freeness, etc.). Do not use this to run a real election.
"""

import os
import re
import json
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, flash, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from jinja2 import DictLoader
from sqlalchemy.exc import IntegrityError

# ----------------------------------------------------------------------------
# App & configuration
# ----------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
# On Render, set a permanent SECRET_KEY environment variable.\n# Also set a permanent AES_KEY so encrypted votes survive restarts.

_database_url = os.environ.get("DATABASE_URL", "sqlite:///evoting.db")
# Render/Heroku sometimes hand out postgres:// which SQLAlchemy 1.4+ rejects
if _database_url.startswith("postgres://"):
    _database_url = _database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = _database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# --- AES (Fernet) key setup --------------------------------------------------
_AES_KEY = os.environ.get("AES_KEY")
if not _AES_KEY:
    _AES_KEY = Fernet.generate_key().decode()
    print("=" * 78)
    print("[WARNING] AES_KEY environment variable not set.")
    print("A temporary key was auto-generated for THIS PROCESS ONLY:")
    print(f"  AES_KEY={_AES_KEY}")
    print("Set this as a persistent environment variable, otherwise every")
    print("restart generates a new key and previously cast votes become")
    print("permanently undecryptable.")
    print("=" * 78)

fernet = Fernet(_AES_KEY.encode() if isinstance(_AES_KEY, str) else _AES_KEY)

# --- Password reset token serializer ----------------------------------------
serializer = URLSafeTimedSerializer(app.secret_key)
RESET_SALT = "password-reset-salt"
RESET_TOKEN_MAX_AGE_SECONDS = 900  # 15 minutes

# --- Outbound email (SMTP) configuration ------------------------------------
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
MAIL_FROM = os.environ.get("MAIL_FROM", SMTP_USERNAME or "no-reply@nairobi-evoting.local")
MAIL_FROM_NAME = os.environ.get("MAIL_FROM_NAME", "Nairobi County E-Voting")
EMAIL_VERIFICATION_MAX_AGE_SECONDS = 86400  # 24 hours


def send_email(to_email, subject, body):
    """Send a plain-text email through the configured SMTP server."""
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = f"{MAIL_FROM_NAME} <{MAIL_FROM}>"
    msg["To"] = to_email

    if not (SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD):
        print("=" * 78)
        print("[EMAIL NOT SENT] SMTP is not configured.")
        print("[EMAIL NOT SENT] Set SMTP_HOST, SMTP_USERNAME and SMTP_PASSWORD.")
        print(f"[EMAIL NOT SENT] Intended recipient: {to_email}")
        print("=" * 78)
        return False

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
            server.ehlo()
            if SMTP_USE_TLS:
                server.starttls()
                server.ehlo()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(MAIL_FROM, [to_email], msg.as_string())

        print(f"[EMAIL SENT] Email sent to {to_email}")
        return True

    except Exception as exc:
        print(f"[EMAIL ERROR] Failed to send email to {to_email}: {type(exc).__name__}: {exc}")
        return False


def send_email_verification_email(to_email, verification_url):
    subject = "Verify your Nairobi County E-Voting email"
    body = (
        "Hello,\n\n"
        "Thank you for registering on the Nairobi County E-Voting Platform.\n\n"
        "Please verify your email address by opening this link:\n\n"
        f"{verification_url}\n\n"
        f"This verification link expires in "
        f"{EMAIL_VERIFICATION_MAX_AGE_SECONDS // 3600} hours.\n\n"
        "If you did not create this account, you can safely ignore this email.\n\n"
        "— Nairobi County E-Voting Platform"
    )
    return send_email(to_email, subject, body)


def send_password_reset_email(to_email, reset_url):
    subject = "Reset your Nairobi County E-Voting password"
    body = (
        "Hello,\n\n"
        "We received a request to reset the password for your Nairobi County "
        "E-Voting account.\n\n"
        f"Reset your password using this link (expires in "
        f"{RESET_TOKEN_MAX_AGE_SECONDS // 60} minutes, and can only be used once):\n\n"
        f"{reset_url}\n\n"
        "If you did not request this, you can safely ignore this email — "
        "your password will remain unchanged.\n\n"
        "— Nairobi County E-Voting Platform"
    )
    return send_email(to_email, subject, body)


GENESIS_HASH = "0" * 64
NATIONAL_ID_REGEX = re.compile(r"^\d{7,8}$")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

CANDIDATE_SEED = [
    ("Maina Kamau", "Alliance for Renewal and Progress", "ARP"),
    ("Amina Hussein", "Green Development Party", "GDP"),
    ("Wycliffe Omondi", "National Economic Movement", "NEM"),
    ("Chepngetich Koech", "People's Democratic Coalition", "PDC"),
    ("Mutua Musyoka", "Unity and Justice Party", "UJP"),
]


# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    national_id = db.Column(db.String(8), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    has_voted = db.Column(db.Boolean, default=False, nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    email_verification_token = db.Column(db.String(500), unique=True, nullable=True)
    email_verification_expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)


class Candidate(db.Model):
    __tablename__ = "candidates"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    party = db.Column(db.String(200), nullable=False)
    abbreviation = db.Column(db.String(10), nullable=False)


class Vote(db.Model):
    __tablename__ = "votes"

    id = db.Column(db.Integer, primary_key=True)
    encrypted_vote = db.Column(db.Text, nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    current_hash = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PasswordResetToken(db.Model):
    __tablename__ = "password_reset_tokens"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    token = db.Column(db.String(500), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return User.query.get(uid)


def get_last_vote_hash():
    last = Vote.query.order_by(Vote.id.desc()).first()
    return last.current_hash if last else GENESIS_HASH


def compute_chain_hash(encrypted_vote_str, previous_hash):
    payload = encrypted_vote_str.encode("utf-8") + previous_hash.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def generate_csrf_token():
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(16)
    return session["_csrf_token"]


def validate_csrf():
    token_in_session = session.get("_csrf_token")
    token_in_form = request.form.get("csrf_token")
    if not token_in_session or not token_in_form or not secrets.compare_digest(
        token_in_session, token_in_form
    ):
        abort(400, description="Invalid or missing CSRF token.")


app.jinja_env.globals["csrf_token"] = generate_csrf_token


def seed_candidates():
    if Candidate.query.count() == 0:
        for name, party, abbr in CANDIDATE_SEED:
            db.session.add(Candidate(name=name, party=party, abbreviation=abbr))
        db.session.commit()
        print(f"[INFO] Seeded {len(CANDIDATE_SEED)} candidates.")


with app.app_context():
    db.create_all()
    seed_candidates()


# ----------------------------------------------------------------------------
# Templates (inline, single-file requirement)
# ----------------------------------------------------------------------------

BASE_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Nairobi County E-Voting{% endblock %}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    :root {
      --ink: #12233d;
      --ink-soft: #3c5170;
      --emerald: #0c8a5f;
      --emerald-dark: #096b49;
      --gold: #d9a441;
      --clay: #b3423a;
      --paper: #f7f5ef;
      --line: #e4e0d3;
    }
    * { box-sizing: border-box; }
    body {
      background: var(--paper);
      color: var(--ink);
      font-family: ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    a { color: var(--emerald-dark); }
    .navbar {
      background: var(--ink) !important;
      border-bottom: 3px solid var(--emerald);
    }
    .navbar-brand {
      font-weight: 700;
      letter-spacing: .2px;
      display: flex;
      align-items: center;
      gap: .5rem;
    }
    .brand-mark {
      width: 28px; height: 28px; flex-shrink: 0;
    }
    .btn-emerald {
      background: var(--emerald); border-color: var(--emerald); color: #fff;
    }
    .btn-emerald:hover { background: var(--emerald-dark); border-color: var(--emerald-dark); color:#fff; }
    .btn-outline-parchment {
      border-color: rgba(255,255,255,.5); color: #fff;
    }
    .btn-outline-parchment:hover { background: rgba(255,255,255,.12); color:#fff; }
    .card {
      border: 1px solid var(--line);
      box-shadow: 0 1px 3px rgba(18,35,61,.06);
      background: #fff;
    }
    .badge-valid { background: var(--emerald); }
    .badge-compromised { background: var(--clay); }
    footer { color: var(--ink-soft); font-size: .85rem; }
  </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark mb-4">
  <div class="container">
    <a class="navbar-brand" href="{{ url_for('home') }}">
      <svg class="brand-mark" viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="5" y="16" width="30" height="19" rx="1.5" fill="#0c8a5f"/>
        <rect x="5" y="16" width="30" height="4" fill="#096b49"/>
        <path d="M13 16 L20 6 L27 16 Z" fill="#d9a441"/>
        <rect x="17.5" y="21" width="5" height="9" rx="1" fill="#f7f5ef"/>
      </svg>
      Nairobi County E-Voting
    </a>
    <div class="d-flex gap-2">
      <a class="btn btn-outline-parchment btn-sm" href="{{ url_for('results') }}">Audit &amp; Results</a>
      {% if session.get('user_id') %}
        {% if not session.get('has_voted') %}
        <a class="btn btn-emerald btn-sm" href="{{ url_for('vote') }}">Cast Vote</a>
        {% endif %}
        <a class="btn btn-outline-parchment btn-sm" href="{{ url_for('logout') }}">Logout ({{ session.get('user_name') }})</a>
      {% else %}
        <a class="btn btn-outline-parchment btn-sm" href="{{ url_for('login') }}">Login</a>
        <a class="btn btn-emerald btn-sm" href="{{ url_for('register') }}">Register</a>
      {% endif %}
    </div>
  </div>
</nav>
<div class="container mb-5">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{ 'danger' if category=='danger' else category }} alert-dismissible fade show" role="alert">
          {{ message }}
          <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {% block content %}{% endblock %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

HOME_HTML = """
{% extends "base.html" %}
{% block content %}
<style>
  .hero {
    background: linear-gradient(135deg, #0f2a44 0%, #12233d 55%, #0c3a2e 100%);
    border-radius: 18px;
    color: #f7f5ef;
    overflow: hidden;
    position: relative;
  }
  .hero::before {
    content: "";
    position: absolute; inset: 0;
    background-image:
      radial-gradient(circle at 10% 20%, rgba(217,164,65,.10) 0, transparent 45%),
      radial-gradient(circle at 90% 80%, rgba(12,138,95,.18) 0, transparent 50%);
    pointer-events: none;
  }
  .hero-inner { position: relative; padding: 3.25rem 2.5rem; }
  .hero-eyebrow {
    display: inline-flex; align-items: center; gap: .5rem;
    font-size: .78rem; letter-spacing: .08em; text-transform: uppercase;
    color: #cfe3d9; background: rgba(255,255,255,.08);
    padding: .35rem .75rem; border-radius: 999px; margin-bottom: 1rem;
  }
  .hero-eyebrow .dot { width: 7px; height: 7px; border-radius: 50%; background: #4fd1a0; }
  .hero h1 { font-weight: 700; line-height: 1.15; }
  .hero p.lead { color: #d7ddea; }
  .hero-actions .btn { padding: .6rem 1.35rem; font-weight: 600; }

  .feature-icon {
    width: 46px; height: 46px; border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }
  .feature-icon.gold  { background: rgba(217,164,65,.14); }
  .feature-icon.green { background: rgba(12,138,95,.14); }
  .feature-icon.navy  { background: rgba(18,35,61,.10); }
  .feature-card { height: 100%; padding: 1.5rem; border-radius: 14px; }
  .feature-title { font-weight: 700; margin: .85rem 0 .4rem; }
  .feature-text { color: #4a5568; font-size: .95rem; margin-bottom: 0; }

  .stat-strip {
    border-radius: 14px; background: #fff; border: 1px solid var(--line);
    padding: 1.25rem 1.5rem;
  }
</style>

<div class="hero mb-4">
  <div class="hero-inner row align-items-center g-4">
    <div class="col-lg-7">
      <span class="hero-eyebrow"><span class="dot"></span> Nairobi County &middot; Gubernatorial Election</span>
      <h1 class="display-6">Vote with confidence. Verify with proof.</h1>
      <p class="lead mt-3">
        A digital ballot box built so that no single vote can be read in the clear,
        and no single record can be quietly altered — every ballot locks into the
        one cast before it, forming a chain anyone can check.
      </p>
      <div class="hero-actions d-flex flex-wrap gap-2 mt-4">
        {% if not session.get('user_id') %}
        <a href="{{ url_for('register') }}" class="btn btn-emerald btn-lg">Register to Vote</a>
        <a href="{{ url_for('login') }}" class="btn btn-outline-parchment btn-lg">Login</a>
        {% else %}
          {% if not session.get('has_voted') %}
          <a href="{{ url_for('vote') }}" class="btn btn-emerald btn-lg">Cast Your Vote</a>
          {% endif %}
        {% endif %}
        <a href="{{ url_for('results') }}" class="btn btn-outline-parchment btn-lg">View Live Audit</a>
      </div>
    </div>
    <div class="col-lg-5 text-center">
      <svg viewBox="0 0 320 280" width="100%" height="auto" style="max-width:320px" xmlns="http://www.w3.org/2000/svg">
        <ellipse cx="160" cy="248" rx="110" ry="14" fill="#000" opacity=".18"/>
        <rect x="70" y="120" width="180" height="110" rx="10" fill="#0c8a5f"/>
        <rect x="70" y="120" width="180" height="26" rx="10" fill="#0a6e4c"/>
        <rect x="140" y="98" width="40" height="28" rx="4" fill="#0a6e4c"/>
        <rect x="145" y="150" width="30" height="55" rx="4" fill="#f7f5ef"/>
        <path d="M96 92 L160 40 L224 92 Z" fill="#d9a441"/>
        <path d="M96 92 L160 40 L160 92 Z" fill="#c79333"/>
        <g>
          <rect x="180" y="6" width="46" height="64" rx="4" fill="#fff" stroke="#12233d" stroke-width="2.5" transform="rotate(-12 203 38)"/>
          <path d="M191 34 L201 44 L219 22" stroke="#0c8a5f" stroke-width="4" fill="none" stroke-linecap="round" stroke-linejoin="round" transform="rotate(-12 203 38)"/>
        </g>
        <circle cx="60" cy="70" r="5" fill="#d9a441" opacity=".8"/>
        <circle cx="255" cy="160" r="4" fill="#f7f5ef" opacity=".7"/>
        <circle cx="245" cy="60" r="3" fill="#d9a441" opacity=".6"/>
      </svg>
    </div>
  </div>
</div>

<div class="row g-3 mb-4">
  <div class="col-md-4">
    <div class="feature-card card">
      <div class="feature-icon green">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect x="5" y="10" width="14" height="10" rx="2" stroke="#0c8a5f" stroke-width="2"/>
          <path d="M8 10V7a4 4 0 018 0v3" stroke="#0c8a5f" stroke-width="2" stroke-linecap="round"/>
          <circle cx="12" cy="15" r="1.6" fill="#0c8a5f"/>
        </svg>
      </div>
      <div class="feature-title">Sealed the moment you vote</div>
      <p class="feature-text">
        Your ballot choice is encrypted with AES before it ever touches the database.
        Not even a system administrator can open an individual vote and see who you chose.
      </p>
    </div>
  </div>
  <div class="col-md-4">
    <div class="feature-card card">
      <div class="feature-icon gold">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect x="3" y="8" width="8" height="8" rx="3" stroke="#c79333" stroke-width="2"/>
          <rect x="13" y="8" width="8" height="8" rx="3" stroke="#c79333" stroke-width="2"/>
          <path d="M11 12h2" stroke="#c79333" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </div>
      <div class="feature-title">Linked to every vote before it</div>
      <p class="feature-text">
        Each new ballot is fused with a SHA-256 fingerprint of the previous one. Change or
        delete a single past vote, and every link after it breaks — instantly and visibly.
      </p>
    </div>
  </div>
  <div class="col-md-4">
    <div class="feature-card card">
      <div class="feature-icon navy">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6l7-3z" stroke="#12233d" stroke-width="2" stroke-linejoin="round"/>
          <path d="M9 12l2 2 4-4" stroke="#0c8a5f" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </div>
      <div class="feature-title">Open to independent scrutiny</div>
      <p class="feature-text">
        The <a href="{{ url_for('results') }}">Audit &amp; Results</a> page walks the entire
        chain in the open — anyone can confirm the tally is genuine, without needing to trust
        us on our word.
      </p>
    </div>
  </div>
</div>
{% endblock %}
"""

REGISTER_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-6">
    <div class="card">
      <div class="card-body p-4">
        <h3 class="mb-3">Voter Registration</h3>
        <p class="text-muted small">A verification link will be sent to your email address after registration.</p>
        <form method="POST" novalidate>
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <div class="mb-3">
            <label class="form-label">Full Name</label>
            <input type="text" class="form-control" name="full_name" required value="{{ full_name or '' }}">
          </div>
          <div class="mb-3">
            <label class="form-label">Email</label>
            <input type="email" class="form-control" name="email" required value="{{ email or '' }}">
          </div>
          <div class="mb-3">
            <label class="form-label">Kenya National ID (7-8 digits)</label>
            <input type="text" class="form-control" name="national_id" pattern="\\d{7,8}" required value="{{ national_id or '' }}">
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input type="password" class="form-control" name="password" minlength="8" required>
          </div>
          <button type="submit" class="btn btn-primary w-100">Register</button>
        </form>
        <p class="mt-3 mb-0">Already registered? <a href="{{ url_for('login') }}">Login here</a>.</p>
      </div>
    </div>
  </div>
</div>
{% endblock %}
"""

LOGIN_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <div class="card">
      <div class="card-body p-4">
        <h3 class="mb-3">Voter Login</h3>
        <form method="POST">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <div class="mb-3">
            <label class="form-label">Email or National ID</label>
            <input type="text" class="form-control" name="identifier" required autofocus>
          </div>
          <div class="mb-3">
            <label class="form-label">Password</label>
            <input type="password" class="form-control" name="password" required>
          </div>
          <button type="submit" class="btn btn-primary w-100">Login</button>
        </form>
        <p class="mt-3 mb-1"><a href="{{ url_for('forgot_password') }}">Forgot password?</a></p>
        <p class="mb-0"><a href="{{ url_for('resend_verification') }}">Resend verification email</a></p>
      </div>
    </div>
  </div>
</div>
{% endblock %}
"""

FORGOT_PASSWORD_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <div class="card">
      <div class="card-body p-4">
        <h3 class="mb-3">Forgot Password</h3>
        <p class="text-muted small">
          Enter the email you registered with. If an account exists for it, we'll
          send a secure reset link that expires in 15 minutes and can only be used once.
        </p>
        <form method="POST">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <div class="mb-3">
            <label class="form-label">Registered Email</label>
            <input type="email" class="form-control" name="email" required autofocus>
          </div>
          <button type="submit" class="btn btn-primary w-100">Send Reset Link</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
"""

RESET_PASSWORD_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-5">
    <div class="card">
      <div class="card-body p-4">
        <h3 class="mb-3">Reset Password</h3>
        <form method="POST">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <div class="mb-3">
            <label class="form-label">New Password</label>
            <input type="password" class="form-control" name="password" minlength="8" required autofocus>
          </div>
          <div class="mb-3">
            <label class="form-label">Confirm New Password</label>
            <input type="password" class="form-control" name="confirm_password" minlength="8" required>
          </div>
          <button type="submit" class="btn btn-primary w-100">Reset Password</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
"""

VOTE_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-md-7">
    <div class="card">
      <div class="card-body p-4">
        <h3 class="mb-1">Cast Your Ballot</h3>
        <p class="text-muted">Nairobi County Gubernatorial Election &mdash; select exactly one candidate.</p>
        <form method="POST">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          {% for c in candidates %}
          <div class="form-check border rounded p-3 mb-2">
            <input class="form-check-input" type="radio" name="candidate_id" id="cand{{ c.id }}" value="{{ c.id }}" required>
            <label class="form-check-label w-100" for="cand{{ c.id }}">
              <strong>{{ c.name }}</strong><br>
              <span class="text-muted">{{ c.party }} ({{ c.abbreviation }})</span>
            </label>
          </div>
          {% endfor %}
          <button type="submit" class="btn btn-success w-100 mt-3">Encrypt &amp; Submit Vote</button>
        </form>
      </div>
    </div>
  </div>
</div>
{% endblock %}
"""

RESULTS_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="card mb-4">
  <div class="card-body p-4">
    <h3 class="mb-3">Audit &amp; Results Dashboard</h3>
    <p>
      Hash Chain Integrity Status:
      {% if chain_valid %}
        <span class="badge badge-valid">VALID</span>
      {% else %}
        <span class="badge badge-compromised">COMPROMISED</span>
      {% endif %}
    </p>
    <p class="text-muted small mb-0">
      Total votes recorded: {{ total_votes }} &mdash;
      Verified before {{ 'a break was detected' if not chain_valid else 'reaching the end of the ledger' }}: {{ verified_count }}
    </p>
    {% if not chain_valid %}
    <div class="alert alert-danger mt-3 mb-0">
      Tampering detected at vote ID <strong>{{ break_point }}</strong>. Tally below only reflects
      votes verified up to that point.
    </div>
    {% endif %}
  </div>
</div>

<div class="card">
  <div class="card-body p-4">
    <h4 class="mb-3">Vote Tally</h4>
    <table class="table table-striped">
      <thead>
        <tr><th>Candidate</th><th>Party</th><th>Votes</th></tr>
      </thead>
      <tbody>
        {% for c in candidates %}
        <tr>
          <td>{{ c.name }}</td>
          <td>{{ c.party }} ({{ c.abbreviation }})</td>
          <td><strong>{{ tally.get(c.id, 0) }}</strong></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}
"""

app.jinja_loader = DictLoader({
    "base.html": BASE_HTML,
    "home.html": HOME_HTML,
    "register.html": REGISTER_HTML,
    "login.html": LOGIN_HTML,
    "forgot_password.html": FORGOT_PASSWORD_HTML,
    "reset_password.html": RESET_PASSWORD_HTML,
    "vote.html": VOTE_HTML,
    "results.html": RESULTS_HTML,
})


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template_string(HOME_HTML)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        validate_csrf()

        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        national_id = request.form.get("national_id", "").strip()
        password = request.form.get("password", "")

        errors = []
        if not full_name:
            errors.append("Full name is required.")
        if not EMAIL_REGEX.match(email):
            errors.append("A valid email address is required.")
        if not NATIONAL_ID_REGEX.match(national_id):
            errors.append("National ID must be 7 to 8 numeric digits.")
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long.")

        if not errors:
            if User.query.filter_by(email=email).first():
                errors.append("An account with this email already exists.")
            if User.query.filter_by(national_id=national_id).first():
                errors.append("This National ID is already registered (one voter, one registration).")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template_string(
                REGISTER_HTML,
                full_name=full_name,
                email=email,
                national_id=national_id
            )

        verification_token = secrets.token_urlsafe(48)
        user = User(
            full_name=full_name,
            email=email,
            national_id=national_id,
            email_verified=False,
            email_verification_token=verification_token,
            email_verification_expires_at=datetime.utcnow()
            + timedelta(seconds=EMAIL_VERIFICATION_MAX_AGE_SECONDS)
        )
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Email or National ID already registered.", "danger")
            return render_template_string(
                REGISTER_HTML,
                full_name=full_name,
                email=email,
                national_id=national_id
            )

        verification_url = url_for(
            "verify_email",
            token=verification_token,
            _external=True
        )

        if send_email_verification_email(user.email, verification_url):
            flash(
                "Registration successful. Please check your email and click the "
                "verification link before logging in.",
                "success"
            )
        else:
            # Keep the account unverified if the mail server is unavailable.
            # This prevents an unverified account from being used.
            flash(
                "Your registration was created, but the verification email could "
                "not be sent. Please use the resend verification option.",
                "warning"
            )

        return redirect(url_for("login"))

    return render_template_string(REGISTER_HTML)


@app.route("/verify-email/<token>")
def verify_email(token):
    user = User.query.filter_by(email_verification_token=token).first()

    if not user:
        flash("This email verification link is invalid.", "danger")
        return redirect(url_for("login"))

    if user.email_verified:
        flash("Your email address has already been verified. You may log in.", "info")
        return redirect(url_for("login"))

    if (
        not user.email_verification_expires_at
        or user.email_verification_expires_at < datetime.utcnow()
    ):
        flash(
            "This email verification link has expired. Please request a new one.",
            "danger"
        )
        return redirect(url_for("resend_verification"))

    user.email_verified = True
    user.email_verification_token = None
    user.email_verification_expires_at = None
    db.session.commit()

    flash("Email verified successfully. You may now log in.", "success")
    return redirect(url_for("login"))


@app.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    if request.method == "POST":
        validate_csrf()
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()

        if user and not user.email_verified:
            token = secrets.token_urlsafe(48)
            user.email_verification_token = token
            user.email_verification_expires_at = (
                datetime.utcnow()
                + timedelta(seconds=EMAIL_VERIFICATION_MAX_AGE_SECONDS)
            )
            db.session.commit()

            verification_url = url_for(
                "verify_email",
                token=token,
                _external=True
            )
            send_email_verification_email(user.email, verification_url)

        # Generic response to avoid revealing whether an account exists.
        flash(
            "If an unverified account exists for that email, a new verification "
            "link has been sent.",
            "info"
        )
        return redirect(url_for("login"))

    resend_html = """
    {% extends "base.html" %}
    {% block content %}
    <div class="row justify-content-center">
      <div class="col-md-5">
        <div class="card">
          <div class="card-body p-4">
            <h3 class="mb-3">Resend Verification Email</h3>
            <p class="text-muted small">
              Enter the email address you used during registration.
            </p>
            <form method="POST">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
              <div class="mb-3">
                <label class="form-label">Registered Email</label>
                <input type="email" class="form-control" name="email" required autofocus>
              </div>
              <button type="submit" class="btn btn-primary w-100">
                Resend Verification Link
              </button>
            </form>
          </div>
        </div>
      </div>
    </div>
    {% endblock %}
    """
    return render_template_string(resend_html)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        validate_csrf()
        identifier = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")

        user = User.query.filter(
            (db.func.lower(User.email) == identifier) | (User.national_id == identifier)
        ).first()

        if not user or not user.check_password(password):
            flash("Invalid credentials.", "danger")
            return render_template_string(LOGIN_HTML)

        if not user.email_verified:
            flash(
                "Please verify your email address before logging in. "
                "You can request a new verification link if needed.",
                "warning"
            )
            return redirect(url_for("resend_verification"))

        session.clear()
        session["user_id"] = user.id
        session["user_name"] = user.full_name
        session["has_voted"] = user.has_voted

        flash(f"Welcome, {user.full_name}.", "success")
        if user.has_voted:
            flash("Our records show you have already voted. Duplicate voting is blocked.", "info")
            return redirect(url_for("results"))
        return redirect(url_for("vote"))

    return render_template_string(LOGIN_HTML)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        validate_csrf()
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first()

        if user:
            token = serializer.dumps(
                {"email": user.email, "nonce": secrets.token_urlsafe(16)},
                salt=RESET_SALT
            )
            expires_at = datetime.utcnow() + timedelta(seconds=RESET_TOKEN_MAX_AGE_SECONDS)

            # Invalidate any previous outstanding tokens for this user.
            PasswordResetToken.query.filter_by(
                user_id=user.id, used=False
            ).update({"used": True})

            db.session.add(PasswordResetToken(
                user_id=user.id,
                token=token,
                expires_at=expires_at
            ))
            db.session.commit()

            reset_url = url_for(
                "reset_password",
                token=token,
                _external=True
            )
            send_password_reset_email(user.email, reset_url)

        # Always show the same generic message to prevent user enumeration
        flash(
            "If that email is registered, a password reset link has been sent to it. "
            f"The link expires in {RESET_TOKEN_MAX_AGE_SECONDS // 60} minutes.",
            "info",
        )
        return redirect(url_for("login"))

    return render_template_string(FORGOT_PASSWORD_HTML)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        token_data = serializer.loads(
            token,
            salt=RESET_SALT,
            max_age=RESET_TOKEN_MAX_AGE_SECONDS
        )
        email = token_data.get("email") if isinstance(token_data, dict) else token_data
        if not isinstance(email, str):
            raise BadSignature("Invalid token payload")
    except SignatureExpired:
        flash("This reset link has expired. Please request a new one.", "danger")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("This reset link is invalid.", "danger")
        return redirect(url_for("forgot_password"))

    record = PasswordResetToken.query.filter_by(token=token).first()
    if not record or record.used or record.expires_at < datetime.utcnow():
        flash("This reset link is invalid or has already been used.", "danger")
        return redirect(url_for("forgot_password"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Account not found.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        validate_csrf()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", "danger")
            return render_template_string(RESET_PASSWORD_HTML)
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template_string(RESET_PASSWORD_HTML)

        user.set_password(password)
        record.used = True
        db.session.commit()

        flash("Password reset successful. You may now log in.", "success")
        return redirect(url_for("login"))

    return render_template_string(RESET_PASSWORD_HTML)


@app.route("/vote", methods=["GET", "POST"])
@login_required
def vote():
    user = current_user()
    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if user.has_voted:
        flash("You have already cast your vote. Duplicate voting is not permitted.", "warning")
        return redirect(url_for("results"))

    candidates = Candidate.query.order_by(Candidate.id).all()

    if request.method == "POST":
        validate_csrf()

        # Re-check DB state right before writing, to close the race window
        # between page render and submission (defence in depth).
        fresh_user = User.query.get(user.id)
        if fresh_user.has_voted:
            flash("You have already cast your vote.", "warning")
            return redirect(url_for("results"))

        try:
            candidate_id = int(request.form.get("candidate_id", ""))
        except (TypeError, ValueError):
            flash("Please select a valid candidate.", "danger")
            return render_template_string(VOTE_HTML, candidates=candidates)

        candidate = Candidate.query.get(candidate_id)
        if not candidate:
            flash("Please select a valid candidate.", "danger")
            return render_template_string(VOTE_HTML, candidates=candidates)

        ballot_payload = json.dumps({
            "candidate_id": candidate.id,
            "cast_at": datetime.utcnow().isoformat(),
            "nonce": secrets.token_hex(8),  # prevents identical ciphertexts for same candidate
        })
        encrypted_bytes = fernet.encrypt(ballot_payload.encode("utf-8"))
        encrypted_str = encrypted_bytes.decode("utf-8")

        previous_hash = get_last_vote_hash()
        current_hash = compute_chain_hash(encrypted_str, previous_hash)

        new_vote = Vote(
            encrypted_vote=encrypted_str,
            previous_hash=previous_hash,
            current_hash=current_hash,
        )

        try:
            db.session.add(new_vote)
            fresh_user.has_voted = True
            db.session.commit()
        except Exception:
            db.session.rollback()
            flash("An error occurred while recording your vote. Please try again.", "danger")
            return render_template_string(VOTE_HTML, candidates=candidates)

        session["has_voted"] = True
        flash("Your vote was encrypted, hash-chained, and recorded successfully.", "success")
        return redirect(url_for("results"))

    return render_template_string(VOTE_HTML, candidates=candidates)


@app.route("/results")
def results():
    candidates = Candidate.query.order_by(Candidate.id).all()
    votes = Vote.query.order_by(Vote.id.asc()).all()

    tally = {c.id: 0 for c in candidates}
    previous_hash = GENESIS_HASH
    chain_valid = True
    verified_count = 0
    break_point = None

    for v in votes:
        expected_hash = compute_chain_hash(v.encrypted_vote, previous_hash)

        if v.previous_hash != previous_hash or v.current_hash != expected_hash:
            chain_valid = False
            break_point = v.id
            break

        try:
            decrypted = fernet.decrypt(v.encrypted_vote.encode("utf-8"))
            data = json.loads(decrypted.decode("utf-8"))
            cand_id = data.get("candidate_id")
            if cand_id in tally:
                tally[cand_id] += 1
        except (InvalidToken, ValueError, json.JSONDecodeError):
            chain_valid = False
            break_point = v.id
            break

        verified_count += 1
        previous_hash = v.current_hash

    return render_template_string(
        RESULTS_HTML,
        candidates=candidates,
        tally=tally,
        chain_valid=chain_valid,
        total_votes=len(votes),
        verified_count=verified_count,
        break_point=break_point,
    )


# ----------------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
