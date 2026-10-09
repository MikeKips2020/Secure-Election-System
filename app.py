"""
Kenya Multi-Level Secure E-Voting Prototype — Advanced V3.1
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
import base64
import hashlib
import secrets
import urllib.request
import urllib.error
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
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

# ----------------------------------------------------------------------------
# App & configuration
# ----------------------------------------------------------------------------

app = Flask(__name__)

_database_url = os.environ.get("DATABASE_URL", "sqlite:///evoting.db")
_is_production = bool(os.environ.get("RENDER") or _database_url.startswith(("postgres://", "postgresql://")))
_secret_key = os.environ.get("SECRET_KEY")
if _is_production and not _secret_key:
    raise RuntimeError("SECRET_KEY must be configured as a persistent environment variable in production.")
app.secret_key = _secret_key or secrets.token_hex(32)

# Render may supply postgres:// or postgresql://.
# requirements.txt installs psycopg2-binary, so explicitly tell SQLAlchemy
# to use the psycopg2 driver rather than SQLAlchemy 2.1's psycopg default.
if _database_url.startswith("postgres://"):
    _database_url = _database_url.replace(
        "postgres://", "postgresql+psycopg2://", 1
    )
elif _database_url.startswith("postgresql://"):
    _database_url = _database_url.replace(
        "postgresql://", "postgresql+psycopg2://", 1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = _database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# --- AES (Fernet) key setup --------------------------------------------------
_AES_KEY = os.environ.get("AES_KEY")
if not _AES_KEY:
    if _is_production:
        raise RuntimeError("AES_KEY must be configured persistently in production; refusing to risk undecryptable ballots.")
    _AES_KEY = Fernet.generate_key().decode()
    print("[DEV WARNING] AES_KEY is temporary. Do not use this local fallback for deployed voting data.")

fernet = Fernet(_AES_KEY.encode() if isinstance(_AES_KEY, str) else _AES_KEY)

# --- Password reset token serializer ----------------------------------------
serializer = URLSafeTimedSerializer(app.secret_key)
RESET_SALT = "password-reset-salt"
RESET_TOKEN_MAX_AGE_SECONDS = 900  # 15 minutes

# --- Email API configuration --------------------------------------------------
# Render Free web services block outbound SMTP ports 25, 465 and 587, so this
# application uses the Resend HTTPS API instead of SMTP.
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
MAIL_FROM = os.environ.get("MAIL_FROM", "onboarding@resend.dev")
MAIL_FROM_NAME = os.environ.get("MAIL_FROM_NAME", "Kenya Secure E-Voting")
EMAIL_VERIFICATION_MAX_AGE_SECONDS = 86400  # 24 hours


def send_email(to_email, subject, html_body, tag):
    """Send an email through the Resend HTTPS API.

    HTTPS works from Render Free because it does not use the blocked SMTP
    ports. No extra Python email package is required.
    """
    if not RESEND_API_KEY:
        print("[EMAIL NOT SENT] RESEND_API_KEY is not configured.")
        print(f"[EMAIL NOT SENT] Intended recipient: {to_email}")
        return False

    payload = json.dumps({
        "from": f"{MAIL_FROM_NAME} <{MAIL_FROM}>",
        "to": [to_email],
        "subject": subject,
        "html": html_body,
        "tags": [{"name": "category", "value": tag}],
    }).encode("utf-8")

    request = urllib.request.Request(
        "https://api.resend.com/emails",
        data=payload,
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
            "User-Agent": "Kenya-Secure-EVoting/3.1.1-RC2",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            response_body = response.read().decode("utf-8")
            print(f"[EMAIL SENT] {tag} email sent to {to_email}: {response_body}")
            return 200 <= response.status < 300
    except urllib.error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        print(f"[EMAIL ERROR] Resend HTTP {exc.code}: {details}")
        return False
    except Exception as exc:
        print(f"[EMAIL ERROR] Failed to send {tag} email to {to_email}: {type(exc).__name__}: {exc}")
        return False


def send_email_verification_email(to_email, verification_url):
    subject = "Verify your Kenya Secure E-Voting email"
    html = f"""
    <html><body>
      <h2>Verify your email address</h2>
      <p>Thank you for registering on the Kenya Secure E-Voting Platform.</p>
      <p>Please click the button below to verify your email address:</p>
      <p><a href="{verification_url}" style="display:inline-block;padding:12px 18px;background:#0c8a5f;color:white;text-decoration:none;border-radius:6px;">Verify Email Address</a></p>
      <p>This link expires in 24 hours.</p>
      <p>If you did not create this account, you can safely ignore this email.</p>
      <p>— Kenya Secure E-Voting Platform</p>
    </body></html>
    """
    return send_email(to_email, subject, html, "email_verification")


def send_password_reset_email(to_email, reset_url):
    subject = "Reset your Kenya Secure E-Voting password"
    html = f"""
    <html><body>
      <h2>Password reset request</h2>
      <p>We received a request to reset the password for your Kenya Secure E-Voting account.</p>
      <p><a href="{reset_url}" style="display:inline-block;padding:12px 18px;background:#0c8a5f;color:white;text-decoration:none;border-radius:6px;">Reset Password</a></p>
      <p>This link expires in 15 minutes and can only be used once.</p>
      <p>If you did not request this, you can safely ignore this email.</p>
      <p>— Kenya Secure E-Voting Platform</p>
    </body></html>
    """
    return send_email(to_email, subject, html, "password_reset")


GENESIS_HASH = "0" * 64
NATIONAL_ID_REGEX = re.compile(r"^\d{7,8}$")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip().lower()
ELECTION_DEFAULT_TITLE = os.environ.get(
    "ELECTION_TITLE", "Kenya General Election"
)

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
    role = db.Column(db.String(20), default="voter", nullable=False)
    region_id = db.Column(db.Integer, nullable=True)
    constituency_id = db.Column(db.Integer, nullable=True)
    ward_id = db.Column(db.Integer, nullable=True)
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
    candidate_number = db.Column(db.String(20), nullable=True)
    manifesto = db.Column(db.Text, nullable=True)
    photo_data = db.Column(db.Text, nullable=True)
    party_symbol_data = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="active")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Region(db.Model):
    __tablename__ = "regions"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False, unique=True)
    code = db.Column(db.String(30), nullable=True, unique=True)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Constituency(db.Model):
    __tablename__ = "constituencies"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False)
    county_id = db.Column(db.Integer, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)

class Ward(db.Model):
    __tablename__ = "wards"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(140), nullable=False)
    constituency_id = db.Column(db.Integer, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)

class Contest(db.Model):
    __tablename__ = "contests"
    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, default=1, nullable=False)
    position = db.Column(db.String(50), nullable=False)
    scope_level = db.Column(db.String(30), nullable=False)
    county_id = db.Column(db.Integer, nullable=True)
    constituency_id = db.Column(db.Integer, nullable=True)
    ward_id = db.Column(db.Integer, nullable=True)
    active = db.Column(db.Boolean, default=True, nullable=False)

class ContestCandidate(db.Model):
    __tablename__ = "contest_candidates"
    id = db.Column(db.Integer, primary_key=True)
    contest_id = db.Column(db.Integer, nullable=False)
    candidate_id = db.Column(db.Integer, nullable=False)

class BallotReceipt(db.Model):
    __tablename__ = "ballot_receipts"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    contest_id = db.Column(db.Integer, nullable=False)
    cast_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "contest_id", name="uq_voter_contest"),)

class Vote(db.Model):
    __tablename__ = "votes"

    id = db.Column(db.Integer, primary_key=True)
    encrypted_vote = db.Column(db.Text, nullable=False)
    previous_hash = db.Column(db.String(64), nullable=False)
    current_hash = db.Column(db.String(64), nullable=False)
    key_version = db.Column(db.String(40), default="v1", nullable=False)
    region_id = db.Column(db.Integer, nullable=True)
    election_id = db.Column(db.Integer, nullable=False, default=1)
    contest_id = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ElectionSetting(db.Model):
    __tablename__ = "election_settings"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False, default=ELECTION_DEFAULT_TITLE)
    is_open = db.Column(db.Boolean, default=True, nullable=False)
    results_visible = db.Column(db.Boolean, default=True, nullable=False)
    opens_at = db.Column(db.DateTime, nullable=True)
    closes_at = db.Column(db.DateTime, nullable=True)
    election_type = db.Column(db.String(30), nullable=False, default="general")
    election_date = db.Column(db.Date, nullable=True)
    is_current = db.Column(db.Boolean, nullable=False, default=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuditEvent(db.Model):
    __tablename__ = "audit_events"

    id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(80), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default="INFO")
    user_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class AuditViewState(db.Model):
    __tablename__ = "audit_view_states"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False, unique=True)
    cleared_through_id = db.Column(db.Integer, nullable=False, default=0)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


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


# Expose the authenticated database user to every Jinja template.
# The navbar therefore reads the current role from the database rather than
# relying on a possibly stale role value in the browser session.
app.jinja_env.globals["current_user"] = current_user


def voter_area(user):
    """Return display names for the authenticated voter's electoral area."""
    if not user:
        return {"county": "Not assigned", "constituency": "Not assigned", "ward": "Not assigned"}
    county = db.session.get(Region, user.region_id) if user.region_id else None
    constituency = db.session.get(Constituency, user.constituency_id) if user.constituency_id else None
    ward = db.session.get(Ward, user.ward_id) if user.ward_id else None
    return {
        "county": county.name if county else "Not assigned",
        "constituency": constituency.name if constituency else "Not assigned",
        "ward": ward.name if ward else "Not assigned",
    }


app.jinja_env.globals["voter_area"] = voter_area


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        if user.role != "admin":
            log_event("UNAUTHORIZED_ADMIN_ACCESS", "WARNING", user.id,
                      f"Attempted access to {request.path}")
            flash("Administrator access is required.", "danger")
            return redirect(url_for("home"))
        return view(*args, **kwargs)
    return wrapped


def log_event(event_type, severity="INFO", user_id=None, details=None):
    try:
        db.session.add(AuditEvent(
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            details=(details or "")[:2000]
        ))
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        print(f"[AUDIT ERROR] {event_type}: {exc}")


def get_election():
    # RC7: one explicitly selected current election; preserve the original row on upgrade.
    election = ElectionSetting.query.filter_by(is_current=True).order_by(ElectionSetting.id.desc()).first()
    if not election:
        election = ElectionSetting.query.order_by(ElectionSetting.id.asc()).first()
        if not election:
            election = ElectionSetting(title=ELECTION_DEFAULT_TITLE, is_open=True, results_visible=False, election_type="general", is_current=True)
            db.session.add(election)
        else:
            election.is_current = True
        db.session.commit()
    return election


def election_is_open(election=None):
    election = election or get_election()
    now = datetime.utcnow()
    if not election.is_open:
        return False
    if election.opens_at and now < election.opens_at:
        return False
    if election.closes_at and now >= election.closes_at:
        return False
    return True


def get_last_vote_hash():
    last = Vote.query.order_by(Vote.id.desc()).first()
    return last.current_hash if last else GENESIS_HASH


def compute_chain_hash(encrypted_vote_str, previous_hash):
    payload = encrypted_vote_str.encode("utf-8") + previous_hash.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def eligible_contests_for(user):
    """Return active contests this voter is entitled to participate in."""
    if not user or user.role == "admin":
        return []
    q = Contest.query.filter_by(active=True, election_id=get_election().id)
    contests = []
    for c in q.order_by(Contest.id).all():
        if c.scope_level == "national":
            contests.append(c)
        elif c.scope_level == "county" and user.region_id and c.county_id == user.region_id:
            contests.append(c)
        elif c.scope_level == "constituency" and user.constituency_id and c.constituency_id == user.constituency_id:
            contests.append(c)
        elif c.scope_level == "ward" and user.ward_id and c.ward_id == user.ward_id:
            contests.append(c)
    return contests


def candidates_for_contest(contest_id):
    links = ContestCandidate.query.filter_by(contest_id=contest_id).all()
    ids = [x.candidate_id for x in links]
    if not ids:
        return []
    return Candidate.query.filter(Candidate.id.in_(ids), Candidate.status == "active").order_by(Candidate.id).all()


def registered_voters_for_contest(contest):
    q = User.query.filter(User.role != "admin")
    if contest.scope_level == "county": q = q.filter(User.region_id == contest.county_id)
    elif contest.scope_level == "constituency": q = q.filter(User.constituency_id == contest.constituency_id)
    elif contest.scope_level == "ward": q = q.filter(User.ward_id == contest.ward_id)
    return q.count()


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


def migrate_database():
    """Safely add email-verification fields to an existing database.

    This runs automatically when the app starts, so a Render Free service does
    not need the paid Pre-Deploy Command feature. Existing users are marked as
    verified only when the email_verified column is being introduced; new users
    are created as unverified and must verify their email.
    """
    inspector = inspect(db.engine)
    tables = inspector.get_table_names()

    if "users" not in tables:
        # db.create_all() below will create the complete current schema.
        return

    existing_columns = {column["name"] for column in inspector.get_columns("users")}
    email_verified_was_added = False

    with db.engine.begin() as connection:
        if "email_verified" not in existing_columns:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE"
            ))
            email_verified_was_added = True

        if "email_verification_token" not in existing_columns:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN email_verification_token VARCHAR(500)"
            ))

        if "email_verification_expires_at" not in existing_columns:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN email_verification_expires_at TIMESTAMP"
            ))

        if "role" not in existing_columns:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'voter'"
            ))
        if "region_id" not in existing_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN region_id INTEGER"))
        if "constituency_id" not in existing_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN constituency_id INTEGER"))
        if "ward_id" not in existing_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN ward_id INTEGER"))

        connection.execute(text("""
            CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email_verification_token
            ON users (email_verification_token)
        """))

        # Existing accounts were registered before email verification existed.
        # Keep those accounts usable; only newly registered accounts require
        # verification. This runs only on the first introduction of the field.
        if email_verified_was_added:
            connection.execute(text(
                "UPDATE users SET email_verified = TRUE WHERE email_verified = FALSE"
            ))

    # Version 2.1 additive schema upgrades. Existing ballots are never rewritten.
    inspector = inspect(db.engine)
    if "votes" in inspector.get_table_names():
        vote_columns = {column["name"] for column in inspector.get_columns("votes")}
        with db.engine.begin() as connection:
            if "key_version" not in vote_columns:
                connection.execute(text(
                    "ALTER TABLE votes ADD COLUMN key_version VARCHAR(40) NOT NULL DEFAULT 'legacy'"
                ))
            if "region_id" not in vote_columns:
                connection.execute(text("ALTER TABLE votes ADD COLUMN region_id INTEGER"))
            if "election_id" not in vote_columns:
                connection.execute(text(
                    "ALTER TABLE votes ADD COLUMN election_id INTEGER NOT NULL DEFAULT 1"
                ))
            if "contest_id" not in vote_columns:
                connection.execute(text("ALTER TABLE votes ADD COLUMN contest_id INTEGER"))

    inspector = inspect(db.engine)
    if "candidates" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("candidates")}
        with db.engine.begin() as connection:
            if "candidate_number" not in cols:
                connection.execute(text("ALTER TABLE candidates ADD COLUMN candidate_number VARCHAR(20)"))
            if "manifesto" not in cols:
                connection.execute(text("ALTER TABLE candidates ADD COLUMN manifesto TEXT"))
            if "status" not in cols:
                connection.execute(text(
                    "ALTER TABLE candidates ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'active'"
                ))
            if "created_at" not in cols:
                connection.execute(text("ALTER TABLE candidates ADD COLUMN created_at TIMESTAMP"))
            if "photo_data" not in cols:
                connection.execute(text("ALTER TABLE candidates ADD COLUMN photo_data TEXT"))
            if "party_symbol_data" not in cols:
                connection.execute(text("ALTER TABLE candidates ADD COLUMN party_symbol_data TEXT"))

    inspector = inspect(db.engine)
    if "election_settings" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("election_settings")}
        with db.engine.begin() as connection:
            if "election_type" not in cols:
                connection.execute(text("ALTER TABLE election_settings ADD COLUMN election_type VARCHAR(30) NOT NULL DEFAULT 'general'"))
            if "election_date" not in cols:
                connection.execute(text("ALTER TABLE election_settings ADD COLUMN election_date DATE"))
            if "is_current" not in cols:
                connection.execute(text("ALTER TABLE election_settings ADD COLUMN is_current BOOLEAN NOT NULL DEFAULT FALSE"))
                connection.execute(text("UPDATE election_settings SET is_current = TRUE WHERE id = (SELECT MIN(id) FROM election_settings)"))

    print("[INFO] Automatic database migration for Advanced Version 3.1.1 RC9 completed.")



def seed_regions():
    """Seed Kenya's 47 counties without altering existing ballots."""
    names=['Baringo', 'Bomet', 'Bungoma', 'Busia', 'Elgeyo-Marakwet', 'Embu', 'Garissa', 'Homa Bay', 'Isiolo', 'Kajiado', 'Kakamega', 'Kericho', 'Kiambu', 'Kilifi', 'Kirinyaga', 'Kisii', 'Kisumu', 'Kitui', 'Kwale', 'Laikipia', 'Lamu', 'Machakos', 'Makueni', 'Mandera', 'Marsabit', 'Meru', 'Migori', 'Mombasa', "Murang'a", 'Nairobi', 'Nakuru', 'Nandi', 'Narok', 'Nyamira', 'Nyandarua', 'Nyeri', 'Samburu', 'Siaya', 'Taita-Taveta', 'Tana River', 'Tharaka-Nithi', 'Trans Nzoia', 'Turkana', 'Uasin Gishu', 'Vihiga', 'Wajir', 'West Pokot']
    for i,name in enumerate(names, start=1):
        r=Region.query.filter_by(name=name).first()
        if not r:
            db.session.add(Region(name=name, code=f"{i:03d}", active=True))
        elif not r.code:
            r.code=f"{i:03d}"
    if not Region.query.filter_by(name="Legacy / Unassigned").first():
        db.session.add(Region(name="Legacy / Unassigned", code="LEGACY", active=True))
    db.session.commit()


GEOGRAPHY_SOURCE_URL = "https://raw.githubusercontent.com/stevehoober254/kenya-county-data/main/county_data.json"

# RC5: canonical county names are taken from the application's 47-county seed.
# Matching ignores punctuation, hyphens, apostrophes and spacing so variants such
# as Elgeyo Marakwet/Elgeyo-Marakwet, Muranga/Murang'a and Taita Taveta/
# Taita-Taveta resolve to one county. Nairobi City is an explicit alias.
CANONICAL_COUNTY_NAMES = [
    'Baringo', 'Bomet', 'Bungoma', 'Busia', 'Elgeyo-Marakwet', 'Embu', 'Garissa',
    'Homa Bay', 'Isiolo', 'Kajiado', 'Kakamega', 'Kericho', 'Kiambu', 'Kilifi',
    'Kirinyaga', 'Kisii', 'Kisumu', 'Kitui', 'Kwale', 'Laikipia', 'Lamu',
    'Machakos', 'Makueni', 'Mandera', 'Marsabit', 'Meru', 'Migori', 'Mombasa',
    "Murang'a", 'Nairobi', 'Nakuru', 'Nandi', 'Narok', 'Nyamira', 'Nyandarua',
    'Nyeri', 'Samburu', 'Siaya', 'Taita-Taveta', 'Tana River', 'Tharaka-Nithi',
    'Trans Nzoia', 'Turkana', 'Uasin Gishu', 'Vihiga', 'Wajir', 'West Pokot'
]


def _county_key(name):
    return "".join(ch for ch in (name or "").casefold() if ch.isalnum())


COUNTY_CANONICAL_BY_KEY = {_county_key(n): n for n in CANONICAL_COUNTY_NAMES}
COUNTY_CANONICAL_BY_KEY.update({
    _county_key("Nairobi City"): "Nairobi",
    _county_key("Nairobi City County"): "Nairobi",
    _county_key("Nairobi County"): "Nairobi",
})


def canonical_county_name(name):
    cleaned = (name or "").strip()
    return COUNTY_CANONICAL_BY_KEY.get(_county_key(cleaned), cleaned)


def _merge_ward(old_w, target_x):
    """Move a ward to target_x, merging a same-name duplicate if necessary."""
    existing = Ward.query.filter(
        Ward.constituency_id == target_x.id,
        db.func.lower(Ward.name) == old_w.name.lower()
    ).first()
    if existing and existing.id != old_w.id:
        User.query.filter_by(ward_id=old_w.id).update(
            {User.ward_id: existing.id}, synchronize_session=False)
        Contest.query.filter_by(ward_id=old_w.id).update(
            {Contest.ward_id: existing.id}, synchronize_session=False)
        db.session.delete(old_w)
    else:
        old_w.constituency_id = target_x.id


def repair_county_aliases():
    """Merge spelling/punctuation variants into the canonical 47 counties.

    This touches geography references only. Votes and ballot receipts are never
    deleted or rewritten. Empty duplicate Region rows are removed only after all
    voter, contest, constituency and ward references have been repointed.
    """
    canonical_rows = {}
    for idx, name in enumerate(CANONICAL_COUNTY_NAMES, start=1):
        row = Region.query.filter(db.func.lower(Region.name) == name.lower()).first()
        if not row:
            row = Region(name=name, code=f"{idx:03d}", active=True)
            db.session.add(row)
            db.session.flush()
        canonical_rows[name] = row

    aliases = []
    for row in Region.query.filter(Region.name != "Legacy / Unassigned").all():
        canonical_name = canonical_county_name(row.name)
        target = canonical_rows.get(canonical_name)
        if target and row.id != target.id:
            aliases.append((row, target))

    moved_constituencies = 0
    removed_regions = 0
    for alias, target in aliases:
        User.query.filter_by(region_id=alias.id).update(
            {User.region_id: target.id}, synchronize_session=False)
        Contest.query.filter_by(county_id=alias.id).update(
            {Contest.county_id: target.id}, synchronize_session=False)

        for old_x in Constituency.query.filter_by(county_id=alias.id).all():
            existing_x = Constituency.query.filter(
                Constituency.county_id == target.id,
                db.func.lower(Constituency.name) == old_x.name.lower()
            ).first()
            if existing_x and existing_x.id != old_x.id:
                for old_w in Ward.query.filter_by(constituency_id=old_x.id).all():
                    _merge_ward(old_w, existing_x)
                User.query.filter_by(constituency_id=old_x.id).update(
                    {User.constituency_id: existing_x.id}, synchronize_session=False)
                Contest.query.filter_by(constituency_id=old_x.id).update(
                    {Contest.constituency_id: existing_x.id}, synchronize_session=False)
                db.session.delete(old_x)
            else:
                old_x.county_id = target.id
            moved_constituencies += 1

        db.session.flush()
        # The alias is now empty of geography and references, so removal is safe.
        db.session.delete(alias)
        removed_regions += 1

    db.session.flush()
    return moved_constituencies, removed_regions


def validate_geography_integrity(expected_payload=None):
    """Validate the complete 47 -> 290 -> 1,450 parent-child hierarchy."""
    official_counties = Region.query.filter(Region.name != "Legacy / Unassigned").all()
    county_ids = [c.id for c in official_counties]
    constituencies = Constituency.query.filter(Constituency.county_id.in_(county_ids)).all() if county_ids else []
    constituency_ids = [x.id for x in constituencies]
    wards = Ward.query.filter(Ward.constituency_id.in_(constituency_ids)).all() if constituency_ids else []

    empty_counties = [c.name for c in official_counties
                      if Constituency.query.filter_by(county_id=c.id).count() == 0]
    orphan_constituencies = Constituency.query.filter(~Constituency.county_id.in_(county_ids)).count() if county_ids else Constituency.query.count()
    all_constituency_ids = [x.id for x in Constituency.query.all()]
    orphan_wards = Ward.query.filter(~Ward.constituency_id.in_(all_constituency_ids)).count() if all_constituency_ids else Ward.query.count()

    nairobi = Region.query.filter(db.func.lower(Region.name) == "nairobi").first()
    nairobi_count = Constituency.query.filter_by(county_id=nairobi.id).count() if nairobi else 0

    errors = []
    if len(official_counties) != 47:
        errors.append(f"expected 47 counties, found {len(official_counties)}")
    if len(constituencies) != 290:
        errors.append(f"expected 290 constituencies, found {len(constituencies)}")
    if len(wards) != 1450:
        errors.append(f"expected 1,450 wards, found {len(wards)}")
    if empty_counties:
        errors.append("counties with no constituencies: " + ", ".join(sorted(empty_counties)))
    if orphan_constituencies:
        errors.append(f"{orphan_constituencies} orphan constituency record(s)")
    if orphan_wards:
        errors.append(f"{orphan_wards} orphan ward record(s)")
    if nairobi_count != 17:
        errors.append(f"Nairobi should have 17 constituencies, found {nairobi_count}")

    # Detect any unexpected county spelling that survived normalisation.
    unexpected = sorted(c.name for c in official_counties
                        if canonical_county_name(c.name) not in CANONICAL_COUNTY_NAMES)
    if unexpected:
        errors.append("unexpected county name(s): " + ", ".join(unexpected))

    if expected_payload:
        for county_data in expected_payload:
            cname = canonical_county_name(county_data.get("name"))
            county = Region.query.filter(db.func.lower(Region.name) == cname.lower()).first()
            expected_x = len(county_data.get("constituencies", []))
            actual_x = Constituency.query.filter_by(county_id=county.id).count() if county else 0
            if actual_x != expected_x:
                errors.append(f"{cname}: expected {expected_x} constituencies, found {actual_x}")

    return (not errors), errors, nairobi_count


def seed_kenya_electoral_geography(force=False):
    """RC5 load/repair for Kenya counties -> constituencies -> wards.

    Normalises all known punctuation/spacing variants, safely merges duplicate
    geography rows, preserves election data, and validates the hierarchy before
    reporting success.
    """
    try:
        moved, removed = repair_county_aliases()
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return False, f"County geography repair failed: {exc}"

    if not force:
        ok, errors, nairobi_count = validate_geography_integrity()
        if ok:
            return True, ("Kenyan electoral geography verified: 47 counties, 290 constituencies, "
                          f"1,450 wards; Nairobi has {nairobi_count} constituencies. "
                          f"Merged {removed} duplicate county record(s).")

    try:
        req = urllib.request.Request(GEOGRAPHY_SOURCE_URL, headers={"User-Agent":"MSc-EVoting-V3.1.1-RC5/1.0"})
        with urllib.request.urlopen(req, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        return False, f"Reference-data download failed: {exc}"

    if not isinstance(payload, list):
        return False, "Reference-data format was not recognised."
    county_count = len(payload)
    constituency_count = sum(len(c.get("constituencies", [])) for c in payload)
    ward_count = sum(len(x.get("wards", [])) for c in payload for x in c.get("constituencies", []))
    if (county_count, constituency_count, ward_count) != (47, 290, 1450):
        return False, (f"Safety check failed: source returned {county_count} counties, "
                       f"{constituency_count} constituencies and {ward_count} wards.")

    try:
        for county_data in payload:
            cname = canonical_county_name(county_data.get("name"))
            county = Region.query.filter(db.func.lower(Region.name) == cname.lower()).first()
            if not county:
                # This should be rare because repair_county_aliases creates the
                # canonical 47 rows, but retain a safe fallback.
                county = Region(name=cname, active=True)
                db.session.add(county)
                db.session.flush()
            for xdata in county_data.get("constituencies", []):
                xname = (xdata.get("name") or "").strip()
                constituency = Constituency.query.filter(
                    Constituency.county_id == county.id,
                    db.func.lower(Constituency.name) == xname.lower()
                ).first()
                if not constituency:
                    constituency = Constituency(name=xname, county_id=county.id, active=True)
                    db.session.add(constituency)
                    db.session.flush()
                for wdata in xdata.get("wards", []):
                    wname = (wdata.get("name") or "").strip()
                    if wname and not Ward.query.filter(
                        Ward.constituency_id == constituency.id,
                        db.func.lower(Ward.name) == wname.lower()
                    ).first():
                        db.session.add(Ward(name=wname, constituency_id=constituency.id, active=True))
        db.session.flush()
        moved2, removed2 = repair_county_aliases()
        db.session.commit()
        moved += moved2
        removed += removed2
    except Exception as exc:
        db.session.rollback()
        return False, f"Reference-data update failed and was rolled back: {exc}"

    ok, errors, nairobi_count = validate_geography_integrity(payload)
    if not ok:
        return False, "Geography integrity check failed: " + "; ".join(errors[:12])

    return True, ("Loaded and verified 47 counties, 290 constituencies and 1,450 wards; "
                  f"Nairobi has {nairobi_count} constituencies. "
                  f"Merged {removed} duplicate county record(s) and reassigned "
                  f"{moved} constituency mapping(s).")

def seed_candidates():
    if Candidate.query.count() == 0:
        for name, party, abbr in CANDIDATE_SEED:
            db.session.add(Candidate(name=name, party=party, abbreviation=abbr))
        db.session.commit()
        print(f"[INFO] Seeded {len(CANDIDATE_SEED)} candidates.")


with app.app_context():
    migrate_database()
    db.create_all()
    seed_candidates()
    seed_regions()
    geo_ok, geo_message = seed_kenya_electoral_geography()
    print(f"[INFO] Kenya geography: {geo_message}")
    get_election()
    if ADMIN_EMAIL:
        admin_user = User.query.filter_by(email=ADMIN_EMAIL).first()
        if admin_user and admin_user.role != "admin":
            admin_user.role = "admin"
            db.session.commit()
            print(f"[INFO] Promoted {ADMIN_EMAIL} to administrator.")


# ----------------------------------------------------------------------------
# Templates (inline, single-file requirement)
# ----------------------------------------------------------------------------

BASE_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{% block title %}Kenya Secure E-Voting{% endblock %}</title>
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
      Kenya Secure E-Voting
    </a>
    <div class="d-flex gap-2">
      <a class="btn btn-outline-parchment btn-sm" href="{{ url_for('results') }}">Audit &amp; Results</a>
      {% if session.get('user_id') %}
        {% if current_user() and current_user().role == 'admin' %}
        <a class="btn btn-warning btn-sm" href="{{ url_for('admin_dashboard') }}">Admin</a>
        {% else %}
        <a class="btn btn-outline-parchment btn-sm" href="{{ url_for('voter_dashboard') }}">Dashboard</a>
         <a class="btn btn-emerald btn-sm" href="{{ url_for('voter_dashboard') }}">My Ballot</a>
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
.hero{background:linear-gradient(135deg,#102a43 0%,#12233d 52%,#0b4a3a 100%);border-radius:18px;color:#f7f5ef;overflow:hidden;position:relative;box-shadow:0 14px 36px rgba(18,35,61,.12)}.hero:before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 12% 18%,rgba(217,164,65,.12),transparent 42%),radial-gradient(circle at 90% 78%,rgba(12,138,95,.22),transparent 48%);pointer-events:none}.hero-inner{position:relative;padding:2.8rem 2.5rem}.hero-eyebrow{display:inline-flex;align-items:center;gap:.5rem;font-size:.76rem;letter-spacing:.08em;text-transform:uppercase;color:#d8e9e1;background:rgba(255,255,255,.08);padding:.38rem .78rem;border-radius:999px}.hero-eyebrow .dot{width:7px;height:7px;border-radius:50%;background:#4fd1a0}.hero h1{font-weight:750;line-height:1.08;letter-spacing:-.02em}.hero .lead{color:#d7ddea;max-width:760px}.hero-actions .btn{padding:.65rem 1.35rem;font-weight:650}.status-strip{background:#fff;border:1px solid var(--line);border-radius:14px;padding:1rem 1.25rem;box-shadow:0 5px 18px rgba(18,35,61,.04)}.status-label{font-size:.76rem;text-transform:uppercase;letter-spacing:.06em;color:#667085}.feature-card{height:100%;padding:1.45rem;border-radius:14px}.feature-icon{width:46px;height:46px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-weight:700}.feature-icon.gold{background:rgba(217,164,65,.14)}.feature-icon.green{background:rgba(12,138,95,.14)}.feature-icon.navy{background:rgba(18,35,61,.10)}.feature-title{font-weight:700;margin:.85rem 0 .4rem}.feature-text{color:#4a5568;font-size:.95rem;margin:0}.how-card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:1.4rem}.step{display:flex;align-items:center;gap:.65rem;white-space:nowrap}.step-num{width:30px;height:30px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;background:#eef6ff;color:#17375e;font-weight:700}.academic-note{border-top:1px solid var(--line);color:#667085;font-size:.9rem;padding-top:1.1rem}
</style>
<div class="hero mb-3"><div class="hero-inner row align-items-center g-4"><div class="col-lg-8"><span class="hero-eyebrow"><span class="dot"></span> Kenya &middot; Secure Electronic Voting System</span><h1 class="display-5 mt-3">Secure. Verifiable. Transparent.</h1><p class="lead mt-3">A prototype electronic voting platform designed to demonstrate secure voter authentication, encrypted ballot storage, duplicate-vote prevention and verifiable election auditing across Kenya's national and devolved electoral structure.</p><div class="hero-actions d-flex flex-wrap gap-2 mt-4">{% if not session.get('user_id') %}<a href="{{ url_for('register') }}" class="btn btn-emerald btn-lg">Register to Vote</a><a href="{{ url_for('login') }}" class="btn btn-outline-parchment btn-lg">Voter Login</a>{% else %}<a href="{{ url_for('vote') }}" class="btn btn-emerald btn-lg">Open My Ballot</a>{% endif %}<a href="{{ url_for('results') }}" class="btn btn-outline-parchment btn-lg">Election Audit</a></div></div><div class="col-lg-4 text-center"><svg viewBox="0 0 300 250" width="100%" style="max-width:285px" xmlns="http://www.w3.org/2000/svg"><ellipse cx="150" cy="225" rx="92" ry="11" fill="#000" opacity=".16"/><path d="M150 25l75 28v54c0 51-31 88-75 111-44-23-75-60-75-111V53z" fill="#0c8a5f"/><path d="M150 25v193c44-23 75-60 75-111V53z" fill="#08704e"/><rect x="105" y="92" width="90" height="68" rx="8" fill="#f7f5ef"/><path d="M118 91l32-25 32 25" fill="#d9a441"/><path d="M129 124l14 14 31-35" fill="none" stroke="#0c8a5f" stroke-width="8" stroke-linecap="round" stroke-linejoin="round"/></svg></div></div></div>
<div class="status-strip mb-4"><div class="row g-3 align-items-center"><div class="col-lg-6"><div class="status-label">Current Election</div><strong>{{ election.title }}</strong>{% if election.election_date %}<span class="text-muted"> &middot; {{ election.election_date.strftime('%d %B %Y') }}</span>{% endif %}</div><div class="col-lg-6 text-lg-end"><span class="badge {{ 'text-bg-success' if voting_open else 'text-bg-secondary' }} me-1">Voting {{ 'Open' if voting_open else 'Closed' }}</span><span class="badge {{ 'text-bg-success' if election.results_visible else 'text-bg-secondary' }}">Results {{ 'Released' if election.results_visible else 'Not Released' }}</span></div></div></div>
{% if session.get('user_id') and current_user() and current_user().role != 'admin' %}{% set area = voter_area(current_user()) %}<div class="card border-0 shadow-sm mb-4"><div class="card-body py-3"><div class="d-flex flex-wrap align-items-center gap-3"><strong>Your Electoral Area</strong><span><strong>County:</strong> {{ area.county }}</span><span><strong>Constituency:</strong> {{ area.constituency }}</span><span><strong>Ward:</strong> {{ area.ward }}</span></div></div></div>{% endif %}
<div class="row g-3 mb-4"><div class="col-md-4"><div class="feature-card card"><div class="feature-icon green">🔒</div><div class="feature-title">Encrypted Ballots</div><p class="feature-text">Ballot selections are encrypted before being stored, helping protect the confidentiality of recorded votes.</p></div></div><div class="col-md-4"><div class="feature-card card"><div class="feature-icon gold">⛓</div><div class="feature-title">Tamper-Evident Audit Chain</div><p class="feature-text">Each ballot is linked through cryptographic hashing, allowing unauthorised modification of stored ballot records to be detected.</p></div></div><div class="col-md-4"><div class="feature-card card"><div class="feature-icon navy">✓</div><div class="feature-title">Independent Verification</div><p class="feature-text">The audit dashboard provides election-integrity information without exposing an individual voter's ballot choice.</p></div></div></div>
<div class="how-card mb-4"><h4 class="mb-3">How it works</h4><div class="d-flex flex-wrap gap-3 justify-content-between"><div class="step"><span class="step-num">1</span>Register</div><div class="step"><span class="step-num">2</span>Verify Email</div><div class="step"><span class="step-num">3</span>Sign In</div><div class="step"><span class="step-num">4</span>Cast Eligible Ballots</div><div class="step"><span class="step-num">5</span>Verify Election Audit</div></div></div>
<div class="academic-note text-center"><strong>MSc Computer Science with Cybersecurity Project</strong><br>Secure Electronic Voting System Prototype &middot; Developed for academic demonstration and evaluation.</div>
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
        <p class="text-muted small">A verification link will be sent to your email after registration.</p>
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
            <label class="form-label">County</label>
            <select class="form-select" name="region_id" id="countySelect" required>
              <option value="">Select county</option>
              {% for r in regions %}<option value="{{ r.id }}" {% if selected_region|string == r.id|string %}selected{% endif %}>{{ r.name }}</option>{% endfor %}
            </select>
          </div>
          <div class="mb-3">
            <label class="form-label">Constituency</label>
            <select class="form-select" name="constituency_id" id="constituencySelect" required disabled><option value="">Select county first</option></select>
          </div>
          <div class="mb-3">
            <label class="form-label">County Assembly Ward</label>
            <select class="form-select" name="ward_id" id="wardSelect" required disabled><option value="">Select constituency first</option></select>
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

<script>
const county=document.getElementById('countySelect'), constituency=document.getElementById('constituencySelect'), ward=document.getElementById('wardSelect');
async function loadConstituencies(selected=''){
  constituency.innerHTML='<option value="">Loading...</option>'; constituency.disabled=true; ward.innerHTML='<option value="">Select constituency first</option>'; ward.disabled=true;
  if(!county.value){ constituency.innerHTML='<option value="">Select county first</option>'; return; }
  const rows=await fetch('/api/constituencies/'+county.value).then(r=>r.json());
  constituency.innerHTML='<option value="">Select constituency</option>'+rows.map(x=>`<option value="${x.id}" ${String(x.id)===String(selected)?'selected':''}>${x.name}</option>`).join(''); constituency.disabled=false;
}
async function loadWards(selected=''){
  ward.innerHTML='<option value="">Loading...</option>'; ward.disabled=true;
  if(!constituency.value){ ward.innerHTML='<option value="">Select constituency first</option>'; return; }
  const rows=await fetch('/api/wards/'+constituency.value).then(r=>r.json());
  ward.innerHTML='<option value="">Select ward</option>'+rows.map(x=>`<option value="${x.id}" ${String(x.id)===String(selected)?'selected':''}>${x.name}</option>`).join(''); ward.disabled=false;
}
county.addEventListener('change',()=>loadConstituencies()); constituency.addEventListener('change',()=>loadWards());
{% if selected_region %}loadConstituencies('{{ selected_constituency or "" }}').then(()=>{% if selected_constituency %}loadWards('{{ selected_ward or "" }}'){% else %}null{% endif %});{% endif %}
</script>
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
<style>
.ballot-choice {
  display:block; cursor:pointer; background:#f1f4f8; color:#12233d;
  border:2px solid #8c99aa; border-radius:12px; padding:16px;
  margin-top:12px; transition:background .15s,border-color .15s,box-shadow .15s;
}
.ballot-choice:hover {background:#e6eef5;border-color:#334e68}
.ballot-choice:has(.ballot-radio:checked) {
  background:#e0f3e9; border-color:#08784d; box-shadow:0 0 0 2px rgba(8,120,77,.15);
}
.ballot-choice .ballot-radio {
  appearance:none; -webkit-appearance:none; flex:0 0 25px;
  width:25px;height:25px;border:3px solid #334e68;
  border-radius:50%;background:#fff;cursor:pointer;margin:0;
}
.ballot-choice .ballot-radio:checked {
  border:7px solid #08784d;background:#fff;
}
.ballot-choice .ballot-radio:focus-visible {outline:3px solid #005fcc;outline-offset:3px}
.ballot-choice .candidate-photo {width:140px;height:140px;object-fit:cover;border-radius:8px}
.ballot-choice .party-logo {width:110px;height:110px;object-fit:contain;background:#fff;border:1px solid #cbd5e1;border-radius:8px;padding:3px}
.ballot-choice .candidate-details {flex:1;min-width:120px}
.ballot-choice .selected-indicator {display:none;color:#086442;font-weight:700}
.ballot-choice:has(.ballot-radio:checked) .selected-indicator {display:inline}
@media(max-width:600px) {
  .ballot-choice .candidate-photo {width:80px;height:80px}
  .ballot-choice .party-logo {width:65px;height:65px}
  .ballot-choice {padding:12px}
}
</style>
<div class="row justify-content-center"><div class="col-lg-10">
<div class="card"><div class="card-body p-4">
<h2>My General Election Ballot</h2>
<p class="text-muted">Choose one candidate per eligible contest. You can change or clear any choice before submitting. Once recorded, a contest is locked.</p>
{% if not contest_rows %}<div class="alert alert-warning">No active contests are configured for your registered electoral area yet.</div>{% endif %}
<form method="POST" id="ballotForm">
<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
{% for row in contest_rows %}
<section class="card mb-4"><div class="card-body">
<div class="d-flex justify-content-between gap-2">
  <div><h4 class="mb-0">{{ row.contest.position }}</h4><small class="text-muted">{{ row.area }}</small></div>
  {% if row.cast %}<span class="badge text-bg-success align-self-start">VOTE RECORDED</span>{% endif %}
</div>
{% if row.cast %}
<p class="mt-3 mb-0 text-muted">This contest is locked. Your candidate choice is not stored in the receipt.</p>
{% elif not row.candidates %}
<div class="alert alert-warning mt-3 mb-0">No active candidates have been registered for this contest.</div>
{% else %}
<fieldset class="mt-2" aria-label="{{ row.contest.position }} candidate choices">
{% for c in row.candidates %}
<label class="ballot-choice" for="c{{row.contest.id}}_{{c.id}}">
 <span class="d-flex align-items-center gap-3 flex-wrap flex-sm-nowrap">
  <input class="ballot-radio" type="radio" name="contest_{{ row.contest.id }}" id="c{{row.contest.id}}_{{c.id}}" value="{{c.id}}" aria-label="{{ c.name }}">
  {% if c.photo_data %}<img class="candidate-photo" src="{{c.photo_data}}" alt="Candidate photograph">{% endif %}
  <span class="candidate-details"><strong>{% if c.candidate_number %}No. {{c.candidate_number}} — {% endif %}{{c.name}}</strong><span class="d-block text-secondary">{{c.party}} ({{c.abbreviation}})</span><span class="selected-indicator">✓ Selected</span></span>
  {% if c.party_symbol_data %}<img class="party-logo" src="{{c.party_symbol_data}}" alt="Party symbol">{% endif %}
 </span>
</label>
{% endfor %}
</fieldset>
<div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mt-3">
 <span class="selection-status text-secondary small" data-contest="{{row.contest.id}}" aria-live="polite">No candidate selected</span>
 <button type="button" class="btn btn-outline-secondary clear-contest" data-contest="{{row.contest.id}}" disabled>↶ Clear Selection</button>
</div>
{% endif %}
</div></section>
{% endfor %}
{% if open_count %}
<button type="submit" class="btn btn-success btn-lg w-100">Review &amp; Submit Selected Votes</button>
<p class="small text-muted mt-2">Only selected contests will be submitted. Unselected contests remain available for later.</p>
{% endif %}
</form>
</div></div></div></div>
<script>
(function(){
 const form=document.getElementById('ballotForm');
 if(!form)return;
 function refresh(){
  form.querySelectorAll('.clear-contest').forEach(button=>{
   const id=button.dataset.contest;
   const radios=[...form.querySelectorAll('input[name="contest_'+id+'"]')];
   const chosen=radios.find(r=>r.checked);
   button.disabled=!chosen;
   const status=form.querySelector('.selection-status[data-contest="'+id+'"]');
   if(status)status.textContent=chosen?'Candidate selected — you may change or clear it':'No candidate selected';
  });
 }
 form.addEventListener('change',refresh);
 form.querySelectorAll('.clear-contest').forEach(button=>{
  button.addEventListener('click',()=>{
   form.querySelectorAll('input[name="contest_'+button.dataset.contest+'"]').forEach(r=>{r.checked=false});
   refresh();
  });
 });
 form.addEventListener('submit',event=>{
  const chosen=[...form.querySelectorAll('.ballot-radio:checked')];
  if(!chosen.length){event.preventDefault();alert('Please select at least one candidate before submitting.');return;}
  const summary=chosen.map(r=>{
   const card=r.closest('.card');
   const position=card?.querySelector('h4')?.textContent.trim()||'Contest';
   const candidate=r.closest('.ballot-choice')?.querySelector('.candidate-details strong')?.textContent.trim()||'Candidate';
   return position+': '+candidate;
  }).join('\\n');
  if(!confirm('Please review your selections:\\n\\n'+summary+'\\n\\nSubmit these votes? Once recorded, they cannot be changed.'))event.preventDefault();
 });
 refresh();
})();
</script>
{% endblock %}
"""
RESULTS_HTML = """
{% extends "base.html" %}{% block content %}
<div class="card mb-4"><div class="card-body p-4"><div class="d-flex justify-content-between gap-3 flex-wrap"><div><h2>{{ '🟢 ELECTION OPEN' if election_open else '🔴 ELECTION CLOSED' }}</h2><p class="mb-1"><strong>{{total_votes}}</strong> encrypted ballot records in the ledger.</p><p class="mb-0">Integrity: <span class="badge {{'text-bg-success' if integrity_status=='VALID' else 'text-bg-danger'}}">{{integrity_status.replace('_',' ')}}</span> &middot; {{verified_count}} verified</p></div><span class="badge {{'text-bg-success' if election_open else 'text-bg-secondary'}} align-self-start">{{'OPEN' if election_open else 'CLOSED'}}</span></div></div></div>
{% if election_open %}<div class="alert alert-info">Candidate standings are hidden while polls are open.</div>
{% elif not show_candidate_results %}<div class="alert alert-warning">Voting is closed, but the administrator has not released final results.</div>
{% else %}
<style>
.results-controls{background:#fff;border:1px solid #e4e0d3;border-radius:12px;padding:1.2rem;margin-bottom:1.2rem}
.results-pie{width:220px;height:220px;max-width:100%;border-radius:50%;position:relative;flex-shrink:0;background:#e7ebef}
.results-pie::after{content:'';position:absolute;inset:34%;background:white;border-radius:50%}
.results-legend{min-width:230px;flex:1}.results-swatch{width:12px;height:12px;display:inline-block;border-radius:3px;margin-right:9px;flex-shrink:0}
.results-legend-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:.48rem 0;border-bottom:1px solid #edf0f2}
.results-contest[hidden]{display:none!important}.results-empty{color:#5c6777}
@media(max-width:575px){.results-pie{width:185px;height:185px}.results-chart-layout{justify-content:center}}
</style>
<h3>Final Results by Contest</h3>
<p class="text-muted">Each pie chart shows the percentage of valid recorded votes for its contest. Turnout is calculated separately using eligible voters.</p>
<div class="results-controls">
 <div class="row g-3">
  <div class="col-md-4"><label class="form-label fw-semibold" for="positionFilter">Electoral position</label><select id="positionFilter" class="form-select"><option value="">All positions</option>{% for position in result_positions %}<option value="{{position}}">{{position}}</option>{% endfor %}</select></div>
  <div class="col-md-4"><label class="form-label fw-semibold" for="countyFilter">County</label><select id="countyFilter" class="form-select"><option value="">All counties</option>{% for county in result_counties %}<option value="{{county}}">{{county}}</option>{% endfor %}</select></div>
  <div class="col-md-4"><label class="form-label fw-semibold" for="areaFilter">Constituency / ward</label><select id="areaFilter" class="form-select"><option value="">All constituencies / wards</option></select></div>
 </div>
 <div class="d-flex flex-wrap align-items-center justify-content-between gap-2 mt-3"><label class="form-check-label"><input class="form-check-input me-2" id="showEmpty" type="checkbox">Show contests without votes</label><button type="button" id="resetFilters" class="btn btn-outline-secondary btn-sm">Reset filters</button></div>
 <p id="resultsCount" class="small text-muted mb-0 mt-2" aria-live="polite"></p>
</div>
{% for r in contest_results %}
<div class="card mb-3 results-contest" data-position="{{r.contest.position|e}}" data-county="{{r.county|e}}" data-area="{{r.local_area|e}}" data-cast="{{r.cast}}">
 <div class="card-body p-3 p-md-4">
  <div class="d-flex justify-content-between gap-2 flex-wrap"><div><h4 class="mb-0">{{r.contest.position}}</h4><span class="text-muted">{{r.area}}</span></div><div class="text-md-end"><strong>{{'%.1f'|format(r.turnout)}}%</strong> turnout<br><small>{{r.cast}} ballots / {{r.eligible}} eligible voters</small></div></div>
  {% if r.cast and r.candidates %}
  <div class="d-flex flex-wrap gap-4 align-items-center mt-3 results-chart-layout">
   <div class="results-pie" role="img" aria-label="Vote share pie chart for {{r.contest.position}} in {{r.area}}" style="background:conic-gradient({% for part in r.pie_parts %}{{part.color}} {{'%.5f'|format(part.start)}}% {{'%.5f'|format(part.end)}}%{% if not loop.last %}, {% endif %}{% endfor %})"></div>
   <div class="results-legend">{% for part in r.pie_parts %}<div class="results-legend-row"><span class="d-flex align-items-center"><span class="results-swatch" style="background:{{part.color}}"></span><span><strong>{{part.candidate.name}}</strong><br><small class="text-muted">{{part.candidate.party}} ({{part.candidate.abbreviation}})</small></span></span><span class="text-end text-nowrap"><strong>{{part.votes}}</strong> votes<br><small>{{'%.1f'|format(part.percent)}}%</small></span></div>{% endfor %}</div>
  </div>
  {% elif r.cast %}<p class="results-empty mt-3 mb-0">Ballots exist for this contest, but no active candidates are available to display. Please review the audit and candidate records.</p>
  {% else %}<p class="results-empty mt-3 mb-0">No ballots recorded for this contest.</p>{% endif %}
 </div>
</div>
{% endfor %}
<p id="noMatchingResults" class="alert alert-light border" hidden>No contests match these filters. Try another position or area, or enable “Show contests without votes”.</p>
{% if legacy_tally %}<div class="card border-warning mb-3"><div class="card-body"><h4>Legacy Demo Ballots</h4><p class="text-muted">These ballots pre-date V3 contest IDs and are preserved separately rather than being assigned to a constituency/ward contest retrospectively.</p>{% for cid,n in legacy_tally.items() %}<div>{{ legacy_candidates.get(cid).name if legacy_candidates.get(cid) else ('Candidate ID ' ~ cid) }}: <strong>{{n}}</strong></div>{% endfor %}</div></div>{% endif %}
<script>
(function(){
 const position=document.getElementById('positionFilter');
 const county=document.getElementById('countyFilter');
 const area=document.getElementById('areaFilter');
 const showEmpty=document.getElementById('showEmpty');
 const cards=Array.from(document.querySelectorAll('.results-contest'));
 const countyWrap=county.closest('.col-md-4');
 const areaWrap=area.closest('.col-md-4');
 const nationalPositions=new Set(['President']);
 function rebuildAreas(){
   const previous=area.value;
   const areas=[...new Set(cards.filter(card=>
     (!position.value||card.dataset.position===position.value)&&
     (!county.value||card.dataset.county===county.value)&&
     card.dataset.area
   ).map(card=>card.dataset.area))].sort((a,b)=>a.localeCompare(b));
   area.replaceChildren(new Option('All constituencies / wards',''));
   areas.forEach(name=>area.add(new Option(name,name)));
   area.value=areas.includes(previous)?previous:'';
   area.disabled=areas.length===0;
 }
 function update(){
   const national=nationalPositions.has(position.value);
   countyWrap.hidden=national;
   areaWrap.hidden=national;
   if(national){county.value='';area.value='';}
   rebuildAreas();
   let count=0;
   cards.forEach(card=>{
     const visible=(!position.value||card.dataset.position===position.value)&&
       (!county.value||card.dataset.county===county.value)&&
       (!area.value||card.dataset.area===area.value)&&
       (showEmpty.checked||Number(card.dataset.cast)>0);
     card.hidden=!visible;
     if(visible)count++;
   });
   document.getElementById('resultsCount').textContent=count+' contest'+(count===1?'':'s')+' displayed';
   document.getElementById('noMatchingResults').hidden=count!==0;
 }
 position.addEventListener('change',update);
 county.addEventListener('change',update);
 area.addEventListener('change',update);
 showEmpty.addEventListener('change',update);
 document.getElementById('resetFilters').addEventListener('click',()=>{
   position.value='';county.value='';area.value='';showEmpty.checked=false;update();
 });
 update();
})();
</script>
{% endif %}
{% if integrity_status=='HASH_FAILURE' %}<div class="alert alert-danger">Hash-chain verification failed at vote ID {{break_point}}.</div>{% elif integrity_status=='DECRYPTION_FAILURE' %}<div class="alert alert-warning">Vote ID {{break_point}} could not be decrypted with the configured key. This is reported separately from hash-chain tampering.</div>{% endif %}
{% endblock %}
"""
ADMIN_HTML = """
{% extends "base.html" %}
{% block content %}
<div class="row g-4">
  <div class="col-lg-7">
    <div class="card">
      <div class="card-body p-4">
        <h3>Administrator Dashboard</h3>
        <p class="text-muted">Election lifecycle and security controls.</p>
        <div class="d-flex gap-2 flex-wrap mb-3">
          <a class="btn btn-outline-primary btn-sm" href="{{ url_for('manage_candidates') }}">Manage Candidates</a>
          <a class="btn btn-outline-primary btn-sm" href="{{ url_for('manage_regions') }}">Manage Counties</a>
          <a class="btn btn-outline-primary btn-sm" href="{{ url_for('manage_geography') }}">Constituencies & Wards</a>
          <a class="btn btn-outline-primary btn-sm" href="{{ url_for('manage_elections') }}">Manage Elections</a>
          <a class="btn btn-outline-primary btn-sm" href="{{ url_for('manage_contests') }}">Election Contests</a>
          <form method="POST" action="{{ url_for('reload_kenya_geography') }}" class="d-inline"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn btn-outline-success btn-sm">Verify / Load Kenya Geography</button></form>
        </div>
        <form method="POST">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <div class="mb-3">
            <label class="form-label">Election title</label>
            <input class="form-control" name="title" value="{{ election.title }}" maxlength="200" required>
          </div>
          <div class="form-check form-switch mb-3">
            <input class="form-check-input" type="checkbox" name="is_open" id="is_open" {% if election.is_open %}checked{% endif %}>
            <label class="form-check-label" for="is_open">Election enabled for voting</label>
          </div>
          <div class="form-check form-switch mb-3">
            <input class="form-check-input" type="checkbox" name="results_visible" id="results_visible" {% if election.results_visible %}checked{% endif %}>
            <label class="form-check-label" for="results_visible">Release final candidate results after polls close</label>
          </div>
          <div class="alert alert-info py-2 small">
            Candidate standings are automatically hidden from voters while the election is open,
            even if final-results release is enabled.
          </div>
          <button class="btn btn-primary" type="submit">Save Election Settings</button>
        </form>
      </div>
    </div>
  </div>
  <div class="col-lg-5">
    <div class="card">
      <div class="card-body p-4">
        <h4>System Summary</h4>
        <p class="mb-1">Registered voters: <strong>{{ registered_voters }}</strong></p>
        <p class="mb-1">Votes recorded: <strong>{{ total_votes }}</strong></p>
        <p class="mb-0">Current status: <strong>{{ 'OPEN' if election_open else 'CLOSED' }}</strong></p>
      </div>
    </div>
  </div>
</div>

<div class="card mt-4">
  <div class="card-body p-4">
    <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-2">
      <h4 class="mb-0">Recent Security Audit Events</h4>
      <div class="d-flex gap-2">
        <a class="btn btn-sm btn-outline-primary" href="{{ url_for('full_audit_log') }}">View Full Audit Log</a>
        <form method="POST" action="{{ url_for('clear_audit_view') }}" onsubmit="return confirm('Clear recent events from this dashboard view? The underlying audit records will NOT be deleted.');">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><button class="btn btn-sm btn-outline-secondary">Clear View</button>
        </form>
      </div>
    </div>
    <div class="table-responsive">
      <table class="table table-sm">
        <thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>User ID</th><th>Details</th></tr></thead>
        <tbody>
        {% for e in events %}
          <tr><td>{{ e.created_at }}</td><td>{{ e.event_type }}</td><td>{{ e.severity }}</td><td>{{ e.user_id or '-' }}</td><td>{{ e.details or '' }}</td></tr>
        {% else %}
          <tr><td colspan="5" class="text-muted">No audit events recorded yet.</td></tr>
        {% endfor %}
        </tbody>
      </table>
    </div>
  </div>
</div>
{% endblock %}
"""


CANDIDATES_HTML = """
{% extends "base.html" %}
{% block content %}
<style>
 .candidate-filter label,.candidate-form label{font-weight:600;color:#183a61}
 .candidate-filter .form-select,.candidate-form .form-control{background:#f5f9fd}
 .candidate-card{border:1px solid #dfe7ef;border-radius:12px;padding:14px;margin-bottom:12px}
 .candidate-photo{width:76px;height:76px;object-fit:cover;border-radius:10px;background:#eef3f8}
 .party-symbol{width:52px;height:52px;object-fit:contain;border-radius:8px;background:white;border:1px solid #e2e8f0;padding:3px}
 .preview-img{width:92px;height:92px;object-fit:cover;border-radius:10px;border:1px solid #dbe3eb;background:white}
 .contest-banner{background:#edf6ff;border-left:4px solid #0d6efd;padding:12px 14px;border-radius:8px}
</style>
<div class="row g-4">
 <div class="col-lg-5"><div class="card"><div class="card-body p-4">
  <h3>Candidate Registration</h3>
  <div class="alert alert-light border small mb-3"><strong>Election:</strong> {{ election.title }}</div>
  <div class="candidate-filter">
   <div class="mb-3"><label class="form-label">Position</label><select id="position" class="form-select"></select></div>
   <div class="mb-3" id="countyWrap"><label class="form-label">County</label><select id="county" class="form-select"></select></div>
   <div class="mb-3" id="constituencyWrap"><label class="form-label">Constituency</label><select id="constituency" class="form-select"></select></div>
   <div class="mb-3" id="wardWrap"><label class="form-label">Ward</label><select id="ward" class="form-select"></select></div>
   <div class="contest-banner small mb-3" id="selectedArea">Select a position and electoral area.</div>
  </div>
  <form method="POST" enctype="multipart/form-data" class="candidate-form" id="candidateForm">
   <input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="action" value="add"><input type="hidden" name="contest_id" id="contest_id">
   <div class="mb-3"><label class="form-label">Full name</label><input class="form-control" name="name" required></div>
   <div class="mb-3"><label class="form-label">Political party</label><input class="form-control" name="party" required></div>
   <div class="row g-2"><div class="col"><label class="form-label">Abbreviation</label><input class="form-control" name="abbreviation" maxlength="10" required></div><div class="col"><label class="form-label">Candidate number <span class="text-danger">*</span></label><input class="form-control" name="candidate_number" required></div></div>
   <div class="row g-3 mt-1">
    <div class="col-md-6"><label class="form-label">Candidate photograph</label><input class="form-control" type="file" name="candidate_photo" id="candidate_photo" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp"><div class="small text-muted mt-1">JPG, PNG or WebP; max 1 MB.</div><div id="candidatePreviewWrap" class="d-none mt-2"><img id="candidatePreview" class="preview-img" alt="Candidate preview"><div><button type="button" id="removeCandidatePhoto" class="btn btn-sm btn-outline-danger mt-2">Remove image</button></div></div></div>
    <div class="col-md-6"><label class="form-label">Party symbol / logo</label><input class="form-control" type="file" name="party_symbol" id="party_symbol" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp"><div class="small text-muted mt-1">JPG, PNG or WebP; max 1 MB.</div><div id="partyPreviewWrap" class="d-none mt-2"><img id="partyPreview" class="preview-img" alt="Party symbol preview"><div><button type="button" id="removePartySymbol" class="btn btn-sm btn-outline-danger mt-2">Remove image</button></div></div></div>
   </div>
   <div class="my-3"><label class="form-label">Short manifesto/profile</label><textarea class="form-control" name="manifesto" rows="4"></textarea></div>
   <button class="btn btn-primary" id="addCandidate" disabled>Add Candidate</button>
  </form>
 </div></div></div>
 <div class="col-lg-7"><div class="card"><div class="card-body p-4">
  <div class="d-flex justify-content-between gap-3 flex-wrap"><div><h3>Registered Candidates</h3><h6 class="text-muted mb-3" id="candidateHeading">Select a contest</h6></div><div style="min-width:220px"><input id="candidateSearch" class="form-control" placeholder="Search candidates..."></div></div>
  <div id="candidateRows"><div class="text-muted">Choose a position and area to view candidates for that contest.</div></div>
  <div class="alert alert-info small mt-3">Candidates are withdrawn rather than deleted, preserving ballot history. Editing changes profile details only; the candidate remains attached to the same contest.</div>
 </div></div></div>
</div>

<div class="modal fade" id="editCandidateModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
<form method="POST" enctype="multipart/form-data"><div class="modal-header"><h5 class="modal-title">Edit Candidate</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div>
<div class="modal-body"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="action" value="edit"><input type="hidden" name="candidate_id" id="edit_id">
<div class="mb-2"><label class="form-label">Full name</label><input class="form-control" name="name" id="edit_name" required></div>
<div class="mb-2"><label class="form-label">Political party</label><input class="form-control" name="party" id="edit_party" required></div>
<div class="row g-2"><div class="col"><label class="form-label">Abbreviation</label><input class="form-control" name="abbreviation" id="edit_abbr" required></div><div class="col"><label class="form-label">Candidate number <span class="text-danger">*</span></label><input class="form-control" name="candidate_number" id="edit_number" required></div></div>
<div class="mt-2"><label class="form-label">Short manifesto/profile</label><textarea class="form-control" name="manifesto" id="edit_manifesto" rows="3"></textarea></div>
<div class="row g-2 mt-1"><div class="col"><label class="form-label">Replace candidate photo</label><input class="form-control" type="file" name="candidate_photo" accept=".jpg,.jpeg,.png,.webp"></div><div class="col"><label class="form-label">Replace party symbol</label><input class="form-control" type="file" name="party_symbol" accept=".jpg,.jpeg,.png,.webp"></div></div>
</div><div class="modal-footer"><button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button><button class="btn btn-primary">Save Changes</button></div></form>
</div></div></div>

<script>
const contests={{ contest_data|tojson }}, counties={{ counties_data|tojson }}, constituencies={{ constituencies_data|tojson }}, wards={{ wards_data|tojson }}, candidateMap={{ candidate_data|tojson }}, csrf={{ csrf_token()|tojson }};
const pos=document.getElementById('position'),county=document.getElementById('county'),con=document.getElementById('constituency'),ward=document.getElementById('ward');
const cw=document.getElementById('countyWrap'),xw=document.getElementById('constituencyWrap'),ww=document.getElementById('wardWrap'),search=document.getElementById('candidateSearch');
let currentRows=[],currentContestId='';
function opts(el,rows,placeholder){el.innerHTML='';let o=new Option(placeholder,'');el.add(o);rows.forEach(r=>el.add(new Option(r.name,r.id)));}
function positions(){let seen=[];contests.forEach(c=>{if(!seen.includes(c.position))seen.push(c.position)});opts(pos,seen.map(x=>({id:x,name:x})),'Select position...');}
function refreshGeo(){let p=pos.value,needCounty=p&&p!='President',needCon=['Member of Parliament','Member of County Assembly'].includes(p),needWard=p=='Member of County Assembly';cw.style.display=needCounty?'':'none';xw.style.display=needCon?'':'none';ww.style.display=needWard?'':'none';opts(county,counties,'Select County...');opts(con,[],'Select Constituency...');opts(ward,[],'Select Ward...');chooseContest();}
function refreshCon(){opts(con,constituencies.filter(x=>String(x.county_id)==String(county.value)),'Select Constituency...');opts(ward,[],'Select Ward...');chooseContest();}
function refreshWard(){opts(ward,wards.filter(x=>String(x.constituency_id)==String(con.value)),'Select Ward...');chooseContest();}
function chooseContest(){let p=pos.value,c=null;if(p==='President')c=contests.find(x=>x.position===p);else if(p&&county.value)c=contests.find(x=>x.position===p&&String(x.county_id)===String(county.value)&&(!['Member of Parliament','Member of County Assembly'].includes(p)||String(x.constituency_id)===String(con.value))&&(p!=='Member of County Assembly'||String(x.ward_id)===String(ward.value)));currentContestId=c?String(c.id):'';document.getElementById('contest_id').value=currentContestId;document.getElementById('addCandidate').disabled=!c;document.getElementById('selectedArea').textContent=c?('Selected Contest: '+p+' — '+c.area):'Select the required position and electoral area.';document.getElementById('candidateHeading').textContent=c?('Candidates for: '+p+' — '+c.area):'Select a contest';currentRows=c?(candidateMap[currentContestId]||[]):[];renderRows();}
function renderRows(){let q=search.value.trim().toLowerCase(),rows=currentRows.filter(r=>!q||[r.name,r.party,r.abbreviation,r.candidate_number].join(' ').toLowerCase().includes(q)),box=document.getElementById('candidateRows');if(!rows.length){box.innerHTML='<div class="text-muted">'+(currentRows.length?'No candidates match your search.':'No candidates registered for this contest yet.')+'</div>';return;}box.innerHTML=rows.map(r=>`<div class="candidate-card"><div class="d-flex gap-3 align-items-center">${r.photo_data?`<img class="candidate-photo" src="${r.photo_data}" alt="">`:`<div class="candidate-photo d-flex align-items-center justify-content-center text-muted">Photo</div>`}<div class="flex-grow-1"><div class="d-flex justify-content-between gap-2"><div><strong>${esc(r.name)}</strong>${r.candidate_number?` <span class="badge text-bg-light">No. ${esc(r.candidate_number)}</span>`:''}<div class="text-muted">${esc(r.party)} (${esc(r.abbreviation)})</div></div>${r.party_symbol_data?`<img class="party-symbol" src="${r.party_symbol_data}" alt="">`:''}</div><div class="mt-2"><span class="badge ${r.status==='active'?'text-bg-success':'text-bg-secondary'}">${esc(r.status.toUpperCase())}</span> <button type="button" class="btn btn-sm btn-outline-primary ms-1" onclick="openEditById(${r.id})">Edit</button><form method="POST" class="d-inline"><input type="hidden" name="csrf_token" value="${esc(csrf)}"><input type="hidden" name="action" value="toggle"><input type="hidden" name="candidate_id" value="${r.id}"><button class="btn btn-sm btn-outline-secondary ms-1">${r.status==='active'?'Withdraw':'Reactivate'}</button></form></div></div></div></div>`).join('');}
function openEditById(id){let r=currentRows.find(x=>String(x.id)===String(id));if(!r)return;document.getElementById('edit_id').value=r.id;document.getElementById('edit_name').value=r.name||'';document.getElementById('edit_party').value=r.party||'';document.getElementById('edit_abbr').value=r.abbreviation||'';document.getElementById('edit_number').value=r.candidate_number||'';document.getElementById('edit_manifesto').value=r.manifesto||'';bootstrap.Modal.getOrCreateInstance(document.getElementById('editCandidateModal')).show();}
function esc(v){return String(v??'').replace(/[&<>'"]/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[ch]));}
function preview(input,img,wrap,removeBtn){let objectUrl=null;function clearSelection(){if(objectUrl){URL.revokeObjectURL(objectUrl);objectUrl=null;}input.value='';img.removeAttribute('src');wrap.classList.add('d-none');}input.addEventListener('change',()=>{if(objectUrl){URL.revokeObjectURL(objectUrl);objectUrl=null;}let f=input.files[0];if(!f){clearSelection();return;}objectUrl=URL.createObjectURL(f);img.src=objectUrl;wrap.classList.remove('d-none');});removeBtn.addEventListener('click',clearSelection);}
preview(document.getElementById('candidate_photo'),document.getElementById('candidatePreview'),document.getElementById('candidatePreviewWrap'),document.getElementById('removeCandidatePhoto'));
preview(document.getElementById('party_symbol'),document.getElementById('partyPreview'),document.getElementById('partyPreviewWrap'),document.getElementById('removePartySymbol'));
pos.addEventListener('change',refreshGeo);county.addEventListener('change',refreshCon);con.addEventListener('change',refreshWard);ward.addEventListener('change',chooseContest);search.addEventListener('input',renderRows);positions();refreshGeo();
</script>
{% endblock %}
"""

REGIONS_HTML = """
{% extends "base.html" %}
{% block content %}
<style>.geo-stat{font-size:1.6rem;font-weight:700;color:#17375e}.protected{font-size:.75rem}</style>
<div class="d-flex justify-content-between align-items-start flex-wrap gap-3 mb-3"><div><h2>Kenyan Electoral Geography Administration</h2><p class="text-muted mb-0">Official imported electoral geography is protected reference data. Use the Geography Browser for the County → Constituency → Ward hierarchy.</p></div><a class="btn btn-outline-primary" href="{{ url_for('manage_geography') }}">Open Geography Browser</a></div>
<div class="row g-3 mb-4"><div class="col-md-4"><div class="card card-body"><div class="geo-stat">{{ official_count }}</div><div>Official Counties</div></div></div><div class="col-md-4"><div class="card card-body"><div class="geo-stat">{{ constituency_count }}</div><div>Constituencies</div></div></div><div class="col-md-4"><div class="card card-body"><div class="geo-stat">{{ ward_count }}</div><div>County Assembly Wards</div></div></div></div>
<div class="card"><div class="card-body p-4">
<div class="d-flex justify-content-between flex-wrap gap-2 mb-3"><div><h3 class="mb-1">Official Kenyan Counties</h3><div class="text-muted small">Protected reference records cannot be deactivated from this screen.</div></div><input id="countySearch" class="form-control" style="max-width:280px" placeholder="Search counties..."></div>
<div class="table-responsive"><table class="table align-middle" id="countyTable"><thead><tr><th>County</th><th>Code</th><th>Status</th><th>Protection</th></tr></thead><tbody>
{% for r in official_regions %}<tr><td>{{ r.name }}</td><td>{{ r.code or '-' }}</td><td><span class="badge text-bg-success">ACTIVE</span></td><td><span class="badge text-bg-light border protected">REFERENCE DATA</span></td></tr>{% endfor %}
</tbody></table></div></div></div>
{% if legacy_region %}<div class="card border-warning mt-4"><div class="card-body"><h4>System / Legacy Record</h4><p class="mb-1"><strong>{{ legacy_region.name }}</strong> <span class="badge text-bg-warning">NOT AN ELECTORAL COUNTY</span></p><p class="text-muted small mb-0">Retained only for compatibility with historical prototype data.</p></div></div>{% endif %}
<details class="card card-body mt-4"><summary class="fw-bold">Advanced Geography Administration</summary><div class="alert alert-warning mt-3">Imported reference geography should normally not be modified. Manual counties are separate administrative additions and all changes are written to the audit log.</div>
<form method="POST" class="row g-2"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="action" value="add"><div class="col-md-5"><label class="form-label fw-semibold">Manual county name</label><input class="form-control" name="name" required></div><div class="col-md-3"><label class="form-label fw-semibold">Code</label><input class="form-control" name="code" placeholder="e.g. TEST"></div><div class="col-md-4 d-flex align-items-end"><button class="btn btn-outline-primary">Add Manual County</button></div></form>
{% if manual_regions %}<hr><h5>Manual additions</h5><table class="table"><thead><tr><th>County</th><th>Code</th><th>Status</th><th></th></tr></thead><tbody>{% for r in manual_regions %}<tr><td>{{r.name}}</td><td>{{r.code or '-'}}</td><td>{{'ACTIVE' if r.active else 'INACTIVE'}}</td><td><form method="POST"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="action" value="toggle"><input type="hidden" name="region_id" value="{{r.id}}"><button class="btn btn-sm btn-outline-secondary">{{'Deactivate' if r.active else 'Activate'}}</button></form></td></tr>{% endfor %}</tbody></table>{% endif %}
</details>
<script>document.getElementById('countySearch').addEventListener('input',function(){let q=this.value.toLowerCase();document.querySelectorAll('#countyTable tbody tr').forEach(r=>r.style.display=r.innerText.toLowerCase().includes(q)?'':'none')});</script>
{% endblock %}
"""

GEOGRAPHY_V3 = r"""{% extends 'base.html' %}{% block content %}
<h2>Kenya Electoral Geography</h2>
<p class="text-muted">Browse the verified reference hierarchy. Select a county, then a constituency to see only its wards.</p>
<div class="row g-4 mb-4">
 <div class="col-lg-7"><div class="card card-body">
  <h4>Geography Browser</h4>
  <label class="form-label">County</label><select id="geoCounty" class="form-select mb-3"><option value="">Select county</option>{% for c in counties %}<option value="{{c.id}}">{{c.name}}</option>{% endfor %}</select>
  <label class="form-label">Constituency</label><select id="geoCon" class="form-select mb-3" disabled><option value="">Select county first</option></select>
  <label class="form-label">Ward</label><select id="geoWard" class="form-select" disabled><option value="">Select constituency first</option></select>
  <div id="geoStatus" class="small text-muted mt-3">Choose a county to browse its constituencies.</div>
 </div></div>
 <div class="col-lg-5"><div class="card card-body"><h4>Reference Data</h4><p><strong>{{county_count}}</strong> counties</p><p><strong>{{constituency_count}}</strong> constituencies</p><p><strong>{{ward_count}}</strong> wards</p><div class="alert alert-info mb-0">Imported geography is reference data. Manual additions are kept under Advanced Geography Administration.</div></div></div>
</div>
<details class="card card-body"><summary class="fw-bold">Advanced Geography Administration</summary><div class="row g-4 mt-1">
 <div class="col-md-6"><form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="kind" value="constituency"><h5>Add Constituency</h5><select class="form-select mb-2" name="county_id" required><option value="">Select county</option>{% for c in counties %}<option value="{{c.id}}">{{c.name}}</option>{% endfor %}</select><input class="form-control mb-2" name="name" required placeholder="Constituency"><button class="btn btn-outline-primary">Add Constituency</button></form></div>
 <div class="col-md-6"><form method="post"><input type="hidden" name="csrf_token" value="{{ csrf_token() }}"><input type="hidden" name="kind" value="ward"><h5>Add Ward</h5><select id="adminCounty" class="form-select mb-2"><option value="">Select county first</option>{% for c in counties %}<option value="{{c.id}}">{{c.name}}</option>{% endfor %}</select><select id="adminCon" class="form-select mb-2" name="constituency_id" required disabled><option value="">Select county first</option></select><input class="form-control mb-2" name="name" required placeholder="Ward"><button class="btn btn-outline-primary">Add Ward</button></form></div>
</div></details>
<script>
async function getJSON(url){const r=await fetch(url); if(!r.ok) throw new Error('Unable to load geography'); return r.json();}
const gc=document.getElementById('geoCounty'), gx=document.getElementById('geoCon'), gw=document.getElementById('geoWard'), gs=document.getElementById('geoStatus');
gc.addEventListener('change', async()=>{gx.disabled=true; gw.disabled=true; gw.innerHTML='<option value="">Select constituency first</option>'; if(!gc.value){gx.innerHTML='<option value="">Select county first</option>';gs.textContent='Choose a county to browse its constituencies.';return;} const rows=await getJSON('/api/constituencies/'+gc.value); gx.innerHTML='<option value="">Select constituency</option>'+rows.map(x=>`<option value="${x.id}">${x.name}</option>`).join(''); gx.disabled=false; gs.textContent=rows.length+' constituencies loaded for the selected county.';});
gx.addEventListener('change', async()=>{gw.disabled=true;if(!gx.value){gw.innerHTML='<option value="">Select constituency first</option>';return;}const rows=await getJSON('/api/wards/'+gx.value);gw.innerHTML='<option value="">Select ward</option>'+rows.map(x=>`<option value="${x.id}">${x.name}</option>`).join('');gw.disabled=false;gs.textContent=rows.length+' wards loaded for the selected constituency.';});
const ac=document.getElementById('adminCounty'), ax=document.getElementById('adminCon'); ac.addEventListener('change',async()=>{ax.disabled=true;if(!ac.value){ax.innerHTML='<option value="">Select county first</option>';return;}const rows=await getJSON('/api/constituencies/'+ac.value);ax.innerHTML='<option value="">Select constituency</option>'+rows.map(x=>`<option value="${x.id}">${x.name}</option>`).join('');ax.disabled=false;});
</script>{% endblock %}"""

CONTESTS_V3 = """{% extends 'base.html' %}{% block content %}
<style>
.contest-stat{font-size:1.55rem;font-weight:700;color:#17375e}.filter-label{font-weight:600;color:#294866}.contest-table td,.contest-table th{vertical-align:middle}.readiness-row{display:flex;justify-content:space-between;gap:1rem;padding:.45rem 0;border-bottom:1px solid #edf0f3}.readiness-row:last-child{border-bottom:0}.scope-card{border-left:4px solid #0d6efd}.protected-note{background:#eef7ff;border:1px solid #cfe7fb;color:#315a78;border-radius:.5rem;padding:.7rem .85rem}
</style>
<div class="d-flex justify-content-between align-items-start flex-wrap gap-3 mb-3"><div><h2 class="mb-1">Election Contests</h2><p class="text-muted mb-0">Browse and verify contests for the current election without scrolling through the full national list.</p></div><a class="btn btn-outline-secondary" href="{{url_for('manage_elections')}}">Election Management</a></div>
<div class="card card-body mb-4 scope-card"><div class="row g-3 align-items-center"><div class="col-lg-7"><h4 class="mb-1">{{election.title}}</h4><div class="text-muted">{{'General Election' if election.election_type=='general' else 'By-Election'}}{% if election.election_date %} · {{election.election_date.strftime('%d %B %Y')}}{% endif %}</div></div><div class="col-lg-5 text-lg-end"><span class="badge text-bg-primary">{{total_contests}} CONTESTS</span> <span class="badge {{'text-bg-success' if election.is_open else 'text-bg-secondary'}}">VOTING {{'OPEN' if election.is_open else 'CLOSED'}}</span> <span class="badge {{'text-bg-success' if election.results_visible else 'text-bg-secondary'}}">RESULTS {{'RELEASED' if election.results_visible else 'NOT RELEASED'}}</span></div></div></div>
<div class="row g-3 mb-4">
{% for item in summary %}<div class="col-md-4 col-xl-2"><div class="card card-body h-100"><div class="contest-stat">{{item.count}}</div><div>{{item.label}}</div></div></div>{% endfor %}
</div>
<div class="row g-4 mb-4"><div class="col-lg-8"><div class="card card-body h-100"><div class="d-flex justify-content-between flex-wrap gap-2 mb-3"><div><h4 class="mb-1">Contest Browser</h4><div class="text-muted small">Filter by position and electoral area.</div></div><input id="contestSearch" class="form-control" style="max-width:250px" placeholder="Search contests..."></div>
<div class="row g-2 mb-3"><div class="col-md-3"><label class="filter-label form-label">Position</label><select id="filterPosition" class="form-select"><option value="">All positions</option>{% for p in positions %}<option>{{p}}</option>{% endfor %}</select></div><div class="col-md-3" id="filterCountyWrap"><label class="filter-label form-label">County</label><select id="filterCounty" class="form-select"><option value="">All counties</option>{% for c in counties %}<option value="{{c.id}}">{{c.name}}</option>{% endfor %}</select></div><div class="col-md-3" id="filterConWrap"><label class="filter-label form-label">Constituency</label><select id="filterCon" class="form-select" disabled><option value="">All constituencies</option></select></div><div class="col-md-3" id="filterWardWrap"><label class="filter-label form-label">Ward</label><select id="filterWard" class="form-select" disabled><option value="">All wards</option></select></div></div>
<div class="table-responsive" style="max-height:560px;overflow:auto"><table class="table table-hover contest-table" id="contestTable"><thead class="sticky-top bg-white"><tr><th>Position</th><th>Area</th><th>Candidates</th></tr></thead><tbody>{% for c in contests %}<tr data-position="{{c.position}}" data-county="{{c.county_id or ''}}" data-con="{{c.constituency_id or ''}}" data-ward="{{c.ward_id or ''}}"><td>{{c.position}}</td><td>{{area(c)}}</td><td><span class="badge {{'text-bg-success' if candidate_counts.get(c.id,0) else 'text-bg-light border'}}">{{candidate_counts.get(c.id,0)}}</span></td></tr>{% endfor %}</tbody></table></div><div class="small text-muted mt-2" id="visibleCount"></div></div></div>
<div class="col-lg-4"><div class="card card-body h-100"><h4>Election Readiness</h4><div class="readiness-row"><span>Contests created</span><strong>{{total_contests}}</strong></div><div class="readiness-row"><span>Geography</span><strong>{{'VERIFIED' if geography_verified else 'CHECK'}}</strong></div><div class="readiness-row"><span>Contests with candidates</span><strong>{{contests_with_candidates}} / {{total_contests}}</strong></div><div class="readiness-row"><span>Without candidates</span><strong>{{contests_without_candidates}}</strong></div><div class="readiness-row"><span>Voting</span><strong>{{'OPEN' if election.is_open else 'CLOSED'}}</strong></div><div class="readiness-row"><span>Results</span><strong>{{'RELEASED' if election.results_visible else 'NOT RELEASED'}}</strong></div><hr><a class="btn btn-outline-primary" href="{{url_for('manage_candidates')}}">Manage Candidates</a></div></div></div>
{% if election.election_type=='general' %}<div class="protected-note"><strong>Protected General Election structure.</strong> These contests were automatically generated from verified electoral geography. Manual contest creation is disabled to prevent duplicate or inconsistent contests.</div>{% else %}<details class="card card-body"><summary class="fw-bold">Advanced By-Election Contest Administration</summary><div class="alert alert-warning mt-3">A By-Election normally contains only the vacancy contest created with the election. Add another contest only when deliberately required.</div><form method="post" class="row g-2" id="contestForm"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><div class="col-md-3"><label class="filter-label form-label">Position</label><select class="form-select" id="position" name="position"><option value="">Select position...</option>{% for p in positions %}<option>{{p}}</option>{% endfor %}</select></div><div class="col-md-3" id="countyWrap"><label class="filter-label form-label">County</label><select class="form-select" id="contestCounty" name="county_id"><option value="">Select county...</option>{% for c in counties %}<option value="{{c.id}}">{{c.name}}</option>{% endfor %}</select></div><div class="col-md-3" id="constituencyWrap"><label class="filter-label form-label">Constituency</label><select class="form-select" id="contestConstituency" name="constituency_id" disabled><option value="">Select county first</option></select></div><div class="col-md-3" id="wardWrap"><label class="filter-label form-label">Ward</label><select class="form-select" id="contestWard" name="ward_id" disabled><option value="">Select constituency first</option></select></div><div class="col-12"><button class="btn btn-primary">Create By-Election Contest</button></div></form></details>{% endif %}
<script>
const fp=document.getElementById('filterPosition'),fc=document.getElementById('filterCounty'),fx=document.getElementById('filterCon'),fw=document.getElementById('filterWard'),q=document.getElementById('contestSearch');
const fcw=document.getElementById('filterCountyWrap'),fxw=document.getElementById('filterConWrap'),fww=document.getElementById('filterWardWrap');
function filterMode(){const p=fp.value,n=p==='President',countyOnly=['Governor','Senator','Woman Representative'].includes(p),mp=p==='Member of Parliament',mca=p==='Member of County Assembly';fcw.style.display=(p&&n)?'none':'';fxw.style.display=(p&&(n||countyOnly))?'none':'';fww.style.display=(p&&(n||countyOnly||mp))?'none':'';if(n){fc.value='';fx.value='';fw.value='';fx.disabled=true;fw.disabled=true;}else if(countyOnly){fx.value='';fw.value='';fx.disabled=true;fw.disabled=true;}else if(mp){fw.value='';fw.disabled=true;}filterRows();}
function filterRows(){let n=0;document.querySelectorAll('#contestTable tbody tr').forEach(r=>{let ok=(!fp.value||r.dataset.position===fp.value)&&(!fc.value||r.dataset.county===fc.value)&&(!fx.value||r.dataset.con===fx.value)&&(!fw.value||r.dataset.ward===fw.value)&&(!q.value||r.innerText.toLowerCase().includes(q.value.toLowerCase()));r.style.display=ok?'':'none';if(ok)n++;});document.getElementById('visibleCount').textContent=n+' contest(s) shown.';}
fp.addEventListener('change',filterMode);q.addEventListener('input',filterRows);fc.addEventListener('change',async()=>{fx.disabled=true;fw.disabled=true;fx.innerHTML='<option value="">All constituencies</option>';fw.innerHTML='<option value="">All wards</option>';if(fc.value){const rows=await fetch('/api/constituencies/'+fc.value).then(r=>r.json());fx.innerHTML='<option value="">All constituencies</option>'+rows.map(x=>`<option value="${x.id}">${x.name}</option>`).join('');fx.disabled=false;}filterRows();});fx.addEventListener('change',async()=>{fw.disabled=true;fw.innerHTML='<option value="">All wards</option>';if(fx.value){const rows=await fetch('/api/wards/'+fx.value).then(r=>r.json());fw.innerHTML='<option value="">All wards</option>'+rows.map(x=>`<option value="${x.id}">${x.name}</option>`).join('');fw.disabled=false;}filterRows();});fw.addEventListener('change',filterRows);filterMode();
{% if election.election_type!='general' %}const pos=document.getElementById('position'),cw=document.getElementById('countyWrap'),xw=document.getElementById('constituencyWrap'),ww=document.getElementById('wardWrap'),county=document.getElementById('contestCounty'),con=document.getElementById('contestConstituency'),ward=document.getElementById('contestWard');function mode(){const p=pos.value,n=p==='President',co=['Governor','Senator','Woman Representative'].includes(p),mp=p==='Member of Parliament';cw.style.display=(!p||n)?'none':'';xw.style.display=(!p||n||co)?'none':'';ww.style.display=(!p||n||co||mp)?'none':'';}pos.addEventListener('change',mode);mode();county.addEventListener('change',async()=>{con.disabled=true;ward.disabled=true;ward.innerHTML='<option value="">Select constituency first</option>';if(!county.value)return;const rows=await fetch('/api/constituencies/'+county.value).then(r=>r.json());con.innerHTML='<option value="">Select constituency...</option>'+rows.map(x=>`<option value="${x.id}">${x.name}</option>`).join('');con.disabled=false;});con.addEventListener('change',async()=>{ward.disabled=true;if(!con.value)return;const rows=await fetch('/api/wards/'+con.value).then(r=>r.json());ward.innerHTML='<option value="">Select ward...</option>'+rows.map(x=>`<option value="${x.id}">${x.name}</option>`).join('');ward.disabled=false;});{% endif %}
</script>{% endblock %}"""

ELECTIONS_RC7 = """{% extends 'base.html' %}{% block content %}
<style>.election-form .form-label{font-weight:600;color:#294866}.election-form .form-select,.election-form .form-control{font-weight:600;color:#263f5d;background:#f4f8fc;border-color:#cbd9e7}</style>
<h2>Election Management</h2><p class="text-muted">Create either a five-year General Election or a vacancy By-Election. Each election keeps its own contests, ballots and results.</p>
<div class="card card-body mb-4 election-form"><h4>Create Election</h4><form method="post"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="action" value="create">
<div class="row g-3"><div class="col-md-5"><label class="form-label">Election title</label><input class="form-control" name="title" required placeholder="e.g. Kenya General Election"></div><div class="col-md-3"><label class="form-label">Election type</label><select class="form-select" id="etype" name="election_type"><option value="general">General Election</option><option value="by_election">By-Election</option></select></div><div class="col-md-4"><label class="form-label">Election date</label><input class="form-control" type="date" name="election_date" required></div></div>
<div id="byFields" class="mt-3" style="display:none"><div class="alert alert-info py-2">A By-Election creates one vacant-seat contest only.</div><div class="row g-3"><div class="col-md-3"><label class="form-label">Position</label><select class="form-select" id="byPos" name="position">{% for p in by_positions %}<option>{{p}}</option>{% endfor %}</select></div><div class="col-md-3" id="byCountyWrap"><label class="form-label">County</label><select class="form-select" id="byCounty" name="county_id"><option value="">Select county</option>{% for c in counties %}<option value="{{c.id}}">{{c.name}}</option>{% endfor %}</select></div><div class="col-md-3" id="byConWrap"><label class="form-label">Constituency</label><select class="form-select" id="byCon" name="constituency_id" disabled><option value="">Select county first</option></select></div><div class="col-md-3" id="byWardWrap"><label class="form-label">Ward</label><select class="form-select" id="byWard" name="ward_id" disabled><option value="">Select constituency first</option></select></div></div></div>
<div class="form-check mt-3"><input class="form-check-input" type="checkbox" name="make_current" id="makeCurrent" checked><label class="form-check-label" for="makeCurrent">Make this the current election</label></div><button class="btn btn-primary mt-3">Create Election</button></form></div>
<div class="card card-body"><h4>Election History</h4><div class="table-responsive"><table class="table align-middle"><thead><tr><th>Election</th><th>Type</th><th>Date</th><th>Contests</th><th>Status</th><th></th></tr></thead><tbody>{% for e in elections %}<tr><td><strong>{{e.title}}</strong></td><td>{{'General Election' if e.election_type=='general' else 'By-Election'}}</td><td>{{e.election_date or '-'}}</td><td>{{contest_counts.get(e.id,0)}}</td><td>{% if e.is_current %}<span class="badge text-bg-success">CURRENT</span>{% else %}<span class="badge text-bg-secondary">HISTORICAL</span>{% endif %}</td><td>{% if not e.is_current %}<form method="post"><input type="hidden" name="csrf_token" value="{{csrf_token()}}"><input type="hidden" name="action" value="select"><input type="hidden" name="election_id" value="{{e.id}}"><button class="btn btn-sm btn-outline-primary">Make Current</button></form>{% endif %}</td></tr>{% endfor %}</tbody></table></div></div>
<script>
const et=document.getElementById('etype'), bf=document.getElementById('byFields'), bp=document.getElementById('byPos'), bc=document.getElementById('byCounty'), bx=document.getElementById('byCon'), bw=document.getElementById('byWard'), bcw=document.getElementById('byCountyWrap'), bxw=document.getElementById('byConWrap'), bww=document.getElementById('byWardWrap');
function typeMode(){bf.style.display=et.value==='by_election'?'':'none'}; et.addEventListener('change',typeMode);typeMode();
function posMode(){const p=bp.value,n=p==='President',co=['Governor','Senator','Woman Representative'].includes(p),mp=p==='Member of Parliament';bcw.style.display=n?'none':'';bxw.style.display=(n||co)?'none':'';bww.style.display=(n||co||mp)?'none':'';}bp.addEventListener('change',posMode);posMode();
bc.addEventListener('change',async()=>{bx.disabled=true;bw.disabled=true;bw.innerHTML='<option value="">Select constituency first</option>';if(!bc.value)return;const r=await fetch('/api/constituencies/'+bc.value).then(x=>x.json());bx.innerHTML='<option value="">Select constituency</option>'+r.map(x=>`<option value="${x.id}">${x.name}</option>`).join('');bx.disabled=false});
bx.addEventListener('change',async()=>{bw.disabled=true;if(!bx.value)return;const r=await fetch('/api/wards/'+bx.value).then(x=>x.json());bw.innerHTML='<option value="">Select ward</option>'+r.map(x=>`<option value="${x.id}">${x.name}</option>`).join('');bw.disabled=false});
</script>{% endblock %}"""

AUDIT_LOG_HTML = """
{% extends "base.html" %}{% block content %}
<div class="card"><div class="card-body p-4"><div class="d-flex justify-content-between"><div><h2>Full Security Audit Log</h2><p class="text-muted">Immutable application audit history. Dashboard Clear View does not delete these records.</p></div><a class="btn btn-outline-secondary align-self-start" href="{{ url_for('admin_dashboard') }}">Back to Admin</a></div>
<form class="row g-2 mb-3" method="GET"><div class="col-md-4"><input class="form-control" name="event" value="{{ event_filter }}" placeholder="Event type contains..."></div><div class="col-md-3"><select class="form-select" name="severity"><option value="">All severities</option>{% for s in ['INFO','WARNING','ERROR','CRITICAL'] %}<option {% if severity_filter==s %}selected{% endif %}>{{s}}</option>{% endfor %}</select></div><div class="col"><button class="btn btn-primary">Filter</button> <a class="btn btn-outline-secondary" href="{{ url_for('full_audit_log') }}">Reset</a></div></form>
<div class="table-responsive"><table class="table table-sm"><thead><tr><th>Time</th><th>Event</th><th>Severity</th><th>User ID</th><th>Details</th></tr></thead><tbody>{% for e in events %}<tr><td>{{e.created_at}}</td><td>{{e.event_type}}</td><td>{{e.severity}}</td><td>{{e.user_id or '-'}}</td><td>{{e.details or ''}}</td></tr>{% else %}<tr><td colspan="5">No matching events.</td></tr>{% endfor %}</tbody></table></div>
</div></div>{% endblock %}
"""


VOTER_DASHBOARD_HTML = """
{% extends "base.html" %}
{% block title %}Voter Dashboard — Kenya Secure E-Voting{% endblock %}
{% block content %}
<div class="row justify-content-center">
  <div class="col-lg-9">
    <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
      <div><h2 class="mb-1">Welcome, {{ user.full_name }}</h2>
      <p class="text-muted mb-0">{{ election.title }}</p></div>
      <span class="badge {{ 'text-bg-success' if voting_open else 'text-bg-secondary' }} fs-6">
        Voting {{ 'OPEN' if voting_open else 'CLOSED' }}</span>
    </div>
    <div class="card mb-3"><div class="card-body">
      <h5>Your Electoral Area</h5>
      <div class="row g-2">
        <div class="col-md-4"><strong>County</strong><br>{{ area.county }}</div>
        <div class="col-md-4"><strong>Constituency</strong><br>{{ area.constituency }}</div>
        <div class="col-md-4"><strong>Ward</strong><br>{{ area.ward }}</div>
      </div>
    </div></div>
    <div class="row g-3 mb-3">
      <div class="col-sm-6"><div class="card"><div class="card-body">
        <div class="text-muted">Eligible contests</div><div class="display-6">{{ eligible_count }}</div>
      </div></div></div>
      <div class="col-sm-6"><div class="card"><div class="card-body">
        <div class="text-muted">Ballots submitted</div>
        <div class="display-6">{{ completed_count }} / {{ eligible_count }}</div>
      </div></div></div>
    </div>
    <div class="card"><div class="card-body">
      <h4>My Ballot</h4>
      <p class="text-muted">Choose when to open your ballot. Each eligible contest can be voted in once.</p>
      {% if voting_open %}
        {% if eligible_count > completed_count %}
          <a class="btn btn-emerald btn-lg" href="{{ url_for('vote') }}">Open My Ballot &rarr;</a>
        {% elif eligible_count > 0 %}
          <div class="alert alert-success mb-0">All your eligible ballots have been submitted.</div>
        {% else %}
          <div class="alert alert-warning mb-0">No eligible contests were found for your electoral area.</div>
        {% endif %}
      {% else %}
        <div class="alert alert-secondary mb-0">Voting is currently closed. Your ballot is unavailable.</div>
      {% endif %}
      {% if contest_statuses %}
      <hr class="my-3">
      <h5>My contest submission status</h5>
      <p class="text-muted small">This shows whether a vote was recorded for each eligible contest, without revealing your candidate selections.</p>
      <div class="list-group mb-3">
        {% for item in contest_statuses %}
        <div class="list-group-item d-flex justify-content-between align-items-center gap-2">
          <span>{{ item.position }}</span>
          <span class="badge {{ 'text-bg-success' if item.recorded else 'text-bg-secondary' }}">{{ 'Vote recorded' if item.recorded else 'Not submitted' }}</span>
        </div>
        {% endfor %}
      </div>
      {% endif %}
      <div class="mt-3"><a href="{{ url_for('results') }}">View Election Audit &amp; Results</a></div>
    </div></div>
  </div>
</div>
{% endblock %}
"""

app.jinja_loader = DictLoader({
    "base.html": BASE_HTML,
    "home.html": HOME_HTML,
    "voter_dashboard.html": VOTER_DASHBOARD_HTML,
    "register.html": REGISTER_HTML,
    "login.html": LOGIN_HTML,
    "forgot_password.html": FORGOT_PASSWORD_HTML,
    "reset_password.html": RESET_PASSWORD_HTML,
    "vote.html": VOTE_HTML,
    "results.html": RESULTS_HTML,
    "admin.html": ADMIN_HTML,
    "audit_log.html": AUDIT_LOG_HTML,
    "candidates.html": CANDIDATES_HTML,
    "regions.html": REGIONS_HTML,
    "geography_v3.html": GEOGRAPHY_V3,
    "contests_v3.html": CONTESTS_V3,
    "elections_rc7.html": ELECTIONS_RC7,
})


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------

@app.route("/")
def home():
    election = get_election()
    return render_template_string(HOME_HTML, election=election, voting_open=election_is_open(election))



@app.route("/voter-dashboard")
@login_required
def voter_dashboard():
    user = current_user()
    if not user:
        session.clear()
        return redirect(url_for("login"))
    if user.role == "admin":
        return redirect(url_for("admin_dashboard"))
    election = get_election()
    contests = eligible_contests_for(user)
    contest_ids = [contest.id for contest in contests]
    completed_count = (BallotReceipt.query.filter(
        BallotReceipt.user_id == user.id,
        BallotReceipt.contest_id.in_(contest_ids)
    ).count() if contest_ids else 0)
    recorded_ids = set(
        row.contest_id for row in BallotReceipt.query.filter(
            BallotReceipt.user_id == user.id,
            BallotReceipt.contest_id.in_(contest_ids)
        ).all()
    ) if contest_ids else set()
    contest_statuses = [
        {"position": contest.position, "recorded": contest.id in recorded_ids}
        for contest in contests
    ]
    return render_template_string(
        VOTER_DASHBOARD_HTML,
        user=user, election=election, area=voter_area(user),
        contest_statuses=contest_statuses,
        voting_open=election_is_open(election),
        eligible_count=len(contests), completed_count=completed_count
    )


@app.route("/api/constituencies/<int:county_id>")
def api_constituencies(county_id):
    rows=Constituency.query.filter_by(county_id=county_id, active=True).order_by(Constituency.name).all()
    return app.response_class(json.dumps([{"id":x.id,"name":x.name} for x in rows]), mimetype="application/json")

@app.route("/api/wards/<int:constituency_id>")
def api_wards(constituency_id):
    rows=Ward.query.filter_by(constituency_id=constituency_id, active=True).order_by(Ward.name).all()
    return app.response_class(json.dumps([{"id":w.id,"name":w.name} for w in rows]), mimetype="application/json")

@app.route("/register", methods=["GET", "POST"])
def register():
    regions=Region.query.filter(Region.active.is_(True), Region.code != "LEGACY").order_by(Region.name).all()
    selected_region=selected_constituency=selected_ward=""
    if request.method == "POST":
        validate_csrf()
        full_name=request.form.get("full_name","").strip(); email=request.form.get("email","").strip().lower()
        national_id=request.form.get("national_id","").strip(); password=request.form.get("password","")
        selected_region=request.form.get("region_id","").strip(); selected_constituency=request.form.get("constituency_id","").strip(); selected_ward=request.form.get("ward_id","").strip()
        region=Region.query.get(int(selected_region)) if selected_region.isdigit() else None
        constituency=Constituency.query.get(int(selected_constituency)) if selected_constituency.isdigit() else None
        ward=Ward.query.get(int(selected_ward)) if selected_ward.isdigit() else None
        errors=[]
        if not full_name: errors.append("Full name is required.")
        if not EMAIL_REGEX.match(email): errors.append("A valid email address is required.")
        if not NATIONAL_ID_REGEX.match(national_id): errors.append("National ID must be 7 to 8 numeric digits.")
        if len(password)<8: errors.append("Password must be at least 8 characters long.")
        if not region or not region.active or region.code=="LEGACY": errors.append("Please select a valid county.")
        if not constituency or not region or constituency.county_id != region.id: errors.append("Please select a constituency within your county.")
        if not ward or not constituency or ward.constituency_id != constituency.id: errors.append("Please select a ward within your constituency.")
        if not errors and User.query.filter_by(email=email).first(): errors.append("An account with this email already exists.")
        if not errors and User.query.filter_by(national_id=national_id).first(): errors.append("This National ID is already registered (one voter, one registration).")
        if errors:
            for e in errors: flash(e,"danger")
            return render_template_string(REGISTER_HTML,full_name=full_name,email=email,national_id=national_id,regions=regions,selected_region=selected_region,selected_constituency=selected_constituency,selected_ward=selected_ward)
        token=secrets.token_urlsafe(48)
        user=User(full_name=full_name,email=email,national_id=national_id,region_id=region.id,constituency_id=constituency.id,ward_id=ward.id,email_verified=False,email_verification_token=token,email_verification_expires_at=datetime.utcnow()+timedelta(seconds=EMAIL_VERIFICATION_MAX_AGE_SECONDS))
        user.set_password(password)
        try: db.session.add(user); db.session.commit()
        except IntegrityError:
            db.session.rollback(); flash("Email or National ID already registered.","danger")
            return render_template_string(REGISTER_HTML,regions=regions,selected_region=selected_region,selected_constituency=selected_constituency,selected_ward=selected_ward)
        verification_url=url_for("verify_email",token=token,_external=True)
        if send_email_verification_email(user.email,verification_url): flash("Registration successful. Please check your email and click the verification link before logging in.","success")
        else: flash("Registration was created, but the verification email could not be sent. Please use the resend verification option.","warning")
        return redirect(url_for("login"))
    return render_template_string(REGISTER_HTML,regions=regions,selected_region="",selected_constituency="",selected_ward="")


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
        flash("This email verification link has expired. Please request a new one.", "danger")
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
                datetime.utcnow() + timedelta(seconds=EMAIL_VERIFICATION_MAX_AGE_SECONDS)
            )
            db.session.commit()

            verification_url = url_for(
                "verify_email", token=token, _external=True
            )
            send_email_verification_email(user.email, verification_url)

        flash(
            "If an unverified account exists for that email, a new verification link "
            "has been sent.",
            "info",
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
            <p class="text-muted small">Enter the email address used during registration.</p>
            <form method="POST">
              <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
              <div class="mb-3">
                <label class="form-label">Registered Email</label>
                <input type="email" class="form-control" name="email" required autofocus>
              </div>
              <button type="submit" class="btn btn-primary w-100">Resend Verification Link</button>
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
                "warning",
            )
            return redirect(url_for("resend_verification"))

        # ADMIN_EMAIL is authoritative for the staging/demo administrator.
        # Promote on login too, so an account created after service startup gains
        # admin access without requiring another restart.
        if ADMIN_EMAIL and user.email.strip().lower() == ADMIN_EMAIL:
            if user.role != "admin":
                user.role = "admin"
                db.session.commit()
                log_event("ADMIN_ROLE_GRANTED", "INFO", user.id,
                          "Administrator role granted from ADMIN_EMAIL during login.")

        session.clear()
        session["user_id"] = user.id
        session["user_name"] = user.full_name

        flash(f"Welcome, {user.full_name}.", "success")
        if user.role == "admin":
            return redirect(url_for("admin_dashboard"))
        # V3 completion is per contest via BallotReceipt. The legacy global
        # User.has_voted flag must not block a voter from remaining contests.
        return redirect(url_for("voter_dashboard"))

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
                salt=RESET_SALT,
            )
            expires_at = datetime.utcnow() + timedelta(seconds=RESET_TOKEN_MAX_AGE_SECONDS)

            # Invalidate any previous outstanding tokens for this user
            PasswordResetToken.query.filter_by(user_id=user.id, used=False).update({"used": True})

            db.session.add(PasswordResetToken(
                user_id=user.id, token=token, expires_at=expires_at
            ))
            db.session.commit()

            reset_url = url_for("reset_password", token=token, _external=True)
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
            token, salt=RESET_SALT, max_age=RESET_TOKEN_MAX_AGE_SECONDS
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
    if not user:
        session.clear(); return redirect(url_for("login"))
    election = get_election()
    if not election_is_open(election):
        flash("Voting is closed. You can review your ballot submission status below.", "info"); return redirect(url_for("voter_dashboard"))

    contests = eligible_contests_for(user)
    if request.method == "POST":
        validate_csrf()
        selected = []
        for contest in contests:
            raw = request.form.get(f"contest_{contest.id}", "").strip()
            if not raw: continue
            if BallotReceipt.query.filter_by(user_id=user.id, contest_id=contest.id).first():
                continue
            if not raw.isdigit():
                flash(f"Invalid candidate selection for {contest.position}.", "danger"); return redirect(url_for("vote"))
            candidate_id = int(raw)
            link = ContestCandidate.query.filter_by(contest_id=contest.id, candidate_id=candidate_id).first()
            candidate = Candidate.query.get(candidate_id)
            if not link or not candidate or candidate.status != "active":
                flash(f"Candidate is not eligible for the {contest.position} contest.", "danger"); return redirect(url_for("vote"))
            selected.append((contest, candidate))
        if not selected:
            flash("Select at least one candidate in an uncast contest.", "warning"); return redirect(url_for("vote"))

        try:
            previous_hash = get_last_vote_hash()
            for contest, candidate in selected:
                # The receipt proves participation in a contest but deliberately contains no candidate choice.
                db.session.add(BallotReceipt(user_id=user.id, contest_id=contest.id))
                payload = json.dumps({
                    "candidate_id": candidate.id, "contest_id": contest.id, "election_id": contest.election_id,
                    "scope_level": contest.scope_level, "county_id": user.region_id,
                    "constituency_id": user.constituency_id, "ward_id": user.ward_id,
                    "cast_at": datetime.utcnow().isoformat(), "nonce": secrets.token_hex(16),
                }, separators=(",", ":"))
                encrypted_str = fernet.encrypt(payload.encode()).decode()
                current_hash = compute_chain_hash(encrypted_str, previous_hash)
                db.session.add(Vote(encrypted_vote=encrypted_str, previous_hash=previous_hash,
                    current_hash=current_hash, key_version=os.environ.get("AES_KEY_VERSION", "v1"),
                    region_id=user.region_id, election_id=contest.election_id, contest_id=contest.id))
                previous_hash = current_hash
            db.session.commit()
        except IntegrityError:
            db.session.rollback(); log_event("DUPLICATE_CONTEST_VOTE_BLOCKED", "WARNING", user.id, "Unique voter/contest receipt blocked duplicate submission")
            flash("One of those contests has already been voted. No duplicate vote was recorded.", "warning"); return redirect(url_for("vote"))
        except Exception as exc:
            db.session.rollback(); log_event("BALLOT_WRITE_FAILURE", "ERROR", user.id, str(exc))
            flash("The ballot could not be recorded. No partial submission was committed.", "danger"); return redirect(url_for("vote"))
        log_event("VOTE_CAST", "INFO", user.id, f"Recorded {len(selected)} contest ballot(s); choices remain encrypted")
        flash(f"Successfully recorded {len(selected)} encrypted contest vote(s).", "success")
        return redirect(url_for("vote"))

    receipts = {r.contest_id for r in BallotReceipt.query.filter_by(user_id=user.id).all()}
    rows=[]
    for c in contests:
        rows.append({"contest":c,"area":contest_area_name(c),"candidates":candidates_for_contest(c.id),"cast":c.id in receipts})
    return render_template_string(VOTE_HTML, contest_rows=rows, open_count=sum(1 for r in rows if not r["cast"] and r["candidates"]))



ALLOWED_IMAGE_MIMES = {"image/jpeg", "image/png", "image/webp"}
MAX_CANDIDATE_IMAGE_BYTES = 1024 * 1024

def uploaded_image_data_url(field_name):
    """Return a small validated image as a data URL, or None when no file supplied."""
    f = request.files.get(field_name)
    if not f or not f.filename:
        return None
    mime = (f.mimetype or "").lower()
    if mime not in ALLOWED_IMAGE_MIMES:
        raise ValueError("Images must be JPG, PNG or WebP.")
    raw = f.read(MAX_CANDIDATE_IMAGE_BYTES + 1)
    if len(raw) > MAX_CANDIDATE_IMAGE_BYTES:
        raise ValueError("Each image must be 1 MB or smaller.")
    # Lightweight signature validation prevents a renamed arbitrary file.
    valid = ((mime == "image/jpeg" and raw[:3] == bytes([0xFF, 0xD8, 0xFF])) or
             (mime == "image/png" and raw[:8] == bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])) or
             (mime == "image/webp" and raw[:4] == b"RIFF" and raw[8:12] == b"WEBP"))
    if not valid:
        raise ValueError("The uploaded file does not appear to be a valid image.")
    return f"data:{mime};base64," + base64.b64encode(raw).decode("ascii")

def candidate_number_in_election(election_id, candidate_number, exclude_candidate_id=None):
    """Return True when a candidate number is already used anywhere in this election."""
    q = (db.session.query(Candidate.id)
         .join(ContestCandidate, ContestCandidate.candidate_id == Candidate.id)
         .join(Contest, Contest.id == ContestCandidate.contest_id)
         .filter(Contest.election_id == election_id,
                 Candidate.candidate_number == candidate_number))
    if exclude_candidate_id is not None:
        q = q.filter(Candidate.id != exclude_candidate_id)
    return q.first() is not None

@app.route("/admin/candidates", methods=["GET", "POST"])
@admin_required
def manage_candidates():
    user = current_user()
    election = get_election()
    if request.method == "POST":
        validate_csrf()
        action = request.form.get("action")
        if action == "add":
            name=request.form.get("name","").strip(); party=request.form.get("party","").strip(); abbr=request.form.get("abbreviation","").strip().upper(); cr=request.form.get("contest_id","")
            contest=Contest.query.filter_by(id=int(cr), election_id=election.id, active=True).first() if cr.isdigit() else None
            if not contest:
                flash("Select a valid contest in the current election.","danger"); return redirect(url_for("manage_candidates"))
            candidate_number=request.form.get("candidate_number","").strip()
            if not candidate_number:
                flash("Candidate number is required.","danger"); return redirect(url_for("manage_candidates"))
            if candidate_number_in_election(election.id, candidate_number):
                flash(f"Candidate number {candidate_number} is already in use for this election.","danger"); return redirect(url_for("manage_candidates"))
            if name and party and abbr:
                try:
                    photo=uploaded_image_data_url("candidate_photo"); symbol=uploaded_image_data_url("party_symbol")
                except ValueError as exc:
                    flash(str(exc),"danger"); return redirect(url_for("manage_candidates"))
                c=Candidate(name=name,party=party,abbreviation=abbr,candidate_number=candidate_number,manifesto=request.form.get("manifesto","").strip() or None,photo_data=photo,party_symbol_data=symbol,status="active")
                db.session.add(c); db.session.flush(); db.session.add(ContestCandidate(contest_id=contest.id,candidate_id=c.id)); db.session.commit()
                log_event("CANDIDATE_CREATED","WARNING",user.id,f"{c.id}: {c.name}; contest={contest.id}; election={election.id}")
                flash(f"Candidate added to {contest.position} — {contest_area_name(contest)}.","success"); return redirect(url_for("manage_candidates"))
            flash("Name, party, abbreviation and candidate number are required.","danger")
        elif action == "edit":
            cid=request.form.get("candidate_id",""); c=Candidate.query.get(int(cid)) if cid.isdigit() else None
            if c:
                links=ContestCandidate.query.filter_by(candidate_id=c.id).all()
                if not any(Contest.query.filter_by(id=l.contest_id,election_id=election.id).first() for l in links):
                    abort(403)
                candidate_number=request.form.get("candidate_number","").strip()
                if not candidate_number:
                    flash("Candidate number is required.","danger"); return redirect(url_for("manage_candidates"))
                if candidate_number_in_election(election.id, candidate_number, exclude_candidate_id=c.id):
                    flash(f"Candidate number {candidate_number} is already in use for this election.","danger"); return redirect(url_for("manage_candidates"))
                c.name=request.form.get("name","").strip() or c.name
                c.party=request.form.get("party","").strip() or c.party
                c.abbreviation=request.form.get("abbreviation","").strip().upper() or c.abbreviation
                c.candidate_number=candidate_number
                c.manifesto=request.form.get("manifesto","").strip() or None
                try:
                    photo=uploaded_image_data_url("candidate_photo"); symbol=uploaded_image_data_url("party_symbol")
                except ValueError as exc:
                    flash(str(exc),"danger"); return redirect(url_for("manage_candidates"))
                if photo: c.photo_data=photo
                if symbol: c.party_symbol_data=symbol
                db.session.commit(); log_event("CANDIDATE_EDITED","WARNING",user.id,f"{c.id}: {c.name}")
                flash("Candidate details updated.","success"); return redirect(url_for("manage_candidates"))
        elif action == "toggle":
            cid=request.form.get("candidate_id",""); c=Candidate.query.get(int(cid)) if cid.isdigit() else None
            if c:
                c.status="withdrawn" if c.status=="active" else "active"; db.session.commit(); log_event("CANDIDATE_STATUS_CHANGED","WARNING",user.id,f"{c.id}: {c.status}"); flash("Candidate status updated.","success"); return redirect(url_for("manage_candidates"))
    contests=Contest.query.filter_by(active=True,election_id=election.id).order_by(Contest.id).all()
    counties=Region.query.filter(Region.code!="LEGACY",Region.active==True).order_by(Region.name).all()
    cons=Constituency.query.filter_by(active=True).order_by(Constituency.name).all(); ws=Ward.query.filter_by(active=True).order_by(Ward.name).all()
    contest_data=[{"id":c.id,"position":c.position,"scope_level":c.scope_level,"county_id":c.county_id,"constituency_id":c.constituency_id,"ward_id":c.ward_id,"area":contest_area_name(c)} for c in contests]
    candidate_data={}
    for link in ContestCandidate.query.filter(ContestCandidate.contest_id.in_([c.id for c in contests])).all() if contests else []:
        cand=Candidate.query.get(link.candidate_id)
        if cand: candidate_data.setdefault(str(link.contest_id),[]).append({"id":cand.id,"name":cand.name,"party":cand.party,"abbreviation":cand.abbreviation,"candidate_number":cand.candidate_number,"manifesto":cand.manifesto,"photo_data":cand.photo_data,"party_symbol_data":cand.party_symbol_data,"status":cand.status})
    return render_template_string(CANDIDATES_HTML,election=election,contest_data=contest_data,counties_data=[{"id":x.id,"name":x.name} for x in counties],constituencies_data=[{"id":x.id,"name":x.name,"county_id":x.county_id} for x in cons],wards_data=[{"id":x.id,"name":x.name,"constituency_id":x.constituency_id} for x in ws],candidate_data=candidate_data)


@app.route("/admin/regions", methods=["GET", "POST"])
@admin_required
def manage_regions():
    user = current_user()
    if request.method == "POST":
        validate_csrf()
        action = request.form.get("action")
        if action == "add":
            name = request.form.get("name", "").strip()
            short_code = request.form.get("code", "").strip().upper() or None
            if short_code and re.fullmatch(r"0(?:0[1-9]|[1-3][0-9]|4[0-7])", short_code):
                flash("Codes 001–047 are reserved for protected official counties.", "danger")
            elif name and not Region.query.filter(db.func.lower(Region.name) == name.lower()).first():
                r = Region(name=name, code=short_code, active=True)
                db.session.add(r); db.session.commit()
                log_event("MANUAL_COUNTY_CREATED", "WARNING", user.id, f"{r.id}: {r.name}")
                flash("Manual county record added.", "success")
                return redirect(url_for("manage_regions"))
            else:
                flash("Enter a unique county name.", "danger")
        elif action == "toggle":
            rid = request.form.get("region_id", "")
            r = Region.query.get(int(rid)) if rid.isdigit() else None
            if r and not (r.code == "LEGACY" or (r.code and re.fullmatch(r"0(?:0[1-9]|[1-3][0-9]|4[0-7])", r.code))):
                r.active = not r.active
                db.session.commit()
                log_event("MANUAL_COUNTY_STATUS_CHANGED", "WARNING", user.id, f"{r.id}: active={r.active}")
                flash("Manual county status updated.", "success")
                return redirect(url_for("manage_regions"))
            flash("Official reference counties and the legacy record are protected.", "warning")
    regions=Region.query.order_by(Region.name).all()
    official=[r for r in regions if r.code and re.fullmatch(r"0(?:0[1-9]|[1-3][0-9]|4[0-7])", r.code)]
    legacy=next((r for r in regions if r.code=="LEGACY"),None)
    manual=[r for r in regions if r not in official and r is not legacy]
    return render_template_string(REGIONS_HTML, official_regions=official, legacy_region=legacy, manual_regions=manual, official_count=len(official), constituency_count=Constituency.query.count(), ward_count=Ward.query.count())



POSITIONS = ["President", "Governor", "Senator", "Woman Representative", "Member of Parliament", "Member of County Assembly"]

def contest_area_name(c):
    if c.scope_level == "national": return "Kenya — National"
    if c.scope_level == "county":
        x=Region.query.get(c.county_id); return (x.name+" County") if x else "County"
    if c.scope_level == "constituency":
        x=Constituency.query.get(c.constituency_id); return x.name if x else "Constituency"
    x=Ward.query.get(c.ward_id); return x.name if x else "Ward"

@app.route("/admin/geography", methods=["GET","POST"])
@admin_required
def manage_geography():
    if request.method=="POST":
        validate_csrf(); kind=request.form.get("kind"); name=request.form.get("name","").strip()
        if kind=="constituency" and request.form.get("county_id","").isdigit():
            db.session.add(Constituency(name=name,county_id=int(request.form["county_id"])))
        elif kind=="ward" and request.form.get("constituency_id","").isdigit():
            db.session.add(Ward(name=name,constituency_id=int(request.form["constituency_id"])))
        db.session.commit(); flash("Electoral geography updated.","success"); return redirect(url_for("manage_geography"))
    counties = Region.query.filter(Region.code!="LEGACY").order_by(Region.name).all()
    return render_template_string(GEOGRAPHY_V3, counties=counties, county_count=len(counties), constituency_count=Constituency.query.count(), ward_count=Ward.query.count())

def _create_contest_if_missing(election_id, position, scope, county=None, constituency=None, ward=None):
    exists=Contest.query.filter_by(election_id=election_id,position=position,scope_level=scope,county_id=county,constituency_id=constituency,ward_id=ward).first()
    if not exists: db.session.add(Contest(election_id=election_id,position=position,scope_level=scope,county_id=county,constituency_id=constituency,ward_id=ward,active=True)); return 1
    return 0

def _build_general_election_contests(election_id):
    created=_create_contest_if_missing(election_id,"President","national")
    counties=Region.query.filter(Region.code!="LEGACY",Region.active==True).all()
    for county in counties:
        for p in ("Governor","Senator","Woman Representative"): created+=_create_contest_if_missing(election_id,p,"county",county=county.id)
    for con in Constituency.query.filter_by(active=True).all(): created+=_create_contest_if_missing(election_id,"Member of Parliament","constituency",county=con.county_id,constituency=con.id)
    for ward in Ward.query.filter_by(active=True).all():
        con=Constituency.query.get(ward.constituency_id)
        if con: created+=_create_contest_if_missing(election_id,"Member of County Assembly","ward",county=con.county_id,constituency=con.id,ward=ward.id)
    return created

@app.route("/admin/elections", methods=["GET","POST"])
@admin_required
def manage_elections():
    user=current_user()
    if request.method=="POST":
        validate_csrf(); action=request.form.get("action")
        if action=="select":
            eid=request.form.get("election_id","")
            target=ElectionSetting.query.get(int(eid)) if eid.isdigit() else None
            if not target: flash("Election not found.","danger"); return redirect(url_for("manage_elections"))
            ElectionSetting.query.update({ElectionSetting.is_current:False}); target.is_current=True; db.session.commit(); log_event("CURRENT_ELECTION_CHANGED","INFO",user.id,target.title); flash("Current election changed.","success"); return redirect(url_for("manage_elections"))
        title=request.form.get("title","").strip()[:200]; etype=request.form.get("election_type"); d=request.form.get("election_date","")
        try: edate=datetime.strptime(d,"%Y-%m-%d").date()
        except ValueError: flash("Enter a valid election date.","danger"); return redirect(url_for("manage_elections"))
        if not title or etype not in ("general","by_election"): flash("Enter a title and valid election type.","danger"); return redirect(url_for("manage_elections"))
        if request.form.get("make_current")=="on": ElectionSetting.query.update({ElectionSetting.is_current:False})
        e=ElectionSetting(title=title,election_type=etype,election_date=edate,is_open=False,results_visible=False,is_current=request.form.get("make_current")=="on"); db.session.add(e); db.session.flush()
        created=0
        if etype=="general": created=_build_general_election_contests(e.id)
        else:
            pos=request.form.get("position"); county=request.form.get("county_id",""); con=request.form.get("constituency_id",""); ward=request.form.get("ward_id",""); county=int(county) if county.isdigit() else None; con=int(con) if con.isdigit() else None; ward=int(ward) if ward.isdigit() else None
            if pos not in POSITIONS: db.session.rollback(); flash("Select a valid by-election position.","danger"); return redirect(url_for("manage_elections"))
            if pos=="President": scope="national"; county=con=ward=None
            elif pos in ("Governor","Senator","Woman Representative"):
                scope="county"; con=ward=None
                if not county or not Region.query.filter_by(id=county,active=True).first(): db.session.rollback(); flash("Select a valid county.","danger"); return redirect(url_for("manage_elections"))
            elif pos=="Member of Parliament":
                scope="constituency"; ward=None; x=Constituency.query.get(con) if con else None
                if not x or x.county_id!=county: db.session.rollback(); flash("Select a valid constituency.","danger"); return redirect(url_for("manage_elections"))
            else:
                scope="ward"; x=Constituency.query.get(con) if con else None; w=Ward.query.get(ward) if ward else None
                if not x or x.county_id!=county or not w or w.constituency_id!=con: db.session.rollback(); flash("Select a valid ward.","danger"); return redirect(url_for("manage_elections"))
            created=_create_contest_if_missing(e.id,pos,scope,county,con,ward)
        db.session.commit(); log_event("ELECTION_CREATED","INFO",user.id,f"{title}; type={etype}; contests={created}"); flash(f"Election created with {created} contest(s). Voting starts CLOSED until you enable it from Admin.","success"); return redirect(url_for("manage_elections"))
    elections=ElectionSetting.query.order_by(ElectionSetting.election_date.desc(),ElectionSetting.id.desc()).all(); counts={e.id:Contest.query.filter_by(election_id=e.id).count() for e in elections}
    return render_template_string(ELECTIONS_RC7,elections=elections,contest_counts=counts,counties=Region.query.filter(Region.code!="LEGACY").order_by(Region.name).all(),by_positions=POSITIONS)

@app.route("/admin/contests", methods=["GET","POST"])
@admin_required
def manage_contests():
    election=get_election()
    # General-election contests are generated from the verified geography and are
    # deliberately protected from manual additions on this page.
    if request.method=="POST":
        validate_csrf()
        if election.election_type=="general":
            flash("General Election contests are protected and generated automatically from verified electoral geography.","warning")
            return redirect(url_for("manage_contests"))
        pos=request.form.get("position"); county=request.form.get("county_id",""); con=request.form.get("constituency_id",""); ward=request.form.get("ward_id","")
        county=int(county) if county.isdigit() else None; con=int(con) if con.isdigit() else None; ward=int(ward) if ward.isdigit() else None
        if pos not in POSITIONS:
            flash("Select a valid election position.","danger"); return redirect(url_for("manage_contests"))
        if pos=="President": scope="national"; county=con=ward=None
        elif pos in ("Governor","Senator","Woman Representative"):
            scope="county"; con=ward=None
            if not county or not Region.query.filter_by(id=county,active=True).first(): flash("Select a valid county for this contest.","danger"); return redirect(url_for("manage_contests"))
        elif pos=="Member of Parliament":
            scope="constituency"; ward=None; constituency=Constituency.query.get(con) if con else None
            if not county or not constituency or constituency.county_id!=county: flash("Select a constituency that belongs to the selected county.","danger"); return redirect(url_for("manage_contests"))
        else:
            scope="ward"; constituency=Constituency.query.get(con) if con else None; ward_obj=Ward.query.get(ward) if ward else None
            if not county or not constituency or constituency.county_id!=county or not ward_obj or ward_obj.constituency_id!=con: flash("Select a ward that belongs to the selected constituency and county.","danger"); return redirect(url_for("manage_contests"))
        duplicate=Contest.query.filter_by(election_id=election.id,position=pos,scope_level=scope,county_id=county,constituency_id=con,ward_id=ward).first()
        if duplicate: flash("That election contest already exists for this area.","warning"); return redirect(url_for("manage_contests"))
        db.session.add(Contest(election_id=election.id,position=pos,scope_level=scope,county_id=county,constituency_id=con,ward_id=ward)); db.session.commit()
        user=current_user(); log_event("CONTEST_CREATED","INFO",user.id if user else None,f"{pos} — {scope}; election={election.id}")
        flash("By-Election contest created.","success"); return redirect(url_for("manage_contests"))
    contests=Contest.query.filter_by(election_id=election.id).order_by(Contest.position,Contest.id).all()
    contest_ids=[c.id for c in contests]
    candidate_counts={cid:0 for cid in contest_ids}
    if contest_ids:
        for cid,count in db.session.query(ContestCandidate.contest_id,db.func.count(ContestCandidate.candidate_id)).filter(ContestCandidate.contest_id.in_(contest_ids)).group_by(ContestCandidate.contest_id).all(): candidate_counts[cid]=count
    counts={p:sum(1 for c in contests if c.position==p) for p in POSITIONS}
    labels={"President":"President","Governor":"Governor","Senator":"Senator","Woman Representative":"Woman Representative","Member of Parliament":"MP","Member of County Assembly":"MCA"}
    summary=[{"label":labels[p],"count":counts[p]} for p in POSITIONS]
    total=len(contests); with_candidates=sum(1 for c in contests if candidate_counts.get(c.id,0)>0)
    official_count=Region.query.filter(Region.code!="LEGACY",Region.active==True).count(); constituency_count=Constituency.query.filter_by(active=True).count(); ward_count=Ward.query.filter_by(active=True).count()
    geography_verified=(official_count==47 and constituency_count==290 and ward_count==1450)
    return render_template_string(CONTESTS_V3,election=election,positions=POSITIONS,counties=Region.query.filter(Region.code!="LEGACY",Region.active==True).order_by(Region.name).all(),contests=contests,area=contest_area_name,candidate_counts=candidate_counts,summary=summary,total_contests=total,contests_with_candidates=with_candidates,contests_without_candidates=total-with_candidates,geography_verified=geography_verified)


@app.route("/results")
def results():
    election=get_election(); user=current_user(); is_admin=bool(user and user.role=="admin")
    votes=Vote.query.filter_by(election_id=election.id).order_by(Vote.id.asc()).all(); previous_hash=GENESIS_HASH
    integrity_status="VALID"; verified_count=0; invalid_ballots=0; break_point=None
    contest_tallies={}; legacy_tally={}; verified_contest_ballots={}
    for v in votes:
        expected=compute_chain_hash(v.encrypted_vote, previous_hash)
        if v.previous_hash != previous_hash or v.current_hash != expected:
            integrity_status="HASH_FAILURE"; break_point=v.id; invalid_ballots=len(votes)-verified_count
            log_event("HASH_CHAIN_FAILURE","CRITICAL",None,f"Ledger mismatch at vote ID {v.id}"); break
        try:
            data=json.loads(fernet.decrypt(v.encrypted_vote.encode()).decode())
            cid=data.get("candidate_id"); contest_id=data.get("contest_id") or getattr(v,"contest_id",None)
            if contest_id:
                contest_tallies.setdefault(contest_id,{})
                contest_tallies[contest_id][cid]=contest_tallies[contest_id].get(cid,0)+1
                verified_contest_ballots[contest_id]=verified_contest_ballots.get(contest_id,0)+1
            else:
                legacy_tally[cid]=legacy_tally.get(cid,0)+1
        except (InvalidToken,ValueError,json.JSONDecodeError):
            integrity_status="DECRYPTION_FAILURE"; break_point=v.id; invalid_ballots=len(votes)-verified_count
            log_event("BALLOT_DECRYPTION_FAILURE","ERROR",None,f"Vote ID {v.id}; key version={getattr(v,'key_version','unknown')}"); break
        verified_count += 1; previous_hash=v.current_hash

    contest_results=[]
    pie_colors=["#0c8a5f","#d9a441","#305f9e","#b3423a","#7954a3","#169ca7","#cc6b32","#687b8e"]
    for contest in Contest.query.filter_by(active=True,election_id=election.id).order_by(Contest.position,Contest.id).all():
        candidates=candidates_for_contest(contest.id); tally=contest_tallies.get(contest.id,{})
        eligible=registered_voters_for_contest(contest); cast=verified_contest_ballots.get(contest.id,0)
        county_obj=db.session.get(Region,contest.county_id) if contest.county_id else None
        constituency_obj=db.session.get(Constituency,contest.constituency_id) if contest.constituency_id else None
        ward_obj=db.session.get(Ward,contest.ward_id) if contest.ward_id else None
        if not county_obj and constituency_obj:
            county_obj=db.session.get(Region,constituency_obj.county_id)
        if not constituency_obj and ward_obj:
            constituency_obj=db.session.get(Constituency,ward_obj.constituency_id)
            if constituency_obj and not county_obj:
                county_obj=db.session.get(Region,constituency_obj.county_id)
        parts=[]; offset=0.0
        # The pie denominator is the number of votes for displayed candidates;
        # preserve the recorded ballot count separately for audit/turnout.
        displayed_total=sum(tally.get(c.id,0) for c in candidates)
        for i,c in enumerate(candidates):
            n=tally.get(c.id,0)
            share=(100.0*n/displayed_total) if displayed_total else 0.0
            end=offset+share
            parts.append({"candidate":c,"votes":n,"percent":share,"start":offset,"end":end,"color":pie_colors[i%len(pie_colors)]})
            offset=end
        contest_results.append({"contest":contest,"area":contest_area_name(contest),"candidates":candidates,"tally":tally,
            "eligible":eligible,"cast":cast,"turnout":(100.0*cast/eligible if eligible else 0.0),
            "county":county_obj.name if county_obj else "","local_area":(ward_obj.name if ward_obj else constituency_obj.name if constituency_obj else ""),
            "pie_parts":parts})
    # Electoral order is fixed: national presidential results always lead.
    position_order = {
        "President": 0, "Governor": 1, "Senator": 2,
        "Woman Representative": 3, "Member of Parliament": 4,
        "Member of County Assembly": 5,
    }
    contest_results.sort(key=lambda r: (
        position_order.get(r["contest"].position, 99),
        r["cast"] == 0,
        r["area"].casefold(),
    ))
    result_positions=sorted(
        {r["contest"].position for r in contest_results},
        key=lambda p: (position_order.get(p, 99), p),
    )
    result_counties=sorted({r["county"] for r in contest_results if r["county"]})
    result_local_areas=sorted({r["local_area"] for r in contest_results if r["local_area"]})
    legacy_candidates={c.id:c for c in Candidate.query.filter(Candidate.id.in_(list(legacy_tally.keys()) or [-1])).all()}
    return render_template_string(RESULTS_HTML, election=election,election_open=election_is_open(election),is_admin=is_admin,
        show_candidate_results=((not election_is_open(election)) and election.results_visible),total_votes=len(votes),verified_count=verified_count,
        invalid_ballots=invalid_ballots,break_point=break_point,integrity_status=integrity_status,contest_results=contest_results,
        legacy_tally=legacy_tally,legacy_candidates=legacy_candidates,
        result_positions=result_positions,result_counties=result_counties,result_local_areas=result_local_areas)


@app.route("/admin/audit/clear-view", methods=["POST"])
@admin_required
def clear_audit_view():
    validate_csrf(); user=current_user(); latest=AuditEvent.query.order_by(AuditEvent.id.desc()).first()
    state=AuditViewState.query.filter_by(user_id=user.id).first()
    if not state: state=AuditViewState(user_id=user.id); db.session.add(state)
    state.cleared_through_id=latest.id if latest else 0; db.session.commit()
    log_event("AUDIT_DASHBOARD_VIEW_CLEARED","INFO",user.id,"Dashboard view cleared; audit records retained")
    flash("Recent audit view cleared. Full audit records were retained.","success"); return redirect(url_for("admin_dashboard"))

@app.route("/admin/audit")
@admin_required
def full_audit_log():
    event_filter=request.args.get("event","").strip(); severity_filter=request.args.get("severity","").strip().upper()
    q=AuditEvent.query
    if event_filter: q=q.filter(AuditEvent.event_type.ilike(f"%{event_filter}%"))
    if severity_filter: q=q.filter(AuditEvent.severity==severity_filter)
    events=q.order_by(AuditEvent.id.desc()).limit(1000).all()
    return render_template_string(AUDIT_LOG_HTML,events=events,event_filter=event_filter,severity_filter=severity_filter)

@app.route("/admin/geography/load", methods=["POST"])
@admin_required
def reload_kenya_geography():
    validate_csrf(); user=current_user(); ok,message=seed_kenya_electoral_geography(force=True)
    log_event("KENYA_GEOGRAPHY_LOAD", "INFO" if ok else "ERROR", user.id, message)
    flash(message, "success" if ok else "danger"); return redirect(url_for("admin_dashboard"))

@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin_dashboard():
    election = get_election()
    user = current_user()

    if request.method == "POST":
        validate_csrf()
        title = request.form.get("title", "").strip()[:200]
        election.title = title or ELECTION_DEFAULT_TITLE
        election.is_open = request.form.get("is_open") == "on"
        election.results_visible = request.form.get("results_visible") == "on"
        db.session.commit()
        log_event(
            "ELECTION_SETTINGS_CHANGED",
            "WARNING",
            user.id,
            f"is_open={election.is_open}; results_visible={election.results_visible}"
        )
        flash("Election settings updated.", "success")
        return redirect(url_for("admin_dashboard"))

    state=AuditViewState.query.filter_by(user_id=user.id).first()
    cleared_through=state.cleared_through_id if state else 0
    events=AuditEvent.query.filter(AuditEvent.id > cleared_through).order_by(AuditEvent.id.desc()).limit(50).all()
    return render_template_string(
        ADMIN_HTML,
        election=election,
        election_open=election_is_open(election),
        registered_voters=User.query.filter(User.role != "admin").count(),
        total_votes=Vote.query.filter_by(election_id=election.id).count(),
        events=events,
    )


# ----------------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
