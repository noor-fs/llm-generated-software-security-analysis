import hmac
import re
import secrets
import time
from functools import wraps
from flask import abort, current_app, g, redirect, request, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
from db import get_db

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,190}\.[^@\s]{2,30}$")

def hash_password(password):
    return generate_password_hash(password, method="scrypt")

def verify_password(password_hash, password):
    try:
        return check_password_hash(password_hash, password)
    except (ValueError, TypeError):
        return False

def valid_password(value):
    return isinstance(value, str) and 12 <= len(value) <= 128

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]

def validate_csrf():
    if request.method == "POST":
        supplied = request.form.get("_csrf", "")
        expected = session.get("_csrf", "")
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            abort(400)

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not getattr(g, "user", None):
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def safe_internal_path(value):
    if not value or not isinstance(value, str):
        return None
    if value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return None

def log_event(event, username=None, detail=None):
    current_app.logger.info("security_event=%s username=%s detail=%s", event,
                            (username or "-")[:80], (detail or "-")[:120])

def enforce_session():
    sid = session.get("sid")
    if not sid:
        return
    db = get_db()
    now = int(time.time())
    row = db.execute(
        "SELECT s.user_id, s.last_seen, u.id, u.username, u.email, u.full_name "
        "FROM active_sessions s JOIN users u ON u.id=s.user_id WHERE s.sid=?",
        (sid,)
    ).fetchone()
    if not row or now - row["last_seen"] > 1800:
        if row:
            db.execute("DELETE FROM active_sessions WHERE sid=?", (sid,))
        session.clear()
        return
    db.execute("UPDATE active_sessions SET last_seen=? WHERE sid=?", (now, sid))
    g.user = row
