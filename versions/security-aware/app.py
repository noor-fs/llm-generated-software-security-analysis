"""DemoBank V3: security-aware fictional Flask banking application.

Academic/local simulation only. It does not connect to real financial services.
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from datetime import date, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("DEMOBANK_DB", os.path.join(BASE_DIR, "instance", "demobank.sqlite3"))
IS_PRODUCTION = os.environ.get("DEMOBANK_ENV", "development").lower() == "production"

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("DEMOBANK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_REFRESH_EACH_REQUEST=True,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
    MAX_FORM_MEMORY_SIZE=256 * 1024,
)
if IS_PRODUCTION and (not os.environ.get("DEMOBANK_SECRET_KEY") or len(app.config["SECRET_KEY"]) < 32):
    raise RuntimeError("Production requires DEMOBANK_SECRET_KEY with at least 32 characters.")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,32}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^[0-9+() .-]{0,30}$")
MAX_TRANSFER_CENTS = 100_000_000
DUMMY_PASSWORD_HASH = generate_password_hash("not-a-real-user-password-for-timing-equalization")
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 900


def get_db():
    if "db" not in g:
        db_dir = os.path.dirname(DB_PATH) or "."
        os.makedirs(db_dir, exist_ok=True)
        g.db = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 10000")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        email TEXT NOT NULL COLLATE NOCASE UNIQUE,
        full_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        phone TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        auth_version INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        account_number TEXT NOT NULL UNIQUE,
        balance_cents INTEGER NOT NULL DEFAULT 0 CHECK(balance_cents >= 0),
        currency TEXT NOT NULL DEFAULT 'QAR',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS transfers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_account_id INTEGER NOT NULL REFERENCES accounts(id),
        recipient_account_id INTEGER NOT NULL REFERENCES accounts(id),
        amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
        description TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL CHECK(status IN ('completed')),
        idempotency_key TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CHECK(sender_account_id != recipient_account_id)
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        is_read INTEGER NOT NULL DEFAULT 0 CHECK(is_read IN (0,1)),
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS login_attempts (
        username_key TEXT NOT NULL,
        ip_key TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        window_started INTEGER NOT NULL,
        locked_until INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY(username_key, ip_key)
    );
    CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);
    CREATE INDEX IF NOT EXISTS idx_transfers_sender ON transfers(sender_account_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_transfers_recipient ON transfers(recipient_account_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at);
    """)
    # Additive migration for V1 databases; existing users/accounts/transactions remain intact.
    columns = {row[1] for row in db.execute("PRAGMA table_info(users)").fetchall()}
    if "auth_version" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0")


def _csrf_valid():
    supplied = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


@app.before_request
def security_and_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not _csrf_valid():
        abort(400)
    # Reject stale/revoked login cookies on every authenticated request.
    if session.get("user_id") is not None:
        user = get_db().execute(
            "SELECT auth_version FROM users WHERE id = ?", (session.get("user_id"),)
        ).fetchone()
        if not user or user["auth_version"] != session.get("auth_version"):
            session.clear()
            session["csrf_token"] = secrets.token_urlsafe(32)


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "upgrade-insecure-requests" if IS_PRODUCTION else
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'"
    )
    if IS_PRODUCTION:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    if request.endpoint not in {"static"}:
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.context_processor
def inject_globals():
    return {"csrf_token": session.get("csrf_token", ""), "current_user": get_current_user()}


def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_db().execute(
        "SELECT id, username, email, full_name, phone, created_at FROM users WHERE id = ?", (user_id,)
    ).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not get_current_user():
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def money(cents):
    return f"{cents / 100:,.2f}"


@app.template_filter("money")
def money_filter(cents):
    return money(cents)


def create_notification(user_id, title, message):
    get_db().execute(
        "INSERT INTO notifications(user_id, title, message) VALUES (?, ?, ?)",
        (user_id, title[:100], message[:500])
    )


def _login_keys(username):
    # Hash identifiers so the throttle table does not retain raw IP/user input.
    ip = request.remote_addr or "unknown"
    return hashlib.sha256(username.casefold().encode("utf-8", "ignore")).hexdigest(), hashlib.sha256(ip.encode()).hexdigest()


def _login_locked(username):
    ukey, ipkey = _login_keys(username)
    row = get_db().execute(
        "SELECT locked_until FROM login_attempts WHERE username_key=? AND ip_key=?", (ukey, ipkey)
    ).fetchone()
    return bool(row and row["locked_until"] > int(time.time()))


def _record_failed_login(username):
    now = int(time.time())
    ukey, ipkey = _login_keys(username)
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        row = db.execute("SELECT * FROM login_attempts WHERE username_key=? AND ip_key=?", (ukey, ipkey)).fetchone()
        if not row or now - row["window_started"] > LOGIN_WINDOW_SECONDS:
            db.execute("INSERT OR REPLACE INTO login_attempts(username_key,ip_key,attempts,window_started,locked_until) VALUES(?,?,1,?,0)", (ukey, ipkey, now))
        else:
            attempts = row["attempts"] + 1
            locked = now + LOGIN_WINDOW_SECONDS if attempts >= LOGIN_MAX_ATTEMPTS else 0
            db.execute("UPDATE login_attempts SET attempts=?, locked_until=? WHERE username_key=? AND ip_key=?", (attempts, locked, ukey, ipkey))
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def _clear_login_failures(username):
    ukey, ipkey = _login_keys(username)
    get_db().execute("DELETE FROM login_attempts WHERE username_key=? AND ip_key=?", (ukey, ipkey))


def _valid_local_next(value):
    # Only accept same-origin relative paths; reject scheme-relative and backslash tricks.
    return bool(value and value.startswith("/") and not value.startswith("//") and "\\" not in value and "\r" not in value and "\n" not in value)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if not full_name or len(full_name) > 100 or any(ord(c) < 32 for c in full_name):
            flash("Enter your name (up to 100 characters).", "error")
        elif not USERNAME_RE.fullmatch(username):
            flash("Username must be 3–32 characters and contain only letters, numbers, and underscores.", "error")
        elif len(email) > 254 or not EMAIL_RE.fullmatch(email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 12 or len(password) > 128:
            flash("Password must be between 12 and 128 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            db = get_db()
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO users(username,email,full_name,password_hash) VALUES(?,?,?,?)",
                    (username, email, full_name, generate_password_hash(password))
                )
                user_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                account_number = "DB" + secrets.token_hex(5).upper()
                db.execute("INSERT INTO accounts(user_id, account_number, balance_cents) VALUES(?,?,?)", (user_id, account_number, 250000))
                db.execute("INSERT INTO notifications(user_id,title,message) VALUES(?,?,?)", (user_id, "Welcome to DemoBank", "Your demo account is ready. Your starting balance is QAR 2,500.00."))
                db.execute("COMMIT")
                session.clear()
                session["user_id"] = user_id
                session["auth_version"] = 0
                session["csrf_token"] = secrets.token_urlsafe(32)
                session.permanent = True
                flash("Account created successfully. Your demo account starts with QAR 2,500.00.", "success")
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                if db.in_transaction: db.execute("ROLLBACK")
                flash("That username or email is already registered.", "error")
            except Exception:
                if db.in_transaction: db.execute("ROLLBACK")
                app.logger.exception("Registration failed")
                flash("We could not create your account. Please try again.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:64]
        password = request.form.get("password", "")
        if _login_locked(username):
            flash("Unable to sign in at this time. Please wait and try again.", "error")
            return render_template("login.html"), 429
        user = get_db().execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
        password_ok = check_password_hash(user["password_hash"], password) if user else check_password_hash(DUMMY_PASSWORD_HASH, password)
        if user and password_ok:
            _clear_login_failures(username)
            session.clear()
            session["user_id"] = user["id"]
            session["auth_version"] = user["auth_version"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            flash(f"Welcome back, {user['full_name'].split()[0]}.", "success")
            destination = request.args.get("next", "")
            return redirect(destination if _valid_local_next(destination) else url_for("dashboard"))
        _record_failed_login(username)
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    # Incrementing auth_version revokes all previously issued cookies for this user.
    get_db().execute("UPDATE users SET auth_version=auth_version+1 WHERE id=?", (session["user_id"],))
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    db = get_db()
    accounts = db.execute("SELECT * FROM accounts WHERE user_id = ?", (user["id"],)).fetchall()
    account_ids = [a["id"] for a in accounts]
    txns = []
    if account_ids:
        marks = ",".join("?" for _ in account_ids)
        txns = db.execute(f"""
            SELECT t.*, sa.account_number AS sender_number, su.full_name AS sender_name,
                   ra.account_number AS recipient_number, ru.full_name AS recipient_name,
                   sa.user_id AS sender_user_id
            FROM transfers t JOIN accounts sa ON sa.id=t.sender_account_id JOIN users su ON su.id=sa.user_id
            JOIN accounts ra ON ra.id=t.recipient_account_id JOIN users ru ON ru.id=ra.user_id
            WHERE t.sender_account_id IN ({marks}) OR t.recipient_account_id IN ({marks})
            ORDER BY t.created_at DESC, t.id DESC LIMIT 5
        """, tuple(account_ids + account_ids)).fetchall()
    unread = db.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND is_read=0", (user["id"],)).fetchone()[0]
    return render_template("dashboard.html", user=user, accounts=accounts, transactions=txns, unread=unread)


@app.route("/account")
@login_required
def account():
    user = get_current_user()
    accounts = get_db().execute("SELECT * FROM accounts WHERE user_id=?", (user["id"],)).fetchall()
    return render_template("account.html", accounts=accounts)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    user = get_current_user()
    db = get_db()
    sender = db.execute("SELECT * FROM accounts WHERE user_id=? ORDER BY id LIMIT 1", (user["id"],)).fetchone()
    recipients = db.execute("SELECT a.account_number, u.full_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.user_id != ? ORDER BY u.full_name", (user["id"],)).fetchall()
    if request.method == "POST":
        recipient_number = request.form.get("recipient", "").strip().upper()
        raw_amount = request.form.get("amount", "").strip()
        description = request.form.get("description", "").strip()
        idem = request.form.get("idempotency_key", "").strip()
        issued_tokens = session.get("transfer_tokens", [])
        if not idem or idem not in issued_tokens or len(idem) > 100:
            flash("Transfer form expired. Reload the page and try again.", "warning")
            return redirect(url_for("transfer"))
        if len(description) > 140 or any(ord(c) < 32 and c not in "\t" for c in description):
            flash("Description must be 140 characters or fewer.", "error")
            return redirect(url_for("transfer"))
        try:
            amount = Decimal(raw_amount)
            if not amount.is_finite() or amount <= 0 or amount > Decimal("1000000") or amount.as_tuple().exponent < -2:
                raise InvalidOperation
            cents = int(amount * 100)
            if cents < 1 or cents > MAX_TRANSFER_CENTS:
                raise InvalidOperation
        except (InvalidOperation, ValueError):
            flash("Enter a valid positive amount with no more than two decimal places (maximum QAR 1,000,000).", "error")
            return redirect(url_for("transfer"))
        if not sender:
            flash("No account is attached to your profile.", "error")
            return redirect(url_for("account"))
        try:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT id FROM transfers WHERE idempotency_key=?", (idem,)).fetchone()
            if existing:
                db.execute("ROLLBACK")
                session["transfer_tokens"] = [t for t in issued_tokens if t != idem]
                flash("This transfer request was already processed; it was not repeated.", "warning")
                return redirect(url_for("transactions"))
            recipient = db.execute("SELECT a.*, u.id AS recipient_user_id, u.full_name AS recipient_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=?", (recipient_number,)).fetchone()
            if not recipient:
                db.execute("ROLLBACK")
                flash("Recipient account was not found.", "error")
                return redirect(url_for("transfer"))
            if recipient["id"] == sender["id"]:
                db.execute("ROLLBACK")
                flash("You cannot transfer money to your own account.", "error")
                return redirect(url_for("transfer"))
            # Re-check ownership and balance inside the same write transaction.
            current = db.execute("SELECT balance_cents FROM accounts WHERE id=? AND user_id=?", (sender["id"], user["id"])).fetchone()
            if not current or current["balance_cents"] < cents:
                db.execute("ROLLBACK")
                flash("Insufficient funds for this transfer.", "error")
                return redirect(url_for("transfer"))
            db.execute("UPDATE accounts SET balance_cents=balance_cents-? WHERE id=? AND user_id=? AND balance_cents>=?", (cents, sender["id"], user["id"], cents))
            if db.execute("SELECT changes()").fetchone()[0] != 1:
                db.execute("ROLLBACK")
                flash("The balance changed before the transfer completed. Please retry.", "error")
                return redirect(url_for("transfer"))
            db.execute("UPDATE accounts SET balance_cents=balance_cents+? WHERE id=?", (cents, recipient["id"]))
            db.execute("INSERT INTO transfers(sender_account_id,recipient_account_id,amount_cents,description,status,idempotency_key) VALUES(?,?,?,?,?,?)", (sender["id"], recipient["id"], cents, description, "completed", idem))
            create_notification(user["id"], "Transfer sent", f"QAR {money(cents)} sent to {recipient['recipient_name']}.")
            create_notification(recipient["recipient_user_id"], "Money received", f"QAR {money(cents)} received from {user['full_name']}.")
            db.execute("COMMIT")
            session["transfer_tokens"] = [t for t in issued_tokens if t != idem]
            flash(f"Transfer complete: QAR {money(cents)} sent to {recipient['recipient_name']}.", "success")
            return redirect(url_for("transactions"))
        except sqlite3.IntegrityError:
            if db.in_transaction: db.execute("ROLLBACK")
            flash("This request was already processed or could not be completed.", "warning")
            return redirect(url_for("transactions"))
        except Exception:
            if db.in_transaction: db.execute("ROLLBACK")
            app.logger.exception("Transfer failed")
            flash("Transfer failed safely. No changes were committed; please try again.", "error")
    token = secrets.token_urlsafe(32)
    tokens = session.get("transfer_tokens", [])[-4:]
    tokens.append(token)
    session["transfer_tokens"] = tokens
    return render_template("transfer.html", sender=sender, recipients=recipients, idempotency_key=token)


@app.route("/transactions")
@login_required
def transactions():
    user = get_current_user()
    db = get_db()
    accounts = db.execute("SELECT id FROM accounts WHERE user_id=?", (user["id"],)).fetchall()
    ids = [a["id"] for a in accounts]
    rows = []
    kind = request.args.get("type", "all")
    if kind not in {"all", "sent", "received"}:
        kind = "all"
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    valid_start = valid_end = ""
    try:
        if start: valid_start = date.fromisoformat(start).isoformat()
        if end: valid_end = date.fromisoformat(end).isoformat()
        if valid_start and valid_end and valid_start > valid_end:
            raise ValueError
    except ValueError:
        valid_start = valid_end = ""
        flash("Invalid date range was ignored.", "warning")
    if ids:
        marks = ",".join("?" for _ in ids)
        sql = f"""SELECT t.*, sa.account_number AS sender_number, su.full_name AS sender_name,
                  ra.account_number AS recipient_number, ru.full_name AS recipient_name, sa.user_id AS sender_user_id
                  FROM transfers t JOIN accounts sa ON sa.id=t.sender_account_id JOIN users su ON su.id=sa.user_id
                  JOIN accounts ra ON ra.id=t.recipient_account_id JOIN users ru ON ru.id=ra.user_id
                  WHERE (t.sender_account_id IN ({marks}) OR t.recipient_account_id IN ({marks}))"""
        params = ids + ids
        if kind == "sent": sql += f" AND t.sender_account_id IN ({marks})"; params += ids
        elif kind == "received": sql += f" AND t.recipient_account_id IN ({marks})"; params += ids
        if valid_start: sql += " AND date(t.created_at) >= date(?)"; params.append(valid_start)
        if valid_end: sql += " AND date(t.created_at) <= date(?)"; params.append(valid_end)
        sql += " ORDER BY t.created_at DESC, t.id DESC LIMIT 200"
        rows = db.execute(sql, params).fetchall()
    return render_template("transactions.html", transactions=rows, filters={"type": kind, "start": valid_start, "end": valid_end})


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_current_user()
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        phone = request.form.get("phone", "").strip()
        if not full_name or len(full_name) > 100 or any(ord(c) < 32 for c in full_name) or not PHONE_RE.fullmatch(phone):
            flash("Please enter a valid name and phone number.", "error")
        else:
            get_db().execute("UPDATE users SET full_name=?, phone=? WHERE id=?", (full_name, phone, user["id"]))
            create_notification(user["id"], "Profile updated", "Your profile details were updated.")
            flash("Profile updated successfully.", "success")
            return redirect(url_for("profile"))
    return render_template("profile.html", user=user)


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        user = get_db().execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
        old = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not user or not check_password_hash(user["password_hash"], old):
            flash("Current password is incorrect.", "error")
        elif len(new) < 12 or len(new) > 128:
            flash("New password must be between 12 and 128 characters.", "error")
        elif new != confirm:
            flash("New passwords do not match.", "error")
        elif check_password_hash(user["password_hash"], new):
            flash("Choose a password different from your current password.", "warning")
        else:
            get_db().execute("UPDATE users SET password_hash=?, auth_version=auth_version+1 WHERE id=?", (generate_password_hash(new), user["id"]))
            session.clear()
            flash("Password changed. Please sign in again.", "success")
            return redirect(url_for("login"))
    return render_template("change_password.html")


@app.route("/notifications", methods=["GET", "POST"])
@login_required
def notifications():
    user = get_current_user()
    db = get_db()
    if request.method == "POST":
        db.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (user["id"],))
        flash("Notifications marked as read.", "success")
        return redirect(url_for("notifications"))
    rows = db.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC, id DESC LIMIT 100", (user["id"],)).fetchall()
    return render_template("notifications.html", notifications=rows)


@app.errorhandler(400)
def bad_request(_error):
    return render_template("error.html", code=400, title="Bad request", message="The request could not be processed. Please reload the page and try again."), 400


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, title="Access denied", message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, title="Page not found", message="The page you requested does not exist."), 404


@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", code=413, title="Request too large", message="The submitted request is too large."), 413


@app.errorhandler(429)
def too_many_requests(_error):
    return render_template("error.html", code=429, title="Please slow down", message="Too many requests. Please wait and try again."), 429


@app.errorhandler(500)
def server_error(_error):
    app.logger.error("Unhandled application error: %s", _error)
    return render_template("error.html", code=500, title="Something went wrong", message="An unexpected error occurred. Please try again."), 500


@app.cli.command("init-db")
def init_db_command():
    init_db()
    print(f"Database initialized at {DB_PATH}")


@app.cli.command("seed-demo")
def seed_demo_command():
    init_db()
    db = get_db()
    demo_users = [
        ("alice", "alice@example.test", "Alice Morgan", "DemoPass123!"),
        ("bob", "bob@example.test", "Bob Taylor", "DemoPass123!"),
        ("charlie", "charlie@example.test", "Charlie Reed", "DemoPass123!"),
    ]
    for username, email, name, password in demo_users:
        if db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            continue
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("INSERT INTO users(username,email,full_name,password_hash) VALUES(?,?,?,?)", (username, email, name, generate_password_hash(password)))
            uid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            db.execute("INSERT INTO accounts(user_id,account_number,balance_cents) VALUES(?,?,?)", (uid, "DB" + secrets.token_hex(5).upper(), 250000))
            db.execute("INSERT INTO notifications(user_id,title,message) VALUES(?,?,?)", (uid, "Welcome to DemoBank", "This is a fictional academic demo account."))
            db.execute("COMMIT")
        except Exception:
            if db.in_transaction: db.execute("ROLLBACK")
            raise
    print("Demo users are ready. Login: alice / bob / charlie. Password for each: DemoPass123!")


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
