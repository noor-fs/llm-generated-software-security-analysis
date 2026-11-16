import os
import sqlite3
import secrets
import re
from datetime import datetime, date
from decimal import Decimal, InvalidOperation
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("DEMOBANK_DB", os.path.join(BASE_DIR, "instance", "demobank.sqlite3"))
IS_PRODUCTION = os.environ.get("DEMOBANK_ENV", "development").lower() == "production"

app = Flask(__name__)
app.config.update(
    # A fresh unpredictable key is used for local development when no key is supplied.
    # This invalidates sessions after a restart; set DEMOBANK_SECRET_KEY for persistence.
    SECRET_KEY=os.environ.get("DEMOBANK_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=IS_PRODUCTION,
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)
if IS_PRODUCTION and not os.environ.get("DEMOBANK_SECRET_KEY"):
    raise RuntimeError("Set DEMOBANK_SECRET_KEY to a long random value in production.")

class StripServerHeader:
    """Remove the development server's identifying Server response header."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        def secure_start_response(status, headers, exc_info=None):
            safe_headers = [(name, value) for name, value in headers
                            if name.lower() != "server"]
            return start_response(status, safe_headers, exc_info)
        return self.wsgi_app(environ, secure_start_response)

app.wsgi_app = StripServerHeader(app.wsgi_app)

@app.after_request
def add_security_headers(response):
    # All application assets are same-origin; no inline scripts/styles are required.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'self'; object-src 'none'; "
        "frame-ancestors 'none'; form-action 'self'; "
        "script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "font-src 'self'; connect-src 'self'"
    )
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    return response

def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
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
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
    CREATE INDEX IF NOT EXISTS idx_accounts_user ON accounts(user_id);
    CREATE INDEX IF NOT EXISTS idx_transfers_sender ON transfers(sender_account_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_transfers_recipient ON transfers(recipient_account_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at);
    """)

@app.before_request
def security_and_csrf():
    # Session-bound CSRF token for all state-changing requests.
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        supplied = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        import hmac
        if not supplied or not expected or not hmac.compare_digest(supplied, expected):
            abort(400, description="CSRF validation failed. Reload the page and try again.")

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
        (user_id, title, message)
    )

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
        if not full_name or len(full_name) > 100:
            flash("Enter your name (up to 100 characters).", "error")
        elif not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
            flash("Username must be 3–32 characters and contain only letters, numbers, and underscores.", "error")
        elif "@" not in email or len(email) > 254:
            flash("Enter a valid email address.", "error")
        elif len(password) < 10 or len(password) > 128:
            flash("Password must be between 10 and 128 characters.", "error")
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
                db.execute(
                    "INSERT INTO accounts(user_id, account_number, balance_cents) VALUES(?,?,?)",
                    (user_id, account_number, 250000)
                )
                db.execute("INSERT INTO notifications(user_id,title,message) VALUES(?,?,?)",
                           (user_id, "Welcome to DemoBank", "Your demo account is ready. Your starting balance is QAR 2,500.00."))
                db.execute("COMMIT")
                session.clear()
                session["user_id"] = user_id
                session["csrf_token"] = secrets.token_urlsafe(32)
                session.permanent = True
                flash("Account created successfully. Your demo account starts with QAR 2,500.00.", "success")
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                db.execute("ROLLBACK")
                flash("That username or email is already registered.", "error")
            except Exception:
                db.execute("ROLLBACK")
                app.logger.exception("Registration failed")
                flash("We could not create your account. Please try again.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            flash(f"Welcome back, {user['full_name'].split()[0]}.", "success")
            destination = request.args.get("next", "")
            if destination.startswith("/") and not destination.startswith("//"):
                return redirect(destination)
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    db = get_db()
    accounts = db.execute("SELECT * FROM accounts WHERE user_id = ?", (user["id"],)).fetchall()
    txns = db.execute("""
        SELECT t.*, sa.account_number AS sender_number, su.full_name AS sender_name,
               ra.account_number AS recipient_number, ru.full_name AS recipient_name,
               sa.user_id AS sender_user_id
        FROM transfers t
        JOIN accounts sa ON sa.id=t.sender_account_id JOIN users su ON su.id=sa.user_id
        JOIN accounts ra ON ra.id=t.recipient_account_id JOIN users ru ON ru.id=ra.user_id
        WHERE sa.user_id=? OR ra.user_id=?
        ORDER BY t.created_at DESC, t.id DESC LIMIT 5
    """, (user["id"], user["id"])).fetchall()
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
    recipients = db.execute("""
        SELECT a.account_number, u.full_name FROM accounts a JOIN users u ON u.id=a.user_id
        WHERE a.user_id != ? ORDER BY u.full_name
    """, (user["id"],)).fetchall()
    if request.method == "POST":
        recipient_number = request.form.get("recipient", "").strip().upper()
        raw_amount = request.form.get("amount", "").strip()
        description = request.form.get("description", "").strip()[:140]
        idem = request.form.get("idempotency_key", "").strip()
        try:
            if not raw_amount or len(raw_amount) > 32:
                raise InvalidOperation
            amount = Decimal(raw_amount)
            if not amount.is_finite() or amount <= 0 or amount > Decimal("1000000") or amount.as_tuple().exponent < -2:
                raise InvalidOperation
            cents = int(amount * 100)
        except (InvalidOperation, ValueError):
            flash("Enter a valid positive amount with no more than two decimal places (maximum QAR 1,000,000).", "error")
            return render_template("transfer.html", sender=sender, recipients=recipients, idempotency_key=secrets.token_urlsafe(24))
        if not sender:
            flash("No account is attached to your profile.", "error")
            return redirect(url_for("account"))
        if not idem or len(idem) > 100:
            flash("Transfer token missing. Reload the page and try again.", "error")
            return redirect(url_for("transfer"))
        try:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT id FROM transfers WHERE idempotency_key=?", (idem,)).fetchone()
            if existing:
                db.execute("ROLLBACK")
                flash("This transfer request was already processed; it was not repeated.", "warning")
                return redirect(url_for("transactions"))
            recipient = db.execute("""
                SELECT a.*, u.id AS recipient_user_id, u.full_name AS recipient_name
                FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=?
            """, (recipient_number,)).fetchone()
            if not recipient:
                db.execute("ROLLBACK")
                flash("Recipient account was not found.", "error")
                return redirect(url_for("transfer"))
            if recipient["id"] == sender["id"]:
                db.execute("ROLLBACK")
                flash("You cannot transfer money to your own account.", "error")
                return redirect(url_for("transfer"))
            current = db.execute("SELECT balance_cents FROM accounts WHERE id=? AND user_id=?", (sender["id"], user["id"])).fetchone()
            if not current or current["balance_cents"] < cents:
                db.execute("ROLLBACK")
                flash("Insufficient funds for this transfer.", "error")
                return redirect(url_for("transfer"))
            db.execute("UPDATE accounts SET balance_cents=balance_cents-? WHERE id=? AND balance_cents>=?",
                       (cents, sender["id"], cents))
            if db.execute("SELECT changes()").fetchone()[0] != 1:
                db.execute("ROLLBACK")
                flash("The balance changed before the transfer completed. Please retry.", "error")
                return redirect(url_for("transfer"))
            db.execute("UPDATE accounts SET balance_cents=balance_cents+? WHERE id=?", (cents, recipient["id"]))
            db.execute("""INSERT INTO transfers(sender_account_id,recipient_account_id,amount_cents,description,status,idempotency_key)
                          VALUES(?,?,?,?,?,?)""",
                       (sender["id"], recipient["id"], cents, description, "completed", idem))
            create_notification(user["id"], "Transfer sent", f"QAR {money(cents)} sent to {recipient['recipient_name']}.")
            create_notification(recipient["recipient_user_id"], "Money received", f"QAR {money(cents)} received from {user['full_name']}.")
            db.execute("COMMIT")
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
    return render_template("transfer.html", sender=sender, recipients=recipients, idempotency_key=secrets.token_urlsafe(24))

@app.route("/transactions")
@login_required
def transactions():
    user = get_current_user()
    db = get_db()
    sql = """
    SELECT t.*, sa.account_number AS sender_number, su.full_name AS sender_name,
           ra.account_number AS recipient_number, ru.full_name AS recipient_name,
           sa.user_id AS sender_user_id
    FROM transfers t JOIN accounts sa ON sa.id=t.sender_account_id JOIN users su ON su.id=sa.user_id
    JOIN accounts ra ON ra.id=t.recipient_account_id JOIN users ru ON ru.id=ra.user_id
    WHERE (sa.user_id=? OR ra.user_id=?)
    """
    params = [user["id"], user["id"]]
    kind = request.args.get("type", "all")
    if kind == "sent":
        sql += " AND sa.user_id=?"
        params.append(user["id"])
    elif kind == "received":
        sql += " AND ra.user_id=?"
        params.append(user["id"])
    start = request.args.get("start", "")
    end = request.args.get("end", "")
    try:
        if start:
            date.fromisoformat(start)
            sql += " AND date(t.created_at) >= date(?)"
            params.append(start)
        if end:
            date.fromisoformat(end)
            sql += " AND date(t.created_at) <= date(?)"
            params.append(end)
    except ValueError:
        flash("Invalid date filter was ignored.", "warning")
    sql += " ORDER BY t.created_at DESC, t.id DESC LIMIT 200"
    rows = db.execute(sql, params).fetchall()
    return render_template("transactions.html", transactions=rows, filters=request.args)

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = get_current_user()
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        phone = request.form.get("phone", "").strip()
        if not full_name or len(full_name) > 100 or len(phone) > 30:
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
        if not check_password_hash(user["password_hash"], old):
            flash("Current password is incorrect.", "error")
        elif len(new) < 10 or len(new) > 128:
            flash("New password must be between 10 and 128 characters.", "error")
        elif new != confirm:
            flash("New passwords do not match.", "error")
        elif check_password_hash(user["password_hash"], new):
            flash("Choose a password different from your current password.", "warning")
        else:
            get_db().execute("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), user["id"]))
            session.clear()
            flash("Password changed. Please sign in again.", "success")
            return redirect(url_for("login"))
    return render_template("change_password.html")

@app.route("/notifications")
@login_required
def notifications():
    user = get_current_user()
    db = get_db()
    rows = db.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC, id DESC LIMIT 100", (user["id"],)).fetchall()
    db.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (user["id"],))
    return render_template("notifications.html", notifications=rows)

@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, title="Bad request", message=getattr(error, "description", "The request could not be understood.")), 400

@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, title="Access denied", message="You do not have permission to access this page."), 403

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, title="Page not found", message="The page you requested does not exist."), 404

@app.errorhandler(500)
def server_error(_error):
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
        existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            continue
        db.execute("BEGIN IMMEDIATE")
        try:
            db.execute("INSERT INTO users(username,email,full_name,password_hash) VALUES(?,?,?,?)",
                       (username, email, name, generate_password_hash(password)))
            uid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            db.execute("INSERT INTO accounts(user_id,account_number,balance_cents) VALUES(?,?,?)",
                       (uid, "DB" + secrets.token_hex(5).upper(), 250000))
            db.execute("INSERT INTO notifications(user_id,title,message) VALUES(?,?,?)",
                       (uid, "Welcome to DemoBank", "This is a fictional academic demo account."))
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
    print("Demo users are ready. Login: alice / bob / charlie. Password for each: DemoPass123!")

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(debug=os.environ.get("DEMOBANK_DEBUG", "0") == "1")
