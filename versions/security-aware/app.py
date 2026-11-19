import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime
from decimal import Decimal, InvalidOperation
from functools import wraps
from flask import Flask, abort, flash, g, jsonify, redirect, render_template, request, session, url_for
from config import Config
from db import get_db, init_db, init_app
from security import (USERNAME_RE, EMAIL_RE, csrf_token, enforce_session, hash_password,
                      verify_password, valid_password, validate_csrf, login_required,
                      safe_internal_path, log_event)

def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    if not app.config.get("SECRET_KEY"):
        if app.config.get("TESTING"):
            app.config["SECRET_KEY"] = "test-only-secret-not-for-deployment"
        else:
            raise RuntimeError("DEMOBANK_SECRET_KEY environment variable is required.")
    if app.config.get("DEBUG"):
        raise RuntimeError("Debug mode is disabled for this application.")
    os.makedirs(app.instance_path, exist_ok=True)
    init_app(app)
    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["money"] = lambda cents: f"${cents / 100:,.2f}"

    logging.basicConfig(level=logging.INFO)
    app.before_request(validate_csrf)
    @app.before_request
    def load_identity():
        g.user = None
        enforce_session()

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers.pop("Server", None)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.context_processor
    def inject_globals():
        return {"current_user": getattr(g, "user", None)}

    @app.route("/")
    def home():
        return render_template("home.html")

    @app.route("/about")
    def about():
        return render_template("about.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            full_name = request.form.get("full_name", "").strip()
            password = request.form.get("password", "")
            if not USERNAME_RE.fullmatch(username) or not EMAIL_RE.fullmatch(email) or not (2 <= len(full_name) <= 80) or not valid_password(password):
                flash("Please check your details. Usernames need 3–30 characters and passwords at least 12 characters.", "error")
                return render_template("register.html")
            db = get_db()
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO users(username,email,full_name,password_hash) VALUES(?,?,?,?)",
                           (username, email, full_name, hash_password(password)))
                uid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                account_number = "DB" + secrets.token_hex(6).upper()
                db.execute("INSERT INTO accounts(user_id,account_number,balance_cents) VALUES(?,?,?)",
                           (uid, account_number, app.config["INITIAL_BALANCE_CENTS"]))
                db.execute("INSERT INTO notifications(user_id,message,category) VALUES(?,?,?)",
                           (uid, "Welcome to DemoBank. Your virtual account is ready.", "success"))
                db.commit()
                flash("Your demo account has been created. You can now sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                db.rollback()
                flash("That username or email is already registered.", "error")
            except Exception:
                db.rollback()
                app.logger.exception("Registration failed")
                flash("We could not complete registration. Please try again.", "error")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            key = username.casefold()[:80]
            db = get_db()
            now = int(time.time())
            db.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (now - 900,))
            attempts = db.execute("SELECT COUNT(*) n FROM login_attempts WHERE username_key=? AND succeeded=0 AND attempted_at>?",
                                  (key, now - 900)).fetchone()["n"]
            user = db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()
            ok = attempts < 5 and user and verify_password(user["password_hash"], password)
            db.execute("INSERT INTO login_attempts(username_key,attempted_at,succeeded) VALUES(?,?,?)",
                       (key, now, 1 if ok else 0))
            if not ok:
                log_event("login_failed", username)
                flash("Invalid username or password.", "error")
                return render_template("login.html"), 401
            # Rotate the server-side session identifier; revoke any old sessions for this account.
            db.execute("DELETE FROM active_sessions WHERE user_id=?", (user["id"],))
            session.clear()
            sid = secrets.token_urlsafe(32)
            session["sid"] = sid
            session.permanent = True
            db.execute("INSERT INTO active_sessions(sid,user_id,created_at,last_seen) VALUES(?,?,?,?)",
                       (sid, user["id"], now, now))
            log_event("login_success", username)
            target = safe_internal_path(request.args.get("next"))
            return redirect(target or url_for("dashboard"))
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        db = get_db()
        db.execute("DELETE FROM active_sessions WHERE user_id=?", (g.user["id"],))
        log_event("logout", g.user["username"])
        session.clear()
        flash("You have been signed out.", "success")
        return redirect(url_for("logout_done"))

    @app.route("/logout/done")
    def logout_done():
        return render_template("logout.html")

    def own_account():
        return get_db().execute("SELECT * FROM accounts WHERE user_id=?", (g.user["id"],)).fetchone()

    @app.route("/dashboard")
    @login_required
    def dashboard():
        account = own_account()
        txs = get_db().execute(
            "SELECT t.*, a.account_number AS sender_no, b.account_number AS recipient_no, "
            "u1.full_name AS sender_name, u2.full_name AS recipient_name "
            "FROM transactions t JOIN accounts a ON a.id=t.sender_account_id "
            "JOIN accounts b ON b.id=t.recipient_account_id "
            "JOIN users u1 ON u1.id=a.user_id JOIN users u2 ON u2.id=b.user_id "
            "WHERE a.user_id=? OR b.user_id=? ORDER BY t.id DESC LIMIT 5",
            (g.user["id"], g.user["id"])).fetchall()
        return render_template("dashboard.html", account=account, transactions=txs)

    @app.route("/account")
    @login_required
    def account():
        return render_template("account.html", account=own_account())

    @app.route("/transfer", methods=["GET", "POST"])
    @login_required
    def transfer():
        if request.method == "POST":
            recipient = request.form.get("recipient", "").strip()
            description = request.form.get("description", "").strip()
            idem = request.form.get("idempotency_key", "")
            raw_amount = request.form.get("amount", "")
            if not re.fullmatch(r"[A-Za-z0-9]{8,40}", idem) or len(description) > 120:
                flash("Please review the transfer details and try again.", "error")
                return redirect(url_for("transfer"))
            try:
                amount = Decimal(raw_amount)
                if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent < -2:
                    raise InvalidOperation()
                cents = int(amount * 100)
            except (InvalidOperation, ValueError, TypeError):
                flash("Enter a valid positive amount with no more than two decimal places.", "error")
                return redirect(url_for("transfer"))
            if cents > app.config["MAX_TRANSFER_CENTS"]:
                flash("The maximum transfer is $100,000.00.", "error")
                return redirect(url_for("transfer"))
            db = get_db()
            try:
                db.execute("BEGIN IMMEDIATE")
                existing = db.execute("SELECT transaction_id FROM idempotency_keys WHERE user_id=? AND idem_key=?",
                                      (g.user["id"], idem)).fetchone()
                if existing:
                    db.rollback()
                    flash("This transfer request was already submitted.", "warning")
                    return redirect(url_for("transactions"))
                sender = db.execute("SELECT * FROM accounts WHERE user_id=?", (g.user["id"],)).fetchone()
                target = db.execute("SELECT a.*,u.full_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=? COLLATE NOCASE",
                                    (recipient,)).fetchone()
                if not target or target["id"] == sender["id"] or sender["balance_cents"] < cents:
                    db.rollback()
                    log_event("transfer_failed", g.user["username"], "invalid recipient, self-transfer, or insufficient funds")
                    flash("Transfer could not be completed. Check the recipient and available balance.", "error")
                    return redirect(url_for("transfer"))
                db.execute("UPDATE accounts SET balance_cents=balance_cents-? WHERE id=? AND balance_cents>=?",
                           (cents, sender["id"], cents))
                if db.execute("SELECT changes()").fetchone()[0] != 1:
                    raise ValueError("insufficient funds")
                db.execute("UPDATE accounts SET balance_cents=balance_cents+? WHERE id=?", (cents, target["id"]))
                reference = "TX" + secrets.token_hex(8).upper()
                db.execute("""
                    INSERT INTO transactions(
                        reference,
                        sender_account_id,
                        recipient_account_id,
                        amount_cents,
                        description,
                        status
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    reference,
                    sender["id"],
                    target["id"],
                    cents,
                    description,
                    "completed"
                ))
                txid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                db.execute("INSERT INTO idempotency_keys(user_id,idem_key,transaction_id) VALUES(?,?,?)",
                           (g.user["id"], idem, txid))
                db.execute("INSERT INTO notifications(user_id,message,category) VALUES(?,?,?)",
                           (g.user["id"], "Your transfer of " + f"${cents/100:,.2f}" + " was completed.", "success"))
                db.execute("INSERT INTO notifications(user_id,message,category) VALUES(?,?,?)",
                           (target["user_id"], "You received a virtual transfer of " + f"${cents/100:,.2f}" + ".", "success"))
                db.commit()
                log_event("transfer_success", g.user["username"], reference)
                flash("Transfer completed successfully.", "success")
                return redirect(url_for("transactions"))
            except Exception:
                db.rollback()
                app.logger.exception("Transfer failed")
                flash("We could not complete the transfer. No funds were moved.", "error")
                return redirect(url_for("transfer"))
        return render_template("transfer.html", account=own_account(), idem=secrets.token_urlsafe(18))

    @app.route("/transactions")
    @login_required
    def transactions():
        kind = request.args.get("type", "all")
        start = request.args.get("from", "")
        end = request.args.get("to", "")
        if kind not in ("all", "incoming", "outgoing"):
            kind = "all"
        clauses = ["(sa.user_id=? OR ra.user_id=?)"]
        params = [g.user["id"], g.user["id"]]
        if kind == "incoming":
            clauses.append("ra.user_id=?"); params.append(g.user["id"])
        elif kind == "outgoing":
            clauses.append("sa.user_id=?"); params.append(g.user["id"])
        if start and re.fullmatch(r"\\d{4}-\\d{2}-\\d{2}", start):
            clauses.append("date(t.created_at)>=date(?)"); params.append(start)
        if end and re.fullmatch(r"\\d{4}-\\d{2}-\\d{2}", end):
            clauses.append("date(t.created_at)<=date(?)"); params.append(end)
        rows = get_db().execute(
            "SELECT t.*,su.full_name sender_name,ru.full_name recipient_name,sa.account_number sender_no,ra.account_number recipient_no "
            "FROM transactions t JOIN accounts sa ON sa.id=t.sender_account_id JOIN users su ON su.id=sa.user_id "
            "JOIN accounts ra ON ra.id=t.recipient_account_id JOIN users ru ON ru.id=ra.user_id WHERE "
            + " AND ".join(clauses) + " ORDER BY t.id DESC LIMIT 200", params).fetchall()
        return render_template("transactions.html", transactions=rows, kind=kind, start=start, end=end)

    @app.route("/profile", methods=["GET", "POST"])
    @login_required
    def profile():
        if request.method == "POST":
            full_name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            if not (2 <= len(full_name) <= 80) or not EMAIL_RE.fullmatch(email):
                flash("Enter a valid name and email address.", "error")
            else:
                try:
                    get_db().execute("UPDATE users SET full_name=?,email=? WHERE id=?", (full_name,email,g.user["id"]))
                    flash("Profile updated.", "success")
                    return redirect(url_for("profile"))
                except sqlite3.IntegrityError:
                    flash("That email address is already in use.", "error")
        fresh = get_db().execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
        return render_template("profile.html", user=fresh)

    @app.route("/settings")
    @login_required
    def settings():
        return render_template("settings.html")

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            old = request.form.get("current_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")
            user = get_db().execute("SELECT * FROM users WHERE id=?", (g.user["id"],)).fetchone()
            if not verify_password(user["password_hash"], old) or not valid_password(new) or new != confirm:
                flash("Password change failed. Check your current password and new password requirements.", "error")
            else:
                db = get_db()
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new),g.user["id"]))
                db.execute("DELETE FROM active_sessions WHERE user_id=?", (g.user["id"],))
                log_event("password_changed", g.user["username"])
                session.clear()
                flash("Password changed. Please sign in again.", "success")
                return redirect(url_for("login"))
        return render_template("change_password.html")

    @app.route("/notifications")
    @login_required
    def notifications():
        db = get_db()
        rows = db.execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100", (g.user["id"],)).fetchall()
        db.execute("UPDATE notifications SET is_read=1 WHERE user_id=?", (g.user["id"],))
        return render_template("notifications.html", notifications=rows)

    @app.route("/403")
    def forbidden():
        return render_template("error.html", code=403, message="You do not have permission to view this page."), 403

    @app.errorhandler(400)
    def bad_request(_):
        return render_template("error.html", code=400, message="The request could not be processed. Refresh and try again."), 400
    @app.errorhandler(403)
    def err403(_):
        return render_template("error.html", code=403, message="You do not have permission to view this page."), 403
    @app.errorhandler(404)
    def err404(_):
        return render_template("error.html", code=404, message="The page you requested could not be found."), 404
    @app.errorhandler(500)
    def err500(_):
        return render_template("error.html", code=500, message="Something went wrong. Please try again later."), 500

    @app.cli.command("init-db")
    def init_db_command():
        init_db()
        print("Database initialized.")

    @app.cli.command("seed-demo")
    def seed_demo_command():
        db = get_db()
        init_db()
        demos = [
            ("alice", "alice@example.test", "Alice Morgan", "DemoPass12345!"),
            ("bob", "bob@example.test", "Bob Taylor", "DemoPass12345!"),
        ]
        for username,email,name,password in demos:
            existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not existing:
                db.execute("INSERT INTO users(username,email,full_name,password_hash) VALUES(?,?,?,?)",
                           (username,email,name,hash_password(password)))
                uid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
                db.execute("INSERT INTO accounts(user_id,account_number,balance_cents) VALUES(?,?,?)",
                           (uid, "DB" + ("ALICE000001" if username=="alice" else "BOB00000002"), 250000))
                db.execute("INSERT INTO notifications(user_id,message,category) VALUES(?,?,?)",
                           (uid, "Demo account ready. Use virtual funds for testing.", "info"))
        print("Demo users created if absent.")
    return app

app = create_app()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
