import os
import sqlite3
import tempfile
import unittest

import app as app_module
from app import app, init_db
from werkzeug.security import generate_password_hash


class DemoBankSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.sqlite3")
        app.config.update(TESTING=True, SECRET_KEY="test-secret-key-not-for-production")
        app_module.DB_PATH = self.db_path
        with app.app_context():
            init_db()
            db = app_module.get_db()
            for username, email, name in [
                ("alice", "alice@example.test", "Alice Morgan"),
                ("bob", "bob@example.test", "Bob Taylor"),
            ]:
                db.execute(
                    "INSERT INTO users(username,email,full_name,password_hash) VALUES(?,?,?,?)",
                    (username, email, name, generate_password_hash("DemoPass123!")),
                )
                uid = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()[0]
                db.execute(
                    "INSERT INTO accounts(user_id,account_number,balance_cents) VALUES(?,?,?)",
                    (uid, "DB" + username.upper() + "12345", 250000),
                )
        self.alice = app.test_client()
        self.bob = app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def token(self, client, path="/login"):
        client.get(path)
        with client.session_transaction() as sess:
            return sess["csrf_token"]

    def login(self, client, username):
        token = self.token(client)
        return client.post("/login", data={
            "csrf_token": token, "username": username, "password": "DemoPass123!"
        }, follow_redirects=True)

    def test_public_pages_and_protected_redirect(self):
        self.assertEqual(self.alice.get("/").status_code, 200)
        self.assertEqual(self.alice.get("/about").status_code, 200)
        self.assertEqual(self.alice.get("/dashboard").status_code, 302)

    def test_security_headers_present(self):
        response = self.alice.get("/")
        self.assertIn("default-src 'self'", response.headers["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertIsNone(response.headers.get("Server"))

    def test_csrf_required_for_post(self):
        response = self.alice.post("/login", data={"username": "alice", "password": "bad"})
        self.assertEqual(response.status_code, 400)

    def test_register_and_login(self):
        client = app.test_client()
        token = self.token(client, "/register")
        response = client.post("/register", data={
            "csrf_token": token, "full_name": "Test User", "username": "test_user",
            "email": "test@example.test", "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Dashboard", response.data)

    def test_transfer_updates_both_balances_and_is_idempotent(self):
        self.login(self.alice, "alice")
        token = self.token(self.alice, "/transfer")
        data = {"csrf_token": token, "recipient": "DBBOB12345", "amount": "25.50",
                "description": "test transfer", "idempotency_key": "unique-transfer-1"}
        first = self.alice.post("/transfer", data=data, follow_redirects=True)
        self.assertEqual(first.status_code, 200)
        second = self.alice.post("/transfer", data=data, follow_redirects=True)
        self.assertEqual(second.status_code, 200)
        with app.app_context():
            db = app_module.get_db()
            a = db.execute("SELECT balance_cents FROM accounts WHERE account_number='DBALICE12345'").fetchone()[0]
            b = db.execute("SELECT balance_cents FROM accounts WHERE account_number='DBBOB12345'").fetchone()[0]
            count = db.execute("SELECT COUNT(*) FROM transfers").fetchone()[0]
        self.assertEqual(a, 247450)
        self.assertEqual(b, 252550)
        self.assertEqual(count, 1)

    def test_negative_transfer_is_rejected_without_balance_change(self):
        self.login(self.alice, "alice")
        token = self.token(self.alice, "/transfer")
        response = self.alice.post("/transfer", data={
            "csrf_token": token, "recipient": "DBBOB12345", "amount": "-10",
            "idempotency_key": "negative-transfer",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with app.app_context():
            balance = app_module.get_db().execute(
                "SELECT balance_cents FROM accounts WHERE account_number='DBALICE12345'"
            ).fetchone()[0]
        self.assertEqual(balance, 250000)

    def test_transaction_history_is_user_scoped(self):
        self.login(self.alice, "alice")
        self.assertEqual(self.alice.get("/transactions").status_code, 200)

    def test_profile_requires_authentication(self):
        self.assertEqual(self.alice.get("/profile").status_code, 302)


if __name__ == "__main__":
    unittest.main()
