import os
import tempfile
import unittest

import app as app_module
from app import app, init_db


class DemoBankSecurityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.sqlite3")
        app.config.update(TESTING=True, SECRET_KEY="test-secret-key-that-is-long-enough-for-tests", WTF_CSRF_ENABLED=True)
        app_module.DB_PATH = self.db_path
        with app.app_context():
            init_db()
        self.client = app.test_client()
        self._register("alice", "alice@example.test")
        self.alice_cookie = None

    def tearDown(self):
        self.tmp.cleanup()

    def csrf(self, client=None):
        client = client or self.client
        client.get("/register")
        with client.session_transaction() as sess:
            return sess.get("csrf_token")

    def _register(self, username, email):
        token = self.csrf()
        return self.client.post("/register", data={
            "csrf_token": token, "full_name": "Test User", "username": username,
            "email": email, "password": "StrongPassword123!", "confirm_password": "StrongPassword123!"
        }, follow_redirects=True)

    def _logout(self, client=None):
        client = client or self.client
        with client.session_transaction() as sess:
            token = sess.get("csrf_token")
        return client.post("/logout", data={"csrf_token": token})

    def _login(self, client, username="alice", password="StrongPassword123!"):
        token = self.csrf(client)
        return client.post("/login", data={"csrf_token": token, "username": username, "password": password})

    def _user_id(self, username="alice"):
        with app.app_context():
            return app_module.get_db().execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()[0]

    def test_home_protected_route_and_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(app.test_client().get("/dashboard").status_code, 302)
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_registration_and_login(self):
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self._logout()
        self.assertEqual(self._login(self.client).status_code, 302)

    def test_csrf_rejected(self):
        response = self.client.post("/login", data={"username": "x", "password": "y"})
        self.assertEqual(response.status_code, 400)

    def test_logout_revokes_other_session_cookie(self):
        second = app.test_client()
        self._login(second)
        self.assertEqual(second.get("/dashboard").status_code, 200)
        self._logout(self.client)
        self.assertEqual(second.get("/dashboard").status_code, 302)

    def test_password_change_revokes_session_and_updates_hash(self):
        with self.client.session_transaction() as sess:
            token = sess["csrf_token"]
        response = self.client.post("/change-password", data={
            "csrf_token": token, "current_password": "StrongPassword123!",
            "new_password": "EvenStrongerPassword456!", "confirm_password": "EvenStrongerPassword456!"
        }, follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        self.assertEqual(self._login(self.client, password="EvenStrongerPassword456!").status_code, 302)

    def test_xss_payload_is_escaped(self):
        payload = '<script>alert(1)</script>'
        with self.client.session_transaction() as sess:
            token = sess["csrf_token"]
        response = self.client.post("/profile", data={"csrf_token": token, "full_name": payload, "phone": ""}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(payload.encode(), response.data)
        self.assertIn(b"&lt;script&gt;", response.data)

    def test_transfer_and_history_are_account_scoped(self):
        self._logout()
        self._register("bob", "bob@example.test")
        self._logout()
        self._login(self.client, "alice")
        with app.app_context():
            db = app_module.get_db()
            sender = db.execute("SELECT * FROM accounts WHERE user_id=?", (self._user_id("alice"),)).fetchone()
            recipient = db.execute("SELECT * FROM accounts WHERE user_id=?", (self._user_id("bob"),)).fetchone()
        page = self.client.get("/transfer")
        self.assertEqual(page.status_code, 200)
        with self.client.session_transaction() as sess:
            csrf = sess["csrf_token"]
            idem = sess["transfer_tokens"][-1]
        response = self.client.post("/transfer", data={
            "csrf_token": csrf, "idempotency_key": idem, "recipient": recipient["account_number"],
            "amount": "12.34", "description": "Test transfer"
        })
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            db = app_module.get_db()
            self.assertEqual(db.execute("SELECT balance_cents FROM accounts WHERE id=?", (sender["id"],)).fetchone()[0], 248766)
            self.assertEqual(db.execute("SELECT balance_cents FROM accounts WHERE id=?", (recipient["id"],)).fetchone()[0], 251234)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM transfers").fetchone()[0], 1)

    def test_transfer_rejects_invalid_amount_without_balance_change(self):
        with self.client.session_transaction() as sess:
            csrf = sess["csrf_token"]
        self.client.get("/transfer")
        with self.client.session_transaction() as sess:
            idem = sess["transfer_tokens"][-1]
            csrf = sess["csrf_token"]
        response = self.client.post("/transfer", data={"csrf_token": csrf, "idempotency_key": idem, "recipient": "DBNOTREAL", "amount": "1.001"})
        self.assertEqual(response.status_code, 302)
        with app.app_context():
            self.assertEqual(app_module.get_db().execute("SELECT COUNT(*) FROM transfers").fetchone()[0], 0)

    def test_login_rate_limit(self):
        for _ in range(app_module.LOGIN_MAX_ATTEMPTS):
            self._logout()
            self._login(self.client, password="wrong-password")
        self._logout()
        response = self._login(self.client, password="wrong-password")
        self.assertEqual(response.status_code, 429)

    def test_all_original_routes_exist(self):
        rules = {rule.rule for rule in app.url_map.iter_rules()}
        for path in ["/", "/about", "/register", "/login", "/logout", "/dashboard", "/account", "/transfer", "/transactions", "/profile", "/settings", "/change-password", "/notifications"]:
            self.assertIn(path, rules)


if __name__ == "__main__":
    unittest.main()
