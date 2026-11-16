import os
import tempfile
import unittest
from app import app, init_db

class DemoBankTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "test.sqlite3")
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        os.environ["DEMOBANK_DB"] = self.db_path
        # app reads DB_PATH at import, so override the module global directly.
        import app as app_module
        app_module.DB_PATH = self.db_path
        with app.app_context():
            init_db()
        self.client = app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def csrf(self):
        self.client.get("/register")
        with self.client.session_transaction() as sess:
            return sess.get("csrf_token")

    def test_home_and_protected_route(self):
        self.assertEqual(self.client.get("/").status_code, 200)
        response = self.client.get("/dashboard", follow_redirects=False)
        self.assertEqual(response.status_code, 302)

    def test_register_and_dashboard(self):
        token = self.csrf()
        response = self.client.post("/register", data={
            "csrf_token": token, "full_name": "Test User", "username": "test_user",
            "email": "test@example.test", "password": "StrongPassword123!",
            "confirm_password": "StrongPassword123!"
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"QAR", response.data)
        self.assertIn(b"Dashboard", response.data)

    def test_csrf_rejected(self):
        self.assertEqual(self.client.post("/login", data={"username": "x", "password": "y"}).status_code, 400)

if __name__ == "__main__":
    unittest.main()
