import tempfile
import unittest
from app import create_app
from db import get_db, init_db

class DemoBankTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile()
        self.app = create_app({"TESTING": True, "SECRET_KEY": "test-secret",
                               "DATABASE": self.tmp.name, "WTF_CSRF_ENABLED": False})
        self.client = self.app.test_client()
        with self.app.app_context():
            init_db()

    def tearDown(self):
        self.tmp.close()

    def csrf(self):
        with self.client.session_transaction() as s:
            return s.get("_csrf")

    def register(self, username, email):
        self.client.get("/register")
        token = self.csrf()
        return self.client.post("/register", data={"_csrf": token, "full_name": username.title()+" User",
            "username": username, "email": email, "password": "TestPassword123!"}, follow_redirects=True)

    def login(self, username):
        self.client.get("/login")
        return self.client.post("/login", data={"_csrf": self.csrf(), "username": username,
                                                "password": "TestPassword123!"}, follow_redirects=True)

    def test_register_login_and_security_headers(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.register("alice", "alice@test.example")
        response = self.login("alice")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Available demo balance", response.data)

    def test_transfer_moves_virtual_funds(self):
        self.register("alice", "alice@test.example")
        self.register("bob", "bob@test.example")
        with self.app.app_context():
            db = get_db()
            alice = db.execute("SELECT id FROM users WHERE username='alice'").fetchone()["id"]
            bob = db.execute("SELECT id FROM users WHERE username='bob'").fetchone()["id"]
            a_no = db.execute("SELECT account_number FROM accounts WHERE user_id=?", (alice,)).fetchone()["account_number"]
            b_no = db.execute("SELECT account_number FROM accounts WHERE user_id=?", (bob,)).fetchone()["account_number"]
            before_a = db.execute("SELECT balance_cents FROM accounts WHERE user_id=?", (alice,)).fetchone()[0]
            before_b = db.execute("SELECT balance_cents FROM accounts WHERE user_id=?", (bob,)).fetchone()[0]
        self.login("alice")
        token = self.csrf()
        self.client.post("/transfer", data={"_csrf":token,"recipient":b_no,"amount":"10.25",
            "description":"test","idempotency_key":"abcdefgh12345678"})
        with self.app.app_context():
            db=get_db()
            after_a=db.execute("SELECT balance_cents FROM accounts WHERE account_number=?", (a_no,)).fetchone()[0]
            after_b=db.execute("SELECT balance_cents FROM accounts WHERE account_number=?", (b_no,)).fetchone()[0]
            self.assertEqual(before_a-after_a,1025)
            self.assertEqual(after_b-before_b,1025)

    def test_post_without_csrf_rejected(self):
        response = self.client.post("/login", data={"username":"x","password":"y"})
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
