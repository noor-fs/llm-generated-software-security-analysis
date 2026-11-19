import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    SECRET_KEY = os.environ.get("DEMOBANK_SECRET_KEY")
    DATABASE = os.environ.get("DEMOBANK_DATABASE", str(BASE_DIR / "instance" / "demobank.sqlite3"))
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = os.environ.get("DEMOBANK_COOKIE_SECURE", "0") == "1"
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = 1800
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024
    INITIAL_BALANCE_CENTS = 100000
    MAX_TRANSFER_CENTS = 10000000
