import sqlite3
from datetime import datetime, timezone
from flask import current_app, g

SCHEMA = '''
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 email TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 full_name TEXT NOT NULL,
 phone TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
 account_number TEXT NOT NULL UNIQUE,
 balance_cents INTEGER NOT NULL DEFAULT 0 CHECK(balance_cents >= 0),
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS transfers (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender_account_id INTEGER NOT NULL REFERENCES accounts(id),
 recipient_account_id INTEGER NOT NULL REFERENCES accounts(id),
 amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
 description TEXT NOT NULL DEFAULT '',
 idempotency_key TEXT NOT NULL,
 created_at TEXT NOT NULL,
 CHECK(sender_account_id <> recipient_account_id),
 UNIQUE(sender_account_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_transfers_sender_date ON transfers(sender_account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_transfers_recipient_date ON transfers(recipient_account_id, created_at DESC);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 message TEXT NOT NULL,
 kind TEXT NOT NULL DEFAULT 'info',
 is_read INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at DESC);
'''

def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def get_db():
    if 'db' not in g:
        conn = sqlite3.connect(current_app.config['DATABASE'], timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys=ON')
        conn.execute('PRAGMA busy_timeout=15000')
        g.db = conn
    return g.db

def close_db(error=None):
    conn = g.pop('db', None)
    if conn is not None:
        conn.close()

def init_db():
    db = get_db()
    db.executescript(SCHEMA)

def notify(user_id, message, kind='info'):
    get_db().execute('INSERT INTO notifications(user_id,message,kind,created_at) VALUES(?,?,?,?)',
                     (user_id, message, kind, now()))
