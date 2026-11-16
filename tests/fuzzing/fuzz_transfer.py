"""Atheris coverage-guided fuzzer for the /transfer endpoint.

Runs the real app through Flask's test client (no server needed) and checks
three properties after every fuzzed request:
  1. The app never returns a 500 error.
  2. No account balance ever goes negative.
  3. Money is never created or destroyed (total of all balances stays the same).

Usage (from the repo root, inside a venv with the app's requirements + atheris):
    python tests/fuzzing/fuzz_transfer.py versions/baseline -max_total_time=1800
    python tests/fuzzing/fuzz_transfer.py versions/self-fixed -max_total_time=1800

Any crash input is saved by libFuzzer as crash-<hash> in the current folder.
Use the same -max_total_time on every version so the comparison is fair.
"""
import os
import re
import sys
import sqlite3
import tempfile

import atheris

APP_DIR = os.path.abspath(sys.argv.pop(1)) if len(sys.argv) > 1 and not sys.argv[1].startswith("-") else None
if not APP_DIR:
    sys.exit("Usage: python fuzz_transfer.py <version-folder> [libFuzzer options]")

DB_FILE = os.path.join(tempfile.mkdtemp(prefix="fuzz-"), "fuzz.sqlite3")
os.environ["DEMOBANK_DB"] = DB_FILE          # baseline / security-aware
os.environ["DEMOBANK_DATABASE"] = DB_FILE    # paid tier
os.environ.setdefault("DEMOBANK_DEBUG", "0")
sys.path.insert(0, APP_DIR)

# Versions differ in layout: app.py (single file) or run.py + package (app factory).
ENTRY = "app" if os.path.exists(os.path.join(APP_DIR, "app.py")) else "run"
with atheris.instrument_imports():
    target = __import__(ENTRY)

flask_app = target.app
flask_app.config["TESTING"] = False  # keep real error handling (500s are what we look for)
runner = flask_app.test_cli_runner()
runner.invoke(args=["init-db"])
runner.invoke(args=["seed-demo"])

def balances():
    with sqlite3.connect(DB_FILE) as db:
        return [r[0] for r in db.execute("SELECT balance_cents FROM accounts")]

START_TOTAL = sum(balances())
client = flask_app.test_client()

CSRF_RE = re.compile(r'name="(csrf_token|_csrf)" value="([^"]*)"')
with sqlite3.connect(DB_FILE) as _db:
    USER = _db.execute("SELECT username FROM users ORDER BY id LIMIT 1").fetchone()[0]  # alice / alex
    RECIPIENTS = [r[0] for r in _db.execute(
        "SELECT a.account_number FROM accounts a JOIN users u ON u.id=a.user_id WHERE u.username != ?", (USER,))]


def login():
    page = client.get("/login").get_data(as_text=True)
    token = CSRF_RE.search(page)
    form = {"username": USER, "identifier": USER, "password": "DemoPass123!"}  # field name differs per version
    if token:
        form[token.group(1)] = token.group(2)
    client.post("/login", data=form)


login()


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # Mix raw junk with number-shaped input so the fuzzer also reaches the
    # code paths behind amount validation (successful and boundary transfers).
    mode = fdp.ConsumeIntInRange(0, 2)
    if mode == 0:
        amount = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 40))
    elif mode == 1:
        cents = fdp.ConsumeIntInRange(-500_000, 500_000)  # -5,000 to 5,000 QAR
        amount = f"{'-' if cents < 0 else ''}{abs(cents) // 100}.{abs(cents) % 100:02d}"
    else:
        amount = repr(fdp.ConsumeRegularFloat())
    description = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 200))
    recipient = RECIPIENTS[fdp.ConsumeIntInRange(0, len(RECIPIENTS) - 1)] if fdp.ConsumeBool() \
        else fdp.ConsumeUnicodeNoSurrogates(16)

    page = client.get("/transfer").get_data(as_text=True)
    if not CSRF_RE.search(page) or 'name="idempotency_key"' not in page:  # logged out or rate limited
        login()
        page = client.get("/transfer").get_data(as_text=True)
    csrf = CSRF_RE.search(page)
    key = re.search(r'name="idempotency_key" value="([^"]*)"', page)

    form = {"idempotency_key": key.group(1) if key else "",
            "recipient": recipient, "amount": amount, "description": description}
    if csrf:
        form[csrf.group(1)] = csrf.group(2)
    resp = client.post("/transfer", data=form)

    assert resp.status_code != 500, f"500 error for amount={amount!r} recipient={recipient!r}"
    current = balances()
    assert min(current) >= 0, f"negative balance {current} after amount={amount!r}"
    assert sum(current) == START_TOTAL, f"money created/destroyed: {sum(current)} != {START_TOTAL} after amount={amount!r}"


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
