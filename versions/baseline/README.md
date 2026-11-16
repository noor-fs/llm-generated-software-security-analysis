# DemoBank

DemoBank is a fictional local banking application for the academic project **Security Analysis of LLM-Generated Software**. All balances and transfers are simulated; no real bank, payment provider, or external service is connected.

## Requirements

- Ubuntu or another Linux distribution
- Python 3.10+
- `python3-venv`

## Quick start

```bash
cd DemoBank
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app init-db
flask --app app seed-demo
flask --app app run --host 127.0.0.1
```

Open `http://127.0.0.1:5000`.

### Demo accounts

All seeded demo accounts use the password `DemoPass123!`:

- `alice`
- `bob`
- `charlie`

New registrations receive a fictional QAR 2,500.00 starting balance. The seed command is safe to run more than once and does not overwrite existing demo users.

## Database and reset

The default database is `instance/demobank.sqlite3`. To reset only your local development database:

```bash
rm -f instance/demobank.sqlite3 instance/demobank.sqlite3-shm instance/demobank.sqlite3-wal
flask --app app init-db
flask --app app seed-demo
```

Keep test data separate by setting `DEMOBANK_DB` to a different file path when running tests or experiments:

```bash
DEMOBANK_DB="$PWD/instance/test.sqlite3" flask --app app init-db
```

## Production-like local configuration

The built-in Flask development server is intended only for local development. Do not expose it to the internet. For a production-like deployment, set a long random secret and disable debug mode:

```bash
export DEMOBANK_ENV=production
export DEMOBANK_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export DEMOBANK_DEBUG=0
flask --app app run --host 127.0.0.1
```

The app will refuse production mode if the secret key is not configured. `SESSION_COOKIE_SECURE` is enabled in production mode, so use HTTPS if you intentionally deploy it beyond localhost.

## Security design notes

- Passwords are stored as Werkzeug password hashes, not plaintext.
- SQL uses parameterized statements; user input is not interpolated into query values.
- State-changing routes require a session-bound CSRF token.
- Sessions use HTTP-only cookies and `SameSite=Lax`; sessions are cleared on login/logout and after password change.
- Login-protected routes derive the user identity from the server-side session and scope profile/account/notification queries to that identity.
- Money is represented as integer cents, avoiding binary floating-point arithmetic.
- Transfers use a SQLite `BEGIN IMMEDIATE` transaction, a conditional debit, foreign keys, non-negative balance constraints, and a unique idempotency key to prevent duplicate processing.
- SQLite foreign-key checks are enabled per connection and a busy timeout is configured.
- Templates use Jinja autoescaping for normal HTML output.
- A transfer is committed together with both balance updates, the transfer record, and notifications; a failure rolls back the transaction.
- The transfer form creates a fresh idempotency key for each rendered form. Reusing a submitted key will not repeat a successful transfer.

## Known academic limitations / follow-up hardening

This is a local academic simulation, not a real banking product. It does not implement MFA, email verification, rate limiting, account recovery, audit-log tamper resistance, fraud monitoring, or external security review. A production service should add these and use a managed deployment configuration, HTTPS, robust secret management, monitoring, and formal threat modeling. Demo passwords are intentionally public and must never be reused.

## Suggested security tests

1. Register with a duplicate username/email; expect a clear error.
2. Try login with a wrong password; expect rejection.
3. Open `/dashboard` while signed out; expect redirect to login.
4. Submit a form without its CSRF token; expect HTTP 400.
5. Attempt a transfer to a nonexistent account, own account, zero amount, excessive precision, or amount above balance; expect no balance changes.
6. Send a transfer to another seeded user; verify both balances, one transfer row, and notifications.
7. Resubmit the same idempotency key; verify no second transfer is created.
8. Confirm transaction history only shows transactions associated with the signed-in user's account(s).
9. Use separate `DEMOBANK_DB` paths for baseline and hardened experiment runs.
