# DemoBank V3 — Security-Aware Edition

DemoBank is a fictional local banking application for the academic project **Security Analysis of LLM-Generated Software**. Balances and transfers are simulated; no real bank, payment provider, or external service is connected. This project is for local learning and testing, not production financial services.

## Requirements

- Windows 10/11 or Linux/macOS
- Python 3.10+
- PowerShell (Windows instructions below)

## Windows PowerShell: install and run

Open PowerShell in the extracted `DemoBank_V3_FreeChatGPT_SecurityAware` folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
flask --app app init-db
flask --app app seed-demo
$env:DEMOBANK_DEBUG = "0"
flask --app app run --host 127.0.0.1 --port 5000
```

If PowerShell blocks virtual-environment activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in the current PowerShell window, then activate again.

Open **http://127.0.0.1:5000**. The command binds to loopback only.

### Seeded fictional demo users

| Username  | Password       |
| --------- | -------------- |
| `alice`   | `DemoPass123!` |
| `bob`     | `DemoPass123!` |
| `charlie` | `DemoPass123!` |

These public academic demo credentials must never be reused elsewhere. Each new registration receives a fictional QAR 2,500.00 starting balance.

## Run automated tests

With the virtual environment activated:

```powershell
python -m unittest -v
```

Tests use a temporary SQLite database and do not modify the normal demo database.

## Database and migration

The default database is `instance/demobank.sqlite3`. V3 preserves V1's `users`, `accounts`, `transfers`, and `notifications` tables and existing data. Initialization adds `users.auth_version` if absent and creates a `login_attempts` table. Back up any database before upgrading.

To use a separate database:

```powershell
$env:DEMOBANK_DB = "$PWD\instance\experiment.sqlite3"
flask --app app init-db
flask --app app seed-demo
```

To reset the local database, stop the server and remove `instance\demobank.sqlite3` and any `-wal` / `-shm` companions before initializing and seeding again. Do not delete experiment data you need.

## Production-like configuration note

The bundled Flask development server is for local use only. Do not expose it to the internet. V3 refuses to start in `DEMOBANK_ENV=production` unless `DEMOBANK_SECRET_KEY` is supplied with at least 32 characters. A production-like deployment also requires HTTPS and a properly configured production WSGI server:

```powershell
$env:DEMOBANK_ENV = "production"
$env:DEMOBANK_SECRET_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:DEMOBANK_DEBUG = "0"
```

`SESSION_COOKIE_SECURE` and HSTS are enabled in production mode. Do not use production mode over plain HTTP.

## Security controls in V3

- Werkzeug password hashes; 12-character minimum for new/changed passwords.
- HTTP-only, SameSite=Lax session cookies, 30-minute lifetime, session regeneration after login/registration, and database-backed `auth_version` revocation after logout/password change.
- Lightweight login throttling per hashed username/IP pair (five failures per 15-minute window).
- Session-bound CSRF token for all state-changing HTTP methods; logout is POST-only.
- Session-derived identity and owner-scoped queries. Sender ownership and available balance are rechecked inside the transfer write transaction.
- Parameterized SQL. Dynamic `IN` placeholders are generated only from database-derived account IDs.
- Jinja autoescaping and restrictive CSP without inline scripts/styles.
- Decimal parsing, integer cents, database constraints, `BEGIN IMMEDIATE`, conditional debit, foreign keys, and unique idempotency keys for transfers.
- Server-issued idempotency tokens bound to the authenticated session.
- Notifications are marked read using CSRF-protected POST, not GET.
- CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`; HSTS in production; `Cache-Control: no-store` on dynamic pages.
- Debug mode disabled in the direct-run entry point; generic user-facing errors and server-side exception logging.
- Request-size limits and server-side validation for user-provided fields and date filters.

## Protections already present in V1

V1 already used Werkzeug password hashes, parameterized SQLite queries, HTTP-only and SameSite=Lax cookies, POST CSRF tokens, authenticated route decorators, owner-scoped account/profile/notification reads, Jinja autoescaping, integer-cent balances, SQLite foreign keys/constraints, a write transaction for transfers, conditional balance debit, and a unique transfer idempotency key. V3 preserves these foundations and strengthens session revocation, validation, CSRF coverage, token issuance, login throttling, security headers, and tests.

## Remaining limitations

- Not a real banking system: no MFA, verified email, account recovery, fraud detection, payment rails, dispute/reversal workflow, or customer support.
- Seeded passwords are public by design. The local login throttle is not a distributed rate limiter and assumes a trusted direct peer IP.
- Flask's default session cookie is signed, not encrypted. Do not store secrets or sensitive personal data in it; server-side sessions are preferable for a real service.
- The development server and SQLite are suitable for this local exercise, not a high-availability or internet-facing financial service. Real deployment needs a production WSGI server, TLS, managed secrets, backups, monitoring, dependency scanning, and security review.
- CSP is intentionally strict; add future integrations narrowly rather than enabling broad `unsafe-inline` allowances.
- The tests cover selected behaviours. They are not a penetration test, formal audit, or OWASP certification. No claim is made that the application is completely secure.
