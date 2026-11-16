# DemoBank V2 — security-hardened comparison build

This is a security-improved continuation of DemoBank V1, not a redesign. It retains the V1 Flask routes, templates, CSS, JavaScript, logo, illustrations, SQLite schema, and user-facing workflows. The application is a fictional local banking simulation; never use real credentials or real financial data.

## Run independently

```bash
cd DemoBank_V2
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m flask --app app init-db
python -m flask --app app seed-demo
python run_local.py --host 127.0.0.1 --port 5002
```

Open http://127.0.0.1:5002. Demo users: `alice`, `bob`, `charlie`; password: `DemoPass123!`.

V2 defaults to `instance/demobank.sqlite3` within this V2 folder. V1 uses its own folder and database. Do not point both applications at the same `DEMOBANK_DB` file.

## Reset V2 development data

This deletes only V2's local database and SQLite sidecar files:

```bash
rm -f instance/demobank.sqlite3 instance/demobank.sqlite3-shm instance/demobank.sqlite3-wal
python -m flask --app app init-db
python -m flask --app app seed-demo
```

Back up the database first if you want to retain data. `seed-demo` is idempotent for existing usernames and will not reset balances or passwords.

## Configuration

For repeatable sessions across server restarts, set a persistent random secret:

```bash
export DEMOBANK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

For production-like configuration, also set `DEMOBANK_ENV=production` and `DEMOBANK_DEBUG=0`. Production mode refuses to start without `DEMOBANK_SECRET_KEY` and enables Secure cookies. The provided `run_local.py` uses a generic `Server: DemoBank` value rather than exposing Werkzeug/Python versions. It is still a development server for localhost testing only; do not expose it to the internet. If you use `flask run` instead, the Werkzeug server may add its own identifying Server header.

To select another isolated database:

```bash
DEMOBANK_DB="$PWD/instance/experiment.sqlite3" python -m flask --app app init-db
```

## Reproduce the V1 dependency environment

The supplied V1 pip-audit report records the exact dependency versions in the package-root `comparison-requirements.txt`. To reduce dependency-version drift, install that same file in both V1 and V2 environments before running the comparison (from the package root use `python -m pip install -r comparison-requirements.txt`). The ordinary `requirements.txt` remains compatible with V1.

## Run tests

```bash
python -m pip install pytest
python -m pytest -v
```

The tests use a temporary SQLite database and do not modify the V2 demo database.

## Security changes from V1

1. Added a restrictive same-origin Content Security Policy, including `frame-ancestors 'none'` and `form-action 'self'`.
2. Added `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, Referrer-Policy, Permissions-Policy, and related hardening headers.
3. Added WSGI response-header filtering for upstream Server headers and a dedicated local runner (`run_local.py`) that emits only a generic `Server: DemoBank` value, avoiding Werkzeug/Python version disclosure.
4. Replaced predictable development fallback signing key with a cryptographically random per-process key. Set `DEMOBANK_SECRET_KEY` to persist sessions across restarts. Production requires an explicit secret.
5. Replaced f-string SQL `IN (...)` construction in dashboard/history with fixed SQL and bound user IDs. This both clarifies the authorization scope and avoids the Bandit B608 / custom Semgrep dynamic-SQL pattern.
6. Tightened username validation to the ASCII character set advertised by the registration form and bounded the raw transfer amount length before Decimal parsing.
7. Disabled Flask debug mode by default.

## Findings interpretation and comparison notes

See `docs/SECURITY_REMEDIATION.md` and `reports/V1/` for the supplied V1 evidence. V1's ZAP report recorded 2 Medium and 2 Low alerts (missing CSP, anti-clickjacking protection, server version disclosure, and `nosniff`) plus 3 informational alerts. The potential-XSS alert is a hotspot, not proof of exploitability. V1's Burp file is a Proxy HTTP history export (26 captured requests), not a Burp Scanner issue report. Bandit and Semgrep dynamic-SQL alerts overlap and are not confirmed SQL injection merely because placeholder-count SQL was assembled dynamically.

No claim is made that V2 is vulnerability-free. Re-run the same tools, rule packs, authentication coverage, scan policies, and test cases against V2 and compare confirmed findings. A scanner result is not evidence of absence of vulnerabilities.
