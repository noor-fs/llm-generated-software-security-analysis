# DemoBank Security Notes and Test Guide

This document maps the implementation to the requested OWASP Top 10:2025 controls. DemoBank is a teaching application with virtual money only; it is not suitable for real financial use.

## A01 — Broken Access Control
- Private routes use `@login_required`; user identity is derived from the server-side session and database, not a submitted user ID.
- Account queries are scoped to `g.user["id"]`; transaction queries require the current user to own the sender or recipient account.
- Default-deny behavior is used for protected routes. Account IDs are never accepted from transfer forms.
- Test: open `/dashboard`, `/account`, `/transfer`, `/transactions`, `/profile`, `/settings`, `/notifications`, and `/change-password` in a logged-out browser. Each should redirect to login. Register two users and confirm one user's history only contains transactions involving their own account.

## A02 — Security Misconfiguration
- Debug mode is false; application startup rejects `DEBUG=True`.
- Unexpected errors render a generic 500 page; stack traces are logged server-side only.
- Every response receives CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy headers. Flask's default Server header is removed.
- Session cookies are HttpOnly and SameSite=Lax. Secure cookies can be enabled with `DEMOBANK_COOKIE_SECURE=1` when using HTTPS.
- Test: inspect response headers with browser devtools or `curl -I http://127.0.0.1:5000/`. Confirm no debug traceback is shown for a deliberately triggered server error.

## A03 — Software Supply Chain Failures
- `requirements.txt` pins the Flask stack to explicit package versions. No runtime CDN or external service is required for application functionality.
- Test: create a clean virtual environment and run `pip install -r requirements.txt`. Review installed package versions using `pip freeze`.

## A04 — Cryptographic Failures
- `DEMOBANK_SECRET_KEY` is required at startup; there is no production fallback. `.env.example` contains a placeholder, not a usable secret.
- Passwords use Werkzeug's salted scrypt password hashing.
- SQLite stores only password hashes. Session IDs are random opaque values stored server-side.
- Test: inspect `users.password_hash` in SQLite; it must not equal the password and should contain a scrypt hash. Unset `DEMOBANK_SECRET_KEY` and verify normal startup fails.

## A05 — Injection
- SQL statements use parameter placeholders; user-controlled values are not concatenated into SQL. The only dynamic SQL fragments in transaction history are selected from fixed server-side allowlisted clauses.
- Server-side validation checks username, email, name, password length, transfer amount, idempotency key, description and filter formats.
- Jinja autoescaping is enabled; templates do not mark user data safe.
- Test: register a name such as `<script>alert(1)</script>` and verify it is rendered as text, not executed. Try SQL-like input in username and recipient fields; it must not alter query behavior.

## A06 — Insecure Design
- Transfers run under SQLite `BEGIN IMMEDIATE`, use integer cents, enforce positive amounts and a $100,000 maximum, and conditionally debit only when sufficient funds exist.
- Database CHECK constraints prohibit negative balances and non-positive transaction amounts.
- An idempotency key per user prevents replayed submissions. Sender and recipient balance changes, transaction record, idempotency record and notifications are committed together.
- Test: attempt a zero, negative, over-limit, or >2-decimal amount; each must fail. Try sending more than the available balance; balances must remain unchanged. Submit the same form twice; only one transaction should be created. For concurrency, submit two transfers whose combined amount exceeds the balance and verify at most one succeeds.

## A07 — Identification and Authentication Failures
- Login errors are generic. Failed attempts are limited to five per normalized username over a rolling 15-minute window.
- Login rotates the session identifier and revokes previous active sessions for that account. Logout and password change revoke all server-side sessions for that user.
- Inactivity expires sessions after 30 minutes. Cookie flags are HttpOnly and SameSite=Lax.
- Test: submit six incorrect passwords and verify subsequent login attempts are blocked during the window. Sign in in two browsers; a later login revokes the earlier session. Logout/password change should invalidate sessions in other browsers.

## A08 — Software and Data Integrity Failures
- All state-changing routes use POST. A per-session CSRF token is checked before every POST request.
- Transfers use an idempotency key and atomic database transaction.
- Test: submit a POST without `_csrf`; expect HTTP 400. Confirm logout is POST-only and that GET requests cannot change account state.

## A09 — Security Logging and Monitoring Failures
- Login successes/failures, logout, password changes and transfers are logged without passwords, CSRF tokens, or session identifiers.
- Logs contain event type, username and limited non-secret context.
- Test: inspect console logs during login and transfer. Confirm no password, cookie, CSRF value or session ID appears.

## A10 — Mishandling of Exceptional Conditions
- Input errors return validation messages; unexpected transfer errors roll back the transaction and display a generic failure message.
- Generic 400/403/404/500 pages avoid exposing internal details.
- Test: submit malformed amounts, unknown recipient account numbers, invalid CSRF tokens and unknown URLs. Responses should be safe and balances must not partially change.

## Redirect safety
- Login's optional `next` value is accepted only when it is a local absolute path beginning with one slash; protocol-relative URLs and backslashes are rejected.
- Test: try `/login?next=https://example.com` and `/login?next=//example.com`; successful login should go to the dashboard.

## Additional deployment guidance
- Use HTTPS and set `DEMOBANK_COOKIE_SECURE=1` outside localhost.
- Use a production WSGI server and reverse proxy; never expose Flask's development server to the public internet.
- Keep the secret out of source control, rotate it if exposed, back up the database, and do not reuse demo credentials.
- This is an academic baseline. Before any production use, commission a professional security review and add stronger operational controls, monitoring, backups, recovery procedures, and deployment hardening.
