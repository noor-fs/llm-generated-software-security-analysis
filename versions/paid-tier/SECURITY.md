# DemoBank security design and test notes

DemoBank is **an academic simulation** and not an audited financial service. Its controls provide a useful security-oriented implementation for comparison but do not establish production readiness.

## Implemented controls

1. **Password hashing:** Werkzeug password hashing and verification, not plaintext password storage. Login failure uses one generic message.
2. **Input validation:** server-side username, email, password, display name, monetary decimal and description validation; HTML limits are only extra UI help.
3. **SQL injection resistance:** all dynamic data in SQLite queries is passed as bound parameters, never interpolated into SQL strings.
4. **CSRF checks:** every POST requires a cryptographically random session-bound hidden token; invalid/missing tokens return HTTP 403. Logout is POST-only.
5. **Session and authorization:** logged-in user ID is loaded server-side on each request. All sensitive routes require login. Transaction lists are restricted by that user's account ownership, rather than an untrusted account-ID URL.
6. **XSS defenses:** Jinja HTML auto-escaping is enabled for app templates. User text is displayed with auto-escaping. Content is not inserted via `innerHTML`.
7. **Money and concurrency:** amount parsing uses decimal input and integer minor units, with strict positivity, 2-decimal precision and an upper limit. `BEGIN IMMEDIATE` serializes SQLite writers; debit uses a conditional update; debit, credit, history and success notifications commit atomically. Balance cannot be negative by schema CHECK.
8. **Duplicate submission:** the transfer form includes a random idempotency key. A unique database constraint on `(sender_account_id, idempotency_key)` and transaction-level duplicate detection prevent double debit after resubmission.
9. **Referential integrity:** SQLite foreign keys enabled for each connection, indexed transaction lookups and database-level CHECK/UNIQUE constraints.
10. **Cookie settings:** HTTP-only, SameSite=Lax, optional Secure cookie flag with `DEMOBANK_SECURE_COOKIES=1` for HTTPS environments. Flask session signatures are keyed using a random secret per process unless the operator explicitly configures one.
11. **Limited request size:** application rejects oversized bodies above 1 MiB.
12. **No external financial integration:** only local virtual credits and local assets.

## Manual test plan

- Register a new account and verify that username/email duplicates are rejected (including case differences); attempt invalid input.
- Sign in/out and verify dashboard, profile, transaction and transfer URLs redirect for unauthenticated users.
- Submit a POST to `/transfer` without `_csrf`: expect 403.
- Try negative amounts, decimals with more than two places, zero, more than the maximum, unknown recipient, self-transfer, insufficient funds; verify no balance changes.
- Transfer 10.25 from seeded `alex` to `jordan`; verify exactly 1025 minor units move, history shows a corresponding entry for both, and notifications appear.
- Re-post the identical transfer body with the identical idempotency key: verify no second debit or extra transfer row.
- Simultaneously submit competing transfers from one account; verify aggregate debits never exceed the balance.
- Log in as a third user and verify that unrelated parties' transactions are not visible; use search and date filters.
- Submit descriptions containing HTML tags and confirm they render as text, not executable markup.
- Change password, log out, and confirm that the old password no longer works.
- Visit an invalid URL and confirm custom 404. Invalid CSRF shows 403.

## Important limitations / further hardening

- No per-user rate limits or login brute-force throttling. Add rate limiting and audit logging for a public deployment.
- No password reset, MFA, session revocation across devices, email validation/verification or device/session management.
- No independent security review, penetration testing, threat monitoring or comprehensive browser-based E2E suite.
- Uses Flask's signed **client-side** session cookies. They are tamper-resistant with a strong secret key, but session invalidation and server-side audit controls are limited. A password change does not terminate other active sessions.
- CSRF token is validated on POST requests; GET must remain read-only. Browser-dependent security headers such as CSP, HSTS and a robust HTTP deployment/proxy configuration would be necessary for public hosting.
- SQLite is suitable for local classroom testing; multi-instance deployment and high transaction volumes warrant a more appropriate database and deployment design.
- The example demo password is public and must never be used with real credentials or internet-facing deployments.
- Seed-generated funds are fixtures, not a customer-facing deposit mechanism. Users registered with zero VC need transfers from seeded accounts for a funded experience.
- Database reset is an explicitly destructive development command, not a migration mechanism; schema migrations and backups are not included.

## Academic comparison

Treat this as an explicitly **security-conscious implementation**, rather than an intentionally insecure baseline. For a controlled experiment, capture the prompt, model version, generated source, dependency versions and identical test cases. Do not assume that a security-oriented prompt produces vulnerability-free code; compare actual test outcomes.
