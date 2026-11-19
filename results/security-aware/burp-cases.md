# Burp test cases: security-aware

Run 2026-11-19 23:11, http://127.0.0.1:5000, through Burp proxy http://172.22.0.1:8080.

| # | Case | Result | Details |
|---|---|---|---|
| 1 | Access without login | Blocked | all private pages redirect or refuse: /dashboard 302, /account 302, /transactions 302, /transfer 302, /profile 302, /settings 302, /notifications 302, /change-password 302 |
| 2 | CSRF token removed / wrong | Blocked | no token -> HTTP 400, wrong token -> HTTP 400; money moved: none |
| 3 | SQL injection (login, transaction filters/search) | Blocked | login with "' OR '1'='1' --" -> rejected; filters/search -> HTTP 200 |
| 4 | Stored XSS (description, profile name) | Blocked | payloads stored but shown escaped (profile update HTTP 302) |
| 5 | Negative / odd amounts | Blocked | -500: rejected; 0: rejected; 0.001: rejected; 1e3: moved {'DBALICE000001': -100000, 'DBBOB00000002': 100000}; NaN: rejected; Infinity: rejected; 99999999: rejected; 1,000: rejected |
| 6 | Transfer from / view another user's account (IDOR) | Blocked | tampered sender fields -> money moved: none; victim data via URL params: no |
| 7 | Replay (same idempotency key x3) | Blocked | 3 submissions with one key -> QAR 1 left the sender (1 expected if only the first counted) |
| 8 | Session after password change | Blocked | only one session allowed: logging in again already ended the older session (/dashboard HTTP 302); password changed: True |
| 9 | Session forgery (exploit script) | Blocked | [-] Not logged in (HTTP 302). Is the app using a different SECRET_KEY? |
| 10 | Open redirect after login | Blocked | stayed on the site: https://evil.example/ -> /dashboard; //evil.example/ -> /dashboard; /\evil.example/ -> /dashboard |
| 11 | Brute force (30 wrong passwords) | Blocked (rate limit / lockout) | wrong-password responses: [401]; limit message seen: False; correct password afterwards: refused |
| 12 | Security headers / cookie flags (logged in) | Blocked | missing: none; Server: Werkzeug/3.1.3 Python/3.12.3; Set-Cookie flags: Expires=Thu, 19 Nov 2026 20:41:17 GMT; HttpOnly; Path=/; SameSite=Lax |
