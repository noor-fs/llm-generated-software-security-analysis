# Burp test cases: summary

Run 2026-11-19 23:11, through Burp proxy http://172.22.0.1:8080. Burp's HTTP history holds every request (port = version: 5001 baseline, 5003 paid-tier, 5000 security-aware, 5002 self-fixed).
Details per version: `results/<version>/burp-cases.md`.

| # | Case | baseline | paid-tier | security-aware | self-fixed |
|---|---|---|---|---|---|
| 1 | Access without login | Blocked | Blocked | Blocked | Blocked |
| 2 | CSRF token removed / wrong | Blocked | Blocked | Blocked | Blocked |
| 3 | SQL injection (login, transaction filters/search) | Blocked | Blocked | Blocked | Blocked |
| 4 | Stored XSS (description, profile name) | Blocked | Blocked | Blocked | Blocked |
| 5 | Negative / odd amounts | Blocked | Blocked | Blocked | Blocked |
| 6 | Transfer from / view another user's account (IDOR) | Blocked | Blocked | Blocked | Blocked |
| 7 | Replay (same idempotency key x3) | Blocked | Blocked | Blocked | Blocked |
| 8 | Session after password change | Vulnerable | Vulnerable | Blocked | Vulnerable |
| 9 | Session forgery (exploit script) | Vulnerable | Blocked | Blocked | Blocked |
| 10 | Open redirect after login | Blocked | Blocked | Blocked | Blocked |
| 11 | Brute force (30 wrong passwords) | Vulnerable (no rate limit) | Vulnerable (no rate limit) | Blocked (rate limit / lockout) | Vulnerable (no rate limit) |
| 12 | Security headers / cookie flags (logged in) | Vulnerable | Vulnerable | Blocked | Blocked |
