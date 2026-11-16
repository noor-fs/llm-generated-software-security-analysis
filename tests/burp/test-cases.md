# Burp Suite manual test cases

Run every case on every version using Proxy → HTTP history and Repeater. Save the request and response (right-click → Save item) as `results/<version>/burp/<case>.txt` and add a screenshot for anything that works.

Result key: **V** = vulnerable (attack worked), **B** = blocked, **N/A** = feature doesn't exist in that version.

| # | Test case | How | Baseline | Self-fixed | Paid | Sec-aware |
|---|---|---|---|---|---|---|
| 1 | Access without login | Log out, then request `/dashboard`, `/account`, `/transactions`, `/profile` directly | | | | |
| 2 | CSRF removal | In Repeater, delete or change `csrf_token` on the transfer and change-password POSTs | | | | |
| 3 | SQL injection | Put `' OR 1=1--` and `"; DROP TABLE users;--` in login, search and description fields | | | | |
| 4 | Stored XSS | Put `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>` in the transfer description and profile name, then view them | | | | |
| 5 | Negative / odd amounts | Send `amount=-500`, `0`, `0.001`, `1e3`, `99999999` | | | | |
| 6 | Transfer from someone else | Change `recipient` to your own account, add `sender=`/`user_id=` parameters, change account numbers | | | | |
| 7 | Replay | Resend a successful transfer unchanged, then with a different amount but the same `idempotency_key` | | | | |
| 8 | Session after password change | Log in on two browsers, change the password in one, replay a request from the other | | | | |
| 9 | Session forgery | Run `exploit/session-forgery/forge_session.py` | V | | | |
| 10 | Open redirect | Log in via `/login?next=/\evil.com` and `/login?next=https://evil.com` | B (https://evil.com) | | | |
| 11 | Brute force | Send 50 wrong passwords for `alice` with Intruder (Community is throttled, that's fine) | | | | |
| 12 | Security headers / cookies | Check responses for `Content-Security-Policy`, `X-Frame-Options`, and cookie `HttpOnly`/`SameSite` flags | | | | |

Burp Suite **Community** has no automated vulnerability scanner, so these are manual tests. Say so in the report.
