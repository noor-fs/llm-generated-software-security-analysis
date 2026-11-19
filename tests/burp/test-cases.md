# Burp Suite test cases

The same 12 cases are run on every version by `run_burp_cases.py`, which sends every request **through Burp's proxy**, so Burp's HTTP history records all of them. The script also checks each result itself (for example, whether money actually moved).

## How to run

1. Run `scripts/run_all_tests.py` at least once first (the Burp script reuses its environments in `.testrun/`).
2. Open **Burp Suite Community** → **Proxy** → **Intercept is off**. Check the listener is `127.0.0.1:8080` (Proxy → Proxy settings).
3. From the repo root:
   ```bash
   python3 tests/burp/run_burp_cases.py
   ```
   It starts each version in turn (fresh database), runs the 12 cases, and stops it. About 2–3 minutes in total.
4. In Burp: **Proxy → HTTP history** → click in the list → **Ctrl+A** → right-click → **Save items** → save as `results/burp-history.xml`. The port shows which version each request belongs to: 5001 baseline, 5003 paid-tier, 5000 security-aware, 5002 self-fixed.
5. For the report and video, pick 2–3 requests (e.g. a transfer with the CSRF token removed, a `-500` amount), right-click → **Send to Repeater**, edit and resend them by hand, and take screenshots.

Results: `results/BURP_SUMMARY.md` (all versions) and `results/<version>/burp-cases.md` (details).

## The 12 cases

| # | Test case | How | Baseline | Paid | Sec-aware | Self-fixed |
|---|---|---|---|---|---|---|
| 1 | Access without login | Log out, then request `/dashboard`, `/account`, `/transactions`, `/profile` directly | | | | |
| 2 | CSRF removal | In Repeater, delete or change `csrf_token` on the transfer and change-password POSTs | | | | |
| 3 | SQL injection | Put `' OR 1=1--` and `"; DROP TABLE users;--` in login, search and description fields | | | | |
| 4 | Stored XSS | Put `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>` in the transfer description and profile name, then view them | | | | |
| 5 | Negative / odd amounts | Send `amount=-500`, `0`, `0.001`, `1e3`, `99999999` | | | | |
| 6 | Transfer from someone else | Change `recipient` to your own account, add `sender=`/`user_id=` parameters, change account numbers | | | | |
| 7 | Replay | Resend a successful transfer unchanged, then with a different amount but the same `idempotency_key` | | | | |
| 8 | Session after password change | Log in on two browsers, change the password in one, replay a request from the other | | | | |
| 9 | Session forgery | Run `exploit/session-forgery/forge_session.py` | V | | | B |
| 10 | Open redirect | Log in via `/login?next=/\evil.com` and `/login?next=https://evil.com` | | | | B (https://evil.com) |
| 11 | Brute force | Send 50 wrong passwords for `alice` with Intruder (Community is throttled, that's fine) | | | | |
| 12 | Security headers / cookies | Check responses for `Content-Security-Policy`, `X-Frame-Options`, and cookie `HttpOnly`/`SameSite` flags | | | | |

Burp Suite **Community** has no automated vulnerability scanner. The cases are scripted and sent through Burp's proxy, with selected requests replayed manually in Repeater. Say so in the report.
