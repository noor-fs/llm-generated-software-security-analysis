# Burp Suite test cases

The same 12 cases are run on every version by `run_burp_cases.py`, which sends every request **through Burp's proxy**, so Burp's HTTP history records all of them. The script also checks each result itself (for example, whether money actually moved).

## How to run

1. Run `scripts/run_all_tests.py` at least once first (the Burp script reuses its environments in `.testrun/`).
2. Open **Burp Suite Community** → **Proxy** → **Intercept is off**. Check the listener is `127.0.0.1:8080` (Proxy → Proxy settings). If Burp runs on Windows and the script in WSL, see the note at the end.
3. From the repo root:
   ```bash
   python3 tests/burp/run_burp_cases.py
   ```
   It starts each version in turn (fresh database), runs the 12 cases, and stops it. About 2–3 minutes in total.
4. In Burp: **Proxy → HTTP history** → click in the list → **Ctrl+A** → right-click → **Save items** → save as `results/burp-history.xml`. The port shows which version each request belongs to: 5001 baseline, 5003 paid-tier, 5000 security-aware, 5002 self-fixed.
5. For the report and video, pick 2–3 requests (e.g. a transfer with the CSRF token removed, a `-500` amount), right-click → **Send to Repeater**, edit and resend them by hand, and take screenshots.

Results: `results/BURP_SUMMARY.md` (all versions) and `results/<version>/burp-cases.md` (details).

## The 12 cases

Results from the final Burp run (19 Nov 2026, commit `6e0453c`). B = blocked, **V** = vulnerable. Details behind every result are in `results/<version>/burp-cases.md`.

| # | Test case | How the script tests it | Baseline | Paid | Sec-aware | Self-fixed |
|---|---|---|---|---|---|---|
| 1 | Access without login | Request `/dashboard`, the account page, `/transactions`, `/transfer`, `/profile`, `/settings`, `/notifications`, `/change-password` without logging in | B | B | B | B |
| 2 | CSRF removal | Send the transfer POST with `csrf_token` removed, then with a wrong value | B | B | B | B |
| 3 | SQL injection | `' OR '1'='1' --` in the login form, plus injection strings in the transaction filters and search | B | B | B | B |
| 4 | Stored XSS | `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>` in the transfer description and profile name, then view the pages | B | B | B | B |
| 5 | Negative / odd amounts | `amount=-500`, `0`, `0.001`, `1e3`, `NaN`, `Infinity`, `99999999`, `1,000` | B | B | B | B |
| 6 | Transfer from / view someone else's account (IDOR) | Transfer to yourself with extra `sender` / `from_account` / `account_id` / `user_id` fields set to the victim, and request the account and transactions pages with the victim's id or account number in the URL | B | B | B | B |
| 7 | Replay | Submit a QAR 1 transfer, resend it with the same `idempotency_key`, then send QAR 2 with that key again | B | B | B | B |
| 8 | Session after password change | Log in twice, change the password in one session, then use the other session | **V** | **V** | B | **V** |
| 9 | Session forgery | Run `exploit/session-forgery/forge_session.py` through the proxy | **V** | B | B | B |
| 10 | Open redirect | Log in via `/login?next=https://evil.example/`, `//evil.example/` and `/\evil.example/` | B | B | B | B |
| 11 | Brute force | 30 wrong passwords for the first demo user, then the correct one | **V** | **V** | B | **V** |
| 12 | Security headers / cookies | Check a logged-in page for `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and the cookie's `HttpOnly`/`SameSite` flags | **V** | **V** | B | B |

Two requests were then replayed by hand in Repeater: a transfer with the CSRF token removed (`results/burp-screenshots/csrf-removed.png`) and `amount=-500` (`negative-amount.png`). The classification of each result (confirmed or not a vulnerability) is in `results/findings.md` sections 2 and 7.

Burp Suite **Community** has no automated vulnerability scanner. The cases are scripted and sent through Burp's proxy, with selected requests replayed manually in Repeater. Say so in the report.

**Burp on Windows, script in WSL:** set Burp's listener to all interfaces and run the script with `--proxy http://$(ip route show default | awk '{print $3}'):8080`. This is how the final run was done; see `docs/TESTING_RUNBOOK.md` section 7.
