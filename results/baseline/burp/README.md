# Burp Suite: baseline

`burp-history.xml` is a Burp Suite Community 2026.10.1 Proxy history export by Kanita Ansari (30 Oct 2026, 26 requests to `127.0.0.1:5001`). It is a record of traffic, not a scanner report.

| Test | Request | Result |
|---|---|---|
| Wrong password | `POST /login`, `password=Demo123` | 200, stayed on login page (rejected) |
| Correct login | `POST /login`, alice / DemoPass123! | 302 → `/dashboard` |
| Transfer more than the balance | `POST /transfer`, `amount=1000000` | 302 back to `/transfer` (rejected) |
| Normal transfer | `POST /transfer`, `amount=100` | 302 → `/transactions` (succeeded) |
| Browsing | dashboard, transactions, notifications | 200 |

A second Kanita export (31 Oct, 14 requests, same port) also tried an **open redirect**: `POST /login?next=https://evil.com` → 302 to `/dashboard`, so it was **blocked**.

Most cases in `tests/burp/test-cases.md` (CSRF removal, SQLi/XSS payloads, negative amounts, IDOR, replay, brute force) are **not** in these exports yet.
