# Security comparison results template

Copy this file for each run. Do not compare raw alert counts without deduplicating and triaging findings.

| Field | V1 | V2 |
|---|---|---|
| Test date/time | | |
| Python version | | |
| Flask/Werkzeug versions | | |
| Bandit version + command | | |
| Semgrep version + config/rules | | |
| pip-audit version | | |
| ZAP version + policy | | |
| Burp Community version | | |
| pytest version | | |
| Database reset/seed state | | |
| Authenticated scan coverage | | |
| Routes actually tested | | |

## Finding triage

| ID | Tool | V1 finding / evidence | Confirmed? | V2 result | Fixed / remaining / new | Notes |
|---|---|---|---|---|---|---|
| | | | | | | |

## Manual test log

| Test | User/context | Request modified | Expected result | Observed result/status | State/data changed? | Pass/fail |
|---|---|---|---|---|---|---|
| Anonymous protected route | | | Redirect to login | | | |
| Cross-user transaction access | Alice | | No Bob-only data | | | |
| Negative/zero transfer | Alice | | Reject; no balance change | | | |
| Excessive precision / amount | Alice | | Reject; no balance change | | | |
| Invalid recipient / self-transfer | Alice | | Reject; no balance change | | | |
| Replay same idempotency key | Alice | | One transfer only | | | |
| Missing/invalid CSRF token | | | HTTP 400 | | | |
| XSS marker in profile/description | | | Render as text | | | |

## Metrics

Let `N_confirmed_V1` be the number of unique confirmed V1 vulnerabilities, `N_fixed` the subset verified fixed in V2, and `N_new` unique confirmed V2 findings not present in V1.

- Fix rate = `N_fixed / N_confirmed_V1 * 100%` (only when denominator > 0).
- Remaining V1 findings = `N_confirmed_V1 - N_fixed`.
- New findings = `N_new`.

Report false positives, informational observations, and untested areas separately. A finding disappearing from one scanner does not by itself prove the underlying issue is fixed; verify with a targeted test.
