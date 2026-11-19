# Findings

This is the master table for the report. Raw tool output is in each version's folder. Research questions are defined in [`docs/SCOPE.md`](../docs/SCOPE.md).

> **Status:** the numbers below come from earlier runs on different machines and settings (see section 5). Their raw files are kept in `results/<version>/earlier/`. The final comparison re-runs every tool on all four versions with the same settings, and those results go directly in `results/<version>/`.

## 1. Tool results by version

| Tool | Baseline | Paid tier | Security-aware | Self-fixed |
|---|---|---|---|---|
| Semgrep | 1 (3 custom rules only) | | | 2 (registry rules, both false positives) |
| Bandit | 2 (B608, false positives) | | | 0 |
| pip-audit (`requirements.txt`) | 0 vulnerable / 7 packages | | | 0 / 7 |
| pytest (own tests) | 3 / 3 | 7 / 9 (2 failures are bugs in GPT-6's tests) | 3 / 3 after follow-up fix (unittest; 2 / 3 before, see section 7) | 8 / 8 |
| pytest (shared HTTP suite) | 19 / 19 | can't run unchanged (different routes) | | not run yet |
| OWASP ZAP | 0 High, 2 Medium, 2 Low, 3 Info | | | 0 High, 0 Medium, 1 Low, 3 Info |
| Burp Suite | Proxy history (see section 4) | | | Proxy history (see section 4) |
| Atheris | ⚠ not valid yet (section 6) | | | ⚠ not valid yet (section 6) |
| **Confirmed vulnerabilities** | **4** | | | **0 of the baseline's 4** |

### Notes on individual results

- **Baseline Bandit B608** (lines 228, 336): the f-string only inserts `?` placeholders (`",".join("?" for _ in ids)`). The values are still bound parameters, so these are false positives.
- **Self-fixed Semgrep `open-redirect`** (line 239): `next` is only followed if it starts with `/` and not `//`, so external URLs are rejected. The Burp test with `next=https://evil.com` was blocked. Likely a false positive.
- **Self-fixed Semgrep `avoid_hardcoded_config_TESTING`**: an audit-style rule about a config setting, not a vulnerability.
- **Self-fixed pip-audit:** Kanita and Hajra's `pip_audit.json` reports 17 vulnerabilities, but it scanned all 92 packages in their environment. Re-run against `requirements.txt` (`pip-audit-requirements.json`, 16 Nov): 0 vulnerabilities. Always audit `requirements.txt`.
- **Paid tier pytest:** `test_transfer_success_repeat_and_authorization` checks that "Lunch" is not on `/transactions?q=Lunch`, but the search box echoes the query back. `test_register_duplicate_and_new_user` reads `_csrf` from the session right after registration calls `session.clear()`.

## 2. Confirmed vulnerabilities

"Confirmed" means we exploited it, or traced it in the code with a clear impact.

| # | Vulnerability | CWE | OWASP 2025 | Found by | Base | Paid | Sec | Fixed |
|---|---|---|---|---|---|---|---|---|
| 1 | Hard-coded fallback `SECRET_KEY` allows session forgery and account takeover | CWE-321 / CWE-798 | A07, A02 | Manual review + PoC (missed by Bandit and Semgrep) | ✓ | | | ✗ |
| 2 | Debug mode on by default when started with `python app.py` | CWE-489 / CWE-215 | A02 | Manual review (missed by Bandit B201, which only matches literal `debug=True`) | ✓ | | | ✗ |
| 3 | No anti-clickjacking protection | CWE-1021 | A02 | ZAP | ✓ | | | ✗ |
| 4 | No Content Security Policy | CWE-693 | A02 | ZAP | ✓ | | | ✗ |

- **#1:** exploited end to end on the baseline (16 Nov 2026). The same exploit failed against the self-fixed version (16 Nov 2026), which uses a random key when none is set. See `exploit/session-forgery/`.
- **#2:** baseline line 474: `DEMOBANK_DEBUG` defaults to `"1"`. Self-fixed defaults to `"0"`.
- **#3, #4:** the self-fixed version sends `Content-Security-Policy` (including `frame-ancestors 'none'`) and `X-Frame-Options: DENY`. ZAP no longer reports them.
- You could count #3 and #4 as one "missing security headers" item. Decide once and use the same rule for every version.

## 3. RQ3: self-fix claims vs. re-test

ChatGPT's own claims are in `versions/self-fixed/docs/SECURITY_REMEDIATION.md`.

| Finding given to ChatGPT | Real? | ChatGPT's verdict | Fixed? | Notes |
|---|---|---|---|---|
| Bandit B608 ×2 | False positive | Said these alone don't prove SQL injection; rewrote the queries anyway | Removed | Bandit now 0 |
| Semgrep custom warning (same line) | False positive | Same as above | Removed | |
| ZAP: missing CSP | Real | Real | ✓ | ZAP no longer reports it |
| ZAP: missing anti-clickjacking | Real | Real | ✓ | ZAP no longer reports it |
| ZAP: X-Content-Type-Options | Real (minor) | Real | ✓ | ZAP no longer reports it |
| ZAP: server version leak | Real (minor) | Real, claims fixed | **Partly** | Fixed only when started with `run_local.py` (header becomes `Server: DemoBank`). With `flask run`, which is how ZAP scanned it, it still sends `Werkzeug/3.1.9 Python/…` |
| ZAP: potential XSS (info) | False positive | Said it's not a confirmed XSS | n/a | Correct call |
| Hard-coded secret key (not reported by any tool) | Real | Changed it without a tool reporting it | ✓ | Forgery exploit fails |
| Debug on by default (not reported by any tool) | Real | Changed it without a tool reporting it | ✓ | Defaults to off |

To add after the final re-test: anything the fix broke (shared HTTP suite, Burp cases), and any new issues.

## 4. Burp Suite

| Export | Version (how we know) | What it covers |
|---|---|---|
| `results/baseline/earlier/burp/burp-history.xml` (30 Oct, 26 requests) | Baseline: no response has a CSP header | Wrong password rejected; transfer above balance rejected; normal transfer works |
| `results/self-fixed/earlier/burp/burp-history.xml` (31 Oct, 14 requests) | Self-fixed: all 14 responses carry the new CSP header | Login, transfer works; open redirect to `https://evil.com` blocked |

Both are proxy histories, not attack runs. Most cases in `tests/burp/test-cases.md` still need to be run on every version.

## 5. Why the final runs must be redone on one setup

| Item | Baseline (Diana) | Self-fixed (Kanita & Hajra) | Paid tier (Noor) |
|---|---|---|---|
| Semgrep rules | 3 custom rules | Semgrep registry rules | not run yet |
| pip-audit target | `requirements.txt` | whole environment (92 packages) | not run yet |
| ZAP mode | CLI quick scan | ZAP desktop | not run yet |
| How the app was started | `flask run` | `flask run` (not `run_local.py`) | not run yet |

For the final runs, use `scripts/run_static_scans.sh`, the ZAP command in `results/README.md`, and the fuzzer in `tests/fuzzing/` on all four versions.

## 6. Atheris runs so far are not valid

Kanita's first fuzzer (`tests/fuzzing/first-attempt/`) never actually tested the app:

- `atheris.instrument_imports()` is called on its own instead of as `with atheris.instrument_imports():`, so nothing is instrumented. libFuzzer warns "no interesting inputs were found… Is the code instrumented for coverage?" and the corpus stays at 1 byte.
- `WTF_CSRF_ENABLED = False` does nothing because none of the apps use Flask-WTF. Every POST still fails the app's CSRF check before reaching any logic.
- The transfer request isn't logged in and uses `recipient_account`, but the field is `recipient`.
- `ValueError`, `KeyError` and `TypeError` are swallowed, and no property is checked.

Re-run with `tests/fuzzing/fuzz_transfer.py` on every version, using the same time limit. In the report this can be a short "lesson learned": a fuzzer that can't get past CSRF and login tests nothing.

## 7. Security-aware version: first checks (19 Nov 2026)

Generated by Hajra with free GPT-5.6 from the security-aware prompt (verified identical to `versions/security-aware/PROMPT.md`). None of its files match the baseline's, so it was built from scratch.

**Transfers do not work at all.** This is a functional bug, not something we caused:

- The `transactions` table declares `status TEXT NOT NULL CHECK(status IN ('completed'))`, but the transfer code inserts a row without `status`. Every transfer raises `IntegrityError` and is rolled back ("We could not complete the transfer. No funds were moved."). 0 of 40 test transfers through the real form succeeded.
- Separately, the form's `idempotency_key` is made with `secrets.token_urlsafe(18)`, which can contain `-` and `_`, but the server only accepts `[A-Za-z0-9]{8,40}`. About 6 in 10 form submissions would be rejected even if the insert worked.
- Its own tests show this: 2/3 pass, and `test_transfer_moves_virtual_funds` fails (balance unchanged). The tests also only run if `DEMOBANK_SECRET_KEY` is set.

For RQ2 this is a finding in itself: with the security requirements added, the free model's first output broke the core feature.

**After one error-only follow-up (19 Nov):** ChatGPT's fix for the missing `status` value was applied exactly as given (see `versions/security-aware/PROMPT.md`). Transfers now work: 27 of 40 test transfers succeeded. The other 13 were rejected by the idempotency-key bug above, which was not reported back, so it is left as is. Its own tests now pass 3/3.

**Security observations so far:**

| Check | Result |
|---|---|
| Secret key | Refuses to start without `DEMOBANK_SECRET_KEY`. Falls back to a fixed `"test-only-secret-not-for-deployment"` only when `TESTING` is on. Session-forgery exploit fails. |
| Debug mode | Refuses to start if debug is on |
| Security headers | CSP, `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy` all present |
| Server version | **Still leaks** `Werkzeug/3.1.9 Python/…`, although the prompt said "Do not reveal server or framework versions" |
| Dependencies | Pinned versions in `requirements.txt` (Flask 3.1.1, Werkzeug 3.1.3) |
| Login | Field names `_csrf`, `username`; demo password `DemoPass12345!` |
