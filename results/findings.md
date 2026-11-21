# Findings

The master results for the report. Research questions are defined in [`docs/SCOPE.md`](../docs/SCOPE.md).

**Source:** the final standardized run (commit `8ab63fc`, 19 Nov 2026), with all seven automated steps on all four versions, run by Noor on one machine (Ubuntu 24.04 under WSL 2 on Windows 11, Python 3.12.3, ZAP 2.17.0), with identical settings. How it was set up and run, step by step: `docs/TESTING_RUNBOOK.md` section 7. Raw output is in `results/<version>/` and the raw count table is in [`RUN_SUMMARY.md`](RUN_SUMMARY.md). Earlier, non-standardized runs are kept in `results/<version>/earlier/` and are **not** used for the comparison.

**Burp:** the 12 manual-attack cases (`tests/burp/test-cases.md`) were run on all four versions through Burp Suite Community 2026.11.2 (commit `6e0453c`, 19 Nov 2026). Summary in [`BURP_SUMMARY.md`](BURP_SUMMARY.md), Burp's full HTTP history (649 requests) in `burp-history.xml`, and Repeater screenshots in `burp-screenshots/`.

## 1. Raw tool results (final run)

| Tool | Baseline (free) | Paid tier | Security-aware | Self-fixed |
|---|---|---|---|---|
| Semgrep (228 rules) | 1 | 0 | 0 | 0 |
| Bandit | 2 (Medium) | 0 | 2 (1 Low, 1 Medium) | 0 |
| pip-audit | 0 / 7 packages | 0 / 11 | 9 entries, 5 distinct IDs / 7 | 0 / 7 |
| Own tests | 3 / 3 | 7 / 9 | 3 / 3 | 8 / 8 |
| Shared HTTP tests (19) | 19 / 19 | n/a (different routes) | n/a (different field names) | 19 / 19 |
| Session-forgery exploit | **Exploited** (QAR 500 moved from bob without his password) | Blocked | Blocked | Blocked |
| ZAP (High / Medium / Low / Info) | 0 / 2 / 2 / 3 | 0 / 2 / 2 / 2 | 0 / 0 / 1 / 3 | 0 / 0 / 0 / 3 |
| Atheris (30 min) | 265,657 runs, no failures | 163,573 runs, no failures | 284,240 runs, no failures | 262,852 runs, no failures |
| Burp: 12 cases, number vulnerable | 4 (cases 8, 9, 11, 12) | 3 (cases 8, 11, 12) | 0 | 2 (cases 8, 11) |

## 2. Every finding, checked

**Confirmed** = we exploited it, or confirmed it in the code with a clear impact. **False positive** = checked, and not a real security problem.

| Version | Tool | Finding | Verdict | Why |
|---|---|---|---|---|
| Baseline | Bandit B608 ×2 (app.py 228, 336) | SQL built from a string | False positive | Only `?` placeholders are inserted (`",".join("?" for _ in ids)`); all values are still bound parameters |
| Baseline | Semgrep `demobank-sql-fstring` (app.py 228) | Same line as above | False positive | Same reason (this is our own custom rule) |
| Baseline | ZAP Medium | CSP header not set | **Confirmed** (V3) | No header in any response |
| Baseline | ZAP Medium | Missing anti-clickjacking header | **Confirmed** (V4) | Pages can be framed by another site |
| Baseline | ZAP Low | Server version disclosed | **Confirmed** (V5) | `Server: Werkzeug/3.1.9 Python/3.12.3` |
| Baseline | ZAP Low | X-Content-Type-Options missing | **Confirmed** (V6) | No `nosniff` header |
| Baseline | Manual + exploit | Hard-coded fallback secret key | **Confirmed** (V1) | Exploited: forged bob's session and moved QAR 500. **Missed by Semgrep and Bandit** |
| Baseline | Manual (code) | Debug on by default with `python app.py` | **Confirmed** (V2) | `DEMOBANK_DEBUG` defaults to `"1"` (app.py 474). Not active when started as the README says (`flask run`). **Missed by Bandit** (B201 only matches literal `debug=True`) |
| Paid tier | ZAP Medium ×2, Low ×2 | Same four header alerts as baseline | **Confirmed** (V3–V6) | No security-header code anywhere in the app |
| Security-aware | Bandit B608 (app.py 265) | SQL built from a string | False positive | Joined clauses are fixed strings; user values go in `params` |
| Security-aware | Bandit B105 (app.py 24) | Hard-coded password string | False positive (not reachable) | `"test-only-secret-not-for-deployment"` is only used when `TESTING` is on. `TESTING = False` in config and only unit tests change it. It is a small lapse against the prompt's "never fall back to a default value" |
| Security-aware | pip-audit | Flask 3.1.1: PYSEC-2026-2151 (fix 3.1.3) | **Confirmed** (V7) | Missing `Vary: Cookie` when the session is accessed; matters behind a caching proxy. Low locally |
| Security-aware | pip-audit | Werkzeug 3.1.3: PYSEC-2026-2044, -2046, -2320, -4312 (fixes 3.1.4–3.1.9) | **Confirmed** (V7) | `safe_join` and Windows device names; exploitable on Windows only. Low on Ubuntu. Cause: the model pinned old versions |
| Security-aware | ZAP Low | Server version disclosed | **Confirmed** (V5) | The prompt explicitly said "Do not reveal server or framework versions" |
| Baseline, paid, self-fixed | Burp case 11 | 30 wrong passwords, then the right one still works | **Confirmed** (V8) | Every wrong attempt got a normal 200 page; no lockout, delay or limit |
| Baseline, paid, self-fixed | Burp case 8 | Old session still works after a password change | **Confirmed** (V9) | A second browser stayed logged in (`/dashboard` 200) after the password was changed in the first |
| Baseline | Burp case 9 | Session forgery through Burp | **Confirmed** (V1) | Same as the exploit: QAR 5 moved from bob's account |
| Baseline, paid | Burp case 12 | Logged-in pages lack CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy | **Confirmed** (V3, V4, V6) | Same as ZAP, now on logged-in pages too. All versions set `HttpOnly` and `SameSite=Lax` on the session cookie |
| Baseline, sec-aware, self-fixed | Burp case 5 | `amount=1e3` accepted as QAR 1,000 | Not a vulnerability | Scientific notation is parsed as a number; exactly that amount moves and nothing is created. Input-validation quirk only. Paid rejects it |
| All | Burp cases 1–7, 10 | No login, CSRF removal, SQL injection, stored XSS, odd amounts, IDOR, replay, open redirect | Blocked everywhere | Paid answers missing/wrong CSRF with 403; the others with 400 |
| All | ZAP Info | User Controllable HTML Element Attribute (Potential XSS) | False positive | Reflected values (CSRF token, search box) are HTML-escaped by Jinja |
| All | ZAP Info | Authentication request / session management identified; User Agent Fuzzer | Not a vulnerability | Informational only |

## 3. Confirmed vulnerabilities by version

| # | Vulnerability | CWE | OWASP 2025 | Severity | Baseline | Paid | Sec-aware | Self-fixed |
|---|---|---|---|---|---|---|---|---|
| V1 | Hard-coded fallback secret key → session forgery, account takeover | CWE-321, CWE-798 | A04, A07 | High | ✓ | ✗ | ✗ | ✗ |
| V2 | Debug mode on by default (`python app.py`) | CWE-489 | A02 | Medium | ✓ | ✗ | ✗ | ✗ |
| V3 | No Content Security Policy | CWE-693 | A02 | Medium | ✓ | ✓ | ✗ | ✗ |
| V4 | No anti-clickjacking protection | CWE-1021 | A02 | Medium | ✓ | ✓ | ✗ | ✗ |
| V5 | Server and framework version disclosed | CWE-497 | A02 | Low | ✓ | ✓ | ✓ | ✗ |
| V6 | No X-Content-Type-Options | CWE-693 | A02 | Low | ✓ | ✓ | ✗ | ✗ |
| V7 | Known-vulnerable pinned dependencies | CWE-1395 | A03 | Low | ✗ | ✗ | ✓ | ✗ |
| V8 | No login rate limiting or lockout (unlimited password guessing) | CWE-307 | A07 | Medium | ✓ | ✓ | ✗ | ✓ |
| V9 | Sessions not ended after a password change | CWE-613 | A07 | Low | ✓ | ✓ | ✗ | ✓ |
| | **Total** | | | | **8** (1 High, 4 Medium, 3 Low) | **6** (3 Medium, 3 Low) | **2** (2 Low) | **2** (1 Medium, 1 Low) |

Severity: ZAP's risk level for the header findings; our judgement for the others. V1–V7 come from the automated run (plus manual review and the exploit); V8–V9 come from the Burp cases. V3 and V4 could be counted as one "missing security headers" item; the comparison doesn't change.

## 4. Results per research question

**RQ1, free vs. paid (same prompt).** Paid had 6 confirmed vulnerabilities against the baseline's 8, and none rated High. It avoided both code-level flaws (the hard-coded secret key and debug default). But everything else is **identical** to the free model's: no CSP, no clickjacking protection, version disclosure, no `nosniff`, unlimited password guessing, and sessions that survive a password change. The prompt asked both models to choose appropriate security practices; neither added security headers or login limits.

**RQ2, security-aware prompt (same free model).** 2 confirmed vulnerabilities against the baseline's 8, both Low. It is the **only** version that locks accounts after repeated wrong passwords and ends other sessions on a password change. Both were explicit requirements in the prompt, and it passed all 12 Burp cases. But the model **broke two explicit requirements**: it still discloses the server version, and pinning versions ("pin their versions") produced old Flask and Werkzeug releases with known vulnerabilities, which the unpinned versions avoided. Its first output also had a broken transfer feature, fixed after one error-only follow-up (see section 6).

**RQ3, self-fix (free model given baseline code + tool results).** 2 confirmed vulnerabilities, down from the baseline's 8. It fixed all 6 baseline issues found by the automated run, including two that **no tool had reported** (secret key, debug default). But it did **not** fix the two found later by Burp (unlimited password guessing, sessions surviving a password change). The material it was given never tested for these. So self-fixing covered what it was shown plus some obvious extras, not weaknesses outside the evidence. No regressions: all 19 shared HTTP tests and its own 8 tests pass. Its claim to hide the server version holds only when started with its `run_local.py`, as its README says; with `flask run` the version still shows (earlier ZAP run).

**Across all versions:** Semgrep (228 rules) and Bandit found no confirmed vulnerability in any version; all 5 of their findings (Bandit 4, Semgrep 1) were false positives. The only High finding (V1) was found by manual review and proven by our exploit, and two of the nine (V8, V9) were only found by the manual Burp cases, not by any automated tool. All four versions blocked the classic attacks: SQL injection, stored XSS, CSRF removal, IDOR, replay, odd amounts and open redirect. Atheris found no balance or money-creation bugs in any version's transfer logic. Coverage stopped growing within seconds (the same as in the 30-second dry run), so it explored everything the transfer endpoint does early on.

## 5. RQ3: self-fix claims vs. re-test

ChatGPT's own claims are in `versions/self-fixed/docs/SECURITY_REMEDIATION.md`.

| Finding given to ChatGPT | Real? | ChatGPT's verdict | Fixed? | Final run |
|---|---|---|---|---|
| Bandit B608 ×2 | False positive | Said these alone don't prove SQL injection; rewrote the queries anyway | Removed | Bandit 0 |
| Semgrep custom warning (same line) | False positive | Same | Removed | Semgrep 0 |
| ZAP: missing CSP | Real | Real | ✓ | No alert |
| ZAP: missing anti-clickjacking | Real | Real | ✓ | No alert |
| ZAP: X-Content-Type-Options | Real (Low) | Real | ✓ | No alert |
| ZAP: server version leak | Real (Low) | Real, claims fixed | ✓ with `run_local.py` only | No alert when started per its README; still leaks with `flask run` |
| ZAP: potential XSS (info) | False positive | Said it's not a confirmed XSS | n/a | Correct call |
| Hard-coded secret key (no tool reported it) | Real | Changed it anyway | ✓ | Exploit blocked |
| Debug on by default (no tool reported it) | Real | Changed it anyway | ✓ | Defaults to off |
| Unlimited password guessing (never given to it: found later by Burp) | Real | Not addressed | ✗ | Burp case 11: still vulnerable |
| Sessions survive a password change (never given to it) | Real | Not addressed | ✗ | Burp case 8: still vulnerable |
| Regressions | | | None | Shared HTTP 19/19, own tests 8/8 |

## 6. Functional bugs (not security, but relevant)

| Version | Bug | Effect |
|---|---|---|
| Paid tier | Two of its own tests are wrong: one searches for "Lunch" and then asserts "Lunch" is absent (the search box echoes it); one reads `_csrf` right after `session.clear()` | 7/9 own tests; the app itself works |
| Security-aware (first output) | Transfer `INSERT` omitted the required `status` value | Every transfer failed. Fixed after one error-only follow-up (`versions/security-aware/PROMPT.md`); original in commit `c09cf78` |
| Security-aware | Form idempotency key from `secrets.token_urlsafe()` can contain `-`/`_`, which the server rejects | About 1 in 3 transfers through the form fail |
| Security-aware | Date-filter regex written as `r"\\d{4}-..."` (double-escaped inside a raw string) | Filtering transactions by date never matches |

## 7. Burp Suite

The same 12 cases on every version, sent through Burp's proxy by `tests/burp/run_burp_cases.py`, which also checks each result (e.g. whether money actually moved). Two cases were then replayed by hand in Repeater (screenshots).

| # | Case | Baseline | Paid | Sec-aware | Self-fixed |
|---|---|---|---|---|---|
| 1 | Access without login | Blocked | Blocked | Blocked | Blocked |
| 2 | CSRF token removed / wrong | Blocked | Blocked | Blocked | Blocked |
| 3 | SQL injection | Blocked | Blocked | Blocked | Blocked |
| 4 | Stored XSS | Blocked | Blocked | Blocked | Blocked |
| 5 | Negative / odd amounts | Blocked | Blocked | Blocked | Blocked |
| 6 | IDOR | Blocked | Blocked | Blocked | Blocked |
| 7 | Replay | Blocked | Blocked | Blocked | Blocked |
| 8 | Session after password change | **Vulnerable** | **Vulnerable** | Blocked | **Vulnerable** |
| 9 | Session forgery | **Vulnerable** | Blocked | Blocked | Blocked |
| 10 | Open redirect | Blocked | Blocked | Blocked | Blocked |
| 11 | Brute force (30 wrong passwords) | **Vulnerable** | **Vulnerable** | Blocked (locked after 5) | **Vulnerable** |
| 12 | Security headers (logged in) | **Vulnerable** | **Vulnerable** | Blocked | Blocked |

**Evidence:** `burp-history.xml` (649 requests: about 160 per version, by port 5001 baseline, 5003 paid, 5000 security-aware, 5002 self-fixed, plus the manual Repeater requests). `burp-screenshots/negative-amount.png` shows `amount=-500` rejected with "Enter a valid positive amount…". `burp-screenshots/csrf-removed.png` shows a transfer without its CSRF token rejected with 400 Bad Request.

**Notes:**
- Security-aware case 8 passes for a stricter reason: it allows one session per user, so logging in again already ended the older session.
- Security-aware rejected `1e3` in one earlier dry run but accepted it in the final run. The difference is its idempotency-key bug (section 6), which randomly rejects about 1 in 3 transfers, not stricter validation.
- The earlier proxy histories (`results/baseline/earlier/burp/`, `results/self-fixed/earlier/burp/`) were browsing only and are not used.

## 8. Notes on the method

- **Earlier results** used different settings per version (Semgrep rules, pip-audit target, ZAP mode, start method), so they are kept for reference only. See the testing plan.
- **Kanita's first Atheris attempt** (`tests/fuzzing/first-attempt/`) never reached the app: no instrumentation (missing `with`), every request blocked at CSRF, the transfer test not logged in and using the wrong field name. It's a lesson learned, not a result.
- **Semgrep "errors"** (8–10 per version) are `PartialParsing` warnings on Jinja HTML templates. Python code was scanned fully, but the templates, where XSS would sit, were only partly checked. State this as a limitation.
- **ZAP** scanned without logging in, so only public pages and redirects were covered.
- **Security-aware's `atheris.log`** is ~34,600 lines because the app logs every rejected transfer (`security_event=transfer_failed`). No errors.
