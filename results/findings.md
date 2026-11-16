# Findings

This is the master table for the report (Tables 5 and 6). Raw tool output is in each version's folder.

## 1. Tool results by version

| Tool | Baseline | Self-fixed | Paid tier | Sec-aware | Notes |
|---|---|---|---|---|---|
| Semgrep | 1 (3 custom rules) | | | 1 (registry rules, false positive) | ⚠ The run in Diana's package used only the 3 custom rules in `config/semgrep-custom.yml` and logged 0 errors. Diana did a separate run that showed errors (in her video). Get that output, then re-run all versions with `scripts/run_static_scans.sh` (adds p/python, p/flask, p/owasp-top-ten) |
| Bandit | 2 (B608, medium) | | | 2 (B608, false positives) | Baseline: both are false positives (see below) |
| pip-audit | 0 vulnerable / 7 packages | | | 0 / 7 | Flask 3.1.3, Werkzeug 3.1.9, Jinja2 3.1.6 |
| pytest (own tests) | 3 / 3 passed | | | 10 / 10 (unittest) | Not comparable across versions |
| pytest (shared HTTP suite) | 19 / 19 | | | | `tests/shared-http`, comparable across versions |
| OWASP ZAP | 0 High, 2 Medium, 2 Low, 3 Info | | | 0 High, 0 Medium, 1 Low, 3 Info | Unauthenticated spider + active scan, ZAP 2.17.0, 17 Oct 2026 (details below) |
| Burp Suite | _Kanita's results_ | | | Not used: 8 manual tests via ZAP Requester, all pass | `tests/burp/test-cases.md` |
| Atheris | _Kanita's / Diana's results_ | | | _not run_ | |
| **Confirmed vulnerabilities** | **4** | | | | |

### Bandit B608 in the baseline: false positive

Lines 228 and 336 build SQL with an f-string, but the only thing inserted is a list of `?` placeholders (`",".join("?" for _ in ids)`). The values are still bound parameters, so this is not SQL injection. Record it as a false positive. It's a good example of why tool counts and confirmed vulnerabilities are counted separately.

### OWASP ZAP on the baseline (`results/baseline/zap/`)

| Alert | Risk | Real? |
|---|---|---|
| Content Security Policy (CSP) header not set | Medium | Yes: no defence-in-depth against XSS |
| Missing anti-clickjacking header (X-Frame-Options / frame-ancestors) | Medium | Yes: the transfer page can be framed by another site |
| Server leaks version (`Werkzeug/3.1.9 Python/3.12.3`) | Low | Yes, minor. Also shows it's running on the Flask development server |
| X-Content-Type-Options header missing | Low | Yes, minor |
| Authentication request identified | Info | Not a vulnerability |
| Session management response identified | Info | Not a vulnerability |
| User-controllable HTML attribute (potential XSS) | Info | False positive: the "user input" is the CSRF token being written back into its own hidden field |

**Coverage limit:** the scan was unauthenticated, so it only reached the 12 public endpoints (`/`, `/about`, `/login`, `/register`, static files). The dashboard, transfer, transactions and profile pages were not scanned. ZAP finding no SQL injection or XSS says nothing about those pages. State this in the report, or re-run with an authenticated context.

## 2. Confirmed vulnerabilities

"Confirmed" means we reproduced it or traced it in the code with a clear impact.

| # | Vulnerability | CWE | OWASP 2025 | Found by | Base | Fixed | Paid | Sec |
|---|---|---|---|---|---|---|---|---|
| 1 | Hard-coded fallback `SECRET_KEY` allows session forgery and account takeover | CWE-321 / CWE-798 | A07, A02 | Manual review + PoC (missed by Bandit and Semgrep) | ✓ | | | ✗ (code: random key; PoC not yet run) |
| 2 | Debug mode on by default when started with `python app.py` (`DEMOBANK_DEBUG` defaults to `"1"`, line 474) | CWE-489 / CWE-215 | A02 | Manual review (missed by Bandit B201, which only matches literal `debug=True`) | ✓ | | | ✗ (`debug=False`) |
| 3 | No anti-clickjacking protection | CWE-1021 | A02 | ZAP | ✓ | | | ✗ (no ZAP alert) |
| 4 | No Content Security Policy | CWE-693 | A02 | ZAP | ✓ | | | ✗ (no ZAP alert) |
| 5 | | | | | | | | |

#1 was tested end to end on 16 Nov 2026 (see `exploit/session-forgery/`). #2 is from the code only. Its impact is limited because the Werkzeug debugger console is PIN-protected, but stack traces with source code would show to users. You could count #3 and #4 as one "missing security headers" item; just decide once and use the same rule for every version.

## 3. Still to verify with Burp

- No login rate limiting (Burp case 11)
- Sessions survive a password change in another browser (Burp case 8)

## 4. Security-aware version notes (`results/security-aware/`)

- **Semgrep** `nan-injection` at line 127: false positive. `bool()` wraps a true/false expression, not user input.
- **Bandit** B608 at lines 354 and 482: same `?`-placeholder pattern as the baseline, so false positives.
- **ZAP**: there's a passive report and an active report. Both are unauthenticated, ZAP 2.17.0 desktop. The baseline's CSP and anti-clickjacking alerts are gone. The server version leak remains.

## 5. Inconsistencies between versions (sort out before the final comparison)

| Item | Baseline | Security-aware |
|---|---|---|
| OS | Ubuntu VM | Windows |
| Semgrep rules | 3 custom rules | Semgrep registry rules |
| Functional tests | pytest, 3 own tests | unittest, 10 own tests |
| ZAP | CLI quick scan | Desktop passive + active scan |
| Burp | Kanita | Not used (ZAP Requester instead) |
| Atheris | Kanita / Diana | Not run |
| Input to ChatGPT | Functional prompt only | Baseline code + security prompt |

Shared-HTTP suite (`tests/shared-http`) not yet run on security-aware.
