# Results

Start with **[`findings.md`](findings.md)**: every finding checked and classified, the confirmed vulnerabilities per version, and the answer to each research question.

## Top-level files

| File | What it is |
|---|---|
| `findings.md` | Master analysis for the report |
| `RUN_SUMMARY.md` | Raw counts from the final automated run (`scripts/run_all_tests.py`, commit `8ab63fc`, 19 Nov 2026) |
| `BURP_SUMMARY.md` | Result of the 12 Burp cases on every version (`tests/burp/run_burp_cases.py`, commit `6e0453c`, 19 Nov 2026) |
| `burp-history.xml` | Burp's full HTTP history from the Burp run (649 requests). The port shows the version: 5001 baseline, 5003 paid-tier, 5000 security-aware, 5002 self-fixed |
| `burp-screenshots/` | Requests replayed by hand in Burp Repeater: `csrf-removed.png` (transfer without CSRF token → 400), `negative-amount.png` (`amount=-500` → rejected) |

## Per version: `results/<version>/`

All files are raw tool output written by the scripts, never edited by hand.

| File | Tool / step |
|---|---|
| `environment.txt` | Date, machine, Python version and every installed package for that version |
| `semgrep.json`, `semgrep.log` | Semgrep: `p/python`, `p/flask`, `p/owasp-top-ten` + `config/semgrep-custom.yml`, tests excluded |
| `bandit.json`, `bandit.log` | Bandit on all app code, tests excluded |
| `pip-audit.json`, `pip-audit.log` | pip-audit on the version's own `requirements.txt` |
| `pytest.xml`, `pytest.log` | The version's own tests |
| `shared-http.xml`, `shared-http.log` | The 19 shared HTTP tests (baseline and self-fixed only; the others use different routes or field names) |
| `server.log` | The app's own log while it was being tested |
| `exploit.txt` | Session-forgery exploit: balances before and after, and EXPLOITED / BLOCKED |
| `zap.html`, `zap.log`, `zap-version.txt` | OWASP ZAP 2.17.0 quick scan (spider + active scan), not logged in |
| `atheris.log` | Atheris, 30 minutes on the transfer endpoint. No `crash-*` files were produced for any version |
| `burp-cases.md`, `burp-cases.json` | The 12 Burp cases for this version, with the details behind each verdict |
| `earlier/` | Results from the earlier, non-standardized runs (different settings per version). Kept for reference only and **not** used in the comparison |

## How these were produced

Run by Noor on 19 Nov 2026 on one laptop: Ubuntu 24.04 under WSL 2 on Windows 11, Python 3.12.3, ZAP 2.17.0, Burp Suite Community 2026.11.2 (on Windows). Each version got a fresh venv and database and was started exactly as its own README says. Full steps and the problems that came up: [`docs/TESTING_RUNBOOK.md`](../docs/TESTING_RUNBOOK.md), section 7.

To reproduce: `python3 scripts/run_all_tests.py`, then `python3 tests/burp/run_burp_cases.py` with Burp open.
