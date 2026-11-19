# Testing Runbook: final automated test run

How to run the final, standardized automated tests on all four versions. One person runs this on one machine, so every version is tested the same way. Why the tests are being re-run: see the testing plan shared with the group, and `results/findings.md` section 5.

## What the run does

`scripts/run_all_tests.py` does everything below for **baseline, paid-tier, security-aware and self-fixed**, in that order, with identical settings:

| # | Step | Exactly what runs | Output in `results/<version>/` |
|---|---|---|---|
| 1 | Fresh environment | New Python venv with the version's own `requirements.txt` | `environment.txt` (Python, OS, all package versions) |
| 2 | Semgrep | `p/python`, `p/flask`, `p/owasp-top-ten` + `config/semgrep-custom.yml`, tests excluded | `semgrep.json`, `semgrep.log` |
| 3 | Bandit | All app code, tests excluded | `bandit.json`, `bandit.log` |
| 4 | pip-audit | The version's own `requirements.txt` | `pip-audit.json`, `pip-audit.log` |
| 5 | Own tests | The version's own tests, run with pytest | `pytest.xml`, `pytest.log` |
| 6 | Start the app | Exactly as its README says, on a fresh demo database | `server.log` |
| 7 | Shared HTTP tests | `tests/shared-http` (baseline and self-fixed only; the others use different routes) | `shared-http.xml`, `shared-http.log` |
| 8 | Exploit | `exploit/session-forgery/forge_session.py`, checking whether money actually moved | `exploit.txt` |
| 9 | OWASP ZAP | Quick scan (spider + active scan), not logged in | `zap.html`, `zap.log`, `zap-version.txt` |
| 10 | Atheris | `tests/fuzzing/fuzz_transfer.py`, 30 minutes per version, all four side by side | `atheris.log` (+ any `crash-*` files) |

At the end it writes **`results/RUN_SUMMARY.md`**, a table of raw counts for every tool and version.

How each app is started (from its own README):

| Version | Port | Start |
|---|---|---|
| baseline | 5001 | `flask --app app run` |
| paid-tier | 5003 | `FLASK_APP=run:app`, `flask run` |
| security-aware | 5000 | `DEMOBANK_SECRET_KEY` set to a fresh random value, `python run.py` (port fixed by `run.py`) |
| self-fixed | 5002 | `python run_local.py` |

Nothing under `versions/` is changed. Venvs and databases go in `.testrun/`, which git ignores. Old results stay in `results/<version>/earlier/`.

## Rules

- **Never edit anything in `versions/`.** If a version fails, record it. Don't fix it.
- Run all four versions in **one run, on one machine**, with the default settings (30-minute fuzzing).
- Close Burp Suite and ZAP desktop before starting.
- Don't change the script's settings between versions.

## 1. Requirements

- **Ubuntu 22.04/24.04, or WSL on Windows.** Atheris doesn't run on plain Windows or macOS.
- **Python 3.12**, plus `python3-venv`: `sudo apt install python3 python3-venv python3-pip git`
- **Internet access**: Semgrep downloads its rules; pip-audit checks an online vulnerability database.
- **OWASP ZAP**, one of:
  - `sudo snap install zaproxy --classic` (found automatically), or
  - the Linux package from zaproxy.org, which needs Java 17+ (`sudo apt install openjdk-17-jre`). If `zap.sh` isn't on your PATH, set `export ZAP_CMD=/path/to/zap.sh`.
- **For Atheris**, if `pip install atheris` fails: `sudo apt install clang`. If it still fails, use Python 3.11.
- About 3 GB free disk space and roughly **1–1.5 hours** (most of it ZAP and the 30-minute fuzzing). On the laptop used for the final run it took about 36 minutes.

## 2. Get the repo

```bash
git clone https://github.com/noor-fs/llm-generated-software-security-analysis.git
cd llm-generated-software-security-analysis
```
(or `git pull` if you already have it)

## 3. Dry run first (about 10 minutes)

Checks everything works before the long run. Fuzzing is cut to 30 seconds:

```bash
python3 scripts/run_all_tests.py --fuzz-seconds 30
```

Then open `results/RUN_SUMMARY.md`. Every row should have a value for every version. The dry run on a cloud Linux machine (without Semgrep and ZAP) gave:

| Tool | baseline | paid-tier | security-aware | self-fixed |
|---|---|---|---|---|
| Bandit | 2 (Medium 2) | 0 | 2 (Low 1, Medium 1) | 0 |
| pip-audit | 0 in 7 packages | 0 in 11 | 9 in 7 | 0 in 7 |
| Own tests | 3/3 | 7/9 (2 failures are bugs in its own tests) | 3/3 | 8/8 |
| Shared HTTP tests | 19/19 | n/a | n/a | 19/19 |
| Exploit | EXPLOITED | BLOCKED | BLOCKED | BLOCKED |
| Atheris | no failures | no failures | no failures | no failures |

Your numbers should match these. Semgrep and ZAP should show counts, not "no output" or "no report".

If something shows "no output", "not found" or "not installed", look at the matching `.log` file in `results/<version>/` and check **Troubleshooting** below.

## 4. Final run (about 1–1.5 hours)

```bash
python3 scripts/run_all_tests.py
```

This overwrites the dry-run files. Leave the machine on and don't run anything on ports 5000–5003 or 8099 meanwhile.

## 5. After the run

1. Open `results/RUN_SUMMARY.md` and check every cell has a value.
2. Commit the results:
   ```bash
   git add results/ .gitignore
   git commit -m "Final standardized automated test run (all four versions)"
   git push
   ```
3. Tell the group. The next step is going through every finding and marking it **confirmed** or **false positive** in `results/findings.md`.

## 6. Burp test cases (after the automated run)

Runs the same 12 attack cases (`tests/burp/test-cases.md`) on all four versions through Burp's proxy. Takes about 10 minutes including setup.

1. Open **Burp Suite Community**, start a temporary project, **Proxy → Intercept is off**, listener `127.0.0.1:8080`.
2. Run:
   ```bash
   python3 tests/burp/run_burp_cases.py
   ```
3. Export Burp's history: **Proxy → HTTP history** → **Ctrl+A** → right-click → **Save items** → `results/burp-history.xml`.
4. Take 2–3 Repeater screenshots for the report (see `tests/burp/test-cases.md`) and save them in `results/burp-screenshots/`.
5. Commit: `git add results/ && git commit -m "Burp test cases (all four versions)" && git push`

A dry run without Burp (`--no-proxy`) on a cloud Linux machine gave:

| # | Case | baseline | paid-tier | security-aware | self-fixed |
|---|---|---|---|---|---|
| 1 | Access without login | Blocked | Blocked | Blocked | Blocked |
| 2 | CSRF token removed / wrong | Blocked | Blocked | Blocked | Blocked |
| 3 | SQL injection | Blocked | Blocked | Blocked | Blocked |
| 4 | Stored XSS | Blocked | Blocked | Blocked | Blocked |
| 5 | Negative / odd amounts | Blocked | Blocked | Blocked | Blocked |
| 6 | IDOR | Blocked | Blocked | Blocked | Blocked |
| 7 | Replay | Blocked | Blocked | Blocked | Blocked |
| 8 | Session after password change | Vulnerable | Vulnerable | Blocked | Vulnerable |
| 9 | Session forgery | Vulnerable | Blocked | Blocked | Blocked |
| 10 | Open redirect | Blocked | Blocked | Blocked | Blocked |
| 11 | Brute force | Vulnerable | Vulnerable | Blocked | Vulnerable |
| 12 | Security headers / cookies | Vulnerable | Vulnerable | Blocked | Blocked |

If "Burp is not listening", Burp isn't open or uses another port (`--proxy http://127.0.0.1:PORT`). If requests hang, Intercept is on.

**Burp on Windows, script in WSL (Ubuntu):** inside WSL, `127.0.0.1:8080` is Ubuntu itself, not Windows, so the script won't find Burp there. Either:
- in Burp, **Proxy → Proxy settings → edit the listener → Bind to address: All interfaces**, then run
  ```bash
  python3 tests/burp/run_burp_cases.py --proxy http://$(ip route show default | awk '{print $3}'):8080
  ```
  (Windows may ask to allow Java/Burp through the firewall: allow it), or
- install the Linux version of Burp inside Ubuntu and run it there (needs Windows 11's built-in Linux GUI support).

## 7. Record: how the final run was done (19 Nov 2026)

This is what was actually done for the results in the report, so the method section can describe it exactly. Run by Noor on one laptop.

**Machine:** Windows 11 Pro, Intel i7-13700H (14 cores), 64 GB RAM. Tests ran in Ubuntu 24.04 under WSL 2 (kernel 6.18.58.1-microsoft-standard-WSL2), Python 3.12.3. OWASP ZAP 2.17.0 from the snap package (it bundles Java 17). Burp Suite Community 2026.11.2 on Windows.

**Setup steps:**
1. Installed WSL and Ubuntu: `wsl --install -d Ubuntu-24.04` (after the first `wsl --install` and a restart, Ubuntu itself was not installed yet, so the command was run a second time).
2. In Ubuntu: `sudo apt update`, then `sudo apt install -y python3 python3-venv python3-pip git clang` and `sudo snap install zaproxy --classic`.
3. Cloned the repo inside Ubuntu's home folder (`~/llm-generated-software-security-analysis`), not under `/mnt/c`, so file access is fast and line endings stay Unix-style. Because the repository is private, git in WSL was set to use the Windows Git Credential Manager:
   `git config --global credential.helper "/mnt/c/Program\ Files/Git/mingw64/bin/git-credential-manager.exe"`.
4. ZAP was found automatically at `/snap/bin/zaproxy` (no `ZAP_CMD` needed).

**Dry run** (`--fuzz-seconds 30`, 21:40–21:48): every row matched the expected table in section 3. Semgrep and ZAP gave counts for all versions.

**Final run** (`python3 scripts/run_all_tests.py`, default settings, 21:51–22:27, about 36 minutes): all steps ran for all four versions ("Skipped steps: none"). The results were identical to the dry run except the Atheris run counts, which were about 40 times higher with the same coverage. No `crash-*` files. Committed as `8ab63fc`.

**Burp run** (`python3 tests/burp/run_burp_cases.py --proxy http://<Windows host IP>:8080`, 23:11): Burp ran on Windows with Intercept off and the listener bound to all interfaces. All 48 results (12 cases × 4 versions) matched the expected table in section 6. Burp's HTTP history (649 requests) was saved to `results/burp-history.xml`, and two requests (transfer without CSRF token, `amount=-500`) were replayed by hand in Repeater for `results/burp-screenshots/`. Committed as `6e0453c`.

**Problems found and how they were handled:**
- **Burp runner crashed on the first attempt** (`KeyError: 'alice'`). Cause: when a version starts, Windows needs a moment before it forwards the new WSL port, so the first requests through Burp got Burp's own error page instead of the app, and the login check failed. The networking itself was fine (checked with a test server). The runner was fixed to wait until the app answers through the proxy, and to stop with a clear message if login fails (commit `9f46551`). No app code was changed.
- **Semgrep "errors"** are `PartialParsing` warnings on the Jinja HTML templates, not crashes. The Python code was scanned fully.
- **ZAP** finished each scan in under a minute. Each `zap.log` ends with "Attack complete" and a report was written. The `libtiff.so.5` warning in the log is about ZAP's desktop interface and does not affect the scan.

## Troubleshooting

| Problem | Fix |
|---|---|
| "Run this on Linux or WSL" | You're on Windows/macOS. Use WSL or the Ubuntu VM |
| Semgrep: "no output" | Check `semgrep.log`. Usually no internet, or Semgrep failed to install in `.testrun/tools` |
| ZAP: "not found" | Install ZAP (see requirements) or set `ZAP_CMD` |
| ZAP: "no report" | Check `zap.log`. If Java is missing, install `openjdk-17-jre` |
| Atheris: "not installed" | `sudo apt install clang`, delete `.testrun/`, run again |
| "port … already in use" | Something is running on that port. Stop it (`fuser -k 5001/tcp`) and re-run |
| App "did not start" | See `results/<version>/server.log` and record the error. Don't fix the app |
| Want to re-run one version only | `python3 scripts/run_all_tests.py --versions paid-tier`. Only for fixing a setup problem; the final results should come from one full run |
