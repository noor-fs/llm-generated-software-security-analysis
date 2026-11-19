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
- About 3 GB free disk space and roughly **1–1.5 hours** (most of it ZAP and the 30-minute fuzzing).

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
