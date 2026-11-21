# Security Analysis of LLM-Generated Software

A ChatGPT-built banking web app (DemoBank) generated four ways and tested with the same seven security tools, to compare model tier, prompt quality and self-fixing.

CMPS 380 Cybersecurity Fundamentals, Qatar University, Fall 2026.

## Research questions

Full scope and definitions: [`docs/SCOPE.md`](docs/SCOPE.md).

**Main question:** How secure is a web application written by ChatGPT, and how much do model tier, prompt quality and self-correction change that?

- **RQ1, Model tier:** Given the same prompt, does the paid ChatGPT model produce a more secure application than the free model?
- **RQ2, Prompt quality:** Using the free model, does adding specific security requirements to the prompt produce a more secure application than a prompt that leaves security to the model?
- **RQ3, Self-fix effectiveness:** When the free model is given its own code and our test results, how many real vulnerabilities does it fix correctly? Does it recognise false alarms, does it break anything, and do its claims match what the tests show?

## Results in short

Confirmed vulnerabilities per version (full analysis in [`results/findings.md`](results/findings.md)):

| | Baseline (free) | Paid tier | Security-aware | Self-fixed |
|---|---|---|---|---|
| Confirmed vulnerabilities | **8** (1 High, 4 Medium, 3 Low) | **6** (3 Medium, 3 Low) | **2** (2 Low) | **2** (1 Medium, 1 Low) |
| Session-forgery exploit | Works | Blocked | Blocked | Blocked |
| Burp cases vulnerable (of 12) | 4 | 3 | 0 | 2 |

- **RQ1:** the paid model avoided the two code-level flaws (hard-coded secret key, debug default) but has the same header, brute-force and session weaknesses as the free model.
- **RQ2:** the security-aware prompt gave the most secure version, but the model still broke two of the prompt's explicit requirements (server version shown, outdated pinned dependencies).
- **RQ3:** the self-fix fixed everything it was shown plus two unreported issues, broke nothing, but did not fix weaknesses outside the evidence it was given.
- Semgrep and Bandit found **no** confirmed vulnerability in any version; the only High finding came from manual review and the exploit.

## Versions

| Folder | Model | What ChatGPT was given | Made by | Answers | Status |
|---|---|---|---|---|---|
| [`versions/baseline`](versions/baseline) | Free, GPT-5.6 | Baseline prompt, new chat | Diana Al-Marri | Reference | Done |
| [`versions/paid-tier`](versions/paid-tier) | Paid, GPT-6 (medium) | Same baseline prompt, new chat | Noor Al Huda Soueid | RQ1 | Done |
| [`versions/security-aware`](versions/security-aware) | Free, GPT-5.6 | Baseline prompt + security section, new chat, no code | Hajra Ghani | RQ2 | Done |
| [`versions/self-fixed`](versions/self-fixed) | Free, GPT-5.6 | Baseline code + baseline test results | Kanita Ansari, Hajra Ghani | RQ3 | Done |

Each folder has a `PROMPT.md` with the exact prompt and chat link. Generated code is committed exactly as ChatGPT produced it and is never edited by hand. `versions/baseline/V1_SHA256.json` holds the original hash of every baseline file. The only post-generation change anywhere is security-aware's transfer fix, which ChatGPT itself produced after one error-only follow-up message (see its `PROMPT.md`).

## Repository layout

```
docs/          SCOPE.md (research questions, method, definitions), TESTING_RUNBOOK.md, the proposal
versions/      the four generated apps, each with PROMPT.md
tests/
  shared-http/ 19 HTTP tests for apps with the baseline's routes
  fuzzing/     Atheris harness for the /transfer endpoint (works on every version)
  burp/        the 12 Burp test cases and run_burp_cases.py, same on every version
results/       findings.md (master analysis), RUN_SUMMARY.md, BURP_SUMMARY.md,
               raw tool output per version, Burp HTTP history and screenshots
exploit/       session-forgery proof of concept
scripts/       run_all_tests.py: the final standardized run of every automated tool on all four versions
               run_static_scans.sh: earlier per-version script (Semgrep, Bandit, pip-audit, pytest)
config/        shared Semgrep rules
```

## Running each version

Python 3.12 on Ubuntu. Give each version its own venv, database and port. These are the start methods from each version's own README, and the ones the final test run used:

| Version | Port | Commands (inside the version folder) |
|---|---|---|
| Baseline | 5001 | `flask --app app init-db`, `flask --app app seed-demo`, `flask --app app run --port 5001` |
| Paid tier | 5003 | `export FLASK_APP=run:app`, `flask init-db`, `flask seed-demo`, `flask run --port 5003` |
| Security-aware | 5000 | `export DEMOBANK_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_hex(32))')`, `export FLASK_APP=app.py`, `flask init-db`, `flask seed-demo`, `python run.py` (port 5000 is fixed in `run.py`) |
| Self-fixed | 5002 | `flask --app app init-db`, `flask --app app seed-demo`, `python run_local.py --host 127.0.0.1 --port 5002` |

Start with `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`. Demo logins: `alice` / `bob` / `charlie` (paid tier: `alex` / `jordan` / `taylor`), password `DemoPass123!`. Security-aware: `alice` / `bob`, password `DemoPass12345!`. Security-aware refuses to start without `DEMOBANK_SECRET_KEY`.

Start each version the way its own README says. For example, the self-fixed version's server-header fix only works when started with `run_local.py`.

## Testing

| Tool | What it checks | How it was run in the final run |
|---|---|---|
| Semgrep | Insecure code patterns | `p/python`, `p/flask`, `p/owasp-top-ten` + `config/semgrep-custom.yml` (228 rules), tests excluded |
| Bandit | Common Python security mistakes | All app code, tests excluded |
| pip-audit | Known vulnerabilities in `requirements.txt` | The version's own `requirements.txt` |
| pytest | Features still work | The version's own tests, plus `tests/shared-http` where routes match (baseline, self-fixed) |
| OWASP ZAP | Automated attack on the running site | Quick scan (spider + active scan), not logged in, ZAP 2.17.0 |
| Burp Suite | The same 12 attack cases on every version | `tests/burp/run_burp_cases.py` sends them through Burp's proxy; 2 replayed by hand in Repeater |
| Atheris | Random input to transfers | `tests/fuzzing/fuzz_transfer.py`, 30 minutes per version |

Plus the session-forgery exploit (`exploit/session-forgery`) on every version, checking whether money actually moved.

`python3 scripts/run_all_tests.py` runs everything except Burp on all four versions in one go; `python3 tests/burp/run_burp_cases.py` runs the Burp cases. See [`docs/TESTING_RUNBOOK.md`](docs/TESTING_RUNBOOK.md).

## How the final tests were run

All results used in the report come from one standardized run, done by Noor on 19 November 2026 on one machine, with identical settings for every version:

- **Machine:** Windows 11 laptop (Intel i7-13700H, 64 GB RAM), with the tests running in **Ubuntu 24.04 under WSL 2**. Python 3.12.3, OWASP ZAP 2.17.0 (snap package), Semgrep/Bandit/pip-audit installed fresh by the runner. Burp Suite Community 2026.11.2 ran on Windows, with the Burp script running in Ubuntu and sending its requests to Burp's proxy.
- **Fresh environment per version:** the runner created a new Python venv from each version's own `requirements.txt` and a fresh demo database, and started each app exactly as its README says.
- **Dry run first** (30-second fuzzing) to check every tool worked. It matched the expected results in the runbook.
- **Final automated run:** `scripts/run_all_tests.py` with default settings (21:51–22:27, about 36 minutes, of which 30 minutes were the four Atheris runs side by side). Committed as `8ab63fc`.
- **Burp run:** `tests/burp/run_burp_cases.py` through Burp's proxy (23:11), then Burp's HTTP history (649 requests) exported and two requests replayed by hand in Repeater for screenshots. Committed as `6e0453c`.
- **Classification:** every finding was then checked and marked confirmed or false positive in `results/findings.md`.

Nothing under `versions/` was changed for the tests. One setup problem came up and was fixed in the test script, not in the apps: with Burp on Windows and the script in WSL, Windows needs a moment to start forwarding a newly opened WSL port, so the first requests reached Burp before the app. The Burp runner now waits until the app answers through the proxy (commit `9f46551`). Earlier, non-standardized results are kept in `results/<version>/earlier/` and are not used for the comparison.

## Proof of concept

[`exploit/session-forgery`](exploit/session-forgery): the baseline signs session cookies with a hard-coded fallback secret key. Anyone can forge a cookie for any user and transfer their money without a password. Bandit and Semgrep both missed it. In the final run it moved QAR 500 out of bob's baseline account, and it was blocked on the paid-tier, security-aware and self-fixed versions (all three use a random or required secret key).

## Known limitations

- One generation per version; ChatGPT can answer differently each time. Models change over time, so results reflect November 2026.
- No profile-picture upload or admin panel, although the proposal listed both.
- The paid model built a differently structured app (package layout, different routes and field names), and security-aware uses different form field names, so `tests/shared-http` only runs on baseline and self-fixed.
- ZAP's quick scan only reaches pages available without logging in.
- Semgrep could only partly parse the Jinja HTML templates (8–10 `PartialParsing` warnings per version), so templates were not fully checked.
- Burp Suite Community has no automated scanner; the 12 cases are scripted and sent through Burp's proxy, with selected requests replayed by hand.
- For the self-fix, ChatGPT was also shown our proposal, so it knew its fixes would be re-tested.

## Team

Diana Al-Marri, Noor Al Huda Soueid, Khadija Alobeid, Kanita Ansari, Hajra Ghani.
