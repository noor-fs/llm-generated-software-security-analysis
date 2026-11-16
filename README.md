# Security Analysis of LLM-Generated Software

A ChatGPT-built banking web app (DemoBank) generated four ways and tested with the same seven security tools, to compare model tier, prompt quality and self-fixing.

CMPS 380 Cybersecurity Fundamentals, Qatar University, Fall 2026.

> **Warning:** this repository contains AI-generated code with known vulnerabilities and a working exploit. Run it only on your own machine or VM, with the fake demo data. Never deploy it.

## Research questions

Full scope and definitions: [`docs/SCOPE.md`](docs/SCOPE.md).

**Main question:** How secure is a web application written by ChatGPT, and how much do model tier, prompt quality and self-correction change that?

- **RQ1, Model tier:** Given the same prompt, does the paid ChatGPT model produce a more secure application than the free model?
- **RQ2, Prompt quality:** Using the free model, does adding specific security requirements to the prompt produce a more secure application than a prompt that leaves security to the model?
- **RQ3, Self-fix effectiveness:** When the free model is given its own code and our test results, how many real vulnerabilities does it fix correctly? Does it recognise false alarms, does it break anything, and do its claims match what the tests show?

## Versions

| Folder | Model | What ChatGPT was given | Made by | Answers | Status |
|---|---|---|---|---|---|
| [`versions/baseline`](versions/baseline) | Free, GPT-5.6 | Baseline prompt, new chat | Diana Al-Marri | Reference | Done |
| [`versions/paid-tier`](versions/paid-tier) | Paid, GPT-6 (medium) | Same baseline prompt, new chat | Noor Al Huda Soueid | RQ1 | Done |
| [`versions/security-aware`](versions/security-aware) | Free, GPT-5.6 | Baseline prompt + security section, new chat, no code | Khadija Alobeid | RQ2 | To generate |
| [`versions/self-fixed`](versions/self-fixed) | Free, GPT-5.6 | Baseline code + baseline test results | Kanita Ansari, Hajra Ghani | RQ3 | Done |

Each folder has a `PROMPT.md` with the exact prompt and chat link. Generated code is committed exactly as ChatGPT produced it and is never edited by hand. `versions/baseline/V1_SHA256.json` holds the original hash of every baseline file.

## Repository layout

```
docs/          SCOPE.md (research questions, method, definitions) and the proposal
versions/      the four generated apps, each with PROMPT.md
tests/
  shared-http/ 19 HTTP tests for apps with the baseline's routes
  fuzzing/     Atheris harness for the /transfer endpoint (works on every version)
  burp/        the 12 Burp test cases, same on every version
results/       raw tool output per version + findings.md (master table)
exploit/       session-forgery proof of concept
scripts/       run_static_scans.sh: Semgrep, Bandit, pip-audit, pytest with the same settings
config/        shared Semgrep rules
```

## Running each version

Python 3.12 on Ubuntu. Give each version its own venv, database and port.

| Version | Port | Commands (inside the version folder) |
|---|---|---|
| Baseline | 5001 | `flask --app app init-db`, `flask --app app seed-demo`, `flask --app app run --port 5001` |
| Paid tier | 5003 | `export FLASK_APP=run:app`, `flask init-db`, `flask seed-demo`, `flask run --port 5003` |
| Security-aware | 5004 | see its README once generated |
| Self-fixed | 5002 | `flask --app app init-db`, `flask --app app seed-demo`, `python run_local.py --host 127.0.0.1 --port 5002` |

Start with `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`. Demo logins: `alice` / `bob` / `charlie` (paid tier: `alex` / `jordan` / `taylor`), password `DemoPass123!`.

Start each version the way its own README says. For example, the self-fixed version's server-header fix only works when started with `run_local.py`.

## Testing

| Tool | What it checks | How to run |
|---|---|---|
| Semgrep | Insecure code patterns | `scripts/run_static_scans.sh <version>` |
| Bandit | Common Python security mistakes | same script |
| pip-audit | Known vulnerabilities in `requirements.txt` | same script |
| pytest | Features still work | same script; plus `tests/shared-http` where routes match |
| OWASP ZAP | Automated attack on the running site | quick scan, see [`results/README.md`](results/README.md) |
| Burp Suite | The same 12 attack cases | [`tests/burp/test-cases.md`](tests/burp/test-cases.md) |
| Atheris | Random input to transfers, 30 min | [`tests/fuzzing/`](tests/fuzzing) |

All four versions are tested on the same machine with the same settings. Results go in `results/<version>/` and are summarised in [`results/findings.md`](results/findings.md).

## Proof of concept

[`exploit/session-forgery`](exploit/session-forgery): the baseline signs session cookies with a hard-coded fallback secret key. Anyone can forge a cookie for any user and transfer their money without a password. Bandit and Semgrep both missed it. It fails against the self-fixed version.

## Known limitations

- One generation per version; ChatGPT can answer differently each time. Models change over time, so results reflect November 2026.
- No profile-picture upload or admin panel, although the proposal listed both.
- The paid model built a differently structured app (package layout, different routes and field names), so `tests/shared-http` does not run on it unchanged.
- ZAP's quick scan only reaches pages available without logging in.
- For the self-fix, ChatGPT was also shown our proposal, so it knew its fixes would be re-tested.

## Team

Diana Al-Marri, Noor Al Huda Soueid, Khadija Alobeid, Kanita Ansari, Hajra Ghani.
