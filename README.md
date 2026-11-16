# Security Analysis of LLM-Generated Software

Security analysis of LLM-generated software: a ChatGPT-built banking web app compared across model tiers, prompt quality and self-repair, tested with Semgrep, Bandit, pip-audit, pytest, OWASP ZAP, Burp Suite and Atheris.

CMPS 380 Cybersecurity Fundamentals, Qatar University, Fall 2026.

> **Warning:** this repository contains deliberately unhardened, AI-generated code and a working exploit. Run it only on your own machine or VM, with the fake demo data. Never deploy it.

## Research questions

1. **Self-fix sufficiency:** How well can an LLM fix the security flaws in its own code?
2. **Model tier:** Does a paid ChatGPT model write more secure code than the free model from the same prompt?
3. **Prompt quality:** Does a security-aware prompt produce more secure code than a basic one?

## Versions

All four are versions of **DemoBank**, a Flask + SQLite banking app with fake users and balances.

| Folder | Built by | Model | Prompt | Answers |
|---|---|---|---|---|
| [`versions/baseline`](versions/baseline) | Diana Al-Marri | ChatGPT free | Basic functional prompt | Reference for all |
| [`versions/self-fixed`](versions/self-fixed) | _TBC_ | ChatGPT free | Baseline + our tool reports fed back | Q1 |
| [`versions/paid-tier`](versions/paid-tier) | Noor Al Huda Soueid | ChatGPT paid (GPT-6, medium) | Same prompt as baseline | Q2 |
| [`versions/security-aware`](versions/security-aware) | Khadija Alobeid | ChatGPT free | Baseline code + security-aware prompt | Q3 |

The baseline must not be edited. `versions/baseline/V1_SHA256.json` holds the hash of every original file so this can be checked.

## Repository layout

```
versions/      the four generated apps (each has its own README and PROMPT.md)
tests/
  shared-http/ 19 HTTP tests that run unchanged against any version
  fuzzing/     Atheris harness for the /transfer endpoint
  burp/        manual test cases, run the same way on every version
results/       raw tool output per version + findings.md (master table)
exploit/       proof-of-concept exploits with step-by-step instructions
scripts/       run_static_scans.sh: same static tools and rules on any version
config/        shared Semgrep rules
docs/          proposal and project notes
```

## Quick start

Requires Python 3.12 on Linux (we used Ubuntu in VirtualBox).

```bash
cd versions/baseline
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
flask --app app init-db
flask --app app seed-demo
flask --app app run --host 127.0.0.1 --port 5001
```

Demo logins: `alice`, `bob`, `charlie`, password `DemoPass123!`. Use port 5002 for the self-fixed version, 5003 for paid-tier and 5004 for security-aware, each with its own venv and database.

## Testing

| # | Tool | Type | How to run |
|---|---|---|---|
| 1 | Semgrep | Static analysis | `scripts/run_static_scans.sh <version>` |
| 2 | Bandit | Static analysis | same script |
| 3 | pip-audit | Dependency check | same script |
| 4 | pytest | Functional tests | same script (uses each version's own tests) |
| 5 | OWASP ZAP | Dynamic scan | see [`results/README.md`](results/README.md) |
| 6 | Burp Suite Community | Manual pen testing | [`tests/burp/test-cases.md`](tests/burp/test-cases.md) |
| 7 | Atheris | Coverage-guided fuzzing | [`tests/fuzzing/`](tests/fuzzing) |

Use the same tool versions, rules and time limits on every version. Results go in `results/<version>/` and are summarised in [`results/findings.md`](results/findings.md).

## Known gaps

- The baseline has no profile picture upload or admin panel, although the proposal listed both. The group agreed to leave them out.
- The versions were tested on different setups (OS, Semgrep rules, ZAP mode). See section 5 of `results/findings.md`. To be aligned before the final comparison.
- Diana's first V2 was built with a security-aware prompt on the paid model, which changes two things at once, so it was scrapped and is not in this repo.

## Proof of concept

[`exploit/session-forgery`](exploit/session-forgery): the baseline signs session cookies with a hard-coded fallback secret key. Anyone can forge a cookie for any user and transfer their money without a password. Neither Bandit nor Semgrep flagged it.

## Team

| Member | Role |
|---|---|
| Diana Al-Marri | Baseline version; ZAP, Semgrep, Bandit, pip-audit, Atheris on baseline |
| Noor Al Huda Soueid | Paid-tier version and its tests |
| Khadija Alobeid | Security-aware version |
| Kanita Ansari | Burp Suite and Atheris testing on baseline; compiling the report |
| Hajra Ghani | _role_ |
