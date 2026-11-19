# Project Scope and Methodology

Security Analysis of LLM-Generated Software | CMPS 380, Fall 2026 | Approved by the group, 16 November 2026

## 1. The project in one paragraph

We use ChatGPT to build the same small banking website (DemoBank) in four different ways, then run the same security tests on all four. By comparing the results, we measure how much three things affect the security of AI-generated code: **which model** writes it (free or paid), **how it is asked** (a general prompt or one with specific security requirements), and **whether it can fix its own mistakes** when shown our test results.

## 2. What changed from the proposal

The proposal listed five possible comparisons and said the list might be reduced. We keep three:

| Kept | Dropped |
|---|---|
| Free vs. paid model | Web chat vs. API |
| General vs. security-aware prompt | Normal chat vs. agentic workflow |
| Self-fix using our test results | |

**Why:** each remaining comparison can be done fairly in the time we have, changing only one thing at a time.

**Also removed:** the profile-picture upload and admin panel. The baseline app does not have them, and adding them would change the app being compared.

## 3. Research questions

**Main question:** How secure is a web application written by ChatGPT, and how much do model tier, prompt quality and self-correction change that?

- **RQ1, Model tier:** Given the same prompt, does the paid ChatGPT model produce a more secure application than the free model?
- **RQ2, Prompt quality:** Using the free model, does adding specific security requirements to the prompt produce a more secure application than a prompt that leaves security to the model?
- **RQ3, Self-fix effectiveness:** When the free model is given its own code and our test results, how many real vulnerabilities does it fix correctly? Does it recognise false alarms, does it break anything, and do its claims about what it fixed match what the tests show?

## 4. Key terms

- **Baseline prompt:** the prompt Diana and Noor both used (confirmed identical). It describes every page and feature in detail. For security it only says "you are responsible for selecting and implementing appropriate security practices", so security is left to the model's judgement.
- **Security-aware prompt:** the baseline prompt, unchanged, plus an extra section listing specific security requirements (see `versions/security-aware/PROMPT.md`).
- **Free model:** free ChatGPT, GPT-5.6 (Luna). Used for the baseline, the self-fix and the security-aware version. **Paid model:** paid ChatGPT (Plus), GPT-6 with medium reasoning.
- **Tool finding:** anything a testing tool reports. It may or may not be a real problem.
- **False positive:** a tool finding that turns out not to be a real problem when checked.
- **Confirmed vulnerability:** a weakness we either exploited, or traced in the code with a clear impact. **This is our main measure.** Raw tool counts are reported but not used to rank versions.
- **Fixed:** after the change, the vulnerability can no longer be exploited or detected, and the app's features still work.

## 5. The four versions

| Version | Model | What ChatGPT is given | Made by | Answers |
|---|---|---|---|---|
| Baseline | Free (GPT-5.6) | Baseline prompt, new chat | Diana | Reference for all |
| Paid tier | Paid (GPT-6, medium) | Same baseline prompt, new chat | Noor | RQ1 |
| Security-aware | Free (GPT-5.6) | Baseline prompt + security section, new chat, no existing code | Hajra (first generation by Khadija, replaced on 19 Nov) | RQ2 |
| Self-fixed | Free (GPT-5.6) | Our proposal, the baseline code and the baseline test results | Kanita & Hajra | RQ3 |

**Fairness rules:** a new chat with memory and custom instructions off; generated code is never edited by hand; every prompt and chat link is saved in the repo; all free-tier versions use GPT-5.6.

The security section in the security-aware prompt is based on the OWASP Top 10:2025 categories, **not** on our test results. Otherwise RQ2 would measure "told what to fix" instead of "asked for security up front".

## 6. How every version is tested

The same seven tests on all four versions, **on the same machine**, with the same settings: Semgrep, Bandit, pip-audit, pytest, OWASP ZAP (quick scan), Burp Suite (the same 12 cases, sent through Burp and recorded) and Atheris (30 minutes on the transfer function). The work is split by task, not by version, so each test is run the same way on all four.

**How it was done in practice (19 Nov 2026):** the earlier test runs had been done by different members with different settings, so they could not be compared fairly (they are kept in `results/<version>/earlier/`). To fix this, Noor wrote one script for all the automated tools (`scripts/run_all_tests.py`) and one for the Burp cases (`tests/burp/run_burp_cases.py`), and ran both on all four versions on one laptop: Ubuntu 24.04 under WSL 2 on Windows 11, Python 3.12.3, ZAP 2.17.0, Burp Suite Community 2026.11.2. A short dry run came first, then the final run with default settings. Every version got a fresh venv and database and was started exactly as its own README says. The exact steps are in `docs/TESTING_RUNBOOK.md`, and the results and their classification are in `results/findings.md`.

## 7. What we measure

**For every version:** confirmed vulnerabilities (number, OWASP Top 10:2025 category, CWE, severity); raw tool findings and false positives per tool; whether features still work.

**For RQ3:** findings fixed correctly, partly, or not at all; whether false positives were identified; claimed fixes that did not work; anything the changes broke; fixes to problems no tool reported.

## 8. What we expect

These are hypotheses, not results we have to reach. If a result goes the other way, we report it as it is.

- **RQ1:** the paid model avoids some of the free model's configuration mistakes (hard-coded secret key, debug mode), but both still miss security headers and rate limiting.
- **RQ2:** the security section removes the problems it names explicitly, but not ones it does not mention.
- **RQ3:** ChatGPT fixes most reported issues, but its claims do not always match the re-test.

## 9. Limits we will state in the report

- One application, one generation per version. Another run could give different results.
- ChatGPT's models change over time; the results reflect November 2026.
- The ZAP quick scan only covers pages it can reach without logging in.
- The paid model built a differently structured app, so some shared tests cannot run on it unchanged.
- Burp test cases are scripted and sent through Burp's proxy, with selected requests replayed manually in Repeater.
- For the self-fix, ChatGPT was also shown our proposal, so it knew its fixes would be re-tested.
