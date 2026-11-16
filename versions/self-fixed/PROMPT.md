# Self-fixed version: how it's made

**Question it answers (Q1):** how well can the LLM fix its own flaws when we give it our test results?

**Model:** ChatGPT free tier, the same model Diana used for the baseline (_model name_)
**Starting point:** an unchanged copy of `versions/baseline`
**Done by:** _TBC_

## Rules (so the comparison is fair)

- Start a **new chat**, the same free model as the baseline.
- Give it the baseline code and the **raw, unfiltered** tool output, false positives included. Whether it recognises false positives is part of the result.
- Don't hint at fixes yourself. Describe what was found, not how to fix it.
- Ask it not to add or change features, so the shared HTTP tests still apply.
- Commit after each round, then re-run all 7 tests.

## Round 1: automated tool reports

Paste in this order: the prompt, `app.py`, `requirements.txt`, then the reports.

```
Below is the code of a Flask banking web app you generated earlier, followed by the
raw output of the security tools we ran on it: Semgrep, Bandit, pip-audit, OWASP ZAP
and Atheris.

For each finding:
1. Say whether it is a real security issue or a false positive, and why.
2. If it is real, fix it.

Do not add new features or change how existing features behave. Keep the same
routes and form field names. Return the complete updated files, then a short list
of every change you made and which finding it addresses.

=== app.py ===
<paste>

=== requirements.txt ===
<paste>

=== Semgrep ===
<paste results/baseline/semgrep.json, or the text output>

=== Bandit ===
<paste results/baseline/bandit.json>

=== pip-audit ===
<paste results/baseline/pip-audit.json>

=== OWASP ZAP ===
<paste the alert list from results/baseline/zap/zap-baseline-5001.html>

=== Atheris ===
<paste the end of the fuzzing log>
```

→ Save the output into this folder, commit as `Self-fix round 1: tool reports`, run the tests and fill in Q1 in `results/findings.md`.

## Round 2: manual testing results

Same chat:

```
We also tested the app manually with Burp Suite and found the following.
For each one, say whether it is real and fix it if so. Same rules as before:
no new features, same routes and field names, return complete files and a change list.

<paste Kanita's Burp findings: what you sent, what happened>

We were also able to log in as another user without their password by creating our
own session cookie, and then make a transfer from their account.
```

The last paragraph describes what the session-forgery PoC did without naming the cause. Whether ChatGPT finds the hard-coded key from the symptom alone is part of what Q1 measures.

→ Commit as `Self-fix round 2: manual findings`, re-test, and run `exploit/session-forgery/forge_session.py` against it.

## What to record for the report

| Finding fed back | Round | ChatGPT said | Fixed? | Broke anything? |
|---|---|---|---|---|
| Bandit B608 (×2) | 1 | real / false positive | | |
| ZAP: missing CSP | 1 | | | |
| ZAP: missing anti-clickjacking | 1 | | | |
| ZAP: server version header | 1 | | | |
| ZAP: X-Content-Type-Options | 1 | | | |
| Session forgery | 2 | | | |
| _Burp findings_ | 2 | | | |
| Debug mode default (never fed back) | – | – | | |

The debug-mode issue (#2 in findings) isn't reported by any tool, so it's never fed back. Whether ChatGPT fixes it anyway shows if it fixes beyond what it's told.

Save the full chat (share link or export) in this file.
