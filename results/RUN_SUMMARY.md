# Automated test run summary

Run: 2026-11-19 22:27 on Linux-6.18.58.1-microsoft-standard-WSL2-x86_64-with-glibc2.39, Python 3.12.3. Fuzzing: 1800s per version, side by side. Skipped steps: none.

Raw counts only: every finding still has to be checked and marked confirmed or false positive in `findings.md`.

| Tool | baseline | paid-tier | security-aware | self-fixed |
|---|---|---|---|---|
| Semgrep | 1 findings, 8 errors | 0 findings, 10 errors | 0 findings, 8 errors | 0 findings, 8 errors |
| Bandit | 2 findings (Medium 2) | 0 findings | 2 findings (Low 1, Medium 1) | 0 findings |
| pip-audit | 0 vulnerabilities in 7 packages | 0 vulnerabilities in 11 packages | 9 vulnerabilities in 7 packages | 0 vulnerabilities in 7 packages |
| Own tests | 3/3 passed | 7/9 passed, 2 failed | 3/3 passed | 8/8 passed |
| Shared HTTP tests | 19/19 passed | n/a (different routes) | n/a (different routes) | 19/19 passed |
| Exploit | EXPLOITED | BLOCKED | BLOCKED | BLOCKED |
| OWASP ZAP | High 0, Medium 2, Low 2, Informational 3 | High 0, Medium 2, Low 2, Informational 2 | High 0, Medium 0, Low 1, Informational 3 | High 0, Medium 0, Low 0, Informational 3 |
| Atheris | 265657 runs, coverage 1287, no failures | 163573 runs, coverage 1267, no failures | 284240 runs, coverage 1294, no failures | 262852 runs, coverage 1304, no failures |

## Exit codes / status per step

```
{
  "baseline": {
    "semgrep": 0,
    "bandit": 1,
    "pip-audit": 0,
    "pytest": 0,
    "shared-http": 0,
    "exploit": "EXPLOITED",
    "zap": 0
  },
  "paid-tier": {
    "semgrep": 0,
    "bandit": 0,
    "pip-audit": 0,
    "pytest": 1,
    "exploit": "BLOCKED",
    "zap": 0
  },
  "security-aware": {
    "semgrep": 0,
    "bandit": 1,
    "pip-audit": 1,
    "pytest": 0,
    "exploit": "BLOCKED",
    "zap": 0
  },
  "self-fixed": {
    "semgrep": 0,
    "bandit": 0,
    "pip-audit": 0,
    "pytest": 0,
    "shared-http": 0,
    "exploit": "BLOCKED",
    "zap": 0
  }
}
```
