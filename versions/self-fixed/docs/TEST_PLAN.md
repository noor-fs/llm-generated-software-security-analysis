# V1/V2 repeatable security test plan

Use isolated local VMs or localhost only, and use fictional demo accounts. Keep tool versions, rulesets, scan modes, authentication context, ports, and test data conditions consistent.

## Static analysis

From each project directory:

```bash
python -m pip install -r requirements.txt bandit pip-audit
bandit -r . -f json -o reports/VERSION/bandit.json
semgrep scan --config auto --json --output reports/VERSION/semgrep.json .
pip-audit -r requirements.txt -f json -o reports/VERSION/pip-audit.json
python -m pytest -v
```

For Semgrep, record the exact config/ruleset and version. The V1 supplied custom rule is not equivalent to `--config auto`; comparisons must use the same rule configuration on both versions. Exclude `.venv`, caches, generated databases, and reports from source scans where appropriate.

## Dynamic scan

1. Initialize and seed the version-specific database.
2. Start V1 on `127.0.0.1:5001` and V2 on `127.0.0.1:5002` (not simultaneously against the same DB).
3. Run ZAP baseline/active scans using the same policy and context. Save HTML and JSON reports in the version's reports folder.
4. If testing authenticated routes, configure ZAP authentication/session handling or manually exercise authenticated endpoints. Record which routes were reached; a public-site crawl is not an authenticated application assessment.

## Burp Community manual checks

Use Proxy HTTP history and Repeater. Community Edition does not provide the Professional automated scanner. Save the history export and a separate human-readable test log with request, changed parameter, expected result, observed status/body, and whether any unauthorized data/state change occurred.

Minimum cases:
- Anonymous access to `/dashboard`, `/account`, `/transfer`, `/transactions`, `/profile`, `/settings`, `/change-password`, `/notifications` redirects to login.
- Alice cannot view Bob-only transaction data by changing IDs/parameters; verify no IDOR is present (the routes should not accept client-supplied ownership IDs).
- Negative, zero, malformed, excessive-precision, over-limit, and over-balance transfer amounts do not change balances.
- Nonexistent and self-recipient transfers fail.
- Replaying an identical idempotency key does not execute a second transfer.
- Missing/invalid CSRF token on every POST is rejected.
- Verify logout clears the session; password change requires current password and signs the user out.
- Try harmless XSS marker strings in name, phone, description, username and search/filter values; confirm they render as text, not executable markup.

## Record results

For each version record tool version, exact command/configuration, date, database reset/seed state, scan URL/port, authenticated coverage, raw report, and triage. Deduplicate the same underlying weakness reported by multiple tools. Separate confirmed vulnerabilities, likely false positives, informational observations, and untested areas.
