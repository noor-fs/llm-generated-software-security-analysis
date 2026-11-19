# Shared HTTP test suite (19 tests)

The same functional tests run against any running version over HTTP. Unlike each version's own tests, these results are comparable across versions. Written by Diana.

```bash
DEMOBANK_URL=http://127.0.0.1:5001 pytest tests/shared-http -v --junitxml=results/baseline/shared-http.xml
```

Change the port and results folder for each version. If a version renames routes (e.g. `/transfer`), note it as a limitation and don't edit the tests.

## Final results (19 Nov 2026)

Run by `scripts/run_all_tests.py` in the final standardized run, against each app started as its own README says:

| Version | Result |
|---|---|
| Baseline | 19 / 19 passed |
| Self-fixed | 19 / 19 passed (no regressions from the self-fix) |
| Paid tier | Not run: different routes and field names (package layout, `/accounts`) |
| Security-aware | Not run: different form field names (`_csrf` instead of `csrf_token`) |

Output: `results/<version>/shared-http.xml` and `shared-http.log`.
