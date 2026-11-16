# Shared HTTP test suite (19 tests)

The same functional tests run against any running version over HTTP. Unlike each version's own tests, these results are comparable across versions. Written by Diana.

```bash
DEMOBANK_URL=http://127.0.0.1:5001 pytest tests/shared-http -v --junitxml=results/baseline/shared-http.xml
```

Change the port and results folder for each version. If a version renames routes (e.g. `/transfer`), note it as a limitation and don't edit the tests.
