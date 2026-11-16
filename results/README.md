# Results

One folder per version. Put the raw output of every tool here, never edited:

```
results/<version>/
  environment.txt        python version + pip freeze (written by the scan script)
  exit-codes.txt
  semgrep.json / .log
  bandit.json / .log
  pip-audit.json / .log
  pytest.xml / .log
  shared-http.xml
  zap/                   baseline.html + baseline.json
  burp/                  saved requests/responses + screenshots
  atheris.log            + any crash-* files
```

`shared-http.xml` in each version's folder is the result of the 19-test suite in `tests/shared-http/`.

## OWASP ZAP (quick scan: spider + active scan)

Diana's baseline log ("Using traditional spider … Active scanning … Attack complete") is the output of ZAP's command-line **quick scan**. Use the same scan on every version so the results compare. Start the version first, then:

```bash
mkdir -p results/paid-tier/zap
zap.sh -cmd -quickurl http://127.0.0.1:5003 \
  -quickout "$PWD/results/paid-tier/zap/zap-paid-tier-5003.html" \
  > results/paid-tier/zap/zap-paid-tier-5003.log 2>&1
```

Change the port and folder for each version. Check the report header shows the same ZAP version as the baseline (2.17.0) and record it if it differs. This scan is **unauthenticated**, so it only reaches the public pages, as in the baseline.

## Atheris

```bash
python tests/fuzzing/fuzz_transfer.py versions/baseline -max_total_time=1800 2>&1 | tee results/baseline/atheris.log
```
