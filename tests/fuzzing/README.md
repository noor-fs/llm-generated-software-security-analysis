# Fuzzing with Atheris

`fuzz_transfer.py` fuzzes the money-transfer endpoint of any version. It runs the real `app.py` through Flask's test client (no server needed), logs in as `alice`, and sends fuzzed amounts, recipients and descriptions. After every request it checks that:

1. the app never returns a **500 error**
2. no balance ever goes **negative**
3. the **total money** across all accounts never changes

```bash
pip install atheris            # Linux, Python 3.12
pip install -r versions/baseline/requirements.txt
python tests/fuzzing/fuzz_transfer.py versions/baseline -max_total_time=1800 2>&1 | tee results/baseline/atheris.log
```

Use the same `-max_total_time` for every version. If a check fails, libFuzzer saves the input as `crash-<hash>`. Move it into `results/<version>/` as evidence. To replay it:

```bash
python tests/fuzzing/fuzz_transfer.py versions/baseline crash-<hash>
```

For the report, record the number of runs (`#N DONE`), the coverage (`cov:`) and whether any crash was found.

The harness works with both layouts: single-file `app.py` (baseline, security-aware) and `run.py` + package (paid tier). It finds the CSRF field name, login user and DB path for each. Short test runs on baseline, security-aware and paid tier (16 Nov 2026) completed with no failures, and real transfers went through. The full runs still need to be done.
