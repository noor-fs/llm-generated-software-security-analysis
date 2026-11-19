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

The harness works with both layouts: single-file `app.py` (baseline, security-aware, self-fixed) and `run.py` + package (paid tier). It finds the CSRF field name, login user and DB path for each.

## Final results (19 Nov 2026)

Run by `scripts/run_all_tests.py` in the final standardized run: 30 minutes per version, all four side by side, Ubuntu 24.04 under WSL 2, Python 3.12.3.

| Version | Runs | Coverage | Failures |
|---|---|---|---|
| Baseline | 265,657 | 1287 | None |
| Paid tier | 163,573 | 1267 | None |
| Security-aware | 284,240 | 1294 | None |
| Self-fixed | 262,852 | 1304 | None |

No `crash-*` files were produced. Coverage was the same as in the 30-second dry run, so it stopped growing early. Security-aware's `atheris.log` is about 34,600 lines because the app logs every rejected transfer; it contains no errors. Logs are in `results/<version>/atheris.log`.

## First attempt

`first-attempt/` holds an earlier harness (`fuzz.py`) and its log. It is kept as a lesson learned but **not valid as a result**: it never instrumented the code, and its requests never got past CSRF and login. See section 8 of `results/findings.md`.
