# DemoBank — Start Here

This package organizes the files you provided into two separate projects: `DemoBank_V1` and `DemoBank_V2`. The 23 V1 files were moved to the expected Flask locations (`templates/` and `static/`) without changing their file bytes. Refer to `V1_SHA256.json` for verification.

## Running V1

```
cd DemoBank_V1
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m flask --app app init-db
python -m flask --app app seed-demo
python -m flask --app app run --host 127.0.0.1 --port 5001
```

## Running V2

```
cd DemoBank_V2
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m flask --app app init-db
python -m flask --app app seed-demo
python -m flask --app app run --host 127.0.0.1 --port 5002
```

Demo accounts: `alice`, `bob`, or `charlie`. The password is `DemoPass123!`. Do not use real credentials. Keep the V1 and V2 databases separate, and do not reinitialize an existing database before confirming that it can safely be deleted.

## What Has Not Yet Been Verified

- The provided application files do not contain routes or forms for profile picture uploads or an admin panel, although these features are mentioned in the proposal. I have not added them because doing so would change the V1 baseline or imply a level of equivalence that has not been established. See `SIDE_NOTES_AR.md` for details.
- The attached V2 report records 15 successful tests and two tests skipped because Flask was unavailable. This is a previous result, not a new test run performed during this session.
- WSL is not installed, but the Ubuntu virtual machine in VirtualBox was used instead. The temporary project share is visible inside the virtual machine, but its current permissions allow access only to `root` and the `vboxsf` group. The `meow` user could not read it. The share needs to be mounted with the correct user permissions before the project can be copied and run.
- Bandit, Semgrep, pip-audit, ZAP, Burp, and Atheris must be installed, run, and their results documented. `NOT_RUN` must not be treated as a clean security result.

The accompanying technical details are stored in `DemoBank_V2/docs/` and `DemoBank_V2/reports/`.
