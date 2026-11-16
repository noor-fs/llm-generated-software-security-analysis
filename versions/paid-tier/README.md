# DemoBank

A complete local-only, fictional banking web app for the university project **Security Analysis of LLM-Generated Software**. Built using Python, Flask, SQLite, Jinja HTML templates, CSS, JavaScript and original local SVG illustrations.

**No real money, banks or payment processing.** Never enter real banking credentials or deploy this academic demonstration for public use without an independent security review.

## Ubuntu setup (Python 3.10+)

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip -y
unzip DemoBank.zip  # only if working from the zip
cd DemoBank
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=run:app
flask init-db
flask seed-demo
flask run --host 127.0.0.1 --port 5000
```

Visit **http://127.0.0.1:5000**. All links and graphics are served locally. For production-like runs, set a persistent random `DEMOBANK_SECRET_KEY` in your environment (do not commit it). Without it, the application uses a new random key per process, so sessions end when the server restarts.

### Demo accounts (seed data only)

| Username | Email | Password | Starting virtual balance |
|---|---|---|---|
| alex | alex@demo.local | DemoPass123! | 1,250.00 VC |
| jordan | jordan@demo.local | DemoPass123! | 890.00 VC |
| taylor | taylor@demo.local | DemoPass123! | 1,575.00 VC |

Log into `alex`, transfer e.g. `25.50` credits to `jordan`, and inspect both accounts and transaction histories. New registered accounts start with **0 VC**; use seeded accounts to demonstrate transfers.

### Run tests

```bash
pytest -q
```

Tests use isolated temporary SQLite files and do not affect the development database.

### Reset the development database

**Destructive: permanently deletes all local DemoBank accounts, virtual balances and transactions. Do not use for a database you care about.** Stop the running app, then:

```bash
export FLASK_APP=run:app
export DEMOBANK_ALLOW_RESET=1
flask reset-db
flask seed-demo
```

`DEMOBANK_DATABASE=/absolute/path/to/file.sqlite3` changes the location of the active database. The default file is `instance/demobank.sqlite3` and is ignored by Git. Test fixtures use separate temporary files.

## Project structure

- `demobank/__init__.py`: application factory, routes, auth, validation and transfer handling
- `demobank/db.py`: schema, connection and notifications
- `demobank/templates/`: Jinja pages and reusable elements
- `demobank/static/css/`: responsive stylesheet
- `demobank/static/js/`: menu, copy, transfer confirmation
- `demobank/static/img/`: original SVG logo and illustrations
- `tests/`: automated application tests
- `run.py`: local application entry point
- `SECURITY.md`: security design, threat model, known limitations and test suggestions

## Use and limitations

- **Virtual credits** are stored in integer cents; 100 cents = 1 VC.
- Transfers only work between DemoBank accounts and are recorded permanently.
- Each request is bound to the authenticated session; no authorization is delegated to user-submitted account IDs.
- There is no administrative funding UI: the `seed-demo` command creates pre-funded virtual demo accounts.
- There is no password recovery/email verification or actual email sending; this is a local teaching project.
- Sessions are cookie-based and use Flask's cryptographic signing. Use a persistent secret key for repeatable sessions.
- Data is held only in local SQLite; the app does not use remote APIs for essential features.
