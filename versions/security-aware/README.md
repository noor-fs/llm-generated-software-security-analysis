# DemoBank

A fictional Flask + SQLite banking application for the university project **Security Analysis of LLM-Generated Software**. It uses virtual funds only and has no connection to any real bank or payment service.

## Requirements
- Ubuntu 22.04/24.04 (or another Linux distribution)
- Python 3.10+
- `python3-venv`

## Setup

```bash
cd demobank
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

Set a fresh secret in your shell (do not commit it):
```bash
export DEMOBANK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
```

Initialize and seed the local development database:
```bash
export FLASK_APP=app.py
flask init-db
flask seed-demo
```

Run locally:
```bash
python run.py
```
Open `http://127.0.0.1:5000`.

## Demo users
`flask seed-demo` creates these local-only test users if they do not already exist:

| Username | Password | Account number |
|---|---|---|
| alice | `DemoPass12345!` | `DBALICE000001` |
| bob | `DemoPass12345!` | `DBBOB00000002` |

Both start with $2,500.00 in fictional funds. Change demo passwords if you reuse the database. Do not seed demo users into any deployed environment.

## Reset the development database
Stop the app, then:
```bash
rm -f instance/demobank.sqlite3
flask init-db
flask seed-demo
```
This permanently deletes local demo accounts and activity. Do not use this command on data you need.

## Tests
```bash
python -m unittest discover -s tests -v
```

## Project structure
- `app.py` — routes, validation, transfer transaction workflow and CLI commands
- `security.py` — authentication helpers, CSRF validation, server-side session checks
- `db.py` — SQLite schema and connection lifecycle
- `config.py` — environment-based configuration
- `templates/` — escaped Jinja templates
- `static/css`, `static/js`, `static/img` — local interface assets
- `tests/` — basic integration tests
- `SECURITY.md` — control inventory and manual test guide

## Important notes
This is a local academic demonstration, not production banking software. Run it only on localhost unless you have reviewed and hardened the deployment configuration. For HTTPS deployments set `DEMOBANK_COOKIE_SECURE=1`, use a production WSGI server, configure a reverse proxy, and use a managed secret.
