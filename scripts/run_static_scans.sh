#!/usr/bin/env bash
# Run Semgrep, Bandit, pip-audit and pytest on one version with identical settings.
# Usage (from the repo root, inside a venv with requirements + semgrep bandit pip-audit pytest):
#   scripts/run_static_scans.sh baseline
#   scripts/run_static_scans.sh self-fixed
#   scripts/run_static_scans.sh paid-tier
#   scripts/run_static_scans.sh security-aware
set -u
VERSION="${1:?Usage: scripts/run_static_scans.sh <baseline|self-fixed|paid-tier|security-aware>}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/versions/$VERSION"
OUT="$ROOT/results/$VERSION"
[ -f "$SRC/app.py" ] || { echo "No app.py in $SRC"; exit 1; }
mkdir -p "$OUT"

{
  echo "date: $(date -Iseconds)"
  python --version
  semgrep --version | sed 's/^/semgrep /'
  python -m pip freeze
} > "$OUT/environment.txt" 2>&1

# 1. Semgrep: standard registry packs + our shared custom rules (same on every version)
semgrep scan --metrics=off \
  --config p/python --config p/flask --config p/owasp-top-ten \
  --config "$ROOT/config/semgrep-custom.yml" \
  --exclude tests --exclude .venv \
  --json --output "$OUT/semgrep.json" "$SRC" > "$OUT/semgrep.log" 2>&1
echo "semgrep_exit=$?" > "$OUT/exit-codes.txt"

# 2. Bandit: all Python files except tests and venv
python -m bandit -r "$SRC" -x "$SRC/.venv,$SRC/tests,$SRC/test_app.py" \
  -f json -o "$OUT/bandit.json" > "$OUT/bandit.log" 2>&1
echo "bandit_exit=$?" >> "$OUT/exit-codes.txt"

# 3. pip-audit: declared requirements
python -m pip_audit -r "$SRC/requirements.txt" -f json -o "$OUT/pip-audit.json" > "$OUT/pip-audit.log" 2>&1
echo "pip_audit_exit=$?" >> "$OUT/exit-codes.txt"

# 4. pytest: the version's own tests
(cd "$SRC" && python -m pytest -ra --junitxml="$OUT/pytest.xml") > "$OUT/pytest.log" 2>&1
echo "pytest_exit=$?" >> "$OUT/exit-codes.txt"

echo "Done. Results in results/$VERSION/ (a non-zero exit code means findings or failures, not that the tool broke)."
cat "$OUT/exit-codes.txt"
