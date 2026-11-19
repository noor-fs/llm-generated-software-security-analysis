#!/usr/bin/env python3
"""Run the full automated test suite on every DemoBank version with identical settings.

For each version this script:
  1. creates a fresh virtual environment and installs the app's requirements
  2. runs Semgrep, Bandit and pip-audit (static checks)
  3. runs the version's own tests with pytest
  4. starts the app the way its own README says, on a fresh demo database
  5. runs the shared HTTP tests (baseline and self-fixed only, same routes)
  6. runs the session-forgery exploit
  7. runs an OWASP ZAP quick scan (spider + active scan, not logged in)
  8. stops the app and runs the Atheris fuzzer on the transfer endpoint

Results go to results/<version>/ and a summary table to results/RUN_SUMMARY.md.
Nothing under versions/ is modified.

Usage (from the repo root, on Linux or WSL):
    python3 scripts/run_all_tests.py                      # everything, all four versions
    python3 scripts/run_all_tests.py --versions baseline  # one version
    python3 scripts/run_all_tests.py --skip zap           # skip a step (semgrep, bandit, pip-audit,
                                                          #   pytest, shared-http, exploit, zap, atheris)
    python3 scripts/run_all_tests.py --fuzz-seconds 60    # short fuzz for a dry run (final runs: 1800)
"""
import argparse
import glob
import html
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / ".testrun"           # venvs, databases, temp files (git-ignored)
RESULTS = ROOT / "results"
STEPS = ["semgrep", "bandit", "pip-audit", "pytest", "shared-http", "exploit", "zap", "atheris"]

# How each version is started, exactly as its own README describes.
VERSIONS = {
    "baseline": {
        "port": 5001,
        "db_env": "DEMOBANK_DB",
        "env": {},
        "setup": [["-m", "flask", "--app", "app", "init-db"], ["-m", "flask", "--app", "app", "seed-demo"]],
        "start": ["-m", "flask", "--app", "app", "run", "--host", "127.0.0.1", "--port", "{port}"],
        "shared_http": True,
    },
    "paid-tier": {
        "port": 5003,
        "db_env": "DEMOBANK_DATABASE",
        "env": {"FLASK_APP": "run:app"},
        "setup": [["-m", "flask", "init-db"], ["-m", "flask", "seed-demo"]],
        "start": ["-m", "flask", "run", "--host", "127.0.0.1", "--port", "{port}"],
        "shared_http": False,   # different routes and field names
    },
    "security-aware": {
        "port": 5000,           # run.py hard-codes port 5000
        "db_env": "DEMOBANK_DATABASE",
        "env": {"FLASK_APP": "app.py", "DEMOBANK_SECRET_KEY": None},   # README: set a fresh secret
        "setup": [["-m", "flask", "init-db"], ["-m", "flask", "seed-demo"]],
        "start": ["run.py"],
        "shared_http": False,   # uses _csrf instead of csrf_token
    },
    "self-fixed": {
        "port": 5002,
        "db_env": "DEMOBANK_DB",
        "env": {},
        "setup": [["-m", "flask", "--app", "app", "init-db"], ["-m", "flask", "--app", "app", "seed-demo"]],
        "start": ["run_local.py", "--host", "127.0.0.1", "--port", "{port}"],
        "shared_http": True,
    },
}


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def run(cmd, out_file=None, cwd=None, env=None, timeout=None):
    """Run a command, write stdout+stderr to out_file, return exit code (or 'timeout')."""
    try:
        res = subprocess.run([str(c) for c in cmd], cwd=cwd, env=env, timeout=timeout,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        code, text = res.returncode, res.stdout
    except subprocess.TimeoutExpired as e:
        code, text = "timeout", (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
    except FileNotFoundError as e:
        code, text = "not-found", str(e)
    if out_file:
        Path(out_file).write_text(f"$ {' '.join(map(str, cmd))}\n\n{text}")
    return code


def port_open(port):
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def make_venv(path, packages, requirements=None):
    if not path.exists():
        subprocess.run([sys.executable, "-m", "venv", str(path)], check=True)
    py = path / "bin" / "python"
    subprocess.run([py, "-m", "pip", "install", "-q", "--upgrade", "pip"], check=True)
    if requirements:
        subprocess.run([py, "-m", "pip", "install", "-q", "-r", str(requirements)], check=True)
    for pkg in packages:   # one by one so a failing optional package (atheris) doesn't block the rest
        r = subprocess.run([py, "-m", "pip", "install", "-q", pkg], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if r.returncode != 0:
            log(f"   ! could not install {pkg}: {r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ''}")
    return py


def find_zap():
    if os.environ.get("ZAP_CMD"):
        return os.environ["ZAP_CMD"]
    for name in ("zap.sh", "zaproxy"):
        if shutil.which(name):
            return shutil.which(name)
    for pattern in ("/opt/zaproxy/zap.sh", "/usr/share/zaproxy/zap.sh", "/snap/bin/zaproxy",
                    str(Path.home() / "ZAP*" / "zap.sh"), str(Path.home() / "*" / "ZAP*" / "zap.sh")):
        hits = glob.glob(pattern)
        if hits:
            return hits[0]
    return None


# ----------------------------------------------------------------- summaries
def summarize_semgrep(p):
    try:
        d = json.loads(Path(p).read_text())
        return f"{len(d.get('results', []))} findings, {len(d.get('errors', []))} errors"
    except Exception:
        return "no output"


def summarize_bandit(p):
    try:
        res = json.loads(Path(p).read_text()).get("results", [])
        sev = {}
        for r in res:
            sev[r["issue_severity"]] = sev.get(r["issue_severity"], 0) + 1
        return f"{len(res)} findings" + (f" ({', '.join(f'{k.title()} {v}' for k, v in sorted(sev.items()))})" if sev else "")
    except Exception:
        return "no output"


def summarize_pip_audit(p):
    try:
        d = json.loads(Path(p).read_text())
        deps = d.get("dependencies", d)
        return f"{sum(len(x.get('vulns', [])) for x in deps)} vulnerabilities in {len(deps)} packages"
    except Exception:
        return "no output"


def summarize_junit(p):
    try:
        root = ET.parse(p).getroot()
        suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
        t = sum(int(s.get("tests", 0)) for s in suites)
        f = sum(int(s.get("failures", 0)) for s in suites)
        e = sum(int(s.get("errors", 0)) for s in suites)
        sk = sum(int(s.get("skipped", 0)) for s in suites)
        return f"{t - f - e - sk}/{t - sk} passed" + (f", {f} failed" if f else "") + (f", {e} errors" if e else "")
    except Exception:
        return "no output"


def summarize_zap(p):
    try:
        text = html.unescape(re.sub(r"<[^>]+>", "\n", Path(p).read_text(errors="replace")))
        lines = [x.strip() for x in text.splitlines() if x.strip()]
        i = lines.index("Summary of Alerts")
        counts = {}
        for risk in ("High", "Medium", "Low", "Informational"):
            j = lines.index(risk, i)
            counts[risk] = lines[j + 1]
        return ", ".join(f"{k} {v}" for k, v in counts.items())
    except Exception:
        return "no report" if not Path(p).exists() else "see report"


def summarize_atheris(p):
    try:
        t = Path(p).read_text(errors="replace")
        done = re.findall(r"#(\d+)\s+DONE\s+cov: (\d+)", t)
        failed = "AssertionError" in t or "==ERROR" in t or "Uncaught Python exception" in t
        if failed:
            return "PROPERTY VIOLATION / CRASH (see log)"
        return f"{done[-1][0]} runs, coverage {done[-1][1]}, no failures" if done else "did not finish (see log)"
    except Exception:
        return "no output"


# ----------------------------------------------------------------- per version
def test_version(name, cfg, args, tools_py):
    src = ROOT / "versions" / name
    out = RESULTS / name
    out.mkdir(parents=True, exist_ok=True)
    work = WORK / name
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    status = {}

    log(f"=== {name} ===")
    log("   creating fresh virtual environment")
    venv_py = make_venv(work / "venv", ["pytest", "requests", "flask-unsign", "atheris"], src / "requirements.txt")
    env = os.environ.copy()
    env["PATH"] = f"{work / 'venv' / 'bin'}{os.pathsep}{env['PATH']}"
    env.pop("DEMOBANK_SECRET_KEY", None)
    for k, v in cfg["env"].items():
        env[k] = v if v is not None else secrets.token_hex(32)

    with open(out / "environment.txt", "w") as f:
        f.write(f"date: {datetime.now(timezone.utc).isoformat()}\nmachine: {platform.platform()}\npython: {platform.python_version()}\n")
        f.write(f"start command: {' '.join(cfg['start'])}  (port {cfg['port']})\n")
        f.write(f"env set: {', '.join(cfg['env']) or 'none'}  (secret values not recorded)\n\n")
        f.write("--- app venv ---\n" + subprocess.run([venv_py, "-m", "pip", "freeze"], stdout=subprocess.PIPE, text=True).stdout)
        f.write("\n--- tools venv ---\n" + subprocess.run([tools_py, "-m", "pip", "freeze"], stdout=subprocess.PIPE, text=True).stdout)

    tools_bin = Path(tools_py).parent
    excludes = ["tests", "test_app.py", ".venv", "venv"]

    if "semgrep" not in args.skip:
        log("   Semgrep")
        cmd = [tools_bin / "semgrep", "scan", "--metrics=off", "--config", "p/python", "--config", "p/flask",
               "--config", "p/owasp-top-ten", "--config", ROOT / "config" / "semgrep-custom.yml"]
        for x in excludes:
            cmd += ["--exclude", x]
        cmd += ["--json", "--output", out / "semgrep.json", src]
        status["semgrep"] = run(cmd, out / "semgrep.log", timeout=1200)

    if "bandit" not in args.skip:
        log("   Bandit")
        status["bandit"] = run([tools_bin / "bandit", "-r", src, "-x", ",".join(str(src / x) for x in excludes),
                                "-f", "json", "-o", out / "bandit.json"], out / "bandit.log", timeout=600)

    if "pip-audit" not in args.skip:
        log("   pip-audit (requirements.txt)")
        status["pip-audit"] = run([tools_bin / "pip-audit", "-r", src / "requirements.txt", "-f", "json",
                                   "-o", out / "pip-audit.json"], out / "pip-audit.log", timeout=900)

    if "pytest" not in args.skip:
        log("   own tests (pytest)")
        test_env = dict(env)
        test_env[cfg["db_env"]] = str(work / "owntests.sqlite3")
        status["pytest"] = run([venv_py, "-m", "pytest", "-p", "no:cacheprovider", f"--junitxml={out / 'pytest.xml'}"],
                               out / "pytest.log", cwd=src, env=test_env, timeout=900)

    needs_server = any(s not in args.skip for s in ("shared-http", "exploit", "zap"))
    server = None
    if needs_server:
        if port_open(cfg["port"]):
            log(f"   ! port {cfg['port']} is already in use; stop whatever is running there and re-run")
            status["server"] = "port busy"
        else:
            db = work / "server.sqlite3"
            env[cfg["db_env"]] = str(db)
            for step in cfg["setup"]:
                run([venv_py] + step, work / "setup.log", cwd=src, env=env, timeout=120)
            cmd = [venv_py] + [c.format(port=cfg["port"]) for c in cfg["start"]]
            log(f"   starting app on port {cfg['port']}")
            server = subprocess.Popen(cmd, cwd=src, env=env, stdout=open(out / "server.log", "w"),
                                      stderr=subprocess.STDOUT, start_new_session=True)
            for _ in range(60):
                if port_open(cfg["port"]):
                    break
                time.sleep(0.5)
            else:
                log("   ! app did not start; see server.log")
                status["server"] = "did not start"
            url = f"http://127.0.0.1:{cfg['port']}"

            if port_open(cfg["port"]):
                if cfg["shared_http"] and "shared-http" not in args.skip:
                    log("   shared HTTP tests")
                    status["shared-http"] = run([venv_py, "-m", "pytest", "-p", "no:cacheprovider", ROOT / "tests" / "shared-http",
                                                 f"--junitxml={out / 'shared-http.xml'}"], out / "shared-http.log",
                                                cwd=ROOT, env={**env, "DEMOBANK_URL": url}, timeout=600)

                if "exploit" not in args.skip:
                    log("   session-forgery exploit")
                    with sqlite3.connect(db) as c:
                        rows = c.execute("SELECT u.id, u.username, a.account_number, a.balance_cents FROM users u "
                                         "JOIN accounts a ON a.user_id = u.id ORDER BY u.id").fetchall()
                    attacker, victim = rows[0], rows[1]
                    code = run([venv_py, ROOT / "exploit" / "session-forgery" / "forge_session.py", "--url", url,
                                "--victim-id", victim[0], "--to", attacker[2], "--amount", "500.00"],
                               work / "exploit-raw.txt", env=env, timeout=120)
                    with sqlite3.connect(db) as c:
                        after = dict(c.execute("SELECT u.id, a.balance_cents FROM users u JOIN accounts a ON a.user_id = u.id").fetchall())
                    moved = victim[3] - after[victim[0]]
                    verdict = "EXPLOITED: money moved without the victim's password" if moved > 0 else "BLOCKED: no money moved"
                    (out / "exploit.txt").write_text(
                        f"victim: {victim[1]} (id {victim[0]}), attacker account: {attacker[2]}\n"
                        f"victim balance before: {victim[3]}, after: {after[victim[0]]} (cents)\n"
                        f"RESULT: {verdict}\n\n" + (work / "exploit-raw.txt").read_text())
                    status["exploit"] = verdict.split(":")[0]

                if "zap" not in args.skip:
                    zap = find_zap()
                    if not zap:
                        log("   ! ZAP not found (set ZAP_CMD=/path/to/zap.sh); skipping ZAP")
                        status["zap"] = "not found"
                    else:
                        log("   OWASP ZAP quick scan (several minutes)")
                        zap_home = work / "zap-home"
                        status["zap"] = run([zap, "-cmd", "-dir", zap_home, "-port", "8099", "-quickurl", url,
                                             "-quickout", out / "zap.html", "-quickprogress"],
                                            out / "zap.log", timeout=3600)
                        run([zap, "-cmd", "-dir", zap_home, "-port", "8099", "-version"], out / "zap-version.txt", timeout=300)

            os.killpg(server.pid, signal.SIGTERM)
            server.wait(timeout=20)

    return status, venv_py, work


def fuzz(name, venv_py, work, seconds):
    out = RESULTS / name
    fuzz_dir = work / "fuzz"
    fuzz_dir.mkdir(exist_ok=True)
    cmd = [venv_py, ROOT / "tests" / "fuzzing" / "fuzz_transfer.py", ROOT / "versions" / name,
           f"-max_total_time={seconds}", "-print_final_stats=1"]
    env = os.environ.copy()
    env.pop("DEMOBANK_SECRET_KEY", None)
    return subprocess.Popen([str(c) for c in cmd], cwd=fuzz_dir, env=env,
                            stdout=open(out / "atheris.log", "w"), stderr=subprocess.STDOUT)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--versions", nargs="+", default=list(VERSIONS), choices=list(VERSIONS))
    ap.add_argument("--skip", nargs="*", default=[], choices=STEPS)
    ap.add_argument("--fuzz-seconds", type=int, default=1800)
    ap.add_argument("--sequential-fuzz", action="store_true", help="run fuzzers one after another instead of side by side")
    args = ap.parse_args()

    if platform.system() != "Linux":
        sys.exit("Run this on Linux or WSL (Atheris and the scripts need Linux).")
    log(f"Python {platform.python_version()} at {sys.executable}")
    WORK.mkdir(exist_ok=True)

    tools_py = None
    if not all(s in args.skip for s in ("semgrep", "bandit", "pip-audit")):
        log("setting up tools (Semgrep, Bandit, pip-audit)")
        tools_py = make_venv(WORK / "tools", ["semgrep", "bandit", "pip-audit"])
    else:
        tools_py = Path(sys.executable)

    all_status, fuzz_jobs = {}, []
    for name in args.versions:
        status, venv_py, work = test_version(name, VERSIONS[name], args, tools_py)
        all_status[name] = status
        if "atheris" not in args.skip:
            r = subprocess.run([venv_py, "-c", "import atheris"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if r.returncode != 0:
                log("   ! atheris is not installed in this venv (see runbook); skipping fuzzing")
                status["atheris"] = "not installed"
            elif args.sequential_fuzz:
                log(f"   Atheris fuzzing for {args.fuzz_seconds}s")
                fuzz(name, venv_py, work, args.fuzz_seconds).wait()
            else:
                fuzz_jobs.append((name, fuzz(name, venv_py, work, args.fuzz_seconds)))

    if fuzz_jobs:
        log(f"Atheris running for {', '.join(n for n, _ in fuzz_jobs)} side by side ({args.fuzz_seconds}s each)...")
        for name, p in fuzz_jobs:
            p.wait()
    for name in args.versions:   # keep any crash inputs as evidence
        for f in glob.glob(str(WORK / name / "fuzz" / "crash-*")):
            shutil.copy(f, RESULTS / name)

    # summary
    rows = [("Tool", *args.versions)]
    rows.append(("Semgrep", *[summarize_semgrep(RESULTS / v / "semgrep.json") for v in args.versions]))
    rows.append(("Bandit", *[summarize_bandit(RESULTS / v / "bandit.json") for v in args.versions]))
    rows.append(("pip-audit", *[summarize_pip_audit(RESULTS / v / "pip-audit.json") for v in args.versions]))
    rows.append(("Own tests", *[summarize_junit(RESULTS / v / "pytest.xml") for v in args.versions]))
    rows.append(("Shared HTTP tests", *[summarize_junit(RESULTS / v / "shared-http.xml") if VERSIONS[v]["shared_http"] else "n/a (different routes)" for v in args.versions]))
    rows.append(("Exploit", *[all_status[v].get("exploit", "not run") for v in args.versions]))
    rows.append(("OWASP ZAP", *[summarize_zap(RESULTS / v / "zap.html") for v in args.versions]))
    rows.append(("Atheris", *[summarize_atheris(RESULTS / v / "atheris.log") if (RESULTS / v / "atheris.log").exists() else all_status[v].get("atheris", "not run") for v in args.versions]))
    md = [f"# Automated test run summary\n\nRun: {datetime.now().strftime('%Y-%m-%d %H:%M')} on {platform.platform()}, Python {platform.python_version()}. "
          f"Fuzzing: {args.fuzz_seconds}s per version, {'sequential' if args.sequential_fuzz else 'side by side'}. "
          f"Skipped steps: {', '.join(args.skip) or 'none'}.\n",
          "Raw counts only: every finding still has to be checked and marked confirmed or false positive in `findings.md`.\n"]
    md.append("| " + " | ".join(rows[0]) + " |")
    md.append("|" + "---|" * len(rows[0]))
    for r in rows[1:]:
        md.append("| " + " | ".join(r) + " |")
    md.append("\n## Exit codes / status per step\n\n```\n" + json.dumps(all_status, indent=2, default=str) + "\n```\n")
    (RESULTS / "RUN_SUMMARY.md").write_text("\n".join(md))
    log(f"done. Summary: {RESULTS / 'RUN_SUMMARY.md'}")
    print("\n".join(md[2:2 + len(rows) + 1]))


if __name__ == "__main__":
    main()
