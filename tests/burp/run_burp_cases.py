#!/usr/bin/env python3
"""Send the 12 Burp test cases to every DemoBank version through Burp Suite's proxy.

Each version is started the same way as in scripts/run_all_tests.py (its README's way,
on a fresh demo database). Every request goes through Burp (default 127.0.0.1:8080), so
Burp's HTTP history records all of it, exactly as if the requests had been sent by hand.
The script also checks the result of each case itself (e.g. did money actually move?).

Before running: open Burp Suite, make sure Proxy -> Intercept is OFF, and the proxy
listener is on 127.0.0.1:8080. Run scripts/run_all_tests.py at least once first (this
script reuses its virtual environments in .testrun/).

Usage (from the repo root, Linux/WSL):
    python3 tests/burp/run_burp_cases.py                    # all four versions, through Burp
    python3 tests/burp/run_burp_cases.py --no-proxy         # dry run without Burp
    python3 tests/burp/run_burp_cases.py --versions paid-tier

Output: results/<version>/burp-cases.md (+ .json) and results/BURP_SUMMARY.md.
Nothing under versions/ is modified.
"""
import argparse
import http.cookiejar
import json
import os
import re
import secrets
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from run_all_tests import VERSIONS, WORK, RESULTS, make_venv, port_open  # noqa: E402

PASSWORDS = ("DemoPass123!", "DemoPass12345!")   # demo password differs per version
XSS = "<script>alert(1)</script>"
XSS_IMG = "<img src=x onerror=alert(1)>"
CSRF_RE = re.compile(r'name="(csrf_token|_csrf)" value="([^"]*)"')
KEY_RE = re.compile(r'name="idempotency_key" value="([^"]*)"')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class Client:
    """A browser-like session: keeps cookies, does not follow redirects, can go through a proxy."""

    def __init__(self, base, proxy):
        self.base, self.jar = base, http.cookiejar.CookieJar()
        proxies = {"http": proxy, "https": proxy} if proxy else {}
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler(proxies),
                                                  urllib.request.HTTPCookieProcessor(self.jar), NoRedirect)

    def req(self, method, path, data=None, headers=None):
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        r = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        try:
            resp = self.opener.open(r, timeout=20)
        except urllib.error.HTTPError as e:
            resp = e
        text = resp.read().decode(errors="replace")
        return resp.status if hasattr(resp, "status") else resp.code, resp.headers, text

    def get(self, path):
        return self.req("GET", path)

    def post(self, path, data):
        return self.req("POST", path, data)

    def csrf(self, page):
        m = CSRF_RE.search(page)
        return {m.group(1): m.group(2)} if m else {}

    def login(self, user, password, path="/login"):
        _, _, page = self.get(path)
        status, h, _ = self.post(path, {"username": user, "identifier": user, "password": password, **self.csrf(page)})
        loc = h.get("Location", "") or ""
        return status in (301, 302, 303) and "login" not in loc

    def form(self, path):
        """Return the hidden CSRF + idempotency fields of a form page."""
        _, _, page = self.get(path)
        fields = self.csrf(page)
        k = KEY_RE.search(page)
        if k:
            fields["idempotency_key"] = k.group(1)
        return fields, page


# ------------------------------------------------------------------ database helpers
def snapshot(db):
    with sqlite3.connect(db) as c:
        return {r[0]: r[1] for r in c.execute("SELECT a.account_number, a.balance_cents FROM accounts a")}


def users(db):
    with sqlite3.connect(db) as c:
        return c.execute("SELECT u.id, u.username, a.account_number FROM users u "
                         "JOIN accounts a ON a.user_id=u.id ORDER BY u.id").fetchall()


def moved(before, after):
    return {k: after[k] - before.get(k, 0) for k in after if after[k] != before.get(k, 0)}


# ------------------------------------------------------------------ the 12 cases
def run_cases(name, base, db, proxy, venv_py, acct_path):
    U = users(db)
    att, vic = U[0], U[1]   # attacker = first demo user (alice/alex), victim = second (bob/jordan)
    pw = {}
    for user in (att, vic):
        for p in PASSWORDS:
            if Client(base, proxy).login(user[1], p):
                pw[user[1]] = p
                break
    A, V = att[1], vic[1]
    results = []

    def add(n, case, verdict, detail):
        results.append({"n": n, "case": case, "verdict": verdict, "detail": detail})

    def logged_in(user):
        c = Client(base, proxy)
        c.login(user, pw[user])
        return c

    def transfer(c, recipient, amount, description="burp test", extra=None, key=None):
        f, _ = c.form("/transfer")
        if key is not None:
            f["idempotency_key"] = key
        data = {**f, "recipient": recipient, "amount": amount, "description": description, **(extra or {})}
        return c.post("/transfer", data), f.get("idempotency_key")

    # 1. Access without login
    c = Client(base, proxy)
    pages = ["/dashboard", acct_path, "/transactions", "/transfer", "/profile", "/settings", "/notifications", "/change-password"]
    codes = {p: c.get(p)[0] for p in pages}
    open_pages = [p for p, s in codes.items() if s == 200]
    add(1, "Access without login", "Vulnerable" if open_pages else "Blocked",
        f"open: {open_pages}" if open_pages else "all private pages redirect or refuse: " + ", ".join(f"{p} {s}" for p, s in codes.items()))

    # 2. CSRF token removed / wrong
    c = logged_in(A)
    b = snapshot(db)
    f, _ = c.form("/transfer")
    tok_name = next((k for k in f if "csrf" in k), "csrf_token")
    s1 = c.post("/transfer", {"idempotency_key": f.get("idempotency_key", ""), "recipient": vic[2], "amount": "1.00", "description": "no csrf"})[0]
    f, _ = c.form("/transfer")
    s2 = c.post("/transfer", {tok_name: "wrong-token", "idempotency_key": f.get("idempotency_key", ""), "recipient": vic[2], "amount": "1.00", "description": "bad csrf"})[0]
    m = moved(b, snapshot(db))
    add(2, "CSRF token removed / wrong", "Vulnerable" if m else "Blocked", f"no token -> HTTP {s1}, wrong token -> HTTP {s2}; money moved: {m or 'none'}")

    # 3. SQL injection
    payload = "' OR '1'='1' --"
    sqli_login = Client(base, proxy).login(payload, "x")
    c = logged_in(A)
    q = urllib.parse.urlencode({"type": "' OR 1=1--", "start": "' OR '1'='1", "from": "' OR '1'='1", "q": "' OR 1=1--"})
    s, _, body = c.get(f"/transactions?{q}")
    verdict = "Vulnerable" if sqli_login else ("Possible (server error)" if s >= 500 else "Blocked")
    add(3, "SQL injection (login, transaction filters/search)", verdict,
        f"login with {payload!r} -> {'logged in' if sqli_login else 'rejected'}; filters/search -> HTTP {s}")

    # 4. Stored XSS (transfer description, profile name)
    c = logged_in(A)
    transfer(c, vic[2], "1.00", description=XSS)
    _, _, page = c.get("/profile")
    form = dict(re.findall(r'name="([a-z_]+)"[^>]*value="([^"]*)"', page))
    form.update(c.csrf(page))
    form["full_name"] = XSS_IMG
    ps = c.post("/profile", form)[0]
    hits = []
    for who, cl in ((A, c), (V, logged_in(V))):
        for p in ("/transactions", "/dashboard", "/profile", "/notifications"):
            body = cl.get(p)[2]
            if XSS in body or XSS_IMG in body:
                hits.append(f"{who}:{p}")
    add(4, "Stored XSS (description, profile name)", "Vulnerable" if hits else "Blocked",
        f"payload shown unescaped on {hits}" if hits else f"payloads stored but shown escaped (profile update HTTP {ps})")

    # 5. Negative / odd amounts
    c = logged_in(A)
    total0 = sum(snapshot(db).values())
    rows, problem = [], False
    for amt in ["-500", "0", "0.001", "1e3", "NaN", "Infinity", "99999999", "1,000"]:
        b = snapshot(db)
        transfer(c, vic[2], amt)
        a = snapshot(db)
        m = moved(b, a)
        bad = (m.get(att[2], 0) > 0) or min(a.values()) < 0 or sum(a.values()) != total0
        problem |= bad
        rows.append(f"{amt}: {'moved ' + str(m) if m else 'rejected'}{' <- PROBLEM' if bad else ''}")
    add(5, "Negative / odd amounts", "Vulnerable" if problem else "Blocked", "; ".join(rows))

    # 6. Transfer from someone else / view their account (IDOR)
    c = logged_in(A)
    b = snapshot(db)
    extra = {"sender": vic[2], "from_account": vic[2], "sender_account": vic[2], "account_id": vic[0], "user_id": vic[0]}
    transfer(c, att[2], "1.00", extra=extra)
    m = moved(b, snapshot(db))
    stolen = m.get(vic[2], 0) < 0
    seen = []
    for p in (f"{acct_path}?id={vic[0]}", f"{acct_path}?account={vic[2]}", f"/transactions?user_id={vic[0]}",
              f"/transactions?account={vic[2]}"):
        plain = c.get(p.split("?")[0])[2]     # same page without the parameter
        if c.get(p)[2].count(vic[2]) > plain.count(vic[2]):
            seen.append(p)
    add(6, "Transfer from / view another user's account (IDOR)", "Vulnerable" if stolen or seen else "Blocked",
        f"tampered sender fields -> money moved: {m or 'none'}; victim data via URL params: {seen or 'no'}")

    # 7. Replay with the same idempotency key
    c = logged_in(A)
    b = snapshot(db)
    (_, _, _), key = transfer(c, vic[2], "1.00", description="replay")
    transfer(c, vic[2], "1.00", description="replay", key=key)
    transfer(c, vic[2], "2.00", description="replay", key=key)
    m = moved(b, snapshot(db))
    count = -m.get(att[2], 0) // 100 if m else 0
    add(7, "Replay (same idempotency key x3)", "Vulnerable" if count > 1 else "Blocked",
        f"3 submissions with one key -> QAR {count} left the sender (1 expected if only the first counted)")

    # 8. Old session still valid after password change
    c2 = logged_in(V)                      # older session ("other browser")
    c1 = logged_in(V)                      # newer session that changes the password
    before = c2.get("/dashboard")[0]
    f, page = c1.form("/change-password")
    new_pw = "NewDemoPass123!x"
    c1.post("/change-password", {**f, "current_password": pw[V], "new_password": new_pw, "confirm_password": new_pw})
    changed = Client(base, proxy).login(V, new_pw)
    after = c2.get("/dashboard")[0]
    if before != 200:
        add(8, "Session after password change", "Blocked",
            f"only one session allowed: logging in again already ended the older session (/dashboard HTTP {before}); password changed: {changed}")
    elif not changed:
        add(8, "Session after password change", "Not tested", "password change did not succeed (see Burp history)")
    else:
        add(8, "Session after password change", "Vulnerable" if after == 200 else "Blocked",
            f"other browser's session after the change -> /dashboard HTTP {after}")

    # 9. Session forgery (hard-coded secret key)
    b = snapshot(db)
    env = {**os.environ, "HTTP_PROXY": proxy or "", "http_proxy": proxy or "", "NO_PROXY": "", "no_proxy": ""}
    env["PATH"] = f"{Path(venv_py).parent}{os.pathsep}{env['PATH']}"
    out = subprocess.run([str(venv_py), str(ROOT / "exploit" / "session-forgery" / "forge_session.py"), "--url", base,
                          "--victim-id", str(vic[0]),
                          "--to", att[2], "--amount", "5.00"], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60)
    m = moved(b, snapshot(db))
    add(9, "Session forgery (exploit script)", "Vulnerable" if m else "Blocked",
        f"money moved: {m}" if m else (out.stdout.strip().splitlines() or ["no output"])[-1])

    # 10. Open redirect after login
    hits, locs = [], []
    for target in ("https://evil.example/", "//evil.example/", "/\\evil.example/"):
        cl = Client(base, proxy)
        path = "/login?next=" + urllib.parse.quote(target, safe="")
        _, _, page = cl.get(path)
        s, h, _ = cl.post(path, {"username": A, "identifier": A, "password": pw[A], **cl.csrf(page)})
        loc = h.get("Location", "") or ""
        dest = urllib.parse.urlparse(urllib.parse.urljoin(base + "/", loc.replace("\\", "/")))
        locs.append(f"{target} -> {loc}")
        if dest.hostname not in ("127.0.0.1", "localhost"):
            hits.append(f"{target} -> {loc}")
    add(10, "Open redirect after login", "Vulnerable" if hits else "Blocked",
        f"redirected off-site: {hits}" if hits else "stayed on the site: " + "; ".join(locs))

    # 11. Brute force (30 wrong passwords, then the right one)
    cl = Client(base, proxy)
    codes, limited = [], False
    for i in range(30):
        _, _, page = cl.get("/login")
        s, _, body = cl.post("/login", {"username": A, "identifier": A, "password": f"Wrong-{i}", **cl.csrf(page)})
        codes.append(s)
        limited |= s == 429 or bool(re.search(r"too many|locked|try again later", body, re.I))
    ok = Client(base, proxy).login(A, pw[A])
    verdict = "Vulnerable (no rate limit)" if ok and not limited else "Blocked (rate limit / lockout)"
    add(11, "Brute force (30 wrong passwords)", verdict,
        f"wrong-password responses: {sorted(set(codes))}; limit message seen: {limited}; correct password afterwards: {'accepted' if ok else 'refused'}")

    # 12. Security headers and cookie flags (logged in)
    cl = Client(base, proxy)
    _, _, page = cl.get("/login")
    s, h, _ = cl.post("/login", {"username": V, "identifier": V, "password": new_pw if changed else pw[V], **cl.csrf(page)})
    cookie = h.get("Set-Cookie", "") or ""
    _, h2, _ = cl.get("/dashboard")
    want = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]
    missing = [x for x in want if not h2.get(x)] + [f"cookie {f}" for f in ("HttpOnly", "SameSite") if f.lower() not in cookie.lower()]
    add(12, "Security headers / cookie flags (logged in)", "Vulnerable" if missing else "Blocked",
        f"missing: {missing or 'none'}; Server: {h2.get('Server')}; Set-Cookie flags: {'; '.join(p.strip() for p in cookie.split(';')[1:]) or 'n/a'}")
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--versions", nargs="+", default=list(VERSIONS), choices=list(VERSIONS))
    ap.add_argument("--proxy", default="http://127.0.0.1:8080")
    ap.add_argument("--no-proxy", action="store_true", help="send directly, without Burp (dry run)")
    args = ap.parse_args()
    proxy = None if args.no_proxy else args.proxy
    # Clear proxy settings from the environment so every request goes exactly where we say
    # (a NO_PROXY entry for 127.0.0.1 would otherwise send requests around Burp).
    for k in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
        os.environ.pop(k, None)
    if proxy:
        host, port = urllib.parse.urlparse(proxy).hostname, urllib.parse.urlparse(proxy).port
        with socket.socket() as s:
            if s.connect_ex((host, port)) != 0:
                sys.exit(f"Burp is not listening on {proxy}. Open Burp (Proxy -> Intercept OFF) or use --no-proxy.")

    summary = {}
    for name in args.versions:
        cfg = VERSIONS[name]
        src, work, out = ROOT / "versions" / name, WORK / name, RESULTS / name
        out.mkdir(parents=True, exist_ok=True)
        venv_py = work / "venv" / "bin" / "python"
        if not venv_py.exists():
            print(f"[{name}] creating virtual environment")
            venv_py = make_venv(work / "venv", ["requests", "flask-unsign"], src / "requirements.txt")
        if port_open(cfg["port"]):
            sys.exit(f"Port {cfg['port']} is busy; stop whatever is running there.")
        env = {**os.environ, "PATH": f"{venv_py.parent}{os.pathsep}{os.environ['PATH']}"}
        env.pop("DEMOBANK_SECRET_KEY", None)
        for k, v in cfg["env"].items():
            env[k] = v if v is not None else secrets.token_hex(32)
        db = work / "burp.sqlite3"
        for p in (db, Path(str(db) + "-wal"), Path(str(db) + "-shm")):
            p.unlink(missing_ok=True)
        env[cfg["db_env"]] = str(db)
        for step in cfg["setup"]:
            subprocess.run([str(venv_py)] + step, cwd=src, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        server = subprocess.Popen([str(venv_py)] + [c.format(port=cfg["port"]) for c in cfg["start"]], cwd=src, env=env,
                                  stdout=open(work / "burp-server.log", "w"), stderr=subprocess.STDOUT, start_new_session=True)
        try:
            for _ in range(60):
                if port_open(cfg["port"]):
                    break
                time.sleep(0.5)
            base = f"http://127.0.0.1:{cfg['port']}"
            print(f"[{name}] running 12 cases against {base}" + (f" via {proxy}" if proxy else " (no proxy)"))
            acct = "/accounts" if name == "paid-tier" else "/account"
            res = run_cases(name, base, db, proxy, venv_py, acct)
        finally:
            os.killpg(server.pid, signal.SIGTERM)
            server.wait(timeout=20)
        summary[name] = res
        (out / "burp-cases.json").write_text(json.dumps(res, indent=2))
        md = [f"# Burp test cases: {name}\n", f"Run {datetime.now():%Y-%m-%d %H:%M}, {base}, " +
              (f"through Burp proxy {proxy}." if proxy else "without proxy (dry run)."), "",
              "| # | Case | Result | Details |", "|---|---|---|---|"]
        md += [f"| {r['n']} | {r['case']} | {r['verdict']} | {r['detail'].replace('|', '/')} |" for r in res]
        (out / "burp-cases.md").write_text("\n".join(md) + "\n")
        for r in res:
            print(f"   {r['n']:>2}. {r['case']:<50} {r['verdict']}")

    names = list(summary)
    lines = ["# Burp test cases: summary\n", f"Run {datetime.now():%Y-%m-%d %H:%M}, " +
             (f"through Burp proxy {proxy}. Burp's HTTP history holds every request (port = version: "
              + ", ".join(f"{VERSIONS[n]['port']} {n}" for n in names) + ")." if proxy else "without proxy (dry run)."),
             "Details per version: `results/<version>/burp-cases.md`.\n",
             "| # | Case | " + " | ".join(names) + " |", "|---|---|" + "---|" * len(names)]
    for i in range(12):
        lines.append(f"| {i + 1} | {summary[names[0]][i]['case']} | " + " | ".join(summary[n][i]["verdict"] for n in names) + " |")
    (RESULTS / "BURP_SUMMARY.md").write_text("\n".join(lines) + "\n")
    print(f"\nSummary: {RESULTS / 'BURP_SUMMARY.md'}")


if __name__ == "__main__":
    main()
