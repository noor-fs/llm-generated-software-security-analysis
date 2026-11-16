# DemoBank V2 security remediation record

## V1 evidence supplied with the project

### Bandit
- Two medium-severity B608 findings at `app.py:228` and `app.py:336`.
- Both are dynamic construction of placeholder lists for SQLite `IN` clauses. The bound account IDs are passed separately as query parameters. These reports alone do not establish SQL injection.

### Semgrep
- One custom warning at `app.py:228` for the same dynamic SQL construction. The rule message itself says to review the construction and not classify it as SQL injection without tracing inputs. Only `app.py` is listed as scanned in the supplied report.

### pip-audit
- Seven dependencies were listed and no known advisories were reported in the supplied JSON. This is a point-in-time dependency result, not a source-code security result.

### OWASP ZAP
- Report generated 17 October 2026 against `http://127.0.0.1:5001`.
- 2 Medium: CSP header missing; anti-clickjacking header missing.
- 2 Low: Server version disclosure; X-Content-Type-Options missing.
- 3 Informational: authentication request identification, session management response identification, and a user-controllable HTML attribute hotspot (potential XSS). Informational alerts are not confirmed vulnerabilities.
- The report's crawl shows a limited set of unauthenticated endpoints. It does not establish authenticated coverage of every transfer/profile/notification route.

### Burp Suite Community
- `reports/V1/burp_history` is a Burp Proxy HTTP history XML export with 26 entries (22 GET and 4 POST). It is not a scanner findings report. A history export alone cannot prove that an authorization bypass, injection, or other attack succeeded or failed.

## V2 code changes

| V1 observation | V2 change | Verification required |
|---|---|---|
| Missing CSP | Same-origin restrictive CSP; no inline script/style allowances | Re-run ZAP; check every page and asset still renders |
| Missing anti-clickjacking protection | CSP `frame-ancestors 'none'` and `X-Frame-Options: DENY` | Re-run ZAP |
| Server header disclosure | WSGI middleware removes upstream `Server` headers; `run_local.py` uses a custom request handler that emits generic `Server: DemoBank` | Inspect response headers and re-run ZAP |
| Missing nosniff | `X-Content-Type-Options: nosniff` | Re-run ZAP |
| Dynamic SQL placeholder-list warnings | Fixed SQL predicates scoped by authenticated user ID and bound parameters | Re-run Bandit and Semgrep |
| Predictable fallback secret | Random local fallback; explicit secret required in production | Verify production startup fails without secret |
| Transfer parser accepts arbitrary input length | Bound raw amount string before Decimal parsing | Run transfer validation tests and fuzz if desired |
| Debug default enabled | Debug disabled unless explicitly enabled | Inspect startup configuration |

## Important limits

- The ZAP XSS hotspot was not treated as a confirmed XSS vulnerability. Templates continue to use Jinja autoescaping; manually test reflected/stored payloads in all user-controlled fields.
- The app has no profile-picture upload or admin panel routes/forms in the supplied V1 source. They were not invented or added to V2, to preserve a fair baseline.
- The schema and table relationships were not changed. Existing V1 databases should not be copied over the V2 database automatically; each version uses a separate SQLite file.
- A fresh random development secret is generated when `DEMOBANK_SECRET_KEY` is unset. This invalidates sessions on process restart. Set a persistent secret when you need persistent sessions.
- V2 has not been independently scanned by ZAP/Burp/Bandit/Semgrep/pip-audit in this build environment. Retest it before claiming findings were resolved.
