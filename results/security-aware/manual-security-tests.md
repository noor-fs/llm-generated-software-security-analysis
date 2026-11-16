# DemoBank V3 – Manual Security Tests

**Experiment:** Security-Aware Prompt (ChatGPT Free)  
**Environment:** Local Flask Application – 127.0.0.1:5003  
**Tools:** Chrome, PowerShell, OWASP ZAP Requester

## Test Results

| ID  | Test                                            | Observed Result                                              | Status |
| --- | ----------------------------------------------- | ------------------------------------------------------------ | ------ |
| T01 | Dashboard access without login                  | Redirected to Login                                          | PASS   |
| T02 | Transfer access without login                   | Redirected to Login                                          | PASS   |
| T03 | Browser Back after Logout                       | Login page displayed                                         | PASS   |
| T04 | Dashboard access after Logout                   | Redirected to Login                                          | PASS   |
| T05 | Login Rate Limiting                             | Temporary sign-in restriction triggered                      | PASS   |
| T06 | POST /login without CSRF token                  | HTTP 400 Bad Request                                         | PASS   |
| T07 | Authenticated POST /transfer without CSRF token | HTTP 400 Bad Request                                         | PASS   |
| T08 | Session Cookie Replay after Logout              | HTTP 200 OK; Login page displayed instead of Alice Dashboard | PASS   |

## CSRF Test Verification

An authenticated POST request was sent to `/transfer` using OWASP ZAP Requester without including the CSRF token. The server returned HTTP 400 Bad Request.

Code inspection confirmed that the global `security_and_csrf()` handler rejects requests with missing or invalid CSRF tokens before the transfer operation is processed.

## Notes

- Tests were conducted on the local DemoBank V3 application.
- The results apply only to the tested scenarios.
- Session Replay Testing is still pending.
- Automated security scan reports are stored separately.

### Session Replay Test Verification (T08)

**Objective:** Check whether an old session cookie can still access the authenticated Dashboard after logout.

**Steps Performed:**

1. Logged in as Alice through the ZAP-controlled browser.
2. Captured an authenticated `GET /dashboard` request in OWASP ZAP.
3. Opened the request in ZAP Requester.
4. Logged out of Alice's account.
5. Replayed the original request containing the old session cookie.

**Observed Result:**

- HTTP Status: `200 OK`
- Response Body: Login page
- Alice's Dashboard and account data were not displayed.

**Test Status:** PASS – No unauthorized access observed.

**Conclusion:** The replayed request did not provide access to Alice's Dashboard after logout. However, this test alone does not fully prove that the old session cookie was invalidated.
