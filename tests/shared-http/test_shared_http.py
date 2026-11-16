"""Identical HTTP checks for every DemoBank version; only demo authentication state changes."""
import os
import re
import http.cookiejar
from urllib.request import build_opener, HTTPCookieProcessor, Request
from urllib.parse import urlencode
from urllib.error import HTTPError
import pytest

BASE = os.environ.get("DEMOBANK_URL", "").rstrip("/")
pytestmark = pytest.mark.skipif(not BASE, reason="Set DEMOBANK_URL to a running authorized local demo")

@pytest.fixture
def browser():
    return build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))

def call(browser, path, data=None):
    request = Request(BASE + path, data=urlencode(data).encode() if data is not None else None)
    try:
        with browser.open(request, timeout=10) as response:
            return response.status, response.read(), response.geturl()
    except HTTPError as error:
        return error.code, error.read(), error.geturl()

def token(browser):
    status, body, _ = call(browser, "/login")
    assert status == 200
    return re.search(rb'name="csrf_token" value="([^"]+)"',body).group(1).decode()

@pytest.mark.parametrize("path", ["/", "/about", "/login", "/register", "/static/css/style.css", "/static/js/main.js", "/static/img/logo.svg", "/static/img/hero.svg", "/static/img/transfer.svg"])
def test_public_pages_and_assets(browser, path):
    assert call(browser, path)[0] == 200

@pytest.mark.parametrize("path", ["/account", "/dashboard", "/transactions", "/profile", "/settings", "/transfer", "/change-password", "/notifications"])
def test_protected_pages_redirect(browser, path):
    status, body, final = call(browser, path)
    assert status == 200 and "/login" in final


def test_missing_csrf_rejected(browser):
    assert call(browser, "/login", {"username":"alice", "password":"wrong"})[0] == 400


def test_login_private_pages_and_logout(browser):
    status, body, final = call(browser, "/login", {"csrf_token":token(browser), "username":"alice", "password":"DemoPass123!"})
    assert status == 200 and "/dashboard" in final
    for path in ("/dashboard", "/account", "/transfer", "/profile", "/settings", "/transactions"):
        status, body, final = call(browser, path)
        assert status == 200 and "/login" not in final
    status, body, _ = call(browser, "/dashboard")
    csrf = re.search(rb'name="csrf_token" value="([^"]+)"',body).group(1).decode()
    assert call(browser, "/logout", {"csrf_token":csrf})[0] == 200
    assert "/login" in call(browser, "/dashboard")[2]
