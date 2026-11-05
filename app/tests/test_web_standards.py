"""OWASP Secure Headers, generic errors, rate limiting, RFC 9116 (no database needed)."""
import asyncio

import httpx

from tgviewer.main import app, login_limiter
from tgviewer.ratelimit import RateLimiter

H = {"X-TGV": "1"}


def request(method: str, path: str, **kw) -> httpx.Response:
    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            return await c.request(method, path, **kw)
    return asyncio.run(go())


def test_secure_headers_on_every_response():
    for path in ("/", "/admin", "/static/app.js", "/healthz", "/nope"):
        h = request("GET", path).headers
        assert "default-src 'self'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
        assert h["x-content-type-options"] == "nosniff"
        assert h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer"
        assert h["cross-origin-opener-policy"] == "same-origin"
        assert h["cross-origin-resource-policy"] == "same-origin"
        assert h["x-permitted-cross-domain-policies"] == "none"
        assert "camera=()" in h["permissions-policy"] and "payment=()" in h["permissions-policy"]
        assert "server" not in h
        assert "access-control-allow-origin" not in h  # no CORS


def test_no_caching_of_pages_and_api():
    for path in ("/", "/admin", "/api/me"):
        assert request("GET", path).headers["cache-control"] == "no-store"
    # Scripts and styles are revalidated, so an update is never hidden by a cached copy.
    for path in ("/static/app.js", "/static/i18n.js", "/static/style.css"):
        assert request("GET", path).headers["cache-control"] == "no-cache"


def test_validation_errors_are_generic():
    r = request("POST", "/api/login", headers={**H, "Content-Type": "application/json"}, content=b'{"username":')
    assert r.status_code == 422 and r.json() == {"detail": "Invalid request"}


def test_security_txt_not_served_without_contact():
    assert request("GET", "/.well-known/security.txt").status_code == 404


def test_rate_limiter_window():
    rl = RateLimiter(max_requests=3, window=60)
    assert [rl.allow("1.2.3.4") for _ in range(4)] == [True, True, True, False]
    assert rl.allow("5.6.7.8")  # other addresses unaffected


def test_login_rate_limit_per_ip():
    login_limiter.reset()
    body = {"username": "nobody-ratelimit", "password": "x"}
    codes = [request("POST", "/api/login", headers=H, json=body).status_code for _ in range(login_limiter.max_requests + 1)]
    assert set(codes[:-1]) == {401} and codes[-1] == 429
    login_limiter.reset()


def test_version_is_public_and_minimal():
    r = request("GET", "/api/version")
    assert r.status_code == 200 and set(r.json()) == {"version"}
