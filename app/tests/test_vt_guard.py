"""VirusTotal must only ever receive GET lookups: never a file upload."""
import asyncio
import inspect

import httpx
import pytest

from tgviewer import vt


def _client(seen: list):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path))
        return httpx.Response(404)
    return vt.VTClient("test-key", min_interval=0, transport=httpx.MockTransport(handler))


def test_allowed_lookups_are_get_only():
    seen: list = []
    c = _client(seen)
    assert asyncio.run(c.file("a" * 64)) is None
    assert asyncio.run(c.url("https://example.com/")) is None
    assert asyncio.run(c.domain("example.com")) is None
    assert [m for m, _ in seen] == ["GET", "GET", "GET"]


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/v3/files"),
    ("POST", "/api/v3/urls"),
    ("GET", "/api/v3/files/upload_url"),
    ("PUT", "/api/v3/files/" + "a" * 64),
    ("GET", "/api/v3/intelligence/search"),
])
def test_anything_else_is_blocked(method, path):
    seen: list = []
    c = _client(seen)
    with pytest.raises(vt.VTPolicyViolation):
        asyncio.run(c._http.request(method, path, content=b"x"))
    assert seen == []  # never reached the network


def test_no_upload_code_in_client():
    source = inspect.getsource(vt)
    for forbidden in (".post(", "upload_url", "files=", "multipart"):
        assert forbidden not in source
