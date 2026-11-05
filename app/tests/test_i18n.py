"""English / Ukrainian: server messages follow the tgv_lang cookie or Accept-Language; Telegram code delivery info."""
import asyncio
import re
from pathlib import Path
from types import SimpleNamespace

import httpx

from tgviewer import i18n
from tgviewer.main import app
from tgviewer.telegram import code_info

H = {"X-TGV": "1"}
STATIC = Path(__file__).parents[1] / "tgviewer" / "static"


def request(method: str, path: str, **kw) -> httpx.Response:
    async def go():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1") as c:
            return await c.request(method, path, **kw)
    return asyncio.run(go())


def test_errors_in_ukrainian_by_cookie_and_header():
    assert request("GET", "/api/me").json()["detail"] == "Not logged in"
    assert request("GET", "/api/me", cookies={"tgv_lang": "uk"}).json()["detail"] == "Ви не ввійшли"
    assert request("GET", "/api/me", headers={"Accept-Language": "uk-UA,uk;q=0.9,en;q=0.8"}).json()["detail"] == "Ви не ввійшли"
    # the cookie (the switch) wins over the browser language
    r = request("GET", "/api/me", cookies={"tgv_lang": "en"}, headers={"Accept-Language": "uk"})
    assert r.json()["detail"] == "Not logged in"


def test_localized_errors_keep_security_headers_and_length():
    r = request("POST", "/api/login", headers={**H, "Content-Type": "application/json"}, content=b'{"username":',
                cookies={"tgv_lang": "uk"})
    assert r.status_code == 422 and r.json() == {"detail": "Некоректний запит"}
    assert r.headers["x-content-type-options"] == "nosniff" and "default-src 'self'" in r.headers["content-security-policy"]
    assert int(r.headers["content-length"]) == len(r.content)


def test_patterns_and_unknown_texts():
    assert i18n.tr("File is larger than 100 MB", "uk") == "Файл більший за 100 МБ"
    assert i18n.tr("Wrong username or password (after 5 failed attempts, wait 15 minutes)", "uk").startswith("Невірне ім'я")
    assert i18n.tr("Telegram: PHONE_NUMBER_INVALID", "uk") == "Telegram: PHONE_NUMBER_INVALID"  # unknown stays as is
    assert i18n.tr("Not logged in", "en") == "Not logged in"


def test_every_server_message_has_a_translation():
    """Every literal HTTPException / JSON error text in the code is in the Ukrainian table (or a pattern)."""
    src = "\n".join(p.read_text(encoding="utf-8") for p in (Path(i18n.__file__).parent).rglob("*.py"))
    texts = set(re.findall(r'HTTPException\(\d+, "([^"]+)"', src)) | set(re.findall(r'\{"detail": "([^"]+)"', src))
    missing = [x for x in texts if i18n.tr(x, "uk") == x]
    assert not missing, missing


def test_frontend_keys_exist_in_both_languages():
    js = (STATIC / "i18n.js").read_text(encoding="utf-8")
    en_block, uk_block = js.split("\n  uk: {", 1)
    key = re.compile(r'"([a-z_]+\.[a-z0-9_.\-]+)":')
    en, uk = set(key.findall(en_block)), set(key.findall(uk_block.split("\n};", 1)[0]))
    assert en == uk, (en ^ uk)
    used = set()
    for name in ("index.html", "app.js"):
        text = (STATIC / name).read_text(encoding="utf-8")
        used |= set(re.findall(r'data-i18n(?:-ph|-title|-alt|-policy)?="([^"]+)"', text))
        used |= set(re.findall(r'\bt\("([a-z_]+\.[a-z0-9_.\-]+)"', text))
    used = {k for k in used if not k.endswith(".")}  # prefixes completed at runtime, e.g. "link.sent." + type
    assert used <= en, used - en
    for prefix, variants in (("link.sent.", "app sms call email email_setup fragment other"), ("link.resend.", "sms call fragment"),
                             ("status.", "scanning clean suspicious blocked malicious error too_large expired sent ready warn dlp_blocked")):
        assert {prefix + v for v in variants.split()} <= en


def test_code_info_tells_where_the_code_went():
    def sent(kind, nxt=None, timeout=None):
        typ = type("SentCodeType" + kind, (), {})()
        nt = type("CodeType" + nxt, (), {})() if nxt else None
        return SimpleNamespace(type=typ, next_type=nt, timeout=timeout)
    assert code_info(sent("App", "Sms", 60)) == {"sent_to": "app", "next": "sms", "timeout": 60}
    assert code_info(sent("Sms")) == {"sent_to": "sms", "next": None, "timeout": None}
    assert code_info(sent("FlashCall", "Call"))["sent_to"] == "call"
    assert code_info(sent("SomethingNew"))["sent_to"] == "other"


def test_gate_page_language():
    # Without a session /go redirects to the login page in any language.
    assert request("GET", "/go/x", cookies={"tgv_lang": "uk"}).status_code == 303


def test_qr_status_waits_and_reports_rounds():
    from datetime import datetime, timedelta, timezone
    from tgviewer.telegram import _Pending, tg

    async def go():
        fut = asyncio.get_running_loop().create_future()
        qr = SimpleNamespace(expires=datetime.now(timezone.utc) + timedelta(seconds=0.2), url="tg://login?token=x")
        p = _Pending(client=None, phone="", phone_code_hash="", qr=qr, qr_round=2, qr_task=fut)
        tg._pending[999] = p
        try:
            first = await tg.qr_status(999, wait=0.5)   # not scanned yet
            fut.set_result("done")
            second = await tg.qr_status(999, wait=0.5)
            return first, second, tg.qr_url(999)
        finally:
            tg._pending.pop(999, None)
    first, second, url = asyncio.run(go())
    assert first == {"next": "waiting", "round": 2}
    assert second == {"next": "done", "round": 2}
    assert url.startswith("tg://login")


def test_consent_must_match_the_current_terms():
    from datetime import timedelta
    from tgviewer.deps import AGREEMENT_DATE, has_consent
    assert not has_consent(SimpleNamespace(consent_at=None))
    assert not has_consent(SimpleNamespace(consent_at=AGREEMENT_DATE - timedelta(minutes=1)))  # older text
    assert has_consent(SimpleNamespace(consent_at=AGREEMENT_DATE + timedelta(minutes=1)))
