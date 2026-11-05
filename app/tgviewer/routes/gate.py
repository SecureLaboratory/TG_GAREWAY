"""/go/<id>: the click-time link gate. Re-checks the link, then redirects,
warns or blocks. The visit itself goes from the user's browser."""
from html import escape

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import i18n, stats
from ..deps import ADMIN_NO_TELEGRAM, get_db, optional_user
from ..links import recheck
from ..models import Link, User

router = APIRouter()

TEXT = {
    "en": {
        "na": "Not available", "notfound": "Link not found", "expired": "It may have expired.",
        "blocked_title": "Link blocked", "blocked": "⛔ This link is blocked",
        "mistake": "If you think this is a mistake, contact the security team.",
        "check_title": "Check this link", "suspicious": "⚠️ This link looks suspicious",
        "check": "Check this link before opening", "domain": "Domain:", "why": "Why:",
        "advice": "Only continue if you expected this link and trust the sender. "
                  "It opens in a new browser tab.",
        "open": "Open anyway",
    },
    "uk": {
        "na": "Недоступно", "notfound": "Посилання не знайдено", "expired": "Можливо, термін його дії минув.",
        "blocked_title": "Посилання заблоковано", "blocked": "⛔ Це посилання заблоковано",
        "mistake": "Якщо ви вважаєте це помилкою, зверніться до служби безпеки.",
        "check_title": "Перевірте посилання", "suspicious": "⚠️ Це посилання виглядає підозріло",
        "check": "Перевірте посилання перед відкриттям", "domain": "Домен:", "why": "Чому:",
        "advice": "Продовжуйте, лише якщо ви очікували це посилання й довіряєте відправникові. "
                  "Воно відкриється в новій вкладці браузера.",
        "open": "Усе одно відкрити",
    },
}


def _page(lang: str, title: str, body: str, status: int = 200) -> HTMLResponse:
    html = (f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<meta name="referrer" content="no-referrer"><title>{escape(title)}</title>'
            f'<link rel="stylesheet" href="/static/style.css"></head>'
            f'<body class="gate"><main class="card gate-card">{body}</main></body></html>')
    return HTMLResponse(html, status_code=status)


@router.get("/go/{link_id}")
async def go(link_id: str, request: Request, confirm: int = 0, user: User | None = Depends(optional_user),
             db=Depends(get_db)):
    if user is None:
        return RedirectResponse("/", status_code=303)
    lang = i18n.pick(request)
    t = TEXT[lang]
    if user.is_admin:  # admins never open users' links (role separation)
        return _page(lang, t["na"], f"<h1>{t['na']}</h1><p>{escape(i18n.tr(ADMIN_NO_TELEGRAM, lang))}</p>", 403)
    link = await db.get(Link, link_id)
    if link is None or link.user_id != user.id:
        return _page(lang, t["notfound"], f"<h1>{t['notfound']}</h1><p>{t['expired']}</p>", 404)

    verdict, reason = await recheck(link)
    url, domain, why = escape(link.url), escape(link.domain), escape(i18n.tr(reason, lang))
    if verdict == "malicious":
        action = "blocked"
        resp = _page(lang, t["blocked_title"],
                     f'<h1 class="bad">{t["blocked"]}</h1><p class="url">{url}</p>'
                     f"<p>{why}</p><p>{t['mistake']}</p>")
    elif verdict == "clean" or confirm:
        action = "opened" if verdict == "clean" else "warned_proceeded"
        resp = RedirectResponse(link.url, status_code=303)
    else:
        action = "warned"
        heading = t["suspicious"] if verdict == "suspicious" else t["check"]
        resp = _page(lang, t["check_title"],
                     f'<h1 class="warn">{heading}</h1><p class="url">{url}</p>'
                     f"<p><b>{t['domain']}</b> {domain}<br><b>{t['why']}</b> {why}</p>"
                     f"<p>{t['advice']}</p>"
                     f'<p class="actions"><a class="btn" href="/go/{escape(link.id)}?confirm=1">{t["open"]}</a></p>')
    stats.record(db, object_type="click", user_id=user.id, chat_ref=link.chat_ref, chat_kind=link.chat_kind,
                 domain=link.domain, url=link.url, verdict=verdict, reason=reason, action=action)
    await db.commit()
    return resp
