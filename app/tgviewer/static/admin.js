"use strict";

const $ = (sel) => document.querySelector(sel);
const BAD = new Set(["malicious", "blocked"]);

// Texts of the admin page (served only through the admin entrance, like this file).
addTexts({
  en: {
    "adm.title": "TG Viewer Admin", "adm.brand": "TG Viewer admin",
    "adm.subtitle": "Users and statistics. Admin accounts can't use Telegram or see users' chats.",
    "adm.users": "Users", "adm.new_username": "new username", "adm.role_user": "User (uses Telegram)",
    "adm.role_admin": "Admin (no Telegram)", "adm.create": "Create user", "adm.temp_pw": "Temporary password:",
    "adm.temp_pw_hint": "Shown once. Give it to the user over a separate channel. They must change it at first login and set up their authenticator app then.",
    "adm.done": "Done", "adm.created": "User {u} created", "adm.new_temp": "New temporary password for {u}",
    "adm.a.reset-password": "Reset password", "adm.a.reset-2fa": "Reset 2FA", "adm.a.unlock": "Unlock",
    "adm.a.disable": "Disable", "adm.a.enable": "Enable",
    "adm.q.reset-password": "Reset the password of {u}? Their sessions end.",
    "adm.q.reset-2fa": "Remove the authenticator of {u}? They set up a new one at next login.",
    "adm.q.disable": "Disable {u}? Their sessions end and their Telegram session is revoked.",
    "adm.st.disabled": "disabled", "adm.st.active": "active", "adm.st.locked": "locked",
    "adm.st.temp": "temporary password", "adm.st.2fa_on": "2FA on", "adm.st.2fa_off": "2FA not set up",
    "adm.tg.na": "n/a", "adm.tg.linked": "linked", "adm.tg.not_linked": "not linked", "adm.you": "you",
    "adm.role.user": "user", "adm.role.admin": "admin",
    "adm.h.username": "Username", "adm.h.role": "Role", "adm.h.status": "Status", "adm.h.telegram": "Telegram",
    "adm.no_data": "No data yet",
    "adm.stats": "Statistics", "adm.period": "Period", "adm.d1": "1 day", "adm.d7": "7 days", "adm.d14": "14 days",
    "adm.d30": "30 days", "adm.d90": "90 days", "adm.per_day": "Scans per day",
    "adm.by_engine": "Detections by engine", "adm.top_domains": "Top blocked / suspicious domains",
    "adm.top_files": "Top file detections", "adm.file_types": "File types", "adm.clicks": "Link clicks",
    "adm.per_user": "Per user (counts only)", "adm.ops": "Engines & feeds",
    "adm.tile.files": "Files scanned", "adm.tile.blocked": "Files blocked", "adm.tile.held": "Files held (suspicious)",
    "adm.tile.outbound": "Outbound files", "adm.tile.links": "Links checked", "adm.tile.bad_links": "Malicious links",
    "adm.tile.latency": "Scan time p50 / p95", "adm.tile.in_flight": "Scans in progress",
    "adm.day": "{day}: {c} clean, {w} suspicious/unknown, {b} blocked",
    "adm.lg.clean": "clean", "adm.lg.warn": "suspicious / unknown", "adm.lg.bad": "blocked / error",
    "adm.h.engine": "Engine", "adm.h.flags": "Flags", "adm.h.domain": "Domain", "adm.h.verdict": "Verdict",
    "adm.h.count": "Count", "adm.h.reason": "Reason", "adm.h.type": "Type", "adm.h.action": "Action",
    "adm.h.user": "User", "adm.h.scanned": "Scanned", "adm.h.blocked": "Blocked", "adm.h.suspicious": "Suspicious",
    "adm.h.component": "Component",
    "adm.click.opened": "Opened (clean)", "adm.click.warned": "Warning shown",
    "adm.click.warned_proceeded": "Proceeded after warning", "adm.click.blocked": "Blocked",
    "adm.ops.mode": "Reputation mode", "adm.ops.feed": "Feed: {n}", "adm.ops.disabled": "disabled",
    "adm.ops.error": "error: {e}", "adm.ops.updated": "{n} entries, updated {d}", "adm.ops.never": "not downloaded yet",
  },
  uk: {
    "adm.title": "TG Viewer: адміністрування", "adm.brand": "TG Viewer: адміністрування",
    "adm.subtitle": "Користувачі та статистика. Облікові записи адміністраторів не можуть користуватися Telegram і не бачать чатів користувачів.",
    "adm.users": "Користувачі", "adm.new_username": "ім'я нового користувача", "adm.role_user": "Користувач (працює з Telegram)",
    "adm.role_admin": "Адміністратор (без Telegram)", "adm.create": "Створити користувача", "adm.temp_pw": "Тимчасовий пароль:",
    "adm.temp_pw_hint": "Показується один раз. Передайте його користувачеві окремим каналом. Під час першого входу користувач має змінити пароль і налаштувати застосунок-автентифікатор.",
    "adm.done": "Готово", "adm.created": "Користувача {u} створено", "adm.new_temp": "Новий тимчасовий пароль для {u}",
    "adm.a.reset-password": "Скинути пароль", "adm.a.reset-2fa": "Скинути 2FA", "adm.a.unlock": "Розблокувати",
    "adm.a.disable": "Вимкнути", "adm.a.enable": "Увімкнути",
    "adm.q.reset-password": "Скинути пароль користувача {u}? Його сеанси завершаться.",
    "adm.q.reset-2fa": "Видалити автентифікатор користувача {u}? Під час наступного входу він налаштує новий.",
    "adm.q.disable": "Вимкнути {u}? Його сеанси завершаться, а сеанс Telegram буде відкликано.",
    "adm.st.disabled": "вимкнено", "adm.st.active": "активний", "adm.st.locked": "заблоковано",
    "adm.st.temp": "тимчасовий пароль", "adm.st.2fa_on": "2FA увімкнено", "adm.st.2fa_off": "2FA не налаштовано",
    "adm.tg.na": "—", "adm.tg.linked": "під'єднано", "adm.tg.not_linked": "не під'єднано", "adm.you": "ви",
    "adm.role.user": "користувач", "adm.role.admin": "адміністратор",
    "adm.h.username": "Ім'я користувача", "adm.h.role": "Роль", "adm.h.status": "Стан", "adm.h.telegram": "Telegram",
    "adm.no_data": "Даних ще немає",
    "adm.stats": "Статистика", "adm.period": "Період", "adm.d1": "1 день", "adm.d7": "7 днів", "adm.d14": "14 днів",
    "adm.d30": "30 днів", "adm.d90": "90 днів", "adm.per_day": "Перевірки за днями",
    "adm.by_engine": "Виявлення за рушіями", "adm.top_domains": "Найчастіші заблоковані / підозрілі домени",
    "adm.top_files": "Найчастіші виявлення у файлах", "adm.file_types": "Типи файлів", "adm.clicks": "Переходи за посиланнями",
    "adm.per_user": "За користувачами (лише кількість)", "adm.ops": "Рушії та фіди",
    "adm.tile.files": "Перевірено файлів", "adm.tile.blocked": "Заблоковано файлів", "adm.tile.held": "Затримано файлів (підозрілі)",
    "adm.tile.outbound": "Вихідні файли", "adm.tile.links": "Перевірено посилань", "adm.tile.bad_links": "Шкідливі посилання",
    "adm.tile.latency": "Час перевірки p50 / p95", "adm.tile.in_flight": "Перевірки в процесі",
    "adm.day": "{day}: чистих {c}, підозрілих/невідомих {w}, заблокованих {b}",
    "adm.lg.clean": "чисті", "adm.lg.warn": "підозрілі / невідомі", "adm.lg.bad": "заблоковані / помилки",
    "adm.h.engine": "Рушій", "adm.h.flags": "Позначок", "adm.h.domain": "Домен", "adm.h.verdict": "Вердикт",
    "adm.h.count": "Кількість", "adm.h.reason": "Причина", "adm.h.type": "Тип", "adm.h.action": "Дія",
    "adm.h.user": "Користувач", "adm.h.scanned": "Перевірено", "adm.h.blocked": "Заблоковано", "adm.h.suspicious": "Підозрілих",
    "adm.h.component": "Компонент",
    "adm.click.opened": "Відкрито (чисте)", "adm.click.warned": "Показано попередження",
    "adm.click.warned_proceeded": "Відкрито після попередження", "adm.click.blocked": "Заблоковано",
    "adm.ops.mode": "Режим репутації", "adm.ops.feed": "Фід: {n}", "adm.ops.disabled": "вимкнено",
    "adm.ops.error": "помилка: {e}", "adm.ops.updated": "записів: {n}, оновлено {d}", "adm.ops.never": "ще не завантажено",
  },
});
// Banner and the events list.
addTexts({
  en: {
    "adm.banner_title": "🔒 Admin panel",
    "adm.banner_text": "Reachable only through the admin tunnel to the server. Admin accounts manage users and see statistics; they can't use Telegram or read chats.",
    "adm.events": "Events: logins and admin actions", "adm.ev_all": "All events", "adm.ev_failed": "Failures only",
    "adm.ev_login": "Logins only", "adm.ev_admin": "Admin actions only", "adm.ev_refresh": "Refresh",
    "adm.h.time": "Time", "adm.h.event": "Event", "adm.h.details": "Reason / details", "adm.h.ip": "IP address",
    "adm.by": "by {a}",
    "ev.auth.login": "Logged in", "ev.auth.password_ok": "Password correct, waiting for the authenticator code",
    "ev.auth.login_failed": "Login failed", "ev.auth.account_locked": "Account locked (too many failures)",
    "ev.auth.password_changed": "Password changed", "ev.auth.totp_enrolled": "Authenticator set up",
    "ev.auth.rate_limited": "Too many attempts from this address",
    "ev.admin.user_created": "User created", "ev.admin.password_reset": "Password reset by an admin",
    "ev.admin.2fa_reset": "2FA reset by an admin", "ev.admin.user_unlocked": "User unlocked",
    "ev.admin.user_disabled": "User disabled", "ev.admin.user_enabled": "User enabled",
    "why.unknown_or_disabled": "unknown username or disabled account",
    "why.bad_password": "wrong password", "why.bad_totp": "wrong authenticator code",
    "why.locked": "account is locked", "why.admin_outside_admin_channel": "admin tried to log in outside the admin entrance (not via localhost or an allowed IP)",
    "det.mfa": "second factor: {v}", "det.next": "next step: {v}", "det.role": "role: {v}", "det.path": "{v}",
  },
  uk: {
    "adm.banner_title": "🔒 Адмін-панель",
    "adm.banner_text": "Доступна лише через адмінський тунель до сервера. Облікові записи адміністраторів керують користувачами й бачать статистику; вони не можуть користуватися Telegram і не бачать чатів.",
    "adm.events": "Події: входи та дії адміністраторів", "adm.ev_all": "Усі події", "adm.ev_failed": "Лише невдалі",
    "adm.ev_login": "Лише входи", "adm.ev_admin": "Лише дії адміністраторів", "adm.ev_refresh": "Оновити",
    "adm.h.time": "Час", "adm.h.event": "Подія", "adm.h.details": "Причина / деталі", "adm.h.ip": "IP-адреса",
    "adm.by": "виконав {a}",
    "ev.auth.login": "Вхід виконано", "ev.auth.password_ok": "Пароль правильний, очікується код автентифікатора",
    "ev.auth.login_failed": "Невдалий вхід", "ev.auth.account_locked": "Обліковий запис заблоковано (забагато невдач)",
    "ev.auth.password_changed": "Пароль змінено", "ev.auth.totp_enrolled": "Автентифікатор налаштовано",
    "ev.auth.rate_limited": "Забагато спроб з цієї адреси",
    "ev.admin.user_created": "Користувача створено", "ev.admin.password_reset": "Пароль скинуто адміністратором",
    "ev.admin.2fa_reset": "2FA скинуто адміністратором", "ev.admin.user_unlocked": "Користувача розблоковано",
    "ev.admin.user_disabled": "Користувача вимкнено", "ev.admin.user_enabled": "Користувача ввімкнено",
    "why.unknown_or_disabled": "невідоме ім'я користувача або вимкнений обліковий запис",
    "why.bad_password": "невірний пароль", "why.bad_totp": "невірний код автентифікатора",
    "why.locked": "обліковий запис заблоковано", "why.admin_outside_admin_channel": "адміністратор намагався увійти не через адмінський вхід (не з localhost і не з дозволеної IP-адреси)",
    "det.mfa": "другий фактор: {v}", "det.next": "наступний крок: {v}", "det.role": "роль: {v}", "det.path": "{v}",
  },
});
applyI18n();

async function api(method, url, body) {
  const opts = { method, headers: { "X-TGV": "1" }, credentials: "same-origin" };
  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  const r = await fetch(url, opts);
  if (r.status === 401 || r.status === 403 && url.startsWith("/api/admin")) { location.replace("/"); throw new Error("not allowed"); }
  let data = null;
  try { data = await r.json(); } catch { /* empty */ }
  if (!r.ok) throw new Error((data && data.detail) || r.statusText);
  return data;
}

// ---------------------------------------------------------------- users
function showSecret(title, password) {
  $("#secret-title").textContent = title;
  $("#secret-value").textContent = password;
  $("#secret-box").classList.remove("hidden");
}

$("#secret-close").addEventListener("click", () => {
  $("#secret-value").textContent = "";
  $("#secret-box").classList.add("hidden");
});

const ACTIONS = [  // action, visible, asks for confirmation
  ["reset-password", (u) => !u.is_self, true],
  ["reset-2fa", (u) => !u.is_self && u.totp_enrolled, true],
  ["unlock", (u) => !u.is_self && u.locked, false],
  ["disable", (u) => !u.is_self && !u.disabled, true],
  ["enable", (u) => !u.is_self && u.disabled, false],
];

async function userAction(u, action, label, question) {
  if (question && !confirm(question)) return;
  try {
    const r = await api("POST", `/api/admin/users/${u.id}/${action}`);
    if (r.temporary_password) showSecret(t("adm.new_temp", { u: u.username }), r.temporary_password);
    loadUsers();
  } catch (e) { $("#error").textContent = `${label}: ${e.message}`; }
}

async function loadUsers() {
  const users = await api("GET", "/api/admin/users");
  const rows = users.map((u) => {
    const status = [u.disabled ? t("adm.st.disabled") : t("adm.st.active"), u.locked ? t("adm.st.locked") : "",
      u.must_change_password ? t("adm.st.temp") : "", u.totp_enrolled ? t("adm.st.2fa_on") : t("adm.st.2fa_off")]
      .filter(Boolean).join(", ");
    const tg = u.role === "admin" ? t("adm.tg.na") : u.telegram_linked ? t("adm.tg.linked") : t("adm.tg.not_linked");
    const actions = el("div", "row-actions");
    for (const [action, visible, asks] of ACTIONS) {
      if (!visible(u)) continue;
      const label = t("adm.a." + action);
      const b = el("button", "small", label);
      b.addEventListener("click", () => userAction(u, action, label, asks && t("adm.q." + action, { u: u.username })));
      actions.append(b);
    }
    if (u.is_self) actions.append(el("span", "muted", t("adm.you")));
    return [u.username, t("adm.role." + u.role), status, tg, actions];
  });
  table("#users", [t("adm.h.username"), t("adm.h.role"), t("adm.h.status"), t("adm.h.telegram"), ""], rows);
}

$("#new-user").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  $("#error").textContent = "";
  try {
    const r = await api("POST", "/api/admin/users", { username: f.get("username"), role: f.get("role") });
    ev.target.reset();
    showSecret(t("adm.created", { u: r.username }), r.temporary_password);
    loadUsers();
  } catch (e) { $("#error").textContent = e.message; }
});

$("#logout-btn").addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST", headers: { "X-TGV": "1" }, credentials: "same-origin" });
  location.replace("/");
});

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function table(id, headers, rows) {
  const tbl = $(id);
  tbl.replaceChildren();
  const tr = el("tr");
  headers.forEach((h) => tr.append(el("th", "", h)));
  tbl.append(tr);
  if (!rows.length) {
    const r = el("tr");
    const td = el("td", "muted", t("adm.no_data"));
    td.colSpan = headers.length;
    r.append(td);
    tbl.append(r);
  }
  for (const row of rows) {
    const r = el("tr");
    for (const cell of row) {
      if (cell instanceof Node) { const td = el("td"); td.append(cell); r.append(td); }
      else r.append(el("td", typeof cell === "number" ? "n" : "", String(cell ?? "")));
    }
    tbl.append(r);
  }
}

function bar(value, max, kind = "") {
  const b = el("div", "bar " + kind);
  b.style.width = `${max ? Math.max(2, (100 * value) / max) : 0}%`;
  return b;
}

function sum(rows, pred) { return rows.filter(pred).reduce((a, r) => a + r.count, 0); }

async function load() {
  const days = $("#days").value;
  const s = await api("GET", `/api/admin/stats?days=${days}`);
  $("#error").textContent = "";

  const files = s.totals.filter((x) => x.object_type === "file");
  const urls = s.totals.filter((x) => x.object_type === "url");
  const tiles = [
    ["adm.tile.files", sum(files, () => true)],
    ["adm.tile.blocked", sum(files, (x) => BAD.has(x.verdict))],
    ["adm.tile.held", sum(files, (x) => x.verdict === "suspicious")],
    ["adm.tile.outbound", sum(files, (x) => x.direction === "outbound")],
    ["adm.tile.links", sum(urls, () => true)],
    ["adm.tile.bad_links", sum(urls, (x) => x.verdict === "malicious")],
    ["adm.tile.latency", `${s.latency_ms.p50} / ${s.latency_ms.p95} ms`],
    ["adm.tile.in_flight", s.in_flight],
  ];
  $("#tiles").replaceChildren(...tiles.map(([key, n]) => {
    const tile = el("div", "tile");
    tile.append(el("div", "num", String(n)), el("div", "muted", t(key)));
    return tile;
  }));

  // daily stacked bars (files + urls)
  const byDay = new Map();
  for (const d of s.daily) {
    const e = byDay.get(d.day) || { clean: 0, warn: 0, bad: 0 };
    if (BAD.has(d.verdict) || d.verdict === "error") e.bad += d.count;
    else if (d.verdict === "clean") e.clean += d.count;
    else e.warn += d.count;
    byDay.set(d.day, e);
  }
  const max = Math.max(1, ...[...byDay.values()].map((e) => e.clean + e.warn + e.bad));
  const daily = $("#daily");
  daily.replaceChildren();
  for (const [day, e] of byDay) {
    const col = el("div", "day");
    col.title = t("adm.day", { day, c: e.clean, w: e.warn, b: e.bad });
    for (const [k, cls] of [["clean", "seg-clean"], ["warn", "seg-suspicious"], ["bad", "seg-bad"]]) {
      const seg = el("div", cls);
      seg.style.height = `${(140 * e[k]) / max}px`;
      col.append(seg);
    }
    daily.append(col);
  }
  $("#legend").replaceChildren(...[["seg-clean", "adm.lg.clean"], ["seg-suspicious", "adm.lg.warn"], ["seg-bad", "adm.lg.bad"]]
    .map(([c, key]) => { const sp = el("span"); const i = el("i", c); sp.append(i, t(key)); return sp; }));

  const emax = Math.max(1, ...s.engines.map((e) => e.count));
  table("#engines", [t("adm.h.engine"), t("adm.h.flags"), ""], s.engines.map((e) => [e.engine, e.count, bar(e.count, emax, "warn")]));
  table("#domains", [t("adm.h.domain"), t("adm.h.verdict"), t("adm.h.count")], s.top_domains.map((d) => [d.domain, d.verdict, d.count]));
  table("#detections", [t("adm.h.reason"), t("adm.h.count")], s.detections.map((d) => [d.reason, d.count]));
  const tmax = Math.max(1, ...s.file_types.map((x) => x.count));
  table("#types", [t("adm.h.type"), t("adm.h.count"), ""], s.file_types.map((x) => [x.type, x.count, bar(x.count, tmax)]));
  const clickLabel = (a) => (["opened", "warned", "warned_proceeded", "blocked"].includes(a) ? t("adm.click." + a) : a);
  table("#clicks", [t("adm.h.action"), t("adm.h.count")], s.clicks.map((c) => [clickLabel(c.action), c.count]));
  table("#per-user", [t("adm.h.user"), t("adm.h.scanned"), t("adm.h.blocked"), t("adm.h.suspicious")],
    s.per_user.map((u) => [u.username, u.scanned, u.blocked, u.suspicious]));

  const ops = s.ops;
  const rows = [["ClamAV", ops.clamav], ["YARA", ops.yara], [t("adm.ops.mode"), ops.reputation_mode], ["VirusTotal", ops.virustotal]];
  for (const f of ops.feeds) {
    const state = !f.enabled ? t("adm.ops.disabled") : f.error ? t("adm.ops.error", { e: f.error }) :
      f.updated ? t("adm.ops.updated", { n: f.entries ?? "?", d: new Date(f.updated).toLocaleString(LANG === "uk" ? "uk" : []) })
        : t("adm.ops.never");
    rows.push([t("adm.ops.feed", { n: f.name }), state]);
  }
  table("#ops", [t("adm.h.component"), t("adm.h.status")], rows);
}

// ---------------------------------------------------------------- events
const known = (prefix, key) => (I18N.en[prefix + key] ? t(prefix + key) : key);
const EVENT_FILTERS = {
  all: () => true,
  failed: (e) => ["auth.login_failed", "auth.account_locked", "auth.rate_limited"].includes(e.action),
  login: (e) => e.action.startsWith("auth."),
  admin: (e) => e.action.startsWith("admin."),
};

async function loadEvents() {
  const events = (await api("GET", "/api/admin/events?limit=300")).filter(EVENT_FILTERS[$("#events-filter").value]);
  const rows = events.map((e) => {
    const details = [e.reason ? known("why.", e.reason) : "",
      ...Object.entries(e.detail || {}).map(([k, v]) => t("det." + k, { v })),
      e.actor ? t("adm.by", { a: e.actor }) : ""].filter(Boolean).join("; ");
    return [new Date(e.time).toLocaleString(LANG === "uk" ? "uk" : []), known("ev.", e.action), e.user, details, e.ip];
  });
  table("#events", [t("adm.h.time"), t("adm.h.event"), t("adm.h.user"), t("adm.h.details"), t("adm.h.ip")], rows);
  // Highlight failures.
  [...$("#events").querySelectorAll("tr")].slice(1).forEach((tr, i) => {
    if (events[i] && EVENT_FILTERS.failed(events[i])) tr.classList.add("ev-fail");
  });
}

$("#events-filter").addEventListener("change", () => loadEvents().catch((e) => { $("#error").textContent = e.message; }));
$("#events-refresh").addEventListener("click", () => loadEvents().catch((e) => { $("#error").textContent = e.message; }));
loadEvents().catch((e) => { $("#error").textContent = e.message; });

$("#days").addEventListener("change", load);
api("GET", "/api/me").then((me) => { $("#me-name").textContent = me.username; });
loadUsers().catch((e) => { $("#error").textContent = e.message; });
load().catch((e) => { $("#error").textContent = e.message; });
setInterval(() => load().catch(() => {}), 60000);
