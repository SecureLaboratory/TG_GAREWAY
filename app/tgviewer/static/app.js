"use strict";
// All message content is inserted with textContent / DOM nodes, never innerHTML.

const $ = (sel) => document.querySelector(sel);
const state = { chatId: null, oldestId: 0, events: null, fileBoxes: new Map(), reloadTimer: null, chatsTimer: null };
applyI18n();  // i18n.js
$("#chat-list").setAttribute("aria-label", t("main.chats"));

async function api(method, url, body, isForm = false) {
  const opts = { method, headers: { "X-TGV": "1" }, credentials: "same-origin" };
  if (body !== undefined) {
    if (isForm) opts.body = body;
    else { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
  }
  const r = await fetch(url, opts);
  let data = null;
  try { data = await r.json(); } catch { /* empty body */ }
  if (!r.ok) {
    const err = new Error((data && (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail))) || r.statusText);
    err.status = r.status;
    err.code = data && data.code;
    throw err;
  }
  return data;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function show(view) {
  $("#build-info").classList.toggle("hidden", view !== "login");
  for (const v of ["login", "consent", "link", "main", "desk"]) $("#view-" + v).classList.toggle("hidden", v !== view);
}

function fmtSize(n) {
  if (!n) return "";
  const u = t("size.units").split(" ");
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function fmtTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString(LANG === "uk" ? "uk" : [], { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit" });
}

// ---------------------------------------------------------------- boot / auth
async function boot() {
  let me;
  try { me = await api("GET", "/api/me"); }
  catch (e) { if (e.status === 401) return show("login"); throw e; }
  // Role separation: admin accounts never use Telegram; they go to user management.
  if (me.is_admin) { location.replace("/admin"); return; }
  $("#me-name").textContent = me.username;
  state.policy = me.policy;
  if (!me.consent) return showConsent(false);
  if (me.access_mode === "browser") return openDesk(me);

  const st = await api("GET", "/api/telegram/status");
  if (!st.configured || !st.linked) {
    show("link");
    $("#link-notconfigured").classList.toggle("hidden", st.configured);
    setLinkStep(st.configured ? "phone" : null);
    return;
  }
  $("#tg-phone").textContent = st.phone || "";
  show("main");
  startEvents();
  loadChats();
}

// Login: step 1 password, step 2 authenticator code (or first-time setup).
function setLoginStep(step) {
  for (const s of ["form", "totp", "enroll", "newpass"]) $("#login-" + s).classList.toggle("hidden", s !== step);
  $("#login-restart").classList.toggle("hidden", step === "form");
  const input = $(`#login-${step} input`);
  if (input) input.focus();
}

async function loginSubmit(ev, fn) {
  ev.preventDefault();
  const btn = ev.target.querySelector("button");
  btn.disabled = true;
  $("#login-error").textContent = "";
  try { await fn(new FormData(ev.target)); }
  catch (e) {
    $("#login-error").textContent = e.message;
    if (e.status === 401 && /password again|пароль ще раз/.test(e.message)) setLoginStep("form");
  } finally { btn.disabled = false; }
}

$("#login-form").addEventListener("submit", (ev) => loginSubmit(ev, async (f) => {
  const r = await api("POST", "/api/login", { username: f.get("username"), password: f.get("password") });
  ev.target.reset();
  if (r.next === "enroll") {
    const info = await api("GET", "/api/login/enroll");
    $("#enroll-secret").textContent = info.secret.replace(/(.{4})/g, "$1 ").trim();
    $("#enroll-qr").src = `/api/login/enroll-qr?t=${Date.now()}`;
    setLoginStep("enroll");
  } else setLoginStep("totp");
}));

function loginDone() {
  $("#enroll-qr").removeAttribute("src");
  $("#enroll-secret").textContent = "";
  setLoginStep("form");
  boot();
}

for (const [form, url] of [["#login-totp", "/api/login/totp"], ["#login-enroll", "/api/login/enroll"]]) {
  $(form).addEventListener("submit", (ev) => loginSubmit(ev, async (f) => {
    const r = await api("POST", url, { code: f.get("code") });
    ev.target.reset();
    if (r.next === "change_password") setLoginStep("newpass");
    else loginDone();
  }));
}

$("#login-newpass").addEventListener("submit", (ev) => loginSubmit(ev, async (f) => {
  if (f.get("password") !== f.get("repeat")) throw new Error(t("newpass.mismatch"));
  await api("POST", "/api/login/new-password", { password: f.get("password") });
  ev.target.reset();
  loginDone();
}));

$("#login-restart").addEventListener("click", () => { $("#login-error").textContent = ""; setLoginStep("form"); });

// Terms and privacy notice: required before using Telegram (again whenever its text changes),
// and readable later through "Privacy". Retention periods come from the server settings.
function showConsent(readOnly) {
  for (const e of document.querySelectorAll("[data-i18n-policy]")) e.textContent = t(e.dataset.i18nPolicy, state.policy || {});
  $("#consent-accept").classList.toggle("hidden", readOnly);
  $("#consent-back").classList.toggle("hidden", !readOnly);
  show("consent");
  window.scrollTo(0, 0);
}

$("#consent-accept").addEventListener("click", async () => { await api("POST", "/api/consent"); boot(); });
$("#consent-back").addEventListener("click", () => boot());

document.addEventListener("click", async (ev) => {
  if (ev.target.closest("[data-action=privacy]")) return showConsent(true);
  if (ev.target.closest("[data-action=logout]")) {
    await api("POST", "/api/logout");
    if (state.events) state.events.close();
    location.reload();
  }
});

$("#unlink-btn").addEventListener("click", async () => {
  if (!confirm(t("main.unlink_q"))) return;
  await api("POST", "/api/telegram/unlink");
  location.reload();
});

// ---------------------------------------------------------------- link telegram
function setLinkStep(step) {
  for (const s of ["phone", "code", "password", "qr"]) $("#link-" + s).classList.toggle("hidden", s !== step);
  $("#link-error").textContent = "";
  if (step !== "qr") state.qrRun = (state.qrRun || 0) + 1;  // stops a running QR wait
}

// QR login: the user scans the code in Telegram → Settings → Devices → Link Desktop Device.
async function startQr() {
  $("#link-error").textContent = "";
  try { await api("POST", "/api/telegram/qr/start"); }
  catch (e) { $("#link-error").textContent = e.message; return; }
  setLinkStep("qr");
  const run = state.qrRun;
  let round = 0;
  $("#link-qr-img").src = `/api/telegram/qr.svg?r=0&t=${Date.now()}`;
  while (run === state.qrRun) {
    let r;
    try { r = await api("GET", "/api/telegram/qr/status"); }
    catch (e) { if (run === state.qrRun) $("#link-error").textContent = e.message; return; }
    if (run !== state.qrRun) return;
    if (r.next === "done") { $("#link-qr-img").removeAttribute("src"); return boot(); }
    if (r.next === "password") return setLinkStep("password");
    if (r.round !== round) {
      round = r.round;
      $("#link-qr-img").src = `/api/telegram/qr.svg?r=${round}&t=${Date.now()}`;
    }
  }
}

$("#link-qr-start").addEventListener("click", startQr);
$("#link-qr-cancel").addEventListener("click", () => setLinkStep("phone"));

async function linkSubmit(ev, url, field, next) {
  ev.preventDefault();
  const value = new FormData(ev.target).get(field);
  const btn = ev.target.querySelector("button");
  btn.disabled = true;
  try {
    const r = await api("POST", url, { [field]: value });
    ev.target.reset();
    next(r);
  } catch (e) { $("#link-error").textContent = e.message; }
  finally { btn.disabled = false; }
}

// Where Telegram delivered the code, and the button for the next way it offers (SMS, call).
function showCodeInfo(r) {
  $("#link-code-hint").textContent = t("link.sent." + (r.sent_to || "other"));
  const resend = $("#link-resend");
  clearInterval(state.resendTimer);
  resend.classList.toggle("hidden", !r.next);
  if (!r.next) return;
  const label = t("link.resend." + r.next);
  let wait = r.timeout || 0;
  const tick = () => {
    resend.disabled = wait > 0;
    resend.textContent = wait > 0 ? t("link.resend.wait", { label, s: wait }) : label;
    if (wait-- <= 0) clearInterval(state.resendTimer);
  };
  tick();
  state.resendTimer = setInterval(tick, 1000);
}

$("#link-phone").addEventListener("submit", (ev) => linkSubmit(ev, "/api/telegram/send-code", "phone", (r) => {
  setLinkStep("code");
  showCodeInfo(r);
}));
$("#link-resend").addEventListener("click", async () => {
  const b = $("#link-resend");
  b.disabled = true;
  $("#link-error").textContent = "";
  try { showCodeInfo(await api("POST", "/api/telegram/resend-code")); }
  catch (e) { $("#link-error").textContent = e.message; b.disabled = false; }
});
$("#link-code").addEventListener("submit", (ev) => linkSubmit(ev, "/api/telegram/sign-in", "code",
  (r) => r.next === "password" ? setLinkStep("password") : boot()));
$("#link-password").addEventListener("submit", (ev) => linkSubmit(ev, "/api/telegram/password", "password", () => boot()));

// ---------------------------------------------------------------- chats
async function loadChats() {
  let chats;
  try { chats = await api("GET", "/api/chats"); }
  catch (e) { if (e.code === "not_linked") return boot(); throw e; }
  const list = $("#chat-list");
  list.replaceChildren();
  for (const c of chats) {
    const b = el("button", "chat-item" + (c.id === state.chatId ? " active" : ""));
    const top = el("div", "row");
    top.append(el("span", "name", c.name));
    if (c.unread) top.append(el("span", "badge", String(c.unread)));
    const text = el("div", "chat-text");
    text.append(top, el("div", "preview", c.preview || ""));
    b.append(avatar(c), text);
    b.title = c.kind;
    b.addEventListener("click", () => openChat(c));
    list.append(b);
  }
}

// Chat icon: the re-encoded profile photo from the gateway, or the initial on a colour.
function avatar(c) {
  const box = el("span", "avatar");
  const initial = el("span", "avatar-initial", (c.name || "?").trim().charAt(0).toUpperCase() || "?");
  box.style.background = `hsl(${Math.abs(Number(c.id) % 360)}, 45%, 55%)`;
  box.append(initial);
  const img = el("img");
  img.alt = "";
  img.loading = "lazy";
  img.onload = () => { box.style.background = "none"; initial.remove(); };
  img.onerror = () => img.remove();
  img.src = `/api/chats/${encodeURIComponent(c.id)}/avatar`;
  box.append(img);
  return box;
}

function scheduleChats() {
  clearTimeout(state.chatsTimer);
  state.chatsTimer = setTimeout(loadChats, 1500);
}

async function openChat(c) {
  state.chatId = c.id;
  state.oldestId = 0;
  $("#chat-title").textContent = c.name;
  // Only where this account may really post (channels: admins only; restricted groups: nobody).
  const writable = c.can_write !== false;
  $("#composer").classList.toggle("hidden", !writable);
  $("#readonly-note").classList.toggle("hidden", writable);
  $("#readonly-note").textContent = writable ? "" : t(c.kind === "channel" ? "main.readonly_channel" : "main.readonly_chat");
  $("#outbox").replaceChildren();
  document.querySelectorAll(".chat-item").forEach((b) => b.classList.remove("active"));
  await loadMessages(false);
  scheduleChats();
}

async function loadMessages(older) {
  const chatId = state.chatId;
  const url = `/api/chats/${chatId}/messages` + (older && state.oldestId ? `?before=${state.oldestId}` : "");
  const msgs = await api("GET", url);
  if (chatId !== state.chatId) return;
  const box = $("#messages");
  const nodes = msgs.map(renderMessage);
  if (older) {
    const more = box.querySelector(".load-more");
    if (more) more.remove();
    box.prepend(...nodes);
  } else {
    state.fileBoxes.clear();
    box.replaceChildren(...nodes);
    box.scrollTop = box.scrollHeight;
  }
  if (msgs.length) {
    state.oldestId = msgs[0].id;
    if (msgs.length >= 40) {
      const more = el("button", "link-btn load-more", t("main.older"));
      more.addEventListener("click", () => loadMessages(true));
      box.prepend(more);
    }
  }
}

function scheduleReload() {
  clearTimeout(state.reloadTimer);
  state.reloadTimer = setTimeout(() => state.chatId && loadMessages(false), 700);
}

// ---------------------------------------------------------------- messages

function renderMessage(m) {
  if (m.service) return el("div", "msg service", m.segments.map((s) => s.v).join(""));
  const wrap = el("div", "msg " + (m.out ? "out" : "in"));
  const head = el("div", "meta");
  head.append(el("span", "sender", m.sender || ""), el("span", "time", fmtTime(m.date)));
  wrap.append(head);
  if (m.segments.length) {
    const body = el("div", "text");
    for (const s of m.segments) {
      if (s.t === "link") {
        const a = el("a", "link v-" + s.verdict, s.v);
        a.href = `/go/${encodeURIComponent(s.id)}`;
        a.target = "_blank";
        a.rel = "noopener noreferrer";
        const title = ["clean", "unknown", "suspicious", "malicious"].includes(s.verdict) ? t("linkv." + s.verdict) : "";
        a.title = `${title}${s.reason ? " (" + trReason(s.reason) + ")" : ""}`;
        body.append(a);
      } else body.append(document.createTextNode(s.v));
    }
    wrap.append(body);
  }
  if (m.media) wrap.append(m.media.kind === "sticker" ? renderSticker(m) : renderAttachment(m));
  wrap.append(renderReactions(m));
  return wrap;
}

// ---------------------------------------------------------------- reactions
const QUICK_REACTIONS = ["👍", "❤️", "😂", "😮", "😢", "🔥", "👏", "🙏"];

async function sendReaction(m, emoji) {
  try { await api("POST", `/api/chats/${state.chatId}/messages/${m.id}/react`, { emoji }); scheduleReload(); }
  catch (e) { alert(e.message); }
}

function renderReactions(m) {
  const row = el("div", "reactions");
  const mine = (m.reactions || []).find((r) => r.mine);
  for (const r of m.reactions || []) {
    const chip = el("button", "reaction" + (r.mine ? " mine" : ""), `${r.emoji} ${r.count}`);
    chip.title = r.custom ? t("react.custom") : (r.mine ? t("react.remove") : t("react.with", { e: r.emoji }));
    chip.disabled = r.custom;
    chip.addEventListener("click", () => sendReaction(m, r.mine ? "" : r.emoji));
    row.append(chip);
  }
  const add = el("button", "reaction add", "☺+");
  add.title = t("react.add");
  add.addEventListener("click", () => {
    const picker = el("div", "reaction-picker");
    for (const e of QUICK_REACTIONS) {
      const b = el("button", "reaction", e);
      b.addEventListener("click", () => sendReaction(m, mine && mine.emoji === e ? "" : e));
      picker.append(b);
    }
    add.replaceWith(picker);
  });
  row.append(add);
  return row;
}

// ---------------------------------------------------------------- stickers
// Static stickers are scanned and re-encoded like photos; animated ones show their emoji only.
function renderSticker(m) {
  const box = el("div", "sticker");
  if (m.media.animated) {
    box.append(el("span", "sticker-emoji", m.media.emoji), el("span", "muted small-text", t("sticker.animated")));
    return box;
  }
  box.append(el("span", "sticker-emoji", m.media.emoji), el("div", "file-status"));
  box.dataset.sticker = "1";
  if (m.file) bindFile(box, m.file);
  else api("POST", `/api/chats/${state.chatId}/messages/${m.id}/scan`).then((f) => bindFile(box, f)).catch(() => {});
  return box;
}

function renderAttachment(m) {
  const box = el("div", "file");
  const info = el("div", "file-info");
  const icon = { photo: "🖼", video: "🎬", voice: "🎤", audio: "🎵", sticker: "🏷", gif: "🎞" }[m.media.kind] || "📄";
  info.append(el("span", "icon", icon), el("span", "fname", m.media.name), el("span", "muted", fmtSize(m.media.size)));
  const status = el("div", "file-status");
  box.append(info, status);
  box.dataset.msgId = m.id;
  if (m.file) bindFile(box, m.file);
  else if (m.media.kind === "photo") {
    // Photos aren't downloaded on arrival (AUTO_SCAN_PHOTOS); they're checked as soon as they're shown.
    status.append(el("div", "status-line s-scanning", t("file.checking")));
    api("POST", `/api/chats/${state.chatId}/messages/${m.id}/scan`).then((f) => bindFile(box, f))
      .catch((e) => { status.textContent = "❗ " + e.message; });
  } else {
    const btn = el("button", "small", t("file.scan_dl"));
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try { bindFile(box, await api("POST", `/api/chats/${state.chatId}/messages/${m.id}/scan`)); }
      catch (e) { status.textContent = "❗ " + e.message; btn.disabled = false; }
    });
    status.append(btn);
  }
  return box;
}

function bindFile(box, f) {
  state.fileBoxes.set(f.id, box);
  renderFileStatus(box, f);
}

const STATUS_ICON = {
  scanning: "⏳", clean: "✅", suspicious: "⚠️", blocked: "⛔", malicious: "⛔", error: "❗",
  too_large: "⛔", expired: "🕓", sent: "✅", ready: "✅", warn: "⚠️", dlp_blocked: "⛔",
};

function renderFileStatus(box, f) {
  const status = box.querySelector(".file-status");
  status.replaceChildren();
  if (box.dataset.sticker) {  // compact: just the re-encoded image once it's clean
    if (f.status === "clean") {
      box.querySelector(".sticker-emoji")?.remove();
      const img = el("img", "sticker-img");
      img.src = `/api/files/${encodeURIComponent(f.id)}/content`;
      img.alt = t("sticker.alt");
      status.append(img);
    } else if (f.status !== "scanning") status.append(el("span", "muted small-text", t("sticker.hidden", { s: f.status })));
    return;
  }
  const [icon, label] = f.status in STATUS_ICON ? [STATUS_ICON[f.status], t("status." + f.status)] : ["", f.status];
  const line = el("div", "status-line s-" + f.status, `${icon} ${label}`);
  status.append(line);
  if (f.reason && f.status !== "clean") status.append(el("div", "reason", f.reason));
  if (f.status === "clean" && f.direction === "inbound") {
    const url = `/api/files/${encodeURIComponent(f.id)}/content`;
    if (f.clean_mime.startsWith("image/")) {
      const img = el("img", "preview-img");
      img.src = url;
      img.alt = f.name;
      status.append(img);
    }
    const a = el("a", "small btn", f.clean_mime.startsWith("image/") ? t("file.open_image") : t("file.download"));
    a.href = url;
    a.target = "_blank";
    a.rel = "noopener";
    status.append(a);
  }
  if (f.direction === "inbound" && f.msg_id && ["error", "expired"].includes(f.status)) {
    const again = el("button", "small", t("file.scan_again"));
    again.addEventListener("click", async () => {
      again.disabled = true;
      try { bindFile(box, await api("POST", `/api/chats/${f.chat_id}/messages/${f.msg_id}/scan`)); }
      catch (e) { status.append(el("div", "reason", e.message)); again.disabled = false; }
    });
    status.append(again);
  }
  if (f.status === "warn") {
    const b = el("button", "small", t("file.send_anyway"));
    b.addEventListener("click", async () => {
      b.disabled = true;
      try { renderFileStatus(box, await api("POST", `/api/files/${f.id}/send`)); }
      catch (e) { status.append(el("div", "reason", e.message)); }
    });
    status.append(b);
  }
  if (f.results && f.results.length) {
    const d = el("details", "engines");
    d.append(el("summary", "", t("file.details")));
    const ul = el("ul");
    for (const r of f.results) ul.append(el("li", "v-" + r.verdict, `${r.engine}: ${r.verdict}${r.detail ? " (" + r.detail + ")" : ""}`));
    d.append(ul);
    status.append(d);
  }
}

async function refreshFile(id) {
  const box = state.fileBoxes.get(id);
  if (!box) return;
  try { renderFileStatus(box, await api("GET", `/api/files/${id}`)); } catch { /* gone */ }
}

// ---------------------------------------------------------------- composer
$("#composer").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const input = $("#text-input");
  const text = input.value.trim();
  if (!text || !state.chatId) return;
  input.disabled = true;
  try { await api("POST", `/api/chats/${state.chatId}/messages`, { text }); input.value = ""; scheduleReload(); }
  catch (e) { alert(e.message); }
  finally { input.disabled = false; input.focus(); }
});

$("#text-input").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && !ev.shiftKey) { ev.preventDefault(); $("#composer").requestSubmit(); }
});

$("#file-input").addEventListener("change", async (ev) => {
  const chatId = state.chatId;
  for (const file of ev.target.files) {
    const box = el("div", "file outgoing");
    const info = el("div", "file-info");
    info.append(el("span", "icon", "📤"), el("span", "fname", file.name), el("span", "muted", fmtSize(file.size)));
    const status = el("div", "file-status", t("file.uploading"));
    box.append(info, status);
    $("#outbox").append(box);
    const form = new FormData();
    form.append("file", file);
    try { bindFile(box, await api("POST", `/api/chats/${chatId}/files`, form, true)); }
    catch (e) { status.textContent = "❗ " + e.message; }
  }
  ev.target.value = "";
});

// ---------------------------------------------------------------- isolated browser
const DESK_URL = "/desk/index.html#path=desk/websockify&autoconnect=true&resize=remote&reconnect=true&reconnect_delay=3000";

async function openDesk(me) {
  show("desk");
  $("#desk-me").textContent = me.username;
  startEvents();
  loadDeskFiles();
  const status = $("#desk-status");
  status.textContent = t("desk.starting_long");
  status.classList.remove("hidden");
  try {
    await api("POST", "/api/desk/start");
    // Wait until the container runs; the stream client then retries until KasmVNC is up.
    for (let i = 0; i < 40; i++) {
      if ((await api("GET", "/api/desk")).status === "running") break;
      await new Promise((res) => setTimeout(res, 1500));
    }
    await new Promise((res) => setTimeout(res, 3000));
    $("#desk-frame").src = DESK_URL;
    $("#desk-frame").classList.remove("hidden");
    status.classList.add("hidden");
  } catch (e) { status.textContent = t("desk.failed") + e.message; }
}

function fileBox(f, icon) {
  const box = el("div", "file");
  const info = el("div", "file-info");
  info.append(el("span", "icon", icon), el("span", "fname", f.name), el("span", "muted", fmtSize(f.size)));
  box.append(info, el("div", "file-status"));
  bindFile(box, f);
  return box;
}

async function loadDeskFiles() {
  const list = await api("GET", "/api/desk/files");
  state.fileBoxes.clear();
  const downloads = list.filter((f) => f.direction === "inbound").map((f) => fileBox(f, "📥"));
  const uploads = list.filter((f) => f.direction === "outbound").map((f) => fileBox(f, "📤"));
  $("#desk-downloads").replaceChildren(...(downloads.length ? downloads : [el("p", "muted small-text", t("desk.nothing"))]));
  $("#desk-outbox").replaceChildren(...uploads);
}

$("#desk-upload").addEventListener("change", async (ev) => {
  for (const file of ev.target.files) {
    const form = new FormData();
    form.append("file", file);
    const placeholder = el("div", "file", t("desk.uploading", { name: file.name }));
    $("#desk-outbox").prepend(placeholder);
    try { placeholder.replaceWith(fileBox(await api("POST", "/api/desk/uploads", form, true), "📤")); }
    catch (e) { placeholder.textContent = `❗ ${file.name}: ${e.message}`; }
  }
  ev.target.value = "";
});

$("#desk-toggle-files").addEventListener("click", () => $("#desk-files").classList.toggle("hidden"));

$("#desk-restart").addEventListener("click", async () => {
  if (!confirm(t("desk.restart_q"))) return;
  $("#desk-frame").classList.add("hidden");
  $("#desk-status").textContent = t("desk.restarting");
  $("#desk-status").classList.remove("hidden");
  await api("POST", "/api/desk/restart");
  setTimeout(() => location.reload(), 4000);
});

$("#desk-reset").addEventListener("click", async () => {
  if (!confirm(t("desk.reset_q"))) return;
  await api("POST", "/api/desk/reset");
  location.reload();
});

// ---------------------------------------------------------------- live events
function startEvents() {
  if (state.events) return;
  state.events = new EventSource("/api/events");
  state.events.onmessage = (ev) => {
    const e = JSON.parse(ev.data);
    if (e.type === "file" && e.new === "download" && !state.fileBoxes.has(e.id)) {
      api("GET", `/api/files/${e.id}`).then((f) => {
        const empty = $("#desk-downloads .small-text");
        if (empty) empty.remove();
        $("#desk-downloads").prepend(fileBox(f, "📥"));
      });
      return;
    }
    if (e.type === "message") {
      if (e.chat_id === state.chatId) scheduleReload();
      scheduleChats();
    } else if (e.type === "file") {
      refreshFile(e.id);
      if (e.status === "sent" && e.chat_id === state.chatId) scheduleReload();
    }
  };
}

boot().catch((e) => { document.body.prepend(el("p", "error", t("common.error") + e.message)); });

// ---------------------------------------------------------------- emoji picker
const EMOJI = ("😀 😃 😄 😁 😆 😅 😂 🤣 😊 😇 🙂 😉 😍 🥰 😘 😋 😜 🤪 🤗 🤔 🤨 😐 😑 😶 🙄 😏 😬 😌 😔 😴 " +
  "😷 🤒 🤯 🥳 😎 🤓 😕 😟 😮 😲 😳 🥺 😢 😭 😱 😤 😡 🤬 👍 👎 👌 ✌️ 🤞 🤝 👏 🙌 🙏 💪 👋 ✋ " +
  "❤️ 🧡 💛 💚 💙 💜 🖤 💔 💯 🔥 ✨ ⭐ 🎉 🎁 ✅ ❌ ⚠️ ❓ ❗ 💡 📌 📎 📅 ⏰ ☕ 🍕 🚀 🌍").split(" ");

function insertAtCursor(input, text) {
  const start = input.selectionStart ?? input.value.length;
  const end = input.selectionEnd ?? input.value.length;
  input.value = input.value.slice(0, start) + text + input.value.slice(end);
  input.selectionStart = input.selectionEnd = start + text.length;
  input.focus();
}

(function setupEmojiPicker() {
  const panel = $("#emoji-panel");
  for (const e of EMOJI) {
    const b = el("button", "emoji", e);
    b.type = "button";
    b.addEventListener("click", () => insertAtCursor($("#text-input"), e));
    panel.append(b);
  }
  $("#emoji-btn").addEventListener("click", () => panel.classList.toggle("hidden"));
  document.addEventListener("click", (ev) => {
    if (!panel.contains(ev.target) && ev.target !== $("#emoji-btn")) panel.classList.add("hidden");
  });
})();

// ---------------------------------------------------------------- chat list: resize and hide
// Drag the divider (or focus it and use the arrow keys; double-click resets). Remembered per browser.
const LIST_DEFAULT = 300, LIST_MIN = 180, LIST_MAX_SHARE = 0.6;
const prefs = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, String(v)); } catch { /* storage blocked: just not remembered */ } },
};

function setListWidth(px) {
  const max = Math.max(LIST_MIN, window.innerWidth * LIST_MAX_SHARE);
  const w = Math.round(Math.min(max, Math.max(LIST_MIN, px)));
  $(".layout").style.setProperty("--list-w", `${w}px`);
  $("#splitter").setAttribute("aria-valuenow", String(w));
  return w;
}

function setListHidden(hidden) {
  $(".layout").classList.toggle("list-hidden", hidden);
  $("#toggle-list").textContent = t(hidden ? "main.show_chats" : "main.hide_chats");
  $("#toggle-list").setAttribute("aria-expanded", String(!hidden));
  prefs.set("tgv-list-hidden", hidden ? "1" : "0");
}

(function setupChatList() {
  setListWidth(Number(prefs.get("tgv-list-w")) || LIST_DEFAULT);
  setListHidden(prefs.get("tgv-list-hidden") === "1");
  $("#toggle-list").addEventListener("click", () => setListHidden(!$(".layout").classList.contains("list-hidden")));

  const sp = $("#splitter");
  const leftEdge = () => $(".layout").getBoundingClientRect().left;
  sp.addEventListener("pointerdown", (ev) => {
    ev.preventDefault();
    sp.setPointerCapture(ev.pointerId);
    document.body.classList.add("resizing");
    const move = (e) => setListWidth(e.clientX - leftEdge());
    const up = (e) => {
      sp.removeEventListener("pointermove", move);
      sp.removeEventListener("pointerup", up);
      document.body.classList.remove("resizing");
      prefs.set("tgv-list-w", setListWidth(e.clientX - leftEdge()));
    };
    sp.addEventListener("pointermove", move);
    sp.addEventListener("pointerup", up);
  });
  sp.addEventListener("keydown", (ev) => {
    if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
    ev.preventDefault();
    const now = Number(sp.getAttribute("aria-valuenow")) || LIST_DEFAULT;
    const step = (ev.shiftKey ? 60 : 20) * (ev.key === "ArrowRight" ? 1 : -1);
    prefs.set("tgv-list-w", setListWidth(now + step));
  });
  sp.addEventListener("dblclick", () => prefs.set("tgv-list-w", setListWidth(LIST_DEFAULT)));
})();

// Release number at the bottom of the login screen.
api("GET", "/api/version").then((v) => { $("#build-info").textContent = t("login.version", { v: v.version }); }).catch(() => {});
