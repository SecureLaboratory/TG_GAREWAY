"use strict";
// English / Ukrainian texts for the web pages. The language: the tgv_lang cookie (set by the
// language switch), else the browser's language. The cookie also tells the server which language
// to use for its messages. Elements carry data-i18n (text), data-i18n-ph (placeholder),
// data-i18n-title (tooltip) or data-i18n-alt; scripts use t("key", { name: value }).

const I18N = {
  en: {
    "common.continue": "Continue", "common.logout": "Log out", "common.error": "Error: ",
    "size.units": "B KB MB GB",
    "login.subtitle": "Secure Telegram gateway", "login.username": "Username", "login.password": "Password",
    "login.totp_prompt": "Enter the 6-digit code from your authenticator app.",
    "login.totp_code": "Authenticator code", "login.login": "Log in", "login.restart": "Start again",
    "login.version": "TG Viewer, version {v}",
    "enroll.title": "Set up two-factor authentication.",
    "enroll.text": "Scan this QR code with an authenticator app (Microsoft Authenticator, Google Authenticator, …), then enter the code it shows.",
    "enroll.qr_alt": "Authenticator QR code",
    "enroll.manual": "Can't scan? Add the account manually with this key:",
    "enroll.code": "Code from the app", "enroll.confirm": "Confirm and log in",
    "newpass.title": "Choose your own password.", "newpass.text": "The one you received was temporary.",
    "newpass.new": "New password (at least 12 characters)", "newpass.repeat": "Repeat new password",
    "newpass.save": "Save and log in", "newpass.mismatch": "The passwords don't match",
    "consent.title": "Terms of use and privacy notice",
    "consent.intro": "This gateway lets you use your own Telegram account from the corporate network. To protect the network, everything you receive and send is checked: attachments by antivirus and document checks before you can open them, files you send also for sensitive data, links when shown and again when you click them. Please read what this means for your data.",
    "consent.stored_h": "What is stored",
    "consent.s_account": "Your gateway account: your username, a hash of your password (never the password itself) and your authenticator key (encrypted).",
    "consent.s_session": "Your Telegram session key, encrypted on the server, so the gateway can stay connected for you, and your phone number in masked form (for example +380*******12).",
    "consent.s_files": "Files you receive or send: up to {quarantine_days} days in quarantine, clean copies up to {clean_days} days. Then they are deleted automatically.",
    "consent.s_links": "Links in your messages: the address and its check result, up to {link_days} days.",
    "consent.s_meta": "Scan results and metadata: file hash, type, size, verdict and time; link domain and verdict.",
    "consent.s_audit": "An audit log for the security team: your logins (time, IP address, success or failure), administrator actions and scan verdicts.",
    "consent.never_h": "What is never stored or logged",
    "consent.n_text": "The text of your messages: it is read live from Telegram and shown to you, never saved or logged.",
    "consent.n_passwords": "Your passwords in readable form, and your Telegram two-step verification password (it goes to Telegram only).",
    "consent.n_contacts": "Your contact list and your list of chats.",
    "consent.n_outside": "Nothing about your files or links is sent to outside services. If the administrator turns on VirusTotal, only file fingerprints (hashes) are looked up, never the files.",
    "consent.who_h": "Who can see what",
    "consent.w_admin": "Administrators see your username, account status, whether Telegram is linked, your login events and the number of scans. They never see your chats, messages, files or contacts, and they can't use your Telegram.",
    "consent.w_sec": "The security team receives the audit log described above (no message text).",
    "consent.rights_h": "Your choices",
    "consent.r_unlink": "You can unlink Telegram at any time (button \"Unlink Telegram\"): the gateway logs out of your account and deletes its copies of your files. The gateway also appears in Telegram → Settings → Devices, where you can end it.",
    "consent.r_leave": "When your account is disabled (for example when you leave the company), your Telegram session on the gateway is revoked.",
    "consent.r_phone": "The gateway protects the corporate network. Telegram on your own phone is not checked by it.",
    "consent.session": "A login to the gateway lasts at most {session_hours} hours.",
    "consent.accept": "I have read this and agree",
    "consent.back": "Back",
    "link.title": "Link your Telegram",
    "link.notconfigured": "The administrator hasn't configured the Telegram API credentials yet (TG_API_ID / TG_API_HASH).",
    "link.phone": "Phone number", "link.send": "Send code", "link.code": "Code", "link.signin": "Sign in",
    "link.sent.app": "Telegram sent the code to your Telegram app on another device, not by SMS: open the chat \"Telegram\" (with the blue tick) on your phone or computer.",
    "link.sent.sms": "Telegram sent the code by SMS.",
    "link.sent.call": "Telegram is calling you: the code is given in the call (or is the last digits of the calling number).",
    "link.sent.email": "Telegram sent the code to the login email of your account.",
    "link.sent.email_setup": "Telegram asks you to set up a login email first: do it in the Telegram app, then try again.",
    "link.sent.fragment": "Telegram sent the code through Fragment (anonymous number).",
    "link.sent.other": "Telegram sent a code.",
    "link.resend.sms": "Send the code by SMS instead", "link.resend.call": "Call me with the code instead",
    "link.resend.fragment": "Send the code through Fragment instead",
    "link.resend.wait": "{label} (available in {s} s)",
    "link.2fa": "Your account has two-step verification. The password goes to Telegram only and isn't stored.",
    "link.tgpass": "Telegram password",
    "link.qr_start": "Link with a QR code (no code needed)",
    "link.or_phone": "Or with your phone number and a login code:",
    "link.qr_steps": "On your phone open Telegram → Settings → Devices → Link Desktop Device, and scan this code.",
    "link.qr_alt": "Telegram login QR code",
    "link.qr_renew": "The code renews itself about every 30 seconds. Keep this page open until your chats appear.",
    "link.qr_cancel": "Use the phone number instead",
    "desk.subtitle": "Telegram Web in an isolated browser", "desk.files": "Files", "desk.restart": "Restart browser",
    "desk.reset": "Reset", "desk.starting": "Starting your isolated browser…",
    "desk.starting_long": "Starting your isolated browser… (the first start can take up to a minute)",
    "desk.failed": "Could not start the isolated browser: ", "desk.frame": "Isolated browser with Telegram Web",
    "desk.downloads": "Downloads",
    "desk.downloads_hint": "Files you download in Telegram Web appear here after scanning. Only clean files can be saved to this PC.",
    "desk.send": "Send a file",
    "desk.send_hint1": "Files are scanned and checked for sensitive data first, then appear in the browser's",
    "desk.send_hint2": "folder: attach them in Telegram from there.",
    "desk.choose": "Choose file", "desk.nothing": "Nothing downloaded yet.", "desk.uploading": "⏳ Uploading {name}…",
    "desk.restart_q": "Restart the isolated browser? You stay logged in to Telegram Web.", "desk.restarting": "Restarting…",
    "desk.reset_q": "Reset deletes your isolated browser and its data, which logs you out of Telegram Web here.\n\nAlso end the session on your phone: Telegram → Settings → Devices.",
    "main.unlink": "Unlink Telegram", "main.chats": "Chats", "main.select": "Select a chat",
    "main.privacy": "Privacy",
    "main.hide_chats": "Hide chats", "main.show_chats": "Show chats",
    "main.resize": "Drag to resize the chat list (arrow keys too; double-click: default width)",
    "main.attach": "Attach a file (scanned before sending)", "main.emoji": "Emoji",
    "main.placeholder": "Write a message… (Enter to send, Shift+Enter for a new line)", "main.send": "Send",
    "main.unlink_q": "Unlink Telegram? The gateway logs out of your account and deletes its copy of your files.",
    "main.older": "Load older messages",
    "main.readonly_channel": "This is a channel: only its admins can post. You can read it and react to posts.",
    "main.readonly_chat": "You can't write in this chat (no permission). You can still read it.",
    "linkv.clean": "Checked: well-known domain",
    "linkv.unknown": "Not on the well-known list: you'll see a warning first",
    "linkv.suspicious": "Suspicious link: you'll see a warning first",
    "linkv.malicious": "Blocked: known malicious link",
    "react.custom": "Custom reaction", "react.remove": "Remove your reaction", "react.with": "React with {e}",
    "react.add": "Add a reaction",
    "sticker.animated": " animated sticker", "sticker.alt": "sticker", "sticker.hidden": " sticker not shown ({s})",
    "file.checking": "⏳ Checking…", "file.scan_dl": "Scan & download", "file.uploading": "⏳ Uploading…",
    "file.open_image": "Open image", "file.download": "Download", "file.scan_again": "Scan again",
    "file.send_anyway": "Send anyway", "file.details": "Scan details",
    "status.scanning": "Scanning…", "status.clean": "Clean", "status.suspicious": "Held: suspicious",
    "status.blocked": "Blocked by policy", "status.malicious": "Blocked: malware", "status.error": "Scan failed",
    "status.too_large": "Too large to scan", "status.expired": "Expired, scan again", "status.sent": "Scanned and sent",
    "status.ready": "Ready in the browser's Uploads folder", "status.warn": "Sensitive data found",
    "status.dlp_blocked": "Not sent: sensitive data",
  },
  uk: {
    "common.continue": "Продовжити", "common.logout": "Вийти", "common.error": "Помилка: ",
    "size.units": "Б КБ МБ ГБ",
    "login.subtitle": "Захищений шлюз до Telegram", "login.username": "Ім'я користувача", "login.password": "Пароль",
    "login.totp_prompt": "Введіть 6-значний код із застосунку-автентифікатора.",
    "login.totp_code": "Код автентифікатора", "login.login": "Увійти", "login.restart": "Почати спочатку",
    "login.version": "TG Viewer, версія {v}",
    "enroll.title": "Налаштуйте двофакторну автентифікацію.",
    "enroll.text": "Відскануйте цей QR-код застосунком-автентифікатором (Microsoft Authenticator, Google Authenticator тощо) і введіть код, який він покаже.",
    "enroll.qr_alt": "QR-код для автентифікатора",
    "enroll.manual": "Не вдається відсканувати? Додайте обліковий запис вручну за цим ключем:",
    "enroll.code": "Код із застосунку", "enroll.confirm": "Підтвердити й увійти",
    "newpass.title": "Оберіть власний пароль.", "newpass.text": "Пароль, який ви отримали, був тимчасовим.",
    "newpass.new": "Новий пароль (щонайменше 12 символів)", "newpass.repeat": "Повторіть новий пароль",
    "newpass.save": "Зберегти й увійти", "newpass.mismatch": "Паролі не збігаються",
    "consent.title": "Умови користування та повідомлення про конфіденційність",
    "consent.intro": "Цей шлюз дає змогу користуватися власним обліковим записом Telegram з корпоративної мережі. Щоб захистити мережу, усе, що ви отримуєте й надсилаєте, перевіряється: вкладення — антивірусом і перевіркою документів, перш ніж ви зможете їх відкрити, файли, які ви надсилаєте, — також на чутливі дані, посилання — під час показу та ще раз, коли ви їх натискаєте. Прочитайте, що це означає для ваших даних.",
    "consent.stored_h": "Що зберігається",
    "consent.s_account": "Ваш обліковий запис у шлюзі: ім'я користувача, хеш пароля (ніколи не сам пароль) і ключ автентифікатора (зашифрований).",
    "consent.s_session": "Ключ вашого сеансу Telegram, зашифрований на сервері, щоб шлюз міг лишатися на зв'язку, і ваш номер телефону в прихованому вигляді (наприклад +380*******12).",
    "consent.s_files": "Файли, які ви отримуєте чи надсилаєте: до {quarantine_days} днів у карантині, чисті копії — до {clean_days} днів. Потім вони видаляються автоматично.",
    "consent.s_links": "Посилання у ваших повідомленнях: адреса й результат перевірки, до {link_days} днів.",
    "consent.s_meta": "Результати перевірок і метадані: хеш файлу, тип, розмір, вердикт і час; домен посилання та вердикт.",
    "consent.s_audit": "Журнал аудиту для служби безпеки: ваші входи (час, IP-адреса, успіх чи невдача), дії адміністраторів і вердикти перевірок.",
    "consent.never_h": "Що ніколи не зберігається й не записується",
    "consent.n_text": "Текст ваших повідомлень: він читається з Telegram у реальному часі й показується вам, але ніколи не зберігається й не записується.",
    "consent.n_passwords": "Ваші паролі в читабельному вигляді, а також пароль двоетапної перевірки Telegram (він передається лише в Telegram).",
    "consent.n_contacts": "Ваш список контактів і список чатів.",
    "consent.n_outside": "Жодні дані про ваші файли чи посилання не передаються зовнішнім сервісам. Якщо адміністратор увімкне VirusTotal, перевірятимуться лише відбитки файлів (хеші), ніколи не самі файли.",
    "consent.who_h": "Хто що бачить",
    "consent.w_admin": "Адміністратори бачать ваше ім'я користувача, стан облікового запису, чи під'єднано Telegram, ваші входи та кількість перевірок. Вони ніколи не бачать ваших чатів, повідомлень, файлів чи контактів і не можуть користуватися вашим Telegram.",
    "consent.w_sec": "Служба безпеки отримує описаний вище журнал аудиту (без тексту повідомлень).",
    "consent.rights_h": "Ваш вибір",
    "consent.r_unlink": "Ви можете будь-коли від'єднати Telegram (кнопка «Від'єднати Telegram»): шлюз вийде з вашого облікового запису й видалить свої копії ваших файлів. Шлюз також видно в Telegram → Налаштування → Пристрої, де цей сеанс можна завершити.",
    "consent.r_leave": "Коли ваш обліковий запис вимикають (наприклад, після звільнення), ваш сеанс Telegram на шлюзі відкликається.",
    "consent.r_phone": "Шлюз захищає корпоративну мережу. Telegram на вашому власному телефоні він не перевіряє.",
    "consent.session": "Вхід у шлюз діє щонайбільше {session_hours} годин.",
    "consent.accept": "Я прочитав(-ла) і погоджуюся",
    "consent.back": "Назад",
    "link.title": "Під'єднайте Telegram",
    "link.notconfigured": "Адміністратор ще не налаштував облікові дані Telegram API (TG_API_ID / TG_API_HASH).",
    "link.phone": "Номер телефону", "link.send": "Надіслати код", "link.code": "Код", "link.signin": "Увійти",
    "link.sent.app": "Telegram надіслав код у ваш застосунок Telegram на іншому пристрої, а не в SMS: відкрийте чат «Telegram» (із синьою позначкою) на телефоні чи комп'ютері.",
    "link.sent.sms": "Telegram надіслав код в SMS.",
    "link.sent.call": "Telegram телефонує вам: код повідомлять у дзвінку (або це останні цифри номера, з якого телефонують).",
    "link.sent.email": "Telegram надіслав код на пошту для входу вашого облікового запису.",
    "link.sent.email_setup": "Telegram просить спершу налаштувати пошту для входу: зробіть це в застосунку Telegram і спробуйте ще раз.",
    "link.sent.fragment": "Telegram надіслав код через Fragment (анонімний номер).",
    "link.sent.other": "Telegram надіслав код.",
    "link.resend.sms": "Надіслати код в SMS", "link.resend.call": "Отримати код дзвінком",
    "link.resend.fragment": "Надіслати код через Fragment",
    "link.resend.wait": "{label} (буде доступно через {s} с)",
    "link.2fa": "У вашому обліковому записі ввімкнено двоетапну перевірку. Пароль передається лише в Telegram і не зберігається.",
    "link.tgpass": "Пароль Telegram",
    "link.qr_start": "Під'єднати за QR-кодом (без коду входу)",
    "link.or_phone": "Або за номером телефону та кодом входу:",
    "link.qr_steps": "На телефоні відкрийте Telegram → Налаштування → Пристрої → Під'єднати пристрій (Link Desktop Device) і відскануйте цей код.",
    "link.qr_alt": "QR-код для входу в Telegram",
    "link.qr_renew": "Код оновлюється приблизно кожні 30 секунд. Не закривайте сторінку, доки не з'являться ваші чати.",
    "link.qr_cancel": "Скористатися номером телефону",
    "desk.subtitle": "Telegram Web в ізольованому браузері", "desk.files": "Файли", "desk.restart": "Перезапустити браузер",
    "desk.reset": "Скинути", "desk.starting": "Запускаємо ваш ізольований браузер…",
    "desk.starting_long": "Запускаємо ваш ізольований браузер… (перший запуск може тривати до хвилини)",
    "desk.failed": "Не вдалося запустити ізольований браузер: ", "desk.frame": "Ізольований браузер із Telegram Web",
    "desk.downloads": "Завантаження",
    "desk.downloads_hint": "Файли, завантажені в Telegram Web, з'являються тут після перевірки. Зберегти на цей ПК можна лише чисті файли.",
    "desk.send": "Надіслати файл",
    "desk.send_hint1": "Файли спершу перевіряються, зокрема на чутливі дані, а потім з'являються в папці браузера",
    "desk.send_hint2": ": прикріплюйте їх у Telegram звідти.",
    "desk.choose": "Вибрати файл", "desk.nothing": "Ще нічого не завантажено.", "desk.uploading": "⏳ Завантаження {name}…",
    "desk.restart_q": "Перезапустити ізольований браузер? Ви залишитеся в Telegram Web.", "desk.restarting": "Перезапуск…",
    "desk.reset_q": "Скидання видаляє ваш ізольований браузер і його дані, тож ви вийдете тут із Telegram Web.\n\nТакож завершіть сеанс на телефоні: Telegram → Налаштування → Пристрої.",
    "main.unlink": "Від'єднати Telegram", "main.chats": "Чати", "main.select": "Оберіть чат",
    "main.privacy": "Конфіденційність",
    "main.hide_chats": "Сховати чати", "main.show_chats": "Показати чати",
    "main.resize": "Потягніть, щоб змінити ширину списку чатів (також стрілками; подвійний клік — типова ширина)",
    "main.attach": "Прикріпити файл (перевіряється перед надсиланням)", "main.emoji": "Емодзі",
    "main.placeholder": "Напишіть повідомлення… (Enter — надіслати, Shift+Enter — новий рядок)", "main.send": "Надіслати",
    "main.unlink_q": "Від'єднати Telegram? Шлюз вийде з вашого облікового запису й видалить свої копії ваших файлів.",
    "main.older": "Завантажити старіші повідомлення",
    "main.readonly_channel": "Це канал: публікувати можуть лише його адміністратори. Ви можете читати його й реагувати на дописи.",
    "main.readonly_chat": "У цьому чаті ви не можете писати (немає дозволу). Читати його можна.",
    "linkv.clean": "Перевірено: відомий домен",
    "linkv.unknown": "Немає в списку відомих: спершу ви побачите попередження",
    "linkv.suspicious": "Підозріле посилання: спершу ви побачите попередження",
    "linkv.malicious": "Заблоковано: відоме шкідливе посилання",
    "react.custom": "Власна реакція", "react.remove": "Прибрати вашу реакцію", "react.with": "Реакція {e}",
    "react.add": "Додати реакцію",
    "sticker.animated": " анімована наліпка", "sticker.alt": "наліпка", "sticker.hidden": " наліпку не показано ({s})",
    "file.checking": "⏳ Перевірка…", "file.scan_dl": "Перевірити й завантажити", "file.uploading": "⏳ Завантаження…",
    "file.open_image": "Відкрити зображення", "file.download": "Завантажити", "file.scan_again": "Перевірити ще раз",
    "file.send_anyway": "Усе одно надіслати", "file.details": "Деталі перевірки",
    "status.scanning": "Перевірка…", "status.clean": "Чисто", "status.suspicious": "Затримано: підозрілий",
    "status.blocked": "Заблоковано політикою", "status.malicious": "Заблоковано: шкідливе ПЗ",
    "status.error": "Помилка перевірки", "status.too_large": "Завеликий для перевірки",
    "status.expired": "Термін минув, перевірте ще раз", "status.sent": "Перевірено й надіслано",
    "status.ready": "Готово в папці Uploads браузера", "status.warn": "Знайдено чутливі дані",
    "status.dlp_blocked": "Не надіслано: чутливі дані",
  },
};

// Link-check reasons come from the server in English (stored with the link).
const REASONS_UK = [
  [/^listed in URLhaus \/ OpenPhish$/, "є в списках URLhaus / OpenPhish"],
  [/^host (\S+) listed in URLhaus$/, "хост $1 є в списку URLhaus"],
  [/^link hides its real host behind '@'$/, "посилання приховує справжню адресу за «@»"],
  [/^link points to a raw IP address$/, "посилання веде на IP-адресу"],
  [/^internationalised \(punycode\) domain, possible look-alike$/, "інтернаціоналізований (punycode) домен, можлива підробка"],
  [/^URL shortener: final destination unknown$/, "скорочувач посилань: кінцева адреса невідома"],
  [/^well-known domain \(Tranco #(\d+)\)$/, "відомий домен (Tranco #$1)"],
  [/^domain is not in the well-known list$/, "домену немає в списку відомих"],
  [/^VirusTotal: (\d+) engine(?:s|\(s\)) flag this link$/, "VirusTotal: рушіїв, що позначають посилання: $1"],
];

const LANG = (() => {
  const m = document.cookie.match(/(?:^|;\s*)tgv_lang=(en|uk)(?:;|$)/);
  if (m) return m[1];
  for (const l of navigator.languages || [navigator.language || ""]) {
    if (/^uk/i.test(l)) return "uk";
    if (/^en/i.test(l)) return "en";
  }
  return "en";
})();

function setLangCookie(lang) {
  document.cookie = `tgv_lang=${lang}; Path=/; Max-Age=31536000; SameSite=Strict` +
    (location.protocol === "https:" ? "; Secure" : "");
}
setLangCookie(LANG);  // the server answers in the same language

function t(key, vars) {
  let s = I18N[LANG][key] ?? I18N.en[key] ?? key;
  if (vars) s = s.replace(/\{(\w+)\}/g, (all, k) => (k in vars ? String(vars[k]) : all));
  return s;
}

function addTexts(dict) {
  for (const lang of Object.keys(dict)) Object.assign(I18N[lang], dict[lang]);
}

function trReason(text) {
  if (LANG !== "uk" || !text) return text;
  for (const [rx, uk] of REASONS_UK) if (rx.test(text)) return text.replace(rx, uk);
  return text;
}

function applyI18n(root = document) {
  document.documentElement.lang = LANG;
  for (const e of root.querySelectorAll("[data-i18n]")) e.textContent = t(e.dataset.i18n);
  for (const e of root.querySelectorAll("[data-i18n-ph]")) e.placeholder = t(e.dataset.i18nPh);
  for (const e of root.querySelectorAll("[data-i18n-title]")) e.title = t(e.dataset.i18nTitle);
  for (const e of root.querySelectorAll("[data-i18n-alt]")) e.alt = t(e.dataset.i18nAlt);
  const other = LANG === "uk" ? "en" : "uk";
  for (const slot of root.querySelectorAll(".lang-slot")) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "link-btn lang-btn";
    b.lang = other;
    b.textContent = other === "uk" ? "Українська" : "English";
    b.addEventListener("click", () => { setLangCookie(other); location.reload(); });
    slot.replaceChildren(b);
  }
}
