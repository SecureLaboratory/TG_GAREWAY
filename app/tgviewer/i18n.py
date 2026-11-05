"""English / Ukrainian texts for what the server says to people: API error messages and the
link gate pages. The code is written in English; UK maps those texts (exactly, or by a pattern
for messages with numbers or names). Unknown texts stay English.

The language comes from the tgv_lang cookie (set by the language switch in the web app), else
from the browser's Accept-Language.
"""
import re

LANGS = ("en", "uk")


def pick(request) -> str:
    lang = request.cookies.get("tgv_lang")
    if lang in LANGS:
        return lang
    for part in request.headers.get("accept-language", "").split(","):
        tag = part.split(";")[0].strip().lower()
        if tag.startswith("uk"):
            return "uk"
        if tag.startswith("en"):
            return "en"
    return "en"


UK = {
    # login and accounts
    "Not logged in": "Ви не ввійшли",
    "Wrong code": "Невірний код",
    "Too many wrong codes, please enter your password again": "Забагато невірних кодів, введіть пароль ще раз",
    "Login expired, please enter your password again": "Час входу минув, введіть пароль ще раз",
    "Code already verified": "Код уже підтверджено",
    "Set up your authenticator first": "Спершу налаштуйте застосунок-автентифікатор",
    "Authenticator is already set up": "Автентифікатор уже налаштовано",
    "No password change pending": "Зміна пароля не очікується",
    "Use at least 12 characters": "Щонайменше 12 символів",
    "Password is too long": "Пароль задовгий",
    "Choose a password different from the temporary one": "Оберіть пароль, відмінний від тимчасового",
    "Too many attempts from this address, try again in a few minutes":
        "Забагато спроб з цієї адреси, спробуйте за кілька хвилин",
    "Admins only": "Лише для адміністраторів",
    "Admin accounts manage users and statistics only; they can't use Telegram":
        "Облікові записи адміністраторів керують лише користувачами та статистикою; вони не можуть користуватися Telegram",
    "Please accept the scanning notice first": "Спершу прийміть повідомлення про перевірку",
    # admin user management
    "User not found": "Користувача не знайдено",
    "User already exists": "Такий користувач уже існує",
    "Role must be user or admin": "Роль має бути user або admin",
    "Username: 3-64 characters, letters, digits, dot, dash, underscore":
        "Ім'я користувача: 3–64 символи, латинські літери, цифри, крапка, дефіс, підкреслення",
    "You can't change your own account here (use the CLI)":
        "Власний обліковий запис тут змінити не можна (скористайтеся командним рядком)",
    # Telegram
    "Enter the phone number in international format, e.g. +380...":
        "Введіть номер телефону в міжнародному форматі, наприклад +380...",
    "Login expired, please start again": "Час входу минув, почніть спочатку",
    "Telegram account is not linked": "Обліковий запис Telegram не під'єднано",
    "TG_API_ID / TG_API_HASH are not configured": "TG_API_ID / TG_API_HASH не налаштовано",
    "chat not found": "чат не знайдено",
    # files and messages
    "This message has no file": "У цьому повідомленні немає файлу",
    "File not found": "Файл не знайдено",
    "Only files with a clean verdict can be opened": "Відкрити можна лише файли, визнані чистими",
    "This file is not waiting for confirmation": "Цей файл не очікує підтвердження",
    "Empty message": "Порожнє повідомлення",
    "You can't write in this chat": "У цьому чаті ви не можете писати",
    "Not a reaction": "Це не реакція",
    "Isolated-browser mode is not enabled": "Режим ізольованого браузера не ввімкнено",
    # generic
    "Not Found": "Не знайдено",
    "Not found": "Не знайдено",
    "Forbidden": "Заборонено",
    "Invalid request": "Некоректний запит",
    "Request too large": "Запит завеликий",
    "Content-Length required": "Потрібен заголовок Content-Length",
    "Missing X-TGV header": "Бракує заголовка X-TGV",
    # link check reasons (stored in English, shown on the gate page)
    "listed in URLhaus / OpenPhish": "є в списках URLhaus / OpenPhish",
    "link hides its real host behind '@'": "посилання приховує справжню адресу за «@»",
    "link points to a raw IP address": "посилання веде на IP-адресу",
    "internationalised (punycode) domain, possible look-alike": "інтернаціоналізований (punycode) домен, можлива підробка",
    "URL shortener: final destination unknown": "скорочувач посилань: кінцева адреса невідома",
    "domain is not in the well-known list": "домену немає в списку відомих",
}

UK_PATTERNS = [
    (re.compile(r"Wrong username or password \(after (\d+) failed attempts, wait (\d+) minutes\)"),
     "Невірне ім'я користувача або пароль (після {0} невдалих спроб — зачекайте {1} хв)"),
    (re.compile(r"File is larger than (\d+) MB"), "Файл більший за {0} МБ"),
    (re.compile(r"Telegram asks to wait (\d+) s before retrying"), "Telegram просить зачекати {0} с перед повтором"),
    (re.compile(r"host (\S+) listed in URLhaus"), "хост {0} є в списку URLhaus"),
    (re.compile(r"well-known domain \(Tranco #(\d+)\)"), "відомий домен (Tranco #{0})"),
    (re.compile(r"VirusTotal: (\d+) engines flag this link"), "VirusTotal: {0} рушіїв позначають це посилання"),
    (re.compile(r"VirusTotal: (\d+) engine\(s\) flag this link"), "VirusTotal: рушіїв, що позначають посилання: {0}"),
]


def tr(text: str, lang: str) -> str:
    if lang != "uk" or not text:
        return text
    if text in UK:
        return UK[text]
    for rx, template in UK_PATTERNS:
        if m := rx.fullmatch(text):
            return template.format(*m.groups())
    return text
