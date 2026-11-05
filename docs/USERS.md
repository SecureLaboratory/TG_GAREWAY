# Users: add, manage, offboard

*English · [Українська](USERS.uk.md)*

There are two kinds of accounts:

| Role | Can | Can't |
|---|---|---|
| **User** | Link *their own* Telegram account, read and send messages, open scanned files and checked links | Use the admin area |
| **Admin** | Create users, reset passwords and 2FA, unlock, disable/enable, view statistics and feed status | Link or use Telegram, read chats, open files or links, see any secret (sessions, authenticator keys, passwords) |

One person who needs both gets **two accounts**: an admin account and a user account.

Every account logs in with a **password and an authenticator app** (TOTP: Microsoft
Authenticator, Google Authenticator, 1Password, …). SSO is planned.

**Language:** the web app is in English and Ukrainian. It follows the browser's language. Change
it with the **English / Українська** button in the top bar or on the login page; the choice is
remembered in the browser.

## Where people log in

| Who | Address | How |
|---|---|---|
| Users | `https://<your domain>` (through your TLS proxy) | from the corporate network |
| Admins | `http://localhost:8081/admin` | **only through a tunnel to the server.** The admin area isn't reachable through the public address: there, `/admin` answers 404 and admin accounts can't log in. Optionally the operator also opens `https://<your domain>/admin` for fixed IP addresses (`ADMIN_ALLOWED_IPS`, [PRODUCTION.md §4a](PRODUCTION.md#4a-admin-access)) |
| Locally (Docker Desktop) | `http://localhost:8080` (users) and `http://localhost:8080/admin` | local front door only |

Use `localhost` in the address. Older deployments accept only that name, so on those
`http://127.0.0.1:8081` returns *400 Bad Request*.

**Open the admin tunnel** from your PC and keep the window open while you work:

```bash
ssh -L 8081:localhost:8081 <user>@<server>
```

Your cloud may offer a way without an open SSH port: a port-forwarding session started from its
CLI. Any tunnel to the server's `localhost:8081` works.

Then browse to **http://localhost:8081/admin**.

## 1. Create the first admin (once, on the server)

The web UI needs an admin to log in with, so the first one is created on the command line.
`-t` gives you a terminal for the password prompt (asked twice, at least 12 characters):

```bash
ssh -t <user>@<server> \
  "cd /opt/tgviewer && sudo docker compose exec api python -m tgviewer.cli create-user admin --admin"
```

Or run the part in quotes in any shell on the server.

Locally, run `docker compose exec api python -m tgviewer.cli create-user admin --admin`.

**First login:**
1. Open the tunnel and go to http://localhost:8081/admin.
2. Log in with the username and password.
3. Scan the QR code with your authenticator app and enter the 6-digit code.

## 2. Add a user (web UI)

1. Log in to the admin area.
2. Under **Users**, type the username. It can have 3–64 characters: letters, digits, `.`, `-`,
   `_`. A good choice is the corporate login, e.g. `j.smith`.
3. Choose the role:
   - **User (uses Telegram)** for employees;
   - **Admin (no Telegram)** for a further administrator.
4. Click **Create user**. A **temporary password** is shown **once**. Copy it.
5. Give the user two things **over a separate channel** from each other (e.g. the address by
   email, the password in person or by phone):
   - the address `https://<your domain>`;
   - the temporary password.

   Whoever logs in first with it sets up the authenticator, so keep it private.

The user list shows each account's status:

| Status | Meaning |
|---|---|
| active / disabled | whether the account can log in |
| locked | 5 wrong attempts: locked for 15 minutes (or until an admin clicks *Unlock*) |
| temporary password | hasn't logged in yet, or the password was reset |
| 2FA on / 2FA not set up | whether the authenticator is enrolled |
| Telegram linked | the user has linked Telegram (status only; admins never see the session) |

### What the new user does

Send these steps along with the address:

1. Open `https://<your domain>` and log in with your username and the temporary password.
2. **Set up the authenticator.** Scan the QR code with an authenticator app on your phone, then
   enter the 6-digit code it shows.
3. **Choose your own password** (at least 12 characters).
4. **Read and accept the terms of use and privacy notice** (in the language you chose). It lists
   what is stored (account, encrypted Telegram session, files for a limited time, scan results,
   login events) and what never is (message text, passwords, contacts). It is shown again whenever
   the text changes, and you can reopen it any time with **Privacy** in the top bar.
5. **Link your Telegram.**
   - Enter your phone number in international format (`+380…`).
   - Enter the login code. The page says where Telegram sent it. Usually it is **not an SMS**: if
     you're logged in to Telegram on your phone or computer, the code arrives **in the Telegram
     app**, as a message in the chat **"Telegram"** (blue tick). If Telegram offers it, a button
     such as **Send the code by SMS instead** appears; it becomes active after the waiting time
     Telegram sets.
   - If your account has two-step verification, enter that password too. It goes to Telegram only
     and isn't stored.
6. Your chats appear. From now on, log in with your password and the code from the
   authenticator app.
   In channels where you aren't an admin, and in groups where writing is restricted, there is no
   message box: a note says you can only read there.

You can unlink Telegram at any time (button **Unlink Telegram**). The gateway also appears in
Telegram → Settings → Devices, where you can end it from your phone.

## 3. Everyday tasks (web UI)

The buttons are next to each user in the admin area. All actions are recorded in the audit log
with the admin who did them.

| Situation | Button | Effect |
|---|---|---|
| Forgot the password | **Reset password** | New temporary password shown once; all their sessions end |
| New phone / lost the authenticator | **Reset 2FA** | They set up a new authenticator at next login; sessions end |
| Locked after wrong attempts | **Unlock** | Can try again immediately |
| Leaves the company, or access must stop | **Disable** | Can't log in, sessions end, **their Telegram session is revoked** on the server |
| Comes back | **Enable** | Can log in again; they link Telegram again |

You can't change **your own** account in the UI. Another admin can do it, or use the command line
below.

## 4. Command line (on the server)

Run these in `/opt/tgviewer` as root on the server (prefix every command with
`docker compose exec api python -m tgviewer.cli`):

| Command | Does |
|---|---|
| `create-user <name>` | New user. Asks for the password (not temporary, ≥ 12 characters) |
| `create-user <name> --admin` | New admin |
| `set-password <name>` | Sets a new password and ends their sessions (use it for your own admin account) |
| `reset-totp <name>` | Removes the authenticator; set up again at next login |
| `disable-user <name>` | Disables the account and revokes the Telegram session |
| `list-users` | All accounts and their flags |

Example:

```bash
ssh -t <user>@<server> \
  "cd /opt/tgviewer && sudo docker compose exec api python -m tgviewer.cli set-password admin"
```

For scripts, `--password-stdin` reads the password from standard input instead of prompting.

## 5. Offboarding checklist

1. Admin area → **Disable** the user. This ends their sessions and revokes the Telegram session
   on the server.
2. Ask the person to check **Telegram → Settings → Devices** on their phone. The gateway session
   should be gone; they can end it there themselves.
3. Their scanned files are removed automatically after the retention period
   (`CLEAN_RETENTION_DAYS`, default 7 days).

## 6. Audit

**In the admin area**, the card **Events: logins and admin actions** lists the latest events,
newest first: who logged in and when, failed logins with the reason (unknown username or disabled
account, wrong password, wrong authenticator code, account locked, admin trying the public
address), lockouts, and admin actions with the admin who did them. Filter by *Failures only*,
*Logins only* or *Admin actions only*. Telegram data and file scans are never shown there.

User-management events go to the JSON audit log (`/data/audit/audit.jsonl` in the `api`
container, ready for any log collector):

| Event | When |
|---|---|
| `admin.user_created` | user created (with role) |
| `admin.password_reset` / `admin.2fa_reset` | reset by an admin |
| `admin.user_unlocked` / `admin.user_disabled` / `admin.user_enabled` | status changed |

Each event includes `actor_id`, the admin who acted. Login successes, failures and lockouts are
logged too. Passwords, codes and message text never are.

## Troubleshooting

| Problem | Cause / fix |
|---|---|
| `http://localhost:8081` doesn't load | The tunnel isn't running (keep the `ssh -L …` window open), or local port 8081 is in use (use `-L 18081:localhost:8081` and open `http://localhost:18081/admin`) |
| *400 Bad Request* | You used `127.0.0.1` on a server that accepts only `localhost`. Use `http://localhost:8081` |
| *404* on `https://<domain>/admin` | Expected: the admin area is only available through the tunnel, or from the addresses in `ADMIN_ALLOWED_IPS` if the operator set it |
| Admin login says "wrong password" through the public address | Expected: admin accounts can log in only through the admin entrance (or from an address in `ADMIN_ALLOWED_IPS`) |
| "Invalid code" from the authenticator | The phone's clock is off. Turn on automatic time. Each code works once |
| Account locked | Wait 15 minutes or ask an admin to click **Unlock** |
| No admin can log in anymore | On the server: `create-user <new-admin> --admin`, or `set-password` / `reset-totp` for the existing admin |
| "The administrator hasn't configured the Telegram API credentials" | `TG_API_ID` / `TG_API_HASH` are missing (see [PRODUCTION.md](PRODUCTION.md#3-settings-and-secrets)) |
| No SMS with the Telegram code | Telegram sends it to the Telegram app first (chat "Telegram" on your phone or computer). Use **Send the code by SMS instead** if the page offers it. Without any other logged-in device, Telegram decides whether SMS is possible |
| "Telegram asks to wait … s" | Too many code requests: wait that long, then try again |
