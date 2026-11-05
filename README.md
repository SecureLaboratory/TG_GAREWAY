# TG Viewer

*English · [Українська](README.uk.md)*

A self-hosted web gateway that lets employees use **their own Telegram account** from a
corporate network, with every attachment and link checked before it reaches the PC.

- Employees open Telegram in the browser through the gateway. The gateway runs the Telegram
  client on the server, so Telegram itself never has to be reachable from the workstations.
- **Every incoming attachment and link is scanned automatically on arrival**, before anyone
  opens it: ClamAV, YARA, document checks, file-type rules, local threat-intel feeds.
- **Outgoing files** get the same scan, plus DLP rules (keys, tokens, card numbers, labels).
- **Admins** manage users and see statistics, but **can't use Telegram, read chats or see any
  secret**. The admin area is reachable only from the server itself, through an SSH tunnel.
- **Privacy:** message text is never stored or logged. Nothing about employee files or links
  is sent to third parties (VirusTotal is optional and hash-only, with no upload code).

> **Status:** working MVP. Try it with a test Telegram account first, not a real employee's.

## Documentation

| I want to… | Read |
|---|---|
| Try it on my PC | [Run locally](#run-locally) below |
| Run it in production (any Linux host or cloud: TLS proxy, secrets, admin entrance) | [docs/PRODUCTION.md](docs/PRODUCTION.md) ([UK](docs/PRODUCTION.uk.md)) |
| Add users, reset passwords, offboard someone | [docs/USERS.md](docs/USERS.md) ([UK](docs/USERS.uk.md)) |
| Report a vulnerability | [SECURITY.md](SECURITY.md) |

## How it works

```
employee browser ──HTTPS──▶ front door (Caddy) ──▶ gateway (FastAPI + Telethon) ──▶ egress proxy ──▶ Telegram
                            :8080 users                 │  scan queue              (allowlist only)
                            127.0.0.1:8081 admins        ├─▶ ClamAV, YARA, oletools, PDF, image re-encoding
                                                         └─▶ Postgres (users, verdicts, encrypted sessions)
```

| Container | Role | Internet |
|---|---|---|
| `edge` | Front door. Public listener for users; admin listener on localhost only | no |
| `api` | Gateway: web UI, Telegram clients, scan pipeline, link gate, DLP | **no direct route**; only through `egress` |
| `egress` | Squid allowlist: Telegram IP ranges, feed and signature sites | yes (filtered) |
| `clamav` | Antivirus daemon and signature updates | through `egress` |
| `postgres` | Database | no |

## What it does

**Scanning.** Automatic on arrival:

| What | When | Default |
|---|---|---|
| Links (text, hidden links, bot/channel buttons) | on arrival | always |
| Attachments (documents, archives, video, …) | on arrival: downloaded into quarantine and scanned | ≤ 50 MB, private chats, groups, bots (`AUTO_SCAN_*`) |
| Photos | when the chat is opened | `AUTO_SCAN_PHOTOS=false` |
| Verified incoming pictures | light path: real-type check, hash lookup and **re-encoding**; the PC only ever gets the re-encoded copy | `IMAGE_FAST_PATH=true` |
| Bigger files, channel posts | when the user clicks *Scan* | |

- Engines: file-type policy (real type, not the name), ZIP inspection with zip-bomb limits,
  **ClamAV**, **YARA** (built-in rules + YARA Forge), oletools (macros, remote templates), PDF
  active content, local hash feeds. A download is enabled only after a clean verdict.
- **Links** are rewritten to `/go/<id>` and checked on receipt and again on click (local feeds,
  Tranco, heuristics). The result is warn, block or redirect.
- **Outgoing files** go through the same scan plus DLP, with the result send, warn (the user
  confirms) or block.

**Accounts and access.**
- Two-step login: password, then an authenticator app (set up in the browser at first login).
  Passwords issued by an admin are temporary and must be changed.
- Roles: users link and use their Telegram, while admins only manage users and see statistics.
- Consent screen before linking. Users can unlink at any time, and disabling a user also revokes
  their Telegram session.
- Linked Telegram sessions and authenticator secrets are encrypted (AES-256-GCM) with a
  **master key** that your deployment supplies from its secret store (`MASTER_KEY_FILE`), so a
  copy of the database alone can't take over accounts. See [docs/PRODUCTION.md](docs/PRODUCTION.md).

**Operations.**
- Web app in **English and Ukrainian**: it follows the browser's language, with a switch in the
  top bar. Server messages and link warnings follow the same choice.
- Admin statistics page and a JSON audit log (JSON lines, easy to ship to any log collector).
- Telegram clients stay connected on the server and catch up on messages missed during downtime.

**Threat-intel feeds** are downloaded and checked locally:

| Feed | Needs |
|---|---|
| OpenPhish, Tranco top list, YARA Forge rules | nothing |
| MalwareBazaar, URLhaus (abuse.ch) | free `ABUSECH_AUTH_KEY` from https://auth.abuse.ch |
| VirusTotal (optional, `REPUTATION_MODE=local+vt`) | `VT_API_KEY`. Lookups are GET by hash only; files are never uploaded |

The status of every feed is on the admin page.

## Requirements

- A **Telegram API ID and hash**: register an app at https://my.telegram.org with a
  **company-owned** phone number. One app serves all users.
- Docker Desktop, or Docker Engine with Compose v2.24 or newer.
- For production: a Linux host, a TLS proxy or load balancer and a secret store
  ([PRODUCTION.md](docs/PRODUCTION.md)).

## Run locally

```bash
cp .env.example .env                  # fill in TG_API_ID and TG_API_HASH; ABUSECH_AUTH_KEY is optional
docker compose up -d --build          # first start takes a few minutes (ClamAV signatures)
docker compose exec api python -m tgviewer.cli create-user admin --admin
```

1. Open http://localhost:8080/admin and log in as `admin`. Locally the front door listens on
   `127.0.0.1` only, so it is also the admin entrance. In production, the admin area moves to a
   separate localhost-only port; you can also open it on the public address for listed IPs
   (`ADMIN_ALLOWED_IPS`, see [docs/PRODUCTION.md](docs/PRODUCTION.md#4a-admin-access)).
2. Set up the authenticator app (scan the QR code).
3. Under **Users**, create a regular user. A temporary password is shown once.
4. Log out, then log in as that user at http://localhost:8080. Set up the authenticator, change
   the password, accept the consent screen and link your Telegram.

The full user guide is in [docs/USERS.md](docs/USERS.md).

## Tests

```bash
docker compose run --rm --no-deps api python -m pytest -q
```

They cover access control (route sweeps for every role), login and lockout, the admin entrance,
web security headers, the scan engines, the VirusTotal GET-only guard and that every text exists
in both languages.

## Repository layout

| Path | Contents |
|---|---|
| `app/` | Gateway (Python, FastAPI, Telethon), frontend in `app/tgviewer/static/`, tests in `app/tests/` |
| `edge/` | Caddy front door: `Caddyfile` (local), `Caddyfile.proxy` (production, behind a TLS proxy) |
| `egress/` | Squid egress allowlist proxy |
| `clamav/` | ClamAV daemon and freshclam config |
| `docker-compose.yml` | The stack (local and base for production) |
| `docker-compose.prod.yml` | Production override: behind a TLS proxy, secure cookies, admin entrance on localhost |
| `docker-compose.secrets.yml` | Secrets as files (from a secret store, in RAM) instead of `.env` |
| `docs/` | Production guide, user guide |

**Keep your installation separate.** This repository is generic: it holds no provider-specific
setup, account IDs, domains or secrets. Keep these in a separate **private** repository:
- your server `.env`;
- your cloud or provider scripts and policies;
- your image-registry override;
- your resource IDs.

Keep secrets only in your secret store.

## Known limitations

- An employee's own phone can still use the same Telegram account, and nothing opened there is
  scanned. The gateway protects the corporate network, not the phone.
- All Telegram clients run in one process, and the scan queue is in-process (no Redis/SQS).
- Files are stored on a local volume, not S3.
- Local accounts with TOTP; SSO (OIDC) is planned.
- ClamAV is the only AV engine; a second engine and a CAPE sandbox are planned.

## License

[MIT](LICENSE). Third-party components (Telethon, ClamAV, Caddy, Squid, PostgreSQL, YARA rule
sets and feeds) keep their own licences and terms.
