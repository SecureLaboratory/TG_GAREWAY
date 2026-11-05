# Running TG Viewer in production

*English · [Українська](PRODUCTION.uk.md)*

This guide works on any Linux host with Docker, in your data centre or in any cloud. It
describes **what** a production setup needs, not one provider's console. Keep the
provider-specific steps for your installation (accounts, network IDs, scripts) in your own
private repository.

```
employees ──HTTPS──▶ your TLS proxy / load balancer ──HTTP──▶ host :8080  edge (users only)
                     (certificate, only corporate IPs)              │
admins ──SSH tunnel──────────────────────────────────▶ host 127.0.0.1:8081  edge (admin entrance)
                                                                    ▼
                                    api (gateway) ── egress (allowlist) ──▶ Telegram, feeds
                                       │  clamav · postgres
```

## 1. Host

| Item | Recommendation |
|---|---|
| OS | Any current Linux with Docker Engine and **Docker Compose v2.24 or newer** (`!reset`/`!override` tags) |
| Size | 2 vCPU, **4 GB RAM** (ClamAV needs ~1.5 GB), **30 GB** disk |
| Disk | Encrypted (LUKS or the provider's volume encryption); daily snapshots or backups |
| Swap | Off, or encrypted. Secrets in RAM must not be paged to disk |
| Docker daemon | Log rotation (`max-size`), `"no-new-privileges": true`, `"live-restore": true` in `/etc/docker/daemon.json` |
| Inbound firewall | Port **8080 only from your TLS proxy**. SSH only from the admins' addresses (or a bastion/VPN). Nothing else |
| Outbound firewall | TCP 443/80 (and Telegram's IP ranges on 443/80/5222). The `egress` container narrows this further |
| Cloud metadata service | If the host has one (`169.254.169.254`), block it for containers, e.g. `iptables -I DOCKER-USER -d 169.254.169.254/32 -j REJECT` at every boot |

## 2. Images

You can build on the host (`docker compose build`). Alternatively, build in CI, push to your
private registry and add a small override of your own that sets `image:` for `api` and `egress`
and `build: !reset null`. Use a fixed version tag per release, and keep the previous one for
rollback.

## 3. Settings and secrets

Start the stack with the production override. It turns on secure cookies and HSTS, sets the host
name allowlist, adds the admin entrance on localhost, and puts the front door behind a proxy.

```
# /opt/tgviewer/.env  (settings)
COMPOSE_FILE=docker-compose.yml:docker-compose.prod.yml:docker-compose.secrets.yml
TGV_DOMAIN=tg.example.com            # the users' host name (exactly this one is accepted)
TRUSTED_PROXY_CIDR=10.0.0.0/16       # addresses of your TLS proxy (for the real client IP)
SECURITY_CONTACT=mailto:security@example.com
# optional: PUBLIC_BIND=10.0.0.5:8080 (listen on one address only), AUTO_SCAN_MAX_MB, … (.env.example)
# optional: ADMIN_ALLOWED_IPS=203.0.113.7  admin area also through the public address, from these IPs (4a)
```

**Secrets:** there are two ways.

| Way | How | Use |
|---|---|---|
| **Files (recommended)** | Add `docker-compose.secrets.yml`. Before each start, write one file per secret into `SECRETS_DIR` (default `/run/tgviewer-secrets`, a **tmpfs** in RAM), from your secret store: OpenBao agent, sops, a cloud secret manager, … | production |
| `.env` | Leave out `docker-compose.secrets.yml`. Put `TG_API_ID`, `TG_API_HASH`, `POSTGRES_PASSWORD`, `ABUSECH_AUTH_KEY` into a root-only `.env` | first tests only |

| Secret file | Content |
|---|---|
| `master_key` | 32 random bytes, base64 (`head -c 32 /dev/urandom \| base64`). Encrypts each user's Telegram session and authenticator (TOTP) secret, so a copy of the database alone can't take over accounts. **Generate once, back it up in your secret store, never change it.** If it's lost, every user must link Telegram and set up the authenticator again |
| `tg_api_id`, `tg_api_hash` | from https://my.telegram.org (company number) |
| `database_password` | long random; set once (Postgres keeps it) |
| `abusech_auth_key`, `vt_api_key` | optional; an empty file if unused |

With the secret files, the app refuses to start without `master_key` (`REQUIRE_MASTER_KEY`), so
it never silently creates a new key.

## 4. TLS proxy / load balancer

Anything that terminates TLS works: nginx, HAProxy, Traefik, or a cloud load balancer.

- **Certificate** for `TGV_DOMAIN`, TLS 1.2+ (1.3 preferred). Redirect HTTP to HTTPS.
- **Forward only `TGV_DOMAIN`** to `http://<host>:8080`. Answer unknown host names with 404.
- Keep `X-Forwarded-For` (the real client IP is used for rate limiting and audit), and set
  `TRUSTED_PROXY_CIDR` to the proxy's addresses.
- **Health check:** `GET /healthz` returns 200 `{"ok":true}`, also when called by IP.
- Allow long-lived connections (idle timeout ≥ 120 s) for live updates.
- Restrict client addresses to your corporate ranges if you can. Optionally put a WAF in front.
- **Never forward port 8081.** The admin entrance must stay local. To reach the admin area through
  the public address instead, use `ADMIN_ALLOWED_IPS` (section 4a).

## 4a. Admin access

Two ways, your choice:

| Way | Setting | Notes |
|---|---|---|
| **Admin entrance on localhost** (default) | nothing to set | `http://localhost:8081/admin` through an SSH tunnel. The admin area isn't reachable from outside at all |
| **Public address from listed IPs** | `ADMIN_ALLOWED_IPS=203.0.113.7,198.51.100.0/28` in `.env` | `https://<domain>/admin` works from those client addresses. Every other address gets 404 and admin accounts can't log in from it. The localhost entrance keeps working |

With an allowlist:
- List only addresses you control, such as a fixed office IP or your VPN's exit address, never a
  home or mobile range shared with other people.
- The check uses the real client IP from `X-Forwarded-For`, which is trusted only from
  `TRUSTED_PROXY_CIDR`. Set that to the proxy's own addresses only: if client networks fall inside
  it, a client there could claim any address.
- If you also restrict client addresses at the TLS proxy, allow these there too.
- Admins still log in with a password and an authenticator. A wrong entry stops the start
  (`ADMIN_ALLOWED_IPS: …` in `docker compose logs api`).

## 5. Start as a service

Use a systemd unit, so that the secrets are written before Compose starts, and removed when it
stops:

```ini
[Unit]
Description=TG Viewer
After=docker.service network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
TimeoutStartSec=1800
WorkingDirectory=/opt/tgviewer
EnvironmentFile=/opt/tgviewer/.env
# ExecStartPre=/usr/local/bin/tgviewer-fetch-secrets   # your script: secret store -> /run/tgviewer-secrets
ExecStart=/usr/bin/docker compose up -d --remove-orphans
ExecStop=/usr/bin/docker compose down
ExecStopPost=/bin/rm -rf /run/tgviewer-secrets

[Install]
WantedBy=multi-user.target
```

`systemctl enable --now tgviewer`. The first start takes a few minutes, while ClamAV loads its
signatures.

## 6. Check

```bash
cd /opt/tgviewer
docker compose ps                                            # postgres, clamav healthy; rest Up
curl -s -H "Host: tg.example.com" http://127.0.0.1:8080/healthz                       # {"ok":true}
curl -s -o /dev/null -w '%{http_code}\n' -H "Host: tg.example.com" http://127.0.0.1:8080/admin   # 404
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8081/admin                  # 200
curl -sI https://tg.example.com/ | grep -i strict-transport                           # HSTS present
```

Also confirm these:
- the `api` container can't reach the internet directly;
- the outbound requests in `docker compose logs egress` are only to Telegram and the feed sites;
- no secret values show up in `docker compose exec api env`.

## 7. First admin and users

Follow [USERS.md](USERS.md). In short: create the first admin on the host
(`docker compose exec api python -m tgviewer.cli create-user admin --admin`), open the tunnel
(`ssh -L 8081:localhost:8081 <host>`), then use http://localhost:8081/admin.

## 8. Operations

| Task | How |
|---|---|
| Update | New images or `git pull` + `docker compose build`, then `systemctl restart tgviewer`. Back up first |
| Roll back | The previous image tag or commit, then restart |
| Backups | The `appdata` and `pgdata` volumes (or the whole disk), and the **master key** in your secret store. Without the key, a backup can't decrypt the linked sessions |
| Logs | `docker compose logs -f api` · `docker compose logs egress` · ClamAV: `docker compose exec clamav tail -f /var/log/clamav/clamd.log` |
| Audit log | `/data/audit/audit.jsonl` in the `api` container (JSON lines) |
| OS updates | Monthly, then a reboot. The service starts by itself |

## Checklist

- [ ] HTTPS works with a valid certificate; HTTP redirects; unknown host names get 404
- [ ] `https://<domain>/admin` gives 404 (with `ADMIN_ALLOWED_IPS`: from every address not on the list); the admin area works through the tunnel
- [ ] Port 8080 is reachable only from the TLS proxy; 8081 is bound to `127.0.0.1`
- [ ] Secrets are only in the secret store and in `/run/tgviewer-secrets` (tmpfs); not in `.env`, not in images, not in git
- [ ] The master key is backed up in the secret store
- [ ] Containers can't reach a cloud metadata service
- [ ] The disk is encrypted; backups or snapshots are scheduled
- [ ] Admin page → *Engines & feeds*: ClamAV version shown, feeds updated
