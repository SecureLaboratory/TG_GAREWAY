# Security policy

## Reporting a vulnerability

Please **don't open a public issue** for security problems. Report them privately through
GitHub: **Security → Report a vulnerability** on this repository (private vulnerability
reporting).

Please include:
- what is affected (component, file, endpoint) and which version or commit;
- steps to reproduce, or a proof of concept;
- the impact as you see it.

You'll get an answer within a few working days. Please give us reasonable time to fix the problem
before disclosing it.

## Scope

In scope: the gateway (`app/`), the front-door and egress configuration (`edge/`, `egress/`), the
Compose files and the documentation.

Out of scope: Telegram itself, third-party images (Caddy, Postgres, ClamAV) and feeds. Report
those upstream. Problems in your own hosting or cloud setup are out of scope too.

## Security design

- Overview: [README.md](README.md#how-it-works) (containers, network isolation, scanning).
- Automated security checks: `app/tests/` (access control, CSRF, login and lockout, file pipeline).
- Production setup and secrets handling are in [docs/PRODUCTION.md](docs/PRODUCTION.md).

Operators: a deployed instance publishes its own contact at `/.well-known/security.txt` once
`SECURITY_CONTACT` is set.
