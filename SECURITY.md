# Security

gpuwatch is meant for a **trusted home or lab LAN**. It has its own login, but don't expose it to the internet. If you need remote access, put it behind a VPN or an access-controlled reverse proxy.

## Threat model and protections

| Area | What gpuwatch does |
|---|---|
| Access | Every page and API needs a sign-in. The password is stored only as a salted PBKDF2-SHA256 hash (`data/auth.json`, mode 600). Sessions are 256-bit random tokens in an `HttpOnly; SameSite=Strict` cookie (also `Secure` behind HTTPS). Failed logins are slowed down. |
| Machine integrations | `/metrics` and `/api/summary` also accept a read-only API token (`Authorization: Bearer …`). It can't change anything. |
| Changes / CSRF | Changing the machine list needs a session, a custom `X-Gpuwatch` header and a same-origin `Origin`. No CORS headers are sent. |
| Browser | Strict Content-Security-Policy: only the dashboard's own script, pinned by SHA-256 (no `unsafe-inline` scripts), no outside connections, no framing. Also `nosniff`, `X-Frame-Options: DENY`, `same-origin` referrers, and HSTS behind HTTPS. |
| Data from machines | Treated as untrusted: type-checked and HTML-escaped before display, size-limited per line. Secrets in process command lines (`--api-key`, tokens, passwords, URL credentials such as `rtsp://user:pass@…`) are redacted on the machine before anything is sent. |
| SSH | Targets are strictly validated (user, host, port; nothing option-like). ssh runs with `-F /dev/null`, `--` before the host, `BatchMode`, and forwarding, agent, proxy and local commands disabled. Host keys are pinned on first use. |
| Pinned services | Can only point at `localhost` / `127.0.0.1` / `[::1]` on that machine (no fetching other hosts through it). API keys are stored on the hub (mode 600) and never sent back to the browser. |
| Container | Runs as `nobody`, read-only root filesystem, all capabilities dropped except those needed to hand `/data` over at start, `no-new-privileges`, memory and process limits. |

## Recommended setup on each machine

- Authorize the hub's key with the line shown under **Manage machines**. It uses `from="<hub IP>"`, `restrict` and a forced `command=`, so the key only works from the hub, can't forward ports or open a terminal, and can only start the collector.
- Use a dedicated, non-admin account (e.g. `gpuwatch`) rather than your own.
- On macOS, the optional sudo rule allows only the exact `powermetrics` command gpuwatch runs. Don't grant `/usr/bin/powermetrics` with arbitrary arguments: it can write files as root.

## Known limitations

- The hub's SSH private key in `data/` can start the collector on every machine you authorized. Protect and back up `data/` like any credential.
- The password in `.env` or the container environment is readable by anyone with Docker or host admin access. gpuwatch itself stores only the hash.
- Plain HTTP on port 9180 sends the password unencrypted on your LAN. Prefer an HTTPS reverse proxy.

## Reporting a vulnerability

Please open a private security advisory on this repository (**Security → Report a vulnerability**) rather than a public issue.
