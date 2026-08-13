[Русский](README.md) | **English**

# MTProxy on a shared TCP/443: Telemt, Nginx SNI routing, and a real cover site

> A Docker MTProto proxy deployment for hosts where public TCP/443 is already shared by Nginx `stream`, HTTPS sites, and Xray/3x-ui.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Runtime: Telemt 3.4.25](https://img.shields.io/badge/Runtime-Telemt%203.4.25-6f42c1.svg)](https://github.com/telemt/telemt)
[![Container: digest pinned](https://img.shields.io/badge/Container-digest--pinned-success.svg)](compose.yaml)

This fork keeps the original systemd scripts, but adds a separate **Docker production path** built around the modern [Telemt](https://github.com/telemt/telemt) engine. It does not require exclusive ownership of public port `443`: Nginx reads SNI without terminating TLS and forwards only the dedicated proxy hostname to a loopback-published container listener.

## Why the runtime was replaced

The official `TelegramMessenger/MTProxy` engine uses a legacy path through Telegram Middle-End nodes on TCP/8888. On some networks, client TCP and Fake-TLS handshakes succeed while the Middle-End pool remains empty (`ready_targets = 0`), leaving Telegram stuck on `Connecting`.

Telemt uses current Telegram DC endpoints directly over TCP/443. This fork pins the container image by digest and verifies operation with more than a healthcheck:

```text
TCP connect → Fake-TLS → Obfuscated2 → req_pq_multi → Telegram resPQ
```

## Architecture

```text
Internet TCP/443
  → Nginx stream + ssl_preread
  → dedicated MTProxy SNI hostname
  → 127.0.0.1:8445
  → Telemt container:443
  → Telegram DC:443

Regular browser or active probe
  → Telemt mask fallback
  → Caddy container:443
  → static cover site
```

- Telemt is published only on `127.0.0.1:8445`; it does not bind public `0.0.0.0:443`.
- Caddy is reachable only inside the Docker network.
- Unauthenticated TLS traffic is relayed to a real HTTPS cover backend.
- Secrets are not embedded in the image, Compose model, or Git.
- Telemt runtime configuration is generated inside a private `tmpfs`.
- The Telemt API is disabled and user links are not printed to production logs.
- Both containers use read-only root filesystems.
- Telemt runs with all Linux capabilities dropped (`cap_drop: ALL`).

## Docker deployment files

| File | Purpose |
|---|---|
| `compose.yaml` | Telemt and Caddy services, loopback publishing, healthchecks, hardening |
| `docker/telemt-entrypoint.sh` | Safely converts `users.conf` into runtime TOML |
| `docker/Caddyfile` | Internal HTTPS cover backend |
| `docker/site/index.html` | Versioned, self-contained cover site |
| `docker/links.py` | Generates Fake-TLS links locally without logging secrets |
| `DOCKER_DEPLOYMENT.md` | Short operational notes |

## Requirements

- A Linux host with Docker Engine and Docker Compose v2;
- Nginx built with `stream` and `stream_ssl_preread`;
- a dedicated DNS hostname with an A record pointing to the host;
- **DNS-only** mode when using Cloudflare DNS: ordinary orange-cloud proxying does not carry arbitrary MTProto TCP;
- a valid TLS certificate for the cover backend;
- a free loopback port at `127.0.0.1:8445`.

The current `compose.yaml` includes deployment-specific values for `tga.unicorndubr1k.org` and its Let's Encrypt certificate path. For another host, replace the hostname in:

- `compose.yaml`;
- `docker/Caddyfile`;
- the Nginx stream map;
- link-generation commands.

## 1. Clone

```bash
git clone https://github.com/dubr1k/MTProxy.git
cd MTProxy
```

## 2. User secrets

Create a separate 16-byte hex secret for each user:

```bash
mkdir -p secrets
umask 077
{
  printf 'phone=%s\n' "$(openssl rand -hex 16)"
  printf 'laptop=%s\n' "$(openssl rand -hex 16)"
} > secrets/users.conf
chmod 600 secrets/users.conf
```

File format:

```text
phone=0123456789abcdef0123456789abcdef
laptop=fedcba9876543210fedcba9876543210
```

Names may contain ASCII letters, digits, `_`, and `-`. Values must be exactly 32 hexadecimal characters. The file is excluded from Git and the Docker build context.

## 3. Certificate and cover site

Caddy does not issue certificates in this deployment; it reads existing Let's Encrypt files through a read-only mount. The current hostname expects:

```text
/etc/letsencrypt/live/tga.unicorndubr1k.org/fullchain.pem
/etc/letsencrypt/live/tga.unicorndubr1k.org/privkey.pem
```

For another domain, change both the site address and certificate paths in `docker/Caddyfile`. The cover site lives at `docker/site/index.html`; it should not mention proxying or internal infrastructure.

## 4. Nginx stream SNI routing

A minimal pattern looks like this:

```nginx
map $ssl_preread_server_name $stream_backend {
    tga.unicorndubr1k.org  mtproxy_backend;
    default                existing_backend;
}

upstream mtproxy_backend {
    server 127.0.0.1:8445;
}

server {
    listen 443 reuseport;
    proxy_pass $stream_backend;
    ssl_preread on;
}
```

This is an example, not a drop-in replacement for an existing map. On a host that already serves Xray/REALITY and multiple HTTPS sites, add only the new SNI entry to the established stream configuration.

Always validate before reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 5. Start

```bash
docker compose config
docker compose pull
docker compose up -d
```

Inspect runtime state:

```bash
docker compose ps
docker inspect mtproxy --format \
  'health={{.State.Health.Status}} restarts={{.RestartCount}} readonly={{.HostConfig.ReadonlyRootfs}}'
ss -lnt | grep '127.0.0.1:8445'
docker compose logs --tail 100 mtproxy
```

Expected state:

- both `mtproxy` and `mask` are `healthy`;
- `RestartCount=0`;
- the host listener exists only at `127.0.0.1:8445`;
- startup logs report every Telegram DC reachable through `direct`;
- no `panic`, `fatal`, or repeating connection errors.

## 6. Generate client links

Links contain credentials. Do not publish them in issues, CI logs, or shared shell history.

```bash
python3 docker/links.py \
  --server tga.unicorndubr1k.org \
  --port 443 \
  --domain tga.unicorndubr1k.org \
  --secrets secrets/users.conf
```

Fake-TLS secret format:

```text
ee + 32 hexadecimal user-secret characters + hex(domain)
```

For manual Telegram Android setup, choose **MTProto Proxy** and enter server, port, and the complete `ee...` secret.

## 7. Verify correctly

An HTTPS `200`, an open TCP/443, or a healthy container does **not** prove that MTProto works. Use a Telegram client or checker that receives a genuine Telegram `resPQ`.

For each user secret, the probe must:

1. connect to the public hostname on `443`;
2. complete Fake-TLS using the same SNI;
3. send the Obfuscated2 initialization;
4. send an encrypted `req_pq_multi`;
5. receive and validate `resPQ` from a Telegram DC.

Also verify the cover site and adjacent routes:

```bash
curl -fsS https://tga.unicorndubr1k.org/ >/dev/null
sudo nginx -t
systemctl is-active nginx
```

On a shared-443 host, regression-test every existing SNI hostname after any stream-map change.

## Updating

The Telemt image is pinned by digest, so `docker compose pull` cannot silently replace the engine. Update deliberately:

1. review the new Telemt release changelog and license;
2. obtain the new image digest;
3. update the digest in `compose.yaml`;
4. run `docker compose config`;
5. recreate the container;
6. repeat the full `resPQ` probe for every secret and regress all SNI routes;
7. restore the previous digest if any gate fails.

To update ordinary fork files:

```bash
git pull --ff-only
docker compose config
docker compose pull
docker compose up -d
```

## Revoke a user

Remove that user's line from `secrets/users.conf`, then recreate only Telemt:

```bash
docker compose up -d --force-recreate mtproxy
```

Other secrets remain unchanged. Keep a protected backup before editing the secrets file.

## Troubleshooting

| Symptom | Check |
|---|---|
| Android does not open the link | Add it manually as MTProto Proxy; separate `tg://` handling from network diagnosis |
| Telegram stays on `Connecting` | Full `resPQ` probe; Telegram DC reachability; complete `ee...` secret format |
| Browser does not show the cover | Caddy health, certificate paths, `mask_host`, SNI routing |
| Cover works but MTProto does not | HTTPS fallback and MTProto are different paths; website health does not prove Telegram upstream |
| No traffic reaches the host | DNS A/AAAA, Cloudflare DNS-only, public firewall, Nginx stream map |
| Other services on 443 break | Roll back the stream-map change and test every previous SNI route |

## Legacy systemd installer

`install_mtproxy.sh` and `uninstall_mtproxy.sh` are retained from upstream for compatibility and history. They deploy the old official `TelegramMessenger/MTProxy` engine directly through systemd and are **not the recommended production path in this fork**. Do not run the legacy installer alongside this Docker deployment without a separate port and a conflict audit.

## Limitations

- MTProto proxies carry Telegram traffic; voice and video calls may bypass the proxy or be unsupported by the client.
- Fake-TLS improves camouflage but cannot guarantee indistinguishability against every DPI system.
- A cover site does not replace correct network routing.
- The Docker healthcheck validates listener readiness, not the complete Telegram protocol.

## Licensing and provenance

- Original project code and the added deployment files are distributed under [MIT](LICENSE).
- The Telemt runtime has its own [Telemt Public License](https://github.com/telemt/telemt/blob/main/LICENSE); this deployment uses an unmodified image pinned by digest.
- This fork is based on [lingeniare/MTProxy](https://github.com/lingeniare/MTProxy).

See [SECURITY.md](SECURITY.md) for vulnerability reporting and secret-handling notes.
