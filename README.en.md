**English** · [Русский](README.md)

<div align="center">

# Proxy Control

**An alternative proxy control panel for experienced operators**

Independent management for MTProxy, NaiveProxy, and Mieru, designed to coexist with 3xUI on the same server.

[![CI](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml/badge.svg)](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[Purpose](#purpose) · [Architecture](#architecture-and-port-443) · [Installation](#installation) · [Protocol configuration](#protocol-configuration) · [Operations](#operations-and-upgrades) · [Security](SECURITY.md)

</div>

<p align="center"><img src="assets/proxy-control-cover.png" alt="Proxy Control illustration" width="100%"></p>

> [!IMPORTANT]
> This project is intended for experienced users and system operators. It assumes practical knowledge of Docker, Nginx, DNS, TLS, network routing, backups, and secure server operations. It is not a beginner-oriented panel and does not replace an understanding of the proxy services it manages.

## Purpose

Proxy Control was created as an independent alternative control panel in the same broad category as 3xUI. It is not a 3xUI fork and is not intended to replace it: the goal is to provide a separate management panel for other proxy protocols and access credentials.

The panel brings several protocols under one interface while keeping their integrations isolated. Each integration uses a narrow management boundary, and sensitive operations are protected by authorization, audit records, and recovery procedures.

## Instructions for humans and AI agents

This section is the project's mandatory operating protocol. It is intended both for people installing Proxy Control manually and for AI agents performing development, validation, deployment, or maintenance.

### For humans

1. Define the scope: core Telemt, NaiveProxy, Mieru, Fleet, or a complete test lab. Do not enable optional boundaries in production merely because they are available.
2. Work from a backup and a known generation. Before changing anything, inspect Git, Docker, Nginx, systemd, ports, DNS, and the owner of TCP/443.
3. Use only synthetic domains, tokens, and passwords in examples. Real secrets must never enter Git, README files, CI, logs, screenshots, or error reports.
4. Run `audit` and `plan` before installation. After installation, check containers as well as Nginx, panel `/healthz`, real protocol paths, and adjacent SNI routes.
5. For production changes, preserve the complete previous generation: Compose files, image/binary digests, volumes, secrets, Nginx state, host services, and recovery records.

### For AI agents

An AI agent must follow this algorithm and provide factual command results. It must not stop at a plan, a source edit, or a statement that the result “looks correct”.

#### Before making changes

1. Read this README, [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), the [compatibility policy](docs/COMPATIBILITY.md), affected documents, and `.github/workflows/test.yml`.
2. Run and record the following without exposing secrets:

   ```bash
   pwd
   git status --short --branch
   git log -3 --oneline
   git diff --check
   docker version
   docker compose version
   systemctl is-active docker nginx 2>/dev/null || true
   ss -lntup
   ```

3. Identify the actual change boundary and every connected interface: README, Compose, Dockerfiles, systemd, Python API, UI, JavaScript, tests, backup/restore, and Fleet. Do not change foreign routes, containers, volumes, secrets, or production configuration without an explicit request.
4. When code changes, write a narrow regression test first, verify that it fails for the expected reason, implement the smallest change, and run the test again.

#### Agent dependency setup

In the project checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r panel/requirements-dev.txt
```

The agent must use this `.venv`, not an arbitrary system Python. If a test needs root for permissions, containers, systemd, or filesystem contracts, run that exact test with `sudo` without substituting production secrets.

#### Mandatory repository checks

After every material change, run the complete gate set:

```bash
.venv/bin/ruff check .
sudo .venv/bin/python -m pytest -q
.venv/bin/python -m unittest -v tests/test_deploy.py
python3 scripts/check-doc-links.py
node --check panel/static/app.js

git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
for unit in deploy/*.service; do systemd-analyze verify "$unit"; done
git diff --check
```

If a command is unavailable, fails, is skipped, or runs with the wrong interpreter, the agent must report the check as incomplete. It must not replace evidence with an assumption.

#### Validate every Compose model and image

In an isolated checkout with synthetic values—not in production—the agent must render every supported Compose model:

```bash
docker compose -f compose.yaml config -q
NAIVE_PUBLIC_HOST=naive.example.com \
  docker compose -f compose.yaml -f compose.naive.yaml config -q
MIERU_PUBLIC_HOST=mieru.example.com MIERU_MITA_GID=321 \
MIERU_MITA_BIN=/bin/true \
MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 \
  docker compose -f compose.yaml -f compose.mieru.yaml config -q
NAIVE_PUBLIC_HOST=naive.example.com MIERU_PUBLIC_HOST=mieru.example.com \
MIERU_MITA_GID=321 MIERU_MITA_BIN=/bin/true \
MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 \
  docker compose -f compose.yaml -f compose.naive.yaml -f compose.mieru.yaml config -q
FLEET_NODE_ID=node-ci FLEET_CENTRAL_URL=https://fleet.example.com:8790 \
FLEET_CLIENT_CERT=/tmp/client.crt FLEET_CLIENT_KEY=/tmp/client.key \
  docker compose -f compose.yaml -f compose.agent.yaml config -q
FLEET_SERVER_CERT=/tmp/server.crt FLEET_SERVER_KEY=/tmp/server.key \
FLEET_CLIENT_CA=/tmp/client-ca.crt \
  docker compose -f compose.yaml -f compose.fleet-central.yaml config -q
```

Before these commands, create only synthetic `secrets/users.conf`, `secrets/telemt-api-token`, `secrets/naive-manager-token`, `secrets/mieru-manager-token`, and `.env` in the isolated checkout following the CI example. Do not mount real `.env` files, Docker secrets, certificates, or volumes.

Build all affected images and check runtime identity:

```bash
docker build -f panel/Dockerfile -t proxy-control-panel:test panel
docker build -f mieru_manager/Dockerfile -t proxy-control-mieru-manager:test .
docker build -f deploy/Dockerfile.agent -t proxy-control-agent:test .
docker build -f deploy/Dockerfile.ingress -t proxy-control-ingress:test .

test "$(docker run --rm --entrypoint id proxy-control-ingress:test -u)" = 10001
test "$(docker run --rm --entrypoint id proxy-control-ingress:test -g)" = 10001
```

For Naive, build the pinned Caddy and verify both the version and the required module:

```bash
mkdir -p /tmp/proxy-control-caddy
timeout 10m docker buildx build \
  --file docker/Dockerfile.caddy-naive \
  --output type=local,dest=/tmp/proxy-control-caddy .
env CADDY_BIN=/tmp/proxy-control-caddy/caddy \
  scripts/check-naive-caddy-build.sh
if env CADDY_BIN=/bin/true scripts/check-naive-caddy-build.sh; then
  echo 'negative Caddy build check unexpectedly passed' >&2
  exit 1
fi
```

The final command must fail. If the checker accepts `/bin/true`, the build is unsafe and the agent must stop.

#### Isolated installation and real acceptance checks

If the installer, Compose, Dockerfile, Nginx, systemd, backup, or restore paths are touched, run the QEMU lab without production access:

```bash
make lab-test
make lab-prepare
make lab-start
make lab-smoke
make lab-full
make lab-stop
make lab-clean
```

`make lab-full` covers installation, repeat runs, `repair`, uninstall, SIGKILL recovery, shared-443 coexistence, Docker/image gates, and secret scanning. Under QEMU/TCG it can take more than an hour; lack of time is not a reason to replace it with a partial test. See the [lab description](tests/lab/README.md).

In the running isolated lab, the agent must check:

- `docker compose ps` and actual `healthy` status for every container;
- panel `/healthz` with the correct `Host`;
- `nginx -t`, local listeners, and every adjacent SNI route;
- MTProxy: Fake-TLS → Obfuscated2 → `req_pq_multi` → `resPQ` → a real test client;
- NaiveProxy: cover HTTPS → authenticated `CONNECT` → payload → tunnel close → accounting;
- Mieru: exact `RUNNING` status, TCP/UDP client, manager health, and Unix socket;
- Fleet: unauthenticated mTLS must be rejected, and an enrolled node must complete an inventory cycle;
- backup integrity, `PRAGMA integrity_check`, file modes, and absence of secrets in logs.

On a live server, an AI agent must not run the full lab, recreate volumes, change the firewall, reissue certificates, or delete orphan containers without separate explicit authorization. Production work starts with a backup and read-only audit, changes one boundary at a time, and verifies rollback.

#### Reporting and completion rules

The AI agent must state:

- which files and boundaries changed;
- which commands actually ran and their results;
- which checks passed, failed, or were not run;
- which containers/services were checked and their states;
- which production actions were not performed because of risk;
- the exact commit after validation when a commit was requested.

It must not claim “installed”, “tested”, “healthy”, “committed”, or “updated” without fresh evidence from the corresponding command. When anything is uncertain, the agent must stop at a safe boundary and name the missing proof.

## Architecture and port 443

The primary deployment scenario is running Proxy Control and 3xUI together on the same server.

Proxy Control:

- does not require a separate public process that claims TCP port 443;
- keeps the panel and internal management interfaces on loopback or dedicated local ports;
- is designed for a shared Nginx `stream` entry point with SNI-based routing;
- can run next to 3xUI, other proxies, and websites behind one shared 443 entry point;
- must not take over or break existing SNI routes.

In other words, Proxy Control does not claim TCP/443 for itself: the port remains available for 3xUI and other services, while the shared Nginx routes traffic by SNI.

```text
Client ── TCP/443 ──► Nginx stream + SNI
                         ├──► 3xUI and its services
                         ├──► MTProxy / Telemt
                         ├──► other proxies and websites
                         └──► Proxy Control HTTPS panel
```

### Boundaries and ports

| Boundary | Typical value | Exposure |
|---|---:|---|
| Shared public entry point | TCP/443 | Existing Nginx `stream` only; SNI routing |
| Telemt/MTProxy | `127.0.0.1:8445` with the automated installer | Nginx and the local host only |
| Panel | `127.0.0.1:8787` | Local access or an operator-controlled HTTPS reverse proxy |
| Telemt API | `mtproxy:9091` | Private Compose network only; never publish it on the host |
| Mieru/mita | Explicitly selected TCP and UDP ports | Mieru public listeners; 443 is never taken automatically |
| Mieru management | `/run/mita/mita.sock` and manager UDS | Local Unix sockets only |
| Fleet ingress | TCP/8790 by default | HTTPS/mTLS only, when enabled |

Containers use explicit `proxy-control-*` names. Docker Compose service names, project `mtproxy`, and existing volumes remain stable where required for safe upgrades of existing deployments. Use the same complete `COMPOSE_FILE` set for every command.

## Project scope

| Boundary | Purpose |
|---|---|
| **MTProxy / Telemt** | Users, Telegram links and QR codes, limits, expiry, quota reset, service status |
| **Panel** | Owner, administrator, and viewer roles, secret-free audit, access management |
| **NaiveProxy / Caddy** | Users, HTTPS configurations and QR codes, enable/disable, per-user quota with admission enforcement, credential rotation, deletion, completed-connection accounting |
| **Mieru / mita** | Users, one-time `mierus://` links and QR codes, credential rotation, rolling quotas, lifecycle management |
| **Fleet mTLS** | Optional inventory and limited management of remote nodes over outbound connections |

Traffic semantics differ by protocol: Telemt separates the current process counter from quota usage, Naive counts payload bytes only after a successful `CONNECT` closes, and Mieru reports no safe per-user traffic counter and does not claim billing-grade precision.

# Installation

## Installation modes

| Scenario | What it deploys | When to use it |
|---|---|---|
| Automated installation | Ubuntu 24.04, Telemt/MTProxy, panel, certificates, and Nginx routes | A new node with an existing Nginx SNI router |
| Manual Compose | Core Telemt and panel | A host with existing certificates, routing, and operator-managed lifecycle |
| Optional boundaries | NaiveProxy, Mieru, and Fleet through separate Compose files/systemd units | Only after the core boundary passes acceptance |

The automated installer does not deploy NaiveProxy, Mieru, or Fleet. This is deliberate: each has separate privileges, host services, secrets, ports, and recovery procedures.

## Requirements and hard stops

The automated core installer requires:

- Ubuntu 24.04 and `systemd`;
- `root` or `sudo`;
- Docker Engine and Compose v2, or the ability to install missing packages;
- A/AAAA DNS records for the proxy and panel names pointing directly to the host;
- TCP/80 available for ACME HTTP-01;
- an existing Nginx `stream` listener owning public TCP/443;
- exactly one understandable `$ssl_preread_server_name` map in the selected route file;
- free local ports;
- an external executable probe that validates real Fake-TLS/Obfuscated2 `req_pq_multi → resPQ` for every secret;
- an independent backup of Nginx, services, routes, Docker state, and adjacent SNI routes.

For raw MTProto, disable the DNS/CDN proxy and use DNS-only mode. A/AAAA, NAT, ambiguous Nginx map, occupied port, non-Nginx 443 owner, missing protocol probe, or failed `nginx -t` is a hard stop, not a reason to continue.

## 1. Clone and audit

```bash
git clone https://github.com/dubr1k/proxy-control.git
cd proxy-control

sudo python3 scripts/proxyctl.py audit \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --json
```

`audit` installs no packages and changes no files or services. Review its output for 443 ownership, DNS, Nginx topology, platform, free ports, and collisions.

Before changing the host, capture a private backup:

```bash
umask 077
sudo nginx -t
sudo nginx -T | sudo tee /root/proxy-control-nginx-T.txt >/dev/null
ss -lntup
systemctl is-active nginx docker
```

`nginx-T.txt`, listener output, container inventories, and logs can disclose internal topology. Do not publish or attach them to public issues.

## Build the external MTProto acceptance probe

Before creating the plan, build the pinned TDLib image and install its root-only wrapper from this checkout:

```bash
sudo ./probe/install.sh
```

The installed `/usr/local/libexec/mtproxy-respq-probe` accepts only `--domain DOMAIN --secrets-file PATH`. It mounts the supplied root-owned private file read-only at a fixed container path; each user entry is converted to its Fake-TLS MTProto secret in the container, then checked through TDLib `addProxy` and `pingProxy`. `probe/Dockerfile` pins the base image by digest and `probe/package-lock.json` locks the exact Node/TDLib dependency graph.

This is intentionally outside installer runtime: the installer provides a path, not individual secrets. Secrets never appear in installer or Docker argv, shell history, logs, or safe probe status. The container has a read-only root filesystem, a bounded `/tmp` tmpfs, no capabilities, and `no-new-privileges`; a nonzero exit for any secret blocks acceptance.

## 2. Plan the automated installation

Use the same parameters that will be used for installation:

```bash
sudo python3 scripts/proxyctl.py plan \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --email admin@example.com \
  --route-file /etc/nginx/stream.d/routes.conf \
  --project-dir /opt/mtproxy-shared443 \
  --users owner,phone \
  --protocol-probe /usr/local/bin/mtproxy-respq-probe \
  --json
```

Review:

- project and route-file paths;
- the package set to be installed;
- certificate names;
- local ports;
- user names;
- the external protocol probe path;
- installer-owned changes versus pre-existing foreign files.

The plan and audit must not contain passwords, tokens, user secrets, access URLs, or QR payloads.

## 3. Install the automated core

```bash
sudo ./install.sh \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --email admin@example.com \
  --route-file /etc/nginx/stream.d/routes.conf \
  --project-dir /opt/mtproxy-shared443 \
  --users owner,phone \
  --protocol-probe /usr/local/bin/mtproxy-respq-probe
```

The default `--project-dir` is `/opt/mtproxy-shared443`. `--users` is a comma-separated list; existing valid secrets are preserved on rerender. `--protocol-probe` is mandatory and must be a real MTProto test, not an HTTP check.

The installer performs these transactional steps:

1. installs only missing Ubuntu packages;
2. creates temporary port-80 HTTP-01 vhosts and requests one certificate for both names;
3. creates mode-`0600` secrets;
4. deploys digest-pinned Telemt, the internal cover site, and the panel;
5. publishes Telemt at `127.0.0.1:8445` and the panel at `127.0.0.1:8787`;
6. bootstraps the panel owner through stdin without printing the password;
7. adds only installer-owned Nginx routes: proxy SNI → `8445`, panel SNI → local HTTPS fallback `8443`;
8. starts Compose and waits for health;
9. runs the mandatory external protocol probe;
10. restores the previous consistent generation if anything fails.

The installer does not change UFW, nftables, iptables, DNS, Xray/3xUI, unrelated containers, or unrelated Nginx routes. Its journal and ownership files live under `/var/lib/proxy-control/`; do not remove them manually.

After installation:

```bash
cd /opt/mtproxy-shared443
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
sudo nginx -t
ss -lntup
```

The initial owner password is stored in `secrets/panel-bootstrap-password` with mode `0600`. Read it only through a protected terminal, log in at `https://panel.example.com/login`, and rotate it immediately. Never copy this file into `.env`, Git, tickets, logs, or broadly accessible backups.

MTProxy requires real acceptance tests:

1. Fake-TLS handshake;
2. Obfuscated2;
3. `req_pq_multi`;
4. validated Telegram `resPQ`;
5. a real Telegram client from the target network;
6. every adjacent SNI route.

A healthy container, an HTTP response, or an open port alone does not validate MTProto.

## 4. Manual core Compose deployment

Use manual mode when certificates, Nginx, and the external protocol probe are already managed by the operator.

Create the secrets. `users.conf` uses one `name=secret` line per user; a Telemt secret must contain 32 `A-Za-z0-9_-` characters:

```bash
install -d -m 0700 secrets
printf 'owner=%s\n' "$(openssl rand -hex 16)" > secrets/users.conf
printf 'phone=%s\n' "$(openssl rand -hex 16)" >> secrets/users.conf
printf 'Bearer %s\n' "$(openssl rand -hex 32)" > secrets/telemt-api-token
chmod 0600 secrets/users.conf secrets/telemt-api-token
```

Place cover-site content in `/var/www/proxy.example.com` and the certificate under `/etc/letsencrypt/live/proxy.example.com/`. Create `.env` next to `compose.yaml`:

```dotenv
COMPOSE_FILE=compose.yaml
MTPROXY_DOMAIN=proxy.example.com
MTPROXY_BACKEND_PORT=8445
MTPROXY_COVER_ROOT=/var/www/proxy.example.com
MTPROXY_LETSENCRYPT_ROOT=/etc/letsencrypt
PANEL_ALLOWED_HOSTS=panel.example.com,localhost,127.0.0.1
PANEL_HEALTHCHECK_HOST=panel.example.com
PANEL_COOKIE_SECURE=true
```

`MTPROXY_COVER_ROOT` and `MTPROXY_LETSENCRYPT_ROOT` must exist before startup. `MTPROXY_BACKEND_PORT` is the local Telemt port, not public 443. Do not publish the Telemt API at `9091` through `ports`.

Validate and start:

```bash
docker compose config -q
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
```

Create the first panel owner without putting the password in arguments or shell history:

```bash
read -rsp 'New owner password: ' PANEL_INITIAL_PASSWORD; echo
printf '%s\n' "$PANEL_INITIAL_PASSWORD" | docker compose run --rm -T panel \
  python -m panel.cli create-admin --username owner --role owner --password-stdin
unset PANEL_INITIAL_PASSWORD
docker compose up -d
```

The password must be at least 12 characters and is stored as Argon2id. `PANEL_COOKIE_SECURE=false` is acceptable only for a temporary local HTTP check; keep it `true` behind HTTPS.

## 5. Nginx, DNS, and panel publication

Add only the required entries to the existing SNI map. Do not replace the complete map with a documentation example.

- the proxy name must route to `127.0.0.1:${MTPROXY_BACKEND_PORT}`;
- the panel name must route to an HTTPS reverse proxy serving `127.0.0.1:8787`, or to the installer-provided `127.0.0.1:8443` fallback;
- Telemt, Naive, and Mieru management APIs must not be public;
- run `sudo nginx -t` first, then `sudo systemctl reload nginx`;
- test the proxy, panel, and every adjacent SNI route.

The automated installer owns the Nginx routes and panel TLS vhost it creates. With manual installation, the operator must provide TLS termination and SNI routing in a controlled way.

## Protocol configuration

### Panel and roles

The panel listens on `127.0.0.1:8787`. For temporary workstation access, use an SSH tunnel:

```bash
ssh -L 8787:127.0.0.1:8787 server
```

Main settings:

| Variable | Purpose |
|---|---|
| `PANEL_ALLOWED_HOSTS` | Comma-separated allowed `Host` values; add the public panel name |
| `PANEL_COOKIE_SECURE` | Must be `true` behind HTTPS; `false` only for a temporary local check |
| `PANEL_DATABASE` | SQLite path; Compose uses `/data/panel.sqlite3` on `panel-data` |
| `PANEL_HEALTHCHECK_HOST` | Host used by the `/healthz` check |
| `TELEMT_API_URL` | Internal Telemt address, usually `http://mtproxy:9091` |
| `TELEMT_API_TOKEN_FILE` | Telemt internal token file |
| `NAIVE_ENABLED`, `NAIVE_PUBLIC_HOST` | Enable NaiveProxy and set its public hostname |
| `MIERU_ENABLED`, `MIERU_PUBLIC_HOST` | Enable Mieru and set its public hostname |

Roles:

- `owner` — administrators, users, credential rotation, and Fleet registry;
- `admin` — protocol users and audit within the permitted boundaries;
- `viewer` — read-only access.

The last active owner cannot be deleted or demoted. Every mutation requires CSRF and is audited without passwords, tokens, URLs, QR payloads, or authorization headers.

Naive/Mieru create and rotate operations reveal client credentials once with `Cache-Control: no-store`. List responses are secret-free. An existing Mieru password cannot be recovered; use **New link + QR**, which rotates the credential and invalidates the old configuration.

### MTProxy / Telemt

The core installation uses:

- a digest-pinned Telemt image;
- a local data plane at `127.0.0.1:8445`;
- an internal Bearer-authenticated API at `http://mtproxy:9091`;
- the `telemt-config` volume as the source of truth after first startup;
- `secrets/users.conf` only for the initial import.

After `telemt-config` is first created, later changes are performed through the API and survive container recreation. Deleting the volume is a destructive reset: the entrypoint imports the original `users.conf` again.

Telemt quota usage and the current process counter are different values. A manual quota reset does not reset the current process counter, and an abrupt stop can lose usage written after the last save. The panel does not claim to provide calendar-based automatic resets.

### NaiveProxy / Caddy

Naive is enabled only through `compose.naive.yaml` and uses a host Caddy service. It requires:

- a pinned Caddy `v2.11.4` build containing `http.handlers.forward_proxy`;
- host binary `/usr/local/bin/caddy`;
- Caddy user `naive-caddy` with UID `10003`;
- group `naive-accounting` with GID `10004`;
- manager identity `10002:101`;
- a non-symlink data directory;
- `/var/log/naive-proxy` owned by `10003:10004`, mode `0750`;
- a manager token and source `Caddyfile`.

Build and verify the pinned binary:

```bash
docker build -f docker/Dockerfile.caddy-naive -t proxy-control-caddy-naive:local .
cid=$(docker create proxy-control-caddy-naive:local)
docker cp "$cid:/caddy" /tmp/proxy-control-caddy
docker rm "$cid"
sudo install -o root -g root -m 0755 /tmp/proxy-control-caddy /usr/local/bin/caddy
rm -f /tmp/proxy-control-caddy
/usr/local/bin/caddy version
/usr/local/bin/caddy list-modules | grep -Fx 'http.handlers.forward_proxy'
```

The expected version is `v2.11.4 h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0=`. The pinned Dockerfile uses a builder digest and an immutable module commit; do not replace them with a moving branch.

Prepare data and identities:

```bash
export NAIVE_DATA_DIR=/var/lib/naive-manager
export NAIVE_PUBLIC_HOST=naive.example.com
install -d -o 10002 -g 101 -m 0700 "$NAIVE_DATA_DIR"
install -d -o 10003 -g 10004 -m 0750 /var/log/naive-proxy
getent passwd 10003 || true
getent group 10004 || true
```

If UID `10003` or GID `10004` belongs to another principal, stop and resolve the collision. Do not apply a blind recursive `chown` to restored data.

Copy the existing Caddyfile to `${NAIVE_DATA_DIR}/Caddyfile`. Create the manager token and two protected copies:

```bash
install -d -m 0700 secrets
printf '%s\n' "$(openssl rand -hex 32)" > secrets/naive-manager-token
cp secrets/naive-manager-token "${NAIVE_DATA_DIR}/manager-token"
chown 10002:101 "${NAIVE_DATA_DIR}/Caddyfile" "${NAIVE_DATA_DIR}/manager-token"
chmod 0640 "${NAIVE_DATA_DIR}/Caddyfile"
chmod 0400 "${NAIVE_DATA_DIR}/manager-token"
```

Add to `.env`:

```dotenv
COMPOSE_FILE=compose.yaml:compose.naive.yaml
NAIVE_PUBLIC_HOST=naive.example.com
NAIVE_DATA_DIR=/var/lib/naive-manager
```

Run the initial import and install the service:

```bash
docker compose config -q
docker compose run --rm --build naive-manager --bootstrap-only
caddy adapt --adapter caddyfile --validate --config "${NAIVE_DATA_DIR}/Caddyfile"
sudo install -o root -g root -m 0755 scripts/check-naive-caddy-build.sh /usr/local/libexec/check-naive-caddy-build
sudo install -o root -g root -m 0644 deploy/caddy-naive.service /etc/systemd/system/caddy-naive.service
sudo systemctl daemon-reload
sudo systemctl enable --now caddy-naive
docker compose up -d --build
```

`naive-manager` uses only the local Caddy Admin API and Unix socket, receives no Docker socket, and can read completed logs but cannot create, truncate, rename, or append to them. Never publish the Caddy Admin API.

Naive acceptance:

1. cover HTTPS without credentials;
2. authenticated `CONNECT` through a real client;
3. a known payload;
4. tunnel closure;
5. accounting increment only after successful closure;
6. no authorization in logs;
7. every adjacent SNI route.

Client connections. One access works as both HTTPS (HTTP/1.1) and HTTP/2: the panel hands out `https://<user>:<pass>@<NAIVE_PUBLIC_HOST>`, and the protocol is chosen by ALPN negotiation during the TLS handshake. Client profiles that list "HTTPS" and "HTTP2" as separate options use the same URL and the same credentials, so there is no need to create an access per variant.

HTTP/3 (`quic://`) is off in this deployment: the Caddy server block declares `protocols h1 h2`, and QUIC needs a public UDP port. The nginx `stream` SNI router only handles TCP and cannot parse a QUIC Initial, so HTTP/3 cannot be published through the same port 443 scheme. Enabling it requires `protocols h1 h2 h3`, a free public UDP port (443/UDP on the host may belong to another service), a Caddy listener on that port that bypasses nginx, and a `quic://<user>:<pass>@<host>:<port>` URL for the client.

Naive accounting is payload bytes from completed tunnels without TLS/IP overhead. A per-user quota removes credentials after the observed limit is reached, but it is not a byte-level hard cap or billing counter: an active tunnel may cause overshoot. If the manager fails, do not delete `transaction.json`, paired backups, `-wal`, or `-shm` files.

### Mieru / mita

Mieru uses the separate **mita 3.35.x** process. It is not included in the MIT repository or images; the operator installs the binary separately.

Pinned packages:

| Architecture | Package URL | Package SHA-256 | `usr/bin/mita` SHA-256 |
|---|---|---|---|
| amd64 | `https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_amd64.deb` | `cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342` | `4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31` |
| arm64 | `https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_arm64.deb` | `66ff435dd5bd6078944cb4eb7fc427366afaac5ab51030ff62561c645c31a9e3` | `a4e486c1531b7bebec02eca2b60dcba2a4971b2cd479c590d8405aab59fe6a23` |

Example for amd64:

```bash
curl -fL --proto '=https' --tlsv1.2 \
  https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_amd64.deb \
  -o mita_3.35.0_amd64.deb
printf '%s  %s\n' cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342 mita_3.35.0_amd64.deb | sha256sum -c -
dpkg-deb -x mita_3.35.0_amd64.deb mita-root
printf '%s  %s\n' 4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 mita-root/usr/bin/mita | sha256sum -c -
sudo install -o root -g root -m 0755 mita-root/usr/bin/mita /usr/bin/mita
```

For arm64, replace the URL and both digests. Verify the executable digest, not only the package digest.

For an extracted binary, create a separate system user if the external package did not create one, and prepare its state directory:

```bash
getent group mita >/dev/null || sudo groupadd --system mita
getent passwd mita >/dev/null || sudo useradd --system --gid mita --home-dir /var/lib/mita --create-home --shell /usr/sbin/nologin mita
sudo install -d -o mita -g mita -m 0700 /var/lib/mita
```

Prepare the `mita` service and stable Unix socket:

```bash
sudo install -m 0644 deploy/mita.tmpfiles.conf /etc/tmpfiles.d/mita.conf
sudo install -m 0644 deploy/mita.service /etc/systemd/system/mita.service
sudo systemd-tmpfiles --create /etc/tmpfiles.d/mita.conf
sudo systemctl daemon-reload
sudo systemctl enable --now mita
MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
```

Accept only the exact result `mita server status is "RUNNING"`. Do not use `RuntimeDirectory=mita` with a bind-mounted UDS and do not enable `MITA_INSECURE_UDS`.

The manager uses fixed UID/GID `10005:10005`; these numbers must not belong to an unrelated principal. `MIERU_MITA_GID` must be a separate non-zero group and must not reuse reserved identities `10001–10005`.

```bash
export MIERU_PUBLIC_HOST=mieru.example.com
export MIERU_MANAGER_TOKEN_FILE=/etc/mieru-manager/token
export MIERU_MANAGER_STATE_DIR=/var/lib/mieru-manager
export MIERU_MITA_BIN=/usr/bin/mita
export MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31
export MIERU_MITA_GID="$(stat -c %g /run/mita/mita.sock)"
getent passwd 10005 || true
getent group 10005 || true
```

Both `prepare` commands are mandatory and must run before `docker compose up`. First create the token in a root-owned directory, then pass it to the verifier:

```bash
sudo install -d -o root -g root -m 0750 /etc/mieru-manager
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/mieru-manager/token'
sudo chown root:root /etc/mieru-manager/token
sudo chmod 0600 /etc/mieru-manager/token
sudo ./scripts/prepare-mieru-token.sh prepare /etc/mieru-manager/token
sudo env MIERU_MITA_GID="$MIERU_MITA_GID" ./scripts/prepare-mieru-state.sh prepare "$MIERU_MANAGER_STATE_DIR"
```

The token must be 32–512 ASCII bytes, stored under an existing root-owned directory chain with no group/other write bits, be a regular non-symlink file, and have owner `root:10005`, mode `0440` after preparation. The state directory must be empty, owned by `10005:10005`, and mode `0700`.

Add to `.env`:

```dotenv
COMPOSE_FILE=compose.yaml:compose.mieru.yaml
MIERU_PUBLIC_HOST=mieru.example.com
MIERU_MITA_BIN=/usr/bin/mita
MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31
MIERU_MITA_GID=20005
MIERU_MANAGER_STATE_DIR=/var/lib/mieru-manager
MIERU_MANAGER_TOKEN_FILE=/etc/mieru-manager/token
```

Replace `20005` with the actual GID of the group that can access `/run/mita/mita.sock`, and verify that it is not reserved:

```bash
docker compose config -q
docker compose up -d --build
docker compose ps
```

Mieru never takes 443. Explicitly configure at least one TCP and/or UDP binding, choose dedicated ports, open them in cloud and host firewalls, and verify with `ss -lntup`. The panel validates configuration through the manager; port, MTU, DNS, egress, and network changes require stop/start.

Creating a user returns a one-time `mierus://` link, QR code, and import command. Rotation, disable, and delete require a controlled restart for revocation. The quota is an approximate application-byte admission check, not a hard billing limit. There is no safe typed per-user traffic boundary, so the UI may report `unavailable`.

When restoring Mieru, always restore `journal.json` together with its original `journal.key`. Never delete or regenerate the key to make a journal start.

### Fleet mTLS

Fleet v1 is optional. Creating a node record with `unenrolled` status is not enrollment. Full enrollment requires a node-local key/CSR, offline CA signing, central certificate binding, mTLS authorization, and a successful inventory command.

#### Central ingress

Initialize an offline CA on a protected operator system:

```bash
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-ca-init --ca-dir /root/mtproxy-fleet-ca
sudo install -m 0644 /root/mtproxy-fleet-ca/ca.crt \
  /etc/mtproxy-panel/fleet-client-ca.crt
```

Keep `ca.key` offline and root-only. The central ingress receives only `ca.crt` and a separate normal WebPKI certificate for the exact `FLEET_CENTRAL_URL` hostname.

For Compose, set the certificate paths and listener:

```dotenv
COMPOSE_FILE=compose.yaml:compose.fleet-central.yaml
FLEET_LISTEN_IP=0.0.0.0
FLEET_LISTEN_PORT=8790
FLEET_SERVER_CERT=/secure/fleet/server.crt
FLEET_SERVER_KEY=/secure/fleet/server.key
FLEET_CLIENT_CA=/etc/mtproxy-panel/fleet-client-ca.crt
```

```bash
docker compose config -q
docker compose up -d --build fleet-ingress panel
```

Never place `ca.key` in the container or on an online server. Restrict the firewall to expected clients and do not use the client CA as the public server identity.

#### Node enrollment

1. Register the node as the owner:

   ```bash
   python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
     fleet-register-node node-1 --display-name 'Node 1'
   ```

2. Generate the key and CSR on the node:

   ```bash
   install -d -m 0700 /etc/mtproxy-agent
   openssl req -new -newkey rsa:3072 -nodes -sha256 \
     -subj '/CN=node-1' \
     -keyout /etc/mtproxy-agent/node-1.key \
     -out /etc/mtproxy-agent/node-1.csr
   chmod 0600 /etc/mtproxy-agent/node-1.key
   ```

   The private key never leaves the node.

3. Sign the CSR offline and bind the certificate:

   ```bash
   python -m panel.cli fleet-sign-csr node-1 \
     --ca-dir /root/mtproxy-fleet-ca \
     --csr /secure-inbox/node-1.csr \
     --out /secure-outbox/node-1.crt \
     --days 90

   python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
     fleet-bind-cert node-1 --cert /secure-inbox/node-1.crt
   ```

   The signer creates the canonical URI SAN `urn:mtproxy-panel:node:<node-id>` and ignores requested identity extensions.

4. Return only the node certificate and public CA certificate to the node. Copy `deploy/agent.env.example` to `/etc/mtproxy-agent/agent.env`; set `FLEET_NODE_ID`, `FLEET_CENTRAL_URL`, `FLEET_CLIENT_CERT`, `FLEET_CLIENT_KEY`, local `TELEMT_API_TOKEN_FILE`, and `FLEET_JOURNAL`.

5. Install the unit and verify the outbound connection:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now mtproxy-agent
   journalctl -u mtproxy-agent --since=-5m --no-pager
   ```

   For the systemd unit, copy `deploy/agent.env.example` to `/etc/mtproxy-agent/agent.env` with owner `root:mtproxy-agent` and mode `0640`. Set `FLEET_NODE_ID`, `FLEET_CENTRAL_URL`, `FLEET_CLIENT_CERT`, `FLEET_CLIENT_KEY`, the local `TELEMT_API_TOKEN_FILE`, and `FLEET_JOURNAL`. The node private key must not be readable by the group or other users.

   Alternatively, run the agent through Compose. Put absolute certificate and key paths in `.env`:

   ```dotenv
   COMPOSE_FILE=compose.yaml:compose.agent.yaml
   FLEET_NODE_ID=node-1
   FLEET_CENTRAL_URL=https://fleet.example.com:8790
   FLEET_CLIENT_CERT=/etc/mtproxy-agent/node-1.crt
   FLEET_CLIENT_KEY=/etc/mtproxy-agent/node-1.key
   ```

   Then run:

   ```bash
   docker compose config -q
   docker compose up -d --build fleet-agent
   ```

   The Compose agent depends on a healthy `mtproxy`, publishes no ports, receives no Docker socket, and stores its journal in the separate `fleet-agent-data` volume. When combined with other boundaries, add `compose.agent.yaml` to the same complete `COMPOSE_FILE` instead of starting a separate project.

6. Send a short-lived inventory command first and wait for a durable result. Only after `connected` and a successful result should you use the allowed mutations.

The central ingress can run as a systemd unit instead of Compose. Copy `deploy/fleet-ingress.env.example` to `/etc/mtproxy-panel/fleet-ingress.env`, set `PANEL_DATABASE`, `FLEET_LISTEN_HOST`, `FLEET_LISTEN_PORT`, WebPKI certificate sources `FLEET_SERVER_CERT_SOURCE`/`FLEET_SERVER_KEY_SOURCE`, runtime copy paths, and `FLEET_CLIENT_CA`, then install `deploy/mtproxy-fleet-ingress.service`:

```bash
sudo install -o root -g root -m 0644 deploy/fleet-ingress.env.example /etc/mtproxy-panel/fleet-ingress.env
sudo install -o root -g root -m 0644 deploy/mtproxy-fleet-ingress.service /etc/systemd/system/mtproxy-fleet-ingress.service
sudo systemctl daemon-reload
sudo systemctl enable --now mtproxy-fleet-ingress
```

The unit stages the certificate and private key into a protected runtime directory; the original root-owned Certbot private-key tree remains inaccessible to the panel. Check `systemctl status mtproxy-fleet-ingress` and the mTLS connection.

Allowed operations are limited to inventory, enable, disable, limit updates, quota reset, and bounded Mieru inspection/lifecycle. Remote create/rotate/reveal and secret-bearing configuration apply are rejected until an authenticated sealed-payload layer exists.

For certificate rotation, create and bind the new certificate, replace it on the node, confirm `connected`, and only then revoke the old serial:

```bash
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-revoke-cert node-1 --serial OLD_HEX_SERIAL
```

## First startup and acceptance

After enabling each boundary, check it separately:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
sudo nginx -t
ss -lntup
systemctl is-active nginx docker
```

If host runtimes are enabled:

```bash
systemctl is-active caddy-naive mita
MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
```

### Acceptance checklist

- **MTProxy:** Fake-TLS → Obfuscated2 → `req_pq_multi` → validated `resPQ` → real Telegram client.
- **NaiveProxy:** cover HTTPS → authenticated `CONNECT` → known payload → tunnel close → accounting check.
- **Mieru:** exact `RUNNING` status → real TCP/UDP client → Internet path → manager health.
- **Panel:** HTTPS, login, roles, temporary create/revoke test, no secrets in lists or audit.
- **Routing:** all adjacent SNI routes after every Nginx change.
- **Storage:** `PRAGMA integrity_check`, file modes, ownership, and no unexplained active recovery journal.

Do not run credential-bearing production tests without a cleanup plan. After testing, remove test users, links, QR codes, logs, and temporary files.

# Backups, upgrades, and rollback

## What to back up

| Boundary | Complete generation |
|---|---|
| Panel | SQLite through online backup, or database plus `-wal`/`-shm` with the writer stopped |
| Telemt | `telemt-config` volume, `secrets/users.conf`, API token, and exact image version |
| Naive | Complete `NAIVE_DATA_DIR`, Caddyfile, `users.json`, paired backups, `transaction.json`, accounting SQLite/WAL/SHM, binary, unit, and log permissions |
| Mieru | State directory, `journal.json` with its original `journal.key`, backups, token, binary, unit, `mita` configuration, and UDS contract |
| Fleet center | Panel database, ingress configuration, public server certificate, client CA; offline CA key separately |
| Fleet node | Agent SQLite/outbox, node key and certificate, trusted CA, local Telemt token, unit, and environment |
| Nginx | stream/http configuration, certificate references, owners, modes, ownership manifest, and backups |
| Deployment | Git revision, complete `COMPOSE_FILE`, image digests, binary versions/digests, packages, and units |

A backup is valid only when it is consistent, protected as a secret, checksummed, and tested through restore. Never store the offline Fleet CA key in the same online archive as node backups.

Example online SQLite backup for the panel:

```bash
docker exec -i proxy-control-panel python - <<'PY'
import sqlite3
src = sqlite3.connect('/data/panel.sqlite3')
dst = sqlite3.connect('/data/panel.backup.sqlite3')
with dst:
    src.backup(dst)
print(dst.execute('PRAGMA integrity_check').fetchone()[0])
dst.close(); src.close()
PY
```

The result must be exactly `ok`. Never copy only the main SQLite file while a WAL writer is active.

Before changing one boundary:

1. stop new mutations;
2. record the revision, images, binary digests, and complete Compose file set;
3. create the complete previous generation;
4. change one boundary only;
5. run health and real protocol acceptance;
6. delete rollback artifacts only after confirmation.

## Runtime version updates from the panel

The panel supports safe updates of three runtime boundaries through a separate root-owned `version-agent`: **Telemt**, **NaiveProxy/Caddy**, and **Mieru/mita**. The panel does not receive the Docker socket, download binaries, or accept URLs from the browser.

Before enabling this boundary:

1. Place a checkout without `.env`, `secrets/`, databases, tokens, or PKI private keys at the path configured by `deploy/version-agent.service` (`/opt/proxy-control` by default).
2. Install the unit and configuration as `root:root` only:

   ```bash
   sudo install -d -m 0750 /etc/proxy-control
   sudo install -o root -g root -m 0644 deploy/version-agent.service /etc/systemd/system/version-agent.service
   sudo install -o root -g root -m 0644 deploy/proxy-control-version-agent.tmpfiles.conf /etc/tmpfiles.d/proxy-control-version-agent.conf
   sudo install -o root -g root -m 0600 deploy/version-agent.env.example /etc/proxy-control/version-agent.env
   sudo install -o root -g root -m 0600 deploy/version-catalog.example.json /etc/proxy-control/versions.json
   sudo systemd-tmpfiles --create /etc/tmpfiles.d/proxy-control-version-agent.conf
   ```

3. Replace every example URL, image reference, and SHA-256 in `/etc/proxy-control/versions.json` with verified artifacts. Telemt accepts only immutable image references with `@sha256:...`; Caddy and mita accept only HTTPS URLs without credentials/query and lowercase SHA-256. Do not add `latest`, HTTP, redirects to another host, or arbitrary commands.
4. Set `PROXY_CONTROL_COMPOSE_DIR`, the complete `PROXY_CONTROL_COMPOSE_FILES`, real binary paths, and systemd service names in `version-agent.env`. Do not omit active Compose overlays.
5. Record current versions in the root-owned `/var/lib/proxy-control/version-agent/state.json` and create a complete backup before the first update. If a current version is unknown, perform a read-only audit first; do not guess `expected_current`.
6. Enable the agent and check only its Unix-socket health endpoint:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now version-agent
   sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health
   sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/versions
   ```

Then recreate only the panel container with the complete Compose file set. Keep the `/run/proxy-control` bind mount; the socket must be mode `0660` and belong to a group accessible to panel UID `10001`.

The UI operation is owner-only and requires the current version (`expected_current`). Under an exclusive lock, the agent:

- rereads the root-owned catalog and rejects versions outside the allowlist;
- pulls the immutable Telemt image, writes `version-overrides/compose.versions.yaml`, starts only `mtproxy`, and waits for `healthy`;
- downloads a size-limited Caddy/mita artifact, verifies SHA-256, runs checker/config validation, and atomically replaces the binary;
- restarts only the corresponding service and verifies `is-active`: a reload would re-read the config but keep the old process on the old binary;
- records the installed build in a root-owned pin (`/etc/proxy-control/caddy-naive.pin`) that the unit's `ExecStartPre` check reads, so the startup check cannot refuse the build just installed;
- refuses to update a binary a container pins by digest (by default `mita` while `proxy-control-mieru-manager` exists), because the container would keep the old inode and a stale hash until it is recreated with an updated pin;
- keeps the previous binary, pin and override and restores them on failure;
- writes state only after health verification succeeds.

If the UI reports `version agent unavailable`, do not update manually from the browser. Check the unit, socket permissions, catalog, complete Compose set, and agent logs. Never run `docker compose down -v`, delete volumes, or change 443 for a version operation. The complete protocol and rollback procedure are also documented in [UPGRADING.md](docs/UPGRADING.md).

## Upgrade and recovery

Do not delete `journal.json`, `journal.key`, `transaction.json`, WAL/SHM, or backups to make startup succeed. Use the documented recovery path:

```bash
sudo python3 scripts/proxyctl.py repair
```

`repair` reads the private ownership manifest, completes interrupted recovery, checks foreign drift, and restarts only recorded services. When uncertain, restore the complete previous generation rather than one file.

To remove the core deployment:

```bash
sudo ./uninstall.sh
```

Uninstall stops Compose, removes only installer-owned routes, files, and packages, and preserves secrets, certificates, and cover roots until a separate ownership review. Re-running resumes from the durable phase. After removal, check `nginx -t`, public listeners, and adjacent SNI routes.

If SSH exits with code `255`, that proves only transport failure. Check `/var/lib/proxy-control/runtime.json`, its phase, services, ownership files, Nginx, and the protocol probe before retrying; never blindly reinstall over an active generation.

# Operations and troubleshooting

Daily checks:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
sudo nginx -t
systemctl --no-pager --full status nginx
systemctl is-active caddy-naive mita 2>/dev/null || true
docker compose logs --since=15m --tail=300 panel mtproxy naive-manager mieru-manager
```

Before sharing output, redact passwords, complete access URLs, QR/reveal payloads, bearer/manager/Fleet tokens, cookies, CSRF values, certificates, private keys, and unnecessary host details.

Common failures:

- **Panel is unavailable:** check `127.0.0.1:8787`, `PANEL_ALLOWED_HOSTS`, `PANEL_COOKIE_SECURE`, the reverse proxy, SQLite, and volume ownership.
- **MTProxy is healthy but clients fail:** check A/AAAA, no CDN in front of raw TCP, the SNI map, Fake-TLS name, every secret, and a real `resPQ` probe.
- **Naive manager is unhealthy:** check the token, UDS, pinned Caddy, `caddy adapt --validate`, `transaction.json`, paired backups, and identities `10002:101` / `10003:10004`.
- **Naive accounting does not change:** the connection must be a successfully completed `CONNECT`; an active or aborted tunnel produces no completed record.
- **Mieru manager is unhealthy:** check the exact `mita` version/digest, `/run/mita/mita.sock`, GID, token/state metadata, and journal; never apply a blind recursive `chown`.
- **An old Mieru user has no QR:** this is expected after one-time reveal; use **New link + QR**, knowing that the old configuration will be revoked.
- **Compose reports orphan containers:** restore the complete persisted `COMPOSE_FILE`; do not approve orphan removal from an incomplete model.
- **Fleet remains `unenrolled`:** a registry record is not enrollment; repeat CSR generation, offline signing, certificate binding, node installation, mTLS authorization, and inventory result.

# Security

- Never publish `.env`, `secrets/`, access URLs, QR codes, tokens, databases, logs, or PKI keys.
- Never publish Telemt, manager UDS/API, or the Caddy Admin API.
- Never mount the Docker socket into project services.
- Never update pinned Telemt, Caddy, or `mita` without provenance, digest, and rollback checks.
- Never pass arbitrary commands, paths, or variables through a manager API.
- Do not treat hiding a UI button as a substitute for server-side authorization.
- Read [SECURITY.md](SECURITY.md) and the [compatibility policy](docs/COMPATIBILITY.md) before production deployment.

# Development validation

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r panel/requirements-dev.txt
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
python3 scripts/check-doc-links.py
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
git diff --check
```

Detailed boundary guides: [documentation map](docs/README.md), [automated installation](INSTALL.en.md), [complete installer and auditor](INSTALLER_AUDITOR.md), [panel](PANEL.en.md), [MTProto behind Nginx](DOCKER_DEPLOYMENT.md), [Mieru](MIERU.en.md), [Mieru sharing](docs/MIERU_SHARING.en.md), [Fleet](FLEET.en.md), [operations](docs/OPERATIONS.en.md), [backup and restore](docs/BACKUP_RESTORE.en.md), [upgrades](docs/UPGRADING.md), [troubleshooting](docs/TROUBLESHOOTING.en.md), [accounting](docs/ACCOUNTING.md), and [validation](docs/VALIDATION.md).

# Status and license

Python tests, quality checks, Compose rendering, image builds, MTProxy/NaiveProxy/Mieru panel integrations, and the responsive interface are validated. The complete QEMU installation and rollback lifecycle, production Fleet enrollment, and billing-grade traffic accounting are not claimed as completed release gates.

Repository code is released under the [MIT License](LICENSE). Telemt, Caddy/forwardproxy, Mieru/`mita`, third-party images, and Python packages retain their own licenses. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
