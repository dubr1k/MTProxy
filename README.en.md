**English** | [Русский](README.md)

# Proxy Control

Multi-protocol proxy control plane for Telemt/MTProto, NaiveProxy/Caddy, and Mieru, with transactional lifecycle management, accounting, a responsive panel, and outbound mTLS fleet agents.

> **Maturity:** local and CI gates cover code, configuration rendering, and image builds. A full Ubuntu 24.04 QEMU lifecycle and production Mieru/fleet deployment remain pending. Treat this release as an operator-reviewed release candidate, not a turnkey managed service.

[![CI](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml/badge.svg)](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What it manages

- **Telemt / MTProto:** users, secrets, limits, runtime and quota counters through Telemt's authenticated private API.
- **NaiveProxy / Caddy:** credentials, transactional Caddy reloads, access links, and durable completion-log accounting.
- **Mieru / mita:** users, rolling quotas, lifecycle and fail-closed transactions through a separately installed GPLv3+ runtime.
- **Control plane:** FastAPI panel with RBAC/audit plus outbound-only mTLS agents and a durable fleet command queue.

## Support status

| Area | Status | Evidence / gate |
|---|---|---|
| Python managers, panel, installer transactions | Verified locally and in CI | Full pytest, unittest, Ruff |
| Compose models and project images | Verified locally and in CI | Core, Naive, Mieru, agent, central ingress renders/builds |
| Existing-host shared TCP/443 installation | Advanced/manual | Fail-closed audit/plan and external protocol probe required |
| Ubuntu 24.04 full lifecycle in QEMU | Pending | Not a required gate yet |
| Production Mieru and fleet enrollment | Pending | No production host or node is claimed as deployed |

## Quickstarts

Clone the proposed standalone repository name:

```sh
git clone https://github.com/dubr1k/proxy-control.git
cd proxy-control
```

Read-only discovery (complete installer supports Ubuntu 24.04):

```sh
sudo python3 scripts/proxyctl.py audit --proxy-domain proxy.example.com --panel-domain panel.example.com --json
sudo python3 scripts/proxyctl.py plan --proxy-domain proxy.example.com --panel-domain panel.example.com \
  --email admin@example.com --route-file /etc/nginx/stream.d/routes.conf \
  --users owner --protocol-probe /usr/local/bin/mtproxy-respq-probe
```

Core Telemt + panel render (provide local `.env` and mode-0600 secrets first):

```sh
docker compose config
docker compose up -d
```

All Proxy Control containers on one node belong to **one Compose stack** with the compatibility name `mtproxy`. Every Compose file declares `name: mtproxy`; overlays extend that stack instead of creating another one. Before the first `up`, persist the complete active file set in `COMPOSE_FILE` (preferably in the root-only `.env`) and use that exact set for `config`, `build`, `up`, `ps`, backup, and rollback. Never run project components under another `-p`/`COMPOSE_PROJECT_NAME`, and never use `--remove-orphans` with an incomplete overlay set.

Naive override requires an explicit public hostname:

```sh
export NAIVE_PUBLIC_HOST=naive.example.com
export COMPOSE_FILE=compose.yaml:compose.naive.yaml
docker compose config
docker compose up -d --build
```

Mieru requires the separately supplied GPLv3+ v3.35.0 `mita` executable. The amd64 example below obtains and extracts the exact pinned upstream package documented in [MIERU.en.md](MIERU.en.md#pinned-upstream-artifacts); use that guide's arm64 URL and both arm64 digests on arm64. Before assigning fixed IDs or public ports, read the mandatory [identity/state collision preflight](MIERU.en.md#mandatory-compose-state-provisioning) and [listener coexistence checks](MIERU.en.md#listener-coexistence), and stop on any unrelated UID/GID or port collision.

```sh
curl -fL --proto '=https' --tlsv1.2 \
  https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_amd64.deb \
  -o mita_3.35.0_amd64.deb
printf '%s  %s\n' cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342 mita_3.35.0_amd64.deb | sha256sum -c -
dpkg-deb -x mita_3.35.0_amd64.deb mita-root
printf '%s  %s\n' 4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 mita-root/usr/bin/mita | sha256sum -c -
export MTPROXY_DOMAIN=proxy.example.com
export MTPROXY_BACKEND_PORT=18445
export MTPROXY_COVER_ROOT=/srv/proxy-control/cover
export MTPROXY_LETSENCRYPT_ROOT=/etc/letsencrypt
export MIERU_PUBLIC_HOST=mieru.example.com
export MIERU_MITA_BIN="$(realpath mita-root/usr/bin/mita)"
test -x "$MIERU_MITA_BIN"
export MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31
export MIERU_MITA_GID="$(stat -c %g /var/run/mita/mita.sock)"
export MIERU_MANAGER_STATE_DIR=/var/lib/mieru-manager
export MIERU_MANAGER_TOKEN_FILE=/etc/mieru-manager/token
sudo install -d -o root -g root -m 0700 /etc/mieru-manager
sudo sh -c 'umask 077; openssl rand -base64 48 > /etc/mieru-manager/token'
getent passwd 10005 || true
getent group 10005 || true
sudo ./scripts/prepare-mieru-token.sh prepare "$MIERU_MANAGER_TOKEN_FILE"
sudo ./scripts/prepare-mieru-state.sh prepare "$MIERU_MANAGER_STATE_DIR"
export COMPOSE_FILE="${COMPOSE_FILE:-compose.yaml}:compose.mieru.yaml"
docker compose config
docker compose up -d --build
```

Fleet preview only: append `compose.agent.yaml` and/or `compose.fleet-central.yaml` to the same `COMPOSE_FILE` after reading [FLEET.en.md](FLEET.en.md). A separate Compose project is forbidden; do not treat a render as enrollment or production validation.

## Architecture

```text
Internet → host Nginx stream/SNI → loopback proxy listeners → Telemt or protocol runtime
                                  ↘ panel TLS → loopback FastAPI + SQLite
Panel → authenticated local Unix/private-network managers → Caddy / mita
Node agent → outbound mTLS → central ingress → durable typed queue
```

Nginx stays the public TCP/443 owner. Managers have bounded APIs and no Docker socket. See [architecture](docs/ARCHITECTURE.md).

## Capability matrix

| Capability | Telemt | Naive | Mieru | Fleet v1 |
|---|---|---|---|---|
| User lifecycle | Yes | Yes | Yes | Telemt enable/disable; no secret mutation |
| Limits / quota | Quota, rate, connections, IPs, expiry | Accounting reset only | Rolling approximate quotas | Typed Telemt limit/reset operations |
| Accounting | Runtime + quota counters | Completed CONNECT payload | Degraded/unavailable | Secret-free inventory/results |
| Transactional apply / rollback | Installer and runtime checks | Paired config/state journal | CAS snapshot journal | Durable command/result queue |
| Remote lifecycle | Local panel | Local manager | Start/stop/restart | Mieru lifecycle allowlist |

## Accounting matrix

| Runtime | What can be shown | Required caveat |
|---|---|---|
| Telemt | runtime `total_octets` and resettable quota usage | Runtime generations and abrupt termination affect persistence; not billing-grade. |
| Naive/Caddy | completed CONNECT payload bytes persisted by collector | Appears on tunnel close; excludes TLS/IP; unfinished tunnels can be lost on process failure. |
| Mieru/mita | quota configuration; metrics degraded/unavailable in this adapter | Approximate application-byte session-admission quota, not a hard billing cap. |

Details: [ACCOUNTING.md](docs/ACCOUNTING.md).

## Security and trust matrix

| Boundary | Exposure / trust | Failure semantics |
|---|---|---|
| Public listeners | Host Nginx and explicitly selected proxy ports only | SNI collision, occupied ports, or invalid Nginx config fail closed |
| Telemt management | Authenticated API on private Compose network; panel is its client | No host-published API |
| Naive / Mieru management | Token-authenticated Unix sockets; pinned local runtime contracts | Unknown fields, drift, invalid journals, and degraded accounting fail closed |
| Credentials and state | Mode-restricted secrets, named volumes/bind state, SQLite/WAL | Back up as secret-bearing generations; never publish links or keys |
| Fleet | Outbound mTLS, certificate-bound identity, typed operations | Durable replay-safe queue; no SSH, Docker socket, or arbitrary command/URL |
| Service identities | Separate fixed/unprivileged identities, read-only roots, dropped capabilities | Preflight numeric-ID and file-mode collisions |

Read [SECURITY.md](SECURITY.md) before deployment.

## Deployment guides

- [Complete installer/auditor](INSTALLER_AUDITOR.md)
- [Panel and Naive](PANEL.en.md)
- [MTProto-specific Docker deployment](DOCKER_DEPLOYMENT.md)
- [Mieru](MIERU.en.md)
- [Fleet](FLEET.en.md)
- [Validation gates](docs/VALIDATION.md)

## Upgrade, rollback, and compatibility

Runtime identifiers such as `/opt/mtproxy-shared443`, Compose project `mtproxy`, existing volumes, unit filenames, installed commands, and fleet URI prefixes are compatibility contracts and are not renamed by product branding. Read [COMPATIBILITY.md](docs/COMPATIBILITY.md) and [UPGRADING.md](docs/UPGRADING.md) before changing images, binaries, routes, or state.

## Known limitations

- QEMU install → audit → repair → upgrade → uninstall → rollback validation is pending.
- Production Mieru deployment and fleet enrollment are pending.
- Mieru per-user metrics are deliberately degraded; fleet v1 excludes secret-bearing remote mutations.
- Shared-443 installation requires an unambiguous existing Nginx map and an external real `resPQ` probe.
- Counters are operational telemetry, not billing records.

## Licensing, provenance, and third-party software

Repository code is MIT under [LICENSE](LICENSE); its existing copyright text is unchanged. Telemt, Caddy/modules, Mieru/mita, legacy MTProxy sources, images, and Python packages retain their own licenses. Mieru/mita is a separately downloaded or mounted GPLv3+ process and is not bundled in this repository or its images. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [SECURITY.md](SECURITY.md). Never include credentials, access URLs, QR codes, certificates, production hostnames, or unsanitized logs in an issue or pull request.
