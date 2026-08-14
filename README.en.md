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

Naive override requires an explicit public hostname:

```sh
export NAIVE_PUBLIC_HOST=naive.example.com
docker compose -f compose.yaml -f compose.naive.yaml config
docker compose -f compose.yaml -f compose.naive.yaml up -d --build
```

Mieru requires a separately obtained, executable-digest-verified `mita` binary and mandatory state preflight:

```sh
sudo install -d -o root -g root -m 0700 /etc/mieru-manager
sudo sh -c 'umask 077; openssl rand -base64 48 > /etc/mieru-manager/token'
export MIERU_MANAGER_TOKEN_FILE=/etc/mieru-manager/token
sudo ./scripts/prepare-mieru-state.sh prepare "${MIERU_MANAGER_STATE_DIR:-/var/lib/mieru-manager}"
sudo ./scripts/prepare-mieru-token.sh prepare "$MIERU_MANAGER_TOKEN_FILE"
docker compose -f compose.yaml -f compose.mieru.yaml config
docker compose -f compose.yaml -f compose.mieru.yaml up -d --build
```

Fleet preview only: render `compose.agent.yaml` and `compose.fleet-central.yaml` with test paths after reading [FLEET.en.md](FLEET.en.md). Do not treat a render as enrollment or production validation.

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
