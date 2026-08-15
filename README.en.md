**English** · [Русский](README.md)

<div align="center">

# Proxy Control

**One secure control plane for MTProxy, NaiveProxy, and Mieru**

Access lifecycle · one-time QR and client configs · honest accounting · transactional changes · outbound-only mTLS fleet

[![CI](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml/badge.svg)](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml)
[![Ubuntu 24.04](https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white)](INSTALL.en.md)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](CONTRIBUTING.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[Quick start](#quick-start) · [Architecture](#architecture) · [Capabilities](#capabilities) · [Guides](#guides) · [Security](SECURITY.md)

</div>

> [!IMPORTANT]
> Proxy Control targets operators who understand Docker, Nginx `stream`, DNS, and backups. Core, Naive, and Mieru pass local/CI gates; Telemt, Naive, and Mieru have been validated in a live deployment. The complete QEMU lifecycle and production fleet enrollment are not yet confirmed release gates.

## What it is

Proxy Control keeps three proxy protocols behind independent typed integrations and gives them a shared security model:

| Integration | Runtime | Panel capabilities |
|---|---|---|
| **MTProxy** | Telemt 3.4.25 | Users, Telegram links/QR, limits, expiry, quota reset, runtime/quota counters |
| **NaiveProxy** | pinned Caddy + forwardproxy | Users, HTTPS URL/QR/config, disable/rotate/delete, completed-CONNECT accounting |
| **Mieru** | separately installed `mita` 3.35.x | Users, one-time `mierus://` URL/QR/config, rotation, rolling quota, lifecycle |
| **Fleet v1** | outbound mTLS agent | Secret-free inventory, typed mutations, ordered durable command/result queue |

The FastAPI/SQLite panel provides `owner` / `admin` / `viewer` roles, Argon2id, CSRF, throttling, and credential-free audit records. Managers receive neither a Docker socket nor arbitrary command execution.

## Design properties

- **One public TCP/443 owner.** Host Nginx `stream` + `ssl_preread` keeps shared 443 and routes SNI to loopback listeners.
- **One Compose stack.** Every node container uses the compatibility project name `mtproxy`; overlays never create separate projects.
- **Bounded secret disclosure.** List APIs omit passwords, access URLs, QR codes, and reveal tokens. Mieru/Naive create and rotate responses are one-time and `Cache-Control: no-store`.
- **Fail-closed transactions.** Config/state changes use backup, journal, validation, atomic replace, and rollback.
- **Honest metrics.** The UI never invents traffic. Missing protocol boundaries render as `unavailable` or `degraded`.
- **Least privilege.** Separate service identities, read-only roots, dropped capabilities, token-authenticated UDS, no Docker socket.
- **Fleet without inbound SSH.** Nodes connect to central ingress over mTLS; identity is bound to URI SAN, serial, and fingerprint.
- **Responsive UI.** Desktop, intermediate, and mobile layouts; QR/config dialogs do not widen the viewport.

## Architecture

```text
                              ┌──────────────────────────────┐
Internet TCP/443 ───────────► │ host Nginx stream + SNI map │
                              └──────────────┬───────────────┘
                 ┌───────────────────────────┼───────────────────────────┐
                 ▼                           ▼                           ▼
        Telemt / MTProto             panel HTTPS                 adjacent SNI
        loopback backend             loopback FastAPI            Xray / sites / etc.
                 │                           │
                 │                  ┌────────┼────────┐
                 │                  ▼        ▼        ▼
                 │               Telemt    Naive    Mieru
                 │               private   manager  manager
                 │               API       UDS      UDS
                 │                          │        │
                 │                        Caddy    host mita
                 └───────────────────────────────────────────────────────

Remote node ── outbound mTLS ──► fleet ingress ──► durable typed queue
```

See [architecture](docs/ARCHITECTURE.md), [compatibility boundary](docs/COMPATIBILITY.md), and [security model](SECURITY.md).

## Quick start

### 1. Clone

```bash
git clone https://github.com/dubr1k/proxy-control.git
cd proxy-control
```

### 2. Run a read-only audit

The complete installer supports Ubuntu 24.04 with an existing, unambiguous Nginx `ssl_preread` map:

```bash
sudo python3 scripts/proxyctl.py audit \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --json
```

### 3. Build a no-change plan

```bash
sudo python3 scripts/proxyctl.py plan \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --email admin@example.com \
  --route-file /etc/nginx/stream.d/routes.conf \
  --users owner,phone \
  --protocol-probe /usr/local/bin/mtproxy-respq-probe \
  --json
```

Review DNS, occupied ports, Nginx ownership, packages, and routes. Only then run `sudo ./install.sh` with the same arguments. See [INSTALL.en.md](INSTALL.en.md) and the [installer/auditor reference](INSTALLER_AUDITOR.md).

### 4. Manual Compose deployment

Prepare a local `.env` and mode-restricted secret files. Never copy production values into Git.

```bash
docker compose -f compose.yaml config -q
docker compose -f compose.yaml up -d --build
docker compose -f compose.yaml ps
```

Overlays extend the **same** `mtproxy` project:

```bash
export COMPOSE_FILE=compose.yaml:compose.naive.yaml:compose.mieru.yaml
docker compose config -q
docker compose up -d --build
```

Persist the exact `COMPOSE_FILE` in a root-only deployment environment and use it for `config`, `build`, `up`, `ps`, backup, and rollback. Never use `--remove-orphans` with an incomplete overlay set.

## Capabilities

| Capability | MTProxy | NaiveProxy | Mieru | Fleet v1 |
|---|:---:|:---:|:---:|:---:|
| Create / disable / enable / delete | ✓ | ✓ | ✓ | Partial |
| Rotate credentials | ✓ | ✓ | ✓ | — |
| QR and client config | Telegram | URL + JSON | `mierus://` + import | — |
| Expiry / limits | ✓ | Accounting baseline | Rolling quota | Typed limits |
| Runtime lifecycle | Telemt | Caddy reload | start/stop/restart | Mieru allowlist |
| Durable transaction / recovery | ✓ | ✓ | ✓ | ✓ |
| Secret-free list/audit | ✓ | ✓ | ✓ | ✓ |

### Sharing a Mieru configuration

When a user is **created**, the panel displays a one-time `mierus://` URL, QR code, and import command. Closing the dialog removes the credential from frontend state. Existing plaintext cannot be recovered from `hashedPassword`; **New link + QR** performs controlled rotation and invalidates the previous configuration. See [Mieru sharing](docs/MIERU_SHARING.en.md).

## Accounting without false precision

| Runtime | Source | Required caveat |
|---|---|---|
| Telemt | runtime `total_octets` + persistent quota usage | A runtime generation may reset diagnostics; abrupt stop may lose recent quota usage |
| Naive/Caddy | payload bytes of completed CONNECT sessions | Values appear on tunnel close and exclude TLS/IP overhead |
| Mieru/mita | quota configuration and typed status | No safe typed per-user traffic boundary; the UI reports `unavailable` |

These are operational signals, not billing records. Details: [ACCOUNTING.md](docs/ACCOUNTING.md).

## Guides

### Installation and protocols

- [Documentation map](docs/README.md)
- [Automated installation — EN](INSTALL.en.md) · [RU](INSTALL.ru.md)
- [Complete installer and auditor — EN](INSTALLER_AUDITOR.md) · [RU](INSTALLER_AUDITOR.ru.md)
- [MTProto behind Nginx SNI — EN](DOCKER_DEPLOYMENT.md) · [RU](DOCKER_DEPLOYMENT.ru.md)
- [Panel and Naive — EN](PANEL.en.md) · [RU](PANEL.ru.md)
- [Mieru — EN](MIERU.en.md) · [RU](MIERU.ru.md)
- [Fleet mTLS — EN](FLEET.en.md) · [RU](FLEET.ru.md)

### Operations

- [Operations runbook — EN](docs/OPERATIONS.en.md) · [RU](docs/OPERATIONS.ru.md)
- [Backup and restore — EN](docs/BACKUP_RESTORE.en.md) · [RU](docs/BACKUP_RESTORE.ru.md)
- [Upgrade and rollback](docs/UPGRADING.md)
- [Troubleshooting — EN](docs/TROUBLESHOOTING.en.md) · [RU](docs/TROUBLESHOOTING.ru.md)
- [Validation gates](docs/VALIDATION.md)
- [Compatibility contracts](docs/COMPATIBILITY.md)

## Upgrade and rollback

Before every change:

1. Record the exact source revision, image/binary digests, and full `COMPOSE_FILE`.
2. Quiesce mutations and create a consistent backup of secrets, SQLite, volumes, manager state/journals, and Nginx ownership files.
3. Run `docker compose config -q` and a read-only plan/audit.
4. Upgrade one protocol boundary at a time.
5. Verify health **and the real protocol path**.
6. On failure, restore the complete previous generation—not one convenient file.

The `Proxy Control` brand does not rename migration-sensitive identifiers: `/opt/mtproxy-shared443`, Compose project `mtproxy`, volumes, unit names, installed commands, and fleet URI prefixes remain stable.

## Security

Read [SECURITY.md](SECURITY.md) before production deployment.

- never publish `.env`, `secrets/`, access URLs, QR codes, tokens, certificates/private keys, databases, or unsanitized logs;
- keep the panel app on loopback and expose it only through an operator-controlled HTTPS boundary;
- never publish Telemt or manager APIs;
- never mount the Docker socket into project services;
- never update pinned Caddy/mita without provenance, digest, and rollback checks;
- rotate the initial owner password;
- regression-test every adjacent SNI after an Nginx change.

Report vulnerabilities privately through GitHub Security Advisories when private reporting is enabled.

## Development validation

```bash
python3 -m venv .venv
.venv/bin/pip install -r panel/requirements-dev.txt
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
python3 -m unittest -v tests/test_deploy.py
python3 scripts/check-doc-links.py
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
git diff --check
```

CI additionally renders every Compose combination, builds project images and the pinned Caddy artifact, verifies systemd units, and checks documentation links.

## Status and limitations

**Validated:**

- full Python test suite and static checks;
- Compose render/build for core, Naive, Mieru, agent, and ingress;
- live Telemt, Naive, and Mieru protocol paths;
- transactional recovery and secret-free API/RBAC regressions;
- responsive desktop/mobile UI including the Mieru QR dialog.

**Not yet claimed as a completed gate:**

- complete QEMU install → audit → repair → upgrade → uninstall → rollback;
- production fleet ingress/enrollment end-to-end;
- billing-grade accounting;
- secret-bearing remote mutations through fleet.

## Licensing and provenance

Repository code is released under the [MIT License](LICENSE). Telemt, Caddy/forwardproxy, Mieru/mita, legacy MTProxy sources, images, and Python packages retain their own licenses. GPLv3+ `mita` is downloaded/mounted separately and is not bundled in the MIT repository or images. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), and [CHANGELOG.md](CHANGELOG.md). Changes must preserve compatibility contracts, include regression coverage, and update RU/EN documentation together.
