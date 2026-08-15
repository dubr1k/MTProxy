**English** · [Русский](README.md)

<div align="center">

# Proxy Control

**An alternative proxy control panel for experienced operators**

Independent management for MTProxy, NaiveProxy, and Mieru, designed to coexist with 3xUI on the same server.

[![CI](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml/badge.svg)](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[Purpose](#purpose) · [Coexisting with 3xUI](#coexisting-with-3xui) · [Capabilities](#capabilities) · [Installation](#installation) · [Security](SECURITY.md)

</div>

<p align="center"><img src="assets/proxy-control-cover.png" alt="Proxy Control illustration" width="100%"></p>

> [!IMPORTANT]
> This project is intended for experienced users and system operators. It assumes practical knowledge of Docker, Nginx, DNS, TLS, network routing, backups, and secure server operations. It is not a beginner-oriented one-click panel and does not replace an understanding of the proxy services it manages.

## Purpose

Proxy Control was created as an independent alternative control panel in the same broad category as 3xUI. It is not a 3xUI fork and is not intended to replace it: the goal is to provide a separate management plane for other proxy protocols and access credentials.

The panel brings several protocols under one interface while keeping their integrations isolated. Each integration uses a narrow management boundary, and sensitive operations are protected by authorization, audit records, and recovery procedures.

## Coexisting with 3xUI

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

Containers use explicit `proxy-control-*` names. Docker Compose service names and existing volumes remain stable where required for safe upgrades of existing deployments.

## Capabilities

| Integration | Management scope |
|---|---|
| **MTProxy / Telemt** | Users, Telegram links and QR codes, limits, expiry, quota reset, service status |
| **NaiveProxy / Caddy** | Users, HTTPS configurations and QR codes, enable/disable, credential rotation, deletion, completed-connection accounting |
| **Mieru / mita** | Users, one-time `mierus://` links and QR codes, credential rotation, rolling quotas, lifecycle management |
| **Remote nodes** | An optional inventory and management plane over outbound mTLS connections |

The panel is built with FastAPI and SQLite. It provides owner, administrator, and viewer roles, Argon2id, CSRF protection, request throttling, and audit records without credentials.

## Installation

Start with a read-only audit of the host and its existing routing:

```bash
git clone https://github.com/dubr1k/proxy-control.git
cd proxy-control

sudo python3 scripts/proxyctl.py audit \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --json
```

After reviewing DNS, ports, Nginx ownership, and backups, prepare a local `.env` file and protected secret files. Never commit production values to Git.

Use one consistent Compose file set for the core deployment and optional integrations:

```bash
export COMPOSE_FILE=compose.yaml:compose.naive.yaml:compose.mieru.yaml
docker compose config -q
docker compose up -d --build
docker compose ps
```

Full guides: [installation](INSTALL.en.md), [panel and NaiveProxy](PANEL.en.md), [MTProxy behind Nginx](DOCKER_DEPLOYMENT.md), [Mieru](MIERU.en.md), and [remote nodes](FLEET.en.md).

## Security

- Publish the panel only through a controlled HTTPS boundary; protocol management APIs must not be exposed to the Internet.
- Access credentials, links, QR codes, and client configurations are disclosed narrowly and omitted from list responses and audit records.
- Management services receive neither the Docker socket nor arbitrary commands or paths.
- Configuration changes use backups, validation, atomic replacement, and recovery on failure.
- Updating images, Caddy, Telemt, or `mita` requires provenance, checksum, and rollback checks.

Read [SECURITY.md](SECURITY.md) before production deployment.

## Documentation

- [Documentation map](docs/README.md)
- [Operations](docs/OPERATIONS.en.md)
- [Backup and restore](docs/BACKUP_RESTORE.en.md)
- [Upgrade and rollback](docs/UPGRADING.md)
- [Compatibility](docs/COMPATIBILITY.md)
- [Validation and limitations](docs/VALIDATION.md)
- [Contributing](CONTRIBUTING.md)

## Development validation

```bash
python3 -m venv .venv
.venv/bin/pip install -r panel/requirements-dev.txt
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
python3 scripts/check-doc-links.py
git diff --check
```

## Status

Python tests, quality checks, Compose rendering, image builds, MTProxy/NaiveProxy/Mieru panel integrations, and the responsive interface are validated.

The complete QEMU installation and rollback lifecycle, production remote-node enrollment, and billing-grade traffic accounting are not claimed as completed release gates.

## License

Repository code is released under the [MIT License](LICENSE). Telemt, Caddy/forwardproxy, Mieru/`mita`, third-party images, and Python packages retain their own licenses. See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
