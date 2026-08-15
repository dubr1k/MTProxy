# Proxy Control documentation

[Русский](#русский) · [English](#english)

This index separates **installation**, **protocol configuration**, **operations**, and **development**. Start with the language-specific README, then follow the runbook for the boundary you are changing.

## Русский

### Начало работы

1. [Обзор продукта и быстрый старт](../README.md)
2. [Автоматическая установка на Ubuntu 24.04](../INSTALL.ru.md)
3. [Полный installer/auditor](../INSTALLER_AUDITOR.ru.md)
4. [Архитектура](ARCHITECTURE.md) и [compatibility contracts](COMPATIBILITY.md)

### Протоколы и панель

- [Панель, роли, Telemt и NaiveProxy](../PANEL.ru.md)
- [MTProto за Nginx SNI](../DOCKER_DEPLOYMENT.ru.md)
- [Mieru/mita](../MIERU.ru.md)
- [Выдача Mieru URL, QR и client config](MIERU_SHARING.ru.md)
- [Fleet mTLS и enrollment](../FLEET.ru.md)

### Эксплуатация

- [Ежедневный операционный runbook](OPERATIONS.ru.md)
- [Backup и restore](BACKUP_RESTORE.ru.md)
- [Upgrade и rollback](UPGRADING.md)
- [Troubleshooting](TROUBLESHOOTING.ru.md)
- [Accounting semantics](ACCOUNTING.md)
- [Validation gates](VALIDATION.md)
- [Security policy](../SECURITY.md)

## English

### Getting started

1. [Product overview and quick start](../README.en.md)
2. [Automated installation on Ubuntu 24.04](../INSTALL.en.md)
3. [Complete installer/auditor](../INSTALLER_AUDITOR.md)
4. [Architecture](ARCHITECTURE.md) and [compatibility contracts](COMPATIBILITY.md)

### Protocols and panel

- [Panel, roles, Telemt, and NaiveProxy](../PANEL.en.md)
- [MTProto behind Nginx SNI](../DOCKER_DEPLOYMENT.md)
- [Mieru/mita](../MIERU.en.md)
- [Mieru URL, QR, and client config sharing](MIERU_SHARING.en.md)
- [Fleet mTLS and enrollment](../FLEET.en.md)

### Operations

- [Daily operations runbook](OPERATIONS.en.md)
- [Backup and restore](BACKUP_RESTORE.en.md)
- [Upgrade and rollback](UPGRADING.md)
- [Troubleshooting](TROUBLESHOOTING.en.md)
- [Accounting semantics](ACCOUNTING.md)
- [Validation gates](VALIDATION.md)
- [Security policy](../SECURITY.md)

## Common rules

- Keep public TCP/443 under the existing host Nginx `stream` router.
- Keep every node in the single Compose project `mtproxy`.
- Persist and reuse the exact full `COMPOSE_FILE` overlay list.
- Treat `.env`, `secrets/`, access URLs, QR codes, databases, journals, and PKI as credentials.
- Back up a complete generation before changing runtime, state, identities, ports, or routes.
- A healthy process is not a protocol test. Validate MTProto `resPQ`, Naive authenticated CONNECT, and Mieru end-to-end transport.
- Never claim unavailable accounting precision.
- Fleet registry creation is not enrollment; enrollment requires certificate issuance, binding, mTLS authorization, and a successful command/result cycle.
