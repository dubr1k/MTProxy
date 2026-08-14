[English](README.en.md) | **Русский**

# Proxy Control

Мультипротокольная панель управления Telemt/MTProto, NaiveProxy/Caddy и Mieru с транзакционным lifecycle, учётом трафика, адаптивным UI и исходящими mTLS fleet-агентами.

> **Зрелость:** локальные и CI-проверки покрывают код, рендер конфигураций и сборку образов. Полный lifecycle в Ubuntu 24.04/QEMU и production-развёртывание Mieru/fleet пока не подтверждены. Рассматривайте релиз как требующий проверки оператором release candidate, а не как готовый managed service.

[![CI](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml/badge.svg)](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Чем управляет проект

- **Telemt / MTProto:** пользователи, секреты, лимиты, runtime- и quota-счётчики через аутентифицированный приватный API Telemt.
- **NaiveProxy / Caddy:** учётные данные, транзакционные reload Caddy, ссылки доступа и durable-учёт по завершённым CONNECT.
- **Mieru / mita:** пользователи, rolling quota, lifecycle и fail-closed транзакции через отдельно установленный GPLv3+ runtime.
- **Control plane:** FastAPI-панель с RBAC/audit, исходящие mTLS-агенты и durable fleet-очередь команд.

## Статус поддержки

| Область | Статус | Проверка |
|---|---|---|
| Python managers, panel, installer transactions | Проверено локально и в CI | Полный pytest, unittest, Ruff |
| Compose-модели и образы проекта | Проверено локально и в CI | Рендер/сборка core, Naive, Mieru, agent, ingress |
| Установка на существующий shared TCP/443 host | Advanced/manual | Обязательны fail-closed audit/plan и внешний protocol probe |
| Полный lifecycle Ubuntu 24.04 в QEMU | Ожидает проверки | Пока не required gate |
| Production Mieru и fleet enrollment | Ожидает проверки | Проект не заявляет изменённый production host/node |

## Быстрый старт

```sh
git clone https://github.com/dubr1k/proxy-control.git
cd proxy-control
```

Read-only discovery (полный installer поддерживает Ubuntu 24.04):

```sh
sudo python3 scripts/proxyctl.py audit --proxy-domain proxy.example.com --panel-domain panel.example.com --json
sudo python3 scripts/proxyctl.py plan --proxy-domain proxy.example.com --panel-domain panel.example.com \
  --email admin@example.com --route-file /etc/nginx/stream.d/routes.conf \
  --users owner --protocol-probe /usr/local/bin/mtproxy-respq-probe
```

Core Telemt + panel (сначала подготовьте `.env` и mode-0600 secrets):

```sh
docker compose config
docker compose up -d
```

Naive override требует явный hostname:

```sh
export NAIVE_PUBLIC_HOST=naive.example.com
docker compose -f compose.yaml -f compose.naive.yaml config
docker compose -f compose.yaml -f compose.naive.yaml up -d --build
```

Для Mieru нужен отдельно поставляемый GPLv3+ executable `mita` v3.35.0. Пример amd64 ниже получает и распаковывает точный pinned upstream package из [MIERU.en.md](MIERU.en.md#pinned-upstream-artifacts); на arm64 используйте указанные там arm64 URL и оба digest. До назначения фиксированных ID и публичных портов прочитайте обязательные проверки [коллизий identity/state](MIERU.en.md#mandatory-compose-state-provisioning) и [совместного использования listeners](MIERU.en.md#listener-coexistence); при коллизии постороннего UID/GID или порта остановитесь.

```sh
curl -fL --proto '=https' --tlsv1.2 \
  https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_amd64.deb \
  -o mita_3.35.0_amd64.deb
printf '%s  %s\n' cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342 mita_3.35.0_amd64.deb | sha256sum -c -
dpkg-deb -x mita_3.35.0_amd64.deb mita-root
printf '%s  %s\n' 4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 mita-root/usr/bin/mita | sha256sum -c -
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
docker compose -f compose.yaml -f compose.mieru.yaml config
docker compose -f compose.yaml -f compose.mieru.yaml up -d --build
```

Fleet preview: рендерьте `compose.agent.yaml` и `compose.fleet-central.yaml` с тестовыми путями только после чтения [FLEET.en.md](FLEET.en.md). Успешный рендер не означает enrollment или production validation.

## Архитектура

```text
Internet → host Nginx stream/SNI → loopback proxy listeners → Telemt или protocol runtime
                                  ↘ panel TLS → loopback FastAPI + SQLite
Panel → authenticated local Unix/private-network managers → Caddy / mita
Node agent → outbound mTLS → central ingress → durable typed queue
```

Nginx остаётся владельцем публичного TCP/443. Managers имеют ограниченные API и не получают Docker socket. Подробнее: [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Матрица возможностей

| Возможность | Telemt | Naive | Mieru | Fleet v1 |
|---|---|---|---|---|
| User lifecycle | Да | Да | Да | Telemt enable/disable; без secret mutation |
| Limits / quota | Quota, rate, connections, IPs, expiry | Только accounting reset | Rolling approximate quotas | Typed Telemt limit/reset |
| Accounting | Runtime + quota | Completed CONNECT payload | Degraded/unavailable | Secret-free inventory/results |
| Transactional apply / rollback | Installer/runtime checks | Paired config/state journal | CAS snapshot journal | Durable command/result queue |
| Remote lifecycle | Локальная panel | Local manager | Start/stop/restart | Mieru lifecycle allowlist |

## Матрица учёта

| Runtime | Что отображается | Обязательное ограничение |
|---|---|---|
| Telemt | runtime `total_octets` и resettable quota usage | Runtime generations и аварийное завершение влияют на persistence; не billing-grade. |
| Naive/Caddy | payload bytes завершённых CONNECT, сохранённые collector | Появляются при закрытии tunnel; без TLS/IP; незавершённые tunnels могут потеряться при сбое процесса. |
| Mieru/mita | quota configuration; metrics degraded/unavailable в adapter | Approximate application-byte session-admission quota, не hard billing cap. |

Подробнее: [ACCOUNTING.md](docs/ACCOUNTING.md).

## Матрица безопасности и доверия

| Граница | Exposure / trust | Failure semantics |
|---|---|---|
| Public listeners | Только host Nginx и явно выбранные proxy ports | SNI collision, занятые ports и invalid Nginx config fail closed |
| Telemt management | Authenticated API в private Compose network; клиент — panel | API не публикуется на host |
| Naive / Mieru management | Token-authenticated Unix sockets, pinned local runtime | Unknown fields, drift, invalid journals и degraded accounting fail closed |
| Credentials/state | Mode-restricted secrets, named volumes/bind state, SQLite/WAL | Backup как secret-bearing generations; не публиковать links/keys |
| Fleet | Outbound mTLS, certificate identity, typed operations | Durable replay-safe queue; без SSH, Docker socket и arbitrary command/URL |
| Service identities | Раздельные unprivileged identities, read-only roots, dropped caps | Preflight numeric-ID и file-mode collisions |

Перед deployment прочитайте [SECURITY.md](SECURITY.md).

## Руководства по развёртыванию

- [Полный installer/auditor](INSTALLER_AUDITOR.md)
- [Panel и Naive](PANEL.ru.md)
- [MTProto-specific Docker deployment](DOCKER_DEPLOYMENT.md)
- [Mieru](MIERU.en.md)
- [Fleet](FLEET.en.md)
- [Validation gates](docs/VALIDATION.md)

## Upgrade, rollback и совместимость

Runtime identifiers `/opt/mtproxy-shared443`, Compose project `mtproxy`, существующие volumes, unit filenames, installed commands и fleet URI prefix — compatibility contracts и не переименовываются вместе с продуктом. Перед изменением образов, binaries, routes или state прочитайте [COMPATIBILITY.md](docs/COMPATIBILITY.md) и [UPGRADING.md](docs/UPGRADING.md).

## Известные ограничения

- QEMU lifecycle install → audit → repair → upgrade → uninstall → rollback ожидает проверки.
- Production Mieru deployment и fleet enrollment ожидают проверки.
- Mieru per-user metrics намеренно degraded; fleet v1 исключает secret-bearing remote mutations.
- Shared-443 installation требует однозначную Nginx map и внешний реальный `resPQ` probe.
- Счётчики — operational telemetry, а не billing records.

## Лицензии, provenance и third-party software

Код repository распространяется по MIT согласно [LICENSE](LICENSE); существующий copyright не изменён. Telemt, Caddy/modules, Mieru/mita, legacy MTProxy sources, images и Python packages имеют собственные лицензии. GPLv3+ Mieru/mita скачивается или монтируется как отдельный процесс и не включён в repository или его images. См. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Contributing и security

См. [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) и [SECURITY.md](SECURITY.md). Не добавляйте в issues/PR credentials, access URLs, QR codes, certificates, production hostnames или unsanitized logs.
