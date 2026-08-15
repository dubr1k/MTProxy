[English](README.en.md) · **Русский**

<div align="center">

# Proxy Control

**Единая безопасная панель для MTProxy, NaiveProxy и Mieru**

Управление доступами · one-time QR и конфигурации · честный accounting · транзакционные изменения · outbound-only mTLS fleet

[![CI](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml/badge.svg)](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml)
[![Ubuntu 24.04](https://img.shields.io/badge/Ubuntu-24.04-E95420?logo=ubuntu&logoColor=white)](INSTALL.ru.md)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](CONTRIBUTING.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[Быстрый старт](#быстрый-старт) · [Архитектура](#архитектура) · [Возможности](#возможности) · [Руководства](#руководства) · [Безопасность](SECURITY.md)

</div>

<p align="center"><img src="assets/proxy-control-cover.png" alt="Proxy Control illustration" width="100%"></p>

> [!IMPORTANT]
> Proxy Control рассчитан на операторов, которые понимают Docker, Nginx `stream`, DNS и резервное копирование. Core, Naive и Mieru проходят локальные/CI-gates; Telemt, Naive и Mieru проверены в рабочем развёртывании. Полный QEMU lifecycle и production fleet enrollment пока не являются подтверждёнными release-gates.

## Что это

Proxy Control разделяет три прокси-протокола на независимые typed-интеграции и объединяет их общей моделью безопасности:

| Интеграция | Runtime | Что даёт панель |
|---|---|---|
| **MTProxy** | Telemt 3.4.25 | Пользователи, Telegram-ссылки/QR, лимиты, expiry, quota reset, runtime/quota counters |
| **NaiveProxy** | pinned Caddy + forwardproxy | Пользователи, HTTPS URL/QR/config, disable/rotate/delete, accounting завершённых CONNECT |
| **Mieru** | отдельно установленный `mita` 3.35.x | Пользователи, one-time `mierus://` URL/QR/config, rotation, rolling quota, lifecycle |
| **Fleet v1** | outbound mTLS agent | Secret-free inventory, typed mutations, ordered durable command/result queue |

Панель построена на FastAPI и SQLite, поддерживает `owner` / `admin` / `viewer`, Argon2id, CSRF, throttling и аудит без credentials. Managers не получают Docker socket и не принимают произвольные команды.

## Ключевые свойства

- **Один public TCP/443 owner.** Host Nginx `stream` + `ssl_preread` остаётся владельцем shared 443 и маршрутизирует SNI на loopback listeners.
- **Один Compose stack.** Все контейнеры узла имеют явные имена `proxy-control-*`; compatibility project name `mtproxy`, service names и volumes сохраняются для миграционной совместимости. Overlays не создают отдельные проекты.
- **Секреты выдаются ограниченно.** List API не содержит passwords, access URLs, QR или reveal tokens. Mieru/Naive create/rotate раскрываются one-time и с `Cache-Control: no-store`.
- **Транзакции fail closed.** Config/state меняются через backup, journal, validation, atomic replace и rollback.
- **Честные метрики.** Интерфейс не синтезирует трафик. Недоступная protocol boundary отображается как `unavailable`/`degraded`.
- **Least privilege.** Раздельные service identities, read-only root filesystems, dropped capabilities, token-authenticated UDS и отсутствие Docker socket.
- **Fleet без входящего SSH.** Узел сам подключается к central ingress по mTLS; identity привязана к URI SAN, serial и fingerprint.
- **Адаптивный UI.** Desktop, intermediate и mobile layouts; QR/config dialogs не расширяют viewport.

## Архитектура

```text
                              ┌──────────────────────────────┐
Internet TCP/443 ───────────► │ host Nginx stream + SNI map │
                              └──────────────┬───────────────┘
                 ┌───────────────────────────┼───────────────────────────┐
                 ▼                           ▼                           ▼
        Telemt / MTProto             panel HTTPS                 соседние SNI
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

Подробнее: [архитектура](docs/ARCHITECTURE.md), [границы совместимости](docs/COMPATIBILITY.md), [модель безопасности](SECURITY.md).

## Быстрый старт

### 1. Получить исходники

```bash
git clone https://github.com/dubr1k/proxy-control.git
cd proxy-control
```

### 2. Выполнить read-only audit

Полный installer поддерживает Ubuntu 24.04 и существующий однозначный Nginx `ssl_preread` map:

```bash
sudo python3 scripts/proxyctl.py audit \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --json
```

### 3. Сформировать план без изменений

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

Проверьте DNS, occupied ports, Nginx ownership, список пакетов и маршруты. Только после этого запускайте `sudo ./install.sh` с теми же аргументами. Полная процедура: [INSTALL.ru.md](INSTALL.ru.md) и [installer/auditor](INSTALLER_AUDITOR.md).

### 4. Ручной Compose deployment

Подготовьте локальный `.env` и mode-restricted secret files. Не копируйте production values в Git.

```bash
docker compose -f compose.yaml config -q
docker compose -f compose.yaml up -d --build
docker compose -f compose.yaml ps
```

Overlays подключаются к **тому же** project `mtproxy`:

```bash
export COMPOSE_FILE=compose.yaml:compose.naive.yaml:compose.mieru.yaml
docker compose config -q
docker compose up -d --build
```

Сохраните точный `COMPOSE_FILE` в root-only deployment environment и используйте его для `config`, `build`, `up`, `ps`, backup и rollback. Никогда не запускайте `--remove-orphans` с неполным набором overlays.

## Возможности

| Возможность | MTProxy | NaiveProxy | Mieru | Fleet v1 |
|---|:---:|:---:|:---:|:---:|
| Create / disable / enable / delete | ✓ | ✓ | ✓ | Частично |
| Rotate credentials | ✓ | ✓ | ✓ | — |
| QR и client config | Telegram | URL + JSON | `mierus://` + import | — |
| Expiry / limits | ✓ | Accounting baseline | Rolling quota | Typed limits |
| Runtime lifecycle | Telemt | Caddy reload | start/stop/restart | Mieru allowlist |
| Durable transaction / recovery | ✓ | ✓ | ✓ | ✓ |
| Secret-free list/audit | ✓ | ✓ | ✓ | ✓ |

### Выдача Mieru-конфигурации

При **создании** пользователя панель показывает one-time `mierus://` URL, QR-код и готовую команду импорта. После закрытия диалога credential не хранится во frontend state. Для существующего пользователя plaintext нельзя восстановить из `hashedPassword`; кнопка **«Новая ссылка + QR»** выполняет controlled rotation и инвалидирует старую конфигурацию. См. [руководство по выдаче Mieru](docs/MIERU_SHARING.ru.md).

## Accounting без ложной точности

| Runtime | Источник | Что важно понимать |
|---|---|---|
| Telemt | runtime `total_octets` + persistent quota usage | Runtime generation может сбросить diagnostic counter; abrupt stop может потерять недавний quota usage |
| Naive/Caddy | payload bytes завершённых CONNECT | Данные появляются после закрытия tunnel; не включают TLS/IP overhead |
| Mieru/mita | quota configuration, typed status | Per-user traffic boundary недоступна безопасно, поэтому показывается `unavailable` |

Эти значения — operational telemetry, а не billing records. Подробнее: [ACCOUNTING.md](docs/ACCOUNTING.md).

## Руководства

### Установка и протоколы

- [Навигатор по всей документации](docs/README.md)
- [Автоматическая установка — RU](INSTALL.ru.md) · [EN](INSTALL.en.md)
- [Полный installer и auditor — RU](INSTALLER_AUDITOR.ru.md) · [EN](INSTALLER_AUDITOR.md)
- [MTProto за Nginx SNI router — RU](DOCKER_DEPLOYMENT.ru.md) · [EN](DOCKER_DEPLOYMENT.md)
- [Панель и Naive — RU](PANEL.ru.md) · [EN](PANEL.en.md)
- [Mieru — RU](MIERU.ru.md) · [EN](MIERU.en.md)
- [Fleet mTLS — RU](FLEET.ru.md) · [EN](FLEET.en.md)

### Эксплуатация

- [Операционный runbook — RU](docs/OPERATIONS.ru.md) · [EN](docs/OPERATIONS.en.md)
- [Backup и restore — RU](docs/BACKUP_RESTORE.ru.md) · [EN](docs/BACKUP_RESTORE.en.md)
- [Upgrade и rollback](docs/UPGRADING.md)
- [Troubleshooting — RU](docs/TROUBLESHOOTING.ru.md) · [EN](docs/TROUBLESHOOTING.en.md)
- [Validation gates](docs/VALIDATION.md)
- [Compatibility contracts](docs/COMPATIBILITY.md)

## Upgrade и rollback

Перед каждым изменением:

1. Зафиксируйте exact source revision, images/binary digests и полный `COMPOSE_FILE`.
2. Остановите mutation traffic и сделайте согласованный backup секретов, SQLite, volumes, manager state/journals и Nginx ownership files.
3. Выполните `docker compose config -q` и read-only plan/audit.
4. Обновляйте по одной protocol boundary.
5. Проверяйте health **и реальный protocol path**.
6. При ошибке восстанавливайте всю предыдущую generation, а не отдельный файл.

Branding `Proxy Control` не переименовывает migration-sensitive runtime identifiers: `/opt/mtproxy-shared443`, Compose project `mtproxy`, volumes, unit names, installed commands и fleet URI prefix остаются совместимыми.

## Безопасность

Перед production deployment обязательно прочитайте [SECURITY.md](SECURITY.md).

- не публикуйте `.env`, `secrets/`, access URLs, QR, tokens, certificates/private keys, databases или unsanitized logs;
- держите panel app на loopback и публикуйте только через собственный HTTPS boundary;
- не публикуйте Telemt/manager APIs;
- не выдавайте containers Docker socket;
- не меняйте pinned Caddy/mita без provenance, digest и rollback проверки;
- initial owner password необходимо заменить;
- проверяйте соседние SNI после каждого Nginx change.

Уязвимости сообщайте приватно через GitHub Security Advisories, если private reporting включён.

## Проверка разработки

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

CI дополнительно рендерит все Compose combinations, собирает project images и pinned Caddy artifact, проверяет systemd units и documentation links.

## Статус и ограничения

**Подтверждено:**

- full Python test suite и static checks;
- Compose render/build для core, Naive, Mieru, agent и ingress;
- рабочие Telemt, Naive и Mieru protocol paths;
- transactional recovery и secret-free API/RBAC regressions;
- desktop/mobile responsive UI, включая Mieru QR dialog.

**Ещё не заявлено как completed gate:**

- полный QEMU install → audit → repair → upgrade → uninstall → rollback;
- production fleet ingress/enrollment end-to-end;
- billing-grade accounting;
- secret-bearing remote mutations через fleet.

## Лицензии и provenance

Код репозитория распространяется по [MIT License](LICENSE). Telemt, Caddy/forwardproxy, Mieru/mita, legacy MTProxy sources, images и Python packages сохраняют собственные лицензии. GPLv3+ `mita` скачивается/монтируется отдельно и не включён в MIT images или repository. См. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Участие в разработке

См. [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) и [CHANGELOG.md](CHANGELOG.md). Изменения должны сохранять compatibility contracts, сопровождаться regression tests и обновлять RU/EN документацию синхронно.
