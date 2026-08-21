[English](README.en.md) · **Русский**

<div align="center">

# Proxy Control

**Альтернативная панель управления прокси-сервисами для опытных пользователей**

Самостоятельное управление MTProxy, NaiveProxy и Mieru с возможностью совместной работы с 3xUI на одном сервере.

[![CI](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml/badge.svg)](https://github.com/dubr1k/proxy-control/actions/workflows/test.yml)
[![Лицензия: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[Назначение](#назначение) · [Архитектура](#архитектура-и-порт-443) · [Установка](#установка) · [Настройка протоколов](#настройка-протоколов) · [Эксплуатация](#эксплуатация-и-обновление) · [Безопасность](SECURITY.md)

</div>

<p align="center"><img src="assets/proxy-control-cover.png" alt="Иллюстрация Proxy Control" width="100%"></p>

> [!IMPORTANT]
> Проект рассчитан на опытных пользователей и администраторов. Он предполагает знание Docker, Nginx, DNS, TLS, сетевой маршрутизации, резервного копирования и безопасной эксплуатации серверов. Это не панель «для новичков» и не замена пониманию того, как устроены прокси-сервисы.

## Назначение

Proxy Control создавался как самостоятельная альтернативная панель по типу 3xUI. Это не ответвление 3xUI и не попытка заменить его: задача проекта — дать оператору отдельный контур управления другими прокси-протоколами и доступами.

Панель объединяет управление несколькими протоколами, но сохраняет их раздельными. Каждая интеграция работает через ограниченный интерфейс управления, а чувствительные операции проходят с проверкой прав, журналированием и возможностью восстановления.

## Инструкция для людей и AI-агентов

Этот раздел является обязательным рабочим протоколом проекта. Он предназначен не только для человека, который устанавливает Proxy Control вручную, но и для AI-агентов, выполняющих разработку, проверку, развёртывание или обслуживание.

### Для людей

1. Определите цель: базовый Telemt, NaiveProxy, Mieru, Fleet или полный тестовый стенд. Не включайте дополнительные контуры «на всякий случай» в боевой среде.
2. Работайте с копией и резервной генерацией. Перед изменениями проверьте Git, Docker, Nginx, systemd, порты, DNS и владельца TCP/443.
3. Используйте только синтетические домены, токены и пароли в примерах. Реальные секреты не должны попадать в Git, README, CI, журналы, скриншоты и сообщения об ошибках.
4. Сначала выполните `audit` и `plan`, затем установку. После установки проверяйте не только контейнеры, но и Nginx, panel `/healthz`, реальные протоколы и соседние SNI-маршруты.
5. Если меняется production, сохраняйте полную предыдущую генерацию: Compose-файлы, образы/digest, тома, секреты, Nginx, host-службы и журналы восстановления.

### Для AI-агентов

AI-агент обязан выполнить этот алгоритм и приложить фактический результат команд. Нельзя ограничиваться описанием плана, изменением кода или сообщением «выглядит рабочим».

#### Перед изменением

1. Прочитать этот README, [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [политику совместимости](docs/COMPATIBILITY.md), затронутые документы и `.github/workflows/test.yml`.
2. Выполнить и зафиксировать вывод без секретов:

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

3. Определить фактическую границу изменения и все связанные интерфейсы: README, Compose, Dockerfile, systemd, Python API, UI, JavaScript, тесты, backup/restore и Fleet. Не менять чужие маршруты, контейнеры, volumes, секреты и production-конфигурацию без явного задания.
4. При изменении кода сначала написать узкий регрессионный тест, убедиться, что он падает по ожидаемой причине, затем внести минимальную реализацию и повторить проверку.

#### Установка зависимостей агента

В рабочей копии проекта:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r panel/requirements-dev.txt
```

Агент должен использовать этот `.venv`, а не случайный системный Python. Если тест требует root для проверки прав, контейнеров, systemd или файловой системы, запускать именно тот тест с `sudo`, не подменяя production-секреты.

#### Обязательные проверки репозитория

После каждого существенного изменения выполнить весь набор:

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

Если команда недоступна, она завершилась с ошибкой, тест был пропущен или проверка выполнена не на том интерпретаторе, агент обязан сообщить это как незавершённую проверку, а не заменять её догадкой.

#### Проверка всех Compose-моделей и образов

В изолированной копии с синтетическими значениями, а не в production, агент обязан проверить все модели:

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

Перед этими командами создайте в изолированной копии только синтетические `secrets/users.conf`, `secrets/telemt-api-token`, `secrets/naive-manager-token`, `secrets/mieru-manager-token` и `.env` по примеру CI. Не подключайте настоящие `.env`, Docker secrets, сертификаты или volumes.

Затем собрать все затронутые образы и проверить runtime identity:

```bash
docker build -f panel/Dockerfile -t proxy-control-panel:test panel
docker build -f mieru_manager/Dockerfile -t proxy-control-mieru-manager:test .
docker build -f deploy/Dockerfile.agent -t proxy-control-agent:test .
docker build -f deploy/Dockerfile.ingress -t proxy-control-ingress:test .

test "$(docker run --rm --entrypoint id proxy-control-ingress:test -u)" = 10001
test "$(docker run --rm --entrypoint id proxy-control-ingress:test -g)" = 10001
```

Для Naive дополнительно собрать зафиксированный Caddy и проверить не только номер версии, но и обязательный модуль:

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

Последняя команда обязана завершиться ошибкой. Если проверка принимает `/bin/true`, сборка небезопасна и агент должен остановиться.

#### Изолированная установка и реальные проверки

Если затронуты установщик, Compose, Dockerfile, Nginx, systemd, резервное копирование или восстановление, запустить QEMU-стенд без production-доступов:

```bash
make lab-test
make lab-prepare
make lab-start
make lab-smoke
make lab-full
make lab-stop
make lab-clean
```

`make lab-full` проверяет установку всех доступных компонентов, повторный запуск, `repair`, удаление, восстановление после SIGKILL, совместную работу на 443, Docker/image gates и сканирование секретов. Команда может работать более часа в режиме QEMU/TCG; отсутствие времени не является основанием заменять её частичным тестом. Подробности — в [описании лаборатории](tests/lab/README.md).

В запущенном изолированном стенде агент обязан проверить:

- `docker compose ps` и фактический статус `healthy` каждого контейнера;
- `/healthz` панели с правильным `Host`;
- `nginx -t`, локальные слушатели и все соседние SNI;
- MTProxy: Fake-TLS → Obfuscated2 → `req_pq_multi` → `resPQ` → реальный тестовый клиент;
- NaiveProxy: cover HTTPS → authenticated `CONNECT` → payload → закрытие туннеля → учёт;
- Mieru: точный статус `RUNNING`, TCP/UDP-клиент, manager health и Unix-сокет;
- Fleet: mTLS без клиентского сертификата должен отклоняться, зарегистрированный узел должен пройти inventory cycle;
- резервную копию, `PRAGMA integrity_check`, режимы файлов и отсутствие секретов в логах.

На живом сервере AI-агент не должен выполнять полный стенд, пересоздавать volumes, менять firewall, перевыпускать сертификаты или удалять orphan-контейнеры без отдельного явного разрешения. Для production сначала сделать backup и read-only аудит, затем менять только одну границу и проверять откат.

#### Правила отчёта и завершения

AI-агент обязан указать:

- какие файлы и границы изменены;
- какие команды реально выполнены и их результаты;
- какие проверки прошли, не прошли или не запускались;
- какие контейнеры/службы проверены и в каком состоянии;
- какие production-действия не выполнялись из-за риска;
- точный commit после проверки, если пользователь запросил commit.

Нельзя заявлять «установлено», «протестировано», «здорово», «закоммичено» или «обновлено», если нет свежего подтверждения соответствующей командой. При любой неопределённости агент должен остановиться на безопасной границе и назвать недостающую проверку.

## Архитектура и порт 443

Основной сценарий — совместное развёртывание Proxy Control и 3xUI на одном сервере.

Proxy Control:

- не требует отдельного публичного процесса, который захватывает TCP-порт 443;
- размещает панель и внутренние управляющие интерфейсы на локальных адресах или выделенных портах;
- рассчитан на общую точку входа Nginx с директивой `stream` и маршрутизацией по SNI;
- может работать рядом с 3xUI, другими прокси и сайтами на одном общем 443;
- не должен перехватывать или ломать существующие SNI-маршруты.

Иными словами, Proxy Control не занимает TCP/443 под себя: порт остаётся свободным для 3xUI и других служб, а общий Nginx маршрутизирует трафик по SNI.

```text
Клиент ── TCP/443 ──► Nginx stream + SNI
                         ├──► 3xUI и его службы
                         ├──► MTProxy / Telemt
                         ├──► другие прокси и сайты
                         └──► HTTPS-панель Proxy Control
```

### Границы и порты

| Граница | Обычно используется | Доступ |
|---|---:|---|
| Общая публичная точка входа | TCP/443 | Только существующий Nginx `stream`; маршрутизация по SNI |
| Telemt/MTProxy | `127.0.0.1:8445` при автоматической установке | Только из Nginx и локальной системы |
| Панель | `127.0.0.1:8787` | Локально или через собственный HTTPS reverse proxy |
| Telemt API | `mtproxy:9091` | Только внутри закрытой сети Compose; публикация на host запрещена |
| Mieru/mita | Явно выбранные TCP- и UDP-порты | Публичные порты Mieru; 443 автоматически не используется |
| Mieru управление | `/run/mita/mita.sock` и manager UDS | Только локальные Unix-сокеты |
| Fleet ingress | TCP/8790 по умолчанию | Только HTTPS/mTLS, если контур включён |

Контейнеры имеют явные имена `proxy-control-*`. Внутренние имена Docker Compose, проект `mtproxy` и существующие тома сохраняются там, где это необходимо для безопасного обновления уже работающих установок. Для всех команд используйте один и тот же полный набор файлов `COMPOSE_FILE`.

## Что входит в проект

| Контур | Назначение |
|---|---|
| **MTProxy / Telemt** | Пользователи, Telegram-ссылки и QR-коды, ограничения, срок действия, сброс квоты, состояние сервиса |
| **Панель** | Роли владельца, администратора и наблюдателя, аудит без секретов, управление доступами |
| **NaiveProxy / Caddy** | Пользователи, HTTPS-конфигурации и QR-коды, включение и отключение, per-user quota с admission enforcement, ротация доступов, удаление, учёт завершённых соединений |
| **Mieru / mita** | Пользователи, одноразовые `mierus://`-ссылки и QR-коды, ротация доступов, скользящие квоты, управление жизненным циклом |
| **Fleet mTLS** | Дополнительный контур инвентаризации и ограниченного управления удалёнными узлами через исходящие соединения |

Учёт трафика различается по протоколам: Telemt разделяет текущий счётчик процесса и расход квоты, Naive учитывает полезные байты только после закрытия успешного `CONNECT`, а Mieru показывает недоступность безопасного счётчика на пользователя и не обещает бухгалтерскую точность.

# Установка

## Варианты установки

| Сценарий | Что разворачивается | Когда использовать |
|---|---|---|
| Автоматическая установка | Ubuntu 24.04, Telemt/MTProxy, панель, сертификаты и маршруты Nginx | Для нового узла с существующим Nginx SNI-маршрутизатором |
| Ручной Compose | Базовый Telemt и панель | Для уже подготовленного сервера или собственного процесса выпуска сертификатов |
| Дополнительные контуры | NaiveProxy, Mieru и Fleet отдельными файлами Compose/systemd | Только после успешной проверки базового контура |

Автоматический установщик не разворачивает NaiveProxy, Mieru и Fleet автоматически. Это сделано намеренно: у них отдельные права, host-сервисы, секреты, порты и процедуры восстановления.

## Требования и жёсткие остановки

Для автоматической установки базового контура требуется:

- Ubuntu 24.04 и `systemd`;
- `root` или `sudo`;
- Docker Engine и Compose v2 либо возможность установить отсутствующие пакеты;
- DNS A/AAAA для прокси- и панельного имени, указывающие напрямую на сервер;
- доступный TCP/80 для ACME HTTP-01;
- существующий Nginx `stream`, владеющий публичным TCP/443;
- ровно одна понятная карта `$ssl_preread_server_name` в выбранном файле маршрутов;
- свободные локальные порты;
- внешний исполняемый протокольный тест, проверяющий настоящий Fake-TLS/Obfuscated2 `req_pq_multi → resPQ` для каждого секрета;
- независимая резервная копия Nginx, служб, маршрутов, Docker-состояния и соседних SNI.

Для raw MTProto DNS/CDN-прокси должен быть отключён: нужен режим DNS-only. Несовпадение A/AAAA, NAT, неоднозначная карта Nginx, занятый порт, владелец 443 не-Nginx, отсутствующий протокольный тест или неуспешная проверка `nginx -t` — это жёсткая остановка, а не повод продолжать установку.

## 1. Получение исходников и аудит

```bash
git clone https://github.com/dubr1k/proxy-control.git
cd proxy-control

sudo python3 scripts/proxyctl.py audit \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --json
```

`audit` не устанавливает пакеты и не меняет файлы или службы. Проверьте его вывод: владельца 443, DNS, топологию Nginx, платформу, свободные порты и возможные коллизии.

Перед изменениями зафиксируйте приватную резервную копию:

```bash
umask 077
sudo nginx -t
sudo nginx -T | sudo tee /root/proxy-control-nginx-T.txt >/dev/null
ss -lntup
systemctl is-active nginx docker
```

Файл `nginx-T.txt`, вывод `ss`, списки контейнеров и журналы могут раскрывать внутреннюю топологию. Не публикуйте их и не отправляйте в открытые задачи.

## Сборка внешнего MTProto acceptance probe

До создания плана из этого checkout соберите зафиксированный TDLib image и установите root-only wrapper:

```bash
sudo ./probe/install.sh
```

Установленный `/usr/local/libexec/mtproxy-respq-probe` принимает только `--domain DOMAIN --secrets-file PATH`. Он монтирует переданный root-owned private file read-only по фиксированному container path; каждая user entry внутри container преобразуется в Fake-TLS MTProto secret и проверяется через TDLib `addProxy` и `pingProxy`. `probe/Dockerfile` фиксирует base image по digest, а `probe/package-lock.json` фиксирует точное Node/TDLib dependency graph.

Это намеренно вне installer runtime: installer передаёт путь, а не отдельные secrets. Secrets не появляются в argv installer или Docker, shell history, logs или safe status probe. У container read-only root filesystem, bounded `/tmp` tmpfs, нет capabilities и включён `no-new-privileges`; nonzero exit для любого secret блокирует acceptance.

## 2. План автоматической установки

Используйте те же параметры, что и для будущей установки:

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

Проверьте в плане:

- пути проекта и файлов маршрутизации;
- список пакетов, которые будут установлены;
- имена сертификатов;
- локальные порты;
- список пользователей;
- путь к внешнему протокольному тесту;
- изменения, которые принадлежат установщику, и существующие чужие файлы.

План и аудит не должны содержать пароли, токены, секреты пользователей, ссылки доступа или QR-полезную нагрузку.

## 3. Автоматическая установка базового контура

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

`--project-dir` по умолчанию — `/opt/mtproxy-shared443`. `--users` принимает имена через запятую; существующие корректные секреты сохраняются при повторном рендеринге. `--protocol-probe` обязателен и должен быть исполняемым настоящим тестом MTProto, а не HTTP-проверкой.

Установщик транзакционно:

1. устанавливает только отсутствующие пакеты Ubuntu;
2. создаёт временные HTTP-01 vhost на TCP/80 и получает сертификат для обоих имён;
3. создаёт секреты с режимом `0600`;
4. разворачивает зафиксированные образы Telemt, внутреннюю маскирующую страницу и панель;
5. публикует Telemt на `127.0.0.1:8445`, панель на `127.0.0.1:8787`;
6. создаёт владельца панели через stdin, не печатая пароль;
7. добавляет только принадлежащие установщику маршруты Nginx: прокси SNI → `8445`, панельный SNI → локальный HTTPS fallback `8443`;
8. запускает Compose с ожиданием работоспособности;
9. выполняет обязательный внешний протокольный тест;
10. при ошибке восстанавливает предыдущую согласованную генерацию.

Установщик не меняет UFW, nftables, iptables, DNS, Xray/3xUI, чужие контейнеры и чужие маршруты Nginx. Его журнал и ownership-файлы находятся в `/var/lib/proxy-control/`; не удаляйте их вручную.

После установки:

```bash
cd /opt/mtproxy-shared443
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
sudo nginx -t
ss -lntup
```

Начальный пароль владельца хранится в `secrets/panel-bootstrap-password` с режимом `0600`. Прочитайте его только через защищённую консоль, сразу войдите через `https://panel.example.com/login` и замените пароль. Не копируйте этот файл в `.env`, Git, тикеты, журналы или резервные копии общего доступа.

Для MTProxy обязательны настоящие проверки:

1. Fake-TLS handshake;
2. Obfuscated2;
3. `req_pq_multi`;
4. проверенный Telegram `resPQ`;
5. реальный Telegram-клиент из целевой сети;
6. проверка всех соседних SNI.

Здоровый контейнер, HTTP-ответ или открытый порт сами по себе не подтверждают работу MTProto.

## 4. Ручной базовый Compose

Ручной режим подходит, если сертификаты, Nginx и внешний протокольный тест уже подготовлены оператором.

Создайте секреты. Формат `users.conf` — одна строка `имя=секрет`; секрет Telemt должен состоять из 32 символов `A-Za-z0-9_-`:

```bash
install -d -m 0700 secrets
printf 'owner=%s\n' "$(openssl rand -hex 16)" > secrets/users.conf
printf 'phone=%s\n' "$(openssl rand -hex 16)" >> secrets/users.conf
printf 'Bearer %s\n' "$(openssl rand -hex 32)" > secrets/telemt-api-token
chmod 0600 secrets/users.conf secrets/telemt-api-token
```

Подготовьте содержимое cover-сайта в `/var/www/proxy.example.com` и сертификат с путями `/etc/letsencrypt/live/proxy.example.com/`. Создайте `.env` рядом с `compose.yaml`:

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

`MTPROXY_COVER_ROOT` и `MTPROXY_LETSENCRYPT_ROOT` должны существовать до запуска. `MTPROXY_BACKEND_PORT` — локальный порт Telemt, а не публичный 443. Не публикуйте Telemt API `9091` через `ports`.

Проверьте и запустите:

```bash
docker compose config -q
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
```

Создайте первого владельца панели, не передавая пароль в аргументах и историю shell:

```bash
read -rsp 'Новый пароль владельца: ' PANEL_INITIAL_PASSWORD; echo
printf '%s\n' "$PANEL_INITIAL_PASSWORD" | docker compose run --rm -T panel \
  python -m panel.cli create-admin --username owner --role owner --password-stdin
unset PANEL_INITIAL_PASSWORD
docker compose up -d
```

Пароль должен содержать не менее 12 символов и хранится как Argon2id. Для локальной временной проверки HTTP можно использовать `PANEL_COOKIE_SECURE=false`, но за HTTPS оставляйте `true`.

## 5. Nginx, DNS и публикация панели

Добавляйте только необходимые записи в существующую карту SNI. Не заменяйте действующую карту целиком примером из документации.

- прокси-имя должно направляться на `127.0.0.1:${MTPROXY_BACKEND_PORT}`;
- панельное имя должно направляться на HTTPS reverse proxy, который обслуживает `127.0.0.1:8787`, либо на установочный fallback `127.0.0.1:8443`;
- управляющие API Telemt, Naive и Mieru не должны публиковаться;
- после изменения сначала выполните `sudo nginx -t`, затем `sudo systemctl reload nginx`;
- проверьте прокси, панель и каждый соседний SNI.

Для автоматической установки Nginx-маршруты и панельный TLS-vhost создаются установщиком. Для ручной установки TLS-терминацию и SNI-маршрутизацию должен контролируемо предоставить оператор сервера.

## Настройка протоколов

### Панель и роли

Панель слушает `127.0.0.1:8787`. Для временного доступа с рабочей станции используйте SSH-туннель:

```bash
ssh -L 8787:127.0.0.1:8787 server
```

Основные параметры:

| Переменная | Назначение |
|---|---|
| `PANEL_ALLOWED_HOSTS` | Разрешённые значения `Host` через запятую; добавьте публичное имя панели |
| `PANEL_COOKIE_SECURE` | Должна быть `true` за HTTPS; `false` допустима только для временной локальной проверки |
| `PANEL_DATABASE` | Путь SQLite; в Compose — `/data/panel.sqlite3` на томе `panel-data` |
| `PANEL_HEALTHCHECK_HOST` | Host, используемый проверкой `/healthz` |
| `TELEMT_API_URL` | Внутренний адрес Telemt, обычно `http://mtproxy:9091` |
| `TELEMT_API_TOKEN_FILE` | Файл внутреннего токена Telemt |
| `NAIVE_ENABLED`, `NAIVE_PUBLIC_HOST` | Включение NaiveProxy и его публичное имя |
| `MIERU_ENABLED`, `MIERU_PUBLIC_HOST` | Включение Mieru и его публичное имя |

Роли:

- `owner` — администраторы, пользователи, ротация и реорганизация доступов, реестр Fleet;
- `admin` — пользователи протоколов и аудит в разрешённых границах;
- `viewer` — только просмотр.

Последнего активного владельца нельзя удалить или понизить. Все изменения требуют CSRF и записываются в аудит без паролей, токенов, ссылок, QR и заголовков авторизации.

Создание и ротация Naive/Mieru показывают секретную конфигурацию один раз с `Cache-Control: no-store`. Списки пользователей секретов не содержат. Повторная выдача существующего Mieru-пароля невозможна: используйте «Новая ссылка + QR», которая ротирует доступ и инвалидирует старую конфигурацию.

### MTProxy / Telemt

Базовая установка использует:

- образ Telemt с зафиксированным digest;
- локальный data plane `127.0.0.1:8445`;
- внутренний API `http://mtproxy:9091` с Bearer-токеном;
- том `telemt-config` как источник истины после первого запуска;
- `secrets/users.conf` только для первоначального импорта.

После первого создания `telemt-config` дальнейшие изменения выполняются через API и переживают пересоздание контейнера. Удаление тома — destructive reset: entrypoint снова импортирует исходный `users.conf`.

Квота Telemt и текущий счётчик процесса — разные величины. Ручной сброс квоты не обнуляет счётчик текущего процесса, а аварийная остановка может потерять расход после последнего сохранения. Автоматический календарный сброс панелью не заявляется.

### NaiveProxy / Caddy

Naive подключается только отдельным `compose.naive.yaml` и использует host-сервис Caddy. Для него нужны:

- зафиксированная сборка Caddy `v2.11.4` с `http.handlers.forward_proxy`;
- host-бинарник `/usr/local/bin/caddy`;
- пользователь Caddy `naive-caddy` с UID `10003`;
- группа `naive-accounting` с GID `10004`;
- manager с UID/GID `10002:101`;
- каталог данных, не являющийся symlink;
- `/var/log/naive-proxy` с владельцем `10003:10004` и режимом `0750`;
- токен manager и исходный `Caddyfile`.

Проверка сборки:

```bash
docker build -f docker/Dockerfile.caddy-naive -t proxy-control-caddy-naive:local .
cid=$(docker create --entrypoint /caddy proxy-control-caddy-naive:local version)
docker cp "$cid:/caddy" /tmp/proxy-control-caddy
docker rm "$cid"
sudo install -o root -g root -m 0755 /tmp/proxy-control-caddy /usr/local/bin/caddy
rm -f /tmp/proxy-control-caddy
/usr/local/bin/caddy version
/usr/local/bin/caddy list-modules | grep -Fx 'http.handlers.forward_proxy'
```

Ожидаемая версия — `v2.11.4 h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0=`. Зафиксированный Dockerfile использует builder digest и immutable commit модуля; не заменяйте их плавающей веткой.

Подготовьте данные и identity:

```bash
export NAIVE_DATA_DIR=/var/lib/naive-manager
export NAIVE_PUBLIC_HOST=naive.example.com
install -d -o 10002 -g 101 -m 0700 "$NAIVE_DATA_DIR"
install -d -o 10003 -g 10004 -m 0750 /var/log/naive-proxy
getent passwd 10003 || true
getent group 10004 || true
```

Если UID `10003` или GID `10004` уже принадлежит другому субъекту, остановитесь и устраните коллизию. Не применяйте recursive `chown` к восстановленным данным.

Скопируйте действующий Caddyfile в `${NAIVE_DATA_DIR}/Caddyfile`. Создайте manager-токен и две защищённые копии:

```bash
install -d -m 0700 secrets
printf '%s\n' "$(openssl rand -hex 32)" > secrets/naive-manager-token
cp secrets/naive-manager-token "${NAIVE_DATA_DIR}/manager-token"
chown 10002:101 "${NAIVE_DATA_DIR}/Caddyfile" "${NAIVE_DATA_DIR}/manager-token"
chmod 0640 "${NAIVE_DATA_DIR}/Caddyfile"
chmod 0400 "${NAIVE_DATA_DIR}/manager-token"
```

В `.env` добавьте:

```dotenv
COMPOSE_FILE=compose.yaml:compose.naive.yaml
NAIVE_PUBLIC_HOST=naive.example.com
NAIVE_DATA_DIR=/var/lib/naive-manager
```

Выполните первоначальный импорт и установите службу:

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

`naive-manager` использует только локальный Caddy Admin API и Unix-сокет, не получает Docker socket и может читать завершённые логи, но не создавать, обрезать, переименовывать или дописывать их. Не публикуйте Caddy Admin API.

Проверка Naive:

1. cover HTTPS без учётных данных;
2. authenticated `CONNECT` через реальный клиент;
3. известный payload;
4. закрытие туннеля;
5. увеличение учёта только после успешного закрытия;
6. отсутствие авторизации в логах;
7. проверка соседних SNI.

Клиентские подключения. Один и тот же доступ работает и как HTTPS (HTTP/1.1), и как HTTP/2: панель выдаёт URL `https://<user>:<pass>@<NAIVE_PUBLIC_HOST>`, а конкретный протокол выбирается ALPN-согласованием в TLS-handshake. Клиентские профили, которые называют варианты «HTTPS» и «HTTP2», используют этот же URL и те же учётные данные — отдельный доступ под каждый вариант создавать не нужно.

HTTP/3 (`quic://`) в поставке выключен: серверный блок Caddy объявляет `protocols h1 h2`, а QUIC требует публичного UDP-порта. SNI-маршрутизация nginx `stream` работает только для TCP и не разбирает QUIC Initial, поэтому HTTP/3 нельзя опубликовать через ту же схему порта 443. Для включения нужны `protocols h1 h2 h3`, свободный публичный UDP-порт (443/UDP на хосте может занимать другой сервис), listener Caddy на этом порту в обход nginx и выдача клиенту URL `quic://<user>:<pass>@<host>:<порт>`.

Учёт Naive — это полезные байты завершённых туннелей без TLS/IP-накладных расходов. Per-user quota отключает credentials после достижения наблюдённого лимита, но не является побайтовым hard cap или платёжным счётчиком: активный туннель может дать overshoot. При сбое manager не удаляйте `transaction.json`, paired backups, `-wal` или `-shm`.

### Mieru / mita

Mieru использует внешний процесс `mita` версии **3.35.x**. Он не входит в MIT-репозиторий и образы; бинарный файл устанавливается оператором отдельно.

Зафиксированные пакеты:

| Архитектура | URL пакета | SHA-256 пакета | SHA-256 `usr/bin/mita` |
|---|---|---|---|
| amd64 | `https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_amd64.deb` | `cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342` | `4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31` |
| arm64 | `https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_arm64.deb` | `66ff435dd5bd6078944cb4eb7fc427366afaac5ab51030ff62561c645c31a9e3` | `a4e486c1531b7bebec02eca2b60dcba2a4971b2cd479c590d8405aab59fe6a23` |

Пример для amd64:

```bash
curl -fL --proto '=https' --tlsv1.2 \
  https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_amd64.deb \
  -o mita_3.35.0_amd64.deb
printf '%s  %s\n' cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342 mita_3.35.0_amd64.deb | sha256sum -c -
dpkg-deb -x mita_3.35.0_amd64.deb mita-root
printf '%s  %s\n' 4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 mita-root/usr/bin/mita | sha256sum -c -
sudo install -o root -g root -m 0755 mita-root/usr/bin/mita /usr/bin/mita
```

Для arm64 замените URL и оба digest. Проверяйте именно digest исполняемого файла, а не только пакета.

Подготовьте отдельного системного пользователя, если он не был создан при установке внешнего пакета, и каталог состояния:

```bash
getent group mita >/dev/null || sudo groupadd --system mita
getent passwd mita >/dev/null || sudo useradd --system --gid mita --home-dir /var/lib/mita --create-home --shell /usr/sbin/nologin mita
sudo install -d -o mita -g mita -m 0700 /var/lib/mita
```

Подготовьте службу `mita` и стабильный Unix-сокет:

```bash
sudo install -m 0644 deploy/mita.tmpfiles.conf /etc/tmpfiles.d/mita.conf
sudo install -m 0644 deploy/mita.service /etc/systemd/system/mita.service
sudo systemd-tmpfiles --create /etc/tmpfiles.d/mita.conf
sudo systemctl daemon-reload
sudo systemctl enable --now mita
MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
```

Принимайте только точный результат `mita server status is "RUNNING"`. Не используйте `RuntimeDirectory=mita` для bind-mounted UDS и не включайте `MITA_INSECURE_UDS`.

Manager использует фиксированные UID/GID `10005:10005`; они не должны принадлежать постороннему субъекту. Socket group `MIERU_MITA_GID` должна быть отдельной ненулевой группой и не совпадать с резервными идентификаторами `10001–10005`.

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

Обе команды `prepare` обязательны и выполняются до `docker compose up`. Сначала создайте токен в root-owned каталоге, затем передайте его скрипту проверки:

```bash
sudo install -d -o root -g root -m 0750 /etc/mieru-manager
sudo sh -c 'umask 077; openssl rand -hex 32 > /etc/mieru-manager/token'
sudo chown root:root /etc/mieru-manager/token
sudo chmod 0600 /etc/mieru-manager/token
sudo ./scripts/prepare-mieru-token.sh prepare /etc/mieru-manager/token
sudo env MIERU_MITA_GID="$MIERU_MITA_GID" ./scripts/prepare-mieru-state.sh prepare "$MIERU_MANAGER_STATE_DIR"
```

Токен должен быть ASCII-длиной 32–512 байт, лежать в существующей root-owned цепочке каталогов без записи для группы и остальных, быть обычным файлом без symlink и иметь после подготовки владельца `root:10005`, режим `0440`. Каталог состояния должен быть пустым, иметь владельца `10005:10005` и режим `0700`.

В `.env` добавьте:

```dotenv
COMPOSE_FILE=compose.yaml:compose.mieru.yaml
MIERU_PUBLIC_HOST=mieru.example.com
MIERU_MITA_BIN=/usr/bin/mita
MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31
MIERU_MITA_GID=20005
MIERU_MANAGER_STATE_DIR=/var/lib/mieru-manager
MIERU_MANAGER_TOKEN_FILE=/etc/mieru-manager/token
```

Вместо `20005` укажите фактический GID группы, имеющей доступ к `/run/mita/mita.sock`, и проверьте, что он не зарезервирован:

```bash
docker compose config -q
docker compose up -d --build
docker compose ps
```

Mieru не занимает 443. В конфигурации Mieru явно задайте хотя бы одно TCP- и/или UDP-сопоставление, выберите выделенные порты, откройте их в облачном и локальном firewall и проверьте `ss -lntup`. Панель проверяет конфигурацию через manager; изменение портов, MTU, DNS, выхода и сетевых параметров требует остановки/запуска.

Создание пользователя выдаёт одноразовую `mierus://`-ссылку, QR-код и команду импорта. Ротация, отключение и удаление требуют контролируемого перезапуска для отзыва доступа. Квота — ограниченная приблизительная проверка допуска по application bytes, а не жёсткий billing-лимит. Безопасного typed-счётчика трафика на пользователя нет, поэтому интерфейс может показывать `unavailable`.

При восстановлении Mieru всегда восстанавливайте `journal.json` вместе с исходным `journal.key`. Не удаляйте и не генерируйте новый ключ, чтобы «починить» журнал.

### Fleet mTLS

Fleet v1 — необязательный контур. Создание записи узла в панели со статусом `unenrolled` не является регистрацией. Полная регистрация требует локального ключа/CSR, подписи offline CA, привязки сертификата в центре, mTLS-авторизации и успешной команды инвентаризации.

#### Центральный узел

Создайте offline CA на защищённой операторской системе:

```bash
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-ca-init --ca-dir /root/mtproxy-fleet-ca
sudo install -m 0644 /root/mtproxy-fleet-ca/ca.crt \
  /etc/mtproxy-panel/fleet-client-ca.crt
```

`ca.key` остаётся offline и root-only. Центральный ingress получает только `ca.crt` и отдельный обычный WebPKI-сертификат для точного имени `FLEET_CENTRAL_URL`.

Для Compose задайте пути сертификатов и порт:

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

Не размещайте `ca.key` в контейнере или на online-сервере. Ограничьте firewall до ожидаемых клиентов и не подменяйте клиентский CA сертификатом публичного сервера.

#### Регистрация узла

1. Создайте запись узла от имени владельца:

   ```bash
   python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
     fleet-register-node node-1 --display-name 'Node 1'
   ```

2. На узле создайте ключ и CSR:

   ```bash
   install -d -m 0700 /etc/mtproxy-agent
   openssl req -new -newkey rsa:3072 -nodes -sha256 \
     -subj '/CN=node-1' \
     -keyout /etc/mtproxy-agent/node-1.key \
     -out /etc/mtproxy-agent/node-1.csr
   chmod 0600 /etc/mtproxy-agent/node-1.key
   ```

   Закрытый ключ никогда не покидает узел.

3. Подпишите CSR offline и привяжите сертификат:

   ```bash
   python -m panel.cli fleet-sign-csr node-1 \
     --ca-dir /root/mtproxy-fleet-ca \
     --csr /secure-inbox/node-1.csr \
     --out /secure-outbox/node-1.crt \
     --days 90

   python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
     fleet-bind-cert node-1 --cert /secure-inbox/node-1.crt
   ```

   Подписывающий инструмент создаёт canonical URI SAN `urn:mtproxy-panel:node:<node-id>` и игнорирует запрошенные identity extensions.

4. Верните на узел только его сертификат и публичный сертификат CA. Скопируйте `deploy/agent.env.example` в `/etc/mtproxy-agent/agent.env`, укажите `FLEET_NODE_ID`, `FLEET_CENTRAL_URL`, `FLEET_CLIENT_CERT`, `FLEET_CLIENT_KEY`, локальный `TELEMT_API_TOKEN_FILE` и путь `FLEET_JOURNAL`.

5. Установите службу и проверьте исходящее подключение:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now mtproxy-agent
   journalctl -u mtproxy-agent --since=-5m --no-pager
   ```

   Для systemd-службы скопируйте `deploy/agent.env.example` в `/etc/mtproxy-agent/agent.env` с владельцем `root:mtproxy-agent` и режимом `0640`. Укажите `FLEET_NODE_ID`, `FLEET_CENTRAL_URL`, `FLEET_CLIENT_CERT`, `FLEET_CLIENT_KEY`, путь к локальному `TELEMT_API_TOKEN_FILE` и `FLEET_JOURNAL`. Закрытый ключ узла не должен быть доступен группе или остальным пользователям.

   Альтернативно агент можно запустить через Compose. В `.env` укажите абсолютные пути к сертификату и ключу:

   ```dotenv
   COMPOSE_FILE=compose.yaml:compose.agent.yaml
   FLEET_NODE_ID=node-1
   FLEET_CENTRAL_URL=https://fleet.example.com:8790
   FLEET_CLIENT_CERT=/etc/mtproxy-agent/node-1.crt
   FLEET_CLIENT_KEY=/etc/mtproxy-agent/node-1.key
   ```

   Затем выполните:

   ```bash
   docker compose config -q
   docker compose up -d --build fleet-agent
   ```

   Compose-агент зависит от здорового `mtproxy`, не публикует порты, не получает Docker socket и хранит журнал в отдельном томе `fleet-agent-data`. При совместном запуске с другими контурами добавьте `compose.agent.yaml` к тому же полному `COMPOSE_FILE`, а не запускайте отдельный проект.

6. Сначала отправьте короткоживущую команду инвентаризации и дождитесь сохранённого результата. Только после `connected` и успешного результата переходите к разрешённым изменениям.

Центральный ingress можно запускать systemd-службой вместо Compose. Скопируйте `deploy/fleet-ingress.env.example` в `/etc/mtproxy-panel/fleet-ingress.env`, задайте `PANEL_DATABASE`, `FLEET_LISTEN_HOST`, `FLEET_LISTEN_PORT`, источники WebPKI-сертификата `FLEET_SERVER_CERT_SOURCE`/`FLEET_SERVER_KEY_SOURCE`, пути runtime-копий и `FLEET_CLIENT_CA`, затем установите `deploy/mtproxy-fleet-ingress.service`:

```bash
sudo install -o root -g root -m 0644 deploy/fleet-ingress.env.example /etc/mtproxy-panel/fleet-ingress.env
sudo install -o root -g root -m 0644 deploy/mtproxy-fleet-ingress.service /etc/systemd/system/mtproxy-fleet-ingress.service
sudo systemctl daemon-reload
sudo systemctl enable --now mtproxy-fleet-ingress
```

Служба сама staging-копирует сертификат и закрытый ключ в защищённый runtime-каталог; исходная закрытая ветка Certbot остаётся недоступной панели. Проверьте `systemctl status mtproxy-fleet-ingress` и mTLS-подключение.

Fleet v1 работает только с Telemt: разрешены inventory refresh, enable, disable, изменение лимитов и сброс квоты. Mieru operations, удалённые create/delete/rotate/reveal и передача secret-bearing configuration apply отклоняются.

Для ротации сертификата сначала создайте и привяжите новый сертификат, замените его на узле, подтвердите `connected` и только затем отзовите старый serial:

```bash
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-revoke-cert node-1 --serial OLD_HEX_SERIAL
```

## Первый запуск и проверка

После включения каждого контура проверяйте его отдельно:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
sudo nginx -t
ss -lntup
systemctl is-active nginx docker
```

Если включены host-сервисы:

```bash
systemctl is-active caddy-naive mita
MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
```

### Приёмочные проверки

- **MTProxy:** Fake-TLS → Obfuscated2 → `req_pq_multi` → validated `resPQ` → реальный Telegram-клиент.
- **NaiveProxy:** cover HTTPS → authenticated `CONNECT` → известный payload → закрытие туннеля → проверка учёта.
- **Mieru:** точный статус `RUNNING` → реальный клиент через TCP/UDP → выход в Интернет → проверка manager health.
- **Панель:** HTTPS, вход, роли, создание и отзыв тестового доступа, отсутствие секретов в списках и аудите.
- **Маршрутизация:** проверка всех соседних SNI после каждого изменения Nginx.
- **Хранилище:** `PRAGMA integrity_check`, режимы файлов, владельцы, отсутствие незавершённого журнала без плана восстановления.

Не выполняйте в production credential-bearing тесты без временного плана очистки. После теста удалите тестовых пользователей, ссылки, QR, журналы и временные файлы.

# Резервное копирование, обновление и откат

## Что резервировать

| Контур | Полная генерация |
|---|---|
| Панель | SQLite через online backup либо база вместе с `-wal`/`-shm` при остановленном writer |
| Telemt | Том `telemt-config`, `secrets/users.conf`, API-токен и точная версия образа |
| Naive | Весь `NAIVE_DATA_DIR`, Caddyfile, `users.json`, paired backups, `transaction.json`, accounting SQLite/WAL/SHM, бинарный файл, unit и права логов |
| Mieru | Каталог состояния, `journal.json` вместе с исходным `journal.key`, backups, token, бинарный файл, unit, конфигурация `mita` и контракт UDS |
| Fleet center | База панели, ingress-конфигурация, публичный серверный сертификат, клиентский CA; offline CA key отдельно |
| Fleet node | SQLite/outbox агента, ключ и сертификат узла, доверенный CA, локальный токен Telemt, unit и environment |
| Nginx | stream/http-конфигурации, сертификаты или ссылки на них, владельцы, режимы, ownership manifest и backups |
| Развёртывание | Git revision, полный `COMPOSE_FILE`, образы/digest, версии бинарных файлов, пакеты и unit-файлы |

Резервная копия должна быть согласованной, защищённой как секрет, иметь checksum и проходить проверку восстановления. Не храните offline Fleet CA key вместе с online-архивом.

Пример безопасного online backup SQLite панели:

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

Ожидается ровно `ok`. Не копируйте только основной файл SQLite при работающем WAL writer.

Перед изменением одной границы:

1. остановите новые изменения;
2. зафиксируйте revision, образы, бинарные digest и полный набор Compose-файлов;
3. создайте полную предыдущую генерацию;
4. изменяйте только одну границу;
5. выполните проверки работоспособности и реальный протокольный тест;
6. удаляйте rollback-артефакты только после подтверждения.

## Обновление runtime-версий из панели

Панель поддерживает безопасное обновление трёх runtime-контуров через отдельный root-owned `version-agent`: **Telemt**, **NaiveProxy/Caddy** и **Mieru/mita**. Сама панель не получает Docker socket, не скачивает бинарники и не принимает URL из браузера.

Перед включением контура:

1. Разместите checkout проекта без `.env`, `secrets/`, баз, токенов и PKI-ключей в пути, который указан в `WorkingDirectory` unit-файла `deploy/version-agent.service` (по умолчанию `/opt/proxy-control`).
2. Установите unit и конфигурацию только от `root:root`:

   ```bash
   sudo install -d -m 0750 /etc/proxy-control
   sudo install -o root -g root -m 0644 deploy/version-agent.service /etc/systemd/system/version-agent.service
   sudo install -o root -g root -m 0644 deploy/proxy-control-version-agent.tmpfiles.conf /etc/tmpfiles.d/proxy-control-version-agent.conf
   sudo install -o root -g root -m 0600 deploy/version-agent.env.example /etc/proxy-control/version-agent.env
   sudo install -o root -g root -m 0600 deploy/version-catalog.example.json /etc/proxy-control/versions.json
   sudo systemd-tmpfiles --create /etc/tmpfiles.d/proxy-control-version-agent.conf
   ```

3. Замените все example URL, image reference и SHA-256 в `/etc/proxy-control/versions.json` на реально проверенные артефакты. Для Telemt разрешены только immutable image references с `@sha256:...`; для Caddy и mita — только HTTPS без credentials/query и с lowercase SHA-256. Не добавляйте «latest», HTTP, redirect на другой host или произвольные команды.
4. Заполните `PROXY_CONTROL_COMPOSE_DIR`, полный `PROXY_CONTROL_COMPOSE_FILES`, реальные пути бинарников и имена systemd-служб в `version-agent.env`. Не удаляйте активные Compose overlays.
5. Перед первым обновлением зафиксируйте текущие версии в root-owned state-файле `/var/lib/proxy-control/version-agent/state.json` и сделайте полный backup. Если текущая версия неизвестна, сначала выполните read-only аудит; не используйте guessed `expected_current`.
6. Включите агент и проверьте только health endpoint через Unix-сокет:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now version-agent
   sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health
   sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/versions
   ```

После этого пересоздайте только panel-контейнер с полным набором Compose-файлов. Bind mount `/run/proxy-control` должен оставаться, а socket должен иметь режим `0660` и группу, доступную UID панели `10001`.

Операция из UI доступна только роли `owner` и требует текущую версию (`expected_current`). Агент под эксклюзивной блокировкой:

- повторно читает root-owned каталог и запрещает версию вне allowlist;
- для Telemt делает `pull` immutable image, пишет `version-overrides/compose.versions.yaml`, поднимает только `mtproxy` и ждёт `healthy`;
- для Caddy/mita скачивает ограниченный по размеру артефакт, проверяет SHA-256, выполняет checker/конфигурационную проверку, атомарно заменяет бинарник;
- перезапускает только соответствующую службу и проверяет `is-active`: reload перечитал бы конфигурацию, но оставил бы работать прежний процесс со старым бинарником;
- записывает установленную сборку в root-owned pin (`/etc/proxy-control/caddy-naive.pin`), который читает `ExecStartPre` службы, поэтому стартовая проверка не отвергает только что установленную версию;
- отказывается обновлять бинарник, который контейнер пинует по digest (по умолчанию `mita` при живом `proxy-control-mieru-manager`): контейнер сохранил бы старый inode и устаревший хеш до пересоздания с новым пином;
- сохраняет предыдущий бинарник, pin и override и при ошибке восстанавливает их;
- записывает state только после успешной проверки health.

Если UI сообщает `version agent unavailable`, это не разрешение обновлять вручную из браузера: проверьте unit, права socket, каталог версий, полный Compose-набор и логи агента. Не запускайте `docker compose down -v`, не удаляйте volumes и не меняйте 443 для операции обновления. Полный протокол и rollback также описаны в [UPGRADING.md](docs/UPGRADING.md).

## Обновление и восстановление

Не удаляйте `journal.json`, `journal.key`, `transaction.json`, WAL/SHM или backups, чтобы «починить» запуск. Используйте документированный путь восстановления:

```bash
sudo python3 scripts/proxyctl.py repair
```

`repair` читает закрытый ownership manifest, завершает прерванное восстановление, проверяет чужие изменения и перезапускает только зарегистрированные службы. При сомнении восстанавливайте всю предыдущую генерацию, а не один файл.

Для удаления базового контура:

```bash
sudo ./uninstall.sh
```

Удаление останавливает Compose, удаляет только принадлежащие установщику маршруты, файлы и пакеты, а секреты, сертификаты и cover-каталоги сохраняет до отдельной проверки владельца. Повторный запуск продолжает с сохранённой фазы. После удаления проверьте `nginx -t`, публичные слушатели и соседние SNI.

Если SSH завершился с кодом `255`, это доказывает только обрыв транспорта. Сначала проверьте `/var/lib/proxy-control/runtime.json`, фазу, службы, ownership-файлы, Nginx и протокольный тест; не запускайте установку повторно вслепую.

# Эксплуатация и устранение проблем

Ежедневная проверка:

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
sudo nginx -t
systemctl --no-pager --full status nginx
systemctl is-active caddy-naive mita 2>/dev/null || true
docker compose logs --since=15m --tail=300 panel mtproxy naive-manager mieru-manager
```

Перед передачей вывода удалите пароли, полные URL доступа, QR и reveal payload, bearer/manager/Fleet-токены, cookies, CSRF, сертификаты, закрытые ключи и лишние сведения о сервере.

Типовые причины отказов:

- **Панель не открывается:** проверьте `127.0.0.1:8787`, `PANEL_ALLOWED_HOSTS`, `PANEL_COOKIE_SECURE`, reverse proxy, SQLite и владельца тома.
- **MTProxy здоров, но клиент не подключается:** проверьте A/AAAA, отсутствие CDN перед raw TCP, SNI map, Fake-TLS имя, каждый секрет и настоящий `resPQ`.
- **Naive manager unhealthy:** проверьте token, UDS, pinned Caddy, `caddy adapt --validate`, `transaction.json`, paired backups и identity `10002:101` / `10003:10004`.
- **Учёт Naive не меняется:** соединение должно завершиться успешным `CONNECT`; активный или прерванный туннель ещё не создаёт запись.
- **Mieru manager unhealthy:** проверьте exact digest/version `mita`, `/run/mita/mita.sock`, GID, token/state metadata и журнал; не применяйте recursive `chown` вслепую.
- **Нет QR старого Mieru-пользователя:** это ожидаемо после одноразовой выдачи; используйте «Новая ссылка + QR», понимая, что старая конфигурация будет отозвана.
- **Появились orphan-контейнеры:** восстановите полный сохранённый `COMPOSE_FILE`; не подтверждайте удаление orphan-контейнеров неполной моделью.
- **Fleet остаётся `unenrolled`:** registry-запись не является enrollment; повторите CSR, offline-подпись, bind сертификата, установку на узел, mTLS authorization и inventory result.

# Безопасность

- Не публикуйте `.env`, `secrets/`, URL доступа, QR, токены, базы, журналы и PKI-ключи.
- Не публикуйте Telemt, manager UDS/API или Caddy Admin API.
- Не подключайте Docker socket к службам проекта.
- Не меняйте pinned Telemt, Caddy или `mita` без проверки происхождения, digest и плана отката.
- Не используйте произвольные команды, пути или переменные через manager API.
- Не считайте скрытие кнопки в интерфейсе заменой серверной проверке роли.
- Перед production-развёртыванием прочитайте [SECURITY.md](SECURITY.md) и [политику совместимости](docs/COMPATIBILITY.md).

# Проверка разработки

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

Полная документация по отдельным границам: [карта документации](docs/README.md), [автоматическая установка](INSTALL.ru.md), [полный установщик и аудитор](INSTALLER_AUDITOR.ru.md), [панель](PANEL.ru.md), [MTProto за Nginx](DOCKER_DEPLOYMENT.ru.md), [Mieru](MIERU.ru.md), [выдача Mieru](docs/MIERU_SHARING.ru.md), [Fleet](FLEET.ru.md), [эксплуатация](docs/OPERATIONS.ru.md), [резервное копирование](docs/BACKUP_RESTORE.ru.md), [обновление](docs/UPGRADING.ru.md), [устранение проблем](docs/TROUBLESHOOTING.ru.md), [учёт трафика](docs/ACCOUNTING.md) и [проверки](docs/VALIDATION.md).

# Статус и лицензия

Подтверждены тесты Python, проверки качества, рендеринг Compose-конфигураций, сборка образов, панели MTProxy/NaiveProxy/Mieru и адаптивный интерфейс. Полный цикл установки и отката в QEMU, регистрация Fleet в боевой среде и бухгалтерская точность учёта трафика не заявляются как завершённые этапы выпуска.

Код репозитория распространяется по [лицензии MIT](LICENSE). Telemt, Caddy/forwardproxy, Mieru/`mita`, сторонние изображения и Python-пакеты сохраняют собственные лицензии. См. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
