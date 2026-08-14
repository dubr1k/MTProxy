# Панель управления MTProxy и NaiveProxy

Панель доступна только на loopback-адресе хоста: `http://127.0.0.1:8787`. Для удалённого доступа используйте SSH-туннель (`ssh -L 8787:127.0.0.1:8787 server`) либо собственный HTTPS reverse proxy. Не публикуйте порт Telemt `9091`: в Compose он намеренно не имеет `ports`.

## Первый запуск

Генератор установки создаёт `secrets/telemt-api-token` с режимом `0600`; значение не попадает в `.env`, state-файл или логи. Не используйте пароль из примеров или production-конфигурации. Создайте первого владельца, передав новый пароль через stdin:

```sh
read -rsp 'Новый пароль: ' PANEL_INITIAL_PASSWORD; echo
printf '%s\n' "$PANEL_INITIAL_PASSWORD" | docker compose run --rm -T panel \
  python -m panel.cli create-admin --username owner --role owner --password-stdin
unset PANEL_INITIAL_PASSWORD
docker compose up -d
```

Пароль должен содержать минимум 12 символов и хранится как Argon2id. В SQLite находятся только администраторы, opaque-сессии в виде SHA-256 digest, login throttling и аудит. Секреты прокси никогда не сохраняются панелью: их создаёт Telemt, а панель держит reveal только в памяти не более 120 секунд и отдаёт один раз.

## Настройки и роли

- `PANEL_ALLOWED_HOSTS` — допустимые Host через запятую; при reverse proxy добавьте публичное имя.
- `PANEL_COOKIE_SECURE=true` — оставляйте `true` при HTTPS; для прямой локальной HTTP-проверки временно задайте `false`.
- `PANEL_DATABASE=/data/panel.sqlite3` — SQLite на volume `panel-data`.
- `TELEMT_API_TOKEN_FILE=/run/secrets/telemt-api-token` — передача внутреннего API-токена.

`owner` управляет администраторами и пользователями; `admin` — пользователями и аудитом; `viewer` — только просмотр. Последнего активного owner нельзя удалить или понизить. Отключение администратора удаляет его сессии. Все мутации требуют CSRF и записываются в аудит без паролей, токенов, ссылок и proxy secrets.

Для owner/admin раздел «Подключения» позволяет создавать, блокировать, разблокировать, ротировать и удалять отдельные доступы. Действующую Telegram-ссылку и QR-код можно открыть повторно явной кнопкой «QR и ссылка»; каждое такое раскрытие записывается в аудит, но сама ссылка и secret в журнал не попадают. Списки пользователей никогда не содержат ссылок или секретов.

## Дополнительное управление NaiveProxy

Интеграция с host Caddy подключается отдельным Docker override, поэтому обычная MTProxy-установка без NaiveProxy не ломается:

```sh
COMPOSE_FILE=compose.yaml:compose.naive.yaml docker compose up -d --build
```

На production-сервере эти значения удобно сохранить в локальном `.env` (он исключён из Git):

```dotenv
COMPOSE_FILE=compose.yaml:compose.naive.yaml
NAIVE_PUBLIC_HOST=proxy.example.com
NAIVE_DATA_DIR=/var/lib/naive-manager
```

`naive-manager` работает отдельным непривилегированным контейнером, использует host network только для локального Caddy Admin API и TLS-probe и не получает Docker socket. Контейнер панели видит лишь token-authenticated Unix socket в отдельном tmpfs volume. Writable bind mount ограничен каталогом `NAIVE_DATA_DIR`, где находятся:

- `Caddyfile` — источник истины Caddy с управляемым блоком `NAIVE-MANAGER USERS`;
- `users.json` — root/manager-only состояние, включая отключённые ключи;
- `backups/` — парные снимки Caddyfile и `users.json` перед каждой мутацией (хранятся последние 20 транзакций);
- `transaction.json` — fsync-журнал незавершённой транзакции; после сбоя manager при старте либо восстанавливает оба предыдущих файла, либо повторно загружает уже полностью записанное новое поколение;
- `manager-token` — копия внутреннего токена с режимом `0400` для UID manager-контейнера.

Перед первым запуском скопируйте действующий Caddyfile в `${NAIVE_DATA_DIR}/Caddyfile`, создайте `secrets/naive-manager-token` с режимом `0600`, передайте такую же копию как `${NAIVE_DATA_DIR}/manager-token`, затем выполните initial import:

```sh
docker compose -f compose.yaml -f compose.naive.yaml run --rm --build naive-manager --bootstrap-only
caddy validate --config /var/lib/naive-manager/Caddyfile
```

После validation переключите host Caddy service на этот Caddyfile и сделайте controlled reload. Manager применяет каждое дальнейшее изменение по схеме paired backup → Caddy adapt с `validate=true` → fsync-журнал → atomic replace → Caddy `/load` → HTTPS probe. При ошибке оба файла восстанавливаются, а восстановленная live-конфигурация обязательно проходит reload и probe; если rollback не подтверждён, manager остаётся unhealthy и сохраняет журнал для startup recovery. Create/reveal/rotate responses имеют `Cache-Control: no-store`; список и аудит не содержат паролей или proxy URL. Viewer видит только имена и статусы.

Клиенту выдаются HTTPS proxy URL, QR и готовый `config.json`:

```json
{"listen":"socks://127.0.0.1:1080","proxy":"https://USER:PASSWORD@proxy.example.com"}
```

## Резервное копирование

Резервируйте volumes `panel-data` и `telemt-config`, каталог `${NAIVE_DATA_DIR}` при включённой Naive-интеграции, а также secret-файлы отдельно с режимом `0600`. `users.conf` импортируется только при первом создании `telemt-config/config.toml`; далее источник истины — конфигурация Telemt, которую его API меняет атомарно. Удаление `telemt-config` приводит к повторному импорту исходного `users.conf`.

```sh
curl -fsS http://127.0.0.1:8787/healthz
docker compose ps
docker compose logs panel mtproxy   # вывод не должен содержать secrets
```
