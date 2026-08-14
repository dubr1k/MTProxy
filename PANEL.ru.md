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

## Трафик, квоты и лимиты Telemt 3.4.25

Панель намеренно показывает два разных счётчика:

- `runtime_total_octets` берётся из `GET /v1/users` (`total_octets`) и суммируется на дашборде как трафик текущего runtime-поколения Telemt. Обычно отсчёт начинается при запуске процесса, но in-runtime reload в 3.4.25 создаёт новое поколение статистики и тоже начинает этот счётчик заново. Это диагностическая runtime-метрика, а не расход квоты; ручной сброс квоты её не обнуляет.
- `quota_used_bytes` берётся из `GET /v1/stats/users/quota` (`used_bytes`) и показывается рядом с `data_quota_bytes`. Это сбрасываемый счётчик, по которому Telemt применяет квоту. `quota_last_reset_epoch_secs` — время последнего ручного сброса, либо `0`, если сброса ещё не было.

Кнопка «Сбросить квоту» вызывает `POST /v1/users/{username}/reset-quota`: Telemt обнуляет quota usage и сразу сохраняет quota-state, не меняя настроенный размер квоты и runtime `total_octets`. В Telemt 3.4.25 нет периодической записи quota-state: он сохраняется при явном сбросе и штатной остановке. После аварийного завершения возможна потеря расхода, накопленного после последнего сохранения. Автоматический дневной или ежемесячный сброс этой панелью не заявляется и не эмулируется; используйте только проверенную внешнюю автоматизацию, если нужен календарный период.

Форма лимитов меняет только документированные поля Telemt: quota bytes, up/down bits per second, TCP connections, unique IPs и RFC3339 expiration. Пустое поле отправляет `null` и снимает соответствующий override. Ответы панели формируются по явным allowlist-полям: Telemt `links`, `secret`, ad tags, списки IP и любые неизвестные или будущие вложенные поля в list/update/reset responses наружу не проходят.

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

`naive-manager` работает отдельным непривилегированным контейнером, использует host network только для loopback Caddy Admin API/TLS-probe и не получает Docker socket. Запись разрешена только в `NAIVE_DATA_DIR` и private runtime socket volume. `/var/log/naive-proxy` подключён read-only как `/logs`; SQLite и WAL учёта лежат под `/data` с mode `0600`. Учитываются только завершённые успешные CONNECT-записи управляемых пользователей: `bytes_read` — client→proxy, `size` — proxy→client. Это payload-байты закрытых туннелей, а не TLS/IP traffic и не enforceable quota.

- `Caddyfile` — источник истины Caddy с управляемым блоком `NAIVE-MANAGER USERS`;
- `users.json` — root/manager-only состояние, включая отключённые ключи;
- `backups/` — парные снимки Caddyfile и `users.json` перед каждой мутацией (хранятся последние 20 транзакций);
- `transaction.json` — fsync-журнал незавершённой транзакции; после сбоя manager при старте либо восстанавливает оба предыдущих файла, либо повторно загружает уже полностью записанное новое поколение;
- `manager-token` — копия внутреннего токена с режимом `0400` для UID manager-контейнера.

Перед первым запуском скопируйте действующий Caddyfile в `${NAIVE_DATA_DIR}/Caddyfile`, создайте `secrets/naive-manager-token` с режимом `0600`, передайте такую же копию как `${NAIVE_DATA_DIR}/manager-token`, затем выполните initial import:

```sh
NAIVE_DATA_DIR=${NAIVE_DATA_DIR:-/var/lib/naive-manager}
test ! -L "${NAIVE_DATA_DIR}" || { echo "NAIVE_DATA_DIR must not be a symlink" >&2; exit 1; }
getent group naive-caddy >/dev/null || groupadd --system --gid 101 naive-caddy
id naive-caddy >/dev/null 2>&1 || useradd --system --uid 10002 --gid naive-caddy --home /nonexistent --shell /usr/sbin/nologin naive-caddy
test "$(id -u naive-caddy)" = 10002 || { echo "naive-caddy must use UID 10002" >&2; exit 1; }
test "$(getent group naive-caddy | cut -d: -f3)" = 101 || { echo "naive-caddy must use GID 101" >&2; exit 1; }
install -d -o 10002 -g 101 -m 0750 "${NAIVE_DATA_DIR}"
install -d -o naive-caddy -g naive-caddy -m 0700 /var/log/naive-proxy
for file in Caddyfile manager-token; do
  test -f "${NAIVE_DATA_DIR}/${file}" && test ! -L "${NAIVE_DATA_DIR}/${file}" || exit 1
done
chown -h 10002:101 "${NAIVE_DATA_DIR}/Caddyfile" "${NAIVE_DATA_DIR}/manager-token"
chmod 0640 "${NAIVE_DATA_DIR}/Caddyfile"
chmod 0400 "${NAIVE_DATA_DIR}/manager-token"
chown 10002:101 "${NAIVE_DATA_DIR}"
docker compose -f compose.yaml -f compose.naive.yaml run --rm --build naive-manager --bootstrap-only
caddy validate --config /var/lib/naive-manager/Caddyfile
install -o root -g root -m 0755 scripts/check-naive-caddy-build.sh /usr/local/libexec/check-naive-caddy-build
install -o root -g root -m 0644 deploy/caddy-naive.service /etc/systemd/system/caddy-naive.service
systemctl daemon-reload
```

Manager-контейнер и host Caddy намеренно используют один dedicated file identity `10002:101`: иначе Caddy access log mode `0600` нельзя безопасно читать через read-only bind manager-а. Systemd unit компенсирует это, делая token, state, journal, backups, traffic DB и WAL недоступными внутри mount namespace Caddy. Остальной sandbox strict, запись разрешена только в `/var/log/naive-proxy`. До cutover выполните `systemd-analyze verify`, проверьте User/Group через `systemctl show` и подтвердите недоступность sensitive paths из namespace работающего unit.

Для миграции сначала остановите mutations и сохраните unit, Caddy binary, Caddyfile, manager data и log directory. Установите pinned binary/checker, выполните checker и точный `caddy adapt --validate`, bootstrap manager, затем переключите unit и запустите Compose override. Старый unit и backup не удаляйте до успешных health, cover HTTPS, authenticated CONNECT, traffic collection и регрессии соседних SNI. Дальнейшие изменения идут через paired backup → adapt/validate → fsync journal → atomic replace → `/load` → HTTPS probe; неподтверждённый rollback оставляет manager unhealthy и сохраняет journal.

Rollback выполняется на host: остановите `naive-manager`, одной генерацией восстановите Caddyfile/unit/binary и snapshot manager data, провалидируйте восстановленным build, перезапустите Caddy и повторите cover/authenticated/SNI probes. Не копируйте один `traffic.sqlite3` без `-wal`/`-shm` при работающем manager. Reset меняет только локальный baseline; viewer reset запрещён, audit сохраняет только action/username без credentials и authorization headers.

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
