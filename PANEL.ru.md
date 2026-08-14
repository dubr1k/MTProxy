# Панель управления MTProxy

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

## Резервное копирование

Резервируйте volumes `panel-data` и `telemt-config`, а также secret-файлы отдельно с режимом `0600`. `users.conf` импортируется только при первом создании `telemt-config/config.toml`; далее источник истины — конфигурация Telemt, которую его API меняет атомарно. Удаление `telemt-config` приводит к повторному импорту исходного `users.conf`.

```sh
curl -fsS http://127.0.0.1:8787/healthz
docker compose ps
docker compose logs panel mtproxy   # вывод не должен содержать secrets
```
