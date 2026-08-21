# Обновление и откат

Процедура предназначена для работающей установки и для panel `version-agent`. Каждый runtime рассматривайте как отдельную границу изменения.

## Общий порядок

1. Прочитайте changelog, политику совместимости, лицензии upstream и сведения о pinned-артефактах.
2. Выполните полный набор проверок из [VALIDATION.md](VALIDATION.md).
3. Остановите новые изменения. Сделайте одну согласованную резервную генерацию: secrets, volumes, SQLite вместе с WAL/SHM, состояние менеджеров и journal keys, Nginx и ownership manifest.
4. Отрендерите Compose и план установщика без применения. Проверьте digest образов и бинарников, numeric identities, порты, mounts и SNI-маршруты.
5. Убедитесь, что работающие контейнеры имеют label проекта `com.docker.compose.project=mtproxy`; используйте точный сохранённый полный набор `COMPOSE_FILE`. Не применяйте `--remove-orphans` к неполной модели.
6. Меняйте только одну границу за раз. После изменения проверяйте конфигурацию, health, протокол, учёт трафика и соседние SNI.
7. При ошибке остановите изменённую службу и восстановите полную предыдущую генерацию с тем же project name и overlays. Не пересоздавайте journal keys и не копируйте состояние частично.

## Обновление из панели через version-agent

Панель не скачивает runtime-артефакты и не получает Docker socket. Отдельный root-owned `version-agent` читает `/etc/proxy-control/versions.json` и слушает только `/run/proxy-control/version-agent.sock`.

Установка:

```bash
sudo install -d -m 0750 /etc/proxy-control
sudo install -o root -g root -m 0644 deploy/version-agent.service /etc/systemd/system/version-agent.service
sudo install -o root -g root -m 0644 deploy/proxy-control-version-agent.tmpfiles.conf /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo install -o root -g root -m 0600 deploy/version-agent.env.example /etc/proxy-control/version-agent.env
sudo install -o root -g root -m 0600 deploy/version-catalog.example.json /etc/proxy-control/versions.json
sudo systemd-tmpfiles --create /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo systemctl daemon-reload
```

Замените все example entries на проверенные оператором артефакты. Для Telemt допустимы только immutable image references (`@sha256:...`). Для NaiveProxy/Caddy и mita — только HTTPS-артефакты с lowercase SHA-256. Каталог является allowlist, а не механизмом discovery; браузер не может его расширить.

В `/etc/proxy-control/version-agent.env` задайте путь deployment и полный список Compose overlays. Агент записывает только generated `version-overrides/compose.versions.yaml`, настроенные бинарники и собственные state/backup. Symlink targets и опасные относительные Compose paths отклоняются. Если настроенный контейнер pin-ит host binary, предварительный Docker inspect работает fail-closed: обновление разрешается только при точном ответе Docker `No such object`; ошибки daemon, permissions, timeout и любое другое неопределённое состояние блокируют операцию.

До первого обновления запишите установленные версии в `/var/lib/proxy-control/version-agent/state.json`. Панель отправляет `expected_current`; несовпадение возвращает `409` и не позволяет устаревшей вкладке изменить уже обновлённый runtime. Компонент в состоянии `rollback_failed` остаётся заблокированным, пока оператор не восстановит и не проверит полную generation, а затем не согласует root-owned state.

Включение и проверка:

```bash
sudo systemctl enable --now version-agent
sudo systemctl is-active version-agent
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/versions
```

Panel Compose должен монтировать `/run/proxy-control` и задавать `VERSION_AGENT_SOCKET=/run/proxy-control/version-agent.sock`. Socket создаётся с режимом `0660`; его numeric group должен быть доступен UID панели `10001`, но не должен быть world-writable.

### Telemt

Агент сначала считывает image работающего контейнера, скачивает выбранный immutable image, использует полный Compose-набор с `version-overrides/compose.versions.yaml`, пересоздаёт только `mtproxy` и проверяет как выбранный image reference, так и статус `healthy`. Ошибка pull, запуска, readback или health восстанавливает прежний override и запускает прежний image. Rollback считается успешным только после проверки прежнего image reference и container health теми же gates. `down -v` не вызывается.

### NaiveProxy/Caddy и Mieru/mita

Агент скачивает не более 256 MiB с HTTPS-host из каталога, проверяет SHA-256, размещает executable с mode `0755`, запускает checker и атомарно заменяет target. Для Caddy дополнительно проверяются Caddyfile и обязательный module checker. Version pin считывается обратно, служба перезапускается, после чего обязателен `systemctl is-active`.

При любой ошибке агент восстанавливает предыдущие binary и pin, проверяет hash восстановленного binary и readback pin, повторяет checker и Caddyfile validation, перезапускает службу и требует успешный `systemctl is-active`. Новая версия записывается в state только после успеха. Если любой restore, config/readback, restart или health gate отката не прошёл, состояние сохраняется и возвращается как `rollback_failed`; не повторяйте update endpoint, пока оператор не восстановит и не проверит полную предыдущую generation.

## Проверка после обновления

Минимальный набор:

```bash
docker compose -f compose.yaml -f compose.naive.yaml -f compose.mieru.yaml ps
curl --fail http://127.0.0.1:8787/healthz
sudo nginx -t
sudo systemctl is-active version-agent caddy-naive mita
sudo journalctl -u version-agent --since=-15min --no-pager
```

Затем выполните реальный protocol smoke-тест изменённой границы и проверьте соседние SNI-маршруты. Перед передачей вывода удалите URL, токены, QR payloads, cookies, сертификаты, закрытые ключи и содержимое journal.

`repair` и `uninstall` используют ownership manifest и намеренно отклоняют foreign drift; см. [COMPATIBILITY.md](COMPATIBILITY.md). Брендинг не является основанием для миграции runtime-path.
