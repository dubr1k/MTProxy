# Troubleshooting Proxy Control

[English](TROUBLESHOOTING.en.md) · **Русский**

Сначала локализуйте boundary. Не перезапускайте всё сразу: это уничтожает evidence и может расширить отказ.

## Быстрая диагностика

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz || true
sudo nginx -t
ss -lntup
systemctl is-active nginx docker caddy-naive mita 2>/dev/null || true
docker compose logs --since=15m --tail=300 panel mtproxy naive-manager mieru-manager 2>/dev/null
```

Не публикуйте raw output до redaction credentials, access URLs, tokens, cookies, PKI и host identities.

## Панель не открывается

1. Проверьте `panel` health и loopback `127.0.0.1:8787`.
2. Проверьте `PANEL_ALLOWED_HOSTS`; public hostname должен быть разрешён.
3. При HTTPS оставьте `PANEL_COOKIE_SECURE=true`.
4. Проверьте Nginx HTTP vhost и stream SNI route отдельно.
5. Проверьте SQLite integrity и ownership volume.
6. Не удаляйте DB/session tables как «сброс».

`401` от protected API без session — нормален. Redirect unauthenticated root на login также нормален.

## Login не работает

- убедитесь, что owner активен и не удалён;
- проверьте clock/timezone, cookie domain/Secure и reverse-proxy headers;
- учитывайте login throttling;
- initial owner создаётся через `panel.cli create-admin --password-stdin`;
- не передавайте пароль в argv или shell history.

## MTProxy healthy, но клиент не подключается

- проверьте DNS A/AAAA и отсутствие proxy/CDN перед raw TCP path;
- убедитесь, что public 443 принадлежит Nginx, а SNI map ведёт на правильный loopback port;
- выполните настоящий `resPQ` probe, не HTTPS check;
- проверьте Fake-TLS domain/secret и каждый active user отдельно;
- regression-test соседние SNI/Xray routes;
- проверьте client из другой сети: ISP path может отличаться.

## Naive manager unhealthy

- проверьте token file mode/ownership и UDS;
- проверьте exact Caddy build checker;
- выполните `caddy adapt --adapter caddyfile --validate` на source config;
- проверьте `transaction.json` и paired backups, не удаляя их;
- проверьте numeric identities: manager `10002:101`, Caddy `10003:10004`, accounting log group `10004`;
- manager должен читать, но не изменять Caddy logs;
- при accounting degraded проверьте rotation/prefix budget и inode continuity.

## Naive traffic не увеличивается

Accounting появляется только после **успешного закрытого CONNECT**. Закройте client tunnel, затем проверьте collector. Значения — payload bytes без TLS/IP. Active/aborted tunnel может не дать ожидаемую запись.

## Mieru manager unhealthy

1. Проверьте host service и exact status:

   ```bash
   systemctl status mita --no-pager
   MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
   ```

2. Проверьте стабильный `/run/mita/mita.sock`, ownership/mode и отсутствие inode replacement после restart.
3. Проверьте pinned `mita` executable digest/version.
4. Проверьте manager token/state metadata:

   ```bash
   sudo ./scripts/prepare-mieru-token.sh verify /etc/mieru-manager/token
   sudo ./scripts/prepare-mieru-state.sh verify /var/lib/mieru-manager
   ```

5. Не удаляйте journal/key. Unknown or unauthenticated state должен fail closed.
6. Проверьте writable config path и `TMPDIR` manager.

## У Mieru нет QR для старого пользователя

Это ожидаемо, если one-time reveal уже закрыт: password хранится только как `hashedPassword`. Нажмите **«Новая ссылка + QR»**. Операция ротирует credential и инвалидирует старый client config. List API намеренно не содержит URL/QR/password.

## Mieru mobile view расширяет страницу

Обновите panel image до revision с responsive Mieru dialog. Проверьте, что deployed `style.css` и `app.js` совпадают с source. На widths `320–900 px` `document.documentElement.scrollWidth - innerWidth` должен быть `0`; long revision, URL, import command и QR должны оставаться внутри карточки/dialog.

## Mieru подключается, но traffic unavailable

Это не ошибка UI. Adapter не парсит human table и не копирует GPL gRPC stubs; безопасной typed per-user metrics boundary нет. Quota — rolling approximate session-admission check, не hard cap.

## Nginx reload не проходит

- не reload до успешного `nginx -t`;
- проверьте duplicate/ambiguous `$ssl_preread_server_name` maps;
- проверьте symlink/content drift owned files;
- восстановите exact backup generation, если change принадлежит installer;
- не заменяйте существующую map примером из документации;
- после rollback снова выполните `nginx -t` и все SNI probes.

## Compose показывает orphan containers

Скорее всего использован неполный `COMPOSE_FILE`. Не подтверждайте removal. Восстановите полный persisted overlay set и повторите `docker compose config --services`/`ps`. Project name должен оставаться `mtproxy`.

## Permission denied после restore

Не применяйте recursive `chown` вслепую. Сверьте documented numeric identities и exact modes. Для Mieru используйте read-only `prepare-*-state/token.sh verify`; для Naive восстановите manager/Caddy/accounting identity split. Исправляйте только после collision preflight.

## Fleet node остаётся unenrolled

Создание node record через UI — только registry stage. Для enrollment нужны:

1. node-local key + CSR;
2. offline CA signing;
3. central certificate binding;
4. node certificate installation;
5. successful mTLS authorization;
6. successful inventory command/result.

Если certificate bound, но node не connected, проверьте URI SAN, serial/fingerprint binding, validity, trust chain, hostname verification, node clock и central URL.

## Installer завершился с SSH exit 255

Transport exit не доказывает rollback или failure. На целевом host проверьте durable `/var/lib/proxy-control/runtime.json`, phase/status, owned files, services, Nginx config и protocol probe. Не повторяйте install вслепую поверх active generation.

## Когда делать rollback

Rollback оправдан, если новая generation не проходит config validation, health + protocol acceptance, accounting continuity или adjacent SNI regression. Восстанавливайте полную generation по [BACKUP_RESTORE.ru.md](BACKUP_RESTORE.ru.md), а не отдельный config/database file.
