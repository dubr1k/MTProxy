# Операционный runbook Proxy Control

[English](OPERATIONS.en.md) · **Русский**

Это руководство — для уже развёрнутого узла. Оно не заменяет [installation guide](../INSTALL.ru.md), [backup contract](BACKUP_RESTORE.ru.md) или protocol-specific acceptance tests.

## 1. Перед началом смены

Зафиксируйте контекст, не выводя secret-bearing environment:

```bash
cd /opt/mtproxy-shared443   # либо фактический checkout/deployment path
git rev-parse HEAD 2>/dev/null || true
docker compose ps
systemctl is-active nginx docker
sudo nginx -t
ss -lntup
```

Проверьте, что используется полный deployment overlay set. Предпочтительный вариант — root-only `.env` с одной строкой:

```dotenv
COMPOSE_FILE=compose.yaml:compose.naive.yaml:compose.mieru.yaml
```

Не печатайте полный `.env` в терминал, issue или CI. Не используйте `docker compose --remove-orphans`, если текущая модель не содержит все активные overlays.

## 2. Ежедневная проверка

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
sudo nginx -t
systemctl --no-pager --full status nginx
```

Если включены host runtimes:

```bash
systemctl is-active caddy-naive mita
MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
```

Для `mita` принимайте только точный anchored status output вида:

```text
mita server status is "RUNNING"
```

Не интерпретируйте произвольное слово `RUNNING` в stderr или соседней строке как успешный статус.

## 3. Protocol acceptance

### MTProxy / Telemt

1. Убедитесь, что public TCP/443 принадлежит Nginx, а Telemt слушает ожидаемый loopback backend.
2. Выполните внешний Fake-TLS → Obfuscated2 → `req_pq_multi` → validated Telegram `resPQ` probe для каждого active secret.
3. Проверьте реальный Telegram client из целевой сети.
4. Regression-test соседние SNI routes.

HTTP health или открытый порт не подтверждают MTProto.

### NaiveProxy

1. Проверьте cover HTTPS без credentials.
2. Выполните authenticated CONNECT и передайте известный payload.
3. Закройте tunnel и только после этого проверьте accounting increment.
4. Убедитесь, что authorization не попал в access logs.
5. Проверьте соседние SNI routes.

### Mieru

1. Проверьте pinned `/usr/bin/mita` version/digest и exact status.
2. Выполните реальный client → server → Internet probe для TCP/UDP согласно active config.
3. Проверьте manager health и panel typed status.
4. Не ожидайте per-user traffic counters: безопасная typed boundary для них отсутствует, поэтому UI показывает `unavailable`.

## 4. Управление пользователями

### Роли

- `owner`: администраторы, пользователи, reveal/rotation и fleet registry;
- `admin`: protocol users и audit в разрешённых границах;
- `viewer`: read-only, без reveal, reset и mutations.

Все mutation endpoints должны требовать CSRF. Audit содержит action/actor/target/result, но не credentials, URLs, QR payloads или reveal tokens.

### One-time credentials

Naive и Mieru create/rotate возвращают credential только через one-time reveal с `Cache-Control: no-store`. После закрытия диалога frontend очищает URL, QR и config fields.

Существующий Mieru password нельзя восстановить из `hashedPassword`. Для повторной выдачи используйте **«Новая ссылка + QR»**; это rotation, после которой старая конфигурация недействительна.

## 5. Изменение конфигурации

Перед mutation:

1. Сделайте backup одной согласованной generation.
2. Зафиксируйте current revision, images/binary digests и service status.
3. Выполните config validation/read-only plan.
4. Меняйте одну protocol boundary.
5. Проверяйте health, real protocol path, accounting и adjacent SNI.
6. Только после этого удаляйте временные rollback artifacts по retention policy.

Naive manager и Mieru manager сами используют backup/journal/recovery. Это не отменяет host-level backup перед deployment change.

## 6. Логи

Используйте bounded запросы и сначала смотрите последние события:

```bash
docker compose logs --since=15m --tail=300 panel mtproxy
journalctl -u nginx -u caddy-naive -u mita --since=-15m --no-pager
```

Перед передачей логов удалите:

- passwords и complete access URLs;
- QR/reveal payloads;
- bearer/manager/fleet tokens;
- cookies, CSRF values, certificate/private key data;
- public IP/hostname/node identity, если это не требуется для приватного incident channel.

## 7. Accounting

- Telemt runtime counter и quota usage — разные величины.
- Naive bytes появляются после закрытия successful CONNECT.
- Mieru per-user traffic отображается как unavailable, а quota — rolling approximate session-admission check.
- Reset создаёт local baseline; он не превращает telemetry в billing record и не задаёт calendar period.

См. [ACCOUNTING.md](ACCOUNTING.md).

## 8. Restart и recovery

Restart выполняйте по одной boundary:

```bash
docker compose restart panel
systemctl restart caddy-naive
systemctl restart mita
```

После каждого restart повторите соответствующий acceptance test. Не удаляйте `journal.json`, `journal.key`, `transaction.json`, WAL/SHM или manager backups, чтобы «починить» startup: это разрушает recovery contract. Используйте documented repair/restore path.

Для installer-owned core:

```bash
sudo python3 scripts/proxyctl.py repair
```

`repair` читает private ownership manifest и намеренно не принимает arbitrary paths.

## 9. Incident sequence

1. Остановите новые mutations, но не уничтожайте process/state.
2. Снимите service status, exact revision, bounded logs и listener ownership.
3. Создайте forensic backup текущей generation.
4. Определите boundary: Nginx routing, panel, Telemt, Caddy/Naive, mita/Mieru или fleet.
5. Выполните negative и positive probe этой boundary.
6. Repair или rollback делайте только после подтверждения root cause.
7. После восстановления выполните полный protocol regression, включая соседние SNI.

См. [Troubleshooting](TROUBLESHOOTING.ru.md).

## 10. Завершение смены

- `docker compose ps` показывает ожидаемые healthy services;
- `nginx -t` успешен;
- public listener ownership не изменился;
- MTProxy/Naive/Mieru acceptance выполнен для затронутых boundaries;
- SQLite integrity и backup checksums проверены;
- temporary configs, clients, worktrees, packages и caches удалены;
- production credentials не остались в shell history, logs или artifacts.
