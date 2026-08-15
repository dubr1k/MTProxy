# Backup и restore Proxy Control

[English](BACKUP_RESTORE.en.md) · **Русский**

Backup считается пригодным только если он согласован, защищён как credential, имеет checksum и был проверен restore-процедурой. Копирование одного удобного файла не является резервной копией generation.

## Что резервировать

| Boundary | Обязательные данные |
|---|---|
| Panel | SQLite database через online backup или вместе с WAL/SHM при остановленном writer |
| Telemt | `telemt-config` volume, исходные secret files, API token |
| Naive | полный `NAIVE_DATA_DIR`, Caddyfile, users state, transaction/backups, accounting SQLite/WAL/SHM, Caddy binary/unit, log ownership contract |
| Mieru | manager state целиком, `journal.json` + исходный `journal.key`, backups, manager token, `mita` config/binary/unit, UDS/tmpfiles contract |
| Fleet central | panel DB, ingress config, public server cert, client CA certificate; offline CA private key отдельно |
| Fleet node | agent SQLite/outbox, node certificate/key, trusted CA, local Telemt token, service env/unit |
| Host routing | Nginx stream/http files, exact modes/owners, ownership manifests и installer backups |
| Deployment | exact Git revision, image IDs/digests, binary digests, полный `COMPOSE_FILE`, package/unit versions |

Не складывайте offline fleet CA key и node backups в один доступный online archive.

## Подготовка

1. Остановите новые mutations.
2. Запишите exact revision и runtime identities.
3. Убедитесь, что все services находятся в известном состоянии.
4. Создайте root-only destination на отдельном filesystem/storage.
5. Не выводите secret paths/content в общий лог.

Пример метаданных:

```bash
umask 077
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup="/root/proxy-control-backup-$stamp"
install -d -m 0700 "$backup"
git rev-parse HEAD > "$backup/source-revision.txt" 2>/dev/null || true
docker compose config --services > "$backup/compose-services.txt"
docker compose images --format json > "$backup/compose-images.json"
```

## SQLite

Предпочтителен online backup API. Для panel container пример зависит от фактического DB path:

```bash
docker exec -i mtproxy-panel-1 python - <<'PY'
import sqlite3
src = sqlite3.connect('/data/panel.sqlite3')
dst = sqlite3.connect('/data/panel.backup.sqlite3')
with dst:
    src.backup(dst)
print(dst.execute('PRAGMA integrity_check').fetchone()[0])
dst.close(); src.close()
PY
```

После этого скопируйте backup file в защищённое место и удалите staging copy. Альтернатива — остановить writer и копировать DB + `-wal` + `-shm` вместе. Никогда не копируйте только main DB при active WAL writer.

Проверка:

```bash
sqlite3 panel.backup.sqlite3 'PRAGMA integrity_check;'
```

Ожидается ровно `ok`.

## Docker volumes

Остановите mutation-capable services или используйте application-consistent snapshot. Архивируйте volume без изменения ownership:

```bash
docker compose stop panel mtproxy
# Выполните проверенный volume snapshot/backup механизм вашей платформы.
docker compose up -d
```

Не удаляйте volume после backup. `telemt-config` содержит credentials и API-mutated source of truth; удаление заставит entrypoint повторно импортировать исходный `users.conf`.

## Naive generation

Остановите panel mutations, manager и host Caddy. Сохраняйте вместе:

- весь `${NAIVE_DATA_DIR}`;
- `/var/log/naive-proxy` с ownership/modes;
- pinned Caddy binary/checker и systemd unit;
- manager token source;
- deployment environment и exact Compose overlay set.

После restore сначала восстановите numeric identities/modes, затем выполните pinned build checker и `caddy adapt --validate`, bootstrap/manager recovery, cover HTTPS, authenticated CONNECT и accounting probe.

## Mieru generation

Остановите panel и `mieru-manager`, затем `mita`, если копируется live config/state. Сохраняйте `journal.json` и **тот же** `journal.key` как одну recovery unit. Не генерируйте новый key для существующего journal.

Перед startup после restore:

```bash
sudo ./scripts/prepare-mieru-state.sh verify /var/lib/mieru-manager
sudo ./scripts/prepare-mieru-token.sh verify /etc/mieru-manager/token
systemctl daemon-reload
systemctl start mita
docker compose up -d mieru-manager panel
```

Проверяйте exact `mita` status, manager health и реальный Mieru client path.

## Nginx и shared 443

Сохраняйте route file, included stream/http files, certificate references, UID/GID/modes и `/var/lib/proxy-control/` manifests/backups. Restore:

1. восстановить файлы во временные paths;
2. проверить owner/mode и symlink policy;
3. atomic replace;
4. `nginx -t`;
5. reload;
6. проверить все соседние SNI, не только Proxy Control.

## Checksums и шифрование

```bash
find "$backup" -type f -print0 | sort -z | xargs -0 sha256sum > "$backup/SHA256SUMS"
chmod 0600 "$backup/SHA256SUMS"
```

Храните archive в зашифрованном/access-controlled storage. Checksums обнаруживают повреждение, но не обеспечивают конфиденциальность или authenticity без защищённого канала/подписи.

## Restore drill

Не реже принятого retention цикла проверяйте восстановление в изолированной среде:

- checksum verification;
- SQLite integrity;
- UID/GID/mode contracts;
- Compose render с точным overlay set;
- manager journal recovery;
- Nginx validation без применения к production;
- protocol probes на test listeners;
- подтверждение, что backup не содержит unintended logs/temp credentials.

## Rollback после upgrade

1. Остановите изменённую boundary.
2. Сохраните failed generation для расследования.
3. Восстановите **полную** предыдущую generation.
4. Восстановите exact images/binaries/units и overlay set.
5. Validate config до start/reload.
6. Выполните health и real protocol probes.
7. Подтвердите adjacent SNI и accounting continuity.

Если restore не подтверждён, не объявляйте rollback успешным и не удаляйте recovery journal.
