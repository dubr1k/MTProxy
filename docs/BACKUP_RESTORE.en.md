# Proxy Control backup and restore

**English** · [Русский](BACKUP_RESTORE.ru.md)

A backup is usable only when it is consistent, protected as a credential, checksummed, and restore-tested. Copying one convenient file is not a generation backup.

## Backup inventory

| Boundary | Required data |
|---|---|
| Panel | SQLite through online backup, or DB + WAL/SHM with the writer stopped |
| Telemt | `telemt-config` volume, source secret files, API token |
| Naive | complete `NAIVE_DATA_DIR`, Caddyfile, user state, transaction/backups, accounting SQLite/WAL/SHM, Caddy binary/unit, log ownership contract |
| Mieru | complete manager state, `journal.json` + original `journal.key`, backups, manager token, mita config/binary/unit, UDS/tmpfiles contract |
| Fleet central | panel DB, ingress config, public server certificate, client CA certificate; offline CA private key separately |
| Fleet node | agent SQLite/outbox, node certificate/key, trusted CA, local Telemt token, service env/unit |
| Host routing | Nginx stream/http files, exact modes/owners, ownership manifests and installer backups |
| Deployment | exact Git revision, image IDs/digests, binary digests, complete `COMPOSE_FILE`, package/unit versions |

Never keep the offline fleet CA key and online node backups in one broadly accessible archive.

## Preparation

1. Stop new mutations.
2. Record the exact revision and runtime identities.
3. Put services into a known state.
4. Create a root-only destination on separate storage.
5. Keep secret paths/content out of shared logs.

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

Prefer the online backup API. Example for the panel container:

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

Copy the backup file to protected storage and remove the staging copy. Alternatively stop the writer and copy DB + `-wal` + `-shm` together. Never copy only the main DB while a WAL writer is active.

```bash
sqlite3 panel.backup.sqlite3 'PRAGMA integrity_check;'
```

The expected output is exactly `ok`.

## Docker volumes

Stop mutation-capable services or use an application-consistent snapshot:

```bash
docker compose stop panel mtproxy
# Use the validated volume snapshot mechanism for your platform.
docker compose up -d
```

The `telemt-config` volume is credential-bearing and contains API-mutated source of truth. Deleting it causes the entrypoint to import the original `users.conf` again.

## Naive generation

Stop panel mutations, manager, and host Caddy. Preserve together:

- complete `${NAIVE_DATA_DIR}`;
- `/var/log/naive-proxy` with ownership/modes;
- pinned Caddy binary/checker and systemd unit;
- manager token source;
- deployment environment and exact Compose overlay set.

After restore, reinstate numeric identities/modes, run the pinned build checker and `caddy adapt --validate`, allow manager recovery, then test cover HTTPS, authenticated CONNECT, and accounting.

## Mieru generation

Stop panel and `mieru-manager`, then `mita` when copying live config/state. Keep `journal.json` and the **same** `journal.key` as one recovery unit. Never generate a new key for an existing journal.

Before startup after restore:

```bash
sudo ./scripts/prepare-mieru-state.sh verify /var/lib/mieru-manager
sudo ./scripts/prepare-mieru-token.sh verify /etc/mieru-manager/token
systemctl daemon-reload
systemctl start mita
docker compose up -d mieru-manager panel
```

Verify exact mita status, manager health, and a real Mieru client path.

## Nginx and shared 443

Preserve the route file, included stream/http files, certificate references, UID/GID/modes, and `/var/lib/proxy-control/` manifests/backups. Restore through temporary paths, metadata/symlink review, atomic replace, `nginx -t`, reload, and regression tests for every adjacent SNI.

## Checksums and encryption

```bash
(
  cd "$backup"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
  chmod 0600 SHA256SUMS
)

# Verify later from the same directory:
(cd "$backup" && sha256sum -c SHA256SUMS)
```

Store the archive in encrypted/access-controlled storage. Checksums detect corruption; they do not provide confidentiality or authenticity without a protected channel/signature.

## Restore drill

On the chosen retention cycle, restore in isolation and verify:

- checksums and SQLite integrity;
- UID/GID/mode contracts;
- Compose render with the exact overlay set;
- manager journal recovery;
- Nginx validation without production apply;
- protocol probes on test listeners;
- absence of unintended logs or temporary credentials in the archive.

## Upgrade rollback

1. Stop the changed boundary.
2. Preserve the failed generation for investigation.
3. Restore the **complete** previous generation.
4. Restore exact images/binaries/units and overlay set.
5. Validate before start/reload.
6. Run health and real protocol probes.
7. Confirm adjacent SNI and accounting continuity.

If restore is not verified, do not claim rollback success and do not delete the recovery journal.
