# Proxy Control operations runbook

**English** · [Русский](OPERATIONS.ru.md)

Use this guide for an already deployed node. It does not replace the [installation guide](../INSTALL.en.md), [backup contract](BACKUP_RESTORE.en.md), or protocol-specific acceptance tests.

## 1. Start of change window

Capture context without printing secret-bearing environment:

```bash
cd /opt/mtproxy-shared443   # or the actual checkout/deployment path
git rev-parse HEAD 2>/dev/null || true
docker compose ps
systemctl is-active nginx docker
sudo nginx -t
ss -lntup
```

Confirm the complete deployment overlay set is active. Prefer a root-only `.env` containing one line such as:

```dotenv
COMPOSE_FILE=compose.yaml:compose.naive.yaml:compose.mieru.yaml
```

Never dump the complete `.env` into a terminal transcript, issue, or CI log. Never use `docker compose --remove-orphans` when the current model omits any deployed overlay.

## 2. Daily health

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz
sudo nginx -t
systemctl --no-pager --full status nginx
```

For enabled host runtimes:

```bash
systemctl is-active caddy-naive mita
MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
```

Accept only anchored mita status output of this exact form:

```text
mita server status is "RUNNING"
```

Do not treat an unrelated `RUNNING` token in stderr or another line as success.

## 3. Protocol acceptance

### MTProxy / Telemt

1. Confirm Nginx owns public TCP/443 and Telemt uses the expected loopback backend.
2. Run an external Fake-TLS → Obfuscated2 → `req_pq_multi` → validated Telegram `resPQ` probe for every active secret.
3. Test a real Telegram client from the target network.
4. Regression-test adjacent SNI routes.

HTTP health and an open port do not prove MTProto.

### NaiveProxy

1. Check unauthenticated cover HTTPS.
2. Open authenticated CONNECT and transfer a known payload.
3. Close the tunnel before checking the accounting increment.
4. Confirm authorization is absent from access logs.
5. Regression-test adjacent SNI routes.

### Mieru

1. Verify pinned `/usr/bin/mita` version/digest and exact status.
2. Run a real client → server → Internet probe for the configured TCP/UDP listeners.
3. Check manager health and panel typed status.
4. Do not expect per-user traffic counters: the safe typed boundary is unavailable and the UI reports `unavailable`.

## 4. User lifecycle

### Roles

- `owner`: administrators, users, reveal/rotation, and fleet registry;
- `admin`: protocol users and audit within allowed boundaries;
- `viewer`: read-only, with no reveal, reset, or mutations.

Every mutation endpoint must require CSRF. Audit stores action/actor/target/result but never credentials, URLs, QR payloads, or reveal tokens.

### One-time credentials

Naive and Mieru create/rotate return credentials only through a one-time reveal with `Cache-Control: no-store`. Closing the dialog clears URL, QR, and config fields from frontend state.

An existing Mieru password cannot be recovered from `hashedPassword`. Use **New link + QR** to rotate; the previous client configuration stops working.

## 5. Configuration changes

Before mutation:

1. Back up one consistent generation.
2. Record current revision, image/binary digests, and service status.
3. Run configuration validation/read-only plan.
4. Change one protocol boundary.
5. Verify health, the real protocol path, accounting, and adjacent SNI.
6. Only then expire temporary rollback artifacts under the retention policy.

Naive and Mieru managers have their own journals and recovery. That does not replace a host-level backup before a deployment change.

## 6. Logs

Use bounded queries and inspect recent events first:

```bash
docker compose logs --since=15m --tail=300 panel mtproxy
journalctl -u nginx -u caddy-naive -u mita --since=-15m --no-pager
```

Before sharing logs, remove passwords, complete access URLs, QR/reveal payloads, tokens, cookies/CSRF values, and PKI material. Keep infrastructure identity only in an approved private incident channel.

## 7. Accounting

- Telemt runtime counter and quota usage are different values.
- Naive bytes appear after a successful CONNECT closes.
- Mieru per-user traffic is unavailable; its quota is a rolling approximate session-admission check.
- Reset creates a local baseline. It does not create billing precision or a calendar period.

See [ACCOUNTING.md](ACCOUNTING.md).

## 8. Restart and recovery

Restart one boundary at a time:

```bash
docker compose restart panel
systemctl restart caddy-naive
systemctl restart mita
```

Repeat the boundary's acceptance test after every restart. Never delete `journal.json`, `journal.key`, `transaction.json`, WAL/SHM, or manager backups to force startup; use documented repair/restore.

For installer-owned core:

```bash
sudo python3 scripts/proxyctl.py repair
```

`repair` loads the private ownership manifest and intentionally accepts no arbitrary path.

## 9. Incident sequence

1. Stop new mutations without destroying process/state.
2. Capture service status, exact revision, bounded logs, and listener ownership.
3. Create a forensic backup of the current generation.
4. Isolate the boundary: Nginx, panel, Telemt, Caddy/Naive, mita/Mieru, or fleet.
5. Run negative and positive probes for that boundary.
6. Repair or roll back only after establishing root cause.
7. Run complete protocol regression, including adjacent SNI routes.

See [Troubleshooting](TROUBLESHOOTING.en.md).

## 10. End-of-window checklist

- expected Compose services are healthy;
- `nginx -t` passes;
- public listener ownership is unchanged;
- acceptance passed for every changed protocol boundary;
- SQLite integrity and backup checksums pass;
- temporary configs, clients, worktrees, packages, and caches are removed;
- no production credential remains in shell history, logs, or artifacts.
