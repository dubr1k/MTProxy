# Proxy Control panel

The panel manages distinct Telemt/MTProto, NaiveProxy/Caddy, Mieru/mita, and fleet boundaries. Protocol-specific capabilities and accounting semantics are not interchangeable.

The panel binds to host loopback only at `http://127.0.0.1:8787`. Use an SSH tunnel (`ssh -L 8787:127.0.0.1:8787 server`) or your own HTTPS reverse proxy remotely. Never publish Telemt port `9091`; Compose intentionally exposes no host port for it.

## First start

The deployment renderer creates `secrets/telemt-api-token` with mode `0600`; it is never placed in `.env`, deployment state, or logs. Do not reuse any example or production password. Create the first owner with a new password supplied on stdin:

```sh
read -rsp 'New password: ' PANEL_INITIAL_PASSWORD; echo
printf '%s\n' "$PANEL_INITIAL_PASSWORD" | docker compose run --rm -T panel \
  python -m panel.cli create-admin --username owner --role owner --password-stdin
unset PANEL_INITIAL_PASSWORD
docker compose up -d
```

Passwords require at least 12 characters and are stored with Argon2id. SQLite stores administrators, opaque-session SHA-256 digests, login throttling, and audit records only. Proxy secrets are never persisted by the panel: Telemt owns them, while a reveal lives in memory for at most 120 seconds and can be consumed once.

## Settings and roles

- `PANEL_ALLOWED_HOSTS`: comma-separated accepted Host values; add the public hostname behind a reverse proxy.
- `PANEL_COOKIE_SECURE=true`: keep enabled with HTTPS; set temporarily to `false` only for direct local HTTP testing.
- `PANEL_DATABASE=/data/panel.sqlite3`: SQLite database on the `panel-data` volume.
- `TELEMT_API_TOKEN_FILE=/run/secrets/telemt-api-token`: internal API-token transport.

`owner` manages administrators and users; `admin` manages users and reads audit; `viewer` is read-only. The last active owner cannot be removed or demoted. Disabling an administrator invalidates their sessions. Every mutation requires CSRF and is audited without passwords, tokens, links, or proxy secrets.

The panel also contains a durable fleet registry and typed per-node command queue. Its Fleet view, direct mTLS pull ingress, manual CSR enrollment, and outbound node service are documented in [FLEET.en.md](FLEET.en.md).

For owners and administrators, the Connections view can create, block, unblock, rotate, and remove individual proxy access records. An active Telegram link and QR code can be reopened through the explicit “QR and link” action. Every reveal is audited, while the link and secret are excluded from audit records and user-list responses.

## Telemt 3.4.25 traffic, quotas, and limits

The panel deliberately exposes two different counters:

- `runtime_total_octets` comes from `GET /v1/users` (`total_octets`) and is summed on the dashboard as traffic of the current Telemt runtime generation. It normally starts with the process, but a 3.4.25 in-runtime reload creates a new statistics generation and starts this counter again. It is a diagnostic runtime metric, not quota usage; resetting quota does not clear it.
- `quota_used_bytes` comes from `GET /v1/stats/users/quota` (`used_bytes`) and is displayed against `data_quota_bytes`. This is the resettable counter Telemt uses for quota enforcement. `quota_last_reset_epoch_secs` is the last manual-reset time, or `0` when no reset has occurred.

“Reset quota” calls `POST /v1/users/{username}/reset-quota`: Telemt clears quota usage and immediately persists quota state without changing the configured quota or runtime `total_octets`. Telemt 3.4.25 has no periodic quota-state checkpoint. State is saved on an explicit reset and graceful shutdown, so an abrupt termination can lose usage accumulated since the last save. The panel does not claim or emulate automatic daily/monthly resets; use separately verified external automation when a calendar period is required.

The limits form changes only documented Telemt fields: quota bytes, up/down bits per second, TCP connections, unique IPs, and RFC3339 expiration. An empty field sends `null` and removes that override. Panel responses use explicit field allowlists: Telemt `links`, `secret`, ad tags, IP lists, and any unknown or future nested fields from list/update/reset responses are not passed through.

## Optional NaiveProxy management

The host-Caddy integration is enabled through a separate Docker override, so a regular MTProxy deployment without NaiveProxy remains compatible:

```sh
COMPOSE_FILE=compose.yaml:compose.naive.yaml docker compose up -d --build
```

Store production-specific values in the local, Git-ignored `.env`:

```dotenv
COMPOSE_FILE=compose.yaml:compose.naive.yaml
NAIVE_PUBLIC_HOST=proxy.example.com
NAIVE_DATA_DIR=/var/lib/naive-manager
```

`naive-manager` is a dedicated unprivileged container. It uses host networking only for the loopback Caddy Admin API and TLS probe, has no Docker socket, and can write only `NAIVE_DATA_DIR` and its private runtime socket volume. `/var/log/naive-proxy` is mounted read-only at `/logs`; accounting state is the mode-`0600` SQLite/WAL set under `/data`. The panel sees only the token-authenticated Unix socket. The manager accepts only complete, successful CONNECT records for managed usernames and exposes explicit secret-free response allowlists. Counters are payload bytes (`bytes_read` client→proxy and `size` proxy→client), appear when a tunnel closes, and are not TLS/IP usage.

The Control Panel's NaiveProxy “Quota, MiB” field sets a per-user `quota_bytes`. `null` means the quota is disabled and the user is unlimited; zero and negative values are rejected. A dedicated manager thread collects completed CONNECT records on an interval (60 s by default, `NAIVE_QUOTA_INTERVAL_SECONDS`) even when the panel is closed, and transactionally disables a user when `total_bytes >= quota_bytes` by removing that user's credentials from the managed Caddy block. Enforcement never runs on a read path: `GET /v1/health` and `GET /v1/traffic` report state and never rewrite the managed config. This is admission enforcement, not a byte-level hard cap: an already-open tunnel may finish and cause overshoot, and a user may keep transferring until the next enforcement pass. Do not use it as an exact billing limit.

Resetting Naive traffic clears only the local accounting baseline and does not automatically re-enable a user disabled by quota. After a reset, explicitly click “Enable”. Removing the quota (`null`) or raising it above the recorded usage does not re-enable access either: the manager only records that the quota no longer holds the user back (`disabled_reason` becomes `manual`), and enabling stays a separate operation. Enabling a user whose usage still exceeds the quota is refused with `409` and the reason code `quota_exhausted`, which the panel shows as an actionable message rather than a manager outage. User passwords, usernames, and access URLs are not returned by list or quota API responses.

Deploy the manager before the panel: an older manager silently ignores `quota_bytes` on create and has no quota endpoint, so a newer panel would report a failure the operator cannot act on.

The production accounting contract keeps ten 10 MiB Caddy rotations plus the active file (110 MiB declared footprint) and allows at most 128 MiB of exact consumed-prefix verification per collection request. Prefix verification is synchronous and request-wide across all retained files; the extra 18 MiB is bounded headroom for an active file crossing its rotation boundary. Startup rejects a verification budget below the declared footprint. A changed prefix or a footprint that exceeds the bounded budget fails closed and makes accounting unhealthy instead of returning counters that may have been replayed or omitted.

Before first start, copy the active Caddyfile to `${NAIVE_DATA_DIR}/Caddyfile`, create `secrets/naive-manager-token` with mode `0600`, provide the same token as `${NAIVE_DATA_DIR}/manager-token`, and run the initial import:

```sh
NAIVE_DATA_DIR=${NAIVE_DATA_DIR:-/var/lib/naive-manager}
test ! -L "${NAIVE_DATA_DIR}" || { echo "NAIVE_DATA_DIR must not be a symlink" >&2; exit 1; }
# Fail closed if the fixed production IDs belong to another account/group.
uid_name=$(getent passwd 10003 | cut -d: -f1 || true)
gid_name=$(getent group 10004 | cut -d: -f1 || true)
test -z "${uid_name}" -o "${uid_name}" = naive-caddy || { echo "UID 10003 collision: ${uid_name}" >&2; exit 1; }
test -z "${gid_name}" -o "${gid_name}" = naive-accounting || { echo "GID 10004 collision: ${gid_name}" >&2; exit 1; }
getent group naive-accounting >/dev/null || groupadd --system --gid 10004 naive-accounting
id naive-caddy >/dev/null 2>&1 || useradd --system --uid 10003 --gid naive-accounting --home /nonexistent --shell /usr/sbin/nologin naive-caddy
test "$(id -u naive-caddy)" = 10003 || { echo "naive-caddy must use UID 10003" >&2; exit 1; }
test "$(id -g naive-caddy)" = 10004 || { echo "naive-caddy must use GID 10004" >&2; exit 1; }
# UID 10002/GID 101 remain the manager identity; GID 10004 is read-only supplementary access.
install -d -o 10002 -g 101 -m 0700 "${NAIVE_DATA_DIR}"
install -d -o 10003 -g 10004 -m 0750 /var/log/naive-proxy
for file in Caddyfile manager-token; do
  test -f "${NAIVE_DATA_DIR}/${file}" && test ! -L "${NAIVE_DATA_DIR}/${file}" || exit 1
done
chown -h 10002:101 "${NAIVE_DATA_DIR}/Caddyfile" "${NAIVE_DATA_DIR}/manager-token"
chmod 0640 "${NAIVE_DATA_DIR}/Caddyfile"
chmod 0400 "${NAIVE_DATA_DIR}/manager-token"
docker compose -f compose.yaml -f compose.naive.yaml run --rm --build naive-manager --bootstrap-only
caddy adapt --adapter caddyfile --validate --config "${NAIVE_DATA_DIR}/Caddyfile" >/dev/null
install -o root -g root -m 0755 scripts/check-naive-caddy-build.sh /usr/local/libexec/check-naive-caddy-build
install -o root -g root -m 0644 deploy/caddy-naive.service /etc/systemd/system/caddy-naive.service
systemctl daemon-reload
```

Host Caddy and the container manager have separate identities: Caddy is UID `10003`, while the manager remains `10002:101` and receives only supplementary accounting GID `10004`. `/var/log/naive-proxy` is `10003:10004` mode `0750`; Caddy creates mode-`0640` logs, so the manager can read but cannot create, truncate, rename, or append them. Manager data remains `10002:101` mode `0700`. At Caddy start and systemd reload, privileged `install` stages the manager-owned source as `/run/caddy-naive/Caddyfile` (`10003:10004`, `0400`) in a mode-`0700` runtime directory. Caddy cannot traverse `/var/lib/naive-manager` at runtime. Manager-driven mutations do not use the staged file: they adapt and validate the just-written source through the loopback admin API and send that exact JSON to `/load`, preserving transactional rollback without a stale-stage window. Verify `systemd-analyze verify`, inspect `systemctl show caddy-naive -p User -p Group`, and confirm the manager cannot append the log while Caddy cannot read manager state before cutover.

For migration, first stop manager mutations and Caddy, then back up the active unit, binary, Caddyfile, manager data, and log directory. Run the UID/GID collision preflight before changing ownership; create the separate identities and permissions; install the pinned binary/checker; run the checker and exact `caddy adapt --validate`; bootstrap the manager; switch the unit; then start Caddy and the Compose override. Re-running bootstrap is idempotent. Faults at prepared, files-replaced, or reload-pending migration phases restore the paired old config/state generation before retry. Do not delete the old unit or backup until health, cover HTTPS, authenticated CONNECT, traffic collection, and all adjacent SNI routes pass. Every later credential mutation follows paired backup → Caddy adapt with `validate=true` → fsync journal → atomic replace → Caddy `/load` → HTTPS probe. Failure restores both files and verifies the restored live generation. An unconfirmed rollback leaves the manager unhealthy and keeps the journal for startup recovery.

Rollback is deliberately host-controlled: stop `naive-manager` and Caddy; restore the saved Caddyfile/unit/binary, manager-data snapshot, log ownership/modes, and previous service identities as one generation; run the restored build's validation; restart Caddy; and re-run cover/authenticated/SNI probes before removing the override. Never copy only `traffic.sqlite3` without its `-wal`/`-shm` files while the manager is running. A traffic reset changes only the local baseline; viewers are denied reset, and audit records the username/action without credentials or authorization headers.

The UI provides an HTTPS proxy URL, QR, and ready-to-download `config.json`:

```json
{"listen":"socks://127.0.0.1:1080","proxy":"https://USER:PASSWORD@proxy.example.com"}
```

## Backup

Back up volumes `panel-data` and `telemt-config`, `${NAIVE_DATA_DIR}` when the Naive integration is enabled, and secret files separately with mode `0600`. `users.conf` is imported only when `telemt-config/config.toml` is first created. Telemt then becomes the source of truth and atomically persists API mutations. Deleting `telemt-config` causes the original `users.conf` to be imported again.

```sh
curl -fsS http://127.0.0.1:8787/healthz
docker compose ps
docker compose logs panel mtproxy   # output must contain no secrets
```
