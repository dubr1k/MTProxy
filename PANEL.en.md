# MTProxy and NaiveProxy control panel

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

For owners and administrators, the Connections view can create, block, unblock, rotate, and remove individual proxy access records. An active Telegram link and QR code can be reopened through the explicit “QR and link” action. Every reveal is audited, while the link and secret are excluded from audit records and user-list responses.

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

`naive-manager` is a dedicated unprivileged container. It uses host networking only for the loopback Caddy Admin API and TLS probe, has no Docker socket, and has a single writable bind mount: `NAIVE_DATA_DIR`. The panel sees only a token-authenticated Unix socket in a dedicated tmpfs volume. The data directory contains the managed Caddyfile, `users.json`, paired transactional backups, an fsync-backed recovery journal, and a mode-`0400` manager-token copy. The latest 20 backup generations are retained.

Before first start, copy the active Caddyfile to `${NAIVE_DATA_DIR}/Caddyfile`, create `secrets/naive-manager-token` with mode `0600`, provide the same token as `${NAIVE_DATA_DIR}/manager-token`, and run the initial import:

```sh
NAIVE_DATA_DIR=${NAIVE_DATA_DIR:-/var/lib/naive-manager}
test ! -L "${NAIVE_DATA_DIR}" || { echo "NAIVE_DATA_DIR must not be a symlink" >&2; exit 1; }
install -d -o root -g root -m 0700 "${NAIVE_DATA_DIR}"
for file in Caddyfile manager-token; do
  test -f "${NAIVE_DATA_DIR}/${file}" && test ! -L "${NAIVE_DATA_DIR}/${file}" || exit 1
done
chown -h 10002:101 "${NAIVE_DATA_DIR}/Caddyfile" "${NAIVE_DATA_DIR}/manager-token"
chmod 0600 "${NAIVE_DATA_DIR}/Caddyfile"
chmod 0400 "${NAIVE_DATA_DIR}/manager-token"
chown 10002:101 "${NAIVE_DATA_DIR}"
docker compose -f compose.yaml -f compose.naive.yaml run --rm --build naive-manager --bootstrap-only
caddy validate --config /var/lib/naive-manager/Caddyfile
```

`${NAIVE_DATA_DIR}`, `Caddyfile`, and the generated `users.json`, `transaction.json`, and `backups/` must be owned by UID/GID `10002:101`. The current production `caddy-naive.service` runs as `root:root`, so it can read the mode-`0700` directory and mode-`0600` Caddyfile. If host Caddy runs as an unprivileged `caddy` user, grant only traverse/read through a dedicated group or ACL and verify access as that user before switching the unit; never make credential-bearing files world-readable.

After validation, point the host Caddy service at that Caddyfile and perform a controlled reload. Every mutation follows paired backup → Caddy adapt with `validate=true` → fsync journal → atomic replace → Caddy `/load` → HTTPS probe. Failure restores both files and requires the restored live configuration to pass reload and probe. An unconfirmed rollback leaves the manager unhealthy and preserves the journal for startup recovery. A restart either restores the previous generation or reloads a completely written new generation according to the journal phase. Create/reveal/rotate responses use `Cache-Control: no-store`; list and audit responses contain no passwords or proxy URLs. Viewers can only see names and status.

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
