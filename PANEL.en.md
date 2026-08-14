# MTProxy control panel

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

## Backup

Back up volumes `panel-data` and `telemt-config`, plus secret files separately with mode `0600`. `users.conf` is imported only when `telemt-config/config.toml` is first created. Telemt then becomes the source of truth and atomically persists API mutations. Deleting `telemt-config` causes the original `users.conf` to be imported again.

```sh
curl -fsS http://127.0.0.1:8787/healthz
docker compose ps
docker compose logs panel mtproxy   # output must contain no secrets
```
