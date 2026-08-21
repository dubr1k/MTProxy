# Upgrading and rollback

This procedure applies to a running installation and to the panel's `version-agent`. Treat every runtime as a separate change boundary.

## General procedure

1. Read the changelog, compatibility policy, upstream licenses, and pinned-artifact notes.
2. Run the full validation commands in [VALIDATION.md](VALIDATION.md).
3. Quiesce mutations. Back up secret files, named volumes, SQLite with WAL/SHM, manager state/journal keys, Nginx files and ownership manifests as one generation.
4. Render Compose and installer plans without applying them. Review image/binary digests, numeric identities, ports, mounts, and SNI routes.
5. Confirm every running project container has Compose project label `com.docker.compose.project=mtproxy`, then use the exact persisted `COMPOSE_FILE` overlay set for the entire change. Never use `--remove-orphans` from a partial model.
6. Upgrade one boundary at a time inside that one stack. Validate configuration, service health, protocol behavior, accounting, and adjacent SNI routes.
7. On failure, stop the changed service and restore the complete previous generation with the same stack name and overlay set. Do not regenerate journal keys or partially copy state.

## Panel version-agent

The panel never downloads a runtime artifact and never receives the Docker socket. A separate root-owned `version-agent` reads `/etc/proxy-control/versions.json` and exposes only a Unix socket at `/run/proxy-control/version-agent.sock`.

Before enabling it:

```bash
sudo install -d -m 0750 /etc/proxy-control
sudo install -o root -g root -m 0644 deploy/version-agent.service /etc/systemd/system/version-agent.service
sudo install -o root -g root -m 0644 deploy/proxy-control-version-agent.tmpfiles.conf /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo install -o root -g root -m 0600 deploy/version-agent.env.example /etc/proxy-control/version-agent.env
sudo install -o root -g root -m 0600 deploy/version-catalog.example.json /etc/proxy-control/versions.json
sudo systemd-tmpfiles --create /etc/tmpfiles.d/proxy-control-version-agent.conf
sudo systemctl daemon-reload
```

Replace every example catalog entry with an operator-verified artifact. Telemt entries must be immutable image references (`@sha256:...`). NaiveProxy/Caddy and mita entries must be HTTPS artifacts with lowercase SHA-256. The catalog is an allowlist, not a discovery mechanism; the browser cannot extend it.

Configure the deployment path and the complete Compose overlay list in `/etc/proxy-control/version-agent.env`. The agent writes only the generated `version-overrides/compose.versions.yaml`, configured binary targets, and its state/backup directory. It refuses symlink targets and invalid relative Compose paths. When a configured container pins a host binary, the preflight Docker inspect is fail-closed: only Docker's exact `No such object` result permits the update; daemon, permission, timeout, and other uncertain inspect failures block it.

Record the currently installed versions in `/var/lib/proxy-control/version-agent/state.json` before the first update. The UI sends `expected_current`; a mismatch returns `409` and prevents a stale browser tab from updating a changed runtime. A component marked `rollback_failed` remains blocked until an operator restores and verifies the complete generation, then reconciles the root-owned state.

Enable and verify the agent without changing the running stack:

```bash
sudo systemctl enable --now version-agent
sudo systemctl is-active version-agent
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/health
sudo curl --fail --unix-socket /run/proxy-control/version-agent.sock http://version-agent/v1/versions
```

The panel Compose service must mount `/run/proxy-control` and set `VERSION_AGENT_SOCKET=/run/proxy-control/version-agent.sock`. The socket is created with mode `0660`; make its numeric group accessible to panel UID `10001` without making it world-writable.

### Telemt

The agent reads back the current container image, pulls the selected immutable image, uses the full configured Compose model plus `version-overrides/compose.versions.yaml`, recreates only `mtproxy`, and verifies both the selected image reference and `healthy` status. A failed pull, start, image readback, or health check restores the previous override and starts the previous image. The rollback is successful only after the previous image reference and container health pass the same gates. It never calls `down -v`.

### NaiveProxy/Caddy and Mieru/mita

The agent downloads at most 256 MiB from the HTTPS host recorded in the catalog, verifies SHA-256, stages the executable with mode `0755`, runs the configured checker, and atomically replaces the target. Caddy is additionally validated against its Caddyfile and module checker. The version pin is read back, the service is restarted, and `systemctl is-active` is required after the operation.

Any failure restores the previous binary and pin, verifies the restored binary hash and pin readback, repeats the configured checker and Caddyfile validation, restarts the service, and requires `systemctl is-active`. State is written as the new version only after success. A rollback that fails any restore, config/readback, restart, or health gate is persisted and returned as `rollback_failed`; do not retry the update endpoint until an operator has restored and verified the complete previous generation.

## Verification after any update

Run, at minimum:

```bash
docker compose -f compose.yaml -f compose.naive.yaml -f compose.mieru.yaml ps
curl --fail http://127.0.0.1:8787/healthz
sudo nginx -t
sudo systemctl is-active version-agent caddy-naive mita
sudo journalctl -u version-agent --since=-15min --no-pager
```

Then perform the real protocol smoke tests for the changed boundary and check adjacent SNI routes. Redact URLs, tokens, QR payloads, cookies, certificates, private keys, and journal contents before sharing output.

`repair` and `uninstall` use the recorded ownership manifest and intentionally reject foreign drift; see [COMPATIBILITY.md](COMPATIBILITY.md). Product branding never authorizes runtime-path migration.
