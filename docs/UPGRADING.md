# Upgrading and rollback

1. Read the changelog, compatibility policy, upstream licenses, and pinned-artifact notes.
2. Run the full validation commands in [VALIDATION.md](VALIDATION.md).
3. Quiesce mutations. Back up secret files, named volumes, SQLite with WAL/SHM, manager state/journal keys, Nginx files and ownership manifests as one generation.
4. Render Compose and installer plans without applying them. Review image/binary digests, numeric identities, ports, mounts, and SNI routes.
5. Confirm every running project container has Compose project label `com.docker.compose.project=mtproxy`, then use the exact persisted `COMPOSE_FILE` overlay set for the entire change. Never use `--remove-orphans` from a partial model.
6. Upgrade one boundary at a time inside that one stack. Validate configuration, service health, protocol behavior, accounting, and adjacent SNI routes.
7. On failure, stop the changed service and restore the complete previous generation with the same stack name and overlay set. Do not regenerate journal keys or partially copy state.

`repair` and `uninstall` use the recorded ownership manifest and intentionally reject foreign drift. Product branding never authorizes runtime-path migration; see [COMPATIBILITY.md](COMPATIBILITY.md).
