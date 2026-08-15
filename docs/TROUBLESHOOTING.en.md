# Proxy Control troubleshooting

**English** · [Русский](TROUBLESHOOTING.ru.md)

Isolate one boundary first. Restarting everything destroys evidence and can widen the outage.

## Initial diagnostics

```bash
docker compose ps
curl -fsS http://127.0.0.1:8787/healthz || true
sudo nginx -t
ss -lntup
systemctl is-active nginx docker caddy-naive mita 2>/dev/null || true
docker compose logs --since=15m --tail=300 panel mtproxy naive-manager mieru-manager 2>/dev/null
```

Redact credentials, access URLs, tokens, cookies, PKI, and infrastructure identity before sharing output.

## Panel unavailable

1. Check panel health and loopback `127.0.0.1:8787`.
2. Confirm the public hostname is in `PANEL_ALLOWED_HOSTS`.
3. Keep `PANEL_COOKIE_SECURE=true` behind HTTPS.
4. Test Nginx HTTP vhost and stream SNI route separately.
5. Verify SQLite integrity and volume ownership.
6. Do not delete DB/session tables as a reset.

A `401` from a protected API without a session is expected. An unauthenticated root redirect to login is also expected.

## Login failure

- confirm an active owner remains;
- inspect clock, cookie domain/Secure, and reverse-proxy headers;
- account for login throttling;
- create the initial owner with `panel.cli create-admin --password-stdin`;
- never pass passwords through argv or shell history.

## MTProxy is healthy but clients fail

- verify DNS A/AAAA and no CDN/proxy in the raw TCP path;
- confirm Nginx owns public 443 and the SNI map points to the correct loopback port;
- run a real `resPQ` probe, not an HTTPS check;
- validate Fake-TLS domain/secret for every active user;
- regression-test adjacent SNI/Xray routes;
- test another network because ISP paths differ.

## Naive manager unhealthy

- verify token mode/ownership and UDS;
- run the exact Caddy build checker;
- run `caddy adapt --adapter caddyfile --validate` against source config;
- inspect, but do not delete, `transaction.json` and paired backups;
- verify identities: manager `10002:101`, Caddy `10003:10004`, accounting group `10004`;
- manager may read but must not mutate Caddy logs;
- for degraded accounting, inspect rotation/prefix budget and inode continuity.

## Naive traffic does not increase

Accounting appears only after a **successful CONNECT closes**. Close the client tunnel, then inspect the collector. Values are payload bytes without TLS/IP overhead; active or aborted tunnels may not produce the expected record.

## Mieru manager unhealthy

```bash
systemctl status mita --no-pager
MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
export MIERU_MITA_GID="$(getent group mita | cut -d: -f3)"
: "${MIERU_MITA_GID:?mita group is missing}"
sudo ./scripts/prepare-mieru-token.sh verify /etc/mieru-manager/token
sudo env MIERU_MITA_GID="$MIERU_MITA_GID" ./scripts/prepare-mieru-state.sh verify /var/lib/mieru-manager
```

Check stable `/run/mita/mita.sock` ownership/mode, pinned executable digest/version, writable config, and manager `TMPDIR`. Never delete journal/key; unknown or unauthenticated state must fail closed.

## No QR for an existing Mieru user

This is expected after the one-time reveal closes: only `hashedPassword` remains. Use **New link + QR** to rotate; the old client configuration becomes invalid. List APIs intentionally exclude URL, QR, and password.

## Mieru mobile view widens the page

Deploy the revision with the responsive Mieru dialog and confirm deployed `style.css`/`app.js` match source. From `320–900 px`, `document.documentElement.scrollWidth - innerWidth` must be `0`; long revision, URL, command, and QR must remain inside the card/dialog.

## Mieru works but traffic is unavailable

This is intentional. The adapter does not parse a human table or copy GPL gRPC stubs; there is no safe typed per-user metrics boundary. Quota is a rolling approximate session-admission check, not a hard cap.

## Nginx reload fails

- never reload before `nginx -t` succeeds;
- inspect duplicate/ambiguous `$ssl_preread_server_name` maps;
- inspect symlink/content drift in owned files;
- restore the exact installer backup generation when applicable;
- never replace an existing map with a documentation example;
- rerun every SNI probe after rollback.

## Compose reports orphans

The active `COMPOSE_FILE` is probably incomplete. Do not confirm removal. Restore the persisted full overlay set and rerun `docker compose config --services` and `ps`. Project name remains `mtproxy`.

## Permission denied after restore

Do not recursively `chown` unknown state. Compare documented numeric identities and exact modes. Use read-only Mieru state/token verifiers; restore the Naive manager/Caddy/accounting identity split. Repair only after collision preflight.

## Fleet node remains unenrolled

UI node creation is only registry state. Enrollment requires local key/CSR, offline CA signing, central certificate binding, node certificate installation, successful mTLS authorization, and a completed inventory command/result. For a bound but disconnected node, inspect URI SAN, serial/fingerprint binding, validity, trust chain, hostname verification, clocks, and central URL.

## Installer command ended with SSH exit 255

Transport exit does not prove failure or rollback. Inspect durable `/var/lib/proxy-control/runtime.json`, phase/status, owned files, services, Nginx configuration, and protocol probe on the target host. Never rerun install blindly over an active generation.

## When to roll back

Rollback when a new generation fails configuration validation, health plus protocol acceptance, accounting continuity, or adjacent SNI regression. Restore a complete generation through [BACKUP_RESTORE.en.md](BACKUP_RESTORE.en.md), not one config or database file.
