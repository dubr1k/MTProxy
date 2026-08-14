# Compatibility policy

Proxy Control product naming does not rename deployed runtime contracts.

The following remain supported unchanged: `/opt/mtproxy-shared443`, `.mtproxy-owned`, marker `mtproxy-shared443`, `/etc/nginx/mtproxy-stream`, `.mtproxy-backup`, Compose project `mtproxy`, volume `mtproxy_panel-data`, `/var/lib/mtproxy-panel`, `/opt/mtproxy-panel`, `/etc/mtproxy-agent`, `/var/lib/mtproxy-agent`, unit filenames `mtproxy-agent.service` and `mtproxy-fleet-ingress.service`, fleet URI `urn:mtproxy-panel:node:`, and installed `scripts/mtproxy-deploy`.

Protocol names (`mtproxy`, `protocols.mtproxy`, `MTPROXY_*`) remain protocol-specific and are not deprecated. Historical changelog entries are not rewritten.

A future migration must provide discovery, read-only planning, backups, ownership checks, explicit cutover, rollback, and tests from an actual prior installation. Never silently move databases, volumes, certificates, units, routes, markers, or fleet identities.
