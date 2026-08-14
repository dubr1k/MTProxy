# Mieru / mita v3.35 management

Proxy Control supports exactly **mita 3.35.x** through a local, authenticated Unix-socket manager. Mita remains a separate GPLv3+ process; this adapter is MIT and contains no copied upstream source or generated stubs.

## Pinned packages

| Architecture | Debian package SHA-256 |
|---|---|
| amd64 | `cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342` |
| arm64 | `66ff435dd5bd6078944cb4eb7fc427366afaac5ab51030ff62561c645c31a9e3` |

Install the upstream package only after checking the matching digest. The v3.35.0 Debian binaries are statically linked, so the same pinned host binary can be mounted into the Debian manager container without copying GPL artifacts into the MIT image. Create non-login user and group `mieru-manager`, add that user to group `mita`, and add the panel service user to group `mieru-manager`. Install `deploy/mieru-manager.service`. Put a random 32+ byte token in `/etc/mieru-manager/token` mode 0600 and configure:

```text
MIERU_PUBLIC_HOST=mieru.example.com
MIERU_MANAGER_TOKEN_FILE=/etc/mieru-manager/token
MIERU_MANAGER_STATE=/var/lib/mieru-manager
MIERU_MITA_SHA256=cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342
```

The helper verifies the pinned SHA-256 before every invocation and accepts only mita 3.35.x at bootstrap. It invokes only fixed `/usr/bin/mita` argv commands with bounded output. Complete secret-bearing JSON is inherited through an anonymous FD and never a named tempfile, command line, log, audit, or HTTP list response. Keep `/var/run/mita/mita.sock` mode 0770; do not enable `MITA_INSECURE_UDS`.

For Compose, combine `compose.yaml` and `compose.mieru.yaml`. Set `MIERU_MITA_BIN` to the verified host binary, `MIERU_MITA_SHA256` to its package digest, and `MIERU_MITA_GID` to the numeric GID that can connect to `/var/run/mita/mita.sock`. The binary and mita runtime directory are mounted read-only; only manager state and its API runtime directory are writable. The manager health check uses the authenticated Unix API, and the panel waits for it to become healthy.

## Listener coexistence

Declare every TCP/UDP Mieru port or range explicitly. **No installer or manager silently takes port 443.** When nginx/MTProxy/NaiveProxy already owns shared 443, choose dedicated Mieru ports (for example 8443 TCP and 8443 UDP), publish them in host/cloud firewalls, and verify both protocols. Loopback management sockets are unrelated to public listeners.

Config updates are full-snapshot CAS transactions with durable backup/journal recovery. Ports, MTU, DNS, egress, traffic patterns and SSRF flags use stop/start. Credential rotation, disable, and delete force restart for revocation; quota-only changes may reload. Unknown observed fields fail closed.

Traffic labels are **application bytes**. Quotas are rolling, approximate session-admission checks—not hard caps or billing counters. “Reset” creates a panel baseline and never deletes `/var/lib/mita/metrics.pb`.

## Fleet limitation

Fleet v1 allowlists secret-free Mieru inspect, metrics, and lifecycle operations. Remote user creation/rotation and full config apply are deliberately rejected because the durable command transport has no sealed payload layer. Do not persist decrypted credentials in fleet SQLite; add authenticated sealed payload encryption before enabling remote credential mutation.

The node agent enables these routes only when both `MIERU_MANAGER_SOCKET` and either `MIERU_MANAGER_TOKEN` or `MIERU_MANAGER_TOKEN_FILE` are configured. Mount the manager UDS read-only into the agent and use a read-only token file. Partial configuration fails closed; no remote command can choose a socket path, HTTP path, lifecycle verb, or request body.
