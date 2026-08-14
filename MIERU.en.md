# Mieru / mita v3.35 management

Proxy Control supports exactly **mita 3.35.x** through a local, authenticated Unix-socket manager. Mita remains a separate GPLv3+ process; this adapter is MIT and contains no copied upstream source or generated stubs.

## Pinned upstream artifacts

Only download the v3.35.0 Debian packages from the exact upstream release URLs below. Verify the **package** digest before extraction; do not install the package merely to obtain the binary. Then extract with `dpkg-deb -x` and verify the separate **`/usr/bin/mita` executable** digest. The manager's `MIERU_MITA_SHA256` runtime gate always uses the executable digest, never the package digest.

| Architecture | Pinned upstream `.deb` URL | Debian package SHA-256 | Extracted `usr/bin/mita` SHA-256 |
|---|---|---|---|
| amd64 | `https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_amd64.deb` | `cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342` | `4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31` |
| arm64 | `https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_arm64.deb` | `66ff435dd5bd6078944cb4eb7fc427366afaac5ab51030ff62561c645c31a9e3` | `a4e486c1531b7bebec02eca2b60dcba2a4971b2cd479c590d8405aab59fe6a23` |

Example for amd64 (substitute the arm64 URL and both arm64 digests when applicable):

```sh
curl -fL --proto '=https' --tlsv1.2 \
  https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_amd64.deb \
  -o mita_3.35.0_amd64.deb
printf '%s  %s\n' cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342 mita_3.35.0_amd64.deb | sha256sum -c -
dpkg-deb -x mita_3.35.0_amd64.deb mita-root
printf '%s  %s\n' 4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 mita-root/usr/bin/mita | sha256sum -c -
```

The v3.35.0 Debian executables are statically linked. Create non-login user and group `mieru-manager`, add that user to group `mita`, and add the panel service user to group `mieru-manager`. Install `deploy/mieru-manager.service`. Put a random 32+ byte token in `/etc/mieru-manager/token` mode 0600 and configure:

```text
MIERU_PUBLIC_HOST=mieru.example.com
MIERU_MANAGER_TOKEN_FILE=/etc/mieru-manager/token
MIERU_MANAGER_STATE=/var/lib/mieru-manager
MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31
```

The helper verifies the pinned executable SHA-256 before every invocation and accepts only mita 3.35.x at bootstrap. It invokes only fixed `/usr/bin/mita` argv commands with in-memory bounded stdout/stderr. Complete secret-bearing JSON is inherited through an anonymous FD and never a named tempfile, command line, log, audit, or HTTP list response. Keep `/var/run/mita/mita.sock` mode 0770; do not enable `MITA_INSECURE_UDS`.

For Compose, combine `compose.yaml` and `compose.mieru.yaml`. Set `MIERU_MITA_BIN` to the extracted, executable-digest-verified host binary, `MIERU_MITA_SHA256` to that executable digest, and `MIERU_MITA_GID` to the numeric GID that can connect to `/var/run/mita/mita.sock`. The binary and mita runtime directory are mounted read-only; only manager state and its API runtime directory are writable. The manager health check uses the authenticated Unix API, and the panel waits for it to become healthy.

## Listener coexistence

Declare every TCP/UDP Mieru port or range explicitly. **No installer or manager silently takes port 443.** When nginx/MTProxy/NaiveProxy already owns shared 443, choose dedicated Mieru ports (for example 8443 TCP and 8443 UDP), publish them in host/cloud firewalls, and verify both protocols. Loopback management sockets are unrelated to public listeners.

Config updates are full-snapshot CAS transactions with durable backup/journal recovery. Ports, MTU, DNS, egress, traffic patterns and SSRF flags use stop/start. Credential rotation, disable, and delete force restart for revocation; quota-only changes may reload. Unknown observed fields fail closed.

Per-user Mieru traffic metrics are deliberately reported as degraded/unavailable in this MIT adapter. In v3.35, `mita get metrics` is opaque grouped diagnostics and `mita get users` renders a human table; only the GPL gRPC `GetUsers` boundary exposes typed histories. The adapter does not invent a JSON shape, parse rounded table values, copy GPL-generated stubs, or claim baseline reset support. Traffic and quota semantics in mita itself remain **application bytes** and rolling approximate session-admission checks—not hard caps or billing counters.

## Fleet limitation

Fleet v1 allowlists secret-free Mieru inspect, metrics, and lifecycle operations. Remote user creation/rotation and full config apply are deliberately rejected because the durable command transport has no sealed payload layer. Do not persist decrypted credentials in fleet SQLite; add authenticated sealed payload encryption before enabling remote credential mutation.

The node agent enables these routes only when both `MIERU_MANAGER_SOCKET` and either `MIERU_MANAGER_TOKEN` or `MIERU_MANAGER_TOKEN_FILE` are configured. Mount the manager UDS read-only into the agent and use a read-only token file. Partial configuration fails closed; no remote command can choose a socket path, HTTP path, lifecycle verb, or request body.
