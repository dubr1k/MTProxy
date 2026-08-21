# Security policy

## Private reporting

Do not publish exploitable details, credentials, proxy links, QR codes, private keys, certificates, node identities, or production configuration in an issue. Use GitHub's private vulnerability reporting if enabled; otherwise contact the maintainer through the security contact on the [repository profile](https://github.com/dubr1k). Include a minimal sanitized reproducer, affected revision and impact.

## Trust boundaries

- **Public listeners:** host Nginx remains the owner of shared TCP/443. Proxy runtimes bind only documented loopback/dedicated ports. Validate `nginx -t` and every adjacent SNI route.
- **Panel/RBAC:** expose the loopback panel only through an operator-controlled HTTPS boundary. Argon2id passwords, opaque sessions, CSRF, trusted hosts, roles and secret-free audit constrain the UI; do not treat them as a substitute for host access control.
- **Telemt:** configuration and quota state are persistent in the credential-bearing `telemt-config` named volume. Its bearer-authenticated API is reachable only on the private Compose network and is used by the panel; it is not disabled and must never be host-published.
- **Naive/Caddy:** the token-authenticated manager Unix socket is the mutation boundary. Caddy completion logs can contain usernames and traffic metadata; protect log rotations and SQLite/WAL state. Counters exclude TLS/IP and unfinished tunnels.
- **Mieru/mita:** the separately supplied GPL runtime is gated by exact executable digest/version and local UDS permissions. The manager is not a sandbox. Preserve state, authenticated journal and key as one generation; unknown state fails closed. Metrics remain degraded rather than guessed.
- **Fleet:** nodes connect outbound over mTLS. Central derives identity from certificate URI SAN plus database binding. Typed allowlists, expected revisions, durable journals and idempotency prevent arbitrary command, URL, SSH or Docker authority. Protect offline CA keys and node keys; application revocation is not OCSP/CRL.
- **Host mutation:** installer operations are owned, journaled, validated and reversible. Foreign drift, ambiguous Nginx maps, occupied ports and incomplete rollback stop further mutation.

## Secrets and state

Protect `secrets/`, complete access URLs, TLS/PKI keys, API/manager tokens, panel and accounting databases, `telemt-config`, Mieru journal keys, fleet outboxes and ownership manifests. Use mode-restricted storage and encrypted/access-controlled backups. Back up SQLite with WAL/SHM safely and restore manager state as complete generations. Never put these values in Git, CI output, screenshots or public logs.

## Dependency and runtime updates

Treat image digest, Caddy module/build, Telemt and mita changes as security changes. Verify provenance, upstream licenses, checksums already documented by the project, configuration render, least-privilege identity, negative authorization tests, rollback and real protocol behavior. A healthy container alone is insufficient.

## Supported status

The repository test/Compose/image gates are maintained, and Telemt, NaiveProxy and Mieru have passed live operator-controlled protocol probes. Ubuntu 24.04 QEMU full lifecycle and production fleet enrollment remain pending; see [VALIDATION.md](docs/VALIDATION.md). Supported deployments use the Compose/Telemt path through `install.sh` or `proxyctl`; the former host/systemd MTProxy installer has been removed.
