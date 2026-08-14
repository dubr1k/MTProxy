# Secure multi-node foundation

This release adds the **offline control-plane foundation**, not a remotely usable agent transport. The distinction is intentional: a bearer token over ordinary server-authenticated HTTPS is not accepted as a substitute for per-node identity.

## Shipped components

### Central registry and queue

`panel.fleet.FleetStore` uses the panel SQLite database in WAL mode and provides:

- stable, validated node IDs and secret-free inventory;
- per-node monotonically increasing command sequences;
- caller-supplied idempotency keys, unique per node;
- canonical typed envelopes at protocol version `1`;
- an allowlist of Telemt operations with operation-specific payload validation;
- mandatory `expected_telemt_revision` optimistic-concurrency preconditions;
- ordered, durable result recording;
- recursive rejection of passwords, tokens, credentials, proxy links, and secrets in inventory and results.

The allowlist deliberately excludes user creation, deletion, secret rotation, generic HTTP forwarding, arbitrary URLs, shell commands, SSH, Docker operations, and host-service control:

- `telemt.inventory.refresh`
- `telemt.user.enable`
- `telemt.user.disable`
- `telemt.user.update_limits`
- `telemt.user.reset_quota`

Panel APIs use the existing opaque sessions, CSRF protection, RBAC, body limit, audit log, and loopback-only panel deployment:

- `GET /api/fleet/nodes` — any authenticated panel role;
- `POST /api/fleet/nodes` — owner only;
- `GET /api/fleet/nodes/{node_id}/commands` — any authenticated panel role;
- `POST /api/fleet/nodes/{node_id}/commands` — owner or admin.

The Fleet UI is read-only and visibly reports that agent transport is disabled.

### Node executor

`panel.node_agent` validates a complete typed envelope before touching Telemt. Its SQLite journal uses WAL plus `synchronous=FULL`, persists command intent before side effects, and binds each sequence to both command ID and a SHA-256 digest of the canonical envelope.

Replay behavior:

1. a completed command returns the stored result without executing again;
2. a different envelope at an already-used sequence is rejected;
3. a sequence gap is rejected;
4. a concurrent duplicate is rejected without changing the in-flight record; `recover_interrupted()` must be called once under exclusive process-startup ownership to convert crash residue to `indeterminate`, which is never retried automatically;
5. transport failures with an uncertain commit outcome are durably recorded as `indeterminate`, while stored errors use fixed, secret-free codes;
6. Telemt's expected revision is sent as its documented `If-Match` header on every mutation, so stale or duplicate attempts fail closed at the local service boundary.

`LocalTelemtExecutor` accepts only an explicit `http://127.0.0.1:PORT` or `http://[::1]:PORT` endpoint without credentials, query, or path. It disables environment proxy inheritance and constructs every method, path, and body itself. It cannot forward a caller-supplied URL, HTTP method, path, header, or arbitrary JSON document. The Telemt bearer credential remains local and is never part of a fleet envelope, inventory, result, audit detail, or journal.

## Deliberately disabled boundary

There are **no `/api/agent/*` routes**, enrollment endpoint, long-poll endpoint, node credential generator, or result-upload endpoint. `auth_state=network_disabled` is set on every node. Consequently, queued commands cannot reach nodes in this release.

Before enabling networking, a later release must provide and test all of the following:

1. WebPKI TLS validation with hostname checking and no insecure override;
2. a private CA and per-node mTLS certificates with node ID binding;
3. short-lived enrollment credentials, one-time use, explicit approval, and revocation;
4. certificate rotation and expiry behavior;
5. central authorization that derives node identity from the verified client certificate, never request JSON;
6. long-poll bounds, rate limits, replay protection, response size limits, and cancellation;
7. safe result upload with sequence/digest binding;
8. end-to-end tests through a real TLS listener, including unknown CA, wrong node certificate, expired certificate, downgrade, and proxy-header spoofing failures.

Do not expose a custom bridge around these omissions. In particular, do not publish Telemt's API, add SSH execution, mount a Docker socket, accept arbitrary callback URLs, or turn the offline executor into a stdin/network daemon without an authenticated transport.

## Backup and inspection

Fleet tables live in `PANEL_DATABASE`; include the existing panel database in backups. The node journal is a separate SQLite file selected by the eventual agent service and must live on durable local storage with restrictive ownership. Inventory and results are designed to be safe to display, but the database should still be treated as administrative data.
