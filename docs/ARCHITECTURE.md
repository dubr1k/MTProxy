# Architecture

Proxy Control separates public data planes from local management and fleet transport.

## Components

1. Host Nginx owns shared TCP/443, inspects SNI, and forwards selected names to loopback listeners.
2. Telemt serves MTProto and uses a persistent `telemt-config` named volume. Its authenticated API is private to Compose and consumed by the panel.
3. Caddy/NaiveProxy and mita remain protocol runtimes. Their managers expose bounded, token-authenticated Unix APIs and transactional state changes.
4. The FastAPI panel binds to loopback, stores RBAC/session/audit/fleet metadata in SQLite, and never uses a Docker socket.
5. Node agents initiate mTLS connections to central ingress. Certificate identity, typed operations, durable journals, idempotency, and ordered results constrain remote authority.

## Trust boundaries

Public proxy traffic, panel HTTPS, private management APIs, secret-bearing persistent state, and fleet PKI are distinct boundaries. A healthy process is not protocol validation. Each mutation validates its target, records durable intent where applicable, applies atomically, probes the new generation, and either commits or restores the exact prior generation.

## Compatibility boundary

Branding is neutral, but migration-sensitive identifiers remain unchanged. See [COMPATIBILITY.md](COMPATIBILITY.md).
