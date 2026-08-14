# Accounting semantics

These counters support operations and quota decisions; none is represented as billing-grade.

| Runtime | Source | Persistence and timing | Limitation |
|---|---|---|---|
| Telemt | `total_octets` plus resettable quota usage | Runtime generations may reset diagnostics; quota state persists on explicit reset and graceful stop | Abrupt termination can lose recent usage |
| Naive/Caddy | Successful completed CONNECT JSON logs, exact consumed-prefix collector, SQLite/WAL | Bytes appear only when a tunnel closes | Payload only; excludes TLS/IP and unfinished tunnels |
| Mieru/mita | Quota configuration | Rolling application-byte session-admission checks | Per-user metrics are degraded/unavailable; not a hard cap |

Back up each database together with its WAL/SHM while quiesced or by a SQLite-safe method. A reset establishes a local baseline; it does not alter raw network traffic or provide calendar-period automation.
