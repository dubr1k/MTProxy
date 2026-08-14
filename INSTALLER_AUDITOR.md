# Fail-closed installer/auditor (`proxyctl`)

`scripts/proxyctl.py` is the GitHub-ready, non-interactive slice for integrating the proxy and panel hostnames into an **existing Nginx `stream` SNI router**. It is intentionally narrower than `install.sh`: it audits and transactionally owns two exact SNI map entries, but does not install packages, issue certificates, mutate a firewall, create containers, or edit unrelated HTTP configuration.

## Safety model

- `audit` is read-only. It reads Nginx/3x-ui state, `ss`, local addresses, DNS, and existing Let's Encrypt certificates. It never reloads a service.
- `plan` emits stable, sorted JSON and makes no changes.
- `apply` accepts only one unambiguous `$ssl_preread_server_name` map, an existing route file, two distinct FQDNs, free loopback backend ports, DNS that resolves to this host, no unhandled AAAA, matching existing certificates, Docker availability, and an Nginx-owned public listener when listener ownership is observable.
- Any direct/ambiguous TCP/443 topology, duplicate SNI route, domain collision, route drift, malformed ownership state, missing backup, or failed validation blocks the operation.
- Route writes preserve the canonical target's mode, UID, and GID. Symlinks are resolved and preserved.
- Before a live write, a private backup and mode-`0600` state journal are durably written under `/var/lib/proxy-control`. Atomic replacements are followed by directory `fsync`.
- `nginx -t` runs before reload. Validation/reload failure restores the exact prior generation. If rollback validation/reload also fails, the journal and backup remain for `repair`; the tool does not claim success.
- `uninstall` restores only the exact pre-install route generation. It refuses foreign drift rather than deleting text it no longer owns.
- No generated secret, proxy link, Xray private key, or certificate private key is read or printed.

## Commands

Use explicit, separate proxy and panel domains:

```bash
sudo python3 scripts/proxyctl.py audit \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --json

sudo python3 scripts/proxyctl.py plan \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --route-file /etc/nginx/stream.d/routes.conf \
  --json > plan.json

sudo python3 scripts/proxyctl.py apply \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --route-file /etc/nginx/stream.d/routes.conf \
  --json

sudo python3 scripts/proxyctl.py repair
sudo python3 scripts/proxyctl.py uninstall
```

Exit code `0` means the requested command completed. Exit code `2` and a single `BLOCKED:` message means a precondition or safety gate failed. JSON output contains hostnames, addresses, process names, ports, and routes only; treat even this inventory as operationally sensitive.

`apply` is idempotent for the exact active plan. `repair` is idempotent when no manifest exists and validates an active owned generation. For an interrupted apply it restores the backup; for an interrupted uninstall it either completes removal from the exact original generation or returns the exact owned generation to active state.

## Ownership manifest

The exact-schema manifest records:

- a random installation ID used in both Nginx markers;
- canonical route and private backup paths;
- original and owned SHA-256 hashes;
- original mode/UID/GID;
- deterministic plan; and
- transaction phase (`applying`, `active`, or `uninstalling`).

Unknown keys, unsafe paths, unknown phases, invalid hashes, or route/backup mismatches fail closed. Do not edit the manifest manually. Preserve `/var/lib/proxy-control` in host backups while the route is installed.

## Verification

Repository CI executes:

```bash
python -m pytest -q panel/tests tests/test_naive_manager.py tests/test_proxyctl.py tests/test_proxyctl_transactions.py
python -m unittest -v tests/test_deploy.py
ruff check .
bash -n install.sh uninstall.sh install_mtproxy.sh uninstall_mtproxy.sh scripts/check-deployment.sh docker/telemt-entrypoint.sh panel/entrypoint.sh
shellcheck install.sh uninstall.sh install_mtproxy.sh uninstall_mtproxy.sh scripts/check-deployment.sh docker/telemt-entrypoint.sh panel/entrypoint.sh
git diff --check
```

Tests cover deterministic planning, secret-safe audit output, DNS/AAAA/TLS checks, domain/port/process collisions, ambiguous maps, symlink canonicalization, metadata preservation, exact backup, apply/reload rollback, interrupted transaction recovery, drift refusal, idempotent repair, and idempotent uninstall.

## Explicit limitations

- This slice manages only two entries in one existing inline Nginx SNI map. Included maps, named upstream indirection, multiple maps, and dynamically generated Nginx syntax are rejected or require manual integration.
- It verifies certificates already on disk under `/etc/letsencrypt/live/<domain>/fullchain.pem`; it does not perform ACME issuance or a public TLS handshake.
- DNS matching uses host interface addresses. Hosts whose public address is only visible through NAT need a separately reviewed preflight workflow; this tool deliberately does not query a third-party “what is my IP” service.
- Listener ownership depends on process information exposed by `ss -lntp`. If ownership is unavailable, the map/topology checks remain active, but an operator must independently confirm Nginx is the sole public TCP/443 owner before apply.
- The configured backends (`127.0.0.1:8445` and `127.0.0.1:8787`) must already speak the protocol expected by the SNI router. This slice does not provision the panel TLS terminator or Compose stack.
- Nginx's complete grammar is not reimplemented. `nginx -t` is authoritative at apply time, and conservative parser ambiguity is a hard stop.
- A successful route transaction does not prove MTProto relay. Run the repository deployment checks and a real `resPQ` protocol probe for every user, then test a real Telegram client on each relevant network.
