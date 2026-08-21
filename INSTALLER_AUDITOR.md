# Complete Proxy Control installer and auditor (`proxyctl`)

**English** · [Русский](INSTALLER_AUDITOR.ru.md)

`install.sh` is a root-only wrapper around `scripts/proxyctl.py install`. The same tool provides the five lifecycle modes: `audit`, `plan`, `install`, `repair`, and `uninstall`. In this stage the complete installer deploys the Telemt/MTProto data plane and panel; NaiveProxy, Mieru, and fleet remain separately configured integrations. It is intended for Ubuntu 24.04 hosts where Nginx already owns public TCP/443 through one unambiguous `ssl_preread` map (including hosts that also run Xray/3x-ui).

## Production command

Both DNS records must already point directly to the host (Cloudflare DNS-only), port 80 must reach Nginx for HTTP-01, and the selected protocol hook must implement a real Fake-TLS/Obfuscated2 `req_pq_multi -> resPQ` check for every secret in the supplied file.

```bash
sudo ./install.sh \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --email ops@example.com \
  --route-file /etc/nginx/stream.d/routes.conf \
  --users owner,phone \
  --protocol-probe /usr/local/bin/mtproxy-respq-probe
```

Use the same arguments with `python3 scripts/proxyctl.py plan ...` for a read-only deterministic plan. Audit is independently read-only:

```bash
sudo python3 scripts/proxyctl.py audit \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com --json
```

After installation:

```bash
sudo python3 scripts/proxyctl.py repair
sudo ./uninstall.sh
```

`repair` and `uninstall` load the exact plan from the private ownership manifest; they take no hostname or path arguments.

## What install owns

1. Installs only missing Ubuntu packages: CA certificates, OpenSSL, curl, Python, Certbot, Docker Engine, Compose v2, and Nginx full/stream support. The manifest records the missing package set so uninstall never purges a pre-existing package.
2. Creates dedicated port-80 webroot vhosts for **both** domains and requests one certificate covering both names.
3. Renders the digest-pinned Telemt, internal Caddy cover, and FastAPI panel Compose project under `/opt/mtproxy-shared443`.
4. Creates mode-`0600` per-user secrets, Telemt API token, and panel bootstrap password. Existing valid credentials are preserved on rerender.
5. Bootstraps the panel owner by passing the password file to container stdin. Command output is suppressed and neither the password, token, user secrets, nor proxy links enter the plan/manifest/stdout.
6. Publishes Telemt at `127.0.0.1:8445` and the panel application at `127.0.0.1:8787`.
7. Creates a host Nginx TLS vhost at existing HTTP fallback listener `127.0.0.1:8443` for the panel, then routes the panel SNI to `127.0.0.1:8443` and proxy SNI to `127.0.0.1:8445`.
8. Pulls and starts Compose with `--wait`, validates running services and panel health, and runs the mandatory protocol hook.

The installer never changes UFW, nftables, iptables, DNS, Xray, 3x-ui, unrelated Nginx routes, or unrelated containers.

## Transactions, repair, and removal

The mode-`0600` runtime manifest is `/var/lib/proxy-control/runtime.json`; it is a strict, phase-specific write-ahead journal for install, rollback, and uninstall. Route generation and its exact private backup are journaled in `/var/lib/proxy-control/ownership.json` and `/var/lib/proxy-control/backups/`. Managed Nginx files are hashed before they are created. All Nginx mutations require `nginx -t` before reload. Route writes preserve canonical mode/UID/GID and refuse symlink or content drift.

If install fails or the process is interrupted, the next matching `install` rolls the journaled generation back and retries, preserving the exact generated credentials and package-ownership set. `repair` also completes an interrupted rollback. If rollback cannot complete, the manifest remains `rollback_failed`; subsequent operations retry it and fail closed on foreign drift rather than claiming success.

Uninstall records `uninstalling` before its first mutation and checkpoints each phase. It stops Compose before removing public routes and vhosts, cleans owned project files, and finally purges only installer-owned packages. A later failure therefore never leaves an `active` manifest pointing at already-deleted runtime files, and Nginx remains available for route validation until routing cleanup is complete. Repeated `uninstall` resumes from the durable phase and tolerates only the exact expected already-removed artifacts. It intentionally leaves `/opt/mtproxy-shared443/secrets/` in place as a private credential backup. Certificates and cover roots are also retained because Certbot or another vhost may use them. Delete these explicitly only after independent ownership review.

## Gates

Repository CI/local verification:

```bash
python3 -m pytest -q panel/tests tests/test_naive_manager.py \
  tests/test_proxyctl.py tests/test_proxyctl_transactions.py \
  tests/test_proxyctl_runtime.py
python3 -m unittest -v tests/test_deploy.py
ruff check .
bash -n install.sh uninstall.sh \
  scripts/check-deployment.sh scripts/prepare-mieru-state.sh scripts/prepare-mieru-token.sh \
  docker/telemt-entrypoint.sh panel/entrypoint.sh
shellcheck install.sh uninstall.sh \
  scripts/check-deployment.sh scripts/prepare-mieru-state.sh scripts/prepare-mieru-token.sh \
  docker/telemt-entrypoint.sh panel/entrypoint.sh
docker compose config -q
git diff --check
```

Runtime tests use a temporary fake root plus an injected command runner. They exercise actual file rendering, secret preservation, manifests, Nginx route transactions, full rollback, package ownership, idempotent uninstall, protocol-hook invocation, and drift refusal without touching the real host.

## Limitations / hard stops

- Ubuntu package names and systemd are assumed for complete install. Other distributions may use `audit`, but complete install is unsupported.
- Existing Nginx is adopted only when exactly one inline `$ssl_preread_server_name` map is discoverable in the selected file. Included/generated maps, multiple maps, and direct non-Nginx TCP/443 owners fail closed.
- The panel TLS listener assumes the existing Nginx HTTP fallback is `127.0.0.1:8443`; the panel app remains on `127.0.0.1:8787`.
- DNS behind NAT, unhandled AAAA, occupied loopback ports, hostname collisions, and foreign managed-file drift are hard stops.
- The protocol hook is mandatory and external because the repository does not bundle a vetted `resPQ` probe. Its exit status is authoritative; its output is suppressed. A successful synthetic probe still does not prove every mobile ISP/client path, so perform real Telegram client tests after install.
- ACME certificates, webroots, and preserved credentials are not automatically destroyed on uninstall.
