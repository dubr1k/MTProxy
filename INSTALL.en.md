# Automated Proxy Control installation on Ubuntu 24.04

**English** · [Русский](INSTALL.ru.md)

Root-only `install.sh` invokes transactional `scripts/proxyctl.py install`. Supported lifecycle:

```text
audit → plan → install → repair → uninstall
```

The complete installer deploys Telemt/MTProxy and the panel. NaiveProxy, Mieru, and fleet are separate integrations applied only after core acceptance.

## Requirements

- Ubuntu 24.04 with systemd;
- root/sudo;
- DNS A/AAAA for proxy and panel names points directly to the host;
- TCP/80 available for ACME HTTP-01;
- public TCP/443 owned by an existing Nginx `stream` listener;
- exactly one understandable `$ssl_preread_server_name` map in the selected route file;
- free loopback ports;
- external executable probe that validates real Fake-TLS/Obfuscated2 `req_pq_multi → resPQ`;
- host-level backup of Nginx, services, and adjacent routes.

Disable CDN/proxying for the raw MTProto hostname. Unhandled AAAA, NAT mismatch, ambiguous maps, and port collisions are hard stops.

## Build and install the external TDLib probe

From the checked-out repository, build the pinned Docker image and install the root-only hook before planning:

```bash
sudo ./probe/install.sh
```

It installs `/usr/local/libexec/mtproxy-respq-probe` with mode `0750`. The hook accepts exactly `--domain DOMAIN --secrets-file PATH`; it validates both inputs, binds the file read-only at `/run/mtproxy/users.conf`, and asks TDLib to `addProxy` then `pingProxy` once for every configured secret. The image base is pinned by digest and its Node dependencies are locked in `probe/package-lock.json`.

The installer supplies only the domain and secret-file path. Individual secrets never enter its argv, the Docker command argv, shell history, or probe output. The container has a read-only root filesystem, a dedicated tmpfs for TDLib state, dropped capabilities, and no-new-privileges. Its only success output is the verified-secret count; any failed secret makes the hook fail closed.

## 1. Read-only audit

```bash
sudo python3 scripts/proxyctl.py audit \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --json
```

Audit installs no package and mutates no file/service. Review listener ownership, DNS, Nginx topology, platform, and collisions.

## 2. Deterministic plan

```bash
sudo python3 scripts/proxyctl.py plan \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --email admin@example.com \
  --route-file /etc/nginx/stream.d/routes.conf \
  --project-dir /opt/mtproxy-shared443 \
  --users owner,phone \
  --protocol-probe /usr/local/bin/mtproxy-respq-probe \
  --json
```

Plan contains no passwords, tokens, user secrets, or access links. Verify managed paths, package ownership, certificate names, loopback ports, route change, and probe path.

## 3. Backup readiness

Before installation preserve the selected Nginx route and includes with metadata, private `nginx -T`, active listeners/units, existing Docker state, and adjacent SNI acceptance results. Installer-owned backups do not replace an independent host backup.

## 4. Install

```bash
sudo ./install.sh \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --email admin@example.com \
  --route-file /etc/nginx/stream.d/routes.conf \
  --project-dir /opt/mtproxy-shared443 \
  --users owner,phone \
  --protocol-probe /usr/local/bin/mtproxy-respq-probe
```

The installer installs only missing packages, obtains a two-name certificate, creates mode-restricted secrets, deploys Compose project `mtproxy`, bootstraps owner through stdin, applies minimal Nginx routes transactionally, waits for health, and runs the required external probe.

It never changes UFW/nftables/iptables, DNS, Xray/3x-ui, unrelated containers, or unrelated Nginx routes.

## 5. Acceptance

```bash
docker compose -f /opt/mtproxy-shared443/compose.yaml ps
curl -fsS http://127.0.0.1:8787/healthz
sudo nginx -t
ss -lntup
```

Also run external `resPQ` for each user secret, a real Telegram client test, panel HTTPS/login, adjacent SNI regression, SQLite integrity/backup checksum, and confirm Telemt API is not host-published.

## 6. Repair

```bash
sudo python3 scripts/proxyctl.py repair
```

`repair` loads `/var/lib/proxy-control/runtime.json`, completes interrupted recovery, validates owned files, and restarts the recorded runtime. It intentionally accepts no arbitrary paths.

## 7. Uninstall

```bash
sudo ./uninstall.sh
```

Uninstall durable-checkpoints phases, removes only owned routes/files/packages, and preserves credential backup, certificates, and cover roots pending ownership review. Repeated execution resumes safely. Revalidate Nginx/listeners/adjacent SNI afterward.

## Interrupted SSH

SSH exit `255` proves transport failure only. Inspect durable manifest phase/status, owned files, services, and protocol probe on the target host. Never blindly rerun installation over an active generation.

## Next integrations

- [Panel and NaiveProxy](PANEL.en.md)
- [Mieru/mita](MIERU.en.md)
- [Fleet mTLS](FLEET.en.md)

See [INSTALLER_AUDITOR.md](INSTALLER_AUDITOR.md), [operations](docs/OPERATIONS.en.md), [backup](docs/BACKUP_RESTORE.en.md), and [validation](docs/VALIDATION.md).
