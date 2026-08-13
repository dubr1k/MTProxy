# Automated VPS installation

The installer deploys this topology:

```text
Internet :443
  → host Nginx stream / ssl_preread
  → your dedicated SNI hostname
  → 127.0.0.1:8445
  → Dockerized Telemt

Telemt cover fallback
  → Caddy on the internal Docker network only
  → external document root at /var/www/YOUR_DOMAIN
```

Nginx remains the sole owner of public TCP/443. Other HTTPS, Xray/REALITY, and raw TCP services can continue sharing that port through distinct SNI routes.

## Supported systems

- Ubuntu 22.04/24.04;
- Debian 12/13;
- root access;
- a direct A record pointing to the VPS;
- Cloudflare must be DNS-only unless a compatible L4/Spectrum product is intentionally used.

## Modes

### `fresh`

Use on a clean VPS with no listener on TCP/443. The installer creates an extensible Nginx stream router:

```bash
sudo ./install.sh \
  --mode fresh \
  --domain proxy.example.com \
  --email admin@example.com \
  --users phone,laptop,reserve
```

Additional SNI services can later be added to `/etc/nginx/mtproxy-stream/routes.conf`. The default route is deliberately closed; point it at your own HTTPS/Xray backend when required.

### `coexist`

Use when Nginx already owns `:443` through a stream map. Pass the **specific file** containing that map:

```bash
sudo ./install.sh \
  --mode coexist \
  --domain proxy.example.com \
  --email admin@example.com \
  --users phone,laptop,reserve \
  --route-file /etc/nginx/stream-conf.d/sni-map.conf
```

The installer:

- does not replace the existing map;
- refuses hostname collisions;
- inserts one marked entry before `default`;
- creates a sibling backup;
- applies the change only after `nginx -t`;
- removes its own route if a later installation step fails.

For unusually complex Nginx layouts, add the route manually and use `scripts/mtproxy-deploy render` to generate the Docker deployment only.

## Additional options

```text
--backend-port 18445     use another loopback Telemt port
--cover-file ./site.html private HTML input, never committed to Git
--project-dir /opt/name  deployment directory
--skip-dns-check         stage before DNS cutover
--manage-firewall        explicitly add allow 80/443 to active UFW
```

Secrets are generated locally in `PROJECT_DIR/secrets/users.conf` with mode `0600`. Re-running the installer preserves secrets for unchanged user names. The firewall is unchanged by default; `--manage-firewall` adds only missing UFW rules and journals ownership for precise removal.

## What the installer does

1. Installs missing dependencies without replacing an existing custom Nginx installation.
2. Validates DNS, ports, and Docker Compose v2.
3. Renders a parameterized deployment under `/opt/mtproxy-shared443`.
4. Copies a private cover file to `/var/www/DOMAIN`, or creates a neutral minimal page.
5. Issues a Let's Encrypt certificate via HTTP-01 webroot.
6. Starts digest-pinned Telemt and internal Caddy containers.
7. Waits for both health checks before changing public SNI routing.
8. Checks Compose, listener state, Nginx, public HTTPS, and critical recent log errors.

A green healthcheck does not prove end-to-end MTProto. Validate every secret with a real `req_pq_multi → resPQ` handshake or a real client from the target network.

## Client links

The installer never prints secret-bearing links. Generate them locally:

```bash
sudo python3 /opt/mtproxy-shared443/docker/links.py \
  --server proxy.example.com \
  --port 443 \
  --domain proxy.example.com \
  --secrets /opt/mtproxy-shared443/secrets/users.conf
```

Redirect output only to a mode-`0600` file (`umask 077`).

## Uninstall

```bash
sudo ./uninstall.sh --yes
```

By default this removes the containers, its own SNI entry, HTTP ACME vhost, and deployment directory. Unrelated Nginx routes, Docker containers, the certificate, and cover document root remain untouched.

Optional destructive cleanup:

```bash
sudo ./uninstall.sh --yes --purge-certificate --purge-cover
```

Removal is driven by the mode-`0600` `state.json` plus an ownership marker. Nginx changes are backed up, applied, validated, and reloaded before containers are stopped. Failures restore the exact previous configuration. The renewal hook and only installer-created UFW rules are removed from recorded state.

## Sandbox tests

```bash
python3 -m unittest -v tests/test_deploy.py
bash -n install.sh uninstall.sh scripts/check-deployment.sh
```

Tests execute real rendering and Nginx-map edits inside a temporary filesystem, covering idempotency, collision refusal, and precise rollback.
