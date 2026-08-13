# Security Policy

## Reporting vulnerabilities

Please do not publish exploitable security issues, secrets, proxy links, private keys, or full production configurations in a public issue. Contact the fork owner through the security contact available on the [repository profile](https://github.com/dubr1k).

## Supported deployment paths

This fork contains two distinct implementations:

1. **Recommended Docker deployment** — digest-pinned Telemt runtime behind Nginx `stream`, with a separate Caddy cover backend.
2. **Legacy systemd installer** — retained from upstream and based on the official `TelegramMessenger/MTProxy` engine.

Security and runtime statements in the current README refer to the Docker path unless explicitly labeled as legacy.

## Docker security architecture

### Public-port isolation

The proxy container does not bind public `0.0.0.0:443`. Docker publishes it only at `127.0.0.1:8445`; the existing host Nginx stream router forwards the dedicated SNI hostname to that listener. This limits accidental conflicts with HTTPS and Xray/REALITY services sharing port 443.

### Digest-pinned runtime

The Telemt image is referenced by an immutable OCI digest in `compose.yaml`. Updates must be explicit and followed by a full MTProto protocol probe. A successful pull or healthy container alone is not an acceptance test.

### Least privilege

The Telemt container uses:

- a read-only root filesystem;
- `cap_drop: ALL`;
- `no-new-privileges:true`;
- a private runtime `tmpfs`;
- no published management or metrics API.

The Caddy cover container also uses a read-only root filesystem. Certificate and static-site mounts are read-only.

### Secret isolation

Per-user 16-byte hexadecimal secrets are stored in `secrets/users.conf`, which must have mode `0600`. The path is excluded from both Git and the Docker build context.

At startup, `docker/telemt-entrypoint.sh` validates names and secret lengths, then renders Telemt configuration into `/run/telemt`, a private tmpfs. Production link output is disabled to prevent credentials from appearing in container logs.

Treat the following as credentials:

- `secrets/users.conf`;
- complete `tg://proxy` and `https://t.me/proxy` links;
- complete `ee...` Fake-TLS secrets;
- TLS private keys;
- Telegram proxy registration/ad tags, if configured later.

Never paste these values into public issues, commits, CI output, screenshots, or shared logs.

### Fake-TLS and masking

Telemt accepts the configured Fake-TLS hostname and forwards unauthenticated/probe traffic to the internal Caddy HTTPS backend. Caddy serves a real certificate and a standalone cover site.

Masking improves resistance to casual probes, but it is not a cryptographic guarantee of DPI indistinguishability. Domain ownership, DNS mode, routing, TLS fingerprints, and client behavior all remain observable factors.

### API exposure

The Telemt API is explicitly disabled in the generated production configuration. Do not enable it on `0.0.0.0` or publish it through Docker without authentication, a narrowly scoped firewall, and a separate security review.

### Verification boundary

The container healthcheck confirms that the Telemt TCP listener is ready. It does not prove Telegram upstream operation. Production verification must perform:

```text
Fake-TLS → Obfuscated2 → req_pq_multi → validated Telegram resPQ
```

Run this test for every user secret after runtime, network, SNI, domain, or secret changes.

## Operational recommendations

1. Keep SSH key-only and restrict administrative access.
2. Keep the host OS, Docker, Nginx, Caddy image, and Telemt runtime patched through controlled updates.
3. Validate `nginx -t` before every stream reload and keep timestamped rollback copies.
4. Regression-test all other SNI routes sharing public TCP/443.
5. Use Cloudflare **DNS-only** unless an explicit compatible L4 product is configured.
6. Back up `secrets/users.conf` only to encrypted or access-controlled storage.
7. Rotate only the affected user's secret when access must be revoked.
8. Inspect logs for repeated handshake failures, but redact links and secrets before sharing them.
9. Do not expose the Docker socket or mount writable host directories into the proxy container.
10. Review the Telemt license and upstream changes before updating the pinned image digest.

## Legacy installer notice

The legacy installer has a different security model: systemd service, host firewall rules, updater jobs, and the old official MTProxy engine. Its configuration, watchdog, and PID namespace behavior should not be assumed to apply to the Docker deployment. Do not operate both paths on the same listener without an explicit port and firewall audit.
