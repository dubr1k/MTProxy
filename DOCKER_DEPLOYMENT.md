# MTProto Docker deployment behind an existing Nginx SNI router

This guide is specifically for the Telemt/MTProto data plane. NaiveProxy, Mieru, panel and fleet details live in their dedicated guides.

```text
Internet TCP/443 → host Nginx stream/SNI → 127.0.0.1:8445 → Telemt
Unauthenticated/probe TLS → Telemt fallback → private-network Caddy mask
Panel → authenticated Telemt API on the private Compose network
```

Telemt is digest-pinned, does not own public `0.0.0.0:443`, and has a read-only root filesystem with capabilities dropped. Caddy's certificate and operator-provisioned cover root are mounted read-only. Use RFC example hostnames in templates and provision production content outside Git.

Create mode-`0600` `secrets/users.conf` and `secrets/telemt-api-token`. On first startup the entrypoint renders configuration into the persistent, credential-bearing `telemt-config` named volume. Existing configuration and API mutations survive container recreation; deleting that volume reimports `users.conf`. The authenticated API is private to Compose and consumed by the panel—do not publish it on the host.

```sh
docker compose config
docker compose up -d
sudo nginx -t
```

Add only the selected SNI entry to the established host map and route it to `127.0.0.1:8445`. Never replace an existing map from an example. Validate before reload and regression-test every adjacent route.

An open port, HTTPS response or healthy container does not prove MTProto. For each user, perform Fake-TLS → Obfuscated2 → `req_pq_multi` → validated Telegram `resPQ`, then test a real client from the target network. See [INSTALLER_AUDITOR.md](INSTALLER_AUDITOR.md), [SECURITY.md](SECURITY.md), and [VALIDATION.md](docs/VALIDATION.md).
