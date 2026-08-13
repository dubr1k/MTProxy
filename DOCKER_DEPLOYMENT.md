# Docker deployment behind an existing Nginx SNI router

This fork adds a pinned, reproducible Docker deployment for hosts where public TCP/443 is already owned by Nginx `stream` and shared with Xray/3x-ui.

## Topology

```text
Internet :443
  -> host Nginx stream (SNI `tga.unicorndubr1k.org`)
  -> 127.0.0.1:8445
  -> mtproxy container :443

Unknown/probe TLS connection
  -> MTProxy fake-TLS fallback to `tga.unicorndubr1k.org:443`
  -> Docker DNS alias `mask`
  -> local Caddy mask sidecar serving the same cover-site files and certificate
```

The Docker-only DNS alias prevents a routing loop back through public port 443. The cover certificate and static files are mounted read-only. Caddy is used for the internal mask endpoint because its current TLS stack accepts the hybrid `X25519MLKEM768` group used by modern clients. MTProxy and its statistics endpoint bind only to host loopback.

## Secrets

Create `secrets/users.conf` with mode `0600`:

```text
alice=32_hex_characters
bob=32_hex_characters
```

Do not commit this file. One `-S` argument is generated per line.

Client links use the Fake-TLS form:

```text
tg://proxy?server=SERVER&port=443&secret=ee<secret><hex(domain)>
```

## Deployment

```bash
docker compose config
docker compose build
docker compose up -d
```

Then add the selected SNI hostname to the existing host Nginx stream map and route it to `127.0.0.1:8445`. Validate with `nginx -t` before reload.

## MEKO review

`MTPROTO_FIX_By_MEKO` was reviewed at commit `8338768aaa45c85030b9a6d891bdb81e1e2ffefd`.

Useful findings:

- use a cover endpoint compatible with current TLS ClientHello variants, especially iOS (implemented with Caddy 2.10);
- V3 distinguishes an iOS SYN fingerprint and applies a per-source SYN limit to other clients;
- the project recommends nftables for Docker deployments.

Not enabled by default here:

- host-wide nftables/iptables fingerprint rules are invasive and would apply at the public Nginx :443 boundary, affecting unrelated HTTPS and Xray traffic;
- V4/Zapret2 packet manipulation is explicitly experimental;
- the generic host sysctl tuning is broader than this five-user deployment requires.

The safe first deployment therefore keeps MEKO rules optional and evidence-driven. Add a narrowly scoped rule only if real client testing reproduces the two-minute retry failure.
