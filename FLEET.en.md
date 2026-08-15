# Proxy Control secure outbound mTLS fleet transport (v1)

**English** · [Русский](FLEET.ru.md)

Fleet nodes make **outbound-only HTTPS connections** to a dedicated central ingress. The ingress performs TLS itself and derives node identity from the verified peer certificate; it does not trust HTTP identity headers and has no bearer-token fallback. The panel never receives SSH, a Docker socket, arbitrary commands, arbitrary URLs, or direct public Telemt access.

## Security and protocol contract

- Server identity: a normal WebPKI certificate for the exact `FLEET_CENTRAL_URL` hostname. The agent uses the operating-system trust store and hostname verification by default. `FLEET_SERVER_CA` exists only for private test PKI.
- Client identity: a private CA issues one certificate per node with the sole URI SAN `urn:mtproxy-panel:node:<node-id>`. Central authorization additionally requires an active database record matching node ID, certificate serial, SHA-256 fingerprint, and validity interval.
- TLS: direct TLS 1.2+, mandatory client certificate, no compression. Unknown client CAs fail during the handshake. A certificate for another node, an unregistered serial/fingerprint, or an application-revoked certificate gets HTTP 403.
- Bounds: 4 KiB request line, 8 KiB headers, configurable body limit capped at 64 KiB (default 16 KiB), no chunked request bodies, maximum 30-second long poll, handshake/request timeout, and per-certificate in-process request rate limit (default 120/minute).
- Commands carry protocol version, UUID, node ID, monotonic sequence, idempotency key, allowlisted operation, expected Telemt revision, actor, expiry, canonical payload SHA-256, and typed payload. Central states are `queued`, `dispatched`, `succeeded`, `failed`, or `indeterminate`. An expired command is still delivered in sequence: the agent journals it as a failed no-op and uploads that durable result before central dispatches the next sequence, so expiry can never execute a mutation or create a sequence gap.
- The agent journals receipt with SQLite WAL + `synchronous=FULL` before invoking Telemt. Completed results form a durable outbox. A lost upload acknowledgment resends the stored result; it does not repeat the Telemt mutation. Crash residue is marked `indeterminate` at exclusive startup and never re-executed.
- The only local authority is a fixed loopback Telemt URL and a node-local bearer credential. Every HTTP method/path/body is constructed from the typed allowlist and mutations include `If-Match`.

## Central deployment

Run the panel and ingress against the **same** `PANEL_DATABASE`. Back it up before first start; startup performs additive schema migration and upgrades the old command status constraint.

1. Obtain a WebPKI server certificate whose SAN matches `fleet.example.com`. Do not use the fleet client CA as the public server identity in production.
2. Initialize the offline client CA on a protected operator system (not in the panel container):

   ```sh
   python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
     fleet-ca-init --ca-dir /root/mtproxy-fleet-ca
   install -m 0644 /root/mtproxy-fleet-ca/ca.crt /etc/mtproxy-panel/fleet-client-ca.crt
   # Keep ca.key offline/root-only; the ingress needs only ca.crt.
   ```

3. Install `deploy/mtproxy-fleet-ingress.service` and `deploy/fleet-ingress.env.example`, adjusting the root-only Certbot source paths and the WebPKI hostname. The unit's root-only `ExecStartPre=+` steps copy the certificate as `0444` and private key as `0400`, owned by `panel:panel`, into its `0700` `/run/mtproxy-fleet-ingress` runtime directory; the long-running process remains `panel:panel`. Do not make the Certbot private key or its parent directories group/world-readable. Restart the unit after certificate renewal so the staged copies are refreshed (for example, from a root-owned Certbot deploy hook: `systemctl restart mtproxy-fleet-ingress.service`). Expose only the selected TCP ingress port. The listener terminates mTLS directly, so no reverse-proxy client-certificate headers are involved.
4. Start it and verify the listener and journal. For containers, `compose.fleet-central.yaml` is a hardened overlay of the same `mtproxy` stack and shares its `panel-data` volume. It must be invoked together with `compose.yaml`, never as a separate project. Bind-mounted ingress private keys must be readable only by container UID/GID 10001. (The node-agent image runs as UID 10002.)

## Enroll `example-node-02` without exporting its private key

On central, register the node:

```sh
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-register-node example-node-02 --display-name 'Example Region 2'
```

On `example-node-02`, generate the key and CSR locally:

```sh
install -d -m 0700 /etc/mtproxy-agent
openssl req -new -newkey rsa:3072 -nodes -sha256 \
  -subj '/CN=example-node-02' \
  -keyout /etc/mtproxy-agent/example-node-02.key \
  -out /etc/mtproxy-agent/example-node-02.csr
chmod 0600 /etc/mtproxy-agent/example-node-02.key
```

Move only the CSR to the protected CA system using the operator's approved file-transfer channel. Sign it there (the signer ignores requested identity extensions and writes the canonical node URI SAN):

```sh
python -m panel.cli fleet-sign-csr example-node-02 --ca-dir /root/mtproxy-fleet-ca \
  --csr /secure-inbox/example-node-02.csr --out /secure-outbox/example-node-02.crt --days 90
```

Transfer the issued public certificate to central and bind its exact serial/fingerprint/validity record:

```sh
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-bind-cert example-node-02 --cert /secure-inbox/example-node-02.crt
```

Return only `example-node-02.crt` and `ca.crt` as needed; never move `example-node-02.key` or `ca.key`. On the node, install the Python package/venv, `deploy/mtproxy-agent.service`, and `deploy/agent.env.example`; store the local Telemt bearer as `/etc/mtproxy-agent/telemt-api-token`, owner/group restricted to the service. The service requires the certificate key to have no group/world mode bits and writes only `/var/lib/mtproxy-agent`.

```sh
systemctl daemon-reload
systemctl enable --now mtproxy-agent
journalctl -u mtproxy-agent --since -5m
```

The panel node `auth_state` changes `unenrolled` → `enrolled` after certificate binding → `connected` after successful mTLS authorization. Queue a short-lived inventory command first, then inspect command status before mutations.

The optional `compose.agent.yaml` joins the same private Compose network and reaches Telemt only as `http://mtproxy:9091`; it is therefore valid only as an overlay of `compose.yaml`. It mounts no Docker socket and publishes no port. Its key bind must be mode 0400/0600 and owned by UID 10002.

## Rotation and revocation

Rotation is overlap-first:

1. Generate a new key and CSR on the node.
2. Sign with `fleet-sign-csr`, then authorize it centrally with `fleet-bind-cert`; both serials are temporarily accepted.
3. Atomically replace the node certificate/key, restart the agent, and verify `auth_state=connected` plus a completed inventory command.
4. Revoke the old serial:

   ```sh
   python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
     fleet-revoke-cert example-node-02 --serial OLD_HEX_SERIAL
   ```

Application revocation is immediate for new HTTP requests even though the TLS chain remains valid. For compromise, revoke first, stop the agent, then issue a fresh key/certificate. The v1 CA tooling does not publish OCSP or a CRL; do not rely on TLS handshake revocation alone.

## Operational checks

- `openssl s_client` without a client certificate must fail the TLS handshake.
- A certificate from another CA must fail the handshake.
- A valid certificate routed to another node path must return 403.
- A revoked serial must return 403.
- Confirm `auth_state`, `last_seen_at`, `dispatched_at`, completion status, and that no completed journal row remains unuploaded.
- Confirm Telemt still listens only on loopback and neither compose file mounts `/var/run/docker.sock`.

## v1 limitations

- Enrollment approval and CSR transfer are manual; there is deliberately no bearer enrollment endpoint.
- Revocation is enforced by the central database after successful TLS, not OCSP/CRL at handshake time.
- The rate limiter is per ingress process and resets on restart; deploy one ingress process for v1 or place a connection limiter in front without terminating/replacing mTLS identity.
- Only inventory, enable, disable, limit updates, and quota reset are allowlisted. Create/delete/rotate/reveal remain excluded because their secret-bearing/reconciliation contracts require a separate design.
- No production host was changed and `example-node-02` was not actually enrolled by this repository change; the artifacts and exact workflow are ready, but deployment still requires its DNS/WebPKI certificate, approved port, CSR transfer, and node-local Telemt API compatibility.
