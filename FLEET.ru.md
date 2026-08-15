# Безопасный fleet transport Proxy Control (mTLS v1)

[English](FLEET.en.md) · **Русский**

Fleet nodes создают только **исходящие HTTPS/mTLS подключения** к central ingress. Панель не получает SSH, Docker socket, arbitrary shell commands/URLs или public Telemt API.

> [!WARNING]
> Создание узла в web UI создаёт registry record со статусом `unenrolled`. Это не enrollment. Полный enrollment требует node-local key/CSR, offline CA signing, central binding, mTLS authorization и успешный command/result cycle.

## Security contract

- Server identity: обычный WebPKI certificate для exact hostname `FLEET_CENTRAL_URL`.
- Client identity: отдельный certificate с единственным URI SAN `urn:mtproxy-panel:node:<node-id>`.
- Central дополнительно сверяет node ID, serial, SHA-256 fingerprint и validity с active DB record.
- TLS 1.2+, mandatory client certificate, без bearer fallback и identity headers.
- Request bounds: bounded line/headers/body, без chunked bodies, timeout и per-certificate rate limit.
- Commands содержат version, UUID, node, monotonic sequence, idempotency key, typed allowlisted operation, expected revision, expiry и payload hash.
- Agent durable-journals receipt до mutation; result хранится в outbox до acknowledgment. Crash residue становится `indeterminate` и не re-execute.
- Локальная authority ограничена fixed loopback Telemt URL и allowlisted method/path/body.

## Central deployment

Panel и ingress используют одну `PANEL_DATABASE`; перед первым ingress startup сделайте SQLite-safe backup.

### 1. Offline client CA

На защищённой operator system:

```bash
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-ca-init --ca-dir /root/mtproxy-fleet-ca
install -m 0644 /root/mtproxy-fleet-ca/ca.crt \
  /etc/mtproxy-panel/fleet-client-ca.crt
```

`ca.key` остаётся offline/root-only. Ingress получает только `ca.crt`.

### 2. Ingress TLS

Получите WebPKI certificate для `fleet.example.com`. Не используйте fleet client CA как public server identity. Установите `deploy/mtproxy-fleet-ingress.service` + `deploy/fleet-ingress.env.example` или используйте `compose.fleet-central.yaml` как overlay того же project `mtproxy`.

Private key source остаётся root-only; unit staging-copy размещает его в protected runtime directory для service identity. После certificate renewal перезапустите ingress через root-owned deploy hook.

```bash
export COMPOSE_FILE=compose.yaml:compose.fleet-central.yaml
docker compose config -q
docker compose up -d --build fleet-ingress panel
```

## Enrollment узла

### 1. Зарегистрировать node

Через owner UI или CLI:

```bash
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-register-node node-1 --display-name 'Node 1'
```

State: `unenrolled`.

### 2. Создать key и CSR на узле

```bash
install -d -m 0700 /etc/mtproxy-agent
openssl req -new -newkey rsa:3072 -nodes -sha256 \
  -subj '/CN=node-1' \
  -keyout /etc/mtproxy-agent/node-1.key \
  -out /etc/mtproxy-agent/node-1.csr
chmod 0600 /etc/mtproxy-agent/node-1.key
```

Private key никогда не покидает узел. Передайте только CSR в offline CA environment.

### 3. Подписать CSR

```bash
python -m panel.cli fleet-sign-csr node-1 \
  --ca-dir /root/mtproxy-fleet-ca \
  --csr /secure-inbox/node-1.csr \
  --out /secure-outbox/node-1.crt \
  --days 90
```

Signer игнорирует requested identity extensions и создаёт canonical URI SAN.

### 4. Bind certificate central-side

```bash
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-bind-cert node-1 --cert /secure-inbox/node-1.crt
```

State: `enrolled`.

### 5. Установить agent

Верните на node public certificate и CA certificate, но не `ca.key`. Установите `deploy/mtproxy-agent.service` + `deploy/agent.env.example`; local Telemt token храните mode-restricted. Agent пишет только в `/var/lib/mtproxy-agent`.

```bash
systemctl daemon-reload
systemctl enable --now mtproxy-agent
journalctl -u mtproxy-agent --since=-5m --no-pager
```

Compose agent overlay публикует 0 ports, не монтирует Docker socket и обращается к Telemt только как `http://mtproxy:9091` внутри private network.

### 6. Acceptance

После успешной mTLS authorization state становится `connected`. Первой отправьте короткоживущую inventory command и дождитесь durable success result. Только затем переходите к mutations.

## Rotation

Rotation overlap-first:

1. создать новый key/CSR на node;
2. подписать и bind новый cert central-side;
3. atomically заменить node certificate/key и restart agent;
4. подтвердить `connected` и inventory success;
5. revoke старый serial:

```bash
python -m panel.cli --database /var/lib/mtproxy-panel/panel.sqlite3 \
  fleet-revoke-cert node-1 --serial OLD_HEX_SERIAL
```

При compromise сначала revoke, затем stop agent и выдайте новый key/cert. V1 не публикует OCSP/CRL; revocation проверяется application database после TLS.

## Negative tests

- без client certificate TLS handshake fails;
- cert от другой CA fails;
- cert node A на path node B получает 403;
- unbound/revoked serial получает 403;
- expired command доставляется как durable failed no-op и не выполняет mutation;
- local Telemt API не опубликован;
- agent не имеет Docker socket;
- completed outbox не остаётся unacknowledged после recovery.

## Ограничения v1

- CSR transfer/approval manual;
- rate limiter per-process и сбрасывается при restart;
- allowlisted только inventory, enable, disable, limit updates, quota reset и bounded Mieru lifecycle/inspect;
- create/delete/rotate/reveal и secret-bearing apply исключены;
- web registry operation не заменяет PKI enrollment;
- production ingress/enrollment end-to-end пока не заявлен как completed gate.

См. [operations](docs/OPERATIONS.ru.md), [backup](docs/BACKUP_RESTORE.ru.md), [security](SECURITY.md) и [troubleshooting](docs/TROUBLESHOOTING.ru.md).
