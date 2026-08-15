# Полный installer и auditor Proxy Control (`proxyctl`)

[English](INSTALLER_AUDITOR.md) · **Русский**

`install.sh` — root-only wrapper над `scripts/proxyctl.py install`. Lifecycle: `audit`, `plan`, `install`, `repair`, `uninstall`. Installer разворачивает Telemt/MTProto и panel на Ubuntu 24.04; NaiveProxy, Mieru и fleet остаются отдельными integrations.

## Production command

DNS обоих names должен указывать напрямую на host, TCP/80 — принимать ACME HTTP-01, а выбранный protocol hook — проверять реальный Fake-TLS/Obfuscated2 `req_pq_multi → resPQ` для каждого secret.

```bash
sudo ./install.sh \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --email ops@example.com \
  --route-file /etc/nginx/stream.d/routes.conf \
  --users owner,phone \
  --protocol-probe /usr/local/bin/mtproxy-respq-probe
```

Сначала используйте те же параметры с `plan`; audit независимо read-only:

```bash
sudo python3 scripts/proxyctl.py audit \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com --json
```

После installation:

```bash
sudo python3 scripts/proxyctl.py repair
sudo ./uninstall.sh
```

`repair` и `uninstall` читают exact plan из private ownership manifest и не принимают hostname/path arguments.

## Что принадлежит installer

1. Только отсутствующие Ubuntu packages: CA certificates, OpenSSL, curl, Python, Certbot, Docker Engine/Compose v2, Nginx full/stream.
2. Dedicated port-80 webroot vhosts для обоих domains и один certificate.
3. Digest-pinned Telemt, internal Caddy cover и FastAPI panel под `/opt/mtproxy-shared443`.
4. Mode-`0600` per-user secrets, Telemt API token и panel bootstrap password; валидные существующие credentials сохраняются.
5. Owner bootstrap через stdin без вывода credential.
6. Telemt `127.0.0.1:8445`, panel app `127.0.0.1:8787`.
7. Host Nginx panel TLS vhost на existing HTTP fallback `127.0.0.1:8443`, panel SNI → `8443`, proxy SNI → `8445`.
8. Compose pull/start `--wait`, health validation и mandatory protocol hook.

Installer не меняет UFW, nftables, iptables, DNS, Xray/3x-ui, unrelated Nginx routes или unrelated containers.

## Transaction model

Private runtime manifest `/var/lib/proxy-control/runtime.json` — phase-specific write-ahead journal install/rollback/uninstall. Route ownership и exact backups находятся в `/var/lib/proxy-control/ownership.json` и `/var/lib/proxy-control/backups/`.

Каждая Nginx mutation:

1. проверяет expected ownership/content/symlink policy;
2. создаёт exact metadata-preserving backup;
3. durable-записывает intent/phase;
4. atomically replaces target;
5. требует `nginx -t`;
6. reloads;
7. запускает health/protocol gates;
8. commits или restores previous generation.

Interrupted install при следующем matching install завершает rollback и повторяет generation, сохраняя credentials/package ownership. Неподтверждённый rollback остаётся `rollback_failed` и блокирует новые mutations.

## Repair

`repair` завершает interrupted rollback, проверяет owned files и manifest, validates Nginx/Compose и restart recorded services. Foreign drift не «исправляется» автоматически.

## Uninstall

Uninstall записывает `uninstalling` до первой mutation и checkpoint каждую phase. Сначала останавливает Compose, затем удаляет public routes/vhosts, owned project files и только installer-owned packages. Nginx остаётся доступен до завершения route validation.

Credentials под `/opt/mtproxy-shared443/secrets/`, certificates и cover roots сохраняются. Удаляйте их отдельно только после ownership/use review.

## Hard stops

- unsupported OS для full install;
- ambiguous/included/multiple Nginx SNI maps;
- non-Nginx public 443 owner;
- DNS/NAT/AAAA mismatch;
- occupied loopback port или hostname collision;
- symlink/foreign content drift;
- missing/non-executable protocol probe;
- failed `nginx -t`, health или real `resPQ`;
- incomplete rollback.

## Проверка repository

```bash
.venv/bin/ruff check .
.venv/bin/python -m pytest -q
python3 -m unittest -v tests/test_deploy.py
python3 scripts/check-doc-links.py
git ls-files -z '*.sh' | xargs -0 -r -n1 bash -n
git ls-files -z '*.sh' | xargs -0 -r shellcheck
docker compose config -q
git diff --check
```

Runtime acceptance должен включать real protocol probe и соседние SNI; test harness с fake root проверяет transactions, recovery, secret preservation, package ownership и idempotent uninstall, но не заменяет target host validation.

См. [INSTALL.ru.md](INSTALL.ru.md), [operations](docs/OPERATIONS.ru.md), [backup](docs/BACKUP_RESTORE.ru.md) и [troubleshooting](docs/TROUBLESHOOTING.ru.md).
