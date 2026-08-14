# Автоматическая установка Proxy Control на VPS

Актуальный root-only `install.sh` вызывает `scripts/proxyctl.py install`. Поддерживаются lifecycle-команды `audit`, `plan`, `install`, `repair`, `uninstall`; см. [INSTALLER_AUDITOR.md](INSTALLER_AUDITOR.md). Исторические режимы `fresh` и `coexist` больше не принимаются и не показаны как runnable examples.

Полный installer рассчитан на Ubuntu 24.04 с существующей однозначной Nginx `ssl_preread` map. На других системах допустим read-only `audit`, но полная установка не поддерживается без validation.

```sh
sudo python3 scripts/proxyctl.py audit --proxy-domain proxy.example.com --panel-domain panel.example.com --json
sudo python3 scripts/proxyctl.py plan --proxy-domain proxy.example.com --panel-domain panel.example.com --email admin@example.com --route-file /etc/nginx/stream.d/routes.conf --users owner --protocol-probe /usr/local/bin/mtproxy-respq-probe
sudo ./install.sh --proxy-domain proxy.example.com --panel-domain panel.example.com --email admin@example.com --route-file /etc/nginx/stream.d/routes.conf --users owner --protocol-probe /usr/local/bin/mtproxy-respq-probe
```

DNS должен указывать прямо на host, port 80 — принимать ACME HTTP-01, а внешний probe — подтверждать Fake-TLS/Obfuscated2 `req_pq_multi → resPQ` для каждого secret. Installer не меняет firewall и не печатает credentials. `repair` и `uninstall` читают точные locations из private ownership manifest и не принимают runtime-location arguments.

Перед применением прочитайте [UPGRADING.md](docs/UPGRADING.md), [COMPATIBILITY.md](docs/COMPATIBILITY.md) и [VALIDATION.md](docs/VALIDATION.md).
