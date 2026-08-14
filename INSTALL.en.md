# Proxy Control automated VPS installation

The current root-only `install.sh` wraps `scripts/proxyctl.py install`. Supported lifecycle commands are `audit`, `plan`, `install`, `repair`, and `uninstall`; see [INSTALLER_AUDITOR.md](INSTALLER_AUDITOR.md). Historical `fresh` and `coexist` modes are not accepted and are not runnable examples.

The complete installer targets Ubuntu 24.04 with an existing, unambiguous Nginx `ssl_preread` map. Other systems may use read-only `audit`, but complete installation is unsupported until validated.

```sh
sudo python3 scripts/proxyctl.py audit --proxy-domain proxy.example.com --panel-domain panel.example.com --json
sudo python3 scripts/proxyctl.py plan --proxy-domain proxy.example.com --panel-domain panel.example.com --email admin@example.com --route-file /etc/nginx/stream.d/routes.conf --users owner --protocol-probe /usr/local/bin/mtproxy-respq-probe
sudo ./install.sh --proxy-domain proxy.example.com --panel-domain panel.example.com --email admin@example.com --route-file /etc/nginx/stream.d/routes.conf --users owner --protocol-probe /usr/local/bin/mtproxy-respq-probe
```

DNS must point directly to the host, port 80 must support ACME HTTP-01, and the external probe must validate real Fake-TLS/Obfuscated2 `req_pq_multi → resPQ` for every secret. The installer never changes the firewall or prints credentials. `repair` and `uninstall` load exact locations from the private ownership manifest and take no runtime-location arguments.

Read [UPGRADING.md](docs/UPGRADING.md), [COMPATIBILITY.md](docs/COMPATIBILITY.md), and [VALIDATION.md](docs/VALIDATION.md) before applying changes.
