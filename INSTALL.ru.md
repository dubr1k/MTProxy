# Автоматическая установка Proxy Control на Ubuntu 24.04

[English](INSTALL.en.md) · **Русский**

Root-only `install.sh` вызывает транзакционный `scripts/proxyctl.py install`. Поддерживаются команды:

```text
audit → plan → install → repair → uninstall
```

Полный installer разворачивает Telemt/MTProxy и panel. NaiveProxy, Mieru и fleet подключаются отдельно после successful core acceptance.

## Требования

- Ubuntu 24.04 + systemd;
- root/sudo;
- DNS A/AAAA для proxy и panel names указывает напрямую на host;
- TCP/80 доступен для ACME HTTP-01;
- public TCP/443 принадлежит существующему Nginx `stream` listener;
- в выбранном route file есть ровно одна понятная `$ssl_preread_server_name` map;
- loopback ports свободны;
- подготовлен внешний executable protocol probe, проверяющий real Fake-TLS/Obfuscated2 `req_pq_multi → resPQ`;
- создан host-level backup Nginx, services и соседних routes.

Cloud/CDN proxy для raw MTProto hostname должен быть отключён (DNS-only). Unhandled AAAA, NAT mismatch, ambiguous Nginx maps и port collisions — hard stops.

## 1. Read-only audit

```bash
sudo python3 scripts/proxyctl.py audit \
  --proxy-domain proxy.example.com \
  --panel-domain panel.example.com \
  --json
```

Audit не устанавливает packages и не меняет files/services. Проверьте listener ownership, DNS, Nginx topology, platform и collisions.

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

Plan не содержит passwords, tokens, user secrets или access links. Сверьте managed paths, package ownership, certificate names, loopback ports, route changes и probe path.

## 3. Backup и rollback readiness

До install сохраните:

- selected Nginx route file и included configs с owner/mode;
- `nginx -T` в приватный artifact;
- active listeners и service units;
- existing Docker/Compose state;
- соседние SNI acceptance results.

Installer создаёт private ownership manifest и exact backups, но это не замена независимому host backup.

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

Installer:

1. устанавливает только отсутствующие packages;
2. получает certificate для обоих names;
3. создаёт mode-restricted secrets;
4. разворачивает Compose project `mtproxy`;
5. bootstraps initial owner через stdin;
6. добавляет минимальные Nginx routes через validated transaction;
7. ждёт health и запускает mandatory external protocol probe.

Он не меняет UFW/nftables/iptables, DNS, Xray/3x-ui, unrelated containers или unrelated Nginx routes.

## 5. Acceptance

```bash
docker compose -f /opt/mtproxy-shared443/compose.yaml ps
curl -fsS http://127.0.0.1:8787/healthz
sudo nginx -t
ss -lntup
```

Обязательно выполните:

- external `resPQ` для каждого user secret;
- реальный Telegram client test;
- panel HTTPS/login;
- adjacent SNI regression;
- SQLite integrity и backup checksum;
- проверку, что Telemt API не опубликован на host.

## 6. Repair

```bash
sudo python3 scripts/proxyctl.py repair
```

`repair` читает exact private manifest `/var/lib/proxy-control/runtime.json`, завершает interrupted rollback/recovery, проверяет owned files и restart. Команда намеренно не принимает arbitrary runtime paths.

## 7. Uninstall

```bash
sudo ./uninstall.sh
```

Uninstall durable-checkpoints phases, удаляет только owned routes/files/packages и сохраняет credential backup, certificates и cover roots до отдельного ownership review. Повторный запуск resume-safe.

После удаления снова проверьте `nginx -t`, public listeners и соседние SNI. Не удаляйте preserved secrets/certificates, пока не подтверждено, что они больше никем не используются.

## Отказ и прерванный SSH

SSH exit `255` доказывает только transport failure. На target host проверьте `/var/lib/proxy-control/runtime.json`, durable phase/status, owned files, services и protocol probe. Не запускайте install повторно вслепую.

## Следующие интеграции

После core acceptance:

- [Panel и NaiveProxy](PANEL.ru.md)
- [Mieru/mita](MIERU.ru.md)
- [Fleet mTLS](FLEET.ru.md)

Подробности transactions и hard stops: [INSTALLER_AUDITOR.md](INSTALLER_AUDITOR.md). Эксплуатация: [docs/OPERATIONS.ru.md](docs/OPERATIONS.ru.md), [backup](docs/BACKUP_RESTORE.ru.md), [validation](docs/VALIDATION.md).
