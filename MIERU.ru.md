# Управление Mieru / mita 3.35

[English](MIERU.en.md) · **Русский**

Proxy Control поддерживает `mita` **3.35.x** через отдельный authenticated Unix-socket manager. `mita` остаётся внешним GPLv3+ процессом: binary не включён в MIT repository/images и устанавливается оператором отдельно.

## Pinned artifacts

| Архитектура | Upstream package | SHA-256 package | SHA-256 `usr/bin/mita` |
|---|---|---|---|
| amd64 | `https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_amd64.deb` | `cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342` | `4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31` |
| arm64 | `https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_arm64.deb` | `66ff435dd5bd6078944cb4eb7fc427366afaac5ab51030ff62561c645c31a9e3` | `a4e486c1531b7bebec02eca2b60dcba2a4971b2cd479c590d8405aab59fe6a23` |

Не устанавливайте package только ради binary: скачайте, проверьте package digest, распакуйте и отдельно проверьте executable digest.

```bash
curl -fL --proto '=https' --tlsv1.2 \
  https://github.com/enfein/mieru/releases/download/v3.35.0/mita_3.35.0_amd64.deb \
  -o mita_3.35.0_amd64.deb
printf '%s  %s\n' cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342 mita_3.35.0_amd64.deb | sha256sum -c -
dpkg-deb -x mita_3.35.0_amd64.deb mita-root
printf '%s  %s\n' 4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31 mita-root/usr/bin/mita | sha256sum -c -
```

Для arm64 замените URL и оба digest.

## Runtime architecture

```text
Panel ── authenticated manager UDS ──► mieru-manager
                                           │ fixed argv + FD secret input
                                           ▼
                                  host-mounted pinned mita
                                           │ management UDS
                                           ▼
                                      mita service
```

Manager не sandbox: безопасность зависит от pinned trusted executable. Secret-bearing JSON передаётся через anonymous FD, не через argv/named tempfile/log. Unknown fields, invalid status и unauthenticated journal fail closed.

## Host service и stable UDS

Production-safe unit использует:

- binary `/usr/bin/mita`;
- mutable config `/var/lib/mita/server_config.json`;
- stable socket directory `/run/mita` через tmpfiles + `ExecStartPre`;
- socket `/run/mita/mita.sock` mode `0770`;
- отдельного non-login user `mita`.

Не используйте `RuntimeDirectory=mita` с bind-mounted UDS: restart может заменить directory inode и оставить container на stale mount.

```bash
sudo install -m 0644 deploy/mita.tmpfiles.conf /etc/tmpfiles.d/mita.conf
sudo install -m 0644 deploy/mita.service /etc/systemd/system/mita.service
sudo systemd-tmpfiles --create /etc/tmpfiles.d/mita.conf
sudo systemctl daemon-reload
sudo systemctl enable --now mita
MITA_UDS_PATH=/run/mita/mita.sock /usr/bin/mita status
```

Принимайте только exact output `mita server status is "RUNNING"`.

## Manager identity и token

Container использует fixed `10005:10005`. Перед назначением выполните collision preflight. Token должен находиться под root-owned, non-writable parent chain; state — отдельный empty directory.

```bash
export MIERU_MANAGER_TOKEN_FILE=/etc/mieru-manager/token
export MIERU_MANAGER_STATE_DIR=/var/lib/mieru-manager
export MIERU_MITA_GID="$(stat -c %g /run/mita/mita.sock)"
getent passwd 10005 || true
getent group 10005 || true
sudo ./scripts/prepare-mieru-token.sh prepare "$MIERU_MANAGER_TOKEN_FILE"
sudo ./scripts/prepare-mieru-state.sh prepare "$MIERU_MANAGER_STATE_DIR"
```

Любая unrelated UID/GID collision — hard stop. Не применяйте recursive `chown` к restored non-empty state.

## Compose overlay

```bash
export MIERU_PUBLIC_HOST=mieru.example.com
export MIERU_MITA_BIN=/usr/bin/mita
export MIERU_MITA_SHA256=4aa03abde846548692dc479359fd9d6c378c0b0e3ab22f94b2c22b1e54dcdb31
export MIERU_MITA_GID="$(stat -c %g /run/mita/mita.sock)"
export MIERU_MANAGER_STATE_DIR=/var/lib/mieru-manager
export MIERU_MANAGER_TOKEN_FILE=/etc/mieru-manager/token
export COMPOSE_FILE=compose.yaml:compose.mieru.yaml
docker compose config -q
docker compose up -d --build
```

Если Naive уже развёрнут, включите `compose.naive.yaml` в тот же полный `COMPOSE_FILE`. Project name остаётся `mtproxy`.

## Listeners

Mieru не захватывает TCP/443 автоматически. Явно выберите dedicated TCP/UDP ports, проверьте `ss -lntup`, cloud firewall и host firewall. Shared 443 остаётся у Nginx. Management UDS не имеет отношения к public listener.

## Пользователи, ссылки и QR

Create возвращает one-time `mierus://` URL, QR и import command. List API secret-free. Existing password из `hashedPassword` не восстанавливается; **«Новая ссылка + QR»** выполняет rotation и инвалидирует старый config. Полный flow: [MIERU_SHARING.ru.md](docs/MIERU_SHARING.ru.md).

Credential rotation, disable и delete требуют controlled restart для revocation. Quota-only change может использовать reload. Config apply — full-snapshot CAS transaction; apply сам по себе не гарантирует изменение live state.

## Accounting

Per-user Mieru metrics намеренно `degraded/unavailable`: `mita get metrics` и human-table users не дают безопасную typed boundary для MIT adapter. Проект не копирует GPL-generated stubs и не парсит rounded table output. Quota — application bytes и rolling approximate session-admission check, не hard billing cap.

## Backup и restore

Остановите services и восстановите complete state generation. `journal.json` и исходный `journal.key` должны восстанавливаться вместе.

```bash
docker compose stop panel mieru-manager
sudo ./scripts/prepare-mieru-state.sh verify /var/lib/mieru-manager
sudo ./scripts/prepare-mieru-token.sh verify /etc/mieru-manager/token
systemctl start mita
docker compose up -d mieru-manager panel
```

Verifier проверяет metadata/key size, не читает secret contents и не исправляет non-empty restored state.

## Acceptance

- package и executable digests совпали;
- `mita` exact status RUNNING;
- UDS стабилен через restart и имеет ожидаемый owner/mode;
- manager healthy и authenticated;
- real Mieru client → server → Internet probe успешен для declared TCP/UDP path;
- create/reveal/rotate API возвращает one-time URL + QR с `no-store`;
- list/audit не содержат credentials;
- mobile dialog не создаёт horizontal overflow;
- adjacent public listeners не изменились.

## Fleet limitation

Fleet v1 допускает только secret-free Mieru inspect/metrics/lifecycle. Remote create/rotate/full apply запрещены до появления authenticated sealed payload layer. Не сохраняйте decrypted credentials в fleet SQLite.
