# Развёртывание MTProto за существующим Nginx SNI-router

[English](DOCKER_DEPLOYMENT.md) · **Русский**

Это руководство относится только к Telemt/MTProto data plane. Панель, NaiveProxy, Mieru и fleet описаны отдельно в [карте документации](docs/README.md).

```text
Internet TCP/443 → host Nginx stream/SNI → 127.0.0.1:8445 → Telemt
Unauthenticated/probe TLS → Telemt fallback → private-network Caddy mask
Panel → authenticated Telemt API в private Compose network
```

## Preconditions

- DNS proxy hostname указывает напрямую на host;
- public TCP/443 уже принадлежит одному Nginx `stream` listener;
- существует однозначная `$ssl_preread_server_name` map;
- loopback backend port свободен;
- подготовлен внешний real MTProto `resPQ` probe;
- adjacent SNI routes и rollback зафиксированы до изменения.

Telemt image pinned, не слушает `0.0.0.0:443`, работает с read-only root и dropped capabilities. Внутренний API аутентифицирован и доступен только private Compose network; не публикуйте его на host.

## Secrets и first start

Создайте mode-`0600` файлы:

- `secrets/users.conf`;
- `secrets/telemt-api-token`.

На первом startup entrypoint рендерит конфигурацию в credential-bearing named volume `telemt-config`. Последующие API mutations переживают recreation container. Удаление volume повторно импортирует исходный `users.conf`, поэтому это destructive reset, а не обычный redeploy.

```bash
docker compose -f compose.yaml config -q
docker compose -f compose.yaml up -d --build
docker compose -f compose.yaml ps
```

## Nginx route

Добавьте только выбранный SNI entry в существующую map и направьте его на `127.0.0.1:8445`. Не заменяйте map примером целиком.

```bash
sudo nginx -t
sudo systemctl reload nginx
```

После reload проверьте выбранный proxy hostname и все соседние SNI routes.

## Acceptance

Healthy container, HTTP response или open port недостаточны. Для каждого active secret выполните:

1. Fake-TLS handshake;
2. Obfuscated2 transport;
3. `req_pq_multi`;
4. валидацию Telegram `resPQ`;
5. реальный Telegram client test из целевой сети.

Проверьте panel → Telemt authenticated API, но не печатайте token или user links.

## Upgrade и rollback

Перед изменением сохраните `telemt-config`, secret files, exact image digest, Compose model, Nginx route и ownership/modes. При отказе восстановите полную generation, выполните `nginx -t`, protocol probe и adjacent SNI regression.

См. [installer/auditor](INSTALLER_AUDITOR.md), [operations](docs/OPERATIONS.ru.md), [security](SECURITY.md) и [validation](docs/VALIDATION.md).
