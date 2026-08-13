# Автоматическая установка на VPS

Installer разворачивает следующую схему:

```text
Интернет :443
  → host Nginx stream / ssl_preread
  → SNI вашего домена
  → 127.0.0.1:8445
  → Telemt в Docker

Telemt cover fallback
  → Caddy только во внутренней Docker-сети
  → внешний document root /var/www/ВАШ_ДОМЕН
```

Таким образом Nginx остаётся единственным владельцем публичного TCP/443. Другие HTTPS-, Xray/REALITY- и TCP-сервисы продолжают использовать тот же порт через отдельные SNI-маршруты.

## Поддерживаемые системы

- Ubuntu 22.04/24.04;
- Debian 12/13;
- root-доступ;
- прямой A-record домена на VPS;
- Cloudflare — только DNS-only, если не используется отдельный L4/Spectrum-продукт.

## Режимы

### `fresh`

Для чистого VPS без listener на TCP/443. Installer создаёт отдельный расширяемый Nginx stream router:

```bash
sudo ./install.sh \
  --mode fresh \
  --domain proxy.example.com \
  --email admin@example.com \
  --users phone,laptop,reserve
```

Новые сервисы затем добавляются в `/etc/nginx/mtproxy-stream/routes.conf` отдельными строками SNI. Значение `default` намеренно закрыто; назначьте ему собственный HTTPS/Xray backend при необходимости.

### `coexist`

Для VPS, где Nginx уже владеет `:443` и использует `stream map`. Укажите **конкретный файл**, содержащий существующую map:

```bash
sudo ./install.sh \
  --mode coexist \
  --domain proxy.example.com \
  --email admin@example.com \
  --users phone,laptop,reserve \
  --route-file /etc/nginx/stream-conf.d/sni-map.conf
```

Installer:

- не заменяет существующую map;
- отказывается работать при коллизии hostname;
- вставляет одну маркированную запись перед `default`;
- создаёт backup рядом с файлом;
- применяет изменение только после `nginx -t`;
- при ошибке удаляет собственную запись и повторно валидирует Nginx.

Если конфигурация сложнее обычной `map $ssl_preread_server_name ...`, добавьте маршрут вручную и используйте генератор `scripts/mtproxy-deploy render`.

## Дополнительные параметры

```text
--backend-port 18445     другой loopback-порт Telemt
--cover-file ./site.html приватный HTML-файл; в Git не попадает
--project-dir /opt/name  каталог развёртывания
--skip-dns-check         только для предварительной staging-установки
--no-firewall            не добавлять allow 80/443 в активный UFW
```

Секреты генерируются локально в `PROJECT_DIR/secrets/users.conf`, режим `0600`. Повторный запуск сохраняет секреты пользователей с прежними именами.

## Что installer делает

1. Устанавливает только отсутствующие зависимости; существующий кастомный Nginx не переустанавливает.
2. Проверяет DNS, занятость портов и Docker Compose v2.
3. Создаёт параметризованный deployment в `/opt/mtproxy-shared443`.
4. Копирует cover-файл во внешний `/var/www/DOMAIN` либо создаёт нейтральную минимальную страницу.
5. Выпускает сертификат Let's Encrypt через HTTP-01 webroot.
6. Запускает закреплённые по digest Telemt и Caddy.
7. Ждёт `healthy`, затем меняет Nginx stream routing.
8. Проверяет Compose, listener, Nginx, HTTPS и новые критические ошибки в логах.

Успешный healthcheck не доказывает полный MTProto маршрут. После установки проверьте каждый секрет настоящим handshake `req_pq_multi → resPQ` или реальным клиентом из целевой сети.

## Ссылки

Installer не печатает ссылки с секретами. Создайте их локально:

```bash
sudo python3 /opt/mtproxy-shared443/docker/links.py \
  --server proxy.example.com \
  --port 443 \
  --domain proxy.example.com \
  --secrets /opt/mtproxy-shared443/secrets/users.conf
```

Перенаправляйте вывод только в защищённый файл (`umask 077`).

## Удаление

```bash
sudo ./uninstall.sh --yes
```

По умолчанию удаляются контейнеры, собственный SNI route, HTTP ACME vhost и deployment directory. Чужие Nginx-маршруты, Docker-контейнеры, сертификат и cover-каталог сохраняются.

Опционально:

```bash
sudo ./uninstall.sh --yes --purge-certificate --purge-cover
```

Удаление основано на mode-`0600` `state.json` и не выполняет широких grep/rm над чужой конфигурацией.

## Dry/sandbox-проверка генератора

```bash
python3 -m unittest -v tests/test_deploy.py
bash -n install.sh uninstall.sh scripts/check-deployment.sh
```

Тесты выполняют реальные операции генерации и изменения Nginx map во временной файловой системе, включая idempotency, collision refusal и точечный rollback.
