**Русский** | [English](README.en.md)

# MTProxy за общим TCP/443: Telemt, Nginx SNI и полноценный cover-сайт

> Docker-развёртывание MTProto-прокси для сервера, где публичный TCP/443 уже занят Nginx `stream`, HTTPS-сайтами и Xray/3x-ui.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Runtime: Telemt 3.4.25](https://img.shields.io/badge/Runtime-Telemt%203.4.25-6f42c1.svg)](https://github.com/telemt/telemt)
[![Container: digest pinned](https://img.shields.io/badge/Container-digest--pinned-success.svg)](compose.yaml)

Этот форк сохраняет исходные systemd-скрипты проекта, но добавляет отдельный, фактически используемый **Docker production-путь** на современном движке [Telemt](https://github.com/telemt/telemt). Он не требует отдавать MTProxy весь публичный порт `443`: Nginx читает SNI без завершения TLS и направляет только выделенный домен на loopback listener контейнера.

## Зачем заменён старый движок

Официальный `TelegramMessenger/MTProxy` использует устаревшую цепочку через Telegram Middle-End на TCP/8888. На части сетей TCP-соединение с клиентом и Fake-TLS проходят успешно, но пул Middle-End остаётся пустым (`ready_targets = 0`), поэтому Telegram бесконечно показывает `Connecting`.

Telemt работает с актуальными Telegram DC напрямую по TCP/443. В этом форке образ зафиксирован по digest, а успешность проверяется не только healthcheck'ом, но и полным протокольным тестом:

```text
TCP connect → Fake-TLS → Obfuscated2 → req_pq_multi → Telegram resPQ
```

## Архитектура

```text
Интернет TCP/443
  → Nginx stream + ssl_preread
  → SNI выбранного MTProxy-домена
  → 127.0.0.1:8445
  → контейнер Telemt:443
  → Telegram DC:443

Обычный браузер или активный probe
  → Telemt mask fallback
  → контейнер Caddy:443
  → статический cover-сайт
```

- Telemt опубликован только на `127.0.0.1:8445` и не конкурирует за `0.0.0.0:443`.
- Caddy доступен только во внутренней Docker-сети.
- Неопознанный TLS-трафик передаётся на реальный HTTPS cover backend.
- Секреты не входят в образ, Compose-конфигурацию или Git.
- Runtime-конфигурация Telemt создаётся в приватном `tmpfs`.
- API Telemt отключён; пользовательские ссылки не печатаются в production-логи.
- Root filesystem обоих контейнеров работает read-only.
- У Telemt удалены все Linux capabilities (`cap_drop: ALL`).

## Состав Docker-развёртывания

| Файл | Назначение |
|---|---|
| `compose.yaml` | Telemt и Caddy, loopback-публикация, healthchecks и hardening |
| `docker/telemt-entrypoint.sh` | Безопасно преобразует `users.conf` в runtime TOML |
| `docker/Caddyfile` | Внутренний HTTPS cover backend |
| `docker/site/index.html` | Версионируемый автономный cover-сайт |
| `docker/links.py` | Локальная генерация Fake-TLS ссылок без вывода секретов в логи |
| `DOCKER_DEPLOYMENT.md` | Краткие эксплуатационные заметки |

## Требования

- Linux-сервер с Docker Engine и Docker Compose v2;
- Nginx, собранный с `stream` и `stream_ssl_preread`;
- отдельный DNS hostname с A-записью на сервер;
- режим **DNS-only**, если DNS обслуживает Cloudflare: обычное orange-cloud proxy не передаёт произвольный MTProto TCP;
- действующий TLS-сертификат для cover backend;
- свободный loopback-порт `127.0.0.1:8445`.

Текущий `compose.yaml` содержит deployment-specific значения `tga.unicorndubr1k.org` и путь сертификата Let's Encrypt. Перед использованием на другом сервере замените hostname в:

- `compose.yaml`;
- `docker/Caddyfile`;
- Nginx stream map;
- командах генерации ссылок.

## 1. Клонирование

```bash
git clone https://github.com/dubr1k/MTProxy.git
cd MTProxy
```

## 2. Пользовательские секреты

Создайте отдельный 16-байтовый hex-секрет для каждого пользователя:

```bash
mkdir -p secrets
umask 077
{
  printf 'phone=%s\n' "$(openssl rand -hex 16)"
  printf 'laptop=%s\n' "$(openssl rand -hex 16)"
} > secrets/users.conf
chmod 600 secrets/users.conf
```

Формат файла:

```text
phone=0123456789abcdef0123456789abcdef
laptop=fedcba9876543210fedcba9876543210
```

Допустимы имена из латинских букв, цифр, `_` и `-`. Значение должно содержать ровно 32 hex-символа. Файл исключён из Git и Docker build context.

## 3. Сертификат и cover-сайт

Caddy не выпускает сертификат сам: он читает существующие файлы Let's Encrypt в режиме read-only. Для текущего hostname ожидаются:

```text
/etc/letsencrypt/live/tga.unicorndubr1k.org/fullchain.pem
/etc/letsencrypt/live/tga.unicorndubr1k.org/privkey.pem
```

Для другого домена измените пути и адрес сайта в `docker/Caddyfile`. Cover-сайт находится в `docker/site/index.html`; он не должен содержать упоминаний прокси или внутренней инфраструктуры.

## 4. Nginx stream SNI routing

Минимальная схема выглядит так:

```nginx
map $ssl_preread_server_name $stream_backend {
    tga.unicorndubr1k.org  mtproxy_backend;
    default                existing_backend;
}

upstream mtproxy_backend {
    server 127.0.0.1:8445;
}

server {
    listen 443 reuseport;
    proxy_pass $stream_backend;
    ssl_preread on;
}
```

Это пример, а не готовая замена существующей карты. На сервере с Xray/REALITY и несколькими HTTPS-сайтами добавляйте только новую SNI-запись в уже действующую конфигурацию.

Проверка перед reload обязательна:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 5. Запуск

```bash
docker compose config
docker compose pull
docker compose up -d
```

Проверьте runtime:

```bash
docker compose ps
docker inspect mtproxy --format \
  'health={{.State.Health.Status}} restarts={{.RestartCount}} readonly={{.HostConfig.ReadonlyRootfs}}'
ss -lnt | grep '127.0.0.1:8445'
docker compose logs --tail 100 mtproxy
```

Ожидается:

- `mtproxy` и `mask` — `healthy`;
- `RestartCount=0`;
- listener только на `127.0.0.1:8445`;
- в логах все Telegram DC доступны через `direct`;
- отсутствуют `panic`, `fatal` и циклические ошибки подключения.

## 6. Генерация ссылок

Ссылки генерируются локально и содержат секреты — не публикуйте их в issue, CI-логах или shell history общего сервера.

```bash
python3 docker/links.py \
  --server tga.unicorndubr1k.org \
  --port 443 \
  --domain tga.unicorndubr1k.org \
  --secrets secrets/users.conf
```

Формат Fake-TLS секрета:

```text
ee + 32 hex-символа пользовательского секрета + hex(домен)
```

Для ручного добавления в Telegram Android выберите **MTProto Proxy** и укажите server, port и полный `ee...` secret.

## 7. Правильная проверка

HTTPS-код `200`, открытый TCP/443 и Docker healthcheck **не доказывают**, что MTProto работает. Нужен клиент или checker, который получает настоящий Telegram `resPQ`.

Проверочный сценарий для каждого секрета:

1. соединиться с публичным hostname на `443`;
2. выполнить Fake-TLS handshake с тем же SNI;
3. отправить Obfuscated2 init;
4. отправить зашифрованный `req_pq_multi`;
5. получить и проверить `resPQ` от Telegram DC.

Дополнительно проверьте cover и соседние маршруты:

```bash
curl -fsS https://tga.unicorndubr1k.org/ >/dev/null
sudo nginx -t
systemctl is-active nginx
```

На shared-443 сервере также протестируйте все существующие SNI hostname после каждого изменения карты.

## Обновление

Образ Telemt закреплён digest'ом, поэтому `docker compose pull` не заменит движок неожиданно. Обновляйте осознанно:

1. изучите changelog и лицензию новой версии Telemt;
2. получите новый image digest;
3. измените digest в `compose.yaml`;
4. выполните `docker compose config`;
5. пересоздайте контейнер;
6. повторите полный `resPQ`-тест для каждого секрета и регрессию SNI-маршрутов;
7. откатите digest, если любой этап не прошёл.

Обычное обновление файлов форка:

```bash
git pull --ff-only
docker compose config
docker compose pull
docker compose up -d
```

## Отзыв пользователя

Удалите строку пользователя из `secrets/users.conf` и пересоздайте только Telemt:

```bash
docker compose up -d --force-recreate mtproxy
```

Остальные секреты сохранятся. Перед удалением сделайте защищённую резервную копию файла.

## Диагностика

| Симптом | Что проверять |
|---|---|
| Ссылка не открывается на Android | Добавить вручную как MTProto Proxy; проверить обработку `tg://` отдельно от сети |
| Вечный `Connecting` | Полный `resPQ`-тест; доступность Telegram DC; формат полного `ee...` секрета |
| Браузер не показывает cover | Caddy health, сертификат, `mask_host`, SNI routing |
| Виден сайт, но MTProto не работает | HTTPS fallback и MTProto — разные ветви; health сайта не доказывает upstream Telegram |
| Не приходит трафик | DNS A/AAAA, Cloudflare DNS-only, публичный firewall, Nginx stream map |
| Сломались другие сервисы на 443 | Откатить изменение stream map и проверить все прежние SNI-маршруты |

## Legacy systemd installer

Файлы `install_mtproxy.sh` и `uninstall_mtproxy.sh` сохранены из upstream для совместимости и истории. Они устанавливают старый официальный `TelegramMessenger/MTProxy` напрямую через systemd и **не являются рекомендуемым production-путём этого форка**. Не запускайте legacy installer поверх Docker-развёртывания без отдельного порта и предварительного аудита конфликтов.

## Ограничения

- MTProto proxy предназначен для трафика Telegram; голосовые и видеозвонки могут обходить его или не поддерживаться клиентом.
- Fake-TLS повышает маскировку, но не гарантирует неразличимость для любого DPI.
- Cover-сайт не заменяет корректную сетевую маршрутизацию.
- Docker healthcheck проверяет готовность listener, а не полный Telegram протокол.

## Лицензии и происхождение

- Код исходного проекта и добавленные deployment-файлы распространяются по [MIT](LICENSE).
- Runtime Telemt имеет собственную [Telemt Public License](https://github.com/telemt/telemt/blob/main/LICENSE); образ используется без модификации и закреплён по digest.
- Форк основан на [lingeniare/MTProxy](https://github.com/lingeniare/MTProxy).

Сведения об уязвимостях и обращении с секретами приведены в [SECURITY.md](SECURITY.md).
