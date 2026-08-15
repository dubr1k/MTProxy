# Выдача конфигураций Mieru

[English](MIERU_SHARING.en.md) · **Русский**

Proxy Control выдаёт Mieru credentials только после **create** или **controlled rotation**. List API, таблицы UI и audit никогда не содержат password, `mierus://` URL, QR payload или reveal token.

## Создание нового доступа

1. Откройте раздел **Mieru**.
2. Нажмите **Добавить**.
3. Укажите username и, при необходимости, rolling quota/expiry.
4. После создания откроется one-time dialog.
5. Передайте пользователю один из вариантов:
   - QR-код;
   - `mierus://` URL;
   - готовую команду `mieru import config 'mierus://…'`;
   - скачанный QR image.
6. Убедитесь, что пользователь импортировал конфигурацию, затем закройте dialog.

Reveal response имеет `Cache-Control: no-store`. URL и QR существуют во frontend только внутри ephemeral dialog и очищаются при закрытии.

## Повторная выдача существующему пользователю

Mita хранит `hashedPassword`; plaintext password восстановить нельзя. Поэтому старую URL/QR невозможно безопасно показать повторно после истечения one-time reveal.

Нажмите **«Новая ссылка + QR»**. Панель:

1. генерирует новый credential;
2. применяет controlled restart/reload согласно Mieru transaction policy;
3. инвалидирует предыдущий client config;
4. показывает новый one-time URL и QR.

Предупредите пользователя, что старый config перестанет работать сразу после успешной rotation.

## Импорт на клиенте

Используйте client version, совместимую с server `mita` 3.35.x. UI показывает готовую shell-safe import command. Не публикуйте URL в ticket, chat history с широким доступом или screenshot.

После импорта проверьте:

- client config содержит ожидаемый server hostname/port;
- DNS и firewall пропускают declared TCP/UDP listeners;
- end-to-end request проходит через Mieru;
- old config после rotation больше не подключается.

## QR и безопасность

QR кодирует **ровно тот же** one-time `mierus://` URL, который показан текстом. Backend формирует SVG data URI из exact URL; frontend не строит второй независимый payload.

Не допускается:

- сохранять URL/QR в localStorage/sessionStorage;
- возвращать их в list API;
- записывать в audit/application logs;
- показывать viewer;
- включать в backups/screenshots/issues;
- пытаться восстановить password из hash.

Create, rotate и reveal доступны только авторизованным mutation roles и защищены CSRF там, где применимо.

## Если dialog был закрыт до передачи

Не ищите URL в DB или logs. Выполните новую rotation через **«Новая ссылка + QR»** и передайте новый credential. Это намеренно одноразовая модель.

## Мобильный интерфейс

На узких экранах QR, URL, import command и action buttons должны оставаться внутри dialog. Поддерживаемый responsive gate проверяет ширины от 320 px и отсутствие horizontal document overflow. Если страница расширяется, сравните deployed `index.html`, `app.js`, `style.css` с current source и обновите panel image.

## Troubleshooting

- **QR отсутствует:** проверьте, что используется create/rotate one-time dialog, а не list view.
- **Старая ссылка не работает:** это ожидаемо после rotation.
- **Новая ссылка импортируется, но соединения нет:** проверьте server status, listener TCP/UDP, DNS/firewall и реальный protocol probe.
- **Traffic unavailable:** это честная limitation typed adapter, а не проблема credential.
- **Viewer не видит QR:** ожидаемое RBAC поведение.

См. [Mieru deployment](../MIERU.ru.md), [operations](OPERATIONS.ru.md) и [troubleshooting](TROUBLESHOOTING.ru.md).
