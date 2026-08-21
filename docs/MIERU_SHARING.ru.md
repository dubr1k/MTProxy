# Выдача конфигураций Mieru

[English](MIERU_SHARING.en.md) · **Русский**

Proxy Control выдаёт Mieru credentials только после **create** или **controlled rotation**. List API, таблицы UI и audit никогда не содержат password, `mierus://` URL, QR payload или reveal token.

## Создание нового доступа

1. Откройте раздел **Mieru**.
2. Нажмите **Добавить**.
3. Укажите username и, при необходимости, rolling quota/expiry.
4. После создания откроется one-time dialog.
5. Выберите целевой client:
   - **Native**: скопируйте штатную `mierus://` URL или shell-safe command `mieru import config 'mierus://…'`; QR содержит ровно эту URL.
   - **Karing**: откройте или отсканируйте `karing://install-config` deep link с полным Mieru sing-box profile либо скачайте этот JSON profile. Вариант доступен, только когда все bindings содержат точные одиночные порты.
   - **Shadowrocket**: не предлагается. Проверенного Mieru import format нет, и Proxy Control его не придумывает.
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

## Матрица клиентов

| Client | Mieru с точными портами | Доступ с port range | QR payload |
| --- | --- | --- | --- |
| Official Mieru | `mierus://`, import command | Поддерживается | Показанная `mierus://` URL |
| Karing | Полный Mieru sing-box profile, download и `karing://install-config` | Не предлагается | Karing deep link с полным profile |
| Shadowrocket | Не предлагается; проверенного формата нет | Не предлагается | Нет |

Используйте official Mieru client, совместимый с server `mita` 3.35.x, либо текущий Karing build. [Официальная инструкция Mieru](https://github.com/enfein/mieru/blob/main/docs/client-install.md) определяет `mierus://`, `mieru import config` и поля Mieru outbound для sing-box. Karing документирует импорт config content и [URL scheme](https://karing.app/en/cooperation/scheme); текущий source Karing содержит Mieru outbound type.

После импорта проверьте ожидаемые hostname/port, доступность declared TCP/UDP listeners, end-to-end transport и отказ старого config после rotation. Не публикуйте credential payload в общедоступных tickets, chats или screenshots.

## QR и безопасность

QR зависит от выбранного client. Для **Native** он кодирует ровно показанную `mierus://` URL. Для **Karing** — ровно показанную `karing://install-config` deep link, где параметр `url` содержит полный Mieru profile. QR никогда не подменяется raw HTTP endpoint или форматом неподдерживаемого client. Backend создаёт SVG из declared payload, а frontend отклоняет QR metadata, не совпадающую с выбранным payload.

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

Client tabs прокручиваются горизонтально, а QR, payload, import command, notice о неподдерживаемом client и action buttons складываются внутри dialog на узких экранах. Responsive gates покрывают ширины от 320 px и требуют отсутствия horizontal document overflow. Выбранный client управляет и видимым payload, и QR; при закрытии dialog очищаются все варианты и отзываются сгенерированные download URLs.

## Troubleshooting

- **QR отсутствует:** проверьте, что используется create/rotate one-time dialog, а не list view.
- **Старая ссылка не работает:** это ожидаемо после rotation.
- **Новая ссылка импортируется, но соединения нет:** проверьте server status, listener TCP/UDP, DNS/firewall и реальный protocol probe.
- **Traffic unavailable:** это честная limitation typed adapter, а не проблема credential.
- **Viewer не видит QR:** ожидаемое RBAC поведение.

См. [Mieru deployment](../MIERU.ru.md), [operations](OPERATIONS.ru.md) и [troubleshooting](TROUBLESHOOTING.ru.md).
