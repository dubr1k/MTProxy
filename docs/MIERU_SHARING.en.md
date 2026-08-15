# Sharing Mieru configurations

**English** · [Русский](MIERU_SHARING.ru.md)

Proxy Control discloses Mieru credentials only after **create** or **controlled rotation**. List APIs, UI tables, and audit never contain passwords, `mierus://` URLs, QR payloads, or reveal tokens.

## Create access

1. Open **Mieru**.
2. Select **Add**.
3. Enter username and optional rolling quota/expiry.
4. A one-time dialog opens after creation.
5. Give the user one of:
   - QR code;
   - `mierus://` URL;
   - generated `mieru import config 'mierus://…'` command;
   - downloaded QR image.
6. Confirm import, then close the dialog.

The reveal response carries `Cache-Control: no-store`. URL and QR exist in frontend only inside the ephemeral dialog and are cleared on close.

## Reissue for an existing user

Mita stores `hashedPassword`; plaintext cannot be recovered. The previous URL/QR therefore cannot be safely displayed after one-time reveal expires.

Select **New link + QR**. The panel:

1. generates a new credential;
2. performs controlled restart/reload under Mieru transaction policy;
3. invalidates the previous client configuration;
4. displays a new one-time URL and QR.

Warn the user that the old config stops working as soon as rotation succeeds.

## Client import

Use a client compatible with server `mita` 3.35.x. The UI provides a shell-safe import command. Never paste the URL into a broadly visible ticket/chat or screenshot.

After import verify expected hostname/port, declared TCP/UDP listener reachability, end-to-end transport, and rejection of the old config after rotation.

## QR security contract

The QR encodes **the exact same** one-time `mierus://` URL shown as text. Backend creates an SVG data URI from the exact URL; frontend never constructs a second independent credential payload.

Never:

- store URL/QR in localStorage or sessionStorage;
- return them from list APIs;
- write them to audit/application logs;
- reveal them to a viewer;
- include them in backups, screenshots, or issues;
- attempt to recover password from a hash.

Create, rotate, and reveal require authorized mutation roles and CSRF where applicable.

## Dialog closed too early

Do not search the DB or logs. Perform another **New link + QR** rotation and deliver the new credential. One-time disclosure is intentional.

## Mobile UI

QR, URL, import command, and actions must stay inside the dialog on narrow screens. Responsive gates cover widths from 320 px and require zero horizontal document overflow. If the page widens, compare deployed `index.html`, `app.js`, and `style.css` to current source, then rebuild the panel image.

## Troubleshooting

- **No QR:** use the create/rotate one-time dialog, not list view.
- **Old link fails:** expected after rotation.
- **New link imports but cannot connect:** check server status, TCP/UDP listener, DNS/firewall, and real protocol probe.
- **Traffic unavailable:** this is an honest adapter limitation, not a credential problem.
- **Viewer sees no QR:** expected RBAC behavior.

See [Mieru deployment](../MIERU.en.md), [operations](OPERATIONS.en.md), and [troubleshooting](TROUBLESHOOTING.en.md).
