export function query(selector, root = document) {
  return root.querySelector(selector);
}

export function queryAll(selector, root = document) {
  return [...root.querySelectorAll(selector)];
}

export function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]);
}

export function icon(name) {
  const shapes = {
    status: '<circle cx="12" cy="12" r="7"/><circle cx="12" cy="12" r="2"/>',
    key: '<path d="M14 7a5 5 0 1 0 3 9l4-4-3-3-2 2-2-2"/>',
    activity: '<path d="M4 13h4l2-5 4 9 2-5h4"/>',
    transfer: '<path d="m8 7 4-4 4 4M12 3v14m4 0-4 4-4-4"/>',
    check: '<path d="m6 12 4 4 8-9"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    manage: '<path d="M5 7h14M8 12h8M10 17h4"/>',
    refresh: '<path d="M20 7v5h-5M19 12a7 7 0 1 0-2 5"/>',
  };
  return `<svg class="ui-icon" viewBox="0 0 24 24" aria-hidden="true">${shapes[name] || ""}</svg>`;
}

export function initials(name) {
  return String(name || "?").slice(0, 2).toUpperCase();
}

export function number(value) {
  return new Intl.NumberFormat("ru-RU").format(Number(value) || 0);
}

export function bytes(value) {
  let count;
  try {
    count = BigInt(String(value ?? 0));
    if (count < 0n) throw new Error("negative byte count");
  } catch {
    return "0 Б";
  }

  const units = ["Б", "КБ", "МБ", "ГБ", "ТБ", "ПБ"];
  let unit = 0;
  let scale = 1n;
  while (unit < units.length - 1 && count >= scale * 1024n) {
    scale *= 1024n;
    unit += 1;
  }
  if (unit === 0) return `${count} ${units[unit]}`;

  const tenths = (count * 10n + scale / 2n) / scale;
  const valueText = tenths < 100n
    ? `${tenths / 10n}.${tenths % 10n}`
    : String((count + scale / 2n) / scale);
  return `${valueText} ${units[unit]}`;
}

export function sumNaiveTraffic(users) {
  return users.reduce((total, user) => total + BigInt(String(user.total_bytes_decimal ?? "0")), 0n);
}

export function date(value) {
  if (!value) return "—";
  const numeric = Number(value);
  const result = new Date(numeric ? (numeric < 1e12 ? numeric * 1000 : numeric) : value);
  if (Number.isNaN(result.valueOf())) return "—";
  return result.toLocaleString("ru-RU", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function localDateTime(value) {
  if (!value) return "";
  const result = new Date(value);
  if (Number.isNaN(result.valueOf())) return "";
  const local = new Date(result.getTime() - result.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}

export function serialise(value) {
  try {
    return JSON.stringify(value ?? {}, null, 2);
  } catch {
    return "Не удалось отобразить детали";
  }
}

export function cssEscape(value) {
  if (globalThis.CSS?.escape) return globalThis.CSS.escape(value);
  return String(value).replace(/[^A-Za-z0-9_-]/g, "\\$&");
}
