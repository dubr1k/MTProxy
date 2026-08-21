import { query } from "./common.js";

function validServer(value) {
  if (/^[A-Za-z0-9.-]{1,253}$/.test(value)) return true;
  if (!/^[0-9A-Fa-f:.]+$/.test(value) || !value.includes(":")) return false;
  try {
    new URL(`http://[${value}]/`);
    return true;
  } catch {
    return false;
  }
}

function proxyLink(value) {
  try {
    const url = new URL(value);
    const allowed = (url.protocol === "tg:" && url.hostname === "proxy" && ["", "/"].includes(url.pathname))
      || (url.protocol === "https:" && ["t.me", "telegram.me"].includes(url.hostname) && url.pathname === "/proxy");
    const keys = [...url.searchParams.keys()];
    const server = url.searchParams.getAll("server");
    const port = url.searchParams.getAll("port");
    const secret = url.searchParams.getAll("secret");
    if (!allowed || url.hash || keys.length !== 3 || new Set(keys).size !== 3
      || server.length !== 1 || port.length !== 1 || secret.length !== 1
      || !validServer(server[0]) || !/^[0-9]{1,5}$/.test(port[0])
      || Number(port[0]) < 1 || Number(port[0]) > 65535
      || !/^[0-9A-Fa-f]{32,512}$/.test(secret[0])) throw new Error("invalid proxy link");
    return value;
  } catch {
    throw new Error("Сервис вернул некорректную ссылку подключения");
  }
}

function qrSource(value) {
  if (typeof value !== "string" || value.length > 500_000
    || !/^data:image\/svg\+xml;base64,[A-Za-z0-9+/=]+$/.test(value)) {
    throw new Error("Сервис вернул некорректный QR-код");
  }
  return value;
}

function shellQuote(value) {
  return `'${String(value).replaceAll("'", "'\"'\"'")}'`;
}

export function createAccessDialogs(context) {
  const { root, state, api, ui } = context;
  let naiveConfigText = "";
  let naiveConfigUrl = "";

  function naiveProxyUrl(value, username) {
    try {
      const url = new URL(value);
      if (url.protocol !== "https:" || url.hostname !== state.naiveService.host || !url.password
        || decodeURIComponent(url.username) !== username || !["", "443"].includes(url.port)
        || !["", "/"].includes(url.pathname) || url.search || url.hash) throw new Error("invalid Naive URL");
      return value;
    } catch {
      throw new Error("Сервис вернул некорректную NaiveProxy-конфигурацию");
    }
  }

  function showAccess(data, username) {
    const link = proxyLink(data.link);
    const qr = qrSource(data.qr);
    query("#access-title", root).textContent = `Доступ · ${username}`;
    query("#access-link", root).value = link;
    query("#qr-image", root).src = qr;
    query("#open-telegram", root).href = link;
    query("#download-qr", root).href = qr;
    query("#download-qr", root).download = `mtproxy-${username}.svg`;
    ui.openModal("#access-modal");
  }

  async function revealToken(token, username) {
    showAccess(await api(`/api/reveal/${encodeURIComponent(token)}`), username);
  }

  function showMieruAccess(data, username) {
    const link = String(data.share_url || "");
    const qr = qrSource(data.qr);
    if (!link.startsWith("mierus://") || link.length > 4096) throw new Error("Некорректная Mieru-ссылка");
    query("#mieru-access-title", root).textContent = `Mieru · ${username}`;
    query("#mieru-share-url", root).value = link;
    query("#mieru-import-command", root).value = `mieru import config ${shellQuote(link)}`;
    query("#mieru-qr-image", root).src = qr;
    query("#download-mieru-qr", root).href = qr;
    query("#download-mieru-qr", root).download = `mieru-${username}.svg`;
    ui.openModal("#mieru-access-modal");
  }

  async function revealMieruToken(token, username) {
    showMieruAccess(await api(`/api/reveal/${encodeURIComponent(token)}`), username);
  }

  function showNaiveAccess(data, username) {
    const url = naiveProxyUrl(data.proxy_url, username);
    const qr = qrSource(data.qr);
    naiveConfigText = JSON.stringify({ listen: "socks://127.0.0.1:1080", proxy: url }, null, 2);
    if (naiveConfigUrl) URL.revokeObjectURL(naiveConfigUrl);
    naiveConfigUrl = URL.createObjectURL(new Blob([`${naiveConfigText}\n`], { type: "application/json" }));
    query("#naive-access-title", root).textContent = `NaiveProxy · ${username}`;
    query("#naive-proxy-url", root).value = url;
    query("#naive-qr-image", root).src = qr;
    const download = query("#download-naive-config", root);
    download.href = naiveConfigUrl;
    download.download = `naive-${username}.json`;
    ui.openModal("#naive-access-modal");
  }

  async function revealNaiveToken(token, username) {
    showNaiveAccess(await api(`/api/reveal/${encodeURIComponent(token)}`), username);
  }

  function bind() {
    query("#copy-link", root)?.addEventListener("click", async () => {
      await ui.copyText(query("#access-link", root));
      ui.toast("Ссылка скопирована");
    });
    query("#access-modal", root)?.addEventListener("close", () => {
      query("#access-link", root).value = "";
      query("#qr-image", root).removeAttribute("src");
      query("#open-telegram", root).removeAttribute("href");
      query("#download-qr", root).removeAttribute("href");
    });
    query("#copy-mieru-url", root)?.addEventListener("click", async () => {
      await ui.copyText(query("#mieru-share-url", root));
      ui.toast("Mieru-ссылка скопирована");
    });
    query("#copy-mieru-command", root)?.addEventListener("click", async () => {
      await ui.copyText(query("#mieru-import-command", root));
      ui.toast("Команда импорта скопирована");
    });
    query("#mieru-access-modal", root)?.addEventListener("close", () => {
      query("#mieru-share-url", root).value = "";
      query("#mieru-import-command", root).value = "";
      query("#mieru-qr-image", root).removeAttribute("src");
      query("#download-mieru-qr", root).removeAttribute("href");
    });
    query("#copy-naive-url", root)?.addEventListener("click", async () => {
      await ui.copyText(query("#naive-proxy-url", root));
      ui.toast("NaiveProxy URL скопирован");
    });
    query("#copy-naive-config", root)?.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(naiveConfigText);
      } catch {
        const input = query("#naive-proxy-url", root);
        input.select();
        document.execCommand("copy");
      }
      ui.toast("config.json скопирован");
    });
    query("#naive-access-modal", root)?.addEventListener("close", () => {
      query("#naive-proxy-url", root).value = "";
      query("#naive-qr-image", root).removeAttribute("src");
      query("#download-naive-config", root).removeAttribute("href");
      if (naiveConfigUrl) URL.revokeObjectURL(naiveConfigUrl);
      naiveConfigText = "";
      naiveConfigUrl = "";
    });
  }

  return { bind, revealToken, revealMieruToken, revealNaiveToken, showAccess, showMieruAccess, showNaiveAccess };
}
