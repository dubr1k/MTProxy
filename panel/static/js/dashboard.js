import { bytes, esc, icon, number, query } from "./common.js";
import { isCurrent } from "./state.js";
import { refreshUsers } from "./users.js";

async function fleetCount(context) {
  try {
    return ((await context.api("/api/fleet/nodes")).items || []).length;
  } catch {
    return null;
  }
}

function paintNavCounts(context, data, nodes) {
  const protocols = data.protocols || {};
  const set = (selector, credentials) => {
    const badge = query(selector, context.root);
    if (badge) badge.textContent = credentials && credentials.available !== false && credentials.total != null
      ? credentials.total
      : "—";
  };
  set("#mieru-count", protocols.mieru?.credentials);
  set("#naive-count", protocols.naive?.credentials);
  const fleet = query("#fleet-count", context.root);
  if (fleet) fleet.textContent = nodes ?? "—";
}

export async function renderDashboard(context, generation) {
  const { api, root, state, ui } = context;
  const [data, users, nodes] = await Promise.all([
    api("/api/dashboard"),
    refreshUsers(context, generation),
    fleetCount(context),
  ]);
  paintNavCounts(context, data, nodes);
  if (!isCurrent(state, generation, "dashboard") || users === null) return;

  const mt = data.protocols?.mtproxy || {};
  const naive = data.protocols?.naive || { available: false, status: "disabled" };
  const mieru = data.protocols?.mieru || { available: false, status: "disabled" };
  const mtReady = mt.ready === true;
  const naiveReady = naive.ready === true;
  const naiveAvailable = naive.available === true;
  const mieruReady = mieru.ready === true;
  const mieruAvailable = mieru.available === true;
  const allReady = mtReady && (!naiveAvailable || naiveReady) && (!mieruAvailable || mieruReady);
  const system = query(".system-mini", root);
  system.classList.toggle("degraded", !allReady);
  query("b", system).textContent = allReady ? "Прокси-сервисы работают" : "Есть неполадки";
  query("small", system).textContent = allReady ? "Сводка актуальна" : "Откройте обзор состояния";

  if (naiveAvailable) state.naiveService = { ready: naiveReady, host: naive.host || state.naiveService.host };
  const mtCredentials = mt.credentials || {};
  const naiveCredentials = naive.credentials || {};
  const naiveState = !naiveAvailable ? "Функция отключена" : naiveReady ? "Manager работает" : "NaiveProxy недоступен";
  const naiveStatus = !naiveAvailable ? "Отключён" : naiveReady ? "Работает" : "Сбой manager";
  const naiveAccess = naiveCredentials.available === false
    ? "Данные недоступны"
    : `${number(naiveCredentials.active)} активных · ${number(naiveCredentials.disabled)} отключённых`;

  ui.view.innerHTML = `<div class="protocol-overview">
    <article class="protocol-card ${mtReady ? "" : "degraded"}">
      <div class="protocol-head"><span><small>MTProto · FakeTLS</small><h2>MTProxy</h2></span><span class="status-pill ${mtReady ? "active" : "blocked"}"><i></i>${mtReady ? "Работает" : "Недоступен"}</span></div>
      <div class="protocol-access"><span><small>Активные доступы</small><strong>${number(mtCredentials.active)}</strong></span><span><small>Отключённые</small><strong>${number(mtCredentials.disabled)}</strong></span></div>
      <div class="protocol-metrics"><span><small>Соединения сейчас</small><b>${number(mt.runtime?.current_connections)}</b></span><span><small>Активные IP</small><b>${number(mt.runtime?.active_ips)}</b></span><span><small>Runtime-трафик</small><b>${bytes(mt.runtime?.traffic_octets)}</b><em>Для текущего runtime-поколения; не квота</em></span></div>
    </article>
    <article class="protocol-card ${mieruReady ? "" : "degraded"}">
      <div class="protocol-head"><span><small>Native AEAD · TCP/UDP</small><h2>Mieru</h2></span><span class="status-pill ${mieruReady ? "active" : "blocked"}"><i></i>${!mieruAvailable ? "Отключён" : mieruReady ? "Работает" : "Недоступен"}</span></div>
      <div class="protocol-access"><span><small>Активные доступы</small><strong>${number(mieru.credentials?.active)}</strong></span><span><small>Отключённые</small><strong>${number(mieru.credentials?.disabled)}</strong></span></div>
      <div class="protocol-metrics"><span><small>Application bytes</small><b>${mieru.traffic?.available ? bytes(mieru.traffic?.bytes) : "—"}</b><em>rolling admission quota (approximate), не hard cap</em></span></div>
    </article>
    <article class="protocol-card naive-card ${naiveReady ? "" : "degraded"}">
      <div class="protocol-head"><span><small>HTTPS · HTTP/2 CONNECT</small><h2>NaiveProxy</h2></span><span class="status-pill ${naiveReady ? "active" : "blocked"}"><i></i>${naiveStatus}</span></div>
      <p class="protocol-note">${naiveState}${naive.host ? ` · ${esc(naive.host)}` : ""}</p>
      <div class="protocol-access"><span><small>Доступы</small><strong>${naiveCredentials.available === false ? "—" : number(naiveCredentials.active)}</strong></span><span><small>Отключённые</small><strong>${naiveCredentials.available === false ? "—" : number(naiveCredentials.disabled)}</strong></span></div>
      <div class="traffic-unavailable"><span>${icon("transfer")}</span><span><b>↑ ${bytes(naive.traffic?.aggregate?.upload_bytes_decimal)} · ↓ ${bytes(naive.traffic?.aggregate?.download_bytes_decimal)} · Σ ${bytes(naive.traffic?.aggregate?.total_bytes_decimal)}</b><small>Только закрытые CONNECT-туннели; активные появятся после закрытия</small></span></div><small class="protocol-caption">${naiveAccess}</small>
    </article>
  </div>
  <div class="dashboard-grid"><section class="panel-card"><div class="panel-head"><h2>Состояние сервисов</h2><span>обновлено сейчас</span></div><div class="service-list">
    <div class="service-row ${mtReady ? "" : "degraded"}"><i></i><span><b>MTProxy · Telemt</b><small>${mtReady ? "Control API отвечает" : "Проверьте Telemt"}</small></span><em>${esc(mt.status || "degraded")}</em></div>
    <div class="service-row ${naiveReady || !naiveAvailable ? "" : "degraded"}"><i></i><span><b>NaiveProxy · manager</b><small>${naiveState}</small></span><em>${esc(naive.status)}</em></div>
    <div class="service-row ${location.protocol === "https:" ? "" : "degraded"}"><i></i><span><b>Proxy Control</b><small>${location.protocol === "https:" ? "HTTPS · защищённое соединение" : "HTTP · соединение не защищено"}</small></span><em>${location.protocol === "https:" ? "secure" : "insecure"}</em></div>
  </div></section></div>`;
}
