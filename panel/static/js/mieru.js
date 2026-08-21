import { bytes, esc, initials, number, query } from "./common.js";
import { isCurrent } from "./state.js";

export async function refreshMieru(context, generation = null) {
  const data = await context.api("/api/mieru/users");
  if (generation !== null && !isCurrent(context.state, generation, context.state.view)) return null;
  context.state.mieruUsers = data.items || [];
  context.state.mieruService = data.service || { ready: false, revision: "" };
  const badge = query("#mieru-count", context.root);
  if (badge) badge.textContent = context.state.mieruUsers.length;
  return context.state.mieruUsers;
}

function quotaSummary(quotas) {
  if (!Array.isArray(quotas) || !quotas.length) return "Без rolling-квоты";
  return quotas.map((quota) => `${number(quota.megabytes)} MiB / ${number(quota.days)} дн.`).join(" · ");
}

function mieruRow(context, user) {
  const enabled = user.enabled === true;
  const traffic = user.traffic_available === true
    ? `<b>↑ ${bytes(user.upload_bytes)} · ↓ ${bytes(user.download_bytes)}</b><small>application bytes · rolling quota approximate</small>`
    : "<b>Недоступно</b><small>mita v3.35 не предоставляет типизированную историю трафика</small>";
  const actions = context.state.me.role === "viewer"
    ? "Только просмотр"
    : `<button class="action-button" data-mieru-action="quotas" data-user="${esc(user.username)}">Квота</button>
       <button class="action-button" data-mieru-action="${enabled ? "disable" : "enable"}" data-user="${esc(user.username)}">${enabled ? "Отключить" : "Включить"}</button>
       <button class="action-button" data-mieru-action="rotate" data-user="${esc(user.username)}">Новая ссылка + QR</button>
       <button class="action-button danger-text" data-mieru-action="delete" data-user="${esc(user.username)}">Удалить</button>`;
  return `<div class="data-row naive-grid">
    <div class="identity"><span class="user-glyph">${esc(initials(user.username))}</span><span><b>${esc(user.username)}</b><small>Mieru · native AEAD</small></span></div>
    <div class="cell"><span class="status-pill ${enabled ? "active" : "blocked"}"><i></i>${enabled ? "Активен" : "Отключён"}</span><small>${esc(quotaSummary(user.quotas))}</small></div>
    <div class="cell">${traffic}</div>
    <div class="row-actions">${actions}</div>
  </div>`;
}

export async function renderMieru(context, generation) {
  const users = await refreshMieru(context, generation);
  if (!isCurrent(context.state, generation, "mieru") || users === null) return;
  const ready = context.state.mieruService.ready === true;
  context.ui.view.innerHTML = `<div class="security-note">Квоты Mieru — rolling application-byte admission quota (approximate): проверяются при открытии сессии и не являются hard cap.</div>
  <div class="naive-overview"><article><small>mita v3.35</small><strong>${ready ? "RUNNING" : "DEGRADED"}</strong><span class="status-pill ${ready ? "active" : "blocked"}"><i></i>${ready ? "Ready" : "Ошибка"}</span></article><article><small>Пользователи</small><strong>${number(users.length)}</strong><span>revision ${esc(context.state.mieruService.revision || "—")}</span></article></div>
  <section class="data-panel"><div class="data-head naive-grid"><span>Пользователь</span><span>Статус и квота</span><span>Трафик</span><span class="align-right">Действия</span></div>${users.length ? users.map((user) => mieruRow(context, user)).join("") : '<div class="empty-state"><h3>Mieru-доступов нет</h3><p>Добавьте доступ, чтобы выдать конфигурацию с one-time reveal.</p></div>'}</section>`;
}

function quotaRow(quota = {}) {
  return `<div class="quota-row" data-mieru-quota-row>
    <label>Окно, дней<input data-mieru-quota-days type="number" min="1" max="3650" step="1" inputmode="numeric" value="${esc(quota.days ?? "")}" aria-label="Окно квоты в днях"></label>
    <label>Квота, MiB<input data-mieru-quota-mib type="number" min="1" max="2147483647" step="1" inputmode="numeric" value="${esc(quota.megabytes ?? "")}" aria-label="Размер квоты в MiB"></label>
    <button class="icon-button quota-remove" type="button" data-mieru-quota-remove aria-label="Удалить квоту">×</button>
  </div>`;
}

function renderQuotaRows(context, quotas = []) {
  const rows = query("#mieru-quota-rows", context.root);
  rows.innerHTML = quotas.length
    ? quotas.map((quota) => quotaRow(quota)).join("")
    : '<p class="form-hint" id="mieru-unlimited-note">Без rolling-квоты: доступ не ограничен квотой Mieru.</p>';
  query("#add-mieru-quota", context.root).disabled = quotas.length >= 16;
}

function collectQuotaRows(context) {
  const rows = [...context.root.querySelectorAll("[data-mieru-quota-row]")];
  const quotas = [];
  for (const row of rows) {
    const days = query("[data-mieru-quota-days]", row).value.trim();
    const megabytes = query("[data-mieru-quota-mib]", row).value.trim();
    if (!days && !megabytes) continue;
    if (!days || !megabytes) throw new Error("Заполните и окно в днях, и квоту в MiB — либо удалите строку");
    quotas.push({ days: Number(days), megabytes: Number(megabytes) });
  }
  return quotas;
}

function createQuotas(context) {
  const days = query("#mieru-days", context.root).value.trim();
  const megabytes = query("#mieru-mib", context.root).value.trim();
  if (!days && !megabytes) return [];
  if (!days || !megabytes) throw new Error("Заполните и окно в днях, и квоту в MiB — либо очистите оба поля для безлимита");
  return [{ days: Number(days), megabytes: Number(megabytes) }];
}

function syncMieruCreateButton(context) {
  const form = query("#mieru-form", context.root);
  query("#create-mieru", context.root).disabled = !form.checkValidity();
}

export function openMieruModal(context) {
  query("#mieru-form", context.root).reset();
  query("#mieru-error", context.root).textContent = "";
  syncMieruCreateButton(context);
  context.ui.openModal("#mieru-modal", "#new-mieru-user");
}

function openMieruQuotaModal(context, user) {
  const form = query("#mieru-quota-form", context.root);
  form.reset();
  query("#mieru-quota-user", context.root).value = user.username;
  query("#mieru-quota-title", context.root).textContent = `Квота · ${user.username}`;
  query("#mieru-quota-error", context.root).textContent = "";
  const quotas = Array.isArray(user.quotas) ? user.quotas : [];
  renderQuotaRows(context, quotas);
  context.ui.openModal("#mieru-quota-modal", quotas.length ? "[data-mieru-quota-days]" : "#add-mieru-quota");
}

export async function handleMieruAction(context, action, username, button) {
  try {
    const { api, state, ui } = context;
    if (action === "quotas") {
      const user = state.mieruUsers.find((item) => item.username === username);
      if (user) openMieruQuotaModal(context, user);
      return;
    }
    const labels = {
      enable: "включить",
      disable: "отключить",
      rotate: "выпустить новую ссылку",
      delete: "удалить",
    };
    if (!await ui.confirmed("Изменить Mieru-доступ?", `${labels[action]} для ${username}. Ротация и отзыв принудительно перезапускают mita.`, "Продолжить")) return;
    ui.setBusy(button, true);
    const revision = state.mieruService.revision;
    let data;
    if (action === "delete") {
      data = await api(`/api/mieru/users/${encodeURIComponent(username)}`, { method: "DELETE", body: JSON.stringify({ expected_revision: revision }) });
    } else {
      data = await api(`/api/mieru/users/${encodeURIComponent(username)}/${action}`, { method: "POST", body: JSON.stringify({ expected_revision: revision }) });
    }
    if (action === "rotate") await context.access.revealMieruToken(data.reveal_token, username);
    ui.toast("Mieru-доступ обновлён");
    await context.navigate("mieru");
  } catch (error) {
    context.ui.toast(error.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

export function bindMieru(context) {
  const { api, root, ui } = context;
  query("#mieru-form", root)?.addEventListener("input", () => syncMieruCreateButton(context));
  query("#mieru-form", root)?.addEventListener("submit", (event) => {
    event.preventDefault();
    query("#create-mieru", root).click();
  });
  query("#mieru-quota-form", root)?.addEventListener("submit", (event) => {
    event.preventDefault();
    query("#save-mieru-quota", root).click();
  });
  query("#create-mieru", root)?.addEventListener("click", async (event) => {
    const form = query("#mieru-form", root);
    const error = query("#mieru-error", root);
    error.textContent = "";
    if (!form.reportValidity()) return;
    const username = query("#new-mieru-user", root).value;
    try {
      ui.setBusy(event.currentTarget, true);
      const data = await api("/api/mieru/users", {
        method: "POST",
        body: JSON.stringify({ username, quotas: createQuotas(context), expected_revision: context.state.mieruService.revision }),
      });
      const access = await api(`/api/reveal/${encodeURIComponent(data.reveal_token)}`);
      query("#mieru-modal", root).close();
      context.access.showMieruAccess(access, username);
      ui.toast("Mieru-доступ создан");
      await context.navigate("mieru");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(event.currentTarget, false);
      syncMieruCreateButton(context);
    }
  });
  query("#add-mieru-quota", root)?.addEventListener("click", () => {
    const current = [...root.querySelectorAll("[data-mieru-quota-row]")];
    if (current.length >= 16) return;
    const rows = query("#mieru-quota-rows", root);
    query("#mieru-unlimited-note", root)?.remove();
    rows.insertAdjacentHTML("beforeend", quotaRow());
    query("#add-mieru-quota", root).disabled = current.length + 1 >= 16;
    query("[data-mieru-quota-days]", rows.lastElementChild)?.focus();
  });
  query("#mieru-quota-rows", root)?.addEventListener("click", (event) => {
    const remove = event.target.closest("[data-mieru-quota-remove]");
    if (!remove) return;
    remove.closest("[data-mieru-quota-row]").remove();
    const quotas = [...root.querySelectorAll("[data-mieru-quota-row]")];
    if (!quotas.length) renderQuotaRows(context, []);
    else query("#add-mieru-quota", root).disabled = quotas.length >= 16;
  });
  query("#save-mieru-quota", root)?.addEventListener("click", async (event) => {
    const form = query("#mieru-quota-form", root);
    const error = query("#mieru-quota-error", root);
    error.textContent = "";
    if (!form.reportValidity()) return;
    try {
      const quotas = collectQuotaRows(context);
      const username = query("#mieru-quota-user", root).value;
      ui.setBusy(event.currentTarget, true, "Сохраняем…");
      await api(`/api/mieru/users/${encodeURIComponent(username)}/quotas`, {
        method: "POST",
        body: JSON.stringify({ quotas, expected_revision: context.state.mieruService.revision }),
      });
      query("#mieru-quota-modal", root).close();
      ui.toast("Квота Mieru сохранена");
      await context.navigate("mieru");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(event.currentTarget, false);
    }
  });
}

export function handleMieruClick(context, button) {
  if (!button.dataset.mieruAction || !button.dataset.user) return false;
  void handleMieruAction(context, button.dataset.mieruAction, button.dataset.user, button);
  return true;
}
