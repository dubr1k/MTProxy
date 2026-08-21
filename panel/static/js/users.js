import { bytes, date, esc, initials, localDateTime, number, query } from "./common.js";
import { isCurrent } from "./state.js";

export async function refreshUsers(context, generation = null) {
  const data = await context.api("/api/users");
  if (generation !== null && !isCurrent(context.state, generation, context.state.view)) return null;
  context.state.users = data.items || [];
  const badge = query("#users-count", context.root);
  if (badge) badge.textContent = context.state.users.length;
  return context.state.users;
}

function userUsage(user) {
  const quota = Number(user.data_quota_bytes) || 0;
  if (!quota) return "Без квоты";
  return `${bytes(user.quota_used_bytes)} / ${bytes(quota)}`;
}

function filteredUsers(state) {
  const needle = state.userQuery.toLowerCase();
  return state.users.filter((user) => (
    (state.userFilter === "all"
      || (state.userFilter === "active" && user.enabled !== false)
      || (state.userFilter === "blocked" && user.enabled === false))
    && String(user.username).toLowerCase().includes(needle)
  ));
}

function userRow(context, user) {
  const enabled = user.enabled !== false;
  const connections = user.current_connections ?? user.active_connections ?? 0;
  const actions = context.state.me.role === "viewer"
    ? "Только просмотр"
    : `<button class="action-button" data-user-action="limits" data-user="${esc(user.username)}">Лимиты</button>
       <button class="action-button share" data-user-action="share" data-user="${esc(user.username)}">Ссылка</button>
       <button class="action-button" data-user-action="${enabled ? "disable" : "enable"}" data-user="${esc(user.username)}">${enabled ? "Заблокировать" : "Включить"}</button>
       <button class="action-button" data-user-action="rotate" data-user="${esc(user.username)}">Новый ключ</button>
       <button class="action-button danger-text" data-user-action="delete" data-user="${esc(user.username)}">Удалить</button>`;
  return `<div class="data-row" data-name="${esc(user.username)}">
    <div class="identity"><span class="user-glyph">${esc(initials(user.username))}</span><span><b>${esc(user.username)}</b><small>MTProto · FakeTLS</small></span></div>
    <div class="cell"><span class="status-pill ${enabled ? "active" : "blocked"}"><i></i>${enabled ? "Активен" : "Заблокирован"}</span></div>
    <div class="cell"><b>${userUsage(user)}</b><small>${number(connections)} соединений</small></div>
    <div class="row-actions">${actions}</div>
  </div>`;
}

export function paintUsers(context) {
  const list = query("#user-list", context.root);
  if (!list) return;
  const items = filteredUsers(context.state);
  list.innerHTML = items.length
    ? items.map((user) => userRow(context, user)).join("")
    : '<div class="empty-state"><span>◇</span><h3>Подключений не найдено</h3><p>Измените поиск или создайте новый доступ.</p></div>';
}

export async function renderUsers(context, generation) {
  const users = await refreshUsers(context, generation);
  if (!isCurrent(context.state, generation, "users") || users === null) return;
  const { state, ui } = context;
  ui.view.innerHTML = `<div class="toolbar">
    <div class="search"><input id="user-search" type="search" value="${esc(state.userQuery)}" placeholder="Поиск по имени" aria-label="Поиск пользователей"></div>
    <div class="filter-pills"><button class="filter-pill ${state.userFilter === "all" ? "active" : ""}" data-user-filter="all">Все · ${state.users.length}</button><button class="filter-pill ${state.userFilter === "active" ? "active" : ""}" data-user-filter="active">Активные</button><button class="filter-pill ${state.userFilter === "blocked" ? "active" : ""}" data-user-filter="blocked">Заблокированные</button></div>
  </div>
  <section class="data-panel"><div class="data-head"><span>Пользователь</span><span>Статус</span><span>Квота и подключения</span><span class="align-right">Действия</span></div><div id="user-list"></div></section>`;
  paintUsers(context);
}

export function openUserModal(context) {
  const form = query("#user-form", context.root);
  form.reset();
  query("#user-error", context.root).textContent = "";
  syncCreateButton(context);
  context.ui.openModal("#user-modal", "#new-user");
}

function syncCreateButton(context) {
  const input = query("#new-user", context.root);
  query("#create-user", context.root).disabled = !input.value || !input.checkValidity();
}

function optionalNumber(root, selector, multiplier = 1) {
  const value = query(selector, root).value;
  return value === "" ? null : Math.round(Number(value) * multiplier);
}

function openLimitsModal(context, user) {
  const { root, ui } = context;
  const form = query("#limits-form", root);
  form.reset();
  query("#limits-user", root).value = user.username;
  query("#limits-title", root).textContent = `Лимиты · ${user.username}`;
  query("#limit-quota", root).value = user.data_quota_bytes ? user.data_quota_bytes / 1_073_741_824 : "";
  query("#limit-up", root).value = user.rate_limit_up_bps ? user.rate_limit_up_bps / 1_000_000 : "";
  query("#limit-down", root).value = user.rate_limit_down_bps ? user.rate_limit_down_bps / 1_000_000 : "";
  query("#limit-connections", root).value = user.max_tcp_conns ?? "";
  query("#limit-ips", root).value = user.max_unique_ips ?? "";
  query("#limit-expiration", root).value = localDateTime(user.expiration_rfc3339);
  query("#limits-error", root).textContent = "";
  ui.openModal("#limits-modal");
}

export async function handleUserAction(context, action, username, button) {
  try {
    const { api, state, ui } = context;
    if (action === "limits") {
      const user = state.users.find((item) => item.username === username);
      if (user) openLimitsModal(context, user);
      return;
    }
    if (action === "share") {
      ui.setBusy(button, true, "Загрузка…");
      context.access.showAccess(await api(`/api/users/${encodeURIComponent(username)}/access`, { method: "POST" }), username);
      return;
    }
    const confirmations = {
      disable: ["Заблокировать доступ?", `${username} будет отключён, активные соединения будут закрыты.`, "Заблокировать"],
      enable: ["Разблокировать доступ?", `${username} снова сможет подключаться к прокси.`, "Разблокировать"],
      rotate: ["Создать новый ключ?", `Старая ссылка ${username} перестанет работать. Сохраните новый QR-код после ротации.`, "Обновить ключ"],
      delete: ["Удалить подключение?", `${username} будет удалён без возможности восстановления.`, "Удалить"],
    };
    const prompt = confirmations[action];
    if (prompt && !await ui.confirmed(...prompt)) return;

    ui.setBusy(button, true);
    if (action === "delete") {
      await api(`/api/users/${encodeURIComponent(username)}`, { method: "DELETE" });
    } else {
      const data = await api(`/api/users/${encodeURIComponent(username)}/${action}`, { method: "POST" });
      if (action === "rotate") await context.access.revealToken(data.reveal_token, username);
    }
    ui.toast({ delete: "Подключение удалено", disable: "Доступ заблокирован", enable: "Доступ разблокирован", rotate: "Ключ обновлён" }[action]);
    await context.navigate("users");
  } catch (error) {
    context.ui.toast(error.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

export function bindUsers(context) {
  const { root, api, ui } = context;
  query("#new-user", root)?.addEventListener("input", () => syncCreateButton(context));
  query("#create-user", root)?.addEventListener("click", async (event) => {
    const input = query("#new-user", root);
    const error = query("#user-error", root);
    error.textContent = "";
    if (!input.reportValidity()) return;
    try {
      ui.setBusy(event.currentTarget, true, "Создаём…");
      const data = await api("/api/users", { method: "POST", body: JSON.stringify({ username: input.value }) });
      const access = await api(`/api/reveal/${encodeURIComponent(data.reveal_token)}`);
      query("#user-modal", root).close();
      context.access.showAccess(access, input.value);
      ui.toast("Доступ создан");
      await context.navigate("users");
    } catch (error) {
      error && (query("#user-error", root).textContent = error.message);
    } finally {
      ui.setBusy(event.currentTarget, false);
      syncCreateButton(context);
    }
  });
  query("#save-limits", root)?.addEventListener("click", async (event) => {
    const form = query("#limits-form", root);
    const error = query("#limits-error", root);
    if (!form.reportValidity()) return;
    const username = query("#limits-user", root).value;
    const expiration = query("#limit-expiration", root).value;
    const payload = {
      data_quota_bytes: optionalNumber(root, "#limit-quota", 1_073_741_824),
      rate_limit_up_bps: optionalNumber(root, "#limit-up", 1_000_000),
      rate_limit_down_bps: optionalNumber(root, "#limit-down", 1_000_000),
      max_tcp_conns: optionalNumber(root, "#limit-connections"),
      max_unique_ips: optionalNumber(root, "#limit-ips"),
      expiration_rfc3339: expiration ? new Date(expiration).toISOString() : null,
    };
    error.textContent = "";
    try {
      ui.setBusy(event.currentTarget, true, "Сохраняем…");
      await api(`/api/users/${encodeURIComponent(username)}/limits`, { method: "POST", body: JSON.stringify(payload) });
      query("#limits-modal", root).close();
      ui.toast("Лимиты сохранены");
      await context.navigate("users");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(event.currentTarget, false);
    }
  });
  query("#reset-quota", root)?.addEventListener("click", async (event) => {
    const username = query("#limits-user", root).value;
    if (!await ui.confirmed("Сбросить счётчик трафика?", `Накопленный расход ${username} станет равен нулю. Сам лимит сохранится.`, "Сбросить")) return;
    try {
      ui.setBusy(event.currentTarget, true);
      await api(`/api/users/${encodeURIComponent(username)}/reset-quota`, { method: "POST" });
      query("#limits-modal", root).close();
      ui.toast("Счётчик трафика сброшен");
      await context.navigate("users");
    } catch (error) {
      query("#limits-error", root).textContent = error.message;
    } finally {
      ui.setBusy(event.currentTarget, false);
    }
  });
}

export function handleUsersInput(context, target) {
  if (target.id !== "user-search") return false;
  context.state.userQuery = target.value;
  paintUsers(context);
  return true;
}

export function handleUsersClick(context, button) {
  if (button.dataset.userFilter) {
    context.state.userFilter = button.dataset.userFilter;
    context.ui.view.querySelectorAll("[data-user-filter]").forEach((item) => item.classList.toggle("active", item === button));
    paintUsers(context);
    return true;
  }
  if (button.dataset.userAction && button.dataset.user) {
    void handleUserAction(context, button.dataset.userAction, button.dataset.user, button);
    return true;
  }
  return false;
}
