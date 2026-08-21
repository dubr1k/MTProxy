import { cssEscape, date, esc, initials, query } from "./common.js";
import { isCurrent } from "./state.js";

const ROLE_NAMES = { owner: "Владелец", admin: "Администратор", viewer: "Наблюдатель" };

export { ROLE_NAMES };

export async function renderVersions(context, generation) {
  const data = await context.api("/api/versions");
  if (!isCurrent(context.state, generation, "versions")) return;
  context.state.versions = data || { enabled: false, components: {} };
  if (context.state.versions.enabled !== true) {
    context.ui.view.innerHTML = '<div class="empty-state"><span>!</span><h3>Агент обновлений недоступен</h3><p>Установите и запустите host version-agent. Панель не скачивает runtime-файлы и не получает Docker socket.</p></div>';
    return;
  }
  const names = { telemt: "Telemt / MTProxy", naive: "NaiveProxy / Caddy", mita: "Mieru / mita" };
  const cards = Object.entries(context.state.versions.components || {}).map(([component, item]) => {
    const available = Array.isArray(item.available) ? item.available : [];
    const current = item.current || "не определена";
    const offered = available.filter((entry) => entry.version !== current);
    const control = offered.length
      ? `<label>Установить проверенную версию<select data-version-select="${esc(component)}"><option value="">Выберите версию</option>${offered.map((entry) => `<option value="${esc(entry.version)}">${esc(entry.version)} · ${esc(entry.kind || "artifact")}</option>`).join("")}</select></label><button class="primary version-update" data-version-update="${esc(component)}" data-current="${esc(current)}" disabled>Обновить ${esc(component)}</button>`
      : `<p class="version-empty"><b>Обновлений не обнаружено</b>${available.length ? "" : " — в каталоге нет версий для этого компонента"}</p><button class="primary version-update" disabled>Обновить ${esc(component)}</button>`;
    return `<article class="version-card"><div class="panel-head"><div><h2>${esc(names[component] || component)}</h2><span>Текущая версия: <b>${esc(current)}</b></span></div><span class="status-pill ${current === "не определена" ? "blocked" : "active"}"><i></i>${current === "не определена" ? "Не определена" : "Установлена"}</span></div>${control}<small class="version-note">Версии добавляет оператор в каталог <code>versions.json</code> на хосте. Источник и SHA-256 проверяются host-agent; произвольные URL из браузера запрещены.</small></article>`;
  }).join("");
  context.ui.view.innerHTML = `<div class="security-note">Обновления выполняются только owner-ролью через отдельный host version-agent. Перед каждой заменой он проверяет allowlist-каталог, immutable digest или SHA-256, сохраняет rollback-копию и проверяет health.</div><section class="version-grid">${cards || '<div class="empty-state"><h3>Каталог версий пуст</h3></div>'}</section>`;
}

async function versionAction(context, component, button) {
  const select = query(`[data-version-select="${cssEscape(component)}"]`, context.ui.view);
  const version = select?.value;
  const current = button.dataset.current;
  if (!version) return;
  if (!await context.ui.confirmed("Обновить runtime?", `${component}: ${current} → ${version}. Сервис будет перезапущен или перезагружен, а при ошибке агент выполнит rollback.`, "Обновить")) return;
  try {
    context.ui.setBusy(button, true, "Обновляем…");
    await context.api(`/api/versions/${encodeURIComponent(component)}/update`, { method: "POST", body: JSON.stringify({ version, expected_current: current === "не определена" ? null : current }) });
    context.ui.toast(`${component} обновлён до ${version}`);
    await context.navigate("versions");
  } catch (error) {
    context.ui.toast(error.message, "error");
  } finally {
    context.ui.setBusy(button, false);
  }
}

export async function renderAdmins(context, generation) {
  const data = await context.api("/api/admins");
  if (!isCurrent(context.state, generation, "admins")) return;
  context.state.admins = data.items || [];
  const activeOwners = context.state.admins.filter((admin) => admin.role === "owner" && admin.active).length;
  const rows = context.state.admins.map((admin) => {
    const lastOwner = admin.role === "owner" && admin.active && activeOwners === 1;
    return `<div class="data-row admin-grid"><div class="identity"><span class="user-glyph">${esc(initials(admin.username))}</span><span><b>${esc(admin.username)}</b><small>Создан ${date(admin.created_at)}</small></span></div><div class="cell"><b>${esc(ROLE_NAMES[admin.role] || admin.role)}</b></div><div class="cell"><span class="status-pill ${admin.active ? "active" : "blocked"}"><i></i>${admin.active ? "Активен" : "Отключён"}</span></div><div class="row-actions"><button class="action-button" data-management-action="edit-admin" data-admin-id="${admin.id}">Настроить</button><button class="action-button ${lastOwner ? "" : "danger-text"}" data-management-action="toggle-admin" data-admin-id="${admin.id}" ${lastOwner ? "disabled title=\"Нельзя отключить последнего владельца\"" : ""}>${admin.active ? "Отключить" : "Включить"}</button></div></div>`;
  }).join("");
  context.ui.view.innerHTML = `<section class="data-panel"><div class="data-head admin-grid"><span>Администратор</span><span>Роль</span><span>Статус</span><span class="align-right">Действия</span></div>${rows || '<div class="empty-state"><h3>Администраторы не найдены</h3></div>'}</section>`;
}

export function openAdminModal(context, admin = null) {
  const { root, state, ui } = context;
  const lastOwner = admin?.role === "owner" && admin?.active && state.admins.filter((item) => item.role === "owner" && item.active).length === 1;
  query("#admin-form", root).reset();
  query("#admin-id", root).value = admin?.id || "";
  query("#admin-user", root).value = admin?.username || "";
  query("#admin-user", root).disabled = Boolean(admin);
  query("#admin-role", root).value = admin?.role || "viewer";
  query("#admin-role", root).disabled = lastOwner;
  query("#admin-modal-title", root).textContent = admin ? "Настроить администратора" : "Новый администратор";
  query("#password-hint", root).textContent = admin ? "Оставьте пустым, чтобы не менять" : "Обязателен для нового администратора";
  query("#admin-password", root).required = !admin;
  query("#admin-error", root).textContent = "";
  query("#delete-admin", root).hidden = !admin || lastOwner;
  ui.openModal("#admin-modal", admin ? "#admin-role" : "#admin-user");
}

export function bindManagement(context) {
  const { root, api, ui } = context;
  query("#save-admin", root)?.addEventListener("click", async (event) => {
    const form = query("#admin-form", root);
    const error = query("#admin-error", root);
    if (!form.reportValidity()) return;
    const id = query("#admin-id", root).value;
    const password = query("#admin-password", root).value;
    const payload = { role: query("#admin-role", root).value };
    if (password) payload.password = password;
    if (!id) {
      payload.username = query("#admin-user", root).value;
      payload.password = password;
    }
    if (!id && password.length < 12) {
      error.textContent = "Пароль должен содержать не менее 12 символов";
      return;
    }
    error.textContent = "";
    try {
      ui.setBusy(event.currentTarget, true, "Сохраняем…");
      await api(id ? `/api/admins/${id}` : "/api/admins", { method: id ? "PATCH" : "POST", body: JSON.stringify(payload) });
      query("#admin-modal", root).close();
      ui.toast(id ? "Администратор обновлён" : "Администратор добавлен");
      await context.navigate("admins");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(event.currentTarget, false);
    }
  });
  query("#delete-admin", root)?.addEventListener("click", async () => {
    const id = query("#admin-id", root).value;
    const admin = context.state.admins.find((item) => String(item.id) === id);
    if (!admin || !await ui.confirmed("Удалить администратора?", `${admin.username} потеряет доступ к панели.`, "Удалить")) return;
    try {
      await api(`/api/admins/${id}`, { method: "DELETE" });
      query("#admin-modal", root).close();
      ui.toast("Администратор удалён");
      await context.navigate("admins");
    } catch (error) {
      ui.toast(error.message, "error");
    }
  });
}

export function handleManagementChange(context, target) {
  const component = target.dataset.versionSelect;
  if (!component) return false;
  const button = query(`[data-version-update="${cssEscape(component)}"]`, context.ui.view);
  if (button) button.disabled = !target.value;
  return true;
}

export function handleManagementClick(context, button) {
  if (button.dataset.versionUpdate) {
    void versionAction(context, button.dataset.versionUpdate, button);
    return true;
  }
  if (button.dataset.managementAction === "edit-admin") {
    openAdminModal(context, context.state.admins.find((admin) => String(admin.id) === button.dataset.adminId));
    return true;
  }
  if (button.dataset.managementAction === "toggle-admin") {
    const admin = context.state.admins.find((item) => String(item.id) === button.dataset.adminId);
    if (!admin || button.disabled) return true;
    void (async () => {
      if (!await context.ui.confirmed(admin.active ? "Отключить администратора?" : "Включить администратора?", admin.active ? `${admin.username} потеряет доступ, активные сессии будут закрыты.` : `${admin.username} снова сможет войти в панель.`, admin.active ? "Отключить" : "Включить")) return;
      try {
        context.ui.setBusy(button, true);
        await context.api(`/api/admins/${admin.id}`, { method: "PATCH", body: JSON.stringify({ active: !admin.active }) });
        context.ui.toast(admin.active ? "Администратор отключён" : "Администратор включён");
        await context.navigate("admins");
      } catch (error) {
        context.ui.toast(error.message, "error");
      } finally {
        context.ui.setBusy(button, false);
      }
    })();
    return true;
  }
  return false;
}
