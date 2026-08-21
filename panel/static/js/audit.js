import { date, esc, query, serialise } from "./common.js";
import { isCurrent } from "./state.js";

const ACTION_NAMES = {
  "auth.login": "Вход в панель",
  "auth.logout": "Выход",
  "user.create": "Создан доступ",
  "user.access": "Открыта ссылка",
  "user.enable": "Доступ включён",
  "user.disable": "Доступ заблокирован",
  "user.rotate": "Ключ обновлён",
  "user.delete": "Доступ удалён",
  "user.limits": "Изменены лимиты",
  "user.reset_quota": "Сброшен счётчик квоты",
  "naive.create": "Создан Naive-доступ",
  "naive.access": "Открыта Naive-конфигурация",
  "naive.enable": "Naive-доступ включён",
  "naive.disable": "Naive-доступ отключён",
  "naive.rotate": "Naive-пароль обновлён",
  "naive.delete": "Naive-доступ удалён",
  "naive.quota": "Изменена Naive-квота",
  "naive.traffic.reset": "Сброшен Naive-счётчик",
  "mieru.create": "Создан Mieru-доступ",
  "mieru.quotas": "Изменена квота Mieru",
  "mieru.enable": "Mieru-доступ включён",
  "mieru.disable": "Mieru-доступ отключён",
  "mieru.rotate": "Mieru-ссылка обновлена",
  "mieru.delete": "Mieru-доступ удалён",
  "fleet.node.create": "Добавлен Fleet-узел",
  "fleet.command.queue": "Команда Fleet поставлена в очередь",
  "runtime.version.update": "Обновлена версия компонента",
  "admin.create": "Создан администратор",
  "admin.update": "Изменён администратор",
  "admin.delete": "Удалён администратор",
};

function auditQuery(audit, beforeId = null) {
  const parameters = new URLSearchParams({ limit: "50" });
  if (audit.actor) parameters.set("actor", audit.actor);
  if (audit.action) parameters.set("action", audit.action);
  if (audit.target) parameters.set("target", audit.target);
  if (beforeId != null) parameters.set("before_id", String(beforeId));
  return parameters;
}

function auditDetails(item) {
  const ip = item.ip ?? item.ip_address ?? item.remote_ip;
  const detail = item.detail ?? {};
  const hasDetail = detail && typeof detail === "object" && Object.keys(detail).length > 0;
  if (!ip && !hasDetail) return "";
  return `<details class="audit-details"><summary>Детали и IP</summary><dl><div><dt>IP</dt><dd>${esc(ip || "не зафиксирован")}</dd></div></dl>${hasDetail ? `<pre>${esc(serialise(detail))}</pre>` : ""}</details>`;
}

function auditRow(item) {
  return `<article class="audit-row">
    <div class="audit-main"><time datetime="${esc(item.happened_at || "")}">${date(item.happened_at)}</time><b>${esc(item.actor_username || "system")}</b><span class="audit-action">${esc(ACTION_NAMES[item.action] || item.action || "—")}</span><span>${esc(item.target || "—")}</span></div>
    ${auditDetails(item)}
  </article>`;
}

function auditMarkup(context) {
  const { audit } = context.state;
  const hasMore = audit.nextCursor !== null && audit.nextCursor !== undefined && audit.nextCursor !== "";
  return `<section class="audit-view">
    <form id="audit-filter-form" class="audit-filters">
      <label>Исполнитель<input id="audit-actor" name="actor" value="${esc(audit.actor)}" maxlength="64" autocomplete="off" placeholder="например, owner"></label>
      <label>Действие<input id="audit-action" name="action" value="${esc(audit.action)}" maxlength="128" autocomplete="off" placeholder="например, user.create"></label>
      <label>Цель<input id="audit-target" name="target" value="${esc(audit.target)}" maxlength="128" autocomplete="off" placeholder="например, alice"></label>
      <div class="audit-filter-actions"><button class="secondary" type="button" data-audit-action="clear">Очистить</button><button class="primary" type="submit">Применить</button></div>
    </form>
    <section class="data-panel"><div class="panel-head"><h2>Журнал действий</h2><span>${audit.items.length ? `Показано ${audit.items.length}` : "Нет записей"}</span></div><div class="audit-list">${audit.items.length ? audit.items.map(auditRow).join("") : '<div class="empty-state"><span>≡</span><h3>Журнал пока пуст</h3><p>Здесь появятся действия администраторов.</p></div>'}</div>${hasMore ? '<footer class="audit-load-more"><button class="secondary" type="button" data-audit-action="more">Загрузить ещё</button></footer>' : ""}</section>
  </section>`;
}

async function loadAudit(context, generation, { append = false } = {}) {
  const audit = context.state.audit;
  const beforeId = append ? audit.nextCursor : null;
  const data = await context.api(`/api/audit?${auditQuery(audit, beforeId)}`);
  if (!isCurrent(context.state, generation, "audit")) return false;
  const items = data.items || [];
  audit.items = append ? [...audit.items, ...items] : items;
  audit.nextCursor = data.next_cursor ?? null;
  return true;
}

export async function renderAudit(context, generation) {
  await loadAudit(context, generation);
  if (!isCurrent(context.state, generation, "audit")) return;
  context.ui.view.innerHTML = auditMarkup(context);
}

async function applyFilters(context, form) {
  const { audit } = context.state;
  audit.actor = query("#audit-actor", form).value.trim();
  audit.action = query("#audit-action", form).value.trim();
  audit.target = query("#audit-target", form).value.trim();
  audit.items = [];
  audit.nextCursor = null;
  await context.navigate("audit");
}

export function handleAuditSubmit(context, form) {
  if (form.id !== "audit-filter-form") return false;
  void applyFilters(context, form).catch((error) => context.ui.toast(error.message, "error"));
  return true;
}

export function handleAuditClick(context, button) {
  if (button.dataset.auditAction === "clear") {
    context.state.audit = { items: [], nextCursor: null, actor: "", action: "", target: "" };
    void context.navigate("audit");
    return true;
  }
  if (button.dataset.auditAction === "more") {
    void (async () => {
      try {
        context.ui.setBusy(button, true, "Загружаем…");
        const generation = context.state.navigationGeneration;
        if (await loadAudit(context, generation, { append: true })) context.ui.view.innerHTML = auditMarkup(context);
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
