import { date, esc, initials, number, query, serialise } from "./common.js";
import { isCurrent } from "./state.js";

export const FLEET_OPERATIONS = [
  "telemt.inventory.refresh",
  "telemt.user.enable",
  "telemt.user.disable",
  "telemt.user.update_limits",
  "telemt.user.reset_quota",
];

const OPERATION_LABELS = {
  "telemt.inventory.refresh": "Обновить inventory Telemt",
  "telemt.user.enable": "Включить пользователя Telemt",
  "telemt.user.disable": "Отключить пользователя Telemt",
  "telemt.user.update_limits": "Изменить лимиты пользователя",
  "telemt.user.reset_quota": "Сбросить квоту пользователя",
};

function visibleCapabilities(node) {
  const capabilities = node.inventory?.capabilities;
  if (!Array.isArray(capabilities)) return [];
  return capabilities.filter((capability) => FLEET_OPERATIONS.includes(capability));
}

function latestRevision(commands) {
  return [...commands].reverse().find((command) => typeof command.result?.telemt_revision === "string")?.result?.telemt_revision || "";
}

function commandStatus(command) {
  const statuses = {
    queued: ["queued", "В очереди", "Агент ещё не получил команду."],
    dispatched: ["executing", "Выполняется", "Команда выдана агенту; дождитесь результата."],
    succeeded: ["succeeded", "Выполнена", "Агент подтвердил результат."],
    indeterminate: ["indeterminate", "Неопределённо", "Нужна сверка inventory: не повторяйте команду вслепую."],
    failed: ["failed", "Не выполнена", "Агент вернул безопасную причину ошибки."],
  };
  return statuses[command.status] || ["indeterminate", "Неизвестный статус", "Проверьте inventory узла."];
}

function commandRow(command) {
  const [tone, label, help] = commandStatus(command);
  const detail = command.result == null
    ? ""
    : `<details class="command-result"><summary>Результат</summary><pre>${esc(serialise(command.result))}</pre></details>`;
  return `<li class="fleet-command" data-command-status="${tone}">
    <div class="fleet-command-head"><span class="command-status ${tone}"><i></i>${label}</span><b>${esc(OPERATION_LABELS[command.operation] || command.operation)}</b><span>№ ${number(command.sequence)}</span></div>
    <p>${help}</p><small>Создана ${date(command.created_at)}${command.completed_at ? ` · завершена ${date(command.completed_at)}` : ""}</small>${detail}
  </li>`;
}

function inventoryList(node) {
  const inventory = node.inventory || {};
  const capabilities = visibleCapabilities(node);
  const facts = [
    ["Регион", inventory.region || "не задан"],
    ["Telemt", inventory.telemt_version || "не определён"],
    ["Агент", inventory.agent_version || "не определён"],
    ["Платформа", inventory.platform || "не определена"],
    ["Hostname", inventory.hostname || "не передан"],
    ["Последний контакт", node.last_seen_at ? date(node.last_seen_at) : "Агент ещё не подключался"],
  ];
  return `<dl class="fleet-facts">${facts.map(([label, value]) => `<div><dt>${label}</dt><dd>${esc(value)}</dd></div>`).join("")}</dl>
    <div class="fleet-capabilities"><span>Возможности Telemt v1</span>${capabilities.length ? capabilities.map((capability) => `<code>${esc(capability)}</code>`).join("") : "<small>Агент ещё не подтвердил поддерживаемые операции.</small>"}</div>`;
}

function commandForm(context, node, commands) {
  if (context.state.me.role === "viewer") return '<p class="form-hint">Наблюдатель видит статус и историю, но не может ставить команды в очередь.</p>';
  const capabilities = visibleCapabilities(node);
  const hasInventory = !capabilities.length || capabilities.includes("telemt.inventory.refresh");
  const revision = latestRevision(commands) || "inventory";
  const options = FLEET_OPERATIONS.map((operation) => `<option value="${operation}" ${capabilities.length && !capabilities.includes(operation) ? "disabled" : ""}>${OPERATION_LABELS[operation]}</option>`).join("");
  return `<form id="fleet-command-form" class="fleet-command-form" novalidate>
    <div class="panel-head"><div><h3>Команда Telemt v1</h3><span>Только typed operations; URL, shell и Mieru operations отсутствуют.</span></div></div>
    <label>Операция<select id="fleet-operation" ${hasInventory ? "" : "disabled"}>${options}</select></label>
    <label>Ожидаемая revision Telemt<input id="fleet-expected-revision" value="${esc(revision)}" pattern="[A-Za-z0-9_.:-]{1,128}" maxlength="128" required aria-describedby="fleet-revision-help"><small id="fleet-revision-help">После refresh используйте revision из последнего подтверждённого результата. Для первой inventory-сверки используется значение inventory.</small></label>
    <div class="fleet-user-field" hidden><label>Пользователь Telemt<input id="fleet-command-username" pattern="[A-Za-z0-9_.\-]+" maxlength="64" autocomplete="off"></label></div>
    <div class="fleet-limit-fields" hidden>
      <label>Квота, байт<input data-fleet-limit="data_quota_bytes" type="number" min="1" max="9223372036854775807" step="1" inputmode="numeric"></label>
      <label>От клиента, бит/с<input data-fleet-limit="rate_limit_up_bps" type="number" min="1" max="1000000000000" step="1" inputmode="numeric"></label>
      <label>К клиенту, бит/с<input data-fleet-limit="rate_limit_down_bps" type="number" min="1" max="1000000000000" step="1" inputmode="numeric"></label>
      <label>TCP-соединения<input data-fleet-limit="max_tcp_conns" type="number" min="1" max="100000" step="1" inputmode="numeric"></label>
      <label>Уникальные IP<input data-fleet-limit="max_unique_ips" type="number" min="1" max="100000" step="1" inputmode="numeric"></label>
    </div>
    <div id="fleet-command-error" class="form-error" role="alert"></div>
    <footer><button class="secondary" type="button" data-fleet-action="prepare-inventory" ${hasInventory ? "" : "disabled"}>Обновить inventory</button><span class="spacer"></span><button class="primary" type="submit" ${hasInventory ? "" : "disabled"}>Поставить в очередь</button></footer>
  </form>`;
}

function nodeDetail(context, node, commands) {
  if (!node) return '<section class="fleet-detail empty-state"><span>◇</span><h3>Выберите узел</h3><p>Откройте карточку, чтобы увидеть inventory и историю команд.</p></section>';
  const connected = node.auth_state === "connected";
  return `<section class="fleet-detail" aria-labelledby="fleet-node-title">
    <div class="fleet-detail-head"><div><span class="eyebrow">FLEET NODE</span><h2 id="fleet-node-title">${esc(node.display_name)}</h2><p>${esc(node.node_id)}</p></div><span class="status-pill ${connected ? "active" : "blocked"}"><i></i>${esc(node.auth_state || "unenrolled")}</span></div>
    ${inventoryList(node)}
    ${commandForm(context, node, commands)}
    <section class="fleet-history" aria-labelledby="fleet-history-title"><div class="panel-head"><h3 id="fleet-history-title">История команд</h3><span>${number(commands.length)} записей</span></div>${commands.length ? `<ol>${commands.map(commandRow).join("")}</ol>` : '<p class="form-hint">Команд для этого узла пока нет.</p>'}</section>
  </section>`;
}

function nodeCard(node, selected) {
  const connected = node.auth_state === "connected";
  return `<button class="fleet-node-card ${selected ? "selected" : ""}" data-fleet-node="${esc(node.node_id)}" aria-current="${selected ? "true" : "false"}">
    <span class="user-glyph">${esc(initials(node.node_id))}</span><span><b>${esc(node.display_name)}</b><small>${esc(node.node_id)} · ${esc(node.inventory?.region || "регион не задан")}</small></span><span class="status-pill ${connected ? "active" : "blocked"}"><i></i>${connected ? "online" : esc(node.auth_state || "unenrolled")}</span>
  </button>`;
}

async function refreshCommands(context, nodeId, generation) {
  const data = await context.api(`/api/fleet/nodes/${encodeURIComponent(nodeId)}/commands`);
  if (!isCurrent(context.state, generation, "fleet") || context.state.fleetSelection !== nodeId) return null;
  context.state.fleetCommands = data.items || [];
  return context.state.fleetCommands;
}

export async function renderFleet(context, generation) {
  const data = await context.api("/api/fleet/nodes");
  if (!isCurrent(context.state, generation, "fleet")) return;
  context.state.fleet = data.items || [];
  query("#fleet-count", context.root).textContent = context.state.fleet.length;
  if (!context.state.fleet.some((node) => node.node_id === context.state.fleetSelection)) {
    context.state.fleetSelection = context.state.fleet[0]?.node_id || "";
    context.state.fleetCommands = [];
  }
  if (context.state.fleetSelection) {
    const commands = await refreshCommands(context, context.state.fleetSelection, generation);
    if (commands === null) return;
  }
  const selected = context.state.fleet.find((node) => node.node_id === context.state.fleetSelection);
  context.ui.view.innerHTML = `<div class="security-note">Узлы подключаются исходящим mTLS long-poll. Идентичность привязана к SAN, серийному номеру и отпечатку сертификата; bearer fallback отсутствует.</div>
    <section class="fleet-layout"><nav class="fleet-node-list" aria-label="Узлы Fleet">${context.state.fleet.length ? context.state.fleet.map((node) => nodeCard(node, node.node_id === context.state.fleetSelection)).join("") : '<div class="empty-state"><span>◇</span><h3>Узлы не зарегистрированы</h3><p>Владелец может добавить обезличенный inventory через Fleet API.</p></div>'}</nav>${nodeDetail(context, selected, context.state.fleetCommands)}</section>`;
  updateCommandFields(context);
}

function updateCommandFields(context) {
  const form = query("#fleet-command-form", context.root);
  if (!form) return;
  const operation = query("#fleet-operation", form).value;
  const needsUser = operation !== "telemt.inventory.refresh";
  const needsLimits = operation === "telemt.user.update_limits";
  query(".fleet-user-field", form).hidden = !needsUser;
  query(".fleet-limit-fields", form).hidden = !needsLimits;
  query("#fleet-command-username", form).required = needsUser;
}

function commandPayload(context, form) {
  const operation = query("#fleet-operation", form).value;
  if (!FLEET_OPERATIONS.includes(operation)) throw new Error("Операция Fleet не поддерживается");
  const expectedRevision = query("#fleet-expected-revision", form).value.trim();
  if (!expectedRevision) throw new Error("Укажите ожидаемую revision Telemt");
  const payload = {};
  if (operation !== "telemt.inventory.refresh") {
    const username = query("#fleet-command-username", form).value.trim();
    if (!username) throw new Error("Укажите пользователя Telemt");
    if (expectedRevision === "inventory") throw new Error("Сначала обновите inventory и используйте подтверждённую revision Telemt");
    payload.username = username;
  }
  if (operation === "telemt.user.update_limits") {
    for (const input of form.querySelectorAll("[data-fleet-limit]")) {
      if (input.value === "") continue;
      const value = Number(input.value);
      if (!Number.isSafeInteger(value) || value < 1) throw new Error("Лимиты должны быть положительными целыми числами");
      payload[input.dataset.fleetLimit] = value;
    }
    if (Object.keys(payload).length === 1) throw new Error("Укажите хотя бы один лимит");
  }
  return { operation, expectedRevision, payload };
}

function idempotencyKey(nodeId) {
  return `fleet-${nodeId}-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

export async function submitFleetCommand(context, form) {
  const selected = context.state.fleet.find((node) => node.node_id === context.state.fleetSelection);
  const error = query("#fleet-command-error", form);
  error.textContent = "";
  if (!selected || !form.reportValidity()) return;
  try {
    const { operation, expectedRevision, payload } = commandPayload(context, form);
    const confirmations = {
      "telemt.user.disable": ["Отключить пользователя Telemt?", `${payload.username} будет отключён на узле ${selected.display_name} после получения команды.`, "Отключить"],
      "telemt.user.reset_quota": ["Сбросить квоту пользователя?", `Учёт квоты ${payload.username} на узле ${selected.display_name} будет сброшен.`, "Сбросить"],
    };
    if (confirmations[operation] && !await context.ui.confirmed(...confirmations[operation])) return;
    const button = query('button[type="submit"]', form);
    context.ui.setBusy(button, true, "Ставим…");
    await context.api(`/api/fleet/nodes/${encodeURIComponent(selected.node_id)}/commands`, {
      method: "POST",
      body: JSON.stringify({
        idempotency_key: idempotencyKey(selected.node_id),
        operation,
        expected_telemt_revision: expectedRevision,
        payload,
      }),
    });
    context.ui.toast("Команда поставлена в очередь");
    await context.navigate("fleet");
  } catch (exception) {
    error.textContent = exception.message;
  } finally {
    context.ui.setBusy(query('button[type="submit"]', form), false);
  }
}

export function openFleetModal(context) {
  query("#fleet-form", context.root).reset();
  query("#fleet-error", context.root).textContent = "";
  context.ui.openModal("#fleet-modal", "#new-node-id");
}

export function bindFleet(context) {
  const { api, root, ui } = context;
  query("#create-fleet-node", root)?.addEventListener("click", async (event) => {
    const form = query("#fleet-form", root);
    const error = query("#fleet-error", root);
    if (!form.reportValidity()) return;
    const nodeId = query("#new-node-id", root).value;
    const displayName = query("#new-node-name", root).value.trim();
    const region = query("#new-node-region", root).value.trim();
    const inventory = region ? { region } : {};
    error.textContent = "";
    try {
      ui.setBusy(event.currentTarget, true, "Добавляем…");
      await api("/api/fleet/nodes", { method: "POST", body: JSON.stringify({ node_id: nodeId, display_name: displayName, inventory }) });
      query("#fleet-modal", root).close();
      context.state.fleetSelection = nodeId;
      ui.toast("Узел добавлен в реестр");
      await context.navigate("fleet");
    } catch (exception) {
      error.textContent = exception.message;
    } finally {
      ui.setBusy(event.currentTarget, false);
    }
  });
}

export function handleFleetClick(context, button) {
  if (button.dataset.fleetNode) {
    context.state.fleetSelection = button.dataset.fleetNode;
    void context.navigate("fleet");
    return true;
  }
  if (button.dataset.fleetAction === "prepare-inventory") {
    const form = query("#fleet-command-form", context.root);
    query("#fleet-operation", form).value = "telemt.inventory.refresh";
    updateCommandFields(context);
    query('button[type="submit"]', form).focus();
    return true;
  }
  return false;
}

export function handleFleetChange(context, target) {
  if (target.id !== "fleet-operation") return false;
  updateCommandFields(context);
  return true;
}

export function handleFleetSubmit(context, form) {
  if (form.id !== "fleet-command-form") return false;
  void submitFleetCommand(context, form);
  return true;
}
