import { api } from "./api.js";
import { createAccessDialogs } from "./access.js";
import { handleAuditClick, handleAuditSubmit, renderAudit } from "./audit.js";
import { query, queryAll } from "./common.js";
import { renderDashboard } from "./dashboard.js";
import {
  bindFleet,
  handleFleetChange,
  handleFleetClick,
  handleFleetSubmit,
  openFleetModal,
  renderFleet,
} from "./fleet.js";
import {
  bindManagement,
  handleManagementChange,
  handleManagementClick,
  openAdminModal,
  renderAdmins,
  renderVersions,
  ROLE_NAMES,
} from "./management.js";
import { bindMieru, handleMieruClick, openMieruModal, renderMieru } from "./mieru.js";
import { bindNaive, handleNaiveClick, handleNaiveInput, openNaiveModal, renderNaive } from "./naive.js";
import { createPanelState } from "./state.js";
import { createUi } from "./ui.js";
import { bindUsers, handleUsersClick, handleUsersInput, openUserModal, renderUsers } from "./users.js";

const TITLES = {
  dashboard: ["Обзор", "Состояние всех прокси-протоколов в одном месте"],
  mieru: ["Mieru", "Пользователи, rolling-квоты и application-byte трафик"],
  users: ["MTProxy", "Пользователи, ссылки и ключи доступа"],
  naive: ["NaiveProxy", "HTTPS-прокси, конфигурации и доступы"],
  versions: ["Версии", "Проверенные обновления runtime-компонентов"],
  fleet: ["Узлы", "Inventory, состояние агента и typed-команды Telemt v1"],
  admins: ["Администраторы", "Роли и доступ к панели"],
  audit: ["Журнал действий", "Изменения, входы и операции с ключами"],
};

const RENDERERS = {
  dashboard: renderDashboard,
  users: renderUsers,
  mieru: renderMieru,
  naive: renderNaive,
  versions: renderVersions,
  fleet: renderFleet,
  admins: renderAdmins,
  audit: renderAudit,
};

function createNavigator(context) {
  return async function navigate(name) {
    const renderer = RENDERERS[name];
    if (!renderer) return;
    const generation = ++context.state.navigationGeneration;
    context.state.view = name;
    const [title, subtitle] = TITLES[name];
    query("#title", context.root).textContent = title;
    query("#subtitle", context.root).textContent = subtitle;
    queryAll("[data-view]", context.root).forEach((button) => button.classList.toggle("active", button.dataset.view === name));

    const canCreate = (context.state.me?.role !== "viewer" && ["users", "naive", "mieru"].includes(name))
      || (name === "fleet" && context.state.me?.role === "owner")
      || (name === "admins" && context.state.me?.role === "owner");
    const add = query("#add", context.root);
    add.hidden = !canCreate;
    query("#add-label", context.root).textContent = {
      admins: "Администратора",
      fleet: "Узел",
      naive: "Naive доступ",
      mieru: "Mieru доступ",
      users: "Подключение",
    }[name] || "Добавить";

    context.ui.renderSkeleton();
    try {
      await renderer(context, generation);
    } catch (error) {
      if (context.state.navigationGeneration === generation && context.state.view === name) context.ui.renderError(error);
    }
  };
}

function bindLogin(root) {
  const form = query("#login", root);
  if (!form) return false;
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = query("button", form);
    const error = query("#error", root);
    error.textContent = "";
    const previous = button.textContent;
    try {
      button.textContent = "Входим…";
      button.disabled = true;
      await api("/api/auth/login", { method: "POST", body: JSON.stringify(Object.fromEntries(new FormData(form))) });
      window.location.assign("/");
    } catch (exception) {
      error.textContent = exception.message;
      button.textContent = previous;
      button.disabled = false;
    }
  });
  const transport = query("#transport-state", root);
  if (transport) {
    const secure = window.location.protocol === "https:";
    transport.classList.toggle("degraded", !secure);
    transport.lastChild.textContent = secure ? " Защищённое HTTPS-соединение" : " HTTP-соединение не защищено";
  }
  return true;
}

function bindPanel(context) {
  const { root, ui } = context;
  queryAll("[data-view]", root).forEach((button) => button.addEventListener("click", () => context.navigate(button.dataset.view)));
  query("#add", root).addEventListener("click", () => {
    if (context.state.view === "admins") openAdminModal(context);
    else if (context.state.view === "fleet") openFleetModal(context);
    else if (context.state.view === "naive") openNaiveModal(context);
    else if (context.state.view === "mieru") openMieruModal(context);
    else openUserModal(context);
  });
  query("#refresh", root).addEventListener("click", (event) => {
    ui.setBusy(event.currentTarget, true, "…");
    context.navigate(context.state.view).finally(() => ui.setBusy(event.currentTarget, false));
  });
  query("#logout", root).addEventListener("click", async () => {
    try {
      await context.api("/api/auth/logout", { method: "POST" });
      window.location.assign("/login");
    } catch (error) {
      ui.toast(error.message, "error");
    }
  });
  query("#mobile-logout", root)?.addEventListener("click", () => query("#logout", root).click());
  query("#profile-button", root).addEventListener("click", () => {
    if (context.state.me) ui.toast(`${context.state.me.username} · ${ROLE_NAMES[context.state.me.role] || context.state.me.role}`);
  });

  bindUsers(context);
  bindMieru(context);
  bindNaive(context);
  bindFleet(context);
  bindManagement(context);
  context.access.bind();

  ui.view.addEventListener("input", (event) => {
    handleUsersInput(context, event.target) || handleNaiveInput(context, event.target);
  });
  ui.view.addEventListener("change", (event) => {
    handleManagementChange(context, event.target) || handleFleetChange(context, event.target);
  });
  ui.view.addEventListener("submit", (event) => {
    event.preventDefault();
    handleFleetSubmit(context, event.target) || handleAuditSubmit(context, event.target);
  });
  ui.view.addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    if (button.dataset.action === "retry") {
      void context.navigate(context.state.view);
      return;
    }
    if (handleAuditClick(context, button)) return;
    if (handleFleetClick(context, button)) return;
    if (handleManagementClick(context, button)) return;
    if (handleMieruClick(context, button)) return;
    if (handleNaiveClick(context, button)) return;
    handleUsersClick(context, button);
  });
}

async function initialise(context) {
  try {
    context.state.me = await context.api("/api/auth/me");
    query("#profile-name", context.root).textContent = context.state.me.username;
    query("#profile-role", context.root).textContent = ROLE_NAMES[context.state.me.role] || context.state.me.role;
    query("#avatar", context.root).textContent = context.state.me.username.slice(0, 2).toUpperCase();
    queryAll('[data-view="naive"]', context.root).forEach((item) => { item.hidden = context.state.me.features?.naive !== true; });
    queryAll('[data-view="mieru"]', context.root).forEach((item) => { item.hidden = context.state.me.features?.mieru !== true; });
    queryAll(".owner-only", context.root).forEach((item) => { item.hidden = context.state.me.role !== "owner"; });
    queryAll(".audit-nav", context.root).forEach((item) => { item.hidden = false; });
    await context.navigate("dashboard");
  } catch (error) {
    context.ui.renderError(error);
  }
}

export function boot(root = document) {
  if (bindLogin(root)) return;
  if (!query("#view", root)) return;
  const context = {
    root,
    api,
    state: createPanelState(),
    ui: createUi(root),
    access: null,
    navigate: null,
  };
  context.access = createAccessDialogs(context);
  context.navigate = createNavigator(context);
  bindPanel(context);
  void initialise(context);
}
