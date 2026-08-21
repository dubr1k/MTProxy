import { esc, query } from "./common.js";

export function createUi(root) {
  const view = query("#view", root);

  function toast(message, type = "ok") {
    const node = root.createElement("div");
    node.className = `toast ${type === "error" ? "error" : ""}`;
    node.textContent = message;
    query("#toast-region", root)?.append(node);
    window.setTimeout(() => node.remove(), 3200);
  }

  function setBusy(button, busy, label = "Подождите…") {
    if (!button) return;
    if (busy) {
      button.dataset.label = button.textContent;
      button.textContent = label;
      button.disabled = true;
      button.setAttribute("aria-busy", "true");
      return;
    }
    button.textContent = button.dataset.label || button.textContent;
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }

  function renderSkeleton() {
    view.innerHTML = '<div class="skeleton-grid"><i></i><i></i><i></i><i></i></div>';
  }

  function renderError(error) {
    view.innerHTML = `<div class="empty-state"><span>!</span><h3>Не удалось загрузить данные</h3><p>${esc(error.message)}</p><button class="secondary" data-action="retry">Повторить</button></div>`;
  }

  function openModal(selector, focusSelector = "") {
    const dialog = query(selector, root);
    dialog?.showModal();
    if (focusSelector) window.setTimeout(() => query(focusSelector, root)?.focus(), 50);
  }

  function confirmed(title, text, button = "Продолжить") {
    const dialog = query("#confirm", root);
    query("#confirm-title", root).textContent = title;
    query("#confirm-text", root).textContent = text;
    query("#confirm-ok", root).textContent = button;
    dialog.showModal();
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "default"), { once: true });
    });
  }

  async function copyText(input) {
    try {
      await navigator.clipboard.writeText(input.value);
    } catch {
      input.select();
      document.execCommand("copy");
    }
  }

  return { view, toast, setBusy, renderSkeleton, renderError, openModal, confirmed, copyText };
}
