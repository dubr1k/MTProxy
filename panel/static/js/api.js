function cookie(name) {
  return document.cookie
    .split("; ")
    .find((entry) => entry.startsWith(`${name}=`))
    ?.split("=")
    .slice(1)
    .join("=");
}

const API_REASONS = {
  quota_exhausted: "Квота исчерпана: сбросьте трафик или увеличьте квоту",
};

// FastAPI validation failures are structured objects. Convert only their safe,
// human-facing fields rather than rendering "[object Object]" in a dialog.
export function problemText(body) {
  if (!body || typeof body !== "object") return "";
  if (API_REASONS[body.code]) return API_REASONS[body.code];
  if (typeof body.detail === "string") return body.detail;
  if (!Array.isArray(body.detail)) return "";

  return body.detail
    .map((item) => {
      if (!item || typeof item !== "object" || typeof item.msg !== "string") return "";
      const field = Array.isArray(item.loc)
        ? item.loc.filter((part) => typeof part === "string" && part !== "body").join(".")
        : "";
      return field ? `${field}: ${item.msg}` : item.msg;
    })
    .filter(Boolean)
    .slice(0, 3)
    .join("; ");
}

export async function api(url, options = {}) {
  const headers = {
    ...options.headers,
    "X-CSRF-Token": cookie("panel_csrf") || "",
  };
  if (options.body && !headers["content-type"]) headers["content-type"] = "application/json";

  const response = await fetch(url, { ...options, headers });
  if (response.status === 401) {
    window.location.assign("/login");
    throw new Error("Сессия завершена");
  }
  if (!response.ok) {
    let detail = "Не удалось выполнить действие";
    try {
      detail = problemText(await response.json()) || detail;
    } catch {
      // A gateway failure may not carry JSON. Keep the generic, safe message.
    }
    throw new Error(detail);
  }
  return response.status === 204 ? null : response.json();
}
