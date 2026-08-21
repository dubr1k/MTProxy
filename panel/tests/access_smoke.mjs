import assert from "node:assert/strict";
import test from "node:test";

import { createAccessDialogs, normaliseAccessPayload } from "../static/js/access.js";

const qr = (payload) => ({ payload, image: "data:image/svg+xml;base64,PHN2Zy8+" });

test("Naive variants keep native config, a Karing-compatible sing-box outbound, and Shadowrocket manual fields distinct", () => {
  const endpoint = "https://phone:secret@naive.example.com";
  const singBoxConfig = { outbounds: [{ type: "naive", server: "naive.example.com" }] };
  const result = normaliseAccessPayload({
    service: "naive",
    username: "phone",
    clients: {
      native: {
        label: "NaiveProxy",
        type: "config",
        config: { listen: "socks://127.0.0.1:1080", proxy: endpoint },
        filename: "naive-phone.json",
      },
      karing: {
        label: "Karing",
        type: "config",
        description: "sing-box outbound — подходит для Karing.",
        config: singBoxConfig,
        filename: "karing-naive-phone.json",
      },
      shadowrocket: {
        label: "Shadowrocket",
        type: "manual",
        fields: {
          proxy_type: "HTTPS",
          server: "naive.example.com",
          port: 443,
          username: "phone",
          password: "secret",
        },
      },
    },
  }, "naive", "phone");

  assert.equal(result.native.payloadType, "config");
  assert.match(result.native.payload, /"proxy": "https:\/\/phone:secret@naive\.example\.com"/);
  assert.equal(result.native.qr, null);
  assert.equal(result.karing.payloadType, "config");
  assert.deepEqual(JSON.parse(result.karing.payload), singBoxConfig);
  assert.equal(result.karing.description, "sing-box outbound — подходит для Karing.");
  assert.equal(result.karing.openLabel, undefined);
  assert.equal(result.karing.qr, null);
  assert.equal(result.shadowrocket.payloadType, "manual");
  assert.match(result.shadowrocket.payload, /Тип: HTTPS/);
  assert.match(result.shadowrocket.payload, /Пароль: secret/);
  assert.equal(result.shadowrocket.qr, null);
});

test("Mieru variants use the native mierus link or the Karing profile deep link", () => {
  const nativeLink = "mierus://phone:secret@mieru.example.com?profile=phone&port=8443&protocol=TCP";
  const karingLink = "karing://install-config?url=%7B%22outbounds%22%3A%5B%5D%7D&name=Mieru";
  const result = normaliseAccessPayload({
    service: "mieru",
    username: "phone",
    clients: {
      native: {
        label: "Mieru",
        type: "link",
        share_url: nativeLink,
        import_command: `mieru import config '${nativeLink}'`,
        qr: qr(nativeLink),
      },
      karing: {
        label: "Karing",
        type: "link",
        import_url: karingLink,
        config: { outbounds: [] },
        filename: "karing-mieru-phone.json",
        qr: qr(karingLink),
      },
    },
    unsupported_clients: {
      shadowrocket: "Проверенный формат импорта Mieru для Shadowrocket отсутствует.",
    },
  }, "mieru", "phone");

  assert.equal(result.native.payload, nativeLink);
  assert.equal(result.native.qr.payload, nativeLink);
  assert.equal(result.karing.payload, karingLink);
  assert.equal(result.karing.qr.payload, karingLink);
  assert.match(result.unsupported, /Shadowrocket/);
});

test("client QR metadata must describe the displayed payload", () => {
  assert.throws(() => normaliseAccessPayload({
    service: "mieru",
    username: "phone",
    clients: {
      native: {
        label: "Mieru",
        type: "link",
        share_url: "mierus://phone:secret@example.com?profile=phone&port=8443&protocol=TCP",
        import_command: "mieru import config x",
        qr: qr("https://phone:secret@example.com"),
      },
    },
    unsupported_clients: {},
  }, "mieru", "phone"), /QR/);
});

function fakeElement() {
  const listeners = {};
  const classes = new Set();
  return {
    value: "",
    textContent: "",
    hidden: false,
    attributes: {},
    listeners,
    classList: {
      toggle(name, enabled) {
        if (enabled) classes.add(name);
        else classes.delete(name);
      },
      contains(name) {
        return classes.has(name);
      },
    },
    addEventListener(name, callback) {
      listeners[name] = callback;
    },
    setAttribute(name, value) {
      this.attributes[name] = String(value);
    },
    removeAttribute(name) {
      delete this.attributes[name];
      if (name === "src" || name === "href" || name === "download") this[name] = "";
    },
  };
}

function fakeRoot(prefix) {
  const ids = [
    `${prefix}-client-tabs`, `${prefix}-client-description`, `${prefix}-payload-label`,
    `${prefix}-payload`, `copy-${prefix}-payload`, `${prefix}-secondary`,
    `${prefix}-secondary-label`, `${prefix}-secondary-payload`, `copy-${prefix}-secondary`,
    `open-${prefix}-client`, `download-${prefix}-payload`, `${prefix}-qr-image`,
    `${prefix}-qr-empty`, `download-${prefix}-qr`, `${prefix}-qr-caption`,
    `${prefix}-unsupported`, `${prefix}-access-title`, `${prefix}-access-modal`,
  ];
  const elements = Object.fromEntries(ids.map((id) => [`#${id}`, fakeElement()]));
  const tabs = elements[`#${prefix}-client-tabs`];
  tabs.buttons = [];
  Object.defineProperty(tabs, "innerHTML", {
    set(value) {
      this.buttons = [...value.matchAll(/data-client=\"([^\"]+)\"/g)].map((match) => {
        const button = fakeElement();
        button.dataset = { client: match[1] };
        button.closest = () => button;
        return button;
      });
    },
  });
  tabs.querySelectorAll = () => tabs.buttons;
  return {
    elements,
    querySelector(selector) {
      return elements[selector] || null;
    },
  };
}

test("dialog renderer shows the Naive Karing sing-box outbound without a broken deep link or QR", () => {
  const root = fakeRoot("naive");
  const opened = [];
  const dialogs = createAccessDialogs({
    root,
    api: async () => { throw new Error("unexpected API call"); },
    ui: {
      openModal: (selector) => opened.push(selector),
      copyText: async () => {},
      toast: () => {},
    },
  });
  dialogs.bind();
  const endpoint = "https://phone:secret@naive.example.com";
  const config = { outbounds: [] };
  dialogs.showNaiveAccess({
    service: "naive",
    username: "phone",
    clients: {
      native: {
        label: "NaiveProxy",
        type: "config",
        config: { listen: "socks://127.0.0.1:1080", proxy: endpoint },
        filename: "naive-phone.json",
      },
      karing: {
        label: "Karing",
        type: "config",
        description: "sing-box outbound — подходит для Karing.",
        config,
        filename: "karing-naive-phone.json",
      },
      shadowrocket: {
        label: "Shadowrocket",
        type: "manual",
        fields: {
          proxy_type: "HTTPS",
          server: "naive.example.com",
          port: 443,
          username: "phone",
          password: "secret",
        },
      },
    },
  }, "phone");

  assert.deepEqual(opened, ["#naive-access-modal"]);
  assert.equal(root.elements["#naive-qr-image"].hidden, true);
  const karingTab = root.elements["#naive-client-tabs"].buttons.find(
    (button) => button.dataset.client === "karing",
  );
  root.elements["#naive-client-tabs"].listeners.click({ target: karingTab });
  assert.equal(root.elements["#naive-qr-image"].hidden, true);
  assert.deepEqual(JSON.parse(root.elements["#naive-payload"].value), config);
  assert.equal(root.elements["#naive-client-description"].textContent, "sing-box outbound — подходит для Karing.");
  assert.notEqual(root.elements["#naive-payload"].value, endpoint);
});
