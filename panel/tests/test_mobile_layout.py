from __future__ import annotations

import base64
import json
import os
import select
import shutil
import socket
import struct
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _browser() -> str:
    executable = next(
        (
            path
            for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable")
            if (path := shutil.which(name))
        ),
        None,
    )
    if executable is None:
        pytest.fail("Chromium-compatible browser is required for the mobile layout gate")
    return executable


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise RuntimeError("Chromium closed the DevTools WebSocket")
        chunks.extend(chunk)
    return bytes(chunks)


class DevTools:
    def __init__(self, url: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        self.connection = socket.create_connection((parsed.hostname, parsed.port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
            "Origin: http://localhost\r\n\r\n"
        )
        self.connection.sendall(request.encode())
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(self.connection.recv(4096))
        if not response.startswith(b"HTTP/1.1 101"):
            raise RuntimeError(f"DevTools WebSocket upgrade failed: {response[:200]!r}")
        self.next_id = 1

    def close(self) -> None:
        self.connection.close()

    def _send(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode()
        mask = os.urandom(4)
        if len(data) < 126:
            header = bytes((0x81, 0x80 | len(data)))
        elif len(data) <= 0xFFFF:
            header = bytes((0x81, 0x80 | 126)) + struct.pack("!H", len(data))
        else:
            header = bytes((0x81, 0x80 | 127)) + struct.pack("!Q", len(data))
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
        self.connection.sendall(header + mask + masked)

    def _receive(self) -> dict[str, Any]:
        first, second = _recv_exact(self.connection, 2)
        opcode = first & 0x0F
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", _recv_exact(self.connection, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", _recv_exact(self.connection, 8))[0]
        if second & 0x80:
            mask = _recv_exact(self.connection, 4)
            payload = bytes(
                byte ^ mask[index % 4] for index, byte in enumerate(_recv_exact(self.connection, length))
            )
        else:
            payload = _recv_exact(self.connection, length)
        if opcode == 0x8:
            raise RuntimeError("Chromium closed the DevTools WebSocket")
        if opcode != 0x1:
            return self._receive()
        return json.loads(payload)

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        message_id = self.next_id
        self.next_id += 1
        self._send({"id": message_id, "method": method, "params": params or {}})
        while True:
            response = self._receive()
            if response.get("id") == message_id:
                if "error" in response:
                    raise RuntimeError(f"DevTools {method} failed: {response['error']}")
                return response.get("result", {})


def _render_at_phone_viewport(page: Path, profile: Path) -> dict[str, Any]:
    process = subprocess.Popen(
        [
            _browser(),
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--remote-allow-origins=*",
            "--remote-debugging-port=0",
            f"--user-data-dir={profile}",
            "about:blank",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert process.stderr is not None
    try:
        deadline = time.monotonic() + 10
        browser_url = None
        while time.monotonic() < deadline:
            readable, _, _ = select.select([process.stderr], [], [], 0.25)
            if readable:
                line = process.stderr.readline()
                if "DevTools listening on " in line:
                    browser_url = line.split("DevTools listening on ", 1)[1].strip()
                    break
            if process.poll() is not None:
                raise RuntimeError(f"Chromium exited before DevTools was ready: {process.returncode}")
        if browser_url is None:
            raise RuntimeError("Chromium DevTools endpoint did not become ready")
        parsed = urllib.parse.urlsplit(browser_url)
        targets = json.load(urllib.request.urlopen(f"http://{parsed.netloc}/json/list", timeout=5))
        target_url = next(target["webSocketDebuggerUrl"] for target in targets if target["type"] == "page")
        devtools = DevTools(target_url)
        try:
            devtools.call(
                "Emulation.setDeviceMetricsOverride",
                {"width": 390, "height": 844, "deviceScaleFactor": 1, "mobile": True},
            )
            devtools.call("Page.navigate", {"url": page.as_uri()})
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                result = devtools.call(
                    "Runtime.evaluate",
                    {
                        "expression": "({result:document.body?.dataset.result,errors:document.body?.dataset.errors,innerWidth})",
                        "returnByValue": True,
                    },
                )["result"].get("value", {})
                if result.get("result"):
                    return result
                time.sleep(0.05)
            raise RuntimeError("Mobile layout assertions did not finish")
        finally:
            devtools.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def test_access_cards_and_navigation_do_not_collide_on_phone(tmp_path: Path) -> None:
    """Real card variants must stack cleanly in an emulated 390 CSS-pixel viewport."""
    css = (ROOT / "static" / "style.css").read_text()
    buttons = "".join(
        f'<button><span class="mobile-icon">◇</span><small>{label}</small></button>'
        for label in ("Обзор", "MTProxy", "Mieru", "Naive", "Версии", "Узлы", "Админы", "Журнал", "Выйти")
    )

    def card(classes: str, glyph: str, username: str, protocol: str, configuration: str) -> str:
        return f"""
          <div class="{classes}">
            <div class="identity"><span class="user-glyph">{glyph}</span><span><b>{username}</b><small>{protocol}</small></span></div>
            <div class="cell"><span class="status-pill active"><i></i>Активен</span></div>
            <div class="cell"><b>↑ 56 Б · ↓ 868 Б · Σ 924 Б</b><small>квота без квоты</small></div>
            <div class="row-actions">
              <button class="action-button">{configuration}</button><button class="action-button">Квота</button>
              <button class="action-button">Сбросить трафик</button><button class="action-button">Отключить</button>
              <button class="action-button">Новая ссылка + QR</button><button class="action-button danger-text">Удалить</button>
            </div>
          </div>
        """

    cards = "".join(
        (
            card("data-row", "MT", "mt-user-with-a-very-long-name", "MTProto · FakeTLS", "Подключение"),
            card("data-row naive-grid", "MI", "mieru-user-with-a-very-long-name", "Mieru · native AEAD", "Конфигурация"),
            card("data-row naive-grid", "NP", "naive-user-with-a-very-long-name", "HTTPS · HTTP/2 CONNECT", "Конфигурация"),
        )
    )
    script = """
      addEventListener("load", () => {
        const errors = [];
        const tolerance = 1;
        if (innerWidth !== 390) errors.push(`viewport is ${innerWidth}px instead of 390px`);
        for (const row of document.querySelectorAll(".data-row")) {
          const [identity, status, traffic, actions] = row.children;
          const boxes = [identity, status, traffic, actions].map((node) => node.getBoundingClientRect());
          if (boxes[1].top + tolerance < boxes[0].bottom) errors.push("status overlaps identity");
          if (boxes[2].top + tolerance < boxes[1].bottom) errors.push("traffic overlaps status");
          if (boxes[3].top + tolerance < boxes[2].bottom) errors.push("actions overlap traffic");
          const rowBox = row.getBoundingClientRect();
          for (const region of row.children) {
            const box = region.getBoundingClientRect();
            if (box.left < rowBox.left - tolerance || box.right > rowBox.right + tolerance || region.scrollWidth > region.clientWidth + tolerance) {
              errors.push("card content escapes horizontally");
            }
          }
          const actionButtons = [...actions.querySelectorAll("button")];
          for (const button of actionButtons) {
            const box = button.getBoundingClientRect();
            if (box.left < rowBox.left - tolerance || box.right > rowBox.right + tolerance) errors.push("action escapes card");
          }
          const buttonBoxes = actionButtons.map((button) => button.getBoundingClientRect());
          if (Math.abs(buttonBoxes[0].top - buttonBoxes[1].top) > tolerance || buttonBoxes[2].top <= buttonBoxes[0].bottom) {
            errors.push("actions are not a compact two-column grid");
          }
        }
        const nav = document.querySelector(".mobile-nav");
        const navButtons = [...nav.querySelectorAll("button")];
        if (!navButtons.every((button) => {
          const box = button.getBoundingClientRect();
          return box.width >= 60 && box.height >= 60;
        })) errors.push("navigation target is smaller than 60px");
        if (nav.scrollWidth <= nav.clientWidth) errors.push("navigation does not scroll");
        document.body.dataset.result = errors.length ? "fail" : "pass";
        document.body.dataset.errors = JSON.stringify(errors);
      });
    """
    page = tmp_path / "mobile-layout.html"
    page.write_text(
        "<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<style>{css}</style></head><body><main>{cards}</main>"
        f"<nav class='mobile-nav'>{buttons}</nav><script>{script}</script></body></html>"
    )

    rendered = _render_at_phone_viewport(page, tmp_path / "chromium-profile")
    errors = json.loads(rendered["errors"])
    assert rendered["innerWidth"] == 390
    assert rendered["result"] == "pass", errors
