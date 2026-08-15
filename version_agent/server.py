from __future__ import annotations

import http.server
import json
import os
import socket
import socketserver
from pathlib import Path

from .catalog import CatalogError
from .service import ConflictError, UpdateError, agent_from_env

_MAX_BODY = 16 * 1024


class UnixHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    address_family = socket.AF_UNIX
    daemon_threads = True
    allow_reuse_address = True
    agent = None

    def __init__(self, socket_path: str, handler, *, gid: int):
        self.socket_path = socket_path
        self.gid = gid
        parent = Path(socket_path).parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            Path(socket_path).unlink()
        except FileNotFoundError:
            pass
        super().__init__(socket_path, handler, bind_and_activate=True)
        os.chmod(socket_path, 0o660)
        try:
            os.chown(socket_path, 0, gid)
        except PermissionError as exc:
            self.server_close()
            raise RuntimeError("cannot set version-agent socket group") from exc

    def server_close(self):
        super().server_close()
        try:
            Path(self.socket_path).unlink()
        except FileNotFoundError:
            pass


class Handler(http.server.BaseHTTPRequestHandler):
    server: UnixHTTPServer

    def log_message(self, _format, *_args):
        # Never log request bodies, because future catalog fields must not become
        # accidental secret-bearing logs.
        return

    def _send(self, status: int, value: dict) -> None:
        payload = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/v1/health":
            self._send(200, {"status": "ok"})
            return
        if self.path != "/v1/versions":
            self._send(404, {"detail": "not found"})
            return
        try:
            self._send(200, self.server.agent.list_versions())
        except (CatalogError, UpdateError):
            self._send(503, {"detail": "version catalog unavailable"})

    def do_POST(self):  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/v1/update":
            self._send(404, {"detail": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > _MAX_BODY:
            self._send(413, {"detail": "request body too large"})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send(422, {"detail": "invalid JSON"})
            return
        if not isinstance(body, dict) or set(body) != {"component", "version", "expected_current"}:
            self._send(422, {"detail": "invalid update request"})
            return
        component = body["component"]
        version = body["version"]
        expected = body["expected_current"]
        if (
            type(component) is not str
            or type(version) is not str
            or (expected is not None and type(expected) is not str)
        ):
            self._send(422, {"detail": "invalid update request"})
            return
        try:
            result = self.server.agent.update(component, version, expected)
        except ConflictError as exc:
            self._send(409, {"detail": str(exc)})
        except CatalogError as exc:
            self._send(422, {"detail": str(exc)})
        except UpdateError:
            self._send(502, {"detail": "update failed and rollback was attempted"})
        else:
            self._send(200, result)


def main() -> None:
    agent = agent_from_env()
    socket_path = os.getenv("PROXY_CONTROL_VERSION_SOCKET", "/run/proxy-control/version-agent.sock")
    gid = int(os.getenv("PROXY_CONTROL_VERSION_SOCKET_GID", "10001"))
    server = UnixHTTPServer(socket_path, Handler, gid=gid)
    server.agent = agent
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
