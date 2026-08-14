from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import socketserver
import ssl
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .service import ManagerConflict, ManagerNotFound, NaiveCredentialManager


class ManagerHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, socket_path: Path, manager: NaiveCredentialManager, token: str, socket_uid: int | None = None, socket_mode: int = 0o600):
        self.socket_path = Path(socket_path)
        self.manager = manager
        self.token = token
        self.socket_uid = socket_uid
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.socket_path.unlink(missing_ok=True)
        super().__init__(str(self.socket_path), ManagerHandler)
        os.chmod(self.socket_path, socket_mode)
        if socket_uid is not None:
            os.chown(self.socket_path, socket_uid, -1)

    def server_close(self):
        super().server_close()
        self.socket_path.unlink(missing_ok=True)


class ManagerHandler(BaseHTTPRequestHandler):
    server: ManagerHTTPServer

    def log_message(self, _format, *_args):
        return

    def _send(self, status: int, payload=None):
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _authorized(self) -> bool:
        supplied = self.headers.get("X-Naive-Token", "")
        if not supplied or not secrets.compare_digest(supplied, self.server.token):
            self._send(401, {"detail": "unauthorized"})
            return False
        return True

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length < 0 or length > 8192:
            raise ValueError("invalid request body")
        if not length:
            return {}
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("object expected")
        return value

    def _dispatch(self):
        if not self._authorized():
            return
        path = urlsplit(self.path).path
        try:
            if self.command == "GET" and path == "/v1/health":
                health = self.server.manager.health()
                return self._send(200 if health.get("ready") is True else 503, health)
            if self.command == "GET" and path == "/v1/users":
                return self._send(200, self.server.manager.list_users())
            if self.command == "POST" and path == "/v1/users":
                return self._send(201, self.server.manager.create(self._body().get("username", "")))
            prefix = "/v1/users/"
            if path.startswith(prefix):
                tail = path[len(prefix):].split("/")
                username = unquote(tail[0])
                if self.command == "DELETE" and len(tail) == 1:
                    self.server.manager.delete(username)
                    return self._send(204)
                if self.command == "POST" and len(tail) == 2:
                    operation = tail[1]
                    self._body()
                    if operation == "access":
                        return self._send(200, self.server.manager.reveal(username))
                    if operation == "rotate":
                        return self._send(200, self.server.manager.rotate(username))
                    if operation == "enable":
                        return self._send(200, self.server.manager.set_enabled(username, True))
                    if operation == "disable":
                        return self._send(200, self.server.manager.set_enabled(username, False))
            self._send(404, {"detail": "not found"})
        except ManagerNotFound:
            self._send(404, {"detail": "not found"})
        except ManagerConflict:
            self._send(409, {"detail": "configuration conflict"})
        except (ValueError, json.JSONDecodeError):
            self._send(422, {"detail": "invalid request"})
        except Exception:
            self._send(500, {"detail": "manager operation failed"})

    do_GET = _dispatch
    do_POST = _dispatch
    do_DELETE = _dispatch


def command_validate(path: Path) -> dict:
    return caddy_adapt(path)


def command_reload() -> None:
    config = caddy_adapt(Path(os.getenv("NAIVE_CADDYFILE", "/data/Caddyfile")))
    request = urllib.request.Request(
        "http://127.0.0.1:2019/load", data=json.dumps(config, separators=(",", ":")).encode(), method="POST",
        headers={"Content-Type": "application/json", "Cache-Control": "must-revalidate"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status not in {200, 204}:
            raise RuntimeError("Caddy reload failed")


def caddy_adapt(path: Path) -> dict:
    request = urllib.request.Request(
        "http://127.0.0.1:2019/adapt?adapter=caddyfile&validate=true", data=path.read_bytes(), method="POST",
        headers={"Content-Type": "text/caddyfile"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.status != 200:
            raise RuntimeError("Caddy validation failed")
        payload = json.loads(response.read())
    if not isinstance(payload, dict):
        raise RuntimeError("Caddy returned an invalid configuration")
    config = payload.get("result", payload)
    if not isinstance(config, dict):
        raise RuntimeError("Caddy returned an invalid configuration")
    return config


def https_probe(host: str, port: int = 4443) -> None:
    context = ssl.create_default_context()
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            tls.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            status = tls.recv(128).split(b"\r\n", 1)[0]
            if not status.startswith((b"HTTP/1.1 200", b"HTTP/2 200")):
                raise RuntimeError("NaiveProxy cover probe failed")


def build_manager() -> NaiveCredentialManager:
    host = os.getenv("NAIVE_PUBLIC_HOST", "chrbased.dubr1k-solutions.com")
    return NaiveCredentialManager(
        caddyfile=Path(os.getenv("NAIVE_CADDYFILE", "/data/Caddyfile")),
        state_file=Path(os.getenv("NAIVE_STATE_FILE", "/data/users.json")),
        backup_dir=Path(os.getenv("NAIVE_BACKUP_DIR", "/data/backups")),
        public_host=host,
        validate=command_validate,
        reload=command_reload,
        probe=lambda: https_probe(host),
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap-only", action="store_true")
    args = parser.parse_args()
    manager = build_manager()
    manager.bootstrap()
    if args.bootstrap_only:
        return
    token_file = Path(os.getenv("NAIVE_MANAGER_TOKEN_FILE", "/etc/naive-manager/token"))
    token = token_file.read_text().strip()
    if len(token) < 32:
        raise SystemExit("manager token is missing or too short")
    server = ManagerHTTPServer(
        Path(os.getenv("NAIVE_MANAGER_SOCKET", "/run/naive-manager/manager.sock")),
        manager,
        token,
        None,
        int(os.getenv("NAIVE_SOCKET_MODE", "600"), 8),
    )
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
