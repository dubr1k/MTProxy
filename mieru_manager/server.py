"""Authenticated, body-bounded HTTP API on a local Unix socket."""

from __future__ import annotations

import json
import os
import secrets
import socketserver
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .service import ConfigConflict, MitaError, ValidationError


class ManagerHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(
        self,
        socket_path: Path,
        manager,
        token: str,
        *,
        socket_uid: int | None = None,
        socket_mode: int = 0o600,
    ):
        if len(token) < 32:
            raise ValueError("manager token is too short")
        self.socket_path, self.manager, self.token = Path(socket_path), manager, token
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

    def _send(self, status: int, value=None):
        data = (
            b"" if value is None else json.dumps(value, separators=(",", ":")).encode()
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def _body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValidationError("invalid body") from exc
        if not 0 <= length <= 32_768:
            raise ValidationError("invalid body")
        try:
            value = json.loads(self.rfile.read(length)) if length else {}
        except ValueError as exc:
            raise ValidationError("invalid body") from exc
        if not isinstance(value, dict):
            raise ValidationError("invalid body")
        return value

    @staticmethod
    def _exact(body: dict, required: set[str], optional: set[str] = frozenset()):
        if not required <= set(body) or set(body) - required - optional:
            raise ValidationError("invalid request fields")

    def _dispatch(self):
        supplied = self.headers.get("X-Mieru-Token", "")
        if not supplied or not secrets.compare_digest(supplied, self.server.token):
            return self._send(401, {"detail": "unauthorized"})
        path = urlsplit(self.path).path
        try:
            if self.command == "GET" and path == "/v1/health":
                return self._send(200, self.server.manager.inspect())
            if self.command == "GET" and path == "/v1/users":
                return self._send(200, self.server.manager.list_users())
            if self.command == "GET" and path == "/v1/metrics":
                return self._send(200, self.server.manager.metrics())
            lifecycle_prefix = "/v1/lifecycle/"
            if self.command == "POST" and path.startswith(lifecycle_prefix):
                action = path[len(lifecycle_prefix) :]
                if action not in {"start", "stop", "restart"}:
                    return self._send(404, {"detail": "not found"})
                body = self._body()
                self._exact(body, set())
                return self._send(200, self.server.manager.lifecycle(action))
            if self.command == "POST" and path == "/v1/users":
                body = self._body()
                self._exact(
                    body,
                    {"username", "quotas", "expected_revision"},
                    {"elevated", "allow_private_ip", "allow_loopback_ip"},
                )
                return self._send(
                    201,
                    self.server.manager.create_user(
                        body["username"],
                        body["quotas"],
                        expected_revision=body["expected_revision"],
                        elevated=body.get("elevated", False),
                        allow_private_ip=body.get("allow_private_ip", False),
                        allow_loopback_ip=body.get("allow_loopback_ip", False),
                    ),
                )
            prefix = "/v1/users/"
            if path.startswith(prefix):
                tail = path[len(prefix) :].split("/")
                username = unquote(tail[0])
                if self.command == "DELETE" and len(tail) == 1:
                    body = self._body()
                    self._exact(body, {"expected_revision"})
                    return self._send(
                        200,
                        self.server.manager.delete_user(
                            username, expected_revision=body["expected_revision"]
                        ),
                    )
                if self.command == "POST" and len(tail) == 2:
                    body = self._body()
                    operation = tail[1]
                    if operation == "quotas":
                        self._exact(body, {"quotas", "expected_revision"})
                        return self._send(
                            200,
                            self.server.manager.set_quotas(
                                username,
                                body["quotas"],
                                expected_revision=body["expected_revision"],
                            ),
                        )
                    if operation == "reset-metrics":
                        self._exact(body, set())
                        return self._send(
                            200, self.server.manager.reset_metric_baseline(username)
                        )
                    self._exact(body, {"expected_revision"})
                    actions = {
                        "enable": self.server.manager.enable_user,
                        "disable": self.server.manager.disable_user,
                        "rotate": self.server.manager.rotate_user,
                    }
                    if operation in actions:
                        return self._send(
                            200,
                            actions[operation](
                                username, expected_revision=body["expected_revision"]
                            ),
                        )
            return self._send(404, {"detail": "not found"})
        except ConfigConflict:
            return self._send(409, {"detail": "configuration conflict"})
        except ValidationError:
            return self._send(422, {"detail": "invalid request"})
        except MitaError:
            return self._send(503, {"detail": "manager operation failed"})

    do_GET = do_POST = do_DELETE = _dispatch
