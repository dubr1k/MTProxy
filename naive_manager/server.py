from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import socket
import socketserver
import ssl
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import unquote, urlsplit

from .service import ManagerConflict, ManagerNotFound, NaiveCredentialManager
from .traffic import (
    ACCOUNTING_MAX_VERIFY_BYTES,
    ACCOUNTING_ROLL_KEEP,
    ACCOUNTING_RETAINED_BYTES,
    TrafficCollector,
)

LOGGER = logging.getLogger("naive_manager")
QUOTA_INTERVAL_SECONDS = 60.0
QUOTA_MAX_BACKOFF_SECONDS = 900.0
CONNECTION_LOST = (BrokenPipeError, ConnectionResetError)


class QuotaEnforcer(threading.Thread):
    """Disable quota-exhausted users even when nobody has the panel open.

    Enforcement lives here rather than in the socket accept loop: a collection
    pass hashes the consumed log prefix and can end in a Caddy validate/reload,
    and the control socket must stay answerable while that runs.
    """

    def __init__(
        self,
        manager: NaiveCredentialManager,
        interval: float = QUOTA_INTERVAL_SECONDS,
        max_backoff: float = QUOTA_MAX_BACKOFF_SECONDS,
    ):
        super().__init__(name="naive-quota-enforcer", daemon=True)
        self.manager = manager
        self.interval = interval
        self.max_backoff = max_backoff
        self._stopped = threading.Event()

    def stop(self) -> None:
        self._stopped.set()

    def run(self) -> None:
        delay = self.interval
        while not self._stopped.wait(delay):
            try:
                disabled = self.manager.enforce_quotas()
            except Exception:
                delay = min(delay * 2, self.max_backoff)
                LOGGER.warning(
                    "quota enforcement failed; next attempt in %.0fs", delay, exc_info=True
                )
                continue
            if disabled:
                LOGGER.info("disabled after quota exhaustion: %s", ", ".join(sorted(disabled)))
            delay = self.interval


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

    def handle_error(self, request, client_address):
        if isinstance(sys.exc_info()[1], CONNECTION_LOST):
            return
        LOGGER.warning("manager request failed", exc_info=True)


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

    def _send_error(self, status: int, payload: dict) -> None:
        """Report a failure, tolerating a client that already hung up."""
        try:
            self._send(status, payload)
        except CONNECTION_LOST:
            self.close_connection = True

    def _dispatch(self):
        try:
            if not self._authorized():
                return
            path = urlsplit(self.path).path
            if self.command == "GET" and path == "/v1/health":
                health = self.server.manager.health()
                return self._send(200 if health.get("ready") is True else 503, health)
            if self.command == "GET" and path == "/v1/users":
                return self._send(200, self.server.manager.list_users())
            if self.command == "GET" and path == "/v1/traffic":
                return self._send(200, self.server.manager.traffic_report())
            if self.command == "POST" and path == "/v1/users":
                body = self._body()
                return self._send(
                    201,
                    self.server.manager.create(
                        body.get("username", ""), body.get("quota_bytes")
                    ),
                )
            prefix = "/v1/users/"
            if path.startswith(prefix):
                tail = path[len(prefix):].split("/")
                username = unquote(tail[0])
                if self.command == "DELETE" and len(tail) == 1:
                    self.server.manager.delete(username)
                    return self._send(204)
                if self.command == "POST" and len(tail) == 2:
                    operation = tail[1]
                    body = self._body()
                    if operation == "access":
                        return self._send(200, self.server.manager.reveal(username))
                    if operation == "rotate":
                        return self._send(200, self.server.manager.rotate(username))
                    if operation == "enable":
                        return self._send(200, self.server.manager.set_enabled(username, True))
                    if operation == "disable":
                        return self._send(200, self.server.manager.set_enabled(username, False))
                    if operation == "quota":
                        if "quota_bytes" not in body:
                            raise ValueError("quota_bytes is required")
                        return self._send(
                            200, self.server.manager.set_quota(username, body["quota_bytes"])
                        )
                if self.command == "POST" and len(tail) == 3 and tail[1:] == ["traffic", "reset"]:
                    self._body()
                    return self._send(200, self.server.manager.reset_traffic(username))
            self._send(404, {"detail": "not found"})
        except CONNECTION_LOST:
            # The panel or the healthcheck hung up mid-response: there is no
            # socket left to report on, and the operation already completed.
            self.close_connection = True
        except ManagerNotFound:
            self._send_error(404, {"detail": "not found"})
        except ManagerConflict as exc:
            self._send_error(409, {"detail": "configuration conflict", "code": exc.code})
        except (ValueError, json.JSONDecodeError):
            self._send_error(422, {"detail": "invalid request"})
        except Exception:
            LOGGER.warning("manager operation failed", exc_info=True)
            self._send_error(500, {"detail": "manager operation failed"})

    do_GET = _dispatch
    do_POST = _dispatch
    do_DELETE = _dispatch


def command_validate(path: Path) -> dict:
    return caddy_adapt(path)


def _rewrite_listener(config: dict) -> dict:
    servers = config.get("apps", {}).get("http", {}).get("servers", {})
    if not isinstance(servers, dict):
        raise RuntimeError("Caddy returned an invalid HTTP configuration")
    rewritten = False
    for server in servers.values():
        if not isinstance(server, dict) or not isinstance(server.get("listen"), list):
            continue
        server["listen"] = [
            "127.0.0.1:4443" if address == "127.0.0.1:443"
            else ":4443" if address == ":443"
            else address
            for address in server["listen"]
        ]
        rewritten = rewritten or any(
            address in {":4443", "127.0.0.1:4443"} for address in server["listen"]
        )
    if not rewritten:
        raise RuntimeError("Caddy configuration has no Naive listener")
    return config


def command_reload() -> None:
    config = _rewrite_listener(
        caddy_adapt(Path(os.getenv("NAIVE_CADDYFILE", "/data/Caddyfile")))
    )
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
    host = os.getenv("NAIVE_PUBLIC_HOST", "").strip()
    if not host:
        raise SystemExit("NAIVE_PUBLIC_HOST is required")
    manager = NaiveCredentialManager(
        caddyfile=Path(os.getenv("NAIVE_CADDYFILE", "/data/Caddyfile")),
        state_file=Path(os.getenv("NAIVE_STATE_FILE", "/data/users.json")),
        backup_dir=Path(os.getenv("NAIVE_BACKUP_DIR", "/data/backups")),
        public_host=host,
        validate=command_validate,
        reload=command_reload,
        probe=lambda: https_probe(host),
    )
    manager.traffic = TrafficCollector(
        Path(os.getenv("NAIVE_TRAFFIC_LOG", "/logs/access.json")),
        Path(os.getenv("NAIVE_TRAFFIC_DATABASE", "/data/traffic.sqlite3")),
        manager.managed_usernames,
        max_verify_bytes=ACCOUNTING_MAX_VERIFY_BYTES,
        expected_retained_bytes=ACCOUNTING_RETAINED_BYTES,
        max_rotations=ACCOUNTING_ROLL_KEEP,
    )
    return manager


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bootstrap-only", action="store_true")
    args = parser.parse_args()
    manager = build_manager()
    manager.bootstrap()
    if args.bootstrap_only:
        return
    traffic = manager.traffic
    if traffic is None:
        raise SystemExit("traffic accounting is unavailable")
    traffic.collect()
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
    enforcer = QuotaEnforcer(
        manager,
        float(os.getenv("NAIVE_QUOTA_INTERVAL_SECONDS", QUOTA_INTERVAL_SECONDS)),
    )
    enforcer.start()
    try:
        server.serve_forever()
    finally:
        enforcer.stop()
        server.server_close()
        traffic.close()


if __name__ == "__main__":
    main()
