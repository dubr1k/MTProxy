from __future__ import annotations

import http.client
import json
import threading

import pytest

from mieru_manager.server import ManagerHTTPServer
from mieru_manager.healthcheck import check as manager_healthcheck
from panel.mieru import MieruClient


class StubManager:
    def __init__(self):
        self.lifecycle_actions = []

    def bootstrap(self):
        return {"ready": True, "version": "3.35.0", "revision": "rev-1"}

    def inspect(self):
        return {"ready": True, "status": "running", "revision": "rev-1"}

    def list_users(self):
        return [{"username": "alice", "enabled": True, "quotas": []}]

    def metrics(self):
        return {"status": "ready", "stale": False, "users": []}

    def lifecycle(self, action):
        self.lifecycle_actions.append(action)
        return {
            "ready": action != "stop",
            "status": "stopped" if action == "stop" else "running",
            "revision": "rev-1",
        }

    def create_user(self, username, quotas, *, expected_revision, **flags):
        assert expected_revision == "rev-1"
        return {
            "username": username,
            "share_url": "mierus://alice:p%40ss@example?port=8443&protocol=TCP",
            "revision": "rev-2",
        }

    def set_quotas(self, username, quotas, *, expected_revision):
        return {"username": username, "revision": "rev-2"}

    def disable_user(self, username, *, expected_revision):
        return {"username": username, "enabled": False, "revision": "rev-2"}

    def enable_user(self, username, *, expected_revision):
        return {"username": username, "enabled": True, "revision": "rev-2"}

    def rotate_user(self, username, *, expected_revision):
        return self.create_user(username, [], expected_revision=expected_revision)

    def delete_user(self, username, *, expected_revision):
        return {"username": username, "revision": "rev-2"}

    def reset_metric_baseline(self, username):
        return {"username": username, "baseline_reset": True}


def request(socket_path, token, method, path, body=None):
    connection = http.client.HTTPConnection("localhost")
    connection.sock = __import__("socket").socket(__import__("socket").AF_UNIX)
    connection.sock.connect(str(socket_path))
    payload = b"" if body is None else json.dumps(body).encode()
    connection.request(
        method,
        path,
        payload,
        {"X-Mieru-Token": token, "Content-Type": "application/json"},
    )
    response = connection.getresponse()
    data = response.read()
    return response.status, dict(response.headers), json.loads(data) if data else None


def test_manager_unix_api_is_authenticated_bounded_and_no_store(tmp_path):
    socket_path = tmp_path / "manager.sock"
    manager = StubManager()
    server = ManagerHTTPServer(socket_path, manager, "x" * 32)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, headers, data = request(socket_path, "wrong", "GET", "/v1/users")
        assert status == 401
        status, headers, data = request(socket_path, "x" * 32, "GET", "/v1/users")
        assert status == 200 and data[0]["username"] == "alice"
        assert headers["Cache-Control"] == "no-store"
        status, _, data = request(
            socket_path,
            "x" * 32,
            "POST",
            "/v1/users",
            {"username": "alice", "quotas": [], "expected_revision": "rev-1"},
        )
        assert status == 201 and data["share_url"].startswith("mierus://")
        status, _, data = request(
            socket_path, "x" * 32, "POST", "/v1/lifecycle/restart", {}
        )
        assert status == 200
        assert data == {"ready": True, "status": "running", "revision": "rev-1"}
        assert manager.lifecycle_actions == ["restart"]
        status, _, _ = request(
            socket_path, "x" * 32, "POST", "/v1/lifecycle/restart", {"action": "stop"}
        )
        assert status == 422
        status, _, _ = request(
            socket_path, "x" * 32, "POST", "/v1/lifecycle/reload", {}
        )
        assert status == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_manager_healthcheck_uses_authenticated_unix_health_endpoint(tmp_path):
    socket_path = tmp_path / "manager.sock"
    token_path = tmp_path / "token"
    token_path.write_text("x" * 32)
    server = ManagerHTTPServer(socket_path, StubManager(), "x" * 32)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert manager_healthcheck(socket_path, token_path) is True
        token_path.write_text("y" * 32)
        assert manager_healthcheck(socket_path, token_path) is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


pytestmark = pytest.mark.anyio


async def test_panel_mieru_owner_lifecycle_is_one_time_and_audited(
    client, login_user, mieru
):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    listed = await client.get("/api/mieru/users")
    assert listed.status_code == 200
    assert (
        listed.json()["quota_semantics"]
        == "rolling application-byte admission quota (approximate)"
    )
    created = await client.post(
        "/api/mieru/users",
        json={
            "username": "phone",
            "quotas": [{"days": 30, "megabytes": 1024}],
            "expected_revision": "rev-1",
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    revealed = await client.get("/api/reveal/" + created.json()["reveal_token"])
    assert revealed.json()["share_url"].startswith("mierus://phone:")
    assert (
        await client.get("/api/reveal/" + created.json()["reveal_token"])
    ).status_code == 410
    assert (
        await client.post(
            "/api/mieru/users/phone/disable",
            json={"expected_revision": created.json()["revision"]},
            headers={"X-CSRF-Token": csrf},
        )
    ).status_code == 200
    assert "share_url" not in (await client.get("/api/mieru/users")).text
    audit = str((await client.get("/api/audit")).json())
    assert "mierus://" not in audit and "mieru.create" in audit


async def test_panel_mieru_viewer_is_read_only(client, login_user):
    store = client._transport.app.state.store
    store.create_admin("viewer-m", "viewer password long enough", "viewer")
    await login_user(client, "viewer-m", "viewer password long enough")
    csrf = client.cookies["panel_csrf"]
    assert (await client.get("/api/mieru/users")).status_code == 200
    response = await client.post(
        "/api/mieru/users",
        json={"username": "x", "quotas": [], "expected_revision": "rev-1"},
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 403


async def test_dashboard_reports_mieru_disabled_ready_and_degraded(
    client, login_user, mieru
):
    await login_user(client)
    ready = (await client.get("/api/dashboard")).json()["protocols"]["mieru"]
    assert (
        ready["status"] == "ready" and ready["traffic"]["label"] == "application bytes"
    )
    mieru.broken = True
    degraded = (await client.get("/api/dashboard")).json()["protocols"]["mieru"]
    assert degraded["status"] == "degraded"


async def test_mieru_client_sanitizes_manager_errors():
    import httpx

    async def handler(_request):
        return httpx.Response(409, text='{"detail":"hash aaaa password secret"}')

    client = MieruClient(
        "/run/mieru.sock", "token", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(Exception, match="manager rejected request") as error:
        await client.list_users()
    assert "password" not in str(error.value)


async def test_mieru_client_lifecycle_uses_fixed_allowlisted_path_and_empty_body():
    import httpx

    seen = {}

    async def handler(request):
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(
            200, json={"ready": True, "status": "running", "revision": "rev-1"}
        )

    client = MieruClient(
        "/run/mieru-manager/manager.sock",
        "x" * 32,
        transport=httpx.MockTransport(handler),
    )
    assert (await client.lifecycle("restart"))["ready"] is True
    assert seen == {"method": "POST", "path": "/v1/lifecycle/restart", "body": {}}
    with pytest.raises(ValueError, match="lifecycle"):
        await client.lifecycle("reload")
