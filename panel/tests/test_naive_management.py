from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit
import pytest
import httpx

from panel.app import Settings, create_app
from panel.naive import MemoryNaive, NaiveClient, NaiveError
from panel.telemt import MemoryTelemt

pytestmark = pytest.mark.anyio


async def test_naive_list_is_secret_free_and_viewer_is_read_only(client, login_user, naive):
    naive.seed("phone", "hidden-password", enabled=True)
    await login_user(client)

    listed = await client.get("/api/naive/users")
    assert listed.status_code == 200
    assert listed.json() == {
        "items": [{
            "username": "phone", "enabled": True, "upload_bytes": 0,
            "download_bytes": 0, "total_bytes": 0,
            "upload_bytes_decimal": "0", "download_bytes_decimal": "0",
            "total_bytes_decimal": "0",
            "disabled_reason": None, "quota_bytes": None,
            "quota_bytes_decimal": None, "quota_used_bytes": 0,
            "quota_used_bytes_decimal": "0", "quota_remaining_bytes": None,
            "quota_remaining_bytes_decimal": None, "quota_exhausted": False,
            "period_start": naive.period_start, "updated_at": naive.period_start,
        }],
        "service": {"ready": True, "host": "naive.example.com"},
        "traffic": {
            "source": "caddy_connect_access_log", "unit": "bytes", "pending": False,
            "directions": {"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"},
        },
    }
    assert "hidden-password" not in listed.text

    await client.post("/api/auth/logout", headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    client.cookies.clear()
    client._transport.app.state.store.create_admin("naive-viewer", "viewer correct horse battery", "viewer")
    await login_user(client, "naive-viewer", "viewer correct horse battery")
    csrf = client.cookies["panel_csrf"]
    assert (await client.get("/api/naive/users")).status_code == 200
    assert (await client.post("/api/naive/users", json={"username": "new"}, headers={"X-CSRF-Token": csrf})).status_code == 403
    assert (await client.post("/api/naive/users/phone/access", headers={"X-CSRF-Token": csrf})).status_code == 403


async def test_naive_owner_can_create_reveal_rotate_toggle_and_delete(client, login_user, naive):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]

    created = await client.post(
        "/api/naive/users",
        json={"username": "ios-phone"},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    first = await client.get("/api/reveal/" + created.json()["reveal_token"])
    assert first.status_code == 200
    assert first.headers["cache-control"] == "no-store"
    reveal = first.json()
    assert set(reveal["clients"]) == {"native", "karing", "shadowrocket"}
    native = reveal["clients"]["native"]
    assert native["type"] == "config"
    assert native["config"]["listen"] == "socks://127.0.0.1:1080"
    assert native["config"]["proxy"].startswith("https://ios-phone:")
    assert native["config"]["proxy"].endswith("@naive.example.com")
    assert "qr" not in native

    karing = reveal["clients"]["karing"]
    assert karing["type"] == "link"
    assert karing["import_url"].startswith("karing://install-config?")
    assert karing["qr"]["payload"] == karing["import_url"]
    assert karing["qr"]["image"].startswith("data:image/svg+xml;base64,")
    karing_query = parse_qs(urlsplit(karing["import_url"]).query)
    profile = json.loads(karing_query["url"][0])
    assert profile == karing["config"]
    assert profile["outbounds"] == [{
        "type": "naive",
        "tag": "naive-ios-phone",
        "server": "naive.example.com",
        "server_port": 443,
        "username": "ios-phone",
        "password": urlsplit(native["config"]["proxy"]).password,
        "tls": {"enabled": True, "server_name": "naive.example.com"},
    }]
    assert not karing["qr"]["payload"].startswith("https://")

    shadowrocket = reveal["clients"]["shadowrocket"]
    assert shadowrocket == {
        "label": "Shadowrocket",
        "type": "manual",
        "fields": {
            "proxy_type": "HTTPS",
            "server": "naive.example.com",
            "port": 443,
            "username": "ios-phone",
            "password": urlsplit(native["config"]["proxy"]).password,
        },
    }
    assert "proxy_url" not in reveal and "qr" not in reveal

    access = await client.post("/api/naive/users/ios-phone/access", headers={"X-CSRF-Token": csrf})
    assert access.status_code == 200
    assert access.json()["clients"]["native"]["config"] == native["config"]

    rotated = await client.post("/api/naive/users/ios-phone/rotate", headers={"X-CSRF-Token": csrf})
    assert rotated.status_code == 200
    second = await client.get("/api/reveal/" + rotated.json()["reveal_token"])
    assert (
        second.json()["clients"]["native"]["config"]["proxy"]
        != native["config"]["proxy"]
    )

    assert (await client.post("/api/naive/users/ios-phone/disable", headers={"X-CSRF-Token": csrf})).status_code == 200
    assert (await client.get("/api/naive/users")).json()["items"][0]["enabled"] is False
    assert (await client.post("/api/naive/users/ios-phone/enable", headers={"X-CSRF-Token": csrf})).status_code == 200
    assert (await client.delete("/api/naive/users/ios-phone", headers={"X-CSRF-Token": csrf})).status_code == 204

    audit = (await client.get("/api/audit")).json()["items"]
    actions = [row["action"] for row in audit]
    assert {"naive.create", "naive.access", "naive.rotate", "naive.disable", "naive.enable", "naive.delete"} <= set(actions)
    audit_text = str(audit)
    assert "hidden-password" not in audit_text
    assert "https://ios-phone:" not in audit_text


async def test_naive_usernames_are_validated_before_manager_call(client, login_user, naive):
    await login_user(client)
    response = await client.post(
        "/api/naive/users",
        json={"username": "bad user"},
        headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )
    assert response.status_code == 422
    assert naive.calls == []


async def test_naive_adapter_accepts_empty_204_delete_response():
    async def handler(request):
        assert request.method == "DELETE"
        return httpx.Response(204)

    adapter = NaiveClient("/run/manager.sock", "internal-token", transport=httpx.MockTransport(handler))
    assert await adapter.delete("phone") is None


def test_enabled_naive_requires_explicit_public_host(tmp_path):
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        naive_public_host="",
        naive_enabled=True,
    )
    with pytest.raises(ValueError, match="NAIVE_PUBLIC_HOST is required"):
        create_app(settings, telemt=MemoryTelemt(), naive=MemoryNaive())


async def test_naive_feature_is_hidden_and_routes_fail_closed_when_disabled(tmp_path):
    class MustNotCallNaive(MemoryNaive):
        async def health(self):
            raise AssertionError("disabled dashboard called Naive health")

        async def list_users(self):
            raise AssertionError("disabled dashboard called Naive users")

    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        naive_enabled=False,
    )
    app = create_app(settings, telemt=MemoryTelemt(), naive=MustNotCallNaive())
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
        follow_redirects=False,
    ) as client:
        login_page = await client.get("/login")
        login = await client.post(
            "/api/auth/login",
            json={"username": "owner", "password": "correct horse battery staple"},
            headers={"X-CSRF-Token": login_page.cookies["panel_csrf"]},
        )
        assert login.status_code == 204
        identity = await client.get("/api/auth/me")
        assert identity.json()["features"]["naive"] is False
        dashboard = await client.get("/api/dashboard")
        assert dashboard.status_code == 200
        assert dashboard.json()["protocols"]["naive"] == {
            "available": False,
            "status": "disabled",
        }
        assert (await client.get("/api/naive/users")).status_code == 404
        assert (
            await client.post(
                "/api/naive/users",
                json={"username": "phone"},
                headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
            )
        ).status_code == 404


async def test_dashboard_stays_available_when_enabled_naive_manager_is_degraded(
    client, login_user,
):
    class BrokenNaive(MemoryNaive):
        async def health(self):
            raise NaiveError("manager contains internal details")

        async def list_users(self):
            raise NaiveError("manager contains internal details")

    client._transport.app.state.naive = BrokenNaive()
    await login_user(client)

    response = await client.get("/api/dashboard")

    assert response.status_code == 200
    assert response.json()["protocols"]["mtproxy"]["status"] == "ready"
    assert response.json()["protocols"]["naive"] == {
        "available": True,
        "status": "degraded",
        "ready": False,
        "host": "naive.example.com",
        "credentials": {"available": False},
        "traffic": {"available": False, "reason": "manager_unavailable"},
    }
    assert "internal details" not in response.text


async def test_creating_reveal_purges_expired_password_bearing_entries(client, login_user, monkeypatch):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    monkeypatch.setattr("panel.app.time.monotonic", lambda: 100.0)
    first = await client.post(
        "/api/naive/users",
        json={"username": "first"},
        headers={"X-CSRF-Token": csrf},
    )
    first_token = first.json()["reveal_token"]
    monkeypatch.setattr("panel.app.time.monotonic", lambda: 1000.0)

    await client.post(
        "/api/naive/users",
        json={"username": "second"},
        headers={"X-CSRF-Token": csrf},
    )

    assert first_token not in client._transport.app.state.reveals


async def test_naive_traffic_is_allowlisted_in_users_and_dashboard_and_admin_can_reset(
    client, login_user, naive,
):
    naive.seed("phone", "hidden", enabled=True)
    naive.set_traffic("phone", upload=12345, download=67890)
    await login_user(client)
    listed = (await client.get("/api/naive/users")).json()
    assert listed["items"][0]["upload_bytes"] == 12345
    assert listed["items"][0]["download_bytes"] == 67890
    assert listed["items"][0]["total_bytes"] == 80235
    assert "password" not in str(listed).lower()
    dashboard = (await client.get("/api/dashboard")).json()["protocols"]["naive"]["traffic"]
    assert dashboard["aggregate"] == {
        "upload_bytes": 12345, "download_bytes": 67890, "total_bytes": 80235,
        "upload_bytes_decimal": "12345", "download_bytes_decimal": "67890",
        "total_bytes_decimal": "80235",
    }
    csrf = client.cookies["panel_csrf"]
    reset = await client.post(
        "/api/naive/users/phone/traffic/reset", headers={"X-CSRF-Token": csrf},
    )
    assert reset.status_code == 200
    assert reset.json()["total_bytes"] == 0
    assert naive.users["phone"]["password"] == "hidden"
    assert ("reset_traffic", "phone") in naive.calls
    audit = (await client.get("/api/audit")).json()["items"]
    assert any(row["action"] == "naive.traffic.reset" for row in audit)


async def test_viewer_cannot_reset_naive_traffic(client, login_user, naive):
    naive.seed("phone", "hidden", enabled=True)
    client._transport.app.state.store.create_admin("reader", "viewer correct horse battery", "viewer")
    await login_user(client, "reader", "viewer correct horse battery")
    response = await client.post(
        "/api/naive/users/phone/traffic/reset",
        headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )
    assert response.status_code == 403
    assert not any(call[0] == "reset_traffic" for call in naive.calls)


async def test_naive_owner_can_set_and_remove_quota_without_changing_password(
    client, login_user, naive,
):
    naive.seed("phone", "hidden", enabled=True)
    await login_user(client)
    csrf = client.cookies["panel_csrf"]

    set_response = await client.post(
        "/api/naive/users/phone/quota",
        json={"quota_bytes": 2 * 1024 * 1024},
        headers={"X-CSRF-Token": csrf},
    )
    assert set_response.status_code == 200
    assert set_response.json() == {
        "username": "phone", "quota_bytes": 2 * 1024 * 1024,
        "enabled": True, "disabled_reason": None,
    }
    assert naive.users["phone"]["password"] == "hidden"
    listed = (await client.get("/api/naive/users")).json()["items"][0]
    assert listed["quota_bytes"] == 2 * 1024 * 1024
    assert listed["quota_used_bytes"] == 0
    assert listed["quota_remaining_bytes"] == 2 * 1024 * 1024

    naive.set_traffic("phone", upload=1024 * 1024, download=1024 * 1024)
    exhausted = (await client.get("/api/naive/users")).json()["items"][0]
    assert exhausted["quota_exhausted"] is True
    assert exhausted["enabled"] is False
    assert exhausted["disabled_reason"] == "quota"

    remove_response = await client.post(
        "/api/naive/users/phone/quota",
        json={"quota_bytes": None},
        headers={"X-CSRF-Token": csrf},
    )
    assert remove_response.status_code == 200
    # Removing the quota lifts the limit but never re-opens access on its own.
    assert remove_response.json() == {
        "username": "phone", "quota_bytes": None,
        "enabled": False, "disabled_reason": "manual",
    }
    unlimited = (await client.get("/api/naive/users")).json()["items"][0]
    assert unlimited["quota_bytes"] is None
    assert unlimited["quota_exhausted"] is False
    assert unlimited["enabled"] is False
    assert unlimited["disabled_reason"] == "manual"
    assert ("set_quota", "phone", 2 * 1024 * 1024) in naive.calls
    assert ("set_quota", "phone", None) in naive.calls
    audit = (await client.get("/api/audit")).json()["items"]
    assert sum(row["action"] == "naive.quota" for row in audit) == 2


async def test_enabling_an_exhausted_user_reports_the_quota_reason_not_an_outage(
    client, login_user, naive,
):
    """A refused enable is an actionable state, not a manager failure."""
    naive.seed("phone", "hidden", enabled=True, quota_bytes=1024)
    naive.set_traffic("phone", upload=1024, download=0)
    await login_user(client)
    csrf = client.cookies["panel_csrf"]

    listed = (await client.get("/api/naive/users")).json()["items"][0]
    assert listed["enabled"] is False
    assert listed["disabled_reason"] == "quota"

    response = await client.post(
        "/api/naive/users/phone/enable", headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "quota_exhausted"
    assert "unavailable" not in response.json()["detail"].lower()


async def test_naive_create_accepts_quota_and_invalid_quota_never_reaches_manager(
    client, login_user, naive,
):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post(
        "/api/naive/users",
        json={"username": "limited", "quota_bytes": 1024},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    assert naive.users["limited"]["quota_bytes"] == 1024

    naive.calls.clear()
    invalid = await client.post(
        "/api/naive/users/limited/quota",
        json={"quota_bytes": 0},
        headers={"X-CSRF-Token": csrf},
    )
    assert invalid.status_code == 422
    assert naive.calls == []


async def test_viewer_cannot_change_naive_quota(client, login_user, naive):
    naive.seed("phone", "hidden", enabled=True)
    client._transport.app.state.store.create_admin("reader", "viewer correct horse battery", "viewer")
    await login_user(client, "reader", "viewer correct horse battery")
    response = await client.post(
        "/api/naive/users/phone/quota",
        json={"quota_bytes": 1024},
        headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )
    assert response.status_code == 403
    assert not any(call[0] == "set_quota" for call in naive.calls)
