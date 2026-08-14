from __future__ import annotations

import pytest

from panel.telemt import TelemtClient, TelemtError


pytestmark = pytest.mark.anyio


async def test_user_crud_rotate_and_one_time_reveal(client, login_user, telemt):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post("/api/users", json={"username": "alice"}, headers={"X-CSRF-Token": csrf})
    assert created.status_code == 201
    body = created.json()
    assert set(body) == {"username", "reveal_token"}
    assert "secret" not in str(client._transport.app.state.store.dump_schema()).lower()
    token = body["reveal_token"]
    revealed = await client.get(f"/api/reveal/{token}")
    assert len(revealed.json()["secret"]) == 32 and "tg://proxy" in revealed.json()["link"]
    assert (await client.get(f"/api/reveal/{token}")).status_code == 410
    assert (await client.post("/api/users/alice/disable", headers={"X-CSRF-Token": csrf})).status_code == 200
    assert telemt.users["alice"]["enabled"] is False
    rotated = await client.post("/api/users/alice/rotate", headers={"X-CSRF-Token": csrf})
    assert rotated.status_code == 200 and "secret" not in rotated.json()
    assert (await client.delete("/api/users/alice", headers={"X-CSRF-Token": csrf})).status_code == 204


async def test_dashboard_collects_health_stats_connections_and_active_ips(client, login_user):
    await login_user(client)
    response = await client.get("/api/dashboard")
    assert response.status_code == 200
    assert set(response.json()) >= {"health", "stats", "connections", "active_ips"}


async def test_ui_is_self_contained_russian_and_has_mobile_navigation_markers(client, login_user):
    await login_user(client)
    page = await client.get("/")
    assert page.status_code == 200
    text = page.text
    assert 'lang="ru"' in text
    assert 'class="sidebar"' in text and 'class="mobile-nav"' in text
    assert "cdn" not in text.lower()
    assert 'id="access-modal"' in text
    assert 'id="qr-image"' in text
    assert 'id="copy-link"' in text
    assert 'class="nav-item owner-only" data-view="admins" hidden' in text
    css = await client.get("/static/style.css")
    assert "@media(max-width:760px)" in css.text
    js = (await client.get("/static/app.js")).text
    assert "function proxyLink" in js and "navigationGeneration" in js
    assert 'value="cancel" formnovalidate' in text
    assert 'id="create-user" type="button" disabled' in text
    assert "admin-form');if(!form.reportValidity()" in js


async def test_telemt_adapter_sends_auth_and_maps_envelope():
    seen = {}
    import httpx
    async def handler(request):
        seen["authorization"] = request.headers.get("authorization")
        return httpx.Response(200, json={"ok": True, "data": [{"username": "a"}], "revision": "r"})
    client = TelemtClient("http://telemt:9091", "Bearer internal-token", transport=httpx.MockTransport(handler))
    assert (await client.list_users())[0]["username"] == "a"
    assert seen["authorization"] == "Bearer internal-token"


async def test_telemt_adapter_does_not_leak_secret_in_errors():
    import httpx
    secret = "0123456789abcdef0123456789abcdef"
    async def handler(request):
        return httpx.Response(500, text=secret)
    client = TelemtClient("http://telemt:9091", "Bearer token", transport=httpx.MockTransport(handler))
    with pytest.raises(TelemtError) as exc:
        await client.create_user("alice")
    assert secret not in str(exc.value)


async def test_user_list_strips_links_and_all_secret_material(client, login_user, telemt):
    await login_user(client)
    telemt.users["alice"] = {
        "username": "alice", "enabled": True, "current_connections": 2,
        "links": {"tls": ["tg://proxy?server=proxy.example.com&secret=ee0123456789abcdef0123456789abcdef"]},
        "secret": "0123456789abcdef0123456789abcdef",
    }
    response = await client.get("/api/users")
    assert response.status_code == 200
    body = response.json()
    assert body["items"][0]["current_connections"] == 2
    assert "links" not in body["items"][0]
    assert "secret" not in str(body).lower()
    assert "tg://" not in str(body)


async def test_admin_can_reopen_share_link_and_qr_without_exposing_it_in_lists_or_audit(client, login_user, telemt):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    link = "tg://proxy?server=proxy.example.com&port=443&secret=ee0123456789abcdef0123456789abcdef"
    telemt.users["alice"] = {
        "username": "alice", "enabled": True, "links": {"tls": [link]},
    }

    first = await client.post("/api/users/alice/access", headers={"X-CSRF-Token": csrf})
    second = await client.post("/api/users/alice/access", headers={"X-CSRF-Token": csrf})

    assert first.status_code == second.status_code == 200
    assert first.json()["username"] == "alice"
    assert first.json()["link"] == link
    assert first.json()["qr"].startswith("data:image/svg+xml;base64,")
    assert first.headers["cache-control"] == "no-store"
    listed = (await client.get("/api/users")).json()
    assert link not in str(listed)
    audit = (await client.get("/api/audit")).json()["items"]
    assert sum(x["action"] == "user.access" and x["target"] == "alice" for x in audit) == 2
    assert link not in str(audit)


async def test_viewer_cannot_reveal_existing_proxy_access(client, login_user, telemt):
    store = client._transport.app.state.store
    store.create_admin("viewer", "viewer password long enough", "viewer")
    telemt.users["alice"] = {"username": "alice", "enabled": True, "links": {"tls": ["tg://secret"]}}
    await login_user(client, "viewer", "viewer password long enough")
    response = await client.post("/api/users/alice/access", headers={"X-CSRF-Token": client.cookies["panel_csrf"]})
    assert response.status_code == 403


async def test_access_rejects_non_telegram_upstream_link(client, login_user, telemt):
    await login_user(client)
    telemt.users["alice"] = {
        "username": "alice", "enabled": True,
        "links": {"tls": ["javascript:alert(document.domain)"]},
    }
    response = await client.post(
        "/api/users/alice/access",
        headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )
    assert response.status_code == 409
    assert "javascript:" not in response.text


@pytest.mark.parametrize("link", [
    "tg://proxy?server=proxy.example.com&port=%C2%B2&secret=ee0123456789abcdef0123456789abcdef",
    "https://[invalid/proxy?server=x&port=443&secret=ee0123456789abcdef0123456789abcdef",
])
async def test_access_returns_sanitized_conflict_for_malformed_upstream_url(client, login_user, telemt, link):
    await login_user(client)
    telemt.users["alice"] = {"username": "alice", "enabled": True, "links": {"tls": [link]}}
    response = await client.post(
        "/api/users/alice/access",
        headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )
    assert response.status_code == 409
    assert response.json() == {"detail": "connection link unavailable"}


async def test_access_accepts_ipv6_mtproxy_server(client, login_user, telemt):
    await login_user(client)
    link = "tg://proxy?server=2001:db8::1&port=443&secret=ee0123456789abcdef0123456789abcdef"
    telemt.users["alice"] = {"username": "alice", "enabled": True, "links": {"tls": [link]}}
    response = await client.post(
        "/api/users/alice/access",
        headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )
    assert response.status_code == 200
    assert response.json()["link"] == link


async def test_reveal_is_bound_to_creating_admin_session(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post("/api/users", json={"username": "alice"}, headers={"X-CSRF-Token": csrf})
    token = created.json()["reveal_token"]
    session = client.cookies["panel_session"]
    client.cookies.set("panel_session", "unrelated-opaque-session")
    assert (await client.get(f"/api/reveal/{token}")).status_code == 401
    client.cookies.set("panel_session", session)
    assert (await client.get(f"/api/reveal/{token}")).status_code == 200
