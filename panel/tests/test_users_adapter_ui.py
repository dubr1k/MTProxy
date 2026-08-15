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


async def test_dashboard_labels_process_runtime_traffic_separately_from_quota(client, login_user, telemt):
    telemt.users.update({
        "alice": {"username": "alice", "enabled": True, "total_octets": 100},
        "bob": {"username": "bob", "enabled": True, "total_octets": 250},
    })
    telemt.quota_usage["alice"] = {"username": "alice", "data_quota_bytes": 1000, "used_bytes": 900, "last_reset_epoch_secs": 123}
    await login_user(client)
    response = await client.get("/api/dashboard")
    assert response.status_code == 200
    assert set(response.json()) >= {"health", "stats", "connections", "active_ips", "traffic"}
    assert response.json()["traffic"] == {"runtime_total_octets": 350}


async def test_dashboard_summarizes_both_protocols_without_naive_traffic_invention(
    client, login_user, telemt, naive,
):
    telemt.users.update({
        "mt-on": {"username": "mt-on", "enabled": True, "total_octets": 1024},
        "mt-off": {"username": "mt-off", "enabled": False, "total_octets": 2048},
    })
    naive.seed("web-on", "not-returned", enabled=True)
    naive.seed("web-off", "also-not-returned", enabled=False)
    await login_user(client)

    body = (await client.get("/api/dashboard")).json()

    assert body["protocols"]["mtproxy"] == {
        "status": "ready",
        "ready": True,
        "credentials": {"active": 1, "disabled": 1, "total": 2},
        "runtime": {
            "traffic_octets": 3072,
            "current_connections": 0,
            "active_ips": 0,
        },
    }
    assert body["protocols"]["naive"] == {
        "available": True,
        "status": "ready",
        "ready": True,
        "host": "naive.example.com",
        "credentials": {"active": 1, "disabled": 1, "total": 2},
        "traffic": {
            "available": True,
            "source": "caddy_connect_access_log",
            "unit": "bytes",
            "directions": {
                "upload_bytes": "client_to_proxy",
                "download_bytes": "proxy_to_client",
            },
            "pending": False,
            "aggregate": {
                "upload_bytes": 0, "download_bytes": 0, "total_bytes": 0,
                "upload_bytes_decimal": "0", "download_bytes_decimal": "0",
                "total_bytes_decimal": "0",
            },
            "users": [
                {
                    "username": "web-on", "upload_bytes": 0, "download_bytes": 0,
                    "total_bytes": 0, "period_start": naive.period_start,
                    "upload_bytes_decimal": "0", "download_bytes_decimal": "0",
                    "total_bytes_decimal": "0",
                    "updated_at": naive.period_start,
                },
                {
                    "username": "web-off", "upload_bytes": 0, "download_bytes": 0,
                    "total_bytes": 0, "period_start": naive.period_start,
                    "upload_bytes_decimal": "0", "download_bytes_decimal": "0",
                    "total_bytes_decimal": "0",
                    "updated_at": naive.period_start,
                },
            ],
            "semantics": {
                "closed_connect_tunnels_only": True,
                "active_tunnels_appear_on_close": True,
                "crash_can_lose_active_tunnel": True,
                "completed_records_survive_restart": True,
                "excludes_tls_ip_overhead": True,
                "reset_is_local_baseline_only": True,
            },
        },
    }
    assert "not-returned" not in str(body)


async def test_naive_traffic_exposes_exact_decimal_strings_above_javascript_safe_integer(
    client, login_user, naive,
):
    naive.seed("large", "not-returned")
    naive.set_traffic("large", upload=2**53 + 1, download=2)
    await login_user(client)

    body = (await client.get("/api/naive/users")).json()

    row = body["items"][0]
    assert row["upload_bytes_decimal"] == "9007199254740993"
    assert row["download_bytes_decimal"] == "2"
    assert row["total_bytes_decimal"] == "9007199254740995"


async def test_user_list_merges_resettable_quota_usage_without_confusing_runtime_traffic(client, login_user, telemt):
    telemt.users["alice"] = {
        "username": "alice", "enabled": True, "data_quota_bytes": 10_000, "total_octets": 750,
    }
    telemt.quota_usage["alice"] = {
        "username": "alice", "data_quota_bytes": 10_000, "used_bytes": 4_000,
        "last_reset_epoch_secs": 1_700_000_000,
    }
    await login_user(client)

    user = (await client.get("/api/users")).json()["items"][0]

    assert user["runtime_total_octets"] == 750
    assert user["quota_used_bytes"] == 4_000
    assert user["quota_last_reset_epoch_secs"] == 1_700_000_000
    assert "total_octets" not in user and "used_bytes" not in user


async def test_admin_can_set_and_reset_per_user_limits(client, login_user, telemt):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    telemt.users["alice"] = {"username": "alice", "enabled": True, "total_octets": 500}
    telemt.quota_usage["alice"] = {"username": "alice", "data_quota_bytes": 10_000, "used_bytes": 500, "last_reset_epoch_secs": 1}
    payload = {
        "data_quota_bytes": 10_000,
        "rate_limit_up_bps": 1_000_000,
        "rate_limit_down_bps": 2_000_000,
        "max_tcp_conns": 4,
        "max_unique_ips": 2,
        "expiration_rfc3339": "2027-01-01T00:00:00Z",
    }

    changed = await client.post(
        "/api/users/alice/limits", json=payload, headers={"X-CSRF-Token": csrf},
    )
    assert changed.status_code == 200
    assert {key: telemt.users["alice"][key] for key in payload} == payload
    reset = await client.post("/api/users/alice/reset-quota", headers={"X-CSRF-Token": csrf})
    assert reset.status_code == 200
    assert reset.json()["used_bytes"] == 0
    assert telemt.quota_usage["alice"]["used_bytes"] == 0
    assert telemt.users["alice"]["total_octets"] == 500
    audit = (await client.get("/api/audit")).json()["items"]
    assert {row["action"] for row in audit} >= {"user.limits", "user.reset_quota"}


async def test_sparse_limit_update_keeps_existing_quota_state(client, login_user, telemt):
    telemt.users["alice"] = {"username": "alice", "enabled": True, "data_quota_bytes": 10_000}
    telemt.quota_usage["alice"] = {
        "username": "alice", "data_quota_bytes": 10_000, "used_bytes": 4_000,
        "last_reset_epoch_secs": 123,
    }
    await login_user(client)

    response = await client.post(
        "/api/users/alice/limits", json={"max_tcp_conns": 3},
        headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )

    assert response.status_code == 200
    assert telemt.quota_usage["alice"]["used_bytes"] == 4_000


async def test_viewer_cannot_change_or_reset_limits(client, login_user, telemt):
    store = client._transport.app.state.store
    store.create_admin("viewer-limits", "viewer password long enough", "viewer")
    telemt.users["alice"] = {"username": "alice", "enabled": True}
    await login_user(client, "viewer-limits", "viewer password long enough")
    csrf = client.cookies["panel_csrf"]
    assert (await client.post(
        "/api/users/alice/limits", json={"data_quota_bytes": 1000}, headers={"X-CSRF-Token": csrf},
    )).status_code == 403
    assert (await client.post(
        "/api/users/alice/reset-quota", headers={"X-CSRF-Token": csrf},
    )).status_code == 403


async def test_telemt_adapter_patches_limits_and_resets_quota():
    seen = []
    import httpx

    async def handler(request):
        seen.append((request.method, request.url.path, request.content))
        return httpx.Response(200, json={"ok": True, "data": {"username": "alice"}, "revision": "r"})

    telemt = TelemtClient("http://telemt:9091", "Bearer internal-token", transport=httpx.MockTransport(handler))
    await telemt.update_user("alice", {"data_quota_bytes": 2048})
    await telemt.reset_quota("alice")
    assert seen[0][:2] == ("PATCH", "/v1/users/alice")
    assert seen[0][2] == b'{"data_quota_bytes":2048}'
    assert seen[1][:2] == ("POST", "/v1/users/alice/reset-quota")


async def test_telemt_adapter_reads_3425_quota_stats_route():
    import httpx
    seen = []

    async def handler(request):
        seen.append((request.method, request.url.path))
        return httpx.Response(200, json={
            "ok": True,
            "data": {"users": [{
                "username": "alice", "data_quota_bytes": 2048,
                "used_bytes": 512, "last_reset_epoch_secs": 123,
            }]},
            "revision": "r",
        })

    telemt = TelemtClient("http://telemt:9091", "Bearer internal-token", transport=httpx.MockTransport(handler))
    assert await telemt.quota_stats() == {"users": [{
        "username": "alice", "data_quota_bytes": 2048,
        "used_bytes": 512, "last_reset_epoch_secs": 123,
    }]}
    assert seen == [("GET", "/v1/stats/users/quota")]


async def test_ui_is_self_contained_russian_and_has_mobile_navigation_markers(client, login_user):
    login_page = await client.get("/login")
    assert "Proxy Control" in login_page.text
    assert "mtproxy" not in login_page.text.lower()
    await login_user(client)
    page = await client.get("/")
    assert page.status_code == 200
    text = page.text
    assert 'lang="ru"' in text
    assert 'class="sidebar"' in text and 'class="mobile-nav"' in text
    assert "Proxy Control" in text
    assert ">MTProxy<" in text and ">Подключения<" not in text
    assert "cdn" not in text.lower()
    assert 'id="access-modal"' in text
    assert 'id="qr-image"' in text
    assert 'id="copy-link"' in text
    assert 'class="nav-item owner-only" data-view="admins" hidden' in text
    css = await client.get("/static/style.css")
    assert "@media(max-width:760px)" in css.text
    assert "@media(max-width:1040px)" in css.text
    assert "@media(max-width:900px)" in css.text
    assert ".row-actions{display:flex;justify-content:flex-end;gap:5px;flex-wrap:wrap}" in css.text
    js = (await client.get("/static/app.js")).text
    assert "function proxyLink" in js and "navigationGeneration" in js
    assert 'value="cancel" formnovalidate' in text
    assert 'id="create-user" type="button" disabled' in text
    assert 'data-view="naive"' in text and 'id="naive-modal"' in text
    assert 'id="naive-access-modal"' in text and 'id="copy-naive-url"' in text
    assert "renderNaive" in js and "naiveAction" in js and "showNaiveAccess" in js
    assert 'class="protocol-overview"' in js
    assert (
        "↑ ${bytes(user.upload_bytes_decimal)} · ↓ ${bytes(user.download_bytes_decimal)} · "
        "Σ ${bytes(user.total_bytes_decimal)}" in js
    )
    assert "BigInt(String(value??0))" in js
    assert "Только закрытые CONNECT-туннели" in js
    assert 'data-naive-action="reset-traffic"' in js
    assert "Сбросить локальный счётчик?" in js
    assert "NaiveProxy недоступен" in js
    assert 'data-quick="naive-users"' in js
    assert "admin-form');if(!form.reportValidity()" in js
    assert 'id="limits-modal"' in text and 'id="save-limits"' in text
    assert "mt.runtime?.traffic_octets" in js
    assert "user.quota_used_bytes" in js and "data-action=\"limits\"" in js
    assert "/limits`" in js and "/reset-quota`" in js
    assert "текущего runtime-поколения" in js
    assert "Автоматического ежемесячного сброса нет" in text
    assert 'data-view="mieru"' in text and 'id="mieru-modal"' in text
    assert 'id="mieru-access-modal"' in text and 'id="mieru-qr-image"' in text
    assert 'id="copy-mieru-url"' in text and 'id="download-mieru-qr"' in text
    assert "renderMieru" in js and "mieruAction" in js
    assert "showMieruAccess" in js and "qrSource(data.qr)" in js
    assert "Новая ссылка + QR" in js
    assert "rolling application-byte admission quota" in js
    assert 'data-quick="mieru-users"' in js
    assert 'id="fleet-modal"' in text and 'id="create-fleet-node"' in text
    assert 'id="new-node-id"' in text and 'id="new-node-name"' in text
    assert "openFleetModal" in js and "createFleetNode" in js
    assert "name==='fleet'&&state.me?.role==='owner'" in js


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


async def test_user_api_allowlist_drops_unknown_and_nested_future_secret_fields(client, login_user, telemt):
    await login_user(client)
    telemt.users["alice"] = {
        "username": "alice", "enabled": True, "total_octets": 12,
        "future_auth": {
            "secret": "future-secret", "nested": {"token": "future-token"},
        },
        "secret_backup": "backup-secret",
    }
    telemt.quota_usage["alice"] = {
        "username": "alice", "data_quota_bytes": 100, "used_bytes": 12,
        "last_reset_epoch_secs": 1, "future": {"secret": "quota-secret"},
    }

    body = (await client.get("/api/users")).json()

    assert body == {"items": [{
        "username": "alice", "enabled": True, "runtime_total_octets": 12,
        "quota_used_bytes": 12, "quota_last_reset_epoch_secs": 1,
    }]}
    assert not any(value in str(body) for value in ("future-secret", "future-token", "backup-secret", "quota-secret"))


async def test_limit_and_reset_responses_use_allowlists(client, login_user, telemt):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    telemt.users["alice"] = {
        "username": "alice", "enabled": True,
        "future": {"secret": "patched-secret"},
    }
    telemt.reset_extra = {"future": {"token": "reset-token"}}

    changed = await client.post(
        "/api/users/alice/limits", json={"data_quota_bytes": 1000}, headers={"X-CSRF-Token": csrf},
    )
    reset = await client.post("/api/users/alice/reset-quota", headers={"X-CSRF-Token": csrf})

    assert changed.json() == {"username": "alice", "enabled": True, "data_quota_bytes": 1000}
    assert set(reset.json()) == {"username", "used_bytes", "last_reset_epoch_secs"}
    assert "patched-secret" not in str(changed.json()) and "reset-token" not in str(reset.json())


async def test_enable_disable_response_uses_user_allowlist(client, login_user, telemt):
    await login_user(client)
    telemt.users["alice"] = {
        "username": "alice", "enabled": True,
        "future": {"secret": "operation-secret"},
    }

    response = await client.post(
        "/api/users/alice/disable",
        headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
    )

    assert response.json() == {"username": "alice", "enabled": False}
    assert "operation-secret" not in response.text


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
