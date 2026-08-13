from __future__ import annotations

import pytest


pytestmark = pytest.mark.anyio


async def test_login_uses_opaque_server_side_session_and_security_headers(client, login_user):
    response = await login_user(client)
    assert response.status_code == 204
    cookie = response.cookies["panel_session"]
    assert "." not in cookie and len(cookie) >= 40
    assert "HttpOnly" in response.headers["set-cookie"]
    dashboard = await client.get("/api/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.headers["content-security-policy"].startswith("default-src 'self'")
    assert dashboard.headers["x-content-type-options"] == "nosniff"


async def test_csrf_required_for_login_and_authenticated_mutations(client, login_user):
    assert (await client.post("/api/auth/login", json={"username": "owner", "password": "x"})).status_code == 403
    await login_user(client)
    assert (await client.post("/api/users", json={"username": "alice"})).status_code == 403


async def test_logout_invalidates_session(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    assert (await client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})).status_code == 204
    assert (await client.get("/api/dashboard")).status_code == 401


async def test_login_rate_limit_is_enforced(client):
    csrf = (await client.get("/login")).cookies["panel_csrf"]
    for _ in range(3):
        response = await client.post("/api/auth/login", json={"username": "owner", "password": "wrong-password"}, headers={"X-CSRF-Token": csrf})
        assert response.status_code == 401
    blocked = await client.post("/api/auth/login", json={"username": "owner", "password": "wrong-password"}, headers={"X-CSRF-Token": csrf})
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


async def test_body_limit_and_validation(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    oversized = b'{"username":"' + b"a" * 70000 + b'"}'
    assert (await client.post("/api/users", content=oversized, headers={"content-type": "application/json", "X-CSRF-Token": csrf})).status_code == 413
    assert (await client.post("/api/users", json={"username": "bad user"}, headers={"X-CSRF-Token": csrf})).status_code == 422
