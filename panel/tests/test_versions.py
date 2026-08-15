from __future__ import annotations

import pytest

from panel.versions import MemoryVersions


@pytest.mark.anyio
async def test_versions_are_visible_and_owner_can_update(client, login_user):
    await login_user(client)
    unavailable = await client.get("/api/versions")
    assert unavailable.status_code == 200
    assert unavailable.json()["enabled"] is False


@pytest.mark.anyio
async def test_version_update_requires_owner_and_current_revision(
    tmp_path, telemt, naive, mieru, login_user
):
    from httpx import ASGITransport, AsyncClient
    from panel.app import Settings, create_app

    versions = MemoryVersions()
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        naive_public_host="naive.example.com",
        naive_enabled=True,
        mieru_enabled=True,
    )
    app = create_app(
        settings, telemt=telemt, naive=naive, mieru=mieru, version_client=versions
    )
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    app.state.store.create_admin("viewer", "correct horse battery staple", "viewer")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        await login_user(client)
        listed = await client.get("/api/versions")
        assert listed.status_code == 200
        assert listed.json()["components"]["telemt"]["current"] == "3.4.24"
        csrf = client.cookies["panel_csrf"]
        response = await client.post(
            "/api/versions/telemt/update",
            json={"version": "3.4.25", "expected_current": "3.4.24"},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 200
        assert versions.calls == [("telemt", "3.4.25", "3.4.24")]
        stale = await client.post(
            "/api/versions/telemt/update",
            json={"version": "3.4.24", "expected_current": "3.4.24"},
            headers={"X-CSRF-Token": csrf},
        )
        assert stale.status_code == 409


@pytest.mark.anyio
async def test_version_update_rejects_viewer(tmp_path, telemt, naive, mieru, login_user):
    from httpx import ASGITransport, AsyncClient
    from panel.app import Settings, create_app

    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        naive_public_host="naive.example.com",
        naive_enabled=True,
        mieru_enabled=True,
    )
    app = create_app(
        settings, telemt=telemt, naive=naive, mieru=mieru, version_client=MemoryVersions()
    )
    app.state.store.create_admin("viewer", "correct horse battery staple", "viewer")
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        await login_user(client, username="viewer")
        response = await client.post(
            "/api/versions/telemt/update",
            json={"version": "3.4.25", "expected_current": "3.4.24"},
            headers={"X-CSRF-Token": client.cookies["panel_csrf"]},
        )
        assert response.status_code == 403
