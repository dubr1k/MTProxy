from __future__ import annotations

import pytest


pytestmark = pytest.mark.anyio


async def test_viewer_cannot_mutate_and_admin_cannot_manage_admins(client, login_user):
    store = client._transport.app.state.store
    store.create_admin("viewer", "viewer password long enough", "viewer")
    store.create_admin("admin", "admin password long enough", "admin")
    await login_user(client, "viewer", "viewer password long enough")
    csrf = client.cookies["panel_csrf"]
    assert (await client.post("/api/users", json={"username": "alice"}, headers={"X-CSRF-Token": csrf})).status_code == 403
    await client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf})
    await login_user(client, "admin", "admin password long enough")
    csrf = client.cookies["panel_csrf"]
    assert (await client.post("/api/admins", json={"username": "new", "password": "long password for new", "role": "viewer"}, headers={"X-CSRF-Token": csrf})).status_code == 403


async def test_last_owner_cannot_be_deleted_or_demoted(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    admins = (await client.get("/api/admins")).json()["items"]
    owner_id = next(x["id"] for x in admins if x["username"] == "owner")
    assert (await client.patch(f"/api/admins/{owner_id}", json={"role": "admin"}, headers={"X-CSRF-Token": csrf})).status_code == 409
    assert (await client.patch(f"/api/admins/{owner_id}", json={"active": False}, headers={"X-CSRF-Token": csrf})).status_code == 409
    assert (await client.delete(f"/api/admins/{owner_id}", headers={"X-CSRF-Token": csrf})).status_code == 409


async def test_mutations_create_secret_free_audit_records(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post("/api/users", json={"username": "alice"}, headers={"X-CSRF-Token": csrf})
    secret = (await client.get(f"/api/reveal/{created.json()['reveal_token']}")).json()["secret"]
    audit = (await client.get("/api/audit")).json()["items"]
    assert any(row["action"] == "user.create" and row["target"] == "alice" for row in audit)
    assert secret not in str(audit)


async def test_viewer_can_read_secret_free_audit(client, login_user):
    store = client._transport.app.state.store
    store.create_admin("viewer", "viewer password long enough", "viewer")
    await login_user(client, "viewer", "viewer password long enough")
    response = await client.get("/api/audit")
    assert response.status_code == 200
    assert "secret" not in str(response.json()).lower()


async def test_audit_cursor_and_filters_are_backward_compatible(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    for username in ("alice", "bob", "carol"):
        response = await client.post(
            "/api/users",
            json={"username": username},
            headers={"X-CSRF-Token": csrf},
        )
        assert response.status_code == 201

    first = (
        await client.get(
            "/api/audit",
            params={"limit": 2, "actor": "OWNER", "action": "user.create"},
        )
    ).json()
    assert [item["target"] for item in first["items"]] == ["carol", "bob"]
    assert first["next_cursor"] == first["items"][-1]["id"]

    second = (
        await client.get(
            "/api/audit",
            params={
                "limit": 2,
                "before_id": first["next_cursor"],
                "actor": "owner",
                "action": "user.create",
            },
        )
    ).json()
    assert [item["target"] for item in second["items"]] == ["alice"]
    assert "next_cursor" not in second

    targeted = (
        await client.get(
            "/api/audit",
            params={"target": "alice", "action": "user.create"},
        )
    ).json()
    assert len(targeted["items"]) == 1
    assert targeted["items"][0]["actor_username"] == "owner"
