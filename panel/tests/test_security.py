from __future__ import annotations
import asyncio
import sqlite3
import threading
import time

import pytest

from panel.store import Store


pytestmark = pytest.mark.anyio


async def test_unauthenticated_browser_root_redirects_to_login_but_api_stays_json_401(client):
    root = await client.get("/", follow_redirects=False)
    assert root.status_code == 303
    assert root.headers["location"] == "/login"
    assert (await client.get("/login")).status_code == 200

    api = await client.get("/api/dashboard")
    assert api.status_code == 401
    assert api.json() == {"detail": "authentication required"}


async def test_login_uses_opaque_server_side_session_and_security_headers(client, login_user):
    response = await login_user(client)
    assert response.status_code == 204
    cookie = response.cookies["panel_session"]
    assert "." not in cookie and len(cookie) >= 40
    assert "HttpOnly" in response.headers["set-cookie"]
    identity = await client.get("/api/auth/me")
    assert identity.status_code == 200
    assert identity.json() == {"username": "owner", "role": "owner", "features": {"naive": True, "mieru": True}}
    dashboard = await client.get("/api/dashboard")
    assert dashboard.status_code == 200
    assert dashboard.headers["content-security-policy"].startswith("default-src 'self'")
    assert "form-action 'self'" in dashboard.headers["content-security-policy"]
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


async def test_concurrent_login_batch_reserves_attempts_and_bounds_argon2(
    client, monkeypatch
):
    store = client._transport.app.state.store
    lock = threading.Lock()
    active = 0
    peak = 0

    def slow_verify(_username, _password):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
        try:
            time.sleep(0.05)
            return None
        finally:
            with lock:
                active -= 1

    monkeypatch.setattr(store, "verify_admin", slow_verify)
    csrf = (await client.get("/login")).cookies["panel_csrf"]
    responses = await asyncio.gather(
        *(
            client.post(
                "/api/auth/login",
                json={"username": "owner", "password": "wrong-password"},
                headers={"X-CSRF-Token": csrf},
            )
            for _ in range(8)
        )
    )

    statuses = [response.status_code for response in responses]
    assert statuses.count(401) == 3
    assert statuses.count(429) == 5
    assert peak <= 2


async def test_successful_login_releases_only_its_own_reservation(
    client, login_user, monkeypatch
):
    store = client._transport.app.state.store
    with store.connect() as db:
        admin = dict(
            db.execute(
                "SELECT * FROM admins WHERE username='owner'"
            ).fetchone()
        )
    monkeypatch.setattr(
        store,
        "verify_admin",
        lambda username, password: admin
        if username == "owner" and password == "correct horse battery staple"
        else None,
    )
    csrf = (await client.get("/login")).cookies["panel_csrf"]
    for _ in range(2):
        assert (
            await client.post(
                "/api/auth/login",
                json={"username": "owner", "password": "wrong-password"},
                headers={"X-CSRF-Token": csrf},
            )
        ).status_code == 401
    assert (await login_user(client)).status_code == 204

    csrf = (await client.get("/login")).cookies["panel_csrf"]
    assert (
        await client.post(
            "/api/auth/login",
            json={"username": "owner", "password": "wrong-password"},
            headers={"X-CSRF-Token": csrf},
        )
    ).status_code == 401
    assert (
        await client.post(
            "/api/auth/login",
            json={"username": "owner", "password": "wrong-password"},
            headers={"X-CSRF-Token": csrf},
        )
    ).status_code == 429


async def test_successful_login_preserves_concurrent_failed_reservation(
    client, monkeypatch
):
    store = client._transport.app.state.store
    with store.connect() as db:
        admin = dict(
            db.execute(
                "SELECT * FROM admins WHERE username='owner'"
            ).fetchone()
        )
    valid_started = threading.Event()
    wrong_finished = threading.Event()

    def interleaved_verify(_username, password):
        if password == "correct horse battery staple":
            valid_started.set()
            assert wrong_finished.wait(timeout=1)
            return admin
        assert valid_started.wait(timeout=1)
        wrong_finished.set()
        return None

    monkeypatch.setattr(store, "verify_admin", interleaved_verify)
    csrf = (await client.get("/login")).cookies["panel_csrf"]
    valid = asyncio.create_task(
        client.post(
            "/api/auth/login",
            json={
                "username": "owner",
                "password": "correct horse battery staple",
            },
            headers={"X-CSRF-Token": csrf},
        )
    )
    assert await asyncio.to_thread(valid_started.wait, 1)
    wrong = asyncio.create_task(
        client.post(
            "/api/auth/login",
            json={"username": "owner", "password": "wrong-password"},
            headers={"X-CSRF-Token": csrf},
        )
    )
    valid_response, wrong_response = await asyncio.gather(valid, wrong)
    assert valid_response.status_code == 204
    assert wrong_response.status_code == 401

    csrf = (await client.get("/login")).cookies["panel_csrf"]
    for _ in range(2):
        assert (
            await client.post(
                "/api/auth/login",
                json={"username": "owner", "password": "wrong-password"},
                headers={"X-CSRF-Token": csrf},
            )
        ).status_code == 401
    assert (
        await client.post(
            "/api/auth/login",
            json={"username": "owner", "password": "wrong-password"},
            headers={"X-CSRF-Token": csrf},
        )
    ).status_code == 429


async def test_login_limiter_migrates_existing_reservations(tmp_path):
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as db:
        db.execute(
            "CREATE TABLE login_attempts "
            "(scope TEXT NOT NULL, happened_at INTEGER NOT NULL)"
        )
        db.execute(
            "INSERT INTO login_attempts VALUES(?,?)",
            ("ip:192.0.2.1", int(time.time())),
        )

    store = Store(database)
    reservation = store.reserve_login_attempt(
        ["ip:192.0.2.1"],
        attempts=3,
        window=60,
    )
    assert reservation
    store.release_login_attempt(reservation)
    with store.connect() as db:
        rows = db.execute(
            "SELECT reservation_id FROM login_attempts"
        ).fetchall()
    assert [row["reservation_id"] for row in rows] == [""]


async def test_body_limit_and_validation(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    oversized = b'{"username":"' + b"a" * 70000 + b'"}'
    assert (await client.post("/api/users", content=oversized, headers={"content-type": "application/json", "X-CSRF-Token": csrf})).status_code == 413
    assert (await client.post("/api/users", json={"username": "bad user"}, headers={"X-CSRF-Token": csrf})).status_code == 422
