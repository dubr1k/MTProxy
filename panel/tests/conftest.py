from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from panel.app import Settings, create_app
from panel.telemt import MemoryTelemt


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def telemt() -> MemoryTelemt:
    return MemoryTelemt(public_host="proxy.example.com", public_port=443)


@pytest.fixture
async def client(tmp_path: Path, telemt: MemoryTelemt):
    settings = Settings(
        database_path=tmp_path / "panel.sqlite3",
        session_cookie_secure=False,
        allowed_hosts=("testserver",),
        login_attempts=3,
        login_window_seconds=60,
        reveal_ttl_seconds=60,
    )
    app = create_app(settings, telemt=telemt)
    app.state.store.create_admin("owner", "correct horse battery staple", "owner")
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver", follow_redirects=False
    ) as value:
        yield value


async def login(client: httpx.AsyncClient, username="owner", password="correct horse battery staple"):
    page = await client.get("/login")
    csrf = page.cookies["panel_csrf"]
    return await client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
        headers={"X-CSRF-Token": csrf},
    )


@pytest.fixture
def login_user():
    return login
