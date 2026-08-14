from __future__ import annotations

import secrets
from urllib.parse import quote

import httpx


class TelemtError(RuntimeError):
    pass


class TelemtClient:
    def __init__(self, base_url: str, auth_header: str, *, timeout=5.0, transport=None):
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header
        self.timeout = timeout
        self.transport = transport

    async def _request(self, method, path, json=None):
        try:
            async with httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout, transport=self.transport,
                                         headers={"Authorization": self.auth_header}) as client:
                response = await client.request(method, path, json=json)
        except httpx.HTTPError as exc:
            raise TelemtError("Telemt API unavailable") from exc
        if response.status_code >= 400:
            raise TelemtError(f"Telemt API error ({response.status_code})")
        try:
            body = response.json()
        except ValueError as exc:
            raise TelemtError("Invalid Telemt API response") from exc
        if not body.get("ok"):
            raise TelemtError("Telemt API rejected request")
        return body.get("data"), body.get("revision")

    async def list_users(self): return (await self._request("GET", "/v1/users"))[0]
    async def create_user(self, username): return (await self._request("POST", "/v1/users", {"username": username}))[0]
    async def delete_user(self, username): return (await self._request("DELETE", f"/v1/users/{quote(username)}"))[0]
    async def set_enabled(self, username, enabled): return (await self._request("POST", f"/v1/users/{quote(username)}/{'enable' if enabled else 'disable'}"))[0]
    async def rotate(self, username): return (await self._request("POST", f"/v1/users/{quote(username)}/rotate-secret", {}))[0]
    async def health(self): return (await self._request("GET", "/v1/health/ready"))[0]
    async def stats(self): return (await self._request("GET", "/v1/stats/summary"))[0]
    async def connections(self): return (await self._request("GET", "/v1/runtime/connections/summary"))[0]
    async def active_ips(self): return (await self._request("GET", "/v1/stats/users/active-ips"))[0]


class MemoryTelemt:
    def __init__(self, public_host="localhost", public_port=443):
        self.users = {}
        self.public_host, self.public_port = public_host, public_port

    async def list_users(self): return list(self.users.values())
    async def create_user(self, username):
        secret = secrets.token_hex(16)
        link = f"tg://proxy?server={self.public_host}&port={self.public_port}&secret=ee{secret}"
        user = {"username": username, "enabled": True, "links": {"tls": [link]}}
        self.users[username] = user
        return {"user": user, "secret": secret}
    async def delete_user(self, username):
        self.users.pop(username)
        return {"username": username}
    async def set_enabled(self, username, enabled):
        self.users[username]["enabled"] = enabled
        return self.users[username]
    async def rotate(self, username):
        secret = secrets.token_hex(16)
        link = f"tg://proxy?server={self.public_host}&port={self.public_port}&secret=ee{secret}"
        self.users[username]["links"] = {"tls": [link]}
        return {"user": self.users[username], "secret": secret}
    async def health(self): return {"ready": True}
    async def stats(self): return {"connections": 0, "bytes": 0}
    async def connections(self): return {"active": 0, "top_users": []}
    async def active_ips(self): return []
