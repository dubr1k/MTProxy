from __future__ import annotations

import copy
import secrets
from urllib.parse import quote

import httpx


class MieruError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class MieruClient:
    def __init__(
        self, socket_path: str, token: str, *, timeout: float = 8, transport=None
    ):
        self.socket_path, self.token, self.timeout, self.transport = (
            socket_path,
            token,
            timeout,
            transport,
        )

    async def _request(self, method, path, payload=None):
        transport = self.transport or httpx.AsyncHTTPTransport(uds=self.socket_path)
        try:
            async with httpx.AsyncClient(
                base_url="http://mieru-manager",
                timeout=self.timeout,
                transport=transport,
                headers={"X-Mieru-Token": self.token},
                trust_env=False,
            ) as client:
                response = await client.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise MieruError("Mieru manager unavailable") from exc
        if response.status_code >= 400:
            status = (
                response.status_code if response.status_code in {404, 409, 422} else 502
            )
            raise MieruError("Mieru manager rejected request", status)
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise MieruError("Invalid Mieru manager response") from exc

    async def health(self):
        return await self._request("GET", "/v1/health")

    async def list_users(self):
        return await self._request("GET", "/v1/users")

    async def metrics(self):
        value = await self._request("GET", "/v1/metrics")
        if value != {
            "status": "error",
            "stale": True,
            "users": [],
            "capability": "unavailable",
            "reason": "typed_histories_unavailable",
        }:
            raise MieruError("Invalid Mieru metrics response")
        return value

    async def lifecycle(self, action):
        if action not in {"start", "stop", "restart"}:
            raise ValueError("invalid Mieru lifecycle action")
        return await self._request("POST", f"/v1/lifecycle/{action}", {})

    async def create(self, payload):
        return await self._request("POST", "/v1/users", payload)

    async def set_quotas(self, username, payload):
        return await self._request(
            "POST", f"/v1/users/{quote(username, safe='')}/quotas", payload
        )

    async def operation(self, username, operation, revision):
        return await self._request(
            "POST",
            f"/v1/users/{quote(username, safe='')}/{operation}",
            {"expected_revision": revision},
        )

    async def delete(self, username, revision):
        return await self._request(
            "DELETE",
            f"/v1/users/{quote(username, safe='')}",
            {"expected_revision": revision},
        )

    async def reset_metrics(self, username):
        return await self._request(
            "POST", f"/v1/users/{quote(username, safe='')}/reset-metrics", {}
        )


class MemoryMieru:
    def __init__(self):
        self.users = {}
        self.revision = "rev-1"
        self.broken = False

    def _next(self):
        self.revision = "rev-" + str(int(self.revision.split("-")[1]) + 1)
        return self.revision

    async def health(self):
        if self.broken:
            raise MieruError("unavailable")
        return {"ready": True, "status": "running", "revision": self.revision}

    async def list_users(self):
        return [copy.deepcopy(item) for item in self.users.values()]

    async def metrics(self):
        if self.broken:
            raise MieruError("unavailable")
        return {
            "status": "error",
            "stale": True,
            "users": [],
            "capability": "unavailable",
            "reason": "typed_histories_unavailable",
        }

    async def create(self, payload):
        if payload["expected_revision"] != self.revision:
            raise MieruError("conflict", 409)
        username = payload["username"]
        password = secrets.token_urlsafe(18)
        self.users[username] = {
            "username": username,
            "enabled": True,
            "quotas": copy.deepcopy(payload["quotas"]),
        }
        revision = self._next()
        return {
            "username": username,
            "share_url": f"mierus://{quote(username, safe='')}:{quote(password, safe='')}@mieru.example.com?profile={quote(username)}&port=8443&protocol=TCP",
            "revision": revision,
        }

    async def operation(self, username, operation, revision):
        if revision != self.revision:
            raise MieruError("conflict", 409)
        if operation == "rotate":
            password = secrets.token_urlsafe(18)
            result = {
                "username": username,
                "share_url": f"mierus://{username}:{password}@mieru.example.com?port=8443&protocol=TCP",
            }
        else:
            self.users[username]["enabled"] = operation == "enable"
            result = {"username": username, "enabled": operation == "enable"}
        result["revision"] = self._next()
        return result

    async def set_quotas(self, username, payload):
        self.users[username]["quotas"] = payload["quotas"]
        return {"username": username, "revision": self._next()}

    async def delete(self, username, revision):
        self.users.pop(username)
        return {"username": username, "revision": self._next()}

    async def reset_metrics(self, username):
        raise MieruError("Mieru metrics unavailable", 409)
