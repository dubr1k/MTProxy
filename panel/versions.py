from __future__ import annotations

import httpx


class VersionAgentError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class VersionClient:
    def __init__(self, socket_path: str, *, timeout: float = 20.0, transport=None):
        self.socket_path = socket_path
        self.timeout = timeout
        self.transport = transport

    async def _request(self, method: str, path: str, payload=None):
        transport = self.transport or httpx.AsyncHTTPTransport(uds=self.socket_path)
        try:
            async with httpx.AsyncClient(
                base_url="http://version-agent",
                timeout=self.timeout,
                transport=transport,
                trust_env=False,
            ) as client:
                response = await client.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise VersionAgentError("version agent unavailable") from exc
        if response.status_code >= 400:
            status = response.status_code if response.status_code in {409, 422} else 502
            raise VersionAgentError("version agent rejected request", status)
        try:
            return response.json()
        except ValueError as exc:
            raise VersionAgentError("invalid version agent response") from exc

    async def list_versions(self):
        return await self._request("GET", "/v1/versions")

    async def update(self, component: str, version: str, expected_current: str | None):
        return await self._request(
            "POST",
            "/v1/update",
            {
                "component": component,
                "version": version,
                "expected_current": expected_current,
            },
        )


class MemoryVersions:
    def __init__(self):
        self.components = {
            "telemt": {
                "current": "3.4.24",
                "available": [
                    {"version": "3.4.24", "kind": "image"},
                    {"version": "3.4.25", "kind": "image"},
                ],
            },
            "naive": {
                "current": "2.11.3",
                "available": [
                    {"version": "2.11.3", "kind": "binary"},
                    {"version": "2.11.4", "kind": "binary"},
                ],
            },
            "mita": {
                "current": "3.34.0",
                "available": [
                    {"version": "3.34.0", "kind": "binary"},
                    {"version": "3.35.0", "kind": "binary"},
                ],
            },
        }
        self.calls = []

    async def list_versions(self):
        return {"enabled": True, "components": self.components}

    async def update(self, component, version, expected_current):
        self.calls.append((component, version, expected_current))
        current = self.components[component]["current"]
        if expected_current != current:
            raise VersionAgentError("version changed", 409)
        self.components[component]["current"] = version
        return {"component": component, "version": version, "changed": True}
