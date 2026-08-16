from __future__ import annotations

import secrets
from datetime import UTC, datetime
from urllib.parse import quote

import httpx


# Reasons the manager may report for a refusal.  Anything else is treated as a
# plain conflict so a manager response can never dictate panel copy.
NAIVE_REASON_CODES = frozenset({"quota_exhausted"})


class NaiveError(RuntimeError):
    def __init__(self, message: str, status_code: int = 502, code: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code if code in NAIVE_REASON_CODES else None


class NaiveClient:
    def __init__(self, socket_path: str, token: str, *, timeout: float = 8.0, transport=None):
        self.socket_path = socket_path
        self.token = token
        self.timeout = timeout
        self.transport = transport

    @staticmethod
    def _reason(response) -> str | None:
        try:
            payload = response.json()
        except ValueError:
            return None
        return payload.get("code") if isinstance(payload, dict) else None

    async def _request(self, method: str, path: str, payload=None):
        transport = self.transport or httpx.AsyncHTTPTransport(uds=self.socket_path)
        try:
            async with httpx.AsyncClient(
                base_url="http://naive-manager",
                timeout=self.timeout,
                transport=transport,
                headers={"X-Naive-Token": self.token},
            ) as client:
                response = await client.request(method, path, json=payload)
        except httpx.HTTPError as exc:
            raise NaiveError("NaiveProxy manager unavailable") from exc
        if response.status_code >= 400:
            status = response.status_code if response.status_code in {404, 409, 422} else 502
            raise NaiveError("NaiveProxy manager rejected request", status, self._reason(response))
        if response.status_code == 204:
            return None
        try:
            return response.json()
        except ValueError as exc:
            raise NaiveError("Invalid NaiveProxy manager response") from exc

    async def health(self): return await self._request("GET", "/v1/health")
    async def list_users(self): return await self._request("GET", "/v1/users")
    async def traffic(self): return await self._request("GET", "/v1/traffic")
    async def create(self, username, quota_bytes=None):
        return await self._request(
            "POST", "/v1/users", {"username": username, "quota_bytes": quota_bytes}
        )
    async def reveal(self, username): return await self._request("POST", f"/v1/users/{quote(username)}/access", {})
    async def rotate(self, username): return await self._request("POST", f"/v1/users/{quote(username)}/rotate", {})
    async def set_enabled(self, username, enabled): return await self._request("POST", f"/v1/users/{quote(username)}/{'enable' if enabled else 'disable'}", {})
    async def set_quota(self, username, quota_bytes):
        return await self._request(
            "POST", f"/v1/users/{quote(username)}/quota", {"quota_bytes": quota_bytes}
        )
    async def delete(self, username): return await self._request("DELETE", f"/v1/users/{quote(username)}")
    async def reset_traffic(self, username): return await self._request("POST", f"/v1/users/{quote(username)}/traffic/reset", {})


class MemoryNaive:
    def __init__(self, public_host="naive.example.com"):
        self.public_host = public_host
        self.users = {}
        self.calls = []
        self.period_start = datetime.now(UTC).isoformat()
        self.traffic_rows = {}

    def seed(self, username, password, *, enabled=True, quota_bytes=None):
        self.users[username] = {
            "username": username, "password": password, "enabled": enabled,
            "quota_bytes": quota_bytes, "disabled_reason": None if enabled else "manual",
        }
        self.traffic_rows.setdefault(username, {"upload_bytes": 0, "download_bytes": 0})

    def set_traffic(self, username, *, upload, download):
        self.traffic_rows[username] = {"upload_bytes": upload, "download_bytes": download}

    def _access(self, username):
        row = self.users[username]
        url = f"https://{quote(username, safe='')}:{quote(row['password'], safe='')}@{self.public_host}"
        return {"username": username, "proxy_url": url, "config": {"listen": "socks://127.0.0.1:1080", "proxy": url}}

    def _used(self, username):
        return sum(self.traffic_rows.get(username, {}).values())

    def _enforce_quotas(self):
        """Mirror the manager's periodic enforcement: exhaustion is persistent."""
        for username, row in self.users.items():
            quota = row["quota_bytes"]
            if row["enabled"] and quota is not None and self._used(username) >= quota:
                row["enabled"] = False
                row["disabled_reason"] = "quota"

    async def health(self): return {"ready": True, "host": self.public_host}
    async def list_users(self):
        self._enforce_quotas()
        return [
            {
                "username": row["username"], "enabled": row["enabled"],
                "quota_bytes": row["quota_bytes"],
                "disabled_reason": row["disabled_reason"],
            }
            for row in self.users.values()
        ]
    async def traffic(self):
        self._enforce_quotas()
        rows = []
        for username, counters in self.traffic_rows.items():
            upload = counters["upload_bytes"]
            download = counters["download_bytes"]
            rows.append({
                "username": username, "upload_bytes": upload, "download_bytes": download,
                "total_bytes": upload + download, "period_start": self.period_start,
                "updated_at": self.period_start,
                "upload_bytes_decimal": str(upload), "download_bytes_decimal": str(download),
                "total_bytes_decimal": str(upload + download),
            })
        return {
            "source": "caddy_connect_access_log", "unit": "bytes", "pending": False,
            "directions": {"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"},
            "aggregate": {
                "upload_bytes": sum(row["upload_bytes"] for row in rows),
                "download_bytes": sum(row["download_bytes"] for row in rows),
                "total_bytes": sum(row["total_bytes"] for row in rows),
                "upload_bytes_decimal": str(sum(row["upload_bytes"] for row in rows)),
                "download_bytes_decimal": str(sum(row["download_bytes"] for row in rows)),
                "total_bytes_decimal": str(sum(row["total_bytes"] for row in rows)),
            },
            "users": rows,
            "semantics": {
                "closed_connect_tunnels_only": True, "active_tunnels_appear_on_close": True,
                "crash_can_lose_active_tunnel": True, "completed_records_survive_restart": True,
                "excludes_tls_ip_overhead": True, "reset_is_local_baseline_only": True,
            },
        }
    async def create(self, username, quota_bytes=None):
        self.calls.append(("create", username))
        self.seed(username, secrets.token_urlsafe(18), quota_bytes=quota_bytes)
        return self._access(username)
    async def reveal(self, username):
        self.calls.append(("access", username))
        return self._access(username)
    async def rotate(self, username):
        self.calls.append(("rotate", username))
        self.users[username]["password"] = secrets.token_urlsafe(18)
        return self._access(username)
    async def set_enabled(self, username, enabled):
        self.calls.append(("enabled", username, enabled))
        if enabled:
            quota = self.users[username]["quota_bytes"]
            if quota is not None and self._used(username) >= quota:
                raise NaiveError("quota exhausted", 409, "quota_exhausted")
        self.users[username]["enabled"] = enabled
        self.users[username]["disabled_reason"] = None if enabled else "manual"
        return {
            "username": username, "enabled": enabled,
            "disabled_reason": self.users[username]["disabled_reason"],
        }
    async def set_quota(self, username, quota_bytes):
        self.calls.append(("set_quota", username, quota_bytes))
        row = self.users[username]
        used = self._used(username)
        row["quota_bytes"] = quota_bytes
        if row["enabled"] and quota_bytes is not None and used >= quota_bytes:
            row["enabled"] = False
            row["disabled_reason"] = "quota"
        elif row["disabled_reason"] == "quota" and (quota_bytes is None or used < quota_bytes):
            row["disabled_reason"] = "manual"
        return {
            "username": username, "quota_bytes": quota_bytes,
            "enabled": row["enabled"], "disabled_reason": row["disabled_reason"],
        }
    async def delete(self, username):
        self.calls.append(("delete", username))
        self.users.pop(username)
        return {"ok": True}
    async def reset_traffic(self, username):
        self.calls.append(("reset_traffic", username))
        self.set_traffic(username, upload=0, download=0)
        return {
            "username": username, "upload_bytes": 0, "download_bytes": 0, "total_bytes": 0,
            "upload_bytes_decimal": "0", "download_bytes_decimal": "0", "total_bytes_decimal": "0",
            "period_start": self.period_start, "updated_at": self.period_start,
        }
