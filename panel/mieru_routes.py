from __future__ import annotations

import asyncio
import re
from typing import Literal
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request

from .mieru import MieruError
from .reveals import qr_data
from .schemas import MieruQuotaUpdate, MieruRevision, MieruUserCreate
from .web_context import RequestContext


def mieru_access(value) -> dict[str, str]:
    if not isinstance(value, str) or len(value) > 4096:
        raise HTTPException(409, "Mieru connection link unavailable")
    try:
        parts = urlsplit(value)
    except ValueError as exc:
        raise HTTPException(409, "Mieru connection link unavailable") from exc
    if (
        parts.scheme != "mierus"
        or not parts.username
        or not parts.password
        or not parts.hostname
        or parts.path not in ("", "/")
        or parts.fragment
    ):
        raise HTTPException(409, "Mieru connection link unavailable")
    return {"share_url": value, "qr": qr_data(value)}


def register_mieru_routes(app, context: RequestContext) -> None:
    def require_mieru():
        if not context.settings.mieru_enabled:
            raise HTTPException(404, "feature unavailable")

    @app.get("/api/mieru/users")
    async def mieru_users(_user=Depends(context.current)):
        require_mieru()
        health, items, metrics = await asyncio.gather(
            app.state.mieru.health(),
            app.state.mieru.list_users(),
            app.state.mieru.metrics(),
        )
        metric_map = {
            row.get("username"): row
            for row in metrics.get("users", [])
            if isinstance(row, dict)
        }
        if metrics != {
            "status": "error",
            "stale": True,
            "users": [],
            "capability": "unavailable",
            "reason": "typed_histories_unavailable",
        }:
            raise MieruError("Invalid Mieru metrics response")
        safe = []
        for item in items:
            if not isinstance(item, dict) or not re.fullmatch(
                r"[A-Za-z0-9_.-]{1,64}", str(item.get("username", ""))
            ):
                continue
            row = {
                "username": item["username"],
                "enabled": item.get("enabled") is True,
                "traffic_available": False,
                "quotas": item.get("quotas", [])
                if isinstance(item.get("quotas", []), list)
                else [],
            }
            metric = metric_map.get(item["username"], {})
            for key in (
                "upload_bytes",
                "download_bytes",
                "application_bytes",
                "stale",
            ):
                if key in metric:
                    row[key] = metric[key]
            safe.append(row)
        return {
            "items": safe,
            "metrics": {
                "capability": "unavailable",
                "reason": "typed_histories_unavailable",
            },
            "service": {
                "ready": health.get("ready") is True,
                "status": health.get("status"),
                "revision": health.get("revision"),
            },
            "quota_semantics": "rolling application-byte admission quota (approximate)",
        }

    @app.post("/api/mieru/users", status_code=201)
    async def mieru_create(
        body: MieruUserCreate,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_mieru()
        payload = body.model_dump()
        payload["quotas"] = [item.model_dump() for item in body.quotas]
        payload["elevated"] = user["role"] == "owner" and (
            body.allow_private_ip or body.allow_loopback_ip
        )
        data = await app.state.mieru.create(payload)
        await context.audit(
            user,
            "mieru.create",
            body.username,
            request,
            {
                "quotas": payload["quotas"],
                "ssrf_flags": bool(payload["elevated"]),
            },
        )
        return {
            "username": body.username,
            "revision": data.get("revision"),
            "reveal_token": context.create_reveal(
                mieru_access(data.get("share_url")), user
            ),
        }

    @app.post("/api/mieru/users/{username}/quotas")
    async def mieru_quotas(
        username: str,
        body: MieruQuotaUpdate,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_mieru()
        payload = {
            "expected_revision": body.expected_revision,
            "quotas": [item.model_dump() for item in body.quotas],
        }
        data = await app.state.mieru.set_quotas(username, payload)
        await context.audit(
            user,
            "mieru.quotas",
            username,
            request,
            {"quotas": payload["quotas"]},
        )
        return data

    @app.post("/api/mieru/users/{username}/reset-metrics")
    async def mieru_reset(
        username: str,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_mieru()
        data = await app.state.mieru.reset_metrics(username)
        await context.audit(user, "mieru.metrics.baseline", username, request)
        return data

    @app.post("/api/mieru/users/{username}/{operation}")
    async def mieru_operation(
        username: str,
        operation: Literal["enable", "disable", "rotate"],
        body: MieruRevision,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_mieru()
        data = await app.state.mieru.operation(
            username, operation, body.expected_revision
        )
        await context.audit(user, f"mieru.{operation}", username, request)
        if operation == "rotate":
            return {
                "username": username,
                "revision": data.get("revision"),
                "reveal_token": context.create_reveal(
                    mieru_access(data.get("share_url")), user
                ),
            }
        return data

    @app.delete("/api/mieru/users/{username}")
    async def mieru_delete(
        username: str,
        body: MieruRevision,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_mieru()
        data = await app.state.mieru.delete(username, body.expected_revision)
        await context.audit(user, "mieru.delete", username, request)
        return data
