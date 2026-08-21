from __future__ import annotations

import asyncio
import ipaddress
import re
from typing import Literal
from urllib.parse import parse_qs, urlsplit

from fastapi import Depends, HTTPException, Request

from .mieru import MieruError
from .naive import NaiveError
from .naive_routes import safe_naive_traffic
from .reveals import qr_data
from .schemas import UserCreate, UserLimits
from .web_context import RequestContext


def safe_user(data, quota=None):
    """Map Telemt's user view to the panel contract; never pass future fields through."""
    if not isinstance(data, dict):
        return {}
    result = {}
    string_fields = ("username", "expiration_rfc3339")
    bool_fields = ("enabled", "in_runtime")
    integer_fields = (
        "max_tcp_conns",
        "data_quota_bytes",
        "rate_limit_up_bps",
        "rate_limit_down_bps",
        "max_unique_ips",
        "current_connections",
        "active_unique_ips",
        "recent_unique_ips",
    )
    for key in string_fields:
        if isinstance(data.get(key), str) or (
            key == "expiration_rfc3339" and data.get(key) is None and key in data
        ):
            result[key] = data[key]
    for key in bool_fields:
        if isinstance(data.get(key), bool):
            result[key] = data[key]
    for key in integer_fields:
        value = data.get(key)
        if (
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
        ) or (value is None and key in data):
            result[key] = value
    runtime_total = data.get("total_octets")
    if (
        isinstance(runtime_total, int)
        and not isinstance(runtime_total, bool)
        and runtime_total >= 0
    ):
        result["runtime_total_octets"] = runtime_total
    if isinstance(quota, dict):
        used = quota.get("used_bytes")
        last_reset = quota.get("last_reset_epoch_secs")
        if isinstance(used, int) and not isinstance(used, bool) and used >= 0:
            result["quota_used_bytes"] = used
        if (
            isinstance(last_reset, int)
            and not isinstance(last_reset, bool)
            and last_reset >= 0
        ):
            result["quota_last_reset_epoch_secs"] = last_reset
    return result


def safe_quota_reset(data):
    if not isinstance(data, dict):
        return {}
    result = {}
    if isinstance(data.get("username"), str):
        result["username"] = data["username"]
    for key in ("used_bytes", "last_reset_epoch_secs"):
        value = data.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            result[key] = value
    return result


def quota_by_username(data):
    rows = data.get("users", []) if isinstance(data, dict) else []
    return {
        row["username"]: row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("username"), str)
    }


def secret_reveal(data):
    user = data.get("user") if isinstance(data.get("user"), dict) else data
    links = user.get("links", {}) if isinstance(user, dict) else {}
    candidates = links.get("tls", []) if isinstance(links, dict) else []
    return {
        "secret": data.get("secret"),
        "link": candidates[0] if candidates else data.get("link"),
    }


def proxy_link(value) -> str:
    """Accept only canonical Telegram MTProxy links from the upstream API."""
    if not isinstance(value, str) or len(value) > 2048:
        raise HTTPException(409, "connection link unavailable")
    try:
        parts = urlsplit(value)
        telegram_target = (
            parts.scheme == "tg"
            and parts.netloc == "proxy"
            and parts.path in {"", "/"}
        ) or (
            parts.scheme == "https"
            and parts.netloc in {"t.me", "telegram.me"}
            and parts.path == "/proxy"
        )
        query = parse_qs(parts.query, keep_blank_values=True)
        server = query.get("server", [])
        port = query.get("port", [])
        secret = query.get("secret", [])
        server_valid = False
        if len(server) == 1:
            try:
                ipaddress.ip_address(server[0])
                server_valid = True
            except ValueError:
                server_valid = (
                    re.fullmatch(r"[A-Za-z0-9.-]{1,253}", server[0]) is not None
                )
        valid = (
            telegram_target
            and not parts.fragment
            and not parts.username
            and not parts.password
            and set(query) == {"server", "port", "secret"}
            and len(server) == len(port) == len(secret) == 1
            and server_valid
            and re.fullmatch(r"[0-9]{1,5}", port[0]) is not None
            and 1 <= int(port[0]) <= 65535
            and re.fullmatch(r"[0-9A-Fa-f]{32,512}", secret[0]) is not None
        )
    except (TypeError, ValueError, OverflowError):
        valid = False
    if not valid:
        raise HTTPException(409, "connection link unavailable")
    return value


def register_telemt_dashboard_routes(app, context: RequestContext) -> None:
    settings = context.settings

    @app.get("/api/dashboard")
    async def dashboard(_user=Depends(context.current)):
        results = await asyncio.gather(
            app.state.telemt.health(),
            app.state.telemt.stats(),
            app.state.telemt.connections(),
            app.state.telemt.active_ips(),
            app.state.telemt.list_users(),
        )
        health, stats, connections, active_ips, items = results
        total_octets = sum(
            value
            for item in items
            if isinstance(item, dict)
            for value in [item.get("total_octets")]
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        )
        mt_active = sum(
            1
            for item in items
            if isinstance(item, dict) and item.get("enabled") is not False
        )
        mt_disabled = sum(
            1
            for item in items
            if isinstance(item, dict) and item.get("enabled") is False
        )
        protocols = {
            "mtproxy": {
                "status": "ready" if health.get("ready") is True else "degraded",
                "ready": health.get("ready") is True,
                "credentials": {
                    "active": mt_active,
                    "disabled": mt_disabled,
                    "total": mt_active + mt_disabled,
                },
                "runtime": {
                    "traffic_octets": total_octets,
                    "current_connections": connections.get("active", 0),
                    "active_ips": len(active_ips),
                },
            }
        }
        if settings.naive_enabled:
            try:
                naive_health, naive_items, naive_traffic_raw = await asyncio.gather(
                    app.state.naive.health(),
                    app.state.naive.list_users(),
                    app.state.naive.traffic(),
                )
                naive_traffic = safe_naive_traffic(naive_traffic_raw)
            except NaiveError:
                protocols["naive"] = {
                    "available": True,
                    "status": "degraded",
                    "ready": False,
                    "host": settings.naive_public_host,
                    "credentials": {"available": False},
                    "traffic": {
                        "available": False,
                        "reason": "manager_unavailable",
                    },
                }
            else:
                naive_active = sum(
                    1
                    for item in naive_items
                    if isinstance(item, dict) and item.get("enabled") is True
                )
                naive_disabled = sum(
                    1
                    for item in naive_items
                    if isinstance(item, dict) and item.get("enabled") is not True
                )
                naive_ready = naive_health.get("ready") is True
                protocols["naive"] = {
                    "available": True,
                    "status": "ready" if naive_ready else "degraded",
                    "ready": naive_ready,
                    "host": settings.naive_public_host,
                    "credentials": {
                        "active": naive_active,
                        "disabled": naive_disabled,
                        "total": naive_active + naive_disabled,
                    },
                    "traffic": {"available": True, **naive_traffic},
                }
        else:
            protocols["naive"] = {"available": False, "status": "disabled"}
        if settings.mieru_enabled:
            try:
                mieru_health, mieru_users, mieru_metrics = await asyncio.gather(
                    app.state.mieru.health(),
                    app.state.mieru.list_users(),
                    app.state.mieru.metrics(),
                )
            except MieruError:
                protocols["mieru"] = {
                    "available": True,
                    "status": "degraded",
                    "ready": False,
                    "credentials": {"available": False},
                    "traffic": {
                        "available": False,
                        "label": "application bytes",
                    },
                }
            else:
                if mieru_metrics != {
                    "status": "error",
                    "stale": True,
                    "users": [],
                    "capability": "unavailable",
                    "reason": "typed_histories_unavailable",
                }:
                    raise MieruError("Invalid Mieru metrics response")
                active = sum(
                    item.get("enabled") is True
                    for item in mieru_users
                    if isinstance(item, dict)
                )
                disabled = sum(
                    item.get("enabled") is not True
                    for item in mieru_users
                    if isinstance(item, dict)
                )
                protocols["mieru"] = {
                    "available": True,
                    "status": "ready"
                    if mieru_health.get("ready") is True
                    else "degraded",
                    "ready": mieru_health.get("ready") is True,
                    "revision": mieru_health.get("revision"),
                    "credentials": {
                        "active": active,
                        "disabled": disabled,
                        "total": active + disabled,
                    },
                    "traffic": {
                        "available": False,
                        "capability": "unavailable",
                        "reason": "typed_histories_unavailable",
                        "label": "application bytes",
                    },
                }
        else:
            protocols["mieru"] = {"available": False, "status": "disabled"}
        return {
            "health": health,
            "stats": stats,
            "connections": connections,
            "active_ips": active_ips,
            "traffic": {"runtime_total_octets": total_octets},
            "protocols": protocols,
        }

    @app.get("/api/users")
    async def users(_user=Depends(context.current)):
        items, quota_data = await asyncio.gather(
            app.state.telemt.list_users(),
            app.state.telemt.quota_stats(),
        )
        quotas = quota_by_username(quota_data)
        return {
            "items": [
                safe_user(item, quotas.get(item.get("username")))
                for item in items
                if isinstance(item, dict)
            ]
        }

    @app.post("/api/users", status_code=201)
    async def add_user(
        body: UserCreate,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        data = await app.state.telemt.create_user(body.username)
        await context.audit(user, "user.create", body.username, request)
        token = context.create_reveal(secret_reveal(data), user)
        return {"username": body.username, "reveal_token": token}

    @app.post("/api/users/{username}/access")
    async def user_access(
        username: str,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        selected = next(
            (
                item
                for item in await app.state.telemt.list_users()
                if item.get("username") == username
            ),
            None,
        )
        if selected is None:
            raise HTTPException(404, "user not found")
        access = secret_reveal(selected)
        if not access.get("link"):
            raise HTTPException(409, "connection link unavailable")
        link = proxy_link(access["link"])
        await context.audit(user, "user.access", username, request)
        return {"username": username, "link": link, "qr": qr_data(link)}

    @app.delete("/api/users/{username}", status_code=204)
    async def delete_user(
        username: str,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        await app.state.telemt.delete_user(username)
        await context.audit(user, "user.delete", username, request)

    @app.post("/api/users/{username}/limits")
    async def user_limits(
        username: str,
        body: UserLimits,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        fields = body.model_dump(exclude_unset=True)
        if not fields:
            raise HTTPException(422, "at least one limit is required")
        data = await app.state.telemt.update_user(username, fields)
        await context.audit(user, "user.limits", username, request, fields)
        return safe_user(data)

    @app.post("/api/users/{username}/reset-quota")
    async def user_reset_quota(
        username: str,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        data = await app.state.telemt.reset_quota(username)
        await context.audit(user, "user.reset_quota", username, request)
        return safe_quota_reset(data)

    @app.post("/api/users/{username}/{operation}")
    async def user_operation(
        username: str,
        operation: Literal["enable", "disable", "rotate"],
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        if operation == "rotate":
            result = await app.state.telemt.rotate(username)
            data = {
                "username": username,
                "reveal_token": context.create_reveal(secret_reveal(result), user),
            }
        else:
            data = safe_user(
                await app.state.telemt.set_enabled(
                    username, operation == "enable"
                )
            )
        await context.audit(user, f"user.{operation}", username, request)
        return data
