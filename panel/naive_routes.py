from __future__ import annotations

import asyncio
import re
from typing import Literal
from urllib.parse import unquote, urlsplit

from fastapi import Depends, HTTPException, Request

from .naive import NaiveError
from .reveals import karing_client
from .schemas import NaiveQuotaUpdate, NaiveUserCreate
from .web_context import RequestContext


def safe_naive_traffic(data):
    if not isinstance(data, dict):
        raise NaiveError("Invalid NaiveProxy traffic response")
    rows = []
    for row in data.get("users", []):
        if not isinstance(row, dict) or re.fullmatch(
            r"[A-Za-z0-9_.-]{1,64}", str(row.get("username", ""))
        ) is None:
            continue
        values = [
            row.get(key)
            for key in ("upload_bytes", "download_bytes", "total_bytes")
        ]
        if any(
            type(value) is not int or not 0 <= value <= 2**63 - 1
            for value in values
        ):
            continue
        if values[0] + values[1] != values[2]:
            continue
        decimals = [
            row.get(f"{key}_decimal", str(value))
            for key, value in zip(
                ("upload_bytes", "download_bytes", "total_bytes"),
                values,
                strict=True,
            )
        ]
        if any(
            decimal != str(value)
            for decimal, value in zip(decimals, values, strict=True)
        ):
            continue
        if not isinstance(row.get("period_start"), str) or not isinstance(
            row.get("updated_at"), str
        ):
            continue
        rows.append(
            {
                "username": row["username"],
                "upload_bytes": values[0],
                "download_bytes": values[1],
                "total_bytes": values[2],
                "upload_bytes_decimal": decimals[0],
                "download_bytes_decimal": decimals[1],
                "total_bytes_decimal": decimals[2],
                "period_start": row["period_start"],
                "updated_at": row["updated_at"],
            }
        )
    directions = {
        "upload_bytes": "client_to_proxy",
        "download_bytes": "proxy_to_client",
    }
    if (
        data.get("source") != "caddy_connect_access_log"
        or data.get("unit") != "bytes"
        or data.get("directions") != directions
    ):
        raise NaiveError("Invalid NaiveProxy traffic response")
    semantics = data.get("semantics") if isinstance(data.get("semantics"), dict) else {}
    semantic_keys = (
        "closed_connect_tunnels_only",
        "active_tunnels_appear_on_close",
        "crash_can_lose_active_tunnel",
        "completed_records_survive_restart",
        "excludes_tls_ip_overhead",
        "reset_is_local_baseline_only",
    )
    upload_total = sum(row["upload_bytes"] for row in rows)
    download_total = sum(row["download_bytes"] for row in rows)
    total = sum(row["total_bytes"] for row in rows)
    if total > 2**63 - 1:
        raise NaiveError("Invalid NaiveProxy traffic response")
    return {
        "source": "caddy_connect_access_log",
        "unit": "bytes",
        "directions": directions,
        "pending": data.get("pending") is True,
        "aggregate": {
            "upload_bytes": upload_total,
            "download_bytes": download_total,
            "total_bytes": total,
            "upload_bytes_decimal": str(upload_total),
            "download_bytes_decimal": str(download_total),
            "total_bytes_decimal": str(total),
        },
        "users": rows,
        "semantics": {
            key: semantics[key]
            for key in semantic_keys
            if type(semantics.get(key)) is bool
        },
    }


def safe_naive_quota(value):
    if value is None:
        return None
    if type(value) is int and 1 <= value <= 2**63 - 1:
        return value
    raise NaiveError("Invalid NaiveProxy quota response")


def register_naive_routes(app, context: RequestContext) -> None:
    settings = context.settings

    def require_naive():
        if not settings.naive_enabled:
            raise HTTPException(404, "feature unavailable")

    def naive_reveal(value, username: str) -> dict:
        if not isinstance(value, dict) or not isinstance(value.get("proxy_url"), str):
            raise HTTPException(409, "NaiveProxy access unavailable")
        raw = value["proxy_url"]
        try:
            parts = urlsplit(raw)
            valid = (
                parts.scheme == "https"
                and parts.hostname == settings.naive_public_host
                and parts.port in {None, 443}
                and unquote(parts.username or "") == username
                and bool(unquote(parts.password or ""))
                and parts.path in {"", "/"}
                and not parts.query
                and not parts.fragment
                and len(raw) <= 2048
            )
        except (TypeError, ValueError, UnicodeError):
            valid = False
        if not valid:
            raise HTTPException(409, "NaiveProxy access unavailable")
        password = unquote(parts.password or "")
        native_config = {"listen": "socks://127.0.0.1:1080", "proxy": raw}
        karing_config = {
            "outbounds": [
                {
                    "type": "naive",
                    "tag": f"naive-{username}",
                    "server": settings.naive_public_host,
                    "server_port": 443,
                    "username": username,
                    "password": password,
                    "tls": {
                        "enabled": True,
                        "server_name": settings.naive_public_host,
                    },
                }
            ]
        }
        return {
            "service": "naive",
            "username": username,
            "clients": {
                "native": {
                    "label": "NaiveProxy",
                    "type": "config",
                    "config": native_config,
                    "filename": f"naive-{username}.json",
                },
                "karing": karing_client(
                    karing_config,
                    name=f"NaiveProxy · {username}",
                    filename=f"karing-naive-{username}.json",
                ),
                "shadowrocket": {
                    "label": "Shadowrocket",
                    "type": "manual",
                    "fields": {
                        "proxy_type": "HTTPS",
                        "server": settings.naive_public_host,
                        "port": 443,
                        "username": username,
                        "password": password,
                    },
                },
            },
        }

    @app.get("/api/naive/users")
    async def naive_users(_user=Depends(context.current)):
        require_naive()
        health, items, traffic_raw = await asyncio.gather(
            app.state.naive.health(),
            app.state.naive.list_users(),
            app.state.naive.traffic(),
        )
        traffic = safe_naive_traffic(traffic_raw)
        by_username = {row["username"]: row for row in traffic["users"]}
        safe_items = [
            {
                "username": item.get("username"),
                "enabled": item.get("enabled") is True,
                "disabled_reason": item.get("disabled_reason")
                if item.get("disabled_reason") in {"manual", "quota"}
                else None,
                "quota_bytes": safe_naive_quota(item.get("quota_bytes")),
                **by_username.get(
                    item.get("username"),
                    {
                        "upload_bytes": 0,
                        "download_bytes": 0,
                        "total_bytes": 0,
                        "upload_bytes_decimal": "0",
                        "download_bytes_decimal": "0",
                        "total_bytes_decimal": "0",
                        "period_start": "",
                        "updated_at": "",
                    },
                ),
            }
            for item in items
            if isinstance(item, dict)
            and re.fullmatch(
                r"[A-Za-z0-9_.-]{1,64}", str(item.get("username", ""))
            )
        ]
        for item in safe_items:
            quota = item["quota_bytes"]
            used = item["total_bytes"]
            item["quota_bytes_decimal"] = None if quota is None else str(quota)
            item["quota_used_bytes"] = used
            item["quota_used_bytes_decimal"] = str(used)
            item["quota_remaining_bytes"] = (
                None if quota is None else max(0, quota - used)
            )
            item["quota_remaining_bytes_decimal"] = (
                None if quota is None else str(max(0, quota - used))
            )
            item["quota_exhausted"] = quota is not None and used >= quota
        return {
            "items": safe_items,
            "service": {
                "ready": health.get("ready") is True,
                "host": settings.naive_public_host,
            },
            "traffic": {
                "source": traffic["source"],
                "unit": traffic["unit"],
                "directions": traffic["directions"],
                "pending": traffic["pending"],
            },
        }

    @app.post("/api/naive/users", status_code=201)
    async def naive_add(
        body: NaiveUserCreate,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_naive()
        data = naive_reveal(
            await app.state.naive.create(body.username, body.quota_bytes),
            body.username,
        )
        await context.audit(
            user,
            "naive.create",
            body.username,
            request,
            {"quota_bytes": body.quota_bytes},
        )
        return {
            "username": body.username,
            "reveal_token": context.create_reveal(data, user),
        }

    @app.post("/api/naive/users/{username}/access")
    async def naive_access(
        username: str,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_naive()
        data = naive_reveal(await app.state.naive.reveal(username), username)
        await context.audit(user, "naive.access", username, request)
        return data

    @app.post("/api/naive/users/{username}/quota")
    async def naive_quota(
        username: str,
        body: NaiveQuotaUpdate,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_naive()
        result = await app.state.naive.set_quota(username, body.quota_bytes)
        if not isinstance(result, dict):
            raise HTTPException(502, "Invalid NaiveProxy quota response")
        quota = safe_naive_quota(result.get("quota_bytes"))
        payload = {"username": username, "quota_bytes": quota}
        if "enabled" in result:
            payload["enabled"] = result.get("enabled") is True
            payload["disabled_reason"] = (
                result.get("disabled_reason")
                if result.get("disabled_reason") in {"manual", "quota"}
                else None
            )
        await context.audit(
            user,
            "naive.quota",
            username,
            request,
            {"quota_bytes": quota},
        )
        return payload

    @app.post("/api/naive/users/{username}/{operation}")
    async def naive_operation(
        username: str,
        operation: Literal["enable", "disable", "rotate"],
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_naive()
        if operation == "rotate":
            data = naive_reveal(await app.state.naive.rotate(username), username)
            result = {
                "username": username,
                "reveal_token": context.create_reveal(data, user),
            }
        else:
            changed = await app.state.naive.set_enabled(
                username, operation == "enable"
            )
            result = {
                "username": username,
                "enabled": changed.get("enabled") is True,
            }
        await context.audit(user, f"naive.{operation}", username, request)
        return result

    @app.post("/api/naive/users/{username}/traffic/reset")
    async def naive_traffic_reset(
        username: str,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_naive()
        data = await app.state.naive.reset_traffic(username)
        traffic = safe_naive_traffic(
            {
                "source": "caddy_connect_access_log",
                "unit": "bytes",
                "directions": {
                    "upload_bytes": "client_to_proxy",
                    "download_bytes": "proxy_to_client",
                },
                "pending": False,
                "users": [data],
                "semantics": {},
            }
        )
        if not traffic["users"]:
            raise HTTPException(502, "Invalid NaiveProxy traffic response")
        await context.audit(user, "naive.traffic.reset", username, request)
        return traffic["users"][0]

    @app.delete("/api/naive/users/{username}", status_code=204)
    async def naive_delete(
        username: str,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        require_naive()
        await app.state.naive.delete(username)
        await context.audit(user, "naive.delete", username, request)
