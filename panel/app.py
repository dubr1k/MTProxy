from __future__ import annotations

import asyncio
import base64
import io
import ipaddress
import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal
from urllib.parse import parse_qs, unquote, urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.middleware.trustedhost import TrustedHostMiddleware
import qrcode
import qrcode.image.svg

from .store import ConflictError, Store
from .fleet import CommandConflict, FleetStore, ProtocolError
from .naive import NaiveClient, NaiveError
from .telemt import TelemtClient, TelemtError


@dataclass(frozen=True)
class Settings:
    database_path: Path = Path(os.getenv("PANEL_DATABASE", "/data/panel.sqlite3"))
    telemt_url: str = os.getenv("TELEMT_API_URL", "http://mtproxy:9091")
    telemt_token: str = field(default_factory=lambda: _secret_setting("TELEMT_API_TOKEN", "TELEMT_API_TOKEN_FILE"))
    naive_socket: str = os.getenv("NAIVE_MANAGER_SOCKET", "/run/naive-manager/manager.sock")
    naive_token: str = field(default_factory=lambda: _secret_setting("NAIVE_MANAGER_TOKEN", "NAIVE_MANAGER_TOKEN_FILE"))
    naive_public_host: str = os.getenv("NAIVE_PUBLIC_HOST", "chrbased.dubr1k-solutions.com")
    naive_enabled: bool = os.getenv("NAIVE_ENABLED", "false").lower() == "true"
    session_cookie_secure: bool = os.getenv("PANEL_COOKIE_SECURE", "true").lower() == "true"
    allowed_hosts: tuple[str, ...] = field(default_factory=lambda: tuple(filter(None, os.getenv("PANEL_ALLOWED_HOSTS", "localhost,127.0.0.1").split(","))))
    session_ttl_seconds: int = 12 * 3600
    login_attempts: int = 5
    login_window_seconds: int = 300
    reveal_ttl_seconds: int = 120
    body_limit_bytes: int = 65536


def _secret_setting(name: str, file_name: str) -> str:
    if os.getenv(file_name):
        return Path(os.environ[file_name]).read_text().strip()
    return os.getenv(name, "")


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class UserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=32)
    @field_validator("username")
    @classmethod
    def valid(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9.-]+", value):
            raise ValueError("invalid username")
        return value


class UserLimits(BaseModel):
    data_quota_bytes: int | None = Field(default=None, strict=True, ge=1, le=2**63 - 1)
    rate_limit_up_bps: int | None = Field(default=None, strict=True, ge=1, le=10**12)
    rate_limit_down_bps: int | None = Field(default=None, strict=True, ge=1, le=10**12)
    max_tcp_conns: int | None = Field(default=None, strict=True, ge=1, le=100_000)
    max_unique_ips: int | None = Field(default=None, strict=True, ge=1, le=100_000)
    expiration_rfc3339: str | None = Field(default=None, max_length=64)

    @field_validator("expiration_rfc3339")
    @classmethod
    def valid_expiration(cls, value):
        if value is None:
            return value
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid RFC3339 timestamp") from exc
        if parsed.tzinfo is None:
            raise ValueError("timezone is required")
        return value


class NaiveUserCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")


class AdminCreate(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,64}$")
    password: str = Field(min_length=12, max_length=1024)
    role: Literal["owner", "admin", "viewer"]


class AdminUpdate(BaseModel):
    role: Literal["owner", "admin", "viewer"] | None = None
    password: str | None = Field(default=None, min_length=12, max_length=1024)
    active: bool | None = None


class FleetNodeCreate(BaseModel):
    node_id: str = Field(pattern=r"^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$")
    display_name: str = Field(min_length=1, max_length=128)
    inventory: dict = Field(default_factory=dict)


class FleetCommandCreate(BaseModel):
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$")
    operation: Literal[
        "telemt.inventory.refresh", "telemt.user.enable", "telemt.user.disable",
        "telemt.user.update_limits", "telemt.user.reset_quota",
    ]
    expected_telemt_revision: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,128}$")
    payload: dict


def create_app(settings: Settings | None = None, *, telemt=None, naive=None):
    settings = settings or Settings()
    app = FastAPI(title="MTProxy Panel", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.state.store = Store(settings.database_path)
    app.state.fleet = FleetStore(settings.database_path)
    app.state.telemt = telemt or TelemtClient(settings.telemt_url, settings.telemt_token)
    app.state.naive = naive or NaiveClient(settings.naive_socket, settings.naive_token)
    app.state.settings = settings
    app.state.reveals = {}
    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.middleware("http")
    async def security(request: Request, call_next):
        length = request.headers.get("content-length")
        try:
            declared_too_large = bool(length and int(length) > settings.body_limit_bytes)
        except ValueError:
            declared_too_large = True
        if declared_too_large:
            response = JSONResponse({"detail": "request body too large"}, 413)
        else:
            body = await request.body()
            response = (JSONResponse({"detail": "request body too large"}, 413)
                        if len(body) > settings.body_limit_bytes else await call_next(request))
        response.headers.update({
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cache-Control": "no-store",
        })
        return response

    def current(request: Request):
        value = app.state.store.session(request.cookies.get("panel_session"))
        if not value:
            raise HTTPException(401, "authentication required")
        return value

    def mutation(request: Request, user=Depends(current)):
        if not app.state.store.csrf_valid(user, request.headers.get("X-CSRF-Token"), request.cookies.get("panel_csrf")):
            raise HTTPException(403, "CSRF validation failed")
        return user

    def roles(*allowed):
        def check(user=Depends(mutation)):
            if user["role"] not in allowed:
                raise HTTPException(403, "insufficient role")
            return user
        return check

    def ip(request): return request.client.host if request.client else "unknown"
    def audit(user, action, target, request, detail=None): app.state.store.audit(user, action, target, ip(request), detail)

    def require_naive():
        if not settings.naive_enabled:
            raise HTTPException(404, "feature unavailable")

    def safe_user(data, quota=None):
        """Map Telemt's user view to the panel contract; never pass future fields through."""
        if not isinstance(data, dict):
            return {}
        result = {}
        string_fields = ("username", "expiration_rfc3339")
        bool_fields = ("enabled", "in_runtime")
        integer_fields = (
            "max_tcp_conns", "data_quota_bytes", "rate_limit_up_bps", "rate_limit_down_bps",
            "max_unique_ips", "current_connections", "active_unique_ips", "recent_unique_ips",
        )
        for key in string_fields:
            if isinstance(data.get(key), str) or (key == "expiration_rfc3339" and data.get(key) is None and key in data):
                result[key] = data[key]
        for key in bool_fields:
            if isinstance(data.get(key), bool):
                result[key] = data[key]
        for key in integer_fields:
            value = data.get(key)
            if (isinstance(value, int) and not isinstance(value, bool) and value >= 0) or (value is None and key in data):
                result[key] = value
        runtime_total = data.get("total_octets")
        if isinstance(runtime_total, int) and not isinstance(runtime_total, bool) and runtime_total >= 0:
            result["runtime_total_octets"] = runtime_total
        if isinstance(quota, dict):
            used = quota.get("used_bytes")
            last_reset = quota.get("last_reset_epoch_secs")
            if isinstance(used, int) and not isinstance(used, bool) and used >= 0:
                result["quota_used_bytes"] = used
            if isinstance(last_reset, int) and not isinstance(last_reset, bool) and last_reset >= 0:
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

    def safe_naive_traffic(data):
        if not isinstance(data, dict):
            raise NaiveError("Invalid NaiveProxy traffic response")
        rows = []
        for row in data.get("users", []):
            if not isinstance(row, dict) or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(row.get("username", ""))) is None:
                continue
            values = [row.get(key) for key in ("upload_bytes", "download_bytes", "total_bytes")]
            if any(type(value) is not int or not 0 <= value <= 2**63 - 1 for value in values):
                continue
            if values[0] + values[1] != values[2]:
                continue
            decimals = [row.get(f"{key}_decimal", str(value)) for key, value in zip(
                ("upload_bytes", "download_bytes", "total_bytes"), values, strict=True,
            )]
            if any(decimal != str(value) for decimal, value in zip(decimals, values, strict=True)):
                continue
            if not isinstance(row.get("period_start"), str) or not isinstance(row.get("updated_at"), str):
                continue
            rows.append({
                "username": row["username"], "upload_bytes": values[0],
                "download_bytes": values[1], "total_bytes": values[2],
                "upload_bytes_decimal": decimals[0], "download_bytes_decimal": decimals[1],
                "total_bytes_decimal": decimals[2],
                "period_start": row["period_start"], "updated_at": row["updated_at"],
            })
        directions = {"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"}
        if data.get("source") != "caddy_connect_access_log" or data.get("unit") != "bytes" or data.get("directions") != directions:
            raise NaiveError("Invalid NaiveProxy traffic response")
        semantics = data.get("semantics") if isinstance(data.get("semantics"), dict) else {}
        semantic_keys = (
            "closed_connect_tunnels_only", "active_tunnels_appear_on_close",
            "crash_can_lose_active_tunnel", "completed_records_survive_restart",
            "excludes_tls_ip_overhead", "reset_is_local_baseline_only",
        )
        upload_total = sum(row["upload_bytes"] for row in rows)
        download_total = sum(row["download_bytes"] for row in rows)
        total = sum(row["total_bytes"] for row in rows)
        if total > 2**63 - 1:
            raise NaiveError("Invalid NaiveProxy traffic response")
        return {
            "source": "caddy_connect_access_log", "unit": "bytes", "directions": directions,
            "pending": data.get("pending") is True,
            "aggregate": {
                "upload_bytes": upload_total, "download_bytes": download_total,
                "total_bytes": total, "upload_bytes_decimal": str(upload_total),
                "download_bytes_decimal": str(download_total), "total_bytes_decimal": str(total),
            },
            "users": rows,
            "semantics": {key: semantics[key] for key in semantic_keys if type(semantics.get(key)) is bool},
        }

    def quota_by_username(data):
        rows = data.get("users", []) if isinstance(data, dict) else []
        return {
            row["username"]: row for row in rows
            if isinstance(row, dict) and isinstance(row.get("username"), str)
        }

    def secret_reveal(data):
        user = data.get("user") if isinstance(data.get("user"), dict) else data
        links = user.get("links", {}) if isinstance(user, dict) else {}
        candidates = links.get("tls", []) if isinstance(links, dict) else []
        return {"secret": data.get("secret"), "link": candidates[0] if candidates else data.get("link")}

    def qr_data(link: str) -> str:
        output = io.BytesIO()
        qrcode.make(link, image_factory=qrcode.image.svg.SvgPathImage).save(output)
        return "data:image/svg+xml;base64," + base64.b64encode(output.getvalue()).decode()

    def proxy_link(value) -> str:
        """Accept only canonical Telegram MTProxy links from the upstream API."""
        if not isinstance(value, str) or len(value) > 2048:
            raise HTTPException(409, "connection link unavailable")
        try:
            parts = urlsplit(value)
            telegram_target = (
                (parts.scheme == "tg" and parts.netloc == "proxy" and parts.path in {"", "/"})
                or (parts.scheme == "https" and parts.netloc in {"t.me", "telegram.me"} and parts.path == "/proxy")
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
                    server_valid = re.fullmatch(r"[A-Za-z0-9.-]{1,253}", server[0]) is not None
            valid = (
                telegram_target and not parts.fragment and not parts.username and not parts.password
                and set(query) == {"server", "port", "secret"}
                and len(server) == len(port) == len(secret) == 1 and server_valid
                and re.fullmatch(r"[0-9]{1,5}", port[0]) is not None
                and 1 <= int(port[0]) <= 65535
                and re.fullmatch(r"[0-9A-Fa-f]{32,512}", secret[0]) is not None
            )
        except (TypeError, ValueError, OverflowError):
            valid = False
        if not valid:
            raise HTTPException(409, "connection link unavailable")
        return value

    def naive_reveal(value, username: str) -> dict:
        if not isinstance(value, dict) or not isinstance(value.get("proxy_url"), str):
            raise HTTPException(409, "NaiveProxy access unavailable")
        raw = value["proxy_url"]
        try:
            parts = urlsplit(raw)
            valid = (
                parts.scheme == "https" and parts.hostname == settings.naive_public_host
                and parts.port in {None, 443} and unquote(parts.username or "") == username
                and bool(unquote(parts.password or "")) and parts.path in {"", "/"}
                and not parts.query and not parts.fragment and len(raw) <= 2048
            )
        except (TypeError, ValueError, UnicodeError):
            valid = False
        if not valid:
            raise HTTPException(409, "NaiveProxy access unavailable")
        return {
            "username": username,
            "proxy_url": raw,
            "config": {"listen": "socks://127.0.0.1:1080", "proxy": raw},
            "qr": qr_data(raw),
        }

    def reveal(data, owner):
        if data.get("link"):
            link = proxy_link(data["link"])
            data = {**data, "link": link, "qr": qr_data(link)}
        now = time.monotonic()
        for expired_token, value in list(app.state.reveals.items()):
            if value[0] < now:
                app.state.reveals.pop(expired_token, None)
        token = secrets.token_urlsafe(32)
        app.state.reveals[token] = (now + settings.reveal_ttl_seconds, owner["token_hash"], data)
        return token

    @app.exception_handler(TelemtError)
    async def telemt_error(_request, _exc): return JSONResponse({"detail": "Telemt service unavailable"}, 502)

    @app.exception_handler(NaiveError)
    async def naive_error(_request, exc): return JSONResponse({"detail": "NaiveProxy manager unavailable"}, exc.status_code)

    @app.get("/healthz")
    async def healthz(): return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        token = secrets.token_urlsafe(32)
        response = HTMLResponse((static / "login.html").read_text())
        response.set_cookie("panel_csrf", token, secure=settings.session_cookie_secure, httponly=False, samesite="strict", path="/")
        return response

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return Response(status_code=204)

    @app.post("/api/auth/login", status_code=204)
    async def do_login(body: Login, request: Request, response: Response):
        csrf = request.cookies.get("panel_csrf")
        if not csrf or not secrets.compare_digest(csrf, request.headers.get("X-CSRF-Token", "")):
            raise HTTPException(403, "CSRF validation failed")
        scopes = [f"ip:{ip(request)}", f"account:{body.username.casefold()}:{ip(request)}"]
        if app.state.store.login_limited(scopes, settings.login_attempts, settings.login_window_seconds):
            raise HTTPException(429, "too many attempts", headers={"Retry-After": str(settings.login_window_seconds)})
        admin = await asyncio.to_thread(app.state.store.verify_admin, body.username, body.password)
        if not admin:
            app.state.store.record_login_failure(scopes)
            raise HTTPException(401, "invalid credentials")
        app.state.store.clear_login_failures(scopes)
        session, session_csrf = app.state.store.create_session(admin["id"], settings.session_ttl_seconds)
        response.set_cookie("panel_session", session, secure=settings.session_cookie_secure, httponly=True, samesite="strict", path="/", max_age=settings.session_ttl_seconds)
        response.set_cookie("panel_csrf", session_csrf, secure=settings.session_cookie_secure, httponly=False, samesite="strict", path="/", max_age=settings.session_ttl_seconds)
        app.state.store.audit(admin, "auth.login", admin["username"], ip(request))

    @app.post("/api/auth/logout", status_code=204)
    async def logout(request: Request, response: Response, user=Depends(mutation)):
        audit(user, "auth.logout", user["username"], request)
        app.state.store.delete_session(request.cookies.get("panel_session"))
        response.delete_cookie("panel_session", path="/")
        response.delete_cookie("panel_csrf", path="/")

    @app.get("/api/auth/me")
    async def me(user=Depends(current)):
        return {"username": user["username"], "role": user["role"], "features": {"naive": settings.naive_enabled}}

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        if not app.state.store.session(request.cookies.get("panel_session")):
            return RedirectResponse("/login", status_code=303)
        return (static / "index.html").read_text()

    @app.get("/api/dashboard")
    async def dashboard(_user=Depends(current)):
        results = await asyncio.gather(
            app.state.telemt.health(), app.state.telemt.stats(), app.state.telemt.connections(),
            app.state.telemt.active_ips(), app.state.telemt.list_users(),
        )
        health, stats, connections, active_ips, items = results
        total_octets = sum(
            value for item in items
            if isinstance(item, dict)
            for value in [item.get("total_octets")]
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        )
        mt_active = sum(
            1 for item in items
            if isinstance(item, dict) and item.get("enabled") is not False
        )
        mt_disabled = sum(
            1 for item in items
            if isinstance(item, dict) and item.get("enabled") is False
        )
        protocols = {
            "mtproxy": {
                "status": "ready" if health.get("ready") is True else "degraded",
                "ready": health.get("ready") is True,
                "credentials": {
                    "active": mt_active, "disabled": mt_disabled,
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
                    app.state.naive.health(), app.state.naive.list_users(), app.state.naive.traffic(),
                )
                naive_traffic = safe_naive_traffic(naive_traffic_raw)
            except NaiveError:
                protocols["naive"] = {
                    "available": True,
                    "status": "degraded",
                    "ready": False,
                    "host": settings.naive_public_host,
                    "credentials": {"available": False},
                    "traffic": {"available": False, "reason": "manager_unavailable"},
                }
            else:
                naive_active = sum(
                    1 for item in naive_items
                    if isinstance(item, dict) and item.get("enabled") is True
                )
                naive_disabled = sum(
                    1 for item in naive_items
                    if isinstance(item, dict) and item.get("enabled") is not True
                )
                naive_ready = naive_health.get("ready") is True
                protocols["naive"] = {
                    "available": True,
                    "status": "ready" if naive_ready else "degraded",
                    "ready": naive_ready,
                    "host": settings.naive_public_host,
                    "credentials": {
                        "active": naive_active, "disabled": naive_disabled,
                        "total": naive_active + naive_disabled,
                    },
                    "traffic": {"available": True, **naive_traffic},
                }
        else:
            protocols["naive"] = {"available": False, "status": "disabled"}
        return {
            "health": health, "stats": stats, "connections": connections,
            "active_ips": active_ips, "traffic": {"runtime_total_octets": total_octets},
            "protocols": protocols,
        }

    @app.get("/api/users")
    async def users(_user=Depends(current)):
        items, quota_data = await asyncio.gather(
            app.state.telemt.list_users(), app.state.telemt.quota_stats(),
        )
        quotas = quota_by_username(quota_data)
        return {"items": [
            safe_user(item, quotas.get(item.get("username")))
            for item in items if isinstance(item, dict)
        ]}

    @app.post("/api/users", status_code=201)
    async def add_user(body: UserCreate, request: Request, user=Depends(roles("owner", "admin"))):
        data = await app.state.telemt.create_user(body.username)
        audit(user, "user.create", body.username, request)
        token = reveal(secret_reveal(data), user)
        return {"username": body.username, "reveal_token": token}

    @app.post("/api/users/{username}/access")
    async def user_access(username: str, request: Request, user=Depends(roles("owner", "admin"))):
        selected = next((item for item in await app.state.telemt.list_users() if item.get("username") == username), None)
        if selected is None:
            raise HTTPException(404, "user not found")
        access = secret_reveal(selected)
        if not access.get("link"):
            raise HTTPException(409, "connection link unavailable")
        link = proxy_link(access["link"])
        audit(user, "user.access", username, request)
        return {"username": username, "link": link, "qr": qr_data(link)}

    @app.delete("/api/users/{username}", status_code=204)
    async def delete_user(username: str, request: Request, user=Depends(roles("owner", "admin"))):
        await app.state.telemt.delete_user(username)
        audit(user, "user.delete", username, request)

    @app.post("/api/users/{username}/limits")
    async def user_limits(username: str, body: UserLimits, request: Request, user=Depends(roles("owner", "admin"))):
        fields = body.model_dump(exclude_unset=True)
        if not fields:
            raise HTTPException(422, "at least one limit is required")
        data = await app.state.telemt.update_user(username, fields)
        audit(user, "user.limits", username, request, fields)
        return safe_user(data)

    @app.post("/api/users/{username}/reset-quota")
    async def user_reset_quota(username: str, request: Request, user=Depends(roles("owner", "admin"))):
        data = await app.state.telemt.reset_quota(username)
        audit(user, "user.reset_quota", username, request)
        return safe_quota_reset(data)

    @app.post("/api/users/{username}/{operation}")
    async def user_operation(username: str, operation: Literal["enable", "disable", "rotate"], request: Request, user=Depends(roles("owner", "admin"))):
        if operation == "rotate":
            result = await app.state.telemt.rotate(username)
            data = {"username": username, "reveal_token": reveal(secret_reveal(result), user)}
        else:
            data = safe_user(await app.state.telemt.set_enabled(username, operation == "enable"))
        audit(user, f"user.{operation}", username, request)
        return data

    @app.get("/api/naive/users")
    async def naive_users(_user=Depends(current)):
        require_naive()
        health, items, traffic_raw = await asyncio.gather(
            app.state.naive.health(), app.state.naive.list_users(), app.state.naive.traffic(),
        )
        traffic = safe_naive_traffic(traffic_raw)
        by_username = {row["username"]: row for row in traffic["users"]}
        safe_items = [
            {
                "username": item.get("username"), "enabled": item.get("enabled") is True,
                **by_username.get(item.get("username"), {
                    "upload_bytes": 0, "download_bytes": 0, "total_bytes": 0,
                    "upload_bytes_decimal": "0", "download_bytes_decimal": "0",
                    "total_bytes_decimal": "0", "period_start": "", "updated_at": "",
                }),
            }
            for item in items if isinstance(item, dict) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(item.get("username", "")))
        ]
        return {
            "items": safe_items,
            "service": {"ready": health.get("ready") is True, "host": settings.naive_public_host},
            "traffic": {
                "source": traffic["source"], "unit": traffic["unit"],
                "directions": traffic["directions"], "pending": traffic["pending"],
            },
        }

    @app.post("/api/naive/users", status_code=201)
    async def naive_add(body: NaiveUserCreate, request: Request, user=Depends(roles("owner", "admin"))):
        require_naive()
        data = naive_reveal(await app.state.naive.create(body.username), body.username)
        audit(user, "naive.create", body.username, request)
        return {"username": body.username, "reveal_token": reveal(data, user)}

    @app.post("/api/naive/users/{username}/access")
    async def naive_access(username: str, request: Request, user=Depends(roles("owner", "admin"))):
        require_naive()
        data = naive_reveal(await app.state.naive.reveal(username), username)
        audit(user, "naive.access", username, request)
        return data

    @app.post("/api/naive/users/{username}/{operation}")
    async def naive_operation(username: str, operation: Literal["enable", "disable", "rotate"], request: Request, user=Depends(roles("owner", "admin"))):
        require_naive()
        if operation == "rotate":
            data = naive_reveal(await app.state.naive.rotate(username), username)
            result = {"username": username, "reveal_token": reveal(data, user)}
        else:
            changed = await app.state.naive.set_enabled(username, operation == "enable")
            result = {"username": username, "enabled": changed.get("enabled") is True}
        audit(user, f"naive.{operation}", username, request)
        return result

    @app.post("/api/naive/users/{username}/traffic/reset")
    async def naive_traffic_reset(username: str, request: Request, user=Depends(roles("owner", "admin"))):
        require_naive()
        data = await app.state.naive.reset_traffic(username)
        traffic = safe_naive_traffic({
            "source": "caddy_connect_access_log", "unit": "bytes",
            "directions": {"upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"},
            "pending": False, "users": [data], "semantics": {},
        })
        if not traffic["users"]:
            raise HTTPException(502, "Invalid NaiveProxy traffic response")
        audit(user, "naive.traffic.reset", username, request)
        return traffic["users"][0]

    @app.delete("/api/naive/users/{username}", status_code=204)
    async def naive_delete(username: str, request: Request, user=Depends(roles("owner", "admin"))):
        require_naive()
        await app.state.naive.delete(username)
        audit(user, "naive.delete", username, request)

    @app.get("/api/reveal/{token}")
    async def get_reveal(token: str, user=Depends(current)):
        value = app.state.reveals.get(token)
        if not value or value[0] < time.monotonic():
            app.state.reveals.pop(token, None)
            raise HTTPException(410, "reveal expired or consumed")
        if not secrets.compare_digest(value[1], user["token_hash"]):
            raise HTTPException(403, "reveal belongs to another session")
        app.state.reveals.pop(token, None)
        return value[2]

    @app.get("/api/admins")
    async def admins(user=Depends(current)):
        if user["role"] != "owner":
            raise HTTPException(403, "insufficient role")
        return {"items": app.state.store.admins()}

    @app.post("/api/admins", status_code=201)
    async def add_admin(body: AdminCreate, request: Request, user=Depends(roles("owner"))):
        try:
            admin_id = app.state.store.create_admin(body.username, body.password, body.role)
        except Exception as exc:
            raise HTTPException(409, "administrator exists") from exc
        audit(user, "admin.create", body.username, request, {"role": body.role})
        return {"id": admin_id}

    @app.patch("/api/admins/{admin_id}")
    async def edit_admin(admin_id: int, body: AdminUpdate, request: Request, user=Depends(roles("owner"))):
        try:
            found = app.state.store.update_admin(admin_id, body.role, body.password, body.active)
        except ConflictError as exc:
            raise HTTPException(409, "cannot demote last owner") from exc
        if not found:
            raise HTTPException(404, "administrator not found")
        audit(user, "admin.update", str(admin_id), request, {"role": body.role, "active": body.active})
        return {"ok": True}

    @app.delete("/api/admins/{admin_id}", status_code=204)
    async def remove_admin(admin_id: int, request: Request, user=Depends(roles("owner"))):
        try:
            found = app.state.store.delete_admin(admin_id)
        except ConflictError as exc:
            raise HTTPException(409, "cannot delete last owner") from exc
        if not found:
            raise HTTPException(404, "administrator not found")
        audit(user, "admin.delete", str(admin_id), request)

    @app.get("/api/audit")
    async def audit_log(_user=Depends(current)):
        return {"items": app.state.store.audits()}

    @app.get("/api/fleet/nodes")
    async def fleet_nodes(_user=Depends(current)):
        return {"items": app.state.fleet.nodes(), "agent_transport": "mtls-pull-v1"}

    @app.post("/api/fleet/nodes", status_code=201)
    async def fleet_add_node(body: FleetNodeCreate, request: Request, user=Depends(roles("owner"))):
        try:
            node = app.state.fleet.register_node(body.node_id, body.display_name, body.inventory)
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "node already exists") from exc
        except ProtocolError as exc:
            raise HTTPException(422, str(exc)) from exc
        audit(user, "fleet.node.create", body.node_id, request, {"display_name": body.display_name, "inventory": body.inventory})
        return node

    @app.get("/api/fleet/nodes/{node_id}/commands")
    async def fleet_commands(node_id: str, user=Depends(current)):
        try:
            app.state.fleet.node(node_id)
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        items = app.state.fleet.commands(node_id)
        if user["role"] == "viewer":
            visible = {"command_id", "sequence", "operation", "status", "created_at", "completed_at"}
            items = [{key: value for key, value in item.items() if key in visible} for item in items]
        return {"items": items}

    @app.post("/api/fleet/nodes/{node_id}/commands", status_code=201)
    async def fleet_queue_command(node_id: str, body: FleetCommandCreate, request: Request, user=Depends(roles("owner", "admin"))):
        try:
            item = app.state.fleet.enqueue(
                node_id, body.idempotency_key, body.operation, body.payload,
                body.expected_telemt_revision, actor=user["username"],
            )
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        except CommandConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ProtocolError as exc:
            raise HTTPException(422, str(exc)) from exc
        audit(user, "fleet.command.queue", node_id, request, {
            "command_id": item["command_id"], "sequence": item["sequence"],
            "operation": item["operation"], "expected_telemt_revision": item["expected_telemt_revision"],
        })
        return item

    return app
