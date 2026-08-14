from __future__ import annotations

import asyncio
import base64
import io
import ipaddress
import os
import re
import secrets
import time
from dataclasses import dataclass, field
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


def create_app(settings: Settings | None = None, *, telemt=None, naive=None):
    settings = settings or Settings()
    app = FastAPI(title="MTProxy Panel", docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(settings.allowed_hosts))
    app.state.store = Store(settings.database_path)
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

    def safe_user(data):
        return {key: value for key, value in data.items() if key not in {"secret", "links"}}

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
        results = await asyncio.gather(app.state.telemt.health(), app.state.telemt.stats(), app.state.telemt.connections(), app.state.telemt.active_ips())
        return dict(zip(("health", "stats", "connections", "active_ips"), results))

    @app.get("/api/users")
    async def users(_user=Depends(current)):
        return {"items": [safe_user(item) for item in await app.state.telemt.list_users()]}

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

    @app.post("/api/users/{username}/{operation}")
    async def user_operation(username: str, operation: Literal["enable", "disable", "rotate"], request: Request, user=Depends(roles("owner", "admin"))):
        if operation == "rotate":
            result = await app.state.telemt.rotate(username)
            data = {"username": username, "reveal_token": reveal(secret_reveal(result), user)}
        else:
            data = await app.state.telemt.set_enabled(username, operation == "enable")
        audit(user, f"user.{operation}", username, request)
        return data

    @app.get("/api/naive/users")
    async def naive_users(_user=Depends(current)):
        require_naive()
        health, items = await asyncio.gather(app.state.naive.health(), app.state.naive.list_users())
        safe_items = [
            {"username": item.get("username"), "enabled": item.get("enabled") is True}
            for item in items if isinstance(item, dict) and re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", str(item.get("username", "")))
        ]
        return {
            "items": safe_items,
            "service": {"ready": health.get("ready") is True, "host": settings.naive_public_host},
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

    return app
