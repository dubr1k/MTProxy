from __future__ import annotations

import asyncio
import secrets
from pathlib import Path

from fastapi import Depends, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse

from .schemas import AdminCreate, AdminUpdate, Login
from .store import ConflictError
from .web_context import RequestContext


def register_auth_admin_audit_routes(
    app, context: RequestContext, static: Path
) -> None:
    settings = context.settings

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(_request: Request):
        token = secrets.token_urlsafe(32)
        response = HTMLResponse((static / "login.html").read_text())
        response.set_cookie(
            "panel_csrf",
            token,
            secure=settings.session_cookie_secure,
            httponly=False,
            samesite="strict",
            path="/",
        )
        return response

    @app.get("/favicon.ico", include_in_schema=False)
    async def favicon():
        return Response(status_code=204)

    @app.post("/api/auth/login", status_code=204)
    async def do_login(body: Login, request: Request, response: Response):
        csrf = request.cookies.get("panel_csrf")
        if not csrf or not secrets.compare_digest(
            csrf, request.headers.get("X-CSRF-Token", "")
        ):
            raise HTTPException(403, "CSRF validation failed")
        scopes = [
            f"ip:{context.client_ip(request)}",
            f"account:{body.username.casefold()}:{context.client_ip(request)}",
        ]
        reserved = await asyncio.to_thread(
            app.state.store.reserve_login_attempt,
            scopes,
            settings.login_attempts,
            settings.login_window_seconds,
        )
        if not reserved:
            raise HTTPException(
                429,
                "too many attempts",
                headers={"Retry-After": str(settings.login_window_seconds)},
            )
        async with app.state.login_verify_slots:
            admin = await asyncio.to_thread(
                app.state.store.verify_admin, body.username, body.password
            )
        if not admin:
            raise HTTPException(401, "invalid credentials")
        await asyncio.to_thread(
            app.state.store.release_login_attempt,
            reserved,
        )
        session, session_csrf = await asyncio.to_thread(
            app.state.store.create_session,
            admin["id"],
            settings.session_ttl_seconds,
        )
        response.set_cookie(
            "panel_session",
            session,
            secure=settings.session_cookie_secure,
            httponly=True,
            samesite="strict",
            path="/",
            max_age=settings.session_ttl_seconds,
        )
        response.set_cookie(
            "panel_csrf",
            session_csrf,
            secure=settings.session_cookie_secure,
            httponly=False,
            samesite="strict",
            path="/",
            max_age=settings.session_ttl_seconds,
        )
        await context.audit(admin, "auth.login", admin["username"], request)

    @app.post("/api/auth/logout", status_code=204)
    async def logout(
        request: Request,
        response: Response,
        user=Depends(context.mutation),
    ):
        await context.audit(user, "auth.logout", user["username"], request)
        await asyncio.to_thread(
            app.state.store.delete_session,
            request.cookies.get("panel_session"),
        )
        response.delete_cookie("panel_session", path="/")
        response.delete_cookie("panel_csrf", path="/")

    @app.get("/api/auth/me")
    async def me(user=Depends(context.current)):
        return {
            "username": user["username"],
            "role": user["role"],
            "features": {
                "naive": settings.naive_enabled,
                "mieru": settings.mieru_enabled,
            },
        }

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        session = await asyncio.to_thread(
            app.state.store.session,
            request.cookies.get("panel_session"),
        )
        if not session:
            return RedirectResponse("/login", status_code=303)
        return (static / "index.html").read_text()

    @app.get("/api/reveal/{token}")
    async def get_reveal(token: str, user=Depends(context.current)):
        return context.consume_reveal(token, user)

    @app.get("/api/admins")
    async def admins(user=Depends(context.current)):
        if user["role"] != "owner":
            raise HTTPException(403, "insufficient role")
        items = await asyncio.to_thread(app.state.store.admins)
        return {"items": items}

    @app.post("/api/admins", status_code=201)
    async def add_admin(
        body: AdminCreate,
        request: Request,
        user=Depends(context.roles("owner")),
    ):
        try:
            admin_id = await asyncio.to_thread(
                app.state.store.create_admin,
                body.username,
                body.password,
                body.role,
            )
        except Exception as exc:
            raise HTTPException(409, "administrator exists") from exc
        await context.audit(
            user,
            "admin.create",
            body.username,
            request,
            {"role": body.role},
        )
        return {"id": admin_id}

    @app.patch("/api/admins/{admin_id}")
    async def edit_admin(
        admin_id: int,
        body: AdminUpdate,
        request: Request,
        user=Depends(context.roles("owner")),
    ):
        try:
            found = await asyncio.to_thread(
                app.state.store.update_admin,
                admin_id,
                body.role,
                body.password,
                body.active,
            )
        except ConflictError as exc:
            raise HTTPException(409, "cannot demote last owner") from exc
        if not found:
            raise HTTPException(404, "administrator not found")
        await context.audit(
            user,
            "admin.update",
            str(admin_id),
            request,
            {"role": body.role, "active": body.active},
        )
        return {"ok": True}

    @app.delete("/api/admins/{admin_id}", status_code=204)
    async def remove_admin(
        admin_id: int,
        request: Request,
        user=Depends(context.roles("owner")),
    ):
        try:
            found = await asyncio.to_thread(app.state.store.delete_admin, admin_id)
        except ConflictError as exc:
            raise HTTPException(409, "cannot delete last owner") from exc
        if not found:
            raise HTTPException(404, "administrator not found")
        await context.audit(user, "admin.delete", str(admin_id), request)

    @app.get("/api/audit")
    async def audit_log(
        limit: int = Query(default=200, ge=1, le=200),
        before_id: int | None = Query(default=None, ge=1),
        actor: str | None = Query(default=None, min_length=1, max_length=64),
        action: str | None = Query(default=None, min_length=1, max_length=128),
        target: str | None = Query(default=None, min_length=1, max_length=256),
        _user=Depends(context.current),
    ):
        rows = await asyncio.to_thread(
            app.state.store.audits,
            limit + 1,
            before_id=before_id,
            actor=actor,
            action=action,
            target=target,
        )
        response = {"items": rows[:limit]}
        if len(rows) > limit:
            response["next_cursor"] = rows[limit - 1]["id"]
        return response
