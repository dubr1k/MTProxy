from __future__ import annotations

import asyncio
import secrets

from fastapi import Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from .settings import Settings


class RequestContext:
    def __init__(self, app, settings: Settings) -> None:
        self.app = app
        self.settings = settings

        async def current(request: Request):
            value = await asyncio.to_thread(
                self.app.state.store.session,
                request.cookies.get("panel_session"),
            )
            if not value:
                raise HTTPException(401, "authentication required")
            return value

        async def mutation(request: Request, user=Depends(current)):
            if not self.app.state.store.csrf_valid(
                user,
                request.headers.get("X-CSRF-Token"),
                request.cookies.get("panel_csrf"),
            ):
                raise HTTPException(403, "CSRF validation failed")
            return user

        self.current = current
        self.mutation = mutation

    def roles(self, *allowed: str):
        async def check(user=Depends(self.mutation)):
            if user["role"] not in allowed:
                raise HTTPException(403, "insufficient role")
            return user

        return check

    @staticmethod
    def client_ip(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    async def audit(
        self,
        user: dict,
        action: str,
        target: str,
        request: Request,
        detail: dict | None = None,
    ) -> None:
        await asyncio.to_thread(
            self.app.state.store.audit,
            user,
            action,
            target,
            self.client_ip(request),
            detail,
        )

    def create_reveal(self, data: dict, owner: dict) -> str:
        now = self.app.state.clock.monotonic()
        for expired_token, value in list(self.app.state.reveals.items()):
            if value[0] < now:
                self.app.state.reveals.pop(expired_token, None)
        token = secrets.token_urlsafe(32)
        self.app.state.reveals[token] = (
            now + self.settings.reveal_ttl_seconds,
            owner["token_hash"],
            data,
        )
        return token

    def consume_reveal(self, token: str, user: dict) -> dict:
        value = self.app.state.reveals.get(token)
        if not value or value[0] < self.app.state.clock.monotonic():
            self.app.state.reveals.pop(token, None)
            raise HTTPException(410, "reveal expired or consumed")
        if not secrets.compare_digest(value[1], user["token_hash"]):
            raise HTTPException(403, "reveal belongs to another session")
        self.app.state.reveals.pop(token, None)
        return value[2]


def install_security_middleware(app, settings: Settings) -> None:
    @app.middleware("http")
    async def security(request: Request, call_next):
        length = request.headers.get("content-length")
        try:
            declared_too_large = bool(
                length and int(length) > settings.body_limit_bytes
            )
        except ValueError:
            declared_too_large = True
        if declared_too_large:
            response = JSONResponse({"detail": "request body too large"}, 413)
        else:
            body = await request.body()
            response = (
                JSONResponse({"detail": "request body too large"}, 413)
                if len(body) > settings.body_limit_bytes
                else await call_next(request)
            )
        response.headers.update(
            {
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                "Cache-Control": "no-store",
            }
        )
        return response
