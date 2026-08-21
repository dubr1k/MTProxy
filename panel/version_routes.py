from __future__ import annotations

from typing import Literal

from fastapi import Depends, Request

from .schemas import VersionUpdate
from .versions import VersionAgentError
from .web_context import RequestContext


def register_version_routes(app, context: RequestContext) -> None:
    @app.get("/api/versions")
    async def versions(_user=Depends(context.current)):
        try:
            return await app.state.versions.list_versions()
        except VersionAgentError:
            return {
                "enabled": False,
                "components": {},
                "reason": "version_agent_unavailable",
            }

    @app.post("/api/versions/{component}/update")
    async def update_version(
        component: Literal["telemt", "naive", "mita"],
        body: VersionUpdate,
        request: Request,
        user=Depends(context.roles("owner")),
    ):
        result = await app.state.versions.update(
            component, body.version, body.expected_current
        )
        await context.audit(
            user,
            "runtime.version.update",
            component,
            request,
            {"version": body.version},
        )
        return result
