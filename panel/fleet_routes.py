from __future__ import annotations

import asyncio
import sqlite3

from fastapi import Depends, HTTPException, Request

from .fleet import CommandConflict, ProtocolError
from .schemas import FleetCommandCreate, FleetNodeCreate
from .web_context import RequestContext


def register_fleet_routes(app, context: RequestContext) -> None:
    @app.get("/api/fleet/nodes")
    async def fleet_nodes(_user=Depends(context.current)):
        items = await asyncio.to_thread(app.state.fleet.nodes)
        return {"items": items, "agent_transport": "mtls-pull-v1"}

    @app.post("/api/fleet/nodes", status_code=201)
    async def fleet_add_node(
        body: FleetNodeCreate,
        request: Request,
        user=Depends(context.roles("owner")),
    ):
        try:
            node = await asyncio.to_thread(
                app.state.fleet.register_node,
                body.node_id,
                body.display_name,
                body.inventory,
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "node already exists") from exc
        except ProtocolError as exc:
            raise HTTPException(422, str(exc)) from exc
        await context.audit(
            user,
            "fleet.node.create",
            body.node_id,
            request,
            {"display_name": body.display_name, "inventory": body.inventory},
        )
        return node

    @app.get("/api/fleet/nodes/{node_id}/commands")
    async def fleet_commands(node_id: str, user=Depends(context.current)):
        try:
            await asyncio.to_thread(app.state.fleet.node, node_id)
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        items = await asyncio.to_thread(app.state.fleet.commands, node_id)
        if user["role"] == "viewer":
            visible = {
                "command_id",
                "sequence",
                "operation",
                "status",
                "created_at",
                "completed_at",
            }
            items = [
                {key: value for key, value in item.items() if key in visible}
                for item in items
            ]
        return {"items": items}

    @app.post("/api/fleet/nodes/{node_id}/commands", status_code=201)
    async def fleet_queue_command(
        node_id: str,
        body: FleetCommandCreate,
        request: Request,
        user=Depends(context.roles("owner", "admin")),
    ):
        try:
            item = await asyncio.to_thread(
                app.state.fleet.enqueue,
                node_id,
                body.idempotency_key,
                body.operation,
                body.payload,
                body.expected_telemt_revision,
                actor=user["username"],
            )
        except KeyError as exc:
            raise HTTPException(404, "node not found") from exc
        except CommandConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ProtocolError as exc:
            raise HTTPException(422, str(exc)) from exc
        await context.audit(
            user,
            "fleet.command.queue",
            node_id,
            request,
            {
                "command_id": item["command_id"],
                "sequence": item["sequence"],
                "operation": item["operation"],
                "expected_telemt_revision": item["expected_telemt_revision"],
            },
        )
        return item
