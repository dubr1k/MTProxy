"""Entrypoint for the central direct-mTLS agent ingress."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

from .agent_transport import AgentTransportServer
from .fleet import FleetStore


def required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"{name} is required")
    return value


async def serve():
    server = AgentTransportServer(
        FleetStore(Path(os.getenv("PANEL_DATABASE", "/data/panel.sqlite3"))),
        host=os.getenv("FLEET_LISTEN_HOST", "0.0.0.0"),
        port=int(os.getenv("FLEET_LISTEN_PORT", "8790")),
        server_cert=Path(required("FLEET_SERVER_CERT")),
        server_key=Path(required("FLEET_SERVER_KEY")),
        client_ca=Path(required("FLEET_CLIENT_CA")),
        poll_seconds=float(os.getenv("FLEET_POLL_SECONDS", "20")),
        request_timeout=float(os.getenv("FLEET_REQUEST_TIMEOUT", "10")),
        body_limit=int(os.getenv("FLEET_BODY_LIMIT", "16384")),
        requests_per_minute=int(os.getenv("FLEET_RATE_PER_MINUTE", "120")),
    )
    await server.start()
    try:
        await asyncio.Event().wait()
    finally:
        await server.close()


def main():
    asyncio.run(serve())


if __name__ == "__main__":
    main()
