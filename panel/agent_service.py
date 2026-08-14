"""Entrypoint for an outbound-only fleet node agent."""
from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

from .fleet import ProtocolError
from .node_agent import AgentJournal, AgentTransportClient, LocalTelemtExecutor, NodeAgent


def required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise SystemExit(f"{name} is required")
    return value


def secret(name: str, file_name: str) -> str:
    path = os.getenv(file_name)
    return Path(path).read_text().strip() if path else required(name)


async def run():
    node_id = required("FLEET_NODE_ID")
    key = Path(required("FLEET_CLIENT_KEY"))
    if stat.S_IMODE(key.stat().st_mode) & 0o077:
        raise ProtocolError("FLEET_CLIENT_KEY must not be group/world accessible")
    journal = AgentJournal(Path(os.getenv("FLEET_JOURNAL", "/var/lib/mtproxy-agent/journal.sqlite3")))
    journal.recover_interrupted()
    executor = LocalTelemtExecutor(
        os.getenv("TELEMT_API_URL", "http://127.0.0.1:9091"),
        secret("TELEMT_API_TOKEN", "TELEMT_API_TOKEN_FILE"),
        timeout=float(os.getenv("TELEMT_API_TIMEOUT", "5")),
    )
    agent = NodeAgent(node_id, journal, executor)
    custom_ca = os.getenv("FLEET_SERVER_CA")
    client = AgentTransportClient(
        node_id=node_id,
        central_url=required("FLEET_CENTRAL_URL"),
        cert=Path(required("FLEET_CLIENT_CERT")), key=key,
        server_ca=Path(custom_ca) if custom_ca else True,
        agent=agent,
    )
    try:
        await client.run_forever()
    finally:
        await client.close()


def main():
    asyncio.run(run())


if __name__ == "__main__":
    main()
