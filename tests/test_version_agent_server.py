from __future__ import annotations

import json
import os
import threading
from pathlib import Path

import httpx

from version_agent.server import Handler, UnixHTTPServer


class FakeAgent:
    def __init__(self):
        self.calls = []

    def list_versions(self):
        return {
            "enabled": True,
            "components": {"telemt": {"current": "old", "available": []}},
        }

    def update(self, component, version, expected_current):
        self.calls.append((component, version, expected_current))
        return {"component": component, "version": version, "changed": True}


def test_unix_socket_server_preserves_update_contract(tmp_path: Path):
    socket_path = tmp_path / "version-agent.sock"
    server = UnixHTTPServer(str(socket_path), Handler, gid=os.getgid())
    agent = FakeAgent()
    server.agent = agent
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        with httpx.Client(base_url="http://version-agent", transport=transport) as client:
            listed = client.get("/v1/versions")
            assert listed.status_code == 200
            assert listed.json()["components"]["telemt"]["current"] == "old"
            # Deliberately use a different JSON key order: the handler must not
            # rely on dict insertion order when parsing a privileged request.
            response = client.post(
                "/v1/update",
                content=json.dumps(
                    {
                        "expected_current": "old",
                        "version": "new",
                        "component": "telemt",
                    }
                ),
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == 200
            assert agent.calls == [("telemt", "new", "old")]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
