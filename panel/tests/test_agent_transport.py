from __future__ import annotations

import hashlib
import ssl
import time
from pathlib import Path

import httpx
import pytest

from panel.agent_transport import AgentTransportServer, CertificateAuthority
from panel.fleet import FleetStore
from panel.node_agent import AgentJournal, AgentTransportClient, NodeAgent

pytestmark = pytest.mark.anyio


def issue_fixture(tmp_path: Path, node_id: str):
    ca = CertificateAuthority(tmp_path / "ca")
    ca.initialize("test fleet CA")
    server_key, server_cert = ca.issue_server("localhost", ["localhost", "127.0.0.1"], days=2)
    node_key, node_cert, metadata = ca.issue_node(node_id, days=2)
    return ca, server_key, server_cert, node_key, node_cert, metadata


async def start_server(tmp_path, store, server_key, server_cert, client_ca, **kwargs):
    server = AgentTransportServer(
        store,
        host="127.0.0.1",
        port=0,
        server_cert=server_cert,
        server_key=server_key,
        client_ca=client_ca,
        poll_seconds=0.05,
        request_timeout=2,
        **kwargs,
    )
    await server.start()
    return server, f"https://localhost:{server.port}"


def mtls_context(ca, cert, key):
    context = ssl.create_default_context(cafile=str(ca))
    context.load_cert_chain(str(cert), str(key))
    return context


async def test_real_tls_poll_binds_san_serial_and_fingerprint_then_records_result(tmp_path):
    ca, server_key, server_cert, node_key, node_cert, metadata = issue_fixture(tmp_path, "vpn-nl2")
    store = FleetStore(tmp_path / "panel.sqlite3")
    store.register_node("vpn-nl2", "Netherlands 2", {})
    store.bind_certificate("vpn-nl2", metadata)
    queued = store.enqueue(
        "vpn-nl2", "disable-alice-01", "telemt.user.disable", {"username": "alice"},
        "rev-1", actor="owner", expires_at=int(time.time()) + 60,
    )
    server, base_url = await start_server(tmp_path, store, server_key, server_cert, ca.cert_path)
    try:
        async with httpx.AsyncClient(
            base_url=base_url, verify=mtls_context(ca.cert_path, node_cert, node_key), trust_env=False
        ) as client:
            response = await client.get("/agent/v1/nodes/vpn-nl2/commands/next")
            assert response.status_code == 200
            command = response.json()["command"]
            assert command["command_id"] == queued["command_id"]
            assert command["actor"] == "owner"
            assert command["payload_sha256"] == hashlib.sha256(b'{"username":"alice"}').hexdigest()
            result = await client.put(
                f"/agent/v1/nodes/vpn-nl2/commands/{queued['command_id']}/result",
                json={
                    "sequence": 1, "status": "succeeded",
                    "result": {"username": "alice", "enabled": False, "telemt_revision": "rev-2"},
                },
            )
            assert result.status_code == 200
        assert store.commands("vpn-nl2")[0]["status"] == "succeeded"
        node = store.node("vpn-nl2")
        assert node["auth_state"] == "connected"
        assert node["last_seen_at"] is not None
    finally:
        await server.close()


async def test_tls_rejects_unknown_ca_and_route_rejects_certificate_for_other_node(tmp_path):
    ca, server_key, server_cert, node_key, node_cert, metadata = issue_fixture(tmp_path, "vpn-nl2")
    other = CertificateAuthority(tmp_path / "other-ca")
    other.initialize("other CA")
    bad_key, bad_cert, _ = other.issue_node("vpn-nl2", days=2)
    wrong_key, wrong_cert, wrong_metadata = ca.issue_node("edge-02", days=2)
    store = FleetStore(tmp_path / "panel.sqlite3")
    store.register_node("vpn-nl2", "Netherlands 2", {})
    store.register_node("edge-02", "Edge 2", {})
    store.bind_certificate("vpn-nl2", metadata)
    store.bind_certificate("edge-02", wrong_metadata)
    server, base_url = await start_server(tmp_path, store, server_key, server_cert, ca.cert_path)
    try:
        with pytest.raises(httpx.TransportError):
            async with httpx.AsyncClient(base_url=base_url, verify=mtls_context(ca.cert_path, bad_cert, bad_key), trust_env=False) as client:
                await client.get("/agent/v1/nodes/vpn-nl2/commands/next")
        async with httpx.AsyncClient(base_url=base_url, verify=mtls_context(ca.cert_path, wrong_cert, wrong_key), trust_env=False) as client:
            response = await client.get("/agent/v1/nodes/vpn-nl2/commands/next")
            assert response.status_code == 403
    finally:
        await server.close()


async def test_revocation_and_request_body_bound_fail_closed(tmp_path):
    ca, server_key, server_cert, node_key, node_cert, metadata = issue_fixture(tmp_path, "vpn-nl2")
    store = FleetStore(tmp_path / "panel.sqlite3")
    store.register_node("vpn-nl2", "Netherlands 2", {})
    store.bind_certificate("vpn-nl2", metadata)
    store.revoke_certificate("vpn-nl2", metadata["serial"])
    server, base_url = await start_server(tmp_path, store, server_key, server_cert, ca.cert_path, body_limit=256)
    try:
        async with httpx.AsyncClient(base_url=base_url, verify=mtls_context(ca.cert_path, node_cert, node_key), trust_env=False) as client:
            assert (await client.get("/agent/v1/nodes/vpn-nl2/commands/next")).status_code == 403
            oversized = await client.put(
                "/agent/v1/nodes/vpn-nl2/commands/00000000-0000-0000-0000-000000000000/result",
                content=b"x" * 257,
            )
            assert oversized.status_code == 413
    finally:
        await server.close()


async def test_agent_client_retries_result_from_durable_outbox_without_reexecution(tmp_path):
    ca, server_key, server_cert, node_key, node_cert, metadata = issue_fixture(tmp_path, "vpn-nl2")
    store = FleetStore(tmp_path / "panel.sqlite3")
    store.register_node("vpn-nl2", "Netherlands 2", {})
    store.bind_certificate("vpn-nl2", metadata)
    store.enqueue(
        "vpn-nl2", "disable-alice-01", "telemt.user.disable", {"username": "alice"}, "rev-1",
        actor="owner", expires_at=int(time.time()) + 60,
    )
    calls = []

    class Executor:
        async def execute(self, _item):
            calls.append(1)
            return {"username": "alice", "enabled": False, "telemt_revision": "rev-2"}

    server, base_url = await start_server(tmp_path, store, server_key, server_cert, ca.cert_path)
    journal = AgentJournal(tmp_path / "journal.sqlite3")
    agent = NodeAgent("vpn-nl2", journal, Executor())
    client = AgentTransportClient(
        node_id="vpn-nl2", central_url=base_url, cert=node_cert, key=node_key,
        server_ca=ca.cert_path, agent=agent, request_timeout=2,
    )
    original_upload = client.upload_result
    attempts = 0

    async def lose_first_ack(result):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.ConnectError("simulated lost connection")
        return await original_upload(result)

    client.upload_result = lose_first_ack
    try:
        assert await client.run_once() is False
        assert len(journal.pending_outbox()) == 1
        assert await client.run_once() is True
        assert journal.pending_outbox() == []
        assert calls == [1]
        assert store.commands("vpn-nl2")[0]["status"] == "succeeded"
    finally:
        await client.close()
        await server.close()
