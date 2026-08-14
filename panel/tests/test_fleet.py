from __future__ import annotations

import json
import asyncio
import hashlib
import time

import httpx
import pytest

from panel.fleet import CommandConflict, FleetStore, ProtocolError, TypedCommand
from panel.agent_service import build_executor
from panel.mieru import MieruError
from panel.node_agent import AgentJournal, ExecutionIndeterminate, LocalMieruExecutor, LocalTelemtExecutor, NodeAgent, RoutingExecutor


pytestmark = pytest.mark.anyio


def command(sequence=1, *, operation="telemt.user.disable", payload=None, revision="rev-7"):
    payload = payload if payload is not None else {"username": "alice"}
    payload_sha256 = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return TypedCommand.parse({
        "protocol_version": 1,
        "command_id": f"018f47ac-1234-7abc-8def-{sequence:012d}",
        "node_id": "edge-01",
        "sequence": sequence,
        "idempotency_key": f"disable-alice-{sequence}",
        "operation": operation,
        "expected_telemt_revision": revision,
        "actor": "owner", "expires_at": int(time.time()) + 60, "payload_sha256": payload_sha256,
        "payload": payload,
    })


def test_typed_protocol_rejects_generic_commands_and_unknown_payload_fields():
    with pytest.raises(ProtocolError, match="operation"):
        command(operation="shell.exec", payload={"command": "id"})
    with pytest.raises(ProtocolError, match="payload"):
        command(payload={"username": "alice", "url": "https://attacker.invalid"})
    with pytest.raises(ProtocolError, match="node_id"):
        TypedCommand.parse({**command().as_dict(), "node_id": "../../etc"})


def test_mieru_fleet_boundary_allows_only_secret_free_inspection_and_lifecycle():
    inspect = command(operation="mieru.inspect", payload={})
    assert inspect.operation == "mieru.inspect"
    restart = command(operation="mieru.lifecycle.restart", payload={})
    assert restart.payload == {}
    with pytest.raises(ProtocolError, match="operation is not allowlisted"):
        command(operation="mieru.config.apply", payload={"config": {"portBindings": []}})
    with pytest.raises(ProtocolError, match="operation"):
        command(operation="mieru.user.rotate", payload={"username": "alice"})


def test_fleet_inventory_accepts_mieru_version_and_capabilities(tmp_path):
    store = FleetStore(tmp_path / "fleet.sqlite3")
    node = store.register_node("edge-01", "edge", {
        "mieru_version": "3.35.0", "capabilities": ["mieru.inspect", "mieru.metrics", "mieru.lifecycle.restart"],
    })
    assert node["inventory"]["mieru_version"] == "3.35.0"


async def test_node_agent_routes_typed_mieru_operations_without_generic_paths():
    class Client:
        async def health(self): return {"status": "running", "ready": True, "revision": "mrev-1"}
        async def metrics(self):
            return {
                "status": "error",
                "stale": True,
                "users": [],
                "capability": "unavailable",
                "reason": "typed_histories_unavailable",
            }
        async def lifecycle(self, action):
            assert action == "restart"
            return {"status": "running", "ready": True, "revision": "mrev-1"}

    executor = RoutingExecutor(telemt=None, mieru=LocalMieruExecutor(Client()))
    inspected = await executor.execute(command(operation="mieru.inspect", payload={}))
    assert inspected == {"mieru_status": "running", "mieru_ready": True, "mieru_revision": "mrev-1"}
    restarted = await executor.execute(command(operation="mieru.lifecycle.restart", payload={}))
    assert restarted["mieru_status"] == "running"
    metrics = await executor.execute(command(operation="mieru.metrics", payload={}))
    assert metrics == {
        "metrics_status": "error",
        "metrics_stale": True,
        "metrics_capability": "unavailable",
        "metrics_reason": "typed_histories_unavailable",
    }


async def test_uncertain_mieru_lifecycle_is_durable_indeterminate(tmp_path):
    class Client:
        async def lifecycle(self, _action):
            raise MieruError("manager unavailable")

    agent = NodeAgent(
        "edge-01",
        AgentJournal(tmp_path / "mieru-agent.sqlite3"),
        LocalMieruExecutor(Client()),
    )
    result = await agent.apply(
        command(operation="mieru.lifecycle.restart", payload={})
    )
    assert result["status"] == "indeterminate"
    assert result["result"] == {"message": "outcome requires Mieru reconciliation"}


def test_agent_service_builds_optional_mieru_routing_from_uds_token_file(
    tmp_path, monkeypatch
):
    token_file = tmp_path / "mieru-token"
    token_file.write_text("m" * 32)
    monkeypatch.setenv("TELEMT_API_TOKEN", "Bearer local-only")
    monkeypatch.setenv("MIERU_MANAGER_SOCKET", "/run/mieru-manager/manager.sock")
    monkeypatch.setenv("MIERU_MANAGER_TOKEN_FILE", str(token_file))

    executor = build_executor()

    assert isinstance(executor, RoutingExecutor)
    assert isinstance(executor.telemt, LocalTelemtExecutor)
    assert isinstance(executor.mieru, LocalMieruExecutor)
    assert executor.mieru.client.socket_path == "/run/mieru-manager/manager.sock"
    assert executor.mieru.client.token == "m" * 32


def test_agent_service_rejects_partial_mieru_configuration(monkeypatch):
    monkeypatch.setenv("TELEMT_API_TOKEN", "Bearer local-only")
    monkeypatch.setenv("MIERU_MANAGER_TOKEN", "m" * 32)
    monkeypatch.delenv("MIERU_MANAGER_SOCKET", raising=False)
    with pytest.raises(ProtocolError, match="both socket and token"):
        build_executor()


def test_fleet_store_assigns_monotonic_sequences_and_enforces_idempotency(tmp_path):
    store = FleetStore(tmp_path / "fleet.sqlite3")
    node = store.register_node("edge-01", "Frankfurt edge", {"telemt_version": "3.4.25", "region": "eu-central"})
    assert node["auth_state"] == "unenrolled"
    first = store.enqueue("edge-01", "same-key", "telemt.user.disable", {"username": "alice"}, "rev-1")
    replay = store.enqueue("edge-01", "same-key", "telemt.user.disable", {"username": "alice"}, "rev-1")
    second = store.enqueue("edge-01", "next-key", "telemt.user.enable", {"username": "alice"}, "rev-2")
    assert replay["command_id"] == first["command_id"]
    assert [first["sequence"], second["sequence"]] == [1, 2]
    with pytest.raises(CommandConflict):
        store.enqueue("edge-01", "same-key", "telemt.user.enable", {"username": "alice"}, "rev-1")


def test_fleet_inventory_and_results_are_recursively_secret_free(tmp_path):
    store = FleetStore(tmp_path / "fleet.sqlite3")
    with pytest.raises(ProtocolError, match="secret-bearing"):
        store.register_node("edge-01", "edge", {"nested": {"api_token": "leak"}})
    store.register_node("edge-01", "edge", {"telemt_version": "3.4.25"})
    queued = store.enqueue("edge-01", "result-k1", "telemt.user.disable", {"username": "alice"}, "rev-1")
    with pytest.raises(ProtocolError, match="secret-bearing"):
        store.record_result("edge-01", queued["command_id"], 1, "succeeded", {"link": "tg://secret"})


def test_result_upload_retry_is_idempotent_but_conflicting_replay_is_rejected(tmp_path):
    store = FleetStore(tmp_path / "fleet.sqlite3")
    store.register_node("edge-01", "edge", {"telemt_version": "3.4.25"})
    queued = store.enqueue("edge-01", "result-replay", "telemt.user.disable", {"username": "alice"}, "rev-1")
    result = {"username": "alice", "enabled": False, "telemt_revision": "rev-2"}
    first = store.record_result("edge-01", queued["command_id"], 1, "succeeded", result)
    replay = store.record_result("edge-01", queued["command_id"], 1, "succeeded", result)
    assert replay == first
    with pytest.raises(CommandConflict):
        store.record_result("edge-01", queued["command_id"], 1, "failed", {"message": "command rejected (ExecutorError)"})


async def test_agent_journal_prevents_reexecution_after_restart_and_rejects_sequence_gap(tmp_path):
    calls = []

    class Executor:
        async def execute(self, item):
            calls.append(item.sequence)
            return {"username": "alice", "enabled": False, "telemt_revision": "rev-8"}

    journal_path = tmp_path / "agent.sqlite3"
    first = NodeAgent("edge-01", AgentJournal(journal_path), Executor())
    result = await first.apply(command())
    restarted = NodeAgent("edge-01", AgentJournal(journal_path), Executor())
    replay = await restarted.apply(command())
    assert replay == result
    assert calls == [1]
    with pytest.raises(ProtocolError, match="sequence gap"):
        await restarted.apply(command(3))


def command_envelope(stored):
    return {key: stored[key] for key in (
        "protocol_version", "command_id", "node_id", "sequence", "idempotency_key", "operation",
        "expected_telemt_revision", "actor", "expires_at", "payload_sha256", "payload",
    )}


async def test_expired_command_advances_node_sequence_without_executing_mutation(tmp_path):
    store = FleetStore(tmp_path / "fleet.sqlite3")
    store.register_node("edge-01", "edge", {"telemt_version": "3.4.25"})
    expired = store.enqueue(
        "edge-01", "expired-disable", "telemt.user.disable", {"username": "alice"}, "rev-1",
        expires_at=int(time.time()) - 1,
    )
    current = store.enqueue(
        "edge-01", "current-enable", "telemt.user.enable", {"username": "alice"}, "rev-1",
        expires_at=int(time.time()) + 60,
    )
    calls = []

    class Executor:
        async def execute(self, item):
            calls.append(item.sequence)
            return {"username": "alice", "enabled": True, "telemt_revision": "rev-2"}

    agent = NodeAgent("edge-01", AgentJournal(tmp_path / "agent.sqlite3"), Executor())

    expired_result = await agent.apply(command_envelope(store.poll_next("edge-01")))
    assert expired_result == {
        "status": "failed", "sequence": 1, "command_id": expired["command_id"],
        "result": {"message": "command rejected (ProtocolError)"},
    }
    assert calls == []
    store.record_result("edge-01", expired["command_id"], 1, "failed", expired_result["result"])
    agent.journal.mark_uploaded(expired["command_id"])

    restarted = NodeAgent("edge-01", AgentJournal(tmp_path / "agent.sqlite3"), Executor())
    current_result = await restarted.apply(command_envelope(store.poll_next("edge-01")))
    assert current_result["command_id"] == current["command_id"]
    assert current_result["status"] == "succeeded"
    assert calls == [2]


async def test_concurrent_duplicate_does_not_corrupt_inflight_execution(tmp_path):
    entered, release = asyncio.Event(), asyncio.Event()

    class Executor:
        async def execute(self, _item):
            entered.set()
            await release.wait()
            return {"username": "alice", "enabled": False, "telemt_revision": "rev-8"}

    agent = NodeAgent("edge-01", AgentJournal(tmp_path / "agent.sqlite3"), Executor())
    running = asyncio.create_task(agent.apply(command()))
    await entered.wait()
    with pytest.raises(ProtocolError, match="already executing"):
        await agent.apply(command())
    release.set()
    assert (await running)["status"] == "succeeded"


async def test_uncertain_transport_outcome_is_durable_indeterminate(tmp_path):
    class Executor:
        async def execute(self, _item):
            raise ExecutionIndeterminate("response lost")

    journal = AgentJournal(tmp_path / "agent.sqlite3")
    result = await NodeAgent("edge-01", journal, Executor()).apply(command())
    assert result["status"] == "indeterminate"
    assert result["result"] == {"message": "outcome requires Telemt reconciliation"}
    with journal.connect() as db:
        assert db.execute("PRAGMA synchronous").fetchone()[0] == 2


async def test_exclusive_startup_recovery_marks_crash_residue_without_reexecution(tmp_path):
    journal = AgentJournal(tmp_path / "agent.sqlite3")
    journal.begin(command())
    assert journal.recover_interrupted() == 1

    class MustNotRun:
        async def execute(self, _item):
            raise AssertionError("recovered command was re-executed")

    replay = await NodeAgent("edge-01", journal, MustNotRun()).apply(command())
    assert replay["status"] == "indeterminate"


def test_exclusive_recovery_labels_mieru_crash_with_operation_specific_reconciliation(
    tmp_path,
):
    journal = AgentJournal(tmp_path / "agent.sqlite3")
    item = command(operation="mieru.lifecycle.restart", payload={})
    journal.begin(item)
    assert journal.recover_interrupted() == 1
    assert journal.pending_outbox()[0]["result"] == {
        "message": "outcome requires Mieru reconciliation"
    }


async def test_local_executor_is_loopback_only_and_sends_revision_precondition():
    seen = {}

    async def handler(request):
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content) if request.content else None
        seen["if_match"] = request.headers.get("if-match")
        return httpx.Response(200, json={"ok": True, "data": {"username": "alice", "enabled": False}, "revision": "rev-8"})

    executor = LocalTelemtExecutor(
        "http://127.0.0.1:9091", "Bearer local-only", transport=httpx.MockTransport(handler)
    )
    result = await executor.execute(command())
    assert seen == {
        "method": "POST",
        "path": "/v1/users/alice/disable",
        "body": None,
        "if_match": "rev-7",
    }
    assert result["telemt_revision"] == "rev-8"
    for unsafe in ("http://telemt:9091", "https://example.com", "http://user:pass@127.0.0.1:9091"):
        with pytest.raises(ProtocolError, match="loopback"):
            LocalTelemtExecutor(unsafe, "Bearer x")


async def test_owner_fleet_api_queues_typed_command(client, login_user):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    created = await client.post(
        "/api/fleet/nodes",
        json={"node_id": "edge-01", "display_name": "Edge 01", "inventory": {"telemt_version": "3.4.25"}},
        headers={"X-CSRF-Token": csrf},
    )
    assert created.status_code == 201
    queued = await client.post(
        "/api/fleet/nodes/edge-01/commands",
        json={
            "idempotency_key": "disable-alice-2026-08-14",
            "operation": "telemt.user.disable",
            "expected_telemt_revision": "rev-7",
            "payload": {"username": "alice"},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert queued.status_code == 201
    body = queued.json()
    assert body["sequence"] == 1 and body["status"] == "queued"
    listing = (await client.get("/api/fleet/nodes/edge-01/commands")).json()["items"]
    assert listing[0]["idempotency_key"] == "disable-alice-2026-08-14"


@pytest.mark.parametrize(
    "operation",
    [
        "mieru.inspect",
        "mieru.metrics",
        "mieru.lifecycle.start",
        "mieru.lifecycle.stop",
        "mieru.lifecycle.restart",
    ],
)
async def test_public_fleet_schema_accepts_advertised_secret_free_mieru_commands(
    client, login_user, operation
):
    await login_user(client)
    csrf = client.cookies["panel_csrf"]
    assert (
        await client.post(
            "/api/fleet/nodes",
            json={"node_id": "edge-01", "display_name": "Edge", "inventory": {}},
            headers={"X-CSRF-Token": csrf},
        )
    ).status_code == 201
    response = await client.post(
        "/api/fleet/nodes/edge-01/commands",
        json={
            "idempotency_key": f"mieru-{operation.replace('.', '-')}",
            "operation": operation,
            "expected_telemt_revision": "mrev-1",
            "payload": {},
        },
        headers={"X-CSRF-Token": csrf},
    )
    assert response.status_code == 201, response.text



async def test_viewer_can_read_fleet_but_cannot_register_or_queue(client, login_user):
    store = client._transport.app.state.store
    fleet = client._transport.app.state.fleet
    fleet.register_node("edge-01", "Edge", {"telemt_version": "3.4.25"})
    fleet.enqueue("edge-01", "viewer-redaction", "telemt.user.disable", {"username": "alice"}, "r")
    store.create_admin("viewer", "viewer password long enough", "viewer")
    await login_user(client, "viewer", "viewer password long enough")
    csrf = client.cookies["panel_csrf"]
    assert (await client.get("/api/fleet/nodes")).status_code == 200
    visible = (await client.get("/api/fleet/nodes/edge-01/commands")).json()["items"][0]
    assert "payload" not in visible and "idempotency_key" not in visible and "expected_telemt_revision" not in visible
    assert (await client.post("/api/fleet/nodes/edge-01/commands", json={
        "idempotency_key": "x-valid-key", "operation": "telemt.user.disable",
        "expected_telemt_revision": "r", "payload": {"username": "alice"},
    }, headers={"X-CSRF-Token": csrf})).status_code == 403
