from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from naive_manager.traffic import TrafficCollector


def record(user="alice", upload=12345, download=12345, **overrides):
    value = {
        "request": {"method": "CONNECT"},
        "status": 200,
        "user_id": user,
        "bytes_read": upload,
        "size": download,
    }
    value.update(overrides)
    return json.dumps(value, separators=(",", ":")) + "\n"


def collector(tmp_path: Path, users=lambda: {"alice", "bob"}):
    log = tmp_path / "logs" / "access.json"
    log.parent.mkdir()
    log.touch(mode=0o600)
    return TrafficCollector(log, tmp_path / "traffic.sqlite3", users), log


def test_exact_connect_directions_are_durable_and_idempotent(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record())

    assert traffic.collect() == 1
    assert traffic.list_traffic()["users"][0] | {"period_start": "x", "updated_at": "x"} == {
        "username": "alice", "upload_bytes": 12345, "download_bytes": 12345,
        "total_bytes": 24690, "period_start": "x", "updated_at": "x",
    }
    assert traffic.collect() == 0
    traffic.close()

    restarted = TrafficCollector(log, tmp_path / "traffic.sqlite3", lambda: {"alice", "bob"})
    assert restarted.collect() == 0
    assert restarted.list_traffic()["aggregate"]["total_bytes"] == 24690


def test_partial_lines_wait_for_completion(tmp_path):
    traffic, log = collector(tmp_path)
    line = record(upload=7, download=9)
    log.write_text(line[:-1])
    assert traffic.collect() == 0
    assert traffic.list_traffic()["pending"] is True
    with log.open("a") as stream:
        stream.write("\n")
    assert traffic.collect() == 1
    assert traffic.list_traffic()["users"][0]["total_bytes"] == 16


def test_record_larger_than_read_budget_is_durably_quarantined_then_progresses(tmp_path):
    log = tmp_path / "logs" / "access.json"
    log.parent.mkdir()
    log.touch(mode=0o600)
    traffic = TrafficCollector(
        log,
        tmp_path / "traffic.sqlite3",
        lambda: {"alice"},
        max_line_bytes=128,
        max_read_bytes=160,
    )
    log.write_bytes(b"x" * 200 + b"\n" + record(upload=7, download=9).encode())

    assert traffic.collect() == 0
    assert traffic.list_traffic()["pending"] is True
    traffic.close()

    restarted = TrafficCollector(
        log,
        tmp_path / "traffic.sqlite3",
        lambda: {"alice"},
        max_line_bytes=128,
        max_read_bytes=160,
    )
    accepted = [restarted.collect() for _ in range(4)]
    assert sum(accepted) == 1
    assert restarted.list_traffic()["aggregate"]["total_bytes"] == 16
    assert restarted.collect() == 0
    assert restarted.list_traffic()["aggregate"]["total_bytes"] == 16
    assert restarted.list_traffic()["pending"] is False


def test_rotation_and_copytruncate_are_processed_once(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=1, download=2))
    assert traffic.collect() == 1
    rotated = log.with_name("access.json.1")
    os.rename(log, rotated)
    log.write_text(record(upload=3, download=4))
    assert traffic.collect() == 1
    assert traffic.collect() == 0
    log.write_text(record(upload=5, download=6))  # copytruncate
    assert traffic.collect() == 1
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 21


def test_strict_filtering_rejects_unknown_sentinels_bad_schema_and_oversize(tmp_path):
    traffic, log = collector(tmp_path)
    invalid = [
        record(user="mallory"), record(user="invalidbase64:secret"),
        record(user="invalid:secret"), record(user="invalidformat:c2VjcmV0"),
        record(user="invalid::"),
        record(status=407), record(**{"request": {"method": "GET"}}),
        record(upload=True), record(download=-1),
        json.dumps({"request": {"method": "CONNECT"}, "status": 200, "user_id": "alice", "bytes_read": 1}) + "\n",
        "not-json\n", "x" * (traffic.max_line_bytes + 1) + "\n",
        record(upload=2, download=3),
    ]
    log.write_text("".join(invalid))
    assert traffic.collect() == 1
    assert traffic.list_traffic()["aggregate"] == {
        "upload_bytes": 2, "download_bytes": 3, "total_bytes": 5,
    }


def test_reset_changes_only_local_baseline_and_is_transactional(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=10, download=20))
    traffic.collect()
    before = traffic.list_traffic()["users"][0]["period_start"]
    reset = traffic.reset("alice")
    assert reset["username"] == "alice"
    assert reset["total_bytes"] == 0
    assert reset["period_start"] >= before
    with log.open("a") as stream:
        stream.write(record(upload=1, download=2))
    traffic.collect()
    assert traffic.list_traffic()["users"][0]["total_bytes"] == 3
    with pytest.raises(KeyError):
        traffic.reset("unknown")


def test_missing_active_log_and_unsafe_files_fail_health(tmp_path):
    traffic, log = collector(tmp_path)
    assert traffic.health()["ready"] is True
    log.unlink()
    assert traffic.health()["ready"] is False
    with pytest.raises(RuntimeError):
        traffic.collect()

    target = tmp_path / "target"
    target.write_text("")
    log.symlink_to(target)
    assert traffic.health()["ready"] is False
    with pytest.raises(RuntimeError):
        traffic.collect()


def test_database_and_wal_are_private_and_database_symlinks_are_rejected(tmp_path):
    traffic, _log = collector(tmp_path)
    database = tmp_path / "traffic.sqlite3"
    assert stat.S_IMODE(database.stat().st_mode) == 0o600
    for suffix in ("-wal", "-shm"):
        sidecar = Path(str(database) + suffix)
        if sidecar.exists():
            assert stat.S_IMODE(sidecar.stat().st_mode) == 0o600
    traffic.close()

    unsafe_log = tmp_path / "other" / "access.json"
    unsafe_log.parent.mkdir()
    unsafe_log.touch(mode=0o600)
    target = tmp_path / "database-target"
    target.touch()
    unsafe_database = tmp_path / "unsafe.sqlite3"
    unsafe_database.symlink_to(target)
    with pytest.raises(RuntimeError, match="database is unsafe"):
        TrafficCollector(unsafe_log, unsafe_database, lambda: {"alice"})


def test_counter_overflow_is_quarantined_without_wrapping_or_replay(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=2**63 - 1, download=0))
    assert traffic.collect() == 1
    with log.open("a") as stream:
        stream.write(record(upload=1, download=0))
    assert traffic.collect() == 0
    assert traffic.collect() == 0
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 2**63 - 1


def test_contract_is_secret_free_and_documents_accounting_limits(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record())
    traffic.collect()
    body = traffic.list_traffic()
    assert body["source"] == "caddy_connect_access_log"
    assert body["unit"] == "bytes"
    assert body["directions"] == {
        "upload_bytes": "client_to_proxy", "download_bytes": "proxy_to_client"
    }
    assert body["semantics"]["closed_connect_tunnels_only"] is True
    assert body["semantics"]["active_tunnels_appear_on_close"] is True
    assert body["semantics"]["crash_can_lose_active_tunnel"] is True
    assert body["semantics"]["completed_records_survive_restart"] is True
    assert body["semantics"]["excludes_tls_ip_overhead"] is True
    assert body["semantics"]["reset_is_local_baseline_only"] is True
    assert "password" not in json.dumps(body).lower()
