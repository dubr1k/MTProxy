from __future__ import annotations

import json
import os
import sqlite3
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
        "upload_bytes_decimal": "12345", "download_bytes_decimal": "12345",
        "total_bytes_decimal": "24690",
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


def test_rename_rotation_is_processed_once(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=1, download=2))
    assert traffic.collect() == 1
    rotated = log.with_name("access.json.1")
    os.rename(log, rotated)
    log.write_text(record(upload=3, download=4))
    assert traffic.collect() == 1
    assert traffic.collect() == 0
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 10


def test_same_size_same_tail_copytruncate_fails_closed(tmp_path):
    traffic, log = collector(tmp_path)
    first = record(upload=1, download=2, padding="x" * 160)
    replacement = record(upload=7, download=8, padding="x" * 160)
    assert len(first) == len(replacement)
    assert first[-64:] == replacement[-64:]
    log.write_text(first)
    assert traffic.collect() == 1

    log.write_text(replacement)
    # Prove the decision is based on persisted content, not mutable metadata.
    current = log.stat()
    with sqlite3.connect(tmp_path / "traffic.sqlite3") as database:
        database.execute(
            "UPDATE traffic_files SET observed_mtime_ns=?,observed_ctime_ns=?",
            (current.st_mtime_ns, current.st_ctime_ns),
        )

    with pytest.raises(RuntimeError, match="rename-only"):
        traffic.collect()
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 3


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
        "upload_bytes_decimal": "2", "download_bytes_decimal": "3",
        "total_bytes_decimal": "5",
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


def test_log_and_database_parent_symlinks_are_rejected(tmp_path):
    real_logs = tmp_path / "real-logs"
    real_logs.mkdir()
    (real_logs / "access.json").write_text("")
    linked_logs = tmp_path / "linked-logs"
    linked_logs.symlink_to(real_logs, target_is_directory=True)
    with pytest.raises(RuntimeError, match="unsafe"):
        TrafficCollector(
            linked_logs / "access.json", tmp_path / "traffic.sqlite3", lambda: {"alice"},
        )

    safe_logs = tmp_path / "safe-logs"
    safe_logs.mkdir()
    (safe_logs / "access.json").write_text("")
    real_data = tmp_path / "real-data"
    real_data.mkdir()
    linked_data = tmp_path / "linked-data"
    linked_data.symlink_to(real_data, target_is_directory=True)
    with pytest.raises(RuntimeError, match="unsafe"):
        TrafficCollector(
            safe_logs / "access.json", linked_data / "traffic.sqlite3", lambda: {"alice"},
        )


def test_counter_overflow_is_quarantined_without_wrapping_or_replay(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=2**63 - 1, download=0))
    assert traffic.collect() == 1
    with log.open("a") as stream:
        stream.write(record(upload=0, download=1))
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


def test_rotation_candidates_are_bounded_before_collection(tmp_path):
    log = tmp_path / "logs" / "access.json"
    log.parent.mkdir()
    log.write_text("")
    for index in range(3):
        log.with_name(f"access.json.{index}").write_text(record(upload=1, download=1))
    traffic = TrafficCollector(
        log, tmp_path / "traffic.sqlite3", lambda: {"alice"}, max_rotations=2,
    )

    with pytest.raises(RuntimeError, match="rotation limit"):
        traffic.collect()


def test_safely_consumed_deleted_rotation_state_is_pruned(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=1, download=2))
    traffic.collect()
    rotated = log.with_name("access.json.1")
    os.rename(log, rotated)
    log.write_text(record(upload=3, download=4))
    traffic.collect()
    rotated.unlink()

    traffic.collect()

    with sqlite3.connect(tmp_path / "traffic.sqlite3") as database:
        assert database.execute("SELECT COUNT(*) FROM traffic_files").fetchone()[0] == 1


def test_archiving_deleted_user_removes_live_counter_without_losing_history(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=11, download=13))
    assert traffic.collect() == 1

    traffic.archive_user("alice")

    assert traffic.list_traffic()["users"] == []
    with sqlite3.connect(tmp_path / "traffic.sqlite3") as database:
        assert database.execute(
            "SELECT username,upload_bytes,download_bytes FROM traffic_archives"
        ).fetchall() == [("alice", 11, 13)]


def test_aggregate_counter_never_exceeds_signed_sqlite_integer(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record(user="alice", upload=2**63 - 2, download=0))
    assert traffic.collect() == 1
    with log.open("a") as stream:
        stream.write(record(user="bob", upload=2, download=0))

    assert traffic.collect() == 0
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 2**63 - 2


def test_counter_contract_includes_exact_decimal_strings(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=2**53 + 1, download=2))
    traffic.collect()

    body = traffic.list_traffic()

    assert body["users"][0]["upload_bytes_decimal"] == "9007199254740993"
    assert body["users"][0]["total_bytes_decimal"] == "9007199254740995"
    assert body["aggregate"]["total_bytes_decimal"] == "9007199254740995"
