from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
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
    rotated = log.with_name("access-2026-08-14T15-00-00.000-size.json")
    os.rename(log, rotated)
    log.write_text(record(upload=3, download=4))
    assert traffic.collect() == 1
    assert traffic.collect() == 0
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 10


@pytest.mark.parametrize("rotate_after_scan", [False, True])
def test_rotation_at_prune_identity_rescan_boundary_is_not_replayed(
    tmp_path, monkeypatch, rotate_after_scan,
):
    """A stale discovery path must never decide whether an inode is still present."""
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=1, download=2))
    rotated = log.with_name("access-2026-08-14T15-00-00.000-size.json")
    real_present_identities = traffic._present_identities

    def rotate():
        os.rename(log, rotated)
        log.write_text("")

    def rotate_at_boundary():
        if not rotate_after_scan:
            rotate()
        present = real_present_identities()
        if rotate_after_scan:
            rotate()
        return present

    monkeypatch.setattr(traffic, "_present_identities", rotate_at_boundary)

    assert traffic.collect() == 1
    monkeypatch.setattr(traffic, "_present_identities", real_present_identities)
    assert traffic.collect() == 0
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 3


def test_new_active_created_after_discovery_is_deferred_to_next_pass(tmp_path, monkeypatch):
    """A stale active pathname must not open a replacement inode in the same pass."""
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=1, download=2))
    rotated = log.with_name("access-2026-08-14T15-00-00.000-size.json")
    real_collect_file = traffic._collect_file
    rotated_once = False

    def rotate_before_open(candidate, users, read_budget, verify_budget):
        nonlocal rotated_once
        if not rotated_once:
            rotated_once = True
            os.rename(log, rotated)
            log.write_text(record(upload=3, download=4))
        return real_collect_file(candidate, users, read_budget, verify_budget)

    monkeypatch.setattr(traffic, "_collect_file", rotate_before_open)

    with pytest.raises(RuntimeError, match="changed during discovery"):
        traffic.collect()
    monkeypatch.setattr(traffic, "_collect_file", real_collect_file)
    assert traffic.collect() == 2
    assert traffic.collect() == 0
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 10


def test_timberjack_rotation_names_are_processed_oldest_first_and_unrelated_files_ignored(tmp_path):
    """Catch matching access.json.* instead of Caddy 2.11 timberjack backup names."""
    traffic, log = collector(tmp_path)
    older = log.with_name("access-2026-08-14T15-00-00.000-size.json")
    newer = log.with_name("access-2026-08-14T15-00-01.123-rotate.json")
    older.write_text(record(upload=1, download=2))
    newer.write_text(record(upload=3, download=4))
    log.write_text(record(upload=5, download=6))
    log.with_name("access.json.1").write_text(record(upload=100, download=100))
    log.with_name("access-2026-08-14T15-00-01.12-size.json").write_text(record(upload=100, download=100))
    log.with_name("other-2026-08-14T15-00-01.123-size.json").write_text(record(upload=100, download=100))

    assert traffic.collect() == 3
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 21


def test_matching_timberjack_rotation_symlink_fails_closed(tmp_path):
    """Catch candidate enumeration following a matching attacker-controlled symlink."""
    traffic, log = collector(tmp_path)
    target = tmp_path / "outside.json"
    target.write_text(record(upload=10, download=20))
    log.with_name("access-2026-08-14T15-00-00.000-size.json").symlink_to(target)

    with pytest.raises(RuntimeError, match="unavailable or unsafe"):
        traffic.collect()


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


def test_same_inode_middle_rewrite_with_identical_sampled_ends_fails_closed(tmp_path):
    """Catch first/last sampling accepting a rewrite wholly inside the consumed prefix."""
    traffic, log = collector(tmp_path)
    first = record(upload=1, download=2, padding="a" * 5000 + "X" * 100 + "z" * 5000)
    replacement = record(upload=1, download=2, padding="a" * 5000 + "Y" * 100 + "z" * 5000)
    assert len(first) == len(replacement) > 8192
    assert first[:4096] == replacement[:4096]
    assert first[-4096:] == replacement[-4096:]
    log.write_text(first)
    assert traffic.collect() == 1

    log.write_text(replacement)

    with pytest.raises(RuntimeError, match="rename-only"):
        traffic.collect()
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 3


def test_consumed_prefix_larger_than_request_budget_fails_closed(tmp_path):
    """Catch silently sampling an old prefix that cannot be verified within bounded work."""
    log = tmp_path / "logs" / "access.json"
    log.parent.mkdir()
    log.write_text(record(padding="x" * 300))
    traffic = TrafficCollector(
        log, tmp_path / "traffic.sqlite3", lambda: {"alice"},
        max_line_bytes=512, max_read_bytes=600, max_verify_bytes=300,
    )
    assert traffic.collect() == 1
    with log.open("a") as stream:
        stream.write(record(upload=1, download=2, padding="y" * 300))

    with pytest.raises(RuntimeError, match="verification budget"):
        traffic.collect()
    assert traffic.health()["ready"] is False


def test_prefix_verification_budget_is_shared_across_all_candidates(tmp_path, monkeypatch):
    """Two retained files must not each receive the full request verification budget."""
    log = tmp_path / "logs" / "access.json"
    log.parent.mkdir()
    rotated = log.with_name("access-2026-08-14T15-00-00.000-size.json")
    line = record(upload=1, download=2).rstrip("\n") + " " * 10 + "\n"
    assert len(line.encode()) == 98
    rotated.write_text(line)
    log.write_text(line)
    traffic = TrafficCollector(
        log, tmp_path / "traffic.sqlite3", lambda: {"alice"},
        max_line_bytes=128, max_read_bytes=512, max_verify_bytes=98,
    )
    assert traffic.collect() == 2
    verified = []
    real_hash_prefix = traffic._hash_prefix

    def recording_hash_prefix(fd, length):
        verified.append(length)
        return real_hash_prefix(fd, length)

    monkeypatch.setattr(traffic, "_hash_prefix", recording_hash_prefix)

    with pytest.raises(RuntimeError, match="verification budget"):
        traffic.collect()
    assert verified == [98]
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 6


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


def test_managed_invaliduser_counts_while_exact_redaction_sentinel_is_rejected(tmp_path):
    """Catch broad startswith('invalid') filtering valid manager usernames."""
    traffic, log = collector(tmp_path, users=lambda: {"invaliduser", "invalid"})
    log.write_text(record(user="invaliduser", upload=5, download=7) + record(user="invalid"))

    assert traffic.collect() == 1
    assert traffic.list_traffic()["users"][0]["username"] == "invaliduser"
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 12


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
        log.with_name(f"access-2026-08-14T15-00-0{index}.000-size.json").write_text(
            record(upload=1, download=1)
        )
    traffic = TrafficCollector(
        log, tmp_path / "traffic.sqlite3", lambda: {"alice"}, max_rotations=2,
    )

    with pytest.raises(RuntimeError, match="rotation limit"):
        traffic.collect()


def test_safely_consumed_deleted_rotation_state_is_pruned(tmp_path):
    traffic, log = collector(tmp_path)
    log.write_text(record(upload=1, download=2))
    traffic.collect()
    rotated = log.with_name("access-2026-08-14T15-00-00.000-size.json")
    os.rename(log, rotated)
    log.write_text(record(upload=3, download=4))
    traffic.collect()
    rotated.unlink()

    traffic.collect()

    with sqlite3.connect(tmp_path / "traffic.sqlite3") as database:
        assert database.execute("SELECT COUNT(*) FROM traffic_files").fetchone()[0] == 1


def test_deleted_partially_consumed_rotation_is_tombstoned_as_persistent_accounting_loss(tmp_path):
    """Catch retaining an absent partial inode forever while reporting accounting as healthy."""
    traffic, log = collector(tmp_path)
    rotated = log.with_name("access-2026-08-14T15-00-00.000-size.json")
    rotated.write_text(record(upload=1, download=2) + record(upload=3, download=4).rstrip("\n"))
    assert traffic.collect() == 1
    rotated.unlink()

    with pytest.raises(RuntimeError, match="accounting loss"):
        traffic.collect()

    assert traffic.health()["ready"] is False
    for operation in (traffic.list_traffic, lambda: traffic.reset("alice"), lambda: traffic.archive_user("alice")):
        with pytest.raises(RuntimeError, match="accounting loss"):
            operation()
    with sqlite3.connect(tmp_path / "traffic.sqlite3") as database:
        assert database.execute("SELECT COUNT(*) FROM traffic_files").fetchone()[0] == 1
        assert database.execute("SELECT error FROM accounting_state WHERE singleton=1").fetchone() == (
            "accounting_loss",
        )


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


def test_panel_naive_overview_sums_decimal_strings_exactly_above_javascript_safe_integer():
    """Catch routing exact decimal accounting through JavaScript Number during aggregation."""
    script = """
const fs = require('fs'), vm = require('vm');
const sandbox = {
  document: {cookie: '', querySelector: () => null, querySelectorAll: () => []},
  location: {protocol: 'https:'}, setTimeout: () => {}, console
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync('panel/static/app.js', 'utf8'), sandbox);
console.log(String(sandbox.sumNaiveTraffic([
  {total_bytes_decimal: '9007199254740993'},
  {total_bytes_decimal: '7'}
])));
"""
    result = subprocess.run(["node", "-e", script], check=True, capture_output=True, text=True)

    assert result.stdout.strip() == "9007199254741000"
