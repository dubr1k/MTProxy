from __future__ import annotations

import hashlib
import json

import pytest

from mieru_manager.service import (
    ConfigConflict,
    MieruManager,
    MitaCLI,
    ValidationError,
    validate_config,
)


BASE = {
    "portBindings": [{"port": 8443, "protocol": "TCP"}],
    "users": [{"name": "alice", "hashedPassword": "a" * 64}],
    "loggingLevel": "INFO",
    "mtu": 1400,
}


def _status_cli(tmp_path, output):
    fake = tmp_path / "mita-status"
    fake.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n")
    fake.chmod(0o755)
    return MitaCLI(executable=fake)


@pytest.mark.parametrize("status", ["RUNNING", "STOPPED", "UNKNOWN"])
def test_cli_parses_official_exact_status_grammar(tmp_path, status):
    assert _status_cli(tmp_path, f'mita server status is "{status}"').status() == status


@pytest.mark.parametrize(
    "output",
    [
        "RUNNING",
        'mita server status is "IDLE"',
        'mita server status is "RUNNING" trailing',
        'prefix mita server status is "RUNNING"',
        'mita server status is "RUNNING"\nmita server status is "STOPPED"',
    ],
)
def test_cli_rejects_ambiguous_or_noncanonical_status(tmp_path, output):
    with pytest.raises(Exception, match="invalid status"):
        _status_cli(tmp_path, output).status()


def test_validation_rejects_overlapping_ports_and_unknown_fields():
    with pytest.raises(ValidationError, match="overlap"):
        validate_config(
            {
                **BASE,
                "portBindings": [
                    {"portRange": "8000-8010", "protocol": "TCP"},
                    {"port": 8005, "protocol": "TCP"},
                ],
            }
        )
    with pytest.raises(ValidationError, match="unknown"):
        validate_config({**BASE, "futureDangerousField": True})


def test_validation_traffic_pattern_matches_mita_v335_schema():
    valid = {
        **BASE,
        "trafficPattern": {
            "seed": 42,
            "unlockAll": True,
            "tcpFragment": {"enable": True, "maxSleepMs": 100},
            "nonce": {
                "type": "NONCE_TYPE_PRINTABLE_SUBSET",
                "applyToAllUDPPacket": True,
                "minLen": 0,
                "maxLen": 12,
            },
            "padding": {"maxMiddlePaddingLen": 0, "maxEndPaddingLen": 255},
            "lowEntropy": {
                "mode": "LOW_ENTROPY_MODE_56",
                "maskRotation": "LOW_ENTROPY_MASK_ROTATE_LEFT_15",
            },
        },
    }
    assert validate_config(valid) is valid

    invalid_patterns = [
        {"seed": "42"},
        {"tcpFragment": {"maxSleepMs": 101}},
        {"nonce": {"type": "RANDOM"}},
        {"nonce": {"type": "NONCE_TYPE_FIXED", "customHexStrings": ["00" * 13]}},
        {"padding": {"maxEndPaddingLen": 256}},
        {"lowEntropy": {"mode": "LOW_ENTROPY_56"}},
        {"lowEntropy": {"maskRotation": 7}},
    ]
    for traffic_pattern in invalid_patterns:
        with pytest.raises(ValidationError):
            validate_config({**BASE, "trafficPattern": traffic_pattern})


def test_validation_enforces_user_quota_mtu_dns_and_privileged_flags():
    bad = json.loads(json.dumps(BASE))
    bad["users"] = [{"name": "é" * 33, "hashedPassword": "a" * 64}]
    with pytest.raises(ValidationError, match="64 bytes"):
        validate_config(bad)
    with pytest.raises(ValidationError, match="quota"):
        validate_config(
            {
                **BASE,
                "users": [
                    {
                        "name": "a",
                        "hashedPassword": "a" * 64,
                        "quotas": [{"days": 0, "megabytes": 1}],
                    }
                ],
            }
        )
    with pytest.raises(ValidationError, match="MTU"):
        validate_config({**BASE, "mtu": 1501})
    with pytest.raises(ValidationError, match="DNS"):
        validate_config(
            {
                **BASE,
                "dns": {"dualStack": "ONLY_IPv4", "hosts": {"bad host": "127.0.0.1"}},
            }
        )
    with pytest.raises(ValidationError, match="elevated"):
        validate_config(
            {
                **BASE,
                "users": [
                    {"name": "a", "hashedPassword": "a" * 64, "allowLoopbackIP": True}
                ],
            }
        )
    validate_config(
        {
            **BASE,
            "users": [
                {"name": "a", "hashedPassword": "a" * 64, "allowLoopbackIP": True}
            ],
        },
        elevated=True,
    )


@pytest.mark.parametrize(
    "interval",
    ["1ms", "999ms", "0.999999999s", "1 s", "1d", "2562047h47m16.854775808s"],
)
def test_validation_rejects_metrics_intervals_outside_go_duration_contract(interval):
    with pytest.raises(ValidationError, match="metrics interval"):
        validate_config({**BASE, "advancedSettings": {"metricsLoggingInterval": interval}})


@pytest.mark.parametrize("interval", ["1s", "1000ms", "1.5s", "1m30s", "+2s"])
def test_validation_accepts_go_durations_at_least_one_second(interval):
    validate_config({**BASE, "advancedSettings": {"metricsLoggingInterval": interval}})


def test_validation_matches_egress_proxy_action_and_proto_int32_bounds():
    proxy = {
        "name": "out",
        "protocol": "SOCKS5_PROXY_PROTOCOL",
        "host": "127.0.0.1",
        "port": 1080,
    }
    with pytest.raises(ValidationError, match="proxy name"):
        validate_config(
            {**BASE, "egress": {"proxies": [proxy], "rules": [{"action": "PROXY"}]}}
        )
    with pytest.raises(ValidationError, match="non-PROXY"):
        validate_config(
            {
                **BASE,
                "egress": {
                    "proxies": [proxy],
                    "rules": [{"action": "DIRECT", "proxyNames": ["out"]}],
                },
            }
        )
    validate_config(
        {
            **BASE,
            "users": [
                {
                    "name": "alice",
                    "hashedPassword": "a" * 64,
                    "quotas": [{"days": 2**31 - 1, "megabytes": 2**31 - 1}],
                }
            ],
        }
    )


class FakeMita:
    def __init__(self, config=None):
        self.config = json.loads(json.dumps(config or BASE))
        self.calls = []
        self.fail_probe = False
        self.metrics_value = {"users": []}
        self.running = True

    def version(self):
        return "3.35.0"

    def observe(self):
        return json.loads(json.dumps(self.config))

    def apply(self, config):
        self.calls.append(("apply", json.loads(json.dumps(config))))
        self.config = self._persist(config)

    def reload(self):
        self.calls.append(("reload",))

    def stop(self):
        self.calls.append(("stop",))
        self.running = False

    def start(self):
        self.calls.append(("start",))
        self.running = True

    def status(self):
        return "RUNNING" if self.running else "STOPPED"

    def probe(self):
        self.calls.append(("probe",))
        if self.fail_probe:
            self.fail_probe = False
            raise RuntimeError("probe secret must not escape")

    def metrics(self):
        return self.metrics_value

    @staticmethod
    def _persist(config):
        value = json.loads(json.dumps(config))
        for user in value.get("users", []):
            if "password" in user:
                raw = user.pop("password")
                user["hashedPassword"] = hashlib.sha256(
                    (raw + "\0" + user["name"]).encode()
                ).hexdigest()
        return value


def manager(tmp_path, mita=None):
    return MieruManager(
        mita=mita or FakeMita(),
        state_dir=tmp_path / "state",
        public_host="proxy.example.com",
    )


def test_lifecycle_revalidates_readback_and_probes_running_service(tmp_path):
    mita = FakeMita()
    service = manager(tmp_path, mita)
    revision = service.bootstrap()["revision"]
    mita.calls.clear()

    stopped = service.lifecycle("stop")
    assert stopped == {"ready": False, "status": "stopped", "revision": revision}
    assert mita.calls == [("stop",)]

    mita.calls.clear()
    started = service.lifecycle("start")
    assert started == {"ready": True, "status": "running", "revision": revision}
    assert mita.calls == [("start",), ("probe",)]

    mita.calls.clear()
    restarted = service.lifecycle("restart")
    assert restarted["ready"] is True
    assert mita.calls == [("stop",), ("start",), ("probe",)]
    with pytest.raises(ValidationError, match="lifecycle"):
        service.lifecycle("reload")


def test_create_uses_complete_snapshot_cas_and_reveals_password_once(tmp_path):
    mita = FakeMita()
    service = manager(tmp_path, mita)
    initial = service.bootstrap()["revision"]

    result = service.create_user(
        "bob", [{"days": 30, "megabytes": 1024}], expected_revision=initial
    )

    assert result["share_url"].startswith("mierus://bob:")
    assert "@proxy.example.com?" in result["share_url"]
    assert mita.calls[0][0] == "apply"
    assert mita.calls[0][1]["portBindings"] == BASE["portBindings"]
    assert "password" in mita.calls[0][1]["users"][1]
    assert mita.calls[1:] == [("reload",), ("probe",)]
    assert "password" not in json.dumps(service.list_users())
    assert "hashedPassword" not in json.dumps(service.list_users())
    with pytest.raises(ConfigConflict, match="revision"):
        service.create_user("carol", [], expected_revision=initial)


def test_create_with_private_or_loopback_policy_forces_controlled_restart(tmp_path):
    for flag in ("allow_private_ip", "allow_loopback_ip"):
        mita = FakeMita()
        service = manager(tmp_path / flag, mita)
        revision = service.bootstrap()["revision"]
        mita.calls.clear()
        service.create_user(
            "bob", [], expected_revision=revision, elevated=True, **{flag: True}
        )
        assert mita.calls[-3:] == [("stop",), ("start",), ("probe",)]


def test_rotation_delete_and_disable_force_restart_and_tombstone_names(tmp_path):
    mita = FakeMita()
    service = manager(tmp_path, mita)
    revision = service.bootstrap()["revision"]
    revision = service.create_user("bob", [], expected_revision=revision)["revision"]
    mita.calls.clear()

    revision = service.disable_user("bob", expected_revision=revision)["revision"]
    assert mita.calls[-3:] == [("stop",), ("start",), ("probe",)]
    assert service.list_users()[1]["enabled"] is False
    mita.calls.clear()
    revision = service.enable_user("bob", expected_revision=revision)["revision"]
    assert mita.calls[-3:] == [("stop",), ("start",), ("probe",)]
    mita.calls.clear()
    rotated = service.rotate_user("bob", expected_revision=revision)
    assert rotated["share_url"].startswith("mierus://bob:")
    assert mita.calls[-3:] == [("stop",), ("start",), ("probe",)]
    mita.calls.clear()
    service.delete_user("bob", expected_revision=rotated["revision"])
    assert mita.calls[-3:] == [("stop",), ("start",), ("probe",)]
    with pytest.raises(ConfigConflict, match="reuse"):
        service.create_user("bob", [], expected_revision=service.inspect()["revision"])


def test_failed_probe_rolls_back_full_snapshot_and_restarts(tmp_path):
    mita = FakeMita()
    service = manager(tmp_path, mita)
    revision = service.bootstrap()["revision"]
    before = mita.observe()
    mita.fail_probe = True

    with pytest.raises(RuntimeError, match="transaction failed"):
        service.create_user("bob", [], expected_revision=revision)

    assert mita.observe() == before
    assert [call[0] for call in mita.calls].count("apply") == 2
    assert mita.calls[-3:] == [("stop",), ("start",), ("probe",)]
    assert (tmp_path / "state" / "journal.json").exists() is False


def _write_recovery_fixture(root, state, before, desired, *, generation=None):
    backup_dir = root / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / f"g{state['generation']}-{state['revision']}.json"
    backup_bytes = json.dumps(
        before, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode() + b"\n"
    backup.write_bytes(backup_bytes)
    backup.chmod(0o600)
    journal = {
        "version": 2,
        "schema": "mieru-transaction-journal-v2",
        "phase": "applied",
        "operation": "user.create",
        "mode": "reload",
        "previous_config_hash": hashlib.sha256(backup_bytes[:-1]).hexdigest(),
        "desired_config_hash": hashlib.sha256(
            json.dumps(desired, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "state_revision": state["revision"],
        "state_generation": state["generation"] if generation is None else generation,
        "next_revision": "f" * 64,
        "next_generation": (state["generation"] if generation is None else generation) + 1,
        "backup_basename": backup.name,
        "backup_size": len(backup_bytes),
        "backup_sha256": hashlib.sha256(backup_bytes).hexdigest(),
    }
    path = root / "journal.json"
    path.write_text(json.dumps(journal))
    path.chmod(0o600)
    return path, backup


def test_recovery_is_generation_bound_and_checks_observed_phase_before_side_effect(tmp_path):
    mita = FakeMita()
    service = manager(tmp_path, mita)
    service.bootstrap()
    root = tmp_path / "state"
    state = json.loads((root / "state.json").read_text())
    desired = {**BASE, "loggingLevel": "DEBUG"}
    mita.config = json.loads(json.dumps(desired))
    _write_recovery_fixture(root, state, BASE, desired)
    mita.calls.clear()

    recovered = manager(tmp_path, mita).bootstrap()
    assert recovered["ready"] is True
    assert mita.config == BASE
    assert mita.calls[:3] == [("apply", BASE), ("stop",), ("start",)]
    assert (root / "journal.json").exists() is False


def test_stale_or_tampered_recovery_journal_fails_closed_without_backup_apply(tmp_path):
    mita = FakeMita()
    service = manager(tmp_path, mita)
    service.bootstrap()
    root = tmp_path / "state"
    state = json.loads((root / "state.json").read_text())
    desired = {**BASE, "loggingLevel": "DEBUG"}
    mita.config = json.loads(json.dumps(desired))
    journal, _ = _write_recovery_fixture(
        root, state, BASE, desired, generation=state["generation"] + 1
    )
    mita.calls.clear()

    with pytest.raises(ConfigConflict, match="recovery"):
        manager(tmp_path, mita).bootstrap()
    assert mita.calls == []
    assert mita.config == desired
    assert journal.exists()


def test_per_user_metrics_fail_closed_when_typed_getusers_boundary_is_unavailable(tmp_path):
    mita = FakeMita()
    service = manager(tmp_path, mita)
    service.bootstrap()
    # Canonical v3.35 `mita get users` is a human table, not typed histories.
    mita.metrics_value = {
        "table": "User  LastActive  1DayDown  1DayUp  7DaysDown  7DaysUp  30DaysDown  30DaysUp\nalice  -  -  -  -  -  -  -"
    }
    assert service.metrics() == {
        "status": "error",
        "stale": True,
        "users": [],
        "capability": "unavailable",
        "reason": "mita v3.35 CLI does not expose typed GetUsers histories",
    }
    with pytest.raises(ConfigConflict, match="unavailable"):
        service.reset_metric_baseline("alice")
    assert not (tmp_path / "state" / "metrics.pb").exists()


def test_share_links_bracket_ipv6_and_reject_traffic_pattern_before_mutation(tmp_path):
    mita = FakeMita()
    service = MieruManager(
        mita=mita, state_dir=tmp_path / "ipv6", public_host="2001:db8::1"
    )
    revision = service.bootstrap()["revision"]
    created = service.create_user("bob", [], expected_revision=revision)
    assert "@[2001:db8::1]?" in created["share_url"]

    config = {**BASE, "trafficPattern": {"seed": 42}}
    mita = FakeMita(config)
    service = manager(tmp_path / "traffic", mita)
    revision = service.bootstrap()["revision"]
    mita.calls.clear()
    with pytest.raises(ValidationError, match="trafficPattern"):
        service.create_user("bob", [], expected_revision=revision)
    assert mita.calls == []


def test_fake_mita_process_covers_fd_lifecycle_rollback_recovery_and_secret_hygiene(
    tmp_path, monkeypatch
):
    fake = tmp_path / "mita"
    argv_log = tmp_path / "argv.jsonl"
    live_config = tmp_path / "live.json"
    running = tmp_path / "running"
    fail_reload = tmp_path / "fail-reload"
    live_config.write_text(json.dumps(BASE))
    running.write_text("yes")
    fake.write_text("""#!/usr/bin/python3
import hashlib, json, os, pathlib, sys
args = sys.argv[1:]
with open(os.environ['ARGV_LOG'], 'a') as stream:
    stream.write(json.dumps(args) + '\\n')
config = pathlib.Path(os.environ['LIVE_CONFIG'])
running = pathlib.Path(os.environ['RUNNING'])
if args == ['version']:
    print('mita 3.35.0')
elif args == ['describe', 'config']:
    print(config.read_text())
elif args[:2] == ['apply', 'config']:
    assert len(args) == 3 and args[2].startswith('/proc/self/fd/')
    value = json.load(open(args[2]))
    for user in value.get('users', []):
        if 'password' in user:
            raw = user.pop('password')
            user['hashedPassword'] = hashlib.sha256((raw + '\\0' + user['name']).encode()).hexdigest()
    config.write_text(json.dumps(value, sort_keys=True))
elif args == ['reload']:
    marker = pathlib.Path(os.environ['FAIL_RELOAD'])
    if marker.exists():
        marker.unlink()
        raise SystemExit(9)
elif args == ['stop']:
    running.unlink(missing_ok=True)
elif args == ['start']:
    running.write_text('yes')
elif args == ['status']:
    state = 'RUNNING' if running.exists() else 'STOPPED'
    print(f'mita server status is "{state}"')
elif args == ['get', 'metrics']:
    print('{"users": []}')
else:
    raise SystemExit(8)
""")
    fake.chmod(0o755)
    cli = MitaCLI(
        executable=fake,
        env={
            "ARGV_LOG": str(argv_log),
            "LIVE_CONFIG": str(live_config),
            "RUNNING": str(running),
            "FAIL_RELOAD": str(fail_reload),
        },
    )
    service = MieruManager(
        mita=cli, state_dir=tmp_path / "manager", public_host="proxy.example.com"
    )
    revision = service.bootstrap()["revision"]
    monkeypatch.setattr("mieru_manager.service.secrets.token_urlsafe", lambda _n: "raw-integration-secret")
    fail_reload.write_text("once")

    with pytest.raises(Exception, match="rolled back") as error:
        service.create_user("bob", [], expected_revision=revision)

    assert json.loads(live_config.read_text()) == BASE
    assert service.lifecycle("stop")["ready"] is False
    assert service.lifecycle("start")["ready"] is True
    assert service.lifecycle("restart")["ready"] is True

    state = json.loads((tmp_path / "manager/state.json").read_text())
    backup = tmp_path / "manager/backups" / f"{state['revision']}.json"
    backup.parent.mkdir(parents=True, exist_ok=True)
    backup_data = json.dumps(BASE, sort_keys=True, separators=(",", ":")).encode()
    backup.write_bytes(backup_data)
    backup.chmod(0o600)
    changed = {**BASE, "loggingLevel": "DEBUG"}
    changed_hash = hashlib.sha256(
        json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    live_config.write_text(json.dumps(changed))
    journal = tmp_path / "manager/journal.json"
    journal.write_text(
        json.dumps(
            {
                "version": 2,
                "schema": "mieru-transaction-journal-v2",
                "phase": "applied",
                "operation": "user.create",
                "mode": "reload",
                "previous_config_hash": state["config_hash"],
                "desired_config_hash": changed_hash,
                "state_revision": state["revision"],
                "state_generation": state["generation"],
                "next_revision": changed_hash,
                "next_generation": state["generation"] + 1,
                "backup_basename": backup.name,
                "backup_size": len(backup_data),
                "backup_sha256": hashlib.sha256(backup_data).hexdigest(),
            }
        )
    )
    journal.chmod(0o600)

    recovered = MieruManager(
        mita=cli, state_dir=tmp_path / "manager", public_host="proxy.example.com"
    ).bootstrap()
    assert recovered["ready"] is True
    assert json.loads(live_config.read_text()) == BASE
    assert journal.exists() is False

    persisted = "\n".join(
        path.read_text(errors="replace")
        for path in tmp_path.rglob("*")
        if path.is_file() and path != fake
    )
    assert "raw-integration-secret" not in persisted
    assert "raw-integration-secret" not in str(error.value)
    assert "/proc/self/fd/" in argv_log.read_text()


def test_cli_refuses_unpinned_or_changed_executable_before_launch(tmp_path):
    marker = tmp_path / "launched"
    fake = tmp_path / "mita"
    fake.write_text(
        "#!/bin/sh\nprintf launched > \"$MARKER\"\nprintf 'mita 3.35.0\\n'\n"
    )
    fake.chmod(0o755)
    digest = hashlib.sha256(fake.read_bytes()).hexdigest()
    assert MitaCLI(
        executable=fake,
        expected_sha256=digest,
        env={"MARKER": str(marker)},
    ).version() == "3.35.0"
    marker.unlink()

    with pytest.raises(Exception, match="digest") as error:
        MitaCLI(
            executable=fake,
            expected_sha256="0" * 64,
            env={"MARKER": str(marker)},
        ).version()
    assert marker.exists() is False
    assert digest not in str(error.value)


def test_cli_passes_complete_config_through_anonymous_fd_and_bounds_output(tmp_path):
    log = tmp_path / "argv.json"
    fake = tmp_path / "mita"
    fake.write_text("""#!/usr/bin/python3
import json, os, sys
with open(os.environ['ARGV_LOG'], 'a') as out: out.write(json.dumps(sys.argv[1:])+'\\n')
if sys.argv[1:] == ['version']: print('mita 3.35.0')
elif sys.argv[1:2] == ['apply']:
    assert sys.argv[2] == 'config' and sys.argv[3].startswith('/proc/self/fd/')
    json.load(open(sys.argv[3]))
elif sys.argv[1:] == ['describe', 'config']: print(json.dumps({'portBindings':[{'port':8443,'protocol':'TCP'}],'users':[]}))
elif sys.argv[1:] == ['status']: print('RUNNING')
elif sys.argv[1:] == ['get', 'metrics']: print(json.dumps({'users':[]}))
""")
    fake.chmod(0o755)
    cli = MitaCLI(
        executable=fake, env={"ARGV_LOG": str(log)}, timeout=2, max_output=4096
    )

    cli.apply(
        {
            "portBindings": [{"port": 8443, "protocol": "TCP"}],
            "users": [{"name": "alice", "password": "not-on-argv"}],
        }
    )

    lines = log.read_text()
    assert "not-on-argv" not in lines
    assert "/proc/self/fd/" in lines
    assert cli.observe()["portBindings"][0]["port"] == 8443


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_cli_kills_child_during_execution_when_either_output_stream_exceeds_cap(
    tmp_path, stream
):
    marker = tmp_path / "completed"
    fake = tmp_path / "mita-overflow"
    fake.write_text(
        "#!/usr/bin/python3\n"
        "import os, sys\n"
        f"out = sys.{stream}.buffer\n"
        "for _ in range(2048):\n"
        "    out.write(b'x' * 1024); out.flush()\n"
        "open(os.environ['MARKER'], 'w').write('child completed')\n"
    )
    fake.chmod(0o755)
    cli = MitaCLI(
        executable=fake,
        env={"MARKER": str(marker)},
        timeout=2,
        max_output=1024,
    )

    with pytest.raises(Exception, match="too large"):
        cli.version()
    assert marker.exists() is False
