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


def test_metrics_are_secret_free_rolling_and_reset_is_panel_baseline(tmp_path):
    mita = FakeMita()
    service = manager(tmp_path, mita)
    service.bootstrap()
    mita.metrics_value = {
        "users": [
            {
                "name": "alice",
                "uploadBytes": 100,
                "downloadBytes": 900,
                "collectedAt": 2_000_000,
            }
        ]
    }
    first = service.metrics()
    assert first["users"][0] == {
        "username": "alice",
        "upload_bytes": 100,
        "download_bytes": 900,
        "application_bytes": 1000,
        "stale": False,
    }
    service.reset_metric_baseline("alice")
    assert service.metrics()["users"][0]["application_bytes"] == 0
    assert not (tmp_path / "state" / "metrics.pb").exists()


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
    print('RUNNING' if running.exists() else 'STOPPED')
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
    backup.write_text(json.dumps(BASE))
    backup.chmod(0o600)
    changed = {**BASE, "loggingLevel": "DEBUG"}
    live_config.write_text(json.dumps(changed))
    journal = tmp_path / "manager/journal.json"
    journal.write_text(
        json.dumps({"version": 1, "phase": "applied", "backup": backup.name})
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
