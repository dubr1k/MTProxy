from __future__ import annotations

import json
import os
import stat
import threading
from pathlib import Path

import httpx
import pytest

from naive_manager.server import ManagerHTTPServer, caddy_adapt
from naive_manager.service import ManagerConflict, ManagerRecoveryError, NaiveCredentialManager


CADDY = """{
    admin 127.0.0.1:2019
}
:4443 {
    bind 127.0.0.1
    route {
        forward_proxy {
            basic_auth old-user old-password
            basic_auth second second-password
            hide_ip
            hide_via
            upstream socks5://127.0.0.1:40000
        }
        file_server { root /var/www/naive }
    }
}
"""


class Hooks:
    def __init__(self):
        self.validated = []
        self.reloads = 0
        self.probes = 0
        self.fail_reload_calls = set()
        self.fail_probe_times = 0
        self.caddyfile: Path | None = None
        self.reload_snapshots = []

    def validate(self, path: Path):
        self.validated.append(path.read_text())

    def reload(self):
        self.reloads += 1
        if self.caddyfile is not None:
            self.reload_snapshots.append(self.caddyfile.read_text())
        if self.reloads in self.fail_reload_calls:
            raise RuntimeError("reload failed")

    def probe(self):
        self.probes += 1
        if self.fail_probe_times:
            self.fail_probe_times -= 1
            raise RuntimeError("probe failed")


def manager(tmp_path: Path, hooks: Hooks) -> NaiveCredentialManager:
    caddy = tmp_path / "Caddyfile"
    if not caddy.exists():
        caddy.write_text(CADDY)
    hooks.caddyfile = caddy
    return NaiveCredentialManager(
        caddyfile=caddy,
        state_file=tmp_path / "state" / "users.json",
        backup_dir=tmp_path / "backups",
        public_host="naive.example.com",
        validate=hooks.validate,
        reload=hooks.reload,
        probe=hooks.probe,
    )


def test_bootstrap_imports_existing_credentials_without_changing_them(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)

    service.bootstrap()

    assert service.list_users() == [
        {"username": "old-user", "enabled": True},
        {"username": "second", "enabled": True},
    ]
    assert service.reveal("old-user")["proxy_url"] == "https://old-user:old-password@naive.example.com"
    rendered = service.caddyfile.read_text()
    assert "# BEGIN NAIVE-MANAGER USERS" in rendered
    assert "basic_auth old-user old-password" in rendered
    assert "upstream socks5://127.0.0.1:40000" in rendered
    assert stat.S_IMODE(service.caddyfile.stat().st_mode) == 0o600
    assert stat.S_IMODE(service.state_file.stat().st_mode) == 0o600
    state = json.loads(service.state_file.read_text())
    assert state["version"] == 1


def test_bootstrap_rejects_preexisting_managed_markers(tmp_path):
    hooks = Hooks()
    caddy = tmp_path / "Caddyfile"
    caddy.write_text(CADDY.replace(
        "            basic_auth old-user old-password",
        "            # BEGIN NAIVE-MANAGER USERS\n"
        "            basic_auth old-user old-password\n"
        "            # END NAIVE-MANAGER USERS",
    ))
    service = manager(tmp_path, hooks)

    with pytest.raises(ManagerConflict, match="managed credential markers already present"):
        service.bootstrap()

    assert not service.state_file.exists()


def test_bootstrap_recovers_after_crash_between_initial_config_and_state_writes(tmp_path, monkeypatch):
    """A first-import crash must not leave a nested or unrecoverable managed block."""
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    from naive_manager import service as service_module

    real_atomic_write = service_module._atomic_write

    class SimulatedCrash(BaseException):
        pass

    def crash_on_state(path, data, mode=0o600):
        if path == service.state_file:
            raise SimulatedCrash("process stopped between initial file writes")
        return real_atomic_write(path, data, mode)

    monkeypatch.setattr(service_module, "_atomic_write", crash_on_state)
    with pytest.raises(SimulatedCrash):
        service.bootstrap()

    monkeypatch.setattr(service_module, "_atomic_write", real_atomic_write)
    recovered = manager(tmp_path, hooks)
    recovered.bootstrap()

    assert recovered.caddyfile.read_text().count("# BEGIN NAIVE-MANAGER USERS") == 1
    assert recovered.list_users() == [
        {"username": "old-user", "enabled": True},
        {"username": "second", "enabled": True},
    ]
    assert not (recovered.state_file.parent / "transaction.json").exists()


def test_bootstrap_recovery_remembers_initial_import_after_recovery_crash(tmp_path, monkeypatch):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    from naive_manager import service as service_module

    real_atomic_write = service_module._atomic_write

    class SimulatedCrash(BaseException):
        pass

    def crash_on_state(path, data, mode=0o600):
        if path == service.state_file:
            raise SimulatedCrash("initial import interrupted")
        return real_atomic_write(path, data, mode)

    monkeypatch.setattr(service_module, "_atomic_write", crash_on_state)
    with pytest.raises(SimulatedCrash):
        service.bootstrap()

    failed_restore = False

    def fail_first_config_restore(path, data, mode=0o600):
        nonlocal failed_restore
        if path == service.caddyfile and not failed_restore:
            failed_restore = True
            raise OSError("recovery interrupted")
        return real_atomic_write(path, data, mode)

    monkeypatch.setattr(service_module, "_atomic_write", fail_first_config_restore)
    with pytest.raises(ManagerRecoveryError, match="transaction recovery failed"):
        manager(tmp_path, hooks).bootstrap()

    transaction = service.state_file.parent / "transaction.json"
    assert json.loads(transaction.read_text())["phase"] == "recovery_failed"

    monkeypatch.setattr(service_module, "_atomic_write", real_atomic_write)
    recovered = manager(tmp_path, hooks)
    recovered.bootstrap()

    assert recovered.caddyfile.read_text().count("# BEGIN NAIVE-MANAGER USERS") == 1
    assert len(recovered.list_users()) == 2
    assert not transaction.exists()


def test_create_disable_enable_rotate_and_delete_are_transactional(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()

    created = service.create("phone")
    assert created["proxy_url"].startswith("https://phone:")
    assert "basic_auth phone " in service.caddyfile.read_text()

    service.set_enabled("phone", False)
    assert "basic_auth phone " not in service.caddyfile.read_text()
    assert service.list_users()[-1] == {"username": "phone", "enabled": False}

    service.set_enabled("phone", True)
    before = service.reveal("phone")["proxy_url"]
    service.rotate("phone")
    assert service.reveal("phone")["proxy_url"] != before

    service.delete("phone")
    assert all(row["username"] != "phone" for row in service.list_users())
    assert hooks.reloads == 5
    assert hooks.probes == 5


def test_successful_mutation_persists_paired_backups_and_clears_journal(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    config_backups_before = len(list(service.backup_dir.glob("*.Caddyfile")))
    state_backups_before = len(list(service.backup_dir.glob("*.users.json")))

    service.create("phone")

    assert len(list(service.backup_dir.glob("*.Caddyfile"))) == config_backups_before + 1
    assert len(list(service.backup_dir.glob("*.users.json"))) == state_backups_before + 1
    assert not (service.state_file.parent / "transaction.json").exists()


def test_live_reload_occurs_only_after_journal_requires_backup_restore(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    phases = []

    def inspect_journal_then_reload():
        transaction = json.loads((service.state_file.parent / "transaction.json").read_text())
        phases.append(transaction["phase"])

    service.reload = inspect_journal_then_reload

    service.create("phone")

    assert phases == ["rollback_pending"]


def test_validated_caddyfile_replace_fsyncs_its_own_parent_directory(tmp_path, monkeypatch):
    hooks = Hooks()
    config_dir = tmp_path / "config"
    state_dir = tmp_path / "state"
    config_dir.mkdir()
    caddy = config_dir / "Caddyfile"
    caddy.write_text(CADDY)
    hooks.caddyfile = caddy
    service = NaiveCredentialManager(
        caddyfile=caddy,
        state_file=state_dir / "users.json",
        backup_dir=tmp_path / "backups",
        public_host="naive.example.com",
        validate=hooks.validate,
        reload=hooks.reload,
        probe=hooks.probe,
    )
    service.bootstrap()
    real_fsync = os.fsync
    synced_directories = set()

    def track_fsync(fd):
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            synced_directories.add((info.st_dev, info.st_ino))
        return real_fsync(fd)

    monkeypatch.setattr("naive_manager.service.os.fsync", track_fsync)

    service.create("phone")

    parent = config_dir.stat()
    assert (parent.st_dev, parent.st_ino) in synced_directories


def test_initial_backup_directory_is_durable_before_live_config_replace(tmp_path, monkeypatch):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    real_fsync = os.fsync
    real_replace = os.replace
    synced_directories = set()

    def track_fsync(fd):
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            synced_directories.add((info.st_dev, info.st_ino))
        return real_fsync(fd)

    def assert_parent_durable_before_replace(source, destination):
        if Path(destination) == service.caddyfile:
            parent = tmp_path.stat()
            assert (parent.st_dev, parent.st_ino) in synced_directories
        return real_replace(source, destination)

    monkeypatch.setattr("naive_manager.service.os.fsync", track_fsync)
    monkeypatch.setattr("naive_manager.service.os.replace", assert_parent_durable_before_replace)

    service.bootstrap()


def test_failed_reload_restores_config_and_state(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    before_config = service.caddyfile.read_bytes()
    before_state = service.state_file.read_bytes()
    hooks.fail_reload_calls = {1}

    with pytest.raises(RuntimeError, match="reload failed"):
        service.create("must-rollback")

    assert service.caddyfile.read_bytes() == before_config
    assert service.state_file.read_bytes() == before_state
    assert "must-rollback" not in service.caddyfile.read_text()


def test_probe_failure_reloads_and_probes_restored_live_configuration(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    before_config = service.caddyfile.read_bytes()
    before_state = service.state_file.read_bytes()
    hooks.fail_probe_times = 1

    with pytest.raises(RuntimeError, match="probe failed"):
        service.create("must-rollback")

    assert service.caddyfile.read_bytes() == before_config
    assert service.state_file.read_bytes() == before_state
    assert len(hooks.reload_snapshots) == 2
    assert "must-rollback" in hooks.reload_snapshots[0]
    assert hooks.reload_snapshots[1].encode() == before_config
    assert hooks.probes == 2


def test_failed_rollback_is_reported_and_manager_stays_unhealthy(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    hooks.fail_probe_times = 1
    hooks.fail_reload_calls = {2}

    with pytest.raises(ManagerRecoveryError, match="rollback failed"):
        service.create("ambiguous-live-state")

    assert service.health()["ready"] is False
    transaction = service.state_file.parent / "transaction.json"
    assert transaction.exists()
    with pytest.raises(ManagerRecoveryError, match="recovery"):
        service.create("must-not-run")

    hooks.fail_reload_calls.clear()
    recovered = manager(tmp_path, hooks)
    recovered.bootstrap()
    assert recovered.health()["ready"] is True
    assert not transaction.exists()


def test_rollback_file_restore_failure_persists_recovery_failed_journal(tmp_path, monkeypatch):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    hooks.fail_probe_times = 1
    from naive_manager import service as service_module
    real_atomic_write = service_module._atomic_write
    failed = False

    def fail_config_restore(path, data, mode=0o600):
        nonlocal failed
        if path == service.caddyfile and not failed:
            failed = True
            raise OSError("restore write failed")
        return real_atomic_write(path, data, mode)

    monkeypatch.setattr(service_module, "_atomic_write", fail_config_restore)

    with pytest.raises(ManagerRecoveryError, match="rollback failed"):
        service.create("restore-failure")

    transaction = json.loads((service.state_file.parent / "transaction.json").read_text())
    assert transaction["phase"] == "recovery_failed"
    assert service.health()["ready"] is False
    with pytest.raises(ManagerRecoveryError, match="recovery"):
        service.create("must-not-run")


def test_bootstrap_recovers_prepared_transaction_from_both_backups(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    before_config = service.caddyfile.read_bytes()
    before_state = service.state_file.read_bytes()
    service.backup_dir.mkdir(parents=True, exist_ok=True)
    config_backup = service.backup_dir / "crash.Caddyfile"
    state_backup = service.backup_dir / "crash.users.json"
    config_backup.write_bytes(before_config)
    state_backup.write_bytes(before_state)
    service.caddyfile.write_text(service.caddyfile.read_text().replace("old-password", "partial-change"))
    changed = json.loads(service.state_file.read_text())
    changed["users"][0]["password"] = "partial-change"
    service.state_file.write_text(json.dumps(changed))
    transaction = service.state_file.parent / "transaction.json"
    transaction.write_text(json.dumps({
        "version": 1,
        "phase": "prepared",
        "config_backup": config_backup.name,
        "state_backup": state_backup.name,
    }))

    recovered = manager(tmp_path, hooks)
    recovered.bootstrap()

    assert recovered.caddyfile.read_bytes() == before_config
    assert recovered.state_file.read_bytes() == before_state
    assert not transaction.exists()
    assert hooks.reload_snapshots[-1].encode() == before_config
    assert hooks.probes == 1


def test_failed_startup_recovery_durably_marks_journal_recovery_failed(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    transaction = service.state_file.parent / "transaction.json"
    transaction.write_text(json.dumps({
        "version": 1,
        "phase": "prepared",
        "config_backup": "missing.Caddyfile",
        "state_backup": "missing.users.json",
    }))

    recovered = manager(tmp_path, hooks)
    with pytest.raises(ManagerRecoveryError, match="transaction recovery failed"):
        recovered.bootstrap()

    assert json.loads(transaction.read_text())["phase"] == "recovery_failed"
    assert recovered.health()["ready"] is False


def test_bootstrap_commits_files_replaced_transaction_by_reloading_current_files(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    before_config = service.caddyfile.read_bytes()
    before_state = service.state_file.read_bytes()
    state = json.loads(service.state_file.read_text())
    state["users"].append({
        "username": "crash-commit",
        "password": "new-password",
        "enabled": True,
        "created_at": "now",
        "updated_at": "now",
    })
    service.caddyfile.write_text(service._render_managed(service.caddyfile.read_text(), state))
    service.state_file.write_bytes(service._encode_state(state))
    service.backup_dir.mkdir(parents=True, exist_ok=True)
    config_backup = service.backup_dir / "commit.Caddyfile"
    state_backup = service.backup_dir / "commit.users.json"
    config_backup.write_bytes(before_config)
    state_backup.write_bytes(before_state)
    transaction = service.state_file.parent / "transaction.json"
    transaction.write_text(json.dumps({
        "version": 1,
        "phase": "files_replaced",
        "config_backup": config_backup.name,
        "state_backup": state_backup.name,
    }))

    recovered = manager(tmp_path, hooks)
    recovered.bootstrap()

    assert recovered.list_users()[-1] == {"username": "crash-commit", "enabled": True}
    assert "basic_auth crash-commit new-password" in recovered.caddyfile.read_text()
    assert not transaction.exists()
    assert "crash-commit" in hooks.reload_snapshots[-1]
    assert hooks.probes == 1


def test_bootstrap_falls_back_to_backups_if_files_replaced_generation_is_incomplete(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    before_config = service.caddyfile.read_bytes()
    before_state = service.state_file.read_bytes()
    service.backup_dir.mkdir(parents=True, exist_ok=True)
    config_backup = service.backup_dir / "partial.Caddyfile"
    state_backup = service.backup_dir / "partial.users.json"
    config_backup.write_bytes(before_config)
    state_backup.write_bytes(before_state)
    service.caddyfile.write_text(service.caddyfile.read_text().replace("old-password", "partial-new"))
    transaction = service.state_file.parent / "transaction.json"
    transaction.write_text(json.dumps({
        "version": 1,
        "phase": "files_replaced",
        "config_backup": config_backup.name,
        "state_backup": state_backup.name,
    }))

    recovered = manager(tmp_path, hooks)
    recovered.bootstrap()

    assert recovered.caddyfile.read_bytes() == before_config
    assert recovered.state_file.read_bytes() == before_state
    assert not transaction.exists()
    assert hooks.reload_snapshots[-1].encode() == before_config


def test_out_of_band_managed_block_edit_is_rejected(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    service.caddyfile.write_text(service.caddyfile.read_text().replace("old-password", "changed-outside"))

    with pytest.raises(ManagerConflict):
        service.create("phone")


def test_additional_basic_auth_outside_managed_block_makes_health_unready(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    text = service.caddyfile.read_text()
    service.caddyfile.write_text(text.replace(
        "            # END NAIVE-MANAGER USERS",
        "            # END NAIVE-MANAGER USERS\n            basic_auth rogue rogue-password",
    ))

    assert service.health()["ready"] is False


def test_multiple_forward_proxy_blocks_make_health_unready(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    service.caddyfile.write_text(
        service.caddyfile.read_text()
        + "\n:4555 {\n    forward_proxy {\n        hide_ip\n    }\n}\n"
    )

    assert service.health()["ready"] is False


def test_unix_api_requires_token_and_never_lists_passwords(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    socket_path = tmp_path / "manager.sock"
    server = ManagerHTTPServer(socket_path, service, "internal-token")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        with httpx.Client(transport=transport, base_url="http://manager") as client:
            assert client.get("/v1/users").status_code == 401
            response = client.get("/v1/users", headers={"X-Naive-Token": "internal-token"})
            assert response.status_code == 200
            assert response.json() == [
                {"username": "old-user", "enabled": True},
                {"username": "second", "enabled": True},
            ]
            assert "old-password" not in response.text
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_unix_health_returns_503_when_manager_is_not_ready(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    hooks.probe = lambda: (_ for _ in ()).throw(RuntimeError("probe failed"))
    service.probe = hooks.probe
    socket_path = tmp_path / "manager.sock"
    server = ManagerHTTPServer(socket_path, service, "internal-token")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        with httpx.Client(transport=transport, base_url="http://manager") as client:
            response = client.get("/v1/health", headers={"X-Naive-Token": "internal-token"})
            assert response.status_code == 503
            assert response.json()["ready"] is False
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_health_fails_closed_while_transaction_journal_exists(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    service.state_file.parent.joinpath("transaction.json").write_text("{}")

    assert service.health()["ready"] is False


def test_invalid_recovery_origin_is_rejected(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    config_backup = next(service.backup_dir.glob("*.Caddyfile"))
    state_backup = next(service.backup_dir.glob("*.users.json"))
    transaction = service.state_file.parent / "transaction.json"
    transaction.write_text(json.dumps({
        "version": 1,
        "phase": "recovery_failed",
        "recovery_from": "unknown_phase",
        "config_backup": config_backup.name,
        "state_backup": state_backup.name,
    }))

    with pytest.raises(ManagerRecoveryError, match="invalid transaction journal"):
        manager(tmp_path, hooks).bootstrap()


def test_unknown_transaction_field_is_rejected(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    config_backup = next(service.backup_dir.glob("*.Caddyfile"))
    state_backup = next(service.backup_dir.glob("*.users.json"))
    transaction = service.state_file.parent / "transaction.json"
    transaction.write_text(json.dumps({
        "version": 1,
        "phase": "prepared",
        "config_backup": config_backup.name,
        "state_backup": state_backup.name,
        "unexpected": "field",
    }))

    with pytest.raises(ManagerRecoveryError, match="invalid transaction journal"):
        manager(tmp_path, hooks).bootstrap()


@pytest.mark.parametrize("payload", [[], {"version": True}])
def test_transaction_root_and_version_types_are_strict(tmp_path, payload):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    transaction = service.state_file.parent / "transaction.json"
    if isinstance(payload, dict):
        config_backup = next(service.backup_dir.glob("*.Caddyfile"))
        state_backup = next(service.backup_dir.glob("*.users.json"))
        payload.update({
            "phase": "prepared",
            "config_backup": config_backup.name,
            "state_backup": state_backup.name,
        })
    transaction.write_text(json.dumps(payload))

    with pytest.raises(ManagerRecoveryError, match="invalid transaction journal"):
        service._read_transaction()


def test_backup_names_must_be_a_matching_typed_pair(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    config_backup = next(service.backup_dir.glob("*.Caddyfile"))
    state_backup = next(service.backup_dir.glob("*.users.json"))
    transaction = service.state_file.parent / "transaction.json"
    transaction.write_text(json.dumps({
        "version": 1,
        "phase": "prepared",
        "config_backup": state_backup.name,
        "state_backup": config_backup.name,
    }))

    with pytest.raises(ManagerRecoveryError, match="invalid transaction journal"):
        service._read_transaction()


def test_recovery_origin_is_rejected_outside_recovery_failed_phase(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    config_backup = next(service.backup_dir.glob("*.Caddyfile"))
    state_backup = next(service.backup_dir.glob("*.users.json"))
    transaction = service.state_file.parent / "transaction.json"
    transaction.write_text(json.dumps({
        "version": 1,
        "phase": "prepared",
        "recovery_from": "files_replaced",
        "config_backup": config_backup.name,
        "state_backup": state_backup.name,
    }))

    with pytest.raises(ManagerRecoveryError, match="invalid transaction journal"):
        manager(tmp_path, hooks).bootstrap()


def test_non_boolean_state_existence_marker_is_rejected(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    config_backup = next(service.backup_dir.glob("*.Caddyfile"))
    state_backup = next(service.backup_dir.glob("*.users.json"))
    transaction = service.state_file.parent / "transaction.json"
    transaction.write_text(json.dumps({
        "version": 1,
        "phase": "bootstrap_prepared",
        "state_existed": "false",
        "config_backup": config_backup.name,
        "state_backup": state_backup.name,
    }))

    with pytest.raises(ManagerRecoveryError, match="invalid transaction journal"):
        manager(tmp_path, hooks).bootstrap()


def test_bootstrap_journal_requires_explicit_absent_state_marker(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    config_backup = next(service.backup_dir.glob("*.Caddyfile"))
    state_backup = next(service.backup_dir.glob("*.users.json"))
    transaction = service.state_file.parent / "transaction.json"
    transaction.write_text(json.dumps({
        "version": 1,
        "phase": "bootstrap_prepared",
        "config_backup": config_backup.name,
        "state_backup": state_backup.name,
    }))

    with pytest.raises(ManagerRecoveryError, match="invalid transaction journal"):
        manager(tmp_path, hooks).bootstrap()


def test_caddy_adapt_unwraps_caddy_211_envelope(tmp_path, monkeypatch):
    candidate = tmp_path / "Caddyfile"
    candidate.write_text("example.com { respond 200 }")

    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *_args): return None
        def read(self): return b'{"result":{"apps":{"http":{}}},"warnings":[]}'

    def open_validated(request, **_kwargs):
        assert "validate=true" in request.full_url
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", open_validated)
    assert caddy_adapt(candidate) == {"apps": {"http": {}}}
