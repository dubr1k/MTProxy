from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import threading
from pathlib import Path

import httpx
import pytest

from naive_manager.server import ManagerHTTPServer, caddy_adapt
from naive_manager.service import (
    ACCOUNTING_BEGIN,
    ACCOUNTING_END,
    ManagerConflict,
    ManagerRecoveryError,
    NaiveCredentialManager,
)
from naive_manager.traffic import TrafficCollector


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
        self.adapted_config = None

    def validate(self, path: Path):
        text = path.read_text()
        self.validated.append(text)
        if self.adapted_config is not None:
            return self.adapted_config
        count = len(NaiveCredentialManager._managed_credentials(text))
        return {"apps": {"http": {"handler": "forward_proxy", "auth_credentials": ["opaque"] * count}}}

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
    assert stat.S_IMODE(service.caddyfile.stat().st_mode) == 0o640
    assert stat.S_IMODE(service.state_file.stat().st_mode) == 0o600
    state = json.loads(service.state_file.read_text())
    assert state["version"] == 1
    assert "# BEGIN NAIVE-MANAGER ACCOUNTING" in rendered
    assert "output file /var/log/naive-proxy/access.json" in rendered
    assert "mode 0640" in rendered and "roll_uncompressed" in rendered
    assert "request>headers>Proxy-Authorization delete" in rendered
    assert "wrap json" in rendered
    assert "sampling" not in rendered
    assert "user_id regexp ^(invalidbase64|invalidformat|invalid):.*$ invalid" in rendered
    accounting = rendered.split("# BEGIN NAIVE-MANAGER ACCOUNTING", 1)[1].split(
        "# END NAIVE-MANAGER ACCOUNTING", 1
    )[0]
    assert "old-password" not in accounting


def test_create_rejects_exact_redaction_sentinel_without_mutation(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    config_before = service.caddyfile.read_bytes()
    state_before = service.state_file.read_bytes()
    backups_before = sorted(service.backup_dir.iterdir())

    with pytest.raises(ValueError, match="reserved username"):
        service.create("invalid")

    assert service.caddyfile.read_bytes() == config_before
    assert service.state_file.read_bytes() == state_before
    assert sorted(service.backup_dir.iterdir()) == backups_before
    assert service.create("invaliduser")["username"] == "invaliduser"


def test_bootstrap_rejects_reserved_sentinel_import_before_mutation(tmp_path):
    hooks = Hooks()
    caddy = tmp_path / "Caddyfile"
    caddy.write_text(CADDY.replace("basic_auth old-user old-password", "basic_auth invalid password"))
    service = manager(tmp_path, hooks)
    config_before = caddy.read_bytes()

    with pytest.raises(ManagerConflict, match="reserved accounting username"):
        service.bootstrap()

    assert caddy.read_bytes() == config_before
    assert not service.state_file.exists()
    assert not service.backup_dir.exists()


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


def test_bootstrap_rejects_caddyfile_reached_through_symlinked_parent(tmp_path):
    hooks = Hooks()
    real = tmp_path / "real-config"
    real.mkdir()
    (real / "Caddyfile").write_text(CADDY)
    linked = tmp_path / "linked-config"
    linked.symlink_to(real, target_is_directory=True)
    hooks.caddyfile = linked / "Caddyfile"
    service = NaiveCredentialManager(
        caddyfile=linked / "Caddyfile",
        state_file=tmp_path / "state" / "users.json",
        backup_dir=tmp_path / "backups",
        public_host="naive.example.com",
        validate=hooks.validate,
        reload=hooks.reload,
        probe=hooks.probe,
    )

    with pytest.raises(ManagerConflict, match="unsafe"):
        service.bootstrap()


@pytest.mark.parametrize("accounting_present", [True, False])
def test_bootstrap_fails_closed_on_reserved_sentinel_in_existing_state(
    tmp_path, accounting_present,
):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    state = json.loads(service.state_file.read_text())
    state["users"][0]["username"] = "invalid"
    service.state_file.write_bytes(service._encode_state(state))
    rendered = service.caddyfile.read_text().replace(
        "basic_auth old-user old-password", "basic_auth invalid old-password",
    )
    if not accounting_present:
        lines = rendered.splitlines()
        begin = next(i for i, line in enumerate(lines) if line.strip() == ACCOUNTING_BEGIN)
        end = next(i for i, line in enumerate(lines) if line.strip() == ACCOUNTING_END)
        rendered = "\n".join(lines[:begin] + lines[end + 1:]) + "\n"
    service.caddyfile.write_text(rendered)
    config_before = service.caddyfile.read_bytes()
    state_before = service.state_file.read_bytes()

    with pytest.raises(ManagerConflict, match="reserved accounting username in manager state"):
        service.bootstrap()

    assert service.caddyfile.read_bytes() == config_before
    assert service.state_file.read_bytes() == state_before
    assert not (service.state_file.parent / "transaction.json").exists()


def test_bootstrap_transactionally_migrates_existing_managed_state_to_accounting(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    lines = service.caddyfile.read_text().splitlines()
    begin = next(i for i, line in enumerate(lines) if line.strip() == "# BEGIN NAIVE-MANAGER ACCOUNTING")
    end = next(i for i, line in enumerate(lines) if line.strip() == "# END NAIVE-MANAGER ACCOUNTING")
    service.caddyfile.write_text("\n".join(lines[:begin] + lines[end + 1:]) + "\n")
    hooks.reloads = hooks.probes = 0

    service.bootstrap()

    assert service.caddyfile.read_text().count("# BEGIN NAIVE-MANAGER ACCOUNTING") == 1
    assert hooks.reloads == 1
    assert hooks.probes == 1
    assert not (service.state_file.parent / "transaction.json").exists()
    backups = len(list(service.backup_dir.glob("*.Caddyfile")))
    service.bootstrap()
    assert len(list(service.backup_dir.glob("*.Caddyfile"))) == backups
    assert hooks.reloads == 1


@pytest.mark.parametrize("fault_phase", ["prepared", "files_replaced", "rollback_pending"])
def test_accounting_migration_fault_at_each_phase_restores_then_retries_idempotently(
    tmp_path, monkeypatch, fault_phase,
):
    """Every durable phase must recover the old generation before a clean retry."""
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    lines = service.caddyfile.read_text().splitlines()
    begin = next(i for i, line in enumerate(lines) if line.strip() == ACCOUNTING_BEGIN)
    end = next(i for i, line in enumerate(lines) if line.strip() == ACCOUNTING_END)
    old_config = "\n".join(lines[:begin] + lines[end + 1:]) + "\n"
    service.caddyfile.write_text(old_config)
    old_state = service.state_file.read_bytes()
    real_write_transaction = NaiveCredentialManager._write_transaction
    injected = False

    class SimulatedCrash(BaseException):
        pass

    def crash_after_phase(self, transaction):
        nonlocal injected
        real_write_transaction(self, transaction)
        if transaction["phase"] == fault_phase and not injected:
            injected = True
            raise SimulatedCrash(fault_phase)

    monkeypatch.setattr(NaiveCredentialManager, "_write_transaction", crash_after_phase)
    with pytest.raises(SimulatedCrash):
        service.bootstrap()

    monkeypatch.setattr(NaiveCredentialManager, "_write_transaction", real_write_transaction)
    recovered = manager(tmp_path, hooks)
    recovered.bootstrap()

    assert injected is True
    assert recovered.state_file.read_bytes() == old_state
    assert recovered.caddyfile.read_text().count(ACCOUNTING_BEGIN) == 1
    assert not (recovered.state_file.parent / "transaction.json").exists()
    recovered.bootstrap()
    assert recovered.caddyfile.read_text().count(ACCOUNTING_BEGIN) == 1


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

    log = tmp_path / "access.json"
    log.write_text("")
    service.traffic = TrafficCollector(log, tmp_path / "traffic.sqlite3", service.managed_usernames)
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


def test_blockless_forward_proxy_directive_makes_health_unready(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    service.caddyfile.write_text(
        service.caddyfile.read_text()
        + "\n:4555 {\n    forward_proxy\n}\n"
    )

    assert service.health()["ready"] is False


def test_global_basic_auth_outside_managed_block_makes_health_unready(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    service.caddyfile.write_text(
        service.caddyfile.read_text()
        + "\n:4666 {\n    basic_auth {\n        rogue JDJhJDE0JHJvZ3Vl\n    }\n    respond 200\n}\n"
    )

    assert service.health()["ready"] is False


@pytest.mark.parametrize(
    "adapted",
    [
        {
            "routes": [
                {"handler": "forward_proxy", "auth_credentials": ["one", "two"]},
                {"handler": "forward_proxy", "auth_credentials": []},
            ]
        },
        {
            "routes": [
                {"handler": "forward_proxy", "auth_credentials": ["one", "two"]},
                {"handler": "authentication", "providers": {"http_basic": {}}},
            ]
        },
        {"routes": [{"handler": "forward_proxy", "auth_credentials": ["extra"]}]},
    ],
    ids=["extra-forward-proxy", "external-authentication", "credential-count-mismatch"],
)
def test_adapted_semantic_drift_makes_health_unready(tmp_path, adapted):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    hooks.adapted_config = adapted

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


def test_authenticated_traffic_api_lists_and_resets_without_changing_credentials(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    log = tmp_path / "access.json"
    log.write_text(json.dumps({
        "request": {"method": "CONNECT"}, "status": 200, "user_id": "old-user",
        "bytes_read": 12, "size": 34,
    }) + "\n")
    service.traffic = TrafficCollector(
        log, tmp_path / "traffic.sqlite3",
        lambda: {row["username"] for row in service.list_users()},
    )
    before = service.reveal("old-user")["proxy_url"]
    socket_path = tmp_path / "manager.sock"
    server = ManagerHTTPServer(socket_path, service, "internal-token")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        transport = httpx.HTTPTransport(uds=str(socket_path))
        with httpx.Client(transport=transport, base_url="http://manager") as client:
            assert client.get("/v1/traffic").status_code == 401
            listed = client.get("/v1/traffic", headers={"X-Naive-Token": "internal-token"})
            assert listed.status_code == 200
            assert listed.json()["users"][0]["total_bytes"] == 46
            reset = client.post(
                "/v1/users/old-user/traffic/reset", json={},
                headers={"X-Naive-Token": "internal-token"},
            )
            assert reset.status_code == 200
            assert reset.json()["total_bytes"] == 0
            assert client.post(
                "/v1/users/unknown/traffic/reset", json={},
                headers={"X-Naive-Token": "internal-token"},
            ).status_code == 404
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert service.reveal("old-user")["proxy_url"] == before


def test_health_and_traffic_report_do_not_deadlock_on_opposite_lock_timing(tmp_path):
    """Traffic collection must never call back into manager state under its lock."""
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    log = tmp_path / "access.json"
    log.write_text("")
    callback_entered = threading.Event()
    release_callback = threading.Event()

    def blocked_users():
        callback_entered.set()
        assert release_callback.wait(1)
        return service.managed_usernames()

    service.traffic = TrafficCollector(log, tmp_path / "traffic.sqlite3", blocked_users)
    results = {}
    report = threading.Thread(target=lambda: results.setdefault("report", service.traffic_report()))
    report.start()
    assert callback_entered.wait(1)
    health = threading.Thread(target=lambda: results.setdefault("health", service.health()))
    health.start()
    release_callback.set()
    report.join(2)
    health.join(2)

    assert not report.is_alive()
    assert not health.is_alive()
    assert set(results) == {"report", "health"}


def test_reset_refuses_when_bounded_drain_cannot_finish_pre_reset_backlog(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    log = tmp_path / "access.json"
    line = json.dumps({
        "request": {"method": "CONNECT"}, "status": 200, "user_id": "old-user",
        "bytes_read": 1, "size": 2,
    }) + "\n"
    log.write_text(line * 8)
    service.traffic = TrafficCollector(
        log, tmp_path / "traffic.sqlite3", service.managed_usernames,
        max_line_bytes=128, max_read_bytes=160, max_drain_rounds=2,
    )

    with pytest.raises(ManagerConflict, match="backlog"):
        service.reset_traffic("old-user")

    while service.traffic.list_traffic()["pending"]:
        service.traffic.collect()
    reset = service.reset_traffic("old-user")
    assert reset["total_bytes"] == 0
    assert service.traffic.list_traffic()["users"][0]["total_bytes"] == 0


def test_delete_refuses_pending_backlog_then_archives_and_tombstones_username(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    log = tmp_path / "access.json"
    line = json.dumps({
        "request": {"method": "CONNECT"}, "status": 200, "user_id": "old-user",
        "bytes_read": 1, "size": 2,
    }) + "\n"
    log.write_text(line * 8)
    service.traffic = TrafficCollector(
        log, tmp_path / "traffic.sqlite3", service.managed_usernames,
        max_line_bytes=128, max_read_bytes=160, max_drain_rounds=1,
    )

    with pytest.raises(ManagerConflict, match="backlog"):
        service.delete("old-user")
    assert any(row["username"] == "old-user" for row in service.list_users())

    while service.traffic.list_traffic()["pending"]:
        service.traffic.collect()
    service.delete("old-user")

    assert all(row["username"] != "old-user" for row in service.list_users())
    assert service.traffic.list_traffic()["users"] == []
    state = json.loads(service.state_file.read_text())
    assert state["tombstones"] == [{"username": "old-user", "deleted_at": state["tombstones"][0]["deleted_at"]}]
    with pytest.raises(ManagerConflict, match="retired"):
        service.create("old-user")


def test_delete_serializes_with_collector_that_already_captured_old_user_snapshot(tmp_path):
    """Catch deletion archiving before a stale collector recreates the retired live counter."""
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    log = tmp_path / "access.json"
    line = json.dumps({
        "request": {"method": "CONNECT"}, "status": 200, "user_id": "old-user",
        "bytes_read": 1, "size": 2,
    }) + "\n"
    log.write_text("")
    snapshot_taken = threading.Event()
    release_snapshot = threading.Event()
    first_snapshot = True
    snapshot_lock = threading.Lock()

    def paused_snapshot():
        nonlocal first_snapshot
        users = service.managed_usernames()
        with snapshot_lock:
            pause = first_snapshot
            first_snapshot = False
        if pause:
            snapshot_taken.set()
            assert release_snapshot.wait(2)
        return users

    traffic = TrafficCollector(log, tmp_path / "traffic.sqlite3", paused_snapshot)
    service.traffic = traffic
    outcomes = {}
    collecting = threading.Thread(target=lambda: outcomes.setdefault("collected", traffic.collect()))
    deleting = threading.Thread(target=lambda: (service.delete("old-user"), outcomes.setdefault("deleted", True)))
    collecting.start()
    assert snapshot_taken.wait(1)
    deleting.start()
    deleting.join(1)
    assert deleting.is_alive()
    log.write_text(line)
    release_snapshot.set()
    collecting.join(2)
    deleting.join(2)

    assert not collecting.is_alive() and not deleting.is_alive()
    assert outcomes == {"deleted": True, "collected": 1}
    assert traffic.list_traffic()["users"] == []
    with sqlite3.connect(tmp_path / "traffic.sqlite3") as database:
        assert database.execute("SELECT COUNT(*) FROM traffic_counters").fetchone()[0] == 0
        assert database.execute(
            "SELECT username,upload_bytes,download_bytes FROM traffic_archives"
        ).fetchall() == [("old-user", 1, 2)]


def test_create_serializes_with_collector_snapshot_before_new_user_record(tmp_path):
    """Creation must commit membership before a later record can be consumed."""
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    log = tmp_path / "access.json"
    log.write_text("")
    snapshot_taken = threading.Event()
    release_snapshot = threading.Event()
    first_snapshot = True
    snapshot_lock = threading.Lock()

    def paused_snapshot():
        nonlocal first_snapshot
        users = service.managed_usernames()
        with snapshot_lock:
            pause = first_snapshot
            first_snapshot = False
        if pause:
            snapshot_taken.set()
            assert release_snapshot.wait(2)
        return users

    traffic = TrafficCollector(log, tmp_path / "traffic.sqlite3", paused_snapshot)
    service.traffic = traffic
    outcomes = {}
    collecting = threading.Thread(target=lambda: outcomes.setdefault("collected", traffic.collect()))
    creating = threading.Thread(target=lambda: outcomes.setdefault("created", service.create("new-user")))
    collecting.start()
    assert snapshot_taken.wait(1)
    creating.start()
    creating.join(1)
    assert creating.is_alive()
    release_snapshot.set()
    collecting.join(2)
    creating.join(2)
    assert not collecting.is_alive() and not creating.is_alive()
    assert outcomes["collected"] == 0

    with log.open("a") as stream:
        stream.write(json.dumps({
            "request": {"method": "CONNECT"}, "status": 200, "user_id": "new-user",
            "bytes_read": 2, "size": 3,
        }) + "\n")
    assert traffic.collect() == 1
    assert traffic.collect() == 0
    assert traffic.list_traffic()["users"][0]["total_bytes"] == 5


def test_concurrent_create_and_collect_stress_completes_without_deadlock(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    log = tmp_path / "access.json"
    log.write_text("")
    traffic = TrafficCollector(log, tmp_path / "traffic.sqlite3", service.managed_usernames)
    service.traffic = traffic
    start = threading.Barrier(2)
    failures = []

    def collect_repeatedly():
        try:
            start.wait()
            for _ in range(40):
                traffic.collect()
        except BaseException as exc:
            failures.append(exc)

    def create_repeatedly():
        try:
            start.wait()
            for index in range(8):
                service.create(f"stress-{index}")
                with log.open("a") as stream:
                    stream.write(json.dumps({
                        "request": {"method": "CONNECT"}, "status": 200,
                        "user_id": f"stress-{index}", "bytes_read": 1, "size": 1,
                    }) + "\n")
        except BaseException as exc:
            failures.append(exc)

    collector_thread = threading.Thread(target=collect_repeatedly)
    creator_thread = threading.Thread(target=create_repeatedly)
    collector_thread.start()
    creator_thread.start()
    collector_thread.join(10)
    creator_thread.join(10)

    assert not collector_thread.is_alive() and not creator_thread.is_alive()
    assert failures == []
    while traffic.list_traffic()["pending"]:
        traffic.collect()
    assert traffic.list_traffic()["aggregate"]["total_bytes"] == 16


def test_persistent_accounting_loss_surfaces_as_conflict_for_report_reset_and_delete(tmp_path):
    """Catch degraded accounting escaping as an internal error or allowing lifecycle mutation."""
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    log = tmp_path / "access.json"
    log.write_text("")
    traffic = TrafficCollector(log, tmp_path / "traffic.sqlite3", service.managed_usernames)
    service.traffic = traffic
    rotated = tmp_path / "access-2026-08-14T15-00-00.000-size.json"
    rotated.write_text(json.dumps({
        "request": {"method": "CONNECT"}, "status": 200, "user_id": "old-user",
        "bytes_read": 1, "size": 2,
    }) + "\n" + "partial")
    assert traffic.collect() == 1
    rotated.unlink()
    with pytest.raises(RuntimeError, match="accounting loss"):
        traffic.collect()

    for operation in (service.traffic_report, lambda: service.reset_traffic("old-user"), lambda: service.delete("old-user")):
        with pytest.raises(ManagerConflict, match="accounting"):
            operation()
    assert any(row["username"] == "old-user" for row in service.list_users())


def test_password_rotation_preserves_accounting_history(tmp_path):
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.bootstrap()
    log = tmp_path / "access.json"
    log.write_text(json.dumps({
        "request": {"method": "CONNECT"}, "status": 200, "user_id": "old-user",
        "bytes_read": 5, "size": 7,
    }) + "\n")
    service.traffic = TrafficCollector(log, tmp_path / "traffic.sqlite3", service.managed_usernames)
    service.traffic.collect()
    created_at = next(
        row["created_at"] for row in json.loads(service.state_file.read_text())["users"]
        if row["username"] == "old-user"
    )

    service.rotate("old-user")

    assert service.traffic.list_traffic()["users"][0]["total_bytes"] == 12
    state = json.loads(service.state_file.read_text())
    assert next(row["created_at"] for row in state["users"] if row["username"] == "old-user") == created_at


@pytest.mark.skipif(not Path("/usr/local/bin/caddy").is_file(), reason="exact local Caddy is absent")
def test_exact_local_caddy_accepts_managed_accounting_config_when_forwardproxy_module_present(tmp_path):
    modules = subprocess.run(
        ["/usr/local/bin/caddy", "list-modules"], check=True, capture_output=True, text=True,
    ).stdout.splitlines()
    if "http.handlers.forward_proxy" not in modules:
        pytest.skip("exact local Caddy lacks http.handlers.forward_proxy")
    hooks = Hooks()
    service = manager(tmp_path, hooks)
    service.caddyfile.write_text(
        service.caddyfile.read_text().replace(
            "file_server { root /var/www/naive }", "file_server {\n            root /var/www/naive\n        }"
        )
    )
    service.bootstrap()
    result = subprocess.run(
        ["/usr/local/bin/caddy", "validate", "--config", str(service.caddyfile)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    version = subprocess.run(
        ["/usr/local/bin/caddy", "version"], check=True, capture_output=True, text=True,
    ).stdout
    assert version.startswith("v2.11.4 ")
