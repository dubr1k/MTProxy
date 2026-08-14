from __future__ import annotations

from argon2 import PasswordHasher, extract_parameters

from panel.store import Store


def test_store_startup_uses_valid_policy_matched_precomputed_dummy_hash(tmp_path, monkeypatch):
    def fail_if_hash_is_generated(_self, _password):
        raise AssertionError("Store startup generated an Argon2 hash")

    monkeypatch.setattr(PasswordHasher, "hash", fail_if_hash_is_generated)

    store = Store(tmp_path / "panel.sqlite3")
    parameters = extract_parameters(store._dummy_hash)

    assert parameters.type.name == "ID"
    assert parameters.version == 19
    assert parameters.memory_cost == 65536
    assert parameters.time_cost == 3
    assert parameters.parallelism == 2


def test_unknown_admin_performs_one_argon2_verify_without_logging_password(tmp_path, monkeypatch, caplog):
    store = Store(tmp_path / "panel.sqlite3")
    password = "not-the-real-password"
    calls = []
    verify = PasswordHasher.verify

    def record_verify(hasher, password_hash, supplied_password):
        calls.append((password_hash, supplied_password))
        return verify(hasher, password_hash, supplied_password)

    monkeypatch.setattr(PasswordHasher, "verify", record_verify)

    assert store.verify_admin("missing-admin", password) is None
    assert calls == [(store._dummy_hash, password)]
    assert password not in caplog.text
