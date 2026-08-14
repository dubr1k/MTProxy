from __future__ import annotations

import fcntl
import json
import os
import stat
from pathlib import Path

import pytest

from scripts.proxyctl import (
    InstallPlan,
    InstallerConflict,
    apply_plan,
    audit_host,
    repair_installation,
    uninstall_installation,
)


def host_root(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "root"
    route = root / "etc/nginx/stream.d/routes.conf"
    route.parent.mkdir(parents=True)
    (root / "etc/nginx/sites-enabled").mkdir(parents=True)
    (root / "etc/nginx/nginx.conf").write_text(
        "events {}\nhttp { include /etc/nginx/sites-enabled/*; }\n"
        "stream { include /etc/nginx/stream.d/*.conf; }\n"
    )
    route.write_text(
        "map $ssl_preread_server_name $upstream_443 {\n"
        "    vpn.example.com 127.0.0.1:10443;\n"
        "    default 127.0.0.1:8443;\n}\n"
        "server { listen 443; ssl_preread on; proxy_pass $upstream_443; }\n"
    )
    return root, route


def make_plan(root: Path, route: Path) -> InstallPlan:
    report = audit_host(
        root=root,
        listening_ports={80, 443, 10443},
        docker_available=True,
        dns_records={
            "mt.example.com": {"A": ["203.0.113.10"], "AAAA": []},
            "panel-mt.example.com": {"A": ["203.0.113.10"], "AAAA": []},
        },
        local_addresses={"203.0.113.10"},
        tls_names={"mt.example.com", "panel-mt.example.com"},
    )
    return InstallPlan.from_audit(
        report,
        proxy_domain="mt.example.com",
        panel_domain="panel-mt.example.com",
        route_file="/etc/nginx/stream.d/routes.conf",
    )


def test_audit_domain_checks_are_sorted_secret_safe_and_detect_dns_tls_failures(tmp_path):
    root, _ = host_root(tmp_path)
    report = audit_host(
        root=root,
        listening_ports={443},
        docker_available=True,
        dns_records={
            "z.example.com": {"A": ["198.51.100.7"], "AAAA": ["2001:db8::7"]},
            "a.example.com": {"A": ["203.0.113.10"], "AAAA": []},
        },
        local_addresses={"203.0.113.10"},
        tls_names={"a.example.com"},
    )

    encoded = json.dumps(report.to_dict(), sort_keys=True)
    assert [item.domain for item in report.domains] == ["a.example.com", "z.example.com"]
    assert report.domains[0].dns_matches_host is True
    assert report.domains[0].tls_certificate_present is True
    assert report.domains[1].dns_matches_host is False
    assert report.domains[1].unhandled_aaaa is True
    assert "secret" not in encoded.lower()
    assert "private" not in encoded.lower()


def test_plan_is_deterministic_and_blocks_failed_domain_preflight(tmp_path):
    root, route = host_root(tmp_path)
    plan = make_plan(root, route)

    first = plan.to_json()
    second = make_plan(root, route).to_json()
    assert first == second
    assert json.loads(first) == {
        "actions": [
            {"kind": "nginx_route", "target": "/etc/nginx/stream.d/routes.conf"},
            {"kind": "ownership_manifest", "target": "/var/lib/proxy-control/ownership.json"},
        ],
        "panel_backend": "127.0.0.1:8787",
        "panel_domain": "panel-mt.example.com",
        "proxy_backend": "127.0.0.1:8445",
        "proxy_domain": "mt.example.com",
        "route_file": "/etc/nginx/stream.d/routes.conf",
        "schema": 1,
    }

    failed = audit_host(
        root=root,
        listening_ports={443},
        docker_available=True,
        dns_records={
            "mt.example.com": {"A": ["198.51.100.9"], "AAAA": []},
            "panel-mt.example.com": {"A": ["203.0.113.10"], "AAAA": []},
        },
        local_addresses={"203.0.113.10"},
        tls_names={"mt.example.com", "panel-mt.example.com"},
    )
    with pytest.raises(InstallerConflict, match="DNS does not resolve to this host"):
        InstallPlan.from_audit(
            failed,
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/etc/nginx/stream.d/routes.conf",
        )

    empty = audit_host(root=root, listening_ports={443}, docker_available=True)
    with pytest.raises(InstallerConflict, match="domain preflight evidence is incomplete"):
        InstallPlan.from_audit(
            empty,
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/etc/nginx/stream.d/routes.conf",
        )


def test_plan_fails_closed_on_ambiguous_map_and_direct_443_listener(tmp_path):
    root, route = host_root(tmp_path)
    route.write_text(route.read_text() + "\nmap $ssl_preread_server_name $other { default 127.0.0.1:9; }\n")
    report = audit_host(root=root, listening_ports={443}, docker_available=True)
    with pytest.raises(InstallerConflict, match="exactly one SNI map"):
        InstallPlan.from_audit(
            report,
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/etc/nginx/stream.d/routes.conf",
            require_domain_preflight=False,
        )

    root2 = tmp_path / "direct"
    root2.mkdir()
    direct = audit_host(root=root2, listening_ports={443}, docker_available=True)
    with pytest.raises(InstallerConflict, match="occupied without an Nginx stream router"):
        InstallPlan.from_audit(
            direct,
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/etc/nginx/stream.d/routes.conf",
            require_domain_preflight=False,
        )


    root3, _ = host_root(tmp_path / "stale")
    stale = audit_host(
        root=root3,
        listening_ports={443},
        listener_owners={443: ["xray"]},
        docker_available=True,
    )
    with pytest.raises(InstallerConflict, match="not owned by Nginx"):
        InstallPlan.from_audit(
            stale,
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/etc/nginx/stream.d/routes.conf",
            require_domain_preflight=False,
        )

    root4, route4 = host_root(tmp_path / "duplicate")
    route4.write_text(route4.read_text().replace(
        "    default", "    vpn.example.com 127.0.0.1:10443;\n    default"
    ))
    duplicate = audit_host(root=root4, listening_ports={443}, docker_available=True)
    assert duplicate.nginx.duplicate_sni_domains == ["vpn.example.com"]

    root5, _ = host_root(tmp_path / "foreign")
    foreign = root5 / "tmp/foreign.conf"
    foreign.parent.mkdir()
    foreign.write_text("map $ssl_preread_server_name $x { default 127.0.0.1:9; }\n")
    with pytest.raises(InstallerConflict, match="audited SNI map file"):
        InstallPlan.from_audit(
            audit_host(root=root5, listening_ports={443}, docker_available=True),
            proxy_domain="mt.example.com",
            panel_domain="panel-mt.example.com",
            route_file="/tmp/foreign.conf",
            require_domain_preflight=False,
        )


def test_apply_is_transactional_preserves_metadata_and_writes_private_manifest(tmp_path):
    root, route = host_root(tmp_path)
    os.chmod(route, 0o640)
    original = route.read_text()
    plan = make_plan(root, route)
    calls: list[str] = []

    manifest = apply_plan(
        plan,
        root=root,
        validate=lambda: calls.append("validate"),
        reload=lambda: calls.append("reload"),
    )

    assert calls == ["validate", "reload"]
    assert "vpn.example.com 127.0.0.1:10443;" in route.read_text()
    assert route.read_text().count("# BEGIN PROXY-CONTROL ROUTES ") == 1
    assert stat.S_IMODE(route.stat().st_mode) == 0o640
    manifest_path = root / "var/lib/proxy-control/ownership.json"
    assert manifest_path == manifest
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o600
    state = json.loads(manifest_path.read_text())
    assert state["route_sha256_before"]
    assert state["route_sha256_owned"]
    backup = root / state["backup_file"].lstrip("/")
    assert backup.read_text() == original
    assert stat.S_IMODE(backup.stat().st_mode) == 0o600


def test_apply_rolls_back_exactly_when_validation_or_reload_fails(tmp_path):
    root, route = host_root(tmp_path)
    original = route.read_bytes()
    plan = make_plan(root, route)

    validation_calls = 0

    def reject_candidate_once() -> None:
        nonlocal validation_calls
        validation_calls += 1
        if validation_calls == 1:
            raise RuntimeError("bad nginx")

    with pytest.raises(RuntimeError, match="bad nginx"):
        apply_plan(plan, root=root, validate=reject_candidate_once)
    assert route.read_bytes() == original
    assert not (root / "var/lib/proxy-control/ownership.json").exists()

    reload_calls = 0

    def reject_reload_once() -> None:
        nonlocal reload_calls
        reload_calls += 1
        if reload_calls == 1:
            raise RuntimeError("reload failed")

    with pytest.raises(RuntimeError, match="reload failed"):
        apply_plan(
            plan,
            root=root,
            validate=lambda: None,
            reload=reject_reload_once,
        )
    assert route.read_bytes() == original
    assert not (root / "var/lib/proxy-control/ownership.json").exists()


def test_repair_and_uninstall_are_idempotent_and_refuse_foreign_drift(tmp_path):
    root, route = host_root(tmp_path)
    original = route.read_text()
    plan = make_plan(root, route)
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)

    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert route.read_text().count("# BEGIN PROXY-CONTROL ROUTES ") == 1

    route.write_text(route.read_text().replace("127.0.0.1:8445", "127.0.0.1:9445"))
    with pytest.raises(InstallerConflict, match="owned route file has drifted"):
        repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    with pytest.raises(InstallerConflict, match="owned route file has drifted"):
        uninstall_installation(root=root, validate=lambda: None, reload=lambda: None)

    # Restore the exact owned generation and remove only our marked block.
    route.write_text(route.read_text().replace("127.0.0.1:9445", "127.0.0.1:8445"))
    uninstall_installation(root=root, validate=lambda: None, reload=lambda: None)
    uninstall_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert route.read_text() == original
    assert not (root / "var/lib/proxy-control/ownership.json").exists()


def test_interrupted_apply_and_uninstall_recover_from_durable_manifest(tmp_path):
    root, route = host_root(tmp_path)
    original = route.read_bytes()
    plan = make_plan(root, route)
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)
    manifest = root / "var/lib/proxy-control/ownership.json"
    state = json.loads(manifest.read_text())
    owned = route.read_bytes()

    state["status"] = "applying"
    manifest.write_text(json.dumps(state))
    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert route.read_bytes() == original
    assert not manifest.exists()

    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)
    state = json.loads(manifest.read_text())
    backup = root / state["backup_file"].lstrip("/")
    state["status"] = "uninstalling"
    manifest.write_text(json.dumps(state))
    route.write_bytes(original)
    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert route.read_bytes() == original
    assert not manifest.exists()
    assert not backup.exists()
    assert owned != original

    # Cleanup is recoverable even if an older generation removed backup first.
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)
    state = json.loads(manifest.read_text())
    backup = root / state["backup_file"].lstrip("/")
    state["status"] = "uninstalling"
    manifest.write_text(json.dumps(state))
    route.write_bytes(original)
    backup.unlink()
    repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert not manifest.exists()


def test_failed_rollback_keeps_recoverable_manifest(tmp_path):
    root, route = host_root(tmp_path)
    plan = make_plan(root, route)
    validations = 0

    def validate() -> None:
        nonlocal validations
        validations += 1
        if validations == 1:
            raise RuntimeError("candidate invalid")

    with pytest.raises(RuntimeError, match="rollback reload failed"):
        apply_plan(
            plan,
            root=root,
            validate=validate,
            reload=lambda: (_ for _ in ()).throw(RuntimeError("rollback reload failed")),
        )
    state = json.loads((root / "var/lib/proxy-control/ownership.json").read_text())
    assert state["status"] == "applying"


def test_manifest_rejects_generation_mismatch_before_touching_route(tmp_path):
    root, route = host_root(tmp_path)
    plan = make_plan(root, route)
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)
    before = route.read_bytes()
    manifest = root / "var/lib/proxy-control/ownership.json"
    state = json.loads(manifest.read_text())
    state["install_id"] = "f" * 32
    manifest.write_text(json.dumps(state))

    with pytest.raises(InstallerConflict, match="generation"):
        repair_installation(root=root, validate=lambda: None, reload=lambda: None)
    assert route.read_bytes() == before


def test_mutations_refuse_a_concurrent_operation_lock(tmp_path):
    root, route = host_root(tmp_path)
    plan = make_plan(root, route)
    lock = root / "run/lock/proxy-control.lock"
    lock.parent.mkdir(parents=True)
    with lock.open("w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(InstallerConflict, match="another proxyctl operation"):
            apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)


def test_symlink_route_is_canonicalized_but_symlink_survives(tmp_path):
    root, route = host_root(tmp_path)
    alias = root / "etc/nginx/stream.d/current.conf"
    alias.symlink_to(route.name)
    report = audit_host(root=root, listening_ports={443}, docker_available=True)
    plan = InstallPlan.from_audit(
        report,
        proxy_domain="mt.example.com",
        panel_domain="panel-mt.example.com",
        route_file="/etc/nginx/stream.d/current.conf",
        require_domain_preflight=False,
    )
    apply_plan(plan, root=root, validate=lambda: None, reload=lambda: None)

    state = json.loads((root / "var/lib/proxy-control/ownership.json").read_text())
    assert state["route_file"] == "/etc/nginx/stream.d/routes.conf"
    assert alias.is_symlink()
