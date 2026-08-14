from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.proxyctl import (
    InstallPlan,
    InstallerConflict,
    audit_host,
    patch_stream_map,
    validate_domain,
)


def fixture_root(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    (root / "etc/nginx/stream.d").mkdir(parents=True)
    (root / "etc/nginx/sites-enabled").mkdir(parents=True)
    (root / "usr/local/x-ui/bin").mkdir(parents=True)
    (root / "etc/nginx/nginx.conf").write_text(
        "events {}\nhttp { include /etc/nginx/sites-enabled/*; }\nstream { include /etc/nginx/stream.d/*.conf; }\n"
    )
    (root / "etc/nginx/stream.d/sni.conf").write_text(
        "map $ssl_preread_server_name $upstream_443 {\n"
        "    vpn.example.com 127.0.0.1:10443;\n"
        "    default 127.0.0.1:8443;\n"
        "}\nserver { listen 443; ssl_preread on; proxy_pass $upstream_443; }\n"
    )
    (root / "etc/nginx/sites-enabled/existing.conf").write_text(
        "server { listen 127.0.0.1:8443 ssl; server_name panel.example.com; }\n"
    )
    (root / "usr/local/x-ui/bin/config.json").write_text(json.dumps({
        "inbounds": [{
            "tag": "in-443-tcp", "protocol": "vless", "listen": "127.0.0.1", "port": 10443,
            "streamSettings": {"security": "reality", "realitySettings": {"serverNames": ["vpn.example.com"]}},
        }],
        "outbounds": [{"tag": "WARP", "protocol": "socks"}],
    }))
    return root


def test_audit_reports_existing_shared_443_without_dumping_secrets(tmp_path):
    root = fixture_root(tmp_path)
    report = audit_host(root=root, listening_ports={22, 80, 443, 10443, 45000}, docker_available=False)

    assert report.nginx.stream_enabled is True
    assert report.nginx.sni_routes == {"vpn.example.com": "127.0.0.1:10443"}
    assert report.xray.inbounds == [{
        "tag": "in-443-tcp", "protocol": "vless", "listen": "127.0.0.1", "port": 10443,
        "security": "reality", "server_names": ["vpn.example.com"],
    }]
    assert report.docker_available is False
    assert report.listening_ports == [22, 80, 443, 10443, 45000]
    assert "privateKey" not in json.dumps(report.to_dict())


def test_install_plan_rejects_domain_and_port_collisions(tmp_path):
    report = audit_host(root=fixture_root(tmp_path), listening_ports={443, 8445, 8787}, docker_available=True)

    with pytest.raises(InstallerConflict, match="domain already routed"):
        InstallPlan.from_audit(report, proxy_domain="vpn.example.com", panel_domain="new-panel.example.com")
    with pytest.raises(InstallerConflict, match="backend port 8445"):
        InstallPlan.from_audit(report, proxy_domain="proxy-new.example.com", panel_domain="new-panel.example.com")


def test_stream_patch_is_owned_idempotent_and_preserves_unrelated_routes():
    original = (
        "map $ssl_preread_server_name $upstream_443 {\n"
        "    vpn.example.com 127.0.0.1:10443;\n"
        "    default 127.0.0.1:8443;\n}\n"
    )
    changed = patch_stream_map(
        original,
        proxy_domain="mt.example.com",
        panel_domain="panel-mt.example.com",
        proxy_backend="127.0.0.1:8445",
        panel_backend="127.0.0.1:8443",
    )

    assert changed.count("# BEGIN PROXY-CONTROL ROUTES") == 1
    assert "vpn.example.com 127.0.0.1:10443;" in changed
    assert changed.index("mt.example.com") < changed.index("default")
    assert patch_stream_map(
        changed,
        proxy_domain="mt.example.com",
        panel_domain="panel-mt.example.com",
        proxy_backend="127.0.0.1:8445",
        panel_backend="127.0.0.1:8443",
    ) == changed


def test_stream_patch_rejects_ambiguous_or_foreign_owned_input():
    with pytest.raises(InstallerConflict, match="exactly one SNI map"):
        patch_stream_map(
            "map $ssl_preread_server_name $a { default x; }\nmap $ssl_preread_server_name $b { default y; }",
            proxy_domain="mt.example.com", panel_domain="panel.example.com",
            proxy_backend="127.0.0.1:8445", panel_backend="127.0.0.1:8443",
        )
    with pytest.raises(InstallerConflict, match="domain already routed"):
        patch_stream_map(
            "map $ssl_preread_server_name $upstream_443 { mt.example.com 127.0.0.1:9999; default 127.0.0.1:8443; }",
            proxy_domain="mt.example.com", panel_domain="panel.example.com",
            proxy_backend="127.0.0.1:8445", panel_backend="127.0.0.1:8443",
        )


@pytest.mark.parametrize("value", ["", "https://example.com", "bad_name.example.com", "*.example.com", "localhost", "a..b.com"])
def test_domain_validation_rejects_unsafe_values(value):
    with pytest.raises(ValueError):
        validate_domain(value)


def test_domain_validation_normalizes_valid_hostname():
    assert validate_domain("Panel-NL2.Example.COM") == "panel-nl2.example.com"
