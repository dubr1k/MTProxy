from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MITA_SHA256 = "cca7a31e7be692bf10dd5c72f8862b92695a8b06e2a3abcb22ede936e74b2342"


def render_mieru_compose() -> dict:
    env = {
        **os.environ,
        "MIERU_PUBLIC_HOST": "mieru.example.com",
        "MIERU_MITA_BIN": "/opt/pinned/mita",
        "MIERU_MITA_SHA256": MITA_SHA256,
        "MIERU_MITA_GID": "321",
        "MTPROXY_DOMAIN": "mt.example.com",
        "MTPROXY_BACKEND_PORT": "8445",
        "MTPROXY_COVER_ROOT": "/tmp",
    }
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "compose.yaml",
            "-f",
            "compose.mieru.yaml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_mieru_overlay_supplies_pinned_host_binary_and_read_only_uds_access():
    config = render_mieru_compose()
    manager = config["services"]["mieru-manager"]
    mounts = {item["target"]: item for item in manager["volumes"]}

    assert mounts["/usr/bin/mita"] == {
        "type": "bind",
        "source": "/opt/pinned/mita",
        "target": "/usr/bin/mita",
        "read_only": True,
        "bind": {},
    }
    assert mounts["/run/mita"]["read_only"] is True
    assert manager["group_add"] == ["321"]
    assert manager["environment"]["MIERU_MITA_SHA256"] == MITA_SHA256
    assert manager["read_only"] is True
    assert manager["cap_drop"] == ["ALL"]
    assert manager["healthcheck"]["test"] == [
        "CMD",
        "python",
        "-m",
        "mieru_manager.healthcheck",
    ]
    assert config["services"]["panel"]["depends_on"]["mieru-manager"]["condition"] == "service_healthy"


def test_mieru_overlay_has_only_intended_writable_runtime_mounts():
    manager = render_mieru_compose()["services"]["mieru-manager"]
    writable_targets = {
        item["target"] for item in manager["volumes"] if not item.get("read_only", False)
    }
    assert writable_targets == {"/var/lib/mieru-manager", "/run/mieru-manager"}
    assert manager["tmpfs"] == ["/tmp:size=8m,mode=0700"]
    assert manager["pids_limit"] == 128
