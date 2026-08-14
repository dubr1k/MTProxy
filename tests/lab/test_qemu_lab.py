from __future__ import annotations

import importlib.util
import json
import socket
import unittest
from pathlib import Path

MODULE = Path(__file__).parents[2] / "scripts" / "lab" / "qemu_lab.py"
spec = importlib.util.spec_from_file_location("qemu_lab", MODULE)
lab = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(lab)


class QemuLabTests(unittest.TestCase):
    def test_allocate_port_returns_bindable_loopback_port(self):
        port = lab.allocate_port()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))

    def test_qemu_command_is_tcg_isolated_and_bounded(self):
        command = lab.qemu_command(
            Path("disk.qcow2"), Path("seed.img"), Path("lab.key"), 22022, Path("pid"), Path("serial.log")
        )
        rendered = " ".join(command)
        self.assertIn("-accel tcg", rendered)
        self.assertIn("-smp 2", rendered)
        self.assertIn("-m 3072", rendered)
        self.assertIn("restrict=on", rendered)
        self.assertIn("hostfwd=tcp:127.0.0.1:22022-:22", rendered)
        self.assertNotIn("tap", rendered)

    def test_sanitize_removes_proxy_links_and_credentials(self):
        text = "password=hello telemt-api-token=abc tg://proxy?server=x&secret=ee123"
        clean = lab.sanitize(text)
        self.assertNotIn("hello", clean)
        self.assertNotIn("abc", clean)
        self.assertNotIn("ee123", clean)
        self.assertIn("[REDACTED]", clean)

    def test_junit_represents_failure(self):
        xml = lab.junit_xml([{"name": "audit", "status": "passed", "seconds": 1.0}, {"name": "install", "status": "failed", "seconds": 2.0, "message": "boom"}])
        self.assertIn('tests="2"', xml)
        self.assertIn('failures="1"', xml)
        self.assertIn("<failure", xml)

    def test_full_scenario_catalog_covers_lifecycle_and_faults(self):
        names = set(lab.SCENARIOS["full"])
        self.assertTrue({
            "audit", "plan", "install", "repair", "idempotence", "uninstall",
            "interrupted-install-recovery", "interrupted-uninstall-recovery",
            "coexistence", "dns-tls-preflight", "docker-build", "secrets-scan",
        } <= names)

    def test_guest_runner_is_invoked_through_bash_for_archived_mode_bits(self):
        remote = lab.guest_remote("smoke", "a" * 64)
        self.assertIn("sudo bash /tmp/mtproxy-source/scripts/lab/guest-runner.sh", remote)

    def test_pinned_image_metadata_has_sha256(self):
        metadata = json.loads((MODULE.parent / "image.json").read_text())
        self.assertRegex(metadata["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("ubuntu-24.04", metadata["url"])


if __name__ == "__main__":
    unittest.main()
