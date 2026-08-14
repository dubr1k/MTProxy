from __future__ import annotations

import importlib.util
import inspect
import json
import socket
import subprocess
import tempfile
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

    def qemu_command(self, mode):
        return lab.qemu_command(
            Path("disk.qcow2"), Path("seed.img"), Path("lab.key"), 22022,
            Path("pid"), Path("serial.log"), mode,
        )

    def test_smoke_qemu_command_has_no_guest_outbound(self):
        rendered = " ".join(self.qemu_command("smoke"))
        self.assertIn("-accel tcg", rendered)
        self.assertIn("-smp 2", rendered)
        self.assertIn("-m 3072", rendered)
        self.assertIn("restrict=on", rendered)
        self.assertIn("hostfwd=tcp:127.0.0.1:22022-:22", rendered)
        self.assertNotIn("tap", rendered)

    def test_full_qemu_command_uses_user_nat_for_policy_bounded_outbound(self):
        rendered = " ".join(self.qemu_command("full"))
        self.assertIn("restrict=off", rendered)
        self.assertIn("hostfwd=tcp:127.0.0.1:22022-:22", rendered)
        self.assertNotIn("tap", rendered)
        self.assertNotIn("bridge", rendered)

    def test_qemu_command_rejects_missing_or_unknown_mode(self):
        for mode in (None, "", "default", "typo"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.qemu_command(mode)

    def test_full_egress_policy_is_valid_and_rejects_non_public_destinations(self):
        policy = lab.full_egress_policy()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".nft") as stream:
            stream.write(policy)
            stream.flush()
            checked = subprocess.run(["nft", "--check", "--file", stream.name], capture_output=True, text=True)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn("ip daddr 10.0.2.3 udp dport 53 accept", policy)
        self.assertIn("ip daddr 10.0.2.3 tcp dport 53 accept", policy)
        for blocked in ("10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16"):
            self.assertIn(blocked, policy)
        self.assertIn("tcp dport { 80, 443 } accept", policy)
        self.assertLess(policy.index("ct state established,related accept"), policy.index("10.0.0.0/8"))

    def test_full_cloud_init_installs_egress_policy_before_readiness(self):
        user_data = lab.user_data("full", "ssh-ed25519 test")
        self.assertIn("/etc/nftables.d/mtproxy-lab-egress.nft", user_data)
        self.assertLess(user_data.index("nft -f"), user_data.index("lab-ready"))
        self.assertLess(user_data.index("systemctl enable nftables.service"), user_data.index("lab-ready"))

    def test_start_requires_explicit_mode_and_smoke_cloud_init_has_no_egress_policy(self):
        mode = inspect.signature(lab.start).parameters["mode"]
        self.assertIs(mode.default, inspect.Parameter.empty)
        self.assertNotIn("nft -f", lab.user_data("smoke", "ssh-ed25519 test"))
        for invalid in (None, "", "default"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                lab.user_data(invalid, "ssh-ed25519 test")

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

    def test_full_preflight_failure_is_named_and_remaining_scenarios_fail_closed(self):
        results = lab.finalize_results("full", [], returncode=100, elapsed=2.5)
        self.assertEqual(results[0], {
            "name": "environment-preflight", "status": "failed", "seconds": 2.5,
            "message": "guest setup failed before scenarios (exit 100)",
        })
        missing = {item["name"] for item in results if item["message"].startswith("result missing")}
        self.assertEqual(missing, set(lab.SCENARIOS["full"]) - {"environment-preflight"})

    def test_full_scenario_catalog_covers_lifecycle_and_faults(self):
        names = set(lab.SCENARIOS["full"])
        self.assertTrue({
            "environment-preflight", "audit", "plan", "install", "repair", "idempotence", "uninstall",
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
