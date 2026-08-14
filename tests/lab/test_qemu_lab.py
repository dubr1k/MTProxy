from __future__ import annotations

import importlib.util
import inspect
import json
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MODULE = Path(__file__).parents[2] / "scripts" / "lab" / "qemu_lab.py"
spec = importlib.util.spec_from_file_location("qemu_lab", MODULE)
lab = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(lab)


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        assert seconds > 0
        self.sleeps.append(seconds)
        self.now += seconds


class QemuLabTests(unittest.TestCase):
    def test_full_install_probes_panel_through_final_tls_sni_route(self):
        runner = (MODULE.parent / "guest-runner.sh").read_text()
        self.assertIn("--resolve \"$PANEL:443:127.0.0.1\"", runner)
        self.assertIn("\"https://$PANEL/healthz\"", runner)
        self.assertIn("jq -e '.status == \"ok\"'", runner)

    def test_fake_certbot_avoids_self_copy_and_populates_each_san_with_source_permissions(self):
        runner = MODULE.parent / "guest-runner.sh"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certbot = root / "certbot"
            generated = subprocess.run(
                ["bash", "-c", f"source {runner!s}; write_fake_certbot {certbot!s}"],
                capture_output=True,
                text=True,
                env={**os.environ, "GUEST_RUNNER_LIB_ONLY": "1"},
            )
            self.assertEqual(generated.returncode, 0, generated.stderr)

            completed = subprocess.run(
                [
                    str(certbot), "certonly",
                    "-d", "proxy.lab.test", "-d", "panel.lab.test",
                    "--cert-name", "proxy.lab.test",
                ],
                capture_output=True,
                text=True,
                env={**os.environ, "LETSENCRYPT_LIVE_ROOT": str(root / "live")},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

            source = root / "live" / "proxy.lab.test"
            panel = root / "live" / "panel.lab.test"
            for filename in ("fullchain.pem", "privkey.pem"):
                self.assertTrue((source / filename).is_file())
                self.assertEqual((source / filename).read_bytes(), (panel / filename).read_bytes())
                self.assertEqual(
                    (source / filename).stat().st_mode & 0o777,
                    (panel / filename).stat().st_mode & 0o777,
                )
            certificate = subprocess.run(
                ["openssl", "x509", "-in", str(source / "fullchain.pem"), "-noout", "-ext", "subjectAltName"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("DNS:proxy.lab.test", certificate.stdout)
            self.assertIn("DNS:panel.lab.test", certificate.stdout)

    def test_case_run_preserves_failure_output_and_does_not_swallow_early_failure(self):
        runner = MODULE.parent / "guest-runner.sh"
        script = f"""
source {runner!s}
fails_early() {{ printf 'first useful error\\n' >&2; false; printf 'must not run\\n' >&2; }}
captured_failure() {{ run_captured /tmp/lab-test-captured.log fails_early; }}
case_run install captured_failure
"""
        completed = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True,
            env={**os.environ, "GUEST_RUNNER_LIB_ONLY": "1"},
        )
        self.assertIn("LAB_RESULT\tinstall\tfailed", completed.stdout)
        self.assertIn("first useful error", completed.stdout)
        self.assertNotIn("must not run", completed.stdout)

    def test_case_run_skips_scenario_when_explicit_prerequisite_failed(self):
        runner = MODULE.parent / "guest-runner.sh"
        script = f"""
source {runner!s}
fails() {{ false; }}
must_not_run() {{ printf 'prerequisite was ignored\\n' >&2; return 0; }}
case_run install fails
case_run repair must_not_run install
"""
        completed = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True,
            env={**os.environ, "GUEST_RUNNER_LIB_ONLY": "1"},
        )
        self.assertIn("LAB_RESULT\trepair\tskipped", completed.stdout)
        self.assertIn("prerequisite failed: install", completed.stdout)
        self.assertNotIn("prerequisite was ignored", completed.stdout)

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

    def test_ssh_command_bounds_connection_and_unresponsive_server(self):
        with mock.patch.object(lab, "_state_port", return_value=22022):
            command = lab.ssh_command("true")
        self.assertIn("BatchMode=yes", command)
        self.assertIn("ConnectTimeout=5", command)
        self.assertIn("ServerAliveInterval=5", command)
        self.assertIn("ServerAliveCountMax=1", command)

    def test_readiness_retries_after_timed_out_probe_and_later_succeeds(self):
        clock = FakeClock()
        probe_timeouts = []

        def probe(command, **kwargs):
            probe_timeouts.append(kwargs["timeout"])
            if len(probe_timeouts) == 1:
                clock.now += kwargs["timeout"]
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            return subprocess.CompletedProcess(command, 0)

        with (
            mock.patch.object(lab.subprocess, "run", side_effect=probe),
            mock.patch.object(lab.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(lab.time, "sleep", side_effect=clock.sleep),
            mock.patch.object(lab, "_state_port", return_value=22022),
        ):
            lab.wait_for_readiness(timeout=30)

        self.assertEqual(probe_timeouts, [10, 10])
        self.assertEqual(clock.sleeps, [5])

    def test_readiness_hung_probes_cannot_exceed_overall_deadline(self):
        clock = FakeClock()
        probe_timeouts = []

        def hung_probe(command, **kwargs):
            probe_timeouts.append(kwargs["timeout"])
            clock.now += kwargs["timeout"]
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])

        with (
            mock.patch.object(lab.subprocess, "run", side_effect=hung_probe),
            mock.patch.object(lab.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(lab.time, "sleep", side_effect=clock.sleep),
            mock.patch.object(lab, "_state_port", return_value=22022),
            self.assertRaisesRegex(TimeoutError, "last SSH readiness probe timed out"),
        ):
            lab.wait_for_readiness(timeout=17)

        self.assertEqual(probe_timeouts, [10, 2])
        self.assertEqual(clock.sleeps, [5])
        self.assertEqual(clock.now, 17)

    def test_readiness_failed_probes_sleep_without_busy_loop_until_deadline(self):
        clock = FakeClock()
        attempts = []

        def failed_probe(command, **kwargs):
            attempts.append(kwargs["timeout"])
            return subprocess.CompletedProcess(command, 255)

        with (
            mock.patch.object(lab.subprocess, "run", side_effect=failed_probe),
            mock.patch.object(lab.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(lab.time, "sleep", side_effect=clock.sleep),
            mock.patch.object(lab, "_state_port", return_value=22022),
            self.assertRaisesRegex(TimeoutError, "last SSH readiness probe exited 255"),
        ):
            lab.wait_for_readiness(timeout=11)

        self.assertEqual(attempts, [10, 6, 1])
        self.assertEqual(clock.sleeps, [5, 5, 1])

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
