#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "scripts" / "mtproxy-deploy"


class DeployCliTests(unittest.TestCase):
    def run_cli(self, *args, root: Path, check=True):
        env = os.environ.copy()
        env["MTPROXY_TEST_ROOT"] = str(root)
        proc = subprocess.run(
            [sys.executable, str(CLI), *args],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        if check and proc.returncode:
            self.fail(f"command failed ({proc.returncode}): {proc.stderr}\n{proc.stdout}")
        return proc

    def test_render_creates_secret_safe_parameterized_stack(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cover = root / "private-cover.html"
            cover.write_text("<h1>Private cover</h1>\n")
            self.run_cli(
                "render",
                "--domain", "proxy.example.com",
                "--email", "admin@example.com",
                "--users", "phone,laptop",
                "--backend-port", "18445",
                "--cover-file", str(cover),
                root=root,
            )
            install = root / "opt/mtproxy-shared443"
            env_text = (install / ".env").read_text()
            compose = (install / "compose.yaml").read_text()
            secrets = (install / "secrets/users.conf").read_text().splitlines()
            self.assertIn("MTPROXY_DOMAIN=proxy.example.com", env_text)
            self.assertIn("MTPROXY_BACKEND_PORT=18445", env_text)
            self.assertIn("127.0.0.1:${MTPROXY_BACKEND_PORT}:443", compose)
            self.assertNotIn("proxy.example.com", compose)
            self.assertEqual([line.split("=", 1)[0] for line in secrets], ["phone", "laptop"])
            self.assertTrue(all(len(line.split("=", 1)[1]) == 32 for line in secrets))
            self.assertEqual((install / ".env").stat().st_mode & 0o777, 0o600)
            self.assertEqual((install / "secrets/users.conf").stat().st_mode & 0o777, 0o600)
            self.assertTrue((install / "uninstall.sh").is_file())
            self.assertTrue((install / "scripts/check-deployment.sh").is_file())
            self.assertTrue((install / "scripts/mtproxy-deploy").is_file())
            self.assertEqual(
                (root / "var/www/proxy.example.com/index.html").read_text(),
                "<h1>Private cover</h1>\n",
            )

    def test_render_is_idempotent_and_preserves_existing_secrets(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            args = (
                "render", "--domain", "proxy.example.com", "--email", "admin@example.com",
                "--users", "phone,laptop",
            )
            self.run_cli(*args, root=root)
            secret_file = root / "opt/mtproxy-shared443/secrets/users.conf"
            before = secret_file.read_text()
            self.run_cli(*args, root=root)
            self.assertEqual(secret_file.read_text(), before)

    def test_coexist_adds_one_marked_route_and_removes_only_that_route(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            route_file = root / "etc/nginx/stream-conf.d/routes.conf"
            route_file.parent.mkdir(parents=True)
            original = """map $ssl_preread_server_name $backend {\n    old.example 127.0.0.1:9443;\n    default 127.0.0.1:7443;\n}\n"""
            route_file.write_text(original)
            common = (
                "--domain", "proxy.example.com", "--backend-port", "18445",
                "--route-file", "/etc/nginx/stream-conf.d/routes.conf",
            )
            self.run_cli("nginx-add-route", *common, root=root)
            self.run_cli("nginx-add-route", *common, root=root)
            changed = route_file.read_text()
            self.assertEqual(changed.count("BEGIN mtproxy-shared443 proxy.example.com"), 1)
            self.assertIn("proxy.example.com 127.0.0.1:18445;", changed)
            self.assertIn("old.example 127.0.0.1:9443;", changed)
            self.run_cli("nginx-remove-route", "--domain", "proxy.example.com", "--route-file", "/etc/nginx/stream-conf.d/routes.conf", root=root)
            self.assertEqual(route_file.read_text(), original)

    def test_coexist_refuses_domain_collision(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            route_file = root / "etc/nginx/routes.conf"
            route_file.parent.mkdir(parents=True)
            route_file.write_text("map $ssl_preread_server_name $backend {\n proxy.example.com 127.0.0.1:9999;\n default 127.0.0.1:7443;\n}\n")
            proc = self.run_cli(
                "nginx-add-route", "--domain", "proxy.example.com", "--backend-port", "18445",
                "--route-file", "/etc/nginx/routes.conf", root=root, check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("already exists", proc.stderr)
            self.assertNotIn("BEGIN mtproxy-shared443", route_file.read_text())

    def test_coexist_refuses_ambiguous_file_with_multiple_defaults(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            route_file = root / "etc/nginx/routes.conf"
            route_file.parent.mkdir(parents=True)
            route_file.write_text(
                "map $ssl_preread_server_name $a {\n default 127.0.0.1:1;\n}\n"
                "map $other $b {\n default 127.0.0.1:2;\n}\n"
            )
            proc = self.run_cli(
                "nginx-add-route", "--domain", "proxy.example.com", "--backend-port", "18445",
                "--route-file", "/etc/nginx/routes.conf", root=root, check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("exactly one", proc.stderr)
            self.assertNotIn("BEGIN mtproxy-shared443", route_file.read_text())

    def test_fresh_router_rerender_preserves_additional_services(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            args = ("nginx-create-router", "--domain", "proxy.example.com", "--backend-port", "18445")
            self.run_cli(*args, root=root)
            routes = root / "etc/nginx/mtproxy-stream/routes.conf"
            routes.write_text(routes.read_text().replace(
                "default 127.0.0.1:9;", "web.example.com 127.0.0.1:9443;\ndefault 127.0.0.1:9;"
            ))
            self.run_cli(*args, root=root)
            text = routes.read_text()
            self.assertEqual(text.count("BEGIN mtproxy-shared443 proxy.example.com"), 1)
            self.assertIn("web.example.com 127.0.0.1:9443;", text)

    def test_fresh_router_keeps_shared_443_extensible(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.run_cli(
                "nginx-create-router", "--domain", "proxy.example.com", "--backend-port", "18445",
                root=root,
            )
            router = (root / "etc/nginx/mtproxy-stream/router.conf").read_text()
            routes = (root / "etc/nginx/mtproxy-stream/routes.conf").read_text()
            self.assertIn("listen 443 reuseport", router)
            self.assertIn("ssl_preread on", router)
            self.assertIn("include /etc/nginx/mtproxy-stream/routes.conf", router)
            self.assertIn("proxy.example.com 127.0.0.1:18445;", routes)
            self.assertIn("default 127.0.0.1:9;", routes)

    def test_invalid_domain_and_user_names_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for args in [
                ("render", "--domain", "bad/domain", "--email", "a@b.co", "--users", "phone"),
                ("render", "--domain", "proxy.example.com", "--email", "a@b.co", "--users", "bad user"),
            ]:
                proc = self.run_cli(*args, root=root, check=False)
                self.assertNotEqual(proc.returncode, 0)

    def test_state_contains_no_secret_values(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.run_cli(
                "render", "--domain", "proxy.example.com", "--email", "admin@example.com", "--users", "phone",
                root=root,
            )
            install = root / "opt/mtproxy-shared443"
            secret = (install / "secrets/users.conf").read_text().split("=", 1)[1].strip()
            state = json.loads((install / "state.json").read_text())
            self.assertNotIn(secret, json.dumps(state))


if __name__ == "__main__":
    unittest.main(verbosity=2)
