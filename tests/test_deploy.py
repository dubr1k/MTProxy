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
    def test_naive_caddy_unit_and_compose_preserve_least_privilege_log_contract(self):
        unit = (ROOT / "deploy/caddy-naive.service").read_text()
        compose = (ROOT / "compose.naive.yaml").read_text()
        checker = (ROOT / "scripts/check-naive-caddy-build.sh").read_text()
        self.assertIn("User=naive-caddy", unit)
        self.assertIn("Group=naive-accounting", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("RuntimeDirectory=caddy-naive", unit)
        self.assertIn("RuntimeDirectoryMode=0700", unit)
        self.assertIn("ProtectProc=invisible", unit)
        self.assertIn("ProcSubset=pid", unit)
        self.assertIn(
            "ExecStartPre=+/usr/bin/install -o 10003 -g 10004 -m 0400 "
            "/var/lib/naive-manager/Caddyfile /run/caddy-naive/Caddyfile",
            unit,
        )
        self.assertIn(
            "ExecReload=+/usr/bin/install -o 10003 -g 10004 -m 0400 "
            "/var/lib/naive-manager/Caddyfile /run/caddy-naive/Caddyfile",
            unit,
        )
        self.assertIn("--config /run/caddy-naive/Caddyfile", unit)
        self.assertIn("ReadWritePaths=/var/log/naive-proxy /run/caddy-naive", unit)
        self.assertIn("InaccessiblePaths=/var/lib/naive-manager", unit)
        self.assertNotIn("User=root", unit)
        self.assertNotIn("--config /var/lib/naive-manager/Caddyfile", unit)
        self.assertIn('user: "10002:101"', compose)
        self.assertIn("group_add:\n      - \"10004\"", compose)
        self.assertIn("/var/log/naive-proxy:/logs:ro", compose)
        self.assertIn("v2.11.4", checker)
        self.assertIn("http.handlers.forward_proxy", checker)
        self.assertIn("h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0=", checker)
        self.assertTrue(os.access(ROOT / "scripts/check-naive-caddy-build.sh", os.X_OK))

    @unittest.skipUnless(os.geteuid() == 0, "numeric permission behavior requires root")
    def test_naive_log_permissions_allow_caddy_write_and_manager_read_only(self):
        """Catch shared UID/GID or writable-group regressions with real kernel checks."""
        with tempfile.TemporaryDirectory(dir="/tmp") as td:
            root = Path(td)
            root.chmod(0o755)
            log_dir = root / "naive-proxy"
            log_dir.mkdir(mode=0o750)
            os.chown(log_dir, 10003, 10004)
            access = log_dir / "access.json"
            access.write_text("record\n")
            os.chown(access, 10003, 10004)
            access.chmod(0o640)

            def attempt(uid, gid, groups, script):
                def demote():
                    os.setgroups(groups)
                    os.setgid(gid)
                    os.setuid(uid)
                return subprocess.run(
                    [sys.executable, "-c", script, str(access)],
                    text=True,
                    capture_output=True,
                    preexec_fn=demote,
                )

            self.assertEqual(
                attempt(10003, 10003, [10004], "import pathlib,sys; pathlib.Path(sys.argv[1]).open('a').write('caddy\\n')").returncode,
                0,
            )
            manager_read = attempt(10002, 101, [10004], "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())")
            self.assertEqual(manager_read.returncode, 0, manager_read.stderr)
            manager_write = attempt(10002, 101, [10004], "import pathlib,sys; pathlib.Path(sys.argv[1]).open('a').write('manager\\n')")
            self.assertNotEqual(manager_write.returncode, 0)
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
            self.assertTrue((install / "panel/Dockerfile").is_file())
            api_token = (install / "secrets/telemt-api-token").read_text().strip()
            self.assertTrue(api_token.startswith("Bearer "))
            self.assertEqual((install / "secrets/telemt-api-token").stat().st_mode & 0o777, 0o600)
            self.assertNotIn(api_token, (install / "state.json").read_text())
            self.assertTrue((install / ".mtproxy-owned").is_file())
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

    def test_coexist_preserves_mode_and_edits_symlink_target(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            canonical = root / "etc/nginx/available/routes.conf"
            canonical.parent.mkdir(parents=True)
            canonical.write_text("map $ssl_preread_server_name $backend {\n default 127.0.0.1:7443;\n}\n")
            canonical.chmod(0o640)
            enabled = root / "etc/nginx/enabled/routes.conf"
            enabled.parent.mkdir(parents=True)
            enabled.symlink_to(canonical)
            self.run_cli(
                "nginx-add-route", "--domain", "proxy.example.com", "--backend-port", "18445",
                "--route-file", "/etc/nginx/enabled/routes.conf", root=root,
            )
            self.assertTrue(enabled.is_symlink())
            self.assertIn("proxy.example.com 127.0.0.1:18445;", canonical.read_text())
            self.assertEqual(canonical.stat().st_mode & 0o777, 0o640)

    def test_render_refuses_unowned_nonempty_install_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            install = root / "opt/mtproxy-shared443"
            install.mkdir(parents=True)
            (install / "foreign.txt").write_text("do not overwrite")
            proc = self.run_cli(
                "render", "--domain", "proxy.example.com", "--email", "admin@example.com", "--users", "phone",
                root=root, check=False,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("not owned", proc.stderr)
            self.assertEqual((install / "foreign.txt").read_text(), "do not overwrite")

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


    def test_fleet_ingress_compose_uses_tls_key_owner_identity(self):
        env = {
            **os.environ,
            "FLEET_SERVER_CERT": "/tmp/server.crt",
            "FLEET_SERVER_KEY": "/tmp/server.key",
            "FLEET_CLIENT_CA": "/tmp/client-ca.crt",
        }
        proc = subprocess.run(
            ["docker", "compose", "-f", "compose.fleet-central.yaml", "config", "--format", "json"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        if proc.returncode:
            self.fail(f"compose render failed ({proc.returncode}): {proc.stderr}")
        service = json.loads(proc.stdout)["services"]["fleet-ingress"]
        self.assertEqual(service["user"], "10001:10001")

    def test_host_fleet_ingress_root_stages_certbot_key_for_panel(self):
        env_file = ROOT / "deploy/fleet-ingress.env.example"
        values = dict(
            line.split("=", 1)
            for line in env_file.read_text().splitlines()
            if line and not line.startswith("#")
        )
        self.assertEqual(
            values["FLEET_SERVER_KEY_SOURCE"],
            "/etc/letsencrypt/live/fleet.example.com/privkey.pem",
        )
        self.assertEqual(
            values["FLEET_SERVER_CERT_SOURCE"],
            "/etc/letsencrypt/live/fleet.example.com/fullchain.pem",
        )
        self.assertEqual(values["FLEET_SERVER_KEY"], "/run/mtproxy-fleet-ingress/server.key")
        self.assertEqual(values["FLEET_SERVER_CERT"], "/run/mtproxy-fleet-ingress/server.crt")

        unit_text = (ROOT / "deploy/mtproxy-fleet-ingress.service").read_text()
        self.assertIn("RuntimeDirectory=mtproxy-fleet-ingress", unit_text)
        self.assertIn("RuntimeDirectoryMode=0700", unit_text)
        self.assertIn(
            "ExecStartPre=+/usr/bin/install -o panel -g panel -m 0400 "
            "${FLEET_SERVER_KEY_SOURCE} /run/mtproxy-fleet-ingress/server.key",
            unit_text,
        )
        self.assertIn(
            "ExecStartPre=+/usr/bin/install -o panel -g panel -m 0444 "
            "${FLEET_SERVER_CERT_SOURCE} /run/mtproxy-fleet-ingress/server.crt",
            unit_text,
        )

        with tempfile.TemporaryDirectory() as td:
            unit = Path(td) / "mtproxy-fleet-ingress.service"
            unit.write_text(unit_text.replace(
                "/opt/mtproxy-panel/venv/bin/python -m panel.agent_ingress", "/bin/true"
            ))
            verified = subprocess.run(
                ["systemd-analyze", "verify", str(unit)], text=True, capture_output=True
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
