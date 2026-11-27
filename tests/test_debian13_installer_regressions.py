import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import io
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import common_functions
from test_marketplace_catalog_lifecycle_matrix import InstallerFixture


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(
    os.name == "posix" and shutil.which("bash"),
    "requires POSIX bash",
)
class Debian13InstallerRegressionTests(unittest.TestCase):
    def test_sync_node_global_bins_never_mirrors_system_usr_bin(self):
        helper = common_functions("sync_node_global_bins")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake_usr_bin = root / "usr/bin"
            fake_local_bin = root / "usr/local/bin"
            fake_node_bin = root / "usr/local/nodejs/bin"
            for d in (fake_usr_bin, fake_local_bin, fake_node_bin):
                d.mkdir(parents=True, exist_ok=True)
            (fake_usr_bin / "autoscan").write_text("#!/bin/sh\necho autoconf\n", encoding="utf-8")
            (fake_usr_bin / "autoscan").chmod(0o755)
            (fake_node_bin / "custom-node-cli").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
            (fake_node_bin / "custom-node-cli").chmod(0o755)

            rebased = (
                helper
                .replace('"/usr/local/nodejs/bin"', f'"{fake_node_bin}"')
                .replace('"/usr/local/bin"', f'"{fake_local_bin}"')
                .replace('"/usr/local/bin/${bin_name}"', f'"{fake_local_bin}/${{bin_name}}"')
                .replace('"/usr/bin/${core_bin}"', f'"{fake_usr_bin}/${{core_bin}}"')
                .replace('"/usr/local/bin/${core_bin}"', f'"{fake_local_bin}/${{core_bin}}"')
                .replace('"/usr/local/nodejs/bin/${core_bin}"', f'"{fake_node_bin}/${{core_bin}}"')
                .replace('/usr/bin|/usr/sbin|/usr/local/bin', f'{fake_usr_bin}|/usr/bin|/usr/sbin|{fake_local_bin}|/usr/local/bin')
            )
            script = (
                "set -euo pipefail\n"
                "command_exists() { [[ \"$1\" == npm ]]; }\n"
                f"npm() {{ printf '%s\\n' \"{root}/usr\"; }}\n"
                f"{rebased}\n"
                "sync_node_global_bins\n"
            )
            res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertFalse((fake_local_bin / "autoscan").exists())
            self.assertFalse((fake_local_bin / "autoscan").is_symlink())
            self.assertTrue((fake_local_bin / "custom-node-cli").is_symlink())

    def test_rollback_app_archive_update_skips_disable_for_missing_unit(self):
        helper = common_functions(
            "safe_restore_path_from_backup",
            "safe_rm_rf",
            "quiesce_services_for_rollback",
            "stop_systemd_unit",
            "systemd_unit_inactive",
            "rollback_app_archive_update",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "backup"
            backup.mkdir()
            (backup / ".af-archive-pending").touch()
            dest = root / "usr/local/bin/gitea"
            dest.parent.mkdir(parents=True)
            dest.write_text("staged-binary", encoding="utf-8")
            (root / "etc/systemd/system").mkdir(parents=True)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            sc = fake_bin / "systemctl"
            sc.write_text(
                "#!/bin/bash\n"
                "case \"$1\" in\n"
                "  disable) echo 'Unit gitea.service does not exist' >&2; exit 1 ;;\n"
                "  is-enabled) exit 1 ;;\n"
                "  is-active) exit 3 ;;\n"
                "  show) if [[ \"$*\" == *\"--property=ActiveState\"* ]]; then printf 'LoadState=not-found\\nActiveState=inactive\\nMainPID=0\\nUnitFileState=\\n'; else printf 'LoadState=not-found\\n'; fi; exit 0 ;;\n"
                "  stop) exit 5 ;;\n"
                "  *) exit 0 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            sc.chmod(0o755)
            rebased = helper.replace("/etc/systemd/system/", f"{root}/etc/systemd/system/")
            script = (
                "set -euo pipefail\n"
                "print_error() { printf '[ERROR] %s\\n' \"$*\" >&2; }\n"
                "print_warn() { printf '[WARN] %s\\n' \"$*\" >&2; }\n"
                "log_info() { :; }\n"
                f"{rebased}\n"
                f"AF_ARCHIVE_BACKUP='{backup}'\n"
                f"AF_ARCHIVE_DESTINATION='{dest}'\n"
                "AF_ARCHIVE_UNIT='gitea'\n"
                "AF_ARCHIVE_ACTIVATED=true\n"
                "AF_ARCHIVE_STATE_PATHS=()\n"
                "AF_ARCHIVE_ROLLBACK_RESTART_UNITS=()\n"
                "AF_ARCHIVE_ROLLBACK_HOOK=''\n"
                "AF_ARCHIVE_ARCHIVE=''\n"
                "AF_ARCHIVE_PREVIOUS=false\n"
                "AF_ARCHIVE_STOPPED=false\n"
                "rollback_app_archive_update 1\n"
            )
            env = {**os.environ, "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}", "LOGFILE": "/dev/null"}
            res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=15)
            self.assertEqual(res.returncode, 1)
            self.assertNotIn("incomplete_rollback", res.stdout + res.stderr)
            self.assertFalse((backup / ".af-archive-pending").exists())
            self.assertFalse(dest.exists())

    def test_kasmvnc_accepts_https_401_despite_curl_eof_exit_56(self):
        source = (ROOT / "packages/package/install/installpackage-kasmvnc").read_text(encoding="utf-8")
        probe_start = source.index("READY=false\nREADY_URL=")
        probe_end = source.index("VERSION_FILE=/var/lib/kasmvnc/.af-version", probe_start)
        probe_block = source[probe_start:probe_end]
        emit_start = source.index("if declare -F af_emit_readiness_record", probe_end)
        emit_end = source.index("fi\n", emit_start) + 3
        emit_block = source[emit_start:emit_end]
        emit_helper = common_functions("af_emit_readiness_record")

        with tempfile.TemporaryDirectory() as tmp:
            fake_bin = Path(tmp) / "bin"
            fake_bin.mkdir()
            for name, content in (
                ("systemctl", "#!/bin/bash\nexit 0\n"),
                ("sleep", "#!/bin/bash\nexit 0\n"),
                (
                    "curl",
                    "#!/bin/bash\n"
                    "for arg in \"$@\"; do\n"
                    "  if [[ \"$arg\" == https://* ]]; then\n"
                    "    printf '401'\n"
                    "    exit 56\n"
                    "  fi\n"
                    "done\n"
                    "printf '000'\n"
                    "exit 7\n",
                ),
            ):
                p = fake_bin / name
                p.write_text(content, encoding="utf-8")
                p.chmod(0o755)
            script = (
                "set -euo pipefail\n"
                "APP_PORT=16081\n"
                "print_error() { printf '[ERROR] %s\\n' \"$*\" >&2; }\n"
                f"{emit_helper}\n"
                f"{probe_block}\n"
                f"{emit_block}\n"
            )
            env = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ.get('PATH', '')}",
                "AF_EMIT_READINESS_RECORD": "1",
            }
            res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=15)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            records = [
                json.loads(line.split("=", 1)[1])
                for line in res.stderr.splitlines()
                if line.startswith("__AF_READINESS_PROBE__=")
            ]
            self.assertEqual(
                records,
                [
                    {
                        "unit": "af-kasmvnc.service",
                        "url": "https://127.0.0.1:16081/",
                        "accept_auth": True,
                        "accept_409": False,
                    }
                ],
            )

    def test_gitea_fresh_install_seeds_secrets_and_traversable_receipt_dir(self):
        with InstallerFixture("gitea") as fixture:
            res = fixture.run("install", port=13002)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            app_ini = (fixture.root / "etc/gitea/app.ini").read_text(encoding="utf-8")
            self.assertIn("SECRET_KEY = ", app_ini)
            self.assertIn("INTERNAL_TOKEN = ", app_ini)
            self.assertIn("JWT_SECRET = ", app_ini)
            self.assertIn("LFS_JWT_SECRET = ", app_ini)
            self.assertEqual((fixture.root / "var/lib/gitea").stat().st_mode & 0o777, 0o755)
            self.assertEqual((fixture.root / "var/lib/gitea/data").stat().st_mode & 0o777, 0o700)
            self.assertEqual((fixture.root / "etc/gitea/app.ini").stat().st_mode & 0o777, 0o640)

    def test_kavita_seeds_appsettings_from_init_template_with_port_and_token(self):
        with InstallerFixture("kavita") as fixture:
            binary = (fixture.root / "host-command").read_bytes()
            init_payload = json.dumps(
                {"TokenKey": "super secret unguessable key", "Port": 5000, "IpAddresses": "0.0.0.0,::"}
            ).encode()
            with tarfile.open(fixture.root / "release.tar.gz", "w:gz") as out:
                for dirname in ("Kavita", "Kavita/config"):
                    d = tarfile.TarInfo(dirname)
                    d.type, d.mode = tarfile.DIRTYPE, 0o755
                    out.addfile(d)
                exe = tarfile.TarInfo("Kavita/Kavita")
                exe.mode, exe.size = 0o755, len(binary)
                out.addfile(exe, io.BytesIO(binary))
                init_cfg = tarfile.TarInfo("Kavita/config/appsettings-init.json")
                init_cfg.mode, init_cfg.size = 0o644, len(init_payload)
                out.addfile(init_cfg, io.BytesIO(init_payload))

            res = fixture.run("install", port=15002)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            cfg_path = fixture.root / "opt/Kavita/config/appsettings.json"
            self.assertTrue(cfg_path.is_file())
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            self.assertEqual(cfg["Port"], 15002)
            self.assertEqual(cfg["IpAddresses"], "127.0.0.1")
            self.assertGreaterEqual(len(cfg["TokenKey"]), 64)
            self.assertNotIn("super secret", cfg["TokenKey"].lower())
            self.assertEqual((fixture.root / "opt/Kavita").stat().st_mode & 0o777, 0o755)
            self.assertEqual((fixture.root / "opt/Kavita/config").stat().st_mode & 0o777, 0o700)
            self.assertEqual(cfg_path.stat().st_mode & 0o777, 0o600)

    def test_nextcloud_install_avoids_dev_stdin_and_sets_traversable_receipt_dirs(self):
        with InstallerFixture("nextcloud") as fixture:
            res = fixture.run("install", port=18088)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
            install_cmds = [cmd for cmd in commands if "maintenance:install" in cmd]
            self.assertTrue(install_cmds, commands)
            for cmd in install_cmds:
                self.assertNotIn("/dev/stdin", cmd)
                self.assertNotIn("-f", cmd)
            self.assertEqual((fixture.root / "var/www/nextcloud").stat().st_mode & 0o777, 0o755)
            self.assertEqual((fixture.root / "var/lib/nextcloud").stat().st_mode & 0o777, 0o755)
            self.assertEqual((fixture.root / "var/lib/nextcloud/data").stat().st_mode & 0o777, 0o700)

    def test_scrutiny_installs_influxdb_frontend_and_purges_companion_unit(self):
        with InstallerFixture("scrutiny") as fixture:
            res = fixture.run("install", port=18098)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertTrue((fixture.root / "opt/scrutiny/bin/influxd").is_file())
            self.assertTrue((fixture.root / "opt/scrutiny/web/index.html").is_file())
            influx_unit = (fixture.root / "etc/systemd/system/scrutiny-influxdb.service").read_text(encoding="utf-8")
            self.assertIn("--http-bind-address=127.0.0.1:8086", influx_unit)
            self.assertIn("ExecStartPost=", influx_unit)
            cfg = (fixture.root / "etc/scrutiny/scrutiny.yaml").read_text(encoding="utf-8")
            self.assertIn(f"path: {fixture.root}/opt/scrutiny/web", cfg)
            self.assertIn('host: "127.0.0.1"', cfg)
            self.assertIn("port: 8086", cfg)
            self.assertEqual((fixture.root / "opt/scrutiny").stat().st_mode & 0o777, 0o755)
            self.assertEqual((fixture.root / "var/lib/scrutiny").stat().st_mode & 0o777, 0o755)
            self.assertEqual((fixture.root / "var/lib/scrutiny/influxdb").stat().st_mode & 0o777, 0o700)

            removed = fixture.run("uninstall")
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            self.assertFalse((fixture.root / "etc/systemd/system/scrutiny-influxdb.service").exists())

    def test_autoscan_and_jellyseerr_receipt_permissions(self):
        with InstallerFixture("autoscan") as fixture:
            res = fixture.run("install", port=13030)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual((fixture.root / "opt/autoscan").stat().st_mode & 0o777, 0o755)
            self.assertEqual((fixture.root / "var/lib/autoscan").stat().st_mode & 0o777, 0o755)
            self.assertEqual((fixture.root / "etc/autoscan/config.yml").stat().st_mode & 0o777, 0o640)

        with InstallerFixture("jellyseerr") as fixture:
            res = fixture.run("install", port=15055)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertEqual((fixture.root / "opt/jellyseerr").stat().st_mode & 0o777, 0o755)
            self.assertEqual((fixture.root / "opt/jellyseerr/package.json").stat().st_mode & 0o777, 0o644)


if __name__ == "__main__":
    unittest.main()
