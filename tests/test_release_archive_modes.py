"""Exercise both release packagers with fixed binaries and varying checkout modes."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix" and shutil.which("tar") and shutil.which("gzip"),
                     "requires POSIX tar and gzip")
class ReleaseArchiveModesTests(unittest.TestCase):
    def test_gold_and_ci_archives_ignore_checkout_and_caller_permissions(self):
        with tempfile.TemporaryDirectory(prefix="af-archive-modes-") as temporary:
            root = Path(temporary)
            source = root / "source"
            executable_names = {
                "./aetherflow-api", "./bin/af", "./bin/af-transcode",
                "./deploy/release-manager.sh", "./deploy/verify-provenance.py",
                "./deploy/log-retention.py", "./packages/example/install.sh",
                "./plugins/telemetry-inspector/backend/hooks/start.sh",
            }
            fixture_files = {
                "scripts/build_gold.sh": (ROOT / "scripts/build_gold.sh").read_bytes(),
                "backend-rs/Cargo.toml": b"[workspace]\n",
                "backend-rs/Cargo.lock": b"# fixed fixture lock\n",
                "backend-rs/crates/af-cli/Cargo.toml": b"[package]\n",
                "backend-rs/crates/af-transcode/Cargo.toml": b"[package]\n",
                ".version": b"v4.0.0\n",
                "web/dist/index.html": b"<!doctype html><title>Fixture</title>\n",
                "web/dist/app.wasm": b"\x00asm\x01\x00\x00\x00",
                "web/dist/.keep": b"",
                "web/dist/locales/en.json": b"{}\n",
                "config/example.yml": b"fixture: true\n",
                "config/openapi-v1.yaml": b"openapi: 3.1.0\n",
                "deploy/systemd/example.service": b"[Unit]\nDescription=Fixture\n",
                "deploy/release-manager.sh": b"#!/bin/sh\nexit 0\n",
                "deploy/verify-provenance.py": b"#!/usr/bin/python3\n",
                "deploy/log-retention.py": b"#!/usr/bin/python3\n",
                "packages/example/install.sh": b"#!/bin/sh\nexit 0\n",
                "plugins/telemetry-inspector/plugin.manifest.json": b'{"id":"telemetry-inspector"}\n',
                "plugins/telemetry-inspector/backend/hooks/start.sh": b"#!/usr/bin/env bash\nexit 0\n",
                "plugins/telemetry-inspector/backend/runtime.py": b"print('ok')\n",
                "plugins/telemetry-inspector/frontend/dist/index.html": b"<!doctype html><title>Plugin</title>\n",
                "backend-rs/target/release/aetherflow-api": b"fixed api fixture\n",
                "backend-rs/target/release/af": b"fixed cli fixture\n",
                "backend-rs/target/release/af-transcode": b"fixed transcode fixture\n",
                "backend-rs/target/x86_64-unknown-linux-gnu/release/aetherflow-api": b"fixed api fixture\n",
                "backend-rs/target/x86_64-unknown-linux-gnu/release/af": b"fixed cli fixture\n",
                "backend-rs/target/x86_64-unknown-linux-gnu/release/af-transcode": b"fixed transcode fixture\n",
            }
            for name, content in fixture_files.items():
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            tool_bin = root / "tools"
            tool_bin.mkdir()
            # Only tool discovery and Cargo are stubbed. Packaging remains real.
            (tool_bin / "cargo").write_text(
                '#!/bin/sh\nprintf "%s\\n" "${RUSTFLAGS-}" >> "$FIXTURE_LINK_FLAGS"\n'
            )
            (tool_bin / "cargo").chmod(0o755)
            bash_env = root / "without-mold.sh"
            bash_env.write_text(
                'command() { if [[ "$*" == "-v mold" ]]; then return 1; fi; builtin command "$@"; }\n'
            )
            link_flags = root / "link-flags.log"
            workflow = (ROOT / ".github/workflows/release.yml").read_text()
            package_step = textwrap.dedent(workflow.split(
                "      - name: Package Release Tarball & SHA-256 Manifest\n        run: |\n", 1
            )[1].split("\n      - name:", 1)[0])
            env = {key: value for key, value in os.environ.items() if key not in {
                "FRONTEND_DIST_DIR", "EMBED_DIST_DIR", "BACKEND_RS_DIR", "BACKEND_DIR",
                "CONFIG_DIR", "PLUGINS_DIR", "CARGO_BUILD_TARGET", "BUILD_DATE", "BINARY_NAME",
                "CLI_BINARY_NAME", "CARGO_BIN_NAME", "CARGO_CLI_BIN_NAME", "VERSION_FILE",
                "TRANSCODE_BINARY_NAME", "CARGO_TRANSCODE_BIN_NAME", "BUILD_TRANSCODE",
                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
            }}
            env.update({
                "PATH": str(tool_bin) + os.pathsep + os.environ["PATH"],
                "BUILD_FRONTEND": "0", "RUN_TESTS": "0", "PACKAGE_RELEASE": "1",
                "BUILD_CLI": "1", "BUILD_TRANSCODE": "1", "CARGO_LOCKED": "1", "TARGETS": "amd64",
                "CARGO_TARGET_DIR": str(source / "backend-rs/target"),
                "SOURCE_DATE_EPOCH": "1700000000", "GIT_COMMIT": "fixed",
                "VERSION": "v4.0.0", "VERSION_STAMP": "v4.0.0",
                "GITHUB_ENV": str(root / "github-env"), "TMPDIR": str(root),
                "FIXTURE_LINK_FLAGS": str(link_flags),
            })
            hashes = set()
            for regular_mode, executable_mode, caller_umask in (
                (0o664, 0o775, "0002"), (0o644, 0o755, "0022"),
                (0o600, 0o700, "0077"), (0o6664, 0o7775, "0000"),
            ):
                for path in sorted(source.rglob("*")):
                    relative = "./" + path.relative_to(source).as_posix()
                    is_executable = relative in executable_names or path.name in {"aetherflow-api", "af", "af-transcode"}
                    path.chmod(executable_mode if path.is_dir() or is_executable else regular_mode)
                    os.utime(path, (1700000001 + regular_mode, 1700000001 + regular_mode))
                source.chmod(executable_mode)
                for packager in ("gold", "ci"):
                    with self.subTest(packager=packager, source_mode=oct(regular_mode), umask=caller_umask):
                        output = root / (packager + caller_umask)
                        if packager == "gold":
                            command = ['bash', '-c', 'umask "$1"; exec bash "$2"',
                                       'archive-mode-test', caller_umask, str(source / "scripts/build_gold.sh")]
                            archive_path = output / "aetherflow-linux-amd64.tar.gz"
                            link_flags.write_text("")
                            run_env = {
                                **env, "OUTPUT_DIR": str(output), "BASH_ENV": str(bash_env),
                                "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "-C debuginfo=1",
                                "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "-C debuginfo=1",
                            }
                        else:
                            command = ['bash', '-c', 'umask "$1"\n' + package_step,
                                       'archive-mode-test', caller_umask]
                            archive_path = source / "release-dist/aetherflow-linux-amd64.tar.gz"
                            run_env = env
                        result = subprocess.run(command, cwd=source, env=run_env,
                                                capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                        if packager == "gold":
                            self.assertEqual(
                                link_flags.read_text().splitlines(),
                                ["-C link-arg=-fuse-ld=bfd -C debuginfo=1"],
                            )
                        hashes.add(hashlib.sha256(archive_path.read_bytes()).hexdigest())
                        with tarfile.open(archive_path) as archive:
                            members = archive.getmembers()
                            self.assertTrue(members)
                            member_names = {member.name for member in members}
                            self.assertTrue(executable_names.issubset(member_names))
                            self.assertIn("./config/example.yml", member_names)
                            self.assertNotIn("./config/openapi-v1.yaml", member_names)
                            self.assertNotIn("./web/dist/.keep", member_names)
                            for member in members:
                                self.assertTrue(member.isdir() or member.isfile(), member.name)
                                expected_mode = 0o755 if member.isdir() or member.name in executable_names else 0o644
                                self.assertEqual(member.mode, expected_mode, member.name)
                                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 1700000000))
            self.assertEqual(len(hashes), 1, "packagers and checkout modes must produce identical archives")


if __name__ == "__main__":
    unittest.main()
