#!/usr/bin/env python3
"""Regression tests for Marketplace archive safety, umask 077 permissions, and installer cleanup."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import common_functions

ROOT = Path(__file__).resolve().parents[1]
INSTALL_DIR = ROOT / "packages/package/install"


def write_tar(path: Path, entries: list[tuple[str, str, bytes | str]], mode: str = "w:gz") -> None:
    """Build a tar archive with explicit member kinds: file, dir, symlink, hardlink, fifo, chr."""
    with tarfile.open(path, mode) as tf:
        for name, kind, payload in entries:
            info = tarfile.TarInfo(name)
            if kind == "file":
                data = payload if isinstance(payload, bytes) else payload.encode("utf-8")
                info.type = tarfile.REGTYPE
                info.mode = 0o755 if name.endswith((".sh", "node", "crystal", "vaultwarden", "Requestrr.WebApi", "invidious_companion")) else 0o644
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            elif kind == "dir":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                tf.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = str(payload)
                tf.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = str(payload)
                tf.addfile(info)
            elif kind == "fifo":
                info.type = tarfile.FIFOTYPE
                tf.addfile(info)
            elif kind == "chr":
                info.type = tarfile.CHRTYPE
                info.devmajor = 1
                info.devminor = 3
                tf.addfile(info)
            else:
                raise ValueError(f"Unsupported kind: {kind}")


class TarArchiveValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="af-tar-hardening-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.helper_script = self.root / "helpers.sh"
        self.helper_script.write_text(
            "set -euo pipefail\n"
            "log_error() { printf '[ERROR] %s\\n' \"$*\" >&2; }\n"
            "print_error() { printf '[ERROR] %s\\n' \"$*\" >&2; }\n"
            + common_functions("af_validate_tar_archive", "af_validate_tar_archive_allow_intra_symlinks", "install_binary_atomic", "af_extract_zip_archive"),
            encoding="utf-8",
        )

    def run_bash(self, body: str, **extra_env: str) -> subprocess.CompletedProcess:
        cmd = f'source "{self.helper_script}"\n{body}\n'
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", cmd],
            env={**os.environ, **extra_env},
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_strict_mode_accepts_regular_entries_and_rejects_all_symlinks_traversal_and_specials(self):
        good = self.root / "good.tar.gz"
        write_tar(good, [(".", "dir", b""), ("bin/app", "file", b"ok")])
        res = self.run_bash(f'af_validate_tar_archive "{good}"')
        self.assertEqual(res.returncode, 0, res.stderr)

        bad_cases = {
            "empty": [],
            "absolute": [("/etc/passwd", "file", b"bad")],
            "traversal": [("a/../../escape", "file", b"bad")],
            "benign_symlink_rejected_in_strict": [
                ("node/lib/npm.js", "file", b"ok"),
                ("node/bin/npm", "symlink", "../lib/npm.js"),
            ],
            "hardlink": [("a", "file", b"ok"), ("b", "hardlink", "a")],
            "fifo": [("pipe", "fifo", b"")],
            "char_device": [("null", "chr", b"")],
        }
        for label, entries in bad_cases.items():
            with self.subTest(case=label):
                archive = self.root / f"strict-{label}.tar.gz"
                write_tar(archive, entries)
                res = self.run_bash(f'af_validate_tar_archive "{archive}"')
                self.assertNotEqual(res.returncode, 0, f"Expected strict rejection for {label}")

        link = self.root / "symlinked.tar.gz"
        link.symlink_to(good)
        res_link = self.run_bash(f'af_validate_tar_archive "{link}"')
        self.assertNotEqual(res_link.returncode, 0)

    def test_intra_symlink_mode_accepts_node_and_crystal_symlinks_and_rejects_escapes(self):
        node_tar = self.root / "node.tar.xz"
        write_tar(
            node_tar,
            [
                ("node-v22.23.4-linux-x64", "dir", b""),
                ("node-v22.23.4-linux-x64/bin/node", "file", b"node-bin"),
                ("node-v22.23.4-linux-x64/lib/node_modules/npm/bin/npm-cli.js", "file", b"npm"),
                ("node-v22.23.4-linux-x64/bin/npm", "symlink", "../lib/node_modules/npm/bin/npm-cli.js"),
                ("node-v22.23.4-linux-x64/bin/npx", "symlink", "../lib/node_modules/npm/bin/npx-cli.js"),
            ],
            mode="w:xz",
        )
        res_flag = self.run_bash(f'af_validate_tar_archive --allow-intra-symlinks --strip-components=1 "{node_tar}"')
        self.assertEqual(res_flag.returncode, 0, res_flag.stderr)
        res_wrapper = self.run_bash(f'af_validate_tar_archive_allow_intra_symlinks --strip-components=1 "{node_tar}"')
        self.assertEqual(res_wrapper.returncode, 0, res_wrapper.stderr)

        # Same archive MUST fail strict mode
        res_strict = self.run_bash(f'af_validate_tar_archive "{node_tar}"')
        self.assertNotEqual(res_strict.returncode, 0)

        crystal_tar = self.root / "crystal.tar.gz"
        write_tar(
            crystal_tar,
            [
                ("crystal-1.22.2-1", "dir", b""),
                ("crystal-1.22.2-1/share/crystal/bin/crystal", "file", b"bin"),
                ("crystal-1.22.2-1/bin/crystal", "symlink", "../share/crystal/bin/crystal"),
                ("crystal-1.22.2-1/embedded/lib/libgc.so.1", "file", b"so"),
                ("crystal-1.22.2-1/embedded/lib/libgc.so", "symlink", "libgc.so.1"),
            ],
        )
        res_crystal = self.run_bash(f'af_validate_tar_archive --allow-intra-symlinks --strip-components=1 "{crystal_tar}"')
        self.assertEqual(res_crystal.returncode, 0, res_crystal.stderr)

        reject_cases = {
            "absolute_symlink": [
                ("top/bin/evil", "symlink", "/etc/passwd"),
            ],
            "strip_aware_escape": [
                # Looks safe before stripping top/, escapes extraction root after --strip-components=1!
                ("top/bin/escape", "symlink", "../../etc/passwd"),
            ],
            "root_level_escape": [
                ("top/escape", "symlink", "../outside"),
            ],
            "chained_escape": [
                ("top/a/up", "symlink", ".."),
                ("top/a/escape", "symlink", "up/.."),
            ],
            "cyclic_symlink": [
                ("top/a/link1", "symlink", "link2"),
                ("top/a/link2", "symlink", "link1"),
            ],
            "entry_through_symlink_ancestor": [
                ("top/sub", "dir", b""),
                ("top/alias", "symlink", "sub"),
                ("top/alias/pwn", "file", b"x"),
            ],
            "hardlink_still_rejected": [
                ("top/bin/a", "file", b"ok"),
                ("top/bin/b", "hardlink", "top/bin/a"),
            ],
            "fifo_still_rejected": [
                ("top/bin/p", "fifo", b""),
            ],
            "device_still_rejected": [
                ("top/bin/d", "chr", b""),
            ],
            "traversal_name_still_rejected": [
                ("top/../../evil", "file", b"x"),
            ],
        }
        for label, entries in reject_cases.items():
            with self.subTest(case=label):
                archive = self.root / f"intra-bad-{label}.tar.gz"
                write_tar(archive, entries)
                res = self.run_bash(f'af_validate_tar_archive --allow-intra-symlinks --strip-components=1 "{archive}"')
                self.assertNotEqual(res.returncode, 0, f"Expected intra-symlink rejection for {label}")

    def test_install_binary_atomic_creates_0755_parent_dirs_under_umask_077(self):
        src = self.root / "source-bin"
        src.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
        dst = self.root / "fresh-root/sub/bin/tool"
        res = self.run_bash(f'umask 077; install_binary_atomic "{src}" "{dst}"')
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(stat.S_IMODE(dst.stat().st_mode), 0o755)
        for parent in (self.root / "fresh-root", self.root / "fresh-root/sub", self.root / "fresh-root/sub/bin"):
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755, f"Parent {parent} must be 0755 under umask 077")

    def test_git_stage_exact_revision_rejects_option_injection_and_negative_build_dir(self):
        script = (
            "set -euo pipefail\n"
            "print_error() { printf '[ERROR] %s\\n' \"$*\" >&2; }\n"
            + common_functions("git_stage_exact_revision")
        )
        helper = self.root / "git-stage.sh"
        helper.write_text(script, encoding="utf-8")
        for repo, build_dir, target in (
            ("--upload-pack=id", str(self.root / "b1"), "v1.0.0"),
            ("https://example.invalid/repo.git", "-bad-dir", "v1.0.0"),
            ("https://example.invalid/repo.git", str(self.root / "b2"), "--upload-pack=id"),
        ):
            with self.subTest(repo=repo, build_dir=build_dir, target=target):
                res = subprocess.run(
                    ["bash", "-c", f'source "{helper}"; git_stage_exact_revision "$1" "$2" "$3"', "_", repo, build_dir, target],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(res.returncode, 0)

    def test_node_tarball_validation_in_jellyseerr_palate_and_maintainerr_rejects_escaping_symlinks_with_valid_sha256(self):
        # Verify the exact validation + extraction lines used by jellyseerr/palate/maintainerr accept benign
        # Node intra-root symlinks and reject escaping symlinks even when SHA-256 matches.
        good_node = self.root / "node-v22.23.4-linux-x64.tar.xz"
        write_tar(
            good_node,
            [
                ("node-v22.23.4-linux-x64/bin/node", "file", b"node"),
                ("node-v22.23.4-linux-x64/lib/node_modules/npm/bin/npm-cli.js", "file", b"npm"),
                ("node-v22.23.4-linux-x64/bin/npm", "symlink", "../lib/node_modules/npm/bin/npm-cli.js"),
            ],
            mode="w:xz",
        )
        out_good = self.root / "runtime-good"
        out_good.mkdir()
        r_good = self.run_bash(
            f'af_validate_tar_archive --allow-intra-symlinks --strip-components=1 "{good_node}" && '
            f'tar -xJf "{good_node}" --strip-components=1 --no-same-owner --no-same-permissions -C "{out_good}"'
        )
        self.assertEqual(r_good.returncode, 0, r_good.stderr)
        self.assertTrue((out_good / "bin/npm").is_symlink())
        self.assertEqual(os.readlink(out_good / "bin/npm"), "../lib/node_modules/npm/bin/npm-cli.js")

        bad_node = self.root / "node-v22.23.4-bad.tar.xz"
        write_tar(
            bad_node,
            [
                ("node-v22.23.4-linux-x64/bin/node", "file", b"node"),
                ("node-v22.23.4-linux-x64/bin/escape", "symlink", "../../etc/passwd"),
            ],
            mode="w:xz",
        )
        out_bad = self.root / "runtime-bad"
        out_bad.mkdir()
        r_bad = self.run_bash(
            f'af_validate_tar_archive --allow-intra-symlinks --strip-components=1 "{bad_node}" && '
            f'tar -xJf "{bad_node}" --strip-components=1 --no-same-owner --no-same-permissions -C "{out_bad}"'
        )
        self.assertNotEqual(r_bad.returncode, 0)
        self.assertEqual(list(out_bad.iterdir()), [])


class VaultwardenOciValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="af-vw-oci-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        source = (INSTALL_DIR / "installpackage-vaultwarden").read_text(encoding="utf-8")
        # Extract the exact validation + extraction block inside the layer loop
        start = source.index('    python3 - "$BLOB_FILE" "$MEMBER_LIST"')
        end = source.index('    rm -f -- "$BLOB_FILE" "$MEMBER_LIST"', start)
        self.block = source[start:end]

    def run_layer_extract(self, blob: Path, extract_dir: Path) -> subprocess.CompletedProcess:
        script = f"""
set -euo pipefail
TMP_EXTRACT={str(extract_dir)!r}
BLOB_FILE={str(blob)!r}
MEMBER_LIST="$TMP_EXTRACT/layer-members.nul"
{self.block}
"""
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=20)

    def test_accepts_base_layer_with_os_symlinks_and_app_layer_with_regular_vaultwarden_and_web_vault(self):
        extract_dir = self.root / "extract"
        extract_dir.mkdir()

        # Layer 1: Debian base layer containing OS symlinks/devices outside vaultwarden/web-vault
        base_layer = self.root / "base.tar.gz"
        write_tar(base_layer, [
            ("bin", "symlink", "usr/bin"),
            ("dev/null", "chr", b""),
            ("usr/bin/sh", "file", b"sh"),
        ])
        r1 = self.run_layer_extract(base_layer, extract_dir)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        self.assertFalse((extract_dir / "usr").exists())
        self.assertFalse((extract_dir / "bin").exists())

        # Layer 2: App layer containing ./vaultwarden and ./web-vault/
        app_layer = self.root / "app.tar.gz"
        write_tar(app_layer, [
            ("./vaultwarden", "file", b"vw-elf"),
            ("./web-vault", "dir", b""),
            ("./web-vault/index.html", "file", b"<html>vault</html>"),
        ])
        r2 = self.run_layer_extract(app_layer, extract_dir)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        self.assertEqual((extract_dir / "vaultwarden").read_bytes(), b"vw-elf")
        self.assertEqual((extract_dir / "web-vault/index.html").read_bytes(), b"<html>vault</html>")

    def test_rejects_malicious_vaultwarden_or_web_vault_members_before_extraction(self):
        cases = {
            "vaultwarden_symlink": [("vaultwarden", "symlink", "/bin/sh")],
            "vaultwarden_dir": [("vaultwarden", "dir", b"")],
            "vaultwarden_hardlink": [("usr/bin/a", "file", b"x"), ("vaultwarden", "hardlink", "usr/bin/a")],
            "web_vault_symlink": [("web-vault/index.html", "symlink", "/etc/shadow")],
            "web_vault_traversal": [("web-vault/../../etc/pwn", "file", b"bad")],
            "web_vault_device": [("web-vault/dev", "chr", b"")],
            "web_vault_fifo": [("web-vault/pipe", "fifo", b"")],
            "absolute_vaultwarden": [("/vaultwarden", "file", b"bad")],
            "traversal_into_vaultwarden": [("foo/../vaultwarden", "file", b"bad")],
        }
        for label, entries in cases.items():
            with self.subTest(case=label):
                extract_dir = self.root / f"extract-{label}"
                extract_dir.mkdir()
                blob = self.root / f"{label}.tar.gz"
                write_tar(blob, entries)
                res = self.run_layer_extract(blob, extract_dir)
                self.assertNotEqual(res.returncode, 0, f"Expected rejection for {label}")
                self.assertEqual(list(extract_dir.glob("vaultwarden*")), [])
                self.assertEqual(list(extract_dir.glob("web-vault*")), [])


class Umask077ReadabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="af-umask-hardening-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_transmission_web_ui_is_world_readable_and_traversable_under_umask_077(self):
        source = (INSTALL_DIR / "installpackage-transmission").read_text(encoding="utf-8")
        start = source.index('        if [[ -d "${TMP_TWC}/src" ]]; then')
        end = source.index('        fi\n    fi\n    rm -rf -- "$TMP_TWC"', start) + len("        fi")
        block = source[start:end].replace("/usr/share/transmission/web", str(self.root / "usr/share/transmission/web"))

        tmp_twc = self.root / "tmp-twc"
        script = f"""
set -euo pipefail
umask 077
TMP_TWC={str(tmp_twc)!r}
mkdir -p "$TMP_TWC/src/tr-web-control/script"
printf '<html>ui</html>\\n' > "$TMP_TWC/src/index.html"
printf 'console.log(1);\\n' > "$TMP_TWC/src/tr-web-control/script/app.js"
{block}
"""
        res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=15)
        self.assertEqual(res.returncode, 0, res.stderr)

        tx_parent = self.root / "usr/share/transmission"
        web_dir = tx_parent / "web"
        nested_dir = web_dir / "tr-web-control/script"
        index_html = web_dir / "index.html"
        app_js = nested_dir / "app.js"

        self.assertEqual(stat.S_IMODE(tx_parent.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(web_dir.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(nested_dir.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(index_html.stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(app_js.stat().st_mode), 0o644)

    def test_dispatcharr_collectstatic_outputs_are_readable_by_service_user_under_umask_077(self):
        source = (INSTALL_DIR / "installpackage-dispatcharr").read_text(encoding="utf-8")
        block = source.split('if [[ -f "${INSTALL_DIR}/manage.py" ]]; then\n', 1)[1].split("\nfi", 1)[0]
        # Run up through the chmod after collectstatic (before manage.py shell)
        collect_end = block.index('    AF_ADMIN_USER=')
        collect_snippet = block[:collect_end]

        install_dir = self.root / "opt/dispatcharr"
        config_dir = self.root / "etc/dispatcharr"
        (install_dir / "env/bin").mkdir(parents=True)
        config_dir.mkdir(parents=True)
        env_file = config_dir / "dispatcharr.env"
        env_file.write_text("DJANGO_SETTINGS_MODULE=dispatcharr.settings\n", encoding="utf-8")
        env_file.chmod(0o640)
        (install_dir / ".env").symlink_to(env_file)
        (install_dir / "manage.py").write_text(
            "import pathlib, sys\n"
            "if sys.argv[1] == 'collectstatic':\n"
            "    d = pathlib.Path('static/assets')\n"
            "    d.mkdir(parents=True, exist_ok=True)\n"
            "    (d / 'bundle.js').write_text('console.log(1)')\n",
            encoding="utf-8",
        )
        (install_dir / "env/bin/python").symlink_to(sys.executable)
        fake_bin = self.root / "bin"
        fake_bin.mkdir()
        su_mock = fake_bin / "su"
        su_mock.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
        su_mock.chmod(0o755)

        script = f"""
set -euo pipefail
umask 077
af_logged() {{ "$@"; }}
APP_USER=dispatcharr
INSTALL_DIR={str(install_dir)!r}
CONFIG_DIR={str(config_dir)!r}
{collect_snippet}
"""
        res = subprocess.run(
            ["bash", "-c", script],
            env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(stat.S_IMODE((install_dir / "static").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((install_dir / "static/assets").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((install_dir / "static/assets/bundle.js").stat().st_mode), 0o644)
        # Symlink target dispatcharr.env must keep its 0640 permissions untouched!
        self.assertEqual(stat.S_IMODE(env_file.stat().st_mode), 0o640)

    def test_invidious_crystal_is_validated_and_readable_after_umask_077_extraction(self):
        source = (INSTALL_DIR / "installpackage-invidious").read_text(encoding="utf-8")
        start = source.index('af_validate_tar_archive --allow-intra-symlinks --strip-components=1 "${TMP_DIR}/crystal.tar.gz"')
        end = source.index('install -m 755 "${TMP_DIR}/invidious_companion"', start) + len('install -m 755 "${TMP_DIR}/invidious_companion" "${INSTALL_DIR}/invidious_companion"')
        snippet = source[start:end]

        tmp_dir = self.root / "tmp"
        install_dir = self.root / "opt/invidious"
        tmp_dir.mkdir()
        install_dir.mkdir(parents=True)

        # Good crystal archive with intra-root relative symlink + good companion archive
        write_tar(
            tmp_dir / "crystal.tar.gz",
            [
                ("crystal-1.22.2-1/share/crystal/bin/crystal", "file", b"#!/bin/sh\necho crystal\n"),
                ("crystal-1.22.2-1/bin/crystal", "symlink", "../share/crystal/bin/crystal"),
            ],
        )
        write_tar(
            tmp_dir / "companion.tar.gz",
            [("invidious_companion", "file", b"#!/bin/sh\necho comp\n")],
        )

        helpers = common_functions("af_validate_tar_archive")
        script = f"""
set -euo pipefail
umask 077
log_error() {{ printf '[ERROR] %s\\n' "$*" >&2; }}
youtube_asset() {{ :; }}
TMP_DIR={str(tmp_dir)!r}
INSTALL_DIR={str(install_dir)!r}
ARCH=x86_64
{helpers}
{snippet}
"""
        res = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=15)
        self.assertEqual(res.returncode, 0, res.stderr)
        crystal_real = install_dir / "crystal/share/crystal/bin/crystal"
        self.assertEqual(stat.S_IMODE((install_dir / "crystal").stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(crystal_real.stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((install_dir / "invidious_companion").stat().st_mode), 0o755)

        # Escaping symlink in crystal.tar.gz must fail before extraction
        bad_install = self.root / "opt/invidious-bad"
        bad_install.mkdir()
        write_tar(tmp_dir / "crystal.tar.gz", [("crystal-1.22.2-1/bin/evil", "symlink", "../../etc/passwd")])
        bad_res = subprocess.run(
            ["bash", "-c", script.replace(repr(str(install_dir)), repr(str(bad_install)))],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(bad_res.returncode, 0)
        self.assertFalse((bad_install / "crystal").exists())


class RequestrrDuplicatiAndBloatCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="af-edge-hardening-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_requestrr_extracts_both_zip_and_tar_gz_and_rejects_malicious_zip(self):
        source = (INSTALL_DIR / "installpackage-requestrr").read_text(encoding="utf-8")
        start = source.index('ASSET_PATH="${ASSET_URL%%\\?*}"')
        end = source.index('chmod 0755 "$RELEASE_DIR/Requestrr.WebApi"', start)
        snippet = source[start:end]
        helpers = common_functions("af_validate_tar_archive", "af_extract_zip_archive")

        # 1. Valid .zip fallback asset (nested directory + Requestrr.WebApi)
        good_zip = self.root / "requestrr-linux-x64.zip"
        with zipfile.ZipFile(good_zip, "w") as zf:
            zf.writestr("requestrr-linux-x64/Requestrr.WebApi", b"zip-binary")
        res_zip = subprocess.run(
            [
                "bash",
                "-c",
                f"""
set -euo pipefail
AF_JOB_SCRATCH_ROOT={str(self.root / 'scratch')!r}
APP_NAME=requestrr
INSTALL_DIR={str(self.root / 'opt/requestrr')!r}
LATEST_TAG=v2.1.6
ASSET_URL="https://github.com/thomst08/requestrr/releases/download/v2.1.6/requestrr-linux-x64.zip?dl=1"
report_progress() {{ :; }}
log_error() {{ printf '%s\\n' "$*" >&2; }}
print_error() {{ printf '%s\\n' "$*" >&2; }}
af_logged() {{ "$@"; }}
download_file() {{ cp {str(good_zip)!r} "$2"; }}
{helpers}
{snippet}
printf '%s\\n' "$RELEASE_DIR/Requestrr.WebApi"
""",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(res_zip.returncode, 0, res_zip.stderr)
        extracted_bin = Path(res_zip.stdout.strip())
        self.assertEqual(extracted_bin.read_bytes(), b"zip-binary")

        # 2. Malicious .zip traversal must fail closed
        bad_zip = self.root / "bad.zip"
        with zipfile.ZipFile(bad_zip, "w") as zf:
            zf.writestr("../escape", b"bad")
        res_bad_zip = subprocess.run(
            [
                "bash",
                "-c",
                f"""
set -euo pipefail
AF_JOB_SCRATCH_ROOT={str(self.root / 'scratch-bad')!r}
APP_NAME=requestrr
INSTALL_DIR={str(self.root / 'opt/requestrr')!r}
LATEST_TAG=v2.1.6
ASSET_URL="https://github.com/thomst08/requestrr/releases/download/v2.1.6/requestrr-linux-x64.zip"
report_progress() {{ :; }}
log_error() {{ printf '%s\\n' "$*" >&2; }}
print_error() {{ printf '%s\\n' "$*" >&2; }}
af_logged() {{ "$@"; }}
download_file() {{ cp {str(bad_zip)!r} "$2"; }}
{helpers}
{snippet}
""",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertNotEqual(res_bad_zip.returncode, 0)

        # 3. Valid .tar.gz asset still works
        good_tar = self.root / "requestrr-linux-x64.tar.gz"
        write_tar(good_tar, [("Requestrr.WebApi", "file", b"tar-binary")])
        res_tar = subprocess.run(
            [
                "bash",
                "-c",
                f"""
set -euo pipefail
AF_JOB_SCRATCH_ROOT={str(self.root / 'scratch-tar')!r}
APP_NAME=requestrr
INSTALL_DIR={str(self.root / 'opt/requestrr')!r}
LATEST_TAG=v2.1.6
ASSET_URL="https://github.com/thomst08/requestrr/releases/download/v2.1.6/requestrr-linux-x64.tar.gz"
report_progress() {{ :; }}
log_error() {{ printf '%s\\n' "$*" >&2; }}
print_error() {{ printf '%s\\n' "$*" >&2; }}
af_logged() {{ "$@"; }}
download_file() {{ cp {str(good_tar)!r} "$2"; }}
{helpers}
{snippet}
printf '%s\\n' "$RELEASE_DIR/Requestrr.WebApi"
""",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(res_tar.returncode, 0, res_tar.stderr)
        self.assertEqual(Path(res_tar.stdout.strip()).read_bytes(), b"tar-binary")

    def test_duplicati_arch_matching_all_deb_fallback_and_fail_closed_mismatch(self):
        source = (INSTALL_DIR / "installpackage-duplicati").read_text(encoding="utf-8")
        start = source.index('ARCH="$(dpkg --print-architecture)"')
        end = source.index('report_progress 65', start)
        snippet = source[start:end]

        def run_select(arch: str, release_json: str, allow_fallback: str = "0") -> subprocess.CompletedProcess:
            fake_bin = self.root / f"bin-{arch}-{abs(hash(release_json))}"
            fake_bin.mkdir(exist_ok=True)
            dpkg = fake_bin / "dpkg"
            dpkg.write_text(f"#!/bin/sh\nprintf '%s\\n' {arch!r}\n", encoding="utf-8")
            dpkg.chmod(0o755)
            script = f"""
set -euo pipefail
print_error() {{ printf '%s\\n' "$*" >&2; }}
LATEST_TAG="v2.1.0"
RELEASES_JSON={release_json!r}
AF_ALLOW_RELEASE_FALLBACK={allow_fallback!r}
{snippet}
printf '%s\\n' "$DEB_URL"
"""
            return subprocess.run(
                ["bash", "-c", script],
                env={**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"},
                capture_output=True,
                text=True,
                timeout=15,
            )

        # Matching arch selects exact deb
        both_json = json.dumps({
            "assets": [
                {"name": "duplicati-2.1.0-linux-x64-gui.deb", "browser_download_url": "https://example.invalid/x64.deb"},
                {"name": "duplicati-2.1.0-linux-arm64-gui.deb", "browser_download_url": "https://example.invalid/arm64.deb"},
            ]
        })
        r_arm = run_select("arm64", both_json)
        self.assertEqual(r_arm.returncode, 0, r_arm.stderr)
        self.assertEqual(r_arm.stdout.strip(), "https://example.invalid/arm64.deb")

        # Architecture mismatch (only x64 published on arm64 host) MUST fail closed
        x64_only_json = json.dumps({
            "assets": [
                {"name": "duplicati-2.1.0-linux-x64-gui.deb", "browser_download_url": "https://example.invalid/x64.deb"},
            ]
        })
        r_mismatch = run_select("arm64", x64_only_json)
        self.assertNotEqual(r_mismatch.returncode, 0)
        self.assertIn("No compatible Duplicati .deb asset", r_mismatch.stderr)

        # Arch-independent _all.deb fallback works when no arch-specific deb exists
        all_deb_json = json.dumps({
            "assets": [
                {"name": "duplicati_2.0.8.1-1_all.deb", "browser_download_url": "https://example.invalid/all.deb"},
            ]
        })
        r_all = run_select("arm64", all_deb_json)
        self.assertEqual(r_all.returncode, 0, r_all.stderr)
        self.assertEqual(r_all.stdout.strip(), "https://example.invalid/all.deb")

        # Unsupported host architecture fails closed
        r_unsupported = run_select("riscv64", all_deb_json)
        self.assertNotEqual(r_unsupported.returncode, 0)
        self.assertIn("Unsupported architecture for Duplicati", r_unsupported.stderr)

    def test_bazarr_fails_closed_when_version_empty_and_has_no_unversioned_latest_url(self):
        source = (INSTALL_DIR / "installpackage-bazarr").read_text(encoding="utf-8")
        self.assertNotIn("releases/latest/download/bazarr.zip", source)
        start = source.index('BAZARR_VERSION="$(github_latest_tag')
        end = source.index('mkdir -p "${AF_JOB_SCRATCH_ROOT', start)
        snippet = source[start:end]
        res = subprocess.run(
            ["bash", "-c", f'set -euo pipefail\nprint_error() {{ printf "%s\\n" "$*" >&2; }}\ngithub_latest_tag() {{ :; }}\n{snippet}\n'],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("Failed to resolve a pinned Bazarr release version", res.stderr)

    def test_installer_hardening_and_bloat_cleanup_contracts(self):
        # Node tarball HTTPS enforcement, validation, --no-same-owner --no-same-permissions, and git_stage_exact_revision
        for app in ("jellyseerr", "palate", "maintainerr"):
            text = (INSTALL_DIR / f"installpackage-{app}").read_text(encoding="utf-8")
            with self.subTest(app=app):
                self.assertIn("--proto '=https' --proto-redir '=https'", text)
                self.assertIn("af_validate_tar_archive --allow-intra-symlinks --strip-components=1", text)
                self.assertIn("--no-same-owner --no-same-permissions", text)
                self.assertIn("git_stage_exact_revision", text)
                self.assertNotIn("git clone --depth 1 --branch", text)
                self.assertNotIn("git clone --quiet --depth 1 --branch", text)

        # FileBot, SABnzbd, Paperless-ngx tar extraction flags
        for app in ("filebot", "sabnzbd", "paperless-ngx"):
            text = (INSTALL_DIR / f"installpackage-{app}").read_text(encoding="utf-8")
            with self.subTest(app=app):
                for line in text.splitlines():
                    if "tar " in line and ("-xJf" in line or "-xzf" in line):
                        self.assertIn("--no-same-owner", line, (app, line))
                        self.assertIn("--no-same-permissions", line, (app, line))

        # Dispatcharr uses git_stage_exact_revision, drops duplicate pg_dump, and runs chmod after collectstatic
        dispatcharr = (INSTALL_DIR / "installpackage-dispatcharr").read_text(encoding="utf-8")
        self.assertIn('git_stage_exact_revision "https://github.com/Dispatcharr/Dispatcharr.git"', dispatcharr)
        self.assertNotIn("git clone --depth 1 --branch", dispatcharr)
        self.assertNotIn("pg_dump --format=custom dispatcharr", dispatcharr)
        self.assertGreater(
            dispatcharr.rindex('chmod -R a+rX,go-w "${INSTALL_DIR}"'),
            dispatcharr.index("manage.py collectstatic --noinput --clear"),
        )

        # Palate drops duplicate pg_dump and duplicate vault.tar.gz
        palate = (INSTALL_DIR / "installpackage-palate").read_text(encoding="utf-8")
        self.assertNotIn("database.dump", palate)
        self.assertNotIn("vault.tar.gz", palate)
        self.assertIn('backup_postgresql_database "$BACKUP_DIR" af_palate', palate)

        # Home Assistant drops back-to-back duplicate stop_systemd_unit
        ha = (INSTALL_DIR / "installpackage-homeassistant").read_text(encoding="utf-8")
        self.assertEqual(ha.count("stop_systemd_unit home-assistant@homeassistant"), 1)

        # n8n drops unreachable second NODE_MAJOR < 24 check
        n8n = (INSTALL_DIR / "installpackage-n8n").read_text(encoding="utf-8")
        self.assertNotIn("current runtime is Node", n8n)
        self.assertIn("NODE_MAJOR < 24", n8n)

        # KasmVNC drops duplicate sha256sum -c after download_file already verified the digest
        kasm = (INSTALL_DIR / "installpackage-kasmvnc").read_text(encoding="utf-8")
        self.assertNotIn("sha256sum -c", kasm)
        self.assertIn('download_file "$ASSET_URL" "${TMP_DIR}/kasmvnc.deb" kasmvnc "${ASSET_DIGEST#sha256:}"', kasm)


if __name__ == "__main__":
    unittest.main()
