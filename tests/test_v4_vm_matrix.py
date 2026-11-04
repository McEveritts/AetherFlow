#!/usr/bin/env python3
"""
Unit tests for `scripts/v4_vm_matrix.py` (`tests/test_v4_vm_matrix.py`).

Scope & Honesty Boundary:
  - These unit tests validate the pure-Python harness primitives in `scripts/v4_vm_matrix.py`:
    1. Official Debian (`SHA512SUMS`) and Ubuntu (`SHA256SUMS`) manifest parsing,
       starred binary entries, missing-entry rejection, and malformed/tampered hex rejection.
    2. `/var/tmp/aetherflow-v4-vm*` workspace path validation (rejecting `/tmp`, `/opt/AetherFlow`,
       relative paths, and `..` traversal).
    3. QEMU/KVM command-line and isolated `LD_LIBRARY_PATH` / `QEMU_MODULE_DIR` construction,
       enforcing loopback-only SSH forwarding (`127.0.0.1:<port>-:22`), `q35,accel=kvm`,
       `nice`/`ionice` resource bounds, explicit `-L` BIOS/firmware paths, and zero host mounts.
    4. Cloud-Init `NoCloud` seed rendering (`user-data` + `meta-data`) with pinned per-VM
       Ed25519 host keys (`StrictHostKeyChecking=yes`).
    5. Release artifact contract verification (`verify_release_artifact_contract`):
       validating required v4 archive files, executable mode bits, `.version` stamp,
       `SHA256SUMS` digest match, Zip-Slip/symlink rejection, and ELF `GLIBC_x.y` compatibility
       against Ubuntu 22.04 (`GLIBC_2.35`).
  - These unit tests DO NOT mock installation outcomes or claim to certify the live OS matrix.
    Real OS matrix boot and lifecycle certification require executing `scripts/v4_vm_matrix.py`
    against `/dev/kvm` on the Linux host.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import v4_vm_matrix as vm_matrix  # noqa: E402


class ManifestAndDigestTests(unittest.TestCase):
    def test_parse_debian_sha512_manifest(self) -> None:
        valid_sha512 = "0464b5d4ae3aa4f658468d88da83af7857b71548b30d46dcb6282770955a747fb95a983476db90d25afd0653af607224c7ebd05122ab71faa106fd712aaad652"
        manifest = (
            "# Official Debian 12 genericcloud manifest\n"
            f"{valid_sha512}  debian-12-genericcloud-amd64.qcow2\n"
        )
        parsed = vm_matrix.parse_checksum_manifest(
            manifest,
            "debian-12-genericcloud-amd64.qcow2",
            algorithm="sha512",
        )
        self.assertEqual(parsed, valid_sha512)

    def test_parse_ubuntu_sha256_manifest_with_star_prefix(self) -> None:
        valid_sha256 = "58be26aa7452f3005a4f7370a43928bfb33a7f35a77a8f3b264bf00266a17ca0"
        manifest = (
            f"{valid_sha256} *jammy-server-cloudimg-amd64.img\n"
            "12ede672ad4a029aad6f6ed71c80287c890e53663a064c21524a6469593c97c4 *jammy-server-cloudimg-amd64-lxd.tar.xz\n"
        )
        parsed = vm_matrix.parse_checksum_manifest(
            manifest,
            "jammy-server-cloudimg-amd64.img",
            algorithm="sha256",
        )
        self.assertEqual(parsed, valid_sha256)

    def test_parse_manifest_rejects_missing_or_corrupt_digest(self) -> None:
        manifest = "deadbeef  jammy-server-cloudimg-amd64.img\n"
        with self.assertRaises(ValueError):
            vm_matrix.parse_checksum_manifest(
                manifest,
                "jammy-server-cloudimg-amd64.img",
                algorithm="sha256",
            )
        with self.assertRaises(ValueError):
            vm_matrix.parse_checksum_manifest(
                "",
                "jammy-server-cloudimg-amd64.img",
                algorithm="sha256",
            )
        with self.assertRaises(ValueError):
            vm_matrix.parse_checksum_manifest(
                manifest,
                "../jammy-server-cloudimg-amd64.img",
                algorithm="sha256",
            )


class WorkRootAndQemuCommandTests(unittest.TestCase):
    def test_validate_work_root_enforces_isolated_var_tmp_prefix(self) -> None:
        valid = vm_matrix.validate_work_root_path("/var/tmp/aetherflow-v4-vm-matrix")
        self.assertEqual(str(valid), "/var/tmp/aetherflow-v4-vm-matrix")

        for forbidden in (
            "/tmp/aetherflow-v4-vm-matrix",
            "/opt/AetherFlow",
            "/var/tmp/other-dir",
            "/var/tmp/aetherflow-v4-vm-matrix/../escape",
            "relative/path",
        ):
            with self.assertRaises(ValueError, msg=f"failed to reject {forbidden}"):
                vm_matrix.validate_work_root_path(forbidden)

    def test_build_qemu_environment_and_command_isolation(self) -> None:
        qroot = "/var/tmp/aetherflow-v4-validation-20261103-052723/tools/qemu-root"
        env = vm_matrix.build_qemu_environment(qroot)
        self.assertIn(f"{qroot}/usr/lib/x86_64-linux-gnu", env["LD_LIBRARY_PATH"])
        self.assertIn(f"{qroot}/lib/x86_64-linux-gnu", env["LD_LIBRARY_PATH"])
        self.assertEqual(
            env["QEMU_MODULE_DIR"],
            f"{qroot}/usr/lib/x86_64-linux-gnu/qemu",
        )

        cmd = vm_matrix.build_qemu_command(
            qemu_root=qroot,
            overlay_qcow2="/var/tmp/aetherflow-v4-vm-matrix/runs/r1/overlay.qcow2",
            seed_iso="/var/tmp/aetherflow-v4-vm-matrix/runs/r1/seed.iso",
            ssh_port=22441,
            pidfile="/var/tmp/aetherflow-v4-vm-matrix/runs/r1/qemu.pid",
            serial_log="/var/tmp/aetherflow-v4-vm-matrix/runs/r1/serial.log",
            vcpus=2,
            memory_mib=3584,
            use_nice=True,
        )
        self.assertEqual(cmd[:8], ["nice", "-n", "10", "ionice", "-c", "2", "-n", "7"])
        self.assertIn("q35,accel=kvm", cmd)
        self.assertIn(f"{qroot}/usr/share/qemu", cmd)
        self.assertIn(f"{qroot}/usr/share/seabios", cmd)
        self.assertIn("user,id=net0,hostfwd=tcp:127.0.0.1:22441-:22", cmd)
        # Ensure zero host filesystem sharing flags
        joined = " ".join(cmd)
        self.assertNotIn("-virtfs", joined)
        self.assertNotIn("-fsdev", joined)
        self.assertNotIn("0.0.0.0:", joined)

    def test_build_qemu_command_rejects_out_of_bounds_resources(self) -> None:
        qroot = "/var/tmp/aetherflow-v4-validation-20261103-052723/tools/qemu-root"
        with self.assertRaises(ValueError):
            vm_matrix.build_qemu_command(
                qemu_root=qroot,
                overlay_qcow2="/var/tmp/aetherflow-v4-vm/o.qcow2",
                seed_iso="/var/tmp/aetherflow-v4-vm/s.iso",
                ssh_port=22,  # privileged port rejected
                pidfile="/var/tmp/aetherflow-v4-vm/p",
                serial_log="/var/tmp/aetherflow-v4-vm/l",
            )
        with self.assertRaises(ValueError):
            vm_matrix.build_qemu_command(
                qemu_root=qroot,
                overlay_qcow2="/var/tmp/aetherflow-v4-vm/o.qcow2",
                seed_iso="/var/tmp/aetherflow-v4-vm/s.iso",
                ssh_port=22022,
                pidfile="/var/tmp/aetherflow-v4-vm/p",
                serial_log="/var/tmp/aetherflow-v4-vm/l",
                memory_mib=16384,  # exceeds 4096 MiB per-VM cap
            )


class NoCloudSeedAndOsReleaseTests(unittest.TestCase):
    def test_render_nocloud_seed_files_pins_keys(self) -> None:
        user_data, meta_data = vm_matrix.render_nocloud_seed_files(
            instance_id="debian-12-run-01",
            hostname="af-debian-12",
            admin_ssh_pubkey="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminKey af-vm",
            guest_host_ed25519_private="-----BEGIN OPENSSH PRIVATE KEY-----\nTESTKEY\n-----END OPENSSH PRIVATE KEY-----",
            guest_host_ed25519_public="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestHostKey host-vm",
        )
        self.assertTrue(user_data.startswith("#cloud-config\n"))
        self.assertIn("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestAdminKey af-vm", user_data)
        self.assertIn("ed25519_private:", user_data)
        self.assertIn("instance-id: debian-12-run-01", meta_data)
        self.assertIn("local-hostname: af-debian-12", meta_data)

    def test_parse_os_release_text(self) -> None:
        sample = (
            'PRETTY_NAME="Ubuntu 22.04.5 LTS"\n'
            "NAME=\"Ubuntu\"\n"
            'VERSION_ID="22.04"\n'
            "ID=ubuntu\n"
            "VERSION_CODENAME=jammy\n"
        )
        parsed = vm_matrix.parse_os_release_text(sample)
        self.assertEqual(parsed["ID"], "ubuntu")
        self.assertEqual(parsed["VERSION_ID"], "22.04")
        self.assertEqual(parsed["VERSION_CODENAME"], "jammy")


class ArtifactContractAndGlibcTests(unittest.TestCase):
    def _build_tarball(
        self,
        path: Path,
        entries: dict[str, tuple[bytes, int]],
        *,
        include_symlink: bool = False,
    ) -> str:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for name, (payload, mode) in entries.items():
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = mode
                tf.addfile(info, io.BytesIO(payload))
            if include_symlink:
                sym = tarfile.TarInfo("evil-link")
                sym.type = tarfile.SYMTYPE
                sym.linkname = "/etc/shadow"
                tf.addfile(sym)
        data = buf.getvalue()
        path.write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def portable_entries(self) -> dict[str, tuple[bytes, int]]:
        return {
            "aetherflow-api": (b"\x7fELF-api index.html _next/", 0o755),
            "af": (b"\x7fELF-new-cli", 0o755),
            "bin/af": (b"\x7fELF-new-cli", 0o755),
            ".version": (b"v4.0.0\n", 0o644),
            "deploy/release-manager.sh": (b"#!/bin/bash\n", 0o755),
            "deploy/release-manager.conf": (b"config\n", 0o644),
            "config/packages.json": (b"{}\n", 0o644),
            "config/package_automation.json": (b"{}\n", 0o644),
        }

    def test_cli_glibc_requirement_is_checked_independently_of_api(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "aetherflow-linux-amd64.tar.gz"
            sums = Path(directory) / "SHA256SUMS"
            digest = self._build_tarball(archive, self.portable_entries())
            sums.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
            report = vm_matrix.verify_release_artifact_contract(
                archive,
                sums,
                readelf_symbol_Inspector=lambda binary_bytes: "2.38" if b"new-cli" in binary_bytes else "2.34",
            )
            self.assertFalse(report["valid"])
            self.assertFalse(report["details"]["glibc_compatible_ubuntu_2204"])
            self.assertEqual(report["details"]["binary_glibc_versions"], {"aetherflow-api": "2.34", "af": "2.38", "bin/af": "2.38"})
            self.assertTrue(any("af requires GLIBC_2.38" in error for error in report["errors"]))

    def test_cli_archive_copies_must_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "aetherflow-linux-amd64.tar.gz"
            sums = Path(directory) / "SHA256SUMS"
            entries = self.portable_entries()
            entries["bin/af"] = (b"\x7fELF-different-cli", 0o755)
            digest = self._build_tarball(archive, entries)
            sums.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
            report = vm_matrix.verify_release_artifact_contract(archive, sums, readelf_symbol_Inspector=lambda binary_bytes: "2.34")
            self.assertFalse(report["valid"])
            self.assertIn("af and bin/af must contain identical CLI bytes", report["errors"])

    def test_remote_contract_rejects_incompatible_cli_and_failed_readelf(self) -> None:
        namespace = {"__name__": "portability_contract_unit"}
        exec(vm_matrix.build_remote_driver_script(), namespace)
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "aetherflow-linux-amd64.tar.gz"
            sums = Path(directory) / "SHA256SUMS"
            digest = self._build_tarball(archive, self.portable_entries())
            sums.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
            for failure_mode in ("cli_glibc", "readelf_failed"):
                def readelf_result(command, **options):
                    is_cli = Path(command[-1]).name in ("af", "bin-af")
                    if failure_mode == "readelf_failed" and is_cli:
                        return 1, "", "invalid ELF", {}
                    version = "2.38" if is_cli else "2.34"
                    return 0, f"Name: GLIBC_{version}\n", "", {}

                with self.subTest(failure_mode=failure_mode), mock.patch.dict(namespace, {"run_bounded": readelf_result}):
                    report = namespace["inspect_artifact_bundle"](archive, sums, vm_matrix.asdict(vm_matrix.DEFAULT_ARTIFACT_CONTRACT))
                self.assertFalse(report["valid"])
                self.assertFalse(report["details"]["glibc_compatible_ubuntu_2204"])
                expected = "GLIBC_2.38" if failure_mode == "cli_glibc" else "readelf inspection failed for af"
                self.assertTrue(any(expected in error for error in report["errors"]), report["errors"])

    def test_verify_release_artifact_contract_passes_valid_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "aetherflow-linux-amd64.tar.gz"
            sums = root / "SHA256SUMS"

            digest = self._build_tarball(
                archive,
                {
                    "aetherflow-api": (b"\x7fELF-binary-payload", 0o755),
                    "af": (b"\x7fELF-cli-payload", 0o755),
                    "bin/af": (b"\x7fELF-cli-payload", 0o755),
                    ".version": (b"v4.0.0\n", 0o644),
                    "deploy/release-manager.sh": (b"#!/bin/bash\n", 0o755),
                    "deploy/release-manager.conf": (b"# conf\n", 0o644),
                    "config/packages.json": (b"{}\n", 0o644),
                    "config/package_automation.json": (b"{}\n", 0o644),
                },
            )
            sums.write_text(f"{digest}  aetherflow-linux-amd64.tar.gz\n", encoding="utf-8")

            report = vm_matrix.verify_release_artifact_contract(
                archive,
                sums,
                readelf_symbol_Inspector=lambda _: "2.34",
            )
            self.assertTrue(report["valid"], report["errors"])
            self.assertTrue(report["details"]["sha256_verified"])
            self.assertEqual(report["details"]["version_stamp"], "v4.0.0")
            self.assertTrue(report["details"]["glibc_compatible_ubuntu_2204"])

    def test_verify_release_artifact_contract_rejects_debian13_glibc_2_38_for_ubuntu_2204(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "aetherflow-linux-amd64.tar.gz"
            sums = root / "SHA256SUMS"

            digest = self._build_tarball(
                archive,
                {
                    "aetherflow-api": (b"\x7fELF-debian13-binary", 0o755),
                    "af": (b"\x7fELF-cli", 0o755),
                    "bin/af": (b"\x7fELF-cli", 0o755),
                    ".version": (b"v4.0.0\n", 0o644),
                    "deploy/release-manager.sh": (b"#!/bin/bash\n", 0o755),
                    "deploy/release-manager.conf": (b"# conf\n", 0o644),
                    "config/packages.json": (b"{}\n", 0o644),
                    "config/package_automation.json": (b"{}\n", 0o644),
                },
            )
            sums.write_text(f"{digest}  aetherflow-linux-amd64.tar.gz\n", encoding="utf-8")

            report = vm_matrix.verify_release_artifact_contract(
                archive,
                sums,
                readelf_symbol_Inspector=lambda _: "2.38",
            )
            self.assertFalse(report["valid"])
            self.assertFalse(report["details"]["glibc_compatible_ubuntu_2204"])
            self.assertTrue(
                any("GLIBC_2.38" in err for err in report["errors"]),
                report["errors"],
            )

    def test_verify_release_artifact_contract_rejects_symlinks_and_missing_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "aetherflow-linux-amd64.tar.gz"
            self._build_tarball(
                archive,
                {
                    "aetherflow-api": (b"\x7fELF", 0o755),
                    ".version": (b"v4.0.0\n", 0o644),
                },
                include_symlink=True,
            )
            report = vm_matrix.verify_release_artifact_contract(
                archive,
                require_manifest=False,
            )
            self.assertFalse(report["valid"])
            self.assertIn("af", report["details"]["missing_entries"])
            self.assertIn("evil-link", report["details"]["symlinks_or_unsafe_entries"])

    def test_verify_release_artifact_contract_requires_independent_sha256sums_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "aetherflow-linux-amd64.tar.gz"
            self._build_tarball(
                archive,
                {
                    "aetherflow-api": (b"\x7fELF-binary-payload index.html _next/", 0o755),
                    "af": (b"\x7fELF-cli-payload", 0o755),
                    "bin/af": (b"\x7fELF-cli-payload", 0o755),
                    ".version": (b"v4.0.0\n", 0o644),
                    "deploy/release-manager.sh": (b"#!/bin/bash\n", 0o755),
                    "deploy/release-manager.conf": (b"# conf\n", 0o644),
                    "config/packages.json": (b"{}\n", 0o644),
                    "config/package_automation.json": (b"{}\n", 0o644),
                },
            )
            # Without SHA256SUMS, require_manifest=True (default) MUST fail closed
            report = vm_matrix.verify_release_artifact_contract(
                archive,
                None,
                readelf_symbol_Inspector=lambda _: "2.34",
            )
            self.assertFalse(report["valid"])
            self.assertTrue(
                any("independent --artifact-sha256-file" in err for err in report["errors"]),
                report["errors"],
            )
            # Passing archive itself as manifest must also be rejected
            self_ref = vm_matrix.verify_release_artifact_contract(
                archive,
                archive,
                readelf_symbol_Inspector=lambda _: "2.34",
            )
            self.assertFalse(self_ref["valid"])
            self.assertTrue(
                any("distinct" in err for err in self_ref["errors"]),
                self_ref["errors"],
            )

    def test_extract_max_glibc_from_elf_symbols(self) -> None:
        sample_readelf = (
            "  0x0020: Version: 1  File: libc.so.6  Cnt: 5\n"
            "  0x0030:   Name: GLIBC_2.2.5  Flags: none  Version: 2\n"
            "  0x0040:   Name: GLIBC_2.17  Flags: none  Version: 4\n"
            "  0x0050:   Name: GLIBC_2.34  Flags: none  Version: 9\n"
            "  0x0060:   Name: GLIBC_2.33  Flags: none  Version: 8\n"
        )
        self.assertEqual(vm_matrix.extract_max_glibc_from_elf_symbols(sample_readelf), "2.34")
        self.assertIsNone(vm_matrix.extract_max_glibc_from_elf_symbols("no dynamic symbols"))


class SourceTarballLayoutAndExtractionRegressionTests(unittest.TestCase):
    """
    Regression tests for Repair (1):
    `tar -xzf ... --strip-components=1 || tar -xzf ...` previously succeeded with exit 0 on
    flat-root tarballs while silently dropping root files (`.version`) and stripping `setup/`
    off `setup/modules/00-core.sh` (turning it into `modules/00-core.sh`).
    """

    def _build_source_tarball(self, path: Path, prefix: str = "") -> str:
        buf = io.BytesIO()
        pfx = f"{prefix.strip('/')}/" if prefix else ""
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            entries = {
                f"{pfx}.version": b"v4.0.0-src\n",
                f"{pfx}setup/modules/00-core.sh": b"#!/bin/bash\n# 00-core\n",
                f"{pfx}setup/modules/02-packages.sh": b"#!/bin/bash\n# 02-packages\n",
                f"{pfx}setup/modules/05-finalize.sh": b"#!/bin/bash\n# 05-finalize\n",
                f"{pfx}setup/modules/06-state.sh": b"#!/bin/bash\n# 06-state\n",
                f"{pfx}setup/modules/modern_stack.sh": b"#!/bin/bash\n# modern_stack\n",
                f"{pfx}deploy/release-manager.sh": b"#!/bin/bash\n# release-manager\n",
                f"{pfx}deploy/release-manager.conf": b"# release-manager.conf\n",
            }
            for name, content in entries.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o755 if name.endswith(".sh") else 0o644
                tf.addfile(info, io.BytesIO(content))
        data = buf.getvalue()
        path.write_bytes(data)
        return hashlib.sha256(data).hexdigest()

    def test_flat_root_source_tarball_preserves_setup_and_deploy_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_tar = root / "flat-source.tar.gz"
            dest = root / "extracted-flat"
            self._build_source_tarball(src_tar, prefix="")

            layout = vm_matrix.inspect_source_tarball_layout(src_tar)
            self.assertTrue(layout["valid"])
            self.assertEqual(layout["layout"], "flat")
            self.assertEqual(layout["strip_components"], 0)
            self.assertIsNone(layout["top_level_prefix"])

            extracted = vm_matrix.extract_validated_source_tarball(src_tar, dest)
            self.assertEqual(extracted["strip_components"], 0)
            for req in vm_matrix.REQUIRED_SOURCE_LAYOUT_ENTRIES:
                self.assertTrue((dest / req).is_file(), f"Missing {req} after flat extraction")
            self.assertTrue((dest / ".version").is_file())
            self.assertFalse((dest / "modules" / "00-core.sh").exists())

    def test_single_top_dir_source_tarball_strips_one_component_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_tar = root / "nested-source.tar.gz"
            dest = root / "extracted-nested"
            self._build_source_tarball(src_tar, prefix="AetherFlow-v4.0.0")

            layout = vm_matrix.inspect_source_tarball_layout(src_tar)
            self.assertTrue(layout["valid"])
            self.assertEqual(layout["layout"], "single_top_dir")
            self.assertEqual(layout["strip_components"], 1)
            self.assertEqual(layout["top_level_prefix"], "AetherFlow-v4.0.0")

            extracted = vm_matrix.extract_validated_source_tarball(src_tar, dest)
            self.assertEqual(extracted["strip_components"], 1)
            for req in vm_matrix.REQUIRED_SOURCE_LAYOUT_ENTRIES:
                self.assertTrue((dest / req).is_file(), f"Missing {req} after single_top_dir extraction")
            self.assertTrue((dest / ".version").is_file())

    def test_source_tarball_rejects_missing_setup_or_unsafe_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad_tar = root / "missing-setup.tar.gz"
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                info = tarfile.TarInfo("README.md")
                info.size = 5
                tf.addfile(info, io.BytesIO(b"hello"))
            bad_tar.write_bytes(buf.getvalue())

            with self.assertRaises(ValueError):
                vm_matrix.inspect_source_tarball_layout(bad_tar)

            traversal_tar = root / "traversal.tar.gz"
            buf2 = io.BytesIO()
            with tarfile.open(fileobj=buf2, mode="w:gz") as tf:
                info = tarfile.TarInfo("../escape.sh")
                info.size = 4
                tf.addfile(info, io.BytesIO(b"echo"))
            traversal_tar.write_bytes(buf2.getvalue())

            with self.assertRaises(ValueError):
                vm_matrix.inspect_source_tarball_layout(traversal_tar)


class CertificationInputAndMandatoryPhaseTests(unittest.TestCase):
    """
    Regression tests for Repairs (2), (3), and (4):
    - `certify-matrix` must require independent supplied `SHA256SUMS` and record SHA + source fingerprint.
    - Empty drill lists (`[]`) or fixture-only runs (`interrupted_update_recovery_fixture`) must NEVER certify.
    - All 4 mandatory phases must execute with `status == 'passed'` and `fixture_only != True`.
    """

    def test_validate_certification_inputs_requires_independent_sha256sums_and_fingerprints_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "aetherflow-linux-amd64.tar.gz"
            sums = root / "SHA256SUMS"
            src_tar = root / "source.tar.gz"

            # Build valid release archive
            art_helper = ArtifactContractAndGlibcTests()
            art_sha = art_helper._build_tarball(
                archive,
                {
                    "aetherflow-api": (b"\x7fELF-binary index.html _next/", 0o755),
                    "af": (b"\x7fELF-cli", 0o755),
                    "bin/af": (b"\x7fELF-cli", 0o755),
                    ".version": (b"v4.0.0\n", 0o644),
                    "deploy/release-manager.sh": (b"#!/bin/bash\n", 0o755),
                    "deploy/release-manager.conf": (b"# conf\n", 0o644),
                    "config/packages.json": (b"{}\n", 0o644),
                    "config/package_automation.json": (b"{}\n", 0o644),
                },
            )
            sums.write_text(f"{art_sha}  aetherflow-linux-amd64.tar.gz\n", encoding="utf-8")

            src_helper = SourceTarballLayoutAndExtractionRegressionTests()
            src_sha = src_helper._build_source_tarball(src_tar, prefix="")

            # Missing SHA256SUMS fails closed
            missing_sums = vm_matrix.validate_certification_inputs(
                artifact_tarball=archive,
                artifact_sha256_file=None,
                source_tarball=src_tar,
                readelf_symbol_Inspector=lambda _: "2.34",
            )
            self.assertTrue(missing_sums["supplied"])
            self.assertFalse(missing_sums["valid"])
            self.assertTrue(
                any("independent" in e and "--artifact-sha256-file" in e for e in missing_sums["errors"]),
                missing_sums["errors"],
            )

            # Valid independent SHA256SUMS + valid source tarball succeeds and records fingerprints
            valid_res = vm_matrix.validate_certification_inputs(
                artifact_tarball=archive,
                artifact_sha256_file=sums,
                source_tarball=src_tar,
                readelf_symbol_Inspector=lambda _: "2.34",
            )
            self.assertTrue(valid_res["valid"], valid_res["errors"])
            self.assertEqual(valid_res["artifact_sha256"], art_sha)
            self.assertEqual(valid_res["manifest_expected_sha256"], art_sha)
            self.assertIsNotNone(valid_res["manifest_file_sha256"])
            self.assertEqual(valid_res["source_sha256"], src_sha)
            self.assertEqual(valid_res["source_layout"]["layout"], "flat")
            self.assertEqual(valid_res["source_layout"]["strip_components"], 0)

    def test_evaluate_certification_status_rejects_empty_partial_or_fixture_only_drills(self) -> None:
        # 1. Empty drills must NOT be certified (`all([])` bug regression)
        status, reasons = vm_matrix.evaluate_certification_status([])
        self.assertEqual(status, "failed")
        self.assertTrue(any("no lifecycle drills" in r for r in reasons))

        # 2. Pending artifact single skip returns boot_verified_pending_artifact, not certified
        status_pending, _ = vm_matrix.evaluate_certification_status([
            {"phase": "artifact_supply_check", "status": "skipped_pending_artifact"}
        ])
        self.assertEqual(status_pending, "boot_verified_pending_artifact")

        # 3. Passing 3 phases + only the fixture phase (`interrupted_update_recovery_fixture`) must FAIL certification
        fixture_only_drills = [
            {"phase": "bootstrap_install_health_and_cli", "status": "passed", "details": {"fixture_only": False}},
            {"phase": "release_update", "status": "passed", "details": {"fixture_only": False}},
            {"phase": "failed_health_rollback_and_db_recovery", "status": "passed", "details": {"fixture_only": False}},
            {"phase": "interrupted_update_recovery_fixture", "status": "passed", "details": {"fixture_only": True}},
        ]
        status_fix, reasons_fix = vm_matrix.evaluate_certification_status(fixture_only_drills)
        self.assertEqual(status_fix, "failed")
        self.assertTrue(
            any("interrupted_update_recovery" in r for r in reasons_fix),
            reasons_fix,
        )

        # 4. Marking mandatory `interrupted_update_recovery` with `fixture_only=True` must also FAIL certification
        spoofed_fixture_drills = fixture_only_drills + [
            {"phase": "interrupted_update_recovery", "status": "passed", "details": {"fixture_only": True}},
        ]
        status_spoof, reasons_spoof = vm_matrix.evaluate_certification_status(spoofed_fixture_drills)
        self.assertEqual(status_spoof, "failed")
        self.assertTrue(
            any("fixture_only=True" in r for r in reasons_spoof),
            reasons_spoof,
        )

        # 5. All 4 mandatory phases passed with `fixture_only=False` (plus optional auxiliary fixture) => certified
        complete_drills = fixture_only_drills + [
            {
                "phase": "interrupted_update_recovery",
                "status": "passed",
                "details": {"fixture_only": False, "real_execution": True},
            },
        ]
        status_ok, reasons_ok = vm_matrix.evaluate_certification_status(complete_drills)
        self.assertEqual(status_ok, "certified")
        self.assertEqual(reasons_ok, [])


class BaselineBuildAndSingleRemoteEngineTests(unittest.TestCase):
    """
    Regression tests for Repairs (3), (5), and (6):
    - `render_baseline_guest_build_script` unconditionally rebuilds frontend assets even when placeholder
      `web/dist/.keep` exists, enforces `Cargo.lock` + `cargo fetch --locked`, and compiles offline with
      `CARGO_LOCKED=1 CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=2` under `nice`/`ionice`.
    - Dead `_invoke_remote_python` is gone; `run_remote_matrix_action` is the single executable remote engine
      and is directly exercised in tests.
    """

    def test_render_baseline_guest_build_script_enforces_frontend_export_locked_offline_and_resource_limits(self) -> None:
        script = vm_matrix.render_baseline_guest_build_script(jobs=2)
        # Never skip frontend build merely because `web/dist` directory exists
        self.assertNotIn("if [[ ! -d web/dist", script)
        self.assertIn("rm -rf web/dist backend/web/dist frontend/out", script)
        self.assertIn("NEXT_STATIC_EXPORT=1", script)
        self.assertIn("npm run build --workspace frontend", script)
        self.assertIn("test -s web/dist/index.html", script)
        self.assertIn("test -d web/dist/_next", script)
        self.assertIn("test -s backend/web/dist/index.html", script)
        # Require Cargo.lock, explicit fetch --locked, then offline compilation with 2 jobs and nice/ionice
        self.assertIn("test -s backend-rs/Cargo.lock", script)
        self.assertIn("cargo fetch --locked", script)
        self.assertIn("CARGO_LOCKED=1", script)
        self.assertIn("CARGO_NET_OFFLINE=true", script)
        self.assertIn("CARGO_BUILD_JOBS=2", script)
        self.assertIn('export RUSTFLAGS="-C link-arg=-fuse-ld=bfd"', script)
        self.assertIn("nice -n 10 ionice -c 2 -n 7", script)

    def test_each_mandatory_lifecycle_script_requires_current_readiness(self) -> None:
        driver = vm_matrix.build_remote_driver_script()
        self.assertIn("apt-get install -yqq curl ca-certificates sqlite3 dos2unix", driver)
        self.assertIn("_init_state\n_syscommands\n_build_modern_stack\n_boot", driver)
        validator = 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ready" else 1)'
        probe = f"curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready | python3 -c '{validator}'"
        for script_name in ("bootstrap_script", "update_script", "rollback_script", "real_interrupted_script"):
            with self.subTest(script_name=script_name):
                script = driver.split(f"{script_name} = r'''", 1)[1].split("'''", 1)[0]
                self.assertIn("set -euo pipefail", script)
                self.assertIn(probe, script)

    def test_readiness_validator_rejects_empty_malformed_and_unready_responses(self) -> None:
        driver = vm_matrix.build_remote_driver_script()
        probe = next(line for line in driver.splitlines() if "| python3 -c 'import json,sys; sys.exit(" in line)
        validator = shlex.split(probe.split("|", 1)[1])[2]
        for payload in ("", "not-json", "null", "[]", "{}", '{"status":true}', '{"status":"starting"}', '{"status":"ready"'):
            with self.subTest(payload=payload):
                outcome = subprocess.run([sys.executable, "-c", validator], input=payload, text=True, capture_output=True)
                self.assertNotEqual(outcome.returncode, 0)
        outcome = subprocess.run([sys.executable, "-c", validator], input='{"status":"ready"}', text=True, capture_output=True)
        self.assertEqual(outcome.returncode, 0, outcome.stderr)

    def test_real_interrupted_update_recovery_drill_launches_updater_and_recovers_via_af_cli(self) -> None:
        driver = vm_matrix.build_remote_driver_script()
        # Verify real updater launch in setsid process group, post-swap boundary observation, PID cmdline check, and CLI rollback
        self.assertIn("setsid env PATH=", driver)
        self.assertIn("bash /opt/AetherFlow/deploy/release-manager.sh deploy --channel stable", driver)
        self.assertIn("/var/tmp/af-drill/post-swap-observed", driver)
        self.assertIn('/proc/${updater_pid}/cmdline', driver)
        self.assertIn("/usr/local/bin/af release rollback --local --json > /tmp/real_interrupted_rollback.json", driver)

    def test_dead_invoke_remote_python_removed_and_run_remote_matrix_action_executes_locally(self) -> None:
        self.assertFalse(
            hasattr(vm_matrix, "_invoke_remote_python"),
            "Dead duplicate _invoke_remote_python must be removed",
        )
        with tempfile.TemporaryDirectory() as tmp:
            work_root = Path(tmp) / "aetherflow-v4-vm-unit"
            qemu_root = Path(tmp) / "qemu-root"
            work_root.mkdir(parents=True, exist_ok=True)
            qemu_root.mkdir(parents=True, exist_ok=True)

            # Exercise `run_remote_matrix_action` directly (`ssh_host='local'`) with a missing SHA256SUMS
            # to verify the real remote driver script compiles, runs, and fails closed without booting a VM.
            fake_tarball = work_root / "aetherflow-linux-amd64.tar.gz"
            ArtHelper = ArtifactContractAndGlibcTests()
            ArtHelper._build_tarball(
                fake_tarball,
                {
                    "aetherflow-api": (b"\x7fELF-binary index.html _next/", 0o755),
                    "af": (b"\x7fELF-cli", 0o755),
                    "bin/af": (b"\x7fELF-cli", 0o755),
                    ".version": (b"v4.0.0\n", 0o644),
                    "deploy/release-manager.sh": (b"#!/bin/bash\n", 0o755),
                    "deploy/release-manager.conf": (b"# conf\n", 0o644),
                    "config/packages.json": (b"{}\n", 0o644),
                    "config/package_automation.json": (b"{}\n", 0o644),
                },
            )
            payload = {
                "action": "certify-matrix",
                "work_root": str(work_root),
                "qemu_root": str(qemu_root),
                "specs": [vm_matrix.asdict(vm_matrix.OS_MATRIX_BY_ID["debian-12"])],
                "artifact_tarball": str(fake_tarball),
                "artifact_sha256_file": None,  # Omitted independent SHA256SUMS -> must fail closed!
                "source_tarball": None,
                "pending_artifact_contract": vm_matrix.asdict(vm_matrix.DEFAULT_ARTIFACT_CONTRACT),
                "update_latest_evidence": False,
            }
            report = vm_matrix.run_remote_matrix_action(
                ssh_host="local",
                payload=payload,
                timeout=30,
            )
            self.assertEqual(report["action"], "certify-matrix")
            self.assertFalse(report["artifact_validation"]["valid"])
            target = report["targets"][0]
            self.assertEqual(target["overall_status"], "failed")
            self.assertEqual(target["drills"][0]["phase"], "artifact_supply_check")
            self.assertEqual(target["drills"][0]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
