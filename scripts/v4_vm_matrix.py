#!/usr/bin/env python3
"""
AetherFlow v4.0 Clean-OS QEMU/KVM Matrix Runner (`scripts/v4_vm_matrix.py`)

Orchestrates isolated, non-Docker, bare-metal systemd virtual machines across the
supported AetherFlow v4 target OS matrix:
  1. Debian 12 (bookworm) — official genericcloud amd64 qcow2
  2. Debian 13 (trixie)   — official genericcloud amd64 qcow2
  3. Ubuntu 22.04 (jammy) — official server cloudimg amd64
  4. Ubuntu 24.04 (noble) — official server cloudimg amd64

Invariants enforced:
  - Pure bare-metal systemd VMs under QEMU/KVM (`accel=kvm`, `-cpu host`), zero Docker.
  - Official HTTPS cloud image download with cryptographic manifest verification
    (SHA-512 for Debian genericcloud, SHA-256 for Ubuntu cloud-images) BEFORE boot.
  - Local per-run qcow2 copy-on-write overlay (`qemu-img create -f qcow2 -F qcow2 -b <base>`),
    leaving cached base images immutable.
  - Ephemeral Ed25519 SSH keypair generated per run outside the repository (`0600`),
    injected via a NoCloud `cidata` ISO (`user-data` + `meta-data`), with guest host
    keys pre-generated and pinned in a per-VM `UserKnownHostsFile` (`StrictHostKeyChecking=yes`).
  - Loopback-only user-mode SLIRP networking (`hostfwd=tcp:127.0.0.1:<port>-:22`),
    zero host filesystem mounts, and zero operator secrets copied into guests.
  - Resource discipline: sequential execution (1 VM at a time), 2 vCPUs, 3584 MiB RAM,
    `nice -n 10` / `ionice -c 2 -n 7`, all disk I/O strictly under `/var/tmp/aetherflow-v4-vm-*`
    (never `/tmp` and never touching host `/opt/AetherFlow`, host systemd units, or host packages).
  - Owned-process cleanup only: tracks only the specific QEMU PID spawned by this run.
  - Supports:
      * `prepare-images`: Download and cryptographically verify official cloud images.
      * `boot-matrix`: Boot clean OS guests, verify SSH, systemd, kernel, GLIBC, and OS identity.
      * `build-baseline-artifact`: Build a GLIBC-portable v4 release tarball inside the
        lowest-GLIBC guest (`ubuntu-22.04`, GLIBC 2.35) from an isolated source snapshot.
      * `certify-matrix`: Run full v4 clean-OS drills (bootstrap install, `/health/ready`,
        `af` CLI checks, release update, deliberate failed-health rollback + DB corruption
        recovery, and interrupted-update recovery) against a supplied v4 release artifact.
      * `verify-contract`: Validate a local release directory or tarball against the
        exact v4 clean-host pending artifact contract.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


DEFAULT_REMOTE_WORK_ROOT = "/var/tmp/aetherflow-v4-vm-matrix"
DEFAULT_QEMU_TOOLS_ROOT = "/var/tmp/aetherflow-v4-validation-20261103-052723/tools/qemu-root"
DEFAULT_NODE_TOOLS_ROOT = "/var/tmp/aetherflow-v4-validation-20261103-052723/tools/node"
DEFAULT_BASELINE_SOURCE_DIR = "/var/tmp/aetherflow-v4-validation-20261103-052723/source"
DEFAULT_VM_VCPUS = 2
DEFAULT_VM_MEMORY_MIB = 3584
DEFAULT_OVERLAY_DISK_SIZE = "24G"


@dataclass(frozen=True)
class OsImageSpec:
    """Official cloud image specification and manifest verification parameters."""

    target_id: str
    distro: str
    version_id: str
    codename: str
    display_name: str
    base_url: str
    image_filename: str
    manifest_filename: str
    checksum_algorithm: str  # "sha512" or "sha256"

    @property
    def image_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.image_filename}"

    @property
    def manifest_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/{self.manifest_filename}"


OFFICIAL_OS_MATRIX: Tuple[OsImageSpec, ...] = (
    OsImageSpec(
        target_id="debian-12",
        distro="debian",
        version_id="12",
        codename="bookworm",
        display_name="Debian GNU/Linux 12 (bookworm)",
        base_url="https://cloud.debian.org/images/cloud/bookworm/latest",
        image_filename="debian-12-genericcloud-amd64.qcow2",
        manifest_filename="SHA512SUMS",
        checksum_algorithm="sha512",
    ),
    OsImageSpec(
        target_id="debian-13",
        distro="debian",
        version_id="13",
        codename="trixie",
        display_name="Debian GNU/Linux 13 (trixie)",
        base_url="https://cloud.debian.org/images/cloud/trixie/latest",
        image_filename="debian-13-genericcloud-amd64.qcow2",
        manifest_filename="SHA512SUMS",
        checksum_algorithm="sha512",
    ),
    OsImageSpec(
        target_id="ubuntu-22.04",
        distro="ubuntu",
        version_id="22.04",
        codename="jammy",
        display_name="Ubuntu 22.04 LTS (Jammy Jellyfish)",
        base_url="https://cloud-images.ubuntu.com/jammy/current",
        image_filename="jammy-server-cloudimg-amd64.img",
        manifest_filename="SHA256SUMS",
        checksum_algorithm="sha256",
    ),
    OsImageSpec(
        target_id="ubuntu-24.04",
        distro="ubuntu",
        version_id="24.04",
        codename="noble",
        display_name="Ubuntu 24.04 LTS (Noble Numbat)",
        base_url="https://cloud-images.ubuntu.com/noble/current",
        image_filename="noble-server-cloudimg-amd64.img",
        manifest_filename="SHA256SUMS",
        checksum_algorithm="sha256",
    ),
)

OS_MATRIX_BY_ID: Dict[str, OsImageSpec] = {spec.target_id: spec for spec in OFFICIAL_OS_MATRIX}


@dataclass(frozen=True)
class PendingArtifactContract:
    """
    Exact contract required by `v4_vm_matrix.py` from the Release/Installer/Rust builders
    to transition from clean-guest boot verification to full v4 matrix certification.
    """

    contract_version: str = "4.0.0-clean-host-v1"
    archive_filename: str = "aetherflow-linux-amd64.tar.gz"
    checksum_filename: str = "SHA256SUMS"
    required_archive_entries: Tuple[str, ...] = (
        "aetherflow-api",
        "af",
        "bin/af",
        ".version",
        "deploy/release-manager.sh",
        "deploy/release-manager.conf",
        "config/packages.json",
        "config/package_automation.json",
    )
    required_executable_entries: Tuple[str, ...] = (
        "aetherflow-api",
        "af",
        "bin/af",
        "deploy/release-manager.sh",
    )
    max_glibc_version: str = "2.35"
    lowest_glibc_target: str = "ubuntu-22.04"
    health_ready_endpoint: str = "http://127.0.0.1:8080/health/ready"
    expected_health_statuses: Tuple[str, ...] = ("ready", "ok")
    installer_env_overrides: Tuple[str, ...] = (
        "AETHERFLOW_PREBUILT_TARBALL",
        "AETHERFLOW_PREBUILT_SHA256_FILE",
        "AETHERFLOW_PREBUILT_SHA256",
        "AETHERFLOW_RELEASE_TAG",
    )


DEFAULT_ARTIFACT_CONTRACT = PendingArtifactContract()


@dataclass
class CommandEvidence:
    """Machine-readable record of a bounded command execution."""

    label: str
    command: str
    exit_code: int
    duration_seconds: float
    stdout_excerpt: str
    stderr_excerpt: str
    timed_out: bool = False


@dataclass
class ImageVerificationEvidence:
    """Machine-readable record of official cloud image manifest & digest verification."""

    target_id: str
    image_url: str
    manifest_url: str
    local_path: str
    checksum_algorithm: str
    expected_digest: str
    actual_digest: str
    sha256_digest: str
    size_bytes: int
    verified_at: str


@dataclass
class GuestBootEvidence:
    """Machine-readable record of a real clean-OS QEMU/KVM guest boot and readiness probe."""

    target_id: str
    run_id: str
    qemu_pid: int
    ssh_port: int
    boot_ready_seconds: float
    os_release: Dict[str, str]
    kernel_release: str
    uname_full: str
    glibc_version: str
    systemd_state: str
    systemd_version: str
    cloud_init_status: str
    root_disk_avail_kb: int
    commands: List[CommandEvidence] = field(default_factory=list)


@dataclass
class DrillPhaseResult:
    """Outcome of a single clean-OS lifecycle drill phase on a booted guest."""

    phase: str
    status: str  # "passed", "failed", "skipped_pending_artifact"
    summary: str
    details: Dict[str, Any] = field(default_factory=dict)
    commands: List[CommandEvidence] = field(default_factory=list)


@dataclass
class TargetMatrixReport:
    """Complete evidence record for a single target OS in the matrix."""

    target_id: str
    display_name: str
    image_evidence: Optional[ImageVerificationEvidence]
    boot_evidence: Optional[GuestBootEvidence]
    drills: List[DrillPhaseResult] = field(default_factory=list)
    overall_status: str = "pending"
    error: Optional[str] = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_glibc_tuple(version_str: str) -> Tuple[int, ...]:
    """Parses a GLIBC version string like '2.35' or '2.41' into an integer tuple."""
    cleaned = version_str.strip()
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", cleaned)
    if not m:
        raise ValueError(f"invalid GLIBC version string: {version_str!r}")
    parts = [int(m.group(1)), int(m.group(2))]
    if m.group(3) is not None:
        parts.append(int(m.group(3)))
    return tuple(parts)


def extract_max_glibc_from_elf_symbols(readelf_output: str) -> Optional[str]:
    """
    Extracts the maximum required `GLIBC_x.y[.z]` symbol version from `readelf --version-info`
    or `objdump -T` output. Returns `None` if no GLIBC symbols are present (e.g. static musl).
    """
    matches = re.findall(r"GLIBC_(\d+\.\d+(?:\.\d+)?)", readelf_output)
    if not matches:
        return None
    best_str = max(matches, key=parse_glibc_tuple)
    return best_str


def is_glibc_compatible(binary_max_glibc: Optional[str], target_glibc: str) -> bool:
    """Returns True if a binary requiring `binary_max_glibc` can run on `target_glibc`."""
    if binary_max_glibc is None:
        return True
    return parse_glibc_tuple(binary_max_glibc) <= parse_glibc_tuple(target_glibc)


def parse_checksum_manifest(
    manifest_text: str,
    target_filename: str,
    algorithm: str = "sha256",
) -> str:
    """
    Parses an official Debian `SHA512SUMS` or Ubuntu `SHA256SUMS` manifest and returns the
    lowercase hex digest for `target_filename`.
    Fails closed if `target_filename` is missing or the digest length/hex format is invalid.
    """
    expected_len = {"sha256": 64, "sha512": 128}.get(algorithm.lower())
    if expected_len is None:
        raise ValueError(f"unsupported checksum algorithm: {algorithm!r}")

    if not target_filename or "/" in target_filename or "\\" in target_filename:
        raise ValueError(f"invalid target filename: {target_filename!r}")

    starred = f"*{target_filename}"
    for raw_line in manifest_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest_raw, name_raw = parts[0], parts[1]
        if name_raw in (target_filename, starred):
            digest = digest_raw.lower()
            if len(digest) != expected_len or not all(c in "0123456789abcdef" for c in digest):
                raise ValueError(
                    f"malformed {algorithm.upper()} digest {digest_raw!r} for {target_filename}"
                )
            return digest

    raise ValueError(f"filename {target_filename!r} not found in {algorithm.upper()} manifest")


def compute_file_digest(path: Path, algorithm: str = "sha256") -> str:
    """Computes the lowercase hex digest (`sha256` or `sha512`) of `path`."""
    algo = algorithm.lower()
    if algo == "sha256":
        hasher = hashlib.sha256()
    elif algo == "sha512":
        hasher = hashlib.sha512()
    else:
        raise ValueError(f"unsupported hash algorithm: {algorithm!r}")

    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def parse_os_release_text(text: str) -> Dict[str, str]:
    """Parses `/etc/os-release` key=value lines without executing shell code."""
    result: Dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
            v = v[1:-1]
        result[k] = v
    return result


def validate_work_root_path(work_root: str) -> PurePosixPath:
    """
    Enforces that the VM workspace path resides strictly under `/var/tmp/aetherflow-v4-vm*`
    so the harness can never touch `/tmp` (99% full) or `/opt/AetherFlow`.
    """
    p = PurePosixPath(work_root)
    if not p.is_absolute():
        raise ValueError(f"work_root must be an absolute POSIX path: {work_root!r}")
    if ".." in p.parts:
        raise ValueError(f"work_root must not contain parent traversal '..': {work_root!r}")
    normalized = str(p)
    if not normalized.startswith("/var/tmp/aetherflow-v4-vm"):
        raise ValueError(
            f"work_root must reside under '/var/tmp/aetherflow-v4-vm*' (got {work_root!r})"
        )
    return p


def build_qemu_environment(qemu_root: str) -> Dict[str, str]:
    """Builds the isolated `LD_LIBRARY_PATH` and `QEMU_MODULE_DIR` environment for extracted QEMU."""
    root = PurePosixPath(qemu_root)
    lib_x86 = str(root / "usr/lib/x86_64-linux-gnu")
    lib_root = str(root / "lib/x86_64-linux-gnu")
    mod_dir = str(root / "usr/lib/x86_64-linux-gnu/qemu")
    return {
        "LD_LIBRARY_PATH": f"{lib_x86}:{lib_root}",
        "QEMU_MODULE_DIR": mod_dir,
    }


def build_qemu_command(
    *,
    qemu_root: str,
    overlay_qcow2: str,
    seed_iso: str,
    ssh_port: int,
    pidfile: str,
    serial_log: str,
    vcpus: int = DEFAULT_VM_VCPUS,
    memory_mib: int = DEFAULT_VM_MEMORY_MIB,
    use_nice: bool = True,
) -> List[str]:
    """
    Constructs the exact QEMU/KVM command line for a clean-OS guest:
      - `accel=kvm`, `-cpu host`
      - Loopback-only SSH port forwarding (`127.0.0.1:<ssh_port>-:22`)
      - Virtio-blk disks for overlay qcow2 and NoCloud seed ISO
      - Zero host filesystem mounts (`-fsdev` / `-virtfs` are never used)
      - Explicit `-L` firmware paths into extracted `qemu-root/usr/share/{qemu,seabios}`
    """
    if not (1024 <= ssh_port <= 65535):
        raise ValueError(f"ssh_port must be in 1024..65535 (got {ssh_port})")
    if vcpus < 1 or vcpus > 4:
        raise ValueError(f"vcpus must be between 1 and 4 for host safety (got {vcpus})")
    if memory_mib < 512 or memory_mib > 4096:
        raise ValueError(f"memory_mib must be between 512 and 4096 MiB (got {memory_mib})")

    qroot = PurePosixPath(qemu_root)
    qemu_bin = str(qroot / "usr/bin/qemu-system-x86_64")
    share_qemu = str(qroot / "usr/share/qemu")
    share_seabios = str(qroot / "usr/share/seabios")

    cmd: List[str] = []
    if use_nice:
        cmd.extend(["nice", "-n", "10", "ionice", "-c", "2", "-n", "7"])

    cmd.extend(
        [
            qemu_bin,
            "-name",
            f"aetherflow-v4-vm-{ssh_port}",
            "-machine",
            "q35,accel=kvm",
            "-cpu",
            "host",
            "-smp",
            str(vcpus),
            "-m",
            f"{memory_mib}M",
            "-L",
            share_qemu,
            "-L",
            share_seabios,
            "-display",
            "none",
            "-no-reboot",
            "-daemonize",
            "-pidfile",
            pidfile,
            "-serial",
            f"file:{serial_log}",
            "-drive",
            f"file={overlay_qcow2},if=virtio,format=qcow2,cache=writeback,discard=unmap",
            "-drive",
            f"file={seed_iso},if=virtio,media=cdrom,format=raw,readonly=on",
            "-netdev",
            f"user,id=net0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22",
            "-device",
            "virtio-net-pci,netdev=net0",
            "-device",
            "virtio-rng-pci",
        ]
    )
    return cmd


def render_nocloud_seed_files(
    *,
    instance_id: str,
    hostname: str,
    admin_ssh_pubkey: str,
    guest_host_ed25519_private: str,
    guest_host_ed25519_public: str,
) -> Tuple[str, str]:
    """
    Renders `(user_data, meta_data)` for a NoCloud `cidata` seed ISO.
    Pre-seeds a deterministic per-VM SSH host key so the host harness can verify
    the guest with `StrictHostKeyChecking=yes` and a dedicated `UserKnownHostsFile`
    (no `StrictHostKeyChecking=no` bypass).
    """
    pub_clean = admin_ssh_pubkey.strip()
    if not pub_clean.startswith("ssh-"):
        raise ValueError("admin_ssh_pubkey must be a valid OpenSSH public key line")

    priv_indented = "\n".join(
        f"    {line}" for line in guest_host_ed25519_private.strip().splitlines()
    )
    pub_host_clean = guest_host_ed25519_public.strip()

    user_data = (
        "#cloud-config\n"
        f"hostname: {hostname}\n"
        "manage_etc_hosts: true\n"
        "disable_root: false\n"
        "ssh_pwauth: false\n"
        "users:\n"
        "  - name: root\n"
        "    lock_passwd: true\n"
        "    ssh_authorized_keys:\n"
        f"      - {pub_clean}\n"
        "ssh_keys:\n"
        "  ed25519_private: |\n"
        f"{priv_indented}\n"
        f"  ed25519_public: {pub_host_clean}\n"
        "growpart:\n"
        "  mode: auto\n"
        "  devices: ['/']\n"
        "  ignore_growroot_disabled: false\n"
        "resize_rootfs: true\n"
        "runcmd:\n"
        "  - [ systemctl, enable, --now, ssh ]\n"
    )

    meta_data = (
        f"instance-id: {instance_id}\n"
        f"local-hostname: {hostname}\n"
    )
    return user_data, meta_data


def verify_release_artifact_contract(
    archive_path: Path,
    manifest_path: Optional[Path] = None,
    contract: PendingArtifactContract = DEFAULT_ARTIFACT_CONTRACT,
    readelf_symbol_Inspector: Optional[Callable[[bytes], Optional[str]]] = None,
    require_manifest: bool = True,
) -> Dict[str, Any]:
    """
    Verifies a candidate v4 release archive (`.tar.gz`) and independent `SHA256SUMS` manifest
    against the `PendingArtifactContract`.
    When `require_manifest=True` (default), omitting `manifest_path` or passing the archive itself
    as the manifest fails closed so a sidecar checksum is never synthesized.
    Returns a machine-readable verification dictionary with `valid: bool` and `errors: List[str]`.
    """
    errors: List[str] = []
    details: Dict[str, Any] = {
        "archive_path": str(archive_path),
        "manifest_path": str(manifest_path) if manifest_path else None,
        "contract_version": contract.contract_version,
        "present_entries": [],
        "missing_entries": [],
        "non_executable_entries": [],
        "symlinks_or_unsafe_entries": [],
        "sha256_verified": False,
        "actual_sha256": None,
        "expected_sha256": None,
        "manifest_file_sha256": None,
        "version_stamp": None,
        "binary_glibc_versions": {},
        "binary_max_glibc": None,
        "glibc_compatible_ubuntu_2204": None,
    }

    if not archive_path.is_file():
        errors.append(f"archive file not found: {archive_path}")
        return {"valid": False, "errors": errors, "details": details}

    actual_sha = compute_file_digest(archive_path, "sha256")
    details["actual_sha256"] = actual_sha

    if manifest_path is None:
        if require_manifest:
            errors.append(
                "independent --artifact-sha256-file (SHA256SUMS) is required for verification; refusing to synthesize checksum sidecar"
            )
    else:
        if not manifest_path.is_file():
            errors.append(f"SHA256SUMS manifest file not found: {manifest_path}")
        else:
            try:
                if archive_path.resolve() == manifest_path.resolve():
                    errors.append(
                        "--artifact-sha256-file (SHA256SUMS) must be an independent file distinct from the archive tarball"
                    )
                else:
                    details["manifest_file_sha256"] = compute_file_digest(manifest_path, "sha256")
                    expected_sha = parse_checksum_manifest(
                        manifest_path.read_text(encoding="utf-8"),
                        archive_path.name,
                        algorithm="sha256",
                    )
                    details["expected_sha256"] = expected_sha
                    if actual_sha != expected_sha:
                        errors.append(
                            f"SHA-256 mismatch for {archive_path.name}: expected {expected_sha}, got {actual_sha}"
                        )
                    else:
                        details["sha256_verified"] = True
            except ValueError as exc:
                errors.append(str(exc))

    entry_modes: Dict[str, int] = {}
    release_binary_bytes: Dict[str, bytes] = {}

    try:
        with tarfile.open(archive_path, mode="r:gz") as tf:
            for member in tf.getmembers():
                raw_name = member.name
                norm_parts: List[str] = []
                unsafe = False
                for part in PurePosixPath(raw_name).parts:
                    if part in ("", "."):
                        continue
                    if part == ".." or part.startswith("/"):
                        unsafe = True
                        break
                    norm_parts.append(part)
                norm_name = "/".join(norm_parts)
                if unsafe:
                    details["symlinks_or_unsafe_entries"].append(raw_name)
                    errors.append(f"unsafe path traversal in archive entry: {raw_name!r}")
                    continue
                if not norm_name:
                    continue
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    details["symlinks_or_unsafe_entries"].append(norm_name)
                    errors.append(
                        f"disallowed non-regular/symlink entry in release archive: {norm_name!r}"
                    )
                    continue
                if member.isfile():
                    entry_modes[norm_name] = member.mode & 0o777
                    if norm_name == ".version":
                        extracted = tf.extractfile(member)
                        if extracted is not None:
                            details["version_stamp"] = (
                                extracted.read().decode("utf-8", errors="replace").strip()
                            )
                    elif norm_name in ("aetherflow-api", "af", "bin/af"):
                        if member.size == 0:
                            errors.append(f"{norm_name} binary in archive is 0 bytes")
                        else:
                            extracted = tf.extractfile(member)
                            if extracted is not None:
                                release_binary_bytes[norm_name] = extracted.read()
    except (tarfile.TarError, OSError) as exc:
        errors.append(f"failed to read tar.gz archive: {exc}")
        return {"valid": False, "errors": errors, "details": details}

    details["present_entries"] = sorted(entry_modes.keys())

    for req in contract.required_archive_entries:
        if req not in entry_modes:
            details["missing_entries"].append(req)
            errors.append(f"missing required archive entry: {req}")

    for exe in contract.required_executable_entries:
        if exe in entry_modes and (entry_modes[exe] & 0o111) == 0:
            details["non_executable_entries"].append(exe)
            errors.append(f"archive entry {exe!r} is not marked executable (mode={oct(entry_modes[exe])})")

    if not details["version_stamp"]:
        errors.append("archive .version stamp is missing or empty")

    if "af" in release_binary_bytes and "bin/af" in release_binary_bytes:
        if release_binary_bytes["af"] != release_binary_bytes["bin/af"]:
            errors.append("af and bin/af must contain identical CLI bytes")
    if readelf_symbol_Inspector is not None:
        compatibility = []
        for binary_name, binary_bytes in release_binary_bytes.items():
            max_glibc = readelf_symbol_Inspector(binary_bytes)
            details["binary_glibc_versions"][binary_name] = max_glibc
            compat = is_glibc_compatible(max_glibc, contract.max_glibc_version)
            compatibility.append(compat)
            if not compat:
                errors.append(
                    f"{binary_name} requires GLIBC_{max_glibc}, which exceeds Ubuntu 22.04 max GLIBC_{contract.max_glibc_version}"
                )
        known_versions = [version for version in details["binary_glibc_versions"].values() if version is not None]
        if known_versions:
            details["binary_max_glibc"] = max(known_versions, key=parse_glibc_tuple)
        if compatibility:
            details["glibc_compatible_ubuntu_2204"] = all(compatibility)

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "details": details,
    }


REQUIRED_SOURCE_LAYOUT_ENTRIES: Tuple[str, ...] = (
    "setup/modules/00-core.sh",
    "setup/modules/02-packages.sh",
    "setup/modules/05-finalize.sh",
    "setup/modules/06-state.sh",
    "setup/modules/modern_stack.sh",
    "deploy/release-manager.sh",
    "deploy/release-manager.conf",
)

MANDATORY_CERTIFICATION_PHASES: Tuple[str, ...] = (
    "bootstrap_install_health_and_cli",
    "release_update",
    "failed_health_rollback_and_db_recovery",
    "interrupted_update_recovery",
)

OPTIONAL_FIXTURE_PHASES: Tuple[str, ...] = (
    "interrupted_update_recovery_fixture",
)


def inspect_source_tarball_layout(
    tarball_path: Path,
    required_entries: Sequence[str] = REQUIRED_SOURCE_LAYOUT_ENTRIES,
) -> Dict[str, Any]:
    """
    Inspects a source tarball before or during extraction and determines whether it is:
      - `flat` (`strip_components = 0`): required paths like `setup/modules/modern_stack.sh` sit at archive root
      - `single_top_dir` (`strip_components = 1`): all entries sit under a single top-level directory prefix
    Rejects tarballs containing unsafe path traversal (`..` or leading `/`), symlinks/device nodes
    outside normal files/links, or missing any required installer/deploy files (`setup/...`, `deploy/...`).
    Never relies on `tar --strip-components=1 || tar` fallback (which succeeds on a flat tarball while
    silently dropping top-level files and `setup/` paths).
    """
    if not tarball_path.is_file():
        raise ValueError(f"source tarball not found: {tarball_path}")

    raw_files: List[str] = []
    unsafe_entries: List[str] = []

    try:
        with tarfile.open(tarball_path, mode="r:*") as tf:
            for member in tf.getmembers():
                raw_name = member.name or ""
                parts: List[str] = []
                is_unsafe = False
                if raw_name.startswith("/") or raw_name.startswith("\\"):
                    is_unsafe = True
                for part in PurePosixPath(raw_name).parts:
                    if part in ("", "."):
                        continue
                    if part == ".." or part.startswith("/"):
                        is_unsafe = True
                        break
                    parts.append(part)
                norm = "/".join(parts)
                if is_unsafe:
                    unsafe_entries.append(raw_name)
                    continue
                if not norm:
                    continue
                if member.isdev() or member.isfifo():
                    unsafe_entries.append(norm)
                    continue
                if member.isfile() or member.issym():
                    raw_files.append(norm)
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"failed to inspect source tarball {tarball_path}: {exc}") from exc

    if unsafe_entries:
        raise ValueError(
            f"source tarball {tarball_path} contains unsafe entries: {unsafe_entries[:5]}"
        )

    file_set = set(raw_files)
    flat_missing = [req for req in required_entries if req not in file_set]
    if not flat_missing:
        return {
            "valid": True,
            "layout": "flat",
            "strip_components": 0,
            "top_level_prefix": None,
            "required_entries_verified": list(required_entries),
            "entry_count": len(file_set),
        }

    # Check if all entries share a single top-level directory prefix
    top_prefixes = {p.split("/", 1)[0] for p in file_set if "/" in p}
    root_level_files = [p for p in file_set if "/" not in p]
    if len(top_prefixes) == 1 and not root_level_files:
        prefix = next(iter(top_prefixes))
        stripped_set = {
            p.split("/", 1)[1] for p in file_set if p.startswith(prefix + "/")
        }
        stripped_missing = [req for req in required_entries if req not in stripped_set]
        if not stripped_missing:
            return {
                "valid": True,
                "layout": "single_top_dir",
                "strip_components": 1,
                "top_level_prefix": prefix,
                "required_entries_verified": list(required_entries),
                "entry_count": len(stripped_set),
            }
        raise ValueError(
            f"source tarball {tarball_path} (single_top_dir={prefix!r}) is missing required entries: {stripped_missing}"
        )

    raise ValueError(
        f"source tarball {tarball_path} has invalid or incomplete layout; missing required entries at root: {flat_missing}"
    )


def extract_validated_source_tarball(
    tarball_path: Path,
    dest_dir: Path,
    required_entries: Sequence[str] = REQUIRED_SOURCE_LAYOUT_ENTRIES,
) -> Dict[str, Any]:
    """
    Validates `tarball_path` via `inspect_source_tarball_layout`, extracts it into `dest_dir`
    using the exact `strip_components` determined from archive structure (no fallback ambiguity),
    and verifies all `required_entries` exist as non-empty files on disk after extraction.
    """
    layout_info = inspect_source_tarball_layout(tarball_path, required_entries=required_entries)
    strip_count = int(layout_info["strip_components"])

    dest_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tarball_path, mode="r:*") as tf:
        for member in tf.getmembers():
            parts = [
                p
                for p in PurePosixPath(member.name or "").parts
                if p not in ("", ".")
            ]
            if len(parts) <= strip_count:
                continue
            rel_parts = parts[strip_count:]
            if any(p == ".." or p.startswith("/") for p in rel_parts):
                raise ValueError(f"unsafe archive member path: {member.name!r}")
            rel_path = Path(*rel_parts)
            target_path = dest_dir / rel_path

            if member.isdir():
                target_path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target_path.parent.mkdir(parents=True, exist_ok=True)
                extracted = tf.extractfile(member)
                if extracted is None:
                    raise ValueError(f"unable to read archive file member: {member.name!r}")
                target_path.write_bytes(extracted.read())
                mode = member.mode & 0o777
                if mode:
                    try:
                        os.chmod(target_path, mode)
                    except OSError:
                        pass

    missing_after: List[str] = []
    for req in required_entries:
        req_path = dest_dir / Path(*PurePosixPath(req).parts)
        if not req_path.is_file() or req_path.stat().st_size == 0:
            missing_after.append(req)

    if missing_after:
        raise ValueError(
            f"post-extraction verification failed in {dest_dir}: missing or empty required files {missing_after}"
        )

    return layout_info


def validate_certification_inputs(
    *,
    artifact_tarball: Optional[Path],
    artifact_sha256_file: Optional[Path],
    source_tarball: Optional[Path],
    contract: PendingArtifactContract = DEFAULT_ARTIFACT_CONTRACT,
    readelf_symbol_Inspector: Optional[Callable[[bytes], Optional[str]]] = None,
) -> Dict[str, Any]:
    """
    Enforces strict pre-certification supply and verification rules:
      1. If `artifact_tarball` is None or does not exist, status is `pending_artifact` (cannot certify).
      2. If `artifact_tarball` is supplied, an independent `artifact_sha256_file` (`SHA256SUMS`)
         MUST also be supplied, MUST exist as a distinct file (`resolve() != artifact_tarball.resolve()`),
         and MUST cryptographically match `artifact_tarball`. Synthesizing a checksum sidecar from the
         tarball on the fly is strictly forbidden.
      3. `source_tarball` MUST exist and pass `inspect_source_tarball_layout`.
      4. `verify_release_artifact_contract` MUST pass (including `sha256_verified == True`).
    Returns a dictionary containing `status` (`"verified"`, `"pending_artifact"`, or `"failed"`),
    `errors`, `artifact_sha256`, `manifest_sha256`, `source_sha256`, `source_layout`, and `contract_report`.
    """
    supplied = bool(artifact_tarball and str(artifact_tarball).strip())
    result: Dict[str, Any] = {
        "supplied": supplied,
        "status": "pending_artifact",
        "valid": False,
        "errors": [],
        "artifact_tarball": str(artifact_tarball) if artifact_tarball else None,
        "artifact_sha256_file": str(artifact_sha256_file) if artifact_sha256_file else None,
        "source_tarball": str(source_tarball) if source_tarball else None,
        "artifact_sha256": None,
        "manifest_expected_sha256": None,
        "manifest_file_sha256": None,
        "source_sha256": None,
        "source_layout": None,
        "contract_report": None,
    }

    if not supplied or artifact_tarball is None:
        result["errors"].append(
            "prebuilt v4 release artifact (--artifact-tarball) was not supplied"
        )
        return result

    if not artifact_tarball.is_file():
        result["status"] = "failed"
        result["errors"].append(f"supplied artifact tarball does not exist: {artifact_tarball}")
        return result

    # Enforce independent supplied SHA256SUMS manifest (never synthesize sidecar)
    if artifact_sha256_file is None or not str(artifact_sha256_file).strip():
        result["status"] = "failed"
        result["errors"].append(
            "certify-matrix requires an independent supplied --artifact-sha256-file (SHA256SUMS); refusing to synthesize checksum sidecar"
        )
        return result

    if not artifact_sha256_file.is_file():
        result["status"] = "failed"
        result["errors"].append(
            f"supplied --artifact-sha256-file does not exist: {artifact_sha256_file}"
        )
        return result

    try:
        if artifact_tarball.resolve() == artifact_sha256_file.resolve():
            result["status"] = "failed"
            result["errors"].append(
                "--artifact-sha256-file must be an independent manifest file, not the tarball itself"
            )
            return result
    except OSError:
        pass

    result["manifest_file_sha256"] = compute_file_digest(artifact_sha256_file, "sha256")

    contract_report = verify_release_artifact_contract(
        artifact_tarball,
        artifact_sha256_file,
        contract=contract,
        readelf_symbol_Inspector=readelf_symbol_Inspector,
    )
    result["contract_report"] = contract_report
    result["artifact_sha256"] = contract_report["details"].get("actual_sha256")
    result["manifest_expected_sha256"] = contract_report["details"].get("expected_sha256")

    if not contract_report["valid"] or not contract_report["details"].get("sha256_verified"):
        result["status"] = "failed"
        result["errors"].extend(contract_report["errors"])
        if not contract_report["details"].get("sha256_verified"):
            result["errors"].append("artifact SHA-256 was not verified against independent SHA256SUMS")
        return result

    if source_tarball is None or not str(source_tarball).strip() or not source_tarball.is_file():
        result["status"] = "failed"
        result["errors"].append(
            f"valid --source-tarball is required for clean-host certification (got {source_tarball})"
        )
        return result

    try:
        source_layout = inspect_source_tarball_layout(source_tarball)
        result["source_layout"] = source_layout
        result["source_sha256"] = compute_file_digest(source_tarball, "sha256")
    except ValueError as exc:
        result["status"] = "failed"
        result["errors"].append(str(exc))
        return result

    result["status"] = "verified"
    result["valid"] = True
    return result


def evaluate_certification_status(
    drills: Sequence[Dict[str, Any]],
    mandatory_phases: Sequence[str] = MANDATORY_CERTIFICATION_PHASES,
) -> Tuple[str, List[str]]:
    """
    Determines the target `overall_status` (`"certified"`, `"failed"`, or `"boot_verified_pending_artifact"`)
    and any missing/failed mandatory phase reasons.

    Invariants enforced:
      - An empty `drills` list (`[]`) NEVER evaluates to `"certified"`.
      - Passing only optional/fixture phases (`interrupted_update_recovery_fixture`) NEVER evaluates
        to `"certified"`.
      - Every phase in `MANDATORY_CERTIFICATION_PHASES` must be present with `status == "passed"`
        and `details.get("real_execution") is not False` (for `interrupted_update_recovery`, must not
        be fixture-only).
    """
    if not drills:
        return "failed", ["no lifecycle drills were executed (empty drill list cannot certify)"]

    by_phase: Dict[str, Dict[str, Any]] = {}
    failed_reasons: List[str] = []

    for d in drills:
        phase_name = str(d.get("phase") or "")
        status = str(d.get("status") or "")
        by_phase[phase_name] = d
        if status == "failed":
            failed_reasons.append(f"phase {phase_name!r} failed: {d.get('summary', '')}")

    if failed_reasons:
        return "failed", failed_reasons

    if (
        len(drills) == 1
        and drills[0].get("phase") == "artifact_supply_check"
        and drills[0].get("status") == "skipped_pending_artifact"
    ):
        return "boot_verified_pending_artifact", [
            "awaiting final converged v4 release artifact and independent SHA256SUMS"
        ]

    missing_or_unpassed: List[str] = []
    for req_phase in mandatory_phases:
        entry = by_phase.get(req_phase)
        if entry is None:
            missing_or_unpassed.append(f"mandatory phase {req_phase!r} was not executed")
            continue
        if entry.get("status") != "passed":
            missing_or_unpassed.append(
                f"mandatory phase {req_phase!r} did not pass (status={entry.get('status')!r})"
            )
            continue
        details = entry.get("details") or {}
        if details.get("fixture_only") is True:
            missing_or_unpassed.append(
                f"mandatory phase {req_phase!r} is marked fixture_only=True; real lifecycle execution is required for certification"
            )

    if missing_or_unpassed:
        return "failed", missing_or_unpassed

    return "certified", []


def render_baseline_guest_build_script(*, jobs: int = 2) -> str:
    """
    Renders the in-guest build script for `build-baseline-artifact` inside Ubuntu 22.04 (GLIBC 2.35).
    Enforces:
      1. Real Next.js static export build (`NEXT_STATIC_EXPORT=1 npm run build --workspace frontend`)
         even when placeholder `web/dist` or `backend/web/dist` directories already exist in the repo.
      2. Verifies `web/dist/index.html` and `web/dist/_next` exist and are non-empty before Rust compile.
      3. Requires `backend-rs/Cargo.lock` to exist and runs `cargo fetch --locked` first, followed by
         offline (`CARGO_NET_OFFLINE=true`), locked (`CARGO_LOCKED=1` / `--locked`) compilation.
      4. Enforces resource discipline inside the guest (`nice -n 10 ionice -c 2 -n 7`, `CARGO_BUILD_JOBS=2`).
    """
    if jobs < 1 or jobs > 4:
        raise ValueError(f"jobs must be between 1 and 4 (got {jobs})")
    return f"""set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -yqq
apt-get install -yqq build-essential pkg-config libssl-dev libsqlite3-dev curl ca-certificates git binutils >/dev/null
tar -xzf /var/tmp/af-build/node.tar.gz -C /usr/local/nodejs
ln -sfn /usr/local/nodejs/bin/node /usr/local/bin/node
ln -sfn /usr/local/nodejs/bin/npm /usr/local/bin/npm
ln -sfn /usr/local/nodejs/bin/npx /usr/local/bin/npx
if ! command -v cargo >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
fi
export PATH="/root/.cargo/bin:/usr/local/nodejs/bin:${{PATH}}"
export CARGO_BUILD_JOBS={jobs}
export RUSTFLAGS="-C link-arg=-fuse-ld=bfd"
tar -xzf /var/tmp/af-build/src.tar.gz -C /var/tmp/af-build/src
cd /var/tmp/af-build/src

# 1. Always build or verify real exported frontend assets (never skip merely because placeholder web/dist directory exists)
if [[ ! -d frontend ]]; then
    echo "ERROR: frontend directory missing from source snapshot" >&2
    exit 1
fi
rm -rf web/dist backend/web/dist frontend/out
nice -n 10 ionice -c 2 -n 7 npm ci --no-fund --no-audit
NEXT_STATIC_EXPORT=1 nice -n 10 ionice -c 2 -n 7 npm run build --workspace frontend
test -s frontend/out/index.html
test -d frontend/out/_next
mkdir -p web/dist backend/web/dist
cp -R frontend/out/. web/dist/
cp -R frontend/out/. backend/web/dist/
test -s web/dist/index.html
test -d web/dist/_next
test -s backend/web/dist/index.html
test -d backend/web/dist/_next

# 2. Require final committed Cargo.lock, prefetch crates explicitly, then compile offline with --locked and 2 jobs
test -s backend-rs/Cargo.lock
(
    cd backend-rs
    nice -n 10 ionice -c 2 -n 7 cargo fetch --locked
)
CARGO_LOCKED=1 CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS={jobs} BUILD_FRONTEND=0 RUN_TESTS=0 OUTPUT_DIR=/var/tmp/af-build/out \\
    nice -n 10 ionice -c 2 -n 7 bash scripts/build_gold.sh

readelf --version-info /var/tmp/af-build/out/linux-amd64/aetherflow-api | grep -oE 'GLIBC_[0-9]+\\.[0-9]+(\\.[0-9]+)?' | sort -V | tail -n 1 > /var/tmp/af-build/out/MAX_GLIBC.txt || true
"""


# ─────────────────────────────────────────────────────────────────────────────
# Remote / Local Linux Execution Engine
# ─────────────────────────────────────────────────────────────────────────────

REMOTE_ENGINE_SCRIPT = r"""
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import uuid

REQUIRED_SOURCE_LAYOUT_ENTRIES = (
    "setup/modules/00-core.sh",
    "setup/modules/02-packages.sh",
    "setup/modules/05-finalize.sh",
    "setup/modules/06-state.sh",
    "setup/modules/modern_stack.sh",
    "deploy/release-manager.sh",
    "deploy/release-manager.conf",
)

MANDATORY_CERTIFICATION_PHASES = (
    "bootstrap_install_health_and_cli",
    "release_update",
    "failed_health_rollback_and_db_recovery",
    "interrupted_update_recovery",
)

def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def run_bounded(cmd, *, timeout=120, env=None, cwd=None, check=False, label="cmd"):
    t0 = time.monotonic()
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    timed_out = False
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            env=merged_env,
            cwd=cwd,
        )
        rc = proc.returncode
        out = proc.stdout or ""
        err = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = 124
        out = (exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""))
        err = (exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""))
    dt = round(time.monotonic() - t0, 3)
    rec = {
        "label": label,
        "command": " ".join(shlex.quote(str(x)) for x in cmd),
        "exit_code": rc,
        "duration_seconds": dt,
        "stdout_excerpt": out[-4000:],
        "stderr_excerpt": err[-4000:],
        "timed_out": timed_out,
    }
    if check and rc != 0:
        raise RuntimeError(f"{label} failed (rc={rc}, timed_out={timed_out}): {err[-800:] or out[-800:]}")
    return rc, out, err, rec

def compute_digest(path, algo):
    h = hashlib.sha512() if algo == "sha512" else hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def parse_manifest(text, filename, algo):
    expected_len = 128 if algo == "sha512" else 64
    starred = "*" + filename
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] in (filename, starred):
            digest = parts[0].lower()
            if len(digest) == expected_len and all(c in "0123456789abcdef" for c in digest):
                return digest
            raise RuntimeError(f"Malformed {algo} digest for {filename}: {parts[0]}")
    raise RuntimeError(f"{filename} not found in manifest")

def inspect_source_tarball(tarball_path, required_entries=REQUIRED_SOURCE_LAYOUT_ENTRIES):
    tarball_path = Path(tarball_path)
    if not tarball_path.is_file():
        raise RuntimeError(f"source tarball not found: {tarball_path}")
    raw_files = []
    unsafe_entries = []
    with tarfile.open(tarball_path, mode="r:*") as tf:
        for member in tf.getmembers():
            raw_name = member.name or ""
            parts = []
            is_unsafe = raw_name.startswith("/") or raw_name.startswith("\\")
            for part in PurePosixPath(raw_name).parts:
                if part in ("", "."):
                    continue
                if part == ".." or part.startswith("/"):
                    is_unsafe = True
                    break
                parts.append(part)
            norm = "/".join(parts)
            if is_unsafe:
                unsafe_entries.append(raw_name)
                continue
            if not norm:
                continue
            if member.isdev() or member.isfifo():
                unsafe_entries.append(norm)
                continue
            if member.isfile() or member.issym():
                raw_files.append(norm)
    if unsafe_entries:
        raise RuntimeError(f"source tarball {tarball_path} contains unsafe entries: {unsafe_entries[:5]}")
    file_set = set(raw_files)
    flat_missing = [req for req in required_entries if req not in file_set]
    if not flat_missing:
        return {
            "valid": True,
            "layout": "flat",
            "strip_components": 0,
            "top_level_prefix": None,
            "required_entries_verified": list(required_entries),
            "entry_count": len(file_set),
        }
    top_prefixes = {p.split("/", 1)[0] for p in file_set if "/" in p}
    root_level_files = [p for p in file_set if "/" not in p]
    if len(top_prefixes) == 1 and not root_level_files:
        prefix = next(iter(top_prefixes))
        stripped_set = {p.split("/", 1)[1] for p in file_set if p.startswith(prefix + "/")}
        stripped_missing = [req for req in required_entries if req not in stripped_set]
        if not stripped_missing:
            return {
                "valid": True,
                "layout": "single_top_dir",
                "strip_components": 1,
                "top_level_prefix": prefix,
                "required_entries_verified": list(required_entries),
                "entry_count": len(stripped_set),
            }
        raise RuntimeError(f"source tarball {tarball_path} (single_top_dir={prefix!r}) missing required entries: {stripped_missing}")
    raise RuntimeError(f"source tarball {tarball_path} has invalid layout; missing required entries at root: {flat_missing}")

def inspect_artifact_bundle(archive_path, manifest_path, contract):
    errors = []
    archive_p = Path(archive_path)
    manifest_p = Path(manifest_path) if manifest_path else None
    details = {
        "archive_path": str(archive_p),
        "manifest_path": str(manifest_p) if manifest_p else None,
        "contract_version": contract.get("contract_version", "4.0.0-clean-host-v1"),
        "present_entries": [],
        "missing_entries": [],
        "non_executable_entries": [],
        "symlinks_or_unsafe_entries": [],
        "sha256_verified": False,
        "actual_sha256": None,
        "expected_sha256": None,
        "manifest_file_sha256": None,
        "version_stamp": None,
        "binary_glibc_versions": {},
        "binary_max_glibc": None,
        "glibc_compatible_ubuntu_2204": None,
        "embedded_ui_index_present": False,
    }
    if not archive_p.is_file():
        errors.append(f"archive file not found: {archive_p}")
        return {"valid": False, "errors": errors, "details": details}
    actual_sha = compute_digest(archive_p, "sha256")
    details["actual_sha256"] = actual_sha

    if manifest_p is None or not str(manifest_path).strip():
        errors.append("independent --artifact-sha256-file (SHA256SUMS) is required for certification; refusing to synthesize checksum sidecar")
        return {"valid": False, "errors": errors, "details": details}
    if not manifest_p.is_file():
        errors.append(f"SHA256SUMS manifest file not found: {manifest_p}")
        return {"valid": False, "errors": errors, "details": details}
    if archive_p.resolve() == manifest_p.resolve():
        errors.append("SHA256SUMS manifest path must be distinct from the archive tarball")
        return {"valid": False, "errors": errors, "details": details}

    details["manifest_file_sha256"] = compute_digest(manifest_p, "sha256")
    try:
        expected_sha = parse_manifest(manifest_p.read_text(encoding="utf-8"), archive_p.name, "sha256")
        details["expected_sha256"] = expected_sha
        if actual_sha != expected_sha:
            errors.append(f"SHA-256 mismatch for {archive_p.name}: expected {expected_sha}, got {actual_sha}")
        else:
            details["sha256_verified"] = True
    except Exception as exc:
        errors.append(str(exc))

    entry_modes = {}
    binary_hashes = {}
    try:
        with tempfile.TemporaryDirectory(prefix="af-verify-contract-") as tmpd:
            tmp_root = Path(tmpd)
            with tarfile.open(archive_p, mode="r:gz") as tf:
                for member in tf.getmembers():
                    raw_name = member.name or ""
                    norm_parts = []
                    unsafe = raw_name.startswith("/") or raw_name.startswith("\\")
                    for part in PurePosixPath(raw_name).parts:
                        if part in ("", "."):
                            continue
                        if part == ".." or part.startswith("/"):
                            unsafe = True
                            break
                        norm_parts.append(part)
                    norm_name = "/".join(norm_parts)
                    if unsafe:
                        details["symlinks_or_unsafe_entries"].append(raw_name)
                        errors.append(f"unsafe path traversal in archive entry: {raw_name!r}")
                        continue
                    if not norm_name:
                        continue
                    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                        details["symlinks_or_unsafe_entries"].append(norm_name)
                        errors.append(f"disallowed non-regular/symlink entry in release archive: {norm_name!r}")
                        continue
                    if member.isfile():
                        entry_modes[norm_name] = member.mode & 0o777
                        if norm_name == ".version":
                            ex = tf.extractfile(member)
                            if ex is not None:
                                details["version_stamp"] = ex.read().decode("utf-8", errors="replace").strip()
                        elif norm_name in ("aetherflow-api", "af", "bin/af"):
                            if member.size == 0:
                                errors.append(f"{norm_name} binary in archive is 0 bytes")
                            else:
                                ex = tf.extractfile(member)
                                if ex is not None:
                                    bin_file = tmp_root / norm_name.replace("/", "-")
                                    data = ex.read()
                                    binary_hashes[norm_name] = hashlib.sha256(data).hexdigest()
                                    bin_file.write_bytes(data)
                                    if norm_name == "aetherflow-api":
                                        details["embedded_ui_index_present"] = (b"index.html" in data and b"_next/" in data)
                                    rc_re, out_re, _, _ = run_bounded(["readelf", "--version-info", str(bin_file)], timeout=20, check=False, label="readelf-glibc")
                                    if rc_re == 0:
                                        matches = re.findall(r"GLIBC_(\d+\.\d+(?:\.\d+)?)", out_re)
                                        if matches:
                                            version_key = lambda version: tuple(int(part) for part in version.split("."))
                                            max_g = max(matches, key=version_key)
                                            details["binary_glibc_versions"][norm_name] = max_g
                                            compat = version_key(max_g) <= version_key(contract.get("max_glibc_version", "2.35"))
                                            if not compat:
                                                errors.append(f"{norm_name} requires GLIBC_{max_g}, exceeding Ubuntu 22.04 max GLIBC_{contract.get('max_glibc_version', '2.35')}")
                                        else:
                                            details["binary_glibc_versions"][norm_name] = None
                                    else:
                                        errors.append(f"readelf inspection failed for {norm_name}: exit {rc_re}")
    except Exception as exc:
        errors.append(f"failed to inspect tar.gz archive: {exc}")
        return {"valid": False, "errors": errors, "details": details}

    if "af" in binary_hashes and "bin/af" in binary_hashes and binary_hashes["af"] != binary_hashes["bin/af"]:
        errors.append("af and bin/af must contain identical CLI bytes")
    versions = details["binary_glibc_versions"]
    known_versions = [version for version in versions.values() if version is not None]
    version_key = lambda version: tuple(int(part) for part in version.split("."))
    if known_versions:
        details["binary_max_glibc"] = max(known_versions, key=version_key)
    if versions:
        details["glibc_compatible_ubuntu_2204"] = len(versions) == len(binary_hashes) and all(
            version is None or version_key(version) <= version_key(contract.get("max_glibc_version", "2.35"))
            for version in versions.values()
        )
    details["present_entries"] = sorted(entry_modes.keys())
    for req in contract.get("required_archive_entries", ()):
        if req not in entry_modes:
            details["missing_entries"].append(req)
            errors.append(f"missing required archive entry: {req}")
    for exe in contract.get("required_executable_entries", ()):
        if exe in entry_modes and (entry_modes[exe] & 0o111) == 0:
            details["non_executable_entries"].append(exe)
            errors.append(f"archive entry {exe!r} is not marked executable")
    if not details["version_stamp"]:
        errors.append("archive .version stamp is missing or empty")

    return {"valid": len(errors) == 0, "errors": errors, "details": details}

def fetch_url_text(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "AetherFlow-v4-VM-Matrix/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="replace")

def ensure_verified_cloud_image(spec, images_dir):
    images_dir = Path(images_dir)
    images_dir.mkdir(parents=True, exist_ok=True)
    target_id = spec["target_id"]
    img_name = spec["image_filename"]
    algo = spec["checksum_algorithm"]
    manifest_url = f"{spec['base_url'].rstrip('/')}/{spec['manifest_filename']}"
    image_url = f"{spec['base_url'].rstrip('/')}/{img_name}"

    manifest_text = fetch_url_text(manifest_url, timeout=45)
    expected_digest = parse_manifest(manifest_text, img_name, algo)

    dest_path = images_dir / img_name
    manifest_cache = images_dir / f"{target_id}.{spec['manifest_filename']}"
    manifest_cache.write_text(manifest_text, encoding="utf-8")

    need_download = True
    if dest_path.is_file() and dest_path.stat().st_size > 0:
        actual = compute_digest(dest_path, algo)
        if actual == expected_digest:
            need_download = False

    if need_download:
        tmp_path = images_dir / f".{img_name}.part.{uuid.uuid4().hex[:8]}"
        try:
            subprocess.run(
                ["curl", "-fsSL", "--retry", "3", "--max-time", "600", "-o", str(tmp_path), image_url],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            actual = compute_digest(tmp_path, algo)
            if actual != expected_digest:
                raise RuntimeError(
                    f"Downloaded image checksum mismatch for {img_name}: expected {expected_digest}, got {actual}"
                )
            os.replace(tmp_path, dest_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    actual_digest = compute_digest(dest_path, algo)
    if actual_digest != expected_digest:
        raise RuntimeError(f"Checksum verification failed for {dest_path}")
    sha256_digest = actual_digest if algo == "sha256" else compute_digest(dest_path, "sha256")
    return {
        "target_id": target_id,
        "image_url": image_url,
        "manifest_url": manifest_url,
        "local_path": str(dest_path),
        "checksum_algorithm": algo,
        "expected_digest": expected_digest,
        "actual_digest": actual_digest,
        "sha256_digest": sha256_digest,
        "size_bytes": dest_path.stat().st_size,
        "verified_at": utc_now(),
    }

def allocate_loopback_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def terminate_owned_qemu_pid(pid):
    if not pid or pid <= 1:
        return
    try:
        cmdline_path = Path(f"/proc/{pid}/cmdline")
        if not cmdline_path.exists():
            return
        cmdline = cmdline_path.read_bytes().decode("utf-8", errors="replace")
        if "qemu-system-x86_64" not in cmdline and "aetherflow-v4-vm" not in cmdline:
            return
        os.kill(pid, signal.SIGTERM)
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if not Path(f"/proc/{pid}").exists():
                return
            time.sleep(0.2)
        if Path(f"/proc/{pid}").exists():
            os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    except PermissionError:
        return

class IsolatedVmSession:
    def __init__(self, spec, image_info, work_root, qemu_root, vcpus=2, memory_mib=3584, disk_size="24G"):
        self.spec = spec
        self.image_info = image_info
        self.work_root = Path(work_root)
        self.qemu_root = Path(qemu_root)
        self.vcpus = vcpus
        self.memory_mib = memory_mib
        self.disk_size = disk_size
        self.run_id = f"{spec['target_id']}-{int(time.time())}-{uuid.uuid4().hex[:6]}"
        self.run_dir = self.work_root / "runs" / self.run_id
        self.ssh_port = allocate_loopback_port()
        self.qemu_pid = 0
        self.commands = []

        qroot = self.qemu_root
        self.qemu_env = {
            "LD_LIBRARY_PATH": f"{qroot}/usr/lib/x86_64-linux-gnu:{qroot}/lib/x86_64-linux-gnu",
            "QEMU_MODULE_DIR": f"{qroot}/usr/lib/x86_64-linux-gnu/qemu",
        }
        self.qemu_bin = str(qroot / "usr/bin/qemu-system-x86_64")
        self.qemu_img_bin = str(qroot / "usr/bin/qemu-img")
        self.genisoimage_bin = str(qroot / "usr/bin/genisoimage")

    def __enter__(self):
        self.run_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.run_dir, 0o700)
        self._prepare_keys_and_seed()
        self._prepare_overlay()
        self._start_vm()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        if self.qemu_pid:
            terminate_owned_qemu_pid(self.qemu_pid)
            self.qemu_pid = 0
        # Remove heavy overlay and ephemeral keys after capturing logs/evidence
        for fname in ("overlay.qcow2", "seed.iso", "id_ed25519", "id_ed25519.pub", "guest_host_ed25519_key", "guest_host_ed25519_key.pub"):
            p = self.run_dir / fname
            if p.exists():
                try:
                    p.unlink()
                except OSError:
                    pass

    def _prepare_keys_and_seed(self):
        self.admin_key = self.run_dir / "id_ed25519"
        self.host_key = self.run_dir / "guest_host_ed25519_key"
        self.known_hosts = self.run_dir / "known_hosts"

        run_bounded(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"af-vm-{self.run_id}", "-f", str(self.admin_key)],
            timeout=15, check=True, label="keygen-admin",
        )
        run_bounded(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-C", f"host-{self.run_id}", "-f", str(self.host_key)],
            timeout=15, check=True, label="keygen-guest-host",
        )
        os.chmod(self.admin_key, 0o600)

        admin_pub = (self.run_dir / "id_ed25519.pub").read_text(encoding="utf-8").strip()
        host_priv = self.host_key.read_text(encoding="utf-8").strip()
        host_pub_full = (self.run_dir / "guest_host_ed25519_key.pub").read_text(encoding="utf-8").strip()
        host_pub_parts = host_pub_full.split()
        host_pub_key_only = " ".join(host_pub_parts[:2])

        # Pin the exact pre-seeded host key in known_hosts for [127.0.0.1]:<port>
        self.known_hosts.write_text(
            f"[127.0.0.1]:{self.ssh_port} {host_pub_key_only}\n",
            encoding="utf-8",
        )
        os.chmod(self.known_hosts, 0o600)

        hostname = f"af-{self.spec['target_id'].replace('.', '-')}"
        priv_indented = "\n".join("    " + line for line in host_priv.splitlines())
        user_data = (
            "#cloud-config\n"
            f"hostname: {hostname}\n"
            "manage_etc_hosts: true\n"
            "disable_root: false\n"
            "ssh_pwauth: false\n"
            "users:\n"
            "  - name: root\n"
            "    lock_passwd: true\n"
            "    ssh_authorized_keys:\n"
            f"      - {admin_pub}\n"
            "ssh_keys:\n"
            "  ed25519_private: |\n"
            f"{priv_indented}\n"
            f"  ed25519_public: {host_pub_full}\n"
            "growpart:\n"
            "  mode: auto\n"
            "  devices: ['/']\n"
            "  ignore_growroot_disabled: false\n"
            "resize_rootfs: true\n"
            "runcmd:\n"
            "  - [ systemctl, enable, --now, ssh ]\n"
        )
        meta_data = f"instance-id: {self.run_id}\nlocal-hostname: {hostname}\n"

        seed_dir = self.run_dir / "seed"
        seed_dir.mkdir(parents=True, exist_ok=True)
        (seed_dir / "user-data").write_text(user_data, encoding="utf-8")
        (seed_dir / "meta-data").write_text(meta_data, encoding="utf-8")

        self.seed_iso = self.run_dir / "seed.iso"
        _, _, _, rec = run_bounded(
            [
                self.genisoimage_bin,
                "-output", str(self.seed_iso),
                "-volid", "cidata",
                "-joliet",
                "-rock",
                str(seed_dir / "user-data"),
                str(seed_dir / "meta-data"),
            ],
            env=self.qemu_env,
            timeout=30,
            check=True,
            label="genisoimage-cidata",
        )
        self.commands.append(rec)

    def _prepare_overlay(self):
        self.overlay_qcow2 = self.run_dir / "overlay.qcow2"
        _, _, _, rec = run_bounded(
            [
                self.qemu_img_bin,
                "create",
                "-f", "qcow2",
                "-F", "qcow2",
                "-b", self.image_info["local_path"],
                str(self.overlay_qcow2),
                self.disk_size,
            ],
            env=self.qemu_env,
            timeout=30,
            check=True,
            label="qemu-img-overlay",
        )
        self.commands.append(rec)

    def _start_vm(self):
        self.pidfile = self.run_dir / "qemu.pid"
        self.serial_log = self.run_dir / "serial.log"
        qroot = self.qemu_root
        cmd = [
            "nice", "-n", "10",
            "ionice", "-c", "2", "-n", "7",
            self.qemu_bin,
            "-name", f"aetherflow-v4-vm-{self.ssh_port}",
            "-machine", "q35,accel=kvm",
            "-cpu", "host",
            "-smp", str(self.vcpus),
            "-m", f"{self.memory_mib}M",
            "-L", str(qroot / "usr/share/qemu"),
            "-L", str(qroot / "usr/share/seabios"),
            "-display", "none",
            "-no-reboot",
            "-daemonize",
            "-pidfile", str(self.pidfile),
            "-serial", f"file:{self.serial_log}",
            "-drive", f"file={self.overlay_qcow2},if=virtio,format=qcow2,cache=writeback,discard=unmap",
            "-drive", f"file={self.seed_iso},if=virtio,media=cdrom,format=raw,readonly=on",
            "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{self.ssh_port}-:22",
            "-device", "virtio-net-pci,netdev=net0",
            "-device", "virtio-rng-pci",
        ]
        _, _, _, rec = run_bounded(cmd, env=self.qemu_env, timeout=30, check=True, label="qemu-start")
        self.commands.append(rec)
        self.qemu_pid = int(self.pidfile.read_text(encoding="utf-8").strip())

    def ssh_base_args(self):
        return [
            "ssh",
            "-i", str(self.admin_key),
            "-p", str(self.ssh_port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=5",
            "root@127.0.0.1",
        ]

    def ssh_run(self, remote_script, *, timeout=120, check=False, label="ssh-cmd"):
        cmd = self.ssh_base_args() + [remote_script]
        rc, out, err, rec = run_bounded(cmd, timeout=timeout, check=check, label=label)
        self.commands.append(rec)
        return rc, out, err, rec

    def copy_to_guest(self, local_path, remote_path, *, timeout=180, label="scp-to-guest"):
        cmd = [
            "scp",
            "-i", str(self.admin_key),
            "-P", str(self.ssh_port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=10",
            str(local_path),
            f"root@127.0.0.1:{remote_path}",
        ]
        rc, out, err, rec = run_bounded(cmd, timeout=timeout, check=True, label=label)
        self.commands.append(rec)
        return rec

    def copy_from_guest(self, remote_path, local_path, *, timeout=180, label="scp-from-guest"):
        cmd = [
            "scp",
            "-i", str(self.admin_key),
            "-P", str(self.ssh_port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.known_hosts}",
            "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=10",
            f"root@127.0.0.1:{remote_path}",
            str(local_path),
        ]
        rc, out, err, rec = run_bounded(cmd, timeout=timeout, check=True, label=label)
        self.commands.append(rec)
        return rec

    def wait_for_ssh_and_systemd(self, timeout=180):
        t0 = time.monotonic()
        deadline = t0 + timeout
        last_err = ""
        while time.monotonic() < deadline:
            if not Path(f"/proc/{self.qemu_pid}").exists():
                raise RuntimeError(f"QEMU process {self.qemu_pid} exited prematurely during boot")
            rc, out, err, _ = run_bounded(
                self.ssh_base_args() + ["cloud-init status --wait >/dev/null 2>&1 || true; echo READY"],
                timeout=25,
                check=False,
                label="ssh-readiness-poll",
            )
            if rc == 0 and "READY" in out:
                boot_secs = round(time.monotonic() - t0, 2)
                probe_script = (
                    "set -e\n"
                    "cat /etc/os-release\n"
                    "echo '===SEP==='\n"
                    "uname -r\n"
                    "echo '===SEP==='\n"
                    "uname -a\n"
                    "echo '===SEP==='\n"
                    "ldd --version | head -n 1\n"
                    "echo '===SEP==='\n"
                    "systemctl is-system-running || true\n"
                    "echo '===SEP==='\n"
                    "systemctl --version | head -n 1\n"
                    "echo '===SEP==='\n"
                    "cloud-init status || true\n"
                    "echo '===SEP==='\n"
                    "df -Pk / | awk 'NR==2 {print $4}'\n"
                )
                _, pout, _, _ = self.ssh_run(probe_script, timeout=30, check=True, label="guest-identity-probe")
                sections = [s.strip() for s in pout.split("===SEP===")]
                os_rel = {}
                for line in sections[0].splitlines():
                    if "=" in line and not line.startswith("#"):
                        k, v = line.split("=", 1)
                        os_rel[k.strip()] = v.strip().strip('"').strip("'")
                glibc_line = sections[3] if len(sections) > 3 else ""
                m_glibc = re.search(r"(\d+\.\d+)", glibc_line.split()[-1] if glibc_line else "")
                glibc_ver = m_glibc.group(1) if m_glibc else glibc_line
                return {
                    "target_id": self.spec["target_id"],
                    "run_id": self.run_id,
                    "qemu_pid": self.qemu_pid,
                    "ssh_port": self.ssh_port,
                    "boot_ready_seconds": boot_secs,
                    "os_release": os_rel,
                    "kernel_release": sections[1] if len(sections) > 1 else "",
                    "uname_full": sections[2] if len(sections) > 2 else "",
                    "glibc_version": glibc_ver,
                    "systemd_state": sections[4] if len(sections) > 4 else "",
                    "systemd_version": sections[5] if len(sections) > 5 else "",
                    "cloud_init_status": sections[6] if len(sections) > 6 else "",
                    "root_disk_avail_kb": int(sections[7]) if len(sections) > 7 and sections[7].isdigit() else 0,
                    "commands": self.commands,
                }
            last_err = (err or out).strip()
            time.sleep(2.0)
        raise RuntimeError(f"Timed out waiting for SSH/cloud-init on {self.spec['target_id']} after {timeout}s: {last_err}")
"""


REMOTE_DRILL_HELPERS = r"""
def evaluate_remote_certification_status(drills, mandatory_phases=MANDATORY_CERTIFICATION_PHASES):
    if not drills:
        return "failed", ["no lifecycle drills were executed"]
    by_phase = {}
    failed_reasons = []
    for d in drills:
        phase_name = str(d.get("phase") or "")
        status = str(d.get("status") or "")
        by_phase[phase_name] = d
        if status == "failed":
            failed_reasons.append(f"phase {phase_name!r} failed: {d.get('summary', '')}")
    if failed_reasons:
        return "failed", failed_reasons
    if (
        len(drills) == 1
        and drills[0].get("phase") == "artifact_supply_check"
        and drills[0].get("status") == "skipped_pending_artifact"
    ):
        return "boot_verified_pending_artifact", ["awaiting final converged v4 release artifact and independent SHA256SUMS"]
    missing = []
    for req_phase in mandatory_phases:
        entry = by_phase.get(req_phase)
        if entry is None:
            missing.append(f"mandatory phase {req_phase!r} was not executed")
            continue
        if entry.get("status") != "passed":
            missing.append(f"mandatory phase {req_phase!r} did not pass (status={entry.get('status')!r})")
            continue
        details = entry.get("details") or {}
        if details.get("fixture_only") is True:
            missing.append(f"mandatory phase {req_phase!r} is marked fixture_only=True")
    if missing:
        return "failed", missing
    return "certified", []

def run_guest_lifecycle_drills(vm, *, artifact_tarball, artifact_sha256_file, source_tarball, validation_summary=None):
    drills = []

    if not artifact_tarball:
        drills.append({
            "phase": "artifact_supply_check",
            "status": "skipped_pending_artifact",
            "summary": "Final prebuilt v4 release artifact (aetherflow-linux-amd64.tar.gz + independent SHA256SUMS) not supplied; guest boot/SSH/systemd verified, awaiting final artifact for install/update/rollback certification.",
            "details": {
                "expected_tarball": artifact_tarball,
                "expected_sha256_file": artifact_sha256_file,
            },
            "commands": [],
        })
        return drills

    if validation_summary and not validation_summary.get("valid", False):
        drills.append({
            "phase": "artifact_supply_check",
            "status": "failed",
            "summary": "Supplied artifact or source bundle failed pre-certification verification: " + "; ".join(validation_summary.get("errors", [])),
            "details": validation_summary,
            "commands": [],
        })
        return drills

    source_layout = (validation_summary or {}).get("source_layout") or inspect_source_tarball(source_tarball)
    strip_components = int(source_layout["strip_components"])

    # Upload verified artifact, independent SHA256SUMS, and source snapshot into the isolated guest
    vm.ssh_run("mkdir -p /var/tmp/af-drill/artifacts /var/tmp/af-drill/source", timeout=20, check=True, label="mkdir-guest-drill")
    vm.copy_to_guest(artifact_tarball, "/var/tmp/af-drill/artifacts/aetherflow-linux-amd64.tar.gz", label="upload-artifact-tarball")
    vm.copy_to_guest(artifact_sha256_file, "/var/tmp/af-drill/artifacts/SHA256SUMS", label="upload-artifact-sha256")
    vm.copy_to_guest(source_tarball, "/var/tmp/af-drill/source.tar.gz", label="upload-source-snapshot")

    # Deterministic, validated source extraction with exact strip_components and post-extraction layout check (no fallback ambiguity)
    extract_cmd = (
        "set -euo pipefail\n"
        "rm -rf /opt/AetherFlow\n"
        "mkdir -p /opt/AetherFlow\n"
        f"tar -xzf /var/tmp/af-drill/source.tar.gz -C /opt/AetherFlow --strip-components={strip_components}\n"
        "for req in setup/modules/00-core.sh setup/modules/02-packages.sh setup/modules/05-finalize.sh setup/modules/06-state.sh setup/modules/modern_stack.sh deploy/release-manager.sh deploy/release-manager.conf; do\n"
        "    if [[ ! -s \"/opt/AetherFlow/${req}\" ]]; then\n"
        "        echo \"MISSING_REQUIRED_SOURCE_ENTRY:/opt/AetherFlow/${req}\" >&2\n"
        "        exit 1\n"
        "    fi\n"
        "done\n"
    )
    vm.ssh_run(extract_cmd, timeout=60, check=True, label="extract-and-verify-source-layout")

    # Ensure minimal runtime dependencies inside the isolated VM guest (sqlite3, curl, ca-certificates)
    vm.ssh_run(
        "export DEBIAN_FRONTEND=noninteractive; apt-get update -yqq && apt-get install -yqq curl ca-certificates sqlite3 dos2unix >/dev/null",
        timeout=180,
        check=True,
        label="guest-install-prereqs",
    )

    # DRILL 1: Tampered artifact fail-closed check + Bootstrap Prebuilt Install & Service Health
    bootstrap_script = r'''
set -euo pipefail
export AF_INSTALL_ROOT=/opt/AetherFlow
export AETHERFLOW_PREBUILT_TARBALL=/var/tmp/af-drill/artifacts/aetherflow-linux-amd64.tar.gz
export AETHERFLOW_PREBUILT_SHA256_FILE=/var/tmp/af-drill/artifacts/SHA256SUMS
export AETHERFLOW_RELEASE_TAG=v4.0.0-clean-matrix

# Verify independent SHA256SUMS matches tarball inside guest before bootstrap
(cd /var/tmp/af-drill/artifacts && sha256sum -c SHA256SUMS)

source /opt/AetherFlow/setup/modules/00-core.sh
source /opt/AetherFlow/setup/modules/06-state.sh
source /opt/AetherFlow/setup/modules/02-packages.sh
source /opt/AetherFlow/setup/modules/05-finalize.sh
source /opt/AetherFlow/setup/modules/modern_stack.sh

# 1a. Verify tampered SHA-256 fails closed before touching /opt/AetherFlow/current
if _stage_prebuilt_release_archive "${AETHERFLOW_PREBUILT_TARBALL}" "" "0000000000000000000000000000000000000000000000000000000000000000" "v4.0.0-tampered" 2>/dev/null; then
    echo "TAMPER_CHECK_FAILED: accepted bad SHA256" >&2
    exit 1
fi

# 1b. Perform real prebuilt v4 control-plane bootstrap (_build_modern_stack + _syscommands + _boot)
local_packages="/opt/AetherFlow/packages/"
local_setup="/opt/AetherFlow/setup/"
OUTTO="/var/log/aetherflow-bootstrap-drill.log"
INSTALL_LOG="/var/log/aetherflow-install-drill.log"
username="admin"
passwd="CleanMatrixAdmin!2026"

_init_state
_syscommands
_build_modern_stack
_boot

systemctl is-active aetherflow-runner.service
systemctl is-active aetherflow-api.service

for i in $(seq 1 20); do
    if curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready > /tmp/health_ready.json 2>/dev/null; then
        break
    fi
    sleep 1
done
cat /tmp/health_ready.json
curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ready" else 1)'
echo ""
readlink -f /opt/AetherFlow/current
/usr/local/bin/af --version
/usr/local/bin/af health --json
/usr/local/bin/af release status --json
'''
    rc1, out1, err1, rec1 = vm.ssh_run(bootstrap_script, timeout=180, check=False, label="drill-1-bootstrap-and-cli")
    drills.append({
        "phase": "bootstrap_install_health_and_cli",
        "status": "passed" if rc1 == 0 else "failed",
        "summary": "Verified independent SHA256SUMS, tampered-digest rejection, prebuilt v4 Rust control-plane bootstrap, systemd unit activation, /health/ready, and native af CLI checks." if rc1 == 0 else f"Bootstrap drill failed (rc={rc1})",
        "details": {"stdout": out1.strip(), "stderr": err1.strip(), "fixture_only": False},
        "commands": [rec1],
    })
    if rc1 != 0:
        return drills

    # DRILL 2: Clean Release Update to a second v4 release slot (v4.0.1-matrix)
    update_script = r'''
set -euo pipefail
mkdir -p /var/tmp/af-drill/release-v2-src
tar -xzf /var/tmp/af-drill/artifacts/aetherflow-linux-amd64.tar.gz -C /var/tmp/af-drill/release-v2-src
printf 'v4.0.1-matrix\n' > /var/tmp/af-drill/release-v2-src/.version
mkdir -p /var/tmp/af-drill/srv/McEveritts/AetherFlow/releases/download/v4.0.1
tar --owner=0 --group=0 --numeric-owner -C /var/tmp/af-drill/release-v2-src -czf /var/tmp/af-drill/srv/McEveritts/AetherFlow/releases/download/v4.0.1/aetherflow-linux-amd64.tar.gz .
(cd /var/tmp/af-drill/srv/McEveritts/AetherFlow/releases/download/v4.0.1 && sha256sum aetherflow-linux-amd64.tar.gz > SHA256SUMS)

# Seed a marker in the live SQLite database to verify online backup preservation
sqlite3 /var/lib/aetherflow/aetherflow.sqlite "CREATE TABLE IF NOT EXISTS _matrix_drill (k TEXT PRIMARY KEY, v TEXT); INSERT OR REPLACE INTO _matrix_drill VALUES ('release_marker', 'pre_v4_0_1');"

export AETHERFLOW_PREBUILT_TARBALL=/var/tmp/af-drill/srv/McEveritts/AetherFlow/releases/download/v4.0.1/aetherflow-linux-amd64.tar.gz
export AETHERFLOW_PREBUILT_SHA256_FILE=/var/tmp/af-drill/srv/McEveritts/AetherFlow/releases/download/v4.0.1/SHA256SUMS
export AETHERFLOW_RELEASE_TAG=v4.0.1-matrix

source /opt/AetherFlow/setup/modules/modern_stack.sh
_pull_prebuilt_release_before="$(readlink -f /opt/AetherFlow/current)"
_pull_prebuilt_v4_release
systemctl restart aetherflow-runner.service aetherflow-api.service

for i in $(seq 1 15); do
    if curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ready" else 1)'
_after="$(readlink -f /opt/AetherFlow/current)"
test "${_pull_prebuilt_release_before}" != "${_after}"
test "$(cat /opt/AetherFlow/releases/.previous_release)" = "${_pull_prebuilt_release_before}"
test "$(cat /opt/AetherFlow/current/.version)" = "v4.0.1-matrix"
/usr/local/bin/af release status --json
'''
    rc2, out2, err2, rec2 = vm.ssh_run(update_script, timeout=120, check=False, label="drill-2-release-update")
    drills.append({
        "phase": "release_update",
        "status": "passed" if rc2 == 0 else "failed",
        "summary": "Updated live control plane to second verified release slot (v4.0.1-matrix), verified .previous_release tracking and /health/ready." if rc2 == 0 else f"Update drill failed (rc={rc2})",
        "details": {"stdout": out2.strip(), "stderr": err2.strip(), "fixture_only": False},
        "commands": [rec2],
    })
    if rc2 != 0:
        return drills

    # DRILL 3: Deliberate Failed-Health Update + Automatic Rollback & Corrupted SQLite Recovery
    rollback_script = r'''
set -euo pipefail
known_good="$(readlink -f /opt/AetherFlow/current)"

# Create a broken candidate release whose aetherflow-api corrupts the DB and exits 1 (failing /health/ready)
mkdir -p /var/tmp/af-drill/broken-src
tar -xzf /var/tmp/af-drill/artifacts/aetherflow-linux-amd64.tar.gz -C /var/tmp/af-drill/broken-src
cat > /var/tmp/af-drill/broken-src/aetherflow-api <<'BROKEN_EOF'
#!/bin/bash
if [[ "${1:-}" == "runner" ]]; then
    sleep 30
    exit 0
fi
printf 'CORRUPTED_BY_BAD_CANDIDATE' > /var/lib/aetherflow/aetherflow.sqlite
exit 1
BROKEN_EOF
chmod 0755 /var/tmp/af-drill/broken-src/aetherflow-api
printf 'v4.0.2-broken\n' > /var/tmp/af-drill/broken-src/.version

mkdir -p /var/tmp/af-drill/broken-bundle
tar --owner=0 --group=0 --numeric-owner -C /var/tmp/af-drill/broken-src -czf /var/tmp/af-drill/broken-bundle/aetherflow-linux-amd64.tar.gz .
(cd /var/tmp/af-drill/broken-bundle && sha256sum aetherflow-linux-amd64.tar.gz > SHA256SUMS)

# Serve the broken bundle via a local loopback HTTP server and exercise deploy/release-manager.sh Stage 1.5 -> Stage 2 -> Stage 3 failure -> Stage 4 automatic rollback + DB restore
python3 -m http.server 18081 --bind 127.0.0.1 --directory /var/tmp/af-drill/broken-bundle >/dev/null 2>&1 &
http_pid=$!
trap 'kill ${http_pid} 2>/dev/null || true' EXIT

mkdir -p /var/tmp/af-drill/shim-bin
cat > /var/tmp/af-drill/shim-bin/curl <<'SHIM_EOF'
#!/bin/bash
args=()
for arg in "$@"; do
    case "${arg}" in
        https://api.github.com/repos/*/releases)
            printf '[{"tag_name":"v4.0.2","draft":false,"prerelease":false,"target_commitish":"master"}]\n'
            exit 0
            ;;
        https://github.com/*/releases/download/*/aetherflow-linux-amd64.tar.gz)
            args+=("http://127.0.0.1:18081/aetherflow-linux-amd64.tar.gz")
            ;;
        https://github.com/*/releases/download/*/SHA256SUMS)
            args+=("http://127.0.0.1:18081/SHA256SUMS")
            ;;
        *)
            args+=("${arg}")
            ;;
    esac
done
exec /usr/bin/curl "${args[@]}"
SHIM_EOF
chmod 0755 /var/tmp/af-drill/shim-bin/curl

set +e
PATH="/var/tmp/af-drill/shim-bin:${PATH}" HEALTH_RETRIES=2 HEALTH_INTERVAL=1 \
    bash /opt/AetherFlow/deploy/release-manager.sh deploy --channel stable
deploy_rc=$?
set -e

kill "${http_pid}" 2>/dev/null || true

# Expect exit code 2 (HealthProbeFailedRollback)
test "${deploy_rc}" -eq 2
reverted_target="$(readlink -f /opt/AetherFlow/current)"
test "${reverted_target}" = "${known_good}"

# Verify SQLite database was automatically restored from pre-swap snapshot and passes integrity_check + marker check
test "$(sqlite3 /var/lib/aetherflow/aetherflow.sqlite 'PRAGMA integrity_check;')" = "ok"
test "$(sqlite3 /var/lib/aetherflow/aetherflow.sqlite "SELECT v FROM _matrix_drill WHERE k='release_marker';")" = "pre_v4_0_1"

# Verify healthy service recovered on :8080
for i in $(seq 1 15); do
    if curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready > /tmp/health_after_rollback.json 2>/dev/null; then
        break
    fi
    sleep 1
done
cat /tmp/health_after_rollback.json
curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ready" else 1)'
'''
    rc3, out3, err3, rec3 = vm.ssh_run(rollback_script, timeout=180, check=False, label="drill-3-failed-health-rollback")
    drills.append({
        "phase": "failed_health_rollback_and_db_recovery",
        "status": "passed" if rc3 == 0 else "failed",
        "summary": "Verified deliberate failed-health update triggers automatic symlink rollback (exit code 2), quarantines corrupted SQLite DB, restores verified pre-swap snapshot, and recovers /health/ready." if rc3 == 0 else f"Failed-health rollback drill failed (rc={rc3})",
        "details": {"stdout": out3.strip(), "stderr": err3.strip(), "fixture_only": False},
        "commands": [rec3],
    })
    if rc3 != 0:
        return drills

    # DRILL 4A (Labeled Auxiliary Fixture): Synthetic .recovery_state.json guard check (`interrupted_update_recovery_fixture`)
    fixture_script = r'''
set -euo pipefail
known_good="$(readlink -f /opt/AetherFlow/current)"
fixture_cand="/opt/AetherFlow/releases/9999999991"
rm -rf "${fixture_cand}"
cp -a "${known_good}" "${fixture_cand}"
printf 'v4.0.3-fixture-interrupted\n' > "${fixture_cand}/.version"

printf '%s\n' "${known_good}" > /opt/AetherFlow/releases/.previous_release
ln -sfn "${fixture_cand}" /opt/AetherFlow/current

cat > /opt/AetherFlow/releases/.recovery_state.json <<EOF
{
  "operation_id": "drill-fixture-op-0001",
  "command": "deploy",
  "channel": "stable",
  "dry_run": false,
  "phase": "stage2_symlink_swap",
  "candidate_release": "${fixture_cand}",
  "previous_release": "${known_good}",
  "resolved_db_path": "/var/lib/aetherflow/aetherflow.sqlite",
  "resolved_db_source": "DATA_DIR",
  "snapshot_path": "${fixture_cand}/data-snapshot/aetherflow.sqlite.bak",
  "started_at": "2026-11-03T06:00:00Z",
  "updated_at": "2026-11-03T06:00:01Z"
}
EOF
chmod 0600 /opt/AetherFlow/releases/.recovery_state.json

if /usr/local/bin/af release deploy --local --dry-run --offline >/dev/null 2>&1; then
    echo "INTERRUPTED_GUARD_FAILED: deploy succeeded despite unfinished stage2_symlink_swap" >&2
    exit 1
fi

/usr/local/bin/af release rollback --local --json > /tmp/fixture_interrupted_rollback.json
test "$(readlink -f /opt/AetherFlow/current)" = "${known_good}"
rm -rf "${fixture_cand}"
'''
    rc4_fix, out4_fix, err4_fix, rec4_fix = vm.ssh_run(fixture_script, timeout=90, check=False, label="drill-4a-interrupted-recovery-fixture")
    drills.append({
        "phase": "interrupted_update_recovery_fixture",
        "status": "passed" if rc4_fix == 0 else "failed",
        "summary": "Auxiliary fixture check: verified synthetic .recovery_state.json guard blocks new deploy and rolls back (non-certifying auxiliary fixture)." if rc4_fix == 0 else f"Auxiliary fixture check failed (rc={rc4_fix})",
        "details": {"stdout": out4_fix.strip(), "stderr": err4_fix.strip(), "fixture_only": True},
        "commands": [rec4_fix],
    })

    # DRILL 4B (Mandatory Real Phase): Launch real updater process (`deploy/release-manager.sh deploy`),
    # observe real Stage 1.5 snapshot + Stage 2 atomic symlink swap to candidate v4.0.3-interrupted,
    # intercept at the controlled post-swap Stage 3 readiness probe boundary BEFORE Stage 4 rollback,
    # terminate ONLY the owned updater process tree, then recover via shipped `/usr/local/bin/af release rollback --local --json`
    # and assert DB integrity + marker row + systemd services + symlink restoration.
    real_interrupted_script = r'''
set -euo pipefail
known_good="$(readlink -f /opt/AetherFlow/current)"
test -d "${known_good}"

# Build a candidate release bundle (v4.0.3-interrupted) whose binary never becomes ready on :8080
# so the real updater enters Stage 3 readiness polling right after completing Stage 1.5 snapshot & Stage 2 symlink swap
rm -rf /var/tmp/af-drill/interrupted-src /var/tmp/af-drill/interrupted-bundle /var/tmp/af-drill/post-swap-observed
mkdir -p /var/tmp/af-drill/interrupted-src /var/tmp/af-drill/interrupted-bundle
tar -xzf /var/tmp/af-drill/artifacts/aetherflow-linux-amd64.tar.gz -C /var/tmp/af-drill/interrupted-src
cat > /var/tmp/af-drill/interrupted-src/aetherflow-api <<'STALL_EOF'
#!/bin/bash
if [[ "${1:-}" == "runner" ]]; then
    sleep 60
    exit 0
fi
# Simulate a hung candidate API server during Stage 3 so /health/ready does not return 200
sleep 60
exit 1
STALL_EOF
chmod 0755 /var/tmp/af-drill/interrupted-src/aetherflow-api
printf 'v4.0.3-interrupted\n' > /var/tmp/af-drill/interrupted-src/.version

tar --owner=0 --group=0 --numeric-owner -C /var/tmp/af-drill/interrupted-src -czf /var/tmp/af-drill/interrupted-bundle/aetherflow-linux-amd64.tar.gz .
(cd /var/tmp/af-drill/interrupted-bundle && sha256sum aetherflow-linux-amd64.tar.gz > SHA256SUMS)

python3 -m http.server 18082 --bind 127.0.0.1 --directory /var/tmp/af-drill/interrupted-bundle >/dev/null 2>&1 &
http_pid=$!
updater_pid=""
trap 'kill ${http_pid} 2>/dev/null || true; if [[ -n "${updater_pid}" ]]; then kill -9 -${updater_pid} ${updater_pid} 2>/dev/null || true; fi' EXIT

# Curl shim that serves v4.0.3-interrupted during Stage 1 and signals /var/tmp/af-drill/post-swap-observed
# when the launched updater enters Stage 3 and polls http://127.0.0.1:8080/health/ready
mkdir -p /var/tmp/af-drill/shim-interrupted
cat > /var/tmp/af-drill/shim-interrupted/curl <<'SHIM_INT_EOF'
#!/bin/bash
args=()
is_health_probe=0
for arg in "$@"; do
    case "${arg}" in
        https://api.github.com/repos/*/releases)
            printf '[{"tag_name":"v4.0.3","draft":false,"prerelease":false,"target_commitish":"master"}]\n'
            exit 0
            ;;
        https://github.com/*/releases/download/*/aetherflow-linux-amd64.tar.gz)
            args+=("http://127.0.0.1:18082/aetherflow-linux-amd64.tar.gz")
            ;;
        https://github.com/*/releases/download/*/SHA256SUMS)
            args+=("http://127.0.0.1:18082/SHA256SUMS")
            ;;
        http://127.0.0.1:8080/health/ready*)
            is_health_probe=1
            args+=("${arg}")
            ;;
        *)
            args+=("${arg}")
            ;;
    esac
done
if [[ "${is_health_probe}" -eq 1 ]]; then
    # Record observable post-swap boundary reached by the real updater
    readlink -f /opt/AetherFlow/current > /var/tmp/af-drill/post-swap-observed
    # Hold inside Stage 3 health probe so the test harness can deterministically terminate the updater process
    sleep 30
    exit 7
fi
exec /usr/bin/curl "${args[@]}"
SHIM_INT_EOF
chmod 0755 /var/tmp/af-drill/shim-interrupted/curl

# Launch the real updater in its own process group (`setsid`) so we can terminate only our own updater tree
setsid env PATH="/var/tmp/af-drill/shim-interrupted:${PATH}" HEALTH_RETRIES=5 HEALTH_INTERVAL=5 \
    bash /opt/AetherFlow/deploy/release-manager.sh deploy --channel stable \
    > /var/tmp/af-drill/real-updater.log 2>&1 &
updater_pid=$!

# Wait for the observable post-swap boundary (/var/tmp/af-drill/post-swap-observed written at Stage 3 probe entry)
for i in $(seq 1 60); do
    if [[ -s /var/tmp/af-drill/post-swap-observed ]]; then
        break
    fi
    if ! kill -0 "${updater_pid}" 2>/dev/null; then
        echo "Updater exited prematurely before post-swap boundary:" >&2
        cat /var/tmp/af-drill/real-updater.log >&2 || true
        exit 1
    fi
    sleep 0.5
done

test -s /var/tmp/af-drill/post-swap-observed
swapped_cand="$(cat /var/tmp/af-drill/post-swap-observed)"
test "${swapped_cand}" != "${known_good}"
test "$(readlink -f /opt/AetherFlow/current)" = "${swapped_cand}"
test "$(cat /opt/AetherFlow/current/.version)" = "v4.0.3-interrupted"
test "$(cat /opt/AetherFlow/releases/.previous_release)" = "${known_good}"
test -s "${swapped_cand}/data-snapshot/aetherflow.sqlite.bak"

# Verify /proc/<updater_pid>/cmdline belongs to our launched release-manager.sh before terminating its process group
cmdline_str="$(tr '\0' ' ' < "/proc/${updater_pid}/cmdline" 2>/dev/null || true)"
case "${cmdline_str}" in
    *release-manager.sh*) ;;
    *)
        echo "Unexpected updater PID cmdline: ${cmdline_str}" >&2
        exit 1
        ;;
esac

# Terminate ONLY the launched updater process group (and any child sleep/curl in that group)
kill -TERM "-${updater_pid}" "${updater_pid}" 2>/dev/null || true
sleep 1
kill -KILL "-${updater_pid}" "${updater_pid}" 2>/dev/null || true
wait "${updater_pid}" 2>/dev/null || true
updater_pid=""
kill "${http_pid}" 2>/dev/null || true

# Confirm the system is genuinely left in an interrupted post-swap state pointing at v4.0.3-interrupted
test "$(readlink -f /opt/AetherFlow/current)" = "${swapped_cand}"
test "$(cat /opt/AetherFlow/releases/.previous_release)" = "${known_good}"

# Now recover using the shipped CLI (`af release rollback --local --json`)
/usr/local/bin/af release rollback --local --json > /tmp/real_interrupted_rollback.json
cat /tmp/real_interrupted_rollback.json

# Assert symlink, .previous_release, SQLite DB integrity & marker row, systemd services, and /health/ready are all intact
test "$(readlink -f /opt/AetherFlow/current)" = "${known_good}"
test "$(cat /opt/AetherFlow/current/.version)" = "v4.0.1-matrix"
test "$(sqlite3 /var/lib/aetherflow/aetherflow.sqlite 'PRAGMA integrity_check;')" = "ok"
test "$(sqlite3 /var/lib/aetherflow/aetherflow.sqlite "SELECT v FROM _matrix_drill WHERE k='release_marker';")" = "pre_v4_0_1"
systemctl is-active aetherflow-runner.service
systemctl is-active aetherflow-api.service

for i in $(seq 1 15); do
    if curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready > /tmp/health_after_interrupted_recovery.json 2>/dev/null; then
        break
    fi
    sleep 1
done
cat /tmp/health_after_interrupted_recovery.json
curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ready" else 1)'
/usr/local/bin/af release status --json
'''
    rc4, out4, err4, rec4 = vm.ssh_run(real_interrupted_script, timeout=180, check=False, label="drill-4b-real-interrupted-update-recovery")
    drills.append({
        "phase": "interrupted_update_recovery",
        "status": "passed" if rc4 == 0 else "failed",
        "summary": "Launched real updater process, intercepted at observable post-swap Stage 3 boundary after real Stage 1.5 DB snapshot and Stage 2 symlink swap, terminated owned updater process group, recovered via shipped `af release rollback --local --json`, and verified DB, services, and symlinks intact." if rc4 == 0 else f"Real interrupted-update recovery drill failed (rc={rc4})",
        "details": {"stdout": out4.strip(), "stderr": err4.strip(), "fixture_only": False, "real_execution": True},
        "commands": [rec4],
    })
    return drills
"""



def build_remote_driver_script() -> str:
    """
    Assembles the complete remote Python matrix driver script executed by `run_remote_matrix_action`.
    """
    guest_build_script_literal = json.dumps(render_baseline_guest_build_script(jobs=2))
    return (
        REMOTE_ENGINE_SCRIPT
        + "\n"
        + REMOTE_DRILL_HELPERS
        + "\nBASELINE_GUEST_BUILD_SCRIPT = "
        + guest_build_script_literal
        + "\n"
        + r"""
def validate_remote_certification_bundle(artifact_tarball, artifact_sha256_file, source_tarball, contract):
    if not artifact_tarball:
        return {
            "supplied": False,
            "valid": False,
            "errors": [],
            "artifact_sha256": None,
            "manifest_expected_sha256": None,
            "manifest_file_sha256": None,
            "source_sha256": None,
            "source_layout": None,
            "contract_report": None,
        }

    errors = []
    contract_report = inspect_artifact_bundle(artifact_tarball, artifact_sha256_file, contract)
    details = contract_report.get("details") or {}
    if not contract_report.get("valid", False):
        errors.extend(contract_report.get("errors") or [])

    source_sha256 = None
    source_layout = None
    if not source_tarball or not str(source_tarball).strip():
        errors.append("--source-tarball is required when --artifact-tarball is supplied")
    else:
        src_p = Path(source_tarball)
        if not src_p.is_file():
            errors.append(f"source tarball not found: {src_p}")
        else:
            source_sha256 = compute_digest(src_p, "sha256")
            try:
                source_layout = inspect_source_tarball(src_p)
            except Exception as exc:
                errors.append(str(exc))

    return {
        "supplied": True,
        "valid": len(errors) == 0,
        "errors": errors,
        "artifact_sha256": details.get("actual_sha256"),
        "manifest_expected_sha256": details.get("expected_sha256"),
        "manifest_file_sha256": details.get("manifest_file_sha256"),
        "source_sha256": source_sha256,
        "source_layout": source_layout,
        "contract_report": contract_report,
    }


def main():
    payload = json.loads(sys.stdin.read())
    action = payload["action"]
    work_root = Path(payload["work_root"])
    qemu_root = Path(payload["qemu_root"])
    images_dir = work_root / "images"
    evidence_dir = work_root / "evidence"
    images_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    specs = payload["specs"]
    results = []

    if action == "prepare-images":
        for spec in specs:
            ev = ensure_verified_cloud_image(spec, images_dir)
            results.append(ev)
        out = {"action": action, "timestamp": utc_now(), "images": results}
        report_file = evidence_dir / f"prepare-images-{int(time.time())}.json"
        report_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
        out["evidence_path"] = str(report_file)
        print("===MATRIX_JSON_BEGIN===")
        print(json.dumps(out))
        print("===MATRIX_JSON_END===")
        return

    if action in ("boot-matrix", "certify-matrix"):
        artifact_tarball = payload.get("artifact_tarball")
        artifact_sha256_file = payload.get("artifact_sha256_file")
        source_tarball = payload.get("source_tarball")
        vcpus = int(payload.get("vcpus", 2))
        memory_mib = int(payload.get("memory_mib", 3584))
        boot_timeout = int(payload.get("boot_timeout", 180))
        contract = payload.get("pending_artifact_contract") or {}

        validation_summary = None
        if action == "certify-matrix":
            validation_summary = validate_remote_certification_bundle(
                artifact_tarball,
                artifact_sha256_file,
                source_tarball,
                contract,
            )

        for spec in specs:
            target_id = spec["target_id"]
            target_report = {
                "target_id": target_id,
                "display_name": spec["display_name"],
                "image_evidence": None,
                "boot_evidence": None,
                "artifact_validation": validation_summary if action == "certify-matrix" else None,
                "drills": [],
                "certification_reasons": [],
                "overall_status": "pending",
                "error": None,
            }
            try:
                if action == "certify-matrix" and validation_summary and validation_summary.get("supplied") and not validation_summary.get("valid"):
                    drills = run_guest_lifecycle_drills(
                        None,
                        artifact_tarball=artifact_tarball,
                        artifact_sha256_file=artifact_sha256_file,
                        source_tarball=source_tarball,
                        validation_summary=validation_summary,
                    )
                    target_report["drills"] = drills
                    status, reasons = evaluate_remote_certification_status(drills)
                    target_report["overall_status"] = status
                    target_report["certification_reasons"] = reasons
                    results.append(target_report)
                    continue

                img_ev = ensure_verified_cloud_image(spec, images_dir)
                target_report["image_evidence"] = img_ev
                with IsolatedVmSession(
                    spec,
                    img_ev,
                    work_root=work_root,
                    qemu_root=qemu_root,
                    vcpus=vcpus,
                    memory_mib=memory_mib,
                ) as vm:
                    boot_ev = vm.wait_for_ssh_and_systemd(timeout=boot_timeout)
                    target_report["boot_evidence"] = boot_ev
                    if action == "certify-matrix":
                        drills = run_guest_lifecycle_drills(
                            vm,
                            artifact_tarball=artifact_tarball,
                            artifact_sha256_file=artifact_sha256_file,
                            source_tarball=source_tarball,
                            validation_summary=validation_summary,
                        )
                        target_report["drills"] = drills
                        status, reasons = evaluate_remote_certification_status(drills)
                        target_report["overall_status"] = status
                        target_report["certification_reasons"] = reasons
                    else:
                        target_report["overall_status"] = "boot_verified"
            except Exception as exc:
                target_report["overall_status"] = "failed"
                target_report["error"] = str(exc)
            results.append(target_report)

        out = {
            "action": action,
            "timestamp": utc_now(),
            "host_uname": " ".join(os.uname()) if hasattr(os, "uname") else sys.platform,
            "work_root": str(work_root),
            "qemu_root": str(qemu_root),
            "pending_artifact_contract": contract,
            "artifact_validation": validation_summary if action == "certify-matrix" else None,
            "mandatory_certification_phases": list(MANDATORY_CERTIFICATION_PHASES),
            "targets": results,
        }
        report_file = evidence_dir / f"{action}-{int(time.time())}.json"
        report_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
        if payload.get("update_latest_evidence", True):
            latest_file = evidence_dir / f"latest-{action}.json"
            latest_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
        out["evidence_path"] = str(report_file)
        print("===MATRIX_JSON_BEGIN===")
        print(json.dumps(out))
        print("===MATRIX_JSON_END===")
        return

    if action == "build-baseline-artifact":
        spec = specs[0]
        source_dir = Path(payload["source_dir"])
        node_root = Path(payload["node_root"])
        output_dir = Path(payload["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        contract = payload.get("pending_artifact_contract") or {}

        img_ev = ensure_verified_cloud_image(spec, images_dir)
        src_tar = work_root / "baseline-build-source.tar.gz"
        run_bounded(
            ["tar", "--exclude=.git", "--exclude=node_modules", "--exclude=target", "-C", str(source_dir), "-czf", str(src_tar), "."],
            timeout=120, check=True, label="pack-source-for-vm-build",
        )
        source_sha256 = compute_digest(src_tar, "sha256")
        source_layout = inspect_source_tarball(src_tar)

        node_tar = work_root / "node-runtime.tar.gz"
        run_bounded(
            ["tar", "-C", str(node_root), "-czf", str(node_tar), "."],
            timeout=120, check=True, label="pack-node-for-vm-build",
        )

        with IsolatedVmSession(
            spec,
            img_ev,
            work_root=work_root,
            qemu_root=qemu_root,
            vcpus=int(payload.get("vcpus", 2)),
            memory_mib=int(payload.get("memory_mib", 3584)),
        ) as vm:
            boot_ev = vm.wait_for_ssh_and_systemd(timeout=180)
            vm.ssh_run("mkdir -p /var/tmp/af-build/src /usr/local/nodejs", timeout=20, check=True, label="mkdir-vm-build")
            vm.copy_to_guest(src_tar, "/var/tmp/af-build/src.tar.gz", timeout=180, label="upload-src-tar")
            vm.copy_to_guest(node_tar, "/var/tmp/af-build/node.tar.gz", timeout=180, label="upload-node-tar")

            vm.ssh_run(BASELINE_GUEST_BUILD_SCRIPT, timeout=1800, check=True, label="vm-build-gold")
            vm.copy_from_guest("/var/tmp/af-build/out/aetherflow-linux-amd64.tar.gz", output_dir / "aetherflow-linux-amd64.tar.gz", label="download-built-tarball")
            vm.copy_from_guest("/var/tmp/af-build/out/SHA256SUMS", output_dir / "SHA256SUMS", label="download-built-sha256")
            vm.copy_from_guest("/var/tmp/af-build/out/MAX_GLIBC.txt", output_dir / "MAX_GLIBC.txt", label="download-max-glibc")

        built_tarball = output_dir / "aetherflow-linux-amd64.tar.gz"
        built_sha256sums = output_dir / "SHA256SUMS"
        artifact_check = inspect_artifact_bundle(built_tarball, built_sha256sums, contract)
        if not artifact_check.get("valid", False):
            raise RuntimeError(
                "Built baseline artifact failed release contract verification: "
                + "; ".join(artifact_check.get("errors") or [])
            )

        out = {
            "action": action,
            "timestamp": utc_now(),
            "builder_guest": boot_ev,
            "artifact_tarball": str(built_tarball),
            "sha256sums": str(built_sha256sums),
            "source_sha256": source_sha256,
            "source_layout": source_layout,
            "artifact_validation": artifact_check,
            "max_glibc": (output_dir / "MAX_GLIBC.txt").read_text(encoding="utf-8").strip() if (output_dir / "MAX_GLIBC.txt").exists() else None,
        }
        report_file = evidence_dir / f"build-baseline-artifact-{int(time.time())}.json"
        report_file.write_text(json.dumps(out, indent=2), encoding="utf-8")
        out["evidence_path"] = str(report_file)
        print("===MATRIX_JSON_BEGIN===")
        print(json.dumps(out))
        print("===MATRIX_JSON_END===")
        return

if __name__ == "__main__":
    main()
"""
    )


def run_remote_matrix_action(
    *,
    ssh_host: Optional[str],
    payload: Dict[str, Any],
    timeout: int = 1800,
) -> Dict[str, Any]:
    """
    Executes the remote Python matrix engine by passing the script via `python3 -c <script>`
    and streaming `payload` as JSON over `stdin`.
    """
    driver_code = build_remote_driver_script()

    envelope = {
        "script": driver_code,
        "payload": payload,
    }
    bootstrap_one_liner = (
        "import json, sys; env = json.loads(sys.stdin.read()); "
        "ns = {'__name__': '__main__'}; "
        "import io; sys.stdin = io.StringIO(json.dumps(env['payload'])); "
        "exec(compile(env['script'], '<v4_vm_matrix_remote>', 'exec'), ns)"
    )

    if ssh_host and ssh_host != "local":
        cmd = ["ssh", ssh_host, f"python3 -c {shlex.quote(bootstrap_one_liner)}"]
    else:
        cmd = [sys.executable, "-c", bootstrap_one_liner]

    proc = subprocess.run(
        cmd,
        input=json.dumps(envelope),
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Remote matrix execution failed (rc={proc.returncode}):\n"
            f"STDOUT:\n{proc.stdout[-2000:]}\nSTDERR:\n{proc.stderr[-2000:]}"
        )

    out = proc.stdout
    begin_marker = "===MATRIX_JSON_BEGIN==="
    end_marker = "===MATRIX_JSON_END==="
    if begin_marker not in out or end_marker not in out:
        raise RuntimeError(f"Missing JSON markers in remote output:\n{out[-2000:]}")
    json_blob = out.split(begin_marker, 1)[1].split(end_marker, 1)[0].strip()
    return json.loads(json_blob)


def resolve_selected_specs(targets_arg: Optional[Sequence[str]]) -> List[OsImageSpec]:
    if not targets_arg:
        return list(OFFICIAL_OS_MATRIX)
    selected: List[OsImageSpec] = []
    for raw in targets_arg:
        for item in raw.split(","):
            tid = item.strip()
            if not tid:
                continue
            if tid not in OS_MATRIX_BY_ID:
                valid = ", ".join(OS_MATRIX_BY_ID.keys())
                raise ValueError(f"Unknown OS target {tid!r} (expected one of: {valid})")
            selected.append(OS_MATRIX_BY_ID[tid])
    return selected


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="v4_vm_matrix.py",
        description="AetherFlow v4.0 Clean-OS QEMU/KVM Matrix Runner (Debian 12/13, Ubuntu 22.04/24.04)",
    )
    p.add_argument(
        "action",
        choices=(
            "prepare-images",
            "boot-matrix",
            "certify-matrix",
            "build-baseline-artifact",
            "verify-contract",
            "print-contract",
        ),
        help="Matrix runner action to execute",
    )
    p.add_argument(
        "--ssh-host",
        default="hetzner" if os.name == "nt" else "local",
        help="SSH host alias for remote Linux execution (or 'local' when running directly on the Linux KVM host)",
    )
    p.add_argument(
        "--work-root",
        default=DEFAULT_REMOTE_WORK_ROOT,
        help=f"Isolated /var/tmp workspace on the KVM host (default: {DEFAULT_REMOTE_WORK_ROOT})",
    )
    p.add_argument(
        "--qemu-root",
        default=DEFAULT_QEMU_TOOLS_ROOT,
        help=f"Extracted QEMU root directory (default: {DEFAULT_QEMU_TOOLS_ROOT})",
    )
    p.add_argument(
        "--node-root",
        default=DEFAULT_NODE_TOOLS_ROOT,
        help=f"Extracted Node.js 24 directory for guest source builds (default: {DEFAULT_NODE_TOOLS_ROOT})",
    )
    p.add_argument(
        "--source-dir",
        default=DEFAULT_BASELINE_SOURCE_DIR,
        help=f"Isolated AetherFlow source directory on KVM host (default: {DEFAULT_BASELINE_SOURCE_DIR})",
    )
    p.add_argument(
        "--targets",
        nargs="*",
        default=None,
        help="Subset of OS targets to run (debian-12, debian-13, ubuntu-22.04, ubuntu-24.04)",
    )
    p.add_argument(
        "--artifact-tarball",
        default=None,
        help="Path on KVM host (or local path for verify-contract) to aetherflow-linux-amd64.tar.gz",
    )
    p.add_argument(
        "--artifact-sha256-file",
        default=None,
        help="Path on KVM host (or local path for verify-contract) to independent SHA256SUMS manifest",
    )
    p.add_argument(
        "--source-tarball",
        default="/var/tmp/aetherflow-v4-validation-20261103-052723/source.tar.gz",
        help="Path on KVM host to source snapshot tarball for installer bootstrap scripts",
    )
    p.add_argument(
        "--output-dir",
        default="/var/tmp/aetherflow-v4-vm-matrix/artifacts/ubuntu-22.04-build",
        help="Output directory on KVM host for build-baseline-artifact",
    )
    p.add_argument(
        "--vcpus",
        type=int,
        default=DEFAULT_VM_VCPUS,
        help="vCPUs per sequential VM guest (1..4, default: 2)",
    )
    p.add_argument(
        "--memory-mib",
        type=int,
        default=DEFAULT_VM_MEMORY_MIB,
        help="RAM in MiB per sequential VM guest (512..4096, default: 3584)",
    )
    p.add_argument(
        "--boot-timeout",
        type=int,
        default=180,
        help="Seconds to wait for guest SSH + cloud-init + systemd readiness (default: 180)",
    )
    p.add_argument(
        "--evidence-out",
        default=None,
        help="Optional local path to save the returned JSON evidence report",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    validate_work_root_path(args.work_root)

    if args.action == "print-contract":
        print(json.dumps(asdict(DEFAULT_ARTIFACT_CONTRACT), indent=2))
        return 0

    if args.action == "verify-contract":
        if not args.artifact_tarball:
            parser.error("--artifact-tarball is required for verify-contract")
        if not args.artifact_sha256_file:
            parser.error("independent --artifact-sha256-file (SHA256SUMS) is required for verify-contract")
        res = verify_release_artifact_contract(
            Path(args.artifact_tarball),
            Path(args.artifact_sha256_file),
            require_manifest=True,
        )
        print(json.dumps(res, indent=2))
        return 0 if res["valid"] else 1

    if args.action == "certify-matrix" and args.artifact_tarball and not args.artifact_sha256_file:
        parser.error("independent --artifact-sha256-file (SHA256SUMS) is required when --artifact-tarball is supplied for certify-matrix")

    specs = resolve_selected_specs(args.targets)
    if args.action == "build-baseline-artifact":
        specs = [OS_MATRIX_BY_ID["ubuntu-22.04"]]

    payload: Dict[str, Any] = {
        "action": args.action,
        "work_root": args.work_root,
        "qemu_root": args.qemu_root,
        "node_root": args.node_root,
        "source_dir": args.source_dir,
        "output_dir": args.output_dir,
        "specs": [asdict(s) for s in specs],
        "artifact_tarball": args.artifact_tarball,
        "artifact_sha256_file": args.artifact_sha256_file,
        "source_tarball": args.source_tarball,
        "vcpus": args.vcpus,
        "memory_mib": args.memory_mib,
        "boot_timeout": args.boot_timeout,
        "pending_artifact_contract": asdict(DEFAULT_ARTIFACT_CONTRACT),
    }

    report = run_remote_matrix_action(
        ssh_host=args.ssh_host,
        payload=payload,
        timeout=3600,
    )

    if args.evidence_out:
        out_path = Path(args.evidence_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps(report, indent=2))

    if args.action in ("boot-matrix", "certify-matrix"):
        for t in report.get("targets", []):
            if t.get("overall_status") == "failed":
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
