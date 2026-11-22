"""Shared OS matrix models, artifact/tarball contract validators, and QEMU/NoCloud builders."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import tarfile
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from lib.vm_guest_common import compute_file_digest, utc_now_iso_z as utc_now_iso

DEFAULT_REMOTE_WORK_ROOT = "/var/tmp/aetherflow-v4-vm-matrix"
DEFAULT_QEMU_TOOLS_ROOT = "/var/tmp/aetherflow-v4-validation-20261103-052723/tools/qemu-root"
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
        "bin/af",
        "bin/speedtest-backend",
        ".version",
        "web/dist/index.html",
        "deploy/release-manager.sh",
        "deploy/release-manager.conf",
        "config/packages.json",
        "config/package_automation.json",
        "plugins/telemetry-inspector/plugin.manifest.json",
        "plugins/telemetry-inspector/backend/hooks/start.sh",
        "plugins/telemetry-inspector/backend/runtime.py",
        "plugins/telemetry-inspector/frontend/dist/index.html",
    )
    required_executable_entries: Tuple[str, ...] = (
        "aetherflow-api",
        "bin/af",
        "bin/speedtest-backend",
        "deploy/release-manager.sh",
        "plugins/telemetry-inspector/backend/hooks/start.sh",
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



V4_RELEASE_TAG_RE = re.compile(
    r"^v([4-9]|[1-9][0-9]+)\.([0-9]+)\.([0-9]+)(?:-[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*)?$"
)


def derive_drill_release_plan(bootstrap_tag: str) -> Dict[str, str]:
    """
    Derives consistent v4+ release tags and channels for clean-OS lifecycle drills
    from the validated artifact bundle's `.version` stamp.
    Synthetic release-manager drills use stable-channel-compatible `v<maj>.<min>.<patch>`
    tags whose `.version` stamp, releases metadata `tag_name`, and download path match.
    """
    tag = (bootstrap_tag or "").strip()
    m = V4_RELEASE_TAG_RE.fullmatch(tag)
    if not m:
        raise ValueError(
            f"validated bundle .version stamp {bootstrap_tag!r} is not a valid v4+ release tag"
        )
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    bootstrap_channel = "nightly" if "-nightly." in tag.lower() else "stable"
    update_tag = f"v{major}.{minor}.{patch + 1}"
    broken_tag = f"v{major}.{minor}.{patch + 2}"
    interrupted_tag = f"v{major}.{minor}.{patch + 3}"
    return {
        "bootstrap_tag": tag,
        "bootstrap_channel": bootstrap_channel,
        "update_tag": update_tag,
        "broken_tag": broken_tag,
        "interrupted_tag": interrupted_tag,
        "fixture_interrupted_tag": f"{interrupted_tag}-fixture-interrupted",
    }


def extract_archive_version_stamp(archive_path: Path | str) -> Optional[str]:
    """Reads and strips the top-level `.version` regular file from a `.tar.gz` release bundle."""
    archive_p = Path(archive_path)
    with tarfile.open(archive_p, mode="r:gz") as tf:
        for member in tf.getmembers():
            raw_name = member.name or ""
            norm_parts = [p for p in PurePosixPath(raw_name).parts if p not in ("", ".")]
            if norm_parts == [".version"] and member.isfile():
                ex = tf.extractfile(member)
                if ex is not None:
                    return ex.read().decode("utf-8", errors="replace").strip()
    return None


def render_loopback_curl_shim(
    *,
    tag: str,
    port: int,
    observe_post_swap_path: Optional[str] = None,
) -> str:
    """
    Renders a private guest-only `curl` fixture shim that maps official GitHub release
    metadata/artifact URLs for `tag` to a loopback HTTP fixture server on `127.0.0.1:<port>`.
    Enforces that production `release-manager.sh` still supplied `--proto '=https'` and
    `--proto-redir '=https'` before adapting transport flags solely for the rewritten loopback
    artifact request, leaving all other requests (including provenance bundles) untouched.
    """
    if not V4_RELEASE_TAG_RE.fullmatch((tag or "").strip()):
        raise ValueError(f"invalid drill release tag for loopback shim: {tag!r}")
    if not (1024 <= int(port) <= 65535):
        raise ValueError(f"loopback fixture port must be in 1024..65535 (got {port})")
    health_hook = ""
    if observe_post_swap_path:
        obs_q = shlex.quote(observe_post_swap_path)
        health_hook = (
            "if [[ \"${is_health_probe}\" -eq 1 ]]; then\n"
            f"    tmp_obs={obs_q}.tmp.$$\n"
            "    readlink -f \"${CURRENT_LINK:-/opt/AetherFlow/current}\" > \"${tmp_obs}\"\n"
            f"    mv -f \"${{tmp_obs}}\" {obs_q}\n"
            "    sleep 30 || true\n"
            "    exit 7\n"
            "fi\n"
        )
    return (
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        "orig_args=(\"$@\")\n"
        "rewritten_args=()\n"
        "rewritten=0\n"
        "is_releases_api=0\n"
        "is_health_probe=0\n"
        "saw_proto_https=0\n"
        "saw_proto_redir_https=0\n"
        "i=0\n"
        "while [[ ${i} -lt ${#orig_args[@]} ]]; do\n"
        "    arg=\"${orig_args[${i}]}\"\n"
        "    case \"${arg}\" in\n"
        "        --proto)\n"
        "            next_val=\"\"\n"
        "            if [[ $((i + 1)) -lt ${#orig_args[@]} ]]; then\n"
        "                next_val=\"${orig_args[$((i + 1))]}\"\n"
        "            fi\n"
        "            if [[ \"${next_val}\" == \"=https\" ]]; then\n"
        "                saw_proto_https=1\n"
        "            fi\n"
        "            i=$((i + 2))\n"
        "            continue\n"
        "            ;;\n"
        "        --proto=*)\n"
        "            if [[ \"${arg#--proto=}\" == \"=https\" ]]; then\n"
        "                saw_proto_https=1\n"
        "            fi\n"
        "            i=$((i + 1))\n"
        "            continue\n"
        "            ;;\n"
        "        --proto-redir)\n"
        "            next_val=\"\"\n"
        "            if [[ $((i + 1)) -lt ${#orig_args[@]} ]]; then\n"
        "                next_val=\"${orig_args[$((i + 1))]}\"\n"
        "            fi\n"
        "            if [[ \"${next_val}\" == \"=https\" ]]; then\n"
        "                saw_proto_redir_https=1\n"
        "            fi\n"
        "            i=$((i + 2))\n"
        "            continue\n"
        "            ;;\n"
        "        --proto-redir=*)\n"
        "            if [[ \"${arg#--proto-redir=}\" == \"=https\" ]]; then\n"
        "                saw_proto_redir_https=1\n"
        "            fi\n"
        "            i=$((i + 1))\n"
        "            continue\n"
        "            ;;\n"
        "        https://api.github.com/repos/*/releases)\n"
        "            is_releases_api=1\n"
        "            ;;\n"
        f"        \"https://github.com/\"*\"/releases/download/{tag}/aetherflow-linux-amd64.tar.gz\")\n"
        "            rewritten=1\n"
        f"            rewritten_args+=(\"http://127.0.0.1:{int(port)}/aetherflow-linux-amd64.tar.gz\")\n"
        "            i=$((i + 1))\n"
        "            continue\n"
        "            ;;\n"
        f"        \"https://github.com/\"*\"/releases/download/{tag}/SHA256SUMS\")\n"
        "            rewritten=1\n"
        f"            rewritten_args+=(\"http://127.0.0.1:{int(port)}/SHA256SUMS\")\n"
        "            i=$((i + 1))\n"
        "            continue\n"
        "            ;;\n"
        "        http://127.0.0.1:[0-9]*/health/ready*)\n"
        "            is_health_probe=1\n"
        "            rewritten_args+=(\"${arg}\")\n"
        "            i=$((i + 1))\n"
        "            continue\n"
        "            ;;\n"
        "        *)\n"
        "            rewritten_args+=(\"${arg}\")\n"
        "            i=$((i + 1))\n"
        "            continue\n"
        "            ;;\n"
        "    esac\n"
        "    i=$((i + 1))\n"
        "done\n"
        "if [[ \"${is_releases_api}\" -eq 1 ]]; then\n"
        "    if [[ \"${saw_proto_https}\" -ne 1 || \"${saw_proto_redir_https}\" -ne 1 ]]; then\n"
        "        echo \"FIXTURE_HTTPS_GUARD_FAILED: releases API request missing --proto =https / --proto-redir =https\" >&2\n"
        "        exit 91\n"
        "    fi\n"
        f"    printf '[{{\"tag_name\":\"{tag}\",\"draft\":false,\"prerelease\":false,\"target_commitish\":\"master\"}}]\\n'\n"
        "    exit 0\n"
        "fi\n"
        "if [[ \"${rewritten}\" -eq 1 ]]; then\n"
        "    if [[ \"${saw_proto_https}\" -ne 1 || \"${saw_proto_redir_https}\" -ne 1 ]]; then\n"
        "        echo \"FIXTURE_HTTPS_GUARD_FAILED: artifact download missing --proto =https / --proto-redir =https\" >&2\n"
        "        exit 92\n"
        "    fi\n"
        "    exec /usr/bin/curl --proto '=http' --proto-redir '=http' \"${rewritten_args[@]}\"\n"
        "fi\n"
        f"{health_hook}"
        "exec /usr/bin/curl ${orig_args[@]+\"${orig_args[@]}\"}\n"
    )


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
        "frontend_wasm_entries": [],
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
    entry_sizes: Dict[str, int] = {}
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
                    entry_sizes[norm_name] = member.size
                    if norm_name == ".version":
                        extracted = tf.extractfile(member)
                        if extracted is not None:
                            details["version_stamp"] = (
                                extracted.read().decode("utf-8", errors="replace").strip()
                            )
                    elif norm_name in (
                        "aetherflow-api",
                        "af",
                        "bin/af",
                        "speedtest-backend",
                        "bin/speedtest-backend",
                    ):
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

    if "web/dist/index.html" in entry_sizes and entry_sizes["web/dist/index.html"] == 0:
        errors.append("web/dist/index.html is empty")
    details["frontend_wasm_entries"] = sorted(
        name for name, size in entry_sizes.items()
        if name.startswith("web/dist/") and name.endswith(".wasm") and size > 0
    )
    if not details["frontend_wasm_entries"]:
        errors.append("missing non-empty .wasm file under web/dist")

    for exe in contract.required_executable_entries:
        if exe in entry_modes and (entry_modes[exe] & 0o111) == 0:
            details["non_executable_entries"].append(exe)
            errors.append(f"archive entry {exe!r} is not marked executable (mode={oct(entry_modes[exe])})")

    if not details["version_stamp"]:
        errors.append("archive .version stamp is missing or empty")
    elif not V4_RELEASE_TAG_RE.fullmatch(details["version_stamp"]):
        errors.append(
            f"archive .version stamp {details['version_stamp']!r} is not a valid v4+ release tag"
        )

    if "af" in release_binary_bytes and "bin/af" in release_binary_bytes:
        if release_binary_bytes["af"] != release_binary_bytes["bin/af"]:
            errors.append("af and bin/af must contain identical CLI bytes")
    if (
        "speedtest-backend" in release_binary_bytes
        and "bin/speedtest-backend" in release_binary_bytes
        and release_binary_bytes["speedtest-backend"] != release_binary_bytes["bin/speedtest-backend"]
    ):
        errors.append("speedtest-backend and bin/speedtest-backend must contain identical binary bytes")
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


