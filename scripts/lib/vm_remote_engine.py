"""Embedded remote Linux KVM execution driver and certification drill templates."""

REMOTE_ENGINE_SCRIPT = r"""
from __future__ import annotations
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
        "frontend_wasm_entries": [],
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
    entry_sizes = {}
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
                        entry_sizes[norm_name] = member.size
                        if norm_name == ".version":
                            ex = tf.extractfile(member)
                            if ex is not None:
                                details["version_stamp"] = ex.read().decode("utf-8", errors="replace").strip()
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
                                ex = tf.extractfile(member)
                                if ex is not None:
                                    bin_file = tmp_root / norm_name.replace("/", "-")
                                    data = ex.read()
                                    binary_hashes[norm_name] = hashlib.sha256(data).hexdigest()
                                    bin_file.write_bytes(data)
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
    if (
        "speedtest-backend" in binary_hashes
        and "bin/speedtest-backend" in binary_hashes
        and binary_hashes["speedtest-backend"] != binary_hashes["bin/speedtest-backend"]
    ):
        errors.append("speedtest-backend and bin/speedtest-backend must contain identical binary bytes")
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
    if "web/dist/index.html" in entry_sizes and entry_sizes["web/dist/index.html"] == 0:
        errors.append("web/dist/index.html is empty")
    details["frontend_wasm_entries"] = sorted(
        name for name, size in entry_sizes.items()
        if name.startswith("web/dist/") and name.endswith(".wasm") and size > 0
    )
    if not details["frontend_wasm_entries"]:
        errors.append("missing non-empty .wasm file under web/dist")
    for exe in contract.get("required_executable_entries", ()):
        if exe in entry_modes and (entry_modes[exe] & 0o111) == 0:
            details["non_executable_entries"].append(exe)
            errors.append(f"archive entry {exe!r} is not marked executable")
    if not details["version_stamp"]:
        errors.append("archive .version stamp is missing or empty")
    elif not V4_RELEASE_TAG_RE.fullmatch(details["version_stamp"]):
        errors.append(
            f"archive .version stamp {details['version_stamp']!r} is not a valid v4+ release tag"
        )

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

    validated_version_stamp = (
        ((validation_summary or {}).get("contract_report") or {})
        .get("details", {})
        .get("version_stamp")
    )
    if not validated_version_stamp:
        try:
            validated_version_stamp = extract_archive_version_stamp(artifact_tarball)
        except Exception as exc:
            drills.append({
                "phase": "artifact_supply_check",
                "status": "failed",
                "summary": f"Unable to read .version stamp from artifact bundle: {exc}",
                "details": {"artifact_tarball": str(artifact_tarball)},
                "commands": [],
            })
            return drills

    try:
        release_plan = derive_drill_release_plan(validated_version_stamp or "")
    except ValueError as exc:
        drills.append({
            "phase": "artifact_supply_check",
            "status": "failed",
            "summary": str(exc),
            "details": {
                "artifact_tarball": str(artifact_tarball),
                "version_stamp": validated_version_stamp,
            },
            "commands": [],
        })
        return drills

    bootstrap_tag = release_plan["bootstrap_tag"]
    bootstrap_channel = release_plan["bootstrap_channel"]
    update_tag = release_plan["update_tag"]
    broken_tag = release_plan["broken_tag"]
    interrupted_tag = release_plan["interrupted_tag"]
    fixture_interrupted_tag = release_plan["fixture_interrupted_tag"]

    update_curl_shim = render_loopback_curl_shim(tag=update_tag, port=18080)
    broken_curl_shim = render_loopback_curl_shim(tag=broken_tag, port=18081)
    interrupted_curl_shim = render_loopback_curl_shim(
        tag=interrupted_tag,
        port=18082,
        observe_post_swap_path="/var/tmp/af-drill/post-swap-observed",
    )

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

    # Ensure minimal runtime dependencies inside the isolated VM guest (sqlite3, curl, ca-certificates, dos2unix, rsync)
    vm.ssh_run(
        "export DEBIAN_FRONTEND=noninteractive; apt-get update -yqq && apt-get install -yqq curl ca-certificates sqlite3 dos2unix rsync >/dev/null",
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
export AETHERFLOW_RELEASE_TAG=__BOOTSTRAP_TAG__
export AETHERFLOW_RELEASE_CHANNEL=__BOOTSTRAP_CHANNEL__

# Verify the uploaded archive; sibling release assets remain on the host.
(cd /var/tmp/af-drill/artifacts && sha256sum --ignore-missing -c SHA256SUMS)

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
test ! -e /opt/AetherFlow/current

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
curl -fsS --max-time 5 http://127.0.0.1:8080/ -o /tmp/af-ui-index.html
cmp /opt/AetherFlow/current/web/dist/index.html /tmp/af-ui-index.html
wasm_file="$(find /opt/AetherFlow/current/web/dist -type f -name '*.wasm' -size +0c -print -quit)"
test -n "${wasm_file}"
test -x /opt/AetherFlow/current/bin/af
test -x /opt/AetherFlow/current/bin/speedtest-backend
test -s /opt/AetherFlow/current/plugins/telemetry-inspector/plugin.manifest.json
test -x /opt/AetherFlow/current/plugins/telemetry-inspector/backend/hooks/start.sh
curl -fsS --max-time 10 "http://127.0.0.1:8080/${wasm_file#/opt/AetherFlow/current/web/dist/}" -o /tmp/af-ui.wasm
cmp "${wasm_file}" /tmp/af-ui.wasm
test "$(tr -d '[:space:]' < /opt/AetherFlow/current/.version)" = "${AETHERFLOW_RELEASE_TAG}"
echo ""
bootstrap_current="$(readlink -f /opt/AetherFlow/current)"
printf '%s\n' "${bootstrap_current}"
/usr/local/bin/af --version
/usr/local/bin/af health --json
/usr/local/bin/af release status --json > /tmp/bootstrap_release_status.json
cat /tmp/bootstrap_release_status.json
python3 - "${bootstrap_current}" "${AETHERFLOW_RELEASE_TAG}" /tmp/bootstrap_release_status.json <<'PY'
import json, sys
cur_path, expected_tag, status_path = sys.argv[1:4]
payload = json.load(open(status_path, encoding="utf-8"))
data = payload.get("data") or {}
assert payload.get("status") == "ok", payload
assert data.get("current_release") == cur_path, data
assert data.get("current_version") == expected_tag, data
PY
'''
    bootstrap_script = (
        bootstrap_script
        .replace("__BOOTSTRAP_TAG__", bootstrap_tag)
        .replace("__BOOTSTRAP_CHANNEL__", bootstrap_channel)
    )
    rc1, out1, err1, rec1 = vm.ssh_run(bootstrap_script, timeout=180, check=False, label="drill-1-bootstrap-and-cli")
    drills.append({
        "phase": "bootstrap_install_health_and_cli",
        "status": "passed" if rc1 == 0 else "failed",
        "summary": f"Verified checksum, tampered-digest rejection, prebuilt bootstrap ({bootstrap_tag}), systemd health, external HTML/WASM serving, the LibreSpeed companion, and af CLI checks." if rc1 == 0 else f"Bootstrap drill failed (rc={rc1})",
        "details": {"stdout": out1.strip(), "stderr": err1.strip(), "bootstrap_tag": bootstrap_tag, "bootstrap_channel": bootstrap_channel, "fixture_only": False},
        "commands": [rec1],
    })
    if rc1 != 0:
        return drills

    # DRILL 2: Positive Release Update through deploy/release-manager.sh (staging, metadata, WAL snapshot, swap, /health/ready, recovery state)
    update_script = r'''
set -euo pipefail
_release_before="$(readlink -f /opt/AetherFlow/current)"
rm -rf /var/tmp/af-drill/release-v2-src /var/tmp/af-drill/release-v2-bundle /var/tmp/af-drill/shim-update
mkdir -p /var/tmp/af-drill/release-v2-src /var/tmp/af-drill/release-v2-bundle /var/tmp/af-drill/shim-update
tar -xzf /var/tmp/af-drill/artifacts/aetherflow-linux-amd64.tar.gz -C /var/tmp/af-drill/release-v2-src
printf '__UPDATE_TAG__\n' > /var/tmp/af-drill/release-v2-src/.version
tar --owner=0 --group=0 --numeric-owner -C /var/tmp/af-drill/release-v2-src -czf /var/tmp/af-drill/release-v2-bundle/aetherflow-linux-amd64.tar.gz .
(cd /var/tmp/af-drill/release-v2-bundle && sha256sum aetherflow-linux-amd64.tar.gz > SHA256SUMS)

# Seed a marker in the live SQLite database as service user aetherflow so DB/WAL ownership stays intact
runuser -u aetherflow -- sqlite3 /var/lib/aetherflow/aetherflow.sqlite "PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS _matrix_drill (k TEXT PRIMARY KEY, v TEXT); INSERT OR REPLACE INTO _matrix_drill VALUES ('release_marker', 'pre_v4_0_1');"

python3 -m http.server 18080 --bind 127.0.0.1 --directory /var/tmp/af-drill/release-v2-bundle >/dev/null 2>&1 &
http_pid=$!
trap 'kill ${http_pid} 2>/dev/null || true' EXIT

for i in $(seq 1 25); do
    if /usr/bin/curl -fsS --max-time 2 http://127.0.0.1:18080/SHA256SUMS >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
/usr/bin/curl -fsS --max-time 2 http://127.0.0.1:18080/SHA256SUMS >/dev/null

cat > /var/tmp/af-drill/shim-update/curl <<'SHIM_UPDATE_EOF'
__UPDATE_CURL_SHIM__SHIM_UPDATE_EOF
chmod 0755 /var/tmp/af-drill/shim-update/curl

PATH="/var/tmp/af-drill/shim-update:${PATH}" HEALTH_RETRIES=10 HEALTH_INTERVAL=2 \
    bash /opt/AetherFlow/deploy/release-manager.sh deploy --channel stable

kill "${http_pid}" 2>/dev/null || true

systemctl is-active aetherflow-runner.service
systemctl is-active aetherflow-api.service

for i in $(seq 1 15); do
    if curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ready" else 1)'
_after="$(readlink -f /opt/AetherFlow/current)"
test "${_release_before}" != "${_after}"
test "$(cat /opt/AetherFlow/releases/.previous_release)" = "${_release_before}"
test "$(tr -d '[:space:]' < /opt/AetherFlow/current/.version)" = "__UPDATE_TAG__"
test -s "${_after}/data-snapshot/aetherflow.sqlite.bak"
test -s "${_after}/data-snapshot/MANIFEST.sha256"
(cd "${_after}/data-snapshot" && sha256sum -c MANIFEST.sha256)
test "$(sqlite3 -readonly "${_after}/data-snapshot/aetherflow.sqlite.bak" 'PRAGMA integrity_check;')" = "ok"
test "$(sqlite3 -readonly "${_after}/data-snapshot/aetherflow.sqlite.bak" "SELECT v FROM _matrix_drill WHERE k='release_marker';")" = "pre_v4_0_1"
/usr/local/bin/af release status --json > /tmp/update_release_status.json
cat /tmp/update_release_status.json
python3 - "${_release_before}" "${_after}" "__UPDATE_TAG__" /tmp/update_release_status.json /opt/AetherFlow/releases/.recovery_state.json <<'PY'
import json, sys
prev_path, cur_path, expected_tag, status_path, rec_path = sys.argv[1:6]
status_payload = json.load(open(status_path, encoding="utf-8"))
data = status_payload.get("data") or {}
assert status_payload.get("status") == "ok", status_payload
assert data.get("current_release") == cur_path, data
assert data.get("previous_release") == prev_path, data
assert data.get("current_version") == expected_tag, data
rec = json.load(open(rec_path, encoding="utf-8"))
assert rec.get("phase") == "complete", rec
assert rec.get("candidate_release") == cur_path, rec
assert rec.get("previous_release") == prev_path, rec
PY
'''
    update_script = (
        update_script
        .replace("__UPDATE_TAG__", update_tag)
        .replace("__UPDATE_CURL_SHIM__", update_curl_shim)
    )
    rc2, out2, err2, rec2 = vm.ssh_run(update_script, timeout=180, check=False, label="drill-2-release-update")
    drills.append({
        "phase": "release_update",
        "status": "passed" if rc2 == 0 else "failed",
        "summary": f"Updated live control plane through release-manager.sh to verified release slot ({update_tag}), verified WAL snapshot, .previous_release, recovery state, and /health/ready." if rc2 == 0 else f"Update drill failed (rc={rc2})",
        "details": {"stdout": out2.strip(), "stderr": err2.strip(), "update_tag": update_tag, "fixture_only": False},
        "commands": [rec2],
    })
    if rc2 != 0:
        return drills

    # DRILL 3: Deliberate Failed-Health Update + Automatic Rollback & Corrupted SQLite Recovery
    rollback_script = r'''
set -euo pipefail
known_good="$(readlink -f /opt/AetherFlow/current)"

# Create a broken candidate release whose aetherflow-api corrupts the DB and exits 1 (failing /health/ready)
rm -rf /var/tmp/af-drill/broken-src /var/tmp/af-drill/broken-bundle /var/tmp/af-drill/shim-bin
mkdir -p /var/tmp/af-drill/broken-src /var/tmp/af-drill/broken-bundle /var/tmp/af-drill/shim-bin
tar -xzf /var/tmp/af-drill/artifacts/aetherflow-linux-amd64.tar.gz -C /var/tmp/af-drill/broken-src
cat > /var/tmp/af-drill/broken-src/aetherflow-api <<'BROKEN_EOF'
#!/bin/bash
if [[ "${1:-}" == "runner" ]]; then
    exec sleep 30
fi
printf 'CORRUPTED_BY_BAD_CANDIDATE' > /var/lib/aetherflow/aetherflow.sqlite
exit 1
BROKEN_EOF
chmod 0755 /var/tmp/af-drill/broken-src/aetherflow-api
printf '__BROKEN_TAG__\n' > /var/tmp/af-drill/broken-src/.version

tar --owner=0 --group=0 --numeric-owner -C /var/tmp/af-drill/broken-src -czf /var/tmp/af-drill/broken-bundle/aetherflow-linux-amd64.tar.gz .
(cd /var/tmp/af-drill/broken-bundle && sha256sum aetherflow-linux-amd64.tar.gz > SHA256SUMS)

# Serve the broken bundle via a local loopback HTTP server and exercise deploy/release-manager.sh Stage 1.5 -> Stage 2 -> Stage 3 failure -> Stage 4 automatic rollback + DB restore
python3 -m http.server 18081 --bind 127.0.0.1 --directory /var/tmp/af-drill/broken-bundle >/dev/null 2>&1 &
http_pid=$!
trap 'kill ${http_pid} 2>/dev/null || true' EXIT

for i in $(seq 1 25); do
    if /usr/bin/curl -fsS --max-time 2 http://127.0.0.1:18081/SHA256SUMS >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
/usr/bin/curl -fsS --max-time 2 http://127.0.0.1:18081/SHA256SUMS >/dev/null

cat > /var/tmp/af-drill/shim-bin/curl <<'SHIM_EOF'
__BROKEN_CURL_SHIM__SHIM_EOF
chmod 0755 /var/tmp/af-drill/shim-bin/curl

rm -f /var/lib/aetherflow/aetherflow.sqlite.corrupted.*

set +e
PATH="/var/tmp/af-drill/shim-bin:${PATH}" HEALTH_RETRIES=5 HEALTH_INTERVAL=2 \
    bash /opt/AetherFlow/deploy/release-manager.sh deploy --channel stable
deploy_rc=$?
set -e
printf 'drill-3 deploy_rc=%s\n' "${deploy_rc}"

kill "${http_pid}" 2>/dev/null || true

# Expect exit code 2 (HealthProbeFailedRollback)
test "${deploy_rc}" -eq 2
reverted_target="$(readlink -f /opt/AetherFlow/current)"
test "${reverted_target}" = "${known_good}"
test "$(tr -d '[:space:]' < /opt/AetherFlow/current/.version)" = "__UPDATE_TAG__"

# Verify broken candidate actually corrupted DB and rollback quarantined + restored from pre-swap snapshot
compgen -G "/var/lib/aetherflow/aetherflow.sqlite.corrupted.*" >/dev/null
test "$(sqlite3 -readonly /var/lib/aetherflow/aetherflow.sqlite 'PRAGMA integrity_check;')" = "ok"
test "$(sqlite3 -readonly /var/lib/aetherflow/aetherflow.sqlite "SELECT v FROM _matrix_drill WHERE k='release_marker';")" = "pre_v4_0_1"
python3 - /opt/AetherFlow/releases/.recovery_state.json <<'PY'
import json, sys
rec = json.load(open(sys.argv[1], encoding="utf-8"))
assert rec.get("phase") == "complete", rec
PY

# Verify healthy service recovered on :8080
systemctl is-active aetherflow-runner.service
systemctl is-active aetherflow-api.service
for i in $(seq 1 15); do
    if curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready > /tmp/health_after_rollback.json 2>/dev/null; then
        break
    fi
    sleep 1
done
cat /tmp/health_after_rollback.json
curl -fsS --max-time 2 http://127.0.0.1:8080/health/ready | python3 -c 'import json,sys; sys.exit(0 if json.load(sys.stdin).get("status") == "ready" else 1)'
'''
    rollback_script = (
        rollback_script
        .replace("__BROKEN_TAG__", broken_tag)
        .replace("__UPDATE_TAG__", update_tag)
        .replace("__BROKEN_CURL_SHIM__", broken_curl_shim)
    )
    rc3, out3, err3, rec3 = vm.ssh_run(rollback_script, timeout=180, check=False, label="drill-3-failed-health-rollback")
    drills.append({
        "phase": "failed_health_rollback_and_db_recovery",
        "status": "passed" if rc3 == 0 else "failed",
        "summary": f"Verified deliberate failed-health update ({broken_tag}) triggers automatic symlink rollback (exit code 2), quarantines corrupted SQLite DB, restores verified pre-swap snapshot, and recovers /health/ready." if rc3 == 0 else f"Failed-health rollback drill failed (rc={rc3})",
        "details": {"stdout": out3.strip(), "stderr": err3.strip(), "broken_tag": broken_tag, "fixture_only": False},
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
printf '__FIXTURE_INTERRUPTED_TAG__\n' > "${fixture_cand}/.version"

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

set +e
/usr/local/bin/af release deploy --local > /tmp/fixture_interrupted_guard.out 2>&1
guard_rc=$?
set -e
if [[ "${guard_rc}" -eq 0 ]]; then
    echo "INTERRUPTED_GUARD_FAILED: deploy succeeded despite unfinished stage2_symlink_swap" >&2
    exit 1
fi
cat /tmp/fixture_interrupted_guard.out
grep -Eqi 'interrupted deployment|unfinished after symlink swap' /tmp/fixture_interrupted_guard.out
test "$(readlink -f /opt/AetherFlow/current)" = "${fixture_cand}"
test "$(cat /opt/AetherFlow/releases/.previous_release)" = "${known_good}"

/usr/local/bin/af release rollback --local --json > /tmp/fixture_interrupted_rollback.json
test "$(readlink -f /opt/AetherFlow/current)" = "${known_good}"
python3 - /opt/AetherFlow/releases/.recovery_state.json <<'PY'
import json, sys
rec = json.load(open(sys.argv[1], encoding="utf-8"))
assert rec.get("phase") == "complete", rec
PY
rm -rf "${fixture_cand}"
'''
    fixture_script = fixture_script.replace("__FIXTURE_INTERRUPTED_TAG__", fixture_interrupted_tag)
    rc4_fix, out4_fix, err4_fix, rec4_fix = vm.ssh_run(fixture_script, timeout=90, check=False, label="drill-4a-interrupted-recovery-fixture")
    drills.append({
        "phase": "interrupted_update_recovery_fixture",
        "status": "passed" if rc4_fix == 0 else "failed",
        "summary": "Auxiliary fixture check: verified synthetic .recovery_state.json guard blocks new deploy and rolls back (non-certifying auxiliary fixture)." if rc4_fix == 0 else f"Auxiliary fixture check failed (rc={rc4_fix})",
        "details": {"stdout": out4_fix.strip(), "stderr": err4_fix.strip(), "fixture_only": True},
        "commands": [rec4_fix],
    })

    # DRILL 4B (Mandatory Real Phase): Launch real updater process (`deploy/release-manager.sh deploy`),
    # observe real Stage 1.5 snapshot + Stage 2 atomic symlink swap to candidate __INTERRUPTED_TAG__,
    # intercept at the controlled post-swap Stage 3 readiness probe boundary BEFORE Stage 4 rollback,
    # terminate ONLY the owned updater process tree, then recover via shipped `/usr/local/bin/af release rollback --local --json`
    # and assert DB integrity + marker row + systemd services + symlink restoration.
    real_interrupted_script = r'''
set -euo pipefail
known_good="$(readlink -f /opt/AetherFlow/current)"
test -d "${known_good}"

# Build a candidate release bundle (__INTERRUPTED_TAG__) whose binary never becomes ready on :8080
# so the real updater enters Stage 3 readiness polling right after completing Stage 1.5 snapshot & Stage 2 symlink swap
rm -rf /var/tmp/af-drill/interrupted-src /var/tmp/af-drill/interrupted-bundle /var/tmp/af-drill/shim-interrupted /var/tmp/af-drill/post-swap-observed /var/tmp/af-drill/post-swap-observed.tmp.*
mkdir -p /var/tmp/af-drill/interrupted-src /var/tmp/af-drill/interrupted-bundle /var/tmp/af-drill/shim-interrupted
tar -xzf /var/tmp/af-drill/artifacts/aetherflow-linux-amd64.tar.gz -C /var/tmp/af-drill/interrupted-src
cat > /var/tmp/af-drill/interrupted-src/aetherflow-api <<'STALL_EOF'
#!/bin/bash
if [[ "${1:-}" == "runner" ]]; then
    exec sleep 60
fi
# Simulate a hung candidate API server during Stage 3 so /health/ready does not return 200
exec sleep 60
STALL_EOF
chmod 0755 /var/tmp/af-drill/interrupted-src/aetherflow-api
printf '__INTERRUPTED_TAG__\n' > /var/tmp/af-drill/interrupted-src/.version

tar --owner=0 --group=0 --numeric-owner -C /var/tmp/af-drill/interrupted-src -czf /var/tmp/af-drill/interrupted-bundle/aetherflow-linux-amd64.tar.gz .
(cd /var/tmp/af-drill/interrupted-bundle && sha256sum aetherflow-linux-amd64.tar.gz > SHA256SUMS)

python3 -m http.server 18082 --bind 127.0.0.1 --directory /var/tmp/af-drill/interrupted-bundle >/dev/null 2>&1 &
http_pid=$!
updater_pid=""
trap 'kill ${http_pid} 2>/dev/null || true; if [[ -n "${updater_pid}" ]]; then kill -9 -${updater_pid} ${updater_pid} 2>/dev/null || true; fi' EXIT

for i in $(seq 1 25); do
    if /usr/bin/curl -fsS --max-time 2 http://127.0.0.1:18082/SHA256SUMS >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done
/usr/bin/curl -fsS --max-time 2 http://127.0.0.1:18082/SHA256SUMS >/dev/null

# Curl shim that serves __INTERRUPTED_TAG__ during Stage 1 and signals /var/tmp/af-drill/post-swap-observed
# when the launched updater enters Stage 3 and polls http://127.0.0.1:8080/health/ready
cat > /var/tmp/af-drill/shim-interrupted/curl <<'SHIM_INT_EOF'
__INTERRUPTED_CURL_SHIM__SHIM_INT_EOF
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
test "$(tr -d '[:space:]' < /opt/AetherFlow/current/.version)" = "__INTERRUPTED_TAG__"
test "$(cat /opt/AetherFlow/releases/.previous_release)" = "${known_good}"
test -s "${swapped_cand}/data-snapshot/aetherflow.sqlite.bak"
test -s "${swapped_cand}/data-snapshot/MANIFEST.sha256"
(cd "${swapped_cand}/data-snapshot" && sha256sum -c MANIFEST.sha256)
test "$(sqlite3 -readonly "${swapped_cand}/data-snapshot/aetherflow.sqlite.bak" 'PRAGMA integrity_check;')" = "ok"

# Verify /proc/<updater_pid>/cmdline belongs to our launched release-manager.sh before terminating its process group
cmdline_str="$(tr '\0' ' ' < "/proc/${updater_pid}/cmdline" 2>/dev/null || true)"
case "${cmdline_str}" in
    *release-manager.sh*) ;;
    *)
        echo "Unexpected updater PID cmdline: ${cmdline_str}" >&2
        exit 1
        ;;
esac

# Terminate ONLY the launched updater process group abruptly at the Stage 3 boundary (preventing automatic rollback)
kill -KILL "-${updater_pid}" "${updater_pid}" 2>/dev/null || true
wait "${updater_pid}" 2>/dev/null || true
updater_pid=""
kill "${http_pid}" 2>/dev/null || true

# Confirm the system is genuinely left in an interrupted post-swap state pointing at __INTERRUPTED_TAG__
test "$(readlink -f /opt/AetherFlow/current)" = "${swapped_cand}"
test "$(cat /opt/AetherFlow/releases/.previous_release)" = "${known_good}"
python3 - "${swapped_cand}" "${known_good}" /opt/AetherFlow/releases/.recovery_state.json <<'PY'
import json, sys
cand, prev, rec_path = sys.argv[1:4]
rec = json.load(open(rec_path, encoding="utf-8"))
assert rec.get("phase") in ("stage2_symlink_swap", "stage3_health_probe"), rec
assert rec.get("candidate_release") == cand, rec
assert rec.get("previous_release") == prev, rec
PY

# Verify a new deploy is refused while interrupted and .previous_release is preserved
set +e
/usr/local/bin/af release deploy --local > /tmp/real_interrupted_guard.out 2>&1
interrupted_deploy_rc=$?
set -e
test "${interrupted_deploy_rc}" -ne 0
grep -Eqi 'interrupted deployment|unfinished after symlink swap' /tmp/real_interrupted_guard.out
test "$(cat /opt/AetherFlow/releases/.previous_release)" = "${known_good}"

# Now recover using the shipped CLI (`af release rollback --local --json`)
/usr/local/bin/af release rollback --local --json > /tmp/real_interrupted_rollback.json
cat /tmp/real_interrupted_rollback.json

# Assert symlink, .previous_release, recovery state, SQLite DB integrity & marker row, systemd services, and /health/ready are all intact
test "$(readlink -f /opt/AetherFlow/current)" = "${known_good}"
test "$(tr -d '[:space:]' < /opt/AetherFlow/current/.version)" = "__UPDATE_TAG__"
python3 - /opt/AetherFlow/releases/.recovery_state.json <<'PY'
import json, sys
rec = json.load(open(sys.argv[1], encoding="utf-8"))
assert rec.get("phase") == "complete", rec
PY
test "$(sqlite3 -readonly /var/lib/aetherflow/aetherflow.sqlite 'PRAGMA integrity_check;')" = "ok"
test "$(sqlite3 -readonly /var/lib/aetherflow/aetherflow.sqlite "SELECT v FROM _matrix_drill WHERE k='release_marker';")" = "pre_v4_0_1"
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
    real_interrupted_script = (
        real_interrupted_script
        .replace("__INTERRUPTED_TAG__", interrupted_tag)
        .replace("__UPDATE_TAG__", update_tag)
        .replace("__INTERRUPTED_CURL_SHIM__", interrupted_curl_shim)
    )
    rc4, out4, err4, rec4 = vm.ssh_run(real_interrupted_script, timeout=180, check=False, label="drill-4b-real-interrupted-update-recovery")
    drills.append({
        "phase": "interrupted_update_recovery",
        "status": "passed" if rc4 == 0 else "failed",
        "summary": f"Launched real updater process ({interrupted_tag}), intercepted at observable post-swap Stage 3 boundary after real Stage 1.5 DB snapshot and Stage 2 symlink swap, terminated owned updater process group, verified deploy refusal while interrupted, recovered via shipped `af release rollback --local --json`, and verified DB, services, and symlinks intact." if rc4 == 0 else f"Real interrupted-update recovery drill failed (rc={rc4})",
        "details": {"stdout": out4.strip(), "stderr": err4.strip(), "interrupted_tag": interrupted_tag, "fixture_only": False, "real_execution": True},
        "commands": [rec4],
    })
    return drills
"""



