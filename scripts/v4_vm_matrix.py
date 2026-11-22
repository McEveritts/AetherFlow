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
import inspect
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


SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from lib.vm_guest_common import compute_file_digest  # noqa: E402
from lib.vm_matrix_helpers import (  # noqa: E402
    DEFAULT_ARTIFACT_CONTRACT,
    DEFAULT_BASELINE_SOURCE_DIR,
    DEFAULT_OVERLAY_DISK_SIZE,
    DEFAULT_QEMU_TOOLS_ROOT,
    DEFAULT_REMOTE_WORK_ROOT,
    DEFAULT_VM_MEMORY_MIB,
    DEFAULT_VM_VCPUS,
    MANDATORY_CERTIFICATION_PHASES,
    OFFICIAL_OS_MATRIX,
    OPTIONAL_FIXTURE_PHASES,
    OS_MATRIX_BY_ID,
    REQUIRED_SOURCE_LAYOUT_ENTRIES,
    V4_RELEASE_TAG_RE,
    CommandEvidence,
    DrillPhaseResult,
    GuestBootEvidence,
    ImageVerificationEvidence,
    OsImageSpec,
    PendingArtifactContract,
    TargetMatrixReport,
    build_qemu_command,
    build_qemu_environment,
    derive_drill_release_plan,
    evaluate_certification_status,
    extract_archive_version_stamp,
    extract_max_glibc_from_elf_symbols,
    extract_validated_source_tarball,
    inspect_source_tarball_layout,
    is_glibc_compatible,
    parse_checksum_manifest,
    parse_glibc_tuple,
    parse_os_release_text,
    render_loopback_curl_shim,
    render_nocloud_seed_files,
    resolve_selected_specs,
    utc_now_iso,
    validate_certification_inputs,
    validate_work_root_path,
    verify_release_artifact_contract,
)
from lib.vm_remote_engine import REMOTE_DRILL_HELPERS, REMOTE_ENGINE_SCRIPT  # noqa: E402


def render_baseline_guest_build_script(*, jobs: int = 2) -> str:
    """
    Renders the in-guest build script for `build-baseline-artifact` inside Ubuntu 22.04 (GLIBC 2.35).
    Enforces:
      1. Real Rust WASM build (`bash scripts/build_wasm_frontend.sh --stage`), using pinned tools,
         even when placeholder `web/dist` directories already exist in the repo.
      2. Verifies the external entrypoint and WASM assets before packaging.
      3. Requires `backend-rs/Cargo.lock` to exist and runs `cargo fetch --locked` first, followed by
         offline (`CARGO_NET_OFFLINE=true`), locked (`CARGO_LOCKED=1` / `--locked`) compilation.
      4. Enforces resource discipline inside the guest (`nice -n 10 ionice -c 2 -n 7`, `CARGO_BUILD_JOBS=2`).
    """
    if jobs < 1 or jobs > 4:
        raise ValueError(f"jobs must be between 1 and 4 (got {jobs})")
    return f"""set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -yqq
apt-get install -yqq build-essential pkg-config libssl-dev libsqlite3-dev curl ca-certificates git binutils python3 >/dev/null
export PATH="/root/.cargo/bin:/var/tmp/af-build/wasm-tools/bin:${{PATH}}"
export CARGO_BUILD_JOBS={jobs}
export RUSTFLAGS="-C link-arg=-fuse-ld=bfd"
tar -xzf /var/tmp/af-build/src.tar.gz -C /var/tmp/af-build/src
cd /var/tmp/af-build/src

# 1. Always build real Rust WASM assets, including when placeholder dist directories exist.
test -s frontend-rs/Cargo.toml
wasm_tool_dir="/var/tmp/af-build/wasm-tools"
mkdir -p "${{wasm_tool_dir}}/bin"
WASM_TOOL_DIR="${{wasm_tool_dir}}" bash scripts/install_wasm_build_tools.sh --ensure
export TRUNK_TOOLS_WASM_OPT=version_133
rm -rf web/dist frontend-rs/dist
# Native backend linker flags must not reach wasm-ld.
RUSTFLAGS="" nice -n 10 ionice -c 2 -n 7 bash scripts/build_wasm_frontend.sh --stage
test -s web/dist/index.html
test -n "$(find web/dist -type f -name '*.wasm' -size +0c -print -quit)"

# 2. Require final committed Cargo.lock, prefetch crates explicitly, then compile offline with --locked and 2 jobs
test -s backend-rs/Cargo.lock
(
    cd backend-rs
    nice -n 10 ionice -c 2 -n 7 cargo fetch --locked
)
CARGO_LOCKED=1 CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS={jobs} BUILD_FRONTEND=0 RUN_TESTS=0 OUTPUT_DIR=/var/tmp/af-build/out \\
    nice -n 10 ionice -c 2 -n 7 bash scripts/build_gold.sh

readelf --version-info \\
    /var/tmp/af-build/out/linux-amd64/aetherflow-api \\
    /var/tmp/af-build/out/linux-amd64/bin/af \\
    /var/tmp/af-build/out/linux-amd64/bin/speedtest-backend \\
    | grep -oE 'GLIBC_[0-9]+\\.[0-9]+(\\.[0-9]+)?' | sort -V | tail -n 1 > /var/tmp/af-build/out/MAX_GLIBC.txt || true
"""



def build_remote_driver_script() -> str:
    """
    Assembles the complete remote Python matrix driver script executed by `run_remote_matrix_action`.
    Shares local drill-fixture helper definitions directly to avoid local/remote drift.
    """
    guest_build_script_literal = json.dumps(render_baseline_guest_build_script(jobs=2))
    shared_drill_helpers = "\n\n".join(
        (
            f"V4_RELEASE_TAG_RE = re.compile({V4_RELEASE_TAG_RE.pattern!r})",
            inspect.getsource(derive_drill_release_plan),
            inspect.getsource(extract_archive_version_stamp),
            inspect.getsource(render_loopback_curl_shim),
        )
    )
    return (
        REMOTE_ENGINE_SCRIPT
        + "\n"
        + shared_drill_helpers
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

        with IsolatedVmSession(
            spec,
            img_ev,
            work_root=work_root,
            qemu_root=qemu_root,
            vcpus=int(payload.get("vcpus", 2)),
            memory_mib=int(payload.get("memory_mib", 3584)),
        ) as vm:
            boot_ev = vm.wait_for_ssh_and_systemd(timeout=180)
            vm.ssh_run("mkdir -p /var/tmp/af-build/src", timeout=20, check=True, label="mkdir-vm-build")
            vm.copy_to_guest(src_tar, "/var/tmp/af-build/src.tar.gz", timeout=180, label="upload-src-tar")

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
    p.add_argument("--node-root", help=argparse.SUPPRESS)  # Compatibility with existing invocations.
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
