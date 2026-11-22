#!/usr/bin/env python3
"""AetherFlow v4 Privileged Guest Drills Harness.

This stdlib-only Python harness executes ONLY inside a disposable QEMU/systemd
guest VM. It refuses to run on bare-metal hosts, on non-Linux systems, without
root privileges, without explicit disposable-guest markers, or with a work root
outside `/var/tmp/aetherflow-v4-guest-drills*`.

It exercises the real shipped `aetherflow-api` (including `aetherflow-api runner`
over Unix domain sockets) and `af` (`af-cli`) binaries—never mocks—and records
artifact SHA-256 digests, commands, exit statuses, effective UID/GID identities,
exact assertions, and failure diagnostics as structured JSON.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows unit-test import fallback
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


HARNESS_SCHEMA_VERSION = "aetherflow.v4.privileged_guest_drills.v1"

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from lib.vm_guest_common import (  # noqa: E402
    ALLOWED_WORK_ROOT_PREFIX,
    DEFAULT_GUEST_MARKER_FILE,
    FORBIDDEN_HOST_PATHS,
    GUEST_ENV_REQUIRED_VALUE,
    GUEST_ENV_VAR,
    GUEST_MARKER_REQUIRED_TOKEN,
    QEMU_VIRT_IDENTIFIERS,
    AssertionRecord,
    CommandRecord,
    DrillAssertionError,
    DrillPhaseResult,
    GuestSafetyError,
    HeldOpenWalSession,
    RunnerDaemonProcess,
    SentinelSnapshot,
    UdsExchangeRecord,
    _UnixDomainHTTPConnection,
    _build_uds_record,
    compute_file_sha256,
    evaluate_cli_envelope,
    evaluate_drill_suite_status as _evaluate_drill_suite_status,
    evaluate_runner_backup_exchange,
    perform_uds_http_request,
    record_phase_assertion as _record_assertion,
    resolve_unprivileged_identity,
    run_recorded_command,
    snapshot_sentinel,
    utc_now_iso,
    validate_binary_not_in_live_host_tree,
    validate_isolated_work_root,
    verify_guest_execution_guardrails,
    verify_sentinel_unchanged,
)

MANDATORY_DRILL_PHASES: Tuple[str, ...] = (
    "binary_and_environment_provenance",
    "authorized_backup_roundtrip_with_live_wal",
    "arbitrary_root_and_sentinel_deletion_rejection",
    "unprivileged_user_and_socket_authorization_denial",
    "restore_integrity_uid_gid_mode_and_quiescence",
    "held_open_wal_snapshot_recovery",
)


def evaluate_drill_suite_status(
    phases: Sequence[DrillPhaseResult],
    required_phases: Sequence[str] = MANDATORY_DRILL_PHASES,
) -> Dict[str, Any]:
    """Fail-closed evaluation of all mandatory drill phases."""
    return _evaluate_drill_suite_status(phases, required_phases=required_phases)


def seed_isolated_root_filesystem(iso_root: Path, owner_uid: int = 0, owner_gid: int = 0) -> Dict[str, Path]:
    """Create a realistic isolated root layout for archive/restore drills inside work_root."""
    var_lib = iso_root / "var/lib/aetherflow"
    backups_dir = var_lib / "backups"
    etc_af = iso_root / "etc/aetherflow"
    etc_legacy = iso_root / "etc/AetherFlow"
    opt_cfg = iso_root / "opt/AetherFlow/dashboard/config"
    systemd_dir = iso_root / "etc/systemd/system"

    for d in (var_lib, backups_dir, etc_af, etc_legacy, opt_cfg, systemd_dir):
        d.mkdir(parents=True, exist_ok=True)

    env_file = etc_af / "aetherflow.env"
    env_file.write_text("AETHERFLOW_ENV=disposable_guest_drill_v4\nSECRET_KEY=original_secret_value\n", encoding="utf-8")
    os.chown(env_file, owner_uid, owner_gid)
    os.chmod(env_file, 0o600)

    lock_file = etc_legacy / ".Lock"
    lock_file.write_text("lock_marker=v4_original\n", encoding="utf-8")
    os.chown(lock_file, owner_uid, owner_gid)
    os.chmod(lock_file, 0o640)

    settings_file = opt_cfg / "settings.json"
    settings_file.write_text(json.dumps({"theme": "nexus", "version": 4}, indent=2) + "\n", encoding="utf-8")
    os.chown(settings_file, owner_uid, owner_gid)
    os.chmod(settings_file, 0o644)

    unit_file = systemd_dir / "aetherflow-api.service"
    unit_file.write_text("[Unit]\nDescription=Isolated AetherFlow API Marker\n", encoding="utf-8")
    os.chown(unit_file, owner_uid, owner_gid)
    os.chmod(unit_file, 0o644)

    return {
        "iso_root": iso_root,
        "var_lib": var_lib,
        "backups_dir": backups_dir,
        "db_path": var_lib / "aetherflow.sqlite",
        "env_file": env_file,
        "lock_file": lock_file,
        "settings_file": settings_file,
        "unit_file": unit_file,
    }


def run_phase_1_provenance(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
    guardrail_info: Dict[str, Any],
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="binary_and_environment_provenance",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    for label, bin_path in (("aetherflow-api", api_bin), ("af", af_bin)):
        exists = bin_path.is_file() and os.access(bin_path, os.X_OK)
        _record_assertion(
            phase,
            f"{label}_binary_executable",
            exists,
            "executable file exists",
            str(bin_path) if exists else "missing or not executable",
        )
        if exists:
            st = bin_path.stat()
            phase.artifacts[label] = {
                "path": str(bin_path),
                "sha256": compute_file_sha256(bin_path),
                "size_bytes": int(st.st_size),
                "mode_octal": f"{stat.S_IMODE(st.st_mode):04o}",
                "uid": int(st.st_uid),
                "gid": int(st.st_gid),
            }

    if af_bin.is_file():
        ver_cmd = run_recorded_command([str(af_bin), "--json", "version"], cwd=work_root)
        phase.commands.append(ver_cmd)
        ok_env, payload, detail = evaluate_cli_envelope(ver_cmd.stdout, expected_status="ok")
        _record_assertion(
            phase,
            "af_cli_version_envelope",
            ver_cmd.exit_code == 0 and ok_env,
            {"exit_code": 0, "status": "ok"},
            {"exit_code": ver_cmd.exit_code, "detail": detail, "payload": payload},
        )

    unpriv_uid, unpriv_gid, unpriv_name = resolve_unprivileged_identity()
    phase.artifacts["identities"] = {
        "runner_euid": os.geteuid(),
        "runner_egid": os.getegid(),
        "unprivileged_uid": unpriv_uid,
        "unprivileged_gid": unpriv_gid,
        "unprivileged_name": unpriv_name,
    }
    phase.artifacts["guardrails"] = guardrail_info

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_2_backup_roundtrip_with_live_wal(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="authorized_backup_roundtrip_with_live_wal",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    iso_root = work_root / "phase2_roundtrip_iso"
    layout = seed_isolated_root_filesystem(iso_root)
    db_path = layout["db_path"]
    backups_dir = layout["backups_dir"]
    sock_path = work_root / "run/phase2_runner.sock"
    log_path = work_root / "logs/phase2_runner.log"

    wal_session = HeldOpenWalSession(db_path)
    daemon = RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=sock_path,
        env_overrides={"AETHERFLOW_BACKUP_ISOLATED_ROOT": str(iso_root)},
        log_path=log_path,
    )
    try:
        wal_info = wal_session.start()
        phase.artifacts["live_wal_state"] = wal_info
        _record_assertion(
            phase,
            "live_sqlite_wal_and_shm_present_during_backup",
            bool(wal_info.get("wal_exists")) and int(wal_info.get("wal_size", 0)) > 0 and bool(wal_info.get("shm_exists")),
            {"wal_exists": True, "wal_size_gt_0": True, "shm_exists": True},
            wal_info,
        )

        daemon.start()

        # 1. Create SQLite backup via UDS runner (/v1/backup create_sqlite) while WAL is held open
        create_sqlite_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_sqlite",
                "app_version": "v4.0.0-drill",
                "timestamp_slug": "20261103T060001Z",
            },
        )
        phase.uds_exchanges.append(create_sqlite_ex)
        ok_cs, _, cs_payload, cs_detail = evaluate_runner_backup_exchange(
            create_sqlite_ex.http_status,
            create_sqlite_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="create_sqlite",
        )
        _record_assertion(
            phase,
            "uds_runner_create_sqlite_with_live_wal",
            ok_cs,
            "HTTP 200 + create_sqlite success",
            cs_detail,
        )
        sqlite_artifact_name = (
            (cs_payload or {}).get("filename")
            if isinstance(cs_payload, dict)
            else None
        )

        # 2. Create full Archive backup via UDS runner (/v1/backup create_archive) while WAL is held open
        create_arch_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_archive",
                "app_version": "v4.0.0-drill",
                "timestamp_slug": "20261103T060002Z",
            },
        )
        phase.uds_exchanges.append(create_arch_ex)
        ok_ca, _, ca_payload, ca_detail = evaluate_runner_backup_exchange(
            create_arch_ex.http_status,
            create_arch_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="create_archive",
        )
        _record_assertion(
            phase,
            "uds_runner_create_archive_with_live_wal",
            ok_ca,
            "HTTP 200 + create_archive success",
            ca_detail,
        )
        archive_artifact_name = (
            (ca_payload or {}).get("filename")
            if isinstance(ca_payload, dict)
            else None
        )

        # 3. Also exercise `af --json backup create --sqlite-only` CLI while WAL is held open
        cli_create_cmd = run_recorded_command(
            [
                str(af_bin),
                "--root",
                str(iso_root),
                "--json",
                "backup",
                "create",
                "--sqlite-only",
                "--backup-dir",
                str(backups_dir),
                "--db-path",
                str(db_path),
                "--timestamp",
                "20261103T060003Z",
            ],
            cwd=work_root,
        )
        phase.commands.append(cli_create_cmd)
        ok_cli_c, cli_c_env, cli_c_detail = evaluate_cli_envelope(cli_create_cmd.stdout, expected_status="ok")
        _record_assertion(
            phase,
            "af_cli_backup_create_with_live_wal",
            cli_create_cmd.exit_code == 0 and ok_cli_c,
            "exit 0 + ok envelope",
            cli_c_detail,
        )
        cli_sqlite_name = (
            Path(((cli_c_env or {}).get("data") or {}).get("primary_artifact_path", "")).name
            if isinstance(cli_c_env, dict)
            else None
        )

        # 4. List inventory via both UDS runner and `af --json backup list`
        list_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={"action": "list"},
        )
        phase.uds_exchanges.append(list_ex)
        ok_list, _, list_payload, list_detail = evaluate_runner_backup_exchange(
            list_ex.http_status,
            list_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="list",
        )
        listed_names = [
            item.get("filename")
            for item in ((list_payload or {}).get("details") or [])
            if isinstance(item, dict)
        ]
        _record_assertion(
            phase,
            "uds_runner_list_contains_created_artifacts",
            ok_list
            and sqlite_artifact_name in listed_names
            and archive_artifact_name in listed_names
            and cli_sqlite_name in listed_names,
            [sqlite_artifact_name, archive_artifact_name, cli_sqlite_name],
            listed_names,
            detail=list_detail,
        )

        cli_list_cmd = run_recorded_command(
            [
                str(af_bin),
                "--root",
                str(iso_root),
                "--json",
                "backup",
                "list",
                "--backup-dir",
                str(backups_dir),
            ],
            cwd=work_root,
        )
        phase.commands.append(cli_list_cmd)
        ok_cli_l, _, cli_l_detail = evaluate_cli_envelope(cli_list_cmd.stdout, expected_status="ok")
        _record_assertion(
            phase,
            "af_cli_backup_list_envelope",
            cli_list_cmd.exit_code == 0 and ok_cli_l,
            "exit 0 + ok envelope",
            cli_l_detail,
        )

        # 5. Verify both artifacts via UDS runner and `af --json backup verify`
        for art_name in (sqlite_artifact_name, archive_artifact_name):
            if not art_name:
                continue
            art_path = backups_dir / art_name
            phase.artifacts[art_name] = {
                "path": str(art_path),
                "sha256": compute_file_sha256(art_path) if art_path.is_file() else None,
            }
            ver_ex = perform_uds_http_request(
                str(sock_path),
                "POST",
                "/v1/backup",
                body={"action": "verify", "filename": art_name},
            )
            phase.uds_exchanges.append(ver_ex)
            ok_v, _, v_payload, v_detail = evaluate_runner_backup_exchange(
                ver_ex.http_status,
                ver_ex.raw_response,
                expect_http_status=200,
                expect_runner_success=True,
                expected_action="verify",
            )
            verified_flag = (v_payload or {}).get("verified") is True
            _record_assertion(
                phase,
                f"uds_runner_verify_{art_name}",
                ok_v and verified_flag,
                {"ok": True, "verified": True},
                {"ok": ok_v, "verified": verified_flag, "detail": v_detail},
            )

            cli_ver_cmd = run_recorded_command(
                [
                    str(af_bin),
                    "--root",
                    str(iso_root),
                    "--json",
                    "backup",
                    "verify",
                    art_name,
                    "--backup-dir",
                    str(backups_dir),
                ],
                cwd=work_root,
            )
            phase.commands.append(cli_ver_cmd)
            ok_cv, _, cv_detail = evaluate_cli_envelope(cli_ver_cmd.stdout, expected_status="ok")
            _record_assertion(
                phase,
                f"af_cli_verify_{art_name}",
                cli_ver_cmd.exit_code == 0 and ok_cv,
                "exit 0 + ok envelope",
                cv_detail,
            )

        # 6. Tamper check: corrupting the `.sha256` sidecar of `cli_sqlite_name` must fail verification
        if cli_sqlite_name:
            sidecar_path = backups_dir / f"{cli_sqlite_name}.sha256"
            orig_sidecar = sidecar_path.read_text(encoding="utf-8")
            sidecar_path.write_text("0" * 64 + f"  {cli_sqlite_name}\n", encoding="utf-8")
            tamper_ex = perform_uds_http_request(
                str(sock_path),
                "POST",
                "/v1/backup",
                body={"action": "verify", "filename": cli_sqlite_name},
            )
            phase.uds_exchanges.append(tamper_ex)
            _record_assertion(
                phase,
                "tampered_sidecar_fails_verification",
                tamper_ex.http_status == 400
                and bool(tamper_ex.runner_response)
                and not bool(tamper_ex.runner_response.get("success", True)),
                "HTTP 400 + RunnerResponse.success == False",
                {"http_status": tamper_ex.http_status, "runner_response": tamper_ex.runner_response},
            )
            # Restore original sidecar so authorized delete can verify and remove it cleanly
            sidecar_path.write_text(orig_sidecar, encoding="utf-8")

        # 7. Delete roundtrip: delete `sqlite_artifact_name` via UDS runner and `cli_sqlite_name` via `af backup delete`
        if sqlite_artifact_name:
            del_ex = perform_uds_http_request(
                str(sock_path),
                "POST",
                "/v1/backup",
                body={"action": "delete", "filename": sqlite_artifact_name},
            )
            phase.uds_exchanges.append(del_ex)
            ok_del, _, _, del_detail = evaluate_runner_backup_exchange(
                del_ex.http_status,
                del_ex.raw_response,
                expect_http_status=200,
                expect_runner_success=True,
                expected_action="delete",
            )
            _record_assertion(
                phase,
                "uds_runner_delete_verified_backup",
                ok_del and not (backups_dir / sqlite_artifact_name).exists(),
                "HTTP 200 + artifact removed from disk",
                del_detail,
            )

        if cli_sqlite_name:
            cli_del_cmd = run_recorded_command(
                [
                    str(af_bin),
                    "--root",
                    str(iso_root),
                    "--json",
                    "backup",
                    "delete",
                    cli_sqlite_name,
                    "--backup-dir",
                    str(backups_dir),
                ],
                cwd=work_root,
            )
            phase.commands.append(cli_del_cmd)
            ok_cdel, _, cdel_detail = evaluate_cli_envelope(cli_del_cmd.stdout, expected_status="ok")
            _record_assertion(
                phase,
                "af_cli_delete_verified_backup",
                cli_del_cmd.exit_code == 0 and ok_cdel and not (backups_dir / cli_sqlite_name).exists(),
                "exit 0 + artifact removed from disk",
                cdel_detail,
            )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(f"Unhandled exception in phase 2: {type(exc).__name__}: {exc}")
        _record_assertion(phase, "phase2_unhandled_exception", False, "no exception", str(exc))
    finally:
        daemon.stop()
        wal_session.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_3_arbitrary_root_and_sentinel_rejection(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="arbitrary_root_and_sentinel_deletion_rejection",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    iso_root = work_root / "phase3_boundary_iso" / "configured-root"
    layout = seed_isolated_root_filesystem(iso_root)
    backups_dir = layout["backups_dir"]
    db_path = layout["db_path"]

    # Seed a valid SQLite DB
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY);")
    conn.commit()
    conn.close()

    # Create three root-owned sentinels:
    # 1. Inside backup_dir with non-backup extension (`root_sentinel_keep.conf`)
    # 2. Inside backup_dir masquerading as `.sqlite` but WITHOUT a verified inventory sidecar (`untracked_sentinel.sqlite`)
    # 3. Outside backup_dir in `work_root / "outside_sentinel/root_outside_sentinel.sqlite"`
    sentinel_conf = backups_dir / "root_sentinel_keep.conf"
    sentinel_conf.write_text("ROOT_OWNED_SENTINEL_CONF=DO_NOT_DELETE\n", encoding="utf-8")
    os.chown(sentinel_conf, 0, 0)
    os.chmod(sentinel_conf, 0o600)

    sentinel_untracked_sqlite = backups_dir / "untracked_sentinel.sqlite"
    sentinel_untracked_sqlite.write_bytes(b"SQLite format 3\x00ROOT_SENTINEL_UNTRACKED_PAYLOAD")
    os.chown(sentinel_untracked_sqlite, 0, 0)
    os.chmod(sentinel_untracked_sqlite, 0o600)

    outside_dir = work_root / "phase3_outside_root"
    outside_dir.mkdir(parents=True, exist_ok=True)
    sentinel_outside = outside_dir / "root_outside_sentinel.sqlite"
    sentinel_outside.write_bytes(b"SQLite format 3\x00OUTSIDE_ROOT_SENTINEL_PAYLOAD")
    os.chown(sentinel_outside, 0, 0)
    os.chmod(sentinel_outside, 0o600)

    snap_conf_before = snapshot_sentinel(sentinel_conf)
    snap_untracked_before = snapshot_sentinel(sentinel_untracked_sqlite)
    snap_outside_before = snapshot_sentinel(sentinel_outside)

    sock_path = work_root / "run/phase3_runner.sock"
    log_path = work_root / "logs/phase3_runner.log"
    daemon = RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=sock_path,
        env_overrides={"AETHERFLOW_BACKUP_ISOLATED_ROOT": str(iso_root)},
        log_path=log_path,
    )
    try:
        daemon.start()

        # Create one legitimate backup so restore_preflight / restore_execute have a real filename
        legit_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_archive",
                "app_version": "v4.0.0-drill",
                "timestamp_slug": "20261103T061000Z",
            },
        )
        phase.uds_exchanges.append(legit_ex)
        legit_filename = (
            (legit_ex.backup_payload or {}).get("filename")
        )
        if not legit_filename:
            raise ValueError("Runner did not return a real backup filename for the boundary drill")

        # 1. Request-selected arbitrary `backup_dir` override outside server-owned backup root -> HTTP 403
        arb_bdir_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_sqlite",
                "backup_dir": str(outside_dir),
                "timestamp_slug": "20261103T061001Z",
            },
        )
        phase.uds_exchanges.append(arb_bdir_ex)
        ok_bdir, _, _, bdir_detail = evaluate_runner_backup_exchange(
            arb_bdir_ex.http_status,
            arb_bdir_ex.raw_response,
            expect_http_status=403,
            expect_runner_success=False,
            expected_error_substring="untrusted backup_dir override",
        )
        _record_assertion(
            phase,
            "reject_arbitrary_request_backup_dir_override",
            ok_bdir,
            "HTTP 403 untrusted backup_dir override",
            bdir_detail,
        )

        # 2. Request-selected arbitrary `db_path` override outside server-owned DB path -> HTTP 403
        arb_db_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_sqlite",
                "db_path": str(sentinel_outside),
                "timestamp_slug": "20261103T061002Z",
            },
        )
        phase.uds_exchanges.append(arb_db_ex)
        ok_db, _, _, db_detail = evaluate_runner_backup_exchange(
            arb_db_ex.http_status,
            arb_db_ex.raw_response,
            expect_http_status=403,
            expect_runner_success=False,
            expected_error_substring="untrusted db_path override",
        )
        _record_assertion(
            phase,
            "reject_arbitrary_request_db_path_override",
            ok_db,
            "HTTP 403 untrusted db_path override",
            db_detail,
        )

        # 3. Request-selected arbitrary `target_root` override on restore_preflight & restore_execute -> HTTP 403
        for r_action in ("restore_preflight", "restore_execute"):
            arb_tr_ex = perform_uds_http_request(
                str(sock_path),
                "POST",
                "/v1/backup",
                body={
                    "action": r_action,
                    "filename": legit_filename,
                    "target_root": str(outside_dir),
                    "confirm_destructive_restore": True,
                    "allow_overwrite": True,
                },
            )
            phase.uds_exchanges.append(arb_tr_ex)
            ok_tr, _, _, tr_detail = evaluate_runner_backup_exchange(
                arb_tr_ex.http_status,
                arb_tr_ex.raw_response,
                expect_http_status=403,
                expect_runner_success=False,
                expected_error_substring="untrusted target_root",
            )
            _record_assertion(
                phase,
                f"reject_arbitrary_target_root_on_{r_action}",
                ok_tr,
                "HTTP 403 untrusted target_root",
                tr_detail,
            )

        # 4. Reject parent traversal `..` in `backup_dir`, `target_root`, and `filename` -> HTTP 400
        trav_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "delete",
                "filename": "../phase3_outside_root/root_outside_sentinel.sqlite",
            },
        )
        phase.uds_exchanges.append(trav_ex)
        _record_assertion(
            phase,
            "reject_parent_traversal_filename_delete",
            trav_ex.http_status == 400
            and bool(trav_ex.runner_response)
            and not bool(trav_ex.runner_response.get("success", True)),
            "HTTP 400 on '../' filename",
            {"http_status": trav_ex.http_status, "runner_response": trav_ex.runner_response},
        )

        # 5. Reject deletion of unknown / uninventoried files (`root_sentinel_keep.conf`, `untracked_sentinel.sqlite`, `nonexistent.sqlite`)
        for bad_name in (
            "root_sentinel_keep.conf",
            "untracked_sentinel.sqlite",
            "nonexistent-backup-20261103T000000Z.sqlite",
        ):
            del_bad_ex = perform_uds_http_request(
                str(sock_path),
                "POST",
                "/v1/backup",
                body={"action": "delete", "filename": bad_name},
            )
            phase.uds_exchanges.append(del_bad_ex)
            _record_assertion(
                phase,
                f"uds_reject_delete_unknown_or_sentinel_{bad_name}",
                del_bad_ex.http_status == 400
                and bool(del_bad_ex.runner_response)
                and not bool(del_bad_ex.runner_response.get("success", True)),
                "HTTP 400 rejection",
                {"http_status": del_bad_ex.http_status, "runner_response": del_bad_ex.runner_response},
            )

            cli_bad_del = run_recorded_command(
                [
                    str(af_bin),
                    "--root",
                    str(iso_root),
                    "--json",
                    "backup",
                    "delete",
                    bad_name,
                    "--backup-dir",
                    str(backups_dir),
                ],
                cwd=work_root,
            )
            phase.commands.append(cli_bad_del)
            _record_assertion(
                phase,
                f"af_cli_reject_delete_unknown_or_sentinel_{bad_name}",
                cli_bad_del.exit_code != 0,
                "non-zero exit code",
                {"exit_code": cli_bad_del.exit_code, "stdout": cli_bad_del.stdout},
            )

        # 6. Verify all three root-owned sentinels are 100% intact (SHA-256, size, UID/GID, mode, inode)
        for label, before_snap, path_obj in (
            ("sentinel_conf", snap_conf_before, sentinel_conf),
            ("sentinel_untracked_sqlite", snap_untracked_before, sentinel_untracked_sqlite),
            ("sentinel_outside", snap_outside_before, sentinel_outside),
        ):
            after_snap = snapshot_sentinel(path_obj)
            unchanged, drifts = verify_sentinel_unchanged(before_snap, after_snap)
            phase.artifacts[label] = {
                "before": asdict(before_snap),
                "after": asdict(after_snap),
                "drifts": drifts,
            }
            _record_assertion(
                phase,
                f"root_owned_{label}_preserved_intact",
                unchanged,
                "zero sentinel drift (SHA-256, mode, UID/GID, inode preserved)",
                drifts if drifts else "intact",
            )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(f"Unhandled exception in phase 3: {type(exc).__name__}: {exc}")
        _record_assertion(phase, "phase3_unhandled_exception", False, "no exception", str(exc))
    finally:
        daemon.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_4_unprivileged_authorization_denial(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="unprivileged_user_and_socket_authorization_denial",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    unpriv_uid, unpriv_gid, unpriv_name = resolve_unprivileged_identity()
    phase.artifacts["unprivileged_identity"] = {
        "uid": unpriv_uid,
        "gid": unpriv_gid,
        "name": unpriv_name,
    }

    iso_root = work_root / "phase4_auth_iso"
    layout = seed_isolated_root_filesystem(iso_root)
    # Traverse permissions on work_root and run dir so unprivileged user can reach the socket inode
    os.chmod(work_root, 0o755)
    run_dir = work_root / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(run_dir, 0o755)

    sock_path = run_dir / "phase4_runner.sock"
    log_path = work_root / "logs/phase4_runner.log"
    daemon = RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=sock_path,
        env_overrides={"AETHERFLOW_BACKUP_ISOLATED_ROOT": str(iso_root)},
        log_path=log_path,
    )
    try:
        daemon.start()

        # 1. Default socket mode 0660 (root:root) blocks unprivileged user at filesystem permission layer
        st_sock = os.stat(sock_path)
        sock_mode = f"{stat.S_IMODE(st_sock.st_mode):04o}"
        _record_assertion(
            phase,
            "runner_socket_default_mode_0660",
            sock_mode == "0660",
            "0660",
            sock_mode,
        )

        dac_ex = perform_uds_http_request(
            str(sock_path),
            "GET",
            "/v1/health",
            run_as_uid=unpriv_uid,
            run_as_gid=unpriv_gid,
        )
        phase.uds_exchanges.append(dac_ex)
        _record_assertion(
            phase,
            "unprivileged_user_denied_by_socket_dac_0660",
            dac_ex.http_status is None
            and dac_ex.socket_error is not None
            and ("PermissionError" in dac_ex.socket_error or "Errno 13" in dac_ex.socket_error),
            "PermissionError (EACCES) on 0660 socket",
            {"http_status": dac_ex.http_status, "socket_error": dac_ex.socket_error},
        )

        # 2. Kernel SO_PEERCRED authorization enforcement:
        # Even if socket permissions are relaxed to 0666 so the unprivileged UID can connect(),
        # `authorize_runner_peer_credentials` in `af-runner` inspects SO_PEERCRED and rejects
        # the unauthorized UID (closing the stream / returning HTTP 403).
        os.chmod(sock_path, 0o666)
        for endpoint, method, req_body in (
            ("/v1/health", "GET", None),
            (
                "/v1/backup",
                "POST",
                {"action": "create_sqlite", "timestamp_slug": "20261103T062000Z"},
            ),
            (
                "/v1/backup",
                "POST",
                {"action": "delete", "filename": "any.sqlite"},
            ),
        ):
            peercred_ex = perform_uds_http_request(
                str(sock_path),
                method,
                endpoint,
                body=req_body,
                run_as_uid=unpriv_uid,
                run_as_gid=unpriv_gid,
            )
            phase.uds_exchanges.append(peercred_ex)
            denied_by_peercred = (
                peercred_ex.http_status == 403
                or (
                    peercred_ex.http_status is None
                    and peercred_ex.socket_error is not None
                )
            )
            _record_assertion(
                phase,
                f"unprivileged_uid_denied_by_so_peercred_{method}_{endpoint.strip('/').replace('/', '_')}",
                denied_by_peercred,
                "rejected by SO_PEERCRED (connection closed or HTTP 403)",
                {
                    "http_status": peercred_ex.http_status,
                    "socket_error": peercred_ex.socket_error,
                    "raw_response": peercred_ex.raw_response,
                },
            )

        # 3. `af --socket <sock> --json health` executed as unprivileged UID must fail with exit code 3 (RunnerIpcFailure)
        unpriv_af_health = run_recorded_command(
            [str(af_bin), "--socket", str(sock_path), "--json", "health"],
            cwd=work_root,
            run_as_uid=unpriv_uid,
            run_as_gid=unpriv_gid,
        )
        phase.commands.append(unpriv_af_health)
        ok_err_env, _, err_detail = evaluate_cli_envelope(
            unpriv_af_health.stderr,
            expected_status="error",
            expected_error_code="runner_ipc_failure",
        )
        _record_assertion(
            phase,
            "af_cli_health_as_unprivileged_uid_rejected_over_uds",
            unpriv_af_health.exit_code == 3 and ok_err_env,
            {"exit_code": 3, "error_code": "runner_ipc_failure"},
            {"exit_code": unpriv_af_health.exit_code, "detail": err_detail},
        )

        # Restore 0660 mode and verify runner log recorded the peer rejection
        os.chmod(sock_path, 0o660)
        runner_logs = daemon.read_logs()
        phase.artifacts["runner_peercred_log_excerpt"] = runner_logs[-1000:]
        _record_assertion(
            phase,
            "runner_logged_unauthorized_peer_rejection",
            "Rejected unauthorized UNIX socket peer" in runner_logs
            or "unauthorized unix socket peer" in runner_logs,
            "log contains unauthorized peer rejection message",
            runner_logs[-400:],
        )

        # 4. Unprivileged user invoking `af --json backup create` without `--root` or `--operator-privileged`
        # must fail closed with exit code 5 (`privilege_required`).
        unpriv_af_backup = run_recorded_command(
            [
                str(af_bin),
                "--json",
                "backup",
                "create",
                "--sqlite-only",
            ],
            cwd=work_root,
            run_as_uid=unpriv_uid,
            run_as_gid=unpriv_gid,
        )
        phase.commands.append(unpriv_af_backup)
        ok_priv_env, _, priv_detail = evaluate_cli_envelope(
            unpriv_af_backup.stderr,
            expected_status="error",
            expected_error_code="privilege_required",
        )
        _record_assertion(
            phase,
            "af_cli_backup_create_as_unprivileged_uid_denied_exit_5",
            unpriv_af_backup.exit_code == 5 and ok_priv_env,
            {"exit_code": 5, "error_code": "privilege_required"},
            {"exit_code": unpriv_af_backup.exit_code, "detail": priv_detail},
        )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(f"Unhandled exception in phase 4: {type(exc).__name__}: {exc}")
        _record_assertion(phase, "phase4_unhandled_exception", False, "no exception", str(exc))
    finally:
        daemon.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_5_restore_integrity_and_quiescence(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="restore_integrity_uid_gid_mode_and_quiescence",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    unpriv_uid, unpriv_gid, _ = resolve_unprivileged_identity()
    iso_root = work_root / "phase5_restore_iso"
    # Seed isolated root with specific non-root ownership (unpriv_uid:unpriv_gid) and strict file modes
    layout = seed_isolated_root_filesystem(iso_root, owner_uid=unpriv_uid, owner_gid=unpriv_gid)
    db_path = layout["db_path"]
    backups_dir = layout["backups_dir"]
    env_file = layout["env_file"]
    lock_file = layout["lock_file"]
    settings_file = layout["settings_file"]

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("CREATE TABLE restore_verify (id INTEGER PRIMARY KEY, label TEXT NOT NULL);")
    conn.execute("INSERT INTO restore_verify (id, label) VALUES (1, 'golden_snapshot_row');")
    conn.commit()
    conn.close()
    os.chown(db_path, unpriv_uid, unpriv_gid)
    os.chmod(db_path, 0o640)

    phase.artifacts["pre_vacuum_db_sha256"] = compute_file_sha256(db_path)
    golden_env_sha = compute_file_sha256(env_file)
    golden_lock_sha = compute_file_sha256(lock_file)

    sock_iso = work_root / "run/phase5_iso_runner.sock"
    log_iso = work_root / "logs/phase5_iso_runner.log"
    daemon_iso = RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=sock_iso,
        env_overrides={
            "AETHERFLOW_BACKUP_ISOLATED_ROOT": str(iso_root),
            "AETHERFLOW_TRUSTED_SQLITE_UID": str(unpriv_uid),
            "AETHERFLOW_TRUSTED_SQLITE_GID": str(unpriv_gid),
        },
        log_path=log_iso,
    )

    # Set up a real disposable systemd unit in the guest `/etc/systemd/system` to test real
    # `CommandQuiescenceController` (`/bin/systemctl stop|start|is-active`) when
    # `AETHERFLOW_BACKUP_ISOLATED_ROOT` is NOT set on the runner.
    drill_unit_name = "aetherflow-v4-drill-quiesce.service"
    drill_unit_path = Path("/etc/systemd/system") / drill_unit_name
    sock_quiesce = work_root / "run/phase5_quiesce_runner.sock"
    log_quiesce = work_root / "logs/phase5_quiesce_runner.log"
    quiesce_staging_root = work_root / "phase5_quiesce_staging"
    quiesce_staging_root.mkdir(parents=True, exist_ok=True)

    daemon_quiesce: Optional[RunnerDaemonProcess] = None
    try:
        daemon_iso.start()

        # 1. Create golden archive backup containing DB + config files with recorded UID/GID/mode in manifest
        create_ex = perform_uds_http_request(
            str(sock_iso),
            "POST",
            "/v1/backup",
            body={
                "action": "create_archive",
                "app_version": "v4.0.0-drill",
                "timestamp_slug": "20261103T063000Z",
            },
        )
        phase.uds_exchanges.append(create_ex)
        ok_cr, _, cr_payload, cr_detail = evaluate_runner_backup_exchange(
            create_ex.http_status,
            create_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="create_archive",
        )
        _record_assertion(
            phase,
            "create_golden_archive_for_restore",
            ok_cr,
            "HTTP 200 create_archive",
            cr_detail,
        )
        archive_filename = (cr_payload or {}).get("filename")
        golden_db_sha = (((cr_payload or {}).get("details") or {}).get("sqlite_snapshot") or {}).get("sha256")
        if not isinstance(golden_db_sha, str) or len(golden_db_sha) != 64:
            raise ValueError("Runner did not return a verified SQLite snapshot checksum")
        assert isinstance(archive_filename, str) and archive_filename

        # 2. Unconfirmed destructive restore MUST fail closed via both UDS runner (HTTP 400) and CLI (exit 6)
        unconf_ex = perform_uds_http_request(
            str(sock_iso),
            "POST",
            "/v1/backup",
            body={
                "action": "restore_execute",
                "filename": archive_filename,
                "target_root": str(iso_root),
                "confirm_destructive_restore": False,
                "allow_overwrite": True,
            },
        )
        phase.uds_exchanges.append(unconf_ex)
        _record_assertion(
            phase,
            "uds_restore_without_confirmation_fails_closed",
            unconf_ex.http_status == 400
            and bool(unconf_ex.runner_response)
            and not bool(unconf_ex.runner_response.get("success", True)),
            "HTTP 400 when confirm_destructive_restore=False",
            {"http_status": unconf_ex.http_status, "runner_response": unconf_ex.runner_response},
        )

        unconf_cli = run_recorded_command(
            [
                str(af_bin),
                "--root",
                str(iso_root),
                "--json",
                "backup",
                "restore",
                archive_filename,
                "--backup-dir",
                str(backups_dir),
                "--target-root",
                str(iso_root),
            ],
            cwd=work_root,
        )
        phase.commands.append(unconf_cli)
        ok_unconf_env, _, unconf_detail = evaluate_cli_envelope(
            unconf_cli.stderr,
            expected_status="error",
            expected_error_code="unsupported_operation",
        )
        _record_assertion(
            phase,
            "af_cli_restore_without_confirmation_exits_6",
            unconf_cli.exit_code == 6 and ok_unconf_env,
            {"exit_code": 6, "error_code": "unsupported_operation"},
            {"exit_code": unconf_cli.exit_code, "detail": unconf_detail},
        )

        # 3. Corrupt live target files, alter ownership/modes to root:root 0777, and plant stale -wal/-shm sidecars
        env_file.write_text("CORRUPTED_ENV=1\n", encoding="utf-8")
        os.chown(env_file, 0, 0)
        os.chmod(env_file, 0o777)

        lock_file.write_text("CORRUPTED_LOCK=1\n", encoding="utf-8")
        os.chown(lock_file, 0, 0)
        os.chmod(lock_file, 0o777)

        conn_c = sqlite3.connect(str(db_path))
        conn_c.execute("DELETE FROM restore_verify;")
        conn_c.execute("INSERT INTO restore_verify (id, label) VALUES (999, 'mutated_post_backup');")
        conn_c.commit()
        conn_c.close()
        os.chown(db_path, 0, 0)
        os.chmod(db_path, 0o777)

        stale_wal = Path(f"{db_path}-wal")
        stale_shm = Path(f"{db_path}-shm")
        stale_wal.write_bytes(b"STALE_WAL_BYTES_MUST_BE_UNLINKED")
        stale_shm.write_bytes(b"STALE_SHM_BYTES_MUST_BE_UNLINKED")

        # 4. Install and start a real disposable systemd unit in the guest, then run a second runner
        # configured with explicit `AETHERFLOW_BACKUP_DIR`, `AETHERFLOW_DB_PATH`, and
        # `AETHERFLOW_RESTORE_STAGING_ROOT` (with `AETHERFLOW_BACKUP_ISOLATED_ROOT` UNSET and
        # `AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE=0`) so `CommandQuiescenceController` executes real
        # `/bin/systemctl stop`, `/bin/systemctl start`, and `/bin/systemctl is-active --quiet`!
        phase.contract_notes.append(
            "Contract note: af-runner sets dry_quiesce=true when AETHERFLOW_BACKUP_ISOLATED_ROOT is non-empty "
            "(crates/af-runner/src/lib.rs:881-887). To exercise real CommandQuiescenceController (/bin/systemctl) "
            "against an isolated target root, the runner must be launched with AETHERFLOW_BACKUP_ISOLATED_ROOT unset "
            "and AETHERFLOW_BACKUP_DIR, AETHERFLOW_DB_PATH, and AETHERFLOW_RESTORE_STAGING_ROOT set."
        )

        drill_unit_path.write_text(
            "[Unit]\n"
            "Description=AetherFlow v4 Privileged Guest Drill Quiescence Target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            f"ExecStart={sys.executable} -c 'import time; time.sleep(3600)'\n"
            "Restart=no\n",
            encoding="utf-8",
        )
        phase.commands.append(run_recorded_command(["systemctl", "daemon-reload"], cwd=work_root))
        phase.commands.append(run_recorded_command(["systemctl", "start", drill_unit_name], cwd=work_root))
        pre_active_cmd = run_recorded_command(["systemctl", "is-active", drill_unit_name], cwd=work_root)
        phase.commands.append(pre_active_cmd)
        pre_pid_cmd = run_recorded_command(
            ["systemctl", "show", "-p", "MainPID", "--value", drill_unit_name],
            cwd=work_root,
        )
        phase.commands.append(pre_pid_cmd)
        pre_main_pid = int(pre_pid_cmd.stdout.strip() or "0")

        _record_assertion(
            phase,
            "systemd_quiesce_target_unit_active_before_restore",
            pre_active_cmd.exit_code == 0 and pre_main_pid > 0,
            {"active": True, "MainPID_gt_0": True},
            {"exit_code": pre_active_cmd.exit_code, "MainPID": pre_main_pid},
        )

        # Copy the golden archive + sidecars into `quiesce_staging_root` or point `AETHERFLOW_BACKUP_DIR` at `backups_dir`
        # and `AETHERFLOW_RESTORE_STAGING_ROOT` at `iso_root` so `validate_runner_restore_target_root` permits `iso_root`!
        daemon_quiesce = RunnerDaemonProcess(
            api_bin=api_bin,
            socket_path=sock_quiesce,
            env_overrides={
                "AETHERFLOW_BACKUP_DIR": str(backups_dir),
                "AETHERFLOW_DB_PATH": str(db_path),
                "AETHERFLOW_RESTORE_STAGING_ROOT": str(iso_root),
                "AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE": "0",
                "AETHERFLOW_TRUSTED_SQLITE_UID": str(unpriv_uid),
                "AETHERFLOW_TRUSTED_SQLITE_GID": str(unpriv_gid),
            },
            log_path=log_quiesce,
        )
        daemon_quiesce.start()

        restore_ex = perform_uds_http_request(
            str(sock_quiesce),
            "POST",
            "/v1/backup",
            body={
                "action": "restore_execute",
                "filename": archive_filename,
                "target_root": str(iso_root),
                "confirm_destructive_restore": True,
                "allow_overwrite": True,
                "quiesce_services": [drill_unit_name],
            },
        )
        phase.uds_exchanges.append(restore_ex)
        ok_rest, _, rest_payload, rest_detail = evaluate_runner_backup_exchange(
            restore_ex.http_status,
            restore_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="restore_execute",
        )
        _record_assertion(
            phase,
            "uds_restore_execute_with_mandatory_service_quiescence",
            ok_rest,
            "HTTP 200 + restore_execute success",
            rest_detail,
        )

        restore_report = (rest_payload or {}).get("details") or {}
        quiesced_list = restore_report.get("quiesced_services") or []
        _record_assertion(
            phase,
            "restore_report_records_quiesced_systemd_service",
            drill_unit_name in quiesced_list,
            [drill_unit_name],
            quiesced_list,
        )

        # Verify systemd service was actually stopped and restarted (MainPID changed and service is active)
        post_active_cmd = run_recorded_command(["systemctl", "is-active", drill_unit_name], cwd=work_root)
        phase.commands.append(post_active_cmd)
        post_pid_cmd = run_recorded_command(
            ["systemctl", "show", "-p", "MainPID", "--value", drill_unit_name],
            cwd=work_root,
        )
        phase.commands.append(post_pid_cmd)
        post_main_pid = int(post_pid_cmd.stdout.strip() or "0")
        _record_assertion(
            phase,
            "systemd_unit_stopped_and_restarted_by_quiescence_controller",
            post_active_cmd.exit_code == 0 and post_main_pid > 0 and post_main_pid != pre_main_pid,
            {"active": True, "MainPID_restarted": True, "pre_pid": pre_main_pid},
            {"exit_code": post_active_cmd.exit_code, "post_pid": post_main_pid, "pre_pid": pre_main_pid},
        )

        # 5. Verify restored file contents (SHA-256), UID/GID, and file modes (0600, 0640, 0640)
        _record_assertion(
            phase,
            "restored_sqlite_db_sha256_and_contents_match_golden",
            compute_file_sha256(db_path) == golden_db_sha,
            golden_db_sha,
            compute_file_sha256(db_path),
        )
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as restored_database:
            restored_rows = restored_database.execute("SELECT id, label FROM restore_verify ORDER BY id").fetchall()
            integrity = restored_database.execute("PRAGMA integrity_check").fetchone()[0]
        _record_assertion(
            phase,
            "restored_sqlite_committed_rows_and_integrity",
            integrity == "ok" and restored_rows == [(1, "golden_snapshot_row")],
            {"integrity": "ok", "rows": [(1, "golden_snapshot_row")]},
            {"integrity": integrity, "rows": restored_rows},
        )
        _record_assertion(
            phase,
            "restored_env_file_sha256_matches_golden",
            compute_file_sha256(env_file) == golden_env_sha,
            golden_env_sha,
            compute_file_sha256(env_file),
        )
        _record_assertion(
            phase,
            "restored_lock_file_sha256_matches_golden",
            compute_file_sha256(lock_file) == golden_lock_sha,
            golden_lock_sha,
            compute_file_sha256(lock_file),
        )

        for label, fpath, expected_mode in (
            ("env_file_0600", env_file, "0600"),
            ("lock_file_0640", lock_file, "0640"),
            ("db_file_0640", db_path, "0640"),
        ):
            st = os.stat(fpath)
            actual_mode = f"{stat.S_IMODE(st.st_mode):04o}"
            _record_assertion(
                phase,
                f"restored_{label}_uid_gid_and_mode_integrity",
                int(st.st_uid) == unpriv_uid
                and int(st.st_gid) == unpriv_gid
                and actual_mode == expected_mode,
                {"uid": unpriv_uid, "gid": unpriv_gid, "mode": expected_mode},
                {"uid": int(st.st_uid), "gid": int(st.st_gid), "mode": actual_mode},
            )

        # 6. Verify stale -wal and -shm sidecars were unlinked during SQLite restore
        _record_assertion(
            phase,
            "stale_wal_and_shm_sidecars_unlinked_on_restore",
            not stale_wal.exists() and not stale_shm.exists(),
            {"wal_exists": False, "shm_exists": False},
            {"wal_exists": stale_wal.exists(), "shm_exists": stale_shm.exists()},
        )

        # 7. Verify rollback when a requested quiesce service fails to stop (non-existent unit)
        env_file.write_text("PRE_FAILED_RESTORE_SENTINEL=keep_on_abort\n", encoding="utf-8")
        before_failed_stop = [snapshot_sentinel(path) for path in (env_file, lock_file, db_path)]
        failed_quiesce_ex = perform_uds_http_request(
            str(sock_quiesce),
            "POST",
            "/v1/backup",
            body={
                "action": "restore_execute",
                "filename": archive_filename,
                "target_root": str(iso_root),
                "confirm_destructive_restore": True,
                "allow_overwrite": True,
                "quiesce_services": ["nonexistent-aetherflow-unit-must-fail.service"],
            },
        )
        phase.uds_exchanges.append(failed_quiesce_ex)
        unchanged_after_failed_stop = [
            verify_sentinel_unchanged(before, snapshot_sentinel(Path(before.path)))
            for before in before_failed_stop
        ]
        stop_failure_response = failed_quiesce_ex.runner_response or {}
        _record_assertion(
            phase,
            "restore_fails_closed_when_quiesce_stop_fails_and_preserves_live_target",
            failed_quiesce_ex.http_status == 500
            and stop_failure_response.get("success") is False
            and "service quiescence failed" in stop_failure_response.get("error", "")
            and all(result[0] for result in unchanged_after_failed_stop),
            "HTTP 500 service quiescence failure + all live target metadata and bytes untouched",
            {
                "http_status": failed_quiesce_ex.http_status,
                "env_content": env_file.read_text(encoding="utf-8").strip(),
                "sentinel_checks": unchanged_after_failed_stop,
            },
        )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(f"Unhandled exception in phase 5: {type(exc).__name__}: {exc}")
        _record_assertion(phase, "phase5_unhandled_exception", False, "no exception", str(exc))
    finally:
        if daemon_quiesce is not None:
            daemon_quiesce.stop()
        daemon_iso.stop()
        if drill_unit_path.exists():
            subprocess.run(["systemctl", "stop", drill_unit_name], check=False, capture_output=True)
            try:
                drill_unit_path.unlink()
            except OSError:
                pass
            subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True)

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_6_held_open_wal_snapshot_recovery(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="held_open_wal_snapshot_recovery",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    source_iso = work_root / "phase6_wal_source_iso"
    source_layout = seed_isolated_root_filesystem(source_iso)
    source_db = source_layout["db_path"]
    source_backups = source_layout["backups_dir"]

    recovery_iso = work_root / "phase6_wal_recovery_iso"
    recovery_layout = seed_isolated_root_filesystem(recovery_iso)
    recovery_db = recovery_layout["db_path"]

    sock_path = work_root / "run/phase6_runner.sock"
    log_path = work_root / "logs/phase6_runner.log"

    wal_session = HeldOpenWalSession(source_db)
    daemon = RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=sock_path,
        env_overrides={
            "AETHERFLOW_BACKUP_ISOLATED_ROOT": str(source_iso),
            "AETHERFLOW_RESTORE_STAGING_ROOT": str(recovery_iso),
        },
        log_path=log_path,
    )
    try:
        wal_info = wal_session.start()
        phase.artifacts["source_live_wal_state"] = wal_info
        daemon.start()

        # 1. Capture both an archive backup and a standalone SQLite backup while `wal_session` holds:
        #    - committed rows strictly in uncheckpointed `-wal` frames (`wal_autocheckpoint=0`)
        #    - an active reader transaction lock
        #    - an uncommitted write transaction (`uncommitted_inflight_txn_must_not_leak`)
        arch_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_archive",
                "app_version": "v4.0.0-drill",
                "timestamp_slug": "20261103T064001Z",
            },
        )
        phase.uds_exchanges.append(arch_ex)
        ok_arch, _, arch_payload, arch_detail = evaluate_runner_backup_exchange(
            arch_ex.http_status,
            arch_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="create_archive",
        )
        _record_assertion(
            phase,
            "capture_archive_snapshot_from_held_open_wal_db",
            ok_arch,
            "HTTP 200 create_archive",
            arch_detail,
        )
        arch_filename = (arch_payload or {}).get("filename")
        assert isinstance(arch_filename, str) and arch_filename

        # 2. Seed `recovery_db` with pre-existing dirty WAL/SHM files, then restore the snapshot into `recovery_iso`
        conn_dirty = sqlite3.connect(str(recovery_db))
        conn_dirty.execute("PRAGMA journal_mode=WAL;")
        conn_dirty.execute("CREATE TABLE old_garbage (x TEXT);")
        conn_dirty.commit()
        conn_dirty.close()
        Path(f"{recovery_db}-wal").write_bytes(b"OLD_DIRTY_WAL_FRAMES")
        Path(f"{recovery_db}-shm").write_bytes(b"OLD_DIRTY_SHM_FRAMES")

        rest_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "restore_execute",
                "filename": arch_filename,
                "target_root": str(recovery_iso),
                "confirm_destructive_restore": True,
                "allow_overwrite": True,
            },
        )
        phase.uds_exchanges.append(rest_ex)
        ok_rest, _, _, rest_detail = evaluate_runner_backup_exchange(
            rest_ex.http_status,
            rest_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="restore_execute",
        )
        _record_assertion(
            phase,
            "restore_held_open_wal_snapshot_into_recovery_root",
            ok_rest,
            "HTTP 200 restore_execute",
            rest_detail,
        )

        # 3. Also test `af --json backup restore` CLI recovery into a second clean directory
        cli_recovery_iso = work_root / "phase6_cli_wal_recovery_iso"
        cli_recovery_layout = seed_isolated_root_filesystem(cli_recovery_iso)
        shutil.copytree(source_backups, cli_recovery_layout["backups_dir"], dirs_exist_ok=True)
        cli_rest_cmd = run_recorded_command(
            [
                str(af_bin),
                "--root",
                str(cli_recovery_iso),
                "--json",
                "backup",
                "restore",
                arch_filename,
                "--backup-dir",
                str(cli_recovery_layout["backups_dir"]),
                "--target-root",
                str(cli_recovery_iso),
                "--confirm-destructive-restore",
                "--allow-overwrite",
            ],
            cwd=work_root,
        )
        phase.commands.append(cli_rest_cmd)
        ok_cli_r, _, cli_r_detail = evaluate_cli_envelope(cli_rest_cmd.stdout, expected_status="ok")
        _record_assertion(
            phase,
            "af_cli_restore_held_open_wal_snapshot",
            cli_rest_cmd.exit_code == 0 and ok_cli_r,
            "exit 0 + ok envelope",
            cli_r_detail,
        )

        # 4. Inspect both recovered SQLite databases:
        #    - PRAGMA integrity_check == "ok"
        #    - PRAGMA quick_check == "ok"
        #    - PRAGMA user_version == 404
        #    - All committed WAL rows (`committed_row_1..3`, `schema_marker`) are present
        #    - Uncommitted in-flight write row (`uncommitted_inflight_txn_must_not_leak`) is NOT present
        for label, target_db in (
            ("uds_recovered_db", recovery_db),
            ("cli_recovered_db", cli_recovery_layout["db_path"]),
        ):
            r_conn = sqlite3.connect(str(target_db))
            try:
                integrity = r_conn.execute("PRAGMA integrity_check;").fetchone()[0]
                quick = r_conn.execute("PRAGMA quick_check;").fetchone()[0]
                user_ver = r_conn.execute("PRAGMA user_version;").fetchone()[0]
                rows = dict(r_conn.execute("SELECT k, v FROM drill_kv ORDER BY k;").fetchall())
            finally:
                r_conn.close()

            expected_rows = dict(wal_session.committed_rows)
            uncommitted_present = wal_session.uncommitted_key in rows
            phase.artifacts[label] = {
                "path": str(target_db),
                "sha256": compute_file_sha256(target_db),
                "integrity_check": integrity,
                "quick_check": quick,
                "user_version": user_ver,
                "recovered_rows": rows,
                "uncommitted_present": uncommitted_present,
            }
            _record_assertion(
                phase,
                f"{label}_sqlite_integrity_and_wal_snapshot_consistency",
                integrity == "ok"
                and quick == "ok"
                and int(user_ver) == 404
                and rows == expected_rows
                and not uncommitted_present,
                {
                    "integrity_check": "ok",
                    "quick_check": "ok",
                    "user_version": 404,
                    "rows": expected_rows,
                    "uncommitted_present": False,
                },
                phase.artifacts[label],
            )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(f"Unhandled exception in phase 6: {type(exc).__name__}: {exc}")
        _record_assertion(phase, "phase6_unhandled_exception", False, "no exception", str(exc))
    finally:
        daemon.stop()
        wal_session.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def execute_guest_drill_suite(
    *,
    confirm_disposable_guest: bool,
    work_root: str,
    api_bin: str,
    af_bin: str,
    guest_marker_file: str = DEFAULT_GUEST_MARKER_FILE,
    keep_work_root: bool = False,
) -> Dict[str, Any]:
    """Run all 6 mandatory privileged guest drill phases and return the structured JSON report."""
    guardrail_info = verify_guest_execution_guardrails(
        confirm_disposable_guest=confirm_disposable_guest,
        work_root=work_root,
        api_bin=api_bin,
        af_bin=af_bin,
        guest_marker_file=guest_marker_file,
    )

    work_root_path = Path(guardrail_info["work_root"])
    api_bin_path = Path(guardrail_info["api_bin"])
    af_bin_path = Path(guardrail_info["af_bin"])

    if work_root_path.exists():
        shutil.rmtree(work_root_path)
    work_root_path.mkdir(parents=True, exist_ok=True)

    suite_started = utc_now_iso()
    t0 = time.monotonic()
    phases: List[DrillPhaseResult] = []
    try:
        phases.append(
            run_phase_1_provenance(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
                guardrail_info=guardrail_info,
            )
        )
        phases.append(
            run_phase_2_backup_roundtrip_with_live_wal(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_3_arbitrary_root_and_sentinel_rejection(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_4_unprivileged_authorization_denial(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_5_restore_integrity_and_quiescence(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_6_held_open_wal_snapshot_recovery(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
    finally:
        if not keep_work_root and work_root_path.exists():
            shutil.rmtree(work_root_path, ignore_errors=True)

    evaluation = evaluate_drill_suite_status(phases)
    suite_completed = utc_now_iso()
    return {
        "schema_version": HARNESS_SCHEMA_VERSION,
        "started_at": suite_started,
        "completed_at": suite_completed,
        "duration_ms": round((time.monotonic() - t0) * 1000.0, 2),
        "guardrails": guardrail_info,
        "evaluation": evaluation,
        "phases": [asdict(p) for p in phases],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AetherFlow v4 Privileged Guest Drills Harness (disposable QEMU/systemd VM only)."
    )
    parser.add_argument(
        "--confirm-disposable-guest",
        action="store_true",
        help="Required explicit confirmation that execution is inside a disposable QEMU/systemd guest.",
    )
    parser.add_argument(
        "--work-root",
        default=f"{ALLOWED_WORK_ROOT_PREFIX}-run",
        help=f"Isolated scratch root inside the guest (must start with {ALLOWED_WORK_ROOT_PREFIX}).",
    )
    parser.add_argument(
        "--api-bin",
        required=True,
        help="Absolute path to the staged `aetherflow-api` binary inside the guest (never /opt/AetherFlow).",
    )
    parser.add_argument(
        "--af-bin",
        required=True,
        help="Absolute path to the staged `af` (`af-cli`) binary inside the guest (never /opt/AetherFlow).",
    )
    parser.add_argument(
        "--guest-marker-file",
        default=DEFAULT_GUEST_MARKER_FILE,
        help=f"Path to disposable guest marker file under /run (default: {DEFAULT_GUEST_MARKER_FILE}).",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional path to write the JSON drill report.",
    )
    parser.add_argument(
        "--keep-work-root",
        action="store_true",
        help="Preserve the isolated --work-root directory after execution for post-mortem inspection.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        report = execute_guest_drill_suite(
            confirm_disposable_guest=bool(args.confirm_disposable_guest),
            work_root=str(args.work_root),
            api_bin=str(args.api_bin),
            af_bin=str(args.af_bin),
            guest_marker_file=str(args.guest_marker_file),
            keep_work_root=bool(args.keep_work_root),
        )
    except GuestSafetyError as exc:
        err_report = {
            "schema_version": HARNESS_SCHEMA_VERSION,
            "timestamp": utc_now_iso(),
            "overall_status": "blocked_by_guest_safety_guardrail",
            "overall_passed": False,
            "error": str(exc),
        }
        rendered = json.dumps(err_report, indent=2, sort_keys=True)
        if args.json_out:
            Path(args.json_out).write_text(rendered + "\n", encoding="utf-8")
        print(rendered)
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["evaluation"]["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
