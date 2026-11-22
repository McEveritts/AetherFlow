"""Load production shell helpers without sourcing host paths or credentials."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def mock_rutorrent_backend(bin_dir):
    """Supply a healthy SCGI boundary in fixtures focused on other installer behavior."""
    shim = bin_dir / "runuser"
    shim.write_text(r"""#!/bin/bash
[[ "$1 $2 $3 $4 $5" == '-u www-data -- php --' ]] || exit 1
grep -Fq 'system.client_version' || exit 1
printf 'ready\n'
""")
    shim.chmod(0o755)


def common_functions(*names):
    names = tuple(dict.fromkeys((
        'af_prepare_logfile_path', 'af_logged', 'af_logged_stderr', 'af_github_curl', 'deb_compare_versions',
        'af_strip_version_prefix', 'af_normalize_exact_registry_version', 'af_read_npm_package_version',
        'af_validate_exact_apt_version', 'installed_apt_package_version', 'apt_package_raw_status',
        'apt_package_has_active_or_transitional_payload', 'apt_package_is_lockstep',
        'verify_apt_package_installed', 'resolve_installed_apt_package_version',
        'af_resolve_recovery_root', 'af_prepare_recovery_root', 'af_create_recovery_backup_dir',
        *names,
    )))
    if 'backup_configured_database' in names or 'restore_configured_database' in names:
        names = tuple(dict.fromkeys((*names, 'configured_database_connection', 'configured_postgresql_cleanup',
                                     'validate_config_paths', 'safe_config_python')))
    if 'safe_rm_rf' in names or 'wait_for_service_ready' in names:
        names = tuple(dict.fromkeys((*names, 'validate_config_paths', 'safe_config_python', 'application_readiness_url', 'af_emit_readiness_record')))
    if 'wait_for_apache_app_ready' in names or 'apache_app_enter_maintenance' in names:
        names = tuple(dict.fromkeys((*names, 'apache_app_readiness_target', 'apache_app_probe_body_is_healthy',
                                     'apache_app_prepare_maintenance_vhost', 'apache_app_capture_worker_pids',
                                     'apache_app_drain_workers', 'apache_app_verify_quiesced',
                                     'apache_app_swap_site_symlink', 'apache_app_enter_maintenance',
                                     'apache_app_quiesce_for_rollback', 'apache_app_activate_vhost',
                                     'apache_app_resume_after_rollback',
                                     'validate_config_paths', 'safe_config_python')))
    if 'begin_state_transaction' in names:
        names = tuple(dict.fromkeys((*names, 'installed_apt_package_version', 'apt_reinstall_marker_path',
                                     'record_apt_package_for_rollback', 'prepare_apt_package_transaction',
                                     'apt-get', 'rollback_apt_packages', 'clear_apt_reinstall_markers', 'write_config_file',
                                     'derive_app_password', 'check_disk_space')))
    if 'stop_systemd_unit' in names:
        names = tuple(dict.fromkeys((*names, 'quiesce_services_for_rollback', 'retained_bind_address')))
    if 'download_file' in names:
        names = tuple(dict.fromkeys((*names, 'af_prepare_logfile_path', 'af_validate_tar_archive')))
    if 'git_checkout_version' in names:
        names = tuple(dict.fromkeys((*names, 'git_stage_exact_revision')))
    if 'af_emit_readiness_record' in names or 'safe_config_python' in names:
        names = tuple(dict.fromkeys((*names, 'safe_config_python', 'af_local_readiness_python',
                                     'af_wait_local_web_services')))
    source = (ROOT / "packages/common.sh").read_text()
    functions = []
    for name in names:
        start = source.index(f"\n{name}() ") + 1
        opening = source[start:source.index("\n", start)]
        ending = "\n)\n" if opening.endswith("(") else "\n}\n"
        end = source.index(ending, start) + len(ending)
        functions.append(source[start:end])
    return "\n".join(functions)


def replace_paths_once(source, replacements):
    """Rebase fixture paths once, even when TMPDIR itself contains /home/."""
    import re
    mapping = dict(replacements)
    pattern = re.compile("|".join(re.escape(path) for path in sorted(mapping, key=len, reverse=True)))
    return pattern.sub(lambda match: mapping[match.group(0)], source)


def installer_common_functions(*names):
    helpers = (
        "queue_app_version", "commit_app_versions", "write_app_version", "resolve_installed_binary_version",
        "safe_restore_path_from_backup", "safe_rm_rf", "safe_config_python", "validate_config_paths",
        "snapshot_app_state", "restore_app_state", "retain_successful_app_backups", "snapshot_state_dirs", "restore_state_snapshot",
        "begin_state_transaction", "cleanup_state_transaction", "systemd_unit_inactive", "stop_systemd_unit", "quiesce_services_for_rollback",
        "verify_systemd_service_active", "wait_for_service_ready", "verify_sha256", "verify_download_sha256", "download_file",
    )
    return common_functions(*dict.fromkeys((*names, *helpers)))


def dpkg_compare_versions_exit_code(arguments):
    """Evaluate `dpkg --compare-versions <v1> <op> <v2>` using `/usr/bin/dpkg` when available,
    falling back to Debian Policy §5.6.12 pure-Python ordering on non-Debian test hosts."""
    import os
    import subprocess

    if os.path.exists("/usr/bin/dpkg"):
        return subprocess.run(["/usr/bin/dpkg", *arguments]).returncode

    idx = list(arguments).index("--compare-versions")
    if idx + 3 >= len(arguments):
        return 2
    v1, op, v2 = arguments[idx + 1], arguments[idx + 2], arguments[idx + 3]

    def _deb_split(ver):
        epoch = 0
        if ":" in ver:
            ep, rest = ver.split(":", 1)
            if not ep.isdigit():
                return None
            epoch, ver = int(ep), rest
        upstream, rev = ver.rsplit("-", 1) if "-" in ver else (ver, "")
        return epoch, upstream, rev

    def _deb_order(ch):
        if ch == "~":
            return -1
        if ("A" <= ch <= "Z") or ("a" <= ch <= "z"):
            return ord(ch)
        return ord(ch) + 256

    def _deb_part_cmp(a, b):
        i = j = 0
        na, nb = len(a), len(b)
        while i < na or j < nb:
            while (i < na and not a[i].isdigit()) or (j < nb and not b[j].isdigit()):
                ca = _deb_order(a[i]) if i < na and not a[i].isdigit() else 0
                cb = _deb_order(b[j]) if j < nb and not b[j].isdigit() else 0
                if ca != cb:
                    return -1 if ca < cb else 1
                if i < na and not a[i].isdigit():
                    i += 1
                if j < nb and not b[j].isdigit():
                    j += 1
            ia, jb = i, j
            while i < na and a[i].isdigit():
                i += 1
            while j < nb and b[j].isdigit():
                j += 1
            da = int(a[ia:i] or "0")
            db = int(b[jb:j] or "0")
            if da != db:
                return -1 if da < db else 1
        return 0

    s1, s2 = _deb_split(v1), _deb_split(v2)
    if s1 is None or s2 is None:
        return 2
    e1, u1, r1 = s1
    e2, u2, r2 = s2
    c = (-1 if e1 < e2 else (1 if e1 > e2 else 0)) or _deb_part_cmp(u1, u2) or _deb_part_cmp(r1, r2)
    ops = {
        "lt": c < 0, "<<": c < 0,
        "le": c <= 0, "<=": c <= 0, "<": c <= 0,
        "eq": c == 0, "=": c == 0,
        "ne": c != 0,
        "ge": c >= 0, ">=": c >= 0, ">": c >= 0,
        "gt": c > 0, ">>": c > 0,
    }
    if op not in ops:
        return 2
    return 0 if ops[op] else 1


if __name__ == "__main__":
    import sys

    if "--compare-versions" in sys.argv[1:]:
        raise SystemExit(dpkg_compare_versions_exit_code(sys.argv[1:]))
    raise SystemExit(2)
