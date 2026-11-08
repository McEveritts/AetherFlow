"""Load production shell helpers without sourcing host paths or credentials."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def common_functions(*names):
    if 'backup_configured_database' in names or 'restore_configured_database' in names:
        names = tuple(dict.fromkeys((*names, 'configured_database_connection', 'configured_postgresql_cleanup',
                                     'validate_config_paths', 'safe_config_python')))
    if 'safe_rm_rf' in names or 'wait_for_service_ready' in names:
        names = tuple(dict.fromkeys((*names, 'validate_config_paths', 'safe_config_python', 'application_readiness_url')))
    if 'begin_state_transaction' in names:
        names = tuple(dict.fromkeys((*names, 'installed_apt_package_version', 'apt_reinstall_marker_path',
                                     'record_apt_package_for_rollback', 'prepare_apt_package_transaction',
                                     'apt-get', 'rollback_apt_packages', 'clear_apt_reinstall_markers', 'write_config_file')))
    if 'stop_systemd_unit' in names:
        names = tuple(dict.fromkeys((*names, 'quiesce_services_for_rollback', 'retained_bind_address')))
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
