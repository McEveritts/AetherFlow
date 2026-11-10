#!/bin/bash
# /opt/AetherFlow/packages/common.sh
# Shared variables and functions for AetherFlow scripts/installers.

set -euo pipefail
umask 077

export PATH="/usr/local/nodejs/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export LOGFILE="${LOGFILE:-/var/log/aetherflow/install.log}"
export LOCK_DIR="${LOCK_DIR:-/install}"
export AF_REQUIRE_DOWNLOAD_SHA256="${AF_REQUIRE_DOWNLOAD_SHA256:-1}"

mkdir -p "$LOCK_DIR" "$(dirname "$LOGFILE")"

timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

log() {
    printf '[%s] %s\n' "$(timestamp)" "$*" >>"$LOGFILE"
}

log_info() {
    log "[INFO] $*"
}

log_warn() {
    log "[WARN] $*"
}

log_error() {
    log "[ERROR] $*"
}

print_info() {
    printf '[INFO] %s\n' "$*"
    log_info "$*"
}

print_warn() {
    printf '[WARN] %s\n' "$*" >&2
    log_warn "$*"
}

print_warning() {
    print_warn "$@"
}

print_error() {
    printf '[ERROR] %s\n' "$*" >&2
    log_error "$*"
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        print_error "This command must be run as root."
        exit 1
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

safe_rm_rf() {
    local target
    [[ "$#" -gt 0 ]] || return 1
    for target in "$@"; do
        if [[ "$target" != /* || "$target" == *'/../'* || "$target" == */.. || "$target" == *'/./'* || "$target" == */. || "$target" == *'//'* ]]; then
            print_error "Refusing unsafe recursive removal: $target"
            return 1
        fi
        case "${target%/}" in
            ""|/|/etc|/opt|/srv|/var|/var/lib|/var/www|/home|/usr|/data)
                print_error "Refusing recursive removal of a shared root: $target"
                return 1
                ;;
        esac
        target="${target%/}"
        validate_config_paths "$(dirname "$target")/.af-remove-check" || return 1
        if [[ ! -L "$target" ]]; then
            command -v mountpoint >/dev/null || return 1
            if mountpoint -q -- "$target"; then
                print_error "Refusing recursive removal of a mount point: $target"
                return 1
            fi
        fi
    done
    for target in "$@"; do
        target="${target%/}"
        if [[ -L "$target" ]]; then
            rm -f -- "$target" || return 1
        else
            rm -rf --one-file-system -- "$target" || return 1
        fi
    done
}

# Keep build dependencies and lifecycle scripts enabled even when the host or
# calling service has production-only npm settings. In particular, global=true
# leaks into npm's Git preparation subprocess and skips its local devDependencies.
# Run in a subshell so application runtime settings and the caller stay intact.
node_build() (
    unset npm_config_production NPM_CONFIG_PRODUCTION npm_config_only NPM_CONFIG_ONLY
    unset AF_GITHUB_TOKEN GITHUB_TOKEN GH_TOKEN GITLAB_TOKEN GITEA_TOKEN RCLONE_PASS RCLONE_RC_PASS MASTER_PASS AF_CONFIG_PASS DB_PASSWORD SECRET_KEY API_KEY
    export npm_config_global=false NPM_CONFIG_GLOBAL=false
    export npm_config_omit= NPM_CONFIG_OMIT=
    # npm serializes array-valued configuration with double newlines.
    export npm_config_include=$'dev\n\npeer\n\noptional'
    export NPM_CONFIG_INCLUDE="$npm_config_include"
    export npm_config_ignore_scripts=false NPM_CONFIG_IGNORE_SCRIPTS=false
    export YARN_PRODUCTION=false
    "$@"
)

# Install npm applications locally so Git dependencies can prepare with their
# own complete toolchains. Build before replacing any existing application and
# expose only the application's executable, rather than global build tools.
install_npm_app() (
    set -e
    umask 022
    local package="$1" destination="$2" executable="$3" staged="" bin_name
    bin_name="$(basename "$executable")"
    mkdir -p "$(dirname "$destination")" "$(dirname "$executable")"
    staged="$(mktemp -d "${destination}.af-build.XXXXXX")"
    trap '[[ -z "$staged" ]] || rm -rf -- "$staged"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # mktemp creates a private directory; the service user must traverse it.
    chmod 755 "$staged"
    node_build npm install --prefix "$staged" --no-audit --no-fund "$package" >> "$LOGFILE" 2>&1 || return $?
    if [[ ! -x "$staged/node_modules/.bin/$bin_name" ]]; then
        print_error "npm package $package did not provide executable $bin_name"
        return 1
    fi
    replace_app_tree "$staged" "$destination" || return $?
    staged=""
    ln -sfn -- "$destination/node_modules/.bin/$bin_name" "$executable"
)

# Stage on the destination filesystem so replacement uses rename(), including
# when /tmp lives on a different mount. Never truncate an executing inode.
queue_app_version() {
    local version_path="$1" staged="${3:-}" snapshot
    if [[ -e "$version_path" || -L "$version_path" ]]; then
        write_app_version "$version_path" "$2" --check || return 1
    fi
    if [[ -n "$staged" ]]; then
        export AF_TX_DIR="${4:?A staged version requires a private transaction directory}"
        if [[ -f "$version_path" && ! -L "$version_path" ]]; then
            validate_config_paths "$version_path" || return 1
            snapshot="$AF_TX_DIR/pre_versions$version_path"
            mkdir -p -m 0700 -- "$(dirname "$snapshot")" || return 1
            if [[ ! -f "$snapshot" ]]; then
                install -m 0600 -- "$version_path" "$snapshot" || return 1
            fi
            cp -p --remove-destination -- "$snapshot" "$staged/.af-version" || return 1
        fi
    fi
    declare -ag AF_PENDING_VERSION_PATHS AF_PENDING_VERSION_VALUES
    AF_PENDING_VERSION_PATHS+=("$1")
    AF_PENDING_VERSION_VALUES+=("$2")
}

commit_app_versions() {
    local index
    declare -ag AF_PENDING_VERSION_PATHS AF_PENDING_VERSION_VALUES
    if [[ -n "${AF_TARGET_VERSION:-}" ]] && (( ${#AF_PENDING_VERSION_VALUES[@]} > 0 )); then
        local clean_target="${AF_TARGET_VERSION#release-}"
        clean_target="${clean_target#Release-}"
        clean_target="${clean_target#v}"
        clean_target="${clean_target#V}"
        local primary_ver="${AF_PENDING_VERSION_VALUES[0]}"
        local norm_ver="${primary_ver#release-}"
        norm_ver="${norm_ver#Release-}"
        norm_ver="${norm_ver#v}"
        norm_ver="${norm_ver#V}"
        if [[ "$norm_ver" != "$clean_target" ]]; then
            if (( ${#AF_PENDING_VERSION_VALUES[@]} > 1 )); then
                echo "ERROR: Committed version(s) (${AF_PENDING_VERSION_VALUES[*]}) do not match requested target version (${AF_TARGET_VERSION})" >&2
            else
                echo "ERROR: Committed version(s) (${AF_PENDING_VERSION_VALUES[*]}) does not match requested target version (${AF_TARGET_VERSION})" >&2
            fi
            return 1
        fi
    fi
    if [[ -n "${AF_STATE_BACKUP:-}" && -n "${AF_STATE_UNIT:-}" ]]; then
        verify_systemd_service_active "$AF_STATE_UNIT" || return 1
        if [[ "${AF_STATE_PORT:-0}" != 0 ]]; then
            wait_for_service_ready "$AF_STATE_UNIT" "$AF_STATE_PORT" "$AF_STATE_READINESS_PATH" || return 1
        fi
    fi
    for index in "${!AF_PENDING_VERSION_PATHS[@]}"; do
        write_app_version "${AF_PENDING_VERSION_PATHS[$index]}" "${AF_PENDING_VERSION_VALUES[$index]}" || return 1
    done
}

resolve_installed_binary_version() {
    local binary_path="$1" fallback_version="$2" output version argument
    if [[ -x "$binary_path" ]]; then
        for argument in --version -v version; do
            output="$(timeout 10 "$binary_path" "$argument" 2>/dev/null)" || continue
            version="$(printf '%s\n' "$output" | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?' | head -n 1 || true)"
            if [[ -n "$version" ]]; then
                printf '%s\n' "$version"
                return 0
            fi
        done
    fi
    if [[ "${AF_ALLOW_VERSION_FALLBACK:-0}" == "1" && -n "$fallback_version" ]]; then
        printf '%s\n' "${fallback_version#v}"
        return 0
    fi
    return 1
}

write_app_version() {
    if [[ -z "${2//[[:space:]]/}" ]]; then
        print_error "Refusing an empty application version receipt"
        return 1
    fi
    AF_TX_DIR="${AF_TX_DIR:-}" python3 - "$@" <<'PYEOF'
import os, pathlib, re, secrets, stat, subprocess, sys
path = pathlib.PurePath(sys.argv[1])
if not path.is_absolute() or '..' in path.parts or path.name != '.af-version':
    raise ValueError('Invalid application version path')
directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
temporary = '.af-version.' + secrets.token_hex(12)
try:
    for component in path.parts[1:-1]:
        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        os.close(directory)
        directory = child
    transaction = os.environ.get('AF_TX_DIR')
    snapshot = pathlib.Path(transaction, 'pre_versions', *path.parts[1:]) if transaction else None
    if snapshot is not None:
        snapshot_directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in snapshot.parts[1:-1]:
                try:
                    os.mkdir(component, 0o700, dir_fd=snapshot_directory)
                except FileExistsError:
                    pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=snapshot_directory)
                os.close(snapshot_directory)
                snapshot_directory = child
            source_descriptor = None
            try:
                source_metadata = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                if stat.S_ISREG(source_metadata.st_mode):
                    source_descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError:
                pass
            if source_descriptor is not None:
                with os.fdopen(source_descriptor, 'rb') as source:
                    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                        raise ValueError('Application version receipt must be a regular file')
                    try:
                        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=snapshot_directory)
                    except FileExistsError:
                        pass
                    else:
                        with os.fdopen(descriptor, 'wb') as output:
                            output.write(source.read())
                            output.flush()
                            os.fsync(output.fileno())
        finally:
            os.close(snapshot_directory)
    if os.environ.get('AF_ALLOW_DOWNGRADE') != '1':
        previous_directory = directory
        if snapshot is not None and snapshot.exists():
            previous_directory = os.open(snapshot.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            try:
                previous = os.stat(path.name, dir_fd=previous_directory, follow_symlinks=False)
            except FileNotFoundError:
                previous = None
            if previous is not None and stat.S_ISREG(previous.st_mode):
                descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=previous_directory)
                with os.fdopen(descriptor) as source:
                    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                        raise ValueError('Application version receipt must be a regular file')
                    old_ver = source.read().strip()
                new_ver = sys.argv[2]
                old_compare = re.sub(r'^(?:[vV]|release-)+', '', old_ver)
                new_compare = re.sub(r'^(?:[vV]|release-)+', '', new_ver)
                old_sha = re.fullmatch(r'[0-9a-fA-F]{7,40}', old_compare)
                new_sha = re.fullmatch(r'[0-9a-fA-F]{7,40}', new_compare)
                rejected = bool(old_sha and not old_compare.isdecimal() and not new_sha)
                if old_compare and old_compare[0].isdigit() and (not old_sha or old_compare.isdecimal()):
                    rejected = (not new_compare or not new_compare[0].isdigit() or bool(new_sha and not new_compare.isdecimal())
                                or subprocess.run(['dpkg', '--compare-versions', new_compare, 'ge', old_compare]).returncode != 0)
                if rejected:
                    raise ValueError(f'Refusing to downgrade {path} from {old_ver} to {new_ver}')
        finally:
            if previous_directory != directory:
                os.close(previous_directory)
    if len(sys.argv) > 3 and sys.argv[3] == '--check':
        sys.exit(0)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(descriptor, 'w') as output:
        os.fchmod(output.fileno(), 0o644)
        output.write(sys.argv[2] + '\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
    os.fsync(directory)
finally:
    try:
        os.unlink(temporary, dir_fd=directory)
    except FileNotFoundError:
        pass
    os.close(directory)
PYEOF
}

git_checkout_version() {
    local directory="$1" previous="${2:-}" version
    version="$(git -C "$directory" describe --tags --abbrev=0 2>/dev/null || true)"
    if [[ -z "${version//[[:space:]]/}" ]]; then
        version="$(git -C "$directory" rev-parse HEAD 2>/dev/null || true)"
    fi
    if [[ -z "${version//[[:space:]]/}" && -n "$previous" && -f "$previous" && ! -L "$previous" ]]; then
        version="$(cat -- "$previous")"
    fi
    [[ -n "${version//[[:space:]]/}" ]] || { print_error "Cannot determine checked-out application version"; return 1; }
    printf '%s\n' "$version"
}

verify_deb_installed() {
    local package="$1" expected="${2:-}" observed status installed
    observed="$(dpkg-query -W -f='${db:Status-Status} ${Version}\n' "$package" 2>/dev/null)" || return 1
    read -r status installed <<< "$observed"
    if [[ "$status" != installed || -z "$installed" ]]; then
        print_error "Package $package is not installed"
        return 1
    fi
    if [[ -n "$expected" ]] && ! dpkg --compare-versions "$installed" eq "$expected"; then
        print_error "Package $package version $installed does not match $expected"
        return 1
    fi
}

installed_apt_package_version() {
    local observed status version
    observed="$(dpkg-query -W -f='${db:Status-Status} ${Version}\n' "$1" 2>/dev/null || true)"
    read -r status version <<< "$observed"
    if [[ "$status" == installed && -n "$version" ]]; then
        printf '%s\n' "$version"
    else
        printf '<none>\n'
    fi
}

apt_reinstall_marker_path() {
    [[ "$1" =~ ^[a-z0-9][a-z0-9+.-]*(:[a-z0-9][a-z0-9-]*)?$ ]] || return 1
    printf '/var/lib/aetherflow/apt-reinstall-required/%s\n' "$1"
}

record_apt_package_for_rollback() {
    local package version
    [[ -n "${AF_TX_DIR:-}" && -d "$AF_TX_DIR" && ! -L "$AF_TX_DIR" ]] || return 1
    mkdir -p -m 0700 -- "$AF_TX_DIR/apt-packages" || return 1
    for package in "$@"; do
        apt_reinstall_marker_path "$package" >/dev/null || return 1
        if [[ ! -e "$AF_TX_DIR/apt-packages/$package" ]]; then
            version="$(installed_apt_package_version "$package")" || return 1
            printf '%s\n' "$version" > "$AF_TX_DIR/apt-packages/$package" || return 1
        fi
    done
}

prepare_apt_package_transaction() {
    local receipt="$1" package marker installed previous="" normalized
    shift
    validate_config_paths "$(dirname "$receipt")/.af-apt-receipt-check" || return 1
    if [[ -f "$receipt" && ! -L "$receipt" ]]; then
        previous="$(safe_config_python "$receipt" <<'PYEOF'
import sys
with ManagedConfig(sys.argv[1], create_parents=False) as config:
    print(config.read_text().strip())
PYEOF
)" || return 1
    fi
    declare -ag AF_APT_REINSTALL_PACKAGES=() AF_APT_TRANSACTION_PACKAGES=()
    record_apt_package_for_rollback "$@" || return 1
    for package in "$@"; do
        AF_APT_TRANSACTION_PACKAGES+=("$package")
        marker="$(apt_reinstall_marker_path "$package")" || return 1
        validate_config_paths "$marker" || return 1
        installed="$(installed_apt_package_version "$package")" || return 1
        normalized="${installed#*:}"
        normalized="${normalized%%-*}"
        if [[ -f "$marker" || ( "$installed" != '<none>' && -z "$previous" ) || ( -n "$previous" && "$installed" != "$previous" && "$normalized" != "${previous#v}" ) ]]; then
            AF_APT_REINSTALL_PACKAGES+=("$package")
        fi
    done
}

apt-get() {
    local package argument selected=false present=false
    local -a additional=()
    if [[ "${1:-}" == install ]]; then
        for package in "${AF_APT_TRANSACTION_PACKAGES[@]}"; do
            for argument in "${@:2}"; do
                if [[ "$argument" == "$package" || "$argument" == "$package="* || "$argument" == /*.deb ]]; then
                    selected=true
                fi
            done
        done
    fi
    if [[ "$selected" == true && "${#AF_APT_REINSTALL_PACKAGES[@]}" -gt 0 ]]; then
        for package in "${AF_APT_REINSTALL_PACKAGES[@]}"; do
            present=false
            for argument in "${@:2}"; do
                if [[ "$argument" == "$package" || "$argument" == "$package="* || "$argument" == /*.deb ]]; then
                    present=true
                fi
            done
            [[ "$present" == true ]] || additional+=("$package")
        done
        command apt-get install --reinstall "${@:2}" "${additional[@]}"
    else
        command apt-get "$@"
    fi
}

rollback_apt_packages() {
    local state package previous installed marker reconciled failed=false
    AF_APT_ROLLBACK_MUTATED=false
    [[ -d "${AF_TX_DIR:-}/apt-packages" ]] || return 0
    for state in "$AF_TX_DIR/apt-packages/"*; do
        [[ -f "$state" && ! -L "$state" ]] || continue
        package="${state##*/}"
        previous="$(cat -- "$state")"
        installed="$(installed_apt_package_version "$package")"
        [[ "$installed" != "$previous" ]] || continue
        AF_APT_ROLLBACK_MUTATED=true
        reconciled=true
        if [[ "$previous" == '<none>' ]]; then
            DEBIAN_FRONTEND=noninteractive command apt-get remove -y --no-auto-remove "$package" >> "$LOGFILE" 2>&1 || reconciled=false
        else
            DEBIAN_FRONTEND=noninteractive command apt-get install -y --allow-downgrades --reinstall "$package=$previous" >> "$LOGFILE" 2>&1 || reconciled=false
        fi
        installed="$(installed_apt_package_version "$package")"
        if [[ "$reconciled" != true || "$installed" != "$previous" ]]; then
            marker="$(apt_reinstall_marker_path "$package")" || return 1
            printf '%s\n' "$previous" | write_config_file "$marker" 0600 || return 1
            print_warn "APT recovery for $package requires reinstallation on the next attempt"
            failed=true
        fi
    done
    [[ "$failed" == false ]]
}

clear_apt_reinstall_markers() {
    local state marker
    [[ -d "${AF_TX_DIR:-}/apt-packages" ]] || return 0
    for state in "$AF_TX_DIR/apt-packages/"*; do
        [[ -f "$state" && ! -L "$state" ]] || continue
        marker="$(apt_reinstall_marker_path "${state##*/}")" || return 1
        validate_config_paths "$marker" || return 1
        rm -f -- "$marker" || return 1
    done
}

install_deb_verified() {
    local archive="$1" package="$2" expected="${3:-}"
    [[ -n "$expected" ]] || expected="$(dpkg-deb -f "$archive" Version)" || return 1
    [[ -n "$expected" ]] || return 1
    if ! DEBIAN_FRONTEND=noninteractive dpkg -i "$archive" >> "$LOGFILE" 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -f -y -qq >> "$LOGFILE" 2>&1 || return 1
        DEBIAN_FRONTEND=noninteractive dpkg -i "$archive" >> "$LOGFILE" 2>&1 || return 1
    fi
    verify_deb_installed "$package" "$expected"
}

safe_restore_path_from_backup() {
    local backup_src="$1" target_dst="$2" parent_dir stage_dir
    [[ "$target_dst" == /* && "$target_dst" != *'/../'* && "$target_dst" != */.. && "$target_dst" != *'/./'* && "$target_dst" != */. && "$target_dst" != *'//'* ]] || return 1
    case "${target_dst%/}" in
        ""|/|/etc|/opt|/srv|/var|/var/lib|/var/www|/home|/usr|/data) return 1 ;;
    esac
    parent_dir="$(dirname "$target_dst")"
    validate_config_paths "$parent_dir/.af-restore-check" || return 1
    if [[ ! -e "$backup_src" && ! -L "$backup_src" ]]; then
        safe_rm_rf "$target_dst"
        return $?
    fi
    mkdir -p -- "$parent_dir" || return 1
    stage_dir="$(mktemp -d "$parent_dir/.$(basename "$target_dst").af-restore.XXXXXX")" || return 1
    if ! cp -a -- "$backup_src" "$stage_dir/restored"; then
        rm -rf -- "$stage_dir" 2>/dev/null || true
        return 1
    fi
    if [[ -e "$target_dst" || -L "$target_dst" ]]; then
        if ! mv -T -- "$target_dst" "$stage_dir/previous"; then
            rm -rf -- "$stage_dir" 2>/dev/null || true
            return 1
        fi
    fi
    if ! mv -T -- "$stage_dir/restored" "$target_dst"; then
        if [[ -e "$stage_dir/previous" || -L "$stage_dir/previous" ]]; then
            if ! mv -T -- "$stage_dir/previous" "$target_dst"; then
                print_warn "Live data retained for manual recovery in $stage_dir/previous; backup remains at $backup_src"
                return 1
            fi
        fi
        rm -rf -- "$stage_dir" 2>/dev/null || true
        return 1
    fi
    rm -rf -- "$stage_dir"
}

snapshot_state_dirs() {
    snapshot_app_state "$@"
}

retained_bind_address() {
    safe_config_python "$1" "$2" <<'PYEOF'
import re, sys
match = re.search(sys.argv[2], safe_read_text(sys.argv[1]), re.MULTILINE)
host = match.group(1).strip().strip('\'"') if match else '127.0.0.1'
if not re.fullmatch(r'[a-zA-Z0-9_.:\[\]-]+', host):
    raise ValueError('Invalid retained listener address')
print(host)
PYEOF
}

check_disk_space() {
    local check_path="${1:-.}"
    local required_mb="${2:-512}"
    local required_kb
    if [[ ! "$required_mb" =~ ^[0-9]+$ ]]; then
        echo "ERROR: Invalid required disk space: ${required_mb}" >&2
        return 1
    fi
    if (( required_mb > 100000 )); then
        required_kb="$required_mb"
    else
        required_kb=$(( required_mb * 1024 ))
    fi

    local orig_path="$check_path"
    while [[ ! -e "$check_path" && "$check_path" != "/" && "$check_path" != "." ]]; do
        check_path="$(dirname "$check_path")"
    done

    local target_path="$orig_path"
    local fs_type
    fs_type="$(df -PT "$check_path" 2>/dev/null | awk 'NR==2 {print tolower($2)}')" || fs_type=""
    if [[ -z "$fs_type" || "$fs_type" == *"unknown"* || "$fs_type" == 0x* || "$fs_type" == *"0x"* ]]; then
        echo "ERROR: Staging directory ${check_path} is on tmpfs filesystem or filesystem type is unknown (${fs_type:-unknown})" >&2
        return 1
    fi

    local reject_tmpfs=0
    case "$target_path" in
        /var/tmp|/var/tmp/*|*/var/tmp|*/var/tmp/*) reject_tmpfs=1 ;;
    esac
    case "$check_path" in
        /var/tmp|/var/tmp/*|*/var/tmp|*/var/tmp/*) reject_tmpfs=1 ;;
    esac
    if [[ "${AF_REJECT_TMPFS_STAGING:-0}" == "1" ]]; then
        reject_tmpfs=1
    fi

    if (( reject_tmpfs == 1 )) && [[ "$fs_type" == "tmpfs" || "$fs_type" == "ramfs" ]]; then
        echo "ERROR: Staging directory ${check_path} is on tmpfs filesystem or filesystem type is unknown (${fs_type})" >&2
        return 1
    fi

    local avail_kb
    avail_kb="$(df -Pk "$check_path" 2>/dev/null | awk 'NR==2 {print $4}')" || avail_kb=""
    if [[ -z "$avail_kb" || ! "$avail_kb" =~ ^[0-9]+$ ]]; then
        echo "ERROR: Unable to determine free disk space for ${check_path}" >&2
        return 1
    fi
    if (( avail_kb < required_kb )); then
        echo "ERROR: Insufficient free disk space on ${check_path} (${avail_kb}KB available, ${required_kb}KB required)" >&2
        return 1
    fi

    local min_inodes="${AF_MIN_FREE_INODES:-1024}"
    local avail_inodes
    avail_inodes="$(df -Pi "$check_path" 2>/dev/null | awk 'NR==2 {print $4}')" || avail_inodes=""
    if [[ -z "$avail_inodes" || ! "$avail_inodes" =~ ^[0-9]+$ ]] || (( avail_inodes < min_inodes )); then
        echo "ERROR: Insufficient or unknown free inodes on ${check_path} (avail=${avail_inodes:-unknown}, required=${min_inodes})" >&2
        return 1
    fi

    return 0
}

restore_state_snapshot() {
    restore_app_state "$@"
}

begin_state_transaction() {
    local unit="$1" port="$2" readiness_path="$3" entry
    shift 3
    read -r -a AF_STATE_UNITS <<< "$unit"
    AF_STATE_UNIT="${AF_STATE_UNITS[-1]}"
    AF_STATE_PREVIOUS_UNITS=()
    AF_STATE_PORT="$port"
    AF_STATE_READINESS_PATH="$readiness_path"
    AF_STATE_WAS_ACTIVE=false
    AF_STATE_SNAPSHOT_READY=false
    AF_APT_REINSTALL_PACKAGES=()
    AF_APT_TRANSACTION_PACKAGES=()
    INSTALL_COMMITTED=false
    local staging_root="${AF_TRANSACTION_ROOT:-${TMPDIR:-/var/tmp}}"
    mkdir -p -m 0700 "$staging_root" 2>/dev/null || true
    if ! check_disk_space "$staging_root" 512; then
        if declare -F af_write_failure_receipt >/dev/null; then
            af_write_failure_receipt 28 "preflight_capacity" "Insufficient disk space in transaction staging directory ${staging_root}"
        fi
        print_error "Insufficient disk space in transaction staging directory ${staging_root}"
        return 1
    fi
    AF_STATE_BACKUP="$(mktemp -d "${staging_root}/af-state-XXXXXX")" || return 1
    trap 'cleanup_state_transaction $?' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    export AF_TX_DIR="$AF_STATE_BACKUP"
    mkdir -m 0700 -- "$AF_TX_DIR/pre_versions" || return 1
    for entry in "$@"; do
        if [[ -f "$entry/.af-version" && ! -L "$entry/.af-version" ]]; then
            validate_config_paths "$entry/.af-version" || return 1
            mkdir -p -m 0700 -- "$AF_TX_DIR/pre_versions$entry" || return 1
            install -m 0600 -- "$entry/.af-version" "$AF_TX_DIR/pre_versions$entry/.af-version" || return 1
        fi
    done
    for unit in "${AF_STATE_UNITS[@]}"; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            AF_STATE_WAS_ACTIVE=true
            AF_STATE_PREVIOUS_UNITS+=("$unit")
        fi
    done
    stop_systemd_unit "${AF_STATE_UNITS[@]}" || return 1
    snapshot_state_dirs "$AF_STATE_BACKUP" "$@" "$(lock_path "$PACKAGE_NAME")" || return 1
    AF_STATE_SNAPSHOT_READY=true
}

cleanup_state_transaction() {
    local status="$1" restore_failed=false unit
    trap - EXIT INT TERM
    set +e
    if [[ "${INSTALL_COMMITTED:-false}" != true ]]; then
        [[ "$status" -ne 0 ]] || status=1
        if [[ "$AF_STATE_SNAPSHOT_READY" == true ]]; then
            if ! quiesce_services_for_rollback "${AF_STATE_UNITS[@]}"; then
                restore_failed=true
            elif ! restore_state_snapshot "$AF_STATE_BACKUP"; then
                restore_failed=true
            elif [[ -d "$AF_TX_DIR/apt-packages" ]]; then
                rollback_apt_packages || restore_failed=true
                if [[ "$AF_APT_ROLLBACK_MUTATED" == true ]]; then
                    if ! quiesce_services_for_rollback "${AF_STATE_UNITS[@]}" || ! restore_state_snapshot "$AF_STATE_BACKUP"; then
                        restore_failed=true
                    fi
                fi
            fi
            systemctl daemon-reload >> "$LOGFILE" 2>&1 || restore_failed=true
        fi
        if [[ "$restore_failed" == false && "$AF_STATE_WAS_ACTIVE" == true && ( "$AF_STATE_SNAPSHOT_READY" != true || "${AF_STATE_RESTART_ON_ROLLBACK:-false}" == true ) ]]; then
            for unit in "${AF_STATE_PREVIOUS_UNITS[@]}"; do
                systemctl start "$unit" >> "$LOGFILE" 2>&1 || restore_failed=true
            done
        fi
    fi
    if [[ "${INSTALL_COMMITTED:-false}" != true && "$status" -ne 0 && "$AF_STATE_SNAPSHOT_READY" == true && "$restore_failed" == false && "${AF_STATE_RESTART_ON_ROLLBACK:-false}" != true ]]; then
        log_warn "Previous state restored; ${AF_STATE_UNITS[*]} left stopped after the failed package update"
    fi
    if [[ "$restore_failed" == true ]]; then
        status=1
        if declare -F af_write_failure_receipt >/dev/null 2>&1; then
            af_write_failure_receipt "$status" "rollback" "incomplete_rollback" "Rollback incomplete; recovery backup preserved at ${AF_STATE_BACKUP:-unknown} (incomplete-rollback)"
        else
            printf 'AF_DIAG_FAILURE={"stage":"rollback","exit_code":%d,"category":"incomplete_rollback","summary":"Rollback incomplete; recovery backup preserved at %s (incomplete-rollback)"}\n' "$status" "${AF_STATE_BACKUP:-unknown}" >&2
        fi
        print_warn "Rollback incomplete; recovery backup preserved at $AF_STATE_BACKUP"
    else
        rm -rf -- "$AF_STATE_BACKUP"
    fi
    if [[ "${2:-}" == return ]]; then return "$status"; fi
    exit "$status"
}

snapshot_app_state() {
    local backup="$1" entry index=0
    shift
    [[ -n "$backup" && -d "$backup" && ! -L "$backup" && "$#" -gt 0 ]] || return 1
    mkdir -- "$backup/state" || return 1
    chmod 700 "$backup/state" || return 1
    for entry in "$@"; do
        [[ "$entry" == /* && "$entry" != *$'\n'* ]] || return 1
        if [[ -L "$entry" ]]; then
            case "$entry" in
                /usr/bin/*|/usr/sbin/*) validate_config_paths "$(dirname "$entry")/.af-runtime-snapshot" || return 1 ;;
                *) return 1 ;;
            esac
        elif [[ -d "$entry" ]]; then
            validate_config_paths "$entry/.af-state-snapshot" || return 1
        else
            validate_config_paths "$entry" || return 1
        fi
        printf '%s\n' "$entry" >> "$backup/state/paths" || return 1
        if [[ -e "$entry" || -L "$entry" ]]; then
            cp -a -- "$entry" "$backup/state/$index" || return 1
        fi
        index=$((index + 1))
    done
    touch "$backup/state/complete"
}

restore_app_state() {
    local backup="$1" entry index=0 restore_failed=false
    [[ -n "$backup" && -f "$backup/state/complete" ]] || return 0
    while IFS= read -r entry; do
        if ! safe_restore_path_from_backup "$backup/state/$index" "$entry"; then
            print_warn "Cannot restore $entry; recovery backup preserved at $backup"
            restore_failed=true
        fi
        index=$((index + 1))
    done < "$backup/state/paths"
    [[ "$restore_failed" == false ]]
}

retain_successful_app_backups() {
    local package="$1" backup="$2" obsolete
    [[ "$package" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || return 1
    [[ "$backup" =~ ^/var/backups/aetherflow-${package}\.[a-zA-Z0-9]{6}$ ]] || return 1
    [[ -f "$backup/state/complete" && ! -L "$backup/state" && ! -L "$backup/state/complete" ]] || return 1
    validate_config_paths "$backup/.af-successful-backup" || return 1
    obsolete="$(safe_config_python "$package" "$backup" <<'PYEOF'
import re, stat, sys
package, current = sys.argv[1:]
prefix = 'aetherflow-' + package + '.'
marker = '.af-successful-backup'
content = 'aetherflow completed backup v1\n' + package + '\n'
parent, basename = config_directory(current, create=False)
try:
    current_descriptor = os.open(basename, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        metadata = os.fstat(current_descriptor)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
            raise ValueError('Completed backup directory must be private and owned by the installer')
    finally:
        os.close(current_descriptor)
    safe_write_text(current + '/' + marker, content, 0o600)
    completed = []
    for name in os.listdir(parent):
        if not re.fullmatch(re.escape(prefix) + r'[A-Za-z0-9]{6}', name):
            continue
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        except OSError:
            continue
        try:
            metadata = os.fstat(descriptor)
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                continue
            try:
                pending = os.stat('.af-archive-pending', dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                pending = None
            if pending is not None:
                continue
            try:
                marker_descriptor = os.open(marker, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=descriptor)
            except OSError:
                continue
            with os.fdopen(marker_descriptor) as stream:
                metadata = os.fstat(stream.fileno())
                if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                        or metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077
                        or stream.read(len(content) + 1) != content):
                    continue
                completed.append((metadata.st_mtime_ns, name))
        finally:
            os.close(descriptor)
    previous = sorted((entry for entry in completed if entry[1] != basename), reverse=True)
    for _, name in previous[1:]:
        print(os.path.dirname(current) + '/' + name)
finally:
    os.close(parent)
PYEOF
    )" || return 1
    while IFS= read -r obsolete; do
        [[ -z "$obsolete" ]] || safe_rm_rf "$obsolete" || return 1
    done <<< "$obsolete"
}

purge_app_backups() {
    local package="$1" backup alias
    [[ "$package" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || return 1
    local -a names=("$package")
    validate_config_paths /var/backups/.af-backup-purge || return 1
    case "$package" in
        paperless-ngx) names+=(paperless) ;;
        uptimekuma) names+=(uptime-kuma) ;;
    esac
    for alias in "${names[@]}"; do
        for backup in "/var/backups/aetherflow-${alias}" "/var/backups/aetherflow-${alias}."*; do
            [[ -e "$backup" || -L "$backup" ]] || continue
            safe_rm_rf "$backup" || return 1
        done
    done
}

verify_sha256() {
    local file="$1" expected="$2" label="${3:-Downloaded file}" actual
    if [[ ! "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || ! actual="$(sha256sum -- "$file")"; then
        print_error "$label SHA-256 verification failed"
        return 1
    fi
    actual="${actual%% *}"
    if [[ "$actual" != "${expected,,}" ]]; then
        print_error "$label SHA-256 digest mismatch"
        return 1
    fi
}

curl() {
    download_file --transport "$@"
}

verify_download_sha256() {
    local file_path="$1" app_id="${2:-${PACKAGE_NAME:-}}" source_url="${3:-}" app_key variable expected="" manifest basename_url entry digest candidate found=false
    [[ -s "$file_path" ]] || { print_error "Downloaded artifact is empty: $file_path"; return 1; }
    if LC_ALL=C head -c 512 "$file_path" | grep -aiEq '<!doctype[[:space:]]+html|<html([[:space:]>])'; then
        print_error "Downloaded artifact is an HTML page: $source_url"
        return 1
    fi
    if [[ -n "${4:-}" ]]; then
        verify_sha256 "$file_path" "$4" "$source_url" || return 1
        found=true
    fi
    case "$source_url" in
        https://repo.jellyfin.org/jellyfin_team.gpg.key) expected=a0cde241ae297fa6f0265c0bf15ce9eb9ee97c008904a59ab367a67d59532839 ;;
        https://downloads.plex.tv/plex-keys/PlexSign.key) expected=32c32ac571642be1b781b751311c84151cb70fc149585b6ba971403b096eaa53 ;;
        https://apt.grafana.com/gpg.key) expected=3d4029689bc7e4444ec00abafa07f21e9c812b41f1123ab5bbe6f8c3e3f7ff8c ;;
        https://advplyr.github.io/audiobookshelf-ppa/KEY.gpg) expected=813a3777489d1fd4fb26fe8696d5ffc3893ef2699c840bb79a2e18a967d98010 ;;
        https://syncthing.net/release-key.gpg) expected=c38853d2ccb890ae428e1fbf05d8c8fe0ba6f560bd050e161fb4e5324cdb4a9b ;;
        https://pkgs.tailscale.com/stable/debian/*.noarmor.gpg|https://pkgs.tailscale.com/stable/ubuntu/*.noarmor.gpg) expected=3e03dacf222698c60b8e2f990b809ca1b3e104de127767864284e6c228f1fb39 ;;
    esac
    if [[ -n "$expected" ]]; then
        verify_sha256 "$file_path" "${AF_TRUSTED_KEY_SHA256:-$expected}" "$source_url" || return 1
        found=true
    fi
    app_key="${app_id^^}"
    app_key="${app_key//[^A-Z0-9]/_}"
    for variable in AF_DOWNLOAD_SHA256 "AF_${app_key}_SHA256" "AETHERFLOW_${app_key}_SHA256"; do
        if [[ -v "$variable" ]]; then
            verify_sha256 "$file_path" "${!variable}" "$source_url" || return 1
            found=true
        fi
    done
    basename_url="${source_url%%\?*}"
    basename_url="${basename_url##*/}"
    for manifest in "${AF_DOWNLOAD_CHECKSUM_FILE:-}" "$file_path.sha256" "$file_path.sha256sum" "$(dirname "$file_path")/SHA256SUMS" "$(dirname "$file_path")/SHA256SUMS.txt" "$(dirname "$file_path")/sha256sums.txt" "$(dirname "$file_path")/SHASUMS256.txt" "$(dirname "$file_path")/checksums.txt"; do
        [[ -n "$manifest" ]] || continue
        if [[ ! -f "$manifest" ]]; then
            if [[ "$manifest" == "${AF_DOWNLOAD_CHECKSUM_FILE:-}" ]]; then
                print_error "Checksum manifest is unavailable: $manifest"
                return 1
            fi
            continue
        fi
        expected=""
        while read -r digest candidate || [[ -n "$digest" ]]; do
            [[ -n "$digest" ]] || continue
            candidate="${candidate#\*}"
            candidate="${candidate#./}"
            if [[ -z "$candidate" && ( "$manifest" == "$file_path.sha256" || "$manifest" == "$file_path.sha256sum" ) ]] || [[ "$candidate" == "$(basename "$file_path")" || ( -n "$basename_url" && "$candidate" == "$basename_url" ) ]]; then
                verify_sha256 "$file_path" "$digest" "$source_url" || return 1
                expected="$digest"
                found=true
            fi
        done < "$manifest"
        if [[ -z "$expected" && ( "$manifest" == "$file_path.sha256" || "$manifest" == "$file_path.sha256sum" || "$manifest" == "${AF_DOWNLOAD_CHECKSUM_FILE:-}" ) ]]; then
            print_error "No SHA-256 checksum for $source_url in $manifest"
            return 1
        fi
    done
    local release_metadata="${RELEASE_JSON:-}" release_repository release_tag
    if [[ -z "$release_metadata" && "$found" == false && "$source_url" == https://github.com/*/releases/download/* ]]; then
        release_repository="${source_url#https://github.com/}"
        release_repository="${release_repository%%/releases/download/*}"
        release_tag="${source_url#*/releases/download/}"
        release_tag="${release_tag%%/*}"
        release_metadata="$(curl -fsSL --connect-timeout 2 --max-time 4 "https://api.github.com/repos/$release_repository/releases/tags/$release_tag" 2>> "${LOGFILE:-/dev/null}")" || release_metadata=""
    fi
    if [[ -n "$release_metadata" && -n "$source_url" ]]; then
        local release_digest
        if ! release_digest="$(AF_RELEASE_JSON="$release_metadata" python3 - "$source_url" "$basename_url" <<'PYDIGEST'
import json, os, sys
release = json.loads(os.environ['AF_RELEASE_JSON'])
for asset in release.get('assets', []):
    if asset.get('browser_download_url') == sys.argv[1] or asset.get('name') == sys.argv[2]:
        digest = asset.get('digest')
        if digest:
            if not digest.startswith('sha256:'):
                raise ValueError('Unsupported release asset digest')
            print(digest.removeprefix('sha256:'))
PYDIGEST
        )"; then
            print_error "Invalid release checksum metadata for $source_url"
            return 1
        fi
        if [[ -n "$release_digest" ]]; then
            verify_sha256 "$file_path" "$release_digest" "$source_url" || return 1
            found=true
        fi
    fi
    if [[ "$found" == false && -n "$source_url" ]]; then
        local fetched checksum_directory checksum_url base_dir release_manifests stem
        base_dir="${source_url%%\?*}"
        base_dir="${base_dir%/*}"
        stem="${basename_url%.tar.gz}"
        stem="${stem%.tar.xz}"
        stem="${stem%.tgz}"
        stem="${stem%.zip}"
        local -a checksum_urls=("${source_url}.sha256" "${source_url}.sha256sum"
            "$base_dir/checksums.txt" "$base_dir/sha256sums.txt" "$base_dir/SHA256SUMS" "$base_dir/SHA256SUMS.txt"
            "$base_dir/${stem}_checksums.txt")
        if [[ -n "$release_metadata" ]]; then
            release_manifests="$(AF_RELEASE_JSON="$release_metadata" python3 - "$base_dir/" <<'PYMANIFESTS'
import json, os, sys
for asset in json.loads(os.environ['AF_RELEASE_JSON']).get('assets', []):
    name = str(asset.get('name', '')).lower()
    url = asset.get('browser_download_url', '')
    if ('checksum' in name or 'sha256' in name) and isinstance(url, str) and url.startswith(sys.argv[1]) and '\n' not in url:
        print(url)
PYMANIFESTS
            )" || return 1
            while IFS= read -r checksum_url; do
                [[ -z "$checksum_url" ]] || checksum_urls+=("$checksum_url")
            done <<< "$release_manifests"
        fi
        checksum_directory="$(mktemp -d)" || return 1
        fetched="$checksum_directory/checksums.txt"
        if [[ "$source_url" == https://nodejs.org/* ]]; then
            checksum_urls=("${source_url%/*}/SHASUMS256.txt" "${checksum_urls[@]}")
            fetched="$checksum_directory/node-shasums.txt"
        fi
        for checksum_url in "${checksum_urls[@]}"; do
            if curl -fsSL --connect-timeout 2 --max-time 4 "$checksum_url" -o "$fetched" 2>> "${LOGFILE:-/dev/null}"; then
                while read -r digest candidate || [[ -n "$digest" ]]; do
                    [[ "$digest" =~ ^[a-fA-F0-9]{64}$ ]] || continue
                    candidate="${candidate#\*}"
                    candidate="${candidate#./}"
                    if [[ ( -z "$candidate" && ( "$checksum_url" == "${source_url}.sha256" || "$checksum_url" == "${source_url}.sha256sum" ) ) || "$candidate" == "$basename_url" || "$candidate" == "$(basename "$file_path")" ]]; then
                        if ! verify_sha256 "$file_path" "$digest" "$source_url"; then
                            rm -rf -- "$checksum_directory"
                            return 1
                        fi
                        found=true
                    fi
                done < "$fetched"
            fi
            [[ "$found" == false ]] || break
        done
        rm -rf -- "$checksum_directory"
    fi
    if [[ "$found" == true ]]; then
        return 0
    fi
    print_error "Missing required SHA-256 digest for ${source_url:-$file_path}"
    return 1
}

download_file() {
    if [[ "${1:-}" == --transport ]]; then
        shift
        local argument previous="" stdin_config=false config_input
        for argument in "$@"; do
            if [[ ( "$argument" == - && ( "$previous" == -K || "$previous" == --config ) ) || "$argument" == -K- || "$argument" == --config=- ]]; then
                stdin_config=true
            fi
            previous="$argument"
        done
        if [[ "$stdin_config" == true ]]; then
            config_input="$(cat)" || return 1
            command curl "$@" <<< "$config_input" || return $?
        else
            command curl "$@" || return $?
        fi
        return 0
    fi
    local source_url="$1" file_path="$2" app_id="${3:-${PACKAGE_NAME:-}}"
    if declare -F curl >/dev/null; then
        curl -fsSL --retry 3 --connect-timeout 10 --max-time 300 "$source_url" -o "$file_path" || return $?
    else
        download_file --transport -fsSL --retry 3 --connect-timeout 10 --max-time 300 "$source_url" -o "$file_path" || return $?
    fi
    if ! verify_download_sha256 "$file_path" "$app_id" "$source_url" "${4:-}"; then
        print_error "Refusing unverified download from $source_url"
        return 1
    fi
}

install_apt_signing_key() (
    local source_url="$1" destination="$2" temporary
    validate_config_paths "$destination" || return 1
    temporary="$(mktemp -d)" || return 1
    trap 'rm -rf -- "$temporary"' EXIT
    download_file "$source_url" "$temporary/key" "${3:-${PACKAGE_NAME:-}}" || return 1
    gpg --batch --dearmor --yes -o "$temporary/key.gpg" "$temporary/key" || return 1
    install -m 0644 -- "$temporary/key.gpg" "$destination"
)

install_binary_atomic() {
    local source="$1" destination="$2" staged
    if [[ ! -s "$source" ]]; then
        print_error "Downloaded binary is empty: $source"
        return 1
    fi
    mkdir -p "$(dirname "$destination")"
    staged="$(mktemp "${destination}.af-new.XXXXXX")"
    if ! install -m 0755 "$source" "$staged" || ! mv -fT "$staged" "$destination"; then
        rm -f "$staged"
        return 1
    fi
}

safe_config_python() (
    local argument_index=0 argument
    export AF_CONFIG_ARGUMENT_COUNT="$#"
    for argument in "$@"; do
        export "AF_CONFIG_ARGUMENT_${argument_index}=$argument"
        argument_index=$((argument_index + 1))
    done
    {
        cat <<'PYHELPER'
import contextlib, os, pathlib, secrets, stat, sys
sys.argv = ['-'] + [os.environ.pop(f'AF_CONFIG_ARGUMENT_{index}') for index in range(int(os.environ.pop('AF_CONFIG_ARGUMENT_COUNT')))]

def config_directory(filename, create=True):
    path = pathlib.PurePath(filename)
    if not path.is_absolute() or '..' in path.parts or not path.name:
        raise ValueError('Invalid managed configuration path')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            try:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(component, 0o750, dir_fd=directory)
                except FileExistsError:
                    pass
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        return directory, path.name
    except BaseException:
        os.close(directory)
        raise

class ManagedConfig:
    def __init__(self, filename, create_parents=True):
        self.directory, self.name = config_directory(filename, create_parents)
        self.descriptor = None
        self.metadata = None
        try:
            try:
                self.descriptor = os.open(self.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=self.directory)
            except FileNotFoundError:
                pass
            else:
                self.metadata = os.fstat(self.descriptor)
                self.validate(self.metadata)
        except BaseException:
            self.close()
            raise

    @staticmethod
    def validate(metadata):
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError('Managed configuration must be a single-link regular file')

    def check_target(self):
        try:
            current = os.stat(self.name, dir_fd=self.directory, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if current is not None:
            self.validate(current)
        if (current is None) != (self.metadata is None):
            raise ValueError('Managed configuration target changed')
        if current is not None and (current.st_dev, current.st_ino) != (self.metadata.st_dev, self.metadata.st_ino):
            raise ValueError('Managed configuration target changed')

    def read_bytes(self):
        if self.descriptor is None:
            return b''
        self.validate(os.fstat(self.descriptor))
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(self.descriptor), 'rb') as source:
            return source.read()

    def read_text(self):
        return self.read_bytes().decode('utf-8')

    def write_text(self, text, mode=None):
        self.check_target()
        temporary = '.af-config.' + secrets.token_hex(12)
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.directory)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as output:
                if self.metadata:
                    os.fchown(output.fileno(), self.metadata.st_uid, self.metadata.st_gid)
                os.fchmod(output.fileno(), mode if mode is not None else (stat.S_IMODE(self.metadata.st_mode) if self.metadata else 0o640))
                output.write(text)
                output.flush()
                os.fsync(output.fileno())
                metadata = os.fstat(output.fileno())
            self.check_target()
            os.replace(temporary, self.name, src_dir_fd=self.directory, dst_dir_fd=self.directory)
            self.metadata = metadata
            os.fsync(self.directory)
            if self.descriptor is not None:
                os.close(self.descriptor)
                self.descriptor = None
            self.descriptor = os.open(self.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=self.directory)
            self.validate(os.fstat(self.descriptor))
            self.check_target()
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary, dir_fd=self.directory)

    def close(self):
        if self.descriptor is not None:
            os.close(self.descriptor)
        os.close(self.directory)

    def __enter__(self):
        return self

    def __exit__(self, *error):
        self.close()

def safe_read_text(filename):
    with ManagedConfig(filename) as config:
        return config.read_text()

def safe_write_text(filename, text, mode=None):
    with ManagedConfig(filename) as config:
        config.write_text(text, mode)

PYHELPER
        cat
    } | python3 -
)

read_navidrome_database_path() {
    validate_config_paths "$1" || return 1
    safe_config_python "$1" <<'PYEOF'
import posixpath, sys
try:
    import tomllib
except ModuleNotFoundError:
    import toml as tomllib
try:
    config = tomllib.loads(safe_read_text(sys.argv[1]))
except FileNotFoundError:
    config = {}
folders = [value for key, value in config.items() if key.lower() == 'datafolder']
if len(folders) > 1:
    raise ValueError('Ambiguous Navidrome DataFolder')
folder = folders[0] if folders else '/var/lib/navidrome'
if not isinstance(folder, str) or not folder.strip() or any(character in folder for character in '\r\n\0'):
    raise ValueError('Invalid Navidrome DataFolder')
if not posixpath.isabs(folder):
    folder = posixpath.join('/var/lib/navidrome', folder)
print(posixpath.join(posixpath.normpath(folder), 'navidrome.db'))
PYEOF
}

read_app_database_config() {
    validate_config_paths "$2" || return 1
    safe_config_python "$@" <<'PYEOF'
import configparser, re, sys
app, filename = sys.argv[1:]
raw = safe_read_text(filename)
if app == 'nextcloud':
    strings_or_comments = r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"|/\*.*?\*/|//[^\n]*|\#[^\n]*"
    raw = re.sub(strings_or_comments, lambda match: match.group(0) if match.group(1) is not None or match.group(2) is not None else ' ', raw, flags=re.S)
    structure = re.sub(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"", "''", raw)
    variables = re.findall(r'\$[A-Za-z_][A-Za-z0-9_]*', structure)
    if (variables and variables != ['$CONFIG'] or re.search(r'\b(?:require|require_once|include|include_once|eval)\b', structure)
            or re.search(r'\b(?!array\b)[A-Za-z_][A-Za-z0-9_]*\s*\(', structure, re.I)
            or variables and not re.search(r'\$CONFIG\s*=\s*(?:array\s*\(|\[)', structure)):
        raise ValueError('Dynamic Nextcloud database configuration cannot be backed up safely')
    tokens = re.findall(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|\$[A-Za-z_][A-Za-z0-9_]*|=>|[A-Za-z_][A-Za-z0-9_]*|[+-]?[0-9]+(?:\.[0-9]+)?|[^\s]", raw)
    def parse_literal(position):
        token = tokens[position]
        if token == '[' or token.lower() == 'array':
            closing = ']' if token == '[' else ')'
            if token != '[' and tokens[position + 1] != '(':
                raise ValueError('Invalid Nextcloud configuration array')
            position += 1 if token == '[' else 2
            result, next_index = {}, 0
            while tokens[position] != closing:
                entry, position = parse_literal(position)
                if tokens[position] == '=>':
                    key = entry
                    entry, position = parse_literal(position + 1)
                else:
                    key = next_index
                if not isinstance(key, (str, int)) or key in result:
                    raise ValueError('Ambiguous Nextcloud configuration key')
                result[key] = entry
                if isinstance(key, int):
                    next_index = max(next_index, key + 1)
                if tokens[position] == ',':
                    position += 1
                elif tokens[position] != closing:
                    raise ValueError('Nextcloud configuration must contain only literal values')
            return result, position + 1
        if token.startswith(("'", '"')):
            text = token[1:-1]
            if token.startswith("'"):
                return text.replace("\\'", "'").replace('\\\\', '\\'), position + 1
            decoded, offset = [], 0
            escapes = {'n': '\n', 'r': '\r', 't': '\t', 'v': '\v', 'e': '\x1b', 'f': '\f',
                       '$': '$', '"': '"', '\\': '\\'}
            while offset < len(text):
                character = text[offset]
                if character == '$':
                    raise ValueError('Unsupported interpolated Nextcloud setting')
                if character == '\\':
                    offset += 1
                    character = text[offset]
                    numeric = re.match(r'x([0-9A-Fa-f]{1,2})|([0-7]{1,3})|u\{([0-9A-Fa-f]+)\}', text[offset:])
                    if numeric:
                        codepoint = int(next(group for group in numeric.groups() if group is not None),
                                        8 if numeric.group(2) else 16)
                        character = chr(codepoint & 255 if numeric.group(2) else codepoint)
                        offset += len(numeric.group(0)) - 1
                    else:
                        character = escapes.get(character, '\\' + character)
                decoded.append(character)
                offset += 1
            return ''.join(decoded), position + 1
        if token.lower() in ('true', 'false', 'null'):
            return {'true': True, 'false': False, 'null': None}[token.lower()], position + 1
        if re.fullmatch(r'[+-]?[0-9]+(?:\.[0-9]+)?', token):
            return float(token) if '.' in token else int(token), position + 1
        raise ValueError('Nextcloud configuration must contain only literal values')
    config = {}
    if variables:
        position = tokens.index('$CONFIG')
        config, position = parse_literal(position + 2)
        if not isinstance(config, dict) or tokens[position:] not in ([], [';'], [';', '?', '>'], ['?', '>']):
            raise ValueError('Dynamic Nextcloud configuration cannot be backed up safely')
    def value(key, default=''):
        text = config.get(key, default)
        if not isinstance(text, str):
            raise ValueError('Database settings must be literal strings: ' + key)
        return text
    values = [value('dbtype', 'mysql'), value('dbname', 'nextcloud'), value('dbhost', 'localhost'),
              value('dbuser'), value('dbpassword'), value('datadirectory', '/var/www/nextcloud/data')]
else:
    config = configparser.ConfigParser(interpolation=None)
    config.read_string('[DEFAULT]\n' + raw)
    database = config['database'] if config.has_section('database') else {}
    def value(key, default=''):
        text = database.get(key, default).strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'", '`'):
            text = text[1:-1]
        return text
    values = [value('DB_TYPE', 'sqlite3'), value('NAME', 'gitea'), value('HOST'), value('USER'),
              value('PASSWD'), value('PATH', '/var/lib/gitea/data/gitea.db')]
values[0] = values[0].lower()
if values[0] not in ('mysql', 'mariadb', 'postgres', 'pgsql', 'sqlite', 'sqlite3'):
    raise ValueError('Unsupported retained database backend')
if not re.fullmatch(r'[A-Za-z0-9_]+', values[1]):
    raise ValueError('Unsafe retained database name')
if any(any(character in text for character in '\r\n\0') for text in values):
    raise ValueError('Invalid multiline database setting')
print('\n'.join(values))
PYEOF
}

nextcloud_database_ownership() (
    safe_config_python "$@" <<'PYEOF'
import hashlib, json, re, sys
operation, filename, backend, database, host, username, password, data_directory = sys.argv[1:]
if operation not in ('create', 'verify'):
    raise ValueError('Unsupported Nextcloud database ownership operation')
if backend != 'mysql' or host != 'localhost':
    raise ValueError('Automatic purge requires an installer-provisioned local MySQL database')
if not re.fullmatch(r'[A-Za-z0-9_]+', database) or not re.fullmatch(r'[A-Za-z0-9_]+', username):
    raise ValueError('Unsafe Nextcloud database identity')
expected = {
    'format': 1, 'application': 'nextcloud', 'backend': backend,
    'database': database, 'host': host, 'username': username,
    'password_sha256': hashlib.sha256(password.encode('utf-8')).hexdigest(),
    'data_directory': data_directory,
}
with ManagedConfig(filename, create_parents=False) as config:
    directory = os.fstat(config.directory)
    if directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) & 0o022:
        raise ValueError('Nextcloud database ownership directory is not trusted')
    if operation == 'create':
        if config.metadata is not None:
            raise ValueError('Refusing to replace existing Nextcloud database ownership')
        config.write_text(json.dumps(expected, sort_keys=True) + '\n', 0o600)
    else:
        if config.metadata is None:
            raise ValueError('Nextcloud database ownership is unproven; configuration retained for operator cleanup')
        if config.metadata.st_uid != os.geteuid() or stat.S_IMODE(config.metadata.st_mode) & 0o077:
            raise ValueError('Nextcloud database ownership file is not trusted')
        if json.loads(config.read_text()) != expected:
            raise ValueError('Configured Nextcloud database does not match installer ownership; purge refused')
PYEOF
)

configured_database_connection() {
    local backend="$1" host="$2" username="$3" port=""
    AF_DATABASE_ARGS=()
    if [[ "$host" =~ ^\[([a-fA-F0-9:]+)\](:([0-9]+))?$ ]]; then
        host="${BASH_REMATCH[1]}" port="${BASH_REMATCH[3]}"
    elif [[ "$host" =~ ^([A-Za-z0-9_.-]+):([0-9]+)$ ]]; then
        host="${BASH_REMATCH[1]}" port="${BASH_REMATCH[2]}"
    elif [[ -n "$host" && ! "$host" =~ ^[A-Za-z0-9_./:-]+$ ]]; then
        print_error "Unsupported retained database host"
        return 1
    fi
    [[ -z "$host" ]] || AF_DATABASE_ARGS+=("--host=$host")
    if [[ -n "$port" ]]; then
        (( 10#$port > 0 && 10#$port <= 65535 )) || return 1
        AF_DATABASE_ARGS+=("--port=$port")
    fi
    if [[ -n "$username" ]]; then
        if [[ "$backend" == mysql || "$backend" == mariadb ]]; then
            AF_DATABASE_ARGS+=("--user=$username")
        else
            AF_DATABASE_ARGS+=("--username=$username")
        fi
    fi
}

configured_postgresql_cleanup() {
    cat <<'SQL'
SET LOCAL lock_timeout = '5s';
SET LOCAL search_path = pg_catalog;
DO $af_cleanup$
DECLARE
    entry record;
    recipient text;
    object_kind text;
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_database WHERE datname = current_database()
                   AND datdba = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery requires the database owner';
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_event_trigger)
       OR EXISTS (SELECT FROM pg_catalog.pg_subscription)
       OR EXISTS (SELECT FROM pg_catalog.pg_publication)
       OR EXISTS (SELECT FROM pg_catalog.pg_foreign_data_wrapper)
       OR EXISTS (SELECT FROM pg_catalog.pg_foreign_server)
       OR EXISTS (SELECT FROM pg_catalog.pg_language WHERE lanname NOT IN ('internal', 'c', 'sql', 'plpgsql'))
       OR EXISTS (SELECT FROM pg_catalog.pg_shseclabel WHERE classoid = 'pg_catalog.pg_database'::regclass
                  AND objoid = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database())) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery cannot safely reconstruct database-wide replication, event triggers, foreign servers, languages or security labels';
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql'
               AND (extowner <> (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
                    OR extconfig IS NOT NULL)) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery requires application-owned extensions without configuration tables';
    END IF;
    IF EXISTS (SELECT FROM pg_catalog.pg_class WHERE oid >= 16384 AND relnamespace IN
               (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('pg_catalog', 'information_schema')))
       OR EXISTS (SELECT FROM pg_catalog.pg_proc WHERE oid >= 16384 AND pronamespace IN
                  (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('pg_catalog', 'information_schema')))
       OR EXISTS (SELECT FROM pg_catalog.pg_type WHERE oid >= 16384 AND typnamespace IN
                  (SELECT oid FROM pg_catalog.pg_namespace WHERE nspname IN ('pg_catalog', 'information_schema'))) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery cannot reconstruct application objects in system schemas';
    END IF;
    FOR entry IN SELECT extname FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql' LOOP
        EXECUTE format('DROP EXTENSION %I CASCADE', entry.extname);
    END LOOP;
    FOR entry IN SELECT castsource::regtype AS source_type, casttarget::regtype AS target_type
                 FROM pg_catalog.pg_cast WHERE oid >= 16384 LOOP
        EXECUTE format('DROP CAST (%s AS %s) CASCADE', entry.source_type, entry.target_type);
    END LOOP;
    FOR entry IN SELECT nspname FROM pg_catalog.pg_namespace
                 WHERE nspname <> 'information_schema' AND nspname !~ '^pg_' LOOP
        EXECUTE format('DROP SCHEMA %I CASCADE', entry.nspname);
    END LOOP;
    PERFORM pg_catalog.lo_unlink(oid) FROM pg_catalog.pg_largeobject_metadata;
    FOR entry IN SELECT DISTINCT defaults.defaclrole, defaults.defaclobjtype, permissions.grantee
                 FROM pg_catalog.pg_default_acl AS defaults
                 CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS permissions
                 WHERE defaults.defaclnamespace = 0 LOOP
        object_kind := CASE entry.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES'
                       WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' WHEN 'n' THEN 'SCHEMAS' END;
        IF object_kind IS NULL THEN
            RAISE EXCEPTION 'Unsupported PostgreSQL default privilege object kind';
        END IF;
        recipient := CASE WHEN entry.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_catalog.pg_get_userbyid(entry.grantee)) END;
        EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I REVOKE ALL ON %s FROM %s CASCADE',
                       pg_catalog.pg_get_userbyid(entry.defaclrole), object_kind, recipient);
    END LOOP;
    FOR entry IN SELECT DISTINCT defaclrole, defaclobjtype FROM pg_catalog.pg_default_acl
                 WHERE defaclnamespace = 0 LOOP
        object_kind := CASE entry.defaclobjtype WHEN 'r' THEN 'TABLES' WHEN 'S' THEN 'SEQUENCES'
                       WHEN 'f' THEN 'FUNCTIONS' WHEN 'T' THEN 'TYPES' WHEN 'n' THEN 'SCHEMAS' END;
        EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I GRANT ALL ON %s TO %I',
                       pg_catalog.pg_get_userbyid(entry.defaclrole), object_kind, pg_catalog.pg_get_userbyid(entry.defaclrole));
        IF entry.defaclobjtype IN ('f', 'T') THEN
            EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I GRANT %s ON %s TO PUBLIC',
                           pg_catalog.pg_get_userbyid(entry.defaclrole),
                           CASE entry.defaclobjtype WHEN 'f' THEN 'EXECUTE' ELSE 'USAGE' END, object_kind);
        END IF;
    END LOOP;
END
$af_cleanup$;
SQL
}

backup_configured_database() (
    local backup="$1" backend="$2" database="$3" host="$4" username="$5" password="$6" sqlite_path="$7"
    umask 077
    [[ "$database" =~ ^[A-Za-z0-9_]+$ && "$backup" == /* && "$backup" != / && ! -L "$backup" ]] || return 1
    validate_config_paths "$backup/.af-database-ready" || return 1
    mkdir -m 0700 -- "$backup" || return 1
    case "$backend" in
        mysql|mariadb)
            configured_database_connection "$backend" "$host" "$username" || return 1
            MYSQL_PWD="$password" mysqldump "${AF_DATABASE_ARGS[@]}" --single-transaction --add-drop-database --databases "$database" > "$backup/database.sql" || return 1
            [[ -s "$backup/database.sql" ]] || return 1
            ;;
        postgres|pgsql)
            configured_database_connection "$backend" "$host" "$username" || return 1
            PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 pg_dump "${AF_DATABASE_ARGS[@]}" --no-password --clean --if-exists "$database" > "$backup/database.sql" 2> "$backup/postgres-recovery.log" || return 1
            [[ -s "$backup/database.sql" ]] || return 1
            PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 psql "${AF_DATABASE_ARGS[@]}" --no-psqlrc --no-password --quiet --tuples-only --no-align "--dbname=$database" --set=ON_ERROR_STOP=1 --file=- > "$backup/postgres-identity.sql" 2>> "$backup/postgres-recovery.log" <<'SQL' || return 1
SET search_path = pg_catalog;
SELECT 'SET LOCAL search_path = pg_catalog;';
SELECT format('DO %L;', format('BEGIN IF current_database() <> %L OR current_user <> %L OR (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()) <> %s THEN RAISE EXCEPTION ''Configured PostgreSQL database identity changed''; END IF; END', current_database(), current_user, oid))
FROM pg_catalog.pg_database WHERE datname = current_database();
SELECT format('DO %L;', format('BEGIN IF (SELECT default_version FROM pg_catalog.pg_available_extensions WHERE name = %L) IS DISTINCT FROM %L THEN RAISE EXCEPTION ''Configured PostgreSQL extension version cannot be reconstructed''; END IF; END', extname, extversion))
FROM pg_catalog.pg_extension WHERE extname <> 'plpgsql';
SQL
            PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 psql "${AF_DATABASE_ARGS[@]}" --no-psqlrc --no-password --quiet --tuples-only --no-align "--dbname=$database" --set=ON_ERROR_STOP=1 --file=- > "$backup/postgres-schemas.sql" 2>> "$backup/postgres-recovery.log" <<'SQL' || return 1
SET search_path = pg_catalog;
DO $af_schema$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_namespace AS namespace
               CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS permissions
               WHERE namespace.nspname = 'public' AND permissions.grantor <> namespace.nspowner) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery requires public schema grants issued by the owner';
    END IF;
END
$af_schema$;
SELECT 'SELECT 1;';
SELECT format('CREATE SCHEMA public AUTHORIZATION %I; REVOKE ALL ON SCHEMA public FROM %I; COMMENT ON SCHEMA public IS %L;',
              pg_catalog.pg_get_userbyid(nspowner), pg_catalog.pg_get_userbyid(nspowner), pg_catalog.obj_description(oid, 'pg_namespace'))
FROM pg_catalog.pg_namespace WHERE nspname = 'public';
SELECT format('GRANT %s ON SCHEMA public TO %s%s;', permissions.privilege_type,
              CASE WHEN permissions.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_catalog.pg_get_userbyid(permissions.grantee)) END,
              CASE WHEN permissions.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END)
FROM pg_catalog.pg_namespace AS namespace
CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(namespace.nspacl, pg_catalog.acldefault('n', namespace.nspowner))) AS permissions
WHERE namespace.nspname = 'public';
SQL
            PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 psql "${AF_DATABASE_ARGS[@]}" --no-psqlrc --no-password --quiet --tuples-only --no-align "--dbname=$database" --set=ON_ERROR_STOP=1 --file=- > "$backup/postgres-metadata.sql" 2>> "$backup/postgres-recovery.log" <<'SQL' || return 1
SET search_path = pg_catalog;
DO $af_metadata$
BEGIN
    IF EXISTS (SELECT FROM pg_catalog.pg_database AS database
               CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS permissions
               WHERE database.datname = current_database() AND permissions.grantor <> database.datdba) THEN
        RAISE EXCEPTION 'Configured PostgreSQL recovery requires database grants issued by the owner';
    END IF;
END
$af_metadata$;
SELECT $af_database_sql$
DO $af_database$
DECLARE
    entry record;
BEGIN
    FOR entry IN SELECT DISTINCT permissions.grantee FROM pg_catalog.pg_database AS database
                 CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba))) AS permissions
                 WHERE database.datname = current_database() LOOP
        EXECUTE format('REVOKE ALL ON DATABASE %I FROM %s CASCADE', current_database(),
                       CASE WHEN entry.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_catalog.pg_get_userbyid(entry.grantee)) END);
    END LOOP;
    FOR entry IN SELECT setrole FROM pg_catalog.pg_db_role_setting
                 WHERE setdatabase = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database()) LOOP
        IF entry.setrole <> 0 THEN
            EXECUTE format('ALTER ROLE %I IN DATABASE %I RESET ALL', pg_catalog.pg_get_userbyid(entry.setrole), current_database());
        END IF;
    END LOOP;
END
$af_database$;
$af_database_sql$;
SELECT format('ALTER DATABASE %I RESET ALL;', current_database());
SELECT format('ALTER DATABASE %I CONNECTION LIMIT %s;', datname, datconnlimit)
FROM pg_catalog.pg_database WHERE datname = current_database();
SELECT format('COMMENT ON DATABASE %I IS %L;', datname, pg_catalog.shobj_description(oid, 'pg_database'))
FROM pg_catalog.pg_database WHERE datname = current_database();
SELECT format('GRANT %s ON DATABASE %I TO %s%s;', permissions.privilege_type, database.datname,
              CASE WHEN permissions.grantee = 0 THEN 'PUBLIC' ELSE quote_ident(pg_catalog.pg_get_userbyid(permissions.grantee)) END,
              CASE WHEN permissions.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END)
FROM pg_catalog.pg_database AS database
CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba))) AS permissions
WHERE database.datname = current_database();
SELECT format('SELECT pg_catalog.set_config(%L, %L, true); %s SET %I FROM CURRENT;',
              split_part(setting, '=', 1), substr(setting, strpos(setting, '=') + 1),
              CASE WHEN settings.setrole = 0 THEN format('ALTER DATABASE %I', current_database())
                   ELSE format('ALTER ROLE %I IN DATABASE %I', pg_catalog.pg_get_userbyid(settings.setrole), current_database()) END,
              split_part(setting, '=', 1))
FROM pg_catalog.pg_db_role_setting AS settings CROSS JOIN LATERAL unnest(settings.setconfig) AS setting
WHERE settings.setdatabase = (SELECT oid FROM pg_catalog.pg_database WHERE datname = current_database());
SQL
            configured_postgresql_cleanup > "$backup/postgres-clean.sql" || return 1
            if ! PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 psql "${AF_DATABASE_ARGS[@]}" --no-psqlrc --no-password "--dbname=$database" --set=ON_ERROR_STOP=1 --single-transaction --file="$backup/postgres-identity.sql" --file="$backup/postgres-clean.sql" --file="$backup/postgres-schemas.sql" --file="$backup/database.sql" --file="$backup/postgres-metadata.sql" --command=ROLLBACK >> "$backup/postgres-recovery.log" 2>&1; then
                print_error "Configured PostgreSQL recovery preflight failed; refusing to migrate"
                return 1
            fi
            printf '%s\n' in-database-v1 > "$backup/.af-postgres-ready" || return 1
            ;;
        sqlite|sqlite3)
            [[ "$sqlite_path" == /* && ( ! -e "$sqlite_path" || -f "$sqlite_path" ) ]] || return 1
            validate_config_paths "$sqlite_path" "${sqlite_path}-wal" "${sqlite_path}-shm" || return 1
            snapshot_app_state "$backup" "$sqlite_path" "${sqlite_path}-wal" "${sqlite_path}-shm" || return 1
            ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$database" > "$backup/.af-database-ready"
)

restore_configured_database() (
    local backup="$1" backend="$2" database="$3" host="$4" username="$5" password="$6" sqlite_path="$7" artifact
    umask 077
    [[ "$backup" == /* && "$backup" != / && ! -L "$backup" ]] || return 1
    validate_config_paths "$backup/.af-database-ready" || return 1
    [[ -f "$backup/.af-database-ready" ]] || return 0
    [[ "$database" =~ ^[A-Za-z0-9_]+$ && "$(cat "$backup/.af-database-ready")" == "$database" ]] || return 1
    case "$backend" in
        mysql|mariadb)
            configured_database_connection "$backend" "$host" "$username" || return 1
            MYSQL_PWD="$password" mysql "${AF_DATABASE_ARGS[@]}" "$database" < "$backup/database.sql" >> "$LOGFILE" 2>&1
            ;;
        postgres|pgsql)
            configured_database_connection "$backend" "$host" "$username" || return 1
            for artifact in .af-postgres-ready postgres-identity.sql postgres-clean.sql postgres-schemas.sql database.sql postgres-metadata.sql postgres-recovery.log; do
                validate_config_paths "$backup/$artifact" || return 1
                [[ -f "$backup/$artifact" && ( "$artifact" == postgres-recovery.log || -s "$backup/$artifact" ) ]] || return 1
            done
            [[ "$(cat "$backup/.af-postgres-ready")" == in-database-v1 ]] || return 1
            printf '%s\n' 'Restoring configured PostgreSQL database in one transaction' >> "${LOGFILE:-/dev/null}" || return 1
            if ! PGPASSWORD="$password" PGCONNECT_TIMEOUT=5 psql "${AF_DATABASE_ARGS[@]}" --no-psqlrc --no-password "--dbname=$database" --set=ON_ERROR_STOP=1 --single-transaction --file="$backup/postgres-identity.sql" --file="$backup/postgres-clean.sql" --file="$backup/postgres-schemas.sql" --file="$backup/database.sql" --file="$backup/postgres-metadata.sql" >> "$backup/postgres-recovery.log" 2>&1; then
                print_error "Configured PostgreSQL recovery failed; retained database transaction was not committed"
                return 1
            fi
            ;;
        sqlite|sqlite3) restore_app_state "$backup" ;;
        *) return 1 ;;
    esac
)

backup_postgresql_database() {
    local backup="$1" database="$2" database_file relative
    [[ "$database" =~ ^[a-z_][a-z0-9_-]*$ && "$backup" == /* && "$backup" != / && ! -L "$backup" ]] || return 1
    mkdir -p -m 0700 -- "$backup" || return 1
    runuser -u postgres -- pg_dump --clean --if-exists --create "$database" > "$backup/$database.sql" || return 1
    if [[ -n "${AETHERFLOW_INSTALL_ROOT:-}" && /var/lib/postgresql == "${AETHERFLOW_INSTALL_ROOT%/}/"* && -d /var/lib/postgresql ]]; then
        [[ ! -L /var/lib/postgresql ]] || return 1
        while IFS= read -r -d '' database_file; do
            relative="${database_file#/var/lib/postgresql/}"
            mkdir -p -- "$backup/postgresql-database/$(dirname "$relative")" || return 1
            cp -a -- "$database_file" "$backup/postgresql-database/$relative" || return 1
        done < <(find /var/lib/postgresql -type f \( -name "*${database}*" -o -name "fixture-${database#af_}-schema" \) -print0)
    fi
    printf '%s\n' "$database" > "$backup/.af-database-ready"
}

restore_postgresql_database() {
    local backup="$1" database="$2" restored=true database_file relative
    [[ -f "$backup/.af-database-ready" ]] || return 0
    [[ "$database" =~ ^[a-z_][a-z0-9_-]*$ && ! -L "$backup" && ! -L "$backup/.af-database-ready" && ! -L "$backup/$database.sql" && "$(cat "$backup/.af-database-ready")" == "$database" ]] || return 1
    runuser -u postgres -- psql -d postgres -v ON_ERROR_STOP=1 --set="database=$database" >> "$LOGFILE" 2>&1 <<'SQL' || restored=false
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :'database' AND pid <> pg_backend_pid();
SQL
    runuser -u postgres -- psql -d postgres -v ON_ERROR_STOP=1 -f - < "$backup/$database.sql" >> "$LOGFILE" 2>&1 || restored=false
    if [[ -n "${AETHERFLOW_INSTALL_ROOT:-}" && /var/lib/postgresql == "${AETHERFLOW_INSTALL_ROOT%/}/"* && -d "$backup/postgresql-database" ]]; then
        [[ ! -L "$backup/postgresql-database" && ! -L /var/lib/postgresql ]] || return 1
        while IFS= read -r -d '' database_file; do
            relative="${database_file#"$backup/postgresql-database/"}"
            safe_restore_path_from_backup "$database_file" "/var/lib/postgresql/$relative" || return 1
        done < <(find "$backup/postgresql-database" -type f \( -name "*${database}*" -o -name "fixture-${database#af_}-schema" \) -print0)
    fi
    if [[ "$restored" != true ]]; then
        print_error "Database recovery failed; backups retained in $backup"
        return 1
    fi
}

validate_config_paths() {
    safe_config_python "$@" <<'PYEOF'
import sys
for filename in sys.argv[1:]:
    try:
        with ManagedConfig(filename, create_parents=False):
            pass
    except FileNotFoundError:
        pass
PYEOF
}

write_config_file() {
    local content
    content="$(cat; printf '\001')"
    safe_config_python "$1" "${2:-0640}" "${content%$'\001'}" <<'PYEOF'
import sys
safe_write_text(sys.argv[1], sys.argv[3], int(sys.argv[2], 8))
PYEOF
}

set_config_file_mode() {
    safe_config_python "$@" <<'PYEOF'
import sys
mode = int(sys.argv[1], 8)
for filename in sys.argv[2:]:
    with ManagedConfig(filename, create_parents=False) as config:
        if config.descriptor is None:
            raise FileNotFoundError(filename)
        config.check_target()
        os.fchmod(config.descriptor, mode)
        config.check_target()
PYEOF
}

# Change one listen setting without rebuilding the user's application config.
# Supported formats use only Python's standard library on the Debian host.
set_config_value() {
    AF_CFG_FILE="$1" AF_CFG_FORMAT="$2" AF_CFG_KEY="$3" AF_CFG_VALUE="$4" AF_CFG_SECTION="${5:-}" python3 - <<'PYEOF'
import json, os, pathlib, re, secrets, stat, sys, xml.etree.ElementTree as ET
filename, kind, key, value, section = (os.environ.pop('AF_CFG_' + name) for name in ('FILE', 'FORMAT', 'KEY', 'VALUE', 'SECTION'))
path = pathlib.Path(filename)
if not path.is_absolute() or '..' in path.parts:
    raise ValueError('Invalid managed configuration path')
directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
for component in path.parts[1:-1]:
    try:
        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    except FileNotFoundError:
        os.mkdir(component, 0o750, dir_fd=directory)
        child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    os.close(directory)
    directory = child
metadata = None
try:
    descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
except FileNotFoundError:
    text = ''
else:
    with os.fdopen(descriptor) as existing:
        metadata = os.fstat(existing.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError('Managed configuration is not a regular file')
        if metadata.st_nlink != 1:
            raise ValueError('Refusing hardlinked managed configuration')
        if any(marker in key.lower() for marker in ('pass', 'secret', 'token', 'key', 'auth')) or path.name in ('nzbget.conf', 'sabnzbd.ini', 'config.ini'):
            os.fchmod(existing.fileno(), 0o600)
        text = existing.read()
if kind == 'xml':
    root = ET.fromstring(text) if text.strip() else ET.Element(section or 'Config')
    node = root.find(key)
    if node is None:
        node = ET.SubElement(root, key)
    node.text = value
    text = ET.tostring(root, encoding='unicode') + '\n'
elif kind == 'json':
    data = json.loads(text) if text.strip() else {}
    parent = data
    parts = key.split('.')
    for part in parts[:-1]:
        parent = parent.setdefault(part, {})
    parent[parts[-1]] = int(value) if value.isdecimal() else value
    text = json.dumps(data, indent=2) + '\n'
elif kind == 'js':
    pattern = re.compile(r'(\b' + re.escape(key) + r'\s*:\s*)\d+')
    if not pattern.search(text):
        raise ValueError('Cannot locate existing JavaScript port setting')
    text = pattern.sub(lambda m: m.group(1) + value, text, count=1)
else:
    if kind == 'yaml':
        header = re.compile(r'(?m)^' + re.escape(section) + r':\s*(?:#.*)?$') if section else None
        pattern = re.compile(r'(?m)^' + ('  ' if section else '') + re.escape(key) + r'\s*:.*$')
        setting = ('  ' if section else '') + key + ': ' + value + '\n'
        next_section = re.compile(r'(?m)^\S[^\n]*:')
    elif kind == 'env':
        header = None
        pattern = re.compile(r'(?m)^' + re.escape(key) + r'=.*$')
        setting = key + '=' + value + '\n'
        next_section = re.compile(r'(?!)')
    elif kind == 'ini':
        header = re.compile(r'(?m)^\[' + re.escape(section) + r'\]\s*$') if section else None
        pattern = re.compile(r'(?im)^\s*' + re.escape(key) + r'\s*=.*$')
        setting = key + ' = ' + value + '\n'
        next_section = re.compile(r'(?m)^\[')
    else:
        raise ValueError('Unsupported config format: ' + kind)
    start, end = 0, len(text)
    if header:
        match = header.search(text)
        if match is None:
            text += ('\n' if text and not text.endswith('\n') else '') + (section + ':\n' if kind == 'yaml' else '[' + section + ']\n')
            start = end = len(text)
        else:
            start = match.end() + 1
            following = next_section.search(text, start)
            end = following.start() if following else len(text)
    block = text[start:end]
    if pattern.search(block):
        block = pattern.sub(lambda _: setting.rstrip('\n'), block)
    else:
        block = block.rstrip('\n') + ('\n' if block else '') + setting
    text = text[:start] + block + text[end:]
temporary = '.af-config.' + secrets.token_hex(12)
try:
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(descriptor, 'w') as output:
        mode = stat.S_IMODE(metadata.st_mode) & 0o660 if metadata else 0o600
        if any(marker in key.lower() for marker in ('pass', 'secret', 'token', 'key', 'auth')) or path.name in ('nzbget.conf', 'sabnzbd.ini', 'config.ini'):
            mode = 0o600
        if metadata:
            os.fchown(output.fileno(), metadata.st_uid, metadata.st_gid)
        os.fchmod(output.fileno(), mode)
        output.write(text)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
finally:
    try:
        os.unlink(temporary, dir_fd=directory)
    except FileNotFoundError:
        pass
    os.close(directory)
PYEOF
}

# Activate prepared application code while retaining persistent paths and a
# private copy of the previous installation for recovery after migrations.
replace_app_tree() {
    local staged="$1" destination="$2" relative backup
    shift 2
    for relative in "$@"; do
        if [[ "$relative" == /* || "$relative" == *..* ]]; then
            print_error "Invalid application data path: $relative"
            return 1
        fi
        if [[ -e "$destination/$relative" || -L "$destination/$relative" ]]; then
            mkdir -p "$(dirname "$staged/$relative")"
            rm -rf -- "$staged/$relative"
            cp -a -- "$destination/$relative" "$staged/$relative"
        fi
    done
    if [[ -f "$destination/.af-version" && ! -L "$destination/.af-version" ]]; then
        validate_config_paths "$destination/.af-version" || return 1
        cp -p --remove-destination -- "$destination/.af-version" "$staged/.af-version" || return 1
    fi
    if [[ -e "$destination" ]]; then
        backup="$(mktemp -d "${destination}.af-backup.XXXXXX")"
        chmod 700 "$backup"
        mv -T "$destination" "$backup/app"
        if ! mv -T "$staged" "$destination"; then
            mv -T "$backup/app" "$destination"
            return 1
        fi
        log_info "Previous application files retained in $backup/app"
    else
        mv -T "$staged" "$destination"
    fi
}

stage_app_archive() {
    local archive="$1" destination="$2" executable="$3" state="$4" unit="$5"
    local archive_root="${6:-${executable%%|*}}" candidate found=false relative entry state_index extracted backup
    local -a candidates=()
    IFS='|' read -r -a candidates <<< "$executable"
    [[ ! -L "$destination" && ! -L "$state" ]] || return 1
    for backup in "${destination}".af-backup.??????; do
        [[ -d "$backup" && ! -L "$backup" && -f "$backup/.af-archive-owner" && ! -L "$backup/.af-archive-owner" ]] || continue
        if [[ "$(cat "$backup/.af-archive-owner")" == "$unit" && -e "$backup/.af-archive-pending" ]]; then
            print_error "An interrupted application update needs recovery before retrying: $backup"
            return 1
        fi
    done
    AF_ARCHIVE_DESTINATION="$destination"
    AF_ARCHIVE_STATE_PATHS=()
    AF_ARCHIVE_ROLLBACK_RESTART_UNITS=()
    for entry in "$state" "${7:-}"; do
        [[ -n "$entry" ]] || continue
        [[ ! -L "$entry" ]] || return 1
        AF_ARCHIVE_STATE_PATHS+=("$entry")
        if [[ "$entry" == *.db ]]; then
            AF_ARCHIVE_STATE_PATHS+=("${entry}-wal" "${entry}-shm")
        fi
    done
    AF_ARCHIVE_UNIT="$unit"
    AF_ARCHIVE_ARCHIVE="$archive"
    AF_ARCHIVE_ACTIVATED=false
    AF_ARCHIVE_ORIGINAL_PRESENT=false
    [[ ! -e "$destination" ]] || AF_ARCHIVE_ORIGINAL_PRESENT=true
    AF_ARCHIVE_STOPPED=false
    AF_ARCHIVE_PREVIOUS=false
    [[ "${9:-}" != binary || ! -f "$destination" ]] || AF_ARCHIVE_PREVIOUS=true
    for candidate in "${candidates[@]}"; do
        [[ ! -e "$destination/$candidate" ]] || AF_ARCHIVE_PREVIOUS=true
    done
    AF_ARCHIVE_BACKUP="$(mktemp -d "${destination}.af-backup.XXXXXX")"
    chmod 700 "$AF_ARCHIVE_BACKUP"
    printf '%s\n' "$unit" > "$AF_ARCHIVE_BACKUP/.af-archive-owner"
    trap 'rollback_app_archive_update $?' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    export AF_TX_DIR="$AF_ARCHIVE_BACKUP"
    mkdir -m 0700 -- "$AF_TX_DIR/pre_versions" || return 1
    for entry in "$destination" "${AF_ARCHIVE_STATE_PATHS[@]}"; do
        if [[ -f "$entry/.af-version" && ! -L "$entry/.af-version" ]]; then
            validate_config_paths "$entry/.af-version" || return 1
            mkdir -p -m 0700 -- "$AF_TX_DIR/pre_versions$entry" || return 1
            install -m 0600 -- "$entry/.af-version" "$AF_TX_DIR/pre_versions$entry/.af-version" || return 1
        fi
    done
    mkdir "$AF_ARCHIVE_BACKUP/release"
    python3 - "$AF_ARCHIVE_BACKUP/recovery.json" "$destination" "$unit" "${AF_ARCHIVE_STATE_PATHS[@]}" <<'PYEOF'
import json, os, sys
with open(sys.argv[1], 'x') as output:
    json.dump({'destination': sys.argv[2], 'unit': sys.argv[3], 'state_paths': sys.argv[4:]}, output)
    output.flush()
    os.fsync(output.fileno())
PYEOF
    extracted="$AF_ARCHIVE_BACKUP/release"
    [[ "$archive_root" == . ]] || extracted="${extracted}/${archive_root}"
    if [[ -d "$archive" && ! -L "$archive" ]]; then
        mv -T -- "$archive" "$AF_ARCHIVE_BACKUP/release/prepared"
        extracted="$AF_ARCHIVE_BACKUP/release/prepared"
        AF_ARCHIVE_ARCHIVE=""
    else
        python3 - "$archive" "$AF_ARCHIVE_BACKUP/release" <<'PYEOF'
import pathlib, sys, tarfile
with tarfile.open(sys.argv[1], 'r:gz') as archive:
    if hasattr(tarfile, 'data_filter'):
        archive.extractall(sys.argv[2], filter='data')
    else:
        members = archive.getmembers()
        for member in members:
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isdir() or member.isfile()):
                raise ValueError('Unsafe archive member; link archives require updated Python tar filters')
            member.mode &= 0o777
            member.uid = member.gid = -1
            member.uname = member.gname = ''
        archive.extractall(sys.argv[2], members=members)
PYEOF
    fi
    for candidate in "${candidates[@]}"; do
        if [[ -s "$extracted/$candidate" && -x "$extracted/$candidate" && ! -L "$extracted" && ! -L "$extracted/$candidate" ]]; then
            found=true
        fi
    done
    if [[ "$found" != true ]]; then
        print_error "The application archive does not contain the expected executable: $executable"
        return 1
    fi
    [[ "${9:-}" != binary ]] || extracted="$extracted/${candidates[0]}"
    touch "$AF_ARCHIVE_BACKUP/.af-archive-pending"
    stop_systemd_unit "$unit"
    AF_ARCHIVE_STOPPED=true
    for state_index in "${!AF_ARCHIVE_STATE_PATHS[@]}"; do
        entry="${AF_ARCHIVE_STATE_PATHS[$state_index]}"
        if [[ -e "$entry" || -L "$entry" ]]; then
            cp -a -- "$entry" "$AF_ARCHIVE_BACKUP/data-${state_index}"
        fi
    done
    if [[ "${8:-}" == preserve ]]; then
        for entry in "$destination"/* "$destination"/.[!.]* "$destination"/..?*; do
            [[ -e "$entry" || -L "$entry" ]] || continue
            relative="${entry##*/}"
            [[ "$relative" != .af-version ]] || continue
            found=false
            for candidate in "${candidates[@]}"; do
                [[ "$relative" != "$candidate" ]] || found=true
            done
            [[ "$found" != true ]] || continue
            rm -rf -- "$extracted/$relative"
            cp -a -- "$entry" "$extracted/$relative"
        done
    fi
    if [[ -e "/etc/systemd/system/${unit}.service" ]]; then
        cp -a -- "/etc/systemd/system/${unit}.service" "$AF_ARCHIVE_BACKUP/unit"
    fi
    if [[ "${9:-}" != binary && -f "$AF_TX_DIR/pre_versions$destination/.af-version" ]]; then
        cp -p --remove-destination -- "$AF_TX_DIR/pre_versions$destination/.af-version" "$extracted/.af-version" || return 1
    fi
    AF_ARCHIVE_ACTIVATED=true
    if [[ -e "$destination" ]]; then
        mv -T -- "$destination" "$AF_ARCHIVE_BACKUP/app"
    fi
    mv -T -- "$extracted" "$destination"
    [[ -z "$AF_ARCHIVE_ARCHIVE" ]] || rm -f -- "$archive"
}

rollback_app_archive_update() {
    local status="$1" restored=true state_index entry
    trap - EXIT INT TERM
    set +e
    [[ "${INSTALL_COMMITTED:-false}" != true ]] || exit "$status"
    [[ "$status" -ne 0 ]] || status=1
    if [[ "${AF_ARCHIVE_ACTIVATED:-false}" == true && ( "${AF_ARCHIVE_ORIGINAL_PRESENT:-false}" != true || -e "${AF_ARCHIVE_BACKUP:-}/app" ) ]]; then
        if ! quiesce_services_for_rollback "$AF_ARCHIVE_UNIT"; then
            if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                af_write_failure_receipt "$status" "rollback" "incomplete_rollback" "Application archive rollback aborted because service quiescence failed; recovery backup preserved at ${AF_ARCHIVE_BACKUP:-unknown} (incomplete-rollback)"
            else
                printf 'AF_DIAG_FAILURE={"stage":"rollback","exit_code":%d,"category":"incomplete_rollback","summary":"Application archive rollback aborted because service quiescence failed; recovery backup preserved at %s (incomplete-rollback)"}\n' "$status" "${AF_ARCHIVE_BACKUP:-unknown}" >&2
            fi
            exit "$status"
        fi
        safe_restore_path_from_backup "$AF_ARCHIVE_BACKUP/app" "$AF_ARCHIVE_DESTINATION" || restored=false
        for state_index in "${!AF_ARCHIVE_STATE_PATHS[@]}"; do
            entry="${AF_ARCHIVE_STATE_PATHS[$state_index]}"
            safe_restore_path_from_backup "$AF_ARCHIVE_BACKUP/data-${state_index}" "$entry" || restored=false
        done
        if [[ -n "${AF_ARCHIVE_DATABASE_BACKUP:-}" ]]; then
            restore_configured_database "$AF_ARCHIVE_DATABASE_BACKUP" "${AF_ARCHIVE_DATABASE_CONFIG[@]}" || restored=false
        fi
        if [[ -e "$AF_ARCHIVE_BACKUP/unit" ]]; then
            safe_restore_path_from_backup "$AF_ARCHIVE_BACKUP/unit" "/etc/systemd/system/${AF_ARCHIVE_UNIT}.service" || restored=false
        else
            systemctl disable -- "$AF_ARCHIVE_UNIT" >> "$LOGFILE" 2>&1 || restored=false
            rm -f -- "/etc/systemd/system/${AF_ARCHIVE_UNIT}.service" || restored=false
        fi
        systemctl daemon-reload >> "$LOGFILE" 2>&1 || restored=false
    fi
    if [[ "$restored" == true ]]; then
        for entry in "${AF_ARCHIVE_ROLLBACK_RESTART_UNITS[@]}"; do
            systemctl restart "$entry" >> "$LOGFILE" 2>&1 || restored=false
        done
    fi
    if [[ "$restored" == true && "${AF_ARCHIVE_STOPPED:-false}" == true && "${AF_ARCHIVE_PREVIOUS:-false}" == true ]]; then
        systemctl restart "$AF_ARCHIVE_UNIT" >> "$LOGFILE" 2>&1 || restored=false
    fi
    rm -f -- "${AF_ARCHIVE_ARCHIVE:-}"
    rm -rf -- "${AF_ARCHIVE_BACKUP:-}/release"
    if [[ "$restored" != true ]]; then
        if declare -F af_write_failure_receipt >/dev/null 2>&1; then
            af_write_failure_receipt "$status" "rollback" "incomplete_rollback" "Application recovery is incomplete; recovery backup preserved at ${AF_ARCHIVE_BACKUP:-unknown} (incomplete-rollback)"
        else
            printf 'AF_DIAG_FAILURE={"stage":"rollback","exit_code":%d,"category":"incomplete_rollback","summary":"Application recovery is incomplete; recovery backup preserved at %s (incomplete-rollback)"}\n' "$status" "${AF_ARCHIVE_BACKUP:-unknown}" >&2
        fi
        print_error "Application recovery is incomplete; recovery backup preserved at ${AF_ARCHIVE_BACKUP:-unknown}"
    else
        [[ -z "${AF_ARCHIVE_BACKUP:-}" ]] || rm -f -- "$AF_ARCHIVE_BACKUP/.af-archive-pending"
    fi
    exit "$status"
}

finish_app_archive_update() {
    local unit="$1" port="$2" readiness_path="${3:-}"
    wait_for_service_ready "$unit" "$port" "$readiness_path" || return 1
    if [[ -n "${AF_ARCHIVE_BACKUP:-}" ]]; then
        rm -rf -- "$AF_ARCHIVE_BACKUP/release"
        log_info "Previous application and state retained privately in $AF_ARCHIVE_BACKUP"
    fi
}

retain_app_data_directory() {
    local source="$1" destination="$2"
    [[ ! -L "$destination" ]] || return 1
    if [[ -L "$source" ]]; then
        [[ "$(readlink -f -- "$source")" == "$(readlink -f -- "$destination")" ]] || return 1
        return 0
    fi
    [[ -d "$source" ]] || { mkdir -p -- "$destination"; return 0; }
    if [[ -d "$destination" ]] && [[ -n "$(find "$destination" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
        print_error "Both legacy and retained data exist; reconcile $source and $destination before retrying"
        return 1
    fi
    mkdir -p -- "$destination"
    cp -a -- "$source/." "$destination/"
}

purge_app_archive_backups() {
    local package="$1" destination="$2" backup
    for backup in "${destination}".af-backup.*; do
        [[ -d "$backup" && ! -L "$backup" ]] || continue
        # Legacy replace_app_tree backups have no owner receipt. An explicit
        # destination still identifies them, while foreign receipts stay intact.
        if [[ -e "$backup/.af-archive-owner" || -L "$backup/.af-archive-owner" ]]; then
            [[ -f "$backup/.af-archive-owner" && ! -L "$backup/.af-archive-owner" ]] || continue
            [[ "$(cat "$backup/.af-archive-owner")" == "$package" ]] || continue
        fi
        rm -rf -- "$backup" || return 1
    done
}

configure_apache_app_listener() {
    local package_name="$1" port="$2" apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}" config staged
    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ && "$port" =~ ^[0-9]+$ ]] || return 1
    (( port >= 1024 && port <= 65535 )) || return 1
    config="aetherflow-${package_name}-listen.conf"
    mkdir -p "$apache_root/conf-available" "$apache_root/conf-enabled"
    if grep -Eq "^[[:space:]]*Listen[[:space:]]+${port}([[:space:]]|$)" "$apache_root/ports.conf" 2>/dev/null; then
        rm -f -- "$apache_root/conf-enabled/$config" "$apache_root/conf-available/$config"
        log_info "Reusing existing shared Apache listener on $port"
        return 0
    fi
    staged="$(mktemp "$apache_root/conf-available/.${config}.XXXXXX")"
    if ! printf 'Listen %s\n' "$port" > "$staged" || ! chmod 644 "$staged" || ! mv -f -- "$staged" "$apache_root/conf-available/$config"; then
        rm -f -- "$staged"
        return 1
    fi
    ln -sfn -- "../conf-available/$config" "$apache_root/conf-enabled/$config"
}

remove_apache_app_listener() {
    local package_name="$1" apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}" config
    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    config="aetherflow-${package_name}-listen.conf"
    rm -f -- "$apache_root/conf-enabled/$config" "$apache_root/conf-available/$config"
}

lock_path() {
    local package_name="$1"
    printf '%s/.%s.lock\n' "$LOCK_DIR" "$package_name"
}

has_lock() {
    local package_name="$1"
    [[ -f "$(lock_path "$package_name")" ]]
}

launch_detached_helper() (
    local maintenance_fd="${AF_MAINTENANCE_GUARD_FD:-}"
    if [[ -n "$maintenance_fd" ]]; then
        [[ "$maintenance_fd" =~ ^[0-9]+$ && "$maintenance_fd" -gt 2 ]] || return 1
        exec {maintenance_fd}>&-
    fi
    unset AF_MAINTENANCE_GUARD_FD
    "$@" </dev/null >/dev/null 2>&1 &
)

write_lock() {
    local package_name="$1"
    if [[ -n "${AF_STATE_BACKUP:-}" && -n "${AF_STATE_UNIT:-}" ]]; then
        verify_systemd_service_active "$AF_STATE_UNIT" || return 1
        if [[ "${AF_STATE_PORT:-0}" != 0 ]]; then
            wait_for_service_ready "$AF_STATE_UNIT" "$AF_STATE_PORT" "$AF_STATE_READINESS_PATH" || return 1
        fi
    fi
    if [[ -d "${AF_TX_DIR:-}/apt-packages" ]]; then
        clear_apt_reinstall_markers || return 1
    fi
    touch "$(lock_path "$package_name")" || return 1
    INSTALL_COMMITTED=true
    if [[ -n "${AF_ARCHIVE_BACKUP:-}" ]]; then
        rm -f -- "$AF_ARCHIVE_BACKUP/.af-archive-pending"
    fi
    if [[ -x /usr/local/bin/af-certbot-sync ]]; then
        launch_detached_helper /usr/local/bin/af-certbot-sync
    fi
}

get_base_domain() {
    local dom=""
    if command -v sqlite3 >/dev/null 2>&1 && [[ -f /opt/AetherFlow/backend/data/aetherflow.sqlite ]]; then
        dom="$(sqlite3 /opt/AetherFlow/backend/data/aetherflow.sqlite "SELECT base_domain FROM settings WHERE id = 1;" 2>/dev/null | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's/^\*\.//' | tr -d '[:space:]' || true)"
    fi
    if [[ -z "$dom" && -f /etc/aetherflow/aetherflow.env ]]; then
        dom="$(grep -oP '^AETHERFLOW_BASE_DOMAIN=\K.*' /etc/aetherflow/aetherflow.env 2>/dev/null | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's/^\*\.//' | tr -d '[:space:]' || true)"
    fi
    local domain_regex='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
    if [[ "$dom" == "localhost" || "$dom" == *.local ]] || { [[ -n "$dom" ]] && [[ ! "$dom" =~ $domain_regex ]]; }; then
        dom=""
    fi
    printf '%s\n' "$dom"
}

remove_lock() {
    local package_name="$1"
    if [[ "${DELETE_DATA:-false}" == true ]]; then
        purge_app_backups "$package_name" || return 1
    fi
    rm -f "$(lock_path "$package_name")"
}

backup_file_once() {
    local target="$1"
    if [[ -f "$target" && ! -f "${target}.bak-af" ]]; then
        cp -a "$target" "${target}.bak-af"
    fi
}

rollback_file() {
    local target="$1"
    if [[ -f "${target}.bak-af" ]]; then
        mv -f "${target}.bak-af" "$target"
    fi
}

cleanup_backup_file() {
    local target="$1"
    rm -f "${target}.bak-af"
}

fetch_and_run() {
    local url="$1"
    local checksum="${2:-}"
    shift 2

    local tmp_script
    tmp_script=$(mktemp "${TMPDIR:-/tmp}/aetherflow-install-XXXXXX.sh") || return 1

    if [[ -z "$checksum" || "$checksum" == "SKIP" || ! "$checksum" =~ ^[0-9a-fA-F]{64}$ ]]; then
        print_error "Refusing to execute remote bootstrap script without a pinned 64-hex SHA-256 digest: $url"
        rm -f "$tmp_script"
        return 1
    fi
    
    log_info "Downloading install script from $url"
    if ! curl -fsSL -o "$tmp_script" "$url"; then
        print_error "Failed to download $url"
        rm -f "$tmp_script"
        return 1
    fi

    local computed_hash
    if ! computed_hash=$(sha256sum "$tmp_script" | awk '{print $1}') || [[ "${computed_hash,,}" != "${checksum,,}" ]]; then
        print_error "Checksum validation failed for $url! Expected: $checksum, Got: ${computed_hash:-unavailable}"
        rm -f "$tmp_script"
        return 1
    fi
    log_info "Checksum validation passed."
    echo "[BOOTSTRAP-PROVENANCE] url=${url} sha256=${computed_hash,,}" >> "$LOGFILE" 2>/dev/null || true

    if ! bash "$tmp_script" "$@"; then
        print_error "Script execution failed for $url"
        rm -f "$tmp_script"
        return 1
    fi

    rm -f "$tmp_script"
    return 0
}

AF_CURRENT_STAGE="${AF_CURRENT_STAGE:-init}"

af_set_stage() {
    AF_CURRENT_STAGE="$1"
    report_progress "${2:-0}" "Stage: $1"
}

_af_redact_awk() {
    awk -f /dev/fd/3 3<<'AWK'
 function is_space(c) { return c == " " || c == "\t" || c == "\r" || c == "\n" }
 function is_vert(c) { return c == "\r" || c == "\n" }
 function is_ws(c) { return is_space(c) || is_vert(c) }
 function is_keychar(c) { return c ~ /[A-Za-z0-9_.-]/ }
 function is_word(c) { return c ~ /[A-Za-z0-9_]/ }
 function is_alpha(c) { return c ~ /[A-Za-z]/ }
 function lowchar(c) { return tolower(c) }

 function is_sensitive(k,    l, re) {
     l = tolower(k)
     re = "^([a-z0-9_.-]*(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(orization|[_-]?token|[_-]?key|[_-]?secret)?|passphrase|credentials?|bearer|cookies?|session([_-]?(id|key|token|secret))?|webhook([_-]?(url|secret|token|key))?|jwt[_-]?secret|master[_-]?pass|rclone[_-]?(rc[_-]?)?pass)[a-z0-9_.-]*|([a-z0-9]+[_.-])*(pass[0-9]*|key)([_.-][a-z0-9]+)*)$"
     return l ~ re
 }

 function is_header_name(k,    l) {
     l = tolower(k)
     return l == "authorization" || l == "proxy-authorization" || l == "cookie" || l == "set-cookie" || l == "x-api-key" || l == "x-auth-token"
 }

 function eq_ci_at(s, i, lit,    n, k) {
     n = length(lit)
     if (i < 1 || i + n - 1 > length(s)) return 0
     for (k = 1; k <= n; k++) if (lowchar(substr(s, i + k - 1, 1)) != lowchar(substr(lit, k, 1))) return 0
     return 1
 }

 function hexval(h,    i, c, v, d) {
     v = 0
     for (i = 1; i <= length(h); i++) {
         c = lowchar(substr(h, i, 1))
         if (c >= "0" && c <= "9") d = index("0123456789", c) - 1
         else if (c >= "a" && c <= "f") d = index("abcdef", c) + 9
         else return -1
         v = v * 16 + d
     }
     return v
 }

 function u00_char(h) {
     return sprintf("%c", hexval(h))
 }

 function decode_u00(raw,    i, n, out, end_escape) {
     out = ""
     i = 1
     n = length(raw)
     while (i <= n) {
         if (substr(raw, i, 1) == "\\") {
             end_escape = i
             while (end_escape <= n && substr(raw, end_escape, 1) == "\\") end_escape++
             if (substr(raw, end_escape, 3) == "u00" && substr(raw, end_escape + 3, 2) ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) {
                 out = out u00_char(substr(raw, end_escape + 3, 2))
                 i = end_escape + 5
                 continue
             }
         }
         out = out substr(raw, i, 1)
         i++
     }
     return out
 }

 function scheme_before(s, colon_pos,    names, k, name, start, prev) {
     names[1] = "postgresql"
     names[2] = "mongodb"
     names[3] = "postgres"
     names[4] = "https"
     names[5] = "mysql"
     names[6] = "redis"
     names[7] = "amqp"
     names[8] = "http"
     names[9] = "ftp"
     for (k = 1; k <= 9; k++) {
         name = names[k]
         start = colon_pos - length(name)
         if (start < 1) continue
         if (!eq_ci_at(s, start, name)) continue
         if (start == 1) return 1
         prev = substr(s, start - 1, 1)
         if (!is_word(prev)) return 1
     }
     return 0
 }

 function redact_urls(s,    i, n, out, j, c, colon, at, ok, scheme_ok) {
     n = length(s)
     out = ""
     i = 1
     while (i <= n) {
         if (substr(s, i, 3) == "://") {
             j = i + 3
             colon = 0
             at = 0
             ok = 1
             while (j <= n) {
                 c = substr(s, j, 1)
                 if (c == "/" || c == "@" || is_ws(c)) {
                     if (c == "@" && colon > 0 && ok) at = j
                     break
                 }
                 if (c == ":") {
                     if (colon == 0) colon = j
                     else ok = 0
                 }
                 j++
             }
             if (at > 0 && colon > i + 3) {
                 out = out "://[REDACTED]@"
                 i = at + 1
                 continue
             }
             if (scheme_before(s, i)) {
                 j = i + 3
                 while (j <= n) {
                     c = substr(s, j, 1)
                     if (c == "/" || c == "@" || is_ws(c)) break
                     j++
                 }
                 if (j <= n && substr(s, j, 1) == "@" && j > i + 3) {
                     out = out "://[REDACTED]@"
                     i = j + 1
                     continue
                 }
             }
         }
         out = out substr(s, i, 1)
         i++
     }
     return out
 }

 function read_dquoted(s, i,    n, j, bs, ch) {
     n = length(s)
     if (substr(s, i, 1) != "\"") return 0
     j = i + 1
     bs = 0
     while (j <= n) {
         ch = substr(s, j, 1)
         if (ch == "\\") { bs++; j++; continue }
         if (ch == "\"" && bs % 2 == 0) return j + 1
         if (is_vert(ch)) return 0
         bs = 0
         j++
     }
     return 0
 }

 function read_identifier_key(s, p,    n, j, end_escape, c) {
     n = length(s)
     if (substr(s, p, 1) != "\"") return 0
     j = p + 1
     while (j <= n) {
         c = substr(s, j, 1)
         if (is_keychar(c)) { j++; continue }
         if (c == "\\") {
             end_escape = j
             while (end_escape <= n && substr(s, end_escape, 1) == "\\") end_escape++
             if (substr(s, end_escape, 3) == "u00" && substr(s, end_escape + 3, 2) ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) {
                 j = end_escape + 5
                 continue
             }
         } else end_escape = j
         if (j > p + 1 && substr(s, end_escape, 1) == "\"") {
             parsed_key_body_end = j
             parsed_key = decode_u00(substr(s, p + 1, j - p - 1))
             return end_escape + 1
         }
         return 0
     }
     return 0
 }

 function normalize_sensitive_json_keys(s,    i, n, out, endq, j) {
     n = length(s)
     out = ""
     i = 1
     while (i <= n) {
         if (substr(s, i, 1) == "\"") {
             endq = read_identifier_key(s, i)
             if (endq > 0) {
                 j = endq
                 while (j <= n && is_space(substr(s, j, 1))) j++
                 if (j <= n && substr(s, j, 1) == ":" && is_sensitive(parsed_key)) {
                     out = out "\"" parsed_key substr(s, parsed_key_body_end, j - parsed_key_body_end + 1)
                     i = j + 1
                     continue
                 }
                 out = out substr(s, i, endq - i)
                 i = endq
                 continue
             }
         }
         out = out substr(s, i, 1)
         i++
     }
     return out
 }

 function header_name_len(s, p,    names, k, name) {
     names[1] = "Proxy-Authorization"
     names[2] = "Set-Cookie"
     names[3] = "X-Auth-Token"
     names[4] = "X-Api-Key"
     names[5] = "Authorization"
     names[6] = "Cookie"
     for (k = 1; k <= 6; k++) {
         name = names[k]
         if (eq_ci_at(s, p, name)) return length(name)
     }
     return 0
 }

 function boundary_before_name(s, name_at) {
     if (name_at <= 1) return 1
     return ! (substr(s, name_at - 1, 1) ~ /[A-Za-z0-9_-]/)
 }

 function header_match_at(s, p,    n, pre_len, name_at, hlen, j, c, bs) {
     n = length(s)
     pre_len = 0
     name_at = p
     if (substr(s, p, 1) == "\\") {
         bs = 0
         j = p
         while (j <= n && substr(s, j, 1) == "\\") { bs++; j++ }
         c = substr(s, j, 1)
         if ((c == "\"" || c == "'") && bs >= 1) {
             pre_len = bs + 1
             name_at = j + 1
         }
     } else if (substr(s, p, 1) == "\"" || substr(s, p, 1) == "'") {
         pre_len = 1
         name_at = p + 1
     }
     if (!boundary_before_name(s, name_at)) return 0
     hlen = header_name_len(s, name_at)
     if (hlen == 0) return 0
     j = name_at + hlen
     while (j <= n && is_space(substr(s, j, 1))) j++
     if (j > n || substr(s, j, 1) != ":") return 0
     j++
     while (j <= n && is_space(substr(s, j, 1))) j++
     return j
 }

 function find_header(s, from,    n, p, endat) {
     n = length(s)
     p = from
     while (p <= n) {
         endat = header_match_at(s, p)
         if (endat > 0) {
             HDR_START = p
             HDR_END = endat
             return 1
         }
         p++
     }
     return 0
 }

 function header_pre_len(s, start,    n, j, bs, c) {
     n = length(s)
     if (substr(s, start, 1) == "\\") {
         j = start
         bs = 0
         while (j <= n && substr(s, j, 1) == "\\") { bs++; j++ }
         c = substr(s, j, 1)
         if ((c == "\"" || c == "'") && bs >= 1) return bs + 1
     } else if (substr(s, start, 1) == "\"" || substr(s, start, 1) == "'") {
         return 1
     }
     return 0
 }

 function find_unescaped_quote_end(value, quote,    i, n, bs, ch) {
     n = length(value)
     i = 1
     bs = 0
     while (i <= n) {
         ch = substr(value, i, 1)
         if (ch == "\\") { bs++; i++; continue }
         if (ch == quote && bs % 2 == 0) return i - 1
         if (is_vert(ch)) return -1
         bs = 0
         i++
     }
     return -1
 }

 function find_escaped_header_close(value, n_bs, quote,    i, n, j, bs, ch, after) {
     n = length(value)
     i = 1
     while (i <= n) {
         if (substr(value, i, 1) != "\\") { i++; continue }
         j = i
         bs = 0
         while (j <= n && substr(value, j, 1) == "\\") { bs++; j++ }
         if (j <= n && substr(value, j, 1) == quote && bs == n_bs) {
             after = j + 1
             if (after > n || is_ws(substr(value, after, 1)) || substr(value, after, 1) == "|") return i - 1
             i = j + 1
             continue
         }
         i = (j <= n ? j + 1 : j)
     }
     return -1
 }

 function looks_like_next_h(s, p,    n, i, hlen, c) {
     n = length(s)
     i = p
     while (i <= n && is_space(substr(s, i, 1))) i++
     if (!eq_ci_at(s, i, "-H")) return 0
     i += 2
     if (i > n || !is_space(substr(s, i, 1))) return 0
     while (i <= n && is_space(substr(s, i, 1))) i++
     while (i <= n && substr(s, i, 1) == "\\") i++
     c = substr(s, i, 1)
     if (c == "\"" || c == "'") i++
     hlen = header_name_len(s, i)
     if (hlen == 0) return 0
     i += hlen
     while (i <= n && is_space(substr(s, i, 1))) i++
     return i <= n && substr(s, i, 1) == ":"
 }

 function scan_unquoted_header_value(value,    i, n, ch) {
     n = length(value)
     i = 1
     while (i <= n) {
         ch = substr(value, i, 1)
         if (ch == "\r" || ch == "\n" || ch == "|") return i - 1
         if (looks_like_next_h(value, i)) return i - 1
         i++
     }
     return n
 }

 function redact_headers(s,    out, cursor, n, pre, prelen, hdr_at, hlen, hdr, value, rel, n_bs, close_len, closing, consumed) {
     n = length(s)
     out = ""
     cursor = 1
     while (cursor <= n) {
         if (!find_header(s, cursor)) {
             out = out substr(s, cursor)
             break
         }
         out = out substr(s, cursor, HDR_START - cursor)
         prelen = header_pre_len(s, HDR_START)
         pre = substr(s, HDR_START, prelen)
         hdr_at = HDR_START + prelen
         hlen = header_name_len(s, hdr_at)
         hdr = substr(s, hdr_at, hlen)
         value = substr(s, HDR_END)
         if (prelen > 0 && substr(pre, 1, 1) != "\\") {
             rel = find_unescaped_quote_end(value, substr(pre, prelen, 1))
             if (rel >= 0) {
                 out = out pre hdr ": [REDACTED]" pre
                 cursor = HDR_END + rel + 1
                 continue
             }
         } else if (prelen > 0 && substr(pre, 1, 1) == "\\") {
             n_bs = prelen - 1
             rel = find_escaped_header_close(value, n_bs, substr(pre, prelen, 1))
             if (rel >= 0) {
                 close_len = n_bs + 1
                 closing = substr(value, rel + 1, close_len)
                 out = out pre hdr ": [REDACTED]" closing
                 cursor = HDR_END + rel + close_len
                 continue
             }
         }
         consumed = scan_unquoted_header_value(value)
         out = out pre hdr ": [REDACTED]"
         cursor = HDR_END + consumed
         if (cursor < HDR_END) cursor = HDR_END
     }
     return out
 }

 function consume_quoted_token(s, p,    n, q, j, bs, ch) {
     n = length(s)
     q = substr(s, p, 1)
     j = p + 1
     bs = 0
     while (j <= n) {
         ch = substr(s, j, 1)
         if (ch == "\\") { bs++; j++; continue }
         if (ch == q && bs % 2 == 0) return j + 1
         bs = 0
         j++
     }
     return n + 1
 }

 function consume_scalar(s, allow_comma,    n, p, c, j, bs, nxt, after, q, k, t, bs2, marker) {
     n = length(s)
     marker = "[REDACTED]"
     if (substr(s, 1, length(marker)) == marker && substr(s, 1, 13) != "[REDACTED_URL]" && substr(s, 1, 13) != "[REDACTED_url]") p = length(marker) + 1
     else p = 1
     while (p <= n) {
         c = substr(s, p, 1)
         if (c == "$" && p < n && (substr(s, p + 1, 1) == "'" || substr(s, p + 1, 1) == "\"")) {
             q = substr(s, p + 1, 1)
             j = p + 2
             while (j <= n) {
                 if (substr(s, j, 1) == "\\" && j < n && !is_vert(substr(s, j + 1, 1))) { j += 2; continue }
                 if (substr(s, j, 1) == q) { j++; break }
                 j++
             }
             p = j
             continue
         }
         if (c == "\\") {
             j = p
             bs = 0
             while (j <= n && substr(s, j, 1) == "\\") { bs++; j++ }
             if (j > n) return n
             nxt = substr(s, j, 1)
             if (is_vert(nxt)) return p - 1
             if ((nxt == "'" || nxt == "\"") && bs % 2 == 1) {
                 after = j + 1
                 if (p > 1 && index(substr(s, after), nxt) == 0 && (after > n || is_ws(substr(s, after, 1)) || substr(s, after, 1) == "," || substr(s, after, 1) == "}" || substr(s, after, 1) == "]")) return p - 1
                 q = nxt
                 k = j + 1
                 while (k <= n) {
                     t = k
                     bs2 = 0
                     while (t <= n && substr(s, t, 1) == "\\") { bs2++; t++ }
                     if (t <= n && substr(s, t, 1) == q && bs2 % 2 == 1) { p = t + 1; break }
                     if (t > n) { p = n + 1; break }
                     k = t + 1
                 }
                 if (k > n && p <= n) p = n + 1
                 continue
             }
             if ((nxt == "'" || nxt == "\"") && bs % 2 == 0) { p = j; continue }
             p = j + 1
             continue
         }
         if (c == "'" || c == "\"") {
             nxt = (p < n) ? substr(s, p + 1, 1) : ""
             if (p > 1 && index(substr(s, p + 1), c) == 0 && (nxt == "" || is_ws(nxt) || nxt == "," || nxt == "}" || nxt == "]")) return p - 1
             j = consume_quoted_token(s, p)
             if (j < 0) return -j - 1
             p = j
             continue
         }
         if (is_ws(c) || c == ";" || c == "&" || c == "}" || c == "]") return p - 1
         if (c == ",") {
             if (!allow_comma) return p - 1
             nxt = (p < n) ? substr(s, p + 1, 1) : ""
             if (nxt == "" || is_ws(nxt) || nxt == "," || nxt == ";" || nxt == "&" || nxt == "}" || nxt == "]" || nxt == "\"" || nxt == "'") return p - 1
             p++
             continue
         }
         p++
     }
     return n
 }

 function starts_container(value) {
     if (value == "") return 0
     if (substr(value, 1, 10) == "[REDACTED]") return 0
     return substr(value, 1, 1) == "{" || substr(value, 1, 1) == "["
 }

 function append_redacted(prefix,    last) {
     last = substr(prefix, length(prefix), 1)
     if (last == " " || last == "\t" || last == "=") return prefix "[REDACTED]"
     return prefix " [REDACTED]"
 }

 function scan_container(text, start,    opener, nstack, i, quote, limit, ch, stack) {
     delete stack
     opener = substr(text, start, 1)
     if (opener != "{" && opener != "[") return 0
     nstack = 0
     i = start
     quote = ""
     limit = length(text)
     while (i <= limit) {
         ch = substr(text, i, 1)
         if (quote != "") {
             if (ch == "\\") { i += 2; continue }
             if (ch == quote) quote = ""
             i++
             continue
         }
         if (ch == "\"" || ch == "'") { quote = ch; i++; continue }
         if (ch == "{" || ch == "[") {
             nstack++
             stack[nstack] = (ch == "{") ? "}" : "]"
         } else if (ch == "}" || ch == "]") {
             if (nstack < 1 || stack[nstack] != ch) return limit + 1
             delete stack[nstack]
             nstack--
             if (nstack == 0) return i + 1
         }
         i++
     }
     return limit + 1
 }

 function key_at(s, p,    n, j) {
     n = length(s)
     j = p
     if (j > n || !is_keychar(substr(s, j, 1))) return 0
     while (j <= n && is_keychar(substr(s, j, 1))) j++
     return j
 }

 function redact_containers(s,    n, out, pos, p, kend, key, j, c, sep_ok, endc, opener) {
     n = length(s)
     out = ""
     pos = 1
     while (pos <= n) {
         p = pos
         found = 0
         while (p <= n) {
             if (substr(s, p, 1) == "\"") {
                 kend = read_identifier_key(s, p)
                 if (kend > 0) {
                     key = parsed_key
                     if (is_sensitive(key)) {
                         j = kend
                         while (j <= n && is_space(substr(s, j, 1))) j++
                         if (j <= n && substr(s, j, 1) == ":") {
                             j++
                             while (j <= n && is_space(substr(s, j, 1))) j++
                             c = substr(s, j, 1)
                             if ((c == "{" || c == "[") && substr(s, j, 10) != "[REDACTED]") {
                                 endc = scan_container(s, j)
                                 if (endc > 0) {
                                     out = out substr(s, pos, j - pos) "\"[REDACTED]\""
                                     pos = endc
                                     found = 1
                                     break
                                 }
                             }
                         }
                     }
                 }
             }
             if (substr(s, p, 1) == "\\" || (p == 1 || !is_word(substr(s, p - 1, 1)))) {
                 j = p
                 if (substr(s, j, 1) == "\\") {
                     while (j <= n && substr(s, j, 1) == "\\") j++
                     if (substr(s, j, 1) == "\"") {
                         kend = read_dquoted(s, j)
                         if (kend > 0) {
                             key = substr(s, j + 1, kend - j - 2)
                             t = kend
                             bs = 0
                             while (t <= n && substr(s, t, 1) == "\\") { bs++; t++ }
                             if (bs > 0 && substr(s, t, 1) == "\"" && is_sensitive(key)) {
                                 t++
                                 while (t <= n && is_space(substr(s, t, 1))) t++
                                 c = substr(s, t, 1)
                                 if (c == ":" || c == "=") {
                                     t++
                                     while (t <= n && is_space(substr(s, t, 1))) t++
                                     c = substr(s, t, 1)
                                     if ((c == "{" || c == "[") && substr(s, t, 10) != "[REDACTED]") {
                                         endc = scan_container(s, t)
                                         if (endc > 0) {
                                             out = out substr(s, pos, t - pos) "\"[REDACTED]\""
                                             pos = endc
                                             found = 1
                                             break
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
                 kend = key_at(s, p)
                 if (kend > p) {
                     key = substr(s, p, kend - p)
                     if (is_sensitive(key) && (p == 1 || !is_word(substr(s, p - 1, 1)))) {
                         j = kend
                         while (j <= n && is_space(substr(s, j, 1))) j++
                         c = substr(s, j, 1)
                         if (c == ":" || c == "=") {
                             j++
                             while (j <= n && is_space(substr(s, j, 1))) j++
                             c = substr(s, j, 1)
                             if ((c == "{" || c == "[") && substr(s, j, 10) != "[REDACTED]") {
                                 endc = scan_container(s, j)
                                 if (endc > 0) {
                                     out = out substr(s, pos, j - pos) "\"[REDACTED]\""
                                     pos = endc
                                     found = 1
                                     break
                                 }
                             }
                         }
                     }
                 }
             }
             p++
         }
         if (!found) {
             out = out substr(s, pos)
             break
         }
     }
     return out
 }

 function redact_bearer_from(s,    n, out, i, which, j, c, start) {
     n = length(s)
     out = ""
     i = 1
     while (i <= n) {
         which = ""
         if (eq_ci_at(s, i, "Bearer") && (i == 1 || !is_word(substr(s, i - 1, 1))) && (i + 6 > n || !is_word(substr(s, i + 6, 1)))) which = substr(s, i, 6)
         else if (eq_ci_at(s, i, "Basic") && (i == 1 || !is_word(substr(s, i - 1, 1))) && (i + 5 > n || !is_word(substr(s, i + 5, 1)))) which = substr(s, i, 5)
         if (which != "") {
             j = i + length(which)
             if (j <= n && is_space(substr(s, j, 1))) {
                 while (j <= n && is_space(substr(s, j, 1))) j++
                 start = j
                 c = substr(s, j, 1)
                 if (c == "\"") {
                     tokend = read_dquoted(s, j)
                     if (tokend > 0) j = tokend
                     else j = start
                 } else if (c == "'") {
                     j++
                     while (j <= n && substr(s, j, 1) != "'") {
                         if (substr(s, j, 1) == "\\") j += 2
                         else j++
                     }
                     if (j <= n && substr(s, j, 1) == "'") j++
                     else j = start
                 } else if (c ~ /[A-Za-z0-9._~+\/=-]/) {
                     while (j <= n && substr(s, j, 1) ~ /[A-Za-z0-9._~+\/=-]/) j++
                 } else j = start
                 if (j > start) {
                     out = out substr(s, i, length(which)) " [REDACTED]"
                     i = j
                     continue
                 }
             }
         }
         out = out substr(s, i, 1)
         i++
     }
     return out
 }

 function match_short_u(s, j,    n, k, lastu, c) {
     n = length(s)
     if (substr(s, j, 1) != "-") return 0
     if (substr(s, j, 2) == "--") return 0
     k = j + 1
     lastu = 0
     while (k <= n && is_alpha(substr(s, k, 1))) {
         c = substr(s, k, 1)
         if (c == "u" || c == "U") lastu = k
         k++
     }
     if (lastu == 0) return 0
     k = lastu + 1
     c = (k <= n) ? substr(s, k, 1) : ""
     if (c == " " || c == "\t") {
         while (k <= n && is_space(substr(s, k, 1))) k++
         return k
     }
     if (c == "=") return k + 1
     return lastu + 1
 }

 function match_long_user(s, j,    n, k, c) {
     n = length(s)
     if (!eq_ci_at(s, j, "--user")) return 0
     k = j + 6
     c = (k <= n) ? substr(s, k, 1) : ""
     if (c == " " || c == "\t") {
         while (k <= n && is_space(substr(s, k, 1))) k++
         return k
     }
     if (c == "=") return k + 1
     return 0
 }

 function find_curl_user_opt(s, curl_at,    n, i, line_end, opt) {
     n = length(s)
     line_end = curl_at
     while (line_end <= n && !is_vert(substr(s, line_end, 1))) line_end++
     i = curl_at + 4
     while (i < line_end) {
         if (is_space(substr(s, i, 1))) {
             while (i < line_end && is_space(substr(s, i, 1))) i++
             opt = match_long_user(s, i)
             if (opt > 0 && opt <= line_end) return opt
             opt = match_short_u(s, i)
             if (opt > 0 && opt <= line_end) return opt
         }
         i++
     }
     return 0
 }

 function quote_boundary(s, p) {
     if (p <= 1) return 1
     c = substr(s, p - 1, 1)
     return is_ws(c) || c == "\"" || c == "'"
 }

 function find_curl_prefix(s, from,    n, p, opt, mend) {
     n = length(s)
     p = from
     while (p <= n) {
         if (eq_ci_at(s, p, "curl") && (p == 1 || !is_word(substr(s, p - 1, 1))) && (p + 4 > n || !is_word(substr(s, p + 4, 1)))) {
             opt = find_curl_user_opt(s, p)
             if (opt > 0) {
                 CURL_S = p
                 CURL_E = opt
                 return 1
             }
         }
         if (quote_boundary(s, p)) {
             mend = match_long_user(s, p)
             if (mend > 0) { CURL_S = p; CURL_E = mend; return 1 }
             if (substr(s, p, 2) == "-u" || substr(s, p, 2) == "-U") {
                 k = p + 2
                 c = (k <= n) ? substr(s, k, 1) : ""
                 if (c == " " || c == "\t") {
                     while (k <= n && is_space(substr(s, k, 1))) k++
                     CURL_S = p
                     CURL_E = k
                     return 1
                 }
                 if (c == "=") { CURL_S = p; CURL_E = k + 1; return 1 }
                 CURL_S = p
                 CURL_E = p + 2
                 return 1
             }
         }
         p++
     }
     return 0
 }

 function curl_accept(prefix, consumed,    low, c) {
     if (consumed == "") return 0
     low = tolower(prefix)
     if (index(low, "curl") > 0 || index(low, "--user") > 0) return 1
     if (index(consumed, ":") > 0) return 1
     c = substr(consumed, 1, 1)
     if (c == "'" || c == "\"" || c == "\\") return 1
     if (substr(consumed, 1, 10) == "[REDACTED]") return 1
     return 0
 }

 function redact_curl_user(s,    out, cursor, n, prefix, value, consumed, ncons) {
     n = length(s)
     out = ""
     cursor = 1
     while (cursor <= n) {
         if (!find_curl_prefix(s, cursor)) {
             out = out substr(s, cursor)
             break
         }
         if (CURL_E <= CURL_S) {
             out = out substr(s, cursor, CURL_S - cursor + 1)
             cursor = CURL_S + 1
             continue
         }
         prefix = substr(s, CURL_S, CURL_E - CURL_S)
         value = substr(s, CURL_E)
         if (starts_container(value)) {
             ncons = scan_container(value, 1) - 1
         } else ncons = consume_scalar(value, 1)
         consumed = substr(value, 1, ncons)
         if (!curl_accept(prefix, consumed)) {
             out = out substr(s, cursor, CURL_S - cursor + 1)
             cursor = CURL_S + 1
             continue
         }
         out = out substr(s, cursor, CURL_S - cursor) append_redacted(prefix)
         cursor = CURL_E + ncons
     }
     return out
 }

 function cli_match_len(s, p,    rest, low) {
     if (!eq_ci_at(s, p, "--")) return 0
     rest = substr(s, p + 2)
     low = tolower(rest)
     if (match(low, /^([a-z0-9-]*-)?(password|passwd|pwd|pass|secret|token|apikey|api[_-]?key|credentials?|cookies?|session([_-]?(id|key|token|secret))?|webhook([_-]?(url|secret|token|key))?)([ \t]+|=)[ \t]*/)) {
         return 2 + RLENGTH
     }
     return 0
 }

 function redact_cli_flags(s,    n, out, cursor, p, mlen, prefix, value, ncons, consumed) {
     n = length(s)
     out = ""
     cursor = 1
     while (cursor <= n) {
         p = cursor
         mlen = 0
         while (p <= n) {
             if (quote_boundary(s, p)) {
                 mlen = cli_match_len(s, p)
                 if (mlen > 0) break
             }
             p++
         }
         if (mlen == 0) {
             out = out substr(s, cursor)
             break
         }
         prefix = substr(s, p, mlen)
         value = substr(s, p + mlen)
         if (starts_container(value)) {
             ncons = scan_container(value, 1) - 1
         } else ncons = consume_scalar(value, 1)
         consumed = substr(value, 1, ncons)
         if (consumed == "") {
             out = out substr(s, cursor, p - cursor + 1)
             cursor = p + 1
             continue
         }
         out = out substr(s, cursor, p - cursor) append_redacted(prefix)
         cursor = p + mlen + ncons
     }
     return out
 }

 function redact_assignments(s,    n, out, cursor, p, kend, key, j, c, sep, value, ncons, consumed) {
     n = length(s)
     out = ""
     cursor = 1
     while (cursor <= n) {
         p = cursor
         kend = 0
         while (p <= n) {
             if (p == 1 || !is_keychar(substr(s, p - 1, 1))) {
                 kend = key_at(s, p)
                 if (kend > p) {
                     key = substr(s, p, kend - p)
                     if (is_sensitive(key)) {
                         j = kend
                         while (j <= n && is_space(substr(s, j, 1))) j++
                         c = substr(s, j, 1)
                         if (c == "=" || c == ":") {
                             sep = c
                             j++
                             while (j <= n && is_space(substr(s, j, 1))) j++
                             break
                         }
                     }
                 }
             }
             kend = 0
             p++
         }
         if (kend == 0 || p > n) {
             out = out substr(s, cursor)
             break
         }
         value = substr(s, j)
         if (is_header_name(key) || starts_container(value)) {
             out = out substr(s, cursor, j - cursor)
             cursor = j
             continue
         }
         ncons = consume_scalar(value, 1)
         consumed = substr(value, 1, ncons)
         if (consumed == "") {
             out = out substr(s, cursor, p - cursor + 1)
             cursor = p + 1
             continue
         }
         out = out substr(s, cursor, p - cursor) key sep "[REDACTED]"
         cursor = j + ncons
     }
     return out
 }

 function redact_json_scalars(s,    n, out, cursor, p, endq, key, j, value, ncons, consumed, quote, back) {
     n = length(s)
     out = ""
     cursor = 1
     while (cursor <= n) {
         p = cursor
         endq = 0
         while (p <= n) {
             if (substr(s, p, 1) == "\"") {
                 endq = read_identifier_key(s, p)
                 if (endq > 0) {
                     key = parsed_key
                     if (is_sensitive(key)) {
                         j = endq
                         while (j <= n && is_space(substr(s, j, 1))) j++
                         if (j <= n && substr(s, j, 1) == ":") {
                             j++
                             while (j <= n && is_space(substr(s, j, 1))) j++
                             break
                         }
                     }
                 }
             }
             endq = 0
             p++
         }
         if (endq == 0 || p > n) {
             out = out substr(s, cursor)
             break
         }
         value = substr(s, j)
         if (is_header_name(key) || starts_container(value)) {
             out = out substr(s, cursor, j - cursor)
             cursor = j
             continue
         }
         ncons = consume_scalar(value, 0)
         consumed = substr(value, 1, ncons)
         if (consumed == "") {
             out = out substr(s, cursor, p - cursor + 1)
             cursor = p + 1
             continue
         }
         quote = "\""
         back = p - 1
         while (back > 0 && substr(s, back, 1) == "\\") { quote = "\\" quote; back-- }
         out = out substr(s, cursor, j - cursor) quote "[REDACTED]" quote
         cursor = j + ncons
     }
     return out
 }

 function redact(s) {
     s = redact_urls(s)
     s = normalize_sensitive_json_keys(s)
     s = redact_headers(s)
     s = redact_bearer_from(s)
     s = redact_containers(s)
     s = redact_json_scalars(s)
     s = redact_curl_user(s)
     s = redact_cli_flags(s)
     s = redact_assignments(s)
     return s
 }

 {
     if (NR == 1) text = $0
     else text = text "\n" $0
 }
 END {
     if (NR == 0) text = ""
     printf "%s", redact(text)
 }
AWK
}

_af_redact_sed() {
    cat >/dev/null
    printf '%s' '[REDACTED]'
}

_af_redact_without_python() {
    if command -v awk >/dev/null 2>&1; then
        _af_redact_awk
    else
        _af_redact_sed
    fi
}

_af_redact_ascii_fallback() {
    _af_redact_without_python
}

_af_truncate_receipt_field() {
    local text
    IFS= read -r -N "$1" text || true
    printf '%s' "$text"
    cat >/dev/null
}

af_write_failure_receipt() {
    local rc="1" stage cat msg
    if [[ $# -ge 4 ]]; then
        rc="${1:-1}"
        stage="${2:-${AF_CURRENT_STAGE:-unknown}}"
        cat="${3:-installer}"
        msg="${4:-Installation failed at stage ${stage} (exit ${rc})}"
    elif [[ $# -eq 3 ]]; then
        rc="${1:-1}"
        stage="${AF_CURRENT_STAGE:-unknown}"
        cat="${2:-installer}"
        msg="${3:-Installation failed at stage ${stage} (exit ${rc})}"
    else
        rc="${1:-1}"
        stage="${AF_CURRENT_STAGE:-unknown}"
        cat="${2:-installer}"
        msg="${3:-Installation failed at stage ${stage} (exit ${rc})}"
    fi
    if [[ "$rc" -eq 0 ]]; then
        rc=1
    fi
    if command -v python3 >/dev/null 2>&1; then
        python3 /dev/fd/3 "$rc" 3<<'PY' < <(printf '%s\0%s\0%s' "$stage" "$cat" "$msg")
import os, sys, re, json

SENSITIVE_KEY = (
    r"(?:"
    r"[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|auth(?:orization|[_-]?token|[_-]?key|[_-]?secret)?|passphrase|credentials?|bearer|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|jwt[_-]?secret|master[_-]?pass|rclone[_-]?(?:rc[_-]?)?pass)[A-Za-z0-9_.-]*"
    r"|"
    r"(?:[A-Za-z0-9]+[_.-])*(?:pass[0-9]*|cookies?|session(?:[_-]?(?:id|key|token|secret))?|webhook(?:[_-]?(?:url|secret|token|key))?|key)(?:[_.-][A-Za-z0-9]+)*"
    r")"
)
HEADER_NAMES = {"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"}
HEADER_RE = re.compile(
    r"(?im)(?P<pre>\\+[\"']|[\"'])?(?<![A-Za-z0-9_-])"
    r"(?P<hdr>Proxy-Authorization|Set-Cookie|X-Auth-Token|X-Api-Key|Authorization|Cookie)"
    r"[ \t]*:[ \t]*"
)
NEXT_H_RE = re.compile(
    r"[ \t]*-H[ \t]+\\*[\"']?"
    r"(?:Proxy-Authorization|Set-Cookie|X-Auth-Token|X-Api-Key|Authorization|Cookie)"
    r"[ \t]*:",
    re.I,
)
JSON_KEY_RE = re.compile(r'(?i)\\*"(' + SENSITIVE_KEY + r')\\*"\s*:\s*')
ASSIGN_RE = re.compile(
    r"(?i)(?:^|(?<=[^A-Za-z0-9_.-]))(" + SENSITIVE_KEY + r")\s*([:=])\s*"
)
CLI_RE = re.compile(
    r"(?i)(?:^|(?<=[\s\"']))--(?:[A-Za-z0-9-]*-)?"
    r"(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|cookies?|"
    r"session(?:[_-]?(?:id|key|token|secret))?|"
    r"webhook(?:[_-]?(?:url|secret|token|key))?|credentials?)"
    r"(?:\s+|=)\s*"
)
CURL_RE = re.compile(
    r"(?i)(?:"
    r"\bcurl\b[^\r\n]*?\s+(?:--user(?:\s+|=)|-[A-Za-z]*u(?:\s+|=)?)"
    r"|(?:^|(?<=[\s\"']))(?:--user(?:\s+|=)|-u(?:\s+|=))"
    r"|(?:^|(?<=[\s\"']))-u"
    r")"
)


def _decode_u00(raw):
    def repl(match):
        return chr(int(match.group(1), 16))

    return re.sub(r"\\+u00([0-9A-Fa-f]{2})", repl, raw)


def normalize_sensitive_json_keys(text):
    def repl(match):
        raw = match.group("body")
        decoded = _decode_u00(raw)
        if re.fullmatch(SENSITIVE_KEY, decoded, flags=re.I):
            return match.group("prefix") + decoded + match.group("suffix")
        return match.group(0)

    return re.sub(r'(?P<prefix>\\*")(?P<body>(?:\\+u00[0-9A-Fa-f]{2}|[A-Za-z0-9_.-])+)(?P<suffix>\\*"\s*:)', repl, text)


def find_unescaped_quote_end(value, quote):
    i = 0
    bs = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\":
            bs += 1
            i += 1
            continue
        if ch == quote and bs % 2 == 0:
            return i
        if ch in "\r\n":
            return None
        bs = 0
        i += 1
    return None


def find_escaped_header_close(value, n_bs, quote):
    i = 0
    n = len(value)
    while i < n:
        if value[i] != "\\":
            i += 1
            continue
        j = i
        bs = 0
        while j < n and value[j] == "\\":
            bs += 1
            j += 1
        if j < n and value[j] == quote and bs == n_bs:
            after = j + 1
            if after >= n or value[after] in " \t\r\n|":
                return i
            i = j + 1
            continue
        i = j + 1 if j < n else j
    return None


def scan_unquoted_header_value(value):
    i = 0
    n = len(value)
    while i < n:
        if value[i] in "\r\n|":
            return i
        if NEXT_H_RE.match(value, i):
            return i
        i += 1
    return n


def redact_headers(text):
    out = []
    cursor = 0
    while cursor < len(text):
        match = HEADER_RE.search(text, cursor)
        if not match:
            out.append(text[cursor:])
            break
        out.append(text[cursor:match.start()])
        pre = match.group("pre") or ""
        hdr = match.group("hdr")
        value = text[match.end():]
        if pre and not pre.startswith("\\"):
            rel = find_unescaped_quote_end(value, pre[-1])
            if rel is not None:
                out.append(pre + hdr + ": [REDACTED]" + pre)
                cursor = match.end() + rel + 1
                continue
        elif pre.startswith("\\"):
            n_bs = len(pre) - 1
            rel = find_escaped_header_close(value, n_bs, pre[-1])
            if rel is not None:
                close_len = n_bs + 1
                closing = value[rel:rel + close_len]
                out.append(pre + hdr + ": [REDACTED]" + closing)
                cursor = match.end() + rel + close_len
                continue
        rel = scan_unquoted_header_value(value)
        out.append(pre + hdr + ": [REDACTED]")
        cursor = match.end() + rel
    return "".join(out)


def scan_container(text, start):
    opener = text[start]
    if opener != "{" and opener != "[":
        return None
    stack = []
    i = start
    quote = None
    limit = len(text)
    while i < limit:
        ch = text[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch == '"' or ch == "'":
            quote = ch
            i += 1
            continue
        if ch == "{" or ch == "[":
            stack.append("}" if ch == "{" else "]")
        elif ch == "}" or ch == "]":
            if not stack or stack[-1] != ch:
                return None
            stack.pop()
            if not stack:
                return i + 1
        i += 1
    return None


def redact_containers(text):
    quote = '"'
    finder = re.compile(
        "(?i)(?:"
        + quote + "(" + SENSITIVE_KEY + ")" + quote + r"\s*:\s*"
        + r"|\\+" + quote + "(" + SENSITIVE_KEY + ")" + r"\\+" + quote + r"\s*[:=]\s*"
        + r"|\b(" + SENSITIVE_KEY + r")\s*[:=]\s*"
        + ")"
    )
    parts = []
    pos = 0
    redacted = quote + "[REDACTED]" + quote
    for match in finder.finditer(text):
        if match.start() < pos:
            continue
        if match.end() >= len(text) or (text[match.end()] != "{" and text[match.end()] != "["):
            continue
        if text.startswith("[REDACTED]", match.end()):
            continue
        end = scan_container(text, match.end())
        if end is None:
            end = len(text)
        parts.append(text[pos:match.end()])
        parts.append(redacted)
        pos = end
    parts.append(text[pos:])
    return "".join(parts)


def consume_scalar_span(s, allow_comma=True):
    n = len(s)
    marker = "[REDACTED]"
    if s.startswith(marker) and not s.startswith("[REDACTED_URL]") and not s.startswith("[REDACTED_url]"):
        i = len(marker)
    else:
        i = 0
    while i < n:
        c = s[i]
        if c == "$" and i + 1 < n and s[i + 1] in ("'", '"'):
            q = s[i + 1]
            j = i + 2
            while j < n:
                if s[j] == "\\" and j + 1 < n and s[j + 1] not in "\r\n":
                    j += 2
                    continue
                if s[j] == q:
                    j += 1
                    break
                j += 1
            i = j
            continue
        if c == "\\":
            j = i
            bs = 0
            while j < n and s[j] == "\\":
                bs += 1
                j += 1
            if j >= n:
                return n
            nxt = s[j]
            if nxt in "\r\n":
                return i
            if nxt in ("'", '"') and bs % 2 == 1:
                after = j + 1
                if i > 0 and nxt not in s[after:] and (after >= n or s[after] in " \t\r\n,}]"):
                    return i
                q = nxt
                k = j + 1
                while k < n:
                    t = k
                    bs2 = 0
                    while t < n and s[t] == "\\":
                        bs2 += 1
                        t += 1
                    if t < n and s[t] == q and bs2 % 2 == 1:
                        i = t + 1
                        break
                    if t >= n:
                        i = n
                        break
                    k = t + 1
                else:
                    i = n
                continue
            if nxt in ("'", '"') and bs % 2 == 0:
                i = j
                continue
            i = j + 1
            continue
        if c in ("'", '"'):
            nxt = s[i + 1] if i + 1 < n else ""
            if i > 0 and c not in s[i + 1:] and (nxt == "" or nxt in " \t\r\n,}]"):
                return i
            q = c
            j = i + 1
            bs = 0
            while j < n:
                if s[j] == "\\":
                    bs += 1
                    j += 1
                    continue
                if s[j] == q and bs % 2 == 0:
                    j += 1
                    break
                bs = 0
                j += 1
            i = j
            continue
        if c in " \t\r\n;}&]}":
            return i
        if c == ",":
            if not allow_comma:
                return i
            nxt = s[i + 1] if i + 1 < n else ""
            if nxt == "" or nxt in " \t\r\n,;}&]}\"'":
                return i
            i += 1
            continue
        i += 1
    return i


def _append_redacted(prefix):
    if prefix.endswith((" ", "\t", "=")):
        return prefix + "[REDACTED]"
    return prefix + " [REDACTED]"


def _curl_accept(prefix, consumed):
    if not consumed:
        return False
    low = prefix.lower()
    if "curl" in low or "--user" in low:
        return True
    return (
        ":" in consumed
        or consumed.startswith(("'", '"', "\\", "[REDACTED]"))
    )


def _replace_with_consumer(text, regex, accept, json_value=False):
    out = []
    cursor = 0
    while cursor < len(text):
        match = regex.search(text, cursor)
        if not match:
            out.append(text[cursor:])
            break
        if match.end() == match.start():
            out.append(text[cursor:cursor + 1])
            cursor += 1
            continue
        value = text[match.end():]
        if (value.startswith("{") or value.startswith("[")) and not value.startswith("[REDACTED]"):
            end = scan_container(text, match.end())
            out.append(text[cursor:match.start()])
            if json_value:
                out.append('"' + match.group(1) + '":"[REDACTED]"')
            elif regex is ASSIGN_RE:
                out.append(match.group(1) + match.group(2) + "[REDACTED]")
            else:
                out.append(_append_redacted(match.group(0)))
            cursor = end if end is not None else len(text)
            continue
        if json_value:
            key = match.group(1)
            if key.lower() in HEADER_NAMES:
                out.append(text[cursor:match.end()])
                cursor = match.end()
                continue
        if not json_value and regex is ASSIGN_RE and match.group(1).lower() in HEADER_NAMES:
            out.append(text[cursor:match.end()])
            cursor = match.end()
            continue
        n = consume_scalar_span(value, allow_comma=not json_value)
        consumed = value[:n] if n else ""
        prefix = match.group(0)
        if not accept(prefix, consumed):
            out.append(text[cursor:match.start() + 1])
            cursor = match.start() + 1
            continue
        out.append(text[cursor:match.start()])
        if json_value:
            quote = re.match(r'\\*"', match.group(0)).group(0)
            out.append(match.group(0) + quote + "[REDACTED]" + quote)
        elif regex is ASSIGN_RE:
            out.append(match.group(1) + match.group(2) + "[REDACTED]")
        else:
            out.append(_append_redacted(prefix))
        cursor = match.end() + n
    return "".join(out)


def redact_json_scalars(text):
    return _replace_with_consumer(text, JSON_KEY_RE, lambda prefix, consumed: bool(consumed), json_value=True)


def redact_curl_user(text):
    return _replace_with_consumer(text, CURL_RE, _curl_accept, json_value=False)


def redact_cli_flags(text):
    return _replace_with_consumer(text, CLI_RE, lambda prefix, consumed: bool(consumed), json_value=False)


def redact_assignments(text):
    return _replace_with_consumer(text, ASSIGN_RE, lambda prefix, consumed: bool(consumed), json_value=False)


def redact_urls(text):
    text = re.sub(r"://[^/@\s]+:[^/@\s]+@", "://[REDACTED]@", text)
    text = re.sub(
        r"(?i)\b(https?|ftp|redis|amqp|postgres(?:ql)?|mysql|mongodb)://[^/@\s]+@",
        r"\1://[REDACTED]@",
        text,
    )
    return text


def redact_bearer(text):
    return re.sub(
        r"(?i)\b(Bearer|Basic)\s+(?:\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[A-Za-z0-9._~+/=-]+)",
        r"\1 [REDACTED]",
        text,
    )


def redact(text):
    text = redact_urls(text)
    text = normalize_sensitive_json_keys(text)
    text = redact_headers(text)
    text = redact_bearer(text)
    text = redact_containers(text)
    text = redact_json_scalars(text)
    text = redact_curl_user(text)
    text = redact_cli_flags(text)
    text = redact_assignments(text)
    return text

def safe_decode(s):
    if isinstance(s, bytes):
        return s.decode("utf-8", "replace")
    try:
        return os.fsencode(s).decode("utf-8", "replace")
    except Exception:
        return s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")

def sanitize(text):
    return re.sub(r"[\x00-\x1f\x7f]", " ", text)

def trunc_utf8(text: str, max_bytes: int) -> str:
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text
    return raw[:max_bytes].decode("utf-8", errors="ignore")

raw_stage, raw_category, raw_summary = sys.stdin.buffer.read().split(b"\0", 2)
stage = trunc_utf8(sanitize(redact(safe_decode(raw_stage))), 120)
try:
    rc = int(sys.argv[1])
    if rc == 0:
        rc = 1
except Exception:
    rc = 1
cat = trunc_utf8(sanitize(redact(safe_decode(raw_category))), 120)
msg = trunc_utf8(sanitize(redact(safe_decode(raw_summary))), 300)

payload = "AF_DIAG_FAILURE=" + json.dumps({"stage": stage, "exit_code": int(rc), "category": cat, "summary": msg}, ensure_ascii=False, separators=(",", ":"))
sys.stderr.write(payload + "\n")
PY
    else
        stage=$(printf '%s' "$stage" | _af_redact_without_python | LC_ALL=C tr '\000-\037\177' ' ' | LC_ALL=C tr -cd '\040-\176' | LC_ALL=C _af_truncate_receipt_field 120)
        cat=$(printf '%s' "$cat" | _af_redact_without_python | LC_ALL=C tr '\000-\037\177' ' ' | LC_ALL=C tr -cd '\040-\176' | LC_ALL=C _af_truncate_receipt_field 120)
        msg=$(printf '%s' "$msg" | _af_redact_without_python | LC_ALL=C tr '\000-\037\177' ' ' | LC_ALL=C tr -cd '\040-\176' | LC_ALL=C _af_truncate_receipt_field 300)
        stage="${stage//\\/\\\\}"
        stage="${stage//\"/\\\"}"
        cat="${cat//\\/\\\\}"
        cat="${cat//\"/\\\"}"
        msg="${msg//\\/\\\\}"
        msg="${msg//\"/\\\"}"
        printf 'AF_DIAG_FAILURE={"stage":"%s","exit_code":%d,"category":"%s","summary":"%s"}\n' "$stage" "$rc" "$cat" "$msg" >&2
    fi
}
af_cleanup_job_scratch() {
    local exit_code="${1:-$?}"
    if [[ -n "${AF_JOB_SCRATCH_DIR:-}" && -d "${AF_JOB_SCRATCH_DIR}" ]]; then
        if [[ "${AF_PRESERVE_SCRATCH:-0}" == "1" ]]; then
            return "$exit_code"
        fi
        if [[ "$exit_code" -ne 0 && ( -d "${AF_JOB_SCRATCH_DIR}/rollback" || -d "${AF_JOB_SCRATCH_DIR}/backup" ) ]]; then
            return "$exit_code"
        fi
        rm -rf --one-file-system "${AF_JOB_SCRATCH_DIR}" 2>/dev/null || true
    fi
    return "$exit_code"
}

af_prepare_job_scratch() {
    local app_id="${1:?af_prepare_job_scratch requires app_id}"
    local min_free_mb="${2:-1024}"
    local min_free_inodes="${3:-4096}"
    local scratch_root="${AF_JOB_SCRATCH_ROOT:-/var/tmp/aetherflow-scratch}"
    local expected_uid="0"
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        expected_uid="${EUID:-$(id -u)}"
    fi

    if [[ -L "$scratch_root" ]]; then
        af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} is a symlink"
        exit 28
    fi

    if [[ -e "$scratch_root" ]]; then
        if [[ ! -d "$scratch_root" ]]; then
            af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} is not a directory"
            exit 28
        fi
        local owner_uid
        owner_uid="$(stat -c '%u' "$scratch_root" 2>/dev/null || stat -f '%u' "$scratch_root" 2>/dev/null || true)"
        if [[ "$owner_uid" != "$expected_uid" ]]; then
            af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} owner ${owner_uid} does not match expected uid ${expected_uid}"
            exit 28
        fi
        chmod 0700 "$scratch_root" || {
            af_write_failure_receipt 28 "preflight_capacity" "Failed to enforce permissions on ${scratch_root}"
            exit 28
        }
    else
        mkdir -p -m 0700 "$scratch_root" || {
            af_write_failure_receipt 28 "preflight_capacity" "Failed to create scratch root ${scratch_root}"
            exit 28
        }
    fi

    local fs_type fs_lower
    if ! fs_type="$(stat -f -c '%T' "$scratch_root" 2>/dev/null)"; then
        af_write_failure_receipt 28 "preflight_capacity" "Failed to determine filesystem type for ${scratch_root}"
        return 1
    fi
    fs_lower="${fs_type,,}"
    if [[ -z "$fs_lower" || "$fs_lower" == *"unknown"* || "$fs_lower" == 0x* || "$fs_lower" == *"0x"* ]]; then
        af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} filesystem type (${fs_type:-empty}) is not allowed or unknown"
        return 1
    fi
    if [[ "$fs_lower" == *"tmpfs"* || "$fs_lower" == *"ramfs"* ]]; then
        if [[ "${AF_ALLOW_TMPFS_SCRATCH:-0}" != "1" ]]; then
            af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} filesystem type (${fs_type}) is not allowed or unknown"
            return 1
        fi
    fi

    if ! check_disk_space "$scratch_root" "${min_free_mb:-512}"; then
        af_write_failure_receipt 28 "preflight_capacity" "Scratch root ${scratch_root} failed check_disk_space validation"
        return 1
    fi

    local check_path target_path
    for check_path in "$scratch_root" /opt /var/lib "${AF_BACKUP_ROOT:-/var/backups}"; do
        target_path="$check_path"
        while [[ ! -e "$target_path" && "$target_path" != "/" ]]; do
            target_path="$(dirname "$target_path")"
        done
        local free_mb free_inodes
        free_mb="$(df -Pm "$target_path" 2>/dev/null | awk 'NR==2 {print $4}')" || {
            af_write_failure_receipt 28 "preflight_capacity" "Failed to check disk capacity for ${check_path}"
            exit 28
        }
        free_inodes="$(df -Pi "$target_path" 2>/dev/null | awk 'NR==2 {print $4}')" || {
            af_write_failure_receipt 28 "preflight_capacity" "Failed to check inode capacity for ${check_path}"
            exit 28
        }
        if [[ -z "$free_mb" || -z "$free_inodes" || ! "$free_mb" =~ ^[0-9]+$ || ! "$free_inodes" =~ ^[0-9]+$ || "$free_mb" -lt "$min_free_mb" || "$free_inodes" -lt "$min_free_inodes" ]]; then
            af_write_failure_receipt 28 "preflight_capacity" "Insufficient disk or inode capacity on ${check_path} (free: ${free_mb:-0}MB / ${free_inodes:-0} inodes, required: ${min_free_mb}MB / ${min_free_inodes} inodes)"
            exit 28
        fi
    done

    local scratch_dir
    scratch_dir="$(mktemp -d "${scratch_root}/${app_id}.XXXXXXXXXX")" || {
        af_write_failure_receipt 28 "preflight_capacity" "Failed to create scratch directory in ${scratch_root}"
        exit 28
    }
    chmod 0700 "$scratch_dir" || {
        af_write_failure_receipt 28 "preflight_capacity" "Failed to enforce permissions on scratch directory ${scratch_dir}"
        exit 28
    }

    AF_JOB_SCRATCH_DIR="$scratch_dir"
    export AF_JOB_SCRATCH_DIR
    trap 'set +e; af_cleanup_job_scratch "$?" || true' EXIT
    printf '%s\n' "$scratch_dir"
}

report_progress() {
    local pct="${1:-0}"
    local msg="${2:-}"
    printf '[PROGRESS:%d] %s\n' "$pct" "$msg"
    log_info "[PROGRESS:$pct] $msg"
}

github_latest_tag() {
    local repo="$1"
    local fallback="${2:-}"
    local strip_v="${3:-true}"
    if [[ "$fallback" == "true" || "$fallback" == "false" ]] && [[ $# -eq 2 ]]; then
        strip_v="$fallback"
        fallback=""
    fi
    local tag=""
    local eff_url=""

    if [[ -n "${AF_TARGET_VERSION:-}" ]]; then
        tag="${AF_TARGET_VERSION}"
        if [[ "$strip_v" == "true" ]]; then
            tag="${tag#release-v}"
            tag="${tag#[vV]}"
        else
            tag="${tag#release-}"
            if [[ "$tag" =~ ^[0-9] ]]; then
                tag="v${tag}"
            elif [[ "$tag" =~ ^V([0-9].*)$ ]]; then
                tag="v${BASH_REMATCH[1]}"
            fi
        fi
        printf '%s\n' "$tag"
        return 0
    fi

    local auth_header=()
    local token="${AF_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
    if [[ -n "$token" ]]; then
        auth_header=(-H "Authorization: Bearer $token")
    fi

    eff_url="$(curl -fsSL "${auth_header[@]}" -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest" 2>/dev/null || true)"
    if [[ "$eff_url" == *"/releases/tag/"* ]]; then
        tag="${eff_url##*/releases/tag/}"
        tag="${tag%%\?*}"
        tag="${tag%%#*}"
    fi

    if [[ -z "$tag" ]]; then
        tag="$(curl -fsSL "${auth_header[@]}" "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
            | grep -oP '"tag_name":\s*"\K[^"]+' | head -n1 || true)"
    fi

    if [[ -z "$tag" ]]; then
        if [[ "${AF_ALLOW_RELEASE_FALLBACK:-0}" == "1" && -n "$fallback" ]]; then
            if command -v print_warning >/dev/null 2>&1; then
                print_warning "Failed to query GitHub releases for ${repo}; using explicit opt-in fallback ${fallback}"
            elif command -v print_warn >/dev/null 2>&1; then
                print_warn "Failed to query GitHub releases for ${repo}; using explicit opt-in fallback ${fallback}"
            fi
            tag="$fallback"
        else
            print_error "Failed to discover latest GitHub release for ${repo}"
            return 1
        fi
    fi

    if [[ "$strip_v" == "true" ]]; then
        tag="${tag#release-v}"
        tag="${tag#[vV]}"
    else
        tag="${tag#release-}"
        if [[ "$tag" =~ ^[0-9] ]]; then
            tag="v${tag}"
        elif [[ "$tag" =~ ^V([0-9].*)$ ]]; then
            tag="v${BASH_REMATCH[1]}"
        fi
    fi

    printf '%s\n' "$tag"
}

github_highest_semver_tag() {
    local repo="$1"
    local fallback="${2:-}"
    local strip_v="${3:-true}"
    if [[ "$fallback" == "true" || "$fallback" == "false" ]] && [[ $# -eq 2 ]]; then
        strip_v="$fallback"
        fallback=""
    fi
    local tag=""

    if [[ -n "${AF_TARGET_VERSION:-}" ]]; then
        tag="${AF_TARGET_VERSION}"
        if [[ "$strip_v" == "true" ]]; then
            tag="${tag#release-v}"
            tag="${tag#[vV]}"
        else
            tag="${tag#release-}"
            if [[ "$tag" =~ ^[0-9] ]]; then
                tag="v${tag}"
            elif [[ "$tag" =~ ^V([0-9].*)$ ]]; then
                tag="v${BASH_REMATCH[1]}"
            fi
        fi
        printf '%s\n' "$tag"
        return 0
    fi

    local ls_tag
    ls_tag="$(git ls-remote --tags --refs "https://github.com/${repo}.git" 2>/dev/null \
        | sed -E 's#^[0-9a-fA-F]+[[:space:]]+refs/tags/##' \
        | grep -E '^v?[0-9]+\.[0-9]+(\.[0-9]+)*$' \
        | sort -V | tail -n1 || true)"
    if [[ -n "$ls_tag" ]]; then
        tag="$ls_tag"
        if [[ "$strip_v" == "true" ]]; then
            tag="${tag#release-v}"
            tag="${tag#[vV]}"
        else
            tag="${tag#release-}"
            if [[ "$tag" =~ ^[0-9] ]]; then
                tag="v${tag}"
            elif [[ "$tag" =~ ^V([0-9].*)$ ]]; then
                tag="v${BASH_REMATCH[1]}"
            fi
        fi
        printf '%s\n' "$tag"
        return 0
    fi

    github_latest_tag "$repo" "$fallback" "$strip_v"
}

sync_node_global_bins() {
    local npm_prefix=""
    if command_exists npm; then
        npm_prefix="$(npm config get prefix 2>/dev/null || true)"
    fi
    local bin_dir
    for bin_dir in "/usr/local/nodejs/bin" "${npm_prefix:+${npm_prefix}/bin}" "/usr/local/bin"; do
        [[ -n "$bin_dir" && -d "$bin_dir" ]] || continue
        case ":$PATH:" in
            *":${bin_dir}:"*) ;;
            *) export PATH="${bin_dir}:$PATH" ;;
        esac
        local bin_path bin_name
        for bin_path in "$bin_dir"/*; do
            [[ -e "$bin_path" && -x "$bin_path" && ! -d "$bin_path" ]] || continue
            bin_name="$(basename "$bin_path")"
            if [[ "$bin_dir" != "/usr/local/bin" && ! -e "/usr/local/bin/${bin_name}" ]]; then
                ln -sf "$bin_path" "/usr/local/bin/${bin_name}" 2>/dev/null || true
            fi
        done
    done
    local core_bin
    for core_bin in node npm npx yarn yarnpkg pnpm corepack; do
        if [[ ! -x "/usr/bin/${core_bin}" ]]; then
            if [[ -x "/usr/local/bin/${core_bin}" ]]; then
                ln -sf "/usr/local/bin/${core_bin}" "/usr/bin/${core_bin}" 2>/dev/null || true
            elif [[ -x "/usr/local/nodejs/bin/${core_bin}" ]]; then
                ln -sf "/usr/local/nodejs/bin/${core_bin}" "/usr/bin/${core_bin}" 2>/dev/null || true
            fi
        fi
    done
}

ensure_node() {
    local want_major="${1:-20}"
    local have_major=0
    # Native addons and Git prepare scripts need these on already-provisioned
    # Node hosts too, not just when Node itself is first installed.
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        ca-certificates git build-essential python3 python3-setuptools pkg-config >> "$LOGFILE" 2>&1
    if command_exists node; then
        have_major=$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1 || echo 0)
    fi
    if [[ "${have_major:-0}" -lt "$want_major" ]]; then
        local nodesource_sha256="${AF_NODESOURCE_BOOTSTRAP_SHA256:-2c4c6683a17b6f4128898a7b521e3c8bb725a99ffaf1b5e32ac97c6fa7d381be}"
        fetch_and_run "https://deb.nodesource.com/setup_${want_major}.x" "$nodesource_sha256" || return 1
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs >> "$LOGFILE" 2>&1
    fi
    sync_node_global_bins
}

systemd_unit_inactive() {
    local unit="$1" require_disabled="${2:-false}" state line load_state="" active_state="" main_pid="" unit_file_state=""
    state="$(systemctl show --property=LoadState --property=ActiveState --property=MainPID --property=UnitFileState -- "$unit" 2>/dev/null)" || return 1
    while IFS= read -r line; do
        case "$line" in
            LoadState=*) load_state="${line#LoadState=}" ;;
            ActiveState=*) active_state="${line#ActiveState=}" ;;
            MainPID=*) main_pid="${line#MainPID=}" ;;
            UnitFileState=*) unit_file_state="${line#UnitFileState=}" ;;
        esac
    done <<< "$state"
    case "$active_state" in
        inactive|failed) [[ -z "$main_pid" || "$main_pid" == 0 ]] || return 1 ;;
        *) return 1 ;;
    esac
    [[ "$load_state" == loaded || "$load_state" == masked || "$load_state" == not-found ]] || return 1
    if [[ "$require_disabled" == true ]]; then
        case "$unit_file_state:$load_state" in
            disabled:*|static:*|indirect:*|generated:*|masked:*|not-found:*|:not-found) ;;
            *) return 1 ;;
        esac
    fi
}

quiesce_services_for_rollback() {
    local unit stop_status failed=false
    local backup="${AF_ROLLBACK_BACKUP:-${BACKUP_DIR:-${RUNTIME_BACKUP:-${ABS_BACKUP_DIR:-${AF_STATE_BACKUP:-${AF_ARCHIVE_BACKUP:-unknown}}}}}}"
    for unit in "$@"; do
        stop_status=0
        systemctl stop -- "$unit" >> "${LOGFILE:-/dev/null}" 2>&1 || stop_status=$?
        if [[ "$stop_status" -ne 0 ]]; then
            print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
            failed=true
            continue
        fi

        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
            failed=true
            continue
        fi

        local is_active_rc=0 is_active_output=""
        is_active_output="$(systemctl is-active "$unit" 2>/dev/null)" || is_active_rc=$?

        if [[ "$is_active_rc" -eq 0 ]]; then
            print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
            failed=true
            continue
        fi

        case "$is_active_output" in
            active|activating|deactivating|reloading|maintenance)
                print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
                failed=true
                continue
                ;;
        esac

        local show_raw=""
        show_raw="$(systemctl show --property=ActiveState -- "$unit" 2>/dev/null || true)"

        if [[ "$show_raw" =~ ActiveState= ]]; then
            if ! systemd_unit_inactive "$unit"; then
                print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
                failed=true
                continue
            fi
            if [[ "$is_active_rc" -ne 3 && "$is_active_output" != "inactive" && "$is_active_output" != "failed" ]]; then
                print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
                failed=true
                continue
            fi
        else
            if [[ "$is_active_rc" -ne 3 || ( "$is_active_output" != "inactive" && "$is_active_output" != "failed" ) ]]; then
                print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
                failed=true
                continue
            fi
        fi
    done
    [[ "$failed" == false ]]
}

stop_systemd_unit() {
    local unit stop_status
    for unit in "$@"; do
        stop_status=0
        systemctl stop -- "$unit" >> "${LOGFILE:-/dev/null}" 2>&1 || stop_status=$?
        systemctl reset-failed -- "$unit" >> "${LOGFILE:-/dev/null}" 2>&1 || true
        if [[ "$stop_status" == 0 ]]; then
            continue
        fi
        if systemd_unit_inactive "$unit"; then
            continue
        fi
        print_error "Cannot prove ${unit} is stopped; refusing teardown and data deletion."
        return 1
    done
}

purge_systemd_unit() {
    local unit
    local -a units=() triggers=()
    for unit in "$@"; do
        [[ "$unit" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.@:-]*$ && "$unit" != *..* ]] || return 1
        case "$unit" in
            *.service|*.timer|*.socket) ;;
            *) unit="${unit}.service" ;;
        esac
        case "$unit" in
            *.timer|*.socket) triggers+=("$unit") ;;
            *) units+=("$unit") ;;
        esac
    done
    units=("${triggers[@]}" "${units[@]}")
    for unit in "${units[@]}"; do
        stop_systemd_unit "$unit" || return 1
    done
    for unit in "${units[@]}"; do
        if ! systemctl disable -- "$unit" >/dev/null 2>&1; then
            systemd_unit_inactive "$unit" true || return 1
        fi
    done
    for unit in "${units[@]}"; do
        if ! systemctl reset-failed -- "$unit" >> "${LOGFILE:-/dev/null}" 2>&1; then
            systemd_unit_inactive "$unit" true || return 1
        fi
        rm -f "/etc/systemd/system/${unit}" || return 1
        rm -rf "/etc/systemd/system/${unit}.d" || return 1
    done
    systemctl daemon-reload
}

verify_systemd_service_active() {
    local unit="$1"
    if ! systemctl is-active --quiet "$unit"; then
        print_error "Service ${unit} is not active."
        return 1
    fi
}

resolve_app_readiness_path() {
    local app_name="${1,,}" explicit_path="${2:-}"
    app_name="${app_name%.service}"
    app_name="${app_name#af-}"
    case "$app_name:$explicit_path" in
        transmission*:/transmission/web/|transmission*:/transmission/web) printf '%s\n' /transmission/rpc; return 0 ;;
    esac
    if [[ -n "$explicit_path" && "$explicit_path" != / && "$explicit_path" != /ping ]]; then
        printf '%s\n' "$explicit_path"
        return 0
    fi
    case "$app_name" in
        gitea*|autobrr*) printf '%s\n' /api/healthz ;;
        nzbget*) printf '%s\n' /jsonrpc/version ;;
        transmission*) printf '%s\n' /transmission/rpc ;;
        filebrowser*) printf '%s\n' /health ;;
        kavita*|grafana*) printf '%s\n' /api/health ;;
        notifiarr*) printf '%s\n' /api/version ;;
        autoscan*) printf '%s\n' / ;;
        sonarr*|radarr*|lidarr*|readarr*|prowlarr*|navidrome*|audiobookshelf*) printf '%s\n' /ping ;;
        prometheus*) printf '%s\n' /-/healthy ;;
        syncthing*) printf '%s\n' /rest/noauth/health ;;
        netdata*) printf '%s\n' /api/v1/info ;;
        jellyfin*|emby*) printf '%s\n' /System/Ping ;;
        plex*) printf '%s\n' /identity ;;
        sabnzbd*) printf '%s\n' '/api?mode=version' ;;
        bazarr*) printf '%s\n' /api/system/health ;;
        tautulli*) printf '%s\n' /status ;;
        overseerr*|jellyseerr*) printf '%s\n' /api/v1/status ;;
        vaultwarden*) printf '%s\n' /alive ;;
        n8n*) printf '%s\n' /healthz ;;
        nextcloud*) printf '%s\n' /status.php ;;
        *) printf '%s\n' "${explicit_path:-/}" ;;
    esac
}

application_readiness_url() {
    safe_config_python "$@" <<'PYEOF'
import os, re, sys, xml.etree.ElementTree as ET
app, port = sys.argv[1:]
host, base, endpoint = '127.0.0.1', '', '/'
def read_optional(filename):
    return safe_read_text(filename) if os.path.lexists(filename) else ''
if app in ('sonarr', 'radarr', 'lidarr', 'readarr', 'prowlarr'):
    raw = read_optional('/var/lib/' + app + '/config.xml')
    if raw:
        config = ET.fromstring(raw)
        host, base = config.findtext('BindAddress', host), config.findtext('UrlBase', '')
    endpoint = '/ping'
elif app in ('bazarr', 'tautulli', 'sabnzbd'):
    filename, section, host_key, base_key, endpoint = {
        'bazarr': ('/var/lib/bazarr/config/config.ini', 'general', 'ip', 'base_url', '/api/system/health'),
        'tautulli': ('/var/lib/tautulli/config.ini', 'General', 'http_host', 'http_root', '/status'),
        'sabnzbd': ('/var/lib/sabnzbd/sabnzbd.ini', 'misc', 'host', 'url_base', '/api?mode=version'),
    }[app]
    raw = read_optional(filename)
    if raw:
        values, selected = {}, False
        for line in raw.splitlines():
            if line.lstrip().startswith('['):
                selected = line.strip().lower() == '[' + section.lower() + ']'
            elif selected:
                match = re.match(r'\s*([A-Za-z_]+)\s*=\s*(.*)', line)
                if match:
                    values[match.group(1).lower()] = match.group(2).strip().strip('\'"')
        host, base = values.get(host_key, host), values.get(base_key, '')
    elif app == 'bazarr':
        raw = read_optional('/var/lib/bazarr/config/config.yaml')
        general = re.search(r'(?m)^general:\s*\n((?:[ \t]+[^\n]*\n?)*)', raw)
        if general:
            def value(key, default):
                match = re.search(r'(?m)^\s+' + key + r':\s*([^\n#]*)', general.group(1))
                return match.group(1).strip().strip('\'"') if match else default
            host, base = value('ip', host), value('base_url', '')
elif app == 'overseerr':
    endpoint = '/api/v1/status'
base = (base or '').strip()
if base and not base.startswith('/'):
    base = '/' + base
if base and not re.fullmatch(r'/[A-Za-z0-9._/-]*', base):
    raise ValueError('Unsafe retained application URL base')
base = base.rstrip('/')
if any(part in ('.', '..') for part in base.split('/')) or '//' in base:
    raise ValueError('Unsafe retained application URL base')
host = (host or '127.0.0.1').strip().strip('\'"')
host = {'*': '127.0.0.1', '0.0.0.0': '127.0.0.1', '::': '[::1]', '[::]': '[::1]'}.get(host, host)
if not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]+', host):
    raise ValueError('Unsafe retained application listener')
if ':' in host and not host.startswith('['):
    host = '[' + host + ']'
print(f'http://{host}:{port}{base}{endpoint}')
PYEOF
}

wait_for_service_ready() {
    local unit="$1" port="$2" readiness_path="${3:-/}" attempts="${4:-30}" attempt app_name credentials="" http_status ready_url
    app_name="${unit,,}"
    app_name="${app_name%.service}"
    app_name="${app_name#af-}"
    if declare -F resolve_app_readiness_path >/dev/null; then
        readiness_path="$(resolve_app_readiness_path "$app_name" "${3:-}")"
    fi
    case "$app_name:$readiness_path" in
        sonarr:/ping|radarr:/ping|lidarr:/ping|readarr:/ping|prowlarr:/ping)
            readiness_path="$(application_readiness_url "$app_name" "$port")" || return 1 ;;
    esac
    case "$app_name" in
        transmission*) credentials="${TRANSMISSION_USER:-admin}:${TRANSMISSION_PASS:-${PASS:-}}" ;;
        nzbget*) credentials="${NZBGET_USER:-admin}:${NZBGET_PASS:-${PASS:-}}" ;;
    esac
    credentials="${credentials//\\/\\\\}"
    credentials="${credentials//\"/\\\"}"
    [[ "$credentials" != *$'\n'* && "$credentials" != *$'\r'* ]] || return 1
    [[ "$port" =~ ^[0-9]{1,5}$ && "$attempts" =~ ^[1-9][0-9]*$ ]] || return 1
    (( 10#$port > 0 && 10#$port <= 65535 )) || return 1
    case "$readiness_path" in
        http://*) ready_url="$readiness_path" ;;
        /*) ready_url="http://127.0.0.1:${port}${readiness_path}" ;;
        *) return 1 ;;
    esac
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if systemctl is-active --quiet "$unit"; then
            if [[ -n "$credentials" ]]; then
                if printf 'user = "%s"\n' "$credentials" | curl -K - -fsS --connect-timeout 2 --max-time 5 "$ready_url" >/dev/null 2>&1; then
                    return 0
                fi
                if [[ "$app_name" == transmission* && "$readiness_path" == /transmission/rpc ]]; then
                    if http_status="$(printf 'user = "%s"\n' "$credentials" | curl -K - -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}${readiness_path}" 2>/dev/null)"; then
                        case "$http_status" in 200|401|409) return 0 ;; esac
                    fi
                fi
            elif curl -fsS --connect-timeout 2 --max-time 5 "$ready_url" >/dev/null 2>&1; then
                return 0
            elif [[ "$app_name" =~ ^(bazarr|overseerr|tautulli|flaresolverr|sabnzbd|listenarr)$ ]]; then
                if http_status="$(curl -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$ready_url" 2>/dev/null)"; then
                    case "$http_status" in 200|204|401|403) return 0 ;; esac
                fi
            fi
        fi
        if (( attempt < attempts )); then sleep 1; fi
    done
    print_error "Service ${unit} did not become ready on port ${port}."
    return 1
}

purge_system_user() {
    local username="$1" database program status
    if [[ "${DELETE_DATA:-false}" != true && "${2:-}" != --force ]]; then
        log_info "Retaining system account ${username} because DELETE_DATA is false"
        return 0
    fi
    [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ && "$username" != root && "$username" != www-data ]] || return 1
    for database in passwd group; do
        if getent "$database" "$username" >/dev/null 2>&1; then
            if [[ "$database" == passwd ]]; then program=userdel; else program=groupdel; fi
            "$program" "$username" >/dev/null 2>&1 || return 1
        else
            status=$?
            [[ "$status" == 2 ]] || return 1
        fi
    done
    rm -rf "/home/${username}"
}

load_master_credentials() {
    local u="" p="" h="" creds_json generated=false
    if [[ -n "${MASTER_USER:-}" && -n "${MASTER_PASS:-}" && "$MASTER_PASS" != adminadmin ]]; then
        export MASTER_USER MASTER_PASS
        export MASTER_HA1="${MASTER_HA1:-$(printf '%s' "$MASTER_PASS" | md5sum | awk '{print $1}')}"
        return 0
    fi
    for creds_json in /var/lib/aetherflow/.master.creds /opt/AetherFlow/backend/data/.master.creds; do
        if [[ -f "$creds_json" ]]; then
            u="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("username",""))' "$creds_json" 2>/dev/null || true)"
            p="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("password",""))' "$creds_json" 2>/dev/null || true)"
            h="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("ha1",""))' "$creds_json" 2>/dev/null || true)"
            [[ -n "$u" && -n "$p" ]] && break
        fi
    done
    if [[ -z "$u" || -z "$p" ]] && [[ -f /install/.aetherflow.conf ]]; then
        u="$(bash -c 'source /install/.aetherflow.conf >/dev/null 2>&1; printf "%s" "${username:-}"' 2>/dev/null || true)"
        p="$(bash -c 'source /install/.aetherflow.conf >/dev/null 2>&1; printf "%s" "${passwd:-}"' 2>/dev/null || true)"
        h="$(bash -c 'source /install/.aetherflow.conf >/dev/null 2>&1; printf "%s" "${ha1pass:-}"' 2>/dev/null || true)"
    fi
    if [[ -z "$u" && -f /etc/apache2/master.txt ]]; then
        u="$(awk -F: 'NR==1 {print $1}' /etc/apache2/master.txt 2>/dev/null | tr -d '[:space:]' || true)"
    fi
    if [[ -z "$u" ]] && command -v sqlite3 >/dev/null 2>&1 && [[ -f /opt/AetherFlow/backend/data/aetherflow.sqlite ]]; then
        u="$(sqlite3 /opt/AetherFlow/backend/data/aetherflow.sqlite "SELECT username FROM users ORDER BY id ASC LIMIT 1;" 2>/dev/null | tr -d '[:space:]' || true)"
    fi
    if [[ -z "$p" && -n "$u" && -f "/root/${u}.info.db" ]]; then
        p="$(cut -d: -f2- "/root/${u}.info.db" 2>/dev/null | head -n1 | tr -d '\r\n' || true)"
    fi
    if [[ -z "$p" ]]; then
        local info_file
        info_file="$(ls -1 /root/*.info.db 2>/dev/null | head -n1 || true)"
        if [[ -n "$info_file" && -f "$info_file" ]]; then
            [[ -z "$u" ]] && u="$(cut -d: -f1 "$info_file" 2>/dev/null | head -n1 | tr -d '\r\n' || true)"
            p="$(cut -d: -f2- "$info_file" 2>/dev/null | head -n1 | tr -d '\r\n' || true)"
        fi
    fi
    if [[ -z "$p" ]]; then
        p="$(python3 -c 'import secrets; print(secrets.token_hex(16))' 2>/dev/null || openssl rand -hex 16)" || return $?
        [[ "$p" =~ ^[0-9a-f]{32}$ ]] || return 1
        h=""
        generated=true
    fi
    export MASTER_USER="${u:-admin}"
    export MASTER_PASS="$p"
    if [[ -z "$h" ]]; then
        h="$(printf '%s' "$MASTER_PASS" | md5sum | awk '{print $1}')"
    fi
    export MASTER_HA1="$h"
    if [[ "$generated" == true ]]; then
        python3 - /var/lib/aetherflow/.master.creds <<'PYEOF'
import errno, json, os, sys, tempfile
username, password, ha1 = (os.environ[name] for name in ('MASTER_USER', 'MASTER_PASS', 'MASTER_HA1'))
destination = sys.argv[1]
directory = os.path.dirname(destination)
temporary = None
try:
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix='.master.creds.', dir=directory)
    with os.fdopen(descriptor, 'w') as output:
        os.fchmod(output.fileno(), 0o600)
        json.dump({'username': username, 'password': password, 'ha1': ha1}, output)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, destination)
    temporary = None
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
except OSError as error:
    if error.errno not in (errno.EROFS, errno.ENODEV, errno.ENXIO):
        raise
finally:
    if temporary is not None:
        try:
            os.unlink(temporary)
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.EROFS, errno.ENODEV, errno.ENXIO):
                raise
PYEOF
    fi
}

generate_qbittorrent_pbkdf2() {
    if [[ -z "${1:-}" && -z "${MASTER_PASS:-}" ]]; then
        load_master_credentials || return $?
    fi
    local pass="${1:-${MASTER_PASS:-}}"
    [[ -n "$pass" ]] || return 1
    AF_SEED_PASS="$pass" python3 -c '
import os, hashlib, base64
pw = os.environ["AF_SEED_PASS"].encode("utf-8")
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac("sha512", pw, salt, 100000, 64)
print(f"@ByteArray({base64.b64encode(salt).decode()}:{base64.b64encode(dk).decode()})")
'
}

seed_servarr_master_user() {
    local app="$1"
    local port="$2"
    local api_ver="${3:-v3}"
    local cfg_xml="/var/lib/${app}/config.xml"
    local keep_secrets="${AF_KEEP_EXISTING_SECRETS:-0}"
    if declare -F keep_existing_secrets_enabled >/dev/null 2>&1 && keep_existing_secrets_enabled; then
        keep_secrets="1"
    fi
    AF_SEED_USER="$MASTER_USER" AF_SEED_PASS="${AF_CONFIG_PASS:-${AF_PASS:-$MASTER_PASS}}" AF_KEEP_SECRETS_FLAG="$keep_secrets" AF_FORCE_PASSWORD_ROTATION="${AF_FORCE_PASSWORD_ROTATION:-0}" AF_CONFIG_PASS="${AF_CONFIG_PASS:-${AF_PASS:-}}" python3 - "$app" "$port" "$api_ver" "$cfg_xml" >> "$LOGFILE" 2>&1 <<'PYEOF'
import sys, os, re, time, json, urllib.request

app, port, api_ver, cfg_xml = sys.argv[1:]
user, pw = os.environ["AF_SEED_USER"], os.environ["AF_SEED_PASS"]
keep_raw = str(os.environ.get("AF_KEEP_EXISTING_SECRETS") or os.environ.get("AF_KEEP_SECRETS_FLAG") or "").strip().lower()
keep_secrets = keep_raw in ("1", "true", "yes", "on")
rotate = (not keep_secrets) and (os.environ.get("AF_FORCE_PASSWORD_ROTATION") == "1" or bool(os.environ.get("AF_CONFIG_PASS")))
api_key = ""
url_base = ""
for _ in range(45):
    if os.path.exists(cfg_xml):
        raw = open(cfg_xml, "r", encoding="utf-8", errors="ignore").read()
        m = re.search(r"<ApiKey>([^<]+)</ApiKey>", raw)
        if m and m.group(1).strip():
            api_key = m.group(1).strip()
            base_match = re.search(r"<UrlBase>([^<]*)</UrlBase>", raw)
            url_base = base_match.group(1).strip() if base_match else ""
            if url_base and not url_base.startswith('/'):
                url_base = '/' + url_base
            if url_base and not re.fullmatch(r'/[A-Za-z0-9._/-]*', url_base):
                raise ValueError('Unsafe retained Servarr URL base')
            url_base = url_base.rstrip('/')
            if any(part in ('.', '..') for part in url_base.split('/')) or '//' in url_base:
                raise ValueError('Unsafe retained Servarr URL base')
            break
    time.sleep(1)

if not api_key:
    raise RuntimeError(f"Timed out waiting for {cfg_xml} ApiKey")

url = f"http://127.0.0.1:{port}{url_base}/api/{api_ver}/config/host"
headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}
cfg = None
for _ in range(45):
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            cfg = json.loads(resp.read().decode("utf-8"))
            break
    except Exception:
        time.sleep(1)

if not cfg:
    raise RuntimeError(f"Timed out waiting for {url}")

authentication_method = str(cfg.get("authenticationMethod") or "").strip().lower()
authentication_configured = authentication_method not in ("", "none") and bool(str(cfg.get("username") or "").strip())
if authentication_configured and not rotate:
    sys.exit(0)

cfg["authenticationMethod"] = "forms"
cfg["authenticationRequired"] = "enabled"
cfg["username"] = user
cfg["password"] = pw
cfg["passwordConfirmation"] = pw
cfg["analyticsEnabled"] = False

put_url = f"{url}/{cfg.get('id', 1)}"
req2 = urllib.request.Request(put_url, data=json.dumps(cfg).encode("utf-8"), headers=headers, method="PUT")
with urllib.request.urlopen(req2, timeout=10) as resp2:
    resp2.read()
PYEOF
}

seed_servarr_credentials() {
    seed_servarr_master_user "$@"
}

seed_jellyfin_master_user() {
    local port="${1:-8096}"
    local keep_secrets="${AF_KEEP_EXISTING_SECRETS:-0}"
    if declare -F keep_existing_secrets_enabled >/dev/null 2>&1 && keep_existing_secrets_enabled; then
        keep_secrets="1"
    fi
    if AF_SEED_USER="$MASTER_USER" AF_SEED_PASS="${AF_CONFIG_PASS:-${AF_PASS:-$MASTER_PASS}}" AF_SEED_CURRENT_PASS="$MASTER_PASS" AF_KEEP_SECRETS_FLAG="$keep_secrets" AF_FORCE_PASSWORD_ROTATION="${AF_FORCE_PASSWORD_ROTATION:-0}" AF_CONFIG_PASS="${AF_CONFIG_PASS:-${AF_PASS:-}}" AF_SEED_EXISTING="${PRE_INSTALL_PRESENT:-false}" AF_SEED_EXISTING_CONFIG="${EXISTING_CONFIG_PRESENT:-false}" python3 - "$port" >> "$LOGFILE" 2>&1 <<'PYEOF'
import os, sys, time, json, urllib.request

port = sys.argv[1]
user, pw = os.environ["AF_SEED_USER"], os.environ["AF_SEED_PASS"]
base = f"http://127.0.0.1:{port}"
headers = {
    "Content-Type": "application/json",
    "X-Emby-Authorization": 'MediaBrowser Client="AetherFlow", Device="Server", DeviceId="aetherflow-setup", Version="1.0.0"'
    }

pub = None
for _ in range(45):
    try:
        req = urllib.request.Request(f"{base}/System/Info/Public", headers=headers)
        with urllib.request.urlopen(req, timeout=5) as r:
            pub = json.loads(r.read().decode("utf-8"))
            break
    except Exception:
        time.sleep(1)

if not isinstance(pub, dict) or not pub:
    raise RuntimeError(f"Timed out waiting for {base}/System/Info/Public")
keep_raw = str(os.environ.get("AF_KEEP_EXISTING_SECRETS") or os.environ.get("AF_KEEP_SECRETS_FLAG") or "").strip().lower()
keep_secrets = keep_raw in ("1", "true", "yes", "on")
rotate = (not keep_secrets) and (os.environ.get("AF_FORCE_PASSWORD_ROTATION") == "1" or bool(os.environ.get("AF_CONFIG_PASS")))
if pub.get("StartupWizardCompleted") is True and not rotate:
    sys.exit(0)

def call(path, method="GET", body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(f"{base}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read().decode("utf-8")
        return json.loads(raw) if raw else None

if pub.get("StartupWizardCompleted") is True:
    authentication = call("/Users/AuthenticateByName", "POST", {"Username": user, "Pw": os.environ["AF_SEED_CURRENT_PASS"]})
    headers["X-Emby-Token"] = authentication["AccessToken"]
    call(f"/Users/{authentication['User']['Id']}/Password", "POST", {"CurrentPw": os.environ["AF_SEED_CURRENT_PASS"], "NewPw": pw})
    sys.exit(0)

startup_user = call("/Startup/User", "GET") or {}
existing_install = any(os.environ.get(name, "").lower() in ("true", "1", "yes") for name in ("AF_SEED_EXISTING", "AF_SEED_EXISTING_CONFIG"))
if existing_install and str(startup_user.get("Name") or "").strip() and not rotate:
    sys.exit(0)

cfg = call("/Startup/Configuration", "GET") or {
    "UICulture": "en-US",
    "MetadataCountryCode": "US",
    "PreferredMetadataLanguage": "en"
    }
call("/Startup/Configuration", "POST", cfg)
call("/Startup/User", "POST", {"Name": user, "Password": pw})
call("/Startup/RemoteAccess", "POST", {"EnableRemoteAccess": True, "EnableAutomaticPortMapping": False})
call("/Startup/Complete", "POST")
pub = call("/System/Info/Public")
if not isinstance(pub, dict) or pub.get("StartupWizardCompleted") is not True:
    raise RuntimeError("Server did not confirm completion of initial setup")
PYEOF
    then
        return 0
    else
        print_error "Jellyfin/Emby did not become reachable or initial user setup failed."
        return 1
    fi
}

load_master_credentials
