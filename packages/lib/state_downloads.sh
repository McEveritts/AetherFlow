# AetherFlow shared helpers: disk space, recovery roots, state transactions, and verified downloads.
# Sourced by packages/common.sh; do not execute directly.

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

af_resolve_recovery_root() {
    local explicit="${1:-}"
    if [[ -n "$explicit" ]]; then
        printf '%s\n' "$explicit"
        return 0
    fi
    if [[ -n "${AF_RECOVERY_ROOT:-}" ]]; then
        printf '%s\n' "${AF_RECOVERY_ROOT}"
        return 0
    fi
    if [[ -n "${AETHERFLOW_RECOVERY_ROOT:-}" ]]; then
        printf '%s\n' "${AETHERFLOW_RECOVERY_ROOT}"
        return 0
    fi
    local default_root="/var/backups/aetherflow-recovery"
    local fixture_root="${AETHERFLOW_FS_ROOT:-${AETHERFLOW_INSTALL_ROOT:-}}"
    if [[ -z "$fixture_root" && "${EUID:-$(id -u)}" -ne 0 ]]; then
        fixture_root="${AF_FIXTURE_ROOT:-${TEST_ROOT:-}}"
    fi
    if [[ -n "$fixture_root" ]]; then
        fixture_root="${fixture_root%/}"
        if [[ "$default_root" != "${fixture_root}/"* ]]; then
            printf '%s/%s\n' "$fixture_root" "${default_root#/}"
            return 0
        fi
    fi
    printf '%s\n' "$default_root"
}

af_prepare_recovery_root() {
    local requested
    requested="$(af_resolve_recovery_root "${1:-}")" || return 1
    local fixture_root="${AETHERFLOW_FS_ROOT:-${AETHERFLOW_INSTALL_ROOT:-}}"
    if [[ -z "$fixture_root" && "${EUID:-$(id -u)}" -ne 0 ]]; then
        fixture_root="${AF_FIXTURE_ROOT:-${TEST_ROOT:-}}"
    fi
    python3 - "$requested" "$fixture_root" <<'PYEOF'
import errno, os, stat, sys

target = sys.argv[1]
fixture_root = sys.argv[2]

def fail(msg):
    sys.stderr.write(f"ERROR: {msg}\n")
    raise SystemExit(1)

def parse_abs_parts(path, label):
    if not path or not path.startswith("/") or "\x00" in path or "\n" in path:
        fail(f"Invalid {label}: {path!r}")
    raw = path.split("/")
    if any(seg == ".." for seg in raw):
        fail(f"Parent traversal prohibited in {label}: {path}")
    return tuple(seg for seg in raw if seg and seg != ".")

target_parts = parse_abs_parts(target, "recovery root")
if not target_parts:
    fail(f"Refusing root directory as recovery root: {target}")

EPHEMERAL_PREFIXES = (
    ("tmp",),
    ("var", "tmp"),
    ("dev", "shm"),
    ("run",),
    ("var", "run"),
)
PROTECTED_EXACT = frozenset((
    (),
    ("var",),
    ("var", "backups"),
    ("var", "lib"),
    ("var", "log"),
    ("opt",),
    ("etc",),
    ("usr",),
    ("home",),
    ("root",),
))

euid = os.geteuid()
fixture_parts = parse_abs_parts(fixture_root, "fixture root") if fixture_root else ()
inside_fixture = bool(fixture_parts) and target_parts[:len(fixture_parts)] == fixture_parts
logical_parts = target_parts[len(fixture_parts):] if inside_fixture else target_parts
is_real_root = (euid == 0) and not inside_fixture

if logical_parts in PROTECTED_EXACT or target_parts in PROTECTED_EXACT:
    fail(f"Refusing protected directory as recovery root: {target}")
if target_parts in EPHEMERAL_PREFIXES:
    fail(f"Recovery root {target} must reside on persistent storage outside ephemeral tmp/run directories")
if is_real_root or inside_fixture:
    if any(logical_parts[:len(p)] == p for p in EPHEMERAL_PREFIXES):
        fail(f"Recovery root {target} must reside on persistent storage outside ephemeral tmp/run directories")
elif fixture_parts:
    if any(target_parts[:len(p)] == p for p in EPHEMERAL_PREFIXES):
        fail(f"Recovery root {target} must reside on persistent storage outside ephemeral tmp/run directories")

norm_target = "/" + "/".join(target_parts)
dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

def is_symlink_error(exc, path, dir_fd=None):
    if exc.errno == errno.ELOOP:
        return True
    if exc.errno == errno.ENOTDIR:
        try:
            st = os.lstat(path, dir_fd=dir_fd) if dir_fd is not None else os.lstat(path)
            return stat.S_ISLNK(st.st_mode)
        except OSError:
            return False
    return False

def open_dir_nofollow(path, label):
    try:
        return os.open(path, dir_flags)
    except OSError as exc:
        if is_symlink_error(exc, path):
            fail(f"{label} {path} is a symlink (symlink traversal prohibited)")
        fail(f"Failed to open {label} {path}: {exc.strerror}")

if is_real_root:
    start_path = "/"
    rel_parts = target_parts
    check_start = True
    check_ancestors = True
    forbidden_write = 0o022
elif inside_fixture:
    start_path = "/" + "/".join(fixture_parts)
    if not os.path.lexists(start_path):
        os.makedirs(start_path, exist_ok=True)
    rel_parts = logical_parts
    check_start = False
    check_ancestors = True
    forbidden_write = 0o022 if euid == 0 else 0o002
else:
    probe = "/" + "/".join(target_parts[:-1]) if len(target_parts) > 1 else "/"
    while probe != "/" and not os.path.lexists(probe):
        probe = os.path.dirname(probe) or "/"
    start_path = probe
    start_parts = parse_abs_parts(start_path, "recovery root ancestor") if start_path != "/" else ()
    rel_parts = target_parts[len(start_parts):]
    check_start = False
    check_ancestors = False
    forbidden_write = 0o002

if not rel_parts:
    fail(f"Invalid recovery root: {norm_target}")

curr_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)) if start_path == "/" else open_dir_nofollow(start_path, "Recovery root ancestor")
current = start_path
try:
    if check_start:
        st = os.fstat(curr_fd)
        mode = stat.S_IMODE(st.st_mode)
        if st.st_uid != euid or (mode & 0o022) != 0:
            fail(f"Recovery root ancestor {current} has untrusted ownership/mode (uid={st.st_uid}, mode=0o{mode:o})")
    for comp in rel_parts[:-1]:
        current = f"/{comp}" if current == "/" else f"{current}/{comp}"
        try:
            next_fd = os.open(comp, dir_flags, dir_fd=curr_fd)
        except OSError as exc:
            if exc.errno == errno.ENOENT:
                try:
                    os.mkdir(comp, 0o755, dir_fd=curr_fd)
                except FileExistsError:
                    pass
                except OSError as mk_exc:
                    fail(f"Failed to create recovery ancestor {current}: {mk_exc.strerror}")
                try:
                    next_fd = os.open(comp, dir_flags, dir_fd=curr_fd)
                except OSError as open_exc:
                    if is_symlink_error(open_exc, comp, dir_fd=curr_fd):
                        fail(f"Recovery root ancestor {current} is a symlink (symlink traversal prohibited)")
                    fail(f"Failed to open recovery ancestor {current}: {open_exc.strerror}")
            elif is_symlink_error(exc, comp, dir_fd=curr_fd):
                fail(f"Recovery root ancestor {current} is a symlink (symlink traversal prohibited)")
            else:
                fail(f"Failed to open recovery ancestor {current}: {exc.strerror}")
        os.close(curr_fd)
        curr_fd = next_fd
        if check_ancestors:
            st = os.fstat(curr_fd)
            mode = stat.S_IMODE(st.st_mode)
            if st.st_uid != euid:
                fail(f"Recovery root ancestor {current} is owned by uid {st.st_uid}, expected {euid}")
            if (mode & forbidden_write) != 0:
                fail(f"Recovery root ancestor {current} has unsafe writable permissions 0o{mode:o}")

    leaf = rel_parts[-1]
    current = f"/{leaf}" if current == "/" else f"{current}/{leaf}"
    created_leaf = False
    try:
        leaf_fd = os.open(leaf, dir_flags, dir_fd=curr_fd)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            try:
                os.mkdir(leaf, 0o700, dir_fd=curr_fd)
                created_leaf = True
            except FileExistsError:
                pass
            except OSError as mk_exc:
                fail(f"Failed to create recovery root {current}: {mk_exc.strerror}")
            try:
                leaf_fd = os.open(leaf, dir_flags, dir_fd=curr_fd)
            except OSError as open_exc:
                if is_symlink_error(open_exc, leaf, dir_fd=curr_fd):
                    fail(f"Recovery root {current} is a symlink (symlink traversal prohibited)")
                fail(f"Failed to open recovery root {current}: {open_exc.strerror}")
        elif is_symlink_error(exc, leaf, dir_fd=curr_fd):
            fail(f"Recovery root {current} is a symlink (symlink traversal prohibited)")
        else:
            fail(f"Failed to open recovery root {current}: {exc.strerror}")
    try:
        if created_leaf:
            os.fchmod(leaf_fd, 0o700)
        st = os.fstat(leaf_fd)
        mode_mask = 0o7777 if euid == 0 else 0o777
        mode = st.st_mode & mode_mask
        if st.st_uid != euid:
            fail(f"Recovery root {current} is owned by uid {st.st_uid}, expected {euid}")
        if mode != 0o700:
            fail(f"Recovery root {current} has permissions 0o{mode:o}, expected private 0o700")
    finally:
        os.close(leaf_fd)
finally:
    os.close(curr_fd)

sys.stdout.write(norm_target + "\n")
PYEOF
}

af_create_recovery_backup_dir() {
    local prefix="${1:?af_create_recovery_backup_dir requires prefix}"
    local recovery_root
    recovery_root="$(af_prepare_recovery_root "${2:-}")" || return 1
    python3 - "$recovery_root" "$prefix" <<'PYEOF'
import errno, os, re, secrets, stat, sys

root, prefix = sys.argv[1], sys.argv[2]

def fail(msg):
    sys.stderr.write(f"ERROR: {msg}\n")
    raise SystemExit(1)

if not re.fullmatch(r"[A-Za-z0-9._-]+", prefix) or prefix in (".", "..") or ".." in prefix:
    fail(f"Invalid recovery backup prefix: {prefix!r}")

euid = os.geteuid()
dir_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
mode_mask = 0o7777 if euid == 0 else 0o777

try:
    root_fd = os.open(root, dir_flags)
except OSError as exc:
    if exc.errno == errno.ELOOP or (exc.errno == errno.ENOTDIR and os.path.islink(root)):
        fail(f"Recovery root {root} is a symlink (symlink traversal prohibited)")
    fail(f"Failed to open recovery root {root}: {exc.strerror}")

try:
    rst = os.fstat(root_fd)
    if rst.st_uid != euid or (rst.st_mode & mode_mask) != 0o700:
        fail(f"Recovery root {root} failed ownership/permission verification (uid={rst.st_uid}, mode=0o{rst.st_mode & mode_mask:o})")
    for _ in range(32):
        name = f"{prefix}{secrets.token_hex(6)}"
        try:
            os.mkdir(name, 0o700, dir_fd=root_fd)
        except FileExistsError:
            continue
        except OSError as exc:
            fail(f"Failed to create recovery backup {root}/{name}: {exc.strerror}")
        try:
            child_fd = os.open(name, dir_flags, dir_fd=root_fd)
        except OSError as exc:
            try:
                os.rmdir(name, dir_fd=root_fd)
            except OSError:
                pass
            fail(f"Failed to verify created recovery backup {root}/{name}: {exc.strerror}")
        try:
            os.fchmod(child_fd, 0o700)
            cst = os.fstat(child_fd)
            cmode = cst.st_mode & mode_mask
            if cst.st_uid != euid or cmode != 0o700:
                try:
                    os.rmdir(name, dir_fd=root_fd)
                except OSError:
                    pass
                fail(f"Created recovery backup {root}/{name} has unexpected ownership/mode (uid={cst.st_uid}, mode=0o{cmode:o})")
        finally:
            os.close(child_fd)
        sys.stdout.write(f"{root}/{name}\n")
        raise SystemExit(0)
    fail(f"Exhausted unique recovery backup names under {root}")
finally:
    os.close(root_fd)
PYEOF
}

restore_state_snapshot() {
    restore_app_state "$@"
}

begin_state_transaction() {
    local unit="$1" port="$2" readiness_path="$3" entry
    shift 3
    declare -ag AF_STATE_UNITS=()
    read -r -a AF_STATE_UNITS <<< "$unit"
    AF_STATE_UNIT=""
    if (( ${#AF_STATE_UNITS[@]} > 0 )); then
        AF_STATE_UNIT="${AF_STATE_UNITS[-1]}"
    fi
    AF_STATE_PREVIOUS_UNITS=()
    AF_STATE_PORT="$port"
    AF_STATE_READINESS_PATH="$readiness_path"
    AF_STATE_WAS_ACTIVE=false
    AF_STATE_SNAPSHOT_READY=false
    AF_APT_REINSTALL_PACKAGES=()
    AF_APT_TRANSACTION_PACKAGES=()
    AF_APT_LOCKSTEP_PACKAGES=()
    AF_APT_PRIMARY_PACKAGE=""
    AF_APT_TARGET_VERSION=""
    AF_APT_LOCAL_DEB=false
    INSTALL_COMMITTED=false
    local staging_root
    staging_root="$(af_prepare_recovery_root "${AF_TRANSACTION_ROOT:-}")" || return 1
    if ! check_disk_space "$staging_root" 512; then
        if declare -F af_write_failure_receipt >/dev/null; then
            af_write_failure_receipt 28 "preflight_capacity" "Insufficient disk space in transaction recovery directory ${staging_root}"
        fi
        print_error "Insufficient disk space in transaction recovery directory ${staging_root}"
        return 1
    fi
    AF_STATE_BACKUP="$(af_create_recovery_backup_dir "af-state-" "$staging_root")" || return 1
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
    local -a stop_units=()
    local idx
    for (( idx=${#AF_STATE_UNITS[@]} - 1; idx>=0; idx-- )); do
        stop_units+=("${AF_STATE_UNITS[$idx]}")
    done
    if (( ${#stop_units[@]} > 0 )); then
        stop_systemd_unit "${stop_units[@]}" || return 1
    fi
    snapshot_state_dirs "$AF_STATE_BACKUP" "$@" "$(lock_path "$PACKAGE_NAME")" || return 1
    AF_STATE_SNAPSHOT_READY=true
}

cleanup_state_transaction() {
    local status="$1" restore_failed=false unit idx
    local -a state_units=("${AF_STATE_UNITS[@]}") stop_units=()
    trap - EXIT INT TERM
    set +e
    if [[ "${INSTALL_COMMITTED:-false}" != true ]]; then
        [[ "$status" -ne 0 ]] || status=1
        if [[ "${AF_STATE_SNAPSHOT_READY:-false}" == true ]]; then
            for (( idx=${#state_units[@]} - 1; idx>=0; idx-- )); do
                stop_units+=("${state_units[$idx]}")
            done
            if ! quiesce_services_for_rollback "${stop_units[@]}"; then
                restore_failed=true
            elif ! restore_state_snapshot "$AF_STATE_BACKUP"; then
                restore_failed=true
            elif [[ -d "$AF_TX_DIR/apt-packages" ]]; then
                rollback_apt_packages || restore_failed=true
                if [[ "$AF_APT_ROLLBACK_MUTATED" == true ]]; then
                    if ! quiesce_services_for_rollback "${stop_units[@]}" || ! restore_state_snapshot "$AF_STATE_BACKUP"; then
                        restore_failed=true
                    fi
                fi
            fi
            af_logged systemctl daemon-reload || restore_failed=true
        fi
        if [[ "$restore_failed" == false && "${AF_STATE_WAS_ACTIVE:-false}" == true && ( "${AF_STATE_SNAPSHOT_READY:-false}" != true || "${AF_STATE_RESTART_ON_ROLLBACK:-false}" == true ) ]]; then
            for unit in "${AF_STATE_PREVIOUS_UNITS[@]}"; do
                af_logged systemctl start "$unit" || restore_failed=true
            done
        fi
    fi
    if [[ "${INSTALL_COMMITTED:-false}" != true && "$status" -ne 0 && "${AF_STATE_SNAPSHOT_READY:-false}" == true && "$restore_failed" == false && "${AF_STATE_RESTART_ON_ROLLBACK:-false}" != true ]]; then
        if (( ${#state_units[@]} > 0 )); then
            log_warn "Previous state restored; ${state_units[*]} left stopped after the failed package update"
        else
            log_warn "Previous state restored after the failed package update"
        fi
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
    local autoscan_release=false
    if [[ "$app_id" == autoscan && "$source_url" == https://github.com/Cloudbox/autoscan/releases/download/* ]]; then
        autoscan_release=true
    fi
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
                if [[ "$autoscan_release" == true && "${manifest##*/}" == checksums.txt && "$digest" =~ ^[0-9a-fA-F]{128}$ ]]; then
                    local actual_sha512=""
                    if ! actual_sha512="$(sha512sum -- "$file_path")"; then
                        print_error "$source_url SHA-512 verification failed"
                        return 1
                    fi
                    actual_sha512="${actual_sha512%% *}"
                    if [[ "$actual_sha512" != "${digest,,}" ]]; then
                        print_error "$source_url SHA-512 digest mismatch"
                        return 1
                    fi
                else
                    verify_sha256 "$file_path" "$digest" "$source_url" || return 1
                fi
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
        release_metadata="$(af_logged_stderr af_github_curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 2 --max-time 4 "https://api.github.com/repos/$release_repository/releases/tags/$release_tag")" || release_metadata=""
    fi
    if [[ -n "$release_metadata" && -n "$source_url" ]]; then
        local release_digest
        if ! release_digest="$(python3 -c '
import json, sys
release = json.load(sys.stdin)
for asset in release.get("assets", []):
    if asset.get("browser_download_url") == sys.argv[1] or asset.get("name") == sys.argv[2]:
        digest = asset.get("digest")
        if digest:
            if not digest.startswith("sha256:"):
                raise ValueError("Unsupported release asset digest")
            print(digest.removeprefix("sha256:"))
' "$source_url" "$basename_url" <<< "$release_metadata"
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
            release_manifests="$(python3 -c '
import json, sys
for asset in json.load(sys.stdin).get("assets", []):
    name = str(asset.get("name", "")).lower()
    url = asset.get("browser_download_url", "")
    if ("checksum" in name or "sha256" in name) and isinstance(url, str) and url.startswith(sys.argv[1]) and "\n" not in url:
        print(url)
' "$base_dir/" <<< "$release_metadata"
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
            local -a _chk_proto=()
            [[ "$checksum_url" == https://* ]] && _chk_proto=(--proto '=https' --proto-redir '=https')
            if af_logged_stderr curl "${_chk_proto[@]}" -fsSL --connect-timeout 2 --max-time 4 "$checksum_url" -o "$fetched"; then
                while read -r digest candidate || [[ -n "$digest" ]]; do
                    if [[ "$digest" =~ ^[a-fA-F0-9]{64}$ ]]; then
                        candidate="${candidate#\*}"
                        candidate="${candidate#./}"
                        if [[ ( -z "$candidate" && ( "$checksum_url" == "${source_url}.sha256" || "$checksum_url" == "${source_url}.sha256sum" ) ) || "$candidate" == "$basename_url" || "$candidate" == "$(basename "$file_path")" ]]; then
                            if ! verify_sha256 "$file_path" "$digest" "$source_url"; then
                                rm -rf -- "$checksum_directory"
                                return 1
                            fi
                            found=true
                        fi
                    elif [[ "$autoscan_release" == true && "${checksum_url##*/}" == checksums.txt && "$digest" =~ ^[a-fA-F0-9]{128}$ ]]; then
                        candidate="${candidate#\*}"
                        candidate="${candidate#./}"
                        if [[ "$candidate" == "$basename_url" || "$candidate" == "$(basename "$file_path")" ]]; then
                            local actual_sha512=""
                            if ! actual_sha512="$(sha512sum -- "$file_path")"; then
                                print_error "$source_url SHA-512 verification failed"
                                rm -rf -- "$checksum_directory"
                                return 1
                            fi
                            actual_sha512="${actual_sha512%% *}"
                            if [[ "$actual_sha512" != "${digest,,}" ]]; then
                                print_error "$source_url SHA-512 digest mismatch"
                                rm -rf -- "$checksum_directory"
                                return 1
                            fi
                            found=true
                        fi
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
    local -a proto_args=()
    [[ "$source_url" == https://* ]] && proto_args=(--proto '=https' --proto-redir '=https')
    if declare -F curl >/dev/null; then
        curl "${proto_args[@]}" -fsSL --retry 3 --connect-timeout 10 --max-time 300 "$source_url" -o "$file_path" || return $?
    else
        download_file --transport "${proto_args[@]}" -fsSL --retry 3 --connect-timeout 10 --max-time 300 "$source_url" -o "$file_path" || return $?
    fi
    if ! verify_download_sha256 "$file_path" "$app_id" "$source_url" "${4:-}"; then
        print_error "Refusing unverified download from $source_url"
        return 1
    fi
}

download_servarr_archive() {
    local repo="$1" version="${2#v}" arch="$3" destination="$4"
    local +x RELEASE_JSON=""
    local title="${repo##*/}" tag="v$version" prefix asset url resolved
    prefix="https://github.com/$repo/releases/download/$tag/"
    asset="$title.master.$version.linux-core-$arch.tar.gz"
    url="$prefix$asset"

    if RELEASE_JSON="$(af_github_curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 5 --max-time 15 "https://api.github.com/repos/$repo/releases/tags/$tag")" && [[ -n "$RELEASE_JSON" ]]; then
        if resolved="$(python3 -c '
import json, sys

prefix, preferred, alternate = sys.argv[1:]
assets = {asset.get("name"): asset.get("browser_download_url")
          for asset in json.load(sys.stdin).get("assets", [])}
for name in (preferred, alternate):
    if assets.get(name) == prefix + name:
        print(prefix + name)
        break
' "$prefix" "$asset" "$title.master.$version.linux-$arch.tar.gz" <<< "$RELEASE_JSON")" && [[ -n "$resolved" ]]; then
            url="$resolved"
        else
            RELEASE_JSON=""
        fi
    fi
    download_file "$url" "$destination"
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
    af_mkdir_p_0755 "$(dirname "$destination")"
    staged="$(mktemp "${destination}.af-new.XXXXXX")"
    if ! install -m 0755 "$source" "$staged" || ! mv -fT "$staged" "$destination"; then
        rm -f "$staged"
        return 1
    fi
}
