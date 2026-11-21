#!/bin/bash
# /opt/AetherFlow/packages/common.sh
# Shared variables and functions for AetherFlow scripts/installers.

set -euo pipefail
umask 077

export PATH="/usr/local/nodejs/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
if [[ -z "${LOGFILE:-}" ]]; then
    case "${0##*/}" in
        installpackage-*) export LOGFILE="/var/log/aetherflow/install-${0##*installpackage-}.log" ;;
        removepackage-*)  export LOGFILE="/var/log/aetherflow/remove-${0##*removepackage-}.log" ;;
        *)                export LOGFILE="/var/log/aetherflow/install.log" ;;
    esac
else
    export LOGFILE
fi
export LOCK_DIR="${LOCK_DIR:-/install}"
export AF_REQUIRE_DOWNLOAD_SHA256="${AF_REQUIRE_DOWNLOAD_SHA256:-1}"
declare -ag AF_PENDING_VERSION_PATHS=() AF_PENDING_VERSION_VALUES=() AF_APT_REINSTALL_PACKAGES=() AF_APT_TRANSACTION_PACKAGES=()

af_github_curl() {
    local _gh_token="${AF_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
    if [[ -n "$_gh_token" && "$_gh_token" != *$'\n'* && "$_gh_token" != *$'\r'* && "$_gh_token" != *'"'* && "$_gh_token" != *'\\'* ]]; then
        printf 'header = "Authorization: Bearer %s"\n' "$_gh_token" | curl -K - "$@"
    else
        curl "$@"
    fi
}

af_prepare_logfile_path() {
    local target="${1:-${LOGFILE:-/var/log/aetherflow/install.log}}"
    [[ "$target" != "/dev/null" ]] || return 0
    [[ -n "$target" ]] || return 1
    local parent_dir="."
    if [[ "$target" == */* ]]; then
        parent_dir="${target%/*}"
        [[ -n "$parent_dir" ]] || parent_dir="/"
    fi
    if [[ -L "$target" || -L "$parent_dir" || ( -e "$target" && ! -f "$target" ) ]]; then
        printf 'Refusing unsafe logfile path: %s\n' "$target" >&2
        return 1
    fi
    if [[ "$parent_dir" == /var/log/aetherflow || "$target" == /var/log/aetherflow/* ]] && [[ -L /var/log/aetherflow ]]; then
        printf 'Refusing symlinked /var/log/aetherflow directory\n' >&2
        return 1
    fi
    if [[ "${EUID:-$(id -u)}" -eq 0 && ( "$parent_dir" == /var/log/aetherflow || "$parent_dir" == */var/log/aetherflow ) ]]; then
        local log_group="root"
        if getent group aetherflow >/dev/null 2>&1; then
            log_group="aetherflow"
        fi
        install -d -m 0750 -o root -g "$log_group" "$parent_dir" || return 1
    else
        mkdir -p -m 0750 -- "$parent_dir" || return 1
    fi
    python3 - "$target" "$parent_dir" <<'PYEOF'
import fcntl, grp, os, stat, sys

target, parent_dir = sys.argv[1], sys.argv[2]
parent_st = os.lstat(parent_dir)
if stat.S_ISLNK(parent_st.st_mode) or not stat.S_ISDIR(parent_st.st_mode):
    raise SystemExit(f"Unsafe log directory: {parent_dir}")
target_gid = 0
if os.geteuid() == 0 and (parent_dir == "/var/log/aetherflow" or parent_dir.endswith("/var/log/aetherflow")):
    try:
        target_gid = grp.getgrnam("aetherflow").gr_gid
    except KeyError:
        target_gid = 0
    if parent_st.st_uid != 0 or parent_st.st_gid != target_gid:
        os.chown(parent_dir, 0, target_gid)
    if stat.S_IMODE(parent_st.st_mode) != 0o750:
        os.chmod(parent_dir, 0o750)
flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(target, flags, 0o640)
try:
    # Intentional LOCK_SH + O_APPEND: blocks deploy/log-retention.py's LOCK_EX
    # truncation/rotation while allowing nested af_logged -> log() opens on the
    # same logfile without self-deadlocking; kernel O_APPEND keeps line writes atomic.
    fcntl.flock(fd, fcntl.LOCK_SH)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise SystemExit(f"Refusing non-regular or hardlinked logfile target: {target}")
        if os.geteuid() == 0 and (parent_dir == "/var/log/aetherflow" or parent_dir.endswith("/var/log/aetherflow")):
            if st.st_uid != 0 or st.st_gid != target_gid:
                os.fchown(fd, 0, target_gid)
            if stat.S_IMODE(st.st_mode) != 0o640:
                os.fchmod(fd, 0o640)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
PYEOF
}

af_ensure_lock_dir() {
    local lock_dir="${1:-$LOCK_DIR}" lock_group="root"
    if [[ -L "$lock_dir" ]]; then
        printf 'Refusing symlinked lock directory: %s\n' "$lock_dir" >&2
        return 1
    fi
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        if getent group aetherflow >/dev/null 2>&1; then
            lock_group="aetherflow"
        fi
        install -d -m 0750 -o root -g "$lock_group" "$lock_dir" || return 1
        chmod 0750 "$lock_dir" || return 1
        chgrp "$lock_group" "$lock_dir" 2>/dev/null || true
    else
        mkdir -p -m 0750 "$lock_dir" || return 1
    fi
}

af_ensure_lock_dir "$LOCK_DIR"
af_prepare_logfile_path "$LOGFILE"

timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

log() {
    local target="${LOGFILE:-/dev/null}"
    [[ "$target" != "/dev/null" ]] || return 0
    local line
    line="$(printf '[%s] %s\n' "$(timestamp)" "$*")"
    python3 - "$target" "$line" <<'PYEOF'
import fcntl, os, stat, sys

target, line = sys.argv[1], sys.argv[2]
parent_dir = os.path.dirname(target) or "."
parent_st = os.lstat(parent_dir)
if stat.S_ISLNK(parent_st.st_mode) or not stat.S_ISDIR(parent_st.st_mode):
    sys.stderr.write(f"Refusing unsafe logfile target: {target}\n")
    raise SystemExit(1)
flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
try:
    fd = os.open(target, flags, 0o640)
except OSError:
    sys.stderr.write(f"Refusing unsafe logfile target: {target}\n")
    raise SystemExit(1)
try:
    # Intentional LOCK_SH + O_APPEND: blocks deploy/log-retention.py's LOCK_EX
    # truncation/rotation while allowing nested af_logged -> log() opens on the
    # same logfile without self-deadlocking; kernel O_APPEND keeps line writes atomic.
    fcntl.flock(fd, fcntl.LOCK_SH)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            sys.stderr.write(f"Refusing unsafe logfile target: {target}\n")
            raise SystemExit(1)
        if not line.endswith("\n"):
            line += "\n"
        data = line.encode("utf-8", errors="replace")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
PYEOF
}

af_logged() {
    local target="${LOGFILE:-/dev/null}"
    if [[ "$target" == "/dev/null" ]]; then
        "$@" >/dev/null 2>&1
        return $?
    fi
    if declare -F af_prepare_logfile_path >/dev/null 2>&1 && [[ ! -f "$target" ]]; then
        af_prepare_logfile_path "$target" || return 1
    fi
    local _flock_bin="flock"
    if ! command -v flock >/dev/null 2>&1 && [[ -x /usr/bin/flock ]]; then
        _flock_bin="/usr/bin/flock"
    fi
    local _out_r="" _meta=""
    exec {_out_r}< <(python3 - "$target" <<'PYEOF'
import fcntl, grp, os, select, stat, sys

target = sys.argv[1]
parent_dir = os.path.dirname(target) or "."
if not os.path.lexists(parent_dir):
    os.makedirs(parent_dir, mode=0o750, exist_ok=True)
pst = os.lstat(parent_dir)
if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
    sys.stderr.write(f"Refusing unsafe logfile path: {target}\n")
    raise SystemExit(1)
flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
try:
    fd = os.open(target, flags, 0o640)
except OSError:
    sys.stderr.write(f"Refusing unsafe logfile path: {target}\n")
    raise SystemExit(1)
try:
    # Intentional LOCK_SH + O_APPEND: blocks deploy/log-retention.py's LOCK_EX
    # truncation/rotation while allowing nested af_logged -> log() opens on the
    # same logfile without self-deadlocking; kernel O_APPEND keeps line writes atomic.
    fcntl.flock(fd, fcntl.LOCK_SH)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            sys.stderr.write(f"Refusing non-regular or hardlinked logfile target: {target}\n")
            raise SystemExit(1)
        if os.geteuid() == 0 and (parent_dir == "/var/log/aetherflow" or parent_dir.endswith("/var/log/aetherflow")):
            try:
                target_gid = grp.getgrnam("aetherflow").gr_gid
            except KeyError:
                target_gid = 0
            if st.st_uid != 0 or st.st_gid != target_gid:
                os.fchown(fd, 0, target_gid)
            if stat.S_IMODE(st.st_mode) != 0o640:
                os.fchmod(fd, 0o640)
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~getattr(os, "O_NONBLOCK", 0))
        sys.stdout.write(f"{os.getpid()}:{fd}\n")
        sys.stdout.flush()
        poller = select.poll()
        poller.register(sys.stdout.fileno(), select.POLLERR | select.POLLHUP)
        poller.poll(5000)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
PYEOF
    ) || return 1
    if ! IFS= read -r _meta <&"$_out_r" || [[ ! "$_meta" =~ ^([0-9]+):([0-9]+)$ ]]; then
        exec {_out_r}<&-
        return 1
    fi
    local _hpid="${BASH_REMATCH[1]}" _hfd="${BASH_REMATCH[2]}" lock_fd=""
    if ! exec {lock_fd}>>"/proc/${_hpid}/fd/${_hfd}"; then
        exec {_out_r}<&-
        return 1
    fi
    if ! "$_flock_bin" -s "$lock_fd"; then
        exec {lock_fd}>&-
        exec {_out_r}<&-
        return 1
    fi
    exec {_out_r}<&-
    local rc=0
    "$@" >&"$lock_fd" 2>&1 || rc=$?
    "$_flock_bin" -u "$lock_fd" 2>/dev/null || true
    exec {lock_fd}>&-
    return "$rc"
}

af_logged_stderr() {
    local target="${LOGFILE:-/dev/null}"
    if [[ "$target" == "/dev/null" ]]; then
        "$@" 2>/dev/null
        return $?
    fi
    if declare -F af_prepare_logfile_path >/dev/null 2>&1 && [[ ! -f "$target" ]]; then
        af_prepare_logfile_path "$target" || return 1
    fi
    local _flock_bin="flock"
    if ! command -v flock >/dev/null 2>&1 && [[ -x /usr/bin/flock ]]; then
        _flock_bin="/usr/bin/flock"
    fi
    local _out_r="" _meta=""
    exec {_out_r}< <(python3 - "$target" <<'PYEOF'
import fcntl, grp, os, select, stat, sys

target = sys.argv[1]
parent_dir = os.path.dirname(target) or "."
if not os.path.lexists(parent_dir):
    os.makedirs(parent_dir, mode=0o750, exist_ok=True)
pst = os.lstat(parent_dir)
if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
    sys.stderr.write(f"Refusing unsafe logfile path: {target}\n")
    raise SystemExit(1)
flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
try:
    fd = os.open(target, flags, 0o640)
except OSError:
    sys.stderr.write(f"Refusing unsafe logfile path: {target}\n")
    raise SystemExit(1)
try:
    # Intentional LOCK_SH + O_APPEND: blocks deploy/log-retention.py's LOCK_EX
    # truncation/rotation while allowing nested af_logged -> log() opens on the
    # same logfile without self-deadlocking; kernel O_APPEND keeps line writes atomic.
    fcntl.flock(fd, fcntl.LOCK_SH)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            sys.stderr.write(f"Refusing non-regular or hardlinked logfile target: {target}\n")
            raise SystemExit(1)
        if os.geteuid() == 0 and (parent_dir == "/var/log/aetherflow" or parent_dir.endswith("/var/log/aetherflow")):
            try:
                target_gid = grp.getgrnam("aetherflow").gr_gid
            except KeyError:
                target_gid = 0
            if st.st_uid != 0 or st.st_gid != target_gid:
                os.fchown(fd, 0, target_gid)
            if stat.S_IMODE(st.st_mode) != 0o640:
                os.fchmod(fd, 0o640)
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl & ~getattr(os, "O_NONBLOCK", 0))
        sys.stdout.write(f"{os.getpid()}:{fd}\n")
        sys.stdout.flush()
        poller = select.poll()
        poller.register(sys.stdout.fileno(), select.POLLERR | select.POLLHUP)
        poller.poll(5000)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
PYEOF
    ) || return 1
    if ! IFS= read -r _meta <&"$_out_r" || [[ ! "$_meta" =~ ^([0-9]+):([0-9]+)$ ]]; then
        exec {_out_r}<&-
        return 1
    fi
    local _hpid="${BASH_REMATCH[1]}" _hfd="${BASH_REMATCH[2]}" lock_fd=""
    if ! exec {lock_fd}>>"/proc/${_hpid}/fd/${_hfd}"; then
        exec {_out_r}<&-
        return 1
    fi
    if ! "$_flock_bin" -s "$lock_fd"; then
        exec {lock_fd}>&-
        exec {_out_r}<&-
        return 1
    fi
    exec {_out_r}<&-
    local rc=0
    "$@" 2>&"$lock_fd" || rc=$?
    "$_flock_bin" -u "$lock_fd" 2>/dev/null || true
    exec {lock_fd}>&-
    return "$rc"
}

af_validate_tar_archive() {
    local archive_path="$1"
    [[ -f "$archive_path" && ! -L "$archive_path" ]] || {
        log_error "Refusing missing or symlinked archive path: ${archive_path}"
        return 1
    }
    python3 - "$archive_path" <<'PYEOF'
import pathlib, sys, tarfile

archive = sys.argv[1]
try:
    with tarfile.open(archive, "r:*") as tf:
        members = tf.getmembers()
        if not members:
            raise ValueError("empty tar archive")
        for member in members:
            name = member.name or ""
            if not (member.isfile() or member.isdir()):
                raise ValueError(f"disallowed non-regular tar entry: {name} (type={member.type!r})")
            if name.startswith("/") or name.startswith("\\"):
                raise ValueError(f"disallowed absolute tar entry: {name}")
            parts = pathlib.PurePosixPath(name).parts
            if ".." in parts:
                raise ValueError(f"disallowed path-traversal tar entry: {name}")
except Exception as exc:
    sys.stderr.write(f"Tar archive validation failed for {archive}: {exc}\n")
    raise SystemExit(1)
PYEOF
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

# Strip supported release/tag prefixes (v/V, release-, rel-, version-, ver-)
# to align shell version normalization with af_release::lifecycle::strip_version_prefix.
af_strip_version_prefix() {
    local value="${1:-}" prev="" lower=""
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    while [[ "$value" != "$prev" ]]; do
        prev="$value"
        lower="${value,,}"
        if [[ "$lower" == release-* || "$lower" == release_* || "$lower" == version-* || "$lower" == version_* ]]; then
            value="${value:8}"
        elif [[ "$lower" == rel-* || "$lower" == rel_* || "$lower" == ver-* || "$lower" == ver_* ]]; then
            value="${value:4}"
        elif [[ "$value" =~ ^[vV]([0-9].*)$ ]]; then
            value="${BASH_REMATCH[1]}"
        fi
        value="${value#"${value%%[![:space:]]*}"}"
        value="${value%"${value##*[![:space:]]}"}"
    done
    printf '%s\n' "$value"
}

# Validate and normalize a concrete exact registry target version for npm or pypi.
# Rejects floating tags, ranges, wildcards, comparators, URLs, and unsafe characters.
af_normalize_exact_registry_version() {
    local ecosystem="${1:-}" raw="${2:-}" trimmed="" normalized="" lower="" msg=""
    trimmed="${raw#"${raw%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    if [[ -z "$trimmed" || ${#trimmed} -gt 256 || "$trimmed" =~ [[:space:][:cntrl:]] || "$trimmed" == *..* || "$trimmed" == */* || "$trimmed" == *\\* ]]; then
        msg="Invalid ${ecosystem} target version: ${raw}"
    else
        normalized="$(af_strip_version_prefix "$trimmed")"
        lower="${normalized,,}"
        case "$lower" in
            ""|latest|next|canary|stable|beta|alpha|rc|nightly|edge|dev|devel|unknown|none|null|undefined|current|installed|pending|default|auto|head|main|master|release|true|false)
                msg="Refusing non-concrete ${ecosystem} target version: ${raw}"
                ;;
        esac
        if [[ -z "$msg" ]]; then
            case "$ecosystem" in
                npm)
                    if [[ ! "$normalized" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
                        msg="Invalid exact npm target version: ${raw}"
                    fi
                    ;;
                pypi)
                    if [[ ! "$normalized" =~ ^([1-9][0-9]*!)?[0-9]+(\.[0-9]+)+((a|b|rc)[0-9]+)?(\.post[0-9]+)?(\.dev[0-9]+)?(\+[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$ ]]; then
                        msg="Invalid exact PyPI target version: ${raw}"
                    fi
                    ;;
                *)
                    msg="Unsupported registry ecosystem: ${ecosystem}"
                    ;;
            esac
        fi
    fi
    if [[ -n "$msg" ]]; then
        if declare -F print_error >/dev/null 2>&1; then
            print_error "$msg"
        elif declare -F log_error >/dev/null 2>&1; then
            log_error "$msg"
        else
            printf 'ERROR: %s\n' "$msg" >&2
        fi
        return 1
    fi
    printf '%s\n' "$normalized"
}

af_read_npm_package_version() {
    local manifest="${1:-}"
    [[ -f "$manifest" && ! -L "$manifest" ]] || return 1
    python3 - "$manifest" <<'PYEOF'
import json, sys
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    data = json.load(fh)
version = data.get("version") if isinstance(data, dict) else None
if not isinstance(version, str) or not version.strip():
    sys.exit(1)
print(version.strip())
PYEOF
}

# Install npm applications locally so Git dependencies can prepare with their
# own complete toolchains. Build before replacing any existing application and
# expose only the application's executable, rather than global build tools.
install_npm_app() (
    set -e
    umask 022
    local package="$1" destination="$2" executable="$3" staged="" bin_name
    local pkg_name="" requested_ver="" installed_ver="" pkg_manifest=""
    bin_name="$(basename "$executable")"

    if [[ "$package" =~ ^(@[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+)@(.+)$ ]]; then
        pkg_name="${BASH_REMATCH[1]}"
        requested_ver="${BASH_REMATCH[2]}"
    elif [[ "$package" =~ ^([a-zA-Z0-9][a-zA-Z0-9._-]*)@(.+)$ && "$package" != *://* && "$package" != *:* ]]; then
        pkg_name="${BASH_REMATCH[1]}"
        requested_ver="${BASH_REMATCH[2]}"
    elif [[ "$package" =~ ^(@[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+|[a-zA-Z0-9][a-zA-Z0-9._-]*)$ && ! -e "$package" ]]; then
        pkg_name="$package"
        if [[ -n "${AF_TARGET_VERSION:-}" ]]; then
            requested_ver="$(af_normalize_exact_registry_version npm "${AF_TARGET_VERSION}")" || return 1
            package="${pkg_name}@${requested_ver}"
        fi
    fi

    if [[ -n "$requested_ver" ]]; then
        requested_ver="$(af_normalize_exact_registry_version npm "$requested_ver")" || return 1
        package="${pkg_name}@${requested_ver}"
    fi

    mkdir -p "$(dirname "$destination")" "$(dirname "$executable")"
    staged="$(mktemp -d "${destination}.af-build.XXXXXX")"
    trap '[[ -z "$staged" ]] || rm -rf -- "$staged"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # mktemp creates a private directory; the service user must traverse it.
    chmod 755 "$staged"
    if [[ -n "$requested_ver" ]]; then
        af_logged node_build npm install --prefix "$staged" --no-audit --no-fund --save-exact "$package" || return $?
    else
        af_logged node_build npm install --prefix "$staged" --no-audit --no-fund "$package" || return $?
    fi
    if [[ ! -x "$staged/node_modules/.bin/$bin_name" ]]; then
        print_error "npm package $package did not provide executable $bin_name"
        return 1
    fi
    if [[ -n "$requested_ver" && -n "$pkg_name" ]]; then
        pkg_manifest="$staged/node_modules/${pkg_name}/package.json"
        if [[ ! -d "$staged/node_modules/${pkg_name}" || -L "$staged/node_modules/${pkg_name}" || ! -f "$pkg_manifest" || -L "$pkg_manifest" ]]; then
            print_error "Installed npm package ${pkg_name} is missing valid package.json metadata for requested version (${requested_ver})"
            return 1
        fi
        installed_ver="$(af_read_npm_package_version "$pkg_manifest" || true)"
        installed_ver="$(af_strip_version_prefix "$installed_ver")"
        if [[ -z "$installed_ver" || "$installed_ver" != "$requested_ver" ]]; then
            print_error "Installed npm package ${pkg_name} version (${installed_ver:-unknown}) does not match requested version (${requested_ver})"
            return 1
        fi
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
    [[ -v AF_PENDING_VERSION_PATHS ]] || declare -ag AF_PENDING_VERSION_PATHS=()
    [[ -v AF_PENDING_VERSION_VALUES ]] || declare -ag AF_PENDING_VERSION_VALUES=()
    AF_PENDING_VERSION_PATHS+=("$1")
    AF_PENDING_VERSION_VALUES+=("$2")
}

commit_app_versions() {
    local index
    [[ -v AF_PENDING_VERSION_PATHS ]] || declare -ag AF_PENDING_VERSION_PATHS=()
    [[ -v AF_PENDING_VERSION_VALUES ]] || declare -ag AF_PENDING_VERSION_VALUES=()
    if [[ -n "${AF_TARGET_VERSION:-}" ]]; then
        if (( ${#AF_PENDING_VERSION_VALUES[@]} == 0 )); then
            echo "ERROR: No application version receipt queued to verify against requested target version (${AF_TARGET_VERSION})" >&2
            return 1
        fi
        local clean_target primary_ver norm_ver target_matches=0
        clean_target="$(af_strip_version_prefix "${AF_TARGET_VERSION}")"
        primary_ver="${AF_PENDING_VERSION_VALUES[0]}"
        norm_ver="$(af_strip_version_prefix "${primary_ver}")"
        if [[ -n "$clean_target" && -n "$norm_ver" && "$norm_ver" == "$clean_target" ]]; then
            target_matches=1
        elif [[ "$norm_ver" =~ ^[0-9a-fA-F]{7,64}$ && "$clean_target" =~ ^[0-9a-fA-F]{7,64}$ ]]; then
            local lower_ver="${norm_ver,,}" lower_target="${clean_target,,}"
            if [[ ( ! "$lower_ver" =~ ^[0-9]+$ || ${#lower_ver} -eq 40 || ${#lower_ver} -eq 64 ) && \
                  ( ! "$lower_target" =~ ^[0-9]+$ || ${#lower_target} -eq 40 || ${#lower_target} -eq 64 ) && \
                  "$lower_ver" == "$lower_target"* ]]; then
                target_matches=1
            fi
        fi
        if [[ "$target_matches" -ne 1 ]]; then
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
import os, pathlib, re, secrets, shutil, stat, subprocess, sys
def _deb_ge(new_v, old_v):
    if shutil.which('dpkg'):
        return subprocess.run(['dpkg', '--compare-versions', new_v, 'ge', old_v]).returncode == 0
    def _split(v):
        ep = 0
        if ':' in v:
            e, r = v.split(':', 1)
            if not e.isdigit(): return None
            ep, v = int(e), r
        return (ep, *(v.rsplit('-', 1) if '-' in v else (v, '')))
    def _ord(c):
        return -1 if c == '~' else (ord(c) if ('A' <= c <= 'Z' or 'a' <= c <= 'z') else ord(c) + 256)
    def _pcmp(a, b):
        i = j = 0
        na, nb = len(a), len(b)
        while i < na or j < nb:
            while (i < na and not a[i].isdigit()) or (j < nb and not b[j].isdigit()):
                ca = _ord(a[i]) if i < na and not a[i].isdigit() else 0
                cb = _ord(b[j]) if j < nb and not b[j].isdigit() else 0
                if ca != cb: return -1 if ca < cb else 1
                if i < na and not a[i].isdigit(): i += 1
                if j < nb and not b[j].isdigit(): j += 1
            ia, jb = i, j
            while i < na and a[i].isdigit(): i += 1
            while j < nb and b[j].isdigit(): j += 1
            da, db = int(a[ia:i] or '0'), int(b[jb:j] or '0')
            if da != db: return -1 if da < db else 1
        return 0
    s1, s2 = _split(new_v), _split(old_v)
    if s1 is None or s2 is None: return False
    c = (-1 if s1[0] < s2[0] else (1 if s1[0] > s2[0] else 0)) or _pcmp(s1[1], s2[1]) or _pcmp(s1[2], s2[2])
    return c >= 0
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
                                or not _deb_ge(new_compare, old_compare))
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
    local directory="$1" previous="${2:-}" expected="${3:-${AF_TARGET_VERSION:-}}" version="" head_commit=""
    local tag="" clean_expected="" norm_tag="" points_at="" is_expected_sha=0
    if [[ -n "$expected" ]]; then
        clean_expected="${expected#release-}"
        clean_expected="${clean_expected#Release-}"
        clean_expected="${clean_expected#v}"
        clean_expected="${clean_expected#V}"
        if [[ "$expected" =~ ^[0-9a-fA-F]{7,64}$ && ( ! "$expected" =~ ^[0-9]+$ || ${#expected} -eq 40 || ${#expected} -eq 64 ) ]]; then
            is_expected_sha=1
        fi
        points_at="$(git -C "$directory" tag --points-at HEAD 2>/dev/null || true)"
        if [[ -n "$points_at" ]]; then
            while IFS= read -r tag; do
                [[ -n "${tag//[[:space:]]/}" ]] || continue
                if [[ "$tag" == "$expected" ]]; then
                    version="$tag"
                    break
                fi
            done <<< "$points_at"
            if [[ -z "$version" ]]; then
                while IFS= read -r tag; do
                    [[ -n "${tag//[[:space:]]/}" ]] || continue
                    norm_tag="${tag#release-}"
                    norm_tag="${norm_tag#Release-}"
                    norm_tag="${norm_tag#v}"
                    norm_tag="${norm_tag#V}"
                    if [[ "$norm_tag" == "$clean_expected" ]]; then
                        version="$tag"
                        break
                    fi
                done <<< "$points_at"
            fi
        fi
        if [[ -z "$version" && "$is_expected_sha" -eq 1 ]]; then
            head_commit="$(git -C "$directory" rev-parse --verify HEAD 2>/dev/null || true)"
            if [[ -n "$head_commit" && "${head_commit,,}" == "${expected,,}"* ]]; then
                version="${head_commit,,}"
            fi
        fi
    fi
    if [[ -z "${version//[[:space:]]/}" ]]; then
        version="$(git -C "$directory" describe --tags --exact-match HEAD 2>/dev/null || true)"
    fi
    if [[ -z "${version//[[:space:]]/}" ]]; then
        head_commit="$(git -C "$directory" rev-parse --verify HEAD 2>/dev/null || true)"
        version="$head_commit"
    fi
    if [[ -z "${version//[[:space:]]/}" && -z "${AF_TARGET_VERSION:-}" && ! -e "$directory/.git" && -n "$previous" && -f "$previous" && ! -L "$previous" ]]; then
        version="$(cat -- "$previous")"
    fi
    [[ -n "${version//[[:space:]]/}" ]] || { print_error "Cannot determine checked-out application version"; return 1; }
    printf '%s\n' "$version"
}

git_stage_exact_revision() {
    local repo_url="${1:-}" build_dir="${2:-}" raw_target="${3:-}"
    local target="" remote_tags="" resolved_output="" selected_kind="" selected_ref="" selected_tag="" expected_commit=""
    local advertised_head="" local_tag_commit="" resolved_commit="" actual_commit=""

    AF_STAGED_GIT_VERSION=""
    AF_STAGED_GIT_REF=""
    AF_STAGED_GIT_COMMIT=""

    if [[ -z "$repo_url" || "$repo_url" == -* || -z "$build_dir" ]]; then
        if declare -F af_write_failure_receipt >/dev/null 2>&1; then
            af_write_failure_receipt 1 "download" "invalid_git_source" "Invalid Git repository URL or staging directory"
        fi
        print_error "Invalid Git repository URL or staging directory"
        return 1
    fi

    # Cloudplow publishes commits on its default branch instead of release tags.
    if [[ -z "$raw_target" && "${4:-}" == "head" ]]; then
        if ! advertised_head="$(git ls-remote --exit-code "$repo_url" HEAD)" ||
            [[ ! "$advertised_head" =~ ^([[:xdigit:]]{40}|[[:xdigit:]]{64})$'\t'HEAD$ ]]; then
            if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                af_write_failure_receipt 1 "download" "invalid_target_commit" "Unable to resolve remote HEAD for ${repo_url}"
            fi
            print_error "Unable to resolve remote HEAD for ${repo_url}"
            return 1
        fi
        selected_kind="commit"
        selected_ref="HEAD"
        expected_commit="${BASH_REMATCH[1],,}"
    else
        if [[ -n "$raw_target" ]]; then
            if ! target="$(python3 -c '
import sys

raw = sys.argv[1]
trimmed = raw.strip()
forbidden = frozenset((
    "latest", "unknown", "none", "null", "undefined", "error", "n/a", "na",
    "current", "installed", "pending", "default", "auto", "true", "false",
    "head", "main", "master", "stable", "beta", "nightly", "edge", "dev",
    "devel", "alpha", "rc", "release",
))
bad_chars = frozenset(";&|`$()<>\"'\''*?!{}[]^~:\\")

if (
    not trimmed
    or len(trimmed) > 256
    or trimmed.startswith("-")
    or ".." in trimmed
    or "@{" in trimmed
    or "/" in trimmed
    or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ch in bad_chars for ch in trimmed)
    or trimmed.lower() in forbidden
):
    sys.exit(1)
print(trimmed)
' "$raw_target")"; then
                if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                    af_write_failure_receipt 1 "download" "invalid_target_version" "Invalid requested target version: ${raw_target}"
                fi
                print_error "Invalid requested target version: ${raw_target}"
                return 1
            fi
        fi

        if ! remote_tags="$(git ls-remote --tags "$repo_url")"; then
            if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                af_write_failure_receipt 1 "download" "git_ls_remote_failed" "Failed to query remote tags from ${repo_url}"
            fi
            print_error "Failed to query remote tags from ${repo_url}"
            return 1
        fi

        if ! resolved_output="$(python3 -c '
import re, sys

target = sys.argv[1]
repo_url = sys.argv[2]

direct = {}
peeled = {}
for line in sys.stdin.read().splitlines():
    line = line.strip()
    if not line:
        continue
    parts = line.split()
    if len(parts) < 2:
        continue
    sha, ref = parts[0].lower(), parts[1]
    if not re.fullmatch(r"[0-9a-f]{7,64}", sha):
        continue
    if not ref.startswith("refs/tags/"):
        continue
    if ref.endswith("^{}"):
        name = ref[len("refs/tags/"):-3]
        if name:
            peeled[name] = sha
    else:
        name = ref[len("refs/tags/"):]
        if name:
            direct[name] = sha

resolved = {name: peeled.get(name, sha) for name, sha in direct.items()}

def strip_prefix(value):
    clean = re.sub(r"^(?:[rR]elease-)", "", value)
    clean = re.sub(r"^[vV]", "", clean)
    return clean

def valid_tag_name(name):
    return (
        bool(name)
        and not name.startswith("-")
        and ".." not in name
        and "@{" not in name
        and "/" not in name
        and not any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name)
    )

if target:
    if target in resolved and valid_tag_name(target):
        print("tag")
        print(f"refs/tags/{target}")
        print(target)
        print(resolved[target])
        sys.exit(0)

    clean = strip_prefix(target)
    candidates = []
    for candidate in (
        f"v{clean}",
        clean,
        f"V{clean}",
        f"release-{clean}",
        f"release-v{clean}",
        f"Release-{clean}",
        f"Release-v{clean}",
    ):
        if candidate and candidate not in candidates and candidate in resolved and valid_tag_name(candidate):
            candidates.append(candidate)

    if candidates:
        commits = {resolved[c] for c in candidates}
        if len(commits) > 1:
            sys.stderr.write(
                f"Ambiguous remote tags for requested target {target!r} in {repo_url}: {candidates}\n"
            )
            sys.exit(2)
        chosen = candidates[0]
        print("tag")
        print(f"refs/tags/{chosen}")
        print(chosen)
        print(resolved[chosen])
        sys.exit(0)

    is_hex = bool(re.fullmatch(r"[0-9a-fA-F]{7,64}", target))
    if is_hex and (not target.isdecimal() or len(target) in (40, 64)):
        lower_sha = target.lower()
        print("commit")
        print(lower_sha)
        print("")
        print(lower_sha)
        sys.exit(0)

    sys.stderr.write(
        f"Requested target version {target!r} was not found in remote tags for {repo_url}\n"
    )
    sys.exit(3)

stable_pattern = re.compile(r"^(?:[rR]elease-)?[vV]?([0-9]+(?:\.[0-9]+)+)$")
stable_candidates = []
for name, sha in resolved.items():
    match = stable_pattern.fullmatch(name)
    if not match or not valid_tag_name(name):
        continue
    nums = tuple(int(part) for part in match.group(1).split("."))
    stable_candidates.append((nums, name, sha))

if not stable_candidates:
    sys.stderr.write(f"No stable release tags found in {repo_url}\n")
    sys.exit(4)

max_len = max(len(item[0]) for item in stable_candidates)
def sort_key(item):
    nums, name, _sha = item
    padded = nums + (0,) * (max_len - len(nums))
    return (padded, len(nums), 1 if name.startswith("v") else 0, name)

_best_nums, best_tag, best_sha = max(stable_candidates, key=sort_key)
print("tag")
print(f"refs/tags/{best_tag}")
print(best_tag)
print(best_sha)
' "$target" "$repo_url" <<< "$remote_tags")"; then
            if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                af_write_failure_receipt 1 "download" "invalid_target_tag" "Unable to resolve target revision '${target:-latest stable tag}' in ${repo_url}"
            fi
            print_error "Unable to resolve target revision '${target:-latest stable tag}' in ${repo_url}"
            return 1
        fi

        {
            IFS= read -r selected_kind
            IFS= read -r selected_ref
            IFS= read -r selected_tag
            IFS= read -r expected_commit
        } <<< "$resolved_output"
    fi

    if [[ -z "$selected_kind" || -z "$expected_commit" || ! "$expected_commit" =~ ^[0-9a-f]{7,64}$ ]]; then
        if declare -F af_write_failure_receipt >/dev/null 2>&1; then
            af_write_failure_receipt 1 "download" "invalid_target_commit" "Resolved Git revision metadata is invalid for ${repo_url}"
        fi
        print_error "Resolved Git revision metadata is invalid for ${repo_url}"
        return 1
    fi

    if [[ "$selected_kind" == "tag" ]]; then
        if [[ -z "$selected_tag" || "$selected_tag" == -* ]]; then
            if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                af_write_failure_receipt 1 "download" "invalid_target_tag" "Invalid resolved tag name '${selected_tag}' for ${repo_url}"
            fi
            print_error "Invalid resolved tag name '${selected_tag}' for ${repo_url}"
            return 1
        fi
        if ! af_logged git clone --no-checkout --depth 1 --branch "$selected_tag" "$repo_url" "$build_dir"; then
            if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                af_write_failure_receipt 1 "download" "git_clone_failed" "Failed to clone ${repo_url} at tag ${selected_tag}"
            fi
            print_error "Failed to clone ${repo_url} at tag ${selected_tag}"
            return 1
        fi
        local_tag_commit="$(git -C "$build_dir" rev-parse --verify --quiet "refs/tags/${selected_tag}^{commit}" 2>/dev/null || true)"
        if [[ "${local_tag_commit,,}" != "$expected_commit" ]]; then
            if ! af_logged git -C "$build_dir" fetch --force --depth 1 origin "refs/tags/${selected_tag}:refs/tags/${selected_tag}"; then
                if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                    af_write_failure_receipt 1 "download" "git_fetch_failed" "Failed to fetch exact tag ${selected_ref} from ${repo_url}"
                fi
                print_error "Failed to fetch exact tag ${selected_ref} from ${repo_url}"
                return 1
            fi
            local_tag_commit="$(git -C "$build_dir" rev-parse --verify --quiet "refs/tags/${selected_tag}^{commit}" 2>/dev/null || true)"
        fi
        if [[ -z "$local_tag_commit" || "${local_tag_commit,,}" != "$expected_commit" ]]; then
            if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                af_write_failure_receipt 1 "download" "git_revision_mismatch" "Fetched tag ${selected_ref} resolved to '${local_tag_commit:-unknown}' instead of expected commit '${expected_commit}'"
            fi
            print_error "Fetched tag ${selected_ref} resolved to '${local_tag_commit:-unknown}' instead of expected commit '${expected_commit}'"
            return 1
        fi
    elif [[ "$selected_kind" == "commit" ]]; then
        if ! af_logged git clone --no-checkout "$repo_url" "$build_dir"; then
            if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                af_write_failure_receipt 1 "download" "git_clone_failed" "Failed to clone ${repo_url} for commit ${expected_commit}"
            fi
            print_error "Failed to clone ${repo_url} for commit ${expected_commit}"
            return 1
        fi
        resolved_commit="$(git -C "$build_dir" rev-parse --verify --quiet "${expected_commit}^{commit}" 2>/dev/null || true)"
        if [[ -z "$resolved_commit" || ! "$resolved_commit" =~ ^[0-9a-fA-F]{7,64}$ || "${resolved_commit,,}" != "${expected_commit}"* ]]; then
            if declare -F af_write_failure_receipt >/dev/null 2>&1; then
                af_write_failure_receipt 1 "download" "invalid_target_commit" "Requested commit '${expected_commit}' was not found in ${repo_url}"
            fi
            print_error "Requested commit '${expected_commit}' was not found in ${repo_url}"
            return 1
        fi
        expected_commit="${resolved_commit,,}"
        selected_ref="$expected_commit"
    else
        print_error "Unsupported resolved Git revision kind: ${selected_kind}"
        return 1
    fi

    if ! af_logged git -C "$build_dir" checkout --detach "$expected_commit"; then
        if declare -F af_write_failure_receipt >/dev/null 2>&1; then
            af_write_failure_receipt 1 "download" "git_checkout_failed" "Failed to check out commit ${expected_commit} for ${selected_ref}"
        fi
        print_error "Failed to check out commit ${expected_commit} for ${selected_ref}"
        return 1
    fi
    actual_commit="$(git -C "$build_dir" rev-parse --verify --quiet "HEAD^{commit}" 2>/dev/null || true)"
    if [[ -z "$actual_commit" || "${actual_commit,,}" != "$expected_commit" ]]; then
        if declare -F af_write_failure_receipt >/dev/null 2>&1; then
            af_write_failure_receipt 1 "download" "git_revision_mismatch" "Staged HEAD (${actual_commit:-unknown}) does not match expected commit (${expected_commit}) for ${selected_ref}"
        fi
        print_error "Staged HEAD (${actual_commit:-unknown}) does not match expected commit (${expected_commit}) for ${selected_ref}"
        return 1
    fi

    AF_STAGED_GIT_VERSION="${selected_tag:-$expected_commit}"
    AF_STAGED_GIT_REF="$selected_ref"
    AF_STAGED_GIT_COMMIT="$expected_commit"
}

deb_compare_versions() {
    local v1="${1:-}" op="${2:-}" v2="${3:-}"
    if command -v dpkg >/dev/null 2>&1; then
        dpkg --compare-versions "$v1" "$op" "$v2"
        return $?
    fi
    python3 - "$v1" "$op" "$v2" <<'PYEOF'
import sys

v1, op, v2 = sys.argv[1], sys.argv[2], sys.argv[3]
if op in ("eq-nl", "lt-nl", "le-nl", "gt-nl", "ge-nl", "ne-nl"):
    if not v1 or not v2:
        if op == "eq-nl":
            sys.exit(0 if v1 == v2 else 1)
        if op == "ne-nl":
            sys.exit(0 if v1 != v2 else 1)
        sys.exit(1)
    op = op[:-3]

def _split(v):
    ep = 0
    if ":" in v:
        e, r = v.split(":", 1)
        if not e.isdigit():
            return None
        ep, v = int(e), r
    return (ep, *(v.rsplit("-", 1) if "-" in v else (v, "")))

def _ord(c):
    return -1 if c == "~" else (ord(c) if ("A" <= c <= "Z" or "a" <= c <= "z") else ord(c) + 256)

def _pcmp(a, b):
    i = j = 0
    na, nb = len(a), len(b)
    while i < na or j < nb:
        while (i < na and not a[i].isdigit()) or (j < nb and not b[j].isdigit()):
            ca = _ord(a[i]) if i < na and not a[i].isdigit() else 0
            cb = _ord(b[j]) if j < nb and not b[j].isdigit() else 0
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
        da, db = int(a[ia:i] or "0"), int(b[jb:j] or "0")
        if da != db:
            return -1 if da < db else 1
    return 0

s1, s2 = _split(v1), _split(v2)
if s1 is None or s2 is None:
    sys.exit(2)
c = (-1 if s1[0] < s2[0] else (1 if s1[0] > s2[0] else 0)) or _pcmp(s1[1], s2[1]) or _pcmp(s1[2], s2[2])
table = {"eq": c == 0, "ne": c != 0, "lt": c < 0, "le": c <= 0, "gt": c > 0, "ge": c >= 0}
if op not in table:
    sys.exit(2)
sys.exit(0 if table[op] else 1)
PYEOF
}

verify_deb_installed() {
    local package="$1" expected="${2:-}" observed status installed
    observed="$(dpkg-query -W -f='${db:Status-Status} ${Version}\n' "$package" 2>/dev/null)" || return 1
    read -r status installed <<< "$observed"
    if [[ "$status" != installed || -z "$installed" ]]; then
        print_error "Package $package is not installed"
        return 1
    fi
    if [[ -n "$expected" ]] && ! deb_compare_versions "$installed" eq "$expected"; then
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
    [[ -v AF_APT_TRANSACTION_PACKAGES ]] || declare -ag AF_APT_TRANSACTION_PACKAGES=()
    [[ -v AF_APT_REINSTALL_PACKAGES ]] || declare -ag AF_APT_REINSTALL_PACKAGES=()
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
            DEBIAN_FRONTEND=noninteractive af_logged command apt-get remove -y --no-auto-remove "$package" || reconciled=false
        else
            DEBIAN_FRONTEND=noninteractive af_logged command apt-get install -y --allow-downgrades --reinstall "$package=$previous" || reconciled=false
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
    if ! DEBIAN_FRONTEND=noninteractive af_logged dpkg -i "$archive"; then
        DEBIAN_FRONTEND=noninteractive af_logged apt-get install -f -y -qq || return 1
        DEBIAN_FRONTEND=noninteractive af_logged dpkg -i "$archive" || return 1
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

    def read_bytes(self, max_bytes=None):
        if self.descriptor is None:
            return b''
        metadata = os.fstat(self.descriptor)
        self.validate(metadata)
        if max_bytes is not None and metadata.st_size > max_bytes:
            raise ValueError('Managed configuration exceeds maximum allowed size')
        os.lseek(self.descriptor, 0, os.SEEK_SET)
        with os.fdopen(os.dup(self.descriptor), 'rb') as source:
            data = source.read() if max_bytes is None else source.read(max_bytes + 1)
        if max_bytes is not None and len(data) > max_bytes:
            raise ValueError('Managed configuration exceeds maximum allowed size')
        return data

    def read_text(self, max_bytes=None):
        return self.read_bytes(max_bytes=max_bytes).decode('utf-8')

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

def safe_read_text(filename, max_bytes=None):
    with ManagedConfig(filename) as config:
        return config.read_text(max_bytes=max_bytes)

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
            MYSQL_PWD="$password" af_logged mysql "${AF_DATABASE_ARGS[@]}" "$database" < "$backup/database.sql"
            ;;
        postgres|pgsql)
            configured_database_connection "$backend" "$host" "$username" || return 1
            for artifact in .af-postgres-ready postgres-identity.sql postgres-clean.sql postgres-schemas.sql database.sql postgres-metadata.sql postgres-recovery.log; do
                validate_config_paths "$backup/$artifact" || return 1
                [[ -f "$backup/$artifact" && ( "$artifact" == postgres-recovery.log || -s "$backup/$artifact" ) ]] || return 1
            done
            [[ "$(cat "$backup/.af-postgres-ready")" == in-database-v1 ]] || return 1
            af_logged printf '%s\n' 'Restoring configured PostgreSQL database in one transaction' || return 1
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
    af_logged runuser -u postgres -- psql -d postgres -v ON_ERROR_STOP=1 --set="database=$database" <<'SQL' || restored=false
SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :'database' AND pid <> pg_backend_pid();
SQL
    af_logged runuser -u postgres -- psql -d postgres -v ON_ERROR_STOP=1 -f - < "$backup/$database.sql" || restored=false
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

# Discover effective local Servarr URLs and API keys from bounded, verified
# config.xml files and synchronize Notifiarr or Unpackerr TOML configs
# without clobbering operator-edited sections or exposing keys in logs.
sync_servarr_toml_config() {
    local consumer="$1"
    local target_config="$2"
    local app_port="${3:-}"
    local log_dir="${4:-}"
    local summary line level message
    summary="$(safe_config_python "$consumer" "$target_config" "$app_port" "$log_dir" <<'PYEOF'
from collections.abc import MutableMapping
import ipaddress
import os
import re
import socket
import sys
import xml.etree.ElementTree as ET

import tomlkit
from tomlkit.exceptions import TOMLKitError
from tomlkit.items import AoT, Table

PORTS = {"sonarr": 8989, "radarr": 7878, "lidarr": 8686, "readarr": 8787, "prowlarr": 9696}
MANAGED = re.compile(r"(?:^| \| )aetherflow-managed (\S+)$")


def local_address(value):
    host = (value or "").strip()
    if host in ("", "*", "localhost", "0.0.0.0"):
        return "127.0.0.1"
    if host in ("::", "[::]"):
        return "[::1]"
    address = ipaddress.ip_address(host.removeprefix("[").removesuffix("]"))
    if address.is_multicast or address.is_link_local:
        raise ValueError("unsupported BindAddress")
    if not address.is_loopback:
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.bind((str(address), 0))
        except OSError:
            raise ValueError("BindAddress is not local") from None
    return f"[{address}]" if address.version == 6 else str(address)


def read_upstream(app):
    try:
        with ManagedConfig(f"/var/lib/{app}/config.xml", create_parents=False) as config:
            if config.descriptor is None:
                return None
            raw = config.read_bytes(max_bytes=256 * 1024)
            config.check_target()
    except FileNotFoundError:
        return None

    try:
        xml = raw.decode("utf-8-sig")
        if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
            raise ValueError("unsupported XML declaration")
        document = ET.fromstring(xml)
        if document.tag != "Config":
            raise ValueError("unexpected XML root")
        key = (document.findtext("ApiKey") or "").strip()
        if not key or any(ord(char) < 32 or ord(char) == 127 for char in key):
            raise ValueError("missing or invalid API key")
        port = int((document.findtext("Port") or "").strip() or PORTS[app])
        if not 1 <= port <= 65535:
            raise ValueError("invalid port")
        base = (document.findtext("UrlBase") or "").strip().rstrip("/")
        if base:
            base = base if base.startswith("/") else f"/{base}"
            if not re.fullmatch(r"/[A-Za-z0-9._/-]*", base) or any(
                part in ("", ".", "..") for part in base[1:].split("/")
            ):
                raise ValueError("invalid URL base")
        return f"http://{local_address(document.findtext('BindAddress'))}:{port}{base}", key
    except (ET.ParseError, ValueError):
        # Parser errors can include configuration excerpts. Keep XML out of logs.
        print(f"WARN: Skipped {app} integration because config.xml is incomplete or invalid")
        return None


def fresh_config(consumer, app_port, log_dir):
    result = tomlkit.document()
    if consumer == "notifiarr":
        port = int(app_port)
        if not 1 <= port <= 65535 or not log_dir:
            raise ValueError("Invalid Notifiarr configuration settings")
        result.add(tomlkit.comment("Notifiarr configuration"))
        defaults = {
            "api_key": "", "bind_addr": f"127.0.0.1:{port}", "ui_password": "",
            "urlbase": "/", "quiet": False,
            "log_file": os.path.join(log_dir, "app.log"),
            "http_log": os.path.join(log_dir, "http.log"),
        }
    else:
        result.add(tomlkit.comment("Unpackerr Configuration - Generated by AetherFlow"))
        defaults = {
            "debug": False, "quiet": False, "error_stderr": False, "activity": False,
            "log_queues": "1m", "log_files": 10, "log_file_mb": 10, "interval": "2m",
            "start_delay": "1m", "retry_delay": "5m", "max_retries": 3, "parallel": 1,
            "file_mode": "0644", "dir_mode": "0755",
        }
    result.update(defaults)
    return result


def get_managed_table(document, consumer, app, key):
    group = document.get(app)
    if isinstance(group, AoT):
        tables = list(group)
    elif consumer == "unpackerr" and isinstance(group, MutableMapping):
        tables = [entry for entry in group.values() if isinstance(entry, Table)]
    else:
        return None
    expected_name = f"AetherFlow {app.capitalize()}"
    stock_url = f"http://127.0.0.1:{PORTS[app]}"
    for table in tables:
        if consumer == "notifiarr" and table.get("name", expected_name) != expected_name:
            continue
        url = table.get("url")
        saved_key = table.get("api_key")
        comment = table.trivia.comment.removeprefix("#").strip()
        marker = MANAGED.search(comment)
        if marker and url in (None, "", marker[1]) and saved_key in (None, "", key):
            return table
        if not marker and isinstance(url, str) and url.rstrip("/") == stock_url and saved_key == key:
            if consumer != "notifiarr" or table.get("name") == expected_name:
                return table
    return None


def update_integration(document, consumer, app, url, key):
    if app not in document:
        table = tomlkit.table()
        if consumer == "notifiarr":
            table["name"] = f"AetherFlow {app.capitalize()}"
            group = tomlkit.aot()
            group.append(table)
            document[app] = group
        else:
            paths = ["/downloads", "/mnt/unionfs"]
            if app in ("sonarr", "radarr"):
                paths.append("/var/lib/rtorrent/downloads")
            table.update({"paths": paths, "protocols": "torrent", "timeout": "10s", "delete_orig": False})
            group = tomlkit.table(is_super_table=True)
            group["0"] = table
            document[app] = group
    else:
        table = get_managed_table(document, consumer, app, key)
        if table is None:
            print(f"INFO: Preserved operator-configured {app} integration")
            return

    if table.get("url") != url:
        table["url"] = url
    if not table.get("api_key"):
        table["api_key"] = key
    existing_comment = table.trivia.comment.removeprefix("#").strip()
    operator_comment = MANAGED.sub("", existing_comment)
    managed_comment = " | ".join(filter(None, (operator_comment, f"aetherflow-managed {url}")))
    if managed_comment != existing_comment:
        table.comment(managed_comment)
    print(f"INFO: Configured local {app} integration")


def sync(consumer, path, app_port, log_dir):
    if consumer not in ("notifiarr", "unpackerr"):
        raise ValueError("Unsupported Servarr integration consumer")
    apps = [app for app in PORTS if consumer == "notifiarr" or app != "prowlarr"]
    discovered = {app: value for app in apps if (value := read_upstream(app)) is not None}
    with ManagedConfig(path, create_parents=True) as config:
        existing = config.read_text(max_bytes=1024 * 1024)
        try:
            document = tomlkit.parse(existing) if existing.strip() else fresh_config(consumer, app_port, log_dir)
        except TOMLKitError:
            print(f"WARN: Preserved {consumer} configuration because its TOML could not be parsed")
            return
        if consumer == "unpackerr":
            # Unpackerr v1 enables a network listener and rewrites the config
            # to persist a UI password unless the listen address is empty.
            webserver = document.get("webserver")
            if webserver is None:
                webserver = tomlkit.table()
                document["webserver"] = webserver
            if isinstance(webserver, MutableMapping) and "listen_addr" not in webserver:
                webserver["listen_addr"] = ""

        for app, (url, key) in discovered.items():
            update_integration(document, consumer, app, url, key)
        if consumer == "unpackerr" and not existing.strip():
            for app in ("sonarr", "radarr"):
                if app not in discovered:
                    document.add(tomlkit.nl())
                    document.add(tomlkit.comment(f"[{app}.0]"))
                    document.add(tomlkit.comment(f'  url = "http://127.0.0.1:{PORTS[app]}"'))
                    document.add(tomlkit.comment('  api_key = ""'))
                    document.add(tomlkit.comment('  paths = ["/downloads", "/mnt/unionfs"]'))
        rendered = document.as_string()
        if rendered != existing:
            config.write_text(rendered, 0o600)
    if not discovered:
        print(f"INFO: No local Servarr upstreams configured for {consumer}; reinstall after installing Servarr apps")


sync(*sys.argv[1:5])
PYEOF
    )" || return $?
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        level="${line%%:*}"
        message="${line#*: }"
        case "$level" in
            WARN)
                if declare -F log_warn >/dev/null 2>&1; then
                    log_warn "$message"
                fi
                ;;
            INFO)
                if declare -F log_info >/dev/null 2>&1; then
                    log_info "$message"
                fi
                ;;
        esac
    done <<< "$summary"
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
    AF_ARCHIVE_ROLLBACK_HOOK=""
    for entry in "$state" "${7:-}"; do
        [[ -n "$entry" ]] || continue
        [[ ! -L "$entry" ]] || return 1
        AF_ARCHIVE_STATE_PATHS+=("$entry")
        if [[ "$entry" == *.db ]]; then
            AF_ARCHIVE_STATE_PATHS+=("${entry}-wal" "${entry}-shm")
        fi
    done
    AF_ARCHIVE_UNIT="$unit"
    AF_ARCHIVE_TIMER_UNIT=""
    AF_ARCHIVE_TIMER_ACTIVE=false
    AF_ARCHIVE_TIMER_ENABLED=false
    AF_ARCHIVE_SOCKET_UNIT=""
    AF_ARCHIVE_SOCKET_ACTIVE=false
    AF_ARCHIVE_SOCKET_ENABLED=false
    if [[ "$unit" != *.timer && "$unit" != *.socket ]]; then
        AF_ARCHIVE_TIMER_UNIT="${unit%.service}.timer"
        AF_ARCHIVE_SOCKET_UNIT="${unit%.service}.socket"
    fi
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
        if hasattr(tarfile, 'fully_trusted_filter'):
            archive.extractall(sys.argv[2], members=members, filter=tarfile.fully_trusted_filter)
        else:
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
    if [[ -n "${AF_ARCHIVE_TIMER_UNIT:-}" ]]; then
        if systemctl is-active --quiet "$AF_ARCHIVE_TIMER_UNIT" 2>/dev/null; then
            AF_ARCHIVE_TIMER_ACTIVE=true
        fi
        if systemctl is-enabled --quiet "$AF_ARCHIVE_TIMER_UNIT" 2>/dev/null; then
            AF_ARCHIVE_TIMER_ENABLED=true
        fi
        if [[ -e "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" ]]; then
            cp -a -- "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" "$AF_ARCHIVE_BACKUP/timer_unit"
        fi
        if [[ "$AF_ARCHIVE_TIMER_ACTIVE" == true || -e "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" ]]; then
            stop_systemd_unit "$AF_ARCHIVE_TIMER_UNIT"
        fi
    fi
    if [[ -n "${AF_ARCHIVE_SOCKET_UNIT:-}" ]]; then
        if systemctl is-active --quiet "$AF_ARCHIVE_SOCKET_UNIT" 2>/dev/null; then
            AF_ARCHIVE_SOCKET_ACTIVE=true
        fi
        if systemctl is-enabled --quiet "$AF_ARCHIVE_SOCKET_UNIT" 2>/dev/null; then
            AF_ARCHIVE_SOCKET_ENABLED=true
        fi
        if [[ -e "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" ]]; then
            cp -a -- "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" "$AF_ARCHIVE_BACKUP/socket_unit"
        fi
        if [[ "$AF_ARCHIVE_SOCKET_ACTIVE" == true || -e "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" ]]; then
            stop_systemd_unit "$AF_ARCHIVE_SOCKET_UNIT"
        fi
    fi
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
        local -a quiesce_units=()
        if [[ -n "${AF_ARCHIVE_TIMER_UNIT:-}" && ( -e "${AF_ARCHIVE_BACKUP:-}/timer_unit" || -e "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" || "${AF_ARCHIVE_TIMER_ACTIVE:-false}" == true ) ]]; then
            quiesce_units+=("$AF_ARCHIVE_TIMER_UNIT")
        fi
        if [[ -n "${AF_ARCHIVE_SOCKET_UNIT:-}" && ( -e "${AF_ARCHIVE_BACKUP:-}/socket_unit" || -e "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" || "${AF_ARCHIVE_SOCKET_ACTIVE:-false}" == true ) ]]; then
            quiesce_units+=("$AF_ARCHIVE_SOCKET_UNIT")
        fi
        quiesce_units+=("$AF_ARCHIVE_UNIT")
        if ! quiesce_services_for_rollback "${quiesce_units[@]}"; then
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
            af_logged systemctl disable -- "$AF_ARCHIVE_UNIT" || restored=false
            rm -f -- "/etc/systemd/system/${AF_ARCHIVE_UNIT}.service" || restored=false
        fi
        if [[ -n "${AF_ARCHIVE_TIMER_UNIT:-}" ]]; then
            if [[ -e "$AF_ARCHIVE_BACKUP/timer_unit" ]]; then
                safe_restore_path_from_backup "$AF_ARCHIVE_BACKUP/timer_unit" "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" || restored=false
            elif [[ -e "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" ]]; then
                af_logged systemctl disable -- "$AF_ARCHIVE_TIMER_UNIT" || restored=false
                rm -f -- "/etc/systemd/system/${AF_ARCHIVE_TIMER_UNIT}" || restored=false
            fi
        fi
        if [[ -n "${AF_ARCHIVE_SOCKET_UNIT:-}" ]]; then
            if [[ -e "$AF_ARCHIVE_BACKUP/socket_unit" ]]; then
                safe_restore_path_from_backup "$AF_ARCHIVE_BACKUP/socket_unit" "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" || restored=false
                if [[ "${AF_ARCHIVE_SOCKET_ENABLED:-false}" != true ]]; then
                    af_logged systemctl disable -- "$AF_ARCHIVE_SOCKET_UNIT" || restored=false
                fi
            elif [[ -e "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" || -L "/etc/systemd/system/sockets.target.wants/${AF_ARCHIVE_SOCKET_UNIT}" ]]; then
                af_logged systemctl disable -- "$AF_ARCHIVE_SOCKET_UNIT" || restored=false
                rm -f -- "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}" "/etc/systemd/system/sockets.target.wants/${AF_ARCHIVE_SOCKET_UNIT}" || restored=false
                rm -rf -- "/etc/systemd/system/${AF_ARCHIVE_SOCKET_UNIT}.d" || restored=false
            fi
        fi
        af_logged systemctl daemon-reload || restored=false
    fi
    if [[ "$restored" == true && -n "${AF_ARCHIVE_ROLLBACK_HOOK:-}" ]] && declare -F "$AF_ARCHIVE_ROLLBACK_HOOK" >/dev/null 2>&1; then
        "$AF_ARCHIVE_ROLLBACK_HOOK" || restored=false
    fi
    if [[ "$restored" == true ]]; then
        for entry in "${AF_ARCHIVE_ROLLBACK_RESTART_UNITS[@]}"; do
            af_logged systemctl restart "$entry" || restored=false
        done
    fi
    if [[ "$restored" == true && -n "${AF_ARCHIVE_SOCKET_UNIT:-}" && -e "$AF_ARCHIVE_BACKUP/socket_unit" ]]; then
        if [[ "${AF_ARCHIVE_SOCKET_ENABLED:-false}" == true ]]; then
            af_logged systemctl enable -- "$AF_ARCHIVE_SOCKET_UNIT" || restored=false
        fi
        if [[ "$restored" == true && "${AF_ARCHIVE_SOCKET_ACTIVE:-false}" == true ]]; then
            af_logged systemctl restart "$AF_ARCHIVE_SOCKET_UNIT" || restored=false
        fi
    fi
    if [[ "$restored" == true && "${AF_ARCHIVE_STOPPED:-false}" == true && "${AF_ARCHIVE_PREVIOUS:-false}" == true ]]; then
        af_logged systemctl restart "$AF_ARCHIVE_UNIT" || restored=false
    fi
    if [[ "$restored" == true && -n "${AF_ARCHIVE_TIMER_UNIT:-}" ]]; then
        if [[ "${AF_ARCHIVE_TIMER_ENABLED:-false}" == true ]]; then
            af_logged systemctl enable -- "$AF_ARCHIVE_TIMER_UNIT" || restored=false
        fi
        if [[ "$restored" == true && "${AF_ARCHIVE_TIMER_ACTIVE:-false}" == true ]]; then
            af_logged systemctl restart "$AF_ARCHIVE_TIMER_UNIT" || restored=false
        fi
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
    local package_name="$1" port="$2" apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}" config staged listen_addr="127.0.0.1"
    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ && "$port" =~ ^[0-9]+$ ]] || return 1
    (( port >= 1024 && port <= 65535 )) || return 1
    if [[ "${AF_APACHE_LISTEN_ALL:-0}" == "1" ]]; then
        listen_addr="0.0.0.0"
    fi
    config="aetherflow-${package_name}-listen.conf"
    mkdir -p "$apache_root/conf-available" "$apache_root/conf-enabled"
    if grep -Eq "^[[:space:]]*Listen[[:space:]]+(${listen_addr}:)?${port}([[:space:]]|$)" "$apache_root/ports.conf" 2>/dev/null; then
        rm -f -- "$apache_root/conf-enabled/$config" "$apache_root/conf-available/$config"
        log_info "Reusing existing shared Apache listener on $port"
        return 0
    fi
    staged="$(mktemp "$apache_root/conf-available/.${config}.XXXXXX")"
    if ! printf 'Listen %s:%s\n' "$listen_addr" "$port" > "$staged" || ! chmod 644 "$staged" || ! mv -f -- "$staged" "$apache_root/conf-available/$config"; then
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

apache_app_readiness_target() {
    local package_name="$1" port="$2" default_path="${3:-/}" apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}" vhost_conf expected_root
    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
    (( 10#$port > 0 && 10#$port <= 65535 )) || return 1
    [[ "$default_path" == /* ]] || return 1
    vhost_conf="${apache_root}/sites-available/${package_name}.conf"
    expected_root="/var/www/${package_name}"
    if [[ ! -e "$vhost_conf" && ! -L "$vhost_conf" ]]; then
        printf 'http://127.0.0.1:%s%s\n\n' "$port" "$default_path"
        return 0
    fi
    safe_config_python "$vhost_conf" "$port" "$default_path" "$expected_root" <<'PYEOF'
import re, sys

vhost_conf, fallback_port, default_path, expected_root = sys.argv[1:5]
raw = safe_read_text(vhost_conf)

blocks = []
current = None
for line in raw.splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        continue
    m_open = re.match(r'^<VirtualHost\s+([^>]+)>\s*$', stripped, re.IGNORECASE)
    if m_open:
        current = {'header': m_open.group(1).strip(), 'lines': []}
        blocks.append(current)
        continue
    if re.match(r'^</VirtualHost>\s*$', stripped, re.IGNORECASE):
        current = None
        continue
    if current is not None:
        current['lines'].append(stripped)

def parse_vhost_endpoint(header):
    tokens = header.split()
    token = tokens[0] if tokens else ''
    m = re.fullmatch(r'(\[[^\]]+\]|[^:\s]+)(?::([0-9]+|\*))?', token)
    if not m:
        return '127.0.0.1', None
    raw_host, raw_port = m.group(1), m.group(2)
    port_val = raw_port if (raw_port and raw_port.isdecimal() and 1 <= int(raw_port) <= 65535) else None
    return raw_host, port_val

selected = None
for block in blocks:
    _, block_port = parse_vhost_endpoint(block['header'])
    if block_port == fallback_port:
        selected = block
        break
if selected is None and blocks:
    selected = blocks[0]

raw_host = '127.0.0.1'
port = fallback_port
if selected is not None:
    raw_host, parsed_port = parse_vhost_endpoint(selected['header'])
    if parsed_port is not None:
        port = parsed_port
    lines = selected['lines']
else:
    lines = [l.strip() for l in raw.splitlines() if l.strip() and not l.strip().startswith('#')]

host_map = {'*': '127.0.0.1', '_default_': '127.0.0.1', '0.0.0.0': '127.0.0.1', '127.0.0.1': '127.0.0.1', '::': '[::1]', '[::]': '[::1]', '::1': '[::1]', '[::1]': '[::1]'}
host = host_map.get(raw_host.lower(), raw_host)
if not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]+', host):
    raise ValueError('Unsafe Apache VirtualHost listener')
if ':' in host and not host.startswith('['):
    host = '[' + host + ']'

scheme = 'http'
server_name = ''
docroot = None
aliases = []

def unquote(val):
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1]
    return val

for line in lines:
    if re.match(r'^SSLEngine\s+on(?:\s|$|#)', line, re.IGNORECASE):
        scheme = 'https'
    m_sn = re.match(r'^ServerName\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
    if m_sn and not server_name:
        cand = unquote(m_sn.group(1))
        cand = re.sub(r'^https?://', '', cand, flags=re.IGNORECASE)
        cand = cand.split(':', 1)[0].strip()
        if re.fullmatch(r'[A-Za-z0-9._-]+', cand):
            server_name = cand
    m_dr = re.match(r'^DocumentRoot\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
    if m_dr and docroot is None:
        docroot = unquote(m_dr.group(1)).rstrip('/') or '/'
    m_al = re.match(r'^Alias\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
    if m_al:
        aliases.append((unquote(m_al.group(1)), unquote(m_al.group(5)).rstrip('/') or '/'))

expected_norm = expected_root.rstrip('/') or '/'
probe_path = default_path
if docroot is not None and docroot != expected_norm:
    for prefix, target in aliases:
        if target == expected_norm and re.fullmatch(r'/[A-Za-z0-9._/-]*', prefix):
            parts = prefix.split('/')
            if '..' not in parts and '.' not in parts and '//' not in prefix:
                clean_prefix = prefix.rstrip('/')
                if default_path == '/':
                    probe_path = (clean_prefix + '/') if clean_prefix else '/'
                else:
                    probe_path = clean_prefix + default_path
                break

print(f'{scheme}://{host}:{port}{probe_path}')
print(server_name)
PYEOF
}

apache_app_probe_body_is_healthy() {
    local package_name="$1" probe_file="$2" sample="" trimmed=""
    sample="$(head -c 8192 "$probe_file" 2>/dev/null | tr -d '\0' || true)"
    trimmed="${sample#"${sample%%[![:space:]]*}"}"
    if [[ "$trimmed" == '<?='* || "$trimmed" == $'\xef\xbb\xbf<?='* ]]; then
        return 1
    fi
    if printf '%s' "$sample" | LC_ALL=C grep -Eiq '<\?php([[:space:]]|$)'; then
        return 1
    fi
    if printf '%s' "$sample" | LC_ALL=C grep -Eiq '<b>(Fatal|Parse) error</b>:|(^|[[:space:]])(Fatal|Parse) error:.* in /'; then
        return 1
    fi
    if printf '%s' "$sample" | LC_ALL=C grep -Eiq 'Apache2 (Debian|Ubuntu) Default Page|<h1[^>]*>[[:space:]]*It works![[:space:]]*</h1>'; then
        return 1
    fi
    if [[ "$package_name" == "nextcloud" ]]; then
        if printf '%s' "$sample" | LC_ALL=C grep -Eiq '"installed"[[:space:]]*:[[:space:]]*false|"maintenance"[[:space:]]*:[[:space:]]*true'; then
            return 1
        fi
    fi
    return 0
}

wait_for_apache_app_ready() {
    local package_name="$1" port="$2" default_path="${3:-/}" attempts="${4:-${AF_READINESS_ATTEMPTS:-30}}"
    local attempt target_output="" ready_url="" server_name="" probe_file="" http_status="" auth_credentials=""
    local -a target_lines=() curl_tls_args=() curl_host_args=()
    local loopback_https_re='^https://(127(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|\[::1\]|localhost)(:[0-9]{1,5})?(/.*)?$'
    local loopback_url_re='^https?://(127(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|\[::1\]|localhost)(:[0-9]{1,5})?(/.*)?$'

    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    [[ "$port" =~ ^[0-9]{1,5}$ && "$attempts" =~ ^[1-9][0-9]*$ ]] || return 1
    (( 10#$port > 0 && 10#$port <= 65535 && 10#$attempts <= 300 )) || return 1
    [[ "$default_path" == /* ]] || return 1

    target_output="$(apache_app_readiness_target "$package_name" "$port" "$default_path")" || return 1
    mapfile -t target_lines <<< "$target_output"
    ready_url="${target_lines[0]:-}"
    server_name="${target_lines[1]:-}"
    [[ -n "$ready_url" ]] || return 1

    if [[ "$ready_url" =~ $loopback_https_re ]]; then
        curl_tls_args=(-k)
    fi
    if [[ -n "$server_name" ]]; then
        curl_host_args=(-H "Host: ${server_name}")
    fi
    if [[ "$package_name" == "rutorrent" && "$ready_url" =~ $loopback_url_re && -n "${MASTER_USER:-}" && -n "${MASTER_PASS:-}" ]]; then
        auth_credentials="${MASTER_USER}:${MASTER_PASS}"
        auth_credentials="${auth_credentials//\\/\\\\}"
        auth_credentials="${auth_credentials//\"/\\\"}"
        if [[ "$auth_credentials" == *$'\n'* || "$auth_credentials" == *$'\r'* ]]; then
            auth_credentials=""
        fi
    fi

    local probe_dir="${TMPDIR:-/tmp}"
    mkdir -p "$probe_dir" || return 1
    probe_file="$(mktemp "${probe_dir}/af-apache-ready.XXXXXX")" || return 1
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if systemctl is-active --quiet apache2; then
            : >"$probe_file"
            if curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" -fsS --connect-timeout 2 --max-time 5 "$ready_url" >"$probe_file" 2>/dev/null; then
                if apache_app_probe_body_is_healthy "$package_name" "$probe_file"; then
                    rm -f -- "$probe_file"
                    return 0
                fi
            else
                http_status="$(curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$ready_url" 2>/dev/null || true)"
                if [[ "$http_status" == "401" ]]; then
                    if [[ -n "$auth_credentials" ]]; then
                        : >"$probe_file"
                        if printf 'user = "%s"\n' "$auth_credentials" | curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" -K - -fsS --connect-timeout 2 --max-time 5 "$ready_url" >"$probe_file" 2>/dev/null; then
                            if apache_app_probe_body_is_healthy "$package_name" "$probe_file"; then
                                rm -f -- "$probe_file"
                                return 0
                            fi
                        else
                            http_status="$(printf 'user = "%s"\n' "$auth_credentials" | curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" -K - -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$ready_url" 2>/dev/null || true)"
                            if [[ "$http_status" == "401" ]]; then
                                rm -f -- "$probe_file"
                                return 0
                            fi
                        fi
                    else
                        rm -f -- "$probe_file"
                        return 0
                    fi
                fi
            fi
        fi
        if (( attempt < attempts )); then sleep 1; fi
    done
    rm -f -- "$probe_file"
    print_error "Apache application ${package_name} did not become ready at ${ready_url}."
    return 1
}

apache_app_prepare_maintenance_vhost() {
    local package_name="$1" port="$2" default_path="${3:-/}"
    local apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}" maint_conf
    local -a app_roots=("/var/www/${package_name}") optional_roots=()
    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 2
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 2
    (( 10#$port > 0 && 10#$port <= 65535 )) || return 2
    [[ "$default_path" == /* ]] || return 2
    case "$package_name" in
        nextcloud) optional_roots+=("/var/www/html/nextcloud") ;;
        rutorrent) app_roots+=("/srv/rutorrent") ;;
    esac
    maint_conf="${apache_root}/sites-available/aetherflow-${package_name}-maintenance.conf"
    safe_config_python "$apache_root" "$package_name" "$port" "$default_path" "$maint_conf" "${#app_roots[@]}" "${app_roots[@]}" "${optional_roots[@]}" <<'PYEOF'
import glob, os, posixpath, re, stat, sys

apache_root, package_name, fallback_port, default_path, maint_conf = sys.argv[1:6]
primary_count = int(sys.argv[6])
primary_roots = sys.argv[7:7 + primary_count]
optional_roots = sys.argv[7 + primary_count:]

sites_avail = os.path.join(apache_root, 'sites-available')
sites_en = os.path.join(apache_root, 'sites-enabled')
conf_en = os.path.join(apache_root, 'conf-enabled')
site_name = f'{package_name}.conf'
maint_name = f'aetherflow-{package_name}-maintenance.conf'
listen_name = f'aetherflow-{package_name}-listen.conf'
site_link = os.path.join(sites_en, site_name)
site_avail = os.path.join(sites_avail, site_name)
legacy_conf_link = os.path.join(conf_en, site_name)

def norm_path(value):
    val = value.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        val = val[1:-1]
    if not val:
        return ''
    return posixpath.normpath(val)

def path_variants(path_str):
    out = set()
    p = norm_path(path_str)
    if p:
        out.add(p)
        if os.path.lexists(p):
            try:
                out.add(os.path.realpath(p))
            except OSError:
                pass
    return out

protected_exact = set()
protected_docroot_targets = set()
for r in primary_roots:
    vs = path_variants(r)
    protected_exact.update(vs)
    protected_docroot_targets.update(vs)
for r in optional_roots:
    vs = path_variants(r)
    protected_exact.update(vs)
    if os.path.lexists(r):
        protected_docroot_targets.update(vs)

def is_same_or_child(path_a, path_b):
    if path_a == path_b:
        return True
    prefix = path_b if path_b == '/' else path_b + '/'
    return path_a.startswith(prefix)

def path_exposes_app(candidate, is_docroot=False):
    cands = path_variants(candidate)
    for c in cands:
        for target in protected_exact:
            if is_same_or_child(c, target):
                return target
        if is_docroot:
            for target in protected_docroot_targets:
                if is_same_or_child(target, c):
                    return target
    return None

def expand_includes(pattern, optional):
    pat = norm_path(pattern)
    if not pat:
        return []
    if not os.path.isabs(pat):
        pat = os.path.join(apache_root, pat)
    matches = sorted(glob.glob(pat))
    if not matches and not optional and not os.path.lexists(pat):
        return None
    result = []
    for m in matches:
        if os.path.isdir(m):
            for entry in sorted(os.listdir(m)):
                full = os.path.join(m, entry)
                if os.path.isfile(full):
                    result.append(full)
        else:
            result.append(m)
    return result

def scan_external_file(file_path, label, depth=0, seen=None):
    if seen is None:
        seen = set()
    if depth > 3:
        return f'deep Apache Include nesting in {label}'
    if not os.path.exists(file_path):
        return f'dangling or missing Apache config {label}'
    try:
        real = os.path.realpath(file_path)
        st = os.stat(real)
        if not stat.S_ISREG(st.st_mode):
            return f'non-regular Apache config {label}'
    except OSError:
        return f'unreadable Apache config {label}'
    if real in seen:
        return None
    seen.add(real)
    try:
        with open(real, 'r', encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError:
        return f'unreadable Apache config {label}'
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        m_dr = re.match(r'^DocumentRoot\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_dr:
            hit = path_exposes_app(m_dr.group(1), is_docroot=True)
            if hit:
                return f'external Apache config {label} DocumentRoot exposes {hit}'
            continue
        m_al = re.match(r'^(?:Alias|AliasMatch|ScriptAlias)\s+(?:"[^"]+"|\'[^\']+\'|[^\s#]+)\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_al:
            hit = path_exposes_app(m_al.group(1), is_docroot=True)
            if hit:
                return f'external Apache config {label} Alias exposes {hit}'
            continue
        m_dir = re.match(r'^<Directory\s+("([^"]+)"|\'([^\']+)\'|([^>\s]+))\s*>', line, re.IGNORECASE)
        if m_dir:
            hit = path_exposes_app(m_dir.group(1), is_docroot=False)
            if hit:
                return f'external Apache config {label} Directory exposes {hit}'
            continue
        m_inc = re.match(r'^(IncludeOptional|Include)\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_inc:
            is_opt = m_inc.group(1).lower() == 'includeoptional'
            inc_files = expand_includes(m_inc.group(2), is_opt)
            if inc_files is None:
                return f'unreadable Include in {label}'
            for inc_file in inc_files:
                blocker = scan_external_file(inc_file, f'{label}->{inc_file}', depth + 1, seen)
                if blocker:
                    return blocker
    return None

def unsupported(reason):
    print('MODE=unsupported')
    print(f'REASON={reason}')
    sys.exit(0)

for sub_label, dir_path, skip_names in (
    ('sites-enabled', sites_en, {site_name}),
    ('conf-enabled', conf_en, {site_name, listen_name}),
):
    if not os.path.isdir(dir_path):
        continue
    for entry in sorted(os.listdir(dir_path)):
        if not entry.endswith('.conf') or entry in skip_names:
            continue
        blocker = scan_external_file(os.path.join(dir_path, entry), f'{sub_label}/{entry}')
        if blocker:
            unsupported(blocker)

has_site = os.path.lexists(site_link)
has_legacy_conf = os.path.lexists(legacy_conf_link)

if not has_site and not has_legacy_conf:
    print('MODE=none')
    sys.exit(0)

if not has_site:
    print('MODE=maintenance')
    print('HAS_SITE=0')
    print('HAS_LEGACY_CONF=1')
    sys.exit(0)

# Validate sites-enabled/<app>.conf safely (fail closed on symlink escape).
try:
    if os.path.islink(site_link):
        if not os.path.isdir(sites_avail):
            raise ValueError(f'Missing Apache sites-available directory for {site_link}')
        avail_real = os.path.realpath(sites_avail)
        target_real = os.path.realpath(site_link)
        if os.path.dirname(target_real) != avail_real or os.path.basename(target_real) not in (site_name, maint_name):
            raise ValueError(f'Unsafe Apache site symlink target: {site_link}')
        if not os.path.isfile(target_real):
            raise ValueError(f'Apache site target is not a regular file: {site_link}')
        raw = safe_read_text(site_avail)
    else:
        raw = safe_read_text(site_link)
except Exception as exc:
    sys.stderr.write(f'ERROR: {exc}\n')
    sys.exit(2)

def unquote(val):
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1]
    return val

def include_is_ssl_only(pattern, optional):
    files = expand_includes(pattern, optional)
    if files is None:
        return False
    for path in files:
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                for raw_l in fh:
                    s = raw_l.strip()
                    if not s or s.startswith('#'):
                        continue
                    if not re.match(r'^SSL[A-Za-z0-9_]+\b', s, re.IGNORECASE):
                        return False
        except OSError:
            return False
    return True

blocks = []
current = None
for raw_line in raw.splitlines():
    stripped = raw_line.strip()
    if not stripped or stripped.startswith('#'):
        continue
    m_open = re.match(r'^<VirtualHost\s+([^>]+)>\s*$', stripped, re.IGNORECASE)
    if m_open:
        if current is not None:
            unsupported(f'nested VirtualHost in {site_name}')
        current = {'header': m_open.group(1).strip(), 'lines': []}
        blocks.append(current)
        continue
    if re.match(r'^</VirtualHost>\s*$', stripped, re.IGNORECASE):
        if current is None:
            unsupported(f'unmatched </VirtualHost> in {site_name}')
        current = None
        continue
    if current is not None:
        current['lines'].append(stripped)
    else:
        unsupported(f'top-level non-VirtualHost directive in {site_name}')

if current is not None or not blocks:
    unsupported(f'missing or unclosed VirtualHost block in {site_name}')

allowed_identity_re = re.compile(
    r'^(?:ServerName|ServerAlias|SSLEngine|SSLCertificateFile|SSLCertificateKeyFile|'
    r'SSLCertificateChainFile|SSLCACertificateFile|SSLProtocol|SSLCipherSuite|'
    r'SSLHonorCipherOrder|SSLCompression|SSLSessionTickets)\s+',
    re.IGNORECASE,
)

def parse_vhost_endpoint(header):
    tokens = header.split()
    token = tokens[0] if tokens else ''
    m = re.fullmatch(r'(\[[^\]]+\]|[^:\s]+)(?::([0-9]+|\*))?', token)
    if not m:
        return '127.0.0.1', None
    raw_host, raw_port = m.group(1), m.group(2)
    port_val = raw_port if (raw_port and raw_port.isdecimal() and 1 <= int(raw_port) <= 65535) else None
    return raw_host, port_val

host_map = {'*': '127.0.0.1', '_default_': '127.0.0.1', '0.0.0.0': '127.0.0.1', '127.0.0.1': '127.0.0.1', '::': '[::1]', '[::]': '[::1]', '::1': '[::1]', '[::1]': '[::1]'}
expected_norm = norm_path(primary_roots[0]) or '/'

rendered_blocks = []
probes = []
seen_probes = set()

for block in blocks:
    preserved = []
    scheme = 'http'
    server_name = ''
    docroot = None
    aliases = []
    for line in block['lines']:
        m_inc = re.match(r'^(IncludeOptional|Include)\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_inc:
            is_opt = m_inc.group(1).lower() == 'includeoptional'
            if include_is_ssl_only(m_inc.group(2), is_opt):
                preserved.append(line)
                continue
            unsupported(f'non-SSL Include directive inside VirtualHost in {site_name}')
        if allowed_identity_re.match(line):
            preserved.append(line)
        if re.match(r'^SSLEngine\s+on(?:\s|$|#)', line, re.IGNORECASE):
            scheme = 'https'
        m_sn = re.match(r'^ServerName\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_sn and not server_name:
            cand = unquote(m_sn.group(1))
            cand = re.sub(r'^https?://', '', cand, flags=re.IGNORECASE)
            cand = cand.split(':', 1)[0].strip()
            if re.fullmatch(r'[A-Za-z0-9._-]+', cand):
                server_name = cand
        m_dr = re.match(r'^DocumentRoot\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_dr and docroot is None:
            docroot = unquote(m_dr.group(1)).rstrip('/') or '/'
        m_al = re.match(r'^Alias\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_al:
            aliases.append((unquote(m_al.group(1)), unquote(m_al.group(5)).rstrip('/') or '/'))

    raw_host, parsed_port = parse_vhost_endpoint(block['header'])
    probe_port = parsed_port or ('443' if scheme == 'https' else fallback_port)
    probe_host = host_map.get(raw_host.lower(), raw_host)
    if not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]+', probe_host):
        unsupported(f'unsafe VirtualHost listener {raw_host} in {site_name}')
    if ':' in probe_host and not probe_host.startswith('['):
        probe_host = '[' + probe_host + ']'

    probe_path = default_path
    if docroot is not None and docroot != expected_norm:
        for prefix, target in aliases:
            if target == expected_norm and re.fullmatch(r'/[A-Za-z0-9._/-]*', prefix):
                parts = prefix.split('/')
                if '..' not in parts and '.' not in parts and '//' not in prefix:
                    clean_prefix = prefix.rstrip('/')
                    if default_path == '/':
                        probe_path = (clean_prefix + '/') if clean_prefix else '/'
                    else:
                        probe_path = clean_prefix + default_path
                    break

    probe_key = (f'{scheme}://{probe_host}:{probe_port}{probe_path}', server_name)
    if probe_key not in seen_probes:
        seen_probes.add(probe_key)
        probes.append(probe_key)

    lines_out = [f"<VirtualHost {block['header']}>"]
    for pl in preserved:
        lines_out.append(f'    {pl}')
    lines_out.extend([
        f'    ErrorDocument 503 "AetherFlow maintenance in progress for {package_name}"',
        '    <IfModule mod_headers.c>',
        '        Header always set Retry-After "30"',
        '        Header always set Cache-Control "no-store"',
        f'        Header always set X-AetherFlow-Maintenance "{package_name}"',
        '    </IfModule>',
        '    <IfModule mod_alias.c>',
        '        RedirectMatch 503 ^',
        '    </IfModule>',
        '    <IfModule !mod_alias.c>',
        '        <Location />',
        '            Require all denied',
        '        </Location>',
        '    </IfModule>',
        '</VirtualHost>',
    ])
    rendered_blocks.append('\n'.join(lines_out))

maint_content = '# Managed temporarily by AetherFlow during application maintenance\n' + '\n\n'.join(rendered_blocks) + '\n'
try:
    safe_write_text(maint_conf, maint_content, 0o644)
except Exception as exc:
    sys.stderr.write(f'ERROR: {exc}\n')
    sys.exit(2)

print('MODE=maintenance')
print('HAS_SITE=1')
print(f'HAS_LEGACY_CONF={1 if has_legacy_conf else 0}')
for url, sn in probes:
    print(f'PROBE={url}\t{sn}')
PYEOF
}

apache_app_capture_worker_pids() {
    local master_pid="" pid="" ppid="" stat_file="" stat_line="" _state=""
    local -a children=()
    if [[ -n "${AF_APACHE_PIDFILE:-}" && -f "${AF_APACHE_PIDFILE}" && ! -L "${AF_APACHE_PIDFILE}" ]]; then
        master_pid="$(tr -dc '0-9' < "${AF_APACHE_PIDFILE}" 2>/dev/null || true)"
    else
        master_pid="$(systemctl show --property=MainPID --value apache2 2>/dev/null || true)"
    fi
    if [[ -z "$master_pid" || ! "$master_pid" =~ ^[0-9]+$ ]] || (( 10#$master_pid <= 1 )) || [[ ! -d "/proc/${master_pid}" ]]; then
        printf '\n\n'
        return 0
    fi
    for stat_file in /proc/[0-9]*/stat; do
        [[ -r "$stat_file" ]] || continue
        pid="${stat_file#/proc/}"
        pid="${pid%/stat}"
        [[ "$pid" != "$master_pid" && "$pid" != "$$" ]] || continue
        if IFS= read -r stat_line < "$stat_file" 2>/dev/null; then
            stat_line="${stat_line##*) }"
            read -r _state ppid _ <<< "$stat_line"
            if [[ "$ppid" == "$master_pid" ]]; then
                children+=("$pid")
            fi
        fi
    done
    printf '%s\n' "$master_pid"
    local IFS=','
    printf '%s\n' "${children[*]}"
}

apache_app_drain_workers() {
    local package_name="$1" master_pid="$2" old_pids_csv="$3"
    local attempts="${AF_APACHE_DRAIN_ATTEMPTS:-30}" attempt pid ppid stat_line="" _state="" fd_link fd_target
    local -a pending=() next_pending=() protected_roots=("/var/www/${package_name}" "/var/lib/${package_name}")
    [[ -n "$master_pid" && -n "$old_pids_csv" ]] || return 0
    case "$package_name" in
        nextcloud) protected_roots+=("/var/www/html/nextcloud") ;;
        rutorrent) protected_roots+=("/srv/rutorrent") ;;
    esac
    IFS=',' read -r -a pending <<< "$old_pids_csv"
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        next_pending=()
        for pid in "${pending[@]}"; do
            [[ -n "$pid" && -r "/proc/${pid}/stat" ]] || continue
            if IFS= read -r stat_line < "/proc/${pid}/stat" 2>/dev/null; then
                stat_line="${stat_line##*) }"
                read -r _state ppid _ <<< "$stat_line"
                if [[ "$ppid" == "$master_pid" ]]; then
                    next_pending+=("$pid")
                fi
            fi
        done
        if (( ${#next_pending[@]} == 0 )); then
            return 0
        fi
        pending=("${next_pending[@]}")
        if (( attempt < attempts )); then
            sleep 0.1 2>/dev/null || sleep 1
        fi
    done
    for pid in "${pending[@]}"; do
        [[ -d "/proc/${pid}/fd" ]] || continue
        for fd_link in "/proc/${pid}/fd"/*; do
            [[ -L "$fd_link" ]] || continue
            fd_target="$(readlink -- "$fd_link" 2>/dev/null || true)"
            [[ -n "$fd_target" ]] || continue
            local root_path
            for root_path in "${protected_roots[@]}"; do
                if [[ "$fd_target" == "$root_path" || "$fd_target" == "${root_path}/"* ]]; then
                    print_warn "Apache worker ${pid} still holds open file ${fd_target} after reload drain timeout"
                    return 1
                fi
            done
        done
    done
    return 0
}

apache_app_verify_quiesced() {
    local package_name="$1" probe_url="$2" server_name="${3:-}" attempts="${4:-${AF_QUIESCE_ATTEMPTS:-5}}"
    local attempt probe_dir hdr_file body_file http_status curl_rc
    local -a curl_tls_args=() curl_host_args=()
    local loopback_https_re='^https://(127(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|\[::1\]|localhost)(:[0-9]{1,5})?(/.*)?$'

    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    [[ "$attempts" =~ ^[1-9][0-9]*$ ]] || return 1
    if [[ "$probe_url" =~ $loopback_https_re ]]; then
        curl_tls_args=(-k)
    fi
    if [[ -n "$server_name" ]]; then
        curl_host_args=(-H "Host: ${server_name}")
    fi

    probe_dir="${TMPDIR:-/tmp}"
    mkdir -p "$probe_dir" || return 1
    hdr_file="$(mktemp "${probe_dir}/af-apache-quiesce-hdr.XXXXXX")" || return 1
    body_file="$(mktemp "${probe_dir}/af-apache-quiesce-body.XXXXXX")" || { rm -f -- "$hdr_file"; return 1; }

    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if ! systemctl is-active --quiet apache2; then
            rm -f -- "$hdr_file" "$body_file"
            return 0
        fi
        : >"$hdr_file"
        : >"$body_file"
        curl_rc=0
        http_status="$(curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" \
            -sS --connect-timeout 2 --max-time 5 -D "$hdr_file" -o "$body_file" -w '%{http_code}' "$probe_url" 2>/dev/null)" || curl_rc=$?
        if [[ "$http_status" == "503" ]]; then
            if LC_ALL=C grep -Eiq "^X-AetherFlow-Maintenance:[[:space:]]*${package_name}[[:space:]]*$" "$hdr_file" 2>/dev/null || \
               LC_ALL=C grep -Fq "AetherFlow maintenance in progress for ${package_name}" "$body_file" 2>/dev/null; then
                rm -f -- "$hdr_file" "$body_file"
                return 0
            fi
        elif [[ "$http_status" == "403" ]]; then
            if LC_ALL=C grep -Eiq "^X-AetherFlow-Maintenance:[[:space:]]*${package_name}[[:space:]]*$" "$hdr_file" 2>/dev/null; then
                rm -f -- "$hdr_file" "$body_file"
                return 0
            fi
        elif [[ "$curl_rc" -eq 7 && "$http_status" == "000" ]]; then
            rm -f -- "$hdr_file" "$body_file"
            return 0
        fi
        if (( attempt < attempts )); then
            sleep 0.5 2>/dev/null || sleep 1
        fi
    done

    rm -f -- "$hdr_file" "$body_file"
    return 1
}

apache_app_swap_site_symlink() {
    local link_path="$1" target="$2" tmp_link
    tmp_link="$(mktemp -u "${link_path}.af-swap.XXXXXX")" || return 1
    if ! ln -s -- "$target" "$tmp_link"; then
        rm -f -- "$tmp_link" 2>/dev/null || true
        return 1
    fi
    if ! mv -Tf -- "$tmp_link" "$link_path"; then
        rm -f -- "$tmp_link" 2>/dev/null || true
        return 1
    fi
}

apache_app_enter_maintenance() {
    local package_name="$1" port="$2" default_path="${3:-/}" backup_dir="$4" for_rollback="${5:-false}"
    local apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}"
    local site_link="${apache_root}/sites-enabled/${package_name}.conf"
    local legacy_conf_link="${apache_root}/conf-enabled/${package_name}.conf"
    local maint_conf="${apache_root}/sites-available/aetherflow-${package_name}-maintenance.conf"
    local maint_backup_dir="${backup_dir}/.af-maint-orig"
    local prep_output="" prep_rc=0 mode="" reason="" has_site="0" has_legacy_conf="0" line
    local -a probe_urls=() probe_hosts=()
    local worker_info="" master_pid="" old_pids_csv=""
    local -a worker_lines=()

    if [[ "$for_rollback" == true ]]; then
        maint_backup_dir="${backup_dir}/.af-maint-rollback"
    else
        AF_APACHE_ACTIVATED_NEW_VHOST=false
    fi

    AF_APACHE_QUIESCE_MODE="none"
    AF_APACHE_IN_MAINTENANCE=false

    if ! systemctl is-active --quiet apache2; then
        return 0
    fi

    prep_output="$(apache_app_prepare_maintenance_vhost "$package_name" "$port" "$default_path")" || prep_rc=$?
    if [[ "$prep_rc" -eq 2 ]]; then
        print_error "Refusing unsafe Apache vhost configuration for ${package_name}."
        return 1
    fi
    if [[ "$prep_rc" -eq 0 ]]; then
        while IFS= read -r line; do
            case "$line" in
                MODE=*) mode="${line#MODE=}" ;;
                REASON=*) reason="${line#REASON=}" ;;
                HAS_SITE=*) has_site="${line#HAS_SITE=}" ;;
                HAS_LEGACY_CONF=*) has_legacy_conf="${line#HAS_LEGACY_CONF=}" ;;
                PROBE=*)
                    local entry="${line#PROBE=}"
                    probe_urls+=("${entry%%$'\t'*}")
                    probe_hosts+=("${entry#*$'\t'}")
                    ;;
            esac
        done <<< "$prep_output"
    else
        mode="unsupported"
        reason="failed to prepare per-app maintenance vhost"
    fi

    if [[ "$mode" == "none" ]]; then
        return 0
    fi

    if [[ "$mode" == "maintenance" ]]; then
        mkdir -p -m 0700 -- "$maint_backup_dir" || return 1
        if [[ "$has_site" == "1" && ( -e "$site_link" || -L "$site_link" ) ]]; then
            cp -a -- "$site_link" "$maint_backup_dir/site-link" || return 1
        fi
        if [[ "$has_legacy_conf" == "1" && ( -e "$legacy_conf_link" || -L "$legacy_conf_link" ) ]]; then
            cp -a -- "$legacy_conf_link" "$maint_backup_dir/legacy-conf" || return 1
        fi

        worker_info="$(apache_app_capture_worker_pids)"
        mapfile -t worker_lines <<< "$worker_info"
        master_pid="${worker_lines[0]:-}"
        old_pids_csv="${worker_lines[1]:-}"

        local swap_ok=true
        if [[ "$has_site" == "1" ]]; then
            apache_app_swap_site_symlink "$site_link" "../sites-available/aetherflow-${package_name}-maintenance.conf" || swap_ok=false
        fi
        if [[ "$swap_ok" == true && "$has_legacy_conf" == "1" ]]; then
            rm -f -- "$legacy_conf_link" || swap_ok=false
        fi
        if [[ "$swap_ok" == true ]]; then
            if af_logged apache2ctl configtest && af_logged systemctl reload apache2; then
                local verified=true idx
                if ! apache_app_drain_workers "$package_name" "$master_pid" "$old_pids_csv"; then
                    verified=false
                fi
                if [[ "$verified" == true ]]; then
                    for idx in "${!probe_urls[@]}"; do
                        if ! apache_app_verify_quiesced "$package_name" "${probe_urls[$idx]}" "${probe_hosts[$idx]}"; then
                            verified=false
                            break
                        fi
                    done
                fi
                if [[ "$verified" == true ]]; then
                    AF_APACHE_QUIESCE_MODE="maintenance"
                    AF_APACHE_IN_MAINTENANCE=true
                    log_info "Quiesced Apache application ${package_name} via per-app maintenance vhost"
                    return 0
                fi
                reason="per-app maintenance verification did not observe quiesced traffic for ${package_name}"
            else
                reason="apache2ctl configtest or reload failed while entering maintenance for ${package_name}"
            fi
        else
            reason="failed to stage per-app maintenance symlink for ${package_name}"
        fi

        # Revert maintenance config before falling back to safe stop.
        if [[ -e "$maint_backup_dir/site-link" || -L "$maint_backup_dir/site-link" ]]; then
            safe_restore_path_from_backup "$maint_backup_dir/site-link" "$site_link" || true
        fi
        if [[ -e "$maint_backup_dir/legacy-conf" || -L "$maint_backup_dir/legacy-conf" ]]; then
            safe_restore_path_from_backup "$maint_backup_dir/legacy-conf" "$legacy_conf_link" || true
        fi
        rm -f -- "$maint_conf"
    fi

    print_warn "Per-app Apache quiescence unavailable for ${package_name} (${reason:-unsupported configuration}); falling back to stopping apache2"
    if [[ "$for_rollback" == true ]]; then
        quiesce_services_for_rollback apache2 || return 1
    else
        stop_systemd_unit apache2 || return 1
    fi
    AF_APACHE_QUIESCE_MODE="stopped"
    AF_APACHE_IN_MAINTENANCE=false
    APACHE_STOPPED=true
    RUNTIME_STOPPED=true
    return 0
}

apache_app_quiesce_for_rollback() {
    local package_name="$1" port="$2" default_path="${3:-/}" backup_dir="$4"
    if [[ "${AF_APACHE_QUIESCE_MODE:-}" == "stopped" ]]; then
        if systemd_unit_inactive apache2; then
            return 0
        fi
        quiesce_services_for_rollback apache2
        return $?
    fi
    if [[ "${AF_APACHE_IN_MAINTENANCE:-false}" == true && "${AF_APACHE_QUIESCE_MODE:-}" == "maintenance" ]]; then
        return 0
    fi
    if [[ "${AF_APACHE_ACTIVATED_NEW_VHOST:-false}" != true && "${AF_APACHE_QUIESCE_MODE:-none}" == "none" ]]; then
        return 0
    fi
    apache_app_enter_maintenance "$package_name" "$port" "$default_path" "$backup_dir" true
}

apache_app_activate_vhost() {
    local package_name="$1" backup_dir="${2:-}"
    local apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}"
    local site_link="${apache_root}/sites-enabled/${package_name}.conf"
    local legacy_conf_link="${apache_root}/conf-enabled/${package_name}.conf"
    local maint_conf="${apache_root}/sites-available/aetherflow-${package_name}-maintenance.conf"
    local link_target=""

    if [[ -L "$site_link" ]]; then
        link_target="$(readlink -- "$site_link" 2>/dev/null || true)"
        if [[ "$link_target" == *"aetherflow-${package_name}-maintenance.conf" ]]; then
            apache_app_swap_site_symlink "$site_link" "../sites-available/${package_name}.conf" || return 1
        fi
    fi
    if [[ -n "$backup_dir" && ( -e "${backup_dir}/.af-maint-orig/legacy-conf" || -L "${backup_dir}/.af-maint-orig/legacy-conf" ) ]]; then
        safe_restore_path_from_backup "${backup_dir}/.af-maint-orig/legacy-conf" "$legacy_conf_link" || return 1
    fi

    af_logged a2enmod rewrite headers env dir mime
    af_logged a2ensite "${package_name}.conf"
    af_logged apache2ctl configtest
    if systemctl is-active --quiet apache2; then
        af_logged systemctl enable apache2 || true
        af_logged systemctl reload apache2
    else
        af_logged systemctl enable --now apache2
    fi

    AF_APACHE_ACTIVATED_NEW_VHOST=true
    AF_APACHE_IN_MAINTENANCE=false
    AF_APACHE_QUIESCE_MODE=""
    APACHE_STOPPED=false
    RUNTIME_STOPPED=false
    rm -f -- "$maint_conf"
}

apache_app_resume_after_rollback() {
    local package_name="$1" backup_dir="${2:-}"
    local apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}"
    local legacy_conf_link="${apache_root}/conf-enabled/${package_name}.conf"
    local maint_conf="${apache_root}/sites-available/aetherflow-${package_name}-maintenance.conf"

    if [[ -n "$backup_dir" && ( -e "${backup_dir}/.af-maint-orig/legacy-conf" || -L "${backup_dir}/.af-maint-orig/legacy-conf" ) ]]; then
        safe_restore_path_from_backup "${backup_dir}/.af-maint-orig/legacy-conf" "$legacy_conf_link" || return 1
    fi
    rm -f -- "$maint_conf"

    if [[ "${AF_APACHE_QUIESCE_MODE:-}" == "stopped" || "${APACHE_STOPPED:-false}" == true || "${RUNTIME_STOPPED:-false}" == true ]]; then
        af_logged apache2ctl configtest && af_logged systemctl start apache2
        return $?
    fi
    if [[ "${AF_APACHE_QUIESCE_MODE:-}" == "maintenance" || "${AF_APACHE_ACTIVATED_NEW_VHOST:-false}" == true ]]; then
        if systemctl is-active --quiet apache2; then
            af_logged apache2ctl configtest && af_logged systemctl reload apache2
            return $?
        fi
        af_logged apache2ctl configtest && af_logged systemctl start apache2
        return $?
    fi
    return 0
}

check_dns_port_53_available() {
    local package_name="$1" competing_package="$2" self_proc_regex="$3"
    local dns_port="${4:-${AF_DNS_PORT:-53}}"
    if [[ ! "$dns_port" =~ ^[0-9]{1,5}$ ]] || (( 10#$dns_port < 1 || 10#$dns_port > 65535 )); then
        print_error "DNS port must be between 1 and 65535 (got: ${dns_port})."
        return 1
    fi
    if [[ "$dns_port" != "53" ]]; then
        return 0
    fi
    local competing_lock="/install/.${competing_package}.lock"
    if [[ -e "$competing_lock" ]]; then
        print_error "Cannot install ${package_name} on DNS port 53 while ${competing_package} is installed (${competing_lock} exists). Remove ${competing_package} first or set AF_DNS_PORT to a non-53 port."
        return 1
    fi
    if command -v ss >/dev/null 2>&1; then
        local ss_bin listeners conflict
        ss_bin="$(command -v ss)"
        if [[ -n "${TEST_ROOT:-}" && "$ss_bin" != "${TEST_ROOT}"* ]] || [[ -n "${AF_FIXTURE_ROOT:-}" && "$ss_bin" != "${AF_FIXTURE_ROOT}"* ]]; then
            return 0
        fi
        listeners="$(ss -H -lntup 'sport = :53' 2>/dev/null || true)"
        if [[ -n "$listeners" ]]; then
            conflict="$(printf '%s\n' "$listeners" | grep -Ev "users:\(\(\"(${self_proc_regex}|systemd-resolved)\"" | grep -Ev '127\.0\.0\.5[34](%[^:[:space:]]+)?:53\b' || true)"
            if [[ -n "$conflict" ]]; then
                print_error "DNS port 53 is already in use by another process; cannot safely configure ${package_name}: ${conflict%%$'\n'*}"
                return 1
            fi
        fi
    fi
    return 0
}

af_backup_resolv_conf_state() {
    local app_name="$1"
    local backup_dir="${2:-}"
    [[ -n "$backup_dir" ]] || backup_dir="/etc/aetherflow/dns-backup"
    local resolv_path="${3:-}"
    [[ -n "$resolv_path" ]] || resolv_path="/etc/resolv.conf"
    [[ "$app_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    python3 - "$app_name" "$backup_dir" "$resolv_path" <<'PYEOF'
import json, os, pathlib, secrets, stat, sys

app_name, backup_dir_str, resolv_str = sys.argv[1:4]
backup_dir = pathlib.PurePath(backup_dir_str)
resolv_path = pathlib.PurePath(resolv_str)
for label, p in (("backup_dir", backup_dir), ("resolv_path", resolv_path)):
    if not p.is_absolute() or ".." in p.parts or not p.name:
        raise ValueError(f"Invalid {label}: {p}")

o_nofollow = getattr(os, "O_NOFOLLOW", 0)
o_directory = getattr(os, "O_DIRECTORY", 0)
o_cloexec = getattr(os, "O_CLOEXEC", 0)

def open_dir_nofollow(path: pathlib.PurePath, create_mode=None):
    fd = os.open("/", os.O_RDONLY | o_directory | o_cloexec)
    try:
        for idx, comp in enumerate(path.parts[1:]):
            try:
                child = os.open(comp, os.O_RDONLY | o_directory | o_nofollow | o_cloexec, dir_fd=fd)
            except FileNotFoundError:
                if create_mode is None:
                    raise
                mode = 0o750 if idx < len(path.parts[1:]) - 1 else create_mode
                os.mkdir(comp, mode, dir_fd=fd)
                child = os.open(comp, os.O_RDONLY | o_directory | o_nofollow | o_cloexec, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise

bdir_fd = open_dir_nofollow(backup_dir, create_mode=0o700)
try:
    os.fchmod(bdir_fd, 0o700)
    state_name = f"{app_name}-resolv.conf.state"
    bak_name = f"{app_name}-resolv.conf.bak"
    try:
        st_existing = os.lstat(state_name, dir_fd=bdir_fd)
    except FileNotFoundError:
        st_existing = None
    if st_existing is not None:
        if stat.S_ISLNK(st_existing.st_mode) or not stat.S_ISREG(st_existing.st_mode):
            raise ValueError(f"Unsafe existing DNS state file: {backup_dir / state_name}")
        raise SystemExit(0)

    rdir_fd = open_dir_nofollow(resolv_path.parent, create_mode=None)
    try:
        try:
            rst = os.lstat(resolv_path.name, dir_fd=rdir_fd)
        except FileNotFoundError:
            state = {"kind": "absent"}
        else:
            if stat.S_ISLNK(rst.st_mode):
                target = os.readlink(resolv_path.name, dir_fd=rdir_fd)
                state = {"kind": "symlink", "target": target}
            elif stat.S_ISREG(rst.st_mode):
                rfd = os.open(resolv_path.name, os.O_RDONLY | o_nofollow | o_cloexec, dir_fd=rdir_fd)
                try:
                    data = os.pread(rfd, 1048576, 0)
                finally:
                    os.close(rfd)
                tmp_bak = f".{bak_name}.{secrets.token_hex(6)}"
                bfd = os.open(tmp_bak, os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow | o_cloexec, 0o600, dir_fd=bdir_fd)
                try:
                    os.fchmod(bfd, 0o600)
                    os.write(bfd, data)
                    os.fsync(bfd)
                finally:
                    os.close(bfd)
                os.replace(tmp_bak, bak_name, src_dir_fd=bdir_fd, dst_dir_fd=bdir_fd)
                state = {"kind": "file", "mode": stat.S_IMODE(rst.st_mode)}
            else:
                raise ValueError(f"Unsupported /etc/resolv.conf file type: {resolv_path}")
    finally:
        os.close(rdir_fd)

    tmp_state = f".{state_name}.{secrets.token_hex(6)}"
    sfd = os.open(tmp_state, os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow | o_cloexec, 0o600, dir_fd=bdir_fd)
    try:
        os.fchmod(sfd, 0o600)
        os.write(sfd, (json.dumps(state, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(sfd)
    finally:
        os.close(sfd)
    os.replace(tmp_state, state_name, src_dir_fd=bdir_fd, dst_dir_fd=bdir_fd)
finally:
    os.close(bdir_fd)
PYEOF
}

af_write_resolv_conf_nameserver() {
    local nameserver="${1:-127.0.0.1}"
    local resolv_path="${2:-}"
    [[ -n "$resolv_path" ]] || resolv_path="/etc/resolv.conf"
    python3 - "$nameserver" "$resolv_path" <<'PYEOF'
import os, pathlib, secrets, stat, sys

nameserver, resolv_str = sys.argv[1:3]
resolv_path = pathlib.PurePath(resolv_str)
if not resolv_path.is_absolute() or ".." in resolv_path.parts or not resolv_path.name:
    raise ValueError(f"Invalid resolv_path: {resolv_path}")

o_nofollow = getattr(os, "O_NOFOLLOW", 0)
o_directory = getattr(os, "O_DIRECTORY", 0)
o_cloexec = getattr(os, "O_CLOEXEC", 0)

fd = os.open("/", os.O_RDONLY | o_directory | o_cloexec)
try:
    for comp in resolv_path.parent.parts[1:]:
        child = os.open(comp, os.O_RDONLY | o_directory | o_nofollow | o_cloexec, dir_fd=fd)
        os.close(fd)
        fd = child
    preserved_lines = []
    try:
        with open(resolv_str, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.startswith(("search ", "domain ", "options ")):
                    preserved_lines.append(stripped)
    except FileNotFoundError:
        pass
    content = "".join(line + "\n" for line in preserved_lines) + f"nameserver {nameserver}\n"
    tmp_name = f".{resolv_path.name}.af-new.{secrets.token_hex(6)}"
    tfd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow | o_cloexec, 0o644, dir_fd=fd)
    try:
        os.fchmod(tfd, 0o644)
        os.write(tfd, content.encode("utf-8"))
        os.fsync(tfd)
    finally:
        os.close(tfd)
    os.replace(tmp_name, resolv_path.name, src_dir_fd=fd, dst_dir_fd=fd)
finally:
    os.close(fd)
PYEOF
}

af_restore_resolv_conf_state() {
    local app_name="$1"
    local dropin_removed="${2:-false}"
    local backup_dir="${3:-}"
    [[ -n "$backup_dir" ]] || backup_dir="/etc/aetherflow/dns-backup"
    local resolv_path="${4:-}"
    [[ -n "$resolv_path" ]] || resolv_path="/etc/resolv.conf"
    local stub_target="${5:-}"
    [[ -n "$stub_target" ]] || stub_target="/run/systemd/resolve/stub-resolv.conf"
    [[ "$app_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    local resolved_active="false"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        resolved_active="true"
    fi
    python3 - "$app_name" "$dropin_removed" "$backup_dir" "$resolv_path" "$stub_target" "$resolved_active" <<'PYEOF'
import json, os, pathlib, secrets, stat, sys

app_name, dropin_removed, backup_dir_str, resolv_str, stub_target, resolved_active = sys.argv[1:7]
backup_dir = pathlib.PurePath(backup_dir_str)
resolv_path = pathlib.PurePath(resolv_str)
o_nofollow = getattr(os, "O_NOFOLLOW", 0)
o_directory = getattr(os, "O_DIRECTORY", 0)
o_cloexec = getattr(os, "O_CLOEXEC", 0)

def open_dir_nofollow(path: pathlib.PurePath):
    fd = os.open("/", os.O_RDONLY | o_directory | o_cloexec)
    try:
        for comp in path.parts[1:]:
            child = os.open(comp, os.O_RDONLY | o_directory | o_nofollow | o_cloexec, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise

rdir_fd = open_dir_nofollow(resolv_path.parent)
try:
    bdir_fd = None
    try:
        bdir_fd = open_dir_nofollow(backup_dir)
    except FileNotFoundError:
        bdir_fd = None

    state_name = f"{app_name}-resolv.conf.state"
    bak_name = f"{app_name}-resolv.conf.bak"
    restored_from_state = False

    if bdir_fd is not None:
        try:
            try:
                st_state = os.lstat(state_name, dir_fd=bdir_fd)
            except FileNotFoundError:
                st_state = None
            if st_state is not None:
                if stat.S_ISLNK(st_state.st_mode) or not stat.S_ISREG(st_state.st_mode):
                    raise ValueError(f"Unsafe DNS backup state file: {backup_dir / state_name}")
                sfd = os.open(state_name, os.O_RDONLY | o_nofollow | o_cloexec, dir_fd=bdir_fd)
                try:
                    state = json.loads(os.pread(sfd, 65536, 0).decode("utf-8"))
                finally:
                    os.close(sfd)
                kind = state.get("kind")
                if kind == "symlink":
                    target = str(state.get("target") or "")
                    if not target or "\n" in target or "\x00" in target:
                        raise ValueError("Invalid saved resolv.conf symlink target")
                    tmp_link = f".{resolv_path.name}.af-restore.{secrets.token_hex(6)}"
                    os.symlink(target, tmp_link, dir_fd=rdir_fd)
                    try:
                        os.replace(tmp_link, resolv_path.name, src_dir_fd=rdir_fd, dst_dir_fd=rdir_fd)
                    except BaseException:
                        try:
                            os.unlink(tmp_link, dir_fd=rdir_fd)
                        except OSError:
                            pass
                        raise
                elif kind == "file":
                    st_bak = os.lstat(bak_name, dir_fd=bdir_fd)
                    if stat.S_ISLNK(st_bak.st_mode) or not stat.S_ISREG(st_bak.st_mode):
                        raise ValueError(f"Unsafe DNS backup file: {backup_dir / bak_name}")
                    bfd = os.open(bak_name, os.O_RDONLY | o_nofollow | o_cloexec, dir_fd=bdir_fd)
                    try:
                        data = os.pread(bfd, 1048576, 0)
                    finally:
                        os.close(bfd)
                    mode = int(state.get("mode") or 0o644) & 0o644
                    if (mode & 0o444) == 0:
                        mode = 0o644
                    tmp_file = f".{resolv_path.name}.af-restore.{secrets.token_hex(6)}"
                    tfd = os.open(tmp_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow | o_cloexec, mode, dir_fd=rdir_fd)
                    try:
                        os.fchmod(tfd, mode)
                        os.write(tfd, data)
                        os.fsync(tfd)
                    finally:
                        os.close(tfd)
                    os.replace(tmp_file, resolv_path.name, src_dir_fd=rdir_fd, dst_dir_fd=rdir_fd)
                elif kind == "absent":
                    try:
                        os.unlink(resolv_path.name, dir_fd=rdir_fd)
                    except FileNotFoundError:
                        pass
                else:
                    raise ValueError(f"Unsupported saved resolv.conf state kind: {kind!r}")

                for fname in (state_name, bak_name):
                    try:
                        os.unlink(fname, dir_fd=bdir_fd)
                    except FileNotFoundError:
                        pass
                restored_from_state = True
        finally:
            os.close(bdir_fd)

    if not restored_from_state and (dropin_removed == "true" or resolved_active == "true") and os.path.exists(stub_target):
        should_restore_stub = False
        try:
            rst = os.lstat(resolv_path.name, dir_fd=rdir_fd)
        except FileNotFoundError:
            should_restore_stub = (dropin_removed == "true")
        else:
            if stat.S_ISLNK(rst.st_mode):
                cur_target = os.readlink(resolv_path.name, dir_fd=rdir_fd)
                if cur_target.endswith("/resolv.conf") and "systemd/resolve" in cur_target:
                    should_restore_stub = True
            elif stat.S_ISREG(rst.st_mode):
                rfd = os.open(resolv_path.name, os.O_RDONLY | o_nofollow | o_cloexec, dir_fd=rdir_fd)
                try:
                    lines = [ln.strip() for ln in os.pread(rfd, 65536, 0).decode("utf-8", errors="replace").splitlines() if ln.strip() and not ln.strip().startswith("#")]
                finally:
                    os.close(rfd)
                ns = [ln.split()[1] for ln in lines if ln.startswith("nameserver ") and len(ln.split()) >= 2]
                if ns == ["127.0.0.1"] or (dropin_removed == "true" and ns == ["127.0.0.53"]):
                    should_restore_stub = True
        if should_restore_stub:
            tmp_link = f".{resolv_path.name}.af-restore.{secrets.token_hex(6)}"
            os.symlink(stub_target, tmp_link, dir_fd=rdir_fd)
            try:
                os.replace(tmp_link, resolv_path.name, src_dir_fd=rdir_fd, dst_dir_fd=rdir_fd)
            except BaseException:
                try:
                    os.unlink(tmp_link, dir_fd=rdir_fd)
                except OSError:
                    pass
                raise
finally:
    os.close(rdir_fd)
PYEOF
}

af_verify_local_dns_lookup() {
    local dns_port="${1:-53}"
    local max_attempts="${2:-15}"
    local retry_delay="${3:-1}"
    local timeout_sec="${4:-2.0}"
    python3 - "$dns_port" "$max_attempts" "$retry_delay" "$timeout_sec" <<'PYEOF'
import os, socket, struct, sys, time

port = int(sys.argv[1])
attempts = max(1, int(sys.argv[2]))
retry_delay = max(0.0, float(sys.argv[3]))
timeout_sec = max(0.1, float(sys.argv[4]))
question = b"\x09localhost\x00" + struct.pack(">HH", 1, 1)

last_err = None
for attempt in range(attempts):
    txid = struct.unpack(">H", os.urandom(2))[0]
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    packet = header + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_sec)
    try:
        sock.connect(("127.0.0.1", port))
        sock.send(packet)
        resp = sock.recv(512)
        if len(resp) >= 12:
            resp_id, flags, questions, answers, _, _ = struct.unpack(">HHHHHH", resp[:12])
            if (resp_id == txid and flags & 0x8000 and not flags & 0x020F
                    and questions == 1 and answers > 0 and resp[12:12 + len(question)] == question):
                raise SystemExit(0)
        last_err = "malformed DNS response"
    except OSError as exc:
        last_err = str(exc)
    finally:
        sock.close()
    if attempt + 1 < attempts and retry_delay > 0:
        time.sleep(retry_delay)

print(f"Local DNS lookup probe failed against 127.0.0.1:{port}: {last_err}", file=sys.stderr)
raise SystemExit(1)
PYEOF
}

lock_path() {
    local package_name="$1"
    printf '%s/.%s.lock\n' "$LOCK_DIR" "$package_name"
}

legacy_swizzin_lock_path() {
    local package_name="$1"
    local fs_root="${AETHERFLOW_FS_ROOT:-${AETHERFLOW_INSTALL_ROOT:-}}"
    if [[ -n "$fs_root" && "$fs_root" != "/" ]]; then
        printf '%s/etc/Swizzin/.%s.lock\n' "${fs_root%/}" "$package_name"
        return 0
    fi
    local clean_lock_dir="${LOCK_DIR%/}"
    if [[ "$clean_lock_dir" == "/install" ]]; then
        printf '/etc/Swizzin/.%s.lock\n' "$package_name"
        return 0
    fi
    if [[ "$clean_lock_dir" == */install ]]; then
        printf '%s/etc/Swizzin/.%s.lock\n' "${clean_lock_dir%/install}" "$package_name"
        return 0
    fi
    return 1
}

remove_legacy_swizzin_lock() {
    local package_name="$1" legacy_lock="" legacy_dir="" legacy_etc=""
    legacy_lock="$(legacy_swizzin_lock_path "$package_name")" || return 0
    legacy_dir="${legacy_lock%/*}"
    legacy_etc="${legacy_dir%/*}"
    if [[ -L "$legacy_etc" || -L "$legacy_dir" ]]; then
        print_error "Refusing symlinked legacy lock directory: $legacy_dir"
        return 1
    fi
    if [[ ! -e "$legacy_lock" && ! -L "$legacy_lock" ]]; then
        return 0
    fi
    if [[ -L "$legacy_lock" || ! -f "$legacy_lock" ]]; then
        print_error "Refusing unsafe legacy installation lock: $legacy_lock"
        return 1
    fi
    rm -f -- "$legacy_lock"
}

has_lock() {
    local package_name="$1" lp=""
    lp="$(lock_path "$package_name")"
    [[ ! -L "$LOCK_DIR" && -d "$LOCK_DIR" && ! -L "$lp" && -f "$lp" ]]
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
    local package_name="$1" lp=""
    if [[ -n "${AF_STATE_BACKUP:-}" && -n "${AF_STATE_UNIT:-}" ]]; then
        verify_systemd_service_active "$AF_STATE_UNIT" || return 1
        if [[ "${AF_STATE_PORT:-0}" != 0 ]]; then
            wait_for_service_ready "$AF_STATE_UNIT" "$AF_STATE_PORT" "$AF_STATE_READINESS_PATH" || return 1
        fi
    fi
    if [[ -d "${AF_TX_DIR:-}/apt-packages" ]]; then
        clear_apt_reinstall_markers || return 1
    fi
    lp="$(lock_path "$package_name")"
    if [[ -L "$LOCK_DIR" || -L "$lp" || ( -e "$lp" && ! -f "$lp" ) ]]; then
        print_error "Refusing unsafe installation lock path: $lp"
        return 1
    fi
    touch "$lp" || return 1
    remove_legacy_swizzin_lock "$package_name" || return 1
    INSTALL_COMMITTED=true
    if [[ -n "${AF_ARCHIVE_BACKUP:-}" ]]; then
        rm -f -- "$AF_ARCHIVE_BACKUP/.af-archive-pending"
    fi
    if [[ -x /usr/local/bin/af-certbot-sync ]]; then
        launch_detached_helper /usr/local/bin/af-certbot-sync
    fi
}

get_base_domain() {
    local dom="" db_cand=""
    local explicit_env_file="${AETHERFLOW_ENV_FILE:-}"
    local skip_host_env="${AETHERFLOW_SKIP_ENV_FILES:-0}"
    local env_file=""
    if [[ -n "$explicit_env_file" ]]; then
        env_file="$explicit_env_file"
    elif [[ "$skip_host_env" != "1" ]]; then
        env_file="/etc/aetherflow/aetherflow.env"
    fi
    local env_af_db="" env_db="" env_aetherflow_db="" env_data_dir="" env_base_domain=""
    if [[ -n "$env_file" && -e "$env_file" ]]; then
        local _parsed_env=""
        _parsed_env="$(python3 - "$env_file" <<'PYEOF' 2>/dev/null || true
import os, stat, sys
target = sys.argv[1]
parent = os.path.dirname(os.path.abspath(target)) or "."
pst = os.lstat(parent)
if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
    raise SystemExit(1)
lst = os.lstat(target)
if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
    raise SystemExit(1)
fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    fst = os.fstat(fd)
    if not stat.S_ISREG(fst.st_mode) or (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
        raise SystemExit(1)
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace", closefd=False) as fh:
        content = fh.read()
finally:
    os.close(fd)
vals = {}
for raw_line in content.splitlines():
    s = raw_line.strip()
    if not s or s.startswith("#"):
        continue
    if s.startswith("export "):
        s = s[7:].strip()
    if "=" not in s:
        continue
    k, v = s.split("=", 1)
    k = k.strip()
    v = v.strip()
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
        v = v[1:-1]
    if k in ("AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH", "DATA_DIR", "AETHERFLOW_BASE_DOMAIN"):
        vals[k] = v
for key in ("AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH", "DATA_DIR", "AETHERFLOW_BASE_DOMAIN"):
    print(vals.get(key, "").replace("\n", "").replace("\r", ""))
PYEOF
)"
        if [[ -n "$_parsed_env" ]]; then
            env_af_db="$(printf '%s\n' "$_parsed_env" | sed -n '1p')"
            env_db="$(printf '%s\n' "$_parsed_env" | sed -n '2p')"
            env_aetherflow_db="$(printf '%s\n' "$_parsed_env" | sed -n '3p')"
            env_data_dir="$(printf '%s\n' "$_parsed_env" | sed -n '4p')"
            env_base_domain="$(printf '%s\n' "$_parsed_env" | sed -n '5p')"
        fi
    fi
    local eff_data_dir="${DATA_DIR:-$env_data_dir}"
    local custom_data_db=""
    if [[ -n "$eff_data_dir" && "${eff_data_dir%/}" != "/var/lib/aetherflow" ]]; then
        custom_data_db="${eff_data_dir%/}/aetherflow.sqlite"
    fi
    if command -v sqlite3 >/dev/null 2>&1; then
        local -a _db_candidates=(
            "${AF_DB_PATH:-}"
            "${DB_PATH:-}"
            "${AETHERFLOW_DB_PATH:-}"
            "$env_af_db"
            "$env_db"
            "$env_aetherflow_db"
            "$custom_data_db"
        )
        if [[ "$skip_host_env" != "1" ]]; then
            _db_candidates+=(
                /var/lib/aetherflow/aetherflow.sqlite
                /opt/AetherFlow/current/data/aetherflow.sqlite
                /opt/AetherFlow/data/aetherflow.sqlite
                /opt/AetherFlow/backend/data/aetherflow.sqlite
            )
        fi
        for db_cand in "${_db_candidates[@]}"
        do
            if [[ -n "$db_cand" && -f "$db_cand" ]]; then
                local has_settings=""
                has_settings="$(sqlite3 "$db_cand" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='settings';" 2>/dev/null | tr -d '[:space:]' || true)"
                if [[ "$has_settings" == "1" ]]; then
                    dom="$(sqlite3 "$db_cand" "SELECT base_domain FROM settings WHERE id = 1;" 2>/dev/null | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's/^\*\.//' | tr -d '[:space:]' || true)"
                    break
                fi
            fi
        done
    fi
    if [[ -z "$dom" ]]; then
        local raw_env_dom="${AETHERFLOW_BASE_DOMAIN:-$env_base_domain}"
        if [[ -n "$raw_env_dom" ]]; then
            dom="$(printf '%s' "$raw_env_dom" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's/^\*\.//' | tr -d '[:space:]')"
        fi
    fi
    local domain_regex='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
    if [[ "$dom" == "localhost" || "$dom" == *.local ]] || { [[ -n "$dom" ]] && [[ ! "$dom" =~ $domain_regex ]]; }; then
        dom=""
    fi
    printf '%s\n' "$dom"
}

remove_lock() {
    local package_name="$1" lp=""
    if [[ "${DELETE_DATA:-false}" == true ]]; then
        purge_app_backups "$package_name" || return 1
    fi
    lp="$(lock_path "$package_name")"
    if [[ -L "$LOCK_DIR" || -L "$lp" || ( -e "$lp" && ! -f "$lp" ) ]]; then
        print_error "Refusing unsafe installation lock path: $lp"
        return 1
    fi
    rm -f -- "$lp" || return 1
    remove_legacy_swizzin_lock "$package_name" || return 1
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
    local -a _boot_proto=()
    [[ "$url" == https://* ]] && _boot_proto=(--proto '=https' --proto-redir '=https')
    if ! curl "${_boot_proto[@]}" -fsSL -o "$tmp_script" "$url"; then
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
    af_logged printf '%s\n' "[BOOTSTRAP-PROVENANCE] url=${url} sha256=${computed_hash,,}" || true

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

    eff_url="$(curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 5 --max-time 15 -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest" 2>/dev/null || true)"
    if [[ "$eff_url" == *"/releases/tag/"* ]]; then
        tag="${eff_url##*/releases/tag/}"
        tag="${tag%%\?*}"
        tag="${tag%%#*}"
    fi

    if [[ -z "$tag" ]]; then
        tag="$(af_github_curl --proto '=https' --proto-redir '=https' -fsSL --connect-timeout 5 --max-time 15 "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
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
    local want_major="${1:-22}"
    local have_major=0
    # Native addons and Git prepare scripts need these on already-provisioned
    # Node hosts too, not just when Node itself is first installed.
    DEBIAN_FRONTEND=noninteractive af_logged apt-get install -y -qq \
        ca-certificates git build-essential python3 python3-setuptools pkg-config
    if command_exists node; then
        have_major=$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1 || echo 0)
    fi
    if [[ "${have_major:-0}" -lt "$want_major" ]]; then
        local nodesource_sha256="${AF_NODESOURCE_BOOTSTRAP_SHA256:-2c4c6683a17b6f4128898a7b521e3c8bb725a99ffaf1b5e32ac97c6fa7d381be}"
        fetch_and_run "https://deb.nodesource.com/setup_${want_major}.x" "$nodesource_sha256" || return 1
        DEBIAN_FRONTEND=noninteractive af_logged apt-get install -y -qq nodejs
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
        inactive) [[ -z "$main_pid" || "$main_pid" == 0 ]] || return 1 ;;
        failed) [[ "$main_pid" == 0 ]] || return 1 ;;
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
    local -a triggers=() workers=() ordered=()
    for unit in "$@"; do
        case "$unit" in
            *.timer|*.socket) triggers+=("$unit") ;;
            *) workers+=("$unit") ;;
        esac
    done
    ordered=("${triggers[@]}" "${workers[@]}")
    for unit in "${ordered[@]}"; do
        stop_status=0
        af_logged systemctl stop -- "$unit" || stop_status=$?
        if [[ "$stop_status" -ne 0 ]]; then
            local _unit_load_state=""
            _unit_load_state="$(systemctl show --property=LoadState -- "$unit" 2>/dev/null || true)"
            if [[ "$stop_status" -eq 5 && "$_unit_load_state" == "LoadState=not-found" ]] && systemd_unit_inactive "$unit"; then
                continue
            fi
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
    local -a triggers=() workers=() ordered=()
    for unit in "$@"; do
        case "$unit" in
            *.timer|*.socket) triggers+=("$unit") ;;
            *) workers+=("$unit") ;;
        esac
    done
    ordered=("${triggers[@]}" "${workers[@]}")
    for unit in "${ordered[@]}"; do
        stop_status=0
        af_logged systemctl stop -- "$unit" || stop_status=$?
        af_logged systemctl reset-failed -- "$unit" || true
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
        if ! af_logged systemctl reset-failed -- "$unit"; then
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
        if raw:
            general = None
            try:
                import yaml
                loaded = yaml.safe_load(raw)
                if isinstance(loaded, dict) and isinstance(loaded.get('general'), dict):
                    general = loaded['general']
            except ImportError:
                general = {}
                in_general = False
                general_indent = None
                child_indent = None
                for line in raw.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith('#'):
                        continue
                    indent = len(line) - len(line.lstrip(' \t'))
                    if not in_general:
                        if indent == 0 and re.match(r'^general\s*:\s*(?:#.*)?$', stripped):
                            in_general = True
                            general_indent = indent
                        continue
                    if indent <= general_indent:
                        break
                    if child_indent is None:
                        if stripped.startswith('-'):
                            continue
                        child_indent = indent
                    if indent != child_indent:
                        continue
                    match = re.match(r'^([A-Za-z0-9_]+)\s*:\s*(.*)$', stripped)
                    if match:
                        k, v = match.group(1), match.group(2).strip()
                        if v and v[0] in ('"', "'"):
                            q = v[0]
                            end_q = v.find(q, 1)
                            v = v[1:end_q] if end_q != -1 else v.strip(q)
                        else:
                            v = v.split('#', 1)[0].strip()
                        general[k] = v
            if isinstance(general, dict):
                if general.get('ip') not in (None, ''):
                    host = str(general['ip'])
                if general.get('port') not in (None, ''):
                    yaml_port = str(general['port']).strip()
                    if not yaml_port.isdecimal() or not 1 <= int(yaml_port) <= 65535:
                        raise ValueError('Unsafe retained application port')
                    port = yaml_port
                if general.get('base_url') not in (None, ''):
                    base = str(general['base_url'])
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
    local -a curl_tls_args=()
    local loopback_https_re='^https://(127(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|\[::1\]|localhost)(:[0-9]{1,5})?(/.*)?$'
    if [[ "$readiness_path" =~ $loopback_https_re ]]; then
        ready_url="$readiness_path"
        curl_tls_args=(-k)
    elif [[ "$readiness_path" == http://* || "$readiness_path" == https://* ]]; then
        ready_url="$readiness_path"
    elif [[ "$readiness_path" == /* ]]; then
        ready_url="http://127.0.0.1:${port}${readiness_path}"
    else
        return 1
    fi
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if systemctl is-active --quiet "$unit"; then
            if [[ -n "$credentials" ]]; then
                if printf 'user = "%s"\n' "$credentials" | curl "${curl_tls_args[@]}" -K - -fsS --connect-timeout 2 --max-time 5 "$ready_url" >/dev/null 2>&1; then
                    return 0
                fi
                if [[ "$app_name" == transmission* && "$readiness_path" == /transmission/rpc ]]; then
                    if http_status="$(printf 'user = "%s"\n' "$credentials" | curl -K - -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}${readiness_path}" 2>/dev/null)"; then
                        case "$http_status" in 200|401|409) return 0 ;; esac
                    fi
                fi
            elif curl "${curl_tls_args[@]}" -fsS --connect-timeout 2 --max-time 5 "$ready_url" >/dev/null 2>&1; then
                return 0
            elif [[ "$app_name" =~ ^(bazarr|overseerr|tautulli|flaresolverr|sabnzbd|listenarr|filebot|pihole-ftl)$ ]]; then
                if http_status="$(curl "${curl_tls_args[@]}" -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$ready_url" 2>/dev/null)"; then
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
    safe_rm_rf "/home/${username}"
}

load_master_credentials() {
    local u="" p="" h="" creds_json generated=false primary_creds_file="/var/lib/aetherflow/.master.creds"
    primary_creds_file="${AETHERFLOW_MASTER_CREDS_FILE:-$primary_creds_file}"
    if [[ -n "${MASTER_USER:-}" && -n "${MASTER_PASS:-}" && "$MASTER_PASS" != adminadmin ]]; then
        export MASTER_USER MASTER_PASS
        export MASTER_HA1="${MASTER_HA1:-$(printf '%s:Welcome to AetherFlow:%s' "$MASTER_USER" "$MASTER_PASS" | md5sum | awk '{print $1}')}"
        return 0
    fi
    local -a _creds_files=("$primary_creds_file")
    if [[ "${AETHERFLOW_SKIP_ENV_FILES:-0}" != "1" ]]; then
        _creds_files+=(/opt/AetherFlow/backend/data/.master.creds)
    fi
    for creds_json in "${_creds_files[@]}"; do
        if [[ -f "$creds_json" && ! -L "$creds_json" ]]; then
            local parsed_creds=""
            parsed_creds="$(python3 - "$creds_json" "$primary_creds_file" 2>/dev/null <<'PYEOF' || true
import base64, ctypes, ctypes.util, json, os, stat, sys

def _read_regular_file_nofollow(target):
    parent = os.path.dirname(os.path.abspath(target)) or "."
    pst = os.lstat(parent)
    if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
        raise OSError(f"Unsafe parent directory for {target}")
    lst = os.lstat(target)
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        raise OSError(f"Refusing non-regular or symlinked file {target}")
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
            raise OSError(f"File identity changed during open for {target}")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as fh:
            return fh.read()
    finally:
        os.close(fd)

def load_aes_key():
    raw = os.environ.get("AES_MASTER_KEY", "").strip()
    if not raw:
        explicit_env = os.environ.get("AETHERFLOW_ENV_FILE", "").strip()
        env_path = explicit_env if explicit_env else (
            "/etc/aetherflow/aetherflow.env" if os.environ.get("AETHERFLOW_SKIP_ENV_FILES") != "1" else ""
        )
        if env_path:
            try:
                for line in _read_regular_file_nofollow(env_path).splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    if s.startswith("export "):
                        s = s[7:].strip()
                    if s.startswith("AES_MASTER_KEY="):
                        candidate = s.split("=", 1)[1].strip().strip("\"'")
                        if candidate:
                            raw = candidate
            except FileNotFoundError:
                raw = ""
            except OSError as exc:
                sys.stderr.write(f"Skipping unreadable env file {env_path}: {exc}\n")
    if not raw:
        return "", None
    if len(raw) == 64:
        try:
            dec_hex = bytes.fromhex(raw)
            if len(dec_hex) == 32:
                return raw, dec_hex
        except ValueError:
            pass
    try:
        dec = base64.b64decode(raw, validate=True)
        if len(dec) == 32:
            return raw, dec
    except Exception:
        pass
    raw_bytes = raw.encode("utf-8")
    return raw, (raw_bytes if len(raw_bytes) == 32 else None)

def _load_libcrypto():
    candidates = []
    found = ctypes.util.find_library("crypto")
    if found:
        candidates.append(found)
    candidates.extend(("libcrypto.so.3", "libcrypto.so.1.1"))
    for name in candidates:
        try:
            lib = ctypes.CDLL(name)
            lib.EVP_CIPHER_CTX_new.argtypes = []
            lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            lib.EVP_CIPHER_CTX_free.restype = None
            lib.EVP_aes_256_gcm.argtypes = []
            lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
            lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
            lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            lib.EVP_DecryptInit_ex.restype = ctypes.c_int
            lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_int]
            lib.EVP_DecryptUpdate.restype = ctypes.c_int
            lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            lib.EVP_DecryptFinal_ex.restype = ctypes.c_int
            return lib
        except OSError:
            continue
    raise RuntimeError("OpenSSL libcrypto unavailable")

def aes_gcm_decrypt(key, nonce, ct_and_tag):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(nonce, ct_and_tag, None)
    except ImportError:
        pass
    if len(nonce) != 12 or len(ct_and_tag) < 16:
        raise ValueError("invalid AES-GCM payload length")
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    lib = _load_libcrypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        key_buf = (ctypes.c_ubyte * 32).from_buffer_copy(key)
        iv_buf = (ctypes.c_ubyte * 12).from_buffer_copy(nonce)
        tag_buf = (ctypes.c_ubyte * 16).from_buffer_copy(tag)
        if lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None) != 1:
            raise ValueError("EVP_DecryptInit_ex cipher failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x9, 12, None) != 1:
            raise ValueError("EVP_CTRL_GCM_SET_IVLEN failed")
        if lib.EVP_DecryptInit_ex(ctx, None, None, ctypes.byref(key_buf), ctypes.byref(iv_buf)) != 1:
            raise ValueError("EVP_DecryptInit_ex key/iv failed")
        out_buf = (ctypes.c_ubyte * max(1, len(ct) + 16))()
        out_len = ctypes.c_int(0)
        if ct:
            ct_buf = (ctypes.c_ubyte * len(ct)).from_buffer_copy(ct)
            if lib.EVP_DecryptUpdate(ctx, ctypes.byref(out_buf), ctypes.byref(out_len), ctypes.byref(ct_buf), len(ct)) != 1:
                raise ValueError("EVP_DecryptUpdate failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x11, 16, ctypes.byref(tag_buf)) != 1:
            raise ValueError("EVP_CTRL_GCM_SET_TAG failed")
        final_len = ctypes.c_int(0)
        tail_ptr = ctypes.cast(ctypes.addressof(out_buf) + out_len.value, ctypes.c_void_p)
        if lib.EVP_DecryptFinal_ex(ctx, tail_ptr, ctypes.byref(final_len)) != 1:
            raise ValueError("AES-GCM authentication failed")
        return bytes(out_buf[:out_len.value + final_len.value])
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)

def decrypt_field(val, key):
    if not isinstance(val, str):
        return ""
    val = val.strip()
    if not val.startswith("enc:v1:"):
        return val
    if key is None:
        raise ValueError("AES_MASTER_KEY missing or invalid for enc:v1: secret")
    blob = base64.b64decode(val[len("enc:v1:"):], validate=True)
    if len(blob) < 28:
        raise ValueError("enc:v1: ciphertext truncated")
    return aes_gcm_decrypt(key, blob[:12], blob[12:]).decode("utf-8")

path, primary_path = sys.argv[1], sys.argv[2]
try:
    raw_text = _read_regular_file_nofollow(path)
except OSError:
    if os.path.abspath(path) == os.path.abspath(primary_path):
        print("__AF_CREDS_FATAL__")
    raise SystemExit(0)
try:
    d = json.loads(raw_text)
except Exception:
    if "enc:v1:" in raw_text or (raw_text.strip() and os.path.abspath(path) == os.path.abspath(primary_path)):
        print("__AF_CREDS_FATAL__")
    raise SystemExit(0)
if not isinstance(d, dict):
    if os.path.abspath(path) == os.path.abspath(primary_path):
        print("__AF_CREDS_FATAL__")
    raise SystemExit(0)
_, key = load_aes_key()
u = str(d.get("username") or "").strip()
raw_pw = d.get("password") or ""
raw_ha1 = d.get("ha1") or ""
try:
    p = decrypt_field(raw_pw, key)
    h = decrypt_field(raw_ha1, key) if str(raw_ha1).strip() else ""
except Exception:
    print("__AF_CREDS_FATAL__")
    raise SystemExit(0)
if isinstance(raw_pw, str) and raw_pw.strip().startswith("enc:v1:") and not p:
    print("__AF_CREDS_FATAL__")
    raise SystemExit(0)
if p == "adminadmin":
    p = ""
print(u)
print(p)
print(h)
PYEOF
)"
            if [[ "$parsed_creds" == "__AF_CREDS_FATAL__"* ]]; then
                printf 'Refusing to overwrite undecryptable or corrupted master credentials file: %s\n' "$creds_json" >&2
                return 1
            fi
            if [[ -n "$parsed_creds" ]]; then
                u="$(printf '%s\n' "$parsed_creds" | sed -n '1p')"
                p="$(printf '%s\n' "$parsed_creds" | sed -n '2p')"
                h="$(printf '%s\n' "$parsed_creds" | sed -n '3p')"
            fi
            [[ -n "$u" && -n "$p" ]] && break
        fi
    done
    local skip_host_env="${AETHERFLOW_SKIP_ENV_FILES:-0}"
    if [[ "$skip_host_env" != "1" ]]; then
        if [[ -z "$u" || -z "$p" ]] && [[ -f /install/.aetherflow.conf && ! -L /install/.aetherflow.conf ]]; then
            local _conf_parsed=""
            _conf_parsed="$(python3 - /install/.aetherflow.conf <<'PYEOF' 2>/dev/null || true
import base64, codecs, os, re, shlex, stat, sys

target = sys.argv[1]
parent = os.path.dirname(os.path.abspath(target)) or "."
pst = os.lstat(parent)
if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
    raise SystemExit(1)
lst = os.lstat(target)
if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
    raise SystemExit(1)
fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    fst = os.fstat(fd)
    if not stat.S_ISREG(fst.st_mode) or (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
        raise SystemExit(1)
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace", closefd=False) as fh:
        raw_lines = fh.read().splitlines()
finally:
    os.close(fd)

def decode_shell_value(raw_val: str) -> str:
    val = raw_val.strip()
    if not val:
        return ""
    if val.startswith("$'") and val.endswith("'") and len(val) >= 3:
        inner = val[2:-1]
        try:
            return codecs.decode(inner, "unicode_escape")
        except Exception:
            return inner
    try:
        tokens = shlex.split(val, posix=True, comments=True)
        if not tokens:
            return ""
        return tokens[0]
    except ValueError:
        if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
            return val[1:-1]
        return val

parsed = {}
for raw_line in raw_lines:
    s = raw_line.strip()
    if not s or s.startswith("#"):
        continue
    if s.startswith("export "):
        s = s[7:].strip()
    if "=" not in s:
        continue
    key, raw_val = s.split("=", 1)
    key = key.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        continue
    if key in ("username", "passwd", "ha1pass"):
        parsed[key] = decode_shell_value(raw_val)

for field in ("username", "passwd", "ha1pass"):
    print(base64.b64encode(parsed.get(field, "").encode("utf-8")).decode("ascii"))
PYEOF
)"
            if [[ -n "$_conf_parsed" ]]; then
                local _conf_u _conf_p _conf_h
                _conf_u="$(printf '%s\n' "$_conf_parsed" | sed -n '1p' | base64 -d 2>/dev/null || true)"
                _conf_p="$(printf '%s\n' "$_conf_parsed" | sed -n '2p' | base64 -d 2>/dev/null || true)"
                _conf_h="$(printf '%s\n' "$_conf_parsed" | sed -n '3p' | base64 -d 2>/dev/null || true)"
                [[ -z "$u" && -n "$_conf_u" ]] && u="$_conf_u"
                [[ -z "$p" && -n "$_conf_p" ]] && p="$_conf_p"
                [[ -z "$h" && "$_conf_h" =~ ^[0-9a-fA-F]{32}$ ]] && h="$_conf_h"
            fi
        fi
        if [[ -z "$u" && -f /etc/apache2/master.txt ]]; then
            u="$(awk -F: 'NR==1 {print $1}' /etc/apache2/master.txt 2>/dev/null | tr -d '[:space:]' || true)"
        fi
    fi
    if [[ -z "$u" ]] && command -v sqlite3 >/dev/null 2>&1; then
        local db_cand="" env_db="" env_data_dir=""
        local _creds_env_file="${AETHERFLOW_ENV_FILE:-}"
        if [[ -z "$_creds_env_file" && "$skip_host_env" != "1" ]]; then
            _creds_env_file="/etc/aetherflow/aetherflow.env"
        fi
        if [[ -n "$_creds_env_file" && -e "$_creds_env_file" ]]; then
            local _creds_env_parsed=""
            _creds_env_parsed="$(python3 - "$_creds_env_file" <<'PYEOF' 2>/dev/null || true
import os, stat, sys
target = sys.argv[1]
parent = os.path.dirname(os.path.abspath(target)) or "."
pst = os.lstat(parent)
if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
    raise SystemExit(1)
lst = os.lstat(target)
if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
    raise SystemExit(1)
fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    fst = os.fstat(fd)
    if not stat.S_ISREG(fst.st_mode) or (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
        raise SystemExit(1)
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace", closefd=False) as fh:
        lines = fh.read().splitlines()
finally:
    os.close(fd)
env_db = ""
env_data = ""
for raw_line in lines:
    s = raw_line.strip()
    if not s or s.startswith("#"):
        continue
    if s.startswith("export "):
        s = s[7:].strip()
    if "=" not in s:
        continue
    k, v = s.split("=", 1)
    k = k.strip()
    v = v.strip().strip("\"'")
    if k in ("AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"):
        env_db = v
    elif k == "DATA_DIR":
        env_data = v
print(env_db.replace("\n", "").replace("\r", ""))
print(env_data.replace("\n", "").replace("\r", ""))
PYEOF
)"
            if [[ -n "$_creds_env_parsed" ]]; then
                env_db="$(printf '%s\n' "$_creds_env_parsed" | sed -n '1p')"
                env_data_dir="$(printf '%s\n' "$_creds_env_parsed" | sed -n '2p')"
            fi
        fi
        local -a _creds_db_candidates=(
            "${AF_DB_PATH:-}"
            "${DB_PATH:-}"
            "${AETHERFLOW_DB_PATH:-}"
            "$env_db"
            "${DATA_DIR:+${DATA_DIR%/}/aetherflow.sqlite}"
            "${env_data_dir:+${env_data_dir%/}/aetherflow.sqlite}"
        )
        if [[ "$skip_host_env" != "1" ]]; then
            _creds_db_candidates+=(
                /var/lib/aetherflow/aetherflow.sqlite
                /opt/AetherFlow/current/data/aetherflow.sqlite
                /opt/AetherFlow/data/aetherflow.sqlite
                /opt/AetherFlow/backend/data/aetherflow.sqlite
            )
        fi
        for db_cand in "${_creds_db_candidates[@]}"; do
            if [[ -n "$db_cand" && -f "$db_cand" ]]; then
                u="$(sqlite3 "$db_cand" "SELECT username FROM users ORDER BY id ASC LIMIT 1;" 2>/dev/null | tr -d '[:space:]' || true)"
                [[ -n "$u" ]] && break
            fi
        done
    fi
    if [[ "$skip_host_env" != "1" ]]; then
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
    fi
    if [[ -z "$p" ]]; then
        p="$(python3 -c 'import secrets; print(secrets.token_hex(16))' 2>/dev/null || openssl rand -hex 16)" || return $?
        [[ "$p" =~ ^[0-9a-f]{32}$ ]] || return 1
        h=""
        generated=true
    fi
    export MASTER_USER="${u:-admin}"
    export MASTER_PASS="$p"
    if [[ ! "$h" =~ ^[0-9a-fA-F]{32}$ ]]; then
        h="$(printf '%s:Welcome to AetherFlow:%s' "$MASTER_USER" "$MASTER_PASS" | md5sum | awk '{print $1}')"
    fi
    export MASTER_HA1="$h"
    if [[ "$generated" == true ]]; then
        python3 - "$primary_creds_file" <<'PYEOF'
import base64, ctypes, ctypes.util, errno, grp, json, os, pwd, stat, sys, tempfile
username, password, ha1 = (os.environ[name] for name in ('MASTER_USER', 'MASTER_PASS', 'MASTER_HA1'))
destination = sys.argv[1]
directory = os.path.dirname(destination) or '.'

def _ensure_no_symlink_ancestors(target_dir):
    abs_dir = os.path.abspath(target_dir)
    probe = abs_dir
    while True:
        if os.path.lexists(probe):
            st = os.lstat(probe)
            if stat.S_ISLNK(st.st_mode):
                raise RuntimeError(f'Refusing symlinked credentials ancestor: {probe}')
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent

def _read_regular_file_nofollow(target):
    parent = os.path.dirname(os.path.abspath(target)) or '.'
    pst = os.lstat(parent)
    if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
        raise OSError(f'Unsafe parent directory for {target}')
    lst = os.lstat(target)
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        raise OSError(f'Refusing non-regular or symlinked file {target}')
    fd = os.open(target, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
            raise OSError(f'File identity changed during open for {target}')
        with os.fdopen(fd, 'r', encoding='utf-8', closefd=False) as fh:
            return fh.read()
    finally:
        os.close(fd)

_ensure_no_symlink_ancestors(directory)
if os.path.lexists(destination):
    dst_st = os.lstat(destination)
    if stat.S_ISLNK(dst_st.st_mode) or not stat.S_ISREG(dst_st.st_mode):
        raise RuntimeError(f'Refusing symlinked or non-regular master credentials path at {destination}')
    existing_raw = _read_regular_file_nofollow(destination)
    if 'enc:v1:' in existing_raw:
        raise RuntimeError(f'Refusing to overwrite encrypted master credentials at {destination}')

def resolve_aes_key():
    raw = os.environ.get('AES_MASTER_KEY', '').strip()
    if not raw:
        explicit_env = os.environ.get('AETHERFLOW_ENV_FILE', '').strip()
        env_path = explicit_env if explicit_env else (
            '/etc/aetherflow/aetherflow.env' if os.environ.get('AETHERFLOW_SKIP_ENV_FILES') != '1' else ''
        )
        if env_path:
            try:
                for line in _read_regular_file_nofollow(env_path).splitlines():
                    s = line.strip()
                    if not s or s.startswith('#'):
                        continue
                    if s.startswith('export '):
                        s = s[7:].strip()
                    if s.startswith('AES_MASTER_KEY='):
                        candidate = s.split('=', 1)[1].strip().strip("\"'")
                        if candidate:
                            raw = candidate
            except FileNotFoundError:
                raw = ''
            except OSError as exc:
                sys.stderr.write(f'Skipping unreadable env file {env_path}: {exc}\n')
    if not raw:
        return '', None
    if len(raw) == 64:
        try:
            dec_hex = bytes.fromhex(raw)
            if len(dec_hex) == 32:
                return raw, dec_hex
        except ValueError:
            pass
    try:
        dec = base64.b64decode(raw, validate=True)
        if len(dec) == 32:
            return raw, dec
    except Exception:
        pass
    raw_bytes = raw.encode('utf-8')
    return raw, (raw_bytes if len(raw_bytes) == 32 else None)

def _load_libcrypto():
    candidates = []
    found = ctypes.util.find_library('crypto')
    if found:
        candidates.append(found)
    candidates.extend(('libcrypto.so.3', 'libcrypto.so.1.1'))
    for name in candidates:
        try:
            lib = ctypes.CDLL(name)
            lib.EVP_CIPHER_CTX_new.argtypes = []
            lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            lib.EVP_CIPHER_CTX_free.restype = None
            lib.EVP_aes_256_gcm.argtypes = []
            lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
            lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
            lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            lib.EVP_EncryptInit_ex.restype = ctypes.c_int
            lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_int]
            lib.EVP_EncryptUpdate.restype = ctypes.c_int
            lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            lib.EVP_EncryptFinal_ex.restype = ctypes.c_int
            return lib
        except OSError:
            continue
    raise RuntimeError('OpenSSL libcrypto unavailable')

def aes_gcm_encrypt(key, nonce, pt):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).encrypt(nonce, pt, None)
    except ImportError:
        pass
    lib = _load_libcrypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError('EVP_CIPHER_CTX_new failed')
    try:
        key_buf = (ctypes.c_ubyte * 32).from_buffer_copy(key)
        iv_buf = (ctypes.c_ubyte * 12).from_buffer_copy(nonce)
        if lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None) != 1:
            raise RuntimeError('EVP_EncryptInit_ex cipher failed')
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x9, 12, None) != 1:
            raise RuntimeError('EVP_CTRL_GCM_SET_IVLEN failed')
        if lib.EVP_EncryptInit_ex(ctx, None, None, ctypes.byref(key_buf), ctypes.byref(iv_buf)) != 1:
            raise RuntimeError('EVP_EncryptInit_ex key/iv failed')
        out_buf = (ctypes.c_ubyte * max(1, len(pt) + 16))()
        out_len = ctypes.c_int(0)
        if pt:
            pt_buf = (ctypes.c_ubyte * len(pt)).from_buffer_copy(pt)
            if lib.EVP_EncryptUpdate(ctx, ctypes.byref(out_buf), ctypes.byref(out_len), ctypes.byref(pt_buf), len(pt)) != 1:
                raise RuntimeError('EVP_EncryptUpdate failed')
        final_len = ctypes.c_int(0)
        tail_ptr = ctypes.cast(ctypes.addressof(out_buf) + out_len.value, ctypes.c_void_p)
        if lib.EVP_EncryptFinal_ex(ctx, tail_ptr, ctypes.byref(final_len)) != 1:
            raise RuntimeError('EVP_EncryptFinal_ex failed')
        tag_buf = (ctypes.c_ubyte * 16)()
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, ctypes.byref(tag_buf)) != 1:
            raise RuntimeError('EVP_CTRL_GCM_GET_TAG failed')
        return bytes(out_buf[:out_len.value + final_len.value]) + bytes(tag_buf)
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)

def maybe_encrypt(plaintext, raw_key, key):
    if not raw_key:
        return plaintext
    if key is None:
        raise RuntimeError('AES_MASTER_KEY is configured but is not a valid 32-byte key')
    nonce = os.urandom(12)
    ct = aes_gcm_encrypt(key, nonce, plaintext.encode('utf-8'))
    return 'enc:v1:' + base64.b64encode(nonce + ct).decode('ascii')

raw_key, key = resolve_aes_key()
stored_password = maybe_encrypt(password, raw_key, key)
stored_ha1 = maybe_encrypt(ha1, raw_key, key)
temporary = None
try:
    aetherflow_owner = None
    if os.geteuid() == 0 and destination == '/var/lib/aetherflow/.master.creds':
        try:
            pw = pwd.getpwnam('aetherflow')
            try:
                gid = grp.getgrnam('aetherflow').gr_gid
            except KeyError:
                gid = pw.pw_gid
            aetherflow_owner = (pw.pw_uid, gid)
        except KeyError:
            aetherflow_owner = None
    _ensure_no_symlink_ancestors(directory)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fchmod(dir_fd, 0o700)
        if aetherflow_owner is not None:
            os.fchown(dir_fd, *aetherflow_owner)
    finally:
        os.close(dir_fd)
    if os.path.lexists(destination) and stat.S_ISLNK(os.lstat(destination).st_mode):
        raise RuntimeError(f'Refusing symlinked master credentials destination: {destination}')
    descriptor, temporary = tempfile.mkstemp(prefix='.master.creds.', dir=directory)
    with os.fdopen(descriptor, 'w') as output:
        os.fchmod(output.fileno(), 0o600)
        if aetherflow_owner is not None:
            os.fchown(output.fileno(), *aetherflow_owner)
        json.dump({'username': username, 'password': stored_password, 'ha1': stored_ha1}, output)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    if os.path.lexists(destination) and stat.S_ISLNK(os.lstat(destination).st_mode):
        raise RuntimeError(f'Refusing symlinked master credentials destination: {destination}')
    os.replace(temporary, destination)
    temporary = None
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
except OSError as error:
    if (
        error.errno in (errno.EACCES, errno.EPERM)
        and os.geteuid() != 0
        and 'AETHERFLOW_MASTER_CREDS_FILE' not in os.environ
        and destination == '/var/lib/aetherflow/.master.creds'
    ):
        pass
    elif error.errno not in (errno.EROFS, errno.ENODEV, errno.ENXIO):
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

derive_app_password() {
    local app_id="${1:?Application id is required for derive_app_password}"
    local master_secret="${2:-${MASTER_PASS:-}}"
    if [[ -z "$master_secret" ]]; then
        load_master_credentials || return $?
        master_secret="$MASTER_PASS"
    fi
    AF_DERIVE_APP="$app_id" AF_DERIVE_SECRET="$master_secret" python3 - <<'PYEOF'
import hashlib, hmac, os
app_id = os.environ["AF_DERIVE_APP"].strip().lower()
secret = os.environ["AF_DERIVE_SECRET"].encode("utf-8")
msg = f"aetherflow:{app_id}:webui:v1".encode("utf-8")
print(hmac.new(secret, msg, hashlib.sha256).hexdigest()[:32])
PYEOF
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
    AF_SEED_USER="$MASTER_USER" AF_SEED_PASS="${AF_CONFIG_PASS:-${AF_PASS:-$MASTER_PASS}}" AF_KEEP_SECRETS_FLAG="$keep_secrets" AF_FORCE_PASSWORD_ROTATION="${AF_FORCE_PASSWORD_ROTATION:-0}" AF_CONFIG_PASS="${AF_CONFIG_PASS:-${AF_PASS:-}}" af_logged python3 - "$app" "$port" "$api_ver" "$cfg_xml" <<'PYEOF'
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
    if AF_SEED_USER="$MASTER_USER" AF_SEED_PASS="${AF_CONFIG_PASS:-${AF_PASS:-$MASTER_PASS}}" AF_SEED_CURRENT_PASS="$MASTER_PASS" AF_KEEP_SECRETS_FLAG="$keep_secrets" AF_FORCE_PASSWORD_ROTATION="${AF_FORCE_PASSWORD_ROTATION:-0}" AF_CONFIG_PASS="${AF_CONFIG_PASS:-${AF_PASS:-}}" AF_SEED_EXISTING="${PRE_INSTALL_PRESENT:-false}" AF_SEED_EXISTING_CONFIG="${EXISTING_CONFIG_PRESENT:-false}" af_logged python3 - "$port" <<'PYEOF'
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
