# AetherFlow shared helpers: logging, logfile locking, archive extraction, and safe removal.
# Sourced by packages/common.sh; do not execute directly.

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


af_mkdir_p_0755() {
    if [[ "$#" -eq 0 ]]; then
        return 0
    fi
    ( umask 022 && mkdir -p -- "$@" ) || return 1
    chmod 0755 -- "$@" || return 1
}

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
    local allow_intra_symlinks=0 strip_components=0 archive_path=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --allow-intra-symlinks)
                allow_intra_symlinks=1
                shift
                ;;
            --strip-components=*)
                strip_components="${1#*=}"
                shift
                ;;
            --strip-components)
                if [[ $# -lt 2 ]]; then
                    if declare -F log_error >/dev/null 2>&1; then
                        log_error "Missing value for --strip-components"
                    else
                        printf '[ERROR] Missing value for --strip-components\n' >&2
                    fi
                    return 1
                fi
                strip_components="$2"
                shift 2
                ;;
            --)
                shift
                break
                ;;
            -*)
                if declare -F log_error >/dev/null 2>&1; then
                    log_error "Unknown option for af_validate_tar_archive: $1"
                else
                    printf '[ERROR] Unknown option for af_validate_tar_archive: %s\n' "$1" >&2
                fi
                return 1
                ;;
            *)
                break
                ;;
        esac
    done
    archive_path="${1:-}"
    if [[ $# -ne 1 || -z "$archive_path" ]]; then
        if declare -F log_error >/dev/null 2>&1; then
            log_error "af_validate_tar_archive requires exactly one archive path"
        else
            printf '[ERROR] af_validate_tar_archive requires exactly one archive path\n' >&2
        fi
        return 1
    fi
    if [[ ! "$strip_components" =~ ^[0-9]+$ ]]; then
        if declare -F log_error >/dev/null 2>&1; then
            log_error "Invalid --strip-components value: ${strip_components}"
        else
            printf '[ERROR] Invalid --strip-components value: %s\n' "${strip_components}" >&2
        fi
        return 1
    fi
    if [[ ! -f "$archive_path" || -L "$archive_path" ]]; then
        if declare -F log_error >/dev/null 2>&1; then
            log_error "Refusing missing or symlinked archive path: ${archive_path}"
        else
            printf '[ERROR] Refusing missing or symlinked archive path: %s\n' "${archive_path}" >&2
        fi
        return 1
    fi
    python3 - "$archive_path" "$allow_intra_symlinks" "$strip_components" <<'PYEOF'
import pathlib, sys, tarfile

archive = sys.argv[1]
allow_intra_symlinks = sys.argv[2] == "1"
strip_components = int(sys.argv[3])
MAX_SYMLINK_HOPS = 40

try:
    with tarfile.open(archive, "r:*") as tf:
        members = tf.getmembers()
        if not members:
            raise ValueError("empty tar archive")
        symlink_map = {}
        seen_non_symlinks = set()
        effective_entries = []
        kept_any = False

        for member in members:
            name = member.name or ""
            if "\x00" in name:
                raise ValueError(f"disallowed NUL byte in tar entry: {name!r}")
            if name.startswith("/") or name.startswith("\\"):
                raise ValueError(f"disallowed absolute tar entry: {name}")
            raw_parts = pathlib.PurePosixPath(name).parts
            if ".." in raw_parts:
                raise ValueError(f"disallowed path-traversal tar entry: {name}")

            is_regular_or_dir = member.isfile() or member.isdir()
            is_symlink = member.issym()
            if not is_regular_or_dir and not (allow_intra_symlinks and is_symlink):
                raise ValueError(f"disallowed non-regular tar entry: {name} (type={member.type!r})")

            norm_parts = tuple(part for part in raw_parts if part not in ("", "."))
            if strip_components > 0:
                if len(norm_parts) <= strip_components:
                    if is_symlink:
                        raise ValueError(f"disallowed stripped tar symlink entry: {name}")
                    continue
                eff_parts = norm_parts[strip_components:]
            else:
                eff_parts = norm_parts
            kept_any = True

            if is_symlink:
                linkname = member.linkname or ""
                if (
                    not linkname
                    or "\x00" in linkname
                    or linkname.startswith("/")
                    or linkname.startswith("\\")
                    or "\\" in linkname
                ):
                    raise ValueError(f"disallowed tar symlink target: {name} -> {linkname!r}")
                if not eff_parts:
                    raise ValueError(f"disallowed root tar symlink entry: {name}")
                if eff_parts in symlink_map or eff_parts in seen_non_symlinks:
                    raise ValueError(f"disallowed duplicate/conflicting tar symlink entry: {name}")
                cur = list(eff_parts[:-1])
                for comp in pathlib.PurePosixPath(linkname).parts:
                    if comp in ("", "."):
                        continue
                    if comp == "..":
                        if not cur:
                            raise ValueError(f"disallowed escaping tar symlink: {name} -> {linkname}")
                        cur.pop()
                    else:
                        cur.append(comp)
                symlink_map[eff_parts] = (name, linkname)
            else:
                if eff_parts in symlink_map:
                    raise ValueError(f"disallowed tar entry colliding with symlink: {name}")
                if eff_parts:
                    seen_non_symlinks.add(eff_parts)
            effective_entries.append((eff_parts, name))

        if strip_components > 0 and not kept_any:
            raise ValueError("tar archive contains no entries after --strip-components")

        if symlink_map:
            for eff_parts, name in effective_entries:
                for depth in range(1, len(eff_parts)):
                    if eff_parts[:depth] in symlink_map:
                        raise ValueError(f"disallowed tar entry traversing symlink ancestor: {name}")

            for start_parts, (orig_name, start_target) in symlink_map.items():
                cur = list(start_parts[:-1])
                queue = list(pathlib.PurePosixPath(start_target).parts)
                hops = 0
                while queue:
                    comp = queue.pop(0)
                    if comp in ("", "."):
                        continue
                    if comp == "..":
                        if not cur:
                            raise ValueError(
                                f"disallowed escaping tar symlink chain: {orig_name} -> {start_target}"
                            )
                        cur.pop()
                        continue
                    cur.append(comp)
                    cur_tuple = tuple(cur)
                    if cur_tuple in symlink_map:
                        hops += 1
                        if hops > MAX_SYMLINK_HOPS:
                            raise ValueError(
                                f"disallowed cyclic tar symlink chain: {orig_name} -> {start_target}"
                            )
                        cur.pop()
                        next_target = symlink_map[cur_tuple][1]
                        queue = list(pathlib.PurePosixPath(next_target).parts) + queue
except Exception as exc:
    sys.stderr.write(f"Tar archive validation failed for {archive}: {exc}\n")
    raise SystemExit(1)
PYEOF
}

af_validate_tar_archive_allow_intra_symlinks() {
    af_validate_tar_archive --allow-intra-symlinks "$@"
}

# Validate all member names and types before extracting into a private staging directory.
af_extract_zip_archive() {
    local archive_path="$1" destination="$2"
    [[ -f "$archive_path" && ! -L "$archive_path" && -d "$destination" && ! -L "$destination" ]] || {
        print_error "Unsafe ZIP archive or staging directory"
        return 1
    }
    python3 - "$archive_path" "$destination" <<'PYEOF'
from pathlib import Path
import shutil, stat, sys, zipfile

archive_path, destination = map(Path, sys.argv[1:])
try:
    with zipfile.ZipFile(archive_path) as archive:
        entries = {}
        for member in archive.infolist():
            is_dir = member.is_dir()
            name = member.filename.removesuffix("/") if is_dir else member.filename
            parts = name.split("/")
            mode = member.external_attr >> 16
            expected_type = stat.S_IFDIR if is_dir else stat.S_IFREG
            if (
                member.orig_filename != member.filename
                or any(part in ("", ".", "..") for part in parts)
                or any(ord(char) < 32 or char in "\\:" for char in name)
                or stat.S_IFMT(mode) not in (0, expected_type)
                or name in entries
            ):
                raise ValueError(f"disallowed ZIP entry: {member.orig_filename!r}")
            entries[name] = (member, is_dir, parts, mode)

        if not entries:
            raise ValueError("empty ZIP archive")
        for member, is_dir, parts, mode in entries.values():
            target = destination.joinpath(*parts)
            if is_dir:
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst)
                if mode & 0o111:
                    target.chmod(stat.S_IMODE(target.stat().st_mode) | (mode & 0o111))
except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
    sys.stderr.write(f"ZIP archive extraction failed: {exc}\n")
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
