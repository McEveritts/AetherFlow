# AetherFlow shared helpers: npm/git/deb/APT version pinning and transaction rollback.
# Sourced by packages/common.sh; do not execute directly.

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

    if [[ -z "$repo_url" || "$repo_url" == -* || -z "$build_dir" || "$build_dir" == -* ]]; then
        if declare -F af_write_failure_receipt >/dev/null 2>&1; then
            af_write_failure_receipt 1 "download" "invalid_git_source" "Invalid Git repository URL or staging directory"
        fi
        print_error "Invalid Git repository URL or staging directory"
        return 1
    fi

    # Cloudplow publishes commits on its default branch instead of release tags.
    if [[ -z "$raw_target" && "${4:-}" == "head" ]]; then
        if ! advertised_head="$(git ls-remote --exit-code -- "$repo_url" HEAD)" ||
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

        if ! remote_tags="$(git ls-remote --tags -- "$repo_url")"; then
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
        if ! af_logged git clone --no-checkout --depth 1 --branch "$selected_tag" -- "$repo_url" "$build_dir"; then
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
        if ! af_logged git clone --no-checkout -- "$repo_url" "$build_dir"; then
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

af_validate_exact_apt_version() {
    local raw="${1:-}" trimmed="" msg=""
    local apt_ver_re='^([0-9]+:)?[0-9][0-9A-Za-z.+~-]*$'
    trimmed="${raw#"${raw%%[![:space:]]*}"}"
    trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
    if [[ -z "$trimmed" || ${#trimmed} -gt 256 || "$trimmed" =~ [[:space:][:cntrl:]] || "$trimmed" == *..* || "$trimmed" == *- || ! "$trimmed" =~ $apt_ver_re ]]; then
        msg="Invalid exact Debian/APT target version: ${raw}"
        if declare -F print_error >/dev/null 2>&1; then
            print_error "$msg"
        elif declare -F log_error >/dev/null 2>&1; then
            log_error "$msg"
        else
            printf 'ERROR: %s\n' "$msg" >&2
        fi
        return 1
    fi
    printf '%s\n' "$trimmed"
}

verify_deb_installed() {
    local package="$1" expected="${2:-}" observed status installed extra=""
    observed="$(dpkg-query -W -f='${db:Status-Status} ${Version}\n' "$package" 2>/dev/null)" || return 1
    read -r status installed extra <<< "$observed"
    if [[ "$status" != installed || -z "$installed" || -n "$extra" ]]; then
        print_error "Package $package is not installed"
        return 1
    fi
    if [[ -n "$expected" ]] && ! deb_compare_versions "$installed" eq "$expected"; then
        print_error "Package $package version $installed does not match $expected"
        return 1
    fi
}

verify_apt_package_installed() {
    local package="$1" expected="${2:-${AF_APT_TARGET_VERSION:-}}" observed="" status="" installed="" extra=""
    observed="$(dpkg-query -W -f='${db:Status-Status} ${Version}\n' "$package" 2>/dev/null || true)"
    read -r status installed extra <<< "$observed"
    if [[ "$status" != installed || -z "$installed" || -n "$extra" ]]; then
        print_error "APT package $package is not installed (dpkg status: ${status:-missing})"
        return 1
    fi
    if [[ -n "$expected" && "$installed" != "$expected" ]]; then
        print_error "APT package $package installed version ($installed) does not match requested exact version ($expected)"
        return 1
    fi
}

installed_apt_package_version() {
    local observed status version extra=""
    observed="$(dpkg-query -W -f='${db:Status-Status} ${Version}\n' "$1" 2>/dev/null || true)"
    read -r status version extra <<< "$observed"
    if [[ "$status" == installed && -n "$version" && -z "$extra" ]]; then
        printf '%s\n' "$version"
    else
        printf '<none>\n'
    fi
}

apt_package_raw_status() {
    local observed="" status="" version="" extra=""
    observed="$(dpkg-query -W -f='${db:Status-Status} ${Version}\n' "$1" 2>/dev/null || true)"
    read -r status version extra <<< "$observed"
    if [[ -n "$status" && -z "$extra" ]]; then
        printf '%s\n' "$status"
    else
        printf 'not-installed\n'
    fi
}

apt_package_has_active_or_transitional_payload() {
    case "$(apt_package_raw_status "$1")" in
        installed|unpacked|half-installed|half-configured|triggers-awaited|triggers-pending)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

apt_package_is_lockstep() {
    local candidate="$1" package
    [[ -v AF_APT_LOCKSTEP_PACKAGES ]] || return 1
    for package in "${AF_APT_LOCKSTEP_PACKAGES[@]}"; do
        if [[ "$package" == "$candidate" ]]; then
            return 0
        fi
    done
    return 1
}

resolve_installed_apt_package_version() {
    local package="$1" fallback="${2:-}" expected="" installed=""
    if [[ "${AF_APT_LOCAL_DEB:-false}" != true ]]; then
        if [[ -n "${AF_APT_TARGET_VERSION:-}" ]]; then
            expected="${AF_APT_TARGET_VERSION}"
        elif [[ -n "${AF_TARGET_VERSION:-}" ]]; then
            expected="$(af_validate_exact_apt_version "${AF_TARGET_VERSION}")" || return 1
        fi
    fi
    if [[ -n "$expected" ]]; then
        verify_apt_package_installed "$package" "$expected" || return 1
        printf '%s\n' "$expected"
        return 0
    fi
    installed="$(installed_apt_package_version "$package")" || return 1
    if [[ "$installed" != '<none>' && -n "$installed" ]]; then
        printf '%s\n' "$installed"
        return 0
    fi
    if [[ -n "$fallback" ]]; then
        printf '%s\n' "$fallback"
        return 0
    fi
    print_error "APT package $package is not installed"
    return 1
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
    local local_deb=false lockstep=false
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --local-deb)
                local_deb=true
                shift
                ;;
            --lockstep)
                lockstep=true
                shift
                ;;
            --)
                shift
                break
                ;;
            *)
                break
                ;;
        esac
    done
    if [[ "$local_deb" == true && "$lockstep" == true ]]; then
        print_error "prepare_apt_package_transaction cannot combine --local-deb and --lockstep"
        return 1
    fi
    [[ "$#" -ge 2 ]] || {
        print_error "prepare_apt_package_transaction requires at least one Debian package name"
        return 1
    }
    local receipt="$1" package marker installed previous="" normalized target=""
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
    declare -ag AF_APT_REINSTALL_PACKAGES=() AF_APT_TRANSACTION_PACKAGES=() AF_APT_LOCKSTEP_PACKAGES=()
    AF_APT_PRIMARY_PACKAGE="$1"
    AF_APT_TARGET_VERSION=""
    AF_APT_LOCAL_DEB="$local_deb"
    if [[ "$local_deb" != true && "$lockstep" == true ]]; then
        AF_APT_LOCKSTEP_PACKAGES=("$@")
    fi
    if [[ "$local_deb" != true && -n "${AF_TARGET_VERSION:-}" ]]; then
        target="$(af_validate_exact_apt_version "${AF_TARGET_VERSION}")" || return 1
        AF_APT_TARGET_VERSION="$target"
        if [[ -e "$receipt" || -L "$receipt" ]]; then
            write_app_version "$receipt" "$target" --check || return 1
        fi
        if [[ "${AF_ALLOW_DOWNGRADE:-0}" != "1" ]]; then
            local -a downgrade_check_pkgs=("$AF_APT_PRIMARY_PACKAGE")
            if [[ "$lockstep" == true ]]; then
                downgrade_check_pkgs=("$@")
            fi
            for package in "${downgrade_check_pkgs[@]}"; do
                installed="$(installed_apt_package_version "$package")" || return 1
                if [[ "$installed" != '<none>' && -n "$installed" ]] && ! deb_compare_versions "$target" ge "$installed"; then
                    print_error "Refusing to downgrade APT package ${package} from ${installed} to ${target}"
                    return 1
                fi
            done
        fi
    fi
    record_apt_package_for_rollback "$@" || return 1
    for package in "$@"; do
        AF_APT_TRANSACTION_PACKAGES+=("$package")
        marker="$(apt_reinstall_marker_path "$package")" || return 1
        validate_config_paths "$marker" || return 1
        installed="$(installed_apt_package_version "$package")" || return 1
        normalized="${installed#*:}"
        normalized="${normalized%%-*}"
        if [[ -f "$marker" || ( "$installed" != '<none>' && -z "$previous" ) || ( "$package" == "$AF_APT_PRIMARY_PACKAGE" && -n "$previous" && "$installed" != "$previous" && "$normalized" != "${previous#v}" ) ]]; then
            AF_APT_REINSTALL_PACKAGES+=("$package")
        fi
    done
}

_af_apt_lock_timeout_value() {
    local raw="${DPKG_LOCK_TIMEOUT:-120}"
    if [[ "$raw" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$raw"
    else
        printf '120\n'
    fi
}

_af_apt_args_have_lock_timeout() {
    local arg expect_opt=false
    for arg in "$@"; do
        if [[ "$expect_opt" == true ]]; then
            expect_opt=false
            [[ "$arg" != DPkg::Lock::Timeout=* ]] || return 0
            continue
        fi
        case "$arg" in
            -o|--option)
                expect_opt=true
                ;;
            -oDPkg::Lock::Timeout=*|-o=DPkg::Lock::Timeout=*|--option=DPkg::Lock::Timeout=*)
                return 0
                ;;
        esac
    done
    return 1
}

apt-get() {
    local package argument arg_pkg="" selected=false primary_selected=false present=false skip_next=false
    local -a rewritten=() additional=() extra_flags=() lock_timeout_args=()
    [[ -v AF_APT_TRANSACTION_PACKAGES ]] || declare -ag AF_APT_TRANSACTION_PACKAGES=()
    [[ -v AF_APT_REINSTALL_PACKAGES ]] || declare -ag AF_APT_REINSTALL_PACKAGES=()
    [[ -v AF_APT_LOCKSTEP_PACKAGES ]] || declare -ag AF_APT_LOCKSTEP_PACKAGES=()
    local primary="${AF_APT_PRIMARY_PACKAGE:-}"
    local target="${AF_APT_TARGET_VERSION:-}"
    local local_deb="${AF_APT_LOCAL_DEB:-false}"

    if ! _af_apt_args_have_lock_timeout "$@"; then
        lock_timeout_args=(-o "DPkg::Lock::Timeout=$(_af_apt_lock_timeout_value)")
    fi

    if [[ "${1:-}" == install ]]; then
        for argument in "${@:2}"; do
            if [[ "$skip_next" == true ]]; then
                skip_next=false
                rewritten+=("$argument")
                continue
            fi
            case "$argument" in
                -o|--option|-t|--target-release|--default-release|-c|--config-file)
                    skip_next=true
                    rewritten+=("$argument")
                    continue
                    ;;
            esac
            if [[ "$local_deb" != true && -n "$primary" && -n "$target" && "$argument" != -* && "$argument" != /*.deb ]]; then
                arg_pkg="${argument%%[=/]*}"
                if [[ "$arg_pkg" == "$primary" ]] || apt_package_is_lockstep "$arg_pkg"; then
                    case "$argument" in
                        "$arg_pkg") argument="${arg_pkg}=${target}" ;;
                        "$arg_pkg=$target") ;;
                        "$arg_pkg="*)
                            print_error "Refusing conflicting APT package target '$argument' for requested exact version '$target'"
                            return 1
                            ;;
                        *)
                            print_error "Refusing floating APT release target '$argument' for requested exact version '$target'"
                            return 1
                            ;;
                    esac
                    [[ "$arg_pkg" != "$primary" ]] || primary_selected=true
                fi
            fi
            rewritten+=("$argument")
            for package in "${AF_APT_TRANSACTION_PACKAGES[@]}"; do
                if [[ "$argument" == "$package" || "$argument" == "$package="* || "$argument" == /*.deb ]]; then
                    selected=true
                fi
            done
        done

        if [[ "$selected" == true ]]; then
            if [[ "${#AF_APT_REINSTALL_PACKAGES[@]}" -gt 0 ]]; then
                for package in "${AF_APT_REINSTALL_PACKAGES[@]}"; do
                    present=false
                    for argument in "${rewritten[@]}"; do
                        if [[ "$argument" == "$package" || "$argument" == "$package="* || "$argument" == /*.deb ]]; then
                            present=true
                            break
                        fi
                    done
                    if [[ "$present" != true ]]; then
                        if [[ "$local_deb" != true && -n "$target" ]] && { [[ "$package" == "$primary" ]] || apt_package_is_lockstep "$package"; }; then
                            additional+=("${package}=${target}")
                            [[ "$package" != "$primary" ]] || primary_selected=true
                        else
                            additional+=("$package")
                        fi
                    fi
                done
                extra_flags+=(--reinstall)
            fi
            if [[ "$primary_selected" == true && "$local_deb" != true && -n "$target" && "${#AF_APT_LOCKSTEP_PACKAGES[@]}" -gt 0 ]]; then
                for package in "${AF_APT_LOCKSTEP_PACKAGES[@]}"; do
                    present=false
                    for argument in "${rewritten[@]}" "${additional[@]}"; do
                        if [[ "$argument" == "$package" || "$argument" == "$package="* || "$argument" == /*.deb ]]; then
                            present=true
                            break
                        fi
                    done
                    if [[ "$present" != true ]]; then
                        additional+=("${package}=${target}")
                    fi
                done
            fi
            if [[ "$primary_selected" == true && "${AF_ALLOW_DOWNGRADE:-0}" == "1" ]]; then
                local has_allow_downgrades=false
                for argument in "${rewritten[@]}"; do
                    [[ "$argument" != "--allow-downgrades" ]] || has_allow_downgrades=true
                done
                [[ "$has_allow_downgrades" == true ]] || extra_flags+=(--allow-downgrades)
            fi
            command apt-get install "${lock_timeout_args[@]}" "${extra_flags[@]}" "${rewritten[@]}" "${additional[@]}" || return $?
            if [[ "$primary_selected" == true ]]; then
                if [[ "${#AF_APT_LOCKSTEP_PACKAGES[@]}" -gt 0 ]]; then
                    for package in "${AF_APT_LOCKSTEP_PACKAGES[@]}"; do
                        verify_apt_package_installed "$package" "$target" || return 1
                    done
                else
                    verify_apt_package_installed "$primary" "$target" || return 1
                fi
            fi
            return 0
        fi
    fi
    if (( $# > 0 )) && [[ "$1" != -* ]]; then
        command apt-get "$1" "${lock_timeout_args[@]}" "${@:2}"
    else
        command apt-get "${lock_timeout_args[@]}" "$@"
    fi
}

rollback_apt_packages() {
    local state package previous installed marker reconciled failed=false idx
    local lock_timeout
    lock_timeout="$(_af_apt_lock_timeout_value)"
    local -a remove_pkgs=() downgrade_pkgs=() downgrade_prevs=() downgrade_specs=()
    AF_APT_ROLLBACK_MUTATED=false
    [[ -d "${AF_TX_DIR:-}/apt-packages" ]] || return 0
    for state in "$AF_TX_DIR/apt-packages/"*; do
        [[ -f "$state" && ! -L "$state" ]] || continue
        package="${state##*/}"
        previous="$(cat -- "$state")"
        if [[ "$previous" == '<none>' ]]; then
            if apt_package_has_active_or_transitional_payload "$package"; then
                AF_APT_ROLLBACK_MUTATED=true
                remove_pkgs+=("$package")
            fi
            continue
        fi
        installed="$(installed_apt_package_version "$package")"
        if [[ "$installed" == "$previous" ]]; then
            continue
        fi
        AF_APT_ROLLBACK_MUTATED=true
        downgrade_pkgs+=("$package")
        downgrade_prevs+=("$previous")
        downgrade_specs+=("${package}=${previous}")
    done

    if (( ${#remove_pkgs[@]} > 1 )); then
        DEBIAN_FRONTEND=noninteractive af_logged command apt-get remove -o "DPkg::Lock::Timeout=${lock_timeout}" -y --no-auto-remove "${remove_pkgs[@]}" || true
    fi
    for package in "${remove_pkgs[@]}"; do
        reconciled=true
        if apt_package_has_active_or_transitional_payload "$package"; then
            DEBIAN_FRONTEND=noninteractive af_logged command apt-get remove -o "DPkg::Lock::Timeout=${lock_timeout}" -y --no-auto-remove "$package" || reconciled=false
        fi
        if [[ "$reconciled" != true ]] || apt_package_has_active_or_transitional_payload "$package"; then
            marker="$(apt_reinstall_marker_path "$package")" || return 1
            printf '%s\n' '<none>' | write_config_file "$marker" 0600 || return 1
            print_warn "APT recovery for $package requires reinstallation on the next attempt"
            failed=true
        fi
    done

    if (( ${#downgrade_specs[@]} > 1 )); then
        DEBIAN_FRONTEND=noninteractive af_logged command apt-get install -o "DPkg::Lock::Timeout=${lock_timeout}" -y --allow-downgrades --reinstall "${downgrade_specs[@]}" || true
    fi
    for idx in "${!downgrade_pkgs[@]}"; do
        package="${downgrade_pkgs[$idx]}"
        previous="${downgrade_prevs[$idx]}"
        reconciled=true
        installed="$(installed_apt_package_version "$package")"
        if [[ "$installed" != "$previous" ]]; then
            DEBIAN_FRONTEND=noninteractive af_logged command apt-get install -o "DPkg::Lock::Timeout=${lock_timeout}" -y --allow-downgrades --reinstall "${package}=${previous}" || reconciled=false
            installed="$(installed_apt_package_version "$package")"
        fi
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
