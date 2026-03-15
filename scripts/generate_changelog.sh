#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-v3.1.0}"
BASE_TAG="${BASE_TAG:-v3.0.1}"
CHANGELOG_FILE="${CHANGELOG_FILE:-${ROOT_DIR}/CHANGELOG.md}"
VERSION_FILE="${VERSION_FILE:-${ROOT_DIR}/.version}"
GENERATED_ON="${GENERATED_ON:-$(date -u +"%B %d, %Y")}"

declare -a features=()
declare -a security=()
declare -a uiux=()
declare -a php_removal_refs=()
declare -a jwt_refs=()

commit_count=0
has_php_removal=0
has_jwt_hardening=0

cleanup_files=()

cleanup() {
  if [[ ${#cleanup_files[@]} -gt 0 ]]; then
    rm -f "${cleanup_files[@]}"
  fi
}
trap cleanup EXIT

make_temp_file() {
  local tmp
  tmp="$(mktemp)"
  cleanup_files+=("${tmp}")
  printf '%s\n' "${tmp}"
}

require_repo() {
  if [[ ! -d "${ROOT_DIR}/.git" ]]; then
    echo "error: ${ROOT_DIR} is not a git repository" >&2
    exit 1
  fi
}

sanitize_text() {
  local text="$1"
  text="${text//$'\r'/}"
  text="${text//$'\342\200\224'/-}"
  text="${text//$'\342\200\234'/\"}"
  text="${text//$'\342\200\235'/\"}"
  text="${text//$'\342\200\231'/\'}"
  printf '%s' "${text}"
}

lower_text() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

resolve_tag_hash() {
  local tag_ref="refs/tags/${BASE_TAG}"
  local tag_file="${ROOT_DIR}/.git/${tag_ref}"
  local line

  if command -v git >/dev/null 2>&1; then
    git -C "${ROOT_DIR}" rev-parse "${BASE_TAG}" 2>/dev/null
    return
  fi

  if [[ -f "${tag_file}" ]]; then
    tr -d '\r\n' < "${tag_file}"
    return
  fi

  if [[ -f "${ROOT_DIR}/.git/packed-refs" ]]; then
    while IFS= read -r line; do
      [[ -z "${line}" || "${line}" == \#* || "${line}" == ^* ]] && continue
      if [[ "${line#* }" == "${tag_ref}" ]]; then
        printf '%s\n' "${line%% *}"
        return
      fi
    done < "${ROOT_DIR}/.git/packed-refs"
  fi

  echo "error: could not resolve ${BASE_TAG}" >&2
  exit 1
}

resolve_head_hash() {
  local head_contents
  local ref_path

  if command -v git >/dev/null 2>&1; then
    git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null
    return
  fi

  head_contents="$(<"${ROOT_DIR}/.git/HEAD")"
  if [[ "${head_contents}" == ref:\ * ]]; then
    ref_path="${head_contents#ref: }"
    tr -d '\r\n' < "${ROOT_DIR}/.git/${ref_path}"
    return
  fi

  printf '%s\n' "${head_contents}"
}

current_branch_log() {
  local head_contents
  local ref_path

  head_contents="$(<"${ROOT_DIR}/.git/HEAD")"
  if [[ "${head_contents}" == ref:\ * ]]; then
    ref_path="${head_contents#ref: }"
    printf '%s\n' "${ROOT_DIR}/.git/logs/${ref_path}"
    return
  fi

  echo "error: detached HEAD fallback is not supported without git in PATH" >&2
  exit 1
}

normalize_subject() {
  local subject
  subject="$(sanitize_text "$1")"

  if [[ "${subject}" =~ ^[[:alpha:]][[:alnum:]_-]*(\([^)]+\))?:[[:space:]]*(.*)$ ]]; then
    subject="${BASH_REMATCH[2]}"
  fi

  case "${subject}" in
    "resolve all frontend lint errors and remove legacy PHP code")
      subject="Removed the remaining legacy PHP codepaths and deprecated ruTorrent-era assets while bringing the Next.js frontend back to a clean lint/build state"
      ;;
    "remove legacy PHP dashboard and remaining migration scripts")
      subject="Deleted the legacy PHP dashboard and migration remnants so the Next.js application is the sole supported UI surface"
      ;;
    "remediate 8 critical audit findings")
      subject="Closed eight critical audit findings across admin authorization, JWT secret handling, session cookie defaults, WebSocket origin checks, and upload sanitization"
      ;;
    "additional hardening pass")
      subject="Applied an additional hardening pass by moving fileshare uploads behind admin-only access, blocking dangerous extensions, and removing destructive update flows"
      ;;
    "implement P1-P15 improvement backlog")
      subject="Implemented the P1-P15 reliability backlog, including rate limiting, safer backups, semver-aware updates, Docker status detection, and initial critical-path test coverage"
      ;;
    "Parts 2 & 5 - Frontend state management + Legacy deprecation + Security hardening")
      subject="Completed the remaining frontend state-management, legacy deprecation, and security-hardening work for the Gold release candidate"
      ;;
    "expand Go API with auth, services, marketplace, updater, and WebSocket endpoints")
      subject="Expanded the Go backend with auth, services, marketplace, updater, and WebSocket endpoints"
      ;;
    "add missing dashboard tabs and enhance existing ones")
      subject="Added the missing dashboard tabs and strengthened the marketplace, services, settings, and AI management flows"
      ;;
    "add UI infrastructure, auth flow, and polish components")
      subject="Added onboarding, toast notifications, real-time UI infrastructure, and a more polished authentication flow"
      ;;
    "Netdata-style dashboard with sparkline charts, per-core CPU heatmap, process list, disk I/O, and swap monitoring")
      subject="Delivered a Netdata-style observability dashboard with sparklines, heatmaps, process insights, and disk/swap telemetry"
      ;;
  esac

  if [[ "${subject}" == "" ]]; then
    subject="Unspecified release work"
  fi

  subject="${subject%.}"
  printf '%s.' "${subject}"
}

categorize_commit() {
  local hash="$1"
  local subject="$2"
  local body="$3"
  local combined
  local combined_lower
  local entry

  combined="$(sanitize_text "${subject}"$'\n'"${body}")"
  combined_lower="$(lower_text "${combined}")"
  entry="- $(normalize_subject "${subject}") (\`${hash:0:7}\`)"

  if [[ "${combined_lower}" == *"legacy php"* ]] || [[ "${combined_lower}" == *"delete dashboard/"* ]] || [[ "${combined_lower}" == *"remove legacy php"* ]]; then
    has_php_removal=1
    php_removal_refs+=("\`${hash:0:7}\`")
  fi

  if [[ "${combined_lower}" == *"jwt"* ]] || [[ "${combined_lower}" == *"jwt_secret"* ]]; then
    has_jwt_hardening=1
    jwt_refs+=("\`${hash:0:7}\`")
  fi

  if [[ "${combined_lower}" == *"security"* ]] || [[ "${combined_lower}" == *"harden"* ]] || [[ "${combined_lower}" == *"jwt"* ]] || [[ "${combined_lower}" == *"csrf"* ]] || [[ "${combined_lower}" == *"cookie"* ]] || [[ "${combined_lower}" == *"path traversal"* ]] || [[ "${combined_lower}" == *"adminonly"* ]] || [[ "${combined_lower}" == *"legacy php"* ]] || [[ "${combined_lower}" == *"delete dashboard/"* ]]; then
    security+=("${entry}")
    return
  fi

  if [[ "${combined_lower}" == *"frontend"* ]] || [[ "${combined_lower}" == *"dashboard"* ]] || [[ "${combined_lower}" == *"widget"* ]] || [[ "${combined_lower}" == *"sidebar"* ]] || [[ "${combined_lower}" == *"tab"* ]] || [[ "${combined_lower}" == *"chart"* ]] || [[ "${combined_lower}" == *"toast"* ]] || [[ "${combined_lower}" == *"skeleton"* ]] || [[ "${combined_lower}" == *"onboarding"* ]] || [[ "${combined_lower}" == *"state management"* ]] || [[ "${combined_lower}" == *"layout"* ]] || [[ "${combined_lower}" == *"marketplace"* ]]; then
    uiux+=("${entry}")
    return
  fi

  features+=("${entry}")
}

collect_commits_with_git() {
  git -C "${ROOT_DIR}" log "${BASE_TAG}..HEAD" --reverse --pretty=format:'%H%x1f%ct%x1f%s%x1f%b%x1e'
}

collect_commits_from_reflog() {
  local base_hash
  local log_file
  local line
  local capture=0
  local old_hash
  local remainder
  local new_hash
  local message
  local subject
  local body

  base_hash="$(resolve_tag_hash)"
  log_file="$(current_branch_log)"

  if [[ ! -f "${log_file}" ]]; then
    echo "error: fallback reflog '${log_file}' was not found" >&2
    exit 1
  fi

  while IFS= read -r line; do
    old_hash="${line%% *}"
    remainder="${line#* }"
    new_hash="${remainder%% *}"
    message="${line#*$'\t'}"

    if [[ "${capture}" -eq 0 && "${old_hash}" == "${base_hash}" ]]; then
      capture=1
    fi

    if [[ "${capture}" -eq 0 ]]; then
      continue
    fi

    if [[ "${message}" != commit:* ]]; then
      continue
    fi

    message="${message#commit: }"
    message="${message//\\n/$'\n'}"
    subject="${message%%$'\n'*}"
    if [[ "${message}" == *$'\n'* ]]; then
      body="${message#*$'\n'}"
    else
      body=""
    fi

    printf '%s\x1f%s\x1f%s\x1f%s\x1e' "${new_hash}" "" "${subject}" "${body}"
  done < "${log_file}"
}

parse_commits() {
  local stream_file
  local record
  local hash
  local remainder
  local subject
  local body

  stream_file="$(make_temp_file)"
  if command -v git >/dev/null 2>&1; then
    collect_commits_with_git > "${stream_file}"
  else
    collect_commits_from_reflog > "${stream_file}"
  fi

  while IFS= read -r -d $'\x1e' record; do
    [[ -z "${record}" ]] && continue

    hash="${record%%$'\x1f'*}"
    remainder="${record#*$'\x1f'}"
    remainder="${remainder#*$'\x1f'}"
    subject="${remainder%%$'\x1f'*}"
    body="${remainder#*$'\x1f'}"

    commit_count=$((commit_count + 1))
    categorize_commit "${hash}" "${subject}" "${body}"
  done < <(cat "${stream_file}" && printf '\x1e')
}

append_section() {
  local title="$1"
  shift
  local entries=("$@")

  printf '### %s\n' "${title}"
  if [[ ${#entries[@]} -eq 0 ]]; then
    printf -- '- No release notes captured for this category.\n\n'
    return
  fi

  printf '%s\n' "${entries[@]}"
  printf '\n'
}

history_tail() {
  local capture=0
  local line

  if [[ ! -f "${CHANGELOG_FILE}" ]]; then
    return
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    if [[ "${capture}" -eq 0 && "${line}" == "## CHANGELOG ${BASE_TAG}"* ]]; then
      capture=1
    fi

    if [[ "${capture}" -eq 1 ]]; then
      printf '%s\n' "${line}"
    fi
  done < "${CHANGELOG_FILE}"
}

write_changelog() {
  local head_hash
  local output_file
  local preserved_history_file
  local php_refs
  local jwt_refs_joined

  head_hash="$(resolve_head_hash)"
  output_file="$(make_temp_file)"
  preserved_history_file="$(make_temp_file)"
  history_tail > "${preserved_history_file}"

  if [[ "${has_php_removal}" -eq 1 ]]; then
    php_refs="$(printf '%s, ' "${php_removal_refs[@]}")"
    php_refs="${php_refs%, }"
    security=("- Completed the retirement of the remaining legacy PHP and dashboard surface area, reducing exposed attack surface before the Gold release candidate. (${php_refs})" "${security[@]}")
  fi

  if [[ "${has_jwt_hardening}" -eq 1 ]]; then
    jwt_refs_joined="$(printf '%s, ' "${jwt_refs[@]}")"
    jwt_refs_joined="${jwt_refs_joined%, }"
    security=("- Tightened JWT handling by failing closed when \`JWT_SECRET\` is missing and reinforcing admin/session protections around auth-sensitive endpoints. (${jwt_refs_joined})" "${security[@]}")
  fi

  {
    printf '## CHANGELOG %s - Gold Release Candidate\n' "${VERSION}"
    printf '_Generated %s from commits since `%s`._\n\n' "${GENERATED_ON}" "${BASE_TAG}"
    printf -- '---\n\n'
    printf '### Release Summary\n'
    printf -- '- Release codename: `Gold`\n'
    printf -- '- Compare range: `%s...%s`\n' "${BASE_TAG}" "${head_hash:0:7}"
    printf -- '- Commits reviewed: `%d`\n' "${commit_count}"
    printf -- '- Version file bumped to `%s`\n\n' "${VERSION}"

    append_section "Features" "${features[@]}"
    append_section "Security Hardening" "${security[@]}"
    append_section "UI/UX Enhancements" "${uiux[@]}"

    if [[ -s "${preserved_history_file}" ]]; then
      printf -- '---\n\n'
      cat "${preserved_history_file}"
      printf '\n'
    fi
  } > "${output_file}"

  mv "${output_file}" "${CHANGELOG_FILE}"
}

main() {
  require_repo
  parse_commits

  if [[ "${commit_count}" -eq 0 ]]; then
    echo "error: no commits found between ${BASE_TAG} and HEAD" >&2
    exit 1
  fi

  printf '%s\n' "${VERSION}" > "${VERSION_FILE}"
  write_changelog

  echo "Updated ${VERSION_FILE} -> ${VERSION}"
  echo "Generated ${CHANGELOG_FILE} from ${BASE_TAG}..HEAD (${commit_count} commits)"
}

main "$@"
