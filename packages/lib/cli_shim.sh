#!/usr/bin/env bash
# Shared native `af` CLI discovery & recursion guard for legacy packages/system/* shims.
# Sourced by packages/system/{af-backup,af-tune,clean_log,showspace}.

af_shim_is_legacy_wrapper() {
  local cand_real legacy_path legacy_real
  local self_real="$1"
  local script_dir="$2"
  local candidate="$3"
  cand_real="$(readlink -f "$candidate" 2>/dev/null || printf '%s' "$candidate")"
  [[ "$cand_real" == "$self_real" ]] && return 0
  for legacy_path in \
    /opt/AetherFlow/packages/system/af \
    /opt/AetherFlow/current/packages/system/af \
    /usr/local/bin/AetherFlow/system/af \
    "${script_dir}/af"; do
    legacy_real="$(readlink -f "$legacy_path" 2>/dev/null || printf '%s' "$legacy_path")"
    [[ "$cand_real" == "$legacy_real" ]] && return 0
  done
  return 1
}

af_shim_is_native_cli() {
  local self_real="$1"
  local script_dir="$2"
  local bin="$3"
  [[ -n "$bin" && -x "$bin" ]] || return 1
  af_shim_is_legacy_wrapper "$self_real" "$script_dir" "$bin" && return 1
  if [[ "$bin" == "${AETHERFLOW_CLI_BIN:-}" ]]; then
    return 0
  fi
  if [[ "$(LC_ALL=C head -c 4 "$bin" 2>/dev/null | od -An -tx1 | tr -d ' \n')" == "7f454c46" ]]; then
    return 0
  fi
  "$bin" --version >/dev/null 2>&1
}

af_exec_native_cli() {
  local subcommand="$1"
  shift
  local self_real script_dir af_bin
  self_real="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
  script_dir="${SCRIPT_DIR:-$(cd "$(dirname "${self_real}")" && pwd)}"

  for af_bin in \
    "${AETHERFLOW_CLI_BIN:-}" \
    /opt/AetherFlow/current/bin/af \
    /opt/AetherFlow/current/af \
    /usr/local/bin/af-cli \
    /opt/AetherFlow/bin/af-cli \
    /usr/local/bin/af; do
    if af_shim_is_native_cli "$self_real" "$script_dir" "$af_bin"; then
      exec "$af_bin" "$subcommand" "$@"
    fi
  done

  printf 'Native AetherFlow CLI binary (/usr/local/bin/af) not found.\n' >&2
  exit 1
}
