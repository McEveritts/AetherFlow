#!/usr/bin/env bash
# Install pinned Linux WASM tools. --ensure preserves matching versions on PATH.
set -euo pipefail

usage() {
    echo "usage: $0 [TOOL_DIR | --bin-dir DIR] [--ensure] [--with-rust]"
}

ensure=0
with_rust=0
tool_root="${WASM_TOOL_DIR:-}"
tool_bin=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ensure) ensure=1; with_rust=1; shift ;;
        --with-rust) with_rust=1; shift ;;
        --bin-dir)
            if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
                usage >&2
                exit 2
            fi
            tool_bin="$2"
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        -*) usage >&2; exit 2 ;;
        *)
            if [[ -n "${positional_root:-}" ]]; then
                usage >&2
                exit 2
            fi
            positional_root="$1"
            tool_root="$1"
            shift
            ;;
    esac
done

if [[ "$(uname -s)" != Linux ]]; then
    echo "[ERROR] Pinned WASM tool downloads require Linux." >&2
    exit 1
fi
case "$(uname -m)" in
    x86_64)
        rustup_target=x86_64-unknown-linux-gnu
        trunk_target=x86_64-unknown-linux-musl
        bindgen_target=x86_64-unknown-linux-musl
        binaryen_arch=x86_64-linux
        tailwind_asset=tailwindcss-linux-x64
        rustup_sha256=a3339fb004c3d0bb9862ba0bce001861fe5cbde9c10d16591eb3f39ee6cd3e7f
        trunk_sha256=a1fe5cd6b053f5a76f66b598d296022a7f06f56def6013cc16cd6897d53f5363
        bindgen_sha256=9687f3bb551b9f66f37ed32a40d7913a00f7962db653054e56857bc306c3227f
        binaryen_sha256=2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489
        tailwind_sha256=e47695cee3f0d90623a91f3939b08bdee610eb5ad99340adff9d4145b284d6cc
        ;;
    aarch64|arm64)
        rustup_target=aarch64-unknown-linux-gnu
        trunk_target=aarch64-unknown-linux-gnu
        bindgen_target=aarch64-unknown-linux-gnu
        binaryen_arch=aarch64-linux
        tailwind_asset=tailwindcss-linux-arm64
        rustup_sha256=c64b33db2c6b9385817ec0e49a84bcfe018ed6e328fe755c3c809580cc70ce7a
        trunk_sha256=b4017d1e0bfcffb4f4bee2be37c48def21e6e6896c3d0f503c43c42f714e57ea
        bindgen_sha256=cc8dd8e90aa9111758168d30c63a14b7f0276997d9d60d3e160a1fb5e7d3b919
        binaryen_sha256=89c07ea56faf38d0fbecf36ca8ec0721756716185f265b568e133d427f299bf8
        tailwind_sha256=ffcd0d21dbd7c605dc12743ff0c0b47debc963c86b399674084c1c8f2c96ecad
        ;;
    *) echo "[ERROR] Pinned WASM tool downloads require Linux x86_64 or aarch64/arm64." >&2; exit 1 ;;
esac

if [[ -n "${tool_bin}" ]]; then
    tool_bin="${tool_bin%/}"
    tool_root="$(dirname -- "${tool_bin}")"
else
    if [[ -z "${tool_root}" ]]; then
        if [[ "${ensure}" == 1 ]]; then
            if [[ -d /usr/local/lib/aetherflow-wasm-tools/bin || -w /usr/local/lib ]]; then
                tool_root="/usr/local/lib/aetherflow-wasm-tools"
            else
                tool_root="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/aetherflow-wasm-tools"
            fi
        else
            tool_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/aetherflow-wasm-tools"
        fi
    fi
    tool_bin="${tool_root}/bin"
fi
mkdir -p "${tool_bin}"
tool_bin="$(cd "${tool_bin}" && pwd)"
tool_root="$(cd "${tool_root}" && pwd)"
export PATH="${tool_bin}:${HOME:-/root}/.cargo/bin:${PATH}"

download_dir="$(mktemp -d "${TMPDIR:-/tmp}/af-wasm-tools.XXXXXX")"
trap 'rm -rf -- "${download_dir}"' EXIT

needs_tool() {
    [[ "${ensure}" == 1 ]] || return 0
    command -v "$1" >/dev/null 2>&1 || return 0
    local expected version
    case "$1" in
        trunk) expected=0.22.1 ;;
        wasm-bindgen) expected=0.2.130 ;;
        wasm-opt) expected=133 ;;
        tailwindcss) expected=v4.3.5 ;;
        *) return 0 ;;
    esac
    version="$("$1" --version 2>&1)" || return 0
    version="$(printf '%s\n' "${version}" | awk -v tool="$1" '
        {
            for (i = 1; i < NF; i++) {
                if ($i == tool) {
                    if (tool == "wasm-opt" && $(i + 1) == "version") {
                        print $(i + 2)
                    } else {
                        print $(i + 1)
                    }
                    exit
                }
            }
        }
    ')"
    [[ "${version}" != "${expected}" ]]
}

download_verified() {
    local url="$1" expected_sha256="$2" destination="$3"
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --retry 3 --output "${destination}" "${url}"
    printf '%s  %s\n' "${expected_sha256}" "${destination}" | sha256sum --check --strict
}

if [[ "${with_rust}" == 1 ]]; then
    requested_toolchain="${RUSTUP_TOOLCHAIN:-}"
    if ! command -v cargo >/dev/null 2>&1 || ! command -v rustup >/dev/null 2>&1; then
        # Official rustup 1.28.1 GNU archive, pinned for the selected CPU.
        download_verified \
            "https://static.rust-lang.org/rustup/archive/1.28.1/${rustup_target}/rustup-init" \
            "${rustup_sha256}" \
            "${download_dir}/rustup-init"
        chmod +x "${download_dir}/rustup-init"
        "${download_dir}/rustup-init" -y --profile minimal --default-toolchain "${requested_toolchain:-stable}"
    elif [[ -n "${requested_toolchain}" ]] && ! rustup run "${requested_toolchain}" rustc --version >/dev/null 2>&1; then
        rustup toolchain install "${requested_toolchain}" --profile minimal
    fi
    if ! rustup target list --installed | grep -Fxq wasm32-unknown-unknown; then
        rustup target add wasm32-unknown-unknown
    fi
fi

if needs_tool trunk; then
    download_verified \
        "https://github.com/trunk-rs/trunk/releases/download/v0.22.1/trunk-${trunk_target}.tar.gz" \
        "${trunk_sha256}" \
        "${download_dir}/trunk.tar.gz"
    mkdir -p "${download_dir}/trunk"
    tar -xzf "${download_dir}/trunk.tar.gz" -C "${download_dir}/trunk" trunk
    install -m 755 "${download_dir}/trunk/trunk" "${tool_bin}/trunk"
fi

if needs_tool wasm-bindgen; then
    download_verified \
        "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/0.2.130/wasm-bindgen-0.2.130-${bindgen_target}.tar.gz" \
        "${bindgen_sha256}" \
        "${download_dir}/bindgen.tar.gz"
    tar -xzf "${download_dir}/bindgen.tar.gz" -C "${download_dir}"
    install -m 755 "${download_dir}/wasm-bindgen-0.2.130-${bindgen_target}/wasm-bindgen" \
        "${tool_bin}/wasm-bindgen"
fi

if needs_tool wasm-opt; then
    download_verified \
        "https://github.com/WebAssembly/binaryen/releases/download/version_133/binaryen-version_133-${binaryen_arch}.tar.gz" \
        "${binaryen_sha256}" \
        "${download_dir}/binaryen.tar.gz"
    tar -xzf "${download_dir}/binaryen.tar.gz" -C "${download_dir}"
    # wasm-opt resolves libbinaryen.so relative to its bin/../lib directory.
    mkdir -p "${tool_root}/lib"
    cp -a "${download_dir}/binaryen-version_133/lib/." "${tool_root}/lib/"
    cp -a "${download_dir}/binaryen-version_133/bin/." "${tool_bin}/"
fi

if needs_tool tailwindcss; then
    download_verified \
        "https://github.com/tailwindlabs/tailwindcss/releases/download/v4.3.5/${tailwind_asset}" \
        "${tailwind_sha256}" \
        "${download_dir}/tailwindcss"
    install -m 755 "${download_dir}/tailwindcss" "${tool_bin}/tailwindcss"
fi

echo "WASM tools available; prepend ${tool_bin} to PATH."
