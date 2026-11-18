#!/usr/bin/env python3
"""Compare two fresh WASM builds; retain all inputs, targets, logs and outputs.

Linux/Python 3.10+ example (reuse this canonical path for later runs):
  python3 scripts/verify_wasm_reproducibility.py \
    --canonical-path "$HOME/.cache/af-repro/workspace" --output "$HOME/.cache/af-repro/run-001"

The output directory must not exist and must be outside the source checkout.
Install the toolchain in rust-toolchain.toml, the pinned WASM tools from
scripts/install_wasm_build_tools.sh, and populate Cargo's cache first. The
registry and git caches are copied into a private Cargo home, then checked for
changes between builds. Global Cargo configuration is not copied; ancestor
Cargo configuration outside the snapshot is rejected. Builds run offline with
at most two Cargo jobs, no wrappers and a fixed locale/time. The canonical path
and its .cargo-home sibling must not exist and must share a filesystem with the
output. Evidence requires space for the source, cache, and both clean targets.

By default, fresh source copies and fresh target directories are built in
sequence at one canonical path. Separate paths change Cargo's identity for the
external af-models path dependency and have produced different raw app WASM
despite --remap-path-prefix; the exact compiler ordering mechanism is unproven.
Each completed workspace is moved aside before the next is created; no build
products are reused. The absolute canonical path, isolated Cargo home path,
host tools and libraries are part of the environment, so equality is not a
claim of cross-path or cross-host equality. Use the same --canonical-path across
verification runs. Use --independent-paths to test the stronger property.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PINNED_TOOLS = {
    "trunk": r"\btrunk 0\.22\.1(?:\s|$)",
    "wasm-bindgen": r"\bwasm-bindgen 0\.2\.130(?:\s|$)",
    "wasm-opt": r"\bwasm-opt version 133(?:\s|$)",
    "tailwindcss": r"\btailwindcss v4\.3\.5(?:\s|$)",
}
STAGES = {
    "raw_app": "target/wasm32-unknown-unknown/release/af-web-app.wasm",
    "raw_worker": "target/wasm32-unknown-unknown/release/af-web-worker.wasm",
    "bindgen_app": "target/wasm-bindgen/release/af-web-app_bg.wasm",
    "optimized_app": "target/wasm-opt/release/af-web-app_bg.wasm",
}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        return {"type": "symlink", "target": os.readlink(path)}
    if stat.S_ISREG(info.st_mode):
        return {"type": "file", "mode": stat.S_IMODE(info.st_mode),
                "size": info.st_size, "sha256": sha256(path)}
    if stat.S_ISDIR(info.st_mode):
        return {"type": "directory", "mode": stat.S_IMODE(info.st_mode)}
    raise ValueError("unsupported input or artifact type: {}".format(path))


def tracked_names(root):
    output = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
    )
    return sorted(set(os.fsdecode(item) for item in output.split(b"\0") if item))


def snapshot_source(root, destination):
    names = tracked_names(root)
    manifest = {}
    destination.mkdir()
    for name in names:
        source = root / name
        if not source.exists() and not source.is_symlink():
            continue
        record = file_record(source)
        if record["type"] == "directory":
            raise ValueError("git submodules are not supported by the snapshot: {}".format(name))
        if record["type"] == "symlink":
            target = Path(record["target"])
            if target.is_absolute() or not (source.parent / target).resolve().is_relative_to(root):
                raise ValueError("source symlink points outside the checkout: {}".format(name))
        manifest[name] = record
        copy = destination / name
        copy.parent.mkdir(parents=True, exist_ok=True)
        if record["type"] == "symlink":
            copy.symlink_to(record["target"])
        else:
            shutil.copy2(source, copy)
        if file_record(copy) != record:
            raise RuntimeError("source changed while being copied: {}".format(name))
    after = {}
    for name in tracked_names(root):
        source = root / name
        if source.exists() or source.is_symlink():
            after[name] = file_record(source)
    if manifest != after:
        raise RuntimeError("source file set or contents changed during snapshot")
    return manifest


def tree_manifest(root):
    if not root.is_dir():
        raise ValueError("missing distribution directory: {}".format(root))
    result = {}
    for path in sorted(root.rglob("*")):
        result[path.relative_to(root).as_posix()] = file_record(path)
    return result


def different_names(first, second):
    return sorted(name for name in set(first) | set(second) if first.get(name) != second.get(name))


def cache_manifest(home):
    manifest = {}
    for name in ("registry", "git"):
        root = home / name
        if root.exists():
            if not root.is_dir() or root.is_symlink():
                raise ValueError("Cargo cache root must be a directory: {}".format(root))
            for relative, record in tree_manifest(root).items():
                path = root / relative
                if record["type"] == "symlink" and not path.resolve().is_relative_to(root.resolve()):
                    raise ValueError("Cargo cache symlink points outside its cache: {}".format(path))
                manifest[name + "/" + relative] = record
    return manifest


def snapshot_cargo_home(source, destination):
    source = source.resolve()
    if destination.resolve().is_relative_to(source):
        raise ValueError("Cargo snapshot must be outside the original Cargo home")
    if not source.is_dir():
        raise ValueError("Cargo home does not exist: {}".format(source))
    if not destination.is_dir() or any(destination.iterdir()):
        raise ValueError("Cargo snapshot destination must be an empty directory: {}".format(destination))
    for name in ("registry", "git"):
        cache = source / name
        if cache.exists() or cache.is_symlink():
            if not cache.is_dir() or cache.is_symlink():
                raise ValueError("Cargo cache root must be a directory: {}".format(cache))
            shutil.copytree(cache, destination / name, symlinks=True)
    original = cache_manifest(source)
    copied = cache_manifest(destination)
    if original != copied:
        raise RuntimeError("Cargo cache changed while being copied")
    return copied


def check_ancestor_configs(path):
    for parent in path.parents:
        for name in ("config", "config.toml"):
            config = parent / ".cargo" / name
            if config.exists():
                raise ValueError("external ancestor Cargo configuration is unsupported: {}".format(config))


def prepare_dependencies(snapshot, env, output):
    metadata_path = output / "cargo-metadata.json"
    log_path = output / "cargo-metadata.log"
    with metadata_path.open("w", encoding="utf-8") as metadata, log_path.open("w", encoding="utf-8") as log:
        completed = subprocess.run(["cargo", "metadata", "--locked", "--offline", "--format-version=1",
                                    "--manifest-path", str(snapshot / "frontend-rs/Cargo.toml")],
                                   env=env, stdout=metadata, stderr=log)
    if completed.returncode:
        raise RuntimeError("offline Cargo metadata failed; see {}".format(log_path))
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    cargo_home = Path(env["CARGO_HOME"]).resolve()
    for package in metadata["packages"]:
        manifest = Path(package["manifest_path"]).resolve()
        if not (manifest.is_relative_to(snapshot.resolve()) or manifest.is_relative_to(cargo_home)):
            raise ValueError("dependency is outside the source and Cargo snapshots: {}".format(manifest))
    manifest = cache_manifest(cargo_home)
    manifest_path = output / "cargo-cache-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest, {"packages": len(metadata["packages"]), "metadata_sha256": sha256(metadata_path),
                      "cache_entries": len(manifest), "manifest_sha256": sha256(manifest_path)}


def check_cache(home, expected):
    changed = different_names(expected, cache_manifest(home))
    if changed:
        raise RuntimeError("isolated Cargo cache changed during build: " + ", ".join(changed[:10]))


def read_u32(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(data):
            raise ValueError("truncated WASM section")
        byte = data[offset]
        offset += 1
        if shift == 28 and byte & 0xf0:
            raise ValueError("invalid WASM section size")
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, offset
    raise ValueError("invalid WASM section size")


def wasm_sections(path):
    data = path.read_bytes()
    if data[:8] != b"\0asm\x01\0\0\0":
        raise ValueError("invalid WASM header: {}".format(path))
    result = []
    offset = 8
    while offset < len(data):
        section_id = data[offset]
        size, payload = read_u32(data, offset + 1)
        end = payload + size
        if end > len(data):
            raise ValueError("truncated WASM section: {}".format(path))
        result.append({"id": section_id, "size": size,
                       "sha256": hashlib.sha256(data[payload:end]).hexdigest()})
        offset = end
    return result


def command_output(command, env=None, cwd=None):
    return subprocess.check_output(command, env=env, cwd=cwd, stderr=subprocess.STDOUT,
                                   text=True).strip()


def tool_environment():
    home = os.environ.get("HOME", str(Path.home()))
    cache = os.environ.get("XDG_CACHE_HOME", str(Path(home) / ".cache"))
    tool_root = os.environ.get("WASM_TOOL_DIR", "/usr/local/lib/aetherflow-wasm-tools")
    tool_path = os.pathsep.join((str(Path(tool_root) / "bin"),
                                 str(Path(cache) / "aetherflow-wasm-tools/bin"),
                                 str(Path(home) / ".cargo/bin"), os.environ.get("PATH", "")))
    env = {"HOME": home, "PATH": tool_path, "TZ": "UTC", "LC_ALL": "C.UTF-8",
           "PYTHONUTF8": "1", "WASM_TOOL_DIR": tool_root, "XDG_CACHE_HOME": cache,
           "CARGO_HOME": os.environ.get("CARGO_HOME", str(Path(home) / ".cargo")),
           "RUSTUP_HOME": os.environ.get("RUSTUP_HOME", str(Path(home) / ".rustup")),
           "CARGO_NET_OFFLINE": "true", "TRUNK_OFFLINE": "true",
           "CARGO_BUILD_JOBS": "2", "CARGO_INCREMENTAL": "0",
           "CARGO_TERM_COLOR": "never", "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": ""}
    return env


def collect_tools(snapshot, env, output):
    text = (snapshot / "rust-toolchain.toml").read_text(encoding="utf-8")
    match = re.search(r'^\s*channel\s*=\s*"(\d+\.\d+\.\d+)"\s*$', text, re.MULTILINE)
    if not match:
        raise ValueError("rust-toolchain.toml must pin a numeric compiler version")
    compiler = match.group(1)
    env["RUSTUP_TOOLCHAIN"] = compiler
    rustc_version = command_output(["rustc", "--version", "--verbose"], env=env)
    if not rustc_version.startswith("rustc " + compiler + " "):
        raise ValueError("rustc does not match the pinned toolchain: " + rustc_version)
    targets = command_output(["rustup", "target", "list", "--installed", "--toolchain", compiler], env=env)
    if "wasm32-unknown-unknown" not in targets.splitlines():
        raise ValueError("the pinned Rust toolchain lacks wasm32-unknown-unknown")
    sysroot = Path(command_output(["rustc", "--print", "sysroot"], env=env)).resolve()
    env["RUSTC"] = str(sysroot / "bin/rustc")
    toolchain = tree_manifest(sysroot)
    toolchain_manifest = output / "toolchain-manifest.json"
    toolchain_manifest.write_text(json.dumps(toolchain, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tools = {}
    for name, pattern in PINNED_TOOLS.items():
        executable = shutil.which(name, path=env["PATH"])
        if not executable:
            raise ValueError("missing pinned tool: {}".format(name))
        version = command_output([executable, "--version"], env=env)
        if not re.search(pattern, version):
            raise ValueError("incorrect {} version: {}".format(name, version))
        realpath = Path(executable).resolve(strict=True)
        tools[name] = {"path": str(realpath), "version": version, "sha256": sha256(realpath)}
    for name in ("cc", "ld", "bash", "python3", "find"):
        executable = shutil.which(name, path=env["PATH"])
        if not executable:
            raise ValueError("missing host build tool: {}".format(name))
        realpath = Path(executable).resolve(strict=True)
        tools[name] = {"path": str(realpath), "version": command_output([executable, "--version"], env=env).splitlines()[0],
                       "sha256": sha256(realpath)}
    try:
        wasm_opt_libraries = command_output(["ldd", tools["wasm-opt"]["path"]], env=env)
    except subprocess.CalledProcessError as error:
        if "statically linked" not in error.output and "not a dynamic executable" not in error.output:
            raise
        wasm_opt_libraries = error.output.strip()
    return {"compiler": compiler, "rustc_verbose": rustc_version,
            "cargo_version": command_output(["cargo", "--version"], env=env),
            "sysroot": str(sysroot), "toolchain_manifest_sha256": sha256(toolchain_manifest),
            "tools": tools,
            "wasm_opt_dynamic_libraries": wasm_opt_libraries}


def build(snapshot, output, label, env, independent_paths, canonical_path=None):
    workspace = output / label if independent_paths else (canonical_path or output / "canonical-workspace")
    destination = output / label
    shutil.copytree(snapshot, workspace, symlinks=True)
    build_env = dict(env)
    build_env.update({"CARGO_TARGET_DIR": str(workspace / "target"),
                      "CARGO_ENCODED_RUSTFLAGS": "--remap-path-prefix={}=/aetherflow".format(workspace),
                      "FRONTEND_DIST_DIR": str(workspace / "web/dist"),
                      "TMPDIR": str(workspace / "tmp")})
    (workspace / "tmp").mkdir()
    log_path = output / (label + ".log")
    print("Building {} in {}".format(label, workspace), flush=True)
    with log_path.open("wb") as log:
        completed = subprocess.run(["bash", "scripts/build_wasm_frontend.sh", "--stage"], cwd=workspace,
                                   env=build_env, stdout=log, stderr=subprocess.STDOUT)
    if not independent_paths:
        workspace.rename(destination)
    if completed.returncode:
        raise RuntimeError("{} failed (exit {}); see {}".format(label, completed.returncode, log_path))
    distribution = tree_manifest(destination / "web/dist")
    if not distribution or "index.html" not in distribution or not any(
            name.endswith(".wasm") and value.get("size", 0) for name, value in distribution.items()):
        raise RuntimeError("{} produced an incomplete distribution".format(label))
    trunk_distribution = tree_manifest(destination / "frontend-rs/dist")
    if any(distribution.get(name) != record for name, record in trunk_distribution.items()):
        raise RuntimeError("{} staged distribution differs from Trunk output".format(label))
    stages = {}
    for name, relative in STAGES.items():
        artifact = destination / relative
        stages[name] = {"sha256": sha256(artifact), "size": artifact.stat().st_size,
                        "sections": wasm_sections(artifact)}
    return {"dist": distribution, "stages": stages, "build_log_sha256": sha256(log_path),
            "build_environment": {key: build_env[key] for key in
                                  ("CARGO_TARGET_DIR", "CARGO_ENCODED_RUSTFLAGS", "FRONTEND_DIST_DIR", "TMPDIR")}}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--output", required=True, type=Path, help="new evidence directory outside the checkout")
    parser.add_argument("--source-date-epoch", help="integer timestamp (default: SOURCE_DATE_EPOCH or HEAD commit time)")
    parser.add_argument("--independent-paths", action="store_true", help="test separate absolute source paths rather than the canonical-path procedure")
    parser.add_argument("--canonical-path", type=Path, help="stable, nonexistent build path to reuse across verification runs")
    args = parser.parse_args()
    root = ROOT.resolve()
    output = args.output.resolve()
    if sys.platform != "linux":
        parser.error("this verifier requires Linux")
    if output.is_relative_to(root):
        parser.error("output must be outside the source checkout")
    if args.independent_paths and args.canonical_path:
        parser.error("--canonical-path cannot be combined with --independent-paths")
    canonical = args.canonical_path.resolve() if args.canonical_path else output / "canonical-workspace"
    cargo_home = output / "cargo-home" if args.independent_paths else canonical.with_name(canonical.name + ".cargo-home")
    env = tool_environment()
    original_cargo_home = Path(env["CARGO_HOME"]).resolve()
    if output.is_relative_to(original_cargo_home) or cargo_home.is_relative_to(original_cargo_home):
        parser.error("output and isolated cache must be outside the original Cargo home")
    if not args.independent_paths:
        if canonical.is_relative_to(root) or output.is_relative_to(canonical):
            parser.error("canonical path must be outside the checkout and not contain the output directory")
        if canonical.is_relative_to(output) and canonical != output / "canonical-workspace":
            parser.error("a canonical path inside the output must be its default canonical-workspace")
        if canonical.exists() or canonical.is_symlink():
            parser.error("canonical build path must not exist")
        if cargo_home.exists() or cargo_home.is_symlink():
            parser.error("canonical Cargo home path must not exist")
    epoch = args.source_date_epoch or os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        epoch = command_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=root)
    if not re.fullmatch(r"[0-9]+", epoch):
        parser.error("SOURCE_DATE_EPOCH must be a non-negative integer")
    output.mkdir(parents=True, exist_ok=False)
    report = {"equal": False, "source_date_epoch": epoch, "platform": platform.platform(),
              "layout": "independent-paths" if args.independent_paths else "canonical-path",
              "assumptions": ["Linux, same host, toolchain, host libraries and shell tools",
                              "offline isolated Cargo registry and git cache; global Cargo config ignored",
                              "repository configuration and build scripts do not read unrecorded external inputs",
                              "fresh source and target for each build", "fixed absolute build and Cargo home paths in canonical mode",
                              "at most two Cargo jobs per build"]}
    cargo_home_created = False
    try:
        if not args.independent_paths:
            canonical.parent.mkdir(parents=True, exist_ok=True)
            if canonical.parent.stat().st_dev != output.stat().st_dev:
                raise ValueError("canonical path and output must be on the same filesystem")
            report["canonical_path"] = str(canonical)
        check_ancestor_configs(output / "input")
        check_ancestor_configs(canonical if not args.independent_paths else output / "build-a")
        source_manifest = snapshot_source(root, output / "input")
        manifest_path = output / "source-manifest.json"
        manifest_path.write_text(json.dumps(source_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        report["source"] = {"files": len(source_manifest), "manifest_sha256": sha256(manifest_path)}
        env["SOURCE_DATE_EPOCH"] = epoch
        report["original_cargo_home"] = str(original_cargo_home)
        print("Snapshotting Cargo registry and git caches", flush=True)
        cargo_home.mkdir()
        cargo_home_created = True
        snapshot_cargo_home(original_cargo_home, cargo_home)
        env["CARGO_HOME"] = str(cargo_home)
        report["cargo_home_build_path"] = str(cargo_home)
        report["tools"] = collect_tools(output / "input", env, output)
        cache, report["dependencies"] = prepare_dependencies(output / "input", env, output)
        report["environment"] = {key: env[key] for key in sorted(env) if key not in {"PATH"}}
        report["environment"]["PATH"] = env["PATH"]
        first = build(output / "input", output, "build-a", env, args.independent_paths, canonical)
        check_cache(cargo_home, cache)
        report["build_a"] = first
        second = build(output / "input", output, "build-b", env, args.independent_paths, canonical)
        check_cache(cargo_home, cache)
        report["build_b"] = second
        report["different_files"] = different_names(first["dist"], second["dist"])
        report["equal"] = not report["different_files"]
        for name, tool in report["tools"]["tools"].items():
            if sha256(Path(tool["path"])) != tool["sha256"]:
                raise RuntimeError("tool changed during builds: " + name)
        toolchain_manifest = output / "toolchain-manifest.json"
        current_toolchain = tree_manifest(Path(report["tools"]["sysroot"]))
        if current_toolchain != json.loads(toolchain_manifest.read_text(encoding="utf-8")):
            raise RuntimeError("Rust toolchain changed during builds")
        check_ancestor_configs(output / "input")
        check_ancestor_configs(canonical if not args.independent_paths else output / "build-a")
        print("Complete distribution trees equal: {}".format(report["equal"]), flush=True)
        if report["different_files"]:
            print("Differing paths: " + ", ".join(report["different_files"]), flush=True)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        report["error"] = str(error)
        report["equal"] = False
        print("error: {}".format(error), file=sys.stderr, flush=True)
    finally:
        if cargo_home_created and cargo_home != output / "cargo-home":
            try:
                cargo_home.rename(output / "cargo-home")
            except OSError as error:
                report["error"] = "could not retain Cargo home: {}".format(error)
                report["equal"] = False
    (output / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Evidence: {}".format(output), flush=True)
    return 0 if report["equal"] else 1


if __name__ == "__main__":
    sys.exit(main())
