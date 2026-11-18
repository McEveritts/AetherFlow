import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("wasm_repro", ROOT / "scripts/verify_wasm_reproducibility.py")
REPRO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPRO)


@unittest.skipUnless(os.name == "posix" and shutil.which("git"), "requires POSIX and git")
class WasmReproducibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="af-repro-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_snapshot_records_untracked_inputs_and_ignores_host_caches(self):
        source = self.root / "source"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        (source / ".gitignore").write_text("ignored/\n")
        (source / "file").write_bytes(b"input")
        (source / "file").chmod(0o751)
        (source / "alias").symlink_to("file")
        (source / "ignored").mkdir()
        (source / "ignored/cache").write_text("not an input")
        manifest = REPRO.snapshot_source(source, self.root / "snapshot")
        self.assertEqual(set(manifest), {".gitignore", "file", "alias"})
        self.assertEqual(manifest["file"]["mode"], 0o751)
        self.assertEqual(manifest["alias"], {"type": "symlink", "target": "file"})
        (source / "file").write_bytes(b"changed")
        self.assertEqual((self.root / "snapshot/file").read_bytes(), b"input")

    def test_snapshot_rejects_symlinks_outside_checkout(self):
        source = self.root / "source"
        source.mkdir()
        subprocess.run(["git", "init", "-q", str(source)], check=True)
        (source / "outside").symlink_to(self.root / "other")
        with self.assertRaisesRegex(ValueError, "outside the checkout"):
            REPRO.snapshot_source(source, self.root / "snapshot")

    def test_cargo_cache_snapshot_is_isolated_and_monitored(self):
        source = self.root / "cargo-source"
        (source / "registry/src/example").mkdir(parents=True)
        (source / "registry/src/example/lib.rs").write_text("original")
        (source / "config.toml").write_text("not copied")
        destination = self.root / "cargo-snapshot"
        destination.mkdir()
        manifest = REPRO.snapshot_cargo_home(source, destination)
        self.assertFalse((destination / "config.toml").exists())
        (source / "registry/src/example/lib.rs").write_text("changed")
        self.assertEqual((destination / "registry/src/example/lib.rs").read_text(), "original")
        REPRO.check_cache(destination, manifest)
        (destination / "registry/src/example/lib.rs").write_text("tampered")
        with self.assertRaisesRegex(RuntimeError, "cache changed"):
            REPRO.check_cache(destination, manifest)
        nested = source / "registry/nested"
        nested.mkdir()
        with self.assertRaisesRegex(ValueError, "outside the original Cargo home"):
            REPRO.snapshot_cargo_home(source, nested)

    def test_cargo_cache_rejects_external_symlinks_and_ancestor_configs(self):
        source = self.root / "cargo-source"
        (source / "registry").mkdir(parents=True)
        (source / "registry/outside").symlink_to(self.root / "elsewhere")
        destination = self.root / "cargo-snapshot"
        destination.mkdir()
        with self.assertRaisesRegex(ValueError, "outside its cache"):
            REPRO.snapshot_cargo_home(source, destination)
        (self.root / ".cargo").mkdir()
        (self.root / ".cargo/config.toml").write_text("[build]\n")
        with self.assertRaisesRegex(ValueError, "ancestor Cargo configuration"):
            REPRO.check_ancestor_configs(self.root / "workspace")

    def test_build_environment_is_offline_and_bounded(self):
        env = REPRO.tool_environment()
        self.assertEqual(env["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(env["TRUNK_OFFLINE"], "true")
        self.assertEqual(env["CARGO_BUILD_JOBS"], "2")
        self.assertEqual(env["RUSTC_WRAPPER"], "")
        self.assertEqual(env["RUSTC_WORKSPACE_WRAPPER"], "")

    def test_tree_comparison_includes_sidecars_names_bytes_and_modes(self):
        first, second = self.root / "first", self.root / "second"
        first.mkdir()
        second.mkdir()
        for folder in (first, second):
            (folder / "app.wasm").write_bytes(b"same")
            (folder / "app.wasm.gz").write_bytes(b"compressed")
        (second / "app.wasm.gz").write_bytes(b"different!")
        (second / "app.wasm.br").write_bytes(b"extra")
        (second / "app.wasm").chmod(0o700)
        self.assertEqual(REPRO.different_names(REPRO.tree_manifest(first), REPRO.tree_manifest(second)),
                         ["app.wasm", "app.wasm.br", "app.wasm.gz"])

    def test_wasm_section_diagnostics_cover_runtime_and_custom_bytes(self):
        path = self.root / "module.wasm"
        path.write_bytes(b"\0asm\x01\0\0\0\x01\x01x\x00\x02ab")
        sections = REPRO.wasm_sections(path)
        self.assertEqual([(section["id"], section["size"]) for section in sections], [(1, 1), (0, 2)])
        self.assertNotEqual(sections[0]["sha256"], sections[1]["sha256"])
        path.write_bytes(b"\0asm\x01\0\0\0\x0a\x03x")
        with self.assertRaisesRegex(ValueError, "truncated"):
            REPRO.wasm_sections(path)

    def test_canonical_builds_use_fresh_sources_and_targets(self):
        snapshot = self.root / "snapshot"
        output = self.root / "output"
        (snapshot / "scripts").mkdir(parents=True)
        output.mkdir()
        (snapshot / "scripts/build_wasm_frontend.sh").write_text(r'''#!/bin/bash
set -eu
test "$1" = --stage
test ! -e "$CARGO_TARGET_DIR"
mkdir -p frontend-rs/dist target/wasm32-unknown-unknown/release target/wasm-bindgen/release target/wasm-opt/release
printf index > frontend-rs/dist/index.html
printf '\000asm\001\000\000\000' > frontend-rs/dist/app.wasm
printf sidecar > frontend-rs/dist/app.wasm.gz
for artifact in target/wasm32-unknown-unknown/release/af-web-app.wasm target/wasm32-unknown-unknown/release/af-web-worker.wasm target/wasm-bindgen/release/af-web-app_bg.wasm target/wasm-opt/release/af-web-app_bg.wasm; do
    cp frontend-rs/dist/app.wasm "$artifact"
done
mkdir -p "$FRONTEND_DIST_DIR"
cp -a frontend-rs/dist/. "$FRONTEND_DIST_DIR/"
printf placeholder > "$FRONTEND_DIST_DIR/.keep"
if [ "${DROP_STAGE_SIDECAR:-0}" = 1 ]; then rm "$FRONTEND_DIST_DIR/app.wasm.gz"; fi
''')
        env = {"PATH": os.environ["PATH"]}
        first = REPRO.build(snapshot, output, "build-a", env, False)
        second = REPRO.build(snapshot, output, "build-b", env, False)
        self.assertEqual(first["dist"], second["dist"])
        self.assertEqual(first["build_environment"], second["build_environment"])
        self.assertEqual(first["build_environment"], {
            "CARGO_TARGET_DIR": str(output / "canonical-workspace/target"),
            "CARGO_ENCODED_RUSTFLAGS": "--remap-path-prefix={}=/aetherflow".format(output / "canonical-workspace"),
            "FRONTEND_DIST_DIR": str(output / "canonical-workspace/web/dist"),
            "TMPDIR": str(output / "canonical-workspace/tmp"),
        })
        self.assertIn(".keep", first["dist"])
        self.assertTrue((output / "build-a/target").is_dir())
        self.assertTrue((output / "build-b/target").is_dir())
        self.assertNotEqual((output / "build-a/target").stat().st_ino, (output / "build-b/target").stat().st_ino)
        self.assertFalse((output / "canonical-workspace").exists())
        with self.assertRaisesRegex(RuntimeError, "staged distribution differs"):
            REPRO.build(snapshot, output, "build-c", {**env, "DROP_STAGE_SIDECAR": "1"}, False)


if __name__ == "__main__":
    unittest.main()
