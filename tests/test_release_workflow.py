import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"


def step_script(name):
    workflow = WORKFLOW.read_text()
    step = re.search(
        rf"^      - name: {re.escape(name)}\n(.*?)(?=^      - name: |^  [\w-]+:|\Z)",
        workflow,
        re.MULTILINE | re.DOTALL,
    )
    if step is None or "        run: |\n" not in step.group(1):
        raise AssertionError(f"Missing shell step: {name}")
    return textwrap.dedent(step.group(1).split("        run: |\n", 1)[1]).strip()


class RustCacheWorkflowTests(unittest.TestCase):
    def test_rust_jobs_cache_downloads_without_compiled_artifacts(self):
        jobs = {
            "ci.yml": ["backend-rs", "frontend-rs"],
            "release.yml": ["security-gate", "release-build"],
            "security.yml": ["rust-security"],
        }
        for filename, job_names in jobs.items():
            workflow = (WORKFLOW.parent / filename).read_text()
            for job_name in job_names:
                with self.subTest(workflow=filename, job=job_name):
                    job = re.search(
                        rf"^  {re.escape(job_name)}:\n(.*?)(?=^  [\w-]+:|\Z)",
                        workflow,
                        re.MULTILINE | re.DOTALL,
                    )
                    self.assertIsNotNone(job, f"Missing Rust job: {job_name}")
                    steps = re.findall(
                        r"^      - name: [^\n]+\n(.*?)(?=^      - |\Z)",
                        job.group(1),
                        re.MULTILINE | re.DOTALL,
                    )
                    caches = [step for step in steps if "uses: Swatinem/rust-cache@" in step]
                    self.assertEqual(len(caches), 1)
                    self.assertIn("          cache-targets: \"false\"\n", caches[0])
                    if job_name in {"backend-rs", "frontend-rs"}:
                        self.assertIn(f'          workspaces: "{job_name} -> target"\n', caches[0])
                    else:
                        self.assertIn(
                            "          workspaces: |\n"
                            "            backend-rs -> target\n"
                            "            frontend-rs -> target\n",
                            caches[0],
                        )


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / ".version").write_text("v4.0.0\n")
        (self.root / "CHANGELOG.md").write_text(
            "## Nightly Patch Notes — November 10, 2026 — Open Canvas UI\n\n"
            "### Interface\n\n* Responsive workspace and audit ledgers.\n\n"
            "---\n\n## Previous release\n\nOlder notes must not be published.\n"
        )
        self.env_file = self.root / "github-env"
        self.env_file.touch()
        self.commands = self.root / "gh-commands.json"
        self.notes = self.root / "published-notes.md"
        (self.root / "release-dist").mkdir()
        self.attest_bundle = self.root / "attest.sigstore.json"
        self.attest_bundle.write_text('{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3"}\n')
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['TEST_GH_COMMANDS']).write_text(json.dumps(sys.argv[1:]))\n"
            "if '--notes-file' in sys.argv:\n"
            "    notes_file = pathlib.Path(sys.argv[sys.argv.index('--notes-file') + 1])\n"
            "    pathlib.Path(os.environ['TEST_RELEASE_NOTES']).write_text(notes_file.read_text())\n"
        )
        gh.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
            "GITHUB_ENV": str(self.env_file),
            "GITHUB_REF": "refs/heads/nightly",
            "GITHUB_REF_NAME": "nightly",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_NUMBER": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "REQUESTED_CHANNEL": "",
            "ATTEST_BUNDLE_PATH": str(self.attest_bundle),
            "TEST_GH_COMMANDS": str(self.commands),
            "TEST_RELEASE_NOTES": str(self.notes),
        }

    def run_step(self, name, **environment):
        return subprocess.run(
            ["bash", "-euo", "pipefail", "-c", step_script(name)],
            cwd=self.root,
            env={**self.env, **environment},
            capture_output=True,
            text=True,
        )

    def resolve(self, **environment):
        result = self.run_step("Resolve Release Identity", **environment)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return dict(line.split("=", 1) for line in self.env_file.read_text().splitlines())

    def release_archives(self, tag):
        release_dir = self.root / "release-dist"
        return [
            release_dir / "aetherflow-linux-amd64.tar.gz",
            *(release_dir / f"speedtest-backend_{tag.removeprefix('v')}_linux_{arch}.tar.gz"
              for arch in ("amd64", "arm64", "armv7")),
        ]

    def write_release_archives(self, tag):
        archives = self.release_archives(tag)
        for archive in archives:
            archive.write_bytes(archive.name.encode())
        manifest = self.root / "release-dist/SHA256SUMS"
        manifest.write_text("".join(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
            for archive in archives
        ))
        return archives, manifest

    def publish(self, tag):
        archives, _ = self.write_release_archives(tag)
        result = self.run_step("Publish to GitHub Releases", RELEASE_TAG=tag)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        command = json.loads(self.commands.read_text())
        self.assertEqual(command[:3], ["release", "create", tag])
        self.assertEqual(command[command.index("--target") + 1], self.env["GITHUB_SHA"])
        self.assertIn("release-dist/SHA256SUMS", command)
        for archive in archives:
            relative_archive = f"release-dist/{archive.name}"
            self.assertIn(relative_archive, command)
            self.assertIn(f"{relative_archive}.sigstore.json", command)
            self.assertEqual(
                archive.with_name(f"{archive.name}.sigstore.json").read_bytes(),
                self.attest_bundle.read_bytes(),
            )
        self.assertNotIn("--clobber", command)
        return command

    def test_publish_fails_closed_without_sigstore_bundle(self):
        tag = "v4.0.0-nightly.123.1"
        self.write_release_archives(tag)
        for missing in ("", str(self.root / "missing.sigstore.json")):
            with self.subTest(missing=missing):
                result = self.run_step(
                    "Publish to GitHub Releases",
                    RELEASE_TAG=tag,
                    ATTEST_BUNDLE_PATH=missing,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.commands.exists())

    def test_release_integrity_requires_the_complete_verified_asset_set(self):
        tag = "v4.0.0-nightly.123.1"
        name = "Verify Release Archive Integrity"
        self.write_release_archives(tag)
        result = self.run_step(name, RELEASE_TAG=tag)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        for problem in ("missing archive", "modified archive", "incomplete manifest"):
            with self.subTest(problem=problem):
                archives, manifest = self.write_release_archives(tag)
                if problem == "missing archive":
                    archives[-1].unlink()
                elif problem == "modified archive":
                    archives[-1].write_text("corrupt")
                else:
                    manifest.write_text("".join(manifest.read_text().splitlines(keepends=True)[:-1]))
                result = self.run_step(name, RELEASE_TAG=tag)
                self.assertNotEqual(result.returncode, 0)

    def test_publish_requires_all_standalone_speedtest_archives(self):
        tag = "v4.0.0"
        archives, _ = self.write_release_archives(tag)
        archives[-1].unlink()
        result = self.run_step("Publish to GitHub Releases", RELEASE_TAG=tag)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.commands.exists())

    def test_nightly_uses_unique_versioned_prerelease_not_base_version(self):
        identity = self.resolve()
        self.assertEqual(identity, {
            "RELEASE_TAG": "v4.0.0-nightly.123.1",
            "VERSION_STAMP": "v4.0.0-nightly.123.1",
        })
        command = self.publish(identity["RELEASE_TAG"])
        self.assertIn("--prerelease", command)
        self.assertIn("--latest=false", command)

    def test_nightly_publishes_current_patch_notes_and_build_identity(self):
        tag = self.resolve()["RELEASE_TAG"]
        command = self.publish(tag)
        self.assertIn("--notes-file", command)
        self.assertNotIn("--notes", command)
        notes = self.notes.read_text()
        self.assertIn("Open Canvas UI", notes)
        self.assertIn("Responsive workspace and audit ledgers.", notes)
        self.assertIn(self.env["GITHUB_SHA"], notes)
        self.assertIn(tag, notes)
        self.assertNotIn("Older notes must not be published.", notes)
        self.assertFalse(Path(command[command.index("--notes-file") + 1]).exists())

    def test_prerelease_refuses_missing_or_unrelated_patch_notes(self):
        tag = "v4.0.0-nightly.123.1"
        self.write_release_archives(tag)
        for content in (None, "", "## CHANGELOG v4.0.0\n\nHistorical notes.\n"):
            with self.subTest(content=content):
                changelog = self.root / "CHANGELOG.md"
                if content is None:
                    changelog.unlink(missing_ok=True)
                else:
                    changelog.write_text(content)
                result = self.run_step("Publish to GitHub Releases", RELEASE_TAG=tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.commands.exists())

    def test_patch_notes_are_literal_text_not_shell_commands(self):
        (self.root / "CHANGELOG.md").write_text(
            "## Nightly Patch Notes — Open Canvas UI\n\n"
            "Keep `$(touch notes-executed)` as literal documentation.\n"
        )
        self.publish("v4.0.0-nightly.123.1")
        self.assertIn("$(touch notes-executed)", self.notes.read_text())
        self.assertFalse((self.root / "notes-executed").exists())

    def test_release_and_ci_typecheck_test_files(self):
        command = "../node_modules/.bin/tsc --noEmit --incremental false"
        typecheck = step_script("Typecheck Playwright E2E Suite")
        self.assertIn(command, typecheck)
        self.assertNotIn("npm run build", WORKFLOW.read_text())
        self.assertIn(command, (WORKFLOW.parent / "ci.yml").read_text())

    def test_ci_and_release_use_wasm_without_legacy_frontend_builds(self):
        for filename in ("ci.yml", "release.yml"):
            workflow = (WORKFLOW.parent / filename).read_text()
            with self.subTest(workflow=filename):
                for legacy in ("npm run build", "NEXT_STATIC_EXPORT", "frontend-static-export"):
                    self.assertNotIn(legacy, workflow)
                self.assertIn("scripts/build_wasm_frontend.sh", workflow)

    def test_release_live_e2e_verifies_extracted_binary_and_external_ui_before_upload(self):
        workflow = WORKFLOW.read_text()
        install = "Install Playwright Browser Engines for Release Verification"
        verify = "Execute Live E2E Against Extracted Release Artifact"
        gate = step_script(verify)
        self.assertIn('tar -xzf release-dist/aetherflow-linux-amd64.tar.gz -C "${RELEASE_E2E_DIR}"', gate)
        self.assertIn('scripts/run_embedded_e2e.sh --binary "${RELEASE_E2E_DIR}/aetherflow-api"', gate)
        self.assertIn('--static-dir "${RELEASE_E2E_DIR}/web/dist"', gate)
        self.assertIn("--port 18080 --playwright", gate)
        self.assertIn("sha256sum --strict --check SHA256SUMS", gate)
        self.assertIn("aetherflow-api bin/af bin/speedtest-backend", gate)
        self.assertIn("plugins/telemetry-inspector/${plugin_asset}", gate)
        self.assertIn("for asset in packages.json package_automation.json; do", gate)
        self.assertIn('test ! -e "${RELEASE_E2E_DIR}/config/openapi-v1.yaml"', gate)
        self.assertIn('test "$(cat "${RELEASE_E2E_DIR}/.version")" = "${VERSION_STAMP}"', gate)
        package = "Package Release Tarball & SHA-256 Manifest"
        self.assertIn("BUILD_FRONTEND=0", step_script(package))
        self.assertIn("bash scripts/build_gold.sh", step_script(package))
        self.assertIn("npx playwright install --with-deps chromium firefox webkit", step_script(install))
        ordered = (
            "Stage External WASM Frontend Assets", package,
            "Build and Package Standalone Rust LibreSpeed Archives", install, verify,
            "Upload Release Bundle Artifact", "Verify Release Archive Integrity",
            "Attest Build Provenance", "Publish to GitHub Releases",
        )
        steps = [workflow.index(f"- name: {name}") for name in ordered]
        self.assertEqual(steps, sorted(steps))

    def test_native_arm64_executes_extracted_release_before_publication(self):
        workflow = WORKFLOW.read_text()
        arm64_job = workflow.split("  release-arm64-runtime:\n", 1)[1].split("  release-publish:\n", 1)[0]
        self.assertIn("runs-on: ubuntu-24.04-arm", arm64_job)
        self.assertIn("needs: [validate-release, release-build]", arm64_job)
        self.assertIn("name: release-dist", arm64_job)
        self.assertRegex(workflow, r"needs: \[.*release-arm64-runtime\]")
        gate = step_script("Execute ARM64 Release Contracts")
        self.assertIn("sha256sum --strict --check SHA256SUMS", gate)
        self.assertIn("aetherflow-linux-arm64.tar.gz", gate)
        self.assertIn("linux_arm64.tar.gz", gate)
        self.assertIn('cmp "${release_root}/bundle/bin/speedtest-backend" "${release_root}/standalone/speedtest-backend"', gate)
        for executable in ("bundle/bin/af", "bundle/bin/speedtest-backend", "standalone/speedtest-backend"):
            self.assertIn('${release_root}/' + executable + '" --version', gate)
        self.assertIn('scripts/run_embedded_e2e.sh --binary "${release_root}/bundle/aetherflow-api"', gate)
        self.assertIn('--static-dir "${release_root}/bundle/web/dist"', gate)

    def test_release_package_step_archives_the_external_frontend(self):
        for path in ("scripts", "backend-rs/crates/af-cli", "backend-rs/crates/af-librespeed",
                     "web/dist/locales", "config", "packages", "deploy",
                     "plugins/telemetry-inspector/backend/hooks",
                     "plugins/telemetry-inspector/frontend/dist",
                     "plugins/sdk-template-rust/backend/src"):
            (self.root / path).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(WORKFLOW.parents[2] / "scripts/build_gold.sh", self.root / "scripts/build_gold.sh")
        (self.root / "backend-rs/Cargo.toml").write_text("[workspace]\n")
        (self.root / "backend-rs/Cargo.lock").write_text("# fixture lock\n")
        for crate in ("af-cli", "af-librespeed"):
            (self.root / "backend-rs/crates" / crate / "Cargo.toml").write_text("[package]\n")
        for name in ("release-manager.sh", "verify-provenance.py", "log-retention.py"):
            (self.root / "deploy" / name).write_text("fixture")
        (self.root / "plugins/README.md").write_text("dev docs\n")
        (self.root / "plugins/sdk-template-rust/backend/src/lib.rs").write_text("// template\n")
        plugin_files = {
            "plugins/telemetry-inspector/plugin.manifest.json": b'{"id":"telemetry-inspector"}\n',
            "plugins/telemetry-inspector/backend/hooks/start.sh": b"#!/usr/bin/env bash\nexit 0\n",
            "plugins/telemetry-inspector/backend/runtime.py": b"print('ok')\n",
            "plugins/telemetry-inspector/frontend/dist/index.html": b"<!doctype html><title>Plugin</title>\n",
        }
        for name, contents in plugin_files.items():
            (self.root / name).write_bytes(contents)
        cargo = self.root / "bin/cargo"
        cargo.write_text("#!/bin/sh\nexit 0\n")
        cargo.chmod(0o755)
        for name in ("deploy/__pycache__/host.pyc", "packages/ui/src/unused.tsx",
                     "packages/tool/tsconfig.tsbuildinfo", "packages/tool/node_modules/cache.js",
                     "plugins/telemetry-inspector/backend/__pycache__/runtime.cpython-311.pyc",
                     "web/dist/.pytest_cache/state", "web/dist/.mypy_cache/state"):
            artifact = self.root / name
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_text("host-only cache or retired React workspace")

        index = self.root / "web/dist/index.html"
        wasm = self.root / "web/dist/app.wasm"
        index.write_bytes(b"<html>app</html>")
        (self.root / "web/dist/locales/en.json.gz").write_bytes(b"compressed")
        (self.root / "config/packages.json").write_bytes(b"{}\n")
        binaries = {"aetherflow-api": b"api", "af": b"cli", "speedtest-backend": b"speedtest"}
        compiled = self.root / "backend-rs/target/x86_64-unknown-linux-gnu/release"
        compiled.mkdir(parents=True)
        for name, contents in binaries.items():
            (compiled / name).write_bytes(contents)
        stage_env = {
            "TMPDIR": str(self.root), "VERSION_STAMP": "v4.0.0-nightly.123.1",
            "SOURCE_DATE_EPOCH": "1794706390",
            "CARGO_TARGET_DIR": str(self.root / "backend-rs/target"),
            "CONFIG_DIR": str(self.root / "config"),
            "PLUGINS_DIR": str(self.root / "plugins"),
            "FRONTEND_DIST_DIR": str(self.root / "web/dist"),
        }
        package = "Package Release Tarball & SHA-256 Manifest"
        archive_path = self.root / "release-dist/aetherflow-linux-amd64.tar.gz"
        for missing in ("wasm", "index"):
            with self.subTest(missing=missing):
                if missing == "index":
                    wasm.write_bytes(b"wasm")
                    index.write_bytes(b"")
                failed = self.run_step(package, **stage_env)
                self.assertNotEqual(failed.returncode, 0)
                self.assertFalse(archive_path.exists())

        index.write_bytes(b"<html>app</html>")
        result = self.run_step(package, **stage_env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tarfile.open(archive_path) as archive:
            expected = {
                "aetherflow-api": b"api", "bin/af": b"cli", "bin/speedtest-backend": b"speedtest",
                ".version": b"v4.0.0-nightly.123.1\n", "config/packages.json": b"{}\n",
                "web/dist/index.html": b"<html>app</html>", "web/dist/app.wasm": b"wasm",
                "web/dist/locales/en.json.gz": b"compressed",
                **plugin_files,
            }
            for name, data in expected.items():
                self.assertEqual(archive.extractfile("./" + name).read(), data)
            names = archive.getnames()
            self.assertEqual(names, sorted(names))
            self.assertNotIn("./af", names)
            self.assertNotIn("./speedtest-backend", names)
            self.assertFalse(any(name.startswith("./packages/ui") or name.startswith("./plugins/sdk-template-rust")
                                 or name == "./plugins/README.md" or "__pycache__" in name
                                 or ".pytest_cache" in name or ".mypy_cache" in name
                                 or "node_modules" in name or name.endswith(".tsbuildinfo") for name in names))
            for member in archive.getmembers():
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 1794706390))
            for name in ("aetherflow-api", "bin/af", "bin/speedtest-backend", "deploy/release-manager.sh",
                         "deploy/verify-provenance.py", "deploy/log-retention.py",
                         "plugins/telemetry-inspector/backend/hooks/start.sh"):
                self.assertEqual(archive.getmember("./" + name).mode, 0o755)
        packed = archive_path.read_bytes()
        self.assertEqual(packed[4:8], b"\0" * 4, "gzip must not record the wall clock")
        for source in self.root.rglob("*"):
            if source.is_file():
                os.utime(source, (1794709999, 1794709999))
        repeated = self.run_step(package, **stage_env)
        self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
        self.assertEqual(archive_path.read_bytes(), packed)

    def test_standalone_speedtest_archives_use_all_three_platforms(self):
        tag = "v4.0.0-nightly.123.1"
        archives = self.release_archives(tag)
        archives[0].write_bytes(b"main release archive")
        for arch in ("amd64", "arm64"):
            stage = self.root / f"release-dist/linux-{arch}/bin"
            stage.mkdir(parents=True)
            (stage / "speedtest-backend").write_bytes(f"staged {arch}".encode())
        (self.root / "backend-rs").mkdir()
        cargo = self.root / "bin/cargo"
        cargo.write_text(
            "#!/bin/sh\nset -eu\n"
            'test "$1 $2 $3 $4 $6 $7 $8 $9" = "build --release --locked --target -p af-librespeed --bin speedtest-backend"\n'
            'test "$AF_BUILD_VERSION" = "4.0.0-nightly.123.1"\n'
            'test "$5" = armv7-unknown-linux-gnueabihf\n'
            'test "$CC_armv7_unknown_linux_gnueabihf" = arm-linux-gnueabihf-gcc\n'
            'test "$CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER" = arm-linux-gnueabihf-gcc\n'
            'mkdir -p "target/$5/release"\n'
            'printf "%s" "$5" > "target/$5/release/speedtest-backend"\n'
        )
        cargo.chmod(0o755)
        result = self.run_step("Build and Package Standalone Rust LibreSpeed Archives",
                               RELEASE_TAG=tag, SOURCE_DATE_EPOCH="1794706390")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for archive_path, expected in zip(
            archives[1:], (b"staged amd64", b"staged arm64", b"armv7-unknown-linux-gnueabihf")
        ):
            with self.subTest(archive=archive_path.name), tarfile.open(archive_path) as archive:
                self.assertEqual(archive.getnames(), ["speedtest-backend"])
                entry = archive.getmember("speedtest-backend")
                self.assertEqual((entry.mode, entry.uid, entry.gid, entry.mtime), (0o755, 0, 0, 1794706390))
                self.assertEqual(archive.extractfile(entry).read(), expected)
        verified = self.run_step("Verify Release Archive Integrity", RELEASE_TAG=tag)
        self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)

    def test_security_checks_frontend_wasm_supply_chain(self):
        workflow = (WORKFLOW.parent / "security.yml").read_text()
        self.assertIn("targets: wasm32-unknown-unknown", workflow)
        self.assertIn("cargo deny --manifest-path ../frontend-rs/Cargo.toml --locked check advisories bans licenses sources", workflow)
        self.assertIn("cargo audit --file ../frontend-rs/Cargo.lock", workflow)

    def test_legacy_capitalized_branch_is_nightly(self):
        identity = self.resolve(GITHUB_REF="refs/heads/Nightly", GITHUB_REF_NAME="Nightly")
        self.assertEqual(identity["RELEASE_TAG"], "v4.0.0-nightly.123.1")

    def test_matching_manual_nightly_dispatch_is_allowed(self):
        identity = self.resolve(GITHUB_EVENT_NAME="workflow_dispatch", REQUESTED_CHANNEL="nightly")
        self.assertEqual(identity["RELEASE_TAG"], "v4.0.0-nightly.123.1")

    def test_manual_channel_cannot_relabel_wrong_branch(self):
        for branch in ["master", "experimental"]:
            with self.subTest(branch=branch):
                result = self.run_step(
                    "Resolve Release Identity",
                    GITHUB_EVENT_NAME="workflow_dispatch",
                    REQUESTED_CHANNEL="nightly",
                    GITHUB_REF=f"refs/heads/{branch}",
                    GITHUB_REF_NAME=branch,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.env_file.read_text(), "")

    def test_manual_experimental_dispatch_is_retired(self):
        result = self.run_step(
            "Resolve Release Identity",
            GITHUB_EVENT_NAME="workflow_dispatch",
            REQUESTED_CHANNEL="experimental",
            GITHUB_REF="refs/heads/experimental",
            GITHUB_REF_NAME="experimental",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.env_file.read_text(), "")

    def test_rerun_has_distinct_immutable_identity(self):
        identity = self.resolve(GITHUB_RUN_ATTEMPT="2")
        self.assertEqual(identity["RELEASE_TAG"], "v4.0.0-nightly.123.2")

    def test_stable_tag_keeps_explicit_version(self):
        identity = self.resolve(GITHUB_REF="refs/tags/v4.0.0", GITHUB_REF_NAME="v4.0.0")
        self.assertEqual(identity["RELEASE_TAG"], "v4.0.0")
        command = self.publish(identity["RELEASE_TAG"])
        self.assertIn("--generate-notes", command)
        self.assertNotIn("--prerelease", command)

    def test_prerelease_tag_is_not_promoted_to_stable(self):
        tag = "v4.0.0-beta.1"
        identity = self.resolve(GITHUB_REF=f"refs/tags/{tag}", GITHUB_REF_NAME=tag)
        self.assertEqual(identity["RELEASE_TAG"], tag)
        command = self.publish(tag)
        self.assertIn("--prerelease", command)
        self.assertIn("--latest=false", command)

    def test_manual_nightly_tag_keeps_requested_version(self):
        tag = "v4.0.0-nightly.89.1"
        identity = self.resolve(
            GITHUB_EVENT_NAME="workflow_dispatch",
            REQUESTED_CHANNEL="nightly",
            GITHUB_REF=f"refs/tags/{tag}",
            GITHUB_REF_NAME=tag,
        )
        self.assertEqual(identity, {"RELEASE_TAG": tag, "VERSION_STAMP": tag})
        command = self.publish(tag)
        self.assertIn("--prerelease", command)
        self.assertIn("--latest=false", command)

    def test_invalid_base_version_fails_closed(self):
        for bad in ("v4.0.0-experimental\n", "v3.99.0\n"):
            with self.subTest(bad=bad):
                (self.root / ".version").write_text(bad)
                result = self.run_step("Resolve Release Identity")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.env_file.read_text(), "")

    def test_pre_v4_tag_fails_closed(self):
        result = self.run_step(
            "Resolve Release Identity",
            GITHUB_REF="refs/tags/v3.2.8",
            GITHUB_REF_NAME="v3.2.8",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.env_file.read_text(), "")

    def test_unsupported_branch_does_not_publish(self):
        result = self.run_step(
            "Resolve Release Identity", GITHUB_REF="refs/heads/master", GITHUB_REF_NAME="master"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.env_file.read_text(), "")

    def test_automatic_branch_releases_only_follow_nightly(self):
        workflow = WORKFLOW.read_text()
        branches = workflow.split("    branches:\n", 1)[1].split("    tags:\n", 1)[0]
        self.assertIn("- nightly", branches)
        self.assertNotIn("- experimental", branches)
        self.assertIn("default: 'nightly'", workflow)
        self.assertIn('VERSION="${VERSION_STAMP}"', step_script("Package Release Tarball & SHA-256 Manifest"))


if __name__ == "__main__":
    unittest.main()
