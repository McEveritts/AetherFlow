import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/release.yml"


def step_script(name):
    workflow = WORKFLOW.read_text()
    step = re.search(
        rf"^      - name: {re.escape(name)}\n(.*?)(?=^      - name: |\Z)",
        workflow,
        re.MULTILINE | re.DOTALL,
    )
    if step is None or "        run: |\n" not in step.group(1):
        raise AssertionError(f"Missing shell step: {name}")
    return textwrap.dedent(step.group(1).split("        run: |\n", 1)[1]).strip()


class RustCacheWorkflowTests(unittest.TestCase):
    def test_rust_jobs_cache_downloads_without_compiled_artifacts(self):
        jobs = {
            "ci.yml": ["backend-rs"],
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
                    self.assertIn("          workspaces: \"backend-rs -> target\"\n", caches[0])


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

    def publish(self, tag):
        result = self.run_step("Publish to GitHub Releases", RELEASE_TAG=tag)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        command = json.loads(self.commands.read_text())
        self.assertEqual(command[:3], ["release", "create", tag])
        self.assertEqual(command[command.index("--target") + 1], self.env["GITHUB_SHA"])
        self.assertIn("release-dist/aetherflow-linux-amd64.tar.gz", command)
        self.assertIn("release-dist/SHA256SUMS", command)
        self.assertNotIn("--clobber", command)
        return command

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
        for content in (None, "", "## CHANGELOG v4.0.0\n\nHistorical notes.\n"):
            with self.subTest(content=content):
                changelog = self.root / "CHANGELOG.md"
                if content is None:
                    changelog.unlink(missing_ok=True)
                else:
                    changelog.write_text(content)
                result = self.run_step(
                    "Publish to GitHub Releases", RELEASE_TAG="v4.0.0-nightly.123.1"
                )
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
        build = step_script("Build Next.js Static Export")
        self.assertIn(command, build)
        self.assertLess(build.index(command), build.index("npm run build"))
        self.assertIn(command, (WORKFLOW.parent / "ci.yml").read_text())

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
        (self.root / ".version").write_text("v4.0.0-experimental\n")
        result = self.run_step("Resolve Release Identity")
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
        self.assertIn('echo "${VERSION_STAMP}" > "${STAGE_DIR}/.version"', workflow)


if __name__ == "__main__":
    unittest.main()
