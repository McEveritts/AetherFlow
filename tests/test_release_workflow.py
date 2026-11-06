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
        self.env_file = self.root / "github-env"
        self.env_file.touch()
        self.commands = self.root / "gh-commands.json"
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['TEST_GH_COMMANDS']).write_text(json.dumps(sys.argv[1:]))\n"
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
