import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires Linux shell tools")
class StreamingValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts/validate-streaming.sh", self.root / "scripts")
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.calls = self.root / "calls.txt"
        self.environment = {
            **os.environ,
            "PATH": f"{self.tools}:{os.environ['PATH']}",
            "AF_TEST_CALLS": str(self.calls),
            "AF_TEST_MISSING_FIXTURE": "0",
            "AF_TEST_FAIL_INTEGRATED": "0",
            "AF_TEST_HANG_TYPESCRIPT": "0",
            "AF_STREAMING_CHECK_TIMEOUT": "10s",
        }
        for name, body in {
            "node": 'printf "test-node\\n"\n',
            "git": 'printf "test-checkout\\n"\n',
            "npm": '''printf 'npm %s\\n' "$*" >> "$AF_TEST_CALLS"
if [[ "$*" == *tsc* && "$AF_TEST_HANG_TYPESCRIPT" == 1 ]]; then
  exec yes > /dev/null
fi
''',
            "cargo": '''printf 'cargo %s\\n' "$*" >> "$AF_TEST_CALLS"
if [[ "$*" == *"-p af-streaming-tests"* && "$AF_TEST_MISSING_FIXTURE" != 1 ]]; then
  printf '{}' > "$AF_STREAMING_CONTRACT_FIXTURE"
fi
if [[ "$*" == *"-p af-api"* && "$AF_TEST_FAIL_INTEGRATED" == 1 ]]; then
  exit 1
fi
''',
        }.items():
            tool = self.tools / name
            tool.write_text("#!/bin/bash\nset -eu\n" + body)
            tool.chmod(0o755)

    def run_gate(self, *arguments):
        return subprocess.run(
            ["bash", str(self.root / "scripts/validate-streaming.sh"), *arguments],
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_scoped_gate_generates_fixture_and_runs_real_test_paths(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls.read_text()
        self.assertIn("-p af-streaming-tests streaming_ext::tests", calls)
        self.assertIn("StreamingTab.rust-contract.test.tsx", calls)
        self.assertNotIn("-p af-api", calls)
        self.assertIn("PASS typescript", result.stdout)
        self.assertEqual(len(list((self.root / "dist").glob("*/rust-dashboard.json"))), 1)

    def test_missing_fixture_fails_instead_of_silently_skipping_contracts(self):
        self.environment["AF_TEST_MISSING_FIXTURE"] = "1"
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL rust-contract-fixture", result.stdout)
        self.assertNotIn("--runTestsByPath", self.calls.read_text())
        self.assertIn("PASS typescript", result.stdout)

    def test_integrated_failures_do_not_hide_remaining_gates(self):
        self.environment["AF_TEST_FAIL_INTEGRATED"] = "1"
        result = self.run_gate("--integrated")
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL rust-integrated-tests", result.stdout)
        self.assertIn("FAIL rust-integrated-build", result.stdout)
        self.assertIn("PASS frontend-all", result.stdout)
        self.assertIn("PASS frontend-build", result.stdout)

    def test_successful_integrated_gate_retains_individual_logs(self):
        result = self.run_gate("--integrated")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result_directory = next((self.root / "dist").iterdir())
        self.assertTrue((result_directory / "environment.txt").is_file())
        self.assertTrue((result_directory / "rust-integrated-tests.log").is_file())
        self.assertTrue((result_directory / "frontend-all.log").is_file())
        self.assertIn("PASS frontend-build", (result_directory / "summary.txt").read_text())

    def test_invalid_arguments_never_run_validation(self):
        for arguments in [("--unknown",), ("--scoped", "--integrated")]:
            with self.subTest(arguments=arguments):
                result = self.run_gate(*arguments)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Usage:", result.stderr)
                self.assertFalse(self.calls.exists())

    def test_timed_out_check_fails_and_remaining_checks_run(self):
        self.environment["AF_TEST_HANG_TYPESCRIPT"] = "1"
        self.environment["AF_STREAMING_CHECK_TIMEOUT"] = "0.1s"
        result = self.run_gate()
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL typescript (exit 124)", result.stdout)
        self.assertIn("PASS streaming-lint", result.stdout)


if __name__ == "__main__":
    unittest.main()
