"""Expose the repository's shell hygiene verifier to the unittest CI suite."""

from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ShellScriptHygieneTests(unittest.TestCase):
    def test_repository_shell_scripts_pass_hygiene_checks(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tests/check_shell_hygiene.py")],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        print(result.stdout, end="")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
