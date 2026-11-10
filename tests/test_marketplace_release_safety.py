"""Exercise release discovery and version receipts without network or host writes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import common_functions


class ReleaseDiscoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="af-release-discovery-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def discover(self, fallback="1.22.3", strip_v="true", **environment):
        body = common_functions("github_latest_tag") + r'''
print_error() { printf '%s\n' "$*" >&2; }
print_warning() { printf '%s\n' "$*" >&2; }
print_warn() { printf '%s\n' "$*" >&2; }
curl() {
    printf '%s\n' "$*" >> "$AF_DISCOVERY_LOG"
    case "$*" in
        *api.github.com/*)
            [[ "${AF_DISCOVERY_API_EXIT:-0}" == 0 ]] || return 22
            printf '%s\n' "${AF_DISCOVERY_API_JSON:-}"
            ;;
        *)
            [[ "${AF_DISCOVERY_REDIRECT_EXIT:-0}" == 0 ]] || return 22
            printf '%s\n' "${AF_DISCOVERY_REDIRECT_URL:-}"
            ;;
    esac
}
github_latest_tag "$1" "$2" "$3"
'''
        variables = {key: value for key, value in os.environ.items()
                     if not key.startswith("AF_DISCOVERY_") and key != "AF_ALLOW_RELEASE_FALLBACK"}
        variables.update(AF_DISCOVERY_LOG=str(self.root / "curl.log"), **environment)
        return subprocess.run(["bash", "-euc", body, "--", "go-gitea/gitea", fallback, strip_v],
                              env=variables, text=True, capture_output=True, timeout=10)

    def assert_discovery_failed(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("Failed to discover latest GitHub release for go-gitea/gitea", result.stderr)

    def test_redirect_discovers_release_without_requesting_api(self):
        result = self.discover(AF_DISCOVERY_REDIRECT_URL="https://github.com/go-gitea/gitea/releases/tag/v2.1.0?source=latest#release")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "2.1.0\n")
        self.assertNotIn("api.github.com", (self.root / "curl.log").read_text())

    def test_redirect_can_preserve_version_prefix(self):
        result = self.discover(strip_v="false", AF_DISCOVERY_REDIRECT_URL="https://github.com/go-gitea/gitea/releases/tag/v2.1.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v2.1.0\n")

    def test_api_discovers_release_when_redirect_fails(self):
        result = self.discover(AF_DISCOVERY_REDIRECT_EXIT="22", AF_DISCOVERY_API_JSON='{"tag_name": "v2.1.0"}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "2.1.0\n")
        self.assertIn("api.github.com/repos/go-gitea/gitea/releases/latest", (self.root / "curl.log").read_text())

    def test_transport_outage_rejects_fallback_by_default(self):
        result = self.discover(AF_DISCOVERY_REDIRECT_EXIT="22", AF_DISCOVERY_API_EXIT="22")
        self.assert_discovery_failed(result)
        self.assertEqual(len((self.root / "curl.log").read_text().splitlines()), 2)

    def test_empty_or_invalid_metadata_rejects_fallback_by_default(self):
        for metadata in ("", "{}", '{"tag_name": null}', "not-json"):
            with self.subTest(metadata=metadata):
                self.assert_discovery_failed(self.discover(AF_DISCOVERY_API_JSON=metadata))

    def test_explicit_opt_in_allows_nonempty_fallback(self):
        result = self.discover(fallback="v1.22.3", AF_ALLOW_RELEASE_FALLBACK="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "1.22.3\n")

    def test_explicit_opt_in_can_preserve_fallback_prefix(self):
        result = self.discover(fallback="v1.22.3", strip_v="false", AF_ALLOW_RELEASE_FALLBACK="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "v1.22.3\n")

    def test_only_literal_one_enables_fallback(self):
        for value in ("", "0", "true", "yes"):
            with self.subTest(value=value):
                self.assert_discovery_failed(self.discover(AF_ALLOW_RELEASE_FALLBACK=value))

    def test_opt_in_without_fallback_still_fails(self):
        self.assert_discovery_failed(self.discover(fallback="", AF_ALLOW_RELEASE_FALLBACK="1"))


class VersionReceiptSafetyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="af-version-receipt-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.version = self.root / ".af-version"

    def write_version(self, version, **environment):
        variables = {key: value for key, value in os.environ.items()
                     if key not in ("AF_ALLOW_DOWNGRADE", "AF_ALLOW_RELEASE_FALLBACK")}
        variables.update(PATH="/usr/bin:/bin", **environment)
        return subprocess.run(["bash", "-euc", common_functions("write_app_version") + '\nwrite_app_version "$1" "$2"',
                               "--", str(self.version), version], env=variables, text=True, capture_output=True, timeout=10)

    def test_fresh_receipt_is_written_atomically(self):
        result = self.write_version("2.1.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.version.read_text(), "2.1.0\n")
        self.assertEqual(list(self.root.glob(".af-version.*")), [])

    def test_equal_and_newer_versions_are_allowed(self):
        self.version.write_text("2.1.0\n")
        for version in ("2.1.0", "2.10.0", "3.0.0"):
            with self.subTest(version=version):
                result = self.write_version(version)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.version.read_text(), version + "\n")

    def test_dpkg_ordering_blocks_downgrades_without_replacing_receipt(self):
        for old, new in (("2.1.0", "1.22.3"), ("2.10.0", "2.9.0"), ("2.1.0", "2.1.0~rc1"), ("2:1.0", "1:9.0")):
            with self.subTest(old=old, new=new):
                self.version.write_text(old + "\n")
                inode = self.version.stat().st_ino
                result = self.write_version(new)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"Refusing to downgrade {self.version} from {old} to {new}", result.stderr)
                self.assertEqual(self.version.read_text(), old + "\n")
                self.assertEqual(self.version.stat().st_ino, inode)
                self.assertEqual(list(self.root.glob(".af-version.*")), [])

    def test_explicit_downgrade_opt_in_allows_older_version(self):
        self.version.write_text("2.1.0\n")
        result = self.write_version("1.22.3", AF_ALLOW_DOWNGRADE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.version.read_text(), "1.22.3\n")

    def test_fallback_opt_in_does_not_allow_downgrades(self):
        self.version.write_text("2.1.0\n")
        result = self.write_version("1.22.3", AF_ALLOW_RELEASE_FALLBACK="1")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.version.read_text(), "2.1.0\n")

    def test_only_literal_one_allows_downgrades(self):
        for value in ("", "0", "true", "yes"):
            with self.subTest(value=value):
                self.version.write_text("2.1.0\n")
                result = self.write_version("1.22.3", AF_ALLOW_DOWNGRADE=value)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.version.read_text(), "2.1.0\n")

    def test_empty_receipts_and_hex_commit_updates_remain_supported(self):
        for old, new in (("", "2.1.0"), ("abcdef123", "fedcba456")):
            with self.subTest(old=old, new=new):
                self.version.write_text(old + "\n")
                result = self.write_version(new)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.version.read_text(), new + "\n")

    def test_incomparable_receipts_require_an_explicit_override(self):
        for old, new in (("2.1.0", "abcdef123"), ("abcdef123", "not-a-commit")):
            with self.subTest(old=old, new=new):
                self.version.write_text(old + "\n")
                result = self.write_version(new)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.version.read_text(), old + "\n")

    def test_existing_symlink_is_replaced_without_reading_or_changing_target(self):
        target = self.root / "operator-version"
        target.write_text("9.9.9\n")
        self.version.symlink_to(target)
        result = self.write_version("2.1.0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.version.is_symlink())
        self.assertEqual(self.version.read_text(), "2.1.0\n")
        self.assertEqual(target.read_text(), "9.9.9\n")

    def test_receipt_swapped_to_fifo_before_open_fails_without_blocking(self):
        self.version.write_text("2.1.0\n")
        program = common_functions("write_app_version").split("<<'PYEOF'\n", 1)[1].split("\nPYEOF", 1)[0]
        probe = '''import os, sys
from unittest.mock import patch
program = sys.argv.pop(1)
original_open = os.open
def swap_receipt(path, flags, *arguments, **keywords):
    if path == '.af-version':
        os.unlink(path, dir_fd=keywords['dir_fd'])
        os.mkfifo(path, dir_fd=keywords['dir_fd'])
    return original_open(path, flags, *arguments, **keywords)
with patch('os.open', side_effect=swap_receipt):
    exec(program)
'''
        variables = {key: value for key, value in os.environ.items() if key != "AF_ALLOW_DOWNGRADE"}
        result = subprocess.run([sys.executable, "-c", probe, program, str(self.version), "1.22.3"],
                                env=variables, text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Application version receipt must be a regular file", result.stderr)
        self.assertTrue(self.version.is_fifo())
        self.assertEqual(list(self.root.glob(".af-version.*")), [])


if __name__ == "__main__":
    unittest.main()
