"""Exercise the exact Bash release-worker receipt function without running a release."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy/release-manager.sh"


class ReleaseReceiptConfinementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="af-receipt-")
        self.root = Path(self.temporary.name)
        self.jobs = self.root / "jobs"
        self.jobs.mkdir()
        self.path = self.jobs / "aetherflow-self-update-fixture.service.json"
        self.unit = "aetherflow-self-update-fixture.service"
        self.payload = {"job_unit": self.unit, "status": "running", "completed": False, "success": False, "exit_code": None, "error": ""}
        self.path.write_text(json.dumps(self.payload))
        metadata = self.jobs.stat()
        self.expected = (metadata.st_dev, metadata.st_ino)
        source = SCRIPT.read_text()
        self.function = source[source.index("write_self_update_status_receipt() {"):source.index("\nfinalize_self_update_status_on_exit()")]
        self.addCleanup(self.temporary.cleanup)

    def invoke(self, phase="succeeded", completed="true", success="true", identity=None):
        identity = self.expected if identity is None else identity
        env = os.environ.copy()
        env.update(SELF_UPDATE_STATUS_FILE=str(self.path), SELF_UPDATE_JOB_UNIT=self.unit,
                   AETHERFLOW_SELF_UPDATE_DIRECTORY_DEV=str(identity[0]),
                   AETHERFLOW_SELF_UPDATE_DIRECTORY_INO=str(identity[1]))
        return subprocess.run(["bash", "-c", "set -euo pipefail\n" + self.function + '\nwrite_self_update_status_receipt "$@"',
                               "receipt-fixture", phase, completed, success,
                               "null" if phase == "running" else ("0" if success == "true" else "9"), ""],
                              env=env, text=True, capture_output=True, timeout=5)

    def test_normal_completion_and_terminal_result_is_not_overwritten(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        completed = self.path.read_bytes()
        self.assertTrue(json.loads(completed)["success"])
        result = self.invoke("failed", "true", "false")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.path.read_bytes(), completed)
        self.assertNotEqual(self.invoke("running", "false", "false").returncode, 0)
        self.assertEqual(self.path.read_bytes(), completed)

    def test_replaced_directory_symlink_cannot_redirect_a_scheduled_write(self):
        moved = self.root / "moved"
        self.jobs.rename(moved)
        outside = self.root / "outside"
        outside.mkdir()
        target = outside / self.path.name
        target.write_text(json.dumps(self.payload))
        original = target.read_bytes()
        self.jobs.symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(target.read_bytes(), original)
        self.assertFalse(Path(str(target) + ".lock").exists())
        self.assertEqual(json.loads((moved / self.path.name).read_text())["status"], "running")

    def test_replaced_real_directory_is_rejected_by_scheduled_identity(self):
        moved = self.root / "moved"
        self.jobs.rename(moved)
        self.jobs.mkdir()
        shutil.copy2(moved / self.path.name, self.path)
        original = self.path.read_bytes()
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertFalse(Path(str(self.path) + ".lock").exists())

    def test_symlinked_ancestor_is_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        original = self.path.read_bytes()
        self.path = alias / "jobs" / self.path.name
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(self.path.read_bytes(), original)

    def test_missing_scheduled_binding_and_missing_receipt_are_rejected(self):
        self.assertNotEqual(self.invoke(identity=("", "")).returncode, 0)
        self.path.unlink()
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertFalse(self.path.exists())

    def test_wrong_receipt_identity_and_oversized_receipt_are_refused(self):
        self.payload["job_unit"] = "aetherflow-self-update-other.service"
        self.path.write_text(json.dumps(self.payload))
        original = self.path.read_bytes()
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(self.path.read_bytes(), original)
        self.path.write_bytes(b"x" * (256 * 1024 + 1))
        self.assertNotEqual(self.invoke().returncode, 0)
        self.assertEqual(self.path.stat().st_size, 256 * 1024 + 1)
        self.assertEqual(list(self.jobs.glob("*.tmp.*")), [])

    def test_concurrent_completions_preserve_one_coherent_terminal(self):
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(self.invoke), executor.submit(self.invoke, "failed", "true", "false")]
            for future in futures:
                result = future.result()
                self.assertEqual(result.returncode, 0, result.stderr)
        terminal = json.loads(self.path.read_text())
        self.assertTrue(terminal["completed"])
        self.assertEqual(terminal["job_unit"], self.unit)
        self.assertEqual(terminal["success"], terminal["status"] == "succeeded")
        self.assertEqual(terminal["exit_code"], 0 if terminal["success"] else 9)
        self.assertEqual(list(self.jobs.glob("*.tmp.*")), [])

    def test_nonregular_or_linked_receipt_entries_are_rejected_without_writes(self):
        for kind in ("symlink", "hardlink", "fifo", "directory"):
            with self.subTest(kind=kind):
                lock = Path(str(self.path) + ".lock")
                lock.unlink(missing_ok=True)
                if kind == "symlink":
                    outside = self.root / "outside-lock"
                    outside.write_text("unchanged")
                    lock.symlink_to(outside)
                elif kind == "hardlink":
                    outside = self.root / "outside-hardlink"
                    outside.write_text("unchanged")
                    os.link(outside, lock)
                elif kind == "fifo":
                    os.mkfifo(lock)
                else:
                    lock.mkdir()
                original = self.path.read_bytes()
                self.assertNotEqual(self.invoke().returncode, 0)
                self.assertEqual(self.path.read_bytes(), original)
                if kind == "directory": lock.rmdir()
                else: lock.unlink()


if __name__ == "__main__":
    unittest.main()
