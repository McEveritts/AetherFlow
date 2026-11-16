#!/usr/bin/env python3
"""Parallel unittest runner for tests/test_*.py preserving setUpClass/tearDownClass isolation."""

import concurrent.futures
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
CHUNK_SIZE = 12

WORKER_CODE = """
import pathlib, sys, unittest
root = pathlib.Path(sys.argv[1]).resolve()
tests_dir = str(root / "tests")
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)
if str(root) not in sys.path:
    sys.path.insert(1, str(root))
suite = unittest.defaultTestLoader.loadTestsFromNames(sys.argv[2:])
runner = unittest.TextTestRunner(verbosity=2)
result = runner.run(suite)
print(f"__PARALLEL_COUNT__={result.testsRun}", flush=True)
sys.exit(0 if result.wasSuccessful() else 1)
"""


def _has_custom_class_fixture(cls: type) -> bool:
    for attr in ("setUpClass", "tearDownClass"):
        method = getattr(cls, attr, None)
        base = getattr(unittest.TestCase, attr, None)
        if getattr(method, "__func__", method) is not getattr(base, "__func__", base):
            return True
    return False


def discover_work_units() -> Tuple[List[Tuple[List[str], int]], int]:
    sys.path.insert(0, str(TESTS_DIR))
    sys.path.insert(1, str(ROOT))
    suite = unittest.defaultTestLoader.discover(str(TESTS_DIR), pattern="test_*.py")
    by_class: Dict[str, Tuple[type, List[str]]] = {}
    errors: List[str] = []

    def walk(node: object) -> None:
        if isinstance(node, unittest.TestSuite):
            for child in node:
                walk(child)
        elif node.__class__.__name__ == "_FailedTest":
            errors.append(str(node))
        else:
            cls = node.__class__
            cls_id = f"{cls.__module__}.{cls.__qualname__}"
            method_name = getattr(node, "_testMethodName", "")
            full_id = f"{cls_id}.{method_name}"
            if cls_id not in by_class:
                by_class[cls_id] = (cls, [])
            by_class[cls_id][1].append(full_id)

    walk(suite)
    if errors:
        raise RuntimeError(f"Test discovery failed: {errors}")

    units: List[Tuple[List[str], int]] = []
    total_tests = 0
    for cls_id, (cls, methods) in sorted(by_class.items()):
        methods.sort()
        total_tests += len(methods)
        if _has_custom_class_fixture(cls) or len(methods) <= CHUNK_SIZE:
            units.append(([cls_id], len(methods)))
        else:
            for i in range(0, len(methods), CHUNK_SIZE):
                chunk = methods[i : i + CHUNK_SIZE]
                units.append((chunk, len(chunk)))

    units.sort(key=lambda item: (-item[1], item[0][0]))
    return units, total_tests


def run_bucket(idx: int, targets: List[str]) -> Tuple[int, int, int, float, str]:
    t0 = time.monotonic()
    proc = subprocess.run(
        [sys.executable, "-c", WORKER_CODE, str(ROOT), *targets],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    elapsed = time.monotonic() - t0
    combined = proc.stdout + proc.stderr
    ran = 0
    for line in combined.splitlines():
        if line.startswith("__PARALLEL_COUNT__="):
            ran = int(line.split("=", 1)[1].strip())
    return idx, proc.returncode, ran, elapsed, combined


def main() -> int:
    units, expected_total = discover_work_units()
    cpus = os.cpu_count() or 4
    default_workers = min(max(cpus * 2, 4), 12)
    workers = int(os.environ.get("AF_TEST_WORKERS", str(default_workers)))
    workers = max(1, min(workers, len(units)))

    buckets: List[List[str]] = [[] for _ in range(workers)]
    loads = [0] * workers
    for targets, count in units:
        target_idx = min(range(workers), key=lambda i: loads[i])
        buckets[target_idx].extend(targets)
        loads[target_idx] += count

    print(
        f"[run_parallel_tests] Running {expected_total} tests across {len(units)} work units "
        f"using {workers} parallel workers (loads={loads})",
        flush=True,
    )

    t0 = time.monotonic()
    total_ran = 0
    failed_workers: List[Tuple[int, int, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(run_bucket, idx, b) for idx, b in enumerate(buckets) if b]
        for fut in concurrent.futures.as_completed(futures):
            idx, rc, ran, elapsed, output = fut.result()
            total_ran += ran
            status = "PASS" if rc == 0 else f"FAIL(rc={rc})"
            print(f"[worker {idx}] {status}: ran {ran} tests in {elapsed:.1f}s", flush=True)
            if rc != 0:
                failed_workers.append((idx, rc, output))

    wall = time.monotonic() - t0
    if failed_workers:
        for idx, rc, output in failed_workers:
            print(f"\n================ WORKER {idx} FAILURE OUTPUT (rc={rc}) ================", file=sys.stderr)
            print(output, file=sys.stderr)
        return 1

    if total_ran != expected_total:
        print(
            f"[FAIL] Expected {expected_total} tests to run, but workers reported {total_ran}",
            file=sys.stderr,
        )
        return 1

    print(f"[PASS] All {total_ran} tests passed in {wall:.1f}s across {workers} workers.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
