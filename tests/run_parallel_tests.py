#!/usr/bin/env python3
"""Parallel unittest runner for tests/test_*.py preserving setUpClass/tearDownClass isolation."""

import argparse
import concurrent.futures
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = ROOT / "tests"
CHUNK_SIZE = 4

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


def discover_work_units(
    patterns: Sequence[str] = ("test_*.py",),
) -> Tuple[List[Tuple[List[str], int]], int]:
    sys.path.insert(0, str(TESTS_DIR))
    sys.path.insert(1, str(ROOT))
    by_class: Dict[str, Tuple[type, set[str]]] = {}
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
                by_class[cls_id] = (cls, set())
            by_class[cls_id][1].add(full_id)

    for pattern in patterns or ("test_*.py",):
        suite = unittest.defaultTestLoader.discover(str(TESTS_DIR), pattern=pattern)
        walk(suite)
    if errors:
        raise RuntimeError(f"Test discovery failed: {errors}")

    units: List[Tuple[List[str], int]] = []
    total_tests = 0
    for cls_id, (cls, method_set) in sorted(by_class.items()):
        methods = sorted(method_set)
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


def parse_shard(spec: str) -> Tuple[int, int]:
    parts = spec.strip().split("/")
    if len(parts) != 2:
        raise ValueError(f"Invalid shard specification {spec!r}; expected '<index>/<total>' (1-based).")
    try:
        shard_index = int(parts[0])
        shard_total = int(parts[1])
    except ValueError as exc:
        raise ValueError(f"Invalid shard specification {spec!r}; expected integer '<index>/<total>'.") from exc
    if shard_total < 1 or shard_index < 1 or shard_index > shard_total:
        raise ValueError(
            f"Invalid shard specification {spec!r}; require 1 <= index <= total (got {shard_index}/{shard_total})."
        )
    return shard_index, shard_total


def select_shard_units(
    units: Sequence[Tuple[List[str], int]],
    shard_index: int,
    shard_total: int,
) -> Tuple[List[Tuple[List[str], int]], int]:
    if shard_total < 1 or shard_index < 1 or shard_index > shard_total:
        raise ValueError(f"Invalid shard range {shard_index}/{shard_total}")
    if shard_total == 1:
        selected = list(units)
        return selected, sum(count for _, count in selected)

    # Group work units by module so bash-heavy installer suites are spread evenly
    # across every shard rather than clustering into a single straggler shard.
    by_module: Dict[str, List[Tuple[List[str], int]]] = {}
    for targets, count in units:
        module_name = targets[0].split(".", 1)[0]
        by_module.setdefault(module_name, []).append((targets, count))

    ordered_modules = sorted(
        by_module.items(),
        key=lambda item: (-sum(count for _, count in item[1]), item[0]),
    )

    shards: List[List[Tuple[List[str], int]]] = [[] for _ in range(shard_total)]
    shard_loads = [0] * shard_total
    for _, module_units in ordered_modules:
        module_units.sort(key=lambda item: (-item[1], item[0][0]))
        module_loads = [0] * shard_total
        for targets, count in module_units:
            target_shard = min(
                range(shard_total),
                key=lambda idx: (module_loads[idx], shard_loads[idx], idx),
            )
            shards[target_shard].append((targets, count))
            module_loads[target_shard] += count
            shard_loads[target_shard] += count

    selected = sorted(shards[shard_index - 1], key=lambda item: (-item[1], item[0][0]))
    return selected, shard_loads[shard_index - 1]


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Parallel unittest runner for tests/test_*.py")
    parser.add_argument(
        "--shard",
        default=os.environ.get("AF_TEST_SHARD", ""),
        help="Optional 1-based shard selector '<index>/<total>' (e.g. 1/4) to run a deterministic balanced partition.",
    )
    parser.add_argument(
        "-p",
        "--pattern",
        action="append",
        dest="patterns",
        help="Optional unittest filename pattern(s) under tests/ (repeatable; defaults to 'test_*.py').",
    )
    args = parser.parse_args(argv)

    patterns = tuple(args.patterns) if args.patterns else ("test_*.py",)
    units, discovered_total = discover_work_units(patterns=patterns)
    shard_label = ""
    if args.shard:
        shard_index, shard_total = parse_shard(args.shard)
        units, expected_total = select_shard_units(units, shard_index, shard_total)
        shard_label = f" [shard {shard_index}/{shard_total} of {discovered_total} total]"
    else:
        expected_total = discovered_total

    if not units:
        print(f"[PASS] No tests assigned{shard_label}.", flush=True)
        return 0

    cpus = os.cpu_count() or 4
    default_workers = min(max(cpus * 2, 4), 12)
    workers = int(os.environ.get("AF_TEST_WORKERS", str(default_workers)))
    workers = max(1, min(workers, len(units)))

    # Dynamic work-stealing: submit each work unit individually (largest first)
    # so fast workers immediately pull remaining units instead of idling behind a
    # slow static bucket.
    scheduled_units = sorted(units, key=lambda item: (-item[1], item[0][0]))
    print(
        f"[run_parallel_tests] Running {expected_total} tests across {len(scheduled_units)} dynamic work units"
        f"{shard_label} using {workers} parallel workers",
        flush=True,
    )

    t0 = time.monotonic()
    total_ran = 0
    failed_units: List[Tuple[int, str, int, str]] = []
    unit_timings: List[Tuple[float, int, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        future_map = {
            pool.submit(run_bucket, idx, targets): (idx, targets[0])
            for idx, (targets, _) in enumerate(scheduled_units)
        }
        for fut in concurrent.futures.as_completed(future_map):
            idx, label = future_map[fut]
            _, rc, ran, elapsed, output = fut.result()
            total_ran += ran
            unit_timings.append((elapsed, ran, label))
            if rc != 0:
                print(f"[unit {idx}] FAIL(rc={rc}): {label} ({ran} tests in {elapsed:.1f}s)", flush=True)
                failed_units.append((idx, label, rc, output))

    wall = time.monotonic() - t0
    if failed_units:
        for idx, label, rc, output in failed_units:
            print(
                f"\n================ UNIT {idx} ({label}) FAILURE OUTPUT (rc={rc}) ================",
                file=sys.stderr,
            )
            print(output, file=sys.stderr)
        return 1

    if total_ran != expected_total:
        print(
            f"[FAIL] Expected {expected_total} tests to run{shard_label}, but workers reported {total_ran}",
            file=sys.stderr,
        )
        return 1

    slowest = sorted(unit_timings, reverse=True)[:5]
    slowest_summary = ", ".join(f"{label}={elapsed:.1f}s({ran})" for elapsed, ran, label in slowest)
    print(
        f"[PASS] All {total_ran} tests passed{shard_label} in {wall:.1f}s across {workers} workers "
        f"(slowest units: {slowest_summary}).",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
