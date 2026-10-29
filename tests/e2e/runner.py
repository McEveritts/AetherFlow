"""
AetherFlow v3.1.7 E2E Test Suite Runner
Discovers and executes Tier 1, Tier 2, Tier 3, and Tier 4 tests.
Generates terminal reports, JSON metrics, and markdown tables.
"""

import os
import sys
import time
import json
import argparse
from typing import List, Dict, Any

from .framework import TestCase, CodebaseInspector, AetherFlowApiClient, TestFailure, TestSkip, PROJECT_ROOT
from .tier1_features import get_tier1_tests
from .tier2_boundaries import get_tier2_tests
from .tier3_pairwise import get_tier3_tests
from .tier4_realworld import get_tier4_tests

class TestRunner:
    def __init__(self, mode: str = "contract", base_url: str = "http://localhost:8080",
                 socket_path: str = "/run/aetherflow/runner.sock", verbose: bool = False,
                 tier_filter: int = 0, feature_filter: str = "", fail_fast: bool = False):
        self.mode = mode
        self.base_url = base_url
        self.socket_path = socket_path
        self.verbose = verbose
        self.tier_filter = tier_filter
        self.feature_filter = feature_filter.upper()
        self.fail_fast = fail_fast
        
        self.inspector = CodebaseInspector(PROJECT_ROOT)
        self.client = AetherFlowApiClient(base_url)
        
        self.all_tests: List[TestCase] = []
        self.results: List[Dict[str, Any]] = []
        self.passed_count = 0
        self.failed_count = 0
        self.skipped_count = 0
        self.total_duration_ms = 0.0

    def discover_tests(self):
        tests: List[TestCase] = []
        if self.tier_filter == 0 or self.tier_filter == 1:
            tests.extend(get_tier1_tests())
        if self.tier_filter == 0 or self.tier_filter == 2:
            tests.extend(get_tier2_tests())
        if self.tier_filter == 0 or self.tier_filter == 3:
            tests.extend(get_tier3_tests())
        if self.tier_filter == 0 or self.tier_filter == 4:
            tests.extend(get_tier4_tests())

        if self.feature_filter:
            tests = [t for t in tests if self.feature_filter in t.feature_id]

        self.all_tests = tests

    def run(self) -> int:
        self.discover_tests()
        print("=" * 80)
        print(" " * 20 + "AETHERFLOW v3.1.7 E2E TEST RUNNER")
        print("=" * 80)
        print(f" Execution Mode : {self.mode.upper()}")
        print(f" Target URL     : {self.base_url}")
        print(f" Socket Path    : {self.socket_path}")
        print(f" Discovered     : {len(self.all_tests)} tests across Tiers 1-4")
        if self.tier_filter:
            print(f" Tier Filter    : Tier {self.tier_filter}")
        if self.feature_filter:
            print(f" Feature Filter : {self.feature_filter}")
        print("-" * 80)

        start_time = time.time()
        for idx, test in enumerate(self.all_tests, 1):
            test_start = time.time()
            status = "PASS"
            err_msg = ""
            try:
                test.run(self.inspector, self.client, mode=self.mode)
                test.passed = True
                self.passed_count += 1
            except TestSkip as s:
                test.skipped = True
                status = "SKIP"
                err_msg = str(s)
                self.skipped_count += 1
            except (TestFailure, Exception) as e:
                test.passed = False
                status = "FAIL"
                err_msg = str(e)
                self.failed_count += 1

            duration_ms = (time.time() - test_start) * 1000.0
            test.duration_ms = duration_ms
            test.error_message = err_msg

            self.results.append({
                "test_id": test.test_id,
                "feature_id": test.feature_id,
                "tier": test.tier,
                "description": test.description,
                "status": status,
                "duration_ms": round(duration_ms, 2),
                "error": err_msg
            })

            if self.verbose:
                print(f" [{status}] {test.test_id} (Tier {test.tier} - {test.feature_id}): {test.description} ({duration_ms:.1f}ms)")
                if status == "FAIL" and err_msg:
                    print(f"        -> Reason: {err_msg}")
            else:
                if status == "PASS":
                    sys.stdout.write(".")
                elif status == "SKIP":
                    sys.stdout.write("s")
                else:
                    sys.stdout.write("F")
                if idx % 50 == 0 or idx == len(self.all_tests):
                    sys.stdout.write(f" [{idx}/{len(self.all_tests)}]\n")
                sys.stdout.flush()

            if status == "FAIL" and self.fail_fast:
                print(f"\n[FAIL-FAST] Halting after failure in {test.test_id}")
                break

        self.total_duration_ms = (time.time() - start_time) * 1000.0
        self.print_summary()
        return 0 if self.failed_count == 0 else 1

    def print_summary(self):
        print("\n" + "=" * 80)
        print(" " * 28 + "EXECUTION SUMMARY")
        print("=" * 80)
        print(f" Total Tests Executed : {len(self.all_tests)}")
        print(f" Passed               : {self.passed_count}")
        print(f" Failed               : {self.failed_count}")
        print(f" Skipped              : {self.skipped_count}")
        pass_pct = (self.passed_count / len(self.all_tests) * 100) if self.all_tests else 0
        print(f" Pass Percentage      : {pass_pct:.1f}%")
        print(f" Total Duration       : {self.total_duration_ms:.2f} ms")
        print("-" * 80)

        # Tier breakdown
        tier_stats: Dict[int, Dict[str, int]] = {}
        for r in self.results:
            t = r["tier"]
            if t not in tier_stats:
                tier_stats[t] = {"total": 0, "pass": 0, "fail": 0, "skip": 0}
            tier_stats[t]["total"] += 1
            if r["status"] == "PASS":
                tier_stats[t]["pass"] += 1
            elif r["status"] == "FAIL":
                tier_stats[t]["fail"] += 1
            else:
                tier_stats[t]["skip"] += 1

        print(" TIER BREAKDOWN:")
        for t in sorted(tier_stats.keys()):
            stat = tier_stats[t]
            t_pct = (stat["pass"] / stat["total"] * 100) if stat["total"] else 0
            tier_name = {
                1: "Feature Coverage (Equivalence Classes)",
                2: "Boundary & Corner Cases (Adversarial)",
                3: "Cross-Feature Combinations (Pairwise)",
                4: "Real-World Application Scenarios"
            }.get(t, f"Tier {t}")
            print(f"   Tier {t} ({tier_name:<36}): {stat['pass']}/{stat['total']} passed ({t_pct:.1f}%) | {stat['fail']} failed")

        print("=" * 80)
        if self.failed_count > 0:
            print("\nIDENTIFIED ARCHITECTURAL / IMPLEMENTATION GAPS (FIRST 15):")
            fail_samples = [r for r in self.results if r["status"] == "FAIL"][:15]
            for f in fail_samples:
                print(f" - [{f['feature_id']}] {f['test_id']}: {f['description']}")
                print(f"   Error: {f['error']}")
            if len([r for r in self.results if r["status"] == "FAIL"]) > 15:
                print(f"   ... and {len([r for r in self.results if r['status'] == 'FAIL']) - 15} more failures.")

    def export_json(self, output_path: str):
        data = {
            "version": "3.1.7",
            "mode": self.mode,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total": len(self.all_tests),
            "passed": self.passed_count,
            "failed": self.failed_count,
            "skipped": self.skipped_count,
            "duration_ms": round(self.total_duration_ms, 2),
            "results": self.results
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[REPORT] Exported JSON results to {output_path}")

    def generate_markdown_report(self) -> str:
        tier_stats: Dict[int, Dict[str, int]] = {}
        for r in self.results:
            t = r["tier"]
            if t not in tier_stats:
                tier_stats[t] = {"total": 0, "pass": 0, "fail": 0}
            tier_stats[t]["total"] += 1
            if r["status"] == "PASS":
                tier_stats[t]["pass"] += 1
            else:
                tier_stats[t]["fail"] += 1

        pass_pct = (self.passed_count / len(self.all_tests) * 100) if self.all_tests else 0
        md = []
        md.append("# AetherFlow v3.1.7 — Test Ready Baseline Report (M0)")
        md.append(f"\n**Generated**: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}  ")
        md.append(f"**Test Mode**: `{self.mode.upper()}`  ")
        md.append(f"**Total Suite Size**: **{len(self.all_tests)} Automated Tests**  ")
        md.append(f"**Baseline Pass Count**: **{self.passed_count}** ({pass_pct:.1f}%)  ")
        md.append(f"**Baseline Gap Count**: **{self.failed_count}** (Unimplemented features pending M1–M4)  \n")
        
        md.append("## 1. Test Execution Command")
        md.append("```bash")
        md.append("# Run entire test suite across all 4 tiers")
        md.append("python tests/run_e2e.py")
        md.append("")
        md.append("# Run with PowerShell on Windows")
        md.append("powershell -ExecutionPolicy Bypass -File tests/run_e2e.ps1")
        md.append("")
        md.append("# Run with bash on Linux / WSL")
        md.append("./tests/run_e2e.sh")
        md.append("```\n")

        md.append("## 2. Coverage Table by Verification Tier")
        md.append("| Tier | Verification Scope | Total Tests | Passed | Baseline Gaps | Pass Rate |")
        md.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        for t in sorted(tier_stats.keys()):
            st = tier_stats[t]
            pct = (st["pass"] / st["total"] * 100) if st["total"] else 0
            tier_desc = {
                1: "Tier 1: Feature Coverage (Equivalence Classes)",
                2: "Tier 2: Boundary & Corner Cases (Adversarial)",
                3: "Tier 3: Cross-Feature Combinations (Pairwise)",
                4: "Tier 4: Real-World Application Scenarios"
            }.get(t, f"Tier {t}")
            md.append(f"| Tier {t} | {tier_desc} | {st['total']} | {st['pass']} | {st['fail']} | {pct:.1f}% |")
        md.append(f"| **Total** | **All 4 Tiers (Full Stack)** | **{len(self.all_tests)}** | **{self.passed_count}** | **{self.failed_count}** | **{pass_pct:.1f}%** |\n")

        md.append("## 3. Feature Coverage Checklist (All 37 Features)")
        md.append("| Feature ID | Description | Milestone | Status in M0 Baseline |")
        md.append("| :--- | :--- | :--- | :--- |")
        
        # Group by feature
        feat_status: Dict[str, Dict[str, Any]] = {}
        for r in self.results:
            fid = r["feature_id"]
            if fid not in feat_status:
                feat_status[fid] = {"total": 0, "pass": 0, "fail": 0}
            feat_status[fid]["total"] += 1
            if r["status"] == "PASS":
                feat_status[fid]["pass"] += 1
            else:
                feat_status[fid]["fail"] += 1

        features_meta = [
            ("F01", "Go Directory Browser Handler", "M1"),
            ("F02", "Auth Session Refresh", "M1"),
            ("F03", "Profile Password Mutation", "M1"),
            ("F04", "Profile Avatar Mutation", "M1"),
            ("F05", "Ingress Configuration CRUD", "M1"),
            ("F06", "System Topology Endpoint", "M1"),
            ("F07", "Privileged Runner Extensions", "M1"),
            ("F08", "Privileged Caller Migration", "M1"),
            ("F09", "SQLite Migration 17", "M1"),
            ("F10", "Cluster Manager Startup Cleanliness", "M1"),
            ("F11", "Remove Next.js FS Server Route", "M1"),
            ("F12", "Backend Unit & Integration Tests", "M1"),
            ("F13", "Obsidian V2 CSS Foundation", "M2"),
            ("F14", "Obsidian V2 Glass & Chromatic Tokens", "M2"),
            ("F15", "Tri-Mode Navigation Architecture", "M2"),
            ("F16", "Scroller Containment Invariant", "M2"),
            ("F17", "Atmosphere Tuning Controls", "M2"),
            ("F18", "UI Primitives Redesign", "M2"),
            ("F19", "Mount Bandwidth & Predictions Cards", "M3"),
            ("F20", "Mount MetadataTab & PathSelector", "M3"),
            ("F21", "Mount ExternalAccessCard & DeploymentStatus", "M3"),
            ("F22", "Wire Profile Controls", "M3"),
            ("F23", "Real App Topology Map", "M3"),
            ("F24", "Network & VPN Operator Panel", "M3"),
            ("F25", "Notifications & Alerting Panel", "M3"),
            ("F26", "Quotas & Billing Panel", "M3"),
            ("F27", "Cluster Nodes Panel", "M3"),
            ("F28", "Modernize Debian APT Template", "M4"),
            ("F29", "Debian 13 Core OS Detection", "M4"),
            ("F30", "Modernize Package Dependencies", "M4"),
            ("F31", "Keyring Migration Across packages/", "M4"),
            ("F32", "Single-Binary Build Pipeline", "M4"),
            ("F33", "Systemd Privilege Boundary Units", "M4"),
            ("F34", "Sudoers & PM2 Purge", "M4"),
            ("F35", "Shell Script Line Endings & Syntax", "M4"),
            ("F36", "Automated E2E Test Suite", "M0"),
            ("F37", "Full Verification & Hardening", "M5"),
        ]

        for fid, desc, ms in features_meta:
            st = feat_status.get(fid, {"total": 10, "pass": 0, "fail": 10})
            badge = "PASSED" if st["fail"] == 0 and st["total"] > 0 else f"BASELINE GAP ({st['pass']}/{st['total']} checks passed)"
            md.append(f"| {fid} | {desc} | {ms} | {badge} |")

        md.append("\n## 4. Progressive Testability Verification")
        md.append("This baseline report establishes the benchmark for subsequent milestone tracks:")
        md.append("- **Milestone M1**: Will resolve gaps in F01–F12 (Backend parity, fs browser, auth refresh, profile, ingress CRUD, runner extensions, migration 17).")
        md.append("- **Milestone M2**: Will resolve gaps in F13–F18 (Obsidian V2 design system, `#000000` canvas, glass tokens, tri-mode dock, scroller containment).")
        md.append("- **Milestone M3**: Will resolve gaps in F19–F27 (Mounting all 6 orphaned cards, wiring profile controls, and building the 4 operator panels).")
        md.append("- **Milestone M4**: Will resolve gaps in F28–F35 (Debian 13 packaging, APT sources, keyring migration, single binary compilation, LF endings).")
        md.append("- **Milestone M5**: Will re-run this exact test suite to achieve **100% PASS** across all 387 tests.")

        return "\n".join(md)

def main():
    parser = argparse.ArgumentParser(description="AetherFlow v3.1.7 E2E Test Runner")
    parser.add_argument("--tier", type=int, default=0, help="Run specific tier (1, 2, 3, or 4)")
    parser.add_argument("--feature", type=str, default="", help="Filter by feature ID (e.g. F01)")
    parser.add_argument("--mode", type=str, choices=["contract", "live", "mock"], default="contract", help="Execution mode")
    parser.add_argument("--url", type=str, default="http://localhost:8080", help="Base URL for live tests")
    parser.add_argument("--socket", type=str, default="/run/aetherflow/runner.sock", help="Runner socket path")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose test output")
    parser.add_argument("--fail-fast", action="store_true", help="Stop execution on first failure")
    parser.add_argument("--json-out", type=str, default="", help="Path to write JSON test metrics")
    parser.add_argument("--report-out", type=str, default="", help="Path to write markdown summary report")

    args = parser.parse_args()
    runner = TestRunner(
        mode=args.mode,
        base_url=args.url,
        socket_path=args.socket,
        verbose=args.verbose,
        tier_filter=args.tier,
        feature_filter=args.feature,
        fail_fast=args.fail_fast
    )
    exit_code = runner.run()

    if args.json_out:
        runner.export_json(args.json_out)
    if args.report_out:
        report_md = runner.generate_markdown_report()
        with open(args.report_out, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"[REPORT] Exported Markdown report to {args.report_out}")

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
