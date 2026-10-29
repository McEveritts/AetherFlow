#!/usr/bin/env python3
"""
AetherFlow v3.1.7 Shell Script Hygiene & Security Verifier
Checks:
1. Syntax validation via `bash -n` across all shell scripts in the codebase
2. Zero active `apt-key` invocations
3. Zero `NOPASSWD: ALL` sudoers permissions
"""

import os
import sys
import subprocess
import re

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def is_shell_script(filepath):
    if filepath.endswith(".sh"):
        return True
    filename = os.path.basename(filepath)
    if "installpackage" in filename or "removepackage" in filename or filename == "updateAetherFlow":
        return True
    try:
        with open(filepath, "rb") as f:
            first_line = f.readline()
            if first_line.startswith(b"#!") and (b"bash" in first_line or b"sh" in first_line):
                return True
    except Exception:
        pass
    return False

def discover_scripts():
    scripts = []
    scan_dirs = ["setup", "deploy", "packages", "scripts", "bin"]
    for d in scan_dirs:
        dir_path = os.path.join(ROOT_DIR, d)
        if not os.path.exists(dir_path):
            continue
        for r, _, files in os.walk(dir_path):
            for f in files:
                p = os.path.join(r, f)
                if is_shell_script(p):
                    scripts.append(p)
    return sorted(list(set(scripts)))

def main():
    print("=" * 80)
    print("       AETHERFLOW v3.1.7 SHELL SCRIPT HYGIENE VERIFIER")
    print("=" * 80)
    
    scripts = discover_scripts()
    print(f" Discovered shell scripts: {len(scripts)}")
    print("-" * 80)

    # 1. bash -n syntax check
    syntax_fails = []
    for s in scripts:
        rel = os.path.relpath(s, ROOT_DIR)
        res = subprocess.run(["bash", "-n", s], capture_output=True, text=True)
        if res.returncode != 0:
            syntax_fails.append((rel, res.stderr.strip()))

    print(f" [bash -n] Checked {len(scripts)} scripts. Failures: {len(syntax_fails)}")
    for rel, err in syntax_fails:
        print(f"   ✗ FAIL: {rel}: {err}")

    # 2. Check for active apt-key calls
    apt_key_pattern = re.compile(r"^\s*apt-key\s+", re.MULTILINE)
    apt_key_violations = []
    for s in scripts:
        rel = os.path.relpath(s, ROOT_DIR)
        try:
            with open(s, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for line_no, line in enumerate(content.splitlines(), 1):
                    line_clean = line.strip()
                    if line_clean.startswith("#"):
                        continue
                    if "apt-key " in line_clean or "apt-key\t" in line_clean:
                        # verify not in a harmless echo/comment
                        if re.search(r"\bapt-key\s+(add|adv|del|list|export)", line_clean):
                            apt_key_violations.append((rel, line_no, line_clean))
        except Exception as e:
            print(f"   Error reading {rel}: {e}")

    print(f" [apt-key] Active invocations found: {len(apt_key_violations)}")
    for rel, lno, line in apt_key_violations:
        print(f"   ✗ VIOLATION: {rel}:{lno} -> {line}")

    # 3. Check for NOPASSWD: ALL in sudoers/scripts
    sudoers_violations = []
    for s in scripts:
        rel = os.path.relpath(s, ROOT_DIR)
        try:
            with open(s, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                for line_no, line in enumerate(content.splitlines(), 1):
                    line_clean = line.strip()
                    if line_clean.startswith("#"):
                        continue
                    if "NOPASSWD: ALL" in line or "NOPASSWD:ALL" in line:
                        sudoers_violations.append((rel, line_no, line_clean))
        except Exception as e:
            pass

    print(f" [sudoers] NOPASSWD: ALL rules found: {len(sudoers_violations)}")
    for rel, lno, line in sudoers_violations:
        print(f"   ✗ VIOLATION: {rel}:{lno} -> {line}")

    print("-" * 80)
    passed = len(syntax_fails) == 0 and len(apt_key_violations) == 0 and len(sudoers_violations) == 0
    status = "SUCCESS - ALL CHECKS PASSED" if passed else "FAILED - VIOLATIONS DETECTED"
    print(f" RESULT: {status}")
    print("=" * 80)
    return 0 if passed else 1

if __name__ == "__main__":
    sys.exit(main())
