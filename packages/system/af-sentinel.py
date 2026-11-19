#!/usr/bin/env python3
"""Compatibility shim delegating legacy af-sentinel.py to native `af sentinel`."""

import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SELF_REAL = os.path.realpath(__file__)
LEGACY_AF_REALS = {
    os.path.realpath(path)
    for path in (
        "/opt/AetherFlow/packages/system/af",
        "/opt/AetherFlow/current/packages/system/af",
        "/usr/local/bin/AetherFlow/system/af",
        os.path.join(SCRIPT_DIR, "af"),
    )
}
EXPLICIT_CLI = os.environ.get("AETHERFLOW_CLI_BIN", "")

CANDIDATES = [
    EXPLICIT_CLI,
    "/opt/AetherFlow/current/bin/af",
    "/opt/AetherFlow/current/af",
    "/usr/local/bin/af-cli",
    "/opt/AetherFlow/bin/af-cli",
    "/usr/local/bin/af",
]

for af_bin in CANDIDATES:
    if not af_bin or not os.path.isfile(af_bin) or not os.access(af_bin, os.X_OK):
        continue
    real_bin = os.path.realpath(af_bin)
    if real_bin == SELF_REAL or real_bin in LEGACY_AF_REALS:
        continue
    if af_bin != EXPLICIT_CLI:
        try:
            with open(af_bin, "rb") as fh:
                is_elf = fh.read(4) == b"\x7fELF"
        except OSError:
            continue
        if not is_elf:
            try:
                res = subprocess.run(
                    [af_bin, "--version"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                if res.returncode != 0:
                    continue
            except Exception:
                continue
    os.execv(af_bin, [af_bin, "sentinel", *sys.argv[1:]])

sys.stderr.write("Native AetherFlow CLI binary (/usr/local/bin/af) not found.\n")
sys.exit(1)
