#!/usr/bin/env python3
"""Compatibility shim delegating legacy af-sentinel.py to native `af sentinel`."""

import os
import sys

CANDIDATES = [
    os.environ.get("AETHERFLOW_CLI_BIN", ""),
    "/opt/AetherFlow/current/bin/af",
    "/opt/AetherFlow/current/af",
    "/usr/local/bin/af-cli",
    "/opt/AetherFlow/bin/af-cli",
    "/usr/local/bin/af",
]

for af_bin in CANDIDATES:
    if not af_bin or not os.path.isfile(af_bin) or not os.access(af_bin, os.X_OK):
        continue
    if af_bin == "/usr/local/bin/af":
        try:
            with open(af_bin, "rb") as fh:
                if b"/usr/local/bin/AetherFlow/system/af" in fh.read(4096):
                    continue
        except OSError:
            continue
    os.execv(af_bin, [af_bin, "sentinel", *sys.argv[1:]])

sys.stderr.write("Native AetherFlow CLI binary (/usr/local/bin/af) not found.\n")
sys.exit(1)
