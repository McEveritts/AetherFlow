#!/usr/bin/env python3
"""
AetherFlow v3.1.7 E2E Test Suite Entrypoint
Usage:
  python tests/run_e2e.py
  python tests/run_e2e.py --tier 1
  python tests/run_e2e.py --feature F01
  python tests/run_e2e.py --mode live --url http://localhost:8080
"""
import sys
import os

# Add project root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tests.e2e.runner import main

if __name__ == "__main__":
    main()
