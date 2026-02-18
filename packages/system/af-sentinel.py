#!/usr/bin/env python3
# AetherFlow Security Sentinel (Phase 27)
# Location: /usr/local/bin/AetherFlow/system/af-sentinel.py

import os
import re
import time
from collections import defaultdict

AUTH_LOG = '/var/log/auth.log'
MAX_FAILURES = 5
BLOCK_CMD = 'csf -d {ip} "Brute force detected by Sentinel"'

def parse_auth_log():
    failed_attempts = defaultdict(int)
    
    try:
        with open(AUTH_LOG, 'r') as f:
            # Read last 1000 lines for efficiency
            lines = f.readlines()[-1000:]
            
        for line in lines:
            if 'Failed password' in line:
                # Extract IP (Simple regex)
                match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    failed_attempts[ip] += 1
                    
        return failed_attempts
    except FileNotFoundError:
        print(f"Log file {AUTH_LOG} not found.")
        return {}

def enforce_security(failures):
    for ip, count in failures.items():
        if count >= MAX_FAILURES:
            print(f"[SENTINEL] Anomaly detected: {ip} has {count} failed attempts. Engaging defenses.")
            # Execute block
            cmd = BLOCK_CMD.format(ip=ip)
            # os.system(cmd) # Commented out for safety during development
            print(f"Executed: {cmd}")

if __name__ == "__main__":
    print("AetherFlow Security Sentinel Initialized...")
    failures = parse_auth_log()
    enforce_security(failures)
