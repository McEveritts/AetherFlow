#!/usr/bin/env python3
"""
AetherFlow v3.1.7 Milestone 5 Live Smoke Test Suite
Verifies:
1. Privileged runner daemon listening on UNIX domain socket in WSL/Linux
2. aetherflow-api single binary serving Next.js SPA HTML at /
3. Health check endpoints (/health/ready)
4. Admin account bootstrap and session lifecycle (/api/v1/public/auth/setup)
5. Session refresh (/api/v1/auth/refresh)
6. Filesystem directory browser (/api/v1/auth/fs?path=/tmp)
7. Ingress routing configs (/api/v1/admin/ingress/configs)
8. System topology (/api/v1/auth/system/topology)
9. Cluster worker nodes (/api/v1/admin/cluster/nodes)
10. Network management status (/api/v1/admin/network/status)
11. User storage disk quotas (/api/v1/admin/quotas)
12. Direct root UNIX socket dispatch (/v1/health via socket)
"""

import sys
import os
import time
import subprocess
import json
import urllib.request
import urllib.parse
import http.cookiejar
import socket

SOCK_PATH = "/tmp/af-runner-test.sock"
DB_PATH = "/tmp/af-smoke.db"
PORT = 18080
BASE_URL = f"http://127.0.0.1:{PORT}"
BINARY_PATH = "/mnt/c/Users/armyw/OneDrive/Documents/Antigravity/AetherFlow/backend/aetherflow-api"

results = []

def record(test_name, passed, detail=""):
    results.append({
        "name": test_name,
        "passed": passed,
        "detail": detail
    })
    mark = "✓ PASS" if passed else "✗ FAIL"
    print(f"[{mark}] {test_name}: {detail}")

class UnixSocketHTTPConnection:
    """Sends raw HTTP request over UNIX domain socket and reads response."""
    @staticmethod
    def request(sock_path, method, path, body=None, headers=None):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(sock_path)
        
        req = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
        if headers:
            for k, v in headers.items():
                req += f"{k}: {v}\r\n"
        if body:
            req += f"Content-Length: {len(body)}\r\n\r\n{body}"
        else:
            req += "\r\n"
            
        s.sendall(req.encode("utf-8"))
        
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        
        # Parse HTTP response
        header_end = resp.find(b"\r\n\r\n")
        if header_end == -1:
            return 500, {}, resp.decode("utf-8", errors="replace")
            
        header_text = resp[:header_end].decode("utf-8", errors="replace")
        body_text = resp[header_end+4:].decode("utf-8", errors="replace")
        
        lines = header_text.split("\r\n")
        status_line = lines[0]
        status_code = int(status_line.split(" ")[1])
        
        res_headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                res_headers[k.strip().lower()] = v.strip()
                
        return status_code, res_headers, body_text

def run_smoke_tests():
    print("=" * 80)
    print("       AETHERFLOW v3.1.7 MILESTONE 5 LIVE SMOKE TEST HARNESS")
    print("=" * 80)
    print(f" Binary       : {BINARY_PATH}")
    print(f" Runner Sock  : {SOCK_PATH}")
    print(f" Temp DB      : {DB_PATH}")
    print(f" HTTP Port    : {PORT}")
    print("-" * 80)
    
    # 0. Cleanup previous artifacts
    if os.path.exists(SOCK_PATH):
        try: os.unlink(SOCK_PATH)
        except Exception: pass
    for ext in ["", "-wal", "-shm"]:
        p = DB_PATH + ext
        if os.path.exists(p):
            try: os.unlink(p)
            except Exception: pass

    # 1. Start Privileged Runner Daemon
    print("[INIT] Launching ./aetherflow-api runner daemon...")
    runner_env = os.environ.copy()
    runner_env["AETHERFLOW_RUNNER_SOCK"] = SOCK_PATH
    runner_proc = subprocess.Popen(
        [BINARY_PATH, "runner"],
        env=runner_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Wait for socket creation
    sock_ready = False
    for _ in range(50):
        if os.path.exists(SOCK_PATH):
            sock_ready = True
            break
        time.sleep(0.1)

    record("Runner Daemon Socket Creation", sock_ready, f"Socket present at {SOCK_PATH}")
    if not sock_ready:
        print("[ERROR] Runner socket failed to create. Aborting.")
        runner_proc.terminate()
        return 1

    # 2. Test Runner Socket Health directly
    try:
        code, h, body = UnixSocketHTTPConnection.request(SOCK_PATH, "GET", "/v1/health")
        data = json.loads(body)
        passed = code == 200 and data.get("success") is True and data.get("output") == "ready"
        record("Runner Socket Direct Health Check (/v1/health)", passed, f"HTTP {code}, payload: {body.strip()}")
    except Exception as e:
        record("Runner Socket Direct Health Check (/v1/health)", False, str(e))

    # 3. Start API Server
    print("[INIT] Launching ./aetherflow-api server on port 18080...")
    server_env = os.environ.copy()
    server_env["PORT"] = str(PORT)
    server_env["DB_PATH"] = DB_PATH
    server_env["AETHERFLOW_RUNNER_SOCK"] = SOCK_PATH
    server_env["CSRF_DISABLED"] = "true"
    server_env["ALLOWED_HOSTS"] = f"127.0.0.1:{PORT},localhost:{PORT},127.0.0.1,localhost"
    server_env["JWT_SECRET"] = "aetherflow-smoke-test-secret-key-32chars-min!!"
    server_env["AF_ALLOWED_FS_ROOTS"] = "/tmp,/mnt,/media,/home,/opt/AetherFlow,/var/lib/aetherflow"

    server_proc = subprocess.Popen(
        [BINARY_PATH],
        env=server_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Wait for server readiness
    server_ready = False
    for _ in range(100):
        try:
            req = urllib.request.Request(f"{BASE_URL}/health/ready")
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    server_ready = True
                    break
        except Exception:
            pass
        time.sleep(0.1)

    record("API Server Ready Check (/health/ready)", server_ready, f"Listening on {BASE_URL}")
    if not server_ready:
        print("[ERROR] Server failed to start. Aborting.")
        server_proc.terminate()
        runner_proc.terminate()
        return 1

    # Set up HTTP CookieJar & opener for session persistence
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    urllib.request.install_opener(opener)

    session_token = ""

    try:
        # Test 1: GET / (Next.js SPA HTML)
        try:
            req = urllib.request.Request(f"{BASE_URL}/", headers={"User-Agent": "AetherSmokeTest/1.0"})
            with opener.open(req, timeout=5.0) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                ctype = resp.headers.get("Content-Type", "")
                has_html = "<!DOCTYPE html>" in body or "<html" in body
                has_spa = "AetherFlow" in body or "_next" in body
                record("GET / (Embedded Next.js SPA HTML)", code == 200 and has_html and has_spa,
                       f"HTTP {code}, Content-Type: {ctype}, Len: {len(body)} bytes")
        except Exception as e:
            record("GET / (Embedded Next.js SPA HTML)", False, str(e))

        # Test 2: GET /health/ready
        try:
            req = urllib.request.Request(f"{BASE_URL}/health/ready")
            with opener.open(req, timeout=5.0) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                record("GET /health/ready", code == 200, f"HTTP {code}, Body: {body.strip()}")
        except Exception as e:
            record("GET /health/ready", False, str(e))

        # Test 3: Setup Admin Account & Session Creation
        try:
            setup_payload = json.dumps({
                "username": "admin",
                "password": "AdminPassword123!"
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{BASE_URL}/api/v1/public/auth/setup",
                data=setup_payload,
                headers={"Content-Type": "application/json", "User-Agent": "AetherSmokeTest/1.0"}
            )
            with opener.open(req, timeout=5.0) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                for c in cookie_jar:
                    if c.name == "aetherflow_session":
                        session_token = c.value
                record("POST /api/v1/public/auth/setup", code == 200 and bool(session_token),
                       f"HTTP {code}, session cookie acquired: {session_token[:16]}...")
        except Exception as e:
            record("POST /api/v1/public/auth/setup", False, str(e))

        auth_headers = {
            "User-Agent": "AetherSmokeTest/1.0",
            "Authorization": f"Bearer {session_token}"
        }

        # Test 4: POST /api/v1/auth/refresh
        try:
            req = urllib.request.Request(
                f"{BASE_URL}/api/v1/auth/refresh",
                data=b"{}",
                headers={"Content-Type": "application/json", **auth_headers}
            )
            with opener.open(req, timeout=5.0) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                if "token" in data:
                    session_token = data["token"]
                    auth_headers["Authorization"] = f"Bearer {session_token}"
                record("POST /api/v1/auth/refresh", code == 200, f"HTTP {code}, Body: {body.strip()}")
        except Exception as e:
            record("POST /api/v1/auth/refresh", False, str(e))

        # Test 5: GET /api/v1/auth/fs?path=/tmp
        try:
            req = urllib.request.Request(
                f"{BASE_URL}/api/v1/auth/fs?path=/tmp",
                headers=auth_headers
            )
            with opener.open(req, timeout=5.0) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                passed = code == 200 and (isinstance(data, list) or "entries" in data or "current_path" in data or "directories" in data)
                entry_count = len(data.get("entries", [])) if isinstance(data, dict) else len(data)
                record("GET /api/v1/auth/fs?path=/tmp", passed, f"HTTP {code}, Entries count: {entry_count}")
        except Exception as e:
            record("GET /api/v1/auth/fs?path=/tmp", False, str(e))

        # Test 6: GET /api/v1/admin/ingress/configs
        try:
            req = urllib.request.Request(
                f"{BASE_URL}/api/v1/admin/ingress/configs",
                headers=auth_headers
            )
            with opener.open(req, timeout=5.0) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                record("GET /api/v1/admin/ingress/configs", code == 200, f"HTTP {code}, Ingress configs response received")
        except Exception as e:
            record("GET /api/v1/admin/ingress/configs", False, str(e))

        # Test 7: GET /api/v1/auth/system/topology
        try:
            req = urllib.request.Request(
                f"{BASE_URL}/api/v1/auth/system/topology",
                headers=auth_headers
            )
            with opener.open(req, timeout=5.0) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                record("GET /api/v1/auth/system/topology", code == 200, f"HTTP {code}, Topology data parsed")
        except Exception as e:
            record("GET /api/v1/auth/system/topology", False, str(e))

        # Test 8: GET /api/v1/admin/cluster/nodes
        try:
            req = urllib.request.Request(
                f"{BASE_URL}/api/v1/admin/cluster/nodes",
                headers=auth_headers
            )
            with opener.open(req, timeout=5.0) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                record("GET /api/v1/admin/cluster/nodes", code == 200, f"HTTP {code}, Cluster nodes response received")
        except Exception as e:
            record("GET /api/v1/admin/cluster/nodes", False, str(e))

        # Test 9: GET /api/v1/admin/network/status
        try:
            req = urllib.request.Request(
                f"{BASE_URL}/api/v1/admin/network/status",
                headers=auth_headers
            )
            with opener.open(req, timeout=5.0) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                record("GET /api/v1/admin/network/status", code == 200, f"HTTP {code}, Network status received")
        except Exception as e:
            record("GET /api/v1/admin/network/status", False, str(e))

        # Test 10: GET /api/v1/admin/quotas
        try:
            req = urllib.request.Request(
                f"{BASE_URL}/api/v1/admin/quotas",
                headers=auth_headers
            )
            with opener.open(req, timeout=5.0) as resp:
                code = resp.status
                body = resp.read().decode("utf-8", errors="replace")
                data = json.loads(body)
                record("GET /api/v1/admin/quotas", code == 200, f"HTTP {code}, User quotas received")
        except Exception as e:
            record("GET /api/v1/admin/quotas", False, str(e))

    finally:
        print("-" * 80)
        print("[CLEANUP] Stopping API server...")
        server_out, server_err = b"", b""
        try:
            server_proc.terminate()
            server_out, server_err = server_proc.communicate(timeout=5)
        except Exception:
            server_proc.kill()
            server_out, server_err = server_proc.communicate()

        if server_err:
            print("[SERVER STDERR]:\n" + server_err.decode("utf-8", errors="replace"))
        if server_out:
            print("[SERVER STDOUT]:\n" + server_out.decode("utf-8", errors="replace"))

        print("[CLEANUP] Stopping Runner daemon...")
        runner_proc.terminate()
        try:
            runner_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            runner_proc.kill()

        if os.path.exists(SOCK_PATH):
            try: os.unlink(SOCK_PATH)
            except Exception: pass
        for ext in ["", "-wal", "-shm"]:
            p = DB_PATH + ext
            if os.path.exists(p):
                try: os.unlink(p)
                except Exception: pass

    print("=" * 80)
    print("                     SMOKE TEST SUMMARY")
    print("=" * 80)
    passed_all = True
    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        if not r["passed"]:
            passed_all = False
        print(f"[{status:4s}] {r['name']:<50} | {r['detail']}")
    print("-" * 80)
    print(f"Result: {len([r for r in results if r['passed']])} / {len(results)} PASSED")
    print("=" * 80)

    return 0 if passed_all else 1

if __name__ == "__main__":
    sys.exit(run_smoke_tests())
