"""
AetherFlow v3.1.7 E2E Test Framework
Provides test case abstractions, assertion helpers, codebase contract inspectors,
HTTP/socket clients, and mock test servers.
"""

import os
import sys
import re
import json
import time
import socket
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar
from typing import Dict, List, Any, Optional, Tuple, Callable

# Project root directory
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

class TestFailure(Exception):
    """Raised when an assertion fails."""
    pass

class TestSkip(Exception):
    """Raised when a test is skipped."""
    pass

class TestCase:
    """Base class for all E2E test cases."""
    def __init__(self, test_id: str, feature_id: str, tier: int, description: str):
        self.test_id = test_id
        self.feature_id = feature_id
        self.tier = tier
        self.description = description
        self.passed = False
        self.skipped = False
        self.error_message = ""
        self.duration_ms = 0.0

    def assert_equal(self, actual: Any, expected: Any, msg: str = ""):
        if actual != expected:
            raise TestFailure(f"{msg} Expected '{expected}', got '{actual}'" if msg else f"Expected '{expected}', got '{actual}'")

    def assert_true(self, condition: bool, msg: str = ""):
        if not condition:
            raise TestFailure(msg or "Condition evaluated to False")

    def assert_false(self, condition: bool, msg: str = ""):
        if condition:
            raise TestFailure(msg or "Condition evaluated to True")

    def assert_in(self, item: Any, container: Any, msg: str = ""):
        if item not in container:
            raise TestFailure(f"{msg} Item '{item}' not found in container" if msg else f"Item '{item}' not found in container")

    def assert_not_in(self, item: Any, container: Any, msg: str = ""):
        if item in container:
            raise TestFailure(f"{msg} Item '{item}' unexpectedly found in container" if msg else f"Item '{item}' unexpectedly found in container")

    def assert_regex(self, text: str, pattern: str, msg: str = ""):
        if not re.search(pattern, text):
            raise TestFailure(f"{msg} Text does not match pattern '{pattern}'" if msg else f"Text does not match pattern '{pattern}'")

    def assert_status_code(self, actual_code: int, expected_code: int, msg: str = ""):
        if actual_code != expected_code:
            raise TestFailure(f"{msg} Expected HTTP status {expected_code}, got {actual_code}" if msg else f"Expected HTTP status {expected_code}, got {actual_code}")

    def skip(self, reason: str):
        raise TestSkip(reason)

    def run(self, inspector: 'CodebaseInspector', client: 'AetherFlowApiClient', mode: str = "contract"):
        raise NotImplementedError("Subclasses must implement run()")

class CodebaseInspector:
    """
    Analyzes project source files to verify interface contracts, route registrations,
    design tokens, systemd units, shell script syntax, and migrations.
    """
    def __init__(self, root: str = PROJECT_ROOT):
        self.root = root

    def read_file(self, rel_path: str) -> Optional[str]:
        full_path = os.path.join(self.root, rel_path)
        if not os.path.exists(full_path):
            return None
        try:
            with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return None

    def read_bytes(self, rel_path: str) -> Optional[bytes]:
        full_path = os.path.join(self.root, rel_path)
        if not os.path.exists(full_path):
            return None
        try:
            with open(full_path, "rb") as f:
                return f.read()
        except Exception:
            return None

    def file_exists(self, rel_path: str) -> bool:
        return os.path.exists(os.path.join(self.root, rel_path))

    def has_crlf_endings(self, rel_path: str) -> bool:
        content = self.read_bytes(rel_path)
        if content is None:
            return False
        return b"\r\n" in content

    def check_route_registered(self, method: str, path_pattern: str) -> bool:
        routes_content = self.read_file("backend/api/routes.go")
        if not routes_content:
            return False
        pattern = re.compile(rf'\.{method}\s*\(\s*"{re.escape(path_pattern)}"', re.IGNORECASE)
        return bool(pattern.search(routes_content))

    def check_go_symbol(self, rel_path: str, symbol_pattern: str) -> bool:
        content = self.read_file(rel_path)
        if not content:
            return False
        return bool(re.search(symbol_pattern, content))

    def check_css_token(self, rel_path: str, token_name: str) -> bool:
        content = self.read_file(rel_path)
        if not content:
            return False
        return token_name in content

    def check_frontend_component_imported(self, component_name: str, parent_file: str) -> bool:
        content = self.read_file(parent_file)
        if not content:
            return False
        return component_name in content

    def get_all_shell_scripts(self) -> List[str]:
        scripts = []
        for d in ["setup", "deploy", "packages"]:
            dir_path = os.path.join(self.root, d)
            if not os.path.exists(dir_path):
                continue
            for r, _, files in os.walk(dir_path):
                for f in files:
                    if f.endswith(".sh") or "installpackage" in f or "removepackage" in f or f == "updateAetherFlow":
                        rel_path = os.path.relpath(os.path.join(r, f), self.root)
                        scripts.append(rel_path)
        return scripts

class AetherFlowApiClient:
    """HTTP client for communicating with live or mock AetherFlow API server."""
    def __init__(self, base_url: str = "http://localhost:8080"):
        self.base_url = base_url.rstrip("/")
        self.cookie_jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.cookie_jar))
        self.jwt_token: Optional[str] = None
        self.csrf_token: Optional[str] = None
        self.auth_username: str = "admin"
        self.auth_password: str = "password"

    def ensure_live_authenticated(self) -> bool:
        """Resolves credentials from env or /root/information.info, bootstraps admin if needed, and logs in."""
        username = os.environ.get("AETHERFLOW_E2E_USER") or os.environ.get("AETHERFLOW_USERNAME")
        password = os.environ.get("AETHERFLOW_E2E_PASS") or os.environ.get("AETHERFLOW_PASSWORD")
        if (not username or not password) and os.path.exists("/root/information.info"):
            try:
                with open("/root/information.info", "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("Admin Username:"):
                            username = username or line.split(":", 1)[1].strip()
                        elif line.startswith("Admin Password:"):
                            password = password or line.split(":", 1)[1].strip()
            except Exception:
                pass
        self.auth_username = username or "admin"
        self.auth_password = password or "password"

        # Seed initial admin if the database has no users yet (returns 409 if already seeded)
        self.request("POST", "/api/v1/public/auth/setup", {
            "username": self.auth_username,
            "password": self.auth_password,
        })

        code, resp, _ = self.request("POST", "/api/v1/public/auth/login", {
            "username": self.auth_username,
            "password": self.auth_password,
        })
        if code == 200:
            token = resp.get("token")
            if token:
                self.set_auth_token(token)
            csrf = resp.get("csrf_token")
            if csrf:
                self.set_csrf_token(csrf)
            return True
        return False

    def set_auth_token(self, token: str):
        self.jwt_token = token

    def set_csrf_token(self, token: str):
        self.csrf_token = token

    def request(self, method: str, path: str, json_body: Optional[Dict[str, Any]] = None,
                headers: Optional[Dict[str, str]] = None, timeout: float = 5.0) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
        url = f"{self.base_url}{path}"
        req_headers = {"User-Agent": "AetherFlow-E2E-Harness/3.1.7"}
        if headers:
            req_headers.update(headers)

        if self.jwt_token:
            req_headers["Authorization"] = f"Bearer {self.jwt_token}"
        if self.csrf_token:
            req_headers["X-CSRF-Token"] = self.csrf_token

        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=req_headers, method=method.upper())
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                resp_code = resp.status
                resp_headers = dict(resp.headers)
                resp_data = resp.read().decode("utf-8")
                try:
                    resp_json = json.loads(resp_data)
                except Exception:
                    resp_json = {"raw": resp_data}
                return resp_code, resp_json, resp_headers
        except urllib.error.HTTPError as e:
            err_code = e.code
            err_headers = dict(e.headers)
            err_data = e.read().decode("utf-8")
            try:
                err_json = json.loads(err_data)
            except Exception:
                err_json = {"raw": err_data}
            return err_code, err_json, err_headers
        except Exception as e:
            return 0, {"error": str(e)}, {}

    def is_server_reachable(self, timeout: float = 1.0) -> bool:
        code, _, _ = self.request("GET", "/health/ready", timeout=timeout)
        return code in [200, 404]

class RunnerSocketClient:
    """Client for testing privileged runner UNIX domain socket or mock interface."""
    def __init__(self, socket_path: str = "/run/aetherflow/runner.sock"):
        self.socket_path = socket_path

    def is_socket_present(self) -> bool:
        return os.path.exists(self.socket_path)

    def send_socket_request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Tuple[int, str]:
        if not self.is_socket_present():
            return 0, "Socket file does not exist"
        if not hasattr(socket, "AF_UNIX"):
            return 0, "AF_UNIX not supported on this platform"
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            sock.connect(self.socket_path)
            body = json.dumps(payload).encode("utf-8") if payload else b""
            req_bytes = f"{method.upper()} {path} HTTP/1.1\r\nHost: runner.sock\r\nContent-Length: {len(body)}\r\nContent-Type: application/json\r\n\r\n".encode("utf-8") + body
            sock.sendall(req_bytes)
            res = sock.recv(8192).decode("utf-8", errors="replace")
            sock.close()
            parts = res.split("\r\n\r\n", 1)
            header_lines = parts[0].split("\r\n")
            status_code = int(header_lines[0].split(" ")[1])
            body_res = parts[1] if len(parts) > 1 else ""
            return status_code, body_res
        except Exception as e:
            return 0, str(e)
