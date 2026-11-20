import hashlib
import hmac
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
import yaml

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11 (e.g. Ubuntu 22.04 Python 3.10)
    tomllib = None  # type: ignore[assignment]

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import common_functions, replace_paths_once

ROOT = Path(__file__).resolve().parent.parent


def _resolve_openable_tmp_root() -> str:
    cand = Path(tempfile.gettempdir()).resolve()
    if all(os.access(p, os.R_OK | os.X_OK) for p in (cand, *cand.parents)):
        return str(cand)
    if Path("/tmp").is_dir() and os.access("/tmp", os.R_OK | os.W_OK | os.X_OK):
        return str(Path("/tmp").resolve())
    return str(cand)


RESOLVED_TMP_ROOT = _resolve_openable_tmp_root()


def _extract_router_routes(code: str) -> list[tuple[str, list[str]]]:
    out: list[tuple[str, list[str]]] = []
    idx = 0
    while True:
        pos = code.find(".route(", idx)
        if pos == -1:
            break
        depth = 0
        end = pos + 6
        in_str = False
        while end < len(code):
            ch = code[end]
            if ch == '"' and code[end - 1] != "\\":
                in_str = not in_str
            elif not in_str:
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        end += 1
                        break
            end += 1
        call = code[pos:end]
        idx = end
        m_path = re.search(
            r'\.route\(\s*(?:"([^"]+)"|crate::streaming_portability::([A-Z_]+))\s*,',
            call,
        )
        if not m_path:
            continue
        if m_path.group(1):
            p = m_path.group(1)
        else:
            const_map = {
                "EXPORT_ROUTE": "/streaming/portability/export",
                "PREVIEW_ROUTE": "/streaming/portability/preview",
                "RESTORE_ROUTE": "/streaming/portability/restore",
            }
            p = const_map[m_path.group(2)]
        methods = sorted(set(re.findall(r"\b(get|post|put|delete|patch|head)\s*\(", call)))
        out.append((p, methods))
    return out


def _parse_gitleaks_toml_fallback(raw: str) -> dict:
    """Minimal TOML subset parser for .gitleaks.toml so Python 3.10 (no stdlib tomllib) runs cleanly."""

    def decode_str(token: str) -> str:
        token = token.strip()
        if token.startswith("'''") and token.endswith("'''"):
            body = token[3:-3]
            return body[1:] if body.startswith("\n") else body
        if token.startswith('"""') and token.endswith('"""'):
            body = token[3:-3]
            return body[1:] if body.startswith("\n") else body
        if token.startswith("'") and token.endswith("'"):
            return token[1:-1]
        if token.startswith('"') and token.endswith('"'):
            return json.loads(token)
        if token == "true":
            return True  # type: ignore[return-value]
        if token == "false":
            return False  # type: ignore[return-value]
        raise ValueError(f"Unsupported TOML scalar in .gitleaks.toml: {token!r}")

    def parse_array(expr: str) -> list[str]:
        inner = expr.strip()[1:-1]
        items: list[str] = []
        token_re = re.compile(r"'''[\s\S]*?'''|\"\"\"[\s\S]*?\"\"\"|'[^']*'|\"(?:\\.|[^\"\\])*\"")
        for m in token_re.finditer(inner):
            items.append(decode_str(m.group(0)))
        return items

    root_doc: dict = {}
    current_target: dict = root_doc
    lines = raw.splitlines()
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()
        i += 1
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "[[rules]]":
            rule: dict = {}
            root_doc.setdefault("rules", []).append(rule)
            current_target = rule
            continue
        if stripped == "[[rules.allowlists]]":
            allow: dict = {}
            root_doc["rules"][-1].setdefault("allowlists", []).append(allow)
            current_target = allow
            continue
        if stripped.startswith("[") and stripped.endswith("]") and not stripped.startswith("[["):
            section = stripped[1:-1].strip()
            current_target = root_doc.setdefault(section, {})
            continue
        if "=" in stripped:
            key, val = stripped.split("=", 1)
            key = key.strip()
            val = val.strip()
            if val.startswith("["):
                while not val.rstrip().endswith("]") and i < len(lines):
                    line_part = lines[i].strip()
                    i += 1
                    if line_part and not line_part.startswith("#"):
                        val += "\n" + line_part
                current_target[key] = parse_array(val)
            else:
                current_target[key] = decode_str(val)
    return root_doc


class TestZeroGoCutoverInvariants(unittest.TestCase):
    """Verify AetherFlow Zero-Go cutover invariants across repo, CI workflows, OpenAPI, and scripts."""

    def test_git_has_no_tracked_go_files(self) -> None:
        proc = subprocess.run(
            ["git", "ls-files", "*.go", "*go.mod", "*go.sum"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        )
        tracked = [line for line in proc.stdout.splitlines() if line.strip()]
        self.assertEqual(
            tracked,
            [],
            f"Zero-Go invariant violated: tracked Go files still present: {tracked}",
        )

    def test_legacy_go_directories_are_removed(self) -> None:
        for rel in (
            "backend",
            "plugins/sdk-template",
            "packages/package/assets/librespeed/backend-patches",
        ):
            self.assertFalse(
                (ROOT / rel).exists(),
                f"Legacy Go directory still exists after cutover: {rel}",
            )

    def test_canonical_root_config_and_openapi_assets_exist(self) -> None:
        for rel in (
            "config/packages.json",
            "config/package_automation.json",
            "config/openapi-v1.yaml",
        ):
            path = ROOT / rel
            self.assertTrue(path.is_file(), f"Missing canonical root config asset: {rel}")
            if path.suffix == ".json":
                parsed = json.loads(path.read_text(encoding="utf-8"))
                self.assertTrue(parsed, f"Expected non-empty JSON asset: {rel}")

        openapi_raw = (ROOT / "config/openapi-v1.yaml").read_text(encoding="utf-8")
        self.assertNotIn("NON-AUTHORITATIVE", openapi_raw)

    def test_openapi_v1_route_parity_with_rust_router(self) -> None:
        routes_rs = (ROOT / "backend-rs/crates/af-api/src/routes.rs").read_text(encoding="utf-8")
        v1_sec = routes_rs.split("fn build_v1_router() -> Router {", 1)[1].split("\n}\n", 1)[0]

        blocks = {}
        for name in (
            "auth_limited_public",
            "oidc_limited_public",
            "public_routes",
            "ai_limited_auth",
            "auth_routes",
            "quota_guarded_upload",
            "admin_routes",
            "compat_routes",
            "ingress_compat_routes",
        ):
            m = re.search(rf"let {name}\s*=\s*Router::new\(\)(.*?);", v1_sec, re.S)
            blocks[name] = _extract_router_routes(m.group(1)) if m else []

        mcb_auth: list[tuple[str, list[str]]] = []
        mcb_pub: list[tuple[str, list[str]]] = []
        mcb_files = sorted((ROOT / "backend-rs/crates/af-api/src").glob("mcbrowser*.rs")) + sorted(
            (ROOT / "backend-rs/crates/af-api/src/mcbrowser").glob("*.rs")
        )
        for f in mcb_files:
            txt = f.read_text(encoding="utf-8")
            if f.name == "shares.rs":
                p1 = txt.split("fn router_with_runtime", 1)[1].split("fn public_router_with_runtime", 1)[0]
                p2 = txt.split("fn public_router_with_runtime", 1)[1].split("// ───", 1)[0]
                mcb_auth.extend(_extract_router_routes(p1))
                mcb_pub.extend(_extract_router_routes(p2))
            else:
                for fn_m in re.finditer(
                    r"pub(?:\([^)]*\))?\s+fn\s+router\(\)\s*->\s*Router\s*\{(.*?)\n\}",
                    txt,
                    re.S,
                ):
                    mcb_auth.extend(_extract_router_routes(fn_m.group(1)))

        expected: dict[str, set[str]] = {}

        def add(prefix: str, items: list[tuple[str, list[str]]]) -> None:
            for p, ms in items:
                fp = re.sub(r":([A-Za-z0-9_]+)", r"{\1}", prefix + p)
                fp = re.sub(r"\*([A-Za-z0-9_]+)", r"{\1}", fp)
                expected.setdefault(fp, set()).update(ms)

        add("/public", blocks["public_routes"] + blocks["auth_limited_public"] + blocks["oidc_limited_public"] + mcb_pub)
        add("/auth", blocks["auth_routes"] + blocks["ai_limited_auth"] + mcb_auth)
        add("/admin", blocks["admin_routes"] + blocks["quota_guarded_upload"])
        add("", blocks["compat_routes"] + blocks["ingress_compat_routes"])

        spec = yaml.safe_load((ROOT / "config/openapi-v1.yaml").read_text(encoding="utf-8"))
        documented: dict[str, set[str]] = {}
        for path_key, path_item in spec.get("paths", {}).items():
            methods = {
                k for k in path_item.keys() if k in {"get", "post", "put", "delete", "patch", "head"}
            }
            documented[path_key] = methods

        self.assertEqual(documented, expected)

        backup_item = spec["paths"]["/admin/backup/download/{filename}"]
        for method in ("post", "get"):
            param_names = {
                p.get("name")
                for p in backup_item[method].get("parameters", [])
                if isinstance(p, dict) and "name" in p
            }
            for stepup_hdr in ("X-Reauth-Password", "X-Reauth-TOTP", "X-Reauth-Confirm"):
                self.assertIn(stepup_hdr, param_names, f"{method.upper()} missing {stepup_hdr}")

    def test_api_docs_v1_routes_exist_in_openapi_spec(self) -> None:
        api_md = (ROOT / "docs/API.md").read_text(encoding="utf-8")
        spec = yaml.safe_load((ROOT / "config/openapi-v1.yaml").read_text(encoding="utf-8"))
        openapi_paths = set((spec.get("paths") or {}).keys())

        table_routes = re.findall(
            r"^\|\s*`[^`]+`\s*\|\s*`(/api/v1/[^`\s]+)`\s*\|",
            api_md,
            re.MULTILINE,
        )
        inline_routes = re.findall(
            r"`(?:(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+|wss?://<host>)(/api/v1/[^`\s?]+)",
            api_md,
        )
        documented_routes = sorted(set(table_routes + inline_routes))
        self.assertTrue(documented_routes, "Expected at least one /api/v1 route in docs/API.md")

        missing: list[str] = []
        for raw_route in documented_routes:
            rel = raw_route[len("/api/v1") :]
            normalized = re.sub(r":([A-Za-z0-9_]+)", r"{\1}", rel)
            if normalized not in openapi_paths:
                missing.append(f"{raw_route} -> {normalized}")

        self.assertEqual(
            missing,
            [],
            f"Routes documented in docs/API.md missing from config/openapi-v1.yaml: {missing}",
        )

    def test_rust_librespeed_and_external_wasm_assets_present(self) -> None:
        librespeed_toml = ROOT / "backend-rs/crates/af-librespeed/Cargo.toml"
        self.assertTrue(
            librespeed_toml.is_file(),
            "Missing native Rust LibreSpeed crate: backend-rs/crates/af-librespeed/Cargo.toml",
        )
        toml_text = librespeed_toml.read_text(encoding="utf-8")
        self.assertIn("speedtest-backend", toml_text)

        embed_rs = (ROOT / "backend-rs/crates/af-api/src/embed.rs").read_text(encoding="utf-8")
        self.assertIn("web/dist", embed_rs)
        self.assertNotIn("backend/web/dist", embed_rs)
        api_manifest = (ROOT / "backend-rs/crates/af-api/Cargo.toml").read_text(encoding="utf-8")
        self.assertNotIn("rust-embed", api_manifest)
        stage_script = (ROOT / "scripts/build_wasm_frontend.sh").read_text(encoding="utf-8")
        self.assertNotIn("LEGACY_EMBED_DIST_DIR", stage_script)

    def test_workflows_are_pure_rust_and_enforce_zero_go_hygiene(self) -> None:
        banned = (
            "actions/setup-go",
            "govulncheck",
            "staticcheck",
            "gosec",
            "backend/web/dist",
            "backend/config",
        )
        for name in ("ci.yml", "release.yml", "security.yml"):
            text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            for token in banned:
                self.assertNotIn(token, text, f"{name} must not reference legacy token {token!r}")
            self.assertIn("git ls-files '*.go' '*go.mod' '*go.sum'", text)
            self.assertIn("-p af-librespeed", text)
            if name in ("ci.yml", "release.yml"):
                self.assertIn("speedtest-backend", text)
                self.assertIn("plugins/sdk-template-rust/backend/Cargo.toml", text)
            if name == "security.yml":
                self.assertIn("plugins/sdk-template-rust/backend/Cargo.lock", text)

        self.assertTrue(
            (ROOT / "plugins/sdk-template-rust/backend/Cargo.lock").is_file(),
            "Missing committed Cargo.lock for plugins/sdk-template-rust/backend",
        )

        rel_text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn('AF_BUILD_VERSION="${RELEASE_TAG#v}"', rel_text)
        self.assertIn("aarch64-unknown-linux-gnu", rel_text)
        self.assertIn("armv7-unknown-linux-gnueabihf", rel_text)
        self.assertIn('${extra_tar}.sigstore.json', rel_text)

    def test_gitleaks_go_allowlists_are_commit_pinned(self) -> None:
        raw = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        fallback_cfg = _parse_gitleaks_toml_fallback(raw)
        if tomllib is not None:
            cfg = tomllib.loads(raw)
            self.assertEqual(fallback_cfg, cfg)
        else:
            cfg = fallback_cfg
        for rule in cfg.get("rules", []):
            for allow in rule.get("allowlists", []):
                paths = allow.get("paths", [])
                if any("backend/" in p and r"\.go" in p for p in paths):
                    commits = allow.get("commits", [])
                    self.assertTrue(
                        commits,
                        f"Gitleaks Go allowlist must be scoped to historical commits: {allow}",
                    )

    def test_installpackage_librespeed_security_and_provenance_contracts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-ls-cutover-", dir=RESOLVED_TMP_ROOT) as tmp:
            root = Path(tmp)
            for rel in (
                "bin",
                "opt/AetherFlow/packages",
                "opt/AetherFlow/deploy",
                "var/log/aetherflow",
                "etc/systemd/system",
                "install",
                "tmp",
                "opt",
            ):
                (root / rel).mkdir(parents=True, exist_ok=True)

            # Build a synthetic speedtest-backend archive (v4.1.0)
            tar_buf = io.BytesIO()
            bin_script = b'#!/bin/sh\nif [ "${1:-}" = "--version" ]; then echo "speedtest-backend 4.1.0"; fi\nexit 0\n'
            with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
                ti = tarfile.TarInfo("speedtest-backend")
                ti.size = len(bin_script)
                ti.mode = 0o755
                tf.addfile(ti, io.BytesIO(bin_script))
            archive_bytes = tar_buf.getvalue()
            expected_sha256 = hashlib.sha256(archive_bytes).hexdigest()
            (root / "release.tar.gz").write_bytes(archive_bytes)
            (root / "SHA256SUMS").write_text(
                f"{expected_sha256}  speedtest-backend_4.1.0_linux_amd64.tar.gz\n",
                encoding="utf-8",
            )
            (root / "release.sigstore.json").write_text('{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}')

            # Stage a stale local 4.0.0 binary to verify AF_TARGET_VERSION=4.1.0 skips it
            stale_local = root / "opt/AetherFlow/bin/speedtest-backend"
            stale_local.parent.mkdir(parents=True, exist_ok=True)
            stale_local.write_text('#!/bin/sh\nif [ "${1:-}" = "--version" ]; then echo "speedtest-backend 4.0.0"; fi\nexit 0\n')
            stale_local.chmod(0o755)

            # Mock host commands
            host_cmd = r'''#!/usr/bin/python3
import json, os, pathlib, shutil, subprocess, sys
root = pathlib.Path(os.environ["TEST_ROOT"])
cmd, args = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
with (root / "commands.jsonl").open("a") as f:
    f.write(json.dumps([cmd, *args]) + "\n")
if cmd == "dpkg":
    if "--compare-versions" in args:
        if os.path.exists("/usr/bin/dpkg"):
            sys.exit(subprocess.run(["/usr/bin/dpkg", *args]).returncode)
        idx = args.index("--compare-versions")
        v1, op, v2 = args[idx + 1], args[idx + 2], args[idx + 3]
        def _deb_split(ver: str):
            epoch = 0
            if ":" in ver:
                ep, ver = ver.split(":", 1)
                epoch = int(ep or 0)
            if "-" in ver:
                upstream, rev = ver.rsplit("-", 1)
            else:
                upstream, rev = ver, ""
            return epoch, upstream, rev
        def _deb_order(ch: str) -> int:
            if ch == "~":
                return -1
            if ("A" <= ch <= "Z") or ("a" <= ch <= "z"):
                return ord(ch)
            return ord(ch) + 256
        def _deb_part_cmp(a: str, b: str) -> int:
            i = j = 0
            na, nb = len(a), len(b)
            while i < na or j < nb:
                while (i < na and not a[i].isdigit()) or (j < nb and not b[j].isdigit()):
                    ca = _deb_order(a[i]) if i < na and not a[i].isdigit() else 0
                    cb = _deb_order(b[j]) if j < nb and not b[j].isdigit() else 0
                    if ca != cb:
                        return -1 if ca < cb else 1
                    if i < na and not a[i].isdigit():
                        i += 1
                    if j < nb and not b[j].isdigit():
                        j += 1
                ia, jb = i, j
                while i < na and a[i].isdigit():
                    i += 1
                while j < nb and b[j].isdigit():
                    j += 1
                da = int(a[ia:i] or "0")
                db = int(b[jb:j] or "0")
                if da != db:
                    return -1 if da < db else 1
            return 0
        def _deb_cmp(a: str, b: str) -> int:
            e1, u1, r1 = _deb_split(a)
            e2, u2, r2 = _deb_split(b)
            if e1 != e2:
                return -1 if e1 < e2 else 1
            c = _deb_part_cmp(u1, u2)
            if c != 0:
                return c
            return _deb_part_cmp(r1, r2)
        c = _deb_cmp(v1, v2)
        ok = {
            "lt": c < 0, "<<": c < 0,
            "le": c <= 0, "<=": c <= 0,
            "eq": c == 0, "=": c == 0,
            "ne": c != 0,
            "ge": c >= 0, ">=": c >= 0,
            "gt": c > 0, ">>": c > 0,
        }[op]
        sys.exit(0 if ok else 1)
    print(os.environ.get("TEST_ARCH", "amd64"))
elif cmd == "curl":
    if "-o" in args:
        target = pathlib.Path(args[args.index("-o") + 1])
        url = [a for a in args if a.startswith("https://")][-1]
        if url.endswith(".sigstore.json"):
            shutil.copyfile(root / "release.sigstore.json", target)
        elif url.endswith("/SHA256SUMS"):
            shutil.copyfile(root / "SHA256SUMS", target)
        elif url.endswith("speedtest-backend_4.1.0_linux_amd64.tar.gz"):
            shutil.copyfile(root / "release.tar.gz", target)
        else:
            sys.exit(22)
    else:
        if os.environ.get("TEST_READINESS_FAIL") == "1":
            sys.exit(7)
        print('{"status":"OK"}')
elif cmd == "systemctl":
    state_file = root / "systemd_state.json"
    st = json.loads(state_file.read_text()) if state_file.exists() else {"active": {}, "enabled": {}}
    clean = [a for a in args if a not in ("--", "--quiet")]
    sub = clean[0] if clean else ""
    rest = [a for a in clean[1:] if not a.startswith("-")]
    now_flag = "--now" in args
    def norm_unit(u: str) -> str:
        return u if u.endswith((".service", ".socket", ".timer")) else u + ".service"
    if sub == "daemon-reload" or sub == "reset-failed":
        sys.exit(0)
    elif sub == "enable":
        for raw_u in rest:
            u = norm_unit(raw_u)
            st["enabled"][u] = True
            wants_dir = root / "etc/systemd/system" / ("sockets.target.wants" if u.endswith(".socket") else "multi-user.target.wants")
            wants_dir.mkdir(parents=True, exist_ok=True)
            link_p = wants_dir / u
            if not link_p.exists() and not link_p.is_symlink():
                link_p.symlink_to(root / "etc/systemd/system" / u)
            if now_flag:
                st["active"][u] = True
        state_file.write_text(json.dumps(st))
        sys.exit(0)
    elif sub == "disable":
        for raw_u in rest:
            u = norm_unit(raw_u)
            st["enabled"][u] = False
            if now_flag:
                st["active"][u] = False
            for wdir in ("sockets.target.wants", "multi-user.target.wants", "timers.target.wants"):
                lp = root / "etc/systemd/system" / wdir / u
                if lp.is_symlink() or lp.exists():
                    lp.unlink()
        state_file.write_text(json.dumps(st))
        sys.exit(0)
    elif sub in ("start", "restart", "reload"):
        for raw_u in rest:
            u = norm_unit(raw_u)
            st["active"][u] = True
        state_file.write_text(json.dumps(st))
        sys.exit(0)
    elif sub == "stop":
        for raw_u in rest:
            u = norm_unit(raw_u)
            st["active"][u] = False
        state_file.write_text(json.dumps(st))
        sys.exit(0)
    elif sub == "is-active":
        u = norm_unit(rest[0]) if rest else ""
        is_act = bool(st["active"].get(u, False))
        if "--quiet" not in args:
            print("active" if is_act else "inactive")
        sys.exit(0 if is_act else 3)
    elif sub == "is-enabled":
        u = norm_unit(rest[0]) if rest else ""
        is_en = bool(st["enabled"].get(u, False))
        if "--quiet" not in args:
            print("enabled" if is_en else "disabled")
        sys.exit(0 if is_en else 1)
    elif sub == "show":
        u = norm_unit(rest[0]) if rest else ""
        is_act = bool(st["active"].get(u, False))
        is_en = bool(st["enabled"].get(u, False))
        unit_exists = (root / "etc/systemd/system" / u).exists()
        print(f"LoadState={'loaded' if unit_exists else 'not-found'}")
        print(f"ActiveState={'active' if is_act else 'inactive'}")
        print("MainPID=0")
        print(f"UnitFileState={'enabled' if is_en else 'disabled'}")
        sys.exit(0)
    sys.exit(0)
elif cmd in ("tar", "mv"):
    sys.exit(subprocess.run(["/usr/bin/" + cmd, *args]).returncode)
elif cmd in ("apt-get", "id", "chown", "useradd"):
    sys.exit(0)
else:
    raise RuntimeError((cmd, args))
'''
            for name in ("dpkg", "curl", "systemctl", "apt-get", "id", "chown", "useradd", "tar", "mv"):
                p = root / "bin" / name
                p.write_text(host_cmd)
                p.chmod(0o755)

            # Mock verify-provenance.py that checks exact CLI arguments & fails when TEST_PROVENANCE_FAIL=1
            verifier = root / "opt/AetherFlow/deploy/verify-provenance.py"
            verifier.write_text(r'''#!/usr/bin/env python3
import json, os, pathlib, sys
root = pathlib.Path(os.environ["TEST_ROOT"])
(root / "provenance_args.json").write_text(json.dumps(sys.argv[1:]))
if os.environ.get("TEST_PROVENANCE_FAIL") == "1":
    sys.stderr.write("[PROVENANCE-FAIL] simulated invalid attestation\n")
    sys.exit(1)
sys.exit(0)
''')
            verifier.chmod(0o755)

            common_src = (ROOT / "packages/common.sh").read_text(encoding="utf-8")
            helpers = common_src[common_src.index("command_exists()"):common_src.index("lock_path()")]
            helpers += common_functions(
                "systemd_unit_inactive",
                "quiesce_services_for_rollback",
                "stop_systemd_unit",
                "verify_systemd_service_active",
                "wait_for_service_ready",
                "af_write_failure_receipt",
                "derive_app_password",
            )
            stubs = """set -euo pipefail
MASTER_USER=admin
MASTER_PASS="top-secret-master-pass-999"
require_root() { :; }
sleep() { :; }
log_info() { :; }
log_warn() { :; }
print_error() { printf '%s\\n' "$*" >&2; }
print_warn() { printf '%s\\n' "$*" >&2; }
report_progress() { :; }
github_latest_tag() { printf '4.1.0\\n'; }
write_lock() { printf 'installed\\n' > "$TEST_ROOT/install/.$1.lock"; INSTALL_COMMITTED=true; [[ -z "${AF_ARCHIVE_BACKUP:-}" ]] || rm -f -- "$AF_ARCHIVE_BACKUP/.af-archive-pending"; }
"""
            rebased_helpers = replace_paths_once(
                helpers,
                [(pfx, str(root) + pfx) for pfx in ("/opt", "/etc/", "/var/", "/tmp/", "/install", "/home/")],
            )
            (root / "opt/AetherFlow/packages/common.sh").write_text(stubs + rebased_helpers)

            installer_src = (ROOT / "packages/package/install/installpackage-librespeed").read_text(encoding="utf-8")
            rebased_installer = replace_paths_once(
                installer_src,
                [(pfx, str(root) + pfx) for pfx in ("/opt", "/etc/", "/var/", "/tmp/", "/install", "/home/")],
            )
            script_path = root / "install_librespeed.sh"
            script_path.write_text(rebased_installer)
            script_path.chmod(0o755)

            base_env = {
                **os.environ,
                "PATH": f"{root}/bin:/usr/bin:/bin",
                "TEST_ROOT": str(root),
                "TMPDIR": str(root / "tmp"),
                "AF_APP_PORT": "18988",
                "AF_TARGET_VERSION": "4.1.0",
            }
            base_env.pop("AETHERFLOW_SKIP_PROVENANCE_VERIFY", None)

            # 1. Default fail-closed provenance verification rejects invalid bundle
            fail_res = subprocess.run(
                ["bash", str(script_path)],
                env={**base_env, "TEST_PROVENANCE_FAIL": "1"},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(fail_res.returncode, 0)
            self.assertFalse((root / "install/.librespeed.lock").exists())

            # 2. Valid provenance + AF_TARGET_VERSION=4.1.0 skips stale 4.0.0 local binary, verifies digest, and hardens config
            ok_res = subprocess.run(
                ["bash", str(script_path)],
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(ok_res.returncode, 0, ok_res.stdout + ok_res.stderr)
            self.assertTrue((root / "install/.librespeed.lock").exists())

            prov_args = json.loads((root / "provenance_args.json").read_text())
            self.assertIn("--digest", prov_args)
            self.assertEqual(prov_args[prov_args.index("--digest") + 1], expected_sha256)
            self.assertIn("--artifact-name", prov_args)
            self.assertEqual(
                prov_args[prov_args.index("--artifact-name") + 1],
                "speedtest-backend_4.1.0_linux_amd64.tar.gz",
            )
            self.assertIn("--tag", prov_args)
            self.assertEqual(prov_args[prov_args.index("--tag") + 1], "v4.1.0")
            self.assertIn("--bundle-file", prov_args)

            self.assertEqual((root / "opt/librespeed/.af-version").read_text().strip(), "4.1.0")

            settings_path = root / "opt/librespeed/settings.toml"
            settings_text = settings_path.read_text(encoding="utf-8")
            self.assertEqual(settings_path.stat().st_mode & 0o777, 0o640)
            self.assertEqual((root / "opt/librespeed").stat().st_mode & 0o7777, 0o1770)
            self.assertNotIn("top-secret-master-pass-999", settings_text)
            expected_derived = hmac.new(
                b"top-secret-master-pass-999",
                b"aetherflow:librespeed:webui:v1",
                hashlib.sha256,
            ).hexdigest()[:32]
            self.assertIn(f'statistics_password="{expected_derived}"', settings_text)
            self.assertIn("redact_ip_addresses=true", settings_text)
            self.assertIn("enable_id_obfuscation=true", settings_text)
            self.assertIn('trusted_proxies=["127.0.0.1", "::1"]', settings_text)
            sec_m = re.search(r'^trusted_proxy_secret="([0-9a-f]{64})"$', settings_text, re.MULTILINE)
            self.assertIsNotNone(sec_m, f"Missing 64-hex trusted_proxy_secret in {settings_text}")
            proxy_snippet_path = root / "etc/aetherflow/librespeed-proxy-token.conf"
            self.assertTrue(proxy_snippet_path.is_file())
            self.assertEqual(proxy_snippet_path.stat().st_mode & 0o777, 0o600)
            self.assertIn(
                f'RequestHeader set X-AetherFlow-Proxy-Token "{sec_m.group(1)}"',  # type: ignore[union-attr]
                proxy_snippet_path.read_text(encoding="utf-8"),
            )

            unit_text = (root / "etc/systemd/system/librespeed.service").read_text(encoding="utf-8")
            for directive in (
                "UMask=0077",
                "NoNewPrivileges=yes",
                "ProtectSystem=strict",
                "ReadWritePaths=",
                "ReadOnlyPaths=",
            ):
                self.assertIn(directive, unit_text)

            # 3. Existing settings.toml upgrade migrates bolt->sqlite, backfills missing keys, and probes HTTPS with -k
            settings_path.write_text(
                'bind_address="127.0.0.1"\n'
                'listen_port=8988\n'
                'statistics_password="custom-stats-password"\n'
                'database_type="bolt"\n'
                'enable_tls=true\n'
                'tls_cert_file="/etc/ssl/mycert.pem"\n'
                'tls_key_file="/etc/ssl/mykey.pem"\n',
                encoding="utf-8",
            )
            (root / "commands.jsonl").unlink(missing_ok=True)
            tls_res = subprocess.run(
                ["bash", str(script_path)],
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(tls_res.returncode, 0, tls_res.stdout + tls_res.stderr)
            upgraded_text = settings_path.read_text(encoding="utf-8")
            self.assertIn("listen_port=18988", upgraded_text)
            self.assertIn('database_type="sqlite"', upgraded_text)
            self.assertNotIn('database_type="bolt"', upgraded_text)
            self.assertIn("redact_ip_addresses=true", upgraded_text)
            self.assertIn("enable_id_obfuscation=true", upgraded_text)
            self.assertIn('trusted_proxies=["127.0.0.1", "::1"]', upgraded_text)
            logged_cmds = [
                json.loads(line)
                for line in (root / "commands.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertTrue(
                any(
                    cmd[0] == "curl"
                    and "-k" in cmd
                    and "https://127.0.0.1:18988/" in cmd
                    for cmd in logged_cmds
                ),
                f"Expected HTTPS readiness probe with -k in commands: {logged_cmds}",
            )

            # 4a. Retained external database_file (including database_type="" and .. traversal normalization)
            #     wins over a stale local speedtest.db while preserving the stale local DB as .pre-migrate.*.bak
            ext_db_dir = root / "var/lib/librespeed"
            ext_db_dir.mkdir(parents=True, exist_ok=True)
            ext_db = ext_db_dir / "speedtest.db"
            ext_db.write_bytes(b"SQLite format 3\x00external-telemetry-payload")
            (ext_db_dir / "speedtest.db-wal").write_bytes(b"external-wal-frames")
            confined_db = root / "opt/librespeed/speedtest.db"
            confined_db.write_bytes(b"SQLite format 3\x00stale-local-payload")
            (root / "opt/librespeed/speedtest.db-wal").write_bytes(b"stale-local-wal")
            unnormalized_ext = f"{root}/opt/librespeed/../../var/lib/librespeed/speedtest.db"

            settings_path.write_text(
                'bind_address="127.0.0.1"\n'
                'listen_port=8988\n'
                'statistics_password="custom-stats-password"\n'
                'redact_ip_addresses=false\n'
                'database_type=""\n'
                f'database_file="{unnormalized_ext}"\n'
                'enable_tls=false\n',
                encoding="utf-8",
            )
            ext_res = subprocess.run(
                ["bash", str(script_path)],
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(ext_res.returncode, 0, ext_res.stdout + ext_res.stderr)
            migrated_cfg = settings_path.read_text(encoding="utf-8")
            self.assertIn(f'database_file="{confined_db}"', migrated_cfg)
            self.assertEqual(confined_db.read_bytes(), b"SQLite format 3\x00external-telemetry-payload")
            self.assertEqual((root / "opt/librespeed/speedtest.db-wal").read_bytes(), b"external-wal-frames")
            pre_migrate_baks = list((root / "opt/librespeed").glob("speedtest.db.pre-migrate.*.bak"))
            self.assertEqual(len(pre_migrate_baks), 1)
            self.assertEqual(pre_migrate_baks[0].read_bytes(), b"SQLite format 3\x00stale-local-payload")
            self.assertTrue(ext_db.exists(), "Original external DB must remain intact as backup")
            self.assertIn('trusted_proxies=["127.0.0.1", "::1"]', migrated_cfg)

            # 4a-ii. Explicit operator trusted_proxies=[] is preserved on upgrade, and custom in-dir
            #        database_file subdirectories plus timestamped .bolt.bak.<ts> artifacts are 0600-hardened
            sub_db_dir = root / "opt/librespeed/sub"
            sub_db_dir.mkdir(parents=True, exist_ok=True)
            sub_db = sub_db_dir / "telemetry.db"
            sub_db_wal = sub_db_dir / "telemetry.db-wal"
            bolt_ts_bak = root / "opt/librespeed/speedtest.db.bolt.bak.1700000000"
            sub_db.write_bytes(b"SQLite format 3\x00subdir-db")
            sub_db_wal.write_bytes(b"subdir-wal")
            bolt_ts_bak.write_bytes(b"\x00" * 16 + b"\xed\xda\x0c\xed" + b"\x00" * 12)
            os.chmod(sub_db, 0o644)
            os.chmod(sub_db_wal, 0o644)
            os.chmod(bolt_ts_bak, 0o644)

            settings_path.write_text(
                'bind_address="127.0.0.1"\n'
                'listen_port=8988\n'
                'trusted_proxies=[]\n'
                'statistics_password="custom-stats-password"\n'
                'redact_ip_addresses=false\n'
                'database_type="sqlite"\n'
                f'database_file="{sub_db}"\n'
                'enable_tls=false\n',
                encoding="utf-8",
            )
            explicit_res = subprocess.run(
                ["bash", str(script_path)],
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(explicit_res.returncode, 0, explicit_res.stdout + explicit_res.stderr)
            explicit_cfg = settings_path.read_text(encoding="utf-8")
            self.assertIn("trusted_proxies=[]", explicit_cfg)
            self.assertNotIn('trusted_proxies=["127.0.0.1"', explicit_cfg)
            for hardened_artifact in (sub_db, sub_db_wal, bolt_ts_bak):
                self.assertEqual(
                    stat.S_IMODE(hardened_artifact.lstat().st_mode),
                    0o600,
                    f"Expected 0600 on {hardened_artifact}",
                )

            # 4a-cidr. Loopback CIDR / comma-separated string trusted_proxies is preserved intact
            settings_path.write_text(
                'bind_address="127.0.0.1"\n'
                'listen_port=8988\n'
                'trusted_proxies="127.0.0.0/8, ::1/128"\n'
                'statistics_password="custom-stats-password"\n'
                'redact_ip_addresses=false\n'
                'database_type="sqlite"\n'
                f'database_file="{sub_db}"\n'
                'enable_tls=false\n',
                encoding="utf-8",
            )
            cidr_res = subprocess.run(
                ["bash", str(script_path)],
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(cidr_res.returncode, 0, cidr_res.stdout + cidr_res.stderr)
            cidr_cfg = settings_path.read_text(encoding="utf-8")
            self.assertIn('trusted_proxies="127.0.0.0/8, ::1/128"', cidr_cfg)
            self.assertNotIn('trusted_proxies=["127.0.0.1"', cidr_cfg)

            # 4b. Missing external database_file (e.g. unmounted volume) fails closed without rewriting settings.toml
            missing_ext = ext_db_dir / "unmounted-volume.db"
            settings_path.write_text(
                'bind_address="127.0.0.1"\n'
                'listen_port=8988\n'
                'statistics_password="custom-stats-password"\n'
                'database_type="sqlite"\n'
                f'database_file="{missing_ext}"\n',
                encoding="utf-8",
            )
            missing_res = subprocess.run(
                ["bash", str(script_path)],
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(missing_res.returncode, 0)
            self.assertIn(f'database_file="{missing_ext}"', settings_path.read_text(encoding="utf-8"))

            # 4c. Disallowed host path (/etc/...) and non-SQLite/non-Bolt file header both fail closed
            etc_secret = root / "etc/aetherflow.env"
            etc_secret.parent.mkdir(parents=True, exist_ok=True)
            etc_secret.write_bytes(b"SQLite format 3\x00fake-header-in-etc")
            settings_path.write_text(
                'bind_address="127.0.0.1"\n'
                'database_type="sqlite"\n'
                f'database_file="{etc_secret}"\n',
                encoding="utf-8",
            )
            etc_res = subprocess.run(
                ["bash", str(script_path)],
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(etc_res.returncode, 0)

            bad_magic_db = ext_db_dir / "not-a-database.db"
            bad_magic_db.write_bytes(b"-----BEGIN PRIVATE KEY-----\nNOT_A_DB")
            settings_path.write_text(
                'bind_address="127.0.0.1"\n'
                'database_type="sqlite"\n'
                f'database_file="{bad_magic_db}"\n',
                encoding="utf-8",
            )
            bad_magic_res = subprocess.run(
                ["bash", str(script_path)],
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(bad_magic_res.returncode, 0)

            # 5. Custom [tuning] TOML subtable in settings.toml keeps all backfilled root keys
            #    in the root preamble BEFORE [tuning] (Carbon P3-1 regression)
            settings_path.write_text(
                'bind_address="127.0.0.1"\n'
                'listen_port=8988\n'
                'statistics_password="custom-stats-password"\n'
                'database_type="bolt"\n'
                '\n'
                '[tuning]\n'
                'worker_threads=4\n',
                encoding="utf-8",
            )
            subtable_res = subprocess.run(
                ["bash", str(script_path)],
                env=base_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(subtable_res.returncode, 0, subtable_res.stdout + subtable_res.stderr)
            subtable_cfg = settings_path.read_text(encoding="utf-8")
            self.assertIn("[tuning]\nworker_threads=4", subtable_cfg)
            root_part, tuning_part = subtable_cfg.split("[tuning]", 1)
            for root_key in (
                "listen_port=18988",
                'database_type="sqlite"',
                "redact_ip_addresses=true",
                "enable_id_obfuscation=true",
                'trusted_proxies=["127.0.0.1", "::1"]',
                "trusted_proxy_secret=",
            ):
                self.assertIn(root_key, root_part, f"Expected {root_key} in TOML root preamble: {subtable_cfg}")
                self.assertNotIn(root_key, tuning_part, f"Key {root_key} leaked under [tuning]: {subtable_cfg}")
            if tomllib is not None:
                parsed_sub = tomllib.loads(subtable_cfg)
                self.assertEqual(parsed_sub["redact_ip_addresses"], True)
                self.assertEqual(parsed_sub["enable_id_obfuscation"], True)
                self.assertEqual(parsed_sub["trusted_proxies"], ["127.0.0.1", "::1"])
                self.assertTrue(parsed_sub["trusted_proxy_secret"])
                self.assertEqual(parsed_sub["tuning"]["worker_threads"], 4)

            # 6. Failed readiness during legacy Go -> Rust cutover rolls back librespeed.socket,
            #    sockets.target.wants/librespeed.socket, proxy snippet, legacy binary, and legacy unit (Sol P2-3 regression)
            for cleanup_p in (
                root / "etc/systemd/system/librespeed.socket",
                root / "etc/systemd/system/sockets.target.wants/librespeed.socket",
                root / "etc/aetherflow/librespeed-proxy-token.conf",
                root / "install/.librespeed.lock",
                root / "systemd_state.json",
            ):
                cleanup_p.unlink(missing_ok=True)
            for old_bak in (root / "opt").glob("librespeed.af-backup.*"):
                shutil.rmtree(old_bak)
            shutil.rmtree(root / "opt/librespeed", ignore_errors=True)
            (root / "opt/librespeed").mkdir(parents=True, exist_ok=True)
            legacy_go_bin = root / "opt/librespeed/speedtest-go"
            legacy_go_bin.write_bytes(b"#!/bin/sh\necho legacy-go-binary\n")
            legacy_go_bin.chmod(0o755)
            (root / "opt/librespeed/.af-version").write_text("1.1.5\n", encoding="utf-8")
            (root / "opt/librespeed/settings.toml").write_text(
                'bind_address="127.0.0.1"\nlisten_port=8988\nstatistics_password="legacy"\n',
                encoding="utf-8",
            )
            legacy_unit = "[Unit]\nDescription=Legacy Go LibreSpeed\n[Service]\nExecStart=/opt/librespeed/speedtest-go\n"
            (root / "etc/systemd/system/librespeed.service").write_text(legacy_unit, encoding="utf-8")
            (root / "systemd_state.json").write_text(
                json.dumps({"active": {"librespeed.service": True}, "enabled": {"librespeed.service": True}}),
                encoding="utf-8",
            )

            rb_res = subprocess.run(
                ["bash", str(script_path)],
                env={**base_env, "TEST_READINESS_FAIL": "1"},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rb_res.returncode, 0)
            self.assertFalse(
                (root / "etc/systemd/system/librespeed.socket").exists(),
                "Rollback left /etc/systemd/system/librespeed.socket behind",
            )
            self.assertFalse(
                (root / "etc/systemd/system/sockets.target.wants/librespeed.socket").is_symlink(),
                "Rollback left sockets.target.wants/librespeed.socket symlink enabled",
            )
            self.assertFalse(
                (root / "etc/aetherflow/librespeed-proxy-token.conf").exists(),
                "Rollback left newly generated librespeed-proxy-token.conf behind",
            )
            self.assertTrue(
                legacy_go_bin.is_file() and not legacy_go_bin.is_symlink(),
                "Rollback failed to restore legacy speedtest-go binary",
            )
            self.assertFalse((root / "opt/librespeed/speedtest-backend").exists())
            self.assertEqual(
                (root / "etc/systemd/system/librespeed.service").read_text(encoding="utf-8"),
                legacy_unit,
            )
            final_sd = json.loads((root / "systemd_state.json").read_text(encoding="utf-8"))
            self.assertFalse(final_sd["active"].get("librespeed.socket", False))
            self.assertFalse(final_sd["enabled"].get("librespeed.socket", False))
            self.assertTrue(
                final_sd["active"].get("librespeed.service", False),
                f"Expected legacy librespeed.service restarted on rollback: {final_sd}",
            )

    def test_update_aetherflow_executes_real_af_binary_and_common_https_readiness_guard(self) -> None:
        with tempfile.TemporaryDirectory(prefix="af-shim-bin-", dir=RESOLVED_TMP_ROOT) as tmp:
            root = Path(tmp)
            bin_dir = root / "current/bin"
            bin_dir.mkdir(parents=True, exist_ok=True)
            # Simulate compiled Rust `af` binary containing the static ownership literal `packages/system/updateAetherFlow`
            # by compiling a tiny C/Python ELF-or-non-shim executable (python3 binary header via compiled helper or python script without shim marker)
            af_log = root / "af_invoked.json"
            fake_af = bin_dir / "af"
            fake_af.write_text(
                "#!/usr/bin/env python3\n"
                "import json, pathlib, sys\n"
                "# Embedded ownership literal: packages/system/updateAetherFlow\n"
                f"pathlib.Path({str(af_log)!r}).write_text(json.dumps(sys.argv[1:]))\n",
                encoding="utf-8",
            )
            fake_af.chmod(0o755)

            dry_res = subprocess.run(
                ["bash", str(ROOT / "packages/system/updateAetherFlow"), "--dry-run", "--channel", "nightly"],
                env={**os.environ, "AF_INSTALL_ROOT": str(root)},
                capture_output=True,
                text=True,
            )
            self.assertEqual(dry_res.returncode, 0, dry_res.stderr)
            self.assertIn(str(fake_af), dry_res.stdout)
            self.assertIn("release deploy --local --channel nightly", dry_res.stdout)

            # --offline without --dry-run must fail closed
            live_offline = subprocess.run(
                ["bash", str(ROOT / "packages/system/updateAetherFlow"), "--offline"],
                env={**os.environ, "AF_INSTALL_ROOT": str(root)},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(live_offline.returncode, 0)

            # --dry-run --offline executes af --dry-run --root <root> release deploy --local --offline
            dry_offline = subprocess.run(
                ["bash", str(ROOT / "packages/system/updateAetherFlow"), "--dry-run", "--offline"],
                env={**os.environ, "AF_INSTALL_ROOT": str(root)},
                capture_output=True,
                text=True,
            )
            self.assertEqual(dry_offline.returncode, 0, dry_offline.stderr)
            invoked_argv = json.loads(af_log.read_text(encoding="utf-8"))
            self.assertEqual(
                invoked_argv,
                ["--dry-run", "--root", str(root), "release", "deploy", "--local", "--offline"],
            )

        wsl_script = (ROOT / "scripts/setup_wsl_dev.sh").read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"curl\b[^\n]*\|\s*(?:sudo\s+(?:-E\s+)?)?(?:ba)?sh\b", wsl_script))
        self.assertIn("bash scripts/install_wasm_build_tools.sh --ensure", wsl_script)
        wasm_tools = (ROOT / "scripts/install_wasm_build_tools.sh").read_text(encoding="utf-8")
        self.assertIn('"${rustup_sha256}"', wasm_tools)
        self.assertIn("sha256sum --check --strict", wasm_tools)

        common_text = (ROOT / "packages/common.sh").read_text(encoding="utf-8")
        self.assertIn(r"\[::1\]|localhost", common_text)
        self.assertNotIn("https://127.*:*", common_text)

    def test_af_certbot_sync_v4_sqlite_and_hosts_reconcile(self) -> None:
        import sqlite3

        with tempfile.TemporaryDirectory(prefix="af-certbot-cutover-", dir=RESOLVED_TMP_ROOT) as tmp:
            root = Path(tmp)
            for rel in ("bin", "etc", "install", "run/aetherflow", "var/lib/aetherflow", "etc/aetherflow"):
                (root / rel).mkdir(parents=True, exist_ok=True)
            (root / "run/aetherflow").chmod(0o750)
            stat_wrapper = root / "bin/stat"
            stat_wrapper.write_text(
                "#!/bin/sh\n"
                'if [ "${1:-}" = "-c" ] && [ "${2:-}" = "%u" ]; then echo 0; exit 0; fi\n'
                'if [ "${1:-}" = "-Lc" ] && [ "${2:-}" = "%a %U:%G" ]; then echo "660 root:aetherflow"; exit 0; fi\n'
                'exec /usr/bin/stat "$@"\n',
                encoding="utf-8",
            )
            stat_wrapper.chmod(0o755)
            (root / "etc/hosts").write_text("127.0.0.1\tlocalhost\n", encoding="utf-8")
            (root / "install/.librespeed.lock").write_text("installed\n", encoding="utf-8")
            (root / "install/.core.lock").write_text("installed\n", encoding="utf-8")

            db_path = root / "var/lib/aetherflow/aetherflow.sqlite"
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, base_domain TEXT)")
            conn.execute("INSERT INTO settings (id, base_domain) VALUES (1, 'box.example.com')")
            conn.commit()
            conn.close()

            src = (ROOT / "packages/system/af-certbot-sync").read_text(encoding="utf-8")
            rebased = replace_paths_once(
                src,
                [(pfx, str(root) + pfx) for pfx in ("/opt", "/etc/", "/run/", "/var/", "/install", "/srv/")],
            )
            script = root / "af-certbot-sync.sh"
            script.write_text(rebased, encoding="utf-8")
            script.chmod(0o755)

            # Without certbot in PATH, /etc/hosts internal DNS block must still be reconciled cleanly
            res = subprocess.run(
                ["bash", str(script)],
                env={**os.environ, "PATH": f"{root}/bin:/usr/bin:/bin"},
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            hosts_after = (root / "etc/hosts").read_text(encoding="utf-8")
            self.assertIn("aetherflow.aether.local", hosts_after)
            self.assertIn("librespeed.aether.local", hosts_after)
            self.assertNotIn("core.aether.local", hosts_after)

    def test_scripts_and_sdk_scaffolder_are_zero_go(self) -> None:
        sdk_script = (ROOT / "scripts/create-plugin-sdk.sh").read_text(encoding="utf-8")
        self.assertIn("rust", sdk_script)
        self.assertNotIn("plugins/sdk-template/", sdk_script)

        with tempfile.TemporaryDirectory(dir=RESOLVED_TMP_ROOT) as tmp:
            bad = subprocess.run(
                ["bash", str(ROOT / "scripts/create-plugin-sdk.sh"), "../bad", "Bad", f"{tmp}/bad"],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(bad.returncode, 0)

            for idx, bad_name in enumerate(("Bad'Quote", "Bad<script>", "Bad/Slash", "Bad{Brace}")):
                bad_res = subprocess.run(
                    [
                        "bash",
                        str(ROOT / "scripts/create-plugin-sdk.sh"),
                        "sample-plugin",
                        bad_name,
                        f"{tmp}/bad-name-{idx}",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(bad_res.returncode, 0, f"Expected rejection for {bad_name!r}")

            out_dir = Path(tmp) / "sample-plugin"
            ok = subprocess.run(
                [
                    "bash",
                    str(ROOT / "scripts/create-plugin-sdk.sh"),
                    "sample-plugin",
                    "Sample Plugin",
                    str(out_dir),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(ok.returncode, 0)
            manifest = json.loads((out_dir / "plugin.manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["id"], "sample-plugin")
            self.assertEqual(manifest["backend"]["binary_name"], "aetherflow-plugin-sample-plugin")
            cargo_toml = (out_dir / "backend/Cargo.toml").read_text(encoding="utf-8")
            self.assertIn('name = "aetherflow-plugin-sample-plugin"', cargo_toml)
            cargo_lock = (out_dir / "backend/Cargo.lock").read_text(encoding="utf-8")
            self.assertIn('name = "aetherflow-plugin-sample-plugin"', cargo_lock)
            self.assertNotIn("aetherflow-plugin-template", cargo_lock)

            # Verify read-only template trees (e.g. Debian/tarball root-owned packaging) still scaffold cleanly.
            ro_repo = Path(tmp) / "ro-repo"
            (ro_repo / "scripts").mkdir(parents=True)
            shutil.copy2(ROOT / "scripts/create-plugin-sdk.sh", ro_repo / "scripts/create-plugin-sdk.sh")
            shutil.copytree(ROOT / "plugins/sdk-template-rust", ro_repo / "plugins/sdk-template-rust")
            for p in (ro_repo / "plugins/sdk-template-rust").rglob("*"):
                if p.is_file():
                    p.chmod(0o444)
            try:
                ro_out = Path(tmp) / "ro-sample-plugin"
                ro_ok = subprocess.run(
                    [
                        "bash",
                        str(ro_repo / "scripts/create-plugin-sdk.sh"),
                        "ro-plugin",
                        "Readonly Plugin",
                        str(ro_out),
                    ],
                    cwd=ro_repo,
                    capture_output=True,
                    text=True,
                    check=True,
                )
                self.assertEqual(ro_ok.returncode, 0)
                self.assertTrue(os.access(ro_out / "plugin.manifest.json", os.W_OK))
            finally:
                for p in (ro_repo / "plugins/sdk-template-rust").rglob("*"):
                    p.chmod(0o755 if p.is_dir() else 0o644)

        modern_stack = (ROOT / "setup/modules/modern_stack.sh").read_text(encoding="utf-8")
        build_gold = (ROOT / "scripts/build_gold.sh").read_text(encoding="utf-8")
        for label, content in (("modern_stack.sh", modern_stack), ("build_gold.sh", build_gold)):
            for token in ("_install_go", "AF_GO_VERSION", "backend/web/dist", "backend/config"):
                self.assertNotIn(token, content, f"{label} must not reference legacy token {token!r}")
            self.assertIsNone(
                re.search(r"\bgo\s+build\b", content),
                f"{label} must not invoke standalone 'go build'",
            )
        self.assertNotIn("https://sh.rustup.rs", modern_stack)
        self.assertIn("static.rust-lang.org/rustup/archive/", modern_stack)
        self.assertIn("sha256sum -c -", modern_stack)

    def test_librespeed_sandbox_installer_and_canonical_db_parity(self) -> None:
        pkg_auto = json.loads((ROOT / "config/package_automation.json").read_text(encoding="utf-8"))
        self.assertEqual(
            pkg_auto["librespeed"]["sandbox_rw_paths"],
            ["/opt/librespeed"],
            "librespeed post-install sandbox drop-in must confine RW access strictly to /opt/librespeed",
        )

        installer = (ROOT / "packages/package/install/installpackage-librespeed").read_text(encoding="utf-8")
        self.assertNotIn("chown -hRP librespeed:librespeed /opt/librespeed", installer)
        self.assertIn("os.fchmod(fd, mode)", installer)
        self.assertIn("dir_fd=parent_fd", installer)
        self.assertIn("dir_fd=cur_fd", installer)

        # Verify readiness target snippet preserves non-loopback IPv4/IPv6 bind_address
        m_ready = re.search(
            r'LS_READINESS_TARGET="\$\(python3 - /opt/librespeed/settings\.toml "\$APP_PORT" <<\'PYEOF\'\n(.*?)\nPYEOF',
            installer,
            re.S,
        )
        self.assertIsNotNone(m_ready)
        snippet = m_ready.group(1)  # type: ignore[union-attr]
        with tempfile.TemporaryDirectory(dir=RESOLVED_TMP_ROOT) as tmp:
            cfg = Path(tmp) / "settings.toml"
            for raw_cfg, expected in (
                ('bind_address="127.0.0.1"\nenable_tls=false\n', "/"),
                ('bind_address="0.0.0.0"\nenable_tls=false\n', "/"),
                ('bind_address="::1"\nenable_tls=false\n', "http://[::1]:8988/"),
                ('bind_address="192.168.1.50"\nenable_tls=false\n', "http://192.168.1.50:8988/"),
                ('bind_address="fd00::55"\nenable_tls=false\n', "http://[fd00::55]:8988/"),
                ('bind_address="192.168.1.50"\nenable_tls=true\n', "https://192.168.1.50:8988/"),
            ):
                cfg.write_text(raw_cfg, encoding="utf-8")
                out = subprocess.check_output(
                    [sys.executable, "-c", snippet, str(cfg), "8988"],
                    text=True,
                ).strip()
                self.assertEqual(out, expected, f"Failed readiness URL for {raw_cfg!r}")

        for rel in ("packages/system/af-certbot-sync", "packages/common.sh"):
            txt = (ROOT / rel).read_text(encoding="utf-8")
            self.assertTrue(
                "(AF_DB_PATH|DB_PATH|AETHERFLOW_DB_PATH)=" in txt
                or '("AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH")' in txt,
                f"Expected DB env precedence check in {rel}",
            )
            self.assertIn("/opt/AetherFlow/current/data/aetherflow.sqlite", txt)

        sec_yml = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertIn(
            "cargo deny --manifest-path ../plugins/sdk-template-rust/backend/Cargo.toml --config deny.toml --locked",
            sec_yml,
        )

        flowai_doc = (ROOT / "docs/flowai.md").read_text(encoding="utf-8")
        self.assertNotIn("backend/providers/", flowai_doc)

    def test_shell_db_precedence_strict_loopback_tls_and_rust_toolchain_pin(self) -> None:
        import sqlite3

        modern_stack = (ROOT / "setup/modules/modern_stack.sh").read_text(encoding="utf-8")
        wsl_dev = (ROOT / "scripts/setup_wsl_dev.sh").read_text(encoding="utf-8")
        self.assertIn("AF_RUST_TOOLCHAIN:-1.99.1", modern_stack)
        self.assertNotIn("AF_RUST_TOOLCHAIN:-1.88.0", modern_stack)
        self.assertIn("AF_RUST_TOOLCHAIN:-1.99.1", wsl_dev)

        get_base_domain_fn = common_functions("get_base_domain")
        wait_ready_fn = common_functions(
            "resolve_app_readiness_path",
            "application_readiness_url",
            "wait_for_service_ready",
        )

        with tempfile.TemporaryDirectory(dir=RESOLVED_TMP_ROOT) as tmp:
            root = Path(tmp)
            env_file = root / "aetherflow.env"
            custom_data = root / "custom-data"
            custom_data.mkdir()
            active_db = custom_data / "aetherflow.sqlite"
            stale_db = root / "stale-default.sqlite"

            with sqlite3.connect(active_db) as conn:
                conn.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, base_domain TEXT)")
                conn.execute("INSERT INTO settings (id, base_domain) VALUES (1, '')")
            with sqlite3.connect(stale_db) as conn:
                conn.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, base_domain TEXT)")
                conn.execute("INSERT INTO settings (id, base_domain) VALUES (1, 'stale.example.com')")

            rebased_gbd = get_base_domain_fn.replace(
                "/var/lib/aetherflow/aetherflow.sqlite", str(stale_db)
            )
            env_file.write_text(f'DATA_DIR="{custom_data}"\n', encoding="utf-8")

            gbd_env = {
                k: v
                for k, v in os.environ.items()
                if k not in ("AETHERFLOW_SKIP_ENV_FILES", "DATA_DIR", "DB_PATH", "AETHERFLOW_DB_PATH")
            }
            gbd_env["AETHERFLOW_ENV_FILE"] = str(env_file)

            # Active custom DATA_DIR DB with empty base_domain MUST NOT fall back to stale default DB
            dom_empty = subprocess.check_output(
                ["bash", "-c", f"{rebased_gbd}\nget_base_domain"],
                env=gbd_env,
                text=True,
            ).strip()
            self.assertEqual(dom_empty, "")

            with sqlite3.connect(active_db) as conn:
                conn.execute("UPDATE settings SET base_domain = 'live.example.org' WHERE id = 1")
            dom_live = subprocess.check_output(
                ["bash", "-c", f"{rebased_gbd}\nget_base_domain"],
                env=gbd_env,
                text=True,
            ).strip()
            self.assertEqual(dom_live, "live.example.org")

            # Verify wait_for_service_ready only passes `-k` for strict loopback HTTPS
            bin_dir = root / "bin"
            bin_dir.mkdir()
            curl_log = root / "curl.jsonl"
            (bin_dir / "systemctl").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (bin_dir / "systemctl").chmod(0o755)
            (bin_dir / "curl").write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "p = pathlib.Path(os.environ['CURL_LOG'])\n"
                "with p.open('a', encoding='utf-8') as fh:\n"
                "    fh.write(json.dumps(sys.argv[1:]) + '\\n')\n"
                "sys.exit(0)\n",
                encoding="utf-8",
            )
            (bin_dir / "curl").chmod(0o755)

            for probe_url, expect_k in (
                ("https://127.0.0.1:8988/", True),
                ("https://[::1]:8988/", True),
                ("https://203.0.113.50:8988/", False),
                ("https://[2001:db8::1]:8988/", False),
                ("https://127.0.0.1.evil.example:8988/", False),
            ):
                curl_log.unlink(missing_ok=True)
                subprocess.run(
                    [
                        "bash",
                        "-c",
                        f"{wait_ready_fn}\nwait_for_service_ready librespeed 8988 '{probe_url}' 1",
                    ],
                    env={
                        **os.environ,
                        "PATH": f"{bin_dir}:/usr/bin:/bin",
                        "CURL_LOG": str(curl_log),
                    },
                    check=True,
                )
                logged = json.loads(curl_log.read_text(encoding="utf-8").splitlines()[0])
                self.assertEqual(
                    "-k" in logged,
                    expect_k,
                    f"Unexpected -k={('-k' in logged)} for {probe_url}: {logged}",
                )

    def test_wave10_update_shim_experimental_channel_rm_root_and_librespeed_socket(self) -> None:
        update_shim = ROOT / "packages/system/updateAetherFlow"
        with tempfile.TemporaryDirectory(dir=RESOLVED_TMP_ROOT) as tmp:
            isolated_root = Path(tmp) / "isolated-af"
            deploy_dir = isolated_root / "deploy"
            deploy_dir.mkdir(parents=True)
            rm_log = Path(tmp) / "rm_invocations.jsonl"
            mock_rm = deploy_dir / "release-manager.sh"
            mock_rm.write_text(
                "#!/bin/bash\n"
                "exec python3 -c \"import json, os, pathlib, sys; "
                "pathlib.Path(os.environ['RM_LOG']).open('a', encoding='utf-8').write("
                "json.dumps({'argv': sys.argv[1:], 'release_root': os.environ.get('AETHERFLOW_RELEASE_ROOT')}) + '\\n')\" \"$@\"\n",
                encoding="utf-8",
            )
            mock_rm.chmod(0o755)

            # Even if a global `af` binary exists in PATH or AETHERFLOW_RELEASE_ROOT points outside,
            # explicit AF_INSTALL_ROOT must strictly confine resolution and override AETHERFLOW_RELEASE_ROOT.
            outside_target = Path(tmp) / "outside-release-root"
            outside_target.mkdir()
            fake_path_bin = Path(tmp) / "fake-path-bin"
            fake_path_bin.mkdir()
            poison_af = fake_path_bin / "af"
            poison_af.write_text("#!/bin/sh\necho POISON >&2\nexit 99\n", encoding="utf-8")
            poison_af.chmod(0o755)

            # A 02-packages.sh / packages/system/af batch wrapper inside usr/local/bin/af must be skipped (not treated as native Rust af)
            usr_local_bin = isolated_root / "usr" / "local" / "bin"
            usr_local_bin.mkdir(parents=True)
            pkg_wrapper_af = usr_local_bin / "af"
            pkg_wrapper_af.write_text(
                "#!/bin/bash\nexec /usr/local/bin/AetherFlow/system/af \"$@\"\n",
                encoding="utf-8",
            )
            pkg_wrapper_af.chmod(0o755)

            env = {
                **os.environ,
                "AF_INSTALL_ROOT": str(isolated_root),
                "AETHERFLOW_RELEASE_ROOT": str(outside_target),
                "RM_LOG": str(rm_log),
                "PATH": f"{fake_path_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            }
            env.pop("AF_BIN", None)

            subprocess.run(
                ["bash", str(update_shim), "--channel", "experimental", "--dry-run", "--offline"],
                env=env,
                check=True,
            )
            dry_preview = subprocess.run(
                ["bash", str(update_shim), "--channel=experimental", "--dry-run"],
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertIn("--root", dry_preview.stdout)
            self.assertIn("--channel nightly", dry_preview.stdout)

            af_bin_dir = isolated_root / "current" / "bin"
            af_bin_dir.mkdir(parents=True)
            mock_af = af_bin_dir / "af"
            mock_af.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "p = pathlib.Path(os.environ['RM_LOG'])\n"
                "with p.open('a', encoding='utf-8') as fh:\n"
                "    fh.write(json.dumps({'argv': sys.argv[1:], 'release_root': os.environ.get('AETHERFLOW_RELEASE_ROOT')}) + '\\n')\n"
                "sys.exit(0)\n",
                encoding="utf-8",
            )
            mock_af.chmod(0o755)

            subprocess.run(
                ["bash", str(update_shim), "--channel=experimental", "--dry-run", "--offline"],
                env=env,
                check=True,
            )

            calls = [json.loads(line) for line in rm_log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(calls), 2)
            self.assertEqual(
                calls[0]["argv"],
                ["deploy", "--root", str(isolated_root), "--dry-run", "--channel", "nightly", "--offline"],
            )
            self.assertEqual(calls[0]["release_root"], str(isolated_root))
            self.assertEqual(
                calls[1]["argv"],
                ["--dry-run", "--root", str(isolated_root), "release", "deploy", "--local", "--channel", "nightly", "--offline"],
            )
            self.assertEqual(calls[1]["release_root"], str(isolated_root.resolve()))

            # Symlinked af or symlinked release-manager.sh escaping AF_INSTALL_ROOT must be rejected (no fallback to REPO_ROOT)
            escape_root = Path(tmp) / "escape-af"
            (escape_root / "current" / "bin").mkdir(parents=True)
            (escape_root / "deploy").mkdir(parents=True)
            (escape_root / "current" / "bin" / "af").symlink_to(poison_af)
            (escape_root / "deploy" / "release-manager.sh").symlink_to(ROOT / "deploy" / "release-manager.sh")
            escape_res = subprocess.run(
                ["bash", str(update_shim), "--dry-run"],
                env={**env, "AF_INSTALL_ROOT": str(escape_root)},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(escape_res.returncode, 0, "Symlink escaping AF_INSTALL_ROOT must fail closed")

            rel_res = subprocess.run(
                ["bash", str(update_shim), "--dry-run"],
                env={**env, "AF_INSTALL_ROOT": "relative/install/root"},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(rel_res.returncode, 0, "Relative AF_INSTALL_ROOT must fail closed")

            # Non-root `updateAetherFlow --check` succeeds on confined `.version` and rejects symlinked `.version`
            check_root = Path(tmp) / "check-only-root"
            (check_root / "current").mkdir(parents=True)
            (check_root / "current" / ".version").write_text("v4.0.0\n", encoding="utf-8")
            check_ok = subprocess.run(
                ["bash", str(update_shim), "--check"],
                env={**env, "AF_INSTALL_ROOT": str(check_root)},
                capture_output=True,
                text=True,
            )
            self.assertEqual(check_ok.returncode, 0, check_ok.stderr)
            self.assertIn("current_version=v4.0.0", check_ok.stdout)

            outside_secret = Path(tmp) / "outside-secret.txt"
            outside_secret.write_text("TOP_SECRET_HOST_LINE\n", encoding="utf-8")
            (check_root / "current" / ".version").unlink()
            (check_root / "current" / ".version").symlink_to(outside_secret)
            check_sym = subprocess.run(
                ["bash", str(update_shim), "--check"],
                env={**env, "AF_INSTALL_ROOT": str(check_root)},
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(check_sym.returncode, 0, "Symlinked .version must fail closed")
            self.assertNotIn("TOP_SECRET_HOST_LINE", check_sym.stdout + check_sym.stderr)

            # Verify `<sysroot>/opt/AetherFlow` vs `<sysroot>` vs standalone `<app_root>` against real compiled `af` binary (Carbon P2-1 regression)
            real_af_candidates = []
            cargo_target_env = os.environ.get("CARGO_TARGET_DIR", "").strip()
            if cargo_target_env:
                ct_path = Path(cargo_target_env)
                real_af_candidates.extend([ct_path / "release/af", ct_path / "debug/af"])
            real_af_candidates.extend(
                [
                    ROOT / "backend-rs/target/release/af",
                    ROOT / "backend-rs/target/debug/af",
                ]
            )
            real_af = next((p for p in real_af_candidates if p.is_file() and os.access(p, os.X_OK)), None)
            if real_af is not None:
                # Case A: AF_INSTALL_ROOT points to `<sysroot>/opt/AetherFlow` (must normalize `--root` to `<sysroot>`, not `<sysroot>/opt/AetherFlow/opt/AetherFlow`)
                sysroot_case = Path(tmp) / "sysroot-layout"
                app_in_sysroot = sysroot_case / "opt" / "AetherFlow"
                rel_slot = app_in_sysroot / "releases" / "v4.0.0"
                (rel_slot / "bin").mkdir(parents=True)
                shutil.copy2(real_af, rel_slot / "bin" / "af")
                (rel_slot / ".version").write_text("v4.0.0\n", encoding="utf-8")
                (app_in_sysroot / "current").symlink_to(rel_slot)

                for install_root_arg in (app_in_sysroot, sysroot_case):
                    chk = subprocess.run(
                        ["bash", str(update_shim), "--check"],
                        env={
                            **os.environ,
                            "AF_INSTALL_ROOT": str(install_root_arg),
                            "PATH": f"{fake_path_bin}:/usr/bin:/bin",
                        },
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(chk.returncode, 0, chk.stdout + chk.stderr)
                    self.assertIn("v4.0.0", chk.stdout, f"Expected active release v4.0.0 for AF_INSTALL_ROOT={install_root_arg}: {chk.stdout}")

                # Case B: Standalone custom `<app_root>` (`<app_root>/{current,releases}`) without `opt/AetherFlow` nesting
                standalone_app = Path(tmp) / "standalone-app-root"
                sa_slot = standalone_app / "releases" / "v4.0.1"
                (sa_slot / "bin").mkdir(parents=True)
                shutil.copy2(real_af, sa_slot / "bin" / "af")
                (sa_slot / ".version").write_text("v4.0.1\n", encoding="utf-8")
                (standalone_app / "current").symlink_to(sa_slot)
                chk_sa = subprocess.run(
                    ["bash", str(update_shim), "--check"],
                    env={
                        **os.environ,
                        "AF_INSTALL_ROOT": str(standalone_app),
                        "PATH": f"{fake_path_bin}:/usr/bin:/bin",
                    },
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(chk_sa.returncode, 0, chk_sa.stdout + chk_sa.stderr)
                self.assertIn("v4.0.1", chk_sa.stdout, f"Expected active release v4.0.1 for standalone AF_INSTALL_ROOT: {chk_sa.stdout}")

        ls_install = (ROOT / "packages/package/install/installpackage-librespeed").read_text(encoding="utf-8")
        ls_remove = (ROOT / "packages/package/remove/removepackage-librespeed").read_text(encoding="utf-8")
        self.assertIn("/etc/systemd/system/librespeed.socket", ls_install)
        self.assertIn("Requires=librespeed.socket", ls_install)
        self.assertIn("idObfuscation_salt.bin", ls_install)
        self.assertIn('purge_systemd_unit "librespeed.socket" "librespeed"', ls_remove)

    def test_multiline_toml_strings_and_isolated_credential_fallbacks(self) -> None:
        ls_install = (ROOT / "packages/package/install/installpackage-librespeed").read_text(encoding="utf-8")
        start_marker = 'safe_config_python /opt/librespeed/settings.toml "$APP_PORT" <<\'PYEOF\'\n'
        idx = ls_install.index(start_marker) + len(start_marker)
        end_idx = ls_install.index("\nPYEOF\n", idx)
        toml_rewriter_py = (
            "def safe_read_text(p):\n"
            "    with open(p, 'r', encoding='utf-8') as f: return f.read()\n"
            "def safe_write_text(p, s):\n"
            "    with open(p, 'w', encoding='utf-8') as f: f.write(s)\n\n"
            + ls_install[idx:end_idx]
        )

        with tempfile.TemporaryDirectory(dir=RESOLVED_TMP_ROOT) as tmp:
            state_dir = Path(tmp) / "librespeed"
            state_dir.mkdir(parents=True)
            cfg = state_dir / "settings.toml"
            multiline_pw = 'line1\nlisten_port=9999\ndatabase_file="/etc/shadow"\nline4'
            cfg.write_text(
                'bind_address="127.0.0.1"\n'
                "listen_port=8989\n"
                f'statistics_password="""\n{multiline_pw}"""\n'
                'database_type="bolt"\n'
                f'database_file="{state_dir}/speedtest.db"\n',
                encoding="utf-8",
            )
            res = subprocess.run(
                ["python3", "-", str(cfg), "18989"],
                input=toml_rewriter_py,
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            updated_cfg = cfg.read_text(encoding="utf-8")
            if tomllib is not None:
                parsed = tomllib.loads(updated_cfg)
                self.assertEqual(parsed["listen_port"], 18989)
                self.assertEqual(parsed["statistics_password"], multiline_pw)
                self.assertEqual(parsed["database_type"], "sqlite")
                self.assertEqual(parsed["database_file"], f"{state_dir}/speedtest.db")
            else:
                self.assertIn("listen_port=18989\n", updated_cfg)
                self.assertIn(f'statistics_password="""\n{multiline_pw}"""\n', updated_cfg)
                self.assertIn('database_type="sqlite"\n', updated_cfg)
                self.assertIn(f'database_file="{state_dir}/speedtest.db"\n', updated_cfg)

            # Verify common.sh load_master_credentials under AETHERFLOW_SKIP_ENV_FILES=1 ignores host username files
            creds_file = Path(tmp) / ".master.creds"
            lock_dir = Path(tmp) / "lock"
            env_file = Path(tmp) / "isolated.env"
            env_file.write_text(f"AES_MASTER_KEY={'a' * 64}\n", encoding="utf-8")
            isolated_env = {
                **os.environ,
                "LOCK_DIR": str(lock_dir),
                "LOGFILE": "/dev/null",
                "MASTER_USER": "",
                "MASTER_PASS": "",
                "AETHERFLOW_SKIP_ENV_FILES": "1",
                "AETHERFLOW_ENV_FILE": str(env_file),
                "AETHERFLOW_MASTER_CREDS_FILE": str(creds_file),
            }
            isolated_env.pop("AES_MASTER_KEY", None)
            chk = subprocess.run(
                [
                    "bash",
                    "-c",
                    f'source "{ROOT / "packages/common.sh"}"; load_master_credentials; printf "%s" "$MASTER_USER"',
                ],
                env=isolated_env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(chk.returncode, 0, chk.stdout + chk.stderr)
            self.assertEqual(chk.stdout.strip(), "admin")
            persisted = json.loads(creds_file.read_text(encoding="utf-8"))
            self.assertEqual(persisted["username"], "admin")
            self.assertTrue(persisted["password"].startswith("enc:v1:"))


if __name__ == "__main__":
    unittest.main()
