import hashlib
import hmac
import io
import json
import os
import re
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

    def test_rust_librespeed_and_neutral_spa_embed_present(self) -> None:
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
        with tempfile.TemporaryDirectory(prefix="af-ls-cutover-") as tmp:
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
        sys.exit(subprocess.run(["/usr/bin/dpkg", *args]).returncode)
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
        print('{"status":"OK"}')
elif cmd == "systemctl":
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
            self.assertEqual(settings_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / "opt/librespeed").stat().st_mode & 0o777, 0o750)
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

    def test_af_certbot_sync_v4_sqlite_and_hosts_reconcile(self) -> None:
        import sqlite3

        with tempfile.TemporaryDirectory(prefix="af-certbot-cutover-") as tmp:
            root = Path(tmp)
            for rel in ("bin", "etc", "install", "var/lib/aetherflow", "etc/aetherflow"):
                (root / rel).mkdir(parents=True, exist_ok=True)
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
                [(pfx, str(root) + pfx) for pfx in ("/opt", "/etc/", "/var/", "/install", "/srv/")],
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

        with tempfile.TemporaryDirectory() as tmp:
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

        modern_stack = (ROOT / "setup/modules/modern_stack.sh").read_text(encoding="utf-8")
        build_gold = (ROOT / "scripts/build_gold.sh").read_text(encoding="utf-8")
        for label, content in (("modern_stack.sh", modern_stack), ("build_gold.sh", build_gold)):
            for token in ("_install_go", "AF_GO_VERSION", "backend/web/dist", "backend/config"):
                self.assertNotIn(token, content, f"{label} must not reference legacy token {token!r}")
            self.assertIsNone(
                re.search(r"\bgo\s+build\b", content),
                f"{label} must not invoke standalone 'go build'",
            )


if __name__ == "__main__":
    unittest.main()
