import hashlib
import json
import os
import pathlib
import stat
import unittest
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

from tests.test_marketplace_catalog_lifecycle_matrix import InstallerFixture


def _build_listenarr_zip(dest: pathlib.Path, version_marker: str, include_dll: bool = False) -> tuple[pathlib.Path, str]:
    """Create a ZIP matching the verified Listenarr v1.10.6-canary layout (self-contained apphost, no .dll)."""
    apphost_stub = (
        "#!/bin/sh\n"
        "# Sentinel apphost — must NEVER be executed by version inspection\n"
        "echo 'ERROR: Listenarr.Api must not be executed for version inspection' >&2\n"
        "exit 99\n"
    )
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("Listenarr.Api", apphost_stub)
        zf.writestr("ffprobe", "#!/bin/sh\nexit 0\n")
        zf.writestr("libe_sqlite3.so", b"\x7fELF" + b"\x00" * 12)
        zf.writestr("wwwroot/index.html", f"<!doctype html><title>Listenarr {version_marker}</title>\n")
        zf.writestr("tools/README.txt", f"listenarr tools {version_marker}\n")
        zf.writestr("licenses/LICENSE.txt", "MIT\n")
        zf.writestr("release-marker.txt", f"{version_marker}\n")
        if include_dll:
            zf.writestr("Listenarr.Api.dll", f"legacy-dll-{version_marker}\n")
    digest = hashlib.sha256(dest.read_bytes()).hexdigest()
    return dest, digest


def _official_release(
    tag: str,
    *,
    prerelease: bool = True,
    draft: bool = False,
    asset_name: str | None = None,
    asset_url: str | None = None,
    digest: str | None = None,
    extra_assets: list[dict] | None = None,
) -> dict:
    ver = tag[1:] if tag.startswith(("v", "V")) else tag
    assets: list[dict] = []
    if asset_name is not None:
        url = asset_url if asset_url is not None else (
            f"https://github.com/Listenarrs/Listenarr/releases/download/{tag}/{asset_name}"
        )
        entry: dict = {
            "name": asset_name,
            "browser_download_url": url,
        }
        if digest is not None:
            entry["digest"] = digest
        assets.append(entry)
    elif digest is not None or asset_url is not None:
        default_name = f"listenarr-{ver}-linux-x64.zip"
        url = asset_url if asset_url is not None else (
            f"https://github.com/Listenarrs/Listenarr/releases/download/{tag}/{default_name}"
        )
        entry = {"name": default_name, "browser_download_url": url}
        if digest is not None:
            entry["digest"] = digest
        assets.append(entry)
    if extra_assets:
        assets.extend(extra_assets)
    return {
        "tag_name": tag,
        "prerelease": prerelease,
        "draft": draft,
        "html_url": f"https://github.com/Listenarrs/Listenarr/releases/tag/{tag}",
        "assets": assets,
    }


def _patch_command(fixture: InstallerFixture, name: str, old: str, new: str) -> None:
    patched = False
    for directory in (fixture.commands, fixture.root / "usr/bin", fixture.root / "usr/sbin"):
        target = directory / name
        if target.exists():
            text = target.read_text(encoding="utf-8")
            if old in text:
                target.write_text(text.replace(old, new), encoding="utf-8")
                target.chmod(0o755)
                patched = True
    if not patched:
        raise AssertionError(f"failed to patch command {name!r}")


def _commands(fixture: InstallerFixture) -> list[list[str]]:
    log = fixture.root / "commands.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line.strip()]


class ListenarrReleasePolicyTests(unittest.TestCase):
    def test_catalog_and_operator_policy_scoped_to_listenarr(self):
        packages = json.loads((ROOT / "config/packages.json").read_text())
        automation = json.loads((ROOT / "config/package_automation.json").read_text())

        self.assertEqual(len(packages), 77)
        self.assertEqual(len(automation), 77)

        prerelease_packages = [
            name for name, spec in automation.items()
            if str(spec.get("update_channel", "")).strip().lower() == "prerelease"
        ]
        self.assertEqual(prerelease_packages, ["listenarr"])

        spec = automation["listenarr"]
        self.assertEqual(spec["update_source"], "github")
        self.assertEqual(spec["update_repo"], "Listenarrs/Listenarr")
        self.assertEqual(spec["update_channel"], "prerelease")
        self.assertTrue(spec["require_download_sha256"])
        self.assertEqual(spec["version_command"], ["cat", "/opt/Listenarr/.af-version"])
        self.assertNotIn("Listenarr.Api.dll", json.dumps(spec))
        self.assertNotIn("Listenarr.Api", json.dumps(spec))

        pkg = next(item for item in packages if item["name"] == "listenarr")
        desc_lower = pkg["description"].lower()
        self.assertIn("prerelease", desc_lower)
        self.assertIn("x64", desc_lower)

        packages_readme = (ROOT / "packages/README.md").read_text().lower()
        self.assertIn("listenarr", packages_readme)
        self.assertIn("prerelease", packages_readme)
        self.assertIn("linux x64", packages_readme)

        marketplace_doc = (ROOT / "docs/marketplace.md").read_text().lower()
        self.assertIn("### listenarr", marketplace_doc)
        self.assertIn("prerelease", marketplace_doc)
        self.assertIn("arm64", marketplace_doc)

    def test_normal_install_selects_official_prerelease_verified_shape_without_dll_or_exec(self):
        with InstallerFixture("listenarr") as fixture:
            z_106, sha_106 = _build_listenarr_zip(fixture.root / "listenarr-1.10.6-canary.zip", "1.10.6-canary")
            z_105, sha_105 = _build_listenarr_zip(fixture.root / "listenarr-1.10.5-canary.zip", "1.10.5-canary")
            z_0271, sha_0271 = _build_listenarr_zip(fixture.root / "listenarr-0.2.71.zip", "0.2.71")
            z_draft, sha_draft = _build_listenarr_zip(fixture.root / "listenarr-1.11.0-canary.zip", "1.11.0-canary")

            releases = [
                _official_release("v1.11.0-canary", prerelease=True, draft=True, digest=f"sha256:{sha_draft}"),
                _official_release(
                    "v1.10.7-canary",
                    prerelease=True,
                    draft=False,
                    extra_assets=[{
                        "name": "listenarr-1.10.7-canary-win-x64.zip",
                        "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.7-canary/listenarr-1.10.7-canary-win-x64.zip",
                        "digest": f"sha256:{sha_106}",
                    }],
                ),
                _official_release("v1.10.5-canary", prerelease=True, draft=False, digest=f"sha256:{sha_105}"),
                _official_release("v1.10.6-canary", prerelease=True, draft=False, digest=f"sha256:{sha_106}"),
                _official_release("0.2.71", prerelease=True, draft=False, digest=f"sha256:{sha_0271}"),
            ]
            releases_file = fixture.file("listenarr-releases.json", json.dumps(releases))
            asset_map_file = fixture.file("listenarr-assets.json", json.dumps({
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip": str(z_106),
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.5-canary/listenarr-1.10.5-canary-linux-x64.zip": str(z_105),
                "https://github.com/Listenarrs/Listenarr/releases/download/0.2.71/listenarr-0.2.71-linux-x64.zip": str(z_0271),
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.11.0-canary/listenarr-1.11.0-canary-linux-x64.zip": str(z_draft),
            }))

            result = fixture.run(
                "install",
                AF_FIXTURE_LISTENARR_RELEASES_FILE=str(releases_file),
                AF_FIXTURE_LISTENARR_ASSET_MAP=str(asset_map_file),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

            # Version receipt matches v1.10.6-canary without standalone Listenarr.Api.dll
            self.assertEqual((fixture.root / "opt/Listenarr/.af-version").read_text(), "1.10.6-canary\n")
            self.assertEqual((fixture.root / "opt/Listenarr/release-marker.txt").read_text(), "1.10.6-canary\n")
            self.assertFalse((fixture.root / "opt/Listenarr/Listenarr.Api.dll").exists())
            self.assertTrue((fixture.root / "opt/Listenarr/Listenarr.Api").is_file())
            self.assertTrue(bool((fixture.root / "opt/Listenarr/Listenarr.Api").stat().st_mode & stat.S_IXUSR))
            self.assertTrue(bool((fixture.root / "opt/Listenarr/ffprobe").stat().st_mode & stat.S_IXUSR))
            self.assertTrue((fixture.root / "opt/Listenarr/wwwroot/index.html").is_file())
            self.assertNotIn("must not be executed", result.stdout + result.stderr)

            # Config symlink points to /var/lib/listenarr/config
            config_link = fixture.root / "opt/Listenarr/config"
            self.assertTrue(config_link.is_symlink())
            self.assertEqual(os.path.realpath(config_link), os.path.realpath(fixture.root / "var/lib/listenarr/config"))

            # Operator-visible log states prerelease policy and exact asset selection
            install_log = (fixture.root / "var/log/aetherflow/install-listenarr.log").read_text()
            self.assertIn("prerelease", install_log.lower())
            self.assertIn("v1.10.6-canary", install_log)
            self.assertIn("listenarr-1.10.6-canary-linux-x64.zip", install_log)

            # Download command targeted exact official URL
            curl_cmds = [cmd for cmd in _commands(fixture) if cmd[0] == "curl"]
            downloaded_urls = [arg for cmd in curl_cmds for arg in cmd[1:] if arg.startswith("https://github.com/")]
            self.assertIn(
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip",
                downloaded_urls,
            )

    def test_normal_install_prefers_future_stable_over_same_version_prerelease(self):
        with InstallerFixture("listenarr") as fixture:
            z_pre, sha_pre = _build_listenarr_zip(fixture.root / "listenarr-1.10.6-canary.zip", "1.10.6-canary")
            z_stable, sha_stable = _build_listenarr_zip(fixture.root / "listenarr-1.10.6.zip", "1.10.6")

            releases = [
                _official_release("v1.10.6-canary", prerelease=True, draft=False, digest=f"sha256:{sha_pre}"),
                _official_release("v1.10.6", prerelease=False, draft=False, digest=f"sha256:{sha_stable}"),
            ]
            releases_file = fixture.file("listenarr-releases.json", json.dumps(releases))
            asset_map_file = fixture.file("listenarr-assets.json", json.dumps({
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip": str(z_pre),
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6/listenarr-1.10.6-linux-x64.zip": str(z_stable),
            }))

            result = fixture.run(
                "install",
                AF_FIXTURE_LISTENARR_RELEASES_FILE=str(releases_file),
                AF_FIXTURE_LISTENARR_ASSET_MAP=str(asset_map_file),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((fixture.root / "opt/Listenarr/.af-version").read_text(), "1.10.6\n")
            self.assertEqual((fixture.root / "opt/Listenarr/release-marker.txt").read_text(), "1.10.6\n")

    def test_exact_target_selection_and_sha256_binding(self):
        cases = (
            ("1.10.5-canary", "1.10.5-canary", "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.5-canary/listenarr-1.10.5-canary-linux-x64.zip"),
            ("v1.10.5-canary", "1.10.5-canary", "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.5-canary/listenarr-1.10.5-canary-linux-x64.zip"),
            ("0.2.71", "0.2.71", "https://github.com/Listenarrs/Listenarr/releases/download/0.2.71/listenarr-0.2.71-linux-x64.zip"),
            ("v0.2.71", "0.2.71", "https://github.com/Listenarrs/Listenarr/releases/download/0.2.71/listenarr-0.2.71-linux-x64.zip"),
        )
        for requested, expected_version, expected_url in cases:
            with self.subTest(requested=requested), InstallerFixture("listenarr") as fixture:
                z_106, sha_106 = _build_listenarr_zip(fixture.root / "listenarr-1.10.6-canary.zip", "1.10.6-canary")
                z_105, sha_105 = _build_listenarr_zip(fixture.root / "listenarr-1.10.5-canary.zip", "1.10.5-canary")
                z_0271, sha_0271 = _build_listenarr_zip(fixture.root / "listenarr-0.2.71.zip", "0.2.71")

                releases = [
                    _official_release("v1.10.6-canary", prerelease=True, draft=False, digest=f"sha256:{sha_106}"),
                    _official_release("v1.10.5-canary", prerelease=True, draft=False, digest=f"sha256:{sha_105}"),
                    _official_release("0.2.71", prerelease=True, draft=False, digest=f"sha256:{sha_0271}"),
                ]
                releases_file = fixture.file("listenarr-releases.json", json.dumps(releases))
                asset_map_file = fixture.file("listenarr-assets.json", json.dumps({
                    "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip": str(z_106),
                    "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.5-canary/listenarr-1.10.5-canary-linux-x64.zip": str(z_105),
                    "https://github.com/Listenarrs/Listenarr/releases/download/0.2.71/listenarr-0.2.71-linux-x64.zip": str(z_0271),
                }))

                result = fixture.run(
                    "install",
                    AF_TARGET_VERSION=requested,
                    AF_FIXTURE_LISTENARR_RELEASES_FILE=str(releases_file),
                    AF_FIXTURE_LISTENARR_ASSET_MAP=str(asset_map_file),
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((fixture.root / "opt/Listenarr/.af-version").read_text(), f"{expected_version}\n")
                self.assertEqual((fixture.root / "opt/Listenarr/release-marker.txt").read_text(), f"{expected_version}\n")

                curl_urls = [
                    arg for cmd in _commands(fixture) if cmd[0] == "curl"
                    for arg in cmd[1:] if arg.startswith("https://github.com/")
                ]
                self.assertEqual(curl_urls, [expected_url])

        # Tampered bytes must fail SHA-256 verification and refuse installation
        with self.subTest(case="tampered-sha256-mismatch"), InstallerFixture("listenarr") as fixture:
            z_105, sha_105 = _build_listenarr_zip(fixture.root / "listenarr-1.10.5-canary.zip", "1.10.5-canary")
            z_tampered, _ = _build_listenarr_zip(fixture.root / "listenarr-tampered.zip", "TAMPERED")
            releases = [
                _official_release("v1.10.5-canary", prerelease=True, draft=False, digest=f"sha256:{sha_105}"),
            ]
            releases_file = fixture.file("listenarr-releases.json", json.dumps(releases))
            asset_map_file = fixture.file("listenarr-assets.json", json.dumps({
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.5-canary/listenarr-1.10.5-canary-linux-x64.zip": str(z_tampered),
            }))

            result = fixture.run(
                "install",
                AF_TARGET_VERSION="1.10.5-canary",
                AF_FIXTURE_LISTENARR_RELEASES_FILE=str(releases_file),
                AF_FIXTURE_LISTENARR_ASSET_MAP=str(asset_map_file),
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse((fixture.root / "opt/Listenarr/.af-version").exists())
            self.assertFalse(fixture.lock.exists())

    def test_early_unsupported_architecture_fails_before_network_or_host_mutation(self):
        for dpkg_arch, uname_m in (("arm64", "aarch64"), ("armhf", "armv7l")):
            with self.subTest(arch=dpkg_arch), InstallerFixture("listenarr") as fixture:
                _patch_command(
                    fixture,
                    "dpkg",
                    "print('amd64' if '--print-architecture' in arguments else '')",
                    f"print({dpkg_arch!r} if '--print-architecture' in arguments else '')",
                )
                _patch_command(
                    fixture,
                    "uname",
                    "elif command == 'uname': print('x86_64')",
                    f"elif command == 'uname': print({uname_m!r})",
                )
                result = fixture.run("install")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                combined = (result.stdout + result.stderr).lower()
                self.assertIn(dpkg_arch, combined)
                self.assertIn("linux x64", combined)

                cmds = [cmd[0] for cmd in _commands(fixture)]
                for forbidden in ("curl", "apt-get", "useradd", "systemctl"):
                    self.assertNotIn(forbidden, cmds, f"{forbidden} must not run on unsupported arch {dpkg_arch}")
                self.assertFalse((fixture.root / "opt/Listenarr").exists())
                self.assertFalse(fixture.lock.exists())

    def test_early_invalid_and_unavailable_target_failures_precede_host_mutation(self):
        # 1. Invalid / floating tokens fail before ANY network or host mutation
        for bad_target in ("latest", "canary", "prerelease", "stable", "../v1.10.6-canary", "   "):
            with self.subTest(bad_target=bad_target), InstallerFixture("listenarr") as fixture:
                result = fixture.run("install", AF_TARGET_VERSION=bad_target)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                cmds = [cmd[0] for cmd in _commands(fixture)]
                for forbidden in ("curl", "apt-get", "useradd", "systemctl"):
                    self.assertNotIn(forbidden, cmds, f"{forbidden} must not run for invalid target {bad_target!r}")
                self.assertFalse((fixture.root / "opt/Listenarr").exists())

        # 2. Unavailable, draft, missing-arch-asset, missing-digest, malformed-digest, and untrusted-URL targets
        #    all fail before apt-get, useradd, systemctl, or /opt/Listenarr mutation.
        dummy_sha = "a" * 64
        scenarios = (
            (
                "missing-tag",
                "9.9.9-canary",
                [_official_release("v1.10.6-canary", digest=f"sha256:{dummy_sha}")],
                "not found",
            ),
            (
                "draft-tag",
                "1.11.0-canary",
                [_official_release("v1.11.0-canary", draft=True, digest=f"sha256:{dummy_sha}")],
                "draft",
            ),
            (
                "target-missing-linux-x64-asset",
                "1.10.7-canary",
                [_official_release(
                    "v1.10.7-canary",
                    extra_assets=[{
                        "name": "listenarr-1.10.7-canary-win-x64.zip",
                        "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.7-canary/listenarr-1.10.7-canary-win-x64.zip",
                        "digest": f"sha256:{dummy_sha}",
                    }],
                )],
                "linux-x64.zip",
            ),
            (
                "missing-sha256-digest",
                "1.10.6-canary",
                [_official_release("v1.10.6-canary", asset_name="listenarr-1.10.6-canary-linux-x64.zip", digest=None)],
                "sha-256",
            ),
            (
                "malformed-sha256-digest",
                "1.10.6-canary",
                [_official_release("v1.10.6-canary", digest="sha256:not-a-valid-hex-digest")],
                "malformed",
            ),
            (
                "cross-tag-asset-url",
                "1.10.6-canary",
                [_official_release(
                    "v1.10.6-canary",
                    asset_name="listenarr-1.10.6-canary-linux-x64.zip",
                    asset_url="https://github.com/Listenarrs/Listenarr/releases/download/v1.10.5-canary/listenarr-1.10.6-canary-linux-x64.zip",
                    digest=f"sha256:{dummy_sha}",
                )],
                "untrusted or cross-tag",
            ),
            (
                "untrusted-host-asset-url",
                "1.10.6-canary",
                [_official_release(
                    "v1.10.6-canary",
                    asset_name="listenarr-1.10.6-canary-linux-x64.zip",
                    asset_url="https://evil.example/listenarr-1.10.6-canary-linux-x64.zip",
                    digest=f"sha256:{dummy_sha}",
                )],
                "untrusted or cross-tag",
            ),
            (
                "normal-zero-x64-releases",
                None,
                [_official_release(
                    "v1.10.7-canary",
                    extra_assets=[{
                        "name": "listenarr-1.10.7-canary-osx-arm64.zip",
                        "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.7-canary/listenarr-1.10.7-canary-osx-arm64.zip",
                        "digest": f"sha256:{dummy_sha}",
                    }],
                )],
                "linux-x64.zip",
            ),
        )
        for name, target, releases, expected_fragment in scenarios:
            with self.subTest(scenario=name), InstallerFixture("listenarr") as fixture:
                releases_file = fixture.file("listenarr-releases.json", json.dumps(releases))
                env = {"AF_FIXTURE_LISTENARR_RELEASES_FILE": str(releases_file)}
                if target is not None:
                    env["AF_TARGET_VERSION"] = target
                result = fixture.run("install", **env)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(expected_fragment, (result.stdout + result.stderr).lower())

                cmds = [cmd[0] for cmd in _commands(fixture)]
                for forbidden in ("apt-get", "useradd", "systemctl"):
                    self.assertNotIn(forbidden, cmds, f"{forbidden} must not run for failure scenario {name}")
                self.assertFalse((fixture.root / "opt/Listenarr").exists())
                self.assertFalse(fixture.lock.exists())

    def test_retained_configuration_and_safe_legacy_migration(self):
        with InstallerFixture("listenarr") as fixture:
            z_105, sha_105 = _build_listenarr_zip(fixture.root / "listenarr-1.10.5-canary.zip", "1.10.5-canary")
            z_106, sha_106 = _build_listenarr_zip(fixture.root / "listenarr-1.10.6-canary.zip", "1.10.6-canary")
            releases = [
                _official_release("v1.10.5-canary", digest=f"sha256:{sha_105}"),
                _official_release("v1.10.6-canary", digest=f"sha256:{sha_106}"),
            ]
            releases_file = fixture.file("listenarr-releases.json", json.dumps(releases))
            asset_map_file = fixture.file("listenarr-assets.json", json.dumps({
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.5-canary/listenarr-1.10.5-canary-linux-x64.zip": str(z_105),
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip": str(z_106),
            }))

            # Seed pre-fix legacy install with real /opt/Listenarr/config directory and custom unit settings
            fixture.file("opt/Listenarr/Listenarr.Api", "#!/bin/sh\nexit 0\n").chmod(0o755)
            fixture.file("opt/Listenarr/.af-version", "0.2.71\n")
            fixture.file("opt/Listenarr/config/database/listenarr.db", "SQLITE-LEGACY-DB-CONTENT")
            fixture.file("opt/Listenarr/config/appsettings.json", '{"OperatorSetting": "keep-this"}\n')
            fixture.file(
                "etc/systemd/system/listenarr.service",
                "[Unit]\nDescription=Listenarr\n\n[Service]\n"
                "Environment=\"ASPNETCORE_URLS=http://127.0.0.1:4646\"\n"
                "Environment=\"LISTENARR_CUSTOM_FLAG=preserved-value\"\n"
                "ExecStart=/opt/Listenarr/Listenarr.Api\n",
            )

            # Update with port=0 (AF_APP_PORT unset) to verify port, bind host, custom env, and legacy config migration
            update_105 = fixture.run(
                "update",
                port=0,
                AF_TARGET_VERSION="1.10.5-canary",
                AF_FIXTURE_LISTENARR_RELEASES_FILE=str(releases_file),
                AF_FIXTURE_LISTENARR_ASSET_MAP=str(asset_map_file),
            )
            self.assertEqual(update_105.returncode, 0, update_105.stdout + update_105.stderr)
            self.assertEqual((fixture.root / "opt/Listenarr/.af-version").read_text(), "1.10.5-canary\n")

            config_link = fixture.root / "opt/Listenarr/config"
            self.assertTrue(config_link.is_symlink())
            self.assertEqual(os.path.realpath(config_link), os.path.realpath(fixture.root / "var/lib/listenarr/config"))
            self.assertEqual(
                (fixture.root / "var/lib/listenarr/config/database/listenarr.db").read_text(),
                "SQLITE-LEGACY-DB-CONTENT",
            )
            self.assertEqual(
                (fixture.root / "var/lib/listenarr/config/appsettings.json").read_text(),
                '{"OperatorSetting": "keep-this"}\n',
            )
            unit_text = (fixture.root / "etc/systemd/system/listenarr.service").read_text()
            self.assertIn("ASPNETCORE_URLS=http://127.0.0.1:4646", unit_text)
            self.assertIn('Environment="LISTENARR_CUSTOM_FLAG=preserved-value"', unit_text)

            # Subsequent update to v1.10.6-canary retains migrated config and service customizations
            update_106 = fixture.run(
                "update",
                port=0,
                AF_TARGET_VERSION="1.10.6-canary",
                AF_FIXTURE_LISTENARR_RELEASES_FILE=str(releases_file),
                AF_FIXTURE_LISTENARR_ASSET_MAP=str(asset_map_file),
            )
            self.assertEqual(update_106.returncode, 0, update_106.stdout + update_106.stderr)
            self.assertEqual((fixture.root / "opt/Listenarr/.af-version").read_text(), "1.10.6-canary\n")
            self.assertEqual(
                (fixture.root / "var/lib/listenarr/config/database/listenarr.db").read_text(),
                "SQLITE-LEGACY-DB-CONTENT",
            )
            self.assertIn("ASPNETCORE_URLS=http://127.0.0.1:4646", (fixture.root / "etc/systemd/system/listenarr.service").read_text())

            # Ordinary uninstall removes /opt/Listenarr (unlinking symlink) without deleting /var/lib/listenarr/config
            removed = fixture.run("remove", DELETE_DATA="false")
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            self.assertFalse((fixture.root / "opt/Listenarr").exists())
            self.assertEqual(
                (fixture.root / "var/lib/listenarr/config/database/listenarr.db").read_text(),
                "SQLITE-LEGACY-DB-CONTENT",
            )

            # Reinstall after retained uninstall re-links /opt/Listenarr/config and preserves data
            reinstalled = fixture.run(
                "install",
                AF_FIXTURE_LISTENARR_RELEASES_FILE=str(releases_file),
                AF_FIXTURE_LISTENARR_ASSET_MAP=str(asset_map_file),
            )
            self.assertEqual(reinstalled.returncode, 0, reinstalled.stdout + reinstalled.stderr)
            self.assertTrue((fixture.root / "opt/Listenarr/config").is_symlink())
            self.assertEqual(
                (fixture.root / "opt/Listenarr/config/database/listenarr.db").read_text(),
                "SQLITE-LEGACY-DB-CONTENT",
            )

            # Explicit purge removes /var/lib/listenarr
            purged = fixture.run("remove", DELETE_DATA="true")
            self.assertEqual(purged.returncode, 0, purged.stdout + purged.stderr)
            self.assertFalse((fixture.root / "var/lib/listenarr").exists())

    def test_legacy_migration_fails_closed_and_rolls_back_on_symlink_or_conflict(self):
        # Case A: Unsafe symlink inside legacy /opt/Listenarr/config
        with self.subTest(case="symlink-in-legacy-config"), InstallerFixture("listenarr") as fixture:
            z_106, sha_106 = _build_listenarr_zip(fixture.root / "listenarr-1.10.6-canary.zip", "1.10.6-canary")
            releases_file = fixture.file("listenarr-releases.json", json.dumps([
                _official_release("v1.10.6-canary", digest=f"sha256:{sha_106}"),
            ]))
            asset_map_file = fixture.file("listenarr-assets.json", json.dumps({
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip": str(z_106),
            }))

            fixture.file("opt/Listenarr/Listenarr.Api", "#!/bin/sh\nexit 0\n").chmod(0o755)
            fixture.file("opt/Listenarr/.af-version", "0.2.71\n")
            fixture.file("opt/Listenarr/config/appsettings.json", '{"legacy": true}\n')
            outside = fixture.file("etc/secret-target", "do-not-copy\n")
            (fixture.root / "opt/Listenarr/config/evil-link").symlink_to(outside)

            result = fixture.run(
                "update",
                AF_FIXTURE_LISTENARR_RELEASES_FILE=str(releases_file),
                AF_FIXTURE_LISTENARR_ASSET_MAP=str(asset_map_file),
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("symlink", (result.stdout + result.stderr).lower())
            # Rollback restored previous installation intact
            self.assertEqual((fixture.root / "opt/Listenarr/.af-version").read_text(), "0.2.71\n")
            self.assertEqual((fixture.root / "opt/Listenarr/config/appsettings.json").read_text(), '{"legacy": true}\n')
            self.assertFalse((fixture.root / "var/lib/listenarr/config/evil-link").exists())

        # Case B: Divergent conflicting file already exists in both legacy and /var/lib/listenarr/config
        with self.subTest(case="divergent-config-conflict"), InstallerFixture("listenarr") as fixture:
            z_106, sha_106 = _build_listenarr_zip(fixture.root / "listenarr-1.10.6-canary.zip", "1.10.6-canary")
            releases_file = fixture.file("listenarr-releases.json", json.dumps([
                _official_release("v1.10.6-canary", digest=f"sha256:{sha_106}"),
            ]))
            asset_map_file = fixture.file("listenarr-assets.json", json.dumps({
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip": str(z_106),
            }))

            fixture.file("opt/Listenarr/Listenarr.Api", "#!/bin/sh\nexit 0\n").chmod(0o755)
            fixture.file("opt/Listenarr/.af-version", "0.2.71\n")
            fixture.file("opt/Listenarr/config/appsettings.json", '{"source": "legacy"}\n')
            fixture.file("var/lib/listenarr/config/appsettings.json", '{"source": "existing-var-lib"}\n')

            result = fixture.run(
                "update",
                AF_FIXTURE_LISTENARR_RELEASES_FILE=str(releases_file),
                AF_FIXTURE_LISTENARR_ASSET_MAP=str(asset_map_file),
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("conflict", (result.stdout + result.stderr).lower())
            # Both files preserved untouched after rollback
            self.assertEqual((fixture.root / "opt/Listenarr/.af-version").read_text(), "0.2.71\n")
            self.assertEqual((fixture.root / "opt/Listenarr/config/appsettings.json").read_text(), '{"source": "legacy"}\n')
            self.assertEqual((fixture.root / "var/lib/listenarr/config/appsettings.json").read_text(), '{"source": "existing-var-lib"}\n')

        # Case C: Service activation failure after legacy migration rolls back prior runtime and legacy config
        with self.subTest(case="activation-failure-rollback"), InstallerFixture("listenarr") as fixture:
            z_106, sha_106 = _build_listenarr_zip(fixture.root / "listenarr-1.10.6-canary.zip", "1.10.6-canary")
            releases_file = fixture.file("listenarr-releases.json", json.dumps([
                _official_release("v1.10.6-canary", digest=f"sha256:{sha_106}"),
            ]))
            asset_map_file = fixture.file("listenarr-assets.json", json.dumps({
                "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip": str(z_106),
            }))

            fixture.file("opt/Listenarr/Listenarr.Api", "#!/bin/sh\nexit 0\n").chmod(0o755)
            fixture.file("opt/Listenarr/.af-version", "0.2.71\n")
            fixture.file("opt/Listenarr/config/database/listenarr.db", "PRE-UPGRADE-DB")
            fixture.file("etc/systemd/system/listenarr.service", "[Service]\nExecStart=/opt/Listenarr/Listenarr.Api\n")

            result = fixture.run(
                "update",
                AF_FIXTURE_FAILURE="readiness",
                AF_FIXTURE_LISTENARR_RELEASES_FILE=str(releases_file),
                AF_FIXTURE_LISTENARR_ASSET_MAP=str(asset_map_file),
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((fixture.root / "opt/Listenarr/.af-version").read_text(), "0.2.71\n")
            self.assertEqual((fixture.root / "opt/Listenarr/config/database/listenarr.db").read_text(), "PRE-UPGRADE-DB")


if __name__ == "__main__":
    unittest.main()
