"""Scoped tests for Threadfin pinned and Pi-hole vendor-managed exact-version policies."""
import hashlib
import json
import os
import shutil
import unittest
from pathlib import Path

from tests.test_marketplace_catalog_lifecycle_matrix import InstallerFixture

ROOT = Path(__file__).resolve().parents[1]

THREADFIN_PINNED_VERSION = "1.2.37"
THREADFIN_PINNED_DIGESTS = {
    "amd64": (
        "Threadfin_linux_amd64_glibc_2.31_compat",
        "0b80a1bb5dc270c35288531408657189fd27c2e4346686743ebd36f3b6acbe42",
    ),
    "arm64": (
        "Threadfin_linux_arm64",
        "1e5e6f065cf2470d1460fae80c68c9631ca79e67ff76f83d47ab4bcb9ceb6213",
    ),
    "armhf": (
        "Threadfin_linux_arm",
        "d64e6b7f8a1ab8aebdd37d06bfb0bddb991c68c9fed52e25530b92ead10c8328",
    ),
}


def _commands(fixture: InstallerFixture) -> list[list[str]]:
    log = fixture.root / "commands.jsonl"
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines() if line]


def _patch_command(fixture: InstallerFixture, command: str, old: str, new: str) -> None:
    for directory in (fixture.commands, fixture.root / "usr/bin", fixture.root / "usr/sbin"):
        path = directory / command
        source = path.read_text()
        assert old in source, f"{old!r} not found in {path}"
        path.write_text(source.replace(old, new, 1))


class RegistryExactVersionMetadataTests(unittest.TestCase):
    def test_threadfin_and_pihole_automation_metadata_are_truthful(self):
        automation = json.loads((ROOT / "config/package_automation.json").read_text(encoding="utf-8"))

        threadfin = automation["threadfin"]
        self.assertEqual(threadfin["update_source"], "pinned")
        self.assertEqual(threadfin["update_package"], THREADFIN_PINNED_VERSION)
        self.assertTrue(threadfin["require_download_sha256"])
        self.assertNotIn("update_repo", threadfin)
        self.assertEqual(threadfin["version_command"], ["cat", "/var/lib/threadfin/.af-version"])

        pihole = automation["pihole"]
        self.assertEqual(pihole["update_source"], "vendor")
        self.assertNotIn("update_repo", pihole)
        self.assertTrue(pihole["require_download_sha256"])
        self.assertEqual(pihole["version_command"], ["/usr/bin/pihole-FTL", "-v"])

        installer = (ROOT / "packages/package/install/installpackage-threadfin").read_text(encoding="utf-8")
        self.assertNotIn("github_latest_tag", installer)
        for asset, digest in THREADFIN_PINNED_DIGESTS.values():
            self.assertIn(asset, installer)
            self.assertIn(digest, installer)


class ThreadfinExactVersionPolicyTests(unittest.TestCase):
    def test_threadfin_pinned_arch_urls_and_exact_target_acceptance(self):
        for arch, (expected_asset, _expected_digest) in THREADFIN_PINNED_DIGESTS.items():
            for target in (None, "1.2.37", "v1.2.37"):
                with self.subTest(arch=arch, target=target), InstallerFixture("threadfin") as fixture:
                    _patch_command(
                        fixture,
                        "dpkg",
                        "print('amd64' if '--print-architecture' in arguments else '')",
                        f"print({arch!r} if '--print-architecture' in arguments else '')",
                    )
                    env = {}
                    if target is not None:
                        env["AF_TARGET_VERSION"] = target
                    res = fixture.run("install", **env)
                    self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                    self.assertEqual(
                        (fixture.root / "var/lib/threadfin/.af-version").read_text().strip(),
                        THREADFIN_PINNED_VERSION,
                    )
                    self.assertTrue(fixture.lock.exists())

                    curl_urls = [
                        arg
                        for cmd in _commands(fixture)
                        if cmd and cmd[0] == "curl"
                        for arg in cmd[1:]
                        if arg.startswith("https://")
                    ]
                    expected_url = (
                        f"https://github.com/Threadfin/Threadfin/releases/download/"
                        f"{THREADFIN_PINNED_VERSION}/{expected_asset}"
                    )
                    self.assertIn(expected_url, curl_urls)
                    self.assertFalse(any("/releases/latest" in url for url in curl_urls), curl_urls)
                    self.assertFalse(any("/download/v1.2.37/" in url for url in curl_urls), curl_urls)

    def test_threadfin_enforces_pinned_sha256_without_override(self):
        for arch in THREADFIN_PINNED_DIGESTS:
            with self.subTest(arch=arch), InstallerFixture("threadfin") as fixture:
                _patch_command(
                    fixture,
                    "dpkg",
                    "print('amd64' if '--print-architecture' in arguments else '')",
                    f"print({arch!r} if '--print-architecture' in arguments else '')",
                )
                # Explicit None removes InstallerFixture's test SHA override so the real pinned digest is enforced.
                res = fixture.run("install", AF_THREADFIN_SHA256=None)
                self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertIn("SHA-256 digest mismatch", res.stderr)
                self.assertFalse(fixture.lock.exists())
                self.assertFalse((fixture.root / "var/lib/threadfin/.af-version").exists())
                self.assertFalse((fixture.root / "usr/local/bin/threadfin").exists())

    def test_threadfin_rejects_mismatched_target_before_state_mutation(self):
        for bad_target in ("1.2.36", "1.2.38", "99.9.9", "latest", "v1.2.36"):
            with self.subTest(target=bad_target), InstallerFixture("threadfin") as fixture:
                existing_settings = fixture.file(
                    "var/lib/threadfin/conf/settings.json",
                    '{"version": "0.5.0", "bindIpAddress": "127.0.0.1", "custom": "keep"}\n',
                )
                existing_ver = fixture.file("var/lib/threadfin/.af-version", "1.2.37\n")

                res = fixture.run("update", AF_TARGET_VERSION=bad_target)
                self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertFalse(
                    any(cmd and cmd[0] in ("apt-get", "curl", "systemctl", "useradd") for cmd in _commands(fixture)),
                    _commands(fixture),
                )
                self.assertEqual(
                    existing_settings.read_text(),
                    '{"version": "0.5.0", "bindIpAddress": "127.0.0.1", "custom": "keep"}\n',
                )
                self.assertEqual(existing_ver.read_text(), "1.2.37\n")
                self.assertFalse(fixture.lock.exists())

    def test_threadfin_rejects_unsupported_arch_and_bad_overrides_before_state_mutation(self):
        with InstallerFixture("threadfin") as fixture:
            _patch_command(
                fixture,
                "dpkg",
                "print('amd64' if '--print-architecture' in arguments else '')",
                "print('riscv64' if '--print-architecture' in arguments else '')",
            )
            res = fixture.run("install")
            self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("Unsupported architecture: riscv64", res.stderr)
            self.assertFalse(
                any(cmd and cmd[0] in ("apt-get", "curl", "systemctl") for cmd in _commands(fixture)),
                _commands(fixture),
            )

        for env in (
            {"AF_THREADFIN_VERSION": "1.2.36", "AF_THREADFIN_SHA256": None},
            {"AF_THREADFIN_SHA256": "skip"},
            {"AF_THREADFIN_SHA256": "not-a-valid-sha"},
            {"AF_THREADFIN_SHA256": ""},
        ):
            with self.subTest(env=env), InstallerFixture("threadfin") as fixture:
                res = fixture.run("install", **env)
                self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertFalse(
                    any(cmd and cmd[0] in ("apt-get", "curl", "systemctl") for cmd in _commands(fixture)),
                    _commands(fixture),
                )
                self.assertFalse(fixture.lock.exists())

    def test_threadfin_accepts_paired_version_and_sha_override_and_preserves_operator_config(self):
        with InstallerFixture("threadfin") as fixture:
            digest = hashlib.sha256((fixture.root / "host-command").read_bytes()).hexdigest()
            settings = fixture.file(
                "var/lib/threadfin/conf/settings.json",
                '{"version": "0.5.0", "bindIpAddress": "127.0.0.1", "operator": "retained"}\n',
            )

            mismatch = fixture.run(
                "update",
                AF_THREADFIN_VERSION="1.2.36",
                AF_THREADFIN_SHA256=digest,
                AF_TARGET_VERSION="1.2.37",
            )
            self.assertNotEqual(mismatch.returncode, 0, mismatch.stdout + mismatch.stderr)
            self.assertFalse(
                any(cmd and cmd[0] in ("apt-get", "curl", "systemctl") for cmd in _commands(fixture)),
                _commands(fixture),
            )

            ok = fixture.run(
                "update",
                AF_THREADFIN_VERSION="1.2.36",
                AF_THREADFIN_SHA256=digest,
                AF_TARGET_VERSION="1.2.36",
            )
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertEqual((fixture.root / "var/lib/threadfin/.af-version").read_text().strip(), "1.2.36")
            self.assertIn('"operator": "retained"', settings.read_text())
            curl_urls = [
                arg
                for cmd in _commands(fixture)
                if cmd and cmd[0] == "curl"
                for arg in cmd[1:]
                if arg.startswith("https://")
            ]
            self.assertIn(
                "https://github.com/Threadfin/Threadfin/releases/download/1.2.36/Threadfin_linux_amd64_glibc_2.31_compat",
                curl_urls,
            )

    def test_threadfin_seeds_loopback_settings_and_preserves_operator_config(self):
        # 1. Fresh install seeds version 0.5.0 + loopback bindIpAddress and HOME in unit
        with InstallerFixture("threadfin") as fixture:
            res = fixture.run("install", port=34401)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            settings_path = fixture.root / "var/lib/threadfin/conf/settings.json"
            self.assertTrue(settings_path.is_file())
            self.assertEqual(
                json.loads(settings_path.read_text(encoding="utf-8")),
                {"version": "0.5.0", "bindIpAddress": "127.0.0.1"},
            )
            unit_text = (fixture.root / "etc/systemd/system/threadfin.service").read_text(encoding="utf-8")
            self.assertIn(f"Environment=HOME={fixture.root}/var/lib/threadfin", unit_text)
            self.assertIn("-port=34401 -bind=127.0.0.1 -config=", unit_text)

        # 2. Existing settings with empty/null/missing bindIpAddress gets loopback default while keeping operator keys
        for initial in (
            '{"version": "0.5.0", "bindIpAddress": "", "tuner": 4, "custom": {"playlist": "keep"}}\n',
            '{"version": "0.5.0", "bindIpAddress": null, "tuner": 4, "custom": {"playlist": "keep"}}\n',
            '{"version": "0.5.0", "tuner": 4, "custom": {"playlist": "keep"}}\n',
        ):
            with self.subTest(initial=initial), InstallerFixture("threadfin") as fixture:
                settings_path = fixture.file("var/lib/threadfin/conf/settings.json", initial)
                res = fixture.run("reinstall", port=34401)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                updated = json.loads(settings_path.read_text(encoding="utf-8"))
                self.assertEqual(updated["version"], "0.5.0")
                self.assertEqual(updated["bindIpAddress"], "127.0.0.1")
                self.assertEqual(updated["tuner"], 4)
                self.assertEqual(updated["custom"], {"playlist": "keep"})

        # 3. Existing settings with explicit non-empty bindIpAddress is preserved byte-for-byte
        for explicit in (
            '{"version":"0.5.0","bindIpAddress":"127.0.0.1","custom":"exact-bytes"}\n',
            '{"version":"0.5.0","bindIpAddress":"192.0.2.10","custom":"exact-bytes"}\n',
        ):
            with self.subTest(explicit=explicit), InstallerFixture("threadfin") as fixture:
                settings_path = fixture.file("var/lib/threadfin/conf/settings.json", explicit)
                res = fixture.run("reinstall", port=34401)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertEqual(settings_path.read_text(encoding="utf-8"), explicit)

    def test_threadfin_rejects_malformed_or_symlinked_settings_fail_closed(self):
        for bad_payload in (
            "{not-valid-json",
            "[]\n",
            '{"bindIpAddress": ""}\n',
            '{"version": "", "bindIpAddress": ""}\n',
            '{"version": "0.5.0", "bindIpAddress": 42}\n',
        ):
            with self.subTest(bad_payload=bad_payload), InstallerFixture("threadfin") as fixture:
                settings_path = fixture.file("var/lib/threadfin/conf/settings.json", bad_payload)
                res = fixture.run("install", port=34401)
                self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertFalse(fixture.lock.exists())
                self.assertEqual(settings_path.read_text(encoding="utf-8"), bad_payload)

        with InstallerFixture("threadfin") as fixture:
            outside = fixture.file("srv/outside-settings.json", '{"version":"0.5.0","bindIpAddress":""}\n')
            conf_dir = fixture.root / "var/lib/threadfin/conf"
            conf_dir.mkdir(parents=True, exist_ok=True)
            link_path = conf_dir / "settings.json"
            link_path.symlink_to(outside)
            res = fixture.run("install", port=34401)
            self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertFalse(fixture.lock.exists())
            self.assertEqual(outside.read_text(encoding="utf-8"), '{"version":"0.5.0","bindIpAddress":""}\n')


class PiHoleExactVersionPolicyTests(unittest.TestCase):
    def test_pihole_rejects_any_af_target_version_before_any_state_mutation(self):
        for target in ("6.8", "6.9", "v6.9", "latest", "   "):
            with self.subTest(target=target), InstallerFixture("pihole") as fixture:
                shutil.rmtree(fixture.root / "etc/lighttpd")
                stub = fixture.file("run/systemd/resolve/stub-resolv.conf", "nameserver 127.0.0.53\n")
                resolver = fixture.root / "etc/resolv.conf"
                resolver.unlink()
                resolver.symlink_to(stub)
                fixture.file("active-systemd-resolved.service", "active\n")
                original_toml = (
                    '[dns]\nupstreams = ["9.9.9.9"]\n'
                    '[webserver]\nport = "8089o"\n'
                    '[webserver.api]\npwhash = "operator-retained-hash"\n'
                )
                toml_path = fixture.file("etc/pihole/pihole.toml", original_toml)
                ver_path = fixture.file("etc/pihole/.af-version", "6.8\n")

                res = fixture.run(
                    "update",
                    port=18089,
                    AF_TARGET_VERSION=target,
                    AF_FIXTURE_PIHOLE_FTL_VERSION="v6.9",
                )
                self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertIn("cannot honor exact target version pins", res.stderr)
                mutating = [
                    cmd
                    for cmd in _commands(fixture)
                    if cmd and cmd[0] not in ("python3",)
                ]
                self.assertEqual(mutating, [], f"Unexpected host commands before rejecting AF_TARGET_VERSION: {mutating}")
                self.assertEqual(os.readlink(resolver), str(stub))
                self.assertFalse((fixture.root / "etc/systemd/resolved.conf.d/pihole.conf").exists())
                self.assertEqual(toml_path.read_text(), original_toml)
                self.assertEqual(ver_path.read_text(), "6.8\n")
                self.assertFalse(fixture.lock.exists())

    def test_pihole_unpinned_install_preserves_bootstrap_checksum_and_records_ftl_version(self):
        with InstallerFixture("pihole") as fixture:
            bad = fixture.run("install", port=18089, AF_PIHOLE_BOOTSTRAP_SHA256="0" * 64)
            self.assertNotEqual(bad.returncode, 0, bad.stdout + bad.stderr)
            self.assertFalse(fixture.lock.exists())

            ok = fixture.run("install", port=18089, AF_FIXTURE_PIHOLE_FTL_VERSION="v6.9")
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            self.assertEqual((fixture.root / "etc/pihole/.af-version").read_text().strip(), "6.9")
            self.assertTrue(fixture.lock.exists())


if __name__ == "__main__":
    unittest.main()
