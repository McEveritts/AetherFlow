"""Targeted fixtures for Notifiarr and Unpackerr Servarr effective-URL workflows."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility
    tomllib = None

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import common_functions, replace_paths_once
from test_marketplace_catalog_lifecycle_matrix import InstallerFixture


def parse_toml(text):
    if tomllib is not None:
        return tomllib.loads(text)
    raise unittest.SkipTest("tomllib unavailable on Python < 3.11")


def servarr_xml(api_key=None, port=None, url_base=None, bind_address=None, extra=""):
    parts = ["<Config>"]
    if bind_address is not None:
        parts.append(f"  <BindAddress>{bind_address}</BindAddress>")
    if port is not None:
        parts.append(f"  <Port>{port}</Port>")
    if url_base is not None:
        parts.append(f"  <UrlBase>{url_base}</UrlBase>")
    if api_key is not None:
        parts.append(f"  <ApiKey>{api_key}</ApiKey>")
    if extra:
        parts.append(extra)
    parts.append("</Config>\n")
    return "\n".join(parts)


class MarketplaceServarrIntegrationTests(unittest.TestCase):
    def fixture(self, app):
        fx = InstallerFixture(app)
        self.addCleanup(fx.close)
        return fx

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_no_tokens_exposed(self, fixture, result, tokens):
        log_dir = fixture.root / "var/log/aetherflow"
        log_text = "\n".join(
            path.read_text(errors="replace")
            for path in sorted(log_dir.glob("*.log"))
        )
        commands_file = fixture.root / "commands.jsonl"
        commands_text = commands_file.read_text(errors="replace") if commands_file.exists() else ""
        haystacks = {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "logfile": log_text,
            "commands": commands_text,
        }
        for token in tokens:
            for source_name, content in haystacks.items():
                self.assertNotIn(token, content, f"Secret token leaked into {source_name}")

    def test_notifiarr_discovers_allocated_ports_urlbases_and_bind_addresses(self):
        fx = self.fixture("notifiarr")
        tokens = {
            "sonarr": 'fx-sonarr-"quote"\\slash$var`tick',
            "radarr": "fx-radarr-token-02",
            "lidarr": "fx-lidarr-token-03",
            "readarr": "fx-readarr-token-04",
            "prowlarr": "fx-prowlarr-token-05",
        }
        fx.file("var/lib/sonarr/config.xml", servarr_xml(
            api_key='fx-sonarr-&quot;quote&quot;\\slash$var`tick',
            port=18989,
            url_base=" /sonarr/ ",
            bind_address="*",
        ))
        fx.file("var/lib/radarr/config.xml", servarr_xml(
            api_key=tokens["radarr"],
            port=17878,
            url_base="radarr",
            bind_address="0.0.0.0",
        ))
        fx.file("var/lib/lidarr/config.xml", servarr_xml(
            api_key=tokens["lidarr"],
            port=None,
            url_base="/music/lidarr/",
            bind_address="127.0.0.1",
        ))
        fx.file("var/lib/readarr/config.xml", servarr_xml(
            api_key=tokens["readarr"],
            port=18787,
            url_base="/",
            bind_address="::",
        ))
        fx.file("var/lib/prowlarr/config.xml", servarr_xml(
            api_key=tokens["prowlarr"],
            port=19696,
            url_base="/prowlarr",
            bind_address="::1",
        ))

        result = fx.run("install", port=15454)
        self.assert_success(result)
        self.assertTrue(fx.lock.exists())

        config_path = fx.root / "etc/notifiarr/notifiarr.conf"
        self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)
        parsed = parse_toml(config_path.read_text())
        self.assertEqual(parsed["bind_addr"], "127.0.0.1:15454")
        self.assertEqual(parsed["ui_password"], "admin:bootstrap-password")

        expected = {
            "sonarr": ("AetherFlow Sonarr", "http://127.0.0.1:18989/sonarr"),
            "radarr": ("AetherFlow Radarr", "http://127.0.0.1:17878/radarr"),
            "lidarr": ("AetherFlow Lidarr", "http://127.0.0.1:8686/music/lidarr"),
            "readarr": ("AetherFlow Readarr", "http://[::1]:18787"),
            "prowlarr": ("AetherFlow Prowlarr", "http://[::1]:19696/prowlarr"),
        }
        for app, (expected_name, expected_url) in expected.items():
            self.assertIn(app, parsed)
            self.assertEqual(len(parsed[app]), 1)
            entry = parsed[app][0]
            self.assertEqual(entry["name"], expected_name)
            self.assertEqual(entry["url"], expected_url)
            self.assertEqual(entry["api_key"], tokens[app])

        self.assert_no_tokens_exposed(fx, result, tokens.values())

    def test_unpackerr_discovers_allocated_ports_urlbases_and_quotes_keys(self):
        fx = self.fixture("unpackerr")
        tokens = {
            "sonarr": 'fx-up-sonarr-"q"\\s$v`t',
            "radarr": "fx-up-radarr-token-02",
            "lidarr": "fx-up-lidarr-token-03",
            "readarr": "fx-up-readarr-token-04",
            "prowlarr": "fx-up-prowlarr-ignored-05",
        }
        fx.file("var/lib/sonarr/config.xml", servarr_xml(
            api_key='fx-up-sonarr-&quot;q&quot;\\s$v`t',
            port=18989,
            url_base="/tv/sonarr/",
            bind_address="*",
        ))
        fx.file("var/lib/radarr/config.xml", servarr_xml(
            api_key=tokens["radarr"],
            port=17878,
            url_base="",
            bind_address="127.0.0.1",
            extra="  <!-- <ApiKey>commented-decoy</ApiKey><Port>9999</Port> -->",
        ))
        fx.file("var/lib/lidarr/config.xml", servarr_xml(
            api_key=tokens["lidarr"],
            port=18686,
            url_base="lidarr",
        ))
        fx.file("var/lib/readarr/config.xml", servarr_xml(
            api_key=tokens["readarr"],
            port=8787,
            url_base="/books",
            bind_address="::",
        ))
        fx.file("var/lib/prowlarr/config.xml", servarr_xml(
            api_key=tokens["prowlarr"],
            port=19696,
            url_base="/prowlarr",
        ))

        result = fx.run("install")
        self.assert_success(result)
        self.assertTrue(fx.lock.exists())

        config_path = fx.root / "etc/unpackerr/unpackerr.conf"
        self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)
        parsed = parse_toml(config_path.read_text())
        self.assertEqual(parsed["interval"], "2m")
        self.assertEqual(parsed["webserver"], {"listen_addr": ""})
        self.assertNotIn("prowlarr", parsed)

        expected = {
            "sonarr": "http://127.0.0.1:18989/tv/sonarr",
            "radarr": "http://127.0.0.1:17878",
            "lidarr": "http://127.0.0.1:18686/lidarr",
            "readarr": "http://[::1]:8787/books",
        }
        for app, expected_url in expected.items():
            self.assertIn(app, parsed)
            self.assertIsInstance(parsed[app], dict)
            self.assertEqual(list(parsed[app].keys()), ["0"])
            entry = parsed[app]["0"]
            self.assertEqual(entry["url"], expected_url)
            self.assertEqual(entry["api_key"], tokens[app])
            self.assertEqual(entry["protocols"], "torrent")
            self.assertEqual(entry["timeout"], "10s")
            self.assertIs(entry["delete_orig"], False)

        self.assert_no_tokens_exposed(fx, result, tokens.values())

    def _primary_entry(self, parsed, consumer, app):
        section = parsed[app]
        if consumer == "unpackerr":
            self.assertIsInstance(section, dict)
            self.assertEqual(list(section.keys()), ["0"])
            return section["0"]
        self.assertIsInstance(section, list)
        self.assertEqual(len(section), 1)
        return section[0]

    def _assert_missing_upstreams_skip_cleanly(self, consumer, config_rel):
        fx = self.fixture(consumer)
        radarr_token = f"fx-{consumer}-valid-radarr"
        malformed_secret = f"fx-{consumer}-malformed-secret"
        unsafe_secret = f"fx-{consumer}-unsafe-urlbase-secret"
        fx.file("var/lib/radarr/config.xml", servarr_xml(
            api_key=radarr_token, port=17879, url_base="/movies"
        ))
        fx.file("var/lib/lidarr/config.xml", servarr_xml(api_key=None, port=18686))
        fx.file("var/lib/readarr/config.xml", f"<Config><ApiKey>{malformed_secret}")
        fx.file("var/lib/prowlarr/config.xml", servarr_xml(
            api_key=unsafe_secret, port=19696, url_base="/prowlarr/../admin"
        ))

        result = fx.run("install")
        self.assert_success(result)
        raw_text = (fx.root / config_rel).read_text()
        parsed = parse_toml(raw_text)
        self.assertIn("radarr", parsed)
        radarr_entry = self._primary_entry(parsed, consumer, "radarr")
        self.assertEqual(radarr_entry["url"], "http://127.0.0.1:17879/movies")
        self.assertEqual(radarr_entry["api_key"], radarr_token)
        if consumer == "unpackerr":
            self.assertEqual(parsed["webserver"], {"listen_addr": ""})
            self.assertIn("# [sonarr.0]", raw_text)
        for skipped in ("sonarr", "lidarr", "readarr", "prowlarr"):
            self.assertNotIn(skipped, parsed)

        self.assert_no_tokens_exposed(
            fx, result, (radarr_token, malformed_secret, unsafe_secret)
        )

    def test_notifiarr_missing_and_invalid_upstreams_skip_cleanly(self):
        self._assert_missing_upstreams_skip_cleanly("notifiarr", "etc/notifiarr/notifiarr.conf")

    def test_unpackerr_missing_and_invalid_upstreams_skip_cleanly(self):
        self._assert_missing_upstreams_skip_cleanly("unpackerr", "etc/unpackerr/unpackerr.conf")

    def _assert_late_installed_and_repair_lifecycle(self, consumer, config_rel):
        fx = self.fixture(consumer)
        # 1. Fresh install with zero upstream Servarr apps installed
        r1 = fx.run("install", port=15460 if consumer == "notifiarr" else None)
        self.assert_success(r1)
        config_path = fx.root / config_rel
        initial = parse_toml(config_path.read_text())
        self.assertNotIn("sonarr", initial)
        self.assertNotIn("radarr", initial)

        # Operator customizes top-level config
        raw = config_path.read_text()
        if consumer == "notifiarr":
            raw = raw.replace('api_key = ""', 'api_key = "operator-site-token"', 1)
        else:
            raw = raw.replace('interval = "2m"', 'interval = "5m"', 1)
        raw = "# operator top comment\n" + raw
        config_path.write_text(raw)

        # 2. Late-install Sonarr and Radarr with fallback ports & UrlBase, then reinstall
        s_tok = f"fx-{consumer}-late-sonarr-1"
        r_tok_1 = f"fx-{consumer}-late-radarr-1"
        fx.file("var/lib/sonarr/config.xml", servarr_xml(
            api_key=s_tok, port=18989, url_base="/sonarr"
        ))
        fx.file("var/lib/radarr/config.xml", servarr_xml(
            api_key=r_tok_1, port=17878, url_base=""
        ))
        r2 = fx.run("reinstall", port=15461 if consumer == "notifiarr" else None)
        self.assert_success(r2)
        after_late = parse_toml(config_path.read_text())
        self.assertIn("# operator top comment", config_path.read_text())
        if consumer == "notifiarr":
            self.assertEqual(after_late["api_key"], "operator-site-token")
            self.assertEqual(after_late["bind_addr"], "127.0.0.1:15461")
            self.assertEqual(after_late["ui_password"], "admin:bootstrap-password")
        else:
            self.assertEqual(after_late["interval"], "5m")
            self.assertEqual(after_late["webserver"], {"listen_addr": ""})
        sonarr_late = self._primary_entry(after_late, consumer, "sonarr")
        radarr_late = self._primary_entry(after_late, consumer, "radarr")
        self.assertEqual(sonarr_late["url"], "http://127.0.0.1:18989/sonarr")
        self.assertEqual(sonarr_late["api_key"], s_tok)
        self.assertEqual(radarr_late["url"], "http://127.0.0.1:17878")
        self.assertEqual(radarr_late["api_key"], r_tok_1)
        self.assert_no_tokens_exposed(fx, r2, (s_tok, r_tok_1))

        # 3. Operator adds custom per-block field; Sonarr moves port & UrlBase; run update
        text_with_edit = config_path.read_text().replace(
            f'api_key = "{s_tok}"\n',
            f'api_key = "{s_tok}"\n  custom_flag = "keep-me"\n',
            1,
        )
        config_path.write_text(text_with_edit)
        fx.file("var/lib/sonarr/config.xml", servarr_xml(
            api_key=s_tok, port=19012, url_base="/tv"
        ))
        r3 = fx.run("update", port=15462 if consumer == "notifiarr" else None)
        self.assert_success(r3)
        after_move = parse_toml(config_path.read_text())
        sonarr_move = self._primary_entry(after_move, consumer, "sonarr")
        self.assertEqual(sonarr_move["url"], "http://127.0.0.1:19012/tv")
        self.assertEqual(sonarr_move["api_key"], s_tok)
        self.assertEqual(sonarr_move["custom_flag"], "keep-me")
        self.assert_no_tokens_exposed(fx, r3, (s_tok, r_tok_1))

        # 4. Remove (retaining data), rotate Radarr key + clear managed api_key, install
        self.assert_success(fx.run("remove"))
        self.assertTrue(config_path.is_file())
        r_tok_2 = f"fx-{consumer}-rotated-radarr-2"
        fx.file("var/lib/radarr/config.xml", servarr_xml(
            api_key=r_tok_2, port=17900, url_base="/radarr"
        ))
        config_path.write_text(
            config_path.read_text().replace(f'api_key = "{r_tok_1}"', 'api_key = ""', 1)
        )
        r4 = fx.run("install", port=15463 if consumer == "notifiarr" else None)
        self.assert_success(r4)
        after_repair = parse_toml(config_path.read_text())
        radarr_repair = self._primary_entry(after_repair, consumer, "radarr")
        sonarr_repair = self._primary_entry(after_repair, consumer, "sonarr")
        self.assertEqual(radarr_repair["url"], "http://127.0.0.1:17900/radarr")
        self.assertEqual(radarr_repair["api_key"], r_tok_2)
        self.assertEqual(sonarr_repair["url"], "http://127.0.0.1:19012/tv")
        self.assertEqual(sonarr_repair["custom_flag"], "keep-me")
        self.assert_no_tokens_exposed(fx, r4, (s_tok, r_tok_1, r_tok_2))

    def test_notifiarr_late_installed_upstreams_and_retained_repair_flow(self):
        self._assert_late_installed_and_repair_lifecycle("notifiarr", "etc/notifiarr/notifiarr.conf")

    def test_unpackerr_late_installed_upstreams_and_retained_repair_flow(self):
        self._assert_late_installed_and_repair_lifecycle("unpackerr", "etc/unpackerr/unpackerr.conf")

    def _assert_legacy_repair_and_operator_preservation(self, consumer, config_rel):
        fx = self.fixture(consumer)
        s_tok = f"fx-{consumer}-legacy-sonarr"
        r_tok = f"fx-{consumer}-op-radarr"
        l_tok = f"fx-{consumer}-disk-lidarr"
        rd_tok = f"fx-{consumer}-late-readarr"

        fx.file("var/lib/sonarr/config.xml", servarr_xml(
            api_key=s_tok, port=18989, url_base="/sonarr"
        ))
        fx.file("var/lib/radarr/config.xml", servarr_xml(
            api_key=r_tok, port=17878, url_base="/radarr"
        ))
        fx.file("var/lib/lidarr/config.xml", servarr_xml(
            api_key=l_tok, port=18686, url_base="/lidarr"
        ))
        fx.file("var/lib/readarr/config.xml", servarr_xml(
            api_key=rd_tok, port=18787, url_base="/readarr"
        ))

        if consumer == "notifiarr":
            existing_conf = (
                'api_key = "operator-notifiarr-key"\n'
                'bind_addr = "127.0.0.1:5454"\n'
                'ui_password = "operator:retained-hash"\n'
                'note = """\n[[readarr]]\nurl = "fake-inside-multiline"\n"""\n\n'
                '[[sonarr]]\n'
                '  name = "AetherFlow Sonarr"\n'
                '  url = "http://127.0.0.1:8989"\n'
                f'  api_key = "{s_tok}"\n'
                '  timeout = "25s"\n\n'
                '[[sonarr]]\n'
                '  name = "Remote 4K Sonarr"\n'
                '  url = "http://10.0.0.9:8989"\n'
                '  api_key = "remote-4k-token"\n\n'
                '[[radarr]]\n'
                '  name = "AetherFlow Radarr"\n'
                '  url = "https://radarr.lan.example/movies"\n'
                f'  api_key = "{r_tok}"\n\n'
                '[[lidarr]]\n'
                '  name = "AetherFlow Lidarr"\n'
                '  url = "http://127.0.0.1:8686"\n'
                '  api_key = "operator-custom-lidarr-token"\n'
            )
        else:
            existing_conf = (
                'interval = "4m"\n'
                'note = """\n[[readarr]]\nurl = "fake-inside-multiline"\n"""\n\n'
                '[[sonarr]]\n'
                '  url = "http://127.0.0.1:8989"\n'
                f'  api_key = "{s_tok}"\n'
                '  paths = ["/mnt/custom-tv"]\n'
                '  timeout = "25s"\n\n'
                '[[sonarr]]\n'
                '  url = "http://10.0.0.9:8989"\n'
                '  api_key = "remote-4k-token"\n'
                '  paths = ["/mnt/4k"]\n\n'
                '[[radarr]]\n'
                '  url = "https://radarr.lan.example/movies"\n'
                f'  api_key = "{r_tok}"\n'
                '  paths = ["/mnt/movies"]\n\n'
                '[[lidarr]]\n'
                '  url = "http://127.0.0.1:8686"\n'
                '  api_key = "operator-custom-lidarr-token"\n'
                '  paths = ["/mnt/music"]\n'
            )

        config_path = fx.file(config_rel, existing_conf)
        result = fx.run("update", port=15470 if consumer == "notifiarr" else None)
        self.assert_success(result)

        parsed = parse_toml(config_path.read_text())
        self.assertEqual(len(parsed["sonarr"]), 2)
        self.assertEqual(parsed["sonarr"][0]["url"], "http://127.0.0.1:18989/sonarr")
        self.assertEqual(parsed["sonarr"][0]["api_key"], s_tok)
        self.assertEqual(parsed["sonarr"][0]["timeout"], "25s")
        if consumer == "unpackerr":
            self.assertEqual(parsed["sonarr"][0]["paths"], ["/mnt/custom-tv"])
        self.assertEqual(parsed["sonarr"][1]["url"], "http://10.0.0.9:8989")
        self.assertEqual(parsed["sonarr"][1]["api_key"], "remote-4k-token")

        self.assertEqual(len(parsed["radarr"]), 1)
        self.assertEqual(parsed["radarr"][0]["url"], "https://radarr.lan.example/movies")
        self.assertEqual(parsed["radarr"][0]["api_key"], r_tok)

        self.assertEqual(len(parsed["lidarr"]), 1)
        self.assertEqual(parsed["lidarr"][0]["url"], "http://127.0.0.1:8686")
        self.assertEqual(parsed["lidarr"][0]["api_key"], "operator-custom-lidarr-token")

        readarr_entry = self._primary_entry(parsed, consumer, "readarr")
        self.assertEqual(readarr_entry["url"], "http://127.0.0.1:18787/readarr")
        self.assertEqual(readarr_entry["api_key"], rd_tok)

        if consumer == "notifiarr":
            self.assertEqual(parsed["api_key"], "operator-notifiarr-key")
            self.assertEqual(parsed["ui_password"], "operator:retained-hash")
            self.assertEqual(parsed["bind_addr"], "127.0.0.1:15470")
        else:
            self.assertEqual(parsed["interval"], "4m")

        self.assert_no_tokens_exposed(fx, result, (s_tok, r_tok, l_tok, rd_tok))

    def test_notifiarr_legacy_stock_url_repair_and_operator_preservation(self):
        self._assert_legacy_repair_and_operator_preservation("notifiarr", "etc/notifiarr/notifiarr.conf")

    def test_unpackerr_legacy_stock_url_repair_and_operator_preservation(self):
        self._assert_legacy_repair_and_operator_preservation("unpackerr", "etc/unpackerr/unpackerr.conf")

    def test_unpackerr_v1_named_table_repair_and_operator_preservation(self):
        fx = self.fixture("unpackerr")
        s_tok = "0123456789abcdef0123456789abcdef"
        r_tok = "fedcba9876543210fedcba9876543210"
        l_tok = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        rd_tok = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

        fx.file("var/lib/sonarr/config.xml", servarr_xml(
            api_key=s_tok, port=18989, url_base="/arrcheck"
        ))
        fx.file("var/lib/radarr/config.xml", servarr_xml(
            api_key=r_tok, port=17878, url_base="/radarr"
        ))
        fx.file("var/lib/lidarr/config.xml", servarr_xml(
            api_key=l_tok, port=18686, url_base="/lidarr"
        ))
        fx.file("var/lib/readarr/config.xml", servarr_xml(
            api_key=rd_tok, port=18787, url_base="/readarr"
        ))

        # Simulate Unpackerr v1.0.1 normalized [app.<slug>] layout with stripped comments
        # and out-of-order sibling tables ([sonarr.0] separated from [sonarr.remote4k]).
        existing_conf = (
            'interval = "4m"\n\n'
            '[webserver]\n'
            '  listen_addr = "127.0.0.1:5656"\n'
            '  ui_password = "!!cryptd!!admin:$2a$10$examplehash"\n\n'
            '[sonarr.0]\n'
            '  url = "http://127.0.0.1:8989"\n'
            f'  api_key = "{s_tok}"\n'
            '  paths = ["/mnt/custom-tv"]\n'
            '  timeout = "25s"\n\n'
            '[radarr.0]\n'
            '  url = "https://radarr.lan.example/movies"\n'
            f'  api_key = "{r_tok}"\n'
            '  paths = ["/mnt/movies"]\n\n'
            '[sonarr.remote4k]\n'
            '  url = "http://10.0.0.9:8989"\n'
            '  api_key = "remote-4k-token"\n'
            '  paths = ["/mnt/4k"]\n\n'
            '[lidarr.custom]\n'
            '  url = "http://127.0.0.1:8686"\n'
            '  api_key = "operator-custom-lidarr-token"\n'
            '  paths = ["/mnt/music"]\n'
        )
        config_path = fx.file("etc/unpackerr/unpackerr.conf", existing_conf)

        r1 = fx.run("update")
        self.assert_success(r1)
        parsed = parse_toml(config_path.read_text())
        self.assertEqual(parsed["webserver"]["listen_addr"], "127.0.0.1:5656")
        self.assertEqual(parsed["webserver"]["ui_password"], "!!cryptd!!admin:$2a$10$examplehash")
        self.assertEqual(sorted(parsed["sonarr"]), ["0", "remote4k"])
        self.assertEqual(parsed["sonarr"]["0"]["url"], "http://127.0.0.1:18989/arrcheck")
        self.assertEqual(parsed["sonarr"]["0"]["api_key"], s_tok)
        self.assertEqual(parsed["sonarr"]["0"]["paths"], ["/mnt/custom-tv"])
        self.assertEqual(parsed["sonarr"]["0"]["timeout"], "25s")
        self.assertEqual(parsed["sonarr"]["remote4k"]["url"], "http://10.0.0.9:8989")
        self.assertEqual(parsed["sonarr"]["remote4k"]["api_key"], "remote-4k-token")
        self.assertEqual(parsed["radarr"]["0"]["url"], "https://radarr.lan.example/movies")
        self.assertEqual(parsed["lidarr"]["custom"]["api_key"], "operator-custom-lidarr-token")
        self.assertEqual(parsed["readarr"]["0"]["url"], "http://127.0.0.1:18787/readarr")
        self.assertEqual(parsed["readarr"]["0"]["api_key"], rd_tok)

        # Follow-up endpoint move updates [sonarr.0] while leaving operator tables intact.
        fx.file("var/lib/sonarr/config.xml", servarr_xml(
            api_key=s_tok, port=19012, url_base="/tv"
        ))
        r2 = fx.run("reinstall")
        self.assert_success(r2)
        parsed_moved = parse_toml(config_path.read_text())
        self.assertEqual(parsed_moved["sonarr"]["0"]["url"], "http://127.0.0.1:19012/tv")
        self.assertEqual(parsed_moved["sonarr"]["remote4k"]["url"], "http://10.0.0.9:8989")
        self.assertEqual(parsed_moved["radarr"]["0"]["url"], "https://radarr.lan.example/movies")

        # Operator edit of [sonarr.0] URL must be preserved on subsequent reinstall.
        edited = config_path.read_text().replace(
            'url = "http://127.0.0.1:19012/tv"',
            'url = "http://127.0.0.1:29999/custom-proxy"',
            1,
        )
        config_path.write_text(edited)
        r3 = fx.run("reinstall")
        self.assert_success(r3)
        parsed_preserved = parse_toml(config_path.read_text())
        self.assertEqual(parsed_preserved["sonarr"]["0"]["url"], "http://127.0.0.1:29999/custom-proxy")
        self.assert_no_tokens_exposed(fx, r3, (s_tok, r_tok, l_tok, rd_tok))

    def test_unpackerr_retained_config_preserves_headless_default(self):
        fx = self.fixture("unpackerr")
        config = fx.file(
            "etc/unpackerr/unpackerr.conf",
            'interval = "3m"\n[webserver]\n# listen_addr = "0.0.0.0:5656"\nmetrics = false\n',
        )

        self.assert_success(fx.run("update"))

        parsed = parse_toml(config.read_text())
        self.assertEqual(parsed["interval"], "3m")
        self.assertEqual(parsed["webserver"]["listen_addr"], "")
        self.assertFalse(parsed["webserver"]["metrics"])

    def _reset_path(self, path):
        if path.is_symlink() or path.is_file() or path.exists():
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()

    def test_unpackerr_fails_closed_on_linked_nonregular_and_oversized_configs(self):
        fx = self.fixture("unpackerr")
        for target_rel in ("etc/unpackerr/unpackerr.conf", "var/lib/sonarr/config.xml"):
            for variant in ("symlink", "hardlink", "symlink-parent", "fifo", "directory", "oversized"):
                if target_rel.endswith("unpackerr.conf") and variant == "oversized":
                    continue
                with self.subTest(target=target_rel, variant=variant):
                    config = fx.root / target_rel
                    self._reset_path(config.parent)
                    backing = fx.file(
                        "root/backing/" + Path(target_rel).name,
                        "<Config><ApiKey>do-not-read</ApiKey></Config>\n",
                    )
                    config.parent.mkdir(parents=True, exist_ok=True)
                    if variant == "symlink-parent":
                        shutil.rmtree(config.parent)
                        config.parent.symlink_to(backing.parent, target_is_directory=True)
                    elif variant == "hardlink":
                        os.link(backing, config)
                    elif variant == "symlink":
                        config.symlink_to(backing)
                    elif variant == "fifo":
                        os.mkfifo(config)
                    elif variant == "directory":
                        config.mkdir()
                    elif variant == "oversized":
                        config.write_text("<Config><ApiKey>x</ApiKey>" + ("A" * 300000) + "</Config>\n")
                    before = (backing.read_bytes(), backing.stat().st_mode, backing.stat().st_mtime_ns)
                    result = fx.run("update")
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(
                        (backing.read_bytes(), backing.stat().st_mode, backing.stat().st_mtime_ns),
                        before,
                    )
                    self.assertFalse(fx.lock.exists())
                    self._reset_path(config.parent)

    def test_notifiarr_fails_closed_on_nonregular_oversized_xml_and_bad_port(self):
        fx = self.fixture("notifiarr")
        xml_path = fx.root / "var/lib/sonarr/config.xml"
        for variant in ("fifo", "directory", "oversized"):
            with self.subTest(variant=variant):
                self._reset_path(xml_path.parent)
                xml_path.parent.mkdir(parents=True, exist_ok=True)
                if variant == "fifo":
                    os.mkfifo(xml_path)
                elif variant == "directory":
                    xml_path.mkdir()
                else:
                    xml_path.write_text("<Config><ApiKey>x</ApiKey>" + ("A" * 300000) + "</Config>\n")
                result = fx.run("install")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(fx.lock.exists())
        self._reset_path(xml_path.parent)
        bad_port = fx.run("install", port=70000)
        self.assertNotEqual(bad_port.returncode, 0, bad_port.stdout + bad_port.stderr)
        self.assertFalse(fx.lock.exists())

    def test_common_helper_bounded_read_validation_and_idempotency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helpers = common_functions("safe_config_python", "validate_config_paths", "sync_servarr_toml_config")
            rebased = replace_paths_once(helpers, [("/var/lib/", str(root) + "/var/lib/")])

            def write_file(rel, content):
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
                return target

            bad_cases = (
                ("sonarr", '<!DOCTYPE foo [<!ENTITY x "y">]><Config><ApiKey>bad-dtd-tok</ApiKey></Config>'),
                ("radarr", "<Other><ApiKey>bad-root-tok</ApiKey></Other>"),
                ("lidarr", "<Config><Port>70000</Port><ApiKey>bad-port-tok</ApiKey></Config>"),
                ("readarr", "<Config><BindAddress>127.0.0.1:9999</BindAddress><ApiKey>bad-host-tok</ApiKey></Config>"),
                ("prowlarr", "<Config><UrlBase>/a?x=1</UrlBase><ApiKey>bad-base-tok</ApiKey></Config>"),
            )
            for app, content in bad_cases:
                write_file(f"var/lib/{app}/config.xml", content)

            conf = root / "etc/notifiarr/notifiarr.conf"
            program = (
                rebased
                + '\nlog_info() { printf "LOG_INFO: %s\\n" "$*"; }\n'
                + 'log_warn() { printf "LOG_WARN: %s\\n" "$*"; }\n'
                + 'sync_servarr_toml_config notifiarr "$1" 5454 "$2"\n'
            )
            res = subprocess.run(
                ["bash", "-euc", program, "fixture", str(conf), str(root / "var/log/notifiarr")],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            parsed = parse_toml(conf.read_text())
            for app, _ in bad_cases:
                self.assertNotIn(app, parsed)
            for leaked in ("bad-dtd-tok", "bad-root-tok", "bad-port-tok", "bad-host-tok", "bad-base-tok"):
                self.assertNotIn(leaked, res.stdout + res.stderr)

            valid_tok = "fx-unit-sonarr-tok"
            write_file("var/lib/sonarr/config.xml", servarr_xml(
                api_key=valid_tok, port=18999, url_base="/sonarr"
            ))
            up_conf = write_file(
                "etc/unpackerr/unpackerr.conf",
                "interval = \"2m\"\n\n[[\"sonarr\"]] # keep this heading\n"
                "  url = 'http://127.0.0.1:8989' # legacy\n"
                f"  api_key = '{valid_tok}'\n",
            )
            up_program = (
                rebased
                + '\nlog_info() { printf "LOG_INFO: %s\\n" "$*"; }\n'
                + 'log_warn() { printf "LOG_WARN: %s\\n" "$*"; }\n'
                + 'sync_servarr_toml_config unpackerr "$1"\n'
            )
            res1 = subprocess.run(
                ["bash", "-euc", up_program, "fixture", str(up_conf)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res1.returncode, 0, res1.stdout + res1.stderr)
            parsed_up = parse_toml(up_conf.read_text())
            self.assertEqual(parsed_up["sonarr"][0]["url"], "http://127.0.0.1:18999/sonarr")
            self.assertEqual(parsed_up["sonarr"][0]["api_key"], valid_tok)
            self.assertIn("# keep this heading", up_conf.read_text())
            self.assertIn("# legacy", up_conf.read_text())
            self.assertNotIn(valid_tok, res1.stdout + res1.stderr)

            before_stat = (up_conf.stat().st_ino, up_conf.stat().st_mtime_ns, up_conf.read_bytes())
            res2 = subprocess.run(
                ["bash", "-euc", up_program, "fixture", str(up_conf)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res2.returncode, 0, res2.stdout + res2.stderr)
            after_stat = (up_conf.stat().st_ino, up_conf.stat().st_mtime_ns, up_conf.read_bytes())
            self.assertEqual(before_stat, after_stat)

            edited = up_conf.read_text().replace(
                'url = "http://127.0.0.1:18999/sonarr"',
                'url = "http://127.0.0.1:29999/custom-proxy"',
                1,
            )
            up_conf.write_text(edited)
            res3 = subprocess.run(
                ["bash", "-euc", up_program, "fixture", str(up_conf)],
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(res3.returncode, 0, res3.stdout + res3.stderr)
            self.assertEqual(
                parse_toml(up_conf.read_text())["sonarr"][0]["url"],
                "http://127.0.0.1:29999/custom-proxy",
            )


if __name__ == "__main__":
    unittest.main()
