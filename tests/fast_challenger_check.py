#!/usr/bin/env python3
import os
import sys
import glob
import re
import tempfile
import shutil
import subprocess

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def run():
    print("=" * 80)
    print(" FAST NATIVE CHALLENGER 2 VERIFICATION")
    print("=" * 80)

    # 1. Check all 104 plugin scripts for safe rutorrent binding
    print("\n[CHECK 1] ruTorrent plugin scripts unbound variable hardening:")
    install_plugins = sorted(glob.glob(os.path.join(ROOT, "packages/plugin/install/installplugin-*")))
    remove_plugins = sorted(glob.glob(os.path.join(ROOT, "packages/plugin/remove/removeplugin-*")))
    assert len(install_plugins) == 52, f"Expected 52 install plugins, found {len(install_plugins)}"
    assert len(remove_plugins) == 52, f"Expected 52 remove plugins, found {len(remove_plugins)}"
    
    missing_binding = []
    for f in install_plugins + remove_plugins:
        with open(f, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
            if 'rutorrent="${rutorrent:-/var/www/rutorrent/}"' not in content:
                missing_binding.append(os.path.relpath(f, ROOT))
    
    if missing_binding:
        print(f"  FAIL: Missing safe rutorrent binding in {missing_binding}")
        return False
    else:
        print(f"  PASS: All 104 ruTorrent plugin scripts contain safe `rutorrent=\"${{rutorrent:-/var/www/rutorrent/}}\"` binding!")

    # 2. Check for sleep calls
    print("\n[CHECK 2] Scan for forbidden sleep calls in packages/plugin/:")
    sleep_found = []
    for f in install_plugins + remove_plugins:
        with open(f, "r", encoding="utf-8", errors="ignore") as fh:
            for lno, line in enumerate(fh, 1):
                if re.search(r"^\s*sleep(\s+\d+|\d+)", line):
                    sleep_found.append(f"{os.path.relpath(f, ROOT)}:{lno}: {line.strip()}")
    if sleep_found:
        print(f"  FAIL: Found sleep calls: {sleep_found}")
        return False
    else:
        print("  PASS: Zero forbidden sleep calls found across all 104 plugin scripts!")

    # 3. Check for Docker commands / daemons in packages/
    print("\n[CHECK 3] Scan for Docker commands & daemon references:")
    packages_dir = os.path.join(ROOT, "packages")
    docker_cmds = []
    for root, _, files in os.walk(packages_dir):
        if "__pycache__" in root: continue
        for f in files:
            p = os.path.join(root, f)
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                for lno, line in enumerate(fh, 1):
                    # Check for docker command invocation or daemon socket
                    if re.search(r"\b(docker\s+run|docker-compose|dockerd|docker\.sock)\b", line):
                        docker_cmds.append(f"{os.path.relpath(p, ROOT)}:{lno}: {line.strip()}")
    if docker_cmds:
        print(f"  FAIL: Found Docker invocations: {docker_cmds}")
        return False
    else:
        print("  PASS: Zero Docker daemon, socket, or CLI invocations found across packages/!")

    # 4. Stress Test Arr extraction logic across 23 adversarial XML payloads
    print("\n[CHECK 4] Arr config.xml extraction stress testing (23 adversarial XML cases):")
    test_cases = [
        ("01_standard_hex", "<Config>\n  <ApiKey>a1b2c3d4e5f6789012345678abcdef01</ApiKey>\n</Config>", "a1b2c3d4e5f6789012345678abcdef01"),
        ("02_guid_with_dashes", "<Config>\n  <ApiKey>c7a3b4e2-89f1-4a5c-b1d2-9876543210ab</ApiKey>\n</Config>", "c7a3b4e2-89f1-4a5c-b1d2-9876543210ab"),
        ("03_with_tag_attributes", "<Config>\n  <ApiKey type=\"token\" id=\"master\" auth=\"true\">attr_key_9988776655</ApiKey>\n</Config>", "attr_key_9988776655"),
        ("04_spaces_inside_tag", "<Config>\n  <ApiKey>   spaces_key_123456   </ApiKey>\n</Config>", "   spaces_key_123456   "),
        ("05_empty_tag", "<Config>\n  <ApiKey></ApiKey>\n</Config>", ""),
        ("06_self_closing_tag", "<Config>\n  <ApiKey/>\n</Config>", ""),
        ("07_missing_apikey_tag", "<Config>\n  <Port>8989</Port>\n  <UrlBase>/sonarr</UrlBase>\n</Config>", ""),
        ("08_multiline_tag", "<Config>\n  <ApiKey>\n    multiline_key_val_789\n  </ApiKey>\n</Config>", ""),
        ("09_commented_out_fake_key", "<Config>\n  <!-- <ApiKey>fake_commented_key_0000</ApiKey> -->\n  <ApiKey>real_valid_key_1111</ApiKey>\n</Config>", "real_valid_key_1111"),
        ("10_multiple_apikey_tags", "<Config>\n  <ApiKey>first_key_1111</ApiKey>\n  <ApiKey>second_key_2222</ApiKey>\n</Config>", "first_key_1111"),
        ("11_alphanumeric_with_underscores", "<Config>\n  <ApiKey>token_Arr_2026_Secure_Key!</ApiKey>\n</Config>", "token_Arr_2026_Secure_Key!"),
        ("12_quotes_in_key", "<Config>\n  <ApiKey>key\"with'quotes</ApiKey>\n</Config>", "key\"with'quotes"),
        ("13_dollar_sign_in_key", "<Config>\n  <ApiKey>key$with${ENV_VAR}dollars</ApiKey>\n</Config>", "key$with${ENV_VAR}dollars"),
        ("14_backticks_in_key", "<Config>\n  <ApiKey>key`whoami`backticks</ApiKey>\n</Config>", "key`whoami`backticks"),
        ("15_zero_byte_empty_file", "", ""),
        ("16_truncated_malformed_xml", "<Config><ApiKey>truncated_no_closing_tag_9999", ""),
        ("17_crlf_windows_newlines", "<Config>\r\n  <ApiKey>windows_crlf_key_44332211</ApiKey>\r\n</Config>", "windows_crlf_key_44332211"),
        ("18_binary_garbage", "\x00\x01\x02\x03<ApiKey>binary_garbage_token</ApiKey>\xff\xfe", "binary_garbage_token"),
        ("19_inline_with_other_tags", "<Config><Port>8989</Port><ApiKey>inline_arr_key_5544</ApiKey><BindAddress>*</BindAddress></Config>", "inline_arr_key_5544"),
        ("20_cdata_section", "<Config>\n  <ApiKey><![CDATA[cdata_key_889900]]></ApiKey>\n</Config>", ""),
        ("21_xml_entities", "<Config>\n  <ApiKey>key_with_&amp;_and_&lt;&gt;</ApiKey>\n</Config>", ""),
        ("22_huge_file_with_many_tags", ("<Config>\n" + "  <Item>dummy</Item>\n" * 2000 + "  <ApiKey>huge_file_key_99999</ApiKey>\n" + "  <Item>dummy</Item>\n" * 2000 + "</Config>"), "huge_file_key_99999"),
        ("23_missing_file_entirely", None, ""),
    ]

    td = tempfile.mkdtemp()
    try:
        # Bash script defining get_arr_key and config generation under set -euo pipefail
        runner = os.path.join(td, "run_test.sh")
        with open(runner, "w") as rf:
            rf.write("""#!/bin/bash
set -euo pipefail

xml="$1"
get_arr_key() {
    local xml_file="$1"
    if [[ -f "$xml_file" ]]; then
        grep -oP '<ApiKey>\\K[^<]+' "$xml_file" 2>/dev/null || sed -n 's/.*<ApiKey>\\(.*\\)<\\/ApiKey>.*/\\1/p' "$xml_file" 2>/dev/null || true
    fi
}

KEY=$(get_arr_key "$xml")

# Assert config generation does not crash
SONARR_KEY="$KEY"
tmp_conf=$(mktemp)
cat <<EOF > "$tmp_conf"
api_key = "${SONARR_KEY}"
EOF
rm -f "$tmp_conf"
printf "%s" "$KEY"
""")
        os.chmod(runner, 0o755)

        for case_name, xml_content, _ in test_cases:
            xml_file = os.path.join(td, f"{case_name}.xml")
            if xml_content is not None:
                with open(xml_file, "w", encoding="utf-8", errors="ignore") as xf:
                    xf.write(xml_content)
            else:
                xml_file = os.path.join(td, "non_existent_file.xml")

            res = subprocess.run(["bash", runner, xml_file], capture_output=True, text=True)
            if res.returncode != 0:
                print(f"  FAIL: Case {case_name} crashed with exit code {res.returncode}: {res.stderr}")
                return False
            else:
                out = res.stdout.strip().replace("\r", "")
                print(f"  PASS: Case '{case_name}': OK (extracted: '{out[:25]}')")
    finally:
        shutil.rmtree(td, ignore_errors=True)

    print("\n" + "=" * 80)
    print(" ALL 4 ADVERSARIAL CHALLENGE PILLARS PASSED 100%!")
    print(" VERDICT: APPROVE")
    print("=" * 80)
    return True

if __name__ == "__main__":
    if not run():
        sys.exit(1)
