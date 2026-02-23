#!/usr/bin/env python3
"""
Batch modernization script for remaining legacy AetherFlow scripts.
Applies the same fixes done to install scripts to:
  - packages/package/remove/
  - packages/plugin/remove/
  - packages/system/
"""

import os
import re
import glob

BASE = os.path.dirname(os.path.abspath(__file__))

# Directories to process
DIRS = [
    os.path.join(BASE, "packages", "package", "remove"),
    os.path.join(BASE, "packages", "plugin", "remove"),
    os.path.join(BASE, "packages", "plugin", "install"),
    os.path.join(BASE, "packages", "system"),
]

COMMON_SOURCE = "source /opt/AetherFlow/packages/common.sh"

stats = {"files_modified": 0, "total_replacements": 0, "skipped": []}


def fix_file(filepath):
    """Apply all legacy fixes to a single file."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            original = f.read()
    except Exception as e:
        stats["skipped"].append((filepath, str(e)))
        return

    content = original
    changes = 0

    # Skip binary or non-shell files
    if "\x00" in content:
        stats["skipped"].append((filepath, "binary file"))
        return

    # --- Fix 1: Add common.sh source if not already present ---
    if COMMON_SOURCE not in content and "#!/bin/bash" in content:
        # Insert after the shebang + comment header block
        # Find end of header comments
        lines = content.split("\n")
        insert_idx = None
        in_header = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            if i == 0 and stripped.startswith("#!"):
                in_header = True
                continue
            if in_header and (stripped.startswith("#") or stripped == ""):
                continue
            else:
                insert_idx = i
                break
        if insert_idx is not None:
            lines.insert(insert_idx, COMMON_SOURCE)
            content = "\n".join(lines)
            changes += 1

    # --- Fix 2: Replace MASTER=$(cat .../master.txt) patterns ---
    master_patterns = [
        r'MASTER=\$\(cat\s+/srv/rutorrent/home/db/master\.txt\)',
        r'MASTER=\$\(cat\s+/etc/apache2/master\.txt(?:\s+2>/dev/null)?\)',
        r'master=\(\$\(cat\s+/srv/rutorrent/home/db/master\.txt\)\)',
        r'username=\$\(cat\s+/srv/rutorrent/home/db/master\.txt\)',
        r'USERNAME=\$\(cat\s+/srv/rutorrent/home/db/master\.txt\)',
        r'user=\$\(cat\s+/srv/rutorrent/home/db/master\.txt\)',
    ]
    for pat in master_patterns:
        new_content = re.sub(pat, '# LEGACY REMOVED: master.txt\nMASTER="$AETHERFLOW_USER"', content)
        if new_content != content:
            changes += 1
            content = new_content

    # Also handle the A1 variable in updateAetherFlow
    a1_pat = r'A1=\$\(cat\s+/etc/apache2/master\.txt\s+2>/dev/null\)'
    new_content = re.sub(a1_pat, '# LEGACY REMOVED: master.txt\nA1="$AETHERFLOW_USER"', content)
    if new_content != content:
        changes += 1
        content = new_content

    # Fix variable names: replace $username, $USERNAME, $user, $master with $MASTER where they were set from master.txt
    # Only do this for specific known patterns where the var was set from master.txt above

    # --- Fix 3: Replace OUTTO legacy paths ---
    outto_patterns = [
        (r'OUTTO=/srv/rutorrent/home/db/output\.log', 'OUTTO=$LOGFILE'),
        (r'OUTTO="/srv/rutorrent/home/db/output\.log"', 'OUTTO=$LOGFILE'),
        (r'OUTTO="/srv/AetherFlow/db/output\.log"', 'OUTTO=$LOGFILE'),
        (r'OUTTO="/root/quick-box\.log"', 'OUTTO=$LOGFILE'),
        (r'OUTTO="/srv/rutorrent/home/db/ffmpeg\.output\.log"', 'OUTTO=$LOGFILE'),
    ]
    for pat, replacement in outto_patterns:
        new_content = re.sub(pat, replacement, content)
        if new_content != content:
            changes += 1
            content = new_content

    # --- Fix 4: Replace local_setup=/etc/AetherFlow/setup/ ---
    old_setup = r'local_setup=/etc/AetherFlow/setup/'
    new_content = re.sub(old_setup, 'local_setup=/opt/AetherFlow/setup/', content)
    if new_content != content:
        changes += 1
        content = new_content

    # --- Fix 5: Comment out uncommented AuthName "rutorrent" and associated auth directives ---
    # Only comment out lines that are NOT already commented
    auth_patterns = [
        r'^(\s*)AuthType\s+Digest',
        r'^(\s*)AuthName\s+"rutorrent"',
        r'^(\s*)AuthUserFile\s+',
        r'^(\s*)Require\s+valid-user',
    ]
    lines = content.split("\n")
    new_lines = []
    for line in lines:
        commented = False
        for pat in auth_patterns:
            if re.match(pat, line) and not line.strip().startswith("#"):
                new_lines.append("#" + line)
                commented = True
                changes += 1
                break
        if not commented:
            new_lines.append(line)
    content = "\n".join(new_lines)

    # --- Fix 6: Replace hardcoded /srv/rutorrent/ paths in operational code ---
    # Replace rutorrent="/srv/rutorrent/" variable assignments
    rut_var_pat = r'rutorrent="/srv/rutorrent/"'
    new_content = content.replace(rut_var_pat, '# LEGACY: rutorrent path no longer used\n# rutorrent="/srv/rutorrent/"')
    if new_content != content:
        changes += 1
        content = new_content

    rut_var_pat2 = r"rutorrent=/srv/rutorrent/"
    new_content = content.replace(rut_var_pat2, '# LEGACY: rutorrent path no longer used\n# rutorrent=/srv/rutorrent/')
    if new_content != content:
        changes += 1
        content = new_content

    # --- Fix 7: Replace printf "" > /srv/rutorrent/home/db/output.log ---
    clean_log_pat = r'printf\s+""\s+>\s+/srv/rutorrent/home/db/output\.log'
    new_content = re.sub(clean_log_pat, 'printf "" > "$LOGFILE"', content)
    if new_content != content:
        changes += 1
        content = new_content

    # --- Fix 8: Replace /srv/rutorrent/home/db/interface.txt ---
    iface_pat = r'/srv/rutorrent/home/db/interface\.txt'
    new_content = re.sub(iface_pat, '/opt/AetherFlow/config/interface.txt', content)
    if new_content != content:
        changes += 1
        content = new_content

    # --- Write back if changed ---
    if changes > 0 and content != original:
        with open(filepath, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        stats["files_modified"] += 1
        stats["total_replacements"] += changes
        print(f"  FIXED ({changes} changes): {os.path.relpath(filepath, BASE)}")
    else:
        pass  # No changes needed


def main():
    print("=" * 60)
    print("AetherFlow Legacy Script Modernization")
    print("=" * 60)

    for d in DIRS:
        if not os.path.isdir(d):
            print(f"\n  SKIP (not found): {d}")
            continue
        rel = os.path.relpath(d, BASE)
        print(f"\n--- Processing: {rel} ---")
        for root, dirs, files in os.walk(d):
            # Skip __pycache__ etc
            dirs[:] = [dd for dd in dirs if not dd.startswith("__")]
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                # Skip .py files (ourselves)
                if fname.endswith(".py"):
                    continue
                fix_file(fpath)

    print("\n" + "=" * 60)
    print(f"DONE: {stats['files_modified']} files modified, {stats['total_replacements']} total replacements")
    if stats["skipped"]:
        print(f"Skipped {len(stats['skipped'])} files:")
        for path, reason in stats["skipped"]:
            print(f"  {os.path.relpath(path, BASE)}: {reason}")
    print("=" * 60)


if __name__ == "__main__":
    main()
