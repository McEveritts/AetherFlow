import os
import re

directory = r"C:\Users\armyw\OneDrive\Documents\AntiGravity\Projects\MediaNexus\dashboard\widgets\app_status"

if not os.path.exists(directory):
    print(f"Directory {directory} not found.")
    exit(1)

count = 0
for filename in os.listdir(directory):
    if filename.endswith(".php"):
        filepath = os.path.join(directory, filename)
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Replace the processExists function block
        new_content = re.sub(
            r'function processExists.*?return\s+\$exists;\s*\}',
            r"require_once($_SERVER['DOCUMENT_ROOT'] . '/inc/SystemInterface.php');\n" +
            r"function processExists($processName, $username) {\n" +
            r"  $sys = \\\\AetherFlow\\\\Inc\\\\SystemInterface::getInstance();\n" +
            r"  return $sys->is_process_running($processName, $username);\n" +
            r"}",
            content,
            flags=re.DOTALL
        )

        if content != new_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Refactored {filename}")
            count += 1

print(f"Total files refactored: {count}")
