import os

setup_file = "c:/Users/armyw/OneDrive/Documents/AntiGravity/Projects/MediaNexus/setup/AetherFlow-Setup"
modules_dir = "c:/Users/armyw/OneDrive/Documents/AntiGravity/Projects/MediaNexus/setup/modules"

with open(setup_file, "r") as f:
    lines = f.readlines()

os.makedirs(modules_dir, exist_ok=True)

ranges = {
    "00-core.sh": [(40, 198), (290, 306)],
    "01-prompts.sh": [(204, 282), (307, 486), (509, 521), (1582, 1604)],
    "02-packages.sh": [(522, 683), (704, 767)],
    "03-services.sh": [(780, 1274), (1321, 1455)],
    "04-security.sh": [(283, 289), (487, 508), (684, 703), (768, 779), (1275, 1320)],
    "05-finalize.sh": [(1456, 1581), (1605, 1668)]
}

for module, r in ranges.items():
    with open(os.path.join(modules_dir, module), "w", newline='\n') as f:
        f.write("#!/bin/bash\n")
        f.write("# Module: " + module + "\n\n")
        for start, end in r:
            f.writelines(lines[start-1:end])

# Write updated Main Script
with open(setup_file, "w", newline='\n') as f:
    f.writelines(lines[0:39])
    
    f.write("\n# Check if running from setup directory or installed location\n")
    f.write("SCRIPT_DIR=\"$( cd \"$( dirname \"${BASH_SOURCE[0]}\" )\" && pwd )\"\n\n")

    f.write("# Load Modules\n")
    f.write("for module in \"${SCRIPT_DIR}/modules/\"*.sh; do\n")
    f.write("    # shellcheck disable=1090\n")
    f.write("    source \"$module\"\n")
    f.write("done\n\n")
    
    # 1669 to the end, but excluding SCRIPT_DIR definition which was at 1688-1689
    # Let me just write exactly line 1669 to 1686 (spinner and clear),
    # then skip SCRIPT_DIR definition and continue from 1690 to end.
    
    # 1669 to 1686
    f.writelines(lines[1668:1686])
    
    # 1690 to 1936
    f.writelines(lines[1689:])
