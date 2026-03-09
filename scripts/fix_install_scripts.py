import os
import re
import glob

INSTALL_DIR = r"c:\Users\armyw\OneDrive\Documents\Antigravity\Projects\AetherFlow\packages\package\install"

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content
    
    # 1. Replace master.txt with common.sh and variable
    content = re.sub(
        r'([A-Za-z0-9_]+)=\$\(cat /srv/rutorrent/home/db/master\.txt\)',
        r'source /opt/AetherFlow/packages/common.sh\n\g<1>=$AETHERFLOW_USER',
        content
    )

    # 2. Logging replacement
    content = re.sub(
        r'OUTTO=[\'\"]/srv/rutorrent/home/db/output\.log[\'\"]',
        r'OUTTO=$LOGFILE',
        content
    )
    content = re.sub(
        r'OUTTO=/srv/rutorrent/home/db/output\.log',
        r'OUTTO=$LOGFILE',
        content
    )
    content = re.sub(
        r'LOGFILE=/srv/rutorrent/home/db/output\.log.*',
        r'',
        content
    )

    # 3. Template paths
    content = re.sub(
        r'/etc/AetherFlow/setup/',
        r'/opt/AetherFlow/setup/',
        content
    )

    # 4. Apache Auth
    # Use re.MULTILINE to comment out these specific lines, dealing with different indents
    content = re.sub(r'(^[ \t]*AuthType Digest)', r'#\1', content, flags=re.MULTILINE)
    content = re.sub(r'(^[ \t]*AuthName "rutorrent")', r'#\1', content, flags=re.MULTILINE)
    content = re.sub(r'(^[ \t]*AuthUserFile \'/etc/htpasswd\')', r'#\1', content, flags=re.MULTILINE)
    content = re.sub(r'(^[ \t]*Require user \$\{username\})', r'#\1', content, flags=re.MULTILINE)

    # 5. Debian exit bug (specific to installpackage-sonarr, but generic enough)
    content = re.sub(
        r'(elif \[\[ \$distribution == "Debian" \]\];\s*then\s*)exit',
        r'\1#exit',
        content
    )

    if content != original_content:
        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.write(content)
        print(f"Updated: {os.path.basename(filepath)}")

def main():
    scripts = glob.glob(os.path.join(INSTALL_DIR, 'installpackage-*'))
    for script in scripts:
        process_file(script)

if __name__ == "__main__":
    main()
