import os

base = r'c:\Users\armyw\OneDrive\Documents\Antigravity\Projects\AetherFlow\packages\package\install'
OUTTO_LINE = 'OUTTO=$LOGFILE'
SOURCE_LINE = 'source /opt/AetherFlow/packages/common.sh'
fixed = 0

for f in os.listdir(base):
    fp = os.path.join(base, f)
    if not os.path.isfile(fp) or f == 'installpackage-sonarr':
        continue
    with open(fp, 'rb') as fh:
        raw = fh.read()
    content = raw.decode('utf-8', errors='replace')
    lines = content.splitlines(True)  # keep line endings

    source_idx = None
    outto_idx = None
    for i, line in enumerate(lines):
        s = line.strip()
        if s == SOURCE_LINE:
            source_idx = i
        if s == OUTTO_LINE and outto_idx is None:
            outto_idx = i

    if source_idx is not None and outto_idx is not None and outto_idx < source_idx:
        source_line = lines.pop(source_idx)
        lines.insert(outto_idx, source_line)
        with open(fp, 'wb') as fh:
            fh.write(b''.join(l.encode('utf-8') for l in lines))
        fixed += 1
        print(f'Fixed: {f}')

print(f'\nTotal fixed: {fixed}')
