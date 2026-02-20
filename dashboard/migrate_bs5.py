import os
import re

DASHBOARD_DIR = "C:\\Users\\armyw\\OneDrive\\Documents\\AntiGravity\\Projects\\MediaNexus\\dashboard"

replacements = [
    # Panels back to Cards
    (r'\bpanel\b', r'card'),
    (r'\bpanel-default\b\s*', r''),
    (r'\bpanel-heading\b', r'card-header'),
    (r'\bpanel-body\b', r'card-body'),
    (r'\bpanel-footer\b', r'card-footer'),
    (r'\bpanel-title\b', r'card-title'),
    
    # Grid system updates
    (r'\bcol-xs-(\d+)\b', r'col-\1'),
    (r'\bcol-xs-offset-(\d+)\b', r'offset-\1'),
    (r'\bcol-sm-offset-(\d+)\b', r'offset-sm-\1'),
    (r'\bcol-md-offset-(\d+)\b', r'offset-md-\1'),
    (r'\bcol-lg-offset-(\d+)\b', r'offset-lg-\1'),
    
    # Utilities
    (r'\bpull-right\b', r'float-end'),
    (r'\bpull-left\b', r'float-start'),
    (r'\btext-right\b', r'text-end'),
    (r'\btext-left\b', r'text-start'),
    (r'\bhidden-xs\b', r'd-none d-sm-block'),
    (r'\bcenter-block\b', r'mx-auto'),
]

def migrate_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    new_content = content
    for old, new in replacements:
        new_content = re.sub(old, new, new_content)

    if content != new_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Updated: {filepath}")

def main():
    for root, dirs, files in os.walk(DASHBOARD_DIR):
        for file in files:
            if file.endswith('.php') or file.endswith('.html') or file.endswith('.js'):
                filepath = os.path.join(root, file)
                try:
                    migrate_file(filepath)
                except Exception as e:
                    print(f"Error processing {filepath}: {e}")

if __name__ == "__main__":
    main()
