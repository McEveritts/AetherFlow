import os
import re
import argparse

# Target directory
WORKSPACE_DIR = './dashboard/'

# Dictionary of strictly bounded regex replacements to run INSIDE class strings
CLASS_REPLACEMENTS = {
    # Panels
    r'\bpanel\b': 'card',
    r'\bpanel-default\b\s?': '', # Matches and removes trailing spaces cleanly
    r'\bpanel-heading\b': 'card-header',
    r'\bpanel-body\b': 'card-body',
    r'\bpanel-footer\b': 'card-footer',
    r'\bpanel-title\b': 'card-title',
    
    # Grid System
    r'\bcol-xs-(\d+)\b': r'col-\1',
    r'\bcol-xs-offset-(\d+)\b': r'offset-\1',
    
    # Utilities & Positioning
    r'\bpull-right\b': 'float-end',
    r'\bpull-left\b': 'float-start',
    r'\btext-right\b': 'text-end',
    r'\btext-left\b': 'text-start',
    r'\bhidden-xs\b': 'd-none d-sm-block'
}

def process_class_attribute(match):
    """
    Takes the matched class="..." string, extracts the inner classes,
    applies the bounded regex safely, and returns the rebuilt attribute.
    """
    class_string = match.group(1)
    
    for old_pattern, new_pattern in CLASS_REPLACEMENTS.items():
        class_string = re.sub(old_pattern, new_pattern, class_string)
    
    # Clean up any accidental double spaces created by deletions
    class_string = re.sub(r'\s{2,}', ' ', class_string).strip()
    
    return f'class="{class_string}"'

def migrate_file(filepath, dry_run=False):
    with open(filepath, 'r', encoding='utf-8') as file:
        content = file.read()

    # Step 1: Find all class attributes and process them through our safe function
    # This regex specifically isolates class="..." avoiding greedy lookaheads across DOM elements
    updated_content = re.sub(r'class="([^"]*)"', process_class_attribute, content)

    # Only write to disk if changes were actually made
    if content != updated_content:
        if not dry_run:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write(updated_content)
            print(f"[MODIFIED] {filepath}")
        else:
            print(f"[DRY RUN - WOULD MODIFY] {filepath}")

def main():
    parser = argparse.ArgumentParser(description="Bootstrap 5 DOM Migration script")
    parser.add_argument('--dry-run', action='store_true', help="Preview the exact DOM changes without permanently overwriting files")
    args = parser.parse_args()

    print(f"Initiating Bootstrap 5 DOM Migration... {'(DRY RUN)' if args.dry_run else ''}")
    for root, _, files in os.walk(WORKSPACE_DIR):
        for file in files:
            if file.endswith(('.php', '.html')):
                migrate_file(os.path.join(root, file), dry_run=args.dry_run)
    print("Migration Complete.")

if __name__ == "__main__":
    main()
