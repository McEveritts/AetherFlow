
import os

files_to_convert = [
    r"setup/sources/xmlrpc-c_1-39-13/install-sh"
]

config_dir = r"setup/configs"
for root, dirs, files in os.walk(config_dir):
    for file in files:
        files_to_convert.append(os.path.join(root, file))

for filepath in files_to_convert:
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        
        if b'\r\n' in content:
            content = content.replace(b'\r\n', b'\n')
            with open(filepath, 'wb') as f:
                f.write(content)
            print(f"Converted: {filepath}")
        else:
            print(f"Skipped (already LF): {filepath}")
    except Exception as e:
        print(f"Error converting {filepath}: {e}")
