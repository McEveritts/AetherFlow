
import os

def convert_line_endings(directory):
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".template") or file.endswith(".sh") or file == "AetherFlow-Setup":
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, 'rb') as f:
                        content = f.read()
                    
                    if b'\r\n' in content:
                        content = content.replace(b'\r\n', b'\n')
                        with open(filepath, 'wb') as f:
                            f.write(content)
                        print(f"Converted: {filepath}")
                except Exception as e:
                    print(f"Error converting {filepath}: {e}")

if __name__ == "__main__":
    convert_line_endings(".")
