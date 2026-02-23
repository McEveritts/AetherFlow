import os

def replace_attributes(dir_path):
    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith('.php') or file.endswith('.html'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                new_content = content.replace('data-toggle="', 'data-bs-toggle="')
                new_content = new_content.replace('data-target="', 'data-bs-target="')
                new_content = new_content.replace('data-dismiss="', 'data-bs-dismiss="')

                if content != new_content:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f"Updated {file_path}")

if __name__ == "__main__":
    replace_attributes("c:/Users/armyw/OneDrive/Documents/Antigravity/Projects/AetherFlow/dashboard")
