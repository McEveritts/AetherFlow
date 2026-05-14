import sys

with open('backend/services/local_dns_manager.go', 'r') as f:
    lines = f.readlines()

new_lines = []
skip = False
for line in lines:
    if "for _, p := range parts[1:] {" in line:
        new_lines.append(line.replace("for _, p := range parts[1:] {", "existingDomains = append(existingDomains, parts[1:]...)"))
        skip = True
        continue
    if skip and "existingDomains = append(existingDomains, p)" in line:
        continue
    if skip and "}" in line:
        skip = False
        continue
    new_lines.append(line)

with open('backend/services/local_dns_manager.go', 'w') as f:
    f.writelines(new_lines)
