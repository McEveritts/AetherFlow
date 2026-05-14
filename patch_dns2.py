import sys

with open('backend/services/local_dns_manager.go', 'r') as f:
    content = f.read()

content = content.replace('''for _, p := range parts[1:] {
						existingDomains = append(existingDomains, p)
					}''', 'existingDomains = append(existingDomains, parts[1:]...)')

with open('backend/services/local_dns_manager.go', 'w') as f:
    f.write(content)
