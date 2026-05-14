import sys

with open('backend/services/deploy_orchestrator.go', 'r') as f:
    content = f.read()

content = content.replace('''func (o *Orchestrator) copyFile(src, dst string) error {''', '/* func (o *Orchestrator) copyFile(src, dst string) error {')
content = content.replace('''_, err = in.WriteTo(out)
	return err
}''', '''_, err = in.WriteTo(out)
	return err
} */''')

with open('backend/services/deploy_orchestrator.go', 'w') as f:
    f.write(content)
