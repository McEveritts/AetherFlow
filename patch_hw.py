import sys

with open('backend/services/hardware.go', 'r') as f:
    content = f.read()

content = content.replace('''func sanitizeFloat64Map(m map[string]float64) {
	for k, v := range m {
		m[k] = sanitizeFloat64(v)
	}
}''', '/* func sanitizeFloat64Map(m map[string]float64) {\n\tfor k, v := range m {\n\t\tm[k] = sanitizeFloat64(v)\n\t}\n} */')

with open('backend/services/hardware.go', 'w') as f:
    f.write(content)
