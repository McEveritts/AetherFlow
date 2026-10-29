package services

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// INIMutator parses line-by-line configuration files to preserve
// specific tab/spacing and comments that a struct-marshaller might destroy.
type INIMutator struct {
	ConfigPath string
}

func NewINIMutator(path string) *INIMutator {
	return &INIMutator{ConfigPath: path}
}

// Backup clones the existing configuration
func (im *INIMutator) Backup() error {
	if _, err := os.Stat(im.ConfigPath); os.IsNotExist(err) {
		return nil
	}
	return copyFileStruct(im.ConfigPath, im.ConfigPath+".bak")
}

// Restore overrides the live configuration with the backup
func (im *INIMutator) Restore() error {
	if _, err := os.Stat(im.ConfigPath + ".bak"); os.IsNotExist(err) {
		return nil
	}
	return copyFileStruct(im.ConfigPath+".bak", im.ConfigPath)
}

// InjectRoutes looks for Key string matches inside INI configs and overwrites values
// dynamically according to the passed mapping.
func (im *INIMutator) InjectRoutes(routes map[string]string) error {
	if im.ConfigPath == "" || len(routes) == 0 {
		return nil
	}

	file, err := os.Open(im.ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // App not configured yet
		}
		return err
	}
	defer file.Close()

	var outputLines []string
	seenKeys := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			if injectedValue, exists := routes[val]; exists {
				line = strings.Replace(line, val, injectedValue, 1)
				seenKeys[val] = true
			} else if specificReplacement, exists := routes[key]; exists {
				line = fmt.Sprintf("%s=%s", parts[0], specificReplacement)
				seenKeys[key] = true
			}
		}

		outputLines = append(outputLines, line)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	finalOutput := strings.Join(outputLines, "\n") + "\n"
	return os.WriteFile(im.ConfigPath, []byte(finalOutput), 0644)
}

// ApplySettings ensures the specified INI key=value pairs exist in the file,
// creating the file under [Preferences] if it does not exist yet.
func (im *INIMutator) ApplySettings(settings map[string]string) error {
	if im.ConfigPath == "" || len(settings) == 0 {
		return nil
	}

	contentBytes, err := os.ReadFile(im.ConfigPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if os.IsNotExist(err) || len(strings.TrimSpace(string(contentBytes))) == 0 {
		if err := os.MkdirAll(filepath.Dir(im.ConfigPath), 0755); err != nil {
			return err
		}
		keys := make([]string, 0, len(settings))
		for k := range settings {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		lines := []string{"[Preferences]"}
		for _, k := range keys {
			lines = append(lines, fmt.Sprintf("%s=%s", k, settings[k]))
		}
		return os.WriteFile(im.ConfigPath, []byte(strings.Join(lines, "\n")+"\n"), 0644)
	}

	var outputLines []string
	seenKeys := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(contentBytes)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			if replacement, ok := settings[key]; ok {
				line = fmt.Sprintf("%s=%s", parts[0], replacement)
				seenKeys[key] = true
			}
		}
		outputLines = append(outputLines, line)
	}

	keys := make([]string, 0, len(settings))
	for k := range settings {
		if !seenKeys[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		outputLines = append(outputLines, fmt.Sprintf("%s=%s", k, settings[k]))
	}

	return os.WriteFile(im.ConfigPath, []byte(strings.Join(outputLines, "\n")+"\n"), 0644)
}

// copyFileStruct handles basic I/O
func copyFileStruct(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
