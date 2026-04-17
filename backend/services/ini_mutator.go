package services

import (
	"bufio"
	"fmt"
	"io"
	"os"
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
	return copyFileStruct(im.ConfigPath, im.ConfigPath+".bak")
}

// Restore overrides the live configuration with the backup
func (im *INIMutator) Restore() error {
	return copyFileStruct(im.ConfigPath+".bak", im.ConfigPath)
}

// InjectRoutes looks for Key string matches inside INI configs and overwrites values
// dynamically according to the passed mapping
func (im *INIMutator) InjectRoutes(routes map[string]string) error {
	file, err := os.Open(im.ConfigPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // App not configured yet
		}
		return err
	}
	defer file.Close()

	var outputLines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Split naive INI format
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			// If the value in the INI matches our search term (e.g. "localhost"),
			// replace it with the new .aether.local target.
			// Example key checks could be more specific, but this broadly replaces targets loop overrides
			if injectedValue, exists := routes[val]; exists {
				// Reconstruct the line preserving the key but replacing value
				line = strings.Replace(line, val, injectedValue, 1)
			} else if specificReplacement, exists := routes[key]; exists {
				// E.g. mapped "WebUI\Host" -> "qbittorrent.aether.local"
				line = fmt.Sprintf("%s=%s", parts[0], specificReplacement)
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

// copyFileStruct handles basic I/O
func copyFileStruct(src, dst string) error {
	in, err := os.Open(src)
	if err != nil { return err }
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil { return err }
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
