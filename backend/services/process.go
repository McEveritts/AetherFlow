package services

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CheckProcessRunning natively scans /proc without spawning the shell
func CheckProcessRunning(processName string) bool {
	procNameLower := strings.ToLower(processName)

	files, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}

	for _, f := range files {
		if f.IsDir() {
			// Check if directory name is numeric (a PID)
			if _, err := strconv.Atoi(f.Name()); err == nil {
				commPath := filepath.Join("/proc", f.Name(), "comm")
				data, err := os.ReadFile(commPath)
				if err == nil {
					commStr := strings.TrimSpace(strings.ToLower(string(data)))
					if strings.Contains(commStr, procNameLower) {
						return true
					}
				}
			}
		}
	}

	return false
}
