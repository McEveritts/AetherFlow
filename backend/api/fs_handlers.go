package api

import (
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// FSEntry represents an individual directory or file entry.
type FSEntry struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	IsDir   bool   `json:"is_dir"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
}

// defaultAllowedRoots provides the standard directory sandbox roots for AetherFlow.
var defaultAllowedRoots = []string{
	"/mnt",
	"/media",
	"/home",
	"/opt/AetherFlow",
	"/var/lib/aetherflow",
}

// getAllowedFSRoots reads configured roots or falls back to system defaults + cwd.
func getAllowedFSRoots() []string {
	var roots []string
	if envRoots := os.Getenv("AF_ALLOWED_FS_ROOTS"); envRoots != "" {
		for _, r := range strings.Split(envRoots, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				roots = append(roots, filepath.Clean(r))
			}
		}
	}

	if len(roots) == 0 {
		for _, r := range defaultAllowedRoots {
			roots = append(roots, filepath.Clean(r))
		}
	}

	// Always allow project working directory in development/testing
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		roots = append(roots, filepath.Clean(cwd))
	}

	// Resolve symlinks on all allowed roots where possible
	var resolvedRoots []string
	for _, root := range roots {
		if realRoot, err := filepath.EvalSymlinks(root); err == nil {
			resolvedRoots = append(resolvedRoots, realRoot)
		} else {
			resolvedRoots = append(resolvedRoots, root)
		}
	}
	return resolvedRoots
}

func isPathAllowed(targetPath string, allowedRoots []string) bool {
	cleanedTarget := filepath.Clean(targetPath)
	for _, root := range allowedRoots {
		cleanedRoot := filepath.Clean(root)
		if cleanedTarget == cleanedRoot {
			return true
		}
		rel, err := filepath.Rel(cleanedRoot, cleanedTarget)
		if err == nil && !strings.HasPrefix(rel, "..") && !strings.HasPrefix(rel, "/") && !strings.HasPrefix(rel, "\\") {
			return true
		}
	}
	return false
}

// BrowseDirectories handles directory listing within an allowlisted sandbox.
// Responds with both directory name array (for PathSelector.tsx) and full FSEntry structures.
func BrowseDirectories(c *gin.Context) {
	rawPath := strings.TrimSpace(c.Query("path"))
	path := rawPath
	if path == "" || rawPath == "" {
		RespondError(c, http.StatusBadRequest, ErrCodeValidation, "Path parameter is required")
		return
	}

	cleanedPath := filepath.Clean(rawPath)

	// Resolve symlinks to prevent directory traversal out of sandbox
	resolvedPath, err := filepath.EvalSymlinks(cleanedPath)
	if err != nil {
		if os.IsNotExist(err) {
			RespondError(c, http.StatusNotFound, "NOT_FOUND", "Directory not found")
			return
		}
		slog.Warn("fs browser symlink evaluation failed", "path", cleanedPath, "error", err)
		RespondError(c, http.StatusBadRequest, "INVALID_PATH", "Could not resolve directory path")
		return
	}

	allowedRoots := getAllowedFSRoots()
	if !isPathAllowed(resolvedPath, allowedRoots) {
		slog.Warn("fs browser path outside allowed roots", "path", resolvedPath, "allowed", allowedRoots)
		RespondError(c, http.StatusForbidden, "FORBIDDEN", "Access denied: path is outside allowed sandbox")
		return
	}

	fileInfo, err := os.Stat(resolvedPath)
	if err != nil {
		RespondError(c, http.StatusNotFound, "NOT_FOUND", "Directory not found")
		return
	}
	if !fileInfo.IsDir() {
		RespondError(c, http.StatusBadRequest, "NOT_A_DIRECTORY", "Path is not a directory")
		return
	}

	entries, err := os.ReadDir(resolvedPath)
	if err != nil {
		slog.Error("fs browser failed to read directory", "path", resolvedPath, "error", err)
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to read directory")
		return
	}

	var directories []string
	var fsEntries []FSEntry

	for _, entry := range entries {
		info, err := entry.Info()
		var size int64
		var modTime string
		if err == nil {
			size = info.Size()
			modTime = info.ModTime().Format(time.RFC3339)
		} else {
			modTime = time.Now().Format(time.RFC3339)
		}

		fullEntryPath := filepath.Join(resolvedPath, entry.Name())
		isDir := entry.IsDir()
		if !isDir && entry.Type()&os.ModeSymlink != 0 {
			if targetInfo, statErr := os.Stat(fullEntryPath); statErr == nil && targetInfo.IsDir() {
				if realTarget, evalErr := filepath.EvalSymlinks(fullEntryPath); evalErr == nil && isPathAllowed(realTarget, allowedRoots) {
					isDir = true
				}
			}
		}
		if isDir {
			directories = append(directories, entry.Name())
		}

		fsEntries = append(fsEntries, FSEntry{
			Name:    entry.Name(),
			Path:    fullEntryPath,
			IsDir:   isDir,
			Size:    size,
			ModTime: modTime,
		})
	}

	if directories == nil {
		directories = []string{}
	}
	if fsEntries == nil {
		fsEntries = []FSEntry{}
	}

	sort.Strings(directories)
	sort.Slice(fsEntries, func(i, j int) bool {
		if fsEntries[i].IsDir != fsEntries[j].IsDir {
			return fsEntries[i].IsDir // directories first
		}
		return fsEntries[i].Name < fsEntries[j].Name
	})

	parentPath := filepath.Dir(resolvedPath)

	c.JSON(http.StatusOK, gin.H{
		"current_path": resolvedPath,
		"parent_path":  parentPath,
		"directories":  directories,
		"entries":      fsEntries,
	})
}
