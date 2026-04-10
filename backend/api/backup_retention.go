package api

import (
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// ── Phase 15: Backup Retention Policy ───────────────────────────────────
//
// Automatically cleans up old backups based on:
//   - Keep the last N backups (default: 10)
//   - Always keep backups from the last 7 days
//   - Log all pruned files for audit

const (
	maxRetainedBackups = 10
	retentionDays      = 7
)

// PruneOldBackups enforces the backup retention policy.
// Call this after every successful backup creation.
func PruneOldBackups() {
	backupDir := getBackupDir()

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		slog.Info("[backup-retention] Failed to read backup directory", "error", err)
		return
	}

	// Collect backup files with timestamps
	type backupEntry struct {
		name    string
		modTime time.Time
		path    string
	}

	var backups []backupEntry
	for _, entry := range entries {
		if entry.IsDir() || !isValidBackupFilename(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backupEntry{
			name:    entry.Name(),
			modTime: info.ModTime(),
			path:    filepath.Join(backupDir, entry.Name()),
		})
	}

	// Sort by modification time, newest first
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].modTime.After(backups[j].modTime)
	})

	if len(backups) <= maxRetainedBackups {
		return // Nothing to prune
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	pruned := 0

	for i := maxRetainedBackups; i < len(backups); i++ {
		// Always keep backups within retention window
		if backups[i].modTime.After(cutoff) {
			continue
		}

		// Remove backup file and its checksum
		if err := os.Remove(backups[i].path); err != nil {
			slog.Error("failed to remove backup", "name", backups[i].name, "error", err)
			continue
		}
		// Also remove checksum file if exists
		os.Remove(backups[i].path + ".sha256")

		slog.Info("pruned old backup", "name", backups[i].name,
			"age", time.Since(backups[i].modTime).Truncate(time.Hour))
		pruned++
	}

	if pruned > 0 {
		slog.Info("backup retention completed", "pruned", pruned, "retained", len(backups)-pruned)
	}
}
