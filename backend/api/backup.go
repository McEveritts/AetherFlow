package api

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

// Helper to reliably find the current database path
func getActiveDbPath() string {
	paths := []string{
		os.Getenv("DB_PATH"),
		filepath.Join("..", "dashboard", "db", "aetherflow.sqlite"),
		filepath.Join("dashboard", "db", "aetherflow.sqlite"),
		filepath.Join(".", "aetherflow.sqlite"),
	}

	for _, p := range paths {
		if p != "" {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return "aetherflow.sqlite"
}

func RunBackup(c *gin.Context) {
	dbPath := getActiveDbPath()
	
	// Create backup dir relative to db location
	backupDir := filepath.Join(filepath.Dir(dbPath), "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup directory"})
		return
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupFile := filepath.Join(backupDir, fmt.Sprintf("aetherflow_%s.sqlite", timestamp))

	source, err := os.Open(dbPath)
	if err != nil {
		log.Printf("Backup failed to open source: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read database file"})
		return
	}
	defer source.Close()

	destination, err := os.Create(backupFile)
	if err != nil {
		log.Printf("Backup failed to create dest: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create backup file"})
		return
	}
	defer destination.Close()

	bytesCopied, err := io.Copy(destination, source)
	if err != nil {
		log.Printf("Backup failed to copy: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "File copy failed"})
		return
	}

	// Simulate secondary snapshot tasks (e.g. Docker configs)
	time.Sleep(1 * time.Second)

	c.JSON(http.StatusOK, gin.H{
		"message": "Backup completed successfully",
		"filename": filepath.Base(backupFile),
		"size": bytesCopied,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

type BackupFile struct {
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	Timestamp string `json:"timestamp"`
}

func GetBackupsList(c *gin.Context) {
	dbPath := getActiveDbPath()
	backupDir := filepath.Join(filepath.Dir(dbPath), "backups")

	entries, err := os.ReadDir(backupDir)
	if err != nil {
		c.JSON(http.StatusOK, []BackupFile{})
		return
	}

	var backups []BackupFile
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".sqlite" {
			info, err := entry.Info()
			if err == nil {
				backups = append(backups, BackupFile{
					Filename:  entry.Name(),
					Size:      info.Size(),
					Timestamp: info.ModTime().Format(time.RFC3339),
				})
			}
		}
	}

	c.JSON(http.StatusOK, backups)
}

func DownloadBackup(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Filename required"})
		return
	}

	filename = filepath.Base(filename)
	dbPath := getActiveDbPath()
	filePath := filepath.Join(filepath.Dir(dbPath), "backups", filename)

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Backup file not found"})
		return
	}

	c.FileAttachment(filePath, filename)
}
