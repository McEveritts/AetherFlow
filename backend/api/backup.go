package api

import (
	"aetherflow/db"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// validBackupFilenameRe strictly allows alphanumeric, underscore, hyphen, and dot,
// ending with .sqlite extension. Blocks path traversal and null bytes.
var validBackupFilenameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]+\.sqlite$`)

// isValidBackupFilename checks that a filename matches the strict whitelist pattern.
func isValidBackupFilename(name string) bool {
	return validBackupFilenameRe.MatchString(name)
}

const (
	defaultBackupChunkSize int64 = 10 * 1024 * 1024 // 10 MiB
)

var backupUploadMu sync.Mutex

// Helper to reliably find the current database path by anchoring to the executable path.
func getActiveDbPath() string {
	if override := os.Getenv("DB_PATH"); override != "" {
		return override // Respect explicit environment variable first
	}

	exePath, err := os.Executable()
	if err != nil {
		slog.Warn("Failed to determine executable path, fallback to working directory", "error", err)
		exePath = "."
	}
	baseDir := filepath.Dir(exePath)

	paths := []string{
		filepath.Join(baseDir, "data", "aetherflow.sqlite"),                                   // Canonical: backend/data/
		filepath.Join(baseDir, "..", "backend", "data", "aetherflow.sqlite"),                  // From project root
		filepath.Join("/opt", "AetherFlow", "backend", "data", "aetherflow.sqlite"),          // Production absolute path
		filepath.Join(baseDir, "..", "dashboard", "db", "aetherflow.sqlite"),                  // Legacy fallback
		filepath.Join(baseDir, "dashboard", "db", "aetherflow.sqlite"),                        // Legacy fallback (alt)
		filepath.Join(baseDir, "aetherflow.sqlite"),                                           // Base directory fallback
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	
	// Ultimate fallback strictly anchored to execution root
	return filepath.Join(baseDir, "data", "aetherflow.sqlite")
}

func getBackupDir() string {
	return filepath.Join(filepath.Dir(getActiveDbPath()), "backups")
}

func safeBackupPath(baseDir, filename string) (string, error) {
	if filename == "" {
		return "", errors.New("filename required")
	}

	cleanName := filepath.Base(filename)
	if cleanName == "." || cleanName == ".." || cleanName == "" {
		return "", errors.New("invalid filename")
	}

	fullPath := filepath.Join(baseDir, cleanName)
	absDir, err := filepath.Abs(baseDir)
	if err != nil {
		return "", errors.New("invalid base backup path")
	}
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", errors.New("invalid backup path")
	}

	rel, err := filepath.Rel(absDir, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", errors.New("invalid backup path")
	}
	return absPath, nil
}

func checksumFilePath(filePath string) string {
	return filePath + ".sha256"
}

func computeFileSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readStoredChecksum(filePath string) (string, error) {
	data, err := os.ReadFile(checksumFilePath(filePath))
	if err != nil {
		return "", err
	}
	sum := strings.TrimSpace(string(data))
	if sum == "" {
		return "", errors.New("checksum file is empty")
	}
	return sum, nil
}

func writeStoredChecksum(filePath, checksum string) error {
	return os.WriteFile(checksumFilePath(filePath), []byte(checksum+"\n"), 0644)
}

func ensureStoredChecksum(filePath string) (string, error) {
	sum, err := readStoredChecksum(filePath)
	if err == nil {
		return sum, nil
	}

	sum, err = computeFileSHA256(filePath)
	if err != nil {
		return "", err
	}
	if err := writeStoredChecksum(filePath, sum); err != nil {
		return "", err
	}
	return sum, nil
}

type BackupFile struct {
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	Timestamp string `json:"timestamp"`
	Checksum  string `json:"checksum,omitempty"`
}

func PerformSystemBackup() (BackupFile, error) {
	backupDir := getBackupDir()
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return BackupFile{}, errors.New("Failed to create backup directory")
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("aetherflow_%s.sqlite", timestamp)

	// Strict whitelist validation for backup filename (CWE-89 defense-in-depth)
	if !isValidBackupFilename(filename) {
		return BackupFile{}, errors.New("Invalid backup filename")
	}

	backupFile, err := safeBackupPath(backupDir, filename)
	if err != nil {
		return BackupFile{}, err
	}

	// Escape single quotes in the path for VACUUM INTO.
	safePath := strings.ReplaceAll(backupFile, "'", "''")
	_, err = db.DB.Exec(fmt.Sprintf(`VACUUM INTO '%s'`, safePath))
	if err != nil {
		slog.Info("Backup VACUUM INTO failed", "value", err)
		return BackupFile{}, errors.New("Backup failed: " + err.Error())
	}

	info, err := os.Stat(backupFile)
	if err != nil {
		return BackupFile{}, errors.New("Backup created but file metadata is unavailable")
	}

	checksum, err := computeFileSHA256(backupFile)
	if err != nil {
		return BackupFile{}, errors.New("Backup created but checksum failed: " + err.Error())
	}
	if err := writeStoredChecksum(backupFile, checksum); err != nil {
		return BackupFile{}, errors.New("Backup created but checksum write failed: " + err.Error())
	}

	// Phase 15: Enforce retention policy after successful backup
	go PruneOldBackups()

	return BackupFile{
		Filename:  filepath.Base(backupFile),
		Size:      info.Size(),
		Timestamp: time.Now().Format(time.RFC3339),
		Checksum:  checksum,
	}, nil
}

func RunBackup(c *gin.Context) {
	bf, err := PerformSystemBackup()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":   "Backup completed successfully",
		"filename":  bf.Filename,
		"size":      bf.Size,
		"checksum":  bf.Checksum,
		"timestamp": bf.Timestamp,
	})
}

func GetBackupsList(c *gin.Context) {
	backupDir := getBackupDir()
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		c.JSON(http.StatusOK, []BackupFile{})
		return
	}

	var backups []BackupFile
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sqlite" {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		filePath := filepath.Join(backupDir, entry.Name())
		checksum, err := ensureStoredChecksum(filePath)
		if err != nil {
			slog.Error("Could not ensure checksum for %s", "value", filePath, "error", err)
		}

		backups = append(backups, BackupFile{
			Filename:  entry.Name(),
			Size:      info.Size(),
			Timestamp: info.ModTime().Format(time.RFC3339),
			Checksum:  checksum,
		})
	}

	c.JSON(http.StatusOK, backups)
}

func DownloadBackup(c *gin.Context) {
	// Phase 28: Re-authentication check — backup download is a high-value
	// exfiltration target, so we require the caller to prove session ownership
	// via X-Reauth-Password header. This mitigates session riding (CSRF).
	reauthPassword := c.GetHeader("X-Reauth-Password")
	if reauthPassword == "" {
		RespondError(c, http.StatusForbidden, ErrCodeForbidden, "Re-authentication required for backup download. Provide X-Reauth-Password header.")
		return
	}
	rawUserID, _ := c.Get("user_id")
	userID, ok := rawUserID.(int)
	if !ok {
		RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, "Invalid session")
		return
	}
	var passwordHash string
	if err := db.DB.QueryRow("SELECT COALESCE(password_hash, '') FROM users WHERE id = ?", userID).Scan(&passwordHash); err != nil || passwordHash == "" {
		RespondError(c, http.StatusForbidden, ErrCodeForbidden, "Re-authentication failed")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(reauthPassword)); err != nil {
		RespondError(c, http.StatusForbidden, ErrCodeForbidden, "Re-authentication failed: invalid password")
		return
	}

	// Audit the backup download
	var username string
	db.DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	db.RecordAudit(userID, username, "backup_download", "backup", c.Param("filename"), "", c.ClientIP(), c.Request.UserAgent())

	filename := c.Param("filename")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Filename required"})
		return
	}

	backupDir := getBackupDir()
	filePath, err := safeBackupPath(backupDir, filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Backup file not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to open backup file"})
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read backup metadata"})
		return
	}

	checksum, err := ensureStoredChecksum(filePath)
	if err == nil {
		c.Header("X-Checksum-SHA256", checksum)
	}

	c.Header("Accept-Ranges", "bytes")
	c.Header("X-Backup-Size", strconv.FormatInt(info.Size(), 10))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(filePath)))

	chunkStr := c.Query("chunk")
	if chunkStr == "" {
		// Range requests are supported automatically by ServeContent.
		http.ServeContent(c.Writer, c.Request, filepath.Base(filePath), info.ModTime(), file)
		return
	}

	chunkIndex, err := strconv.Atoi(chunkStr)
	if err != nil || chunkIndex < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chunk index"})
		return
	}

	chunkSize := defaultBackupChunkSize
	if sizeStr := c.Query("chunk_size"); sizeStr != "" {
		parsed, parseErr := strconv.ParseInt(sizeStr, 10, 64)
		if parseErr != nil || parsed <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid chunk_size"})
			return
		}
		chunkSize = parsed
	}

	start := int64(chunkIndex) * chunkSize
	if start >= info.Size() {
		c.JSON(http.StatusRequestedRangeNotSatisfiable, gin.H{"error": "Chunk out of range"})
		return
	}

	end := start + chunkSize - 1
	if end >= info.Size() {
		end = info.Size() - 1
	}
	toSend := end - start + 1
	progress := float64(end+1) / float64(info.Size()) * 100

	if _, err := file.Seek(start, io.SeekStart); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to seek backup file"})
		return
	}

	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, info.Size()))
	c.Header("Content-Length", strconv.FormatInt(toSend, 10))
	c.Header("X-Chunk-Index", strconv.Itoa(chunkIndex))
	c.Header("X-Chunk-Size", strconv.FormatInt(chunkSize, 10))
	c.Header("X-Progress", fmt.Sprintf("%.2f", progress))
	c.Status(http.StatusPartialContent)

	if _, err := io.CopyN(c.Writer, file, toSend); err != nil && !errors.Is(err, io.EOF) {
		slog.Error("Chunked download failed for %s", "value", filePath, "error", err)
	}
}

func UploadBackupChunk(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Filename required"})
		return
	}

	chunkIndex, err := strconv.Atoi(c.Query("chunk"))
	if err != nil || chunkIndex < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "chunk query must be a non-negative integer"})
		return
	}

	totalChunks, err := strconv.Atoi(c.Query("total"))
	if err != nil || totalChunks <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "total query must be a positive integer"})
		return
	}

	backupDir := getBackupDir()
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare backup directory"})
		return
	}

	finalPath, err := safeBackupPath(backupDir, filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	uploadDir := filepath.Join(backupDir, ".upload-"+filepath.Base(filename))
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare upload staging directory"})
		return
	}

	chunkPath := filepath.Join(uploadDir, fmt.Sprintf("%06d.part", chunkIndex))
	chunkFile, err := os.Create(chunkPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create chunk file"})
		return
	}
	written, copyErr := io.Copy(chunkFile, c.Request.Body)
	closeErr := chunkFile.Close()
	if copyErr != nil || closeErr != nil || written == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to persist chunk payload"})
		return
	}

	backupUploadMu.Lock()
	defer backupUploadMu.Unlock()

	entries, err := os.ReadDir(uploadDir)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to inspect upload state"})
		return
	}

	received := 0
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".part") {
			received++
		}
	}
	progress := float64(received) / float64(totalChunks) * 100

	if received < totalChunks {
		c.JSON(http.StatusOK, gin.H{
			"message":  "Chunk received",
			"filename": filepath.Base(finalPath),
			"received": received,
			"total":    totalChunks,
			"progress": progress,
			"complete": false,
		})
		return
	}

	tempFinalPath := finalPath + ".uploading"
	out, err := os.Create(tempFinalPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to build final backup file"})
		return
	}

	for i := 0; i < totalChunks; i++ {
		partPath := filepath.Join(uploadDir, fmt.Sprintf("%06d.part", i))
		part, err := os.Open(partPath)
		if err != nil {
			out.Close()
			os.Remove(tempFinalPath)
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Missing chunk %d", i)})
			return
		}

		if _, err := io.Copy(out, part); err != nil {
			part.Close()
			out.Close()
			os.Remove(tempFinalPath)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to assemble backup file"})
			return
		}
		part.Close()
	}

	if err := out.Close(); err != nil {
		os.Remove(tempFinalPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to finalize assembled backup file"})
		return
	}

	checksum, err := computeFileSHA256(tempFinalPath)
	if err != nil {
		os.Remove(tempFinalPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to compute assembled checksum"})
		return
	}

	if expected := strings.TrimSpace(c.Query("checksum")); expected != "" && !strings.EqualFold(expected, checksum) {
		os.Remove(tempFinalPath)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":    "Checksum verification failed",
			"expected": expected,
			"actual":   checksum,
		})
		return
	}

	if err := os.Rename(tempFinalPath, finalPath); err != nil {
		os.Remove(tempFinalPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to activate assembled backup file"})
		return
	}

	if err := writeStoredChecksum(finalPath, checksum); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Backup uploaded but checksum persistence failed"})
		return
	}

	_ = os.RemoveAll(uploadDir)
	info, statErr := os.Stat(finalPath)
	if statErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Upload completed but file metadata lookup failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Chunked upload completed",
		"filename":  filepath.Base(finalPath),
		"size":      info.Size(),
		"checksum":  checksum,
		"received":  totalChunks,
		"total":     totalChunks,
		"progress":  100.0,
		"complete":  true,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}
