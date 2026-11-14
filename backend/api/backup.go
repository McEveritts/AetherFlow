package api

import (
	"aetherflow/db"
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	_ "modernc.org/sqlite"
)

// validBackupFilenameRe strictly allows alphanumeric start followed by alphanumeric,
// underscore, hyphen, and dot, ending with .sqlite extension. Blocks leading dots,
// path traversal, double extensions, and null bytes.
var validBackupFilenameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*\.sqlite$`)

// isValidBackupFilename checks that a filename matches the strict whitelist pattern.
func isValidBackupFilename(name string) bool {
	if len(name) > 128 || strings.Contains(name, "..") {
		return false
	}
	return validBackupFilenameRe.MatchString(name)
}

const (
	defaultBackupChunkSize int64 = 10 * 1024 * 1024 // 10 MiB
	maxBackupTotalChunks   int   = 1024             // 10 GiB max total upload
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
		filepath.Join(baseDir, "data", "aetherflow.sqlite"),                         // Canonical: backend/data/
		filepath.Join(baseDir, "..", "backend", "data", "aetherflow.sqlite"),        // From project root
		filepath.Join("/opt", "AetherFlow", "backend", "data", "aetherflow.sqlite"), // Production absolute path
		filepath.Join(baseDir, "..", "dashboard", "db", "aetherflow.sqlite"),        // Legacy fallback
		filepath.Join(baseDir, "dashboard", "db", "aetherflow.sqlite"),              // Legacy fallback (alt)
		filepath.Join(baseDir, "aetherflow.sqlite"),                                 // Base directory fallback
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
		return BackupFile{}, errors.New("failed to create backup directory")
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("aetherflow_%s.sqlite", timestamp)

	// Strict whitelist validation for backup filename (CWE-89 defense-in-depth)
	if !isValidBackupFilename(filename) {
		return BackupFile{}, errors.New("invalid backup filename")
	}

	backupFile, err := safeBackupPath(backupDir, filename)
	if err != nil {
		return BackupFile{}, err
	}

	// Escape single quotes in the path for VACUUM INTO.
	safePath := strings.ReplaceAll(backupFile, "'", "''")
	_, err = db.DB.Exec(fmt.Sprintf(`VACUUM INTO '%s'`, safePath))
	if err != nil {
		slog.Info("Backup VACUUM INTO failed", "error", err)
		return BackupFile{}, errors.New("backup failed: " + err.Error())
	}

	info, err := os.Stat(backupFile)
	if err != nil {
		return BackupFile{}, errors.New("backup created but file metadata is unavailable")
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
		InternalError(c, err.Error())
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

func openConfinedBackupRoot(createDir bool) (*os.Root, string, error) {
	backupDir, err := filepath.Abs(getBackupDir())
	if err != nil {
		return nil, "", err
	}
	if createDir {
		if err := os.MkdirAll(backupDir, 0750); err != nil {
			return nil, "", err
		}
	}
	info, err := os.Lstat(backupDir)
	if err != nil {
		return nil, backupDir, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, backupDir, errors.New("backup directory must not be a symlink")
	}
	root, err := os.OpenRoot(backupDir)
	if err != nil {
		return nil, backupDir, err
	}
	return root, backupDir, nil
}

func computeRootFileSHA256(root *os.Root, relName string) (string, error) {
	linfo, err := root.Lstat(relName)
	if err != nil {
		return "", err
	}
	if linfo.Mode()&os.ModeSymlink != 0 || linfo.IsDir() {
		return "", errors.New("refusing to hash non-regular backup file")
	}
	f, err := root.Open(relName)
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

func ensureRootStoredChecksum(root *os.Root, relName string) (string, error) {
	sumName := relName + ".sha256"
	if linfo, lErr := root.Lstat(sumName); lErr == nil && linfo.Mode()&os.ModeSymlink == 0 && !linfo.IsDir() {
		if data, rErr := root.ReadFile(sumName); rErr == nil {
			if sum := strings.TrimSpace(string(data)); sum != "" {
				return sum, nil
			}
		}
	}
	sum, err := computeRootFileSHA256(root, relName)
	if err != nil {
		return "", err
	}
	if linfo, lErr := root.Lstat(sumName); lErr == nil && linfo.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("refusing to write symlinked checksum file")
	}
	if err := root.WriteFile(sumName, []byte(sum+"\n"), 0640); err != nil {
		return "", err
	}
	return sum, nil
}

func validateUploadedSQLiteBackup(root *os.Root, backupDir, relTempName string) error {
	linfo, err := root.Lstat(relTempName)
	if err != nil || linfo.Mode()&os.ModeSymlink != 0 || linfo.IsDir() {
		return errors.New("invalid assembled backup file")
	}
	f, err := root.Open(relTempName)
	if err != nil {
		return err
	}
	header := make([]byte, 16)
	n, readErr := io.ReadFull(f, header)
	_ = f.Close()
	if readErr != nil || n != 16 || !bytes.Equal(header, []byte("SQLite format 3\x00")) {
		return errors.New("uploaded file is not a valid SQLite 3 database")
	}

	absCandidate := filepath.Join(backupDir, relTempName)
	verifyDB, err := sql.Open("sqlite", absCandidate+"?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(3000)")
	if err != nil {
		return errors.New("failed to open uploaded SQLite database for verification")
	}
	defer verifyDB.Close()

	var quickCheck string
	if err := verifyDB.QueryRow("PRAGMA quick_check").Scan(&quickCheck); err != nil || strings.ToLower(strings.TrimSpace(quickCheck)) != "ok" {
		return errors.New("uploaded SQLite database failed integrity verification")
	}
	return nil
}

func GetBackupsList(c *gin.Context) {
	root, backupDir, err := openConfinedBackupRoot(false)
	if err != nil {
		c.JSON(http.StatusOK, []BackupFile{})
		return
	}
	defer root.Close()

	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		c.JSON(http.StatusOK, []BackupFile{})
		return
	}

	backups := make([]BackupFile, 0)
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || !isValidBackupFilename(entry.Name()) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		checksum, err := ensureRootStoredChecksum(root, entry.Name())
		if err != nil {
			slog.Error("could not ensure checksum", "dir", backupDir, "name", entry.Name(), "error", err)
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

	filename := c.Param("filename")
	if filename == "" {
		BadRequest(c, "Filename required")
		return
	}
	if !isValidBackupFilename(filename) {
		BadRequest(c, "Invalid backup filename")
		return
	}

	// Audit the backup download
	var username string
	db.DB.QueryRow("SELECT username FROM users WHERE id = ?", userID).Scan(&username)
	db.RecordAudit(userID, username, "backup_download", "backup", filename, "", c.ClientIP(), c.Request.UserAgent())

	root, _, rootErr := openConfinedBackupRoot(false)
	if rootErr != nil {
		if os.IsNotExist(rootErr) {
			NotFoundError(c, "Backup file not found")
			return
		}
		InternalError(c, "Failed to access backup directory")
		return
	}
	defer root.Close()

	linfo, lErr := root.Lstat(filename)
	if os.IsNotExist(lErr) {
		NotFoundError(c, "Backup file not found")
		return
	}
	if lErr != nil || linfo.Mode()&os.ModeSymlink != 0 || linfo.IsDir() {
		BadRequest(c, "Refusing to serve non-regular backup file")
		return
	}

	file, err := root.Open(filename)
	if err != nil {
		if os.IsNotExist(err) {
			NotFoundError(c, "Backup file not found")
			return
		}
		InternalError(c, "Failed to open backup file")
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		InternalError(c, "Failed to read backup metadata")
		return
	}

	checksum, err := ensureRootStoredChecksum(root, filename)
	if err == nil {
		c.Header("X-Checksum-SHA256", checksum)
	}

	c.Header("Accept-Ranges", "bytes")
	c.Header("X-Backup-Size", strconv.FormatInt(info.Size(), 10))
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	chunkStr := c.Query("chunk")
	if chunkStr == "" {
		// Range requests are supported automatically by ServeContent.
		http.ServeContent(c.Writer, c.Request, filename, info.ModTime(), file)
		return
	}

	chunkIndex, err := strconv.Atoi(chunkStr)
	if err != nil || chunkIndex < 0 {
		BadRequest(c, "Invalid chunk index")
		return
	}

	chunkSize := defaultBackupChunkSize
	if sizeStr := c.Query("chunk_size"); sizeStr != "" {
		parsed, parseErr := strconv.ParseInt(sizeStr, 10, 64)
		if parseErr != nil || parsed <= 0 || parsed > defaultBackupChunkSize {
			BadRequest(c, "Invalid chunk_size")
			return
		}
		chunkSize = parsed
	}

	start := int64(chunkIndex) * chunkSize
	if start >= info.Size() {
		RespondError(c, http.StatusRequestedRangeNotSatisfiable, "RANGE_NOT_SATISFIABLE", "Chunk out of range")
		return
	}

	end := start + chunkSize - 1
	if end >= info.Size() {
		end = info.Size() - 1
	}
	toSend := end - start + 1
	progress := float64(end+1) / float64(info.Size()) * 100

	if _, err := file.Seek(start, io.SeekStart); err != nil {
		InternalError(c, "Failed to seek backup file")
		return
	}

	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, info.Size()))
	c.Header("Content-Length", strconv.FormatInt(toSend, 10))
	c.Header("X-Chunk-Index", strconv.Itoa(chunkIndex))
	c.Header("X-Chunk-Size", strconv.FormatInt(chunkSize, 10))
	c.Header("X-Progress", fmt.Sprintf("%.2f", progress))
	c.Status(http.StatusPartialContent)

	if _, err := io.CopyN(c.Writer, file, toSend); err != nil && !errors.Is(err, io.EOF) {
		slog.Error("chunked download failed", "name", filename, "error", err)
	}
}

func UploadBackupChunk(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		BadRequest(c, "Filename required")
		return
	}
	if !isValidBackupFilename(filename) {
		BadRequest(c, "Invalid backup filename: must match *.sqlite without path separators")
		return
	}

	chunkIndex, err := strconv.Atoi(c.Query("chunk"))
	if err != nil || chunkIndex < 0 {
		BadRequest(c, "chunk query must be a non-negative integer")
		return
	}

	totalChunks, err := strconv.Atoi(c.Query("total"))
	if err != nil || totalChunks <= 0 || totalChunks > maxBackupTotalChunks || chunkIndex >= totalChunks {
		BadRequest(c, "total query must be between 1 and 1024 and greater than chunk")
		return
	}

	// Enforce strict 10 MiB per-chunk request body cap
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, defaultBackupChunkSize)

	root, backupDir, rootErr := openConfinedBackupRoot(true)
	if rootErr != nil {
		InternalError(c, "Failed to prepare confined backup directory")
		return
	}
	defer root.Close()

	if linfo, lErr := root.Lstat(filename); lErr == nil && (linfo.Mode()&os.ModeSymlink != 0 || linfo.IsDir()) {
		BadRequest(c, "Refusing to overwrite symlink or directory")
		return
	}

	stageRelDir := ".upload-" + filename
	if linfo, lErr := root.Lstat(stageRelDir); lErr == nil && linfo.Mode()&os.ModeSymlink != 0 {
		BadRequest(c, "Refusing symlinked staging directory")
		return
	}
	if err := root.MkdirAll(stageRelDir, 0750); err != nil {
		InternalError(c, "Failed to prepare upload staging directory")
		return
	}

	chunkRelPath := fmt.Sprintf("%s/%06d.part", stageRelDir, chunkIndex)
	if linfo, lErr := root.Lstat(chunkRelPath); lErr == nil && linfo.Mode()&os.ModeSymlink != 0 {
		BadRequest(c, "Refusing symlinked chunk file")
		return
	}
	chunkFile, err := root.OpenFile(chunkRelPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		InternalError(c, "Failed to create chunk file")
		return
	}
	written, copyErr := io.Copy(chunkFile, c.Request.Body)
	closeErr := chunkFile.Close()
	if copyErr != nil {
		_ = root.Remove(chunkRelPath)
		if copyErr.Error() == "http: request body too large" {
			RespondError(c, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "Backup chunk exceeds 10 MiB limit")
			return
		}
		BadRequest(c, "Failed to persist chunk payload")
		return
	}
	if closeErr != nil || written == 0 {
		_ = root.Remove(chunkRelPath)
		BadRequest(c, "Failed to persist chunk payload")
		return
	}

	backupUploadMu.Lock()
	defer backupUploadMu.Unlock()

	entries, err := fs.ReadDir(root.FS(), stageRelDir)
	if err != nil {
		InternalError(c, "Failed to inspect upload state")
		return
	}

	received := 0
	for _, entry := range entries {
		if !entry.IsDir() && entry.Type()&fs.ModeSymlink == 0 && strings.HasSuffix(entry.Name(), ".part") {
			received++
		}
	}
	progress := float64(received) / float64(totalChunks) * 100

	if received < totalChunks {
		c.JSON(http.StatusOK, gin.H{
			"message":  "Chunk received",
			"filename": filename,
			"received": received,
			"total":    totalChunks,
			"progress": progress,
			"complete": false,
		})
		return
	}

	tempFinalName := filename + ".uploading"
	if linfo, lErr := root.Lstat(tempFinalName); lErr == nil && linfo.Mode()&os.ModeSymlink != 0 {
		BadRequest(c, "Refusing symlinked temporary backup file")
		return
	}
	out, err := root.OpenFile(tempFinalName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0640)
	if err != nil {
		InternalError(c, "Failed to build final backup file")
		return
	}

	for i := 0; i < totalChunks; i++ {
		partRel := fmt.Sprintf("%s/%06d.part", stageRelDir, i)
		part, err := root.Open(partRel)
		if err != nil {
			_ = out.Close()
			_ = root.Remove(tempFinalName)
			BadRequest(c, fmt.Sprintf("Missing chunk %d", i))
			return
		}

		if _, err := io.Copy(out, part); err != nil {
			_ = part.Close()
			_ = out.Close()
			_ = root.Remove(tempFinalName)
			InternalError(c, "Failed to assemble backup file")
			return
		}
		_ = part.Close()
	}

	if err := out.Close(); err != nil {
		_ = root.Remove(tempFinalName)
		InternalError(c, "Failed to finalize assembled backup file")
		return
	}

	checksum, err := computeRootFileSHA256(root, tempFinalName)
	if err != nil {
		_ = root.Remove(tempFinalName)
		InternalError(c, "Failed to compute assembled checksum")
		return
	}

	if expected := strings.TrimSpace(c.Query("checksum")); expected != "" && !strings.EqualFold(expected, checksum) {
		_ = root.Remove(tempFinalName)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":    "Checksum verification failed",
			"expected": expected,
			"actual":   checksum,
		})
		return
	}

	if valErr := validateUploadedSQLiteBackup(root, backupDir, tempFinalName); valErr != nil {
		_ = root.Remove(tempFinalName)
		_ = root.RemoveAll(stageRelDir)
		BadRequest(c, valErr.Error())
		return
	}

	if err := root.Rename(tempFinalName, filename); err != nil {
		_ = root.Remove(tempFinalName)
		InternalError(c, "Failed to activate assembled backup file")
		return
	}

	if err := root.WriteFile(filename+".sha256", []byte(checksum+"\n"), 0640); err != nil {
		InternalError(c, "Backup uploaded but checksum persistence failed")
		return
	}

	_ = root.RemoveAll(stageRelDir)
	info, statErr := root.Stat(filename)
	if statErr != nil {
		InternalError(c, "Upload completed but file metadata lookup failed")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":   "Chunked upload completed",
		"filename":  filename,
		"size":      info.Size(),
		"checksum":  checksum,
		"received":  totalChunks,
		"total":     totalChunks,
		"progress":  100.0,
		"complete":  true,
		"timestamp": time.Now().Format(time.RFC3339),
	})
}
