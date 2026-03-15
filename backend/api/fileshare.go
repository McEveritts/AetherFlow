package api

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// Maximum upload file size: 50 MiB
	maxUploadSize = 50 * 1024 * 1024
)

type FileInfo struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ModTime   string `json:"modTime"`
	Extension string `json:"extension"`
}

func getUploadDir() string {
	// Check environment variable first
	if envPath := os.Getenv("AETHERFLOW_UPLOAD_DIR"); envPath != "" {
		if _, err := os.Stat(envPath); err == nil {
			return envPath
		}
	}

	paths := []string{
		filepath.Join(".", "uploads"),
		filepath.Join("..", "uploads"),
		filepath.Join("/opt", "AetherFlow", "uploads"),
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Create local upload folder if none exist
	defaultPath := filepath.Join(".", "uploads")
	if err := os.MkdirAll(defaultPath, 0755); err != nil {
		log.Printf("Failed to create upload directory: %v", err)
	}
	return defaultPath
}

func GetFilesList(c *gin.Context) {
	uploadDir := getUploadDir()
	files, err := os.ReadDir(uploadDir)
	if err != nil {
		log.Printf("Error reading upload directory: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read files directory"})
		return
	}

	var fileList []FileInfo
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		info, err := f.Info()
		if err != nil {
			continue
		}

		fileList = append(fileList, FileInfo{
			Name:      info.Name(),
			Size:      info.Size(),
			ModTime:   info.ModTime().Format(time.RFC3339),
			Extension: filepath.Ext(info.Name()),
		})
	}

	c.JSON(http.StatusOK, fileList)
}

// blockedExtensions contains file extensions that are never allowed.
var blockedExtensions = map[string]bool{
	".exe": true, ".sh": true, ".bat": true, ".cmd": true,
	".ps1": true, ".php": true, ".jsp": true, ".cgi": true,
	".pif": true, ".scr": true, ".com": true, ".msi": true,
	".vbs": true, ".vbe": true, ".wsf": true, ".wsh": true,
	".py": true, ".rb": true, ".pl": true, ".jar": true,
}

// blockedContentTypes contains MIME types that indicate executable content.
var blockedContentTypes = map[string]bool{
	"application/x-executable":      true,
	"application/x-msdos-program":   true,
	"application/x-msdownload":      true,
	"application/x-dosexec":         true,
	"application/x-sharedlib":       true,
	"application/x-pie-executable":  true,
	"application/x-elf":             true,
	"application/vnd.microsoft.portable-executable": true,
}

// sanitizeFilename strips null bytes, directory components, and validates the filename.
func sanitizeFilename(name string) (string, error) {
	// Strip null bytes (null byte injection prevention)
	name = strings.ReplaceAll(name, "\x00", "")

	// Strip directory components
	safeName := filepath.Base(name)
	if safeName == "." || safeName == ".." || safeName == string(filepath.Separator) || safeName == "" {
		return "", &uploadError{"Invalid filename"}
	}

	// Check ALL extensions for double-extension attacks (e.g., exploit.php.jpg)
	lower := strings.ToLower(safeName)
	parts := strings.Split(lower, ".")
	for _, part := range parts[1:] { // skip the first element (filename without ext)
		if blockedExtensions["."+part] {
			return "", &uploadError{"File type not allowed: ." + part}
		}
	}

	return safeName, nil
}

type uploadError struct {
	msg string
}

func (e *uploadError) Error() string {
	return e.msg
}

func UploadFile(c *gin.Context) {
	// Enforce maximum body size
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUploadSize)

	file, err := c.FormFile("file")
	if err != nil {
		if err.Error() == "http: request body too large" {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "File exceeds maximum allowed size of 50 MB"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded or invalid payload"})
		return
	}

	// Enforce file size limit at header level too
	if file.Size > maxUploadSize {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "File exceeds maximum allowed size of 50 MB"})
		return
	}

	// Sanitize filename (strips nulls, checks all extensions)
	safeName, err := sanitizeFilename(file.Filename)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Content-type sniffing: read first 512 bytes to detect actual content type
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}
	defer src.Close()

	sniffBuf := make([]byte, 512)
	n, _ := src.Read(sniffBuf)
	detectedType := http.DetectContentType(sniffBuf[:n])

	if blockedContentTypes[detectedType] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "File content type not allowed: " + detectedType})
		return
	}

	uploadDir := getUploadDir()
	dst := filepath.Join(uploadDir, safeName)

	if err := c.SaveUploadedFile(file, dst); err != nil {
		log.Printf("Failed to save uploaded file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file securely"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "File uploaded successfully",
		"filename": safeName,
	})
}
