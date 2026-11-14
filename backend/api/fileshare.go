package api

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// Maximum upload chunk/file size: 50 MiB
	maxUploadSize = 50 * 1024 * 1024
)

type FileInfo struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ModTime   string `json:"modTime"`
	Extension string `json:"extension"`
	IsDir     bool   `json:"isDir"`
}

func getUploadDir() string {
	// Check environment variable first
	if envPath := strings.TrimSpace(os.Getenv("AETHERFLOW_UPLOAD_DIR")); envPath != "" {
		cleanEnvPath := filepath.Clean(envPath)
		if _, err := os.Stat(cleanEnvPath); err == nil { // #nosec G703 -- trusted operator AETHERFLOW_UPLOAD_DIR environment variable
			return cleanEnvPath
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
		slog.Error("failed to create upload directory", "error", err)
	}
	return defaultPath
}

// resolveUploadSubdir safely resolves a relative virtual path (e.g. "/" or "/docs") inside uploadDir.
func resolveUploadSubdir(rawSubPath string) (string, error) {
	baseDir, err := filepath.Abs(getUploadDir())
	if err != nil {
		return "", err
	}
	trimmed := strings.TrimSpace(rawSubPath)
	if trimmed == "" || trimmed == "/" || trimmed == "." {
		return baseDir, nil
	}
	// If the user selected an absolute path matching baseDir via PathSelector, allow it
	if filepath.IsAbs(trimmed) {
		cleanedAbs := filepath.Clean(trimmed)
		rel, relErr := filepath.Rel(baseDir, cleanedAbs)
		if relErr == nil && !strings.HasPrefix(rel, "..") {
			return cleanedAbs, nil
		}
	}
	relSub := strings.TrimLeft(trimmed, "/\\")
	target := filepath.Clean(filepath.Join(baseDir, relSub))
	rel, err := filepath.Rel(baseDir, target)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", &uploadError{"Invalid directory path"}
	}
	return target, nil
}

// openConfinedUploadSubdir opens an os.Root anchored at getUploadDir() and returns
// the clean relative subdirectory inside that root, rejecting path traversal and symlinks.
func openConfinedUploadSubdir(rawSubPath string, createSubdir bool) (*os.Root, string, error) {
	baseDir, err := filepath.Abs(getUploadDir())
	if err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(baseDir, 0750); err != nil {
		return nil, "", err
	}
	baseInfo, err := os.Lstat(baseDir)
	if err != nil || baseInfo.Mode()&os.ModeSymlink != 0 || !baseInfo.IsDir() {
		return nil, "", &uploadError{"Invalid base upload directory"}
	}
	root, err := os.OpenRoot(baseDir)
	if err != nil {
		return nil, "", err
	}

	targetAbs, err := resolveUploadSubdir(rawSubPath)
	if err != nil {
		_ = root.Close()
		return nil, "", err
	}
	relDir, err := filepath.Rel(baseDir, targetAbs)
	if err != nil || strings.HasPrefix(relDir, "..") {
		_ = root.Close()
		return nil, "", &uploadError{"Invalid directory path"}
	}
	relDir = filepath.ToSlash(filepath.Clean(relDir))
	if relDir == "" {
		relDir = "."
	}

	if relDir != "." {
		// Verify no existing path segment along relDir is a symlink.
		parts := strings.Split(relDir, "/")
		accum := ""
		for _, part := range parts {
			if part == "" || part == "." || part == ".." {
				_ = root.Close()
				return nil, "", &uploadError{"Invalid directory path"}
			}
			if accum == "" {
				accum = part
			} else {
				accum = accum + "/" + part
			}
			if linfo, lErr := root.Lstat(accum); lErr == nil {
				if linfo.Mode()&os.ModeSymlink != 0 || !linfo.IsDir() {
					_ = root.Close()
					return nil, "", &uploadError{"Symlink or non-directory component not allowed"}
				}
			}
		}
		if createSubdir {
			if mkErr := root.MkdirAll(relDir, 0750); mkErr != nil {
				_ = root.Close()
				return nil, "", mkErr
			}
		}
	}

	return root, relDir, nil
}

func isBlockedMagicBytes(sniff []byte) (string, bool) {
	if len(sniff) == 0 {
		return "", false
	}
	detectedType := http.DetectContentType(sniff)
	if blockedContentTypes[detectedType] {
		return detectedType, true
	}
	// Explicit binary/script header magic checks (handles short chunks < 512 bytes)
	if bytes.HasPrefix(sniff, []byte{0x7f, 'E', 'L', 'F'}) {
		return "application/x-elf", true
	}
	if bytes.HasPrefix(sniff, []byte{'M', 'Z'}) {
		return "application/x-dosexec", true
	}
	if bytes.HasPrefix(sniff, []byte{'#', '!'}) {
		return "application/x-shellscript", true
	}
	if len(sniff) >= 4 {
		magic := sniff[:4]
		if bytes.Equal(magic, []byte{0xfe, 0xed, 0xfa, 0xce}) ||
			bytes.Equal(magic, []byte{0xfe, 0xed, 0xfa, 0xcf}) ||
			bytes.Equal(magic, []byte{0xce, 0xfa, 0xed, 0xfe}) ||
			bytes.Equal(magic, []byte{0xcf, 0xfa, 0xed, 0xfe}) {
			return "application/x-mach-binary", true
		}
	}
	return "", false
}

func GetFilesList(c *gin.Context) {
	root, relDir, err := openConfinedUploadSubdir(c.Query("path"), true)
	if err != nil {
		BadRequest(c, err.Error())
		return
	}
	defer root.Close()

	files, err := fs.ReadDir(root.FS(), relDir)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, []FileInfo{})
			return
		}
		slog.Error("reading upload directory", "error", err)
		InternalError(c, "Failed to read files directory")
		return
	}

	fileList := make([]FileInfo, 0, len(files))
	for _, f := range files {
		if f.Type()&fs.ModeSymlink != 0 {
			continue
		}
		info, err := f.Info()
		if err != nil {
			continue
		}

		ext := ""
		if !f.IsDir() {
			ext = filepath.Ext(info.Name())
		}

		fileList = append(fileList, FileInfo{
			Name:      info.Name(),
			Size:      info.Size(),
			ModTime:   info.ModTime().Format(time.RFC3339),
			Extension: ext,
			IsDir:     f.IsDir(),
		})
	}

	sort.Slice(fileList, func(i, j int) bool {
		if fileList[i].IsDir != fileList[j].IsDir {
			return fileList[i].IsDir
		}
		return strings.ToLower(fileList[i].Name) < strings.ToLower(fileList[j].Name)
	})

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
	"application/x-executable":                      true,
	"application/x-msdos-program":                   true,
	"application/x-msdownload":                      true,
	"application/x-dosexec":                         true,
	"application/x-sharedlib":                       true,
	"application/x-pie-executable":                  true,
	"application/x-elf":                             true,
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
			RespondError(c, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "File exceeds maximum allowed size of 50 MB")
			return
		}
		BadRequest(c, "No file uploaded or invalid payload")
		return
	}

	// Enforce file size limit at header level too
	if file.Size > maxUploadSize {
		RespondError(c, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE", "File exceeds maximum allowed size of 50 MB")
		return
	}

	// Support explicit filename header from chunked uploads when FormData blob name is "blob"
	rawFilename := file.Filename
	if headerFilename := strings.TrimSpace(c.GetHeader("X-File-Name")); headerFilename != "" && (rawFilename == "" || rawFilename == "blob") {
		rawFilename = headerFilename
	}

	// Sanitize filename (strips nulls, checks all extensions)
	safeName, err := sanitizeFilename(rawFilename)
	if err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Content-type sniffing: read first 512 bytes to detect actual content type
	src, err := file.Open()
	if err != nil {
		InternalError(c, "Failed to read file")
		return
	}
	defer src.Close()

	sniffBuf := make([]byte, 512)
	n, _ := src.Read(sniffBuf)
	if blockedType, blocked := isBlockedMagicBytes(sniffBuf[:n]); blocked {
		BadRequest(c, "File content type not allowed: "+blockedType)
		return
	}

	if _, seekErr := src.Seek(0, io.SeekStart); seekErr != nil {
		InternalError(c, "Failed to reset file stream")
		return
	}

	root, relDir, dirErr := openConfinedUploadSubdir(c.GetHeader("X-Target-Path"), true)
	if dirErr != nil {
		BadRequest(c, dirErr.Error())
		return
	}
	defer root.Close()

	relTarget := safeName
	if relDir != "." {
		relTarget = relDir + "/" + safeName
	}

	if linfo, lErr := root.Lstat(relTarget); lErr == nil {
		if linfo.Mode()&os.ModeSymlink != 0 || linfo.IsDir() {
			BadRequest(c, "Refusing to overwrite symlink or directory")
			return
		}
	}

	chunkIdx, _ := strconv.Atoi(c.GetHeader("X-Chunk-Index"))
	if chunkIdx < 0 {
		BadRequest(c, "Invalid chunk index")
		return
	}
	openFlags := os.O_CREATE | os.O_WRONLY
	if chunkIdx > 0 {
		openFlags |= os.O_APPEND
	} else {
		openFlags |= os.O_TRUNC
	}

	out, openErr := root.OpenFile(relTarget, openFlags, 0640)
	if openErr != nil {
		slog.Error("failed to open target file for upload", "error", openErr)
		InternalError(c, "Failed to save file securely")
		return
	}

	if _, copyErr := io.Copy(out, src); copyErr != nil {
		_ = out.Close()
		slog.Error("failed to write uploaded file chunk", "error", copyErr)
		InternalError(c, "Failed to save file securely")
		return
	}
	if closeErr := out.Close(); closeErr != nil {
		InternalError(c, "Failed to finalize uploaded chunk")
		return
	}

	// Re-validate magic bytes on the assembled file prefix so split-chunk magic headers cannot bypass sniffing.
	if chunkIdx > 0 {
		if verifyFile, vErr := root.Open(relTarget); vErr == nil {
			assembledHead := make([]byte, 512)
			vn, _ := verifyFile.Read(assembledHead)
			_ = verifyFile.Close()
			if blockedType, blocked := isBlockedMagicBytes(assembledHead[:vn]); blocked {
				_ = root.Remove(relTarget)
				BadRequest(c, "File content type not allowed: "+blockedType)
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "File uploaded successfully",
		"filename": safeName,
	})
}

// HandleDownloadFile securely serves a fileshare download from an os.Root-confined descriptor.
func HandleDownloadFile(c *gin.Context) {
	filename := c.Param("filename")

	// Ensure no path traversal and valid naming occurs
	safeName, err := sanitizeFilename(filename)
	if err != nil {
		BadRequest(c, err.Error())
		return
	}

	root, relDir, dirErr := openConfinedUploadSubdir(c.Query("path"), false)
	if dirErr != nil {
		BadRequest(c, dirErr.Error())
		return
	}
	defer root.Close()

	relTarget := safeName
	if relDir != "." {
		relTarget = relDir + "/" + safeName
	}

	linfo, statErr := root.Lstat(relTarget)
	if os.IsNotExist(statErr) {
		NotFoundError(c, "File not found")
		return
	}
	if statErr != nil {
		InternalError(c, "Failed to inspect file")
		return
	}
	if linfo.Mode()&os.ModeSymlink != 0 || linfo.IsDir() {
		BadRequest(c, "Refusing to serve symlink or directory")
		return
	}

	f, openErr := root.Open(relTarget)
	if openErr != nil {
		if os.IsNotExist(openErr) {
			NotFoundError(c, "File not found")
			return
		}
		InternalError(c, "Failed to open file")
		return
	}
	defer f.Close()

	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", safeName))
	http.ServeContent(c.Writer, c.Request, safeName, linfo.ModTime(), f)
}

// DeleteSharedFile deletes a file from the fileshare directory inside os.Root confinement.
func DeleteSharedFile(c *gin.Context) {
	filename := c.Param("filename")
	safeName, err := sanitizeFilename(filename)
	if err != nil {
		BadRequest(c, err.Error())
		return
	}

	root, relDir, dirErr := openConfinedUploadSubdir(c.Query("path"), false)
	if dirErr != nil {
		BadRequest(c, dirErr.Error())
		return
	}
	defer root.Close()

	relTarget := safeName
	if relDir != "." {
		relTarget = relDir + "/" + safeName
	}

	info, statErr := root.Lstat(relTarget)
	if os.IsNotExist(statErr) {
		NotFoundError(c, "File not found")
		return
	}
	if statErr != nil {
		InternalError(c, "Failed to inspect file")
		return
	}
	if info.IsDir() {
		BadRequest(c, "Cannot delete directory via file endpoint")
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		BadRequest(c, "Refusing to delete symlink via file endpoint")
		return
	}

	if rmErr := root.Remove(relTarget); rmErr != nil {
		slog.Error("failed to delete shared file", "name", relTarget, "error", rmErr)
		InternalError(c, "Failed to delete file")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "File deleted",
		"filename": safeName,
	})
}

// DownloadFile preserves the legacy admin handler name while delegating to the canonical auth-safe download path.
func DownloadFile(c *gin.Context) {
	HandleDownloadFile(c)
}
