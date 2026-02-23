package api

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

type FileInfo struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	ModTime   string `json:"modTime"`
	Extension string `json:"extension"`
}

func getUploadDir() string {
	// Fallback to local testing paths or existing PHP dashboard paths
	paths := []string{
		filepath.Join("..", "dashboard", "fileshare", "uploads"),
		filepath.Join("dashboard", "fileshare", "uploads"),
		filepath.Join(".", "uploads"),
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

func UploadFile(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded or invalid payload"})
		return
	}

	uploadDir := getUploadDir()
	dst := filepath.Join(uploadDir, file.Filename)

	if err := c.SaveUploadedFile(file, dst); err != nil {
		log.Printf("Failed to save uploaded file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file securely"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "File uploaded successfully",
		"filename": file.Filename,
	})
}
