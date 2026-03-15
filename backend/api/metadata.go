package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// MetadataScanRequest is the request body for starting a metadata scan.
type MetadataScanRequest struct {
	Path string `json:"path" binding:"required"`
}

// HandleMetadataScan starts an async metadata enrichment scan.
func HandleMetadataScan(c *gin.Context) {
	var req MetadataScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Sanitize and validate path
	cleanPath := filepath.Clean(req.Path)
	if strings.Contains(cleanPath, "..") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path traversal not allowed"})
		return
	}

	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Directory does not exist"})
		return
	}

	if services.Enricher.IsScanning() {
		c.JSON(http.StatusConflict, gin.H{"error": "A scan is already in progress"})
		return
	}

	// Get API key
	apiKey := ""
	db.DB.QueryRow("SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1").Scan(&apiKey)
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gemini API key not configured"})
		return
	}

	services.Enricher.StartEnrichment(cleanPath, apiKey)

	c.JSON(http.StatusOK, gin.H{
		"message": "Metadata enrichment scan started",
		"path":    cleanPath,
	})
}

// HandleMetadataStatus returns the current scan status.
func HandleMetadataStatus(c *gin.Context) {
	c.JSON(http.StatusOK, services.Enricher.Status())
}

// HandleMetadataResults returns enriched metadata from the database.
func HandleMetadataResults(c *gin.Context) {
	results, err := services.GetStoredMetadata()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query metadata: " + err.Error()})
		return
	}
	if results == nil {
		results = []services.EnrichedMedia{}
	}
	c.JSON(http.StatusOK, results)
}
