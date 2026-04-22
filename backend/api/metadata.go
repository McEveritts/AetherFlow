package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

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
		BadRequest(c, err.Error())
		return
	}

	// Sanitize and validate path
	cleanPath := filepath.Clean(req.Path)
	if strings.Contains(cleanPath, "..") {
		BadRequest(c, "Path traversal not allowed")
		return
	}

	if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
		BadRequest(c, "Directory does not exist")
		return
	}

	if services.Enricher.IsScanning() {
		ConflictError(c, "A scan is already in progress")
		return
	}

	// Get API key (always decrypted)
	ps, err := ResolveProviderSettings()
	if err != nil || ps.GeminiAPIKey == "" {
		InternalError(c, "Gemini API key not configured. Set it in Settings → FlowAI Engine.")
		return
	}

	services.Enricher.StartEnrichment(cleanPath, ps.GeminiAPIKey)

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
		InternalError(c, "Failed to query metadata: " + err.Error())
		return
	}
	if results == nil {
		results = []services.EnrichedMedia{}
	}
	c.JSON(http.StatusOK, results)
}
