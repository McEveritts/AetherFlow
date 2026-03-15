package api

import (
	"net/http"
	"os"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// HandleBandwidthAnalyze triggers AI bandwidth analysis.
func HandleBandwidthAnalyze(c *gin.Context) {
	apiKey := ""
	db.DB.QueryRow("SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1").Scan(&apiKey)
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gemini API key not configured"})
		return
	}

	rec, err := services.AnalyzeBandwidth(apiKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Bandwidth analysis failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, rec)
}

// HandleBandwidthApply is a stub that accepts recommended limits.
// Actual torrent client integration is user-configurable.
func HandleBandwidthApply(c *gin.Context) {
	var req struct {
		UploadKBps   int `json:"upload_kbps"`
		DownloadKBps int `json:"download_kbps"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Integrate with transmission/rtorrent APIs when configured
	c.JSON(http.StatusOK, gin.H{
		"message":      "Bandwidth limits noted. Torrent client integration pending configuration.",
		"upload_kbps":  req.UploadKBps,
		"download_kbps": req.DownloadKBps,
	})
}
