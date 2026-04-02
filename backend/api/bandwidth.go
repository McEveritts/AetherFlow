package api

import (
	"net/http"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// HandleBandwidthAnalyze triggers AI bandwidth analysis.
func HandleBandwidthAnalyze(c *gin.Context) {
	apiKey, err := GetDecryptedGeminiKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":        "Not Implemented",
		"message":      "Bandwidth limits noted. Torrent client xmlrpc/rpc integration pending configuration.",
		"upload_kbps":  req.UploadKBps,
		"download_kbps": req.DownloadKBps,
	})
}
