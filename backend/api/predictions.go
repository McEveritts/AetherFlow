package api

import (
	"net/http"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// HandleGetPredictions returns the latest prediction report (or runs one on demand).
func HandleGetPredictions(c *gin.Context) {
	apiKey, err := GetDecryptedGeminiKey()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	report, err := services.AnalyzeResourceTrends(apiKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Prediction analysis failed: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}

// HandleAnalyzePredictions triggers a fresh prediction analysis.
func HandleAnalyzePredictions(c *gin.Context) {
	HandleGetPredictions(c) // Same logic, POST triggers fresh analysis
}

// HandleGetMetricsHistory returns raw metrics history data.
func HandleGetMetricsHistory(c *gin.Context) {
	snapshots, err := services.GetMetricsHistory(30)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query metrics history: " + err.Error()})
		return
	}
	if snapshots == nil {
		snapshots = []services.MetricsSnapshot{}
	}
	c.JSON(http.StatusOK, snapshots)
}
