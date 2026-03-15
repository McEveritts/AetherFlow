package api

import (
	"net/http"
	"os"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// HandleGetPredictions returns the latest prediction report (or runs one on demand).
func HandleGetPredictions(c *gin.Context) {
	apiKey := ""
	db.DB.QueryRow("SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1").Scan(&apiKey)
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gemini API key not configured"})
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
