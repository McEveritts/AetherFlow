package api

import (
	"net/http"
	"strconv"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// HandleGetPredictions returns the latest prediction report (or runs one on demand).
func HandleGetPredictions(c *gin.Context) {
	apiKey, err := GetDecryptedGeminiKey()
	if err != nil {
		InternalError(c, err.Error())
		return
	}

	report, err := services.AnalyzeResourceTrends(apiKey)
	if err != nil {
		InternalError(c, "Prediction analysis failed: " + err.Error())
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
	daysStr := c.Query("days")
	days := 90 // Default to 90 for long term data visualization
	if daysStr != "" {
		if parsed, err := strconv.Atoi(daysStr); err == nil && parsed > 0 {
			days = parsed
		}
	}

	snapshots, err := services.GetMetricsHistory(days)
	if err != nil {
		InternalError(c, "Failed to query metrics history: " + err.Error())
		return
	}
	if snapshots == nil {
		snapshots = []services.MetricsSnapshot{}
	}
	c.JSON(http.StatusOK, snapshots)
}
