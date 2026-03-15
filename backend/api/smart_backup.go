package api

import (
	"encoding/json"
	"net/http"
	"os"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// HandleGetOptimalWindow returns the AI-calculated optimal backup window.
func HandleGetOptimalWindow(c *gin.Context) {
	if services.BackupScheduler == nil {
		c.JSON(http.StatusOK, gin.H{
			"message":        "Smart backup scheduler not initialized",
			"optimal_window": nil,
		})
		return
	}

	status := services.BackupScheduler.GetScheduleStatus()
	c.JSON(http.StatusOK, status)
}

// HandleSetBackupSchedule toggles the backup schedule mode.
func HandleSetBackupSchedule(c *gin.Context) {
	var req struct {
		Mode string `json:"mode" binding:"required"` // "manual" or "smart"
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Mode != "manual" && req.Mode != "smart" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Mode must be 'manual' or 'smart'"})
		return
	}

	_, err := db.DB.Exec("UPDATE settings SET backup_schedule_mode = ? WHERE id = 1", req.Mode)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update schedule mode: " + err.Error()})
		return
	}

	// If switching to smart mode, trigger an immediate window calculation
	if req.Mode == "smart" {
		apiKey := ""
		db.DB.QueryRow("SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1").Scan(&apiKey)
		if apiKey == "" {
			apiKey = os.Getenv("GEMINI_API_KEY")
		}
		if apiKey != "" {
			go func() {
				window, err := services.FindOptimalBackupWindow(apiKey)
				if err == nil {
					windowJSON, _ := json.Marshal(window)
					db.DB.Exec("UPDATE settings SET backup_optimal_window = ? WHERE id = 1", string(windowJSON))
				}
			}()
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Backup schedule mode updated",
		"mode":    req.Mode,
	})
}
