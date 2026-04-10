package api

import (
	"encoding/json"
	"net/http"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// HandleGetOptimalWindow returns the AI-calculated optimal backup window.
func HandleGetOptimalWindow(c *gin.Context) {
	if services.BackupScheduler == nil {
		var (
			mode       string
			windowJSON string
			nextRunRaw string
		)
		_ = db.DB.QueryRow(
			`SELECT
				COALESCE(backup_schedule_mode, 'manual'),
				COALESCE(backup_optimal_window, ''),
				COALESCE(backup_next_run_at, '')
			FROM settings WHERE id = 1`,
		).Scan(&mode, &windowJSON, &nextRunRaw)

		payload := gin.H{
			"mode":    mode,
			"running": false,
		}
		if windowJSON != "" {
			var window services.BackupWindow
			if err := json.Unmarshal([]byte(windowJSON), &window); err == nil {
				payload["optimal_window"] = &window
			}
		}
		if nextRunRaw != "" {
			payload["next_backup_at"] = nextRunRaw
		}
		c.JSON(http.StatusOK, payload)
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
		BadRequest(c, err.Error())
		return
	}

	if req.Mode != "manual" && req.Mode != "smart" {
		BadRequest(c, "Mode must be 'manual' or 'smart'")
		return
	}

	_, err := db.DB.Exec("UPDATE settings SET backup_schedule_mode = ? WHERE id = 1", req.Mode)
	if err != nil {
		InternalError(c, "Failed to update schedule mode: " + err.Error())
		return
	}

	if services.BackupScheduler != nil {
		services.BackupScheduler.SetMode(req.Mode)
		if req.Mode == "smart" {
			services.BackupScheduler.TriggerRecalculation()
		}
	}

	payload := gin.H{
		"message": "Backup schedule mode updated",
		"mode":    req.Mode,
	}
	if services.BackupScheduler != nil {
		for key, value := range services.BackupScheduler.GetScheduleStatus() {
			payload[key] = value
		}
	}

	c.JSON(http.StatusOK, payload)
}
