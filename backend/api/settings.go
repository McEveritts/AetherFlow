package api

import (
	"log"
	"net/http"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

type SettingsPayload struct {
	AiModel         string `json:"aiModel"`
	SystemPrompt    string `json:"systemPrompt"`
	Language        string `json:"language"`
	Timezone        string `json:"timezone"`
	UpdateChannel   string `json:"updateChannel"`
	DefaultDashboard string `json:"defaultDashboard"`
	SetupCompleted  bool   `json:"setupCompleted"`
}

func GetSettings(c *gin.Context) {
	var s SettingsPayload
	err := db.DB.QueryRow(`
		SELECT ai_model, system_prompt, language, timezone, update_channel, default_dashboard, setup_completed
		FROM settings WHERE id = 1
	`).Scan(&s.AiModel, &s.SystemPrompt, &s.Language, &s.Timezone, &s.UpdateChannel, &s.DefaultDashboard, &s.SetupCompleted)

	if err != nil {
		log.Printf("Error fetching settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load settings"})
		return
	}

	c.JSON(http.StatusOK, s)
}

func updateSettings(c *gin.Context) {
	var req SettingsPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err := db.DB.Exec(`
		UPDATE settings SET 
			ai_model = ?, 
			system_prompt = ?,
			language = ?,
			timezone = ?,
			update_channel = ?,
			default_dashboard = ?,
			setup_completed = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = 1
	`, req.AiModel, req.SystemPrompt, req.Language, req.Timezone, req.UpdateChannel, req.DefaultDashboard, req.SetupCompleted)

	if err != nil {
		log.Printf("Error updating settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save settings"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Settings saved successfully",
		"data":    req,
	})
}
