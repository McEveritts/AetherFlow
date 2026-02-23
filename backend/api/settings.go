package api

import (
	"log"
	"net/http"
	"strings"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

type SettingsPayload struct {
	AiModel          string `json:"aiModel"`
	SystemPrompt     string `json:"systemPrompt"`
	Language         string `json:"language"`
	Timezone         string `json:"timezone"`
	UpdateChannel    string `json:"updateChannel"`
	DefaultDashboard string `json:"defaultDashboard"`
	SetupCompleted   bool   `json:"setupCompleted"`
	GeminiApiKey     string `json:"geminiApiKey"`
}

func GetSettings(c *gin.Context) {
	var s SettingsPayload
	err := db.DB.QueryRow(`
		SELECT ai_model, system_prompt, language, timezone, update_channel, default_dashboard, setup_completed, COALESCE(gemini_api_key, '')
		FROM settings WHERE id = 1
	`).Scan(&s.AiModel, &s.SystemPrompt, &s.Language, &s.Timezone, &s.UpdateChannel, &s.DefaultDashboard, &s.SetupCompleted, &s.GeminiApiKey)

	if err != nil {
		log.Printf("Error fetching settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load settings"})
		return
	}

	// Mask the API key for security - only show last 4 chars
	if len(s.GeminiApiKey) > 4 {
		s.GeminiApiKey = "****" + s.GeminiApiKey[len(s.GeminiApiKey)-4:]
	}
	c.JSON(http.StatusOK, s)
}

func updateSettings(c *gin.Context) {
	var req SettingsPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Only update API key if it's not the masked version
	var err error
	if strings.HasPrefix(req.GeminiApiKey, "****") || req.GeminiApiKey == "" {
		// Don't overwrite existing key
		_, err = db.DB.Exec(`
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
	} else {
		_, err = db.DB.Exec(`
			UPDATE settings SET 
				ai_model = ?, 
				system_prompt = ?,
				language = ?,
				timezone = ?,
				update_channel = ?,
				default_dashboard = ?,
				setup_completed = ?,
				gemini_api_key = ?,
				updated_at = CURRENT_TIMESTAMP
			WHERE id = 1
		`, req.AiModel, req.SystemPrompt, req.Language, req.Timezone, req.UpdateChannel, req.DefaultDashboard, req.SetupCompleted, req.GeminiApiKey)
	}

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
