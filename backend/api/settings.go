package api

import (
	"log/slog"
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
	OpenaiApiKey     string `json:"openaiApiKey"`
	LmStudioEndpoint string `json:"lmStudioEndpoint"`
	OllamaEndpoint   string `json:"ollamaEndpoint"`
	AnthropicApiKey  string `json:"anthropicApiKey"`
	AnthropicEndpoint string `json:"anthropicEndpoint"`
}

func GetSettings(c *gin.Context) {
	var s SettingsPayload
	err := db.DB.QueryRow(`
		SELECT ai_model, system_prompt, language, timezone, update_channel, default_dashboard, setup_completed, 
		       COALESCE(gemini_api_key, ''), COALESCE(openai_api_key, ''), COALESCE(lm_studio_endpoint, ''), COALESCE(ollama_endpoint, ''),
		       COALESCE(anthropic_api_key, ''), COALESCE(anthropic_endpoint, '')
		FROM settings WHERE id = 1
	`).Scan(&s.AiModel, &s.SystemPrompt, &s.Language, &s.Timezone, &s.UpdateChannel, &s.DefaultDashboard, &s.SetupCompleted, 
		    &s.GeminiApiKey, &s.OpenaiApiKey, &s.LmStudioEndpoint, &s.OllamaEndpoint, &s.AnthropicApiKey, &s.AnthropicEndpoint)

	if err != nil {
		slog.Error("fetching settings", "error", err)
		InternalError(c, "Failed to load settings")
		return
	}

	// Decrypt the API keys before masking
	if s.GeminiApiKey != "" {
		if decrypted, err := DecryptKey(s.GeminiApiKey); err == nil {
			s.GeminiApiKey = decrypted
		}
	}
	if s.OpenaiApiKey != "" {
		if decrypted, err := DecryptKey(s.OpenaiApiKey); err == nil {
			s.OpenaiApiKey = decrypted
		}
	}
	if s.AnthropicApiKey != "" {
		if decrypted, err := DecryptKey(s.AnthropicApiKey); err == nil {
			s.AnthropicApiKey = decrypted
		}
	}

	// Mask the API keys for security - only show last 4 chars
	if len(s.GeminiApiKey) > 4 {
		s.GeminiApiKey = "****" + s.GeminiApiKey[len(s.GeminiApiKey)-4:]
	}
	if len(s.OpenaiApiKey) > 4 {
		s.OpenaiApiKey = "****" + s.OpenaiApiKey[len(s.OpenaiApiKey)-4:]
	}
	if len(s.AnthropicApiKey) > 4 {
		s.AnthropicApiKey = "****" + s.AnthropicApiKey[len(s.AnthropicApiKey)-4:]
	}
	c.JSON(http.StatusOK, s)
}

func updateSettings(c *gin.Context) {
	var req SettingsPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Handle API key encryption individually 
	var err error
	
	geminiKeyStr := ""
	if strings.HasPrefix(req.GeminiApiKey, "****") || req.GeminiApiKey == "" {
		// Don't overwrite existing
		geminiKeyStr = "gemini_api_key" // sql identifier workaround
	} else {
		if encrypted, err := EncryptKey(req.GeminiApiKey); err == nil {
			geminiKeyStr = "'" + strings.ReplaceAll(encrypted, "'", "''") + "'"
		} else {
			geminiKeyStr = "'" + strings.ReplaceAll(req.GeminiApiKey, "'", "''") + "'"
		}
	}

	openaiKeyStr := ""
	if strings.HasPrefix(req.OpenaiApiKey, "****") || req.OpenaiApiKey == "" {
		openaiKeyStr = "openai_api_key"
	} else {
		if encrypted, err := EncryptKey(req.OpenaiApiKey); err == nil {
			openaiKeyStr = "'" + strings.ReplaceAll(encrypted, "'", "''") + "'"
		} else {
			openaiKeyStr = "'" + strings.ReplaceAll(req.OpenaiApiKey, "'", "''") + "'"
		}
	}

	anthropicKeyStr := ""
	if strings.HasPrefix(req.AnthropicApiKey, "****") || req.AnthropicApiKey == "" {
		anthropicKeyStr = "anthropic_api_key"
	} else {
		if encrypted, err := EncryptKey(req.AnthropicApiKey); err == nil {
			anthropicKeyStr = "'" + strings.ReplaceAll(encrypted, "'", "''") + "'"
		} else {
			anthropicKeyStr = "'" + strings.ReplaceAll(req.AnthropicApiKey, "'", "''") + "'"
		}
	}

	// Because of our conditional logic to ignore masked strings, building query dynamically is safer
	_, err = db.DB.Exec(`
		UPDATE settings SET 
			ai_model = ?, 
			system_prompt = ?,
			language = ?,
			timezone = ?,
			update_channel = ?,
			default_dashboard = ?,
			setup_completed = ?,
			gemini_api_key = `+geminiKeyStr+`,
			openai_api_key = `+openaiKeyStr+`,
			anthropic_api_key = `+anthropicKeyStr+`,
			lm_studio_endpoint = ?,
			ollama_endpoint = ?,
			anthropic_endpoint = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = 1
	`, req.AiModel, req.SystemPrompt, req.Language, req.Timezone, req.UpdateChannel, req.DefaultDashboard, req.SetupCompleted, req.LmStudioEndpoint, req.OllamaEndpoint, req.AnthropicEndpoint)


	if err != nil {
		slog.Error("updating settings", "error", err)
		InternalError(c, "Failed to save settings")
		return
	}

	// Return settings without raw API keys
	req.GeminiApiKey = ""
	req.OpenaiApiKey = ""
	req.AnthropicApiKey = ""
	c.JSON(http.StatusOK, gin.H{
		"message": "Settings saved successfully",
		"data":    req,
	})
}
