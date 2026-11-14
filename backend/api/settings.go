package api

import (
	"log/slog"
	"net/http"
	"strings"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

type SettingsPayload struct {
	AiModel           string `json:"aiModel"`
	SystemPrompt      string `json:"systemPrompt"`
	Language          string `json:"language"`
	Timezone          string `json:"timezone"`
	UpdateChannel     string `json:"updateChannel"`
	DefaultDashboard  string `json:"defaultDashboard"`
	SetupCompleted    bool   `json:"setupCompleted"`
	BaseDomain        string `json:"baseDomain"`
	GeminiApiKey      string `json:"geminiApiKey"`
	OpenaiApiKey      string `json:"openaiApiKey"`
	LmStudioEndpoint  string `json:"lmStudioEndpoint"`
	OllamaEndpoint    string `json:"ollamaEndpoint"`
	AnthropicApiKey   string `json:"anthropicApiKey"`
	AnthropicEndpoint string `json:"anthropicEndpoint"`
}

func GetSettings(c *gin.Context) {
	var s SettingsPayload
	err := db.DB.QueryRow(`
		SELECT ai_model, system_prompt, language, timezone, update_channel, default_dashboard, setup_completed, 
		       COALESCE(gemini_api_key, ''), COALESCE(openai_api_key, ''), COALESCE(lm_studio_endpoint, ''), COALESCE(ollama_endpoint, ''),
		       COALESCE(anthropic_api_key, ''), COALESCE(anthropic_endpoint, ''), COALESCE(base_domain, '')
		FROM settings WHERE id = 1
	`).Scan(&s.AiModel, &s.SystemPrompt, &s.Language, &s.Timezone, &s.UpdateChannel, &s.DefaultDashboard, &s.SetupCompleted, 
		    &s.GeminiApiKey, &s.OpenaiApiKey, &s.LmStudioEndpoint, &s.OllamaEndpoint, &s.AnthropicApiKey, &s.AnthropicEndpoint, &s.BaseDomain)

	if err != nil {
		slog.Error("fetching settings", "error", err)
		InternalError(c, "Failed to load settings")
		return
	}

	if s.BaseDomain == "" {
		s.BaseDomain = services.ResolveBaseDomain()
	} else {
		s.BaseDomain = db.NormalizeBaseDomain(s.BaseDomain)
	}
	if s.UpdateChannel != "nightly" {
		s.UpdateChannel = "stable"
	}

	role, _ := c.Get("user_role")
	if role != "admin" {
		s.GeminiApiKey = ""
		s.OpenaiApiKey = ""
		s.AnthropicApiKey = ""
		s.LmStudioEndpoint = ""
		s.OllamaEndpoint = ""
		s.AnthropicEndpoint = ""
		c.JSON(http.StatusOK, s)
		return
	}

	maskStoredAPIKey := func(raw string) string {
		if raw == "" {
			return ""
		}
		decrypted, err := DecryptKey(raw)
		if err != nil || strings.HasPrefix(decrypted, "enc:v1:") {
			return "****"
		}
		if len(decrypted) > 4 {
			return "****" + decrypted[len(decrypted)-4:]
		}
		return ""
	}
	s.GeminiApiKey = maskStoredAPIKey(s.GeminiApiKey)
	s.OpenaiApiKey = maskStoredAPIKey(s.OpenaiApiKey)
	s.AnthropicApiKey = maskStoredAPIKey(s.AnthropicApiKey)
	c.JSON(http.StatusOK, s)
}

func updateSettings(c *gin.Context) {
	var req SettingsPayload
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	prevBaseDomain := db.GetBaseDomain()
	if rawDomain := strings.TrimSpace(req.BaseDomain); rawDomain != "" {
		normalized := db.NormalizeBaseDomain(rawDomain)
		if normalized == "" || !domainRegex.MatchString(normalized) || len(normalized) > 253 {
			RespondError(c, http.StatusBadRequest, "INVALID_DOMAIN", "Invalid base domain format (e.g., domain.com)")
			return
		}
		req.BaseDomain = normalized
	} else {
		req.BaseDomain = ""
	}
	if req.UpdateChannel != "nightly" {
		req.UpdateChannel = "stable"
	}

	// Fail-closed encryption of third-party API keys using parameterized SQL.
	updateGeminiKey := 0
	geminiEncrypted := ""
	if !strings.HasPrefix(req.GeminiApiKey, "****") && req.GeminiApiKey != "" {
		enc, encErr := EncryptKey(req.GeminiApiKey)
		if encErr != nil {
			slog.Error("failed to encrypt gemini_api_key", "error", encErr)
			InternalError(c, "Failed to encrypt API key")
			return
		}
		updateGeminiKey = 1
		geminiEncrypted = enc
	}

	updateOpenAIKey := 0
	openaiEncrypted := ""
	if !strings.HasPrefix(req.OpenaiApiKey, "****") && req.OpenaiApiKey != "" {
		enc, encErr := EncryptKey(req.OpenaiApiKey)
		if encErr != nil {
			slog.Error("failed to encrypt openai_api_key", "error", encErr)
			InternalError(c, "Failed to encrypt API key")
			return
		}
		updateOpenAIKey = 1
		openaiEncrypted = enc
	}

	updateAnthropicKey := 0
	anthropicEncrypted := ""
	if !strings.HasPrefix(req.AnthropicApiKey, "****") && req.AnthropicApiKey != "" {
		enc, encErr := EncryptKey(req.AnthropicApiKey)
		if encErr != nil {
			slog.Error("failed to encrypt anthropic_api_key", "error", encErr)
			InternalError(c, "Failed to encrypt API key")
			return
		}
		updateAnthropicKey = 1
		anthropicEncrypted = enc
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
			base_domain = ?,
			gemini_api_key = CASE WHEN ? = 1 THEN ? ELSE gemini_api_key END,
			openai_api_key = CASE WHEN ? = 1 THEN ? ELSE openai_api_key END,
			anthropic_api_key = CASE WHEN ? = 1 THEN ? ELSE anthropic_api_key END,
			lm_studio_endpoint = ?,
			ollama_endpoint = ?,
			anthropic_endpoint = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = 1
	`,
		req.AiModel,
		req.SystemPrompt,
		req.Language,
		req.Timezone,
		req.UpdateChannel,
		req.DefaultDashboard,
		req.SetupCompleted,
		req.BaseDomain,
		updateGeminiKey, geminiEncrypted,
		updateOpenAIKey, openaiEncrypted,
		updateAnthropicKey, anthropicEncrypted,
		req.LmStudioEndpoint,
		req.OllamaEndpoint,
		req.AnthropicEndpoint,
	)


	if err != nil {
		slog.Error("updating settings", "error", err)
		InternalError(c, "Failed to save settings")
		return
	}

	db.InvalidateIngressCache()

	if req.BaseDomain != "" {
		services.SyncInstalledAppsBaseDomain(prevBaseDomain, req.BaseDomain)
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
