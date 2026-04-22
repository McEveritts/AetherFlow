package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"aetherflow/db"
	"aetherflow/providers"

	"github.com/gin-gonic/gin"
)

type ChatMessage struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

// allowedAIModels is the set of valid model identifiers across all providers.
var allowedAIModels = map[string]bool{
	// Gemini (current frontier)
	"gemini-3.1-pro-preview":          true,
	"gemini-3-flash-preview":          true,
	"gemini-3.1-flash-lite-preview":   true,
	"gemini-3-pro-image-preview":      true,
	"gemini-3.1-flash-image-preview":  true,
	// Gemini (stable)
	"gemini-2.5-pro":        true,
	"gemini-2.5-flash":      true,
	"gemini-2.0-flash":      true,
	"gemini-2.0-flash-lite": true,
	"gemini-1.5-pro":        true,
	"gemini-1.5-flash":      true,
	// OpenAI
	"gpt-4o":       true,
	"gpt-4o-mini":  true,
	"gpt-4-turbo":  true,
	"gpt-5.4":      true,
	"gpt-5.4-mini": true,
	// Anthropic
	"claude-opus":         true,
	"claude-opus-4.5":     true,
	"claude-opus-4.6":     true,
	"claude-sonnet-4.5":   true,
	"claude-sonnet-4.6":   true,
	"claude-4-6-sonnet":   true,
	"claude-4-6-haiku":    true,
	"claude-4-5-opus":     true,
	// Local AI (OpenAI-compatible endpoints)
	"lm-studio":       true,
	"ollama":           true,
	"anthropic-local":  true,
}

type ChatRequest struct {
	Message  string        `json:"message" binding:"required"`
	History  []ChatMessage `json:"history"`
	Model    string        `json:"model"`
	Provider string        `json:"provider"` // "gemini", "openai", "anthropic", "localai"
}

// SupportChatRequest extends ChatRequest with context mode for support-aware chat.
type SupportChatRequest struct {
	ChatRequest
	ContextMode string `json:"context_mode"` // "logs", "metrics", "full"
}

type ChatResponse struct {
	Reply          string          `json:"reply"`
	ProposedAction *ProposedAction `json:"proposed_action,omitempty"`
}

// ProposedAction is an AI-generated action proposal that requires operator approval.
// When present, the action has already been queued in pending_actions.
type ProposedAction struct {
	Type        string `json:"type"`         // always "system_action"
	ActionID    int    `json:"action_id"`    // ID in pending_actions table
	Title       string `json:"title"`        // human-readable title
	Description string `json:"description"` // what the action will do
	DangerLevel string `json:"danger_level"` // "info", "warning", "critical"
	Impact      string `json:"impact"`       // blast radius description
}

// allowedContextModes is the set of valid support context modes.
var allowedContextModes = map[string]bool{
	"logs":    true,
	"metrics": true,
	"full":    true,
}

// runChatSession is the shared helper that routes a chat request to the correct
// AI provider based on the model prefix or explicit provider field.
func runChatSession(c *gin.Context, systemPrompt string, modelOverride string, providerHint string, history []ChatMessage, message string) {
	ctx := context.Background()

	// 1. Resolve all provider settings (decrypted keys, endpoints)
	ps, err := ResolveProviderSettings()
	if err != nil {
		InternalError(c, err.Error())
		return
	}

	// 2. Determine model and provider
	aiModel := modelOverride
	if aiModel == "" {
		aiModel = ps.DefaultModel
	}
	if !allowedAIModels[aiModel] {
		BadRequest(c, "Invalid AI model. Check settings for available models.")
		return
	}

	providerType := ResolveProvider(providerHint, aiModel)

	// 3. Build provider config with decrypted credentials
	cfg := buildProviderConfig(ps, providerType, aiModel)

	// Use system prompt from settings if none provided
	prompt := systemPrompt
	if prompt == "" {
		prompt = ps.SystemPrompt
	}

	// 4. Create provider and execute chat
	provider, err := providers.NewProvider(providerType, cfg)
	if err != nil {
		InternalError(c, fmt.Sprintf("AI provider initialization failed: %v", err))
		return
	}
	defer provider.Close()

	// Convert history to provider format
	providerHistory := make([]providers.Message, len(history))
	for i, hm := range history {
		providerHistory[i] = providers.Message{Role: hm.Role, Text: hm.Text}
	}

	resp, err := provider.Chat(ctx, prompt, providerHistory, message)
	if err != nil {
		InternalError(c, fmt.Sprintf("Generation error: %v", err))
		return
	}

	replyText := resp.Text
	if replyText == "" {
		replyText = "I received an empty response. Please try again."
	}

	// Check if the AI response contains an actionable proposal
	proposal := extractProposedAction(replyText, message)

	if proposal != nil {
		// Queue the proposed action through the approval gate
		actionID, needsApproval := db.QueueAction(
			proposal.DangerLevel, // classification
			"FlowAI",             // source
			proposal.Title,       // action
			proposal.Description, // reason
		)
		if needsApproval {
			proposal.ActionID = int(actionID)
			// Phase 14: Broadcast to all connected clients for real-time inbox updates
			BroadcastActionQueued(int64(actionID), proposal.DangerLevel, "FlowAI", proposal.Title)
			// Phase 20: Record AI proposal in audit trail
			db.RecordAudit(
				resolveActorID(c),
				resolveActorEmail(c),
				"ai_action_proposed",
				"pending_action",
				fmt.Sprintf("%d", actionID),
				fmt.Sprintf("classification=%s title=%s", proposal.DangerLevel, proposal.Title),
				c.ClientIP(),
				c.Request.UserAgent(),
			)
			c.JSON(http.StatusOK, ChatResponse{
				Reply:          replyText,
				ProposedAction: proposal,
			})
			return
		}
	}

	c.JSON(http.StatusOK, ChatResponse{Reply: replyText})
}

// buildProviderConfig constructs a ProviderConfig from resolved settings.
func buildProviderConfig(ps *ProviderSettings, providerType string, model string) providers.ProviderConfig {
	switch providerType {
	case "openai":
		return providers.ProviderConfig{APIKey: ps.OpenAIAPIKey, Model: model}
	case "anthropic":
		return providers.ProviderConfig{APIKey: ps.AnthropicAPIKey, Endpoint: ps.AnthropicEndpoint, Model: model}
	case "localai":
		endpoint := ps.LMStudioEndpoint
		switch model {
		case "ollama":
			endpoint = ps.OllamaEndpoint
			if endpoint == "" {
				endpoint = "http://localhost:11434"
			}
		case "anthropic-local":
			endpoint = ps.AnthropicEndpoint
			if endpoint == "" {
				endpoint = "http://localhost:8080"
			}
		default: // lm-studio
			if endpoint == "" {
				endpoint = "http://localhost:1234"
			}
		}
		return providers.ProviderConfig{Endpoint: endpoint, Model: model}
	default: // gemini
		return providers.ProviderConfig{APIKey: ps.GeminiAPIKey, Model: model}
	}
}

func handleAiChat(c *gin.Context) {
	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	runChatSession(c, "", req.Model, req.Provider, req.History, req.Message)
}

// handleAiSupport handles the AI support chatbot endpoint.
// It auto-injects recent system logs and/or metrics into the AI prompt context
// to help users troubleshoot seedbox errors.
func handleAiSupport(c *gin.Context) {
	var req SupportChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Default to full context if not specified
	if req.ContextMode == "" {
		req.ContextMode = "full"
	}
	if !allowedContextModes[req.ContextMode] {
		BadRequest(c, "Invalid context_mode. Allowed: logs, metrics, full")
		return
	}

	// Strictly verify admin role before allowing access to system logs or metrics context!
	role, exists := c.Get("user_role")
	if !exists || role != "admin" {
		Forbidden(c, "Forbidden: Admin access required for AI support diagnostics")
		return
	}

	// Build context-enriched system prompt using provider settings
	ps, err := ResolveProviderSettings()
	if err != nil {
		InternalError(c, err.Error())
		return
	}

	var contextBlock strings.Builder
	contextBlock.WriteString(ps.SystemPrompt)
	contextBlock.WriteString("\n\nYou are in SUPPORT MODE. The user is troubleshooting a server issue. ")
	contextBlock.WriteString("Use the following live system data to help diagnose problems:\n\n")

	switch req.ContextMode {
	case "logs":
		contextBlock.WriteString(getRecentLogContext(50))
	case "metrics":
		contextBlock.WriteString(getSystemMetricsContext())
	case "full":
		contextBlock.WriteString(getRecentLogContext(30))
		contextBlock.WriteString("\n")
		contextBlock.WriteString(getSystemMetricsContext())
	}

	contextBlock.WriteString("\nAnalyze the above data in context of the user's question. ")
	contextBlock.WriteString("Provide specific, actionable troubleshooting steps. Reference specific log entries or metrics when relevant.")

	runChatSession(c, contextBlock.String(), req.Model, req.Provider, req.History, req.Message)
}

func TestAiConnection(c *gin.Context) {
	var req struct {
		GeminiKey    string `json:"gemini_api_key"`
		OpenAIKey    string `json:"openai_api_key"`
		AnthropicKey string `json:"anthropic_api_key"`
		Provider     string `json:"provider"`
		Endpoint     string `json:"endpoint"`
	}

	c.ShouldBindJSON(&req)

	// Determine which provider to test
	providerType := req.Provider
	if providerType == "" {
		providerType = "gemini"
	}

	// Resolve stored credentials as baseline
	ps, err := ResolveProviderSettings()
	if err != nil {
		InternalError(c, err.Error())
		return
	}

	// Override keys if fresh (unsaved) ones were provided for testing
	if req.GeminiKey != "" && !strings.HasPrefix(req.GeminiKey, "****") {
		ps.GeminiAPIKey = req.GeminiKey
	}
	if req.OpenAIKey != "" && !strings.HasPrefix(req.OpenAIKey, "****") {
		ps.OpenAIAPIKey = req.OpenAIKey
	}
	if req.AnthropicKey != "" && !strings.HasPrefix(req.AnthropicKey, "****") {
		ps.AnthropicAPIKey = req.AnthropicKey
	}
	if req.Endpoint != "" {
		// Override the relevant endpoint for localai testing
		ps.LMStudioEndpoint = req.Endpoint
		ps.OllamaEndpoint = req.Endpoint
	}

	// Select an appropriate test model per provider
	testModel := "gemini-2.0-flash"
	switch providerType {
	case "openai":
		testModel = "gpt-4o"
	case "anthropic":
		testModel = "claude-sonnet-4.5"
	case "localai":
		testModel = "local-test"
	}

	cfg := buildProviderConfig(ps, providerType, testModel)

	ctx := context.Background()
	provider, err := providers.NewProvider(providerType, cfg)
	if err != nil {
		BadRequest(c, fmt.Sprintf("Provider initialization failed: %v", err))
		return
	}
	defer provider.Close()

	if err := provider.TestConnection(ctx); err != nil {
		Unauthorized(c, fmt.Sprintf("Connection test failed: %v", err))
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("%s connection successful", providerType),
	})
}

// ── Phase 18: AI → Action Gate Bridge ───────────────────────────────────

// actionKeywords maps destructive operation keywords to their classification
// and human-readable descriptions. The AI's reply is scanned for these patterns
// to decide whether to create a proposed action for operator approval.
var actionKeywords = []struct {
	Keywords      []string
	Classification string
	TitleTemplate string
	Impact        string
}{
	{
		Keywords:      []string{"restart", "reboot"},
		Classification: "warn",
		TitleTemplate: "Restart %s",
		Impact:        "Service will be temporarily unavailable during restart (5-30 seconds).",
	},
	{
		Keywords:      []string{"stop", "shutdown"},
		Classification: "warn",
		TitleTemplate: "Stop %s",
		Impact:        "Service will become unavailable until manually started.",
	},
	{
		Keywords:      []string{"delete", "remove", "uninstall", "purge"},
		Classification: "critical",
		TitleTemplate: "Delete %s",
		Impact:        "Data associated with this service may be permanently lost.",
	},
	{
		Keywords:      []string{"update", "upgrade", "patch"},
		Classification: "warn",
		TitleTemplate: "Update %s",
		Impact:        "Service will restart after update. Configuration may change.",
	},
}

// extractProposedAction scans the AI reply and original user message for
// destructive operation keywords. If a match is found, it constructs a
// ProposedAction that will be queued via the action gate system.
func extractProposedAction(aiReply string, userMessage string) *ProposedAction {
	combined := strings.ToLower(aiReply + " " + userMessage)

	for _, spec := range actionKeywords {
		for _, kw := range spec.Keywords {
			if !strings.Contains(combined, kw) {
				continue
			}

			// Try to extract a service target from the user message
			target := extractServiceTarget(userMessage)
			title := fmt.Sprintf(spec.TitleTemplate, target)

			return &ProposedAction{
				Type:        "system_action",
				Title:       title,
				Description: fmt.Sprintf("AI-proposed: %s", title),
				DangerLevel: spec.Classification,
				Impact:      spec.Impact,
			}
		}
	}

	return nil
}

// extractServiceTarget attempts to identify a service name from the user's message.
// Looks for common service names or returns "target service" as fallback.
func extractServiceTarget(message string) string {
	lower := strings.ToLower(message)
	knownServices := []string{
		"nginx", "postgres", "postgresql", "redis",
		"qbittorrent", "sonarr", "radarr", "lidarr", "prowlarr",
		"plex", "jellyfin", "emby", "transmission", "deluge",
		"jackett", "wireguard", "tailscale", "caddy", "traefik",
	}
	for _, svc := range knownServices {
		if strings.Contains(lower, svc) {
			return svc
		}
	}
	return "target service"
}
