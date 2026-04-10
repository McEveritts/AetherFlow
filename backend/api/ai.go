package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

type ChatMessage struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

// allowedAIModels is the set of valid Gemini model identifiers.
var allowedAIModels = map[string]bool{
	"gemini-2.0-flash":      true,
	"gemini-2.0-flash-lite": true,
	"gemini-2.5-pro":        true,
	"gemini-2.5-flash":      true,
	"gemini-1.5-pro":        true,
	"gemini-1.5-flash":      true,
}

type ChatRequest struct {
	Message string        `json:"message" binding:"required"`
	History []ChatMessage `json:"history"`
	Model   string        `json:"model"`
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

// runChatSession is a shared helper that executes a Gemini chat session with the given
// system prompt, model override, history, and message. Used by both handleAiChat and handleAiSupport.
func runChatSession(c *gin.Context, systemPrompt string, modelOverride string, history []ChatMessage, message string) {
	ctx := context.Background()
	bundle, err := getGeminiBundle(ctx)
	if err != nil {
		InternalError(c, err.Error())
		return
	}
	defer bundle.Client.Close()

	aiModel := bundle.DefaultModel
	if modelOverride != "" {
		if !allowedAIModels[modelOverride] {
			BadRequest(c, "Invalid AI model. Check settings for available models.")
			return
		}
		aiModel = modelOverride
	}

	// Use provided system prompt, or fall back to bundle default
	prompt := systemPrompt
	if prompt == "" {
		prompt = bundle.SystemPrompt
	}

	model := bundle.Client.GenerativeModel(aiModel)
	model.SystemInstruction = genai.NewUserContent(genai.Text(prompt))

	session := model.StartChat()

	// Pre-load history
	for _, hm := range history {
		if hm.Role == "user" {
			session.History = append(session.History, &genai.Content{
				Parts: []genai.Part{genai.Text(hm.Text)},
				Role:  "user",
			})
		} else if hm.Role == "assistant" {
			session.History = append(session.History, &genai.Content{
				Parts: []genai.Part{genai.Text(hm.Text)},
				Role:  "model",
			})
		}
	}

	resp, err := session.SendMessage(ctx, genai.Text(message))
	if err != nil {
		InternalError(c, fmt.Sprintf("Generation error: %v", err))
		return
	}

	var replyText string
	if resp != nil && len(resp.Candidates) > 0 && resp.Candidates[0].Content != nil {
		for _, part := range resp.Candidates[0].Content.Parts {
			if text, ok := part.(genai.Text); ok {
				replyText += string(text)
			}
		}
	}
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
			c.JSON(http.StatusOK, ChatResponse{
				Reply:          replyText,
				ProposedAction: proposal,
			})
			return
		}
	}

	c.JSON(http.StatusOK, ChatResponse{Reply: replyText})
}

func handleAiChat(c *gin.Context) {
	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	runChatSession(c, "", req.Model, req.History, req.Message)
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

	// Build context-enriched system prompt
	ctx := context.Background()
	bundle, err := getGeminiBundle(ctx)
	if err != nil {
		InternalError(c, err.Error())
		return
	}
	bundle.Client.Close() // We only needed settings; runChatSession creates its own client

	var contextBlock strings.Builder
	contextBlock.WriteString(bundle.SystemPrompt)
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

	runChatSession(c, contextBlock.String(), req.Model, req.History, req.Message)
}

func TestAiConnection(c *gin.Context) {
	var req struct {
		ApiKey string `json:"gemini_api_key"`
	}

	c.ShouldBindJSON(&req)

	// If key is masked or empty, read the real key from the database
	keyToTest := req.ApiKey
	if keyToTest == "" || strings.HasPrefix(keyToTest, "****") {
		var savedKey string
		err := db.DB.QueryRow("SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1").Scan(&savedKey)
		if err != nil || savedKey == "" {
			BadRequest(c, "No API key saved. Please enter and save a key first.")
			return
		}
		// Decrypt if stored encrypted
		if decrypted, decErr := DecryptKey(savedKey); decErr == nil {
			savedKey = decrypted
		}
		keyToTest = savedKey
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(keyToTest))
	if err != nil {
		InternalError(c, fmt.Sprintf("Initialization error: %v", err))
		return
	}
	defer client.Close()

	model := client.GenerativeModel("gemini-2.0-flash")
	resp, err := model.GenerateContent(ctx, genai.Text("Reply with the exact word: SUCCESS"))
	if err != nil {
		Unauthorized(c, "API Key is invalid or quota exceeded")
		return
	}

	if resp != nil && len(resp.Candidates) > 0 && resp.Candidates[0].Content != nil {
		for _, part := range resp.Candidates[0].Content.Parts {
			if _, ok := part.(genai.Text); ok {
				c.JSON(http.StatusOK, gin.H{"message": "Connection successful"})
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Connection successful but unrecognized response"})
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
		"nginx", "docker", "postgres", "postgresql", "redis",
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
