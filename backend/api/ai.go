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
	Reply string `json:"reply"`
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer bundle.Client.Close()

	aiModel := bundle.DefaultModel
	if modelOverride != "" {
		if !allowedAIModels[modelOverride] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid AI model. Check settings for available models."})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Generation error: %v", err)})
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

	c.JSON(http.StatusOK, ChatResponse{Reply: replyText})
}

func handleAiChat(c *gin.Context) {
	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Default to full context if not specified
	if req.ContextMode == "" {
		req.ContextMode = "full"
	}
	if !allowedContextModes[req.ContextMode] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid context_mode. Allowed: logs, metrics, full"})
		return
	}

	// Build context-enriched system prompt
	ctx := context.Background()
	bundle, err := getGeminiBundle(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
			c.JSON(http.StatusBadRequest, gin.H{"error": "No API key saved. Please enter and save a key first."})
			return
		}
		keyToTest = savedKey
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(keyToTest))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Initialization error: %v", err)})
		return
	}
	defer client.Close()

	model := client.GenerativeModel("gemini-2.0-flash")
	resp, err := model.GenerateContent(ctx, genai.Text("Reply with the exact word: SUCCESS"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "API Key is invalid or quota exceeded"})
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
