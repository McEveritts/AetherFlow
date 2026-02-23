package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"aetherflow/db"
	"github.com/gin-gonic/gin"
	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

type ChatMessage struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

type ChatRequest struct {
	Message string        `json:"message" binding:"required"`
	History []ChatMessage `json:"history"`
	Model   string        `json:"model"`
}

type ChatResponse struct {
	Reply string `json:"reply"`
}

func handleAiChat(c *gin.Context) {
	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Try to get API key from database settings first, then fall back to env
	apiKey := ""
	db.DB.QueryRow("SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1").Scan(&apiKey)
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gemini API key not configured. Set it in Settings → FlowAI Engine."})
		return
	}

	// Fetch Settings for default model and system prompt
	var aiModel, systemPrompt string
	err := db.DB.QueryRow("SELECT ai_model, system_prompt FROM settings WHERE id = 1").Scan(&aiModel, &systemPrompt)
	if err != nil {
		aiModel = "gemini-2.5-pro"
		systemPrompt = "You are FlowAI, a helpful server assistant."
		log.Printf("Warning: Using fallback AI settings. DB Error: %v", err)
	}

	// Per-request model override from the chat selector
	if req.Model != "" {
		aiModel = req.Model
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to initialize Gemini client: %v", err)})
		return
	}
	defer client.Close()

	model := client.GenerativeModel(aiModel)
	model.SystemInstruction = genai.NewUserContent(genai.Text(systemPrompt))

	session := model.StartChat()

	// Pre-load history
	for _, hm := range req.History {
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

	resp, err := session.SendMessage(ctx, genai.Text(req.Message))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Generation error: %v", err)})
		return
	}

	var replyText string
	for _, part := range resp.Candidates[0].Content.Parts {
		if text, ok := part.(genai.Text); ok {
			replyText += string(text)
		}
	}

	c.JSON(http.StatusOK, ChatResponse{Reply: replyText})
}

func TestAiConnection(c *gin.Context) {
	var req struct {
		ApiKey string `json:"gemini_api_key" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing gemini_api_key in request body"})
		return
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(req.ApiKey))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Initialization error: %v", err)})
		return
	}
	defer client.Close()

	model := client.GenerativeModel("gemini-1.5-flash") // Use simple fast model for ping
	resp, err := model.GenerateContent(ctx, genai.Text("Reply with the exact word: SUCCESS"))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "API Key is invalid or quota exceeded"})
		return
	}

	for _, part := range resp.Candidates[0].Content.Parts {
		if _, ok := part.(genai.Text); ok {
			c.JSON(http.StatusOK, gin.H{"message": "Connection successful"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Connection successful but unrecognized response"})
}
