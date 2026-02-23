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

	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "GEMINI_API_KEY is not configured in .env"})
		return
	}

	// Fetch Settings
	var aiModel, systemPrompt string
	err := db.DB.QueryRow("SELECT ai_model, system_prompt FROM settings WHERE id = 1").Scan(&aiModel, &systemPrompt)
	if err != nil {
		// Fallbacks if db is unreachable
		aiModel = "gemini-2.5-pro"
		systemPrompt = "You are FlowAI, a helpful server assistant."
		log.Printf("Warning: Using fallback AI settings. DB Error: %v", err)
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
