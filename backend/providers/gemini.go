package providers

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// GeminiProvider wraps the Google generative-ai-go SDK.
type GeminiProvider struct {
	client *genai.Client
	model  string
}

// NewGeminiProvider creates a Gemini provider with the given config.
// The caller is responsible for calling Close() when done.
func NewGeminiProvider(cfg ProviderConfig) (*GeminiProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("Gemini API key not configured. Set it in Settings → FlowAI Engine")
	}

	model := cfg.Model
	if model == "" {
		model = "gemini-2.0-flash"
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(cfg.APIKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	return &GeminiProvider{client: client, model: model}, nil
}

// Chat implements AIProvider.Chat for Gemini using the chat session API.
func (g *GeminiProvider) Chat(ctx context.Context, systemPrompt string, history []Message, message string) (*Response, error) {
	model := g.client.GenerativeModel(g.model)
	if systemPrompt != "" {
		model.SystemInstruction = genai.NewUserContent(genai.Text(systemPrompt))
	}

	session := model.StartChat()

	// Pre-load history
	for _, hm := range history {
		role := hm.Role
		if role == "assistant" {
			role = "model" // Gemini SDK uses "model" instead of "assistant"
		}
		session.History = append(session.History, &genai.Content{
			Parts: []genai.Part{genai.Text(hm.Text)},
			Role:  role,
		})
	}

	resp, err := session.SendMessage(ctx, genai.Text(message))
	if err != nil {
		return nil, fmt.Errorf("Gemini generation error: %w", err)
	}

	text := extractGeminiText(resp)
	if text == "" {
		return &Response{Text: "I received an empty response. Please try again."}, nil
	}

	return &Response{Text: text}, nil
}

// Generate implements AIProvider.Generate for Gemini using a single-shot prompt.
func (g *GeminiProvider) Generate(ctx context.Context, prompt string) (*Response, error) {
	model := g.client.GenerativeModel(g.model)
	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, fmt.Errorf("Gemini generation error: %w", err)
	}

	text := extractGeminiText(resp)
	if text == "" {
		return nil, fmt.Errorf("Gemini returned empty response")
	}

	return &Response{Text: text}, nil
}

// TestConnection implements AIProvider.TestConnection for Gemini.
func (g *GeminiProvider) TestConnection(ctx context.Context) error {
	model := g.client.GenerativeModel("gemini-2.0-flash")
	resp, err := model.GenerateContent(ctx, genai.Text("Reply with the exact word: SUCCESS"))
	if err != nil {
		return fmt.Errorf("Gemini connection test failed: %w", err)
	}
	text := extractGeminiText(resp)
	if text == "" {
		return fmt.Errorf("Gemini returned empty test response")
	}
	return nil
}

// Close implements AIProvider.Close.
func (g *GeminiProvider) Close() error {
	if g.client != nil {
		return g.client.Close()
	}
	return nil
}

// extractGeminiText extracts text content from a Gemini response.
func extractGeminiText(resp *genai.GenerateContentResponse) string {
	if resp == nil || len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		return ""
	}
	var sb strings.Builder
	for _, part := range resp.Candidates[0].Content.Parts {
		if text, ok := part.(genai.Text); ok {
			sb.WriteString(string(text))
		}
	}
	return sb.String()
}
