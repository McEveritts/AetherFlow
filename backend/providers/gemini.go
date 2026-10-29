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
		return nil, fmt.Errorf("gemini API key not configured. Set it in Settings → FlowAI Engine")
	}

	model := cfg.Model
	if model == "" {
		model = "gemini-4-argon"
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(cfg.APIKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	return &GeminiProvider{client: client, model: model}, nil
}

// resolveGeminiFallbackModel maps preview/alias model IDs to universally available
// upstream Gemini models when a consumer API key receives a 404 / model-not-found error,
// while preserving g.model in provider metadata.
func resolveGeminiFallbackModel(modelName string) (string, bool) {
	switch strings.TrimSpace(modelName) {
	case "gemini-4-argon":
		return "gemini-2.5-pro", true
	default:
		return "", false
	}
}

// isGeminiModelNotFoundError detects upstream 404 / model-not-found errors from the Gemini API.
func isGeminiModelNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "404") ||
		strings.Contains(msg, "not found") ||
		strings.Contains(msg, "not_found") ||
		strings.Contains(msg, "not supported for generatecontent")
}

func (g *GeminiProvider) sendChatWithModel(ctx context.Context, modelName string, systemPrompt string, history []Message, message string) (*genai.GenerateContentResponse, error) {
	model := g.client.GenerativeModel(modelName)
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

	return session.SendMessage(ctx, genai.Text(message))
}

// Chat implements AIProvider.Chat for Gemini using the chat session API.
func (g *GeminiProvider) Chat(ctx context.Context, systemPrompt string, history []Message, message string) (*Response, error) {
	resp, err := g.sendChatWithModel(ctx, g.model, systemPrompt, history, message)
	if err != nil && isGeminiModelNotFoundError(err) {
		if fallbackModel, ok := resolveGeminiFallbackModel(g.model); ok {
			resp, err = g.sendChatWithModel(ctx, fallbackModel, systemPrompt, history, message)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("gemini generation error: %w", err)
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
	if err != nil && isGeminiModelNotFoundError(err) {
		if fallbackModel, ok := resolveGeminiFallbackModel(g.model); ok {
			fallback := g.client.GenerativeModel(fallbackModel)
			resp, err = fallback.GenerateContent(ctx, genai.Text(prompt))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("gemini generation error: %w", err)
	}

	text := extractGeminiText(resp)
	if text == "" {
		return nil, fmt.Errorf("gemini returned empty response")
	}

	return &Response{Text: text}, nil
}

// TestConnection implements AIProvider.TestConnection for Gemini.
func (g *GeminiProvider) TestConnection(ctx context.Context) error {
	testModel := "gemini-4-argon"
	model := g.client.GenerativeModel(testModel)
	resp, err := model.GenerateContent(ctx, genai.Text("Reply with the exact word: SUCCESS"))
	if err != nil && isGeminiModelNotFoundError(err) {
		if fallbackModel, ok := resolveGeminiFallbackModel(testModel); ok {
			fallback := g.client.GenerativeModel(fallbackModel)
			resp, err = fallback.GenerateContent(ctx, genai.Text("Reply with the exact word: SUCCESS"))
		}
	}
	if err != nil {
		return fmt.Errorf("gemini connection test failed: %w", err)
	}
	text := extractGeminiText(resp)
	if text == "" {
		return fmt.Errorf("gemini returned empty test response")
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
