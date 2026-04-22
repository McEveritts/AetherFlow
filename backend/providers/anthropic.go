package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	anthropicDefaultEndpoint = "https://api.anthropic.com"
	anthropicAPIVersion      = "2023-06-01"
	anthropicMaxTokens       = 4096
)

// AnthropicProvider implements AIProvider for the Anthropic Messages API.
type AnthropicProvider struct {
	apiKey   string
	endpoint string
	model    string
	client   *http.Client
}

// anthropicModelMapping translates frontend model IDs to Anthropic API identifiers.
var anthropicModelMapping = map[string]string{
	"claude-opus":       "claude-opus-4-20260401",
	"claude-opus-4.5":   "claude-opus-4-5-20260401",
	"claude-opus-4.6":   "claude-opus-4-6-20260401",
	"claude-sonnet-4.5": "claude-sonnet-4-5-20260401",
	"claude-sonnet-4.6": "claude-sonnet-4-6-20260401",
	"claude-4-6-sonnet": "claude-sonnet-4-6-20260401",
	"claude-4-6-haiku":  "claude-haiku-4-6-20260401",
	"claude-4-5-opus":   "claude-opus-4-5-20260401",
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	Messages  []anthropicMessage `json:"messages"`
	System    string             `json:"system,omitempty"`
	MaxTokens int                `json:"max_tokens"`
}

type anthropicContentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type anthropicResponse struct {
	Content []anthropicContentBlock `json:"content"`
	Error   *anthropicError         `json:"error,omitempty"`
}

type anthropicError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// NewAnthropicProvider creates a provider for the Anthropic Messages API.
func NewAnthropicProvider(cfg ProviderConfig) (*AnthropicProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("Anthropic API key not configured. Set it in Settings → FlowAI Engine")
	}

	endpoint := anthropicDefaultEndpoint
	if cfg.Endpoint != "" {
		endpoint = cfg.Endpoint
	}

	// Map frontend model ID to Anthropic API model
	model := cfg.Model
	if mapped, ok := anthropicModelMapping[model]; ok {
		model = mapped
	}

	return &AnthropicProvider{
		apiKey:   cfg.APIKey,
		endpoint: endpoint,
		model:    model,
		client:   &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// Chat implements AIProvider.Chat via the Anthropic Messages API.
func (a *AnthropicProvider) Chat(ctx context.Context, systemPrompt string, history []Message, message string) (*Response, error) {
	messages := make([]anthropicMessage, 0, len(history)+1)
	for _, hm := range history {
		messages = append(messages, anthropicMessage{Role: hm.Role, Content: hm.Text})
	}
	messages = append(messages, anthropicMessage{Role: "user", Content: message})

	return a.doRequest(ctx, systemPrompt, messages)
}

// Generate implements AIProvider.Generate via a single-message Anthropic call.
func (a *AnthropicProvider) Generate(ctx context.Context, prompt string) (*Response, error) {
	messages := []anthropicMessage{{Role: "user", Content: prompt}}
	return a.doRequest(ctx, "", messages)
}

// TestConnection implements AIProvider.TestConnection.
func (a *AnthropicProvider) TestConnection(ctx context.Context) error {
	_, err := a.Generate(ctx, "Reply with the exact word: SUCCESS")
	return err
}

// Close implements AIProvider.Close (no-op for HTTP clients).
func (a *AnthropicProvider) Close() error {
	return nil
}

func (a *AnthropicProvider) doRequest(ctx context.Context, systemPrompt string, messages []anthropicMessage) (*Response, error) {
	reqBody := anthropicRequest{
		Model:     a.model,
		Messages:  messages,
		System:    systemPrompt,
		MaxTokens: anthropicMaxTokens,
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Anthropic request: %w", err)
	}

	url := a.endpoint + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create Anthropic request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("Anthropic API request failed: %w", err)
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, 2*1024*1024)
	respBytes, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("failed to read Anthropic response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp anthropicResponse
		if json.Unmarshal(respBytes, &errResp) == nil && errResp.Error != nil {
			return nil, fmt.Errorf("Anthropic API error (%d): %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("Anthropic API error: %d %s", resp.StatusCode, string(respBytes))
	}

	var anthropicResp anthropicResponse
	if err := json.Unmarshal(respBytes, &anthropicResp); err != nil {
		return nil, fmt.Errorf("failed to parse Anthropic response: %w", err)
	}

	var text string
	for _, block := range anthropicResp.Content {
		if block.Type == "text" {
			text += block.Text
		}
	}

	if text == "" {
		return nil, fmt.Errorf("Anthropic returned empty response")
	}

	return &Response{Text: text}, nil
}
