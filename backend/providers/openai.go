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

const openaiDefaultEndpoint = "https://api.openai.com"

// OpenAIProvider implements AIProvider for the OpenAI chat completions API.
// Also used by NewLocalAIProvider for LM Studio and Ollama (OpenAI-compatible).
type OpenAIProvider struct {
	apiKey   string
	endpoint string
	model    string
	client   *http.Client
}

// openaiMessage mirrors the OpenAI chat message format.
type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiRequest struct {
	Model    string          `json:"model"`
	Messages []openaiMessage `json:"messages"`
}

type openaiChoice struct {
	Message openaiMessage `json:"message"`
}

type openaiResponse struct {
	Choices []openaiChoice `json:"choices"`
	Error   *openaiError   `json:"error,omitempty"`
}

type openaiError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
}

// NewOpenAIProvider creates a provider for the OpenAI API.
func NewOpenAIProvider(cfg ProviderConfig) (*OpenAIProvider, error) {
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("OpenAI API key not configured. Set it in Settings → FlowAI Engine")
	}

	endpoint := openaiDefaultEndpoint
	if cfg.Endpoint != "" {
		endpoint = cfg.Endpoint
	}

	return &OpenAIProvider{
		apiKey:   cfg.APIKey,
		endpoint: endpoint,
		model:    cfg.Model,
		client:   &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// NewLocalAIProvider creates a provider for OpenAI-compatible local endpoints
// (LM Studio, Ollama). API key requirement is relaxed.
func NewLocalAIProvider(cfg ProviderConfig) (*OpenAIProvider, error) {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		return nil, fmt.Errorf("Local AI endpoint not configured. Set it in Settings → FlowAI Engine → Local AI Engines")
	}

	return &OpenAIProvider{
		apiKey:   cfg.APIKey, // may be empty for local endpoints
		endpoint: endpoint,
		model:    cfg.Model,
		client:   &http.Client{Timeout: 120 * time.Second},
	}, nil
}

// Chat implements AIProvider.Chat via the /v1/chat/completions endpoint.
func (o *OpenAIProvider) Chat(ctx context.Context, systemPrompt string, history []Message, message string) (*Response, error) {
	messages := make([]openaiMessage, 0, len(history)+2)

	if systemPrompt != "" {
		messages = append(messages, openaiMessage{Role: "system", Content: systemPrompt})
	}
	for _, hm := range history {
		messages = append(messages, openaiMessage{Role: hm.Role, Content: hm.Text})
	}
	messages = append(messages, openaiMessage{Role: "user", Content: message})

	return o.doRequest(ctx, messages)
}

// Generate implements AIProvider.Generate via a single-message chat completion.
func (o *OpenAIProvider) Generate(ctx context.Context, prompt string) (*Response, error) {
	messages := []openaiMessage{{Role: "user", Content: prompt}}
	return o.doRequest(ctx, messages)
}

// TestConnection implements AIProvider.TestConnection.
func (o *OpenAIProvider) TestConnection(ctx context.Context) error {
	_, err := o.Generate(ctx, "Reply with the exact word: SUCCESS")
	return err
}

// Close implements AIProvider.Close (no-op for HTTP clients).
func (o *OpenAIProvider) Close() error {
	return nil
}

func (o *OpenAIProvider) doRequest(ctx context.Context, messages []openaiMessage) (*Response, error) {
	reqBody := openaiRequest{Model: o.model, Messages: messages}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal OpenAI request: %w", err)
	}

	url := o.endpoint + "/v1/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenAI request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)
	}

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("OpenAI API request failed: %w", err)
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, 2*1024*1024)
	respBytes, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenAI response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp openaiResponse
		if json.Unmarshal(respBytes, &errResp) == nil && errResp.Error != nil {
			return nil, fmt.Errorf("OpenAI API error (%d): %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("OpenAI API error: %d %s", resp.StatusCode, string(respBytes))
	}

	var chatResp openaiResponse
	if err := json.Unmarshal(respBytes, &chatResp); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAI response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("OpenAI returned no choices")
	}

	return &Response{Text: chatResp.Choices[0].Message.Content}, nil
}
