// Package providers defines the AIProvider interface and factory for routing
// AI requests to different LLM backends (Gemini, OpenAI, Anthropic, LocalAI).
//
// All provider implementations receive their credentials via ProviderConfig
// at construction time (dependency injection). They never read from the
// database, environment, or global state directly.
package providers

import (
	"context"
	"fmt"
)

// ProviderConfig holds the credentials and endpoint overrides for a provider.
// Constructed by the caller (api or services layer) from decrypted settings.
type ProviderConfig struct {
	APIKey   string // Decrypted API key (Gemini, OpenAI, Anthropic)
	Endpoint string // Custom base URL override (for local AI or proxies)
	Model    string // Model identifier to use (e.g., "gemini-2.0-flash", "gpt-4o")
}

// Message represents a single turn in a chat conversation.
type Message struct {
	Role string // "user" or "assistant"
	Text string
}

// Response holds the result from an AI provider call.
type Response struct {
	Text string
}

// AIProvider is the core abstraction for all AI backends.
// Implementations are stateful (hold a client/config) and created via NewProvider.
type AIProvider interface {
	// Chat sends a multi-turn conversation to the AI model and returns the response.
	Chat(ctx context.Context, systemPrompt string, history []Message, message string) (*Response, error)

	// Generate sends a single prompt (no history/system prompt) and returns the response.
	// Used by background services (bandwidth analysis, predictions, etc).
	Generate(ctx context.Context, prompt string) (*Response, error)

	// TestConnection validates that the provider is reachable with the configured credentials.
	TestConnection(ctx context.Context) error

	// Close releases any resources held by the provider (e.g., gRPC connections).
	Close() error
}

// NewProvider creates an AIProvider for the given provider type.
// providerType must be one of: "gemini", "openai", "anthropic", "localai".
func NewProvider(providerType string, cfg ProviderConfig) (AIProvider, error) {
	switch providerType {
	case "gemini":
		return NewGeminiProvider(cfg)
	case "openai":
		return NewOpenAIProvider(cfg)
	case "anthropic":
		return NewAnthropicProvider(cfg)
	case "localai":
		return NewLocalAIProvider(cfg)
	default:
		return nil, fmt.Errorf("unknown AI provider: %q", providerType)
	}
}
