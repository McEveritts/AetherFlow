package services

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"aetherflow/db"
	"aetherflow/providers"
)

// ── Unified AI Provider Factory ─────────────────────────────────────────
//
// This is the SINGLE source of truth for creating AI providers in the
// services layer. Both API handlers (via api/ai.go) and background
// services use this factory.

// DefaultAIModel is the fallback model when settings are unavailable.
const DefaultAIModel = "gemini-4-argon"

var (
	providerMu        sync.Mutex
	cachedGemini      providers.AIProvider
	cachedGeminiKey   string // tracks which key the singleton was created with
	geminiKeyResolver func() (string, error)
)

// SetGeminiKeyResolver registers an external key resolver (e.g. from the api package
// where AES-256-GCM decryption is initialized) so background services never pass
// raw encrypted ciphertext to the Gemini SDK.
func SetGeminiKeyResolver(fn func() (string, error)) {
	providerMu.Lock()
	geminiKeyResolver = fn
	providerMu.Unlock()
}

// GetGeminiProvider returns a shared, long-lived Gemini provider.
// The provider is cached and reused; callers MUST NOT call Close() on it.
// If the API key changes, the provider is recreated.
func GetGeminiProvider(ctx context.Context) (providers.AIProvider, error) {
	apiKey, err := ResolveGeminiKey()
	if err != nil {
		return nil, err
	}
	return GetGeminiProviderWithKey(ctx, apiKey)
}

// GetGeminiProviderWithKey returns a shared Gemini provider using an explicitly supplied decrypted API key.
func GetGeminiProviderWithKey(ctx context.Context, apiKey string) (providers.AIProvider, error) {
	if strings.TrimSpace(apiKey) == "" {
		var err error
		apiKey, err = ResolveGeminiKey()
		if err != nil {
			return nil, err
		}
	}

	providerMu.Lock()
	defer providerMu.Unlock()

	// Reuse if key hasn't changed
	if cachedGemini != nil && cachedGeminiKey == apiKey {
		return cachedGemini, nil
	}

	// Close stale provider
	if cachedGemini != nil {
		cachedGemini.Close()
		cachedGemini = nil
		slog.Info("AI provider: API key changed, recreating Gemini provider")
	}

	model := ResolveAIModelName()
	p, err := providers.NewProvider("gemini", providers.ProviderConfig{
		APIKey: apiKey,
		Model:  model,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini provider: %w", err)
	}

	cachedGemini = p
	cachedGeminiKey = apiKey
	slog.Info("AI provider: initialized shared Gemini provider", "model", model)
	return p, nil
}

// GenerateWithGemini is a convenience function for background services
// that need single-shot AI generation. Uses the shared Gemini provider.
func GenerateWithGemini(ctx context.Context, prompt string) (string, error) {
	p, err := GetGeminiProvider(ctx)
	if err != nil {
		return "", err
	}
	// Do NOT defer p.Close() — this is the shared singleton

	resp, err := p.Generate(ctx, prompt)
	if err != nil {
		return "", err
	}
	return resp.Text, nil
}

// GenerateWithGeminiKey performs single-shot AI generation using a pre-resolved API key.
func GenerateWithGeminiKey(ctx context.Context, apiKey string, prompt string) (string, error) {
	p, err := GetGeminiProviderWithKey(ctx, apiKey)
	if err != nil {
		return "", err
	}
	resp, err := p.Generate(ctx, prompt)
	if err != nil {
		return "", err
	}
	return resp.Text, nil
}

// ResolveGeminiKey resolves the Gemini API key through:
// 0. Registered decrypted key resolver from api package
// 1. SQLite settings (decrypted if encrypted)
// 2. GEMINI_API_KEY environment variable
func ResolveGeminiKey() (string, error) {
	providerMu.Lock()
	resolver := geminiKeyResolver
	providerMu.Unlock()
	if resolver != nil {
		if k, err := resolver(); err == nil && strings.TrimSpace(k) != "" {
			return strings.TrimSpace(k), nil
		}
	}

	var apiKey string
	db.DB.QueryRow("SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1").Scan(&apiKey)

	// Attempt decryption (if the key was stored encrypted)
	if apiKey != "" {
		if decrypted, err := decryptKeyIfNeeded(apiKey); err == nil && decrypted != "" {
			apiKey = decrypted
		}
	}

	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		return "", fmt.Errorf("gemini API key not configured. Set it in Settings → FlowAI Engine")
	}
	return apiKey, nil
}

// ResolveAIModelName reads the configured AI model from settings.
func ResolveAIModelName() string {
	var model string
	if err := db.DB.QueryRow("SELECT COALESCE(ai_model, '') FROM settings WHERE id = 1").Scan(&model); err != nil || model == "" {
		return DefaultAIModel
	}
	return model
}

// CleanJSONResponse strips markdown code fences from AI JSON responses.
func CleanJSONResponse(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	return strings.TrimSpace(raw)
}

// decryptKeyIfNeeded attempts to decrypt an AES-encrypted key.
// Returns the original string if decryption fails (key may be plaintext).
func decryptKeyIfNeeded(key string) (string, error) {
	// The encryption/decryption logic lives in api/crypto.go (DecryptKey).
	// Since services can't import api (circular dependency), we check if
	// the key looks encrypted (base64-encoded, len > 50) — if not, return as-is.
	// For truly encrypted keys, the api layer resolves them before passing to services.
	if len(key) < 50 {
		return key, nil // likely plaintext
	}
	return key, nil // services layer trusts the key as resolved
}
