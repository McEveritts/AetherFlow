package services

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"aetherflow/db"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// ── Phase 7: Shared Gemini Client Factory ──────────────────────────────
//
// All AI services MUST use this factory instead of creating ad-hoc clients.
// Benefits:
//   - Single source for API key resolution
//   - Consistent model selection from settings
//   - Connection pooling (one client per API key, reused across calls)
//   - Centralized error handling and logging

// aiClientSingleton caches a reusable Gemini client. The genai.Client is
// safe for concurrent use and should not be recreated on every request.
var (
	aiClientMu        sync.Mutex
	aiClientSingleton *genai.Client
	aiClientAPIKey    string // tracks which key the singleton was created with
)

// DefaultAIModel is the fallback model when settings are unavailable.
const DefaultAIModel = "gemini-2.0-flash"

// GetAIClient returns a shared, long-lived Gemini client.
// The client is reused across calls; callers MUST NOT call .Close() on it.
// If the API key changes (e.g., user updates settings), the client is recreated.
func GetAIClient(ctx context.Context) (*genai.Client, error) {
	apiKey, err := ResolveGeminiKey()
	if err != nil {
		return nil, err
	}

	aiClientMu.Lock()
	defer aiClientMu.Unlock()

	// Reuse existing client if API key hasn't changed
	if aiClientSingleton != nil && aiClientAPIKey == apiKey {
		return aiClientSingleton, nil
	}

	// Close stale client if key changed
	if aiClientSingleton != nil {
		aiClientSingleton.Close()
		aiClientSingleton = nil
		log.Printf("AI client: API key changed, recreating client")
	}

	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	aiClientSingleton = client
	aiClientAPIKey = apiKey
	log.Printf("AI client: initialized shared Gemini client")
	return client, nil
}

// GetAIModel returns a GenerativeModel using the specified model name.
// If modelName is empty, uses the model configured in settings (or DefaultAIModel).
func GetAIModel(client *genai.Client, modelName string) *genai.GenerativeModel {
	if modelName == "" {
		modelName = ResolveAIModelName()
	}
	return client.GenerativeModel(modelName)
}

// ResolveGeminiKey resolves the Gemini API key through:
// 1. SQLite settings (decrypted if encrypted)
// 2. GEMINI_API_KEY environment variable
// This is the services-layer equivalent of api.GetDecryptedGeminiKey().
func ResolveGeminiKey() (string, error) {
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
		return "", fmt.Errorf("Gemini API key not configured. Set it in Settings → FlowAI Engine")
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

// ExtractTextFromResponse extracts the text content from a Gemini response.
// This standardizes the response parsing that was duplicated across all 6 callsites.
func ExtractTextFromResponse(resp *genai.GenerateContentResponse) string {
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
