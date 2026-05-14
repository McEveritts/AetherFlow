package api

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"aetherflow/db"
	"aetherflow/services"
)

// ProviderSettings holds all provider configuration from the settings table.
type ProviderSettings struct {
	GeminiAPIKey      string
	OpenAIAPIKey      string
	AnthropicAPIKey   string
	AnthropicEndpoint string
	LMStudioEndpoint  string
	OllamaEndpoint    string
	DefaultModel      string
	SystemPrompt      string
}

// ResolveProviderSettings reads all AI provider settings from the database.
func ResolveProviderSettings() (*ProviderSettings, error) {
	ps := &ProviderSettings{}
	err := db.DB.QueryRow(`
		SELECT
			COALESCE(gemini_api_key, ''),
			COALESCE(openai_api_key, ''),
			COALESCE(anthropic_api_key, ''),
			COALESCE(anthropic_endpoint, ''),
			COALESCE(lm_studio_endpoint, ''),
			COALESCE(ollama_endpoint, ''),
			COALESCE(ai_model, ''),
			COALESCE(system_prompt, '')
		FROM settings WHERE id = 1
	`).Scan(
		&ps.GeminiAPIKey, &ps.OpenAIAPIKey, &ps.AnthropicAPIKey,
		&ps.AnthropicEndpoint, &ps.LMStudioEndpoint, &ps.OllamaEndpoint,
		&ps.DefaultModel, &ps.SystemPrompt,
	)
	if err != nil {
		ps.DefaultModel = "gemini-2.0-flash"
		ps.SystemPrompt = "You are FlowAI, a helpful server assistant."
		slog.Warn("Using fallback AI settings. DB Error", "error", err)
	}

	// Decrypt API keys
	if ps.GeminiAPIKey != "" {
		if decrypted, decErr := DecryptKey(ps.GeminiAPIKey); decErr == nil {
			ps.GeminiAPIKey = decrypted
		}
	}
	if ps.OpenAIAPIKey != "" {
		if decrypted, decErr := DecryptKey(ps.OpenAIAPIKey); decErr == nil {
			ps.OpenAIAPIKey = decrypted
		}
	}
	if ps.AnthropicAPIKey != "" {
		if decrypted, decErr := DecryptKey(ps.AnthropicAPIKey); decErr == nil {
			ps.AnthropicAPIKey = decrypted
		}
	}

	// Fall back to env vars
	if ps.GeminiAPIKey == "" {
		ps.GeminiAPIKey = os.Getenv("GEMINI_API_KEY")
	}
	if ps.OpenAIAPIKey == "" {
		ps.OpenAIAPIKey = os.Getenv("OPENAI_API_KEY")
	}
	if ps.AnthropicAPIKey == "" {
		ps.AnthropicAPIKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if ps.DefaultModel == "" {
		ps.DefaultModel = "gemini-2.0-flash"
	}

	return ps, nil
}

// ResolveProvider determines which provider to use based on the model ID.
func ResolveProvider(provider string, modelID string) string {
	if provider != "" {
		return provider
	}
	// Auto-detect from model ID prefix
	switch {
	case strings.HasPrefix(modelID, "gemini"):
		return "gemini"
	case strings.HasPrefix(modelID, "gpt"):
		return "openai"
	case strings.HasPrefix(modelID, "claude"):
		return "anthropic"
	case modelID == "lm-studio" || modelID == "ollama" || modelID == "anthropic-local":
		return "localai"
	default:
		return "gemini"
	}
}

// getRecentLogContext queries the log aggregator for recent error/warning entries
// and formats them into a text block suitable for AI context injection.
func getRecentLogContext(count int) string {
	if services.Logs == nil {
		return "[Log aggregator not available]"
	}

	entries := services.Logs.Query(services.LogFilter{
		Limit: count,
	})

	if len(entries) == 0 {
		return "[No recent log entries found]"
	}

	var sb strings.Builder
	sb.WriteString("=== RECENT SYSTEM LOGS ===\n")
	for _, entry := range entries {
		sb.WriteString(fmt.Sprintf("[%s] [%s] [%s] %s: %s\n",
			entry.Timestamp.Format("2006-01-02 15:04:05"),
			entry.Priority,
			entry.Source,
			entry.Unit,
			entry.Message,
		))
	}
	sb.WriteString("=== END LOGS ===\n")
	return sb.String()
}

// getSystemMetricsContext formats the current system metrics as a text block
// for injection into AI prompts.
func getSystemMetricsContext() string {
	metrics := services.GetSystemMetricsCore()

	var sb strings.Builder
	sb.WriteString("=== CURRENT SYSTEM METRICS ===\n")
	sb.WriteString(fmt.Sprintf("CPU Usage: %.1f%%\n", metrics.CPUUsage))
	sb.WriteString(fmt.Sprintf("CPU Frequency: %.0f MHz\n", metrics.CPUFreqMhz))

	if total, ok := metrics.Memory["total"]; ok {
		used := metrics.Memory["used"]
		sb.WriteString(fmt.Sprintf("Memory: %.2f / %.2f GB (%.1f%%)\n", used, total, (used/total)*100))
	}

	if swapTotal, ok := metrics.Swap["total"]; ok && swapTotal > 0 {
		swapUsed := metrics.Swap["used"]
		sb.WriteString(fmt.Sprintf("Swap: %.2f / %.2f GB\n", swapUsed, swapTotal))
	}

	for _, disk := range metrics.Disks {
		sb.WriteString(fmt.Sprintf("Disk %s (%s): %.1f / %.1f GB (%.1f%% used)\n",
			disk.MountPoint, disk.Device, disk.UsedGB, disk.TotalGB, disk.UsedPct))
	}

	if readBPS, ok := metrics.DiskIO["read_bytes_sec"]; ok {
		writeBPS := metrics.DiskIO["write_bytes_sec"]
		sb.WriteString(fmt.Sprintf("Disk I/O: Read %.0f B/s, Write %.0f B/s\n", readBPS, writeBPS))
	}

	if down, ok := metrics.Network["down"]; ok {
		up := metrics.Network["up"]
		conns := metrics.Network["active_connections"]
		sb.WriteString(fmt.Sprintf("Network: Down %v, Up %v, Active Connections: %v\n", down, up, conns))
	}

	sb.WriteString(fmt.Sprintf("Uptime: %s\n", metrics.Uptime))
	if len(metrics.LoadAverage) >= 3 {
		sb.WriteString(fmt.Sprintf("Load Average: %.2f / %.2f / %.2f\n",
			metrics.LoadAverage[0], metrics.LoadAverage[1], metrics.LoadAverage[2]))
	}

	if len(metrics.Processes) > 0 {
		sb.WriteString("Top Processes:\n")
		limit := 5
		if len(metrics.Processes) < limit {
			limit = len(metrics.Processes)
		}
		for _, p := range metrics.Processes[:limit] {
			sb.WriteString(fmt.Sprintf("  PID %d: %s (CPU: %.1f%%, Mem: %.1f%%)\n", p.PID, p.Name, p.CPU, p.Mem))
		}
	}

	sb.WriteString("=== END METRICS ===\n")
	return sb.String()
}
