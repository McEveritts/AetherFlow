package api

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// GeminiClientBundle holds an initialized Gemini client and model settings.
type GeminiClientBundle struct {
	Client       *genai.Client
	APIKey       string
	DefaultModel string
	SystemPrompt string
}

// getGeminiBundle resolves the API key, default model, and system prompt,
// then creates a ready-to-use Gemini client. Caller must defer bundle.Client.Close().
func getGeminiBundle(ctx context.Context) (*GeminiClientBundle, error) {
	// Resolve API key: DB first, then env
	apiKey := ""
	db.DB.QueryRow("SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1").Scan(&apiKey)
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("Gemini API key not configured. Set it in Settings → FlowAI Engine.")
	}

	// Resolve default model and system prompt
	var aiModel, systemPrompt string
	err := db.DB.QueryRow("SELECT ai_model, system_prompt FROM settings WHERE id = 1").Scan(&aiModel, &systemPrompt)
	if err != nil {
		aiModel = "gemini-2.5-pro"
		systemPrompt = "You are FlowAI, a helpful server assistant."
		log.Printf("Warning: Using fallback AI settings. DB Error: %v", err)
	}

	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Gemini client: %v", err)
	}

	return &GeminiClientBundle{
		Client:       client,
		APIKey:       apiKey,
		DefaultModel: aiModel,
		SystemPrompt: systemPrompt,
	}, nil
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
		used, _ := metrics.Memory["used"]
		sb.WriteString(fmt.Sprintf("Memory: %.2f / %.2f GB (%.1f%%)\n", used, total, (used/total)*100))
	}

	if swapTotal, ok := metrics.Swap["total"]; ok && swapTotal > 0 {
		swapUsed, _ := metrics.Swap["used"]
		sb.WriteString(fmt.Sprintf("Swap: %.2f / %.2f GB\n", swapUsed, swapTotal))
	}

	for _, disk := range metrics.Disks {
		sb.WriteString(fmt.Sprintf("Disk %s (%s): %.1f / %.1f GB (%.1f%% used)\n",
			disk.MountPoint, disk.Device, disk.UsedGB, disk.TotalGB, disk.UsedPct))
	}

	if readBPS, ok := metrics.DiskIO["read_bytes_sec"]; ok {
		writeBPS, _ := metrics.DiskIO["write_bytes_sec"]
		sb.WriteString(fmt.Sprintf("Disk I/O: Read %.0f B/s, Write %.0f B/s\n", readBPS, writeBPS))
	}

	if down, ok := metrics.Network["down"]; ok {
		up, _ := metrics.Network["up"]
		conns, _ := metrics.Network["active_connections"]
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
