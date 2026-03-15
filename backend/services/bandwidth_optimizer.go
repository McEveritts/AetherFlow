package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// BandwidthRecommendation holds the AI's bandwidth optimization suggestion.
type BandwidthRecommendation struct {
	RecommendedUploadKBps   int     `json:"recommended_upload_kbps"`
	RecommendedDownloadKBps int     `json:"recommended_download_kbps"`
	Reasoning               string  `json:"reasoning"`
	Confidence              float64 `json:"confidence"`
	SwarmHealth             string  `json:"swarm_health"` // "healthy", "congested", "underutilized"
	Suggestions             []string `json:"suggestions"`
}

// AnalyzeBandwidth gathers system metrics and asks Gemini for bandwidth optimization advice.
func AnalyzeBandwidth(apiKey string) (*BandwidthRecommendation, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key required")
	}

	metrics := GetSystemMetricsCore()

	// Build metrics context
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CPU Usage: %.1f%%\n", metrics.CPUUsage))
	if total, ok := metrics.Memory["total"]; ok {
		used, _ := metrics.Memory["used"]
		sb.WriteString(fmt.Sprintf("Memory: %.2f / %.2f GB\n", used, total))
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
	if len(metrics.LoadAverage) >= 3 {
		sb.WriteString(fmt.Sprintf("Load Average: %.2f / %.2f / %.2f\n",
			metrics.LoadAverage[0], metrics.LoadAverage[1], metrics.LoadAverage[2]))
	}

	prompt := fmt.Sprintf(`You are a seedbox bandwidth optimization expert. Analyze the following server metrics and recommend optimal torrent client bandwidth limits.

Current System Metrics:
%s

Based on these metrics, determine:
1. Optimal upload speed limit (in KB/s)
2. Optimal download speed limit (in KB/s)
3. Overall swarm health assessment
4. Specific optimization suggestions

Respond ONLY with valid JSON (no markdown, no explanation):
{"recommended_upload_kbps": 0, "recommended_download_kbps": 0, "reasoning": "...", "confidence": 0.0, "swarm_health": "healthy|congested|underutilized", "suggestions": ["..."]}`, sb.String())

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("Gemini client error: %v", err)
	}
	defer client.Close()

	model := client.GenerativeModel("gemini-2.0-flash")
	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, fmt.Errorf("generation error: %v", err)
	}

	var replyText string
	if resp != nil && len(resp.Candidates) > 0 && resp.Candidates[0].Content != nil {
		for _, part := range resp.Candidates[0].Content.Parts {
			if text, ok := part.(genai.Text); ok {
				replyText += string(text)
			}
		}
	}

	replyText = strings.TrimSpace(replyText)
	replyText = strings.TrimPrefix(replyText, "```json")
	replyText = strings.TrimPrefix(replyText, "```")
	replyText = strings.TrimSuffix(replyText, "```")
	replyText = strings.TrimSpace(replyText)

	var rec BandwidthRecommendation
	if err := json.Unmarshal([]byte(replyText), &rec); err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %v", err)
	}

	return &rec, nil
}

// getAIKey resolves the Gemini API key from DB or environment.
func getAIKey() string {
	var apiKey string
	if db := os.Getenv("GEMINI_API_KEY"); db != "" {
		return db
	}
	log.Printf("Bandwidth optimizer: no API key in env, will check DB at call time")
	_ = apiKey
	return ""
}
