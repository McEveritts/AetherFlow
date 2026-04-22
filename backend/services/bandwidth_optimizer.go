package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// BandwidthRecommendation holds the AI's bandwidth optimization suggestion.
type BandwidthRecommendation struct {
	RecommendedUploadKBps   int      `json:"recommended_upload_kbps"`
	RecommendedDownloadKBps int      `json:"recommended_download_kbps"`
	Reasoning               string   `json:"reasoning"`
	Confidence              float64  `json:"confidence"`
	SwarmHealth             string   `json:"swarm_health"` // "healthy", "congested", "underutilized"
	Suggestions             []string `json:"suggestions"`
}

// AnalyzeBandwidth gathers system metrics and asks the AI for bandwidth optimization advice.
func AnalyzeBandwidth(apiKey string) (*BandwidthRecommendation, error) {
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
	replyText, err := GenerateWithGemini(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("bandwidth analysis failed: %v", err)
	}

	replyText = CleanJSONResponse(replyText)

	var rec BandwidthRecommendation
	if err := json.Unmarshal([]byte(replyText), &rec); err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %v", err)
	}

	return &rec, nil
}
