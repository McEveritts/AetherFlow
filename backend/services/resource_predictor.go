package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// PredictionReport is the AI-generated resource prediction analysis.
type PredictionReport struct {
	TrendSummary        string   `json:"trend_summary"`
	CPUTrend            string   `json:"cpu_trend"` // "stable", "increasing", "decreasing", "critical"
	MemoryTrend         string   `json:"memory_trend"`
	DiskIOTrend         string   `json:"disk_io_trend"`
	NetworkTrend        string   `json:"network_trend"`
	Warnings            []string `json:"warnings"`
	Recommendations     []string `json:"recommendations"`
	PredictedBottleneck string   `json:"predicted_bottleneck"` // "none", "cpu", "memory", "disk", "network"
	ConfidenceScore     float64  `json:"confidence_score"`
}

var (
	predictionCacheMu      sync.Mutex
	cachedPredictionReport *PredictionReport
	cachedPredictionAt     time.Time
)

const predictionCacheTTL = 10 * time.Minute

// AnalyzeResourceTrends queries 30 days of metrics and sends them to Gemini for trend analysis.
func AnalyzeResourceTrends(apiKey string) (*PredictionReport, error) {
	predictionCacheMu.Lock()
	if cachedPredictionReport != nil && time.Since(cachedPredictionAt) < predictionCacheTTL {
		rep := *cachedPredictionReport
		predictionCacheMu.Unlock()
		return &rep, nil
	}
	predictionCacheMu.Unlock()

	snapshots, err := GetMetricsHistory(30)
	if err != nil {
		return nil, fmt.Errorf("failed to query metrics history: %v", err)
	}

	if len(snapshots) == 0 {
		return &PredictionReport{
			TrendSummary:        "Insufficient data. Metrics recording has just started. Check back after 24-48 hours.",
			CPUTrend:            "unknown",
			MemoryTrend:         "unknown",
			DiskIOTrend:         "unknown",
			NetworkTrend:        "unknown",
			Warnings:            []string{"Not enough historical data for trend analysis"},
			Recommendations:     []string{"Allow the metrics recorder to collect at least 24 hours of data"},
			PredictedBottleneck: "none",
			ConfidenceScore:     0.0,
		}, nil
	}

	// Build summary metrics for the AI prompt
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Data points: %d (spanning up to 30 days)\n\n", len(snapshots)))

	// Calculate averages and peaks
	var cpuSum, memSum, diskReadSum, diskWriteSum, loadSum float64
	var cpuMax, memMax, diskReadMax, diskWriteMax, loadMax float64
	for _, s := range snapshots {
		cpuSum += s.CPUAvg
		if s.CPUAvg > cpuMax {
			cpuMax = s.CPUAvg
		}
		memPct := 0.0
		if s.MemTotalGB > 0 {
			memPct = (s.MemUsedGB / s.MemTotalGB) * 100
		}
		memSum += memPct
		if memPct > memMax {
			memMax = memPct
		}
		diskReadSum += s.DiskReadBPS
		if s.DiskReadBPS > diskReadMax {
			diskReadMax = s.DiskReadBPS
		}
		diskWriteSum += s.DiskWriteBPS
		if s.DiskWriteBPS > diskWriteMax {
			diskWriteMax = s.DiskWriteBPS
		}
		loadSum += s.LoadAvg1
		if s.LoadAvg1 > loadMax {
			loadMax = s.LoadAvg1
		}
	}
	n := float64(len(snapshots))
	cpuAvg := cpuSum / n
	memAvg := memSum / n
	loadAvg := loadSum / n
	sb.WriteString(fmt.Sprintf("CPU: avg=%.1f%%, peak=%.1f%%\n", cpuAvg, cpuMax))
	sb.WriteString(fmt.Sprintf("Memory: avg=%.1f%%, peak=%.1f%%\n", memAvg, memMax))
	sb.WriteString(fmt.Sprintf("Disk Read: avg=%.0f B/s, peak=%.0f B/s\n", diskReadSum/n, diskReadMax))
	sb.WriteString(fmt.Sprintf("Disk Write: avg=%.0f B/s, peak=%.0f B/s\n", diskWriteSum/n, diskWriteMax))
	sb.WriteString(fmt.Sprintf("Load Average: avg=%.2f, peak=%.2f\n", loadAvg, loadMax))

	// Include recent 10 snapshots for trend direction
	recentStart := len(snapshots) - 10
	if recentStart < 0 {
		recentStart = 0
	}
	sb.WriteString("\nRecent snapshots (newest):\n")
	for _, s := range snapshots[recentStart:] {
		memPct := 0.0
		if s.MemTotalGB > 0 {
			memPct = (s.MemUsedGB / s.MemTotalGB) * 100
		}
		sb.WriteString(fmt.Sprintf("  [%s] CPU:%.1f%% Mem:%.1f%% Load:%.2f\n", s.Timestamp, s.CPUAvg, memPct, s.LoadAvg1))
	}

	prompt := fmt.Sprintf(`You are a server capacity planning expert. Analyze the following 30-day metrics summary from a seedbox server and predict resource bottlenecks.

%s

Provide your analysis as JSON ONLY (no markdown, no explanation):
{"trend_summary": "...", "cpu_trend": "stable|increasing|decreasing|critical", "memory_trend": "...", "disk_io_trend": "...", "network_trend": "...", "warnings": ["..."], "recommendations": ["..."], "predicted_bottleneck": "none|cpu|memory|disk|network", "confidence_score": 0.0}

Be specific about cgroup limits, upgrade recommendations, and timeframes.`, sb.String())

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	replyText, err := GenerateWithGeminiKey(ctx, apiKey, prompt)
	if err != nil {
		slog.Warn("Resource predictor AI call failed; returning statistical fallback report", "error", err)
		fallback := buildStatisticalPredictionReport(len(snapshots), cpuAvg, cpuMax, memAvg, memMax, loadAvg)
		return fallback, nil
	}

	replyText = CleanJSONResponse(replyText)

	var report PredictionReport
	if err := json.Unmarshal([]byte(replyText), &report); err != nil {
		slog.Info("Resource predictor: raw AI response", "response", replyText)
		fallback := buildStatisticalPredictionReport(len(snapshots), cpuAvg, cpuMax, memAvg, memMax, loadAvg)
		return fallback, nil
	}

	predictionCacheMu.Lock()
	repCopy := report
	cachedPredictionReport = &repCopy
	cachedPredictionAt = time.Now()
	predictionCacheMu.Unlock()

	return &report, nil
}

func buildStatisticalPredictionReport(count int, cpuAvg, cpuMax, memAvg, memMax, loadAvg float64) *PredictionReport {
	cpuTrend := "stable"
	bottleneck := "none"
	warnings := []string{}
	recs := []string{"Resource utilization is within nominal operating envelopes."}

	if cpuAvg > 80 || cpuMax > 95 {
		cpuTrend = "increasing"
		bottleneck = "cpu"
		warnings = append(warnings, fmt.Sprintf("Peak CPU utilization reached %.1f%%", cpuMax))
	}
	memTrend := "stable"
	if memAvg > 85 || memMax > 95 {
		memTrend = "increasing"
		if bottleneck == "none" {
			bottleneck = "memory"
		}
		warnings = append(warnings, fmt.Sprintf("Memory utilization averaged %.1f%% (peak %.1f%%)", memAvg, memMax))
	}

	return &PredictionReport{
		TrendSummary:        fmt.Sprintf("Statistical baseline across %d telemetry snapshots: CPU avg %.1f%% (peak %.1f%%), Memory avg %.1f%% (peak %.1f%%), Load avg %.2f.", count, cpuAvg, cpuMax, memAvg, memMax, loadAvg),
		CPUTrend:            cpuTrend,
		MemoryTrend:         memTrend,
		DiskIOTrend:         "stable",
		NetworkTrend:        "stable",
		Warnings:            warnings,
		Recommendations:     recs,
		PredictedBottleneck: bottleneck,
		ConfidenceScore:     0.75,
	}
}
