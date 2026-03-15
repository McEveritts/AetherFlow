package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"aetherflow/db"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// BackupWindow represents the AI-determined optimal backup time.
type BackupWindow struct {
	OptimalHour  int     `json:"optimal_hour"`  // 0-23
	DurationMins int     `json:"duration_mins"` // estimated backup duration
	Confidence   float64 `json:"confidence"`
	Reasoning    string  `json:"reasoning"`
	Timezone     string  `json:"timezone"`
}

// SmartBackupScheduler manages AI-driven backup scheduling.
type SmartBackupScheduler struct {
	mu           sync.RWMutex
	running      bool
	lastWindow   *BackupWindow
	nextBackupAt *time.Time
}

// Global scheduler instance.
var BackupScheduler *SmartBackupScheduler

// InitSmartBackupScheduler starts the smart backup scheduler.
func InitSmartBackupScheduler() {
	BackupScheduler = &SmartBackupScheduler{}

	// Check if smart scheduling is enabled
	var mode string
	err := db.DB.QueryRow("SELECT COALESCE(backup_schedule_mode, 'manual') FROM settings WHERE id = 1").Scan(&mode)
	if err != nil || mode != "smart" {
		log.Println("Smart backup scheduler: disabled (mode=manual)")
		return
	}

	// Load cached optimal window
	var windowJSON string
	db.DB.QueryRow("SELECT COALESCE(backup_optimal_window, '') FROM settings WHERE id = 1").Scan(&windowJSON)
	if windowJSON != "" {
		var window BackupWindow
		if err := json.Unmarshal([]byte(windowJSON), &window); err == nil {
			BackupScheduler.lastWindow = &window
		}
	}

	go BackupScheduler.schedulerLoop()
	log.Println("Smart backup scheduler initialized")
}

func (sbs *SmartBackupScheduler) schedulerLoop() {
	// Recalculate optimal window daily
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	// Initial calculation after 5 minutes
	time.Sleep(5 * time.Minute)
	sbs.recalculate()

	for range ticker.C {
		sbs.recalculate()
	}
}

func (sbs *SmartBackupScheduler) recalculate() {
	apiKey := ""
	db.DB.QueryRow("SELECT COALESCE(gemini_api_key, '') FROM settings WHERE id = 1").Scan(&apiKey)
	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		log.Println("Smart backup: no API key, skipping window calculation")
		return
	}

	window, err := FindOptimalBackupWindow(apiKey)
	if err != nil {
		log.Printf("Smart backup: failed to calculate window: %v", err)
		return
	}

	sbs.mu.Lock()
	sbs.lastWindow = window
	sbs.mu.Unlock()

	// Cache in database
	windowJSON, _ := json.Marshal(window)
	db.DB.Exec("UPDATE settings SET backup_optimal_window = ? WHERE id = 1", string(windowJSON))

	log.Printf("Smart backup: optimal window calculated → %02d:00 UTC (confidence: %.0f%%)", window.OptimalHour, window.Confidence*100)
}

// GetOptimalWindow returns the current cached optimal backup window.
func (sbs *SmartBackupScheduler) GetOptimalWindow() *BackupWindow {
	sbs.mu.RLock()
	defer sbs.mu.RUnlock()
	return sbs.lastWindow
}

// GetScheduleStatus returns the current scheduling state.
func (sbs *SmartBackupScheduler) GetScheduleStatus() map[string]interface{} {
	sbs.mu.RLock()
	defer sbs.mu.RUnlock()

	var mode string
	db.DB.QueryRow("SELECT COALESCE(backup_schedule_mode, 'manual') FROM settings WHERE id = 1").Scan(&mode)

	result := map[string]interface{}{
		"mode":    mode,
		"running": sbs.running,
	}

	if sbs.lastWindow != nil {
		result["optimal_window"] = sbs.lastWindow
	}
	if sbs.nextBackupAt != nil {
		result["next_backup_at"] = sbs.nextBackupAt.Format(time.RFC3339)
	}

	return result
}

// FindOptimalBackupWindow analyzes historical I/O to determine the best backup time.
func FindOptimalBackupWindow(apiKey string) (*BackupWindow, error) {
	snapshots, err := GetMetricsHistory(30)
	if err != nil {
		return nil, fmt.Errorf("failed to query metrics history: %v", err)
	}

	if len(snapshots) < 10 {
		return &BackupWindow{
			OptimalHour:  3,
			DurationMins: 30,
			Confidence:   0.3,
			Reasoning:    "Insufficient historical data. Defaulting to 03:00 UTC as a common low-traffic window.",
			Timezone:     "UTC",
		}, nil
	}

	// Build hourly activity summary
	type hourStats struct {
		count    int
		cpuSum   float64
		diskSum  float64
		loadSum  float64
	}
	hours := make([]hourStats, 24)

	for _, s := range snapshots {
		t, err := time.Parse(time.RFC3339, s.Timestamp)
		if err != nil {
			continue
		}
		h := t.Hour()
		hours[h].count++
		hours[h].cpuSum += s.CPUAvg
		hours[h].diskSum += s.DiskReadBPS + s.DiskWriteBPS
		hours[h].loadSum += s.LoadAvg1
	}

	var sb strings.Builder
	sb.WriteString("Hourly activity averages (over 30 days):\n")
	for h := 0; h < 24; h++ {
		if hours[h].count > 0 {
			n := float64(hours[h].count)
			sb.WriteString(fmt.Sprintf("  %02d:00 — CPU: %.1f%%, Disk I/O: %.0f B/s, Load: %.2f (%d samples)\n",
				h, hours[h].cpuSum/n, hours[h].diskSum/n, hours[h].loadSum/n, hours[h].count))
		} else {
			sb.WriteString(fmt.Sprintf("  %02d:00 — No data\n", h))
		}
	}

	prompt := fmt.Sprintf(`You are a server operations expert. Analyze the following hourly activity pattern from a seedbox server and determine the optimal time window for running database backups with minimal impact on media streaming.

%s

Respond ONLY with valid JSON (no markdown, no explanation):
{"optimal_hour": 0, "duration_mins": 30, "confidence": 0.0, "reasoning": "...", "timezone": "UTC"}

Choose the hour with the lowest combined CPU, Disk I/O, and load average.`, sb.String())

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

	var window BackupWindow
	if err := json.Unmarshal([]byte(replyText), &window); err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %v", err)
	}

	return &window, nil
}
