package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"aetherflow/db"

	"github.com/google/generative-ai-go/genai"
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
	keyResolver  func() (string, error) // injected from api layer to avoid circular import
	executor     func() error           // injected executor
}

// Global scheduler instance.
var BackupScheduler *SmartBackupScheduler

// InitSmartBackupScheduler starts the smart backup scheduler.
// keyResolver should be a function that returns the decrypted Gemini API key.
func InitSmartBackupScheduler(keyResolver func() (string, error), executor func() error) {
	BackupScheduler = &SmartBackupScheduler{
		keyResolver: keyResolver,
		executor:    executor,
	}

	BackupScheduler.loadPersistedState()

	go BackupScheduler.schedulerLoop()
	go BackupScheduler.executorLoop()

	mode := BackupScheduler.currentMode()
	if mode == "smart" && BackupScheduler.GetOptimalWindow() == nil {
		BackupScheduler.TriggerRecalculation()
	}

	slog.Info("smart backup scheduler initialized", "mode", mode)
}

func (sbs *SmartBackupScheduler) executorLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	ctx := SubsystemContext()
	for {
		select {
		case <-ctx.Done():
			slog.Info("smart backup executor: shutdown signal received")
			return
		case <-ticker.C:
			if sbs.currentMode() != "smart" {
				continue
			}

			now := time.Now().UTC()
			nextRun := sbs.ensureNextBackupAt(now)
			if nextRun == nil {
				continue
			}

			timeToRun := now.After(*nextRun) || now.Equal(*nextRun)
			if timeToRun {
				slog.Info("smart backup: initiating background backup")
				if sbs.executor != nil {
					err := sbs.executor()
					if err != nil {
						slog.Error("smart backup: background backup failed", "error", err)
					} else {
						slog.Info("smart backup: background backup completed")
					}
				}

				sbs.advanceNextBackupAt(now)
			}
		}
	}
}

func (sbs *SmartBackupScheduler) schedulerLoop() {
	// Recalculate optimal window daily
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	initialDelay := time.NewTimer(5 * time.Second)
	defer initialDelay.Stop()

	ctx := SubsystemContext()
	for {
		select {
		case <-ctx.Done():
			slog.Info("smart backup scheduler: shutdown signal received")
			return
		case <-initialDelay.C:
			if sbs.currentMode() == "smart" {
				if sbs.GetOptimalWindow() == nil {
					sbs.recalculate()
				} else {
					sbs.ensureNextBackupAt(time.Now().UTC())
				}
			}
		case <-ticker.C:
			if sbs.currentMode() == "smart" {
				sbs.recalculate()
			}
		}
	}
}

func (sbs *SmartBackupScheduler) recalculate() {
	if sbs.currentMode() != "smart" {
		return
	}

	var apiKey string
	var err error
	if sbs.keyResolver != nil {
		apiKey, err = sbs.keyResolver()
		if err != nil {
			slog.Info("smart backup: no API key, skipping window calculation")
			return
		}
	}
	if apiKey == "" {
		slog.Info("smart backup: no API key, skipping window calculation")
		return
	}

	window, err := FindOptimalBackupWindow(apiKey)
	if err != nil {
		slog.Error("smart backup: failed to calculate window", "error", err)
		return
	}

	sbs.mu.Lock()
	sbs.lastWindow = window
	nextRun := nextBackupTime(window, time.Now().UTC())
	sbs.nextBackupAt = &nextRun
	sbs.running = true
	sbs.mu.Unlock()

	sbs.persistState(window, &nextRun)

	slog.Info("smart backup: optimal window calculated", "hour_utc", window.OptimalHour, "confidence", window.Confidence)
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

	mode := sbs.currentMode()

	result := map[string]interface{}{
		"mode":    mode,
		"running": mode == "smart" && sbs.running,
	}

	if sbs.lastWindow != nil {
		result["optimal_window"] = sbs.lastWindow
	}
	if sbs.nextBackupAt != nil {
		result["next_backup_at"] = sbs.nextBackupAt.Format(time.RFC3339)
	}

	return result
}

// SetMode updates the in-memory scheduler state to match the persisted mode.
func (sbs *SmartBackupScheduler) SetMode(mode string) {
	if sbs == nil {
		return
	}

	var nextRun *time.Time

	sbs.mu.Lock()
	sbs.running = mode == "smart"
	if mode != "smart" {
		sbs.nextBackupAt = nil
	} else if sbs.lastWindow != nil {
		next := nextBackupTime(sbs.lastWindow, time.Now().UTC())
		sbs.nextBackupAt = &next
		nextRun = &next
	}
	sbs.mu.Unlock()

	sbs.persistState(nil, nextRun)
}

// TriggerRecalculation runs an asynchronous optimal-window refresh.
func (sbs *SmartBackupScheduler) TriggerRecalculation() {
	if sbs == nil {
		return
	}

	go sbs.recalculate()
}

func (sbs *SmartBackupScheduler) loadPersistedState() {
	var (
		mode       string
		windowJSON string
		nextRunRaw string
	)

	err := db.DB.QueryRow(
		`SELECT
			COALESCE(backup_schedule_mode, 'manual'),
			COALESCE(backup_optimal_window, ''),
			COALESCE(backup_next_run_at, '')
		FROM settings WHERE id = 1`,
	).Scan(&mode, &windowJSON, &nextRunRaw)
	if err != nil {
		slog.Warn("smart backup: failed to load persisted state", "error", err)
		return
	}

	sbs.mu.Lock()
	defer sbs.mu.Unlock()

	sbs.running = mode == "smart"

	if windowJSON != "" {
		var window BackupWindow
		if err := json.Unmarshal([]byte(windowJSON), &window); err == nil {
			sbs.lastWindow = &window
		} else {
			slog.Warn("smart backup: failed to parse cached optimal window", "error", err)
		}
	}

	if nextRunRaw != "" {
		nextRun, err := time.Parse(time.RFC3339, nextRunRaw)
		if err == nil {
			sbs.nextBackupAt = &nextRun
		} else {
			slog.Warn("smart backup: failed to parse cached next run time", "error", err)
		}
	}
}

func (sbs *SmartBackupScheduler) currentMode() string {
	var mode string
	if err := db.DB.QueryRow("SELECT COALESCE(backup_schedule_mode, 'manual') FROM settings WHERE id = 1").Scan(&mode); err != nil {
		return "manual"
	}
	return mode
}

func (sbs *SmartBackupScheduler) ensureNextBackupAt(now time.Time) *time.Time {
	sbs.mu.Lock()
	defer sbs.mu.Unlock()

	if sbs.lastWindow == nil {
		return nil
	}
	if sbs.nextBackupAt == nil {
		next := nextBackupTime(sbs.lastWindow, now)
		sbs.nextBackupAt = &next
		go sbs.persistState(nil, &next)
	}

	next := *sbs.nextBackupAt
	return &next
}

func (sbs *SmartBackupScheduler) advanceNextBackupAt(now time.Time) {
	sbs.mu.Lock()
	defer sbs.mu.Unlock()

	if sbs.lastWindow == nil {
		return
	}

	next := nextBackupTime(sbs.lastWindow, now.Add(time.Minute))
	sbs.nextBackupAt = &next
	go sbs.persistState(nil, &next)
}

func (sbs *SmartBackupScheduler) persistState(window *BackupWindow, nextRun *time.Time) {
	if db.DB == nil {
		return
	}

	if window != nil {
		windowJSON, _ := json.Marshal(window)
		nextValue := ""
		if nextRun != nil {
			nextValue = nextRun.UTC().Format(time.RFC3339)
		}
		if _, err := db.DB.Exec(
			"UPDATE settings SET backup_optimal_window = ?, backup_next_run_at = ? WHERE id = 1",
			string(windowJSON), nextValue,
		); err != nil {
			slog.Error("smart backup: failed to persist schedule state", "error", err)
		}
		return
	}

	nextValue := ""
	if nextRun != nil {
		nextValue = nextRun.UTC().Format(time.RFC3339)
	}
	if _, err := db.DB.Exec("UPDATE settings SET backup_next_run_at = ? WHERE id = 1", nextValue); err != nil {
		slog.Error("smart backup: failed to persist next backup time", "error", err)
	}
}

func nextBackupTime(window *BackupWindow, now time.Time) time.Time {
	current := now.UTC()
	next := time.Date(current.Year(), current.Month(), current.Day(), window.OptimalHour, 0, 0, 0, time.UTC)
	if current.After(next) || current.Equal(next) {
		next = next.Add(24 * time.Hour)
	}
	return next
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
	client, err := GetAIClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("Gemini client error: %v", err)
	}

	model := GetAIModel(client, "")
	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, fmt.Errorf("generation error: %v", err)
	}

	replyText := CleanJSONResponse(ExtractTextFromResponse(resp))

	var window BackupWindow
	if err := json.Unmarshal([]byte(replyText), &window); err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %v", err)
	}

	return &window, nil
}
