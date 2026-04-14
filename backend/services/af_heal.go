package services

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"aetherflow/db"
	"aetherflow/logging"

	"github.com/gin-gonic/gin"
)

// healLog is the domain-scoped structured logger for the heal subsystem.
var healLog *slog.Logger

// ── Phase 10: Service Lifecycle Stabilization ───────────────────────────
//
// Hardened heal worker with:
//   - Restart budget (max restarts per hour per service) to prevent restart storms
//   - Command timeout (30s deadline) to prevent hung processes
//   - Panic recovery in the goroutine and in each check cycle
//   - Phase 9 integration: destructive restarts are gated through action approval
//     unless AF_HEAL_AUTO_APPROVE=true is set

var HealWorkerActive bool

const (
	maxRestartsPerHour = 10
	commandTimeout     = 30 * time.Second
)

// restartBudget tracks restart counts per service to prevent storm loops.
type restartBudget struct {
	mu      sync.Mutex
	counts  map[string]int // service name → restart count this window
	resetAt time.Time
}

var budget = &restartBudget{
	counts:  make(map[string]int),
	resetAt: time.Now().Add(time.Hour),
}

func (rb *restartBudget) canRestart(service string) bool {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	// Reset window if expired
	if time.Now().After(rb.resetAt) {
		rb.counts = make(map[string]int)
		rb.resetAt = time.Now().Add(time.Hour)
	}

	return rb.counts[service] < maxRestartsPerHour
}

func (rb *restartBudget) record(service string) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.counts[service]++
}

// healAutoApprove controls whether af-heal bypasses the approval gate.
// Set via AF_HEAL_AUTO_APPROVE=true for fully autonomous healing.
var healAutoApprove = strings.EqualFold(os.Getenv("AF_HEAL_AUTO_APPROVE"), "true")

// StartHealWorker starts the af-heal background orchestrator.
// It performs process monitoring and automated recovery of crashed services.
func StartHealWorker(interval time.Duration) {
	if HealWorkerActive {
		return
	}
	HealWorkerActive = true

	go func() {
		// Phase 10: Panic recovery to prevent goroutine death
		defer func() {
			if r := recover(); r != nil {
				healLog.Error("PANIC recovered in heal worker", "panic", r)
				HealWorkerActive = false
				// Attempt to self-restart after panic
				time.Sleep(5 * time.Second)
				StartHealWorker(interval)
			}
		}()

		mode := "GATED (approval required)"
		if healAutoApprove {
			mode = "AUTO-APPROVE (immediate execution)"
		}
		healLog = logging.ForDomain("control", "af-heal")
		healLog.Info("recovery orchestrator initialized",
			"mode", mode,
			"budget", maxRestartsPerHour,
			"timeout", commandTimeout.String())

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		ctx := SubsystemContext()
		for {
			select {
			case <-ctx.Done():
				healLog.Info("shutdown signal received, stopping heal worker")
				HealWorkerActive = false
				return
			case <-ticker.C:
				performHealCheck()
			}
		}
	}()
}

func performHealCheck() {
	// Phase 10: Recover from panics in individual check cycles
	defer func() {
		if r := recover(); r != nil {
			healLog.Error("PANIC recovered in heal check cycle", "panic", r)
		}
	}()

	servicesMap := GetActiveServices()

	for displayName, detailsObj := range servicesMap {
		details, ok := detailsObj.(gin.H)
		if !ok {
			continue
		}

		status, _ := details["status"].(string)
		managedBy, _ := details["managed_by"].(string)
		processName, _ := details["process"].(string)

		// Skip services without a known process manager
		if managedBy == "" || processName == "" {
			continue
		}

		// Determine if the process requires healing
		needsHeal := false
		switch status {
		case "error", "failed", "errored", "crashed":
			needsHeal = true
		}

		if !needsHeal {
			continue
		}

		// Phase 10: Check restart budget before attempting recovery
		if !budget.canRestart(processName) {
			healLog.Warn("restart budget exhausted — skipping",
				"service", displayName,
				"max_per_hour", maxRestartsPerHour)
			if Notifier != nil {
				Notifier.Dispatch(Notification{
					Level:   NotifyCritical,
					Title:   "af-heal Restart Budget Exhausted",
					Message: displayName + " has exceeded the maximum restart attempts. Manual intervention required.",
				})
			}
			continue
		}

		healLog.Info("detected ailing service",
			"service", displayName,
			"process", processName,
			"manager", managedBy)

		// ── Phase 9 Integration: Action Approval Gate ──
		if healAutoApprove {
			// Auto-approve mode: execute immediately
			executeRecovery(displayName, processName, managedBy, 0)
		} else {
			// Gated mode: queue for human approval, then poll
			actionLabel := fmt.Sprintf("restart:%s:%s", processName, managedBy)
			reason := fmt.Sprintf("Service %s detected in '%s' state by af-heal", displayName, status)

			actionID, needsApproval := db.QueueAction("warn", "af-heal", actionLabel, reason)
			if !needsApproval {
				// Classification was safe (shouldn't happen for restarts, but handle gracefully)
				executeRecovery(displayName, processName, managedBy, 0)
			} else {
				healLog.Info("recovery queued for approval",
					"action_id", actionID,
					"service", displayName)
				// Start a background poller that checks for approval
				go pollForApproval(actionID, displayName, processName, managedBy)
			}
		}

		budget.record(processName)
	}
}

// pollForApproval checks the approval gate every 10 seconds for up to 30 minutes.
// If approved, it executes the recovery. If not approved within the window, it expires.
func pollForApproval(actionID int, displayName, processName, managedBy string) {
	defer func() {
		if r := recover(); r != nil {
			healLog.Error("PANIC in approval poller", "action_id", actionID, "panic", r)
		}
	}()

	timeout := time.After(30 * time.Minute)
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			healLog.Warn("action expired without approval", "action_id", actionID)
			return
		case <-ticker.C:
			if db.IsActionApproved(actionID) {
				healLog.Info("action approved, executing recovery",
					"action_id", actionID,
					"service", displayName)
				executeRecovery(displayName, processName, managedBy, actionID)
				return
			}
			// Also check if it was rejected
			var status string
			if err := db.DB.QueryRow(`SELECT status FROM pending_actions WHERE id = ?`, actionID).Scan(&status); err == nil {
				if status == "rejected" {
					healLog.Info("action rejected by admin, skipping recovery",
						"action_id", actionID,
						"service", displayName)
					return
				}
			}
		}
	}
}

// executeRecovery performs the actual service restart with timeout.
// If actionID > 0, it updates the action gate record with the result.
func executeRecovery(displayName, processName, managedBy string, actionID int) {
	// Phase 10: All exec.Command calls have a 30-second context timeout
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	var cmd *exec.Cmd
	switch managedBy {
	case "systemd":
		cmd = exec.CommandContext(ctx, "systemctl", "restart", processName)
	case "pm2":
		cmd = exec.CommandContext(ctx, "pm2", "restart", processName)
	default:
		healLog.Warn("recovery skipped: unknown manager",
			"service", displayName,
			"manager", managedBy)
		return
	}

	output, err := cmd.CombinedOutput()
	outputStr := strings.TrimSpace(string(output))

	if err != nil {
		healLog.Error("recovery failed",
			"service", displayName,
			"manager", managedBy,
			"error", err,
			"output", outputStr)
		if actionID > 0 {
			db.MarkActionFailed(actionID, fmt.Sprintf("error: %v\noutput: %s", err, outputStr))
		}
		if Notifier != nil {
			Notifier.Dispatch(Notification{
				Level:   NotifyCritical,
				Title:   "af-heal Recovery Failed",
				Message: fmt.Sprintf("Failed to recover %s via %s: %v", displayName, managedBy, err),
			})
		}
	} else {
		healLog.Info("service recovered successfully",
			"service", displayName,
			"process", processName,
			"manager", managedBy)
		if actionID > 0 {
			db.MarkActionExecuted(actionID, outputStr)
		}
		if Notifier != nil {
			Notifier.Dispatch(Notification{
				Level:   NotifySuccess,
				Title:   "af-heal Auto-Recovery",
				Message: fmt.Sprintf("Recovered %s (%s) via %s.", displayName, processName, managedBy),
			})
		}
	}
}
