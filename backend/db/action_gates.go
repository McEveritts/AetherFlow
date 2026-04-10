package db

import (
	"log/slog"
	"time"
)

// ── Phase 9: Action Gate DB Operations ──────────────────────────────────
//
// These are the data-layer operations for the action approval gate system.
// Extracted from api/ to avoid import cycles between api ↔ services.
// The HTTP handlers remain in api/action_gates.go.

// QueueAction inserts a destructive action into the pending_actions approval queue.
// Returns the action ID and whether the action requires approval (true = blocked).
// Classification "safe" returns (0, false) — caller should execute directly.
func QueueAction(classification, source, action, reason string) (int, bool) {
	if classification == "safe" {
		return 0, false
	}

	result, err := DB.Exec(
		`INSERT INTO pending_actions (classification, source, action, reason, status) VALUES (?, ?, ?, ?, 'pending')`,
		classification, source, action, reason,
	)
	if err != nil {
		slog.Info("[action-gates] Failed to queue action", "value", err)
		return 0, true // Fail-safe: assume approval needed if DB insert fails
	}

	id, _ := result.LastInsertId()
	slog.Info("action gate queued",
		"classification", classification,
		"action_id", id,
		"source", source,
		"action", action,
		"reason", reason,
	)
	return int(id), true
}

// MarkActionExecuted updates a previously approved action's status to "executed".
func MarkActionExecuted(actionID int, executionLog string) {
	now := time.Now().Format(time.RFC3339)
	_, err := DB.Exec(
		`UPDATE pending_actions SET status = 'executed', resolved_at = ?, execution_log = ? WHERE id = ? AND status = 'approved'`,
		now, executionLog, actionID,
	)
	if err != nil {
		slog.Error("failed to mark action as executed", "action_id", actionID, "error", err)
	}
}

// MarkActionFailed updates a previously approved action's status to "failed".
func MarkActionFailed(actionID int, executionLog string) {
	now := time.Now().Format(time.RFC3339)
	_, err := DB.Exec(
		`UPDATE pending_actions SET status = 'failed', resolved_at = ?, execution_log = ? WHERE id = ? AND status = 'approved'`,
		now, executionLog, actionID,
	)
	if err != nil {
		slog.Error("failed to mark action as failed", "action_id", actionID, "error", err)
	}
}

// IsActionApproved checks whether a specific queued action has been approved.
func IsActionApproved(actionID int) bool {
	var status string
	err := DB.QueryRow(`SELECT status FROM pending_actions WHERE id = ?`, actionID).Scan(&status)
	if err != nil {
		return false
	}
	return status == "approved"
}

// GetActionStatus returns the current status of a pending action.
func GetActionStatus(actionID int) string {
	var status string
	err := DB.QueryRow(`SELECT status FROM pending_actions WHERE id = ?`, actionID).Scan(&status)
	if err != nil {
		return ""
	}
	return status
}
