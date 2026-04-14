package api

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

// ── Phase 9: AI Operations — Action Approval Gates (HTTP Handlers) ─────
//
// HTTP API layer for the action approval gate system. The data operations
// (queue, mark, check) live in db/action_gates.go to avoid import cycles.
//
// Classification tiers:
//   - safe: read-only queries (auto-execute)
//   - warn: service restarts, config changes (queue for approval)
//   - critical: data deletion, service removal (always require approval)

// PendingAction is the JSON response shape for pending actions.
type PendingAction struct {
	ID             int     `json:"id"`
	Classification string  `json:"classification"`
	Source         string  `json:"source"`
	Action         string  `json:"action"`
	Reason         string  `json:"reason"`
	Status         string  `json:"status"`
	CreatedAt      string  `json:"created_at"`
	ResolvedAt     *string `json:"resolved_at,omitempty"`
	ResolvedBy     *string `json:"resolved_by,omitempty"`
	ExecutionLog   *string `json:"execution_log,omitempty"`
}

// ListPendingActions returns actions, optionally filtered by status.
// GET /api/admin/actions/pending?status=pending (default: pending only)
func ListPendingActions(c *gin.Context) {
	statusFilter := c.DefaultQuery("status", "pending")

	validStatuses := map[string]bool{
		"pending": true, "approved": true, "rejected": true,
		"executed": true, "failed": true, "all": true,
	}
	if !validStatuses[statusFilter] {
		RespondError(c, http.StatusBadRequest, ErrCodeBadRequest,
			"Invalid status filter. Use: pending, approved, rejected, executed, failed, all")
		return
	}

	var rows *sql.Rows
	var err error
	if statusFilter == "all" {
		rows, err = db.DB.Query(
			`SELECT id, classification, source, action, reason, status, created_at, resolved_at, resolved_by
			 FROM pending_actions ORDER BY created_at DESC LIMIT 100`,
		)
	} else {
		rows, err = db.DB.Query(
			`SELECT id, classification, source, action, reason, status, created_at, resolved_at, resolved_by
			 FROM pending_actions WHERE status = ? ORDER BY created_at DESC LIMIT 100`,
			statusFilter,
		)
	}
	if err != nil {
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to query actions")
		return
	}
	defer rows.Close()

	actions := []PendingAction{}
	for rows.Next() {
		var a PendingAction
		if err := rows.Scan(&a.ID, &a.Classification, &a.Source, &a.Action, &a.Reason,
			&a.Status, &a.CreatedAt, &a.ResolvedAt, &a.ResolvedBy); err != nil {
			slog.Info("[action-gates] Row scan error", "error", err)
			continue
		}
		actions = append(actions, a)
	}

	c.JSON(http.StatusOK, gin.H{"actions": actions, "filter": statusFilter, "count": len(actions)})
}

// ApproveAction transitions a pending action to "approved" status.
// The originating subsystem (af-heal, AI) polls for this status change
// and executes the operation — this endpoint does NOT run commands.
// POST /api/admin/actions/:id/approve
func ApproveAction(c *gin.Context) {
	actionID := c.Param("id")
	resolvedBy := resolveActorEmail(c)

	var currentStatus string
	err := db.DB.QueryRow(
		`SELECT status FROM pending_actions WHERE id = ?`, actionID,
	).Scan(&currentStatus)

	if err == sql.ErrNoRows {
		RespondError(c, http.StatusNotFound, ErrCodeNotFound, "Action not found")
		return
	}
	if err != nil {
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to query action")
		return
	}
	if currentStatus != "pending" {
		RespondError(c, http.StatusConflict, ErrCodeConflict, "Action already resolved: "+currentStatus)
		return
	}

	now := time.Now().Format(time.RFC3339)
	_, err = db.DB.Exec(
		`UPDATE pending_actions SET status = 'approved', resolved_at = ?, resolved_by = ? WHERE id = ? AND status = 'pending'`,
		now, resolvedBy, actionID,
	)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to approve action")
		return
	}

	slog.Info("action gate approved", "action_id", actionID, "resolved_by", resolvedBy)
	db.RecordAudit(resolveActorID(c), resolvedBy, "action_approve", "pending_action", actionID, "", c.ClientIP(), c.Request.UserAgent())
	c.JSON(http.StatusOK, gin.H{
		"status":  "approved",
		"message": "Action approved. The originating subsystem will execute it.",
	})
}

// RejectAction rejects a pending action.
// POST /api/admin/actions/:id/reject
func RejectAction(c *gin.Context) {
	actionID := c.Param("id")
	resolvedBy := resolveActorEmail(c)

	now := time.Now().Format(time.RFC3339)
	result, err := db.DB.Exec(
		`UPDATE pending_actions SET status = 'rejected', resolved_at = ?, resolved_by = ? WHERE id = ? AND status = 'pending'`,
		now, resolvedBy, actionID,
	)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to reject action")
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		RespondError(c, http.StatusNotFound, ErrCodeNotFound, "Action not found or already resolved")
		return
	}

	slog.Info("action gate rejected", "action_id", actionID, "resolved_by", resolvedBy)
	db.RecordAudit(resolveActorID(c), resolvedBy, "action_reject", "pending_action", actionID, "", c.ClientIP(), c.Request.UserAgent())
	c.JSON(http.StatusOK, gin.H{"status": "rejected"})
}

// resolveActorEmail extracts the acting user's email from the JWT context.
func resolveActorEmail(c *gin.Context) string {
	if email, ok := c.Get("user_email"); ok {
		if s, ok := email.(string); ok && s != "" {
			return s
		}
	}
	return "admin"
}

// resolveActorID extracts the acting user's ID from the JWT context.
func resolveActorID(c *gin.Context) int {
	if id, ok := c.Get("user_id"); ok {
		if i, ok := id.(int); ok {
			return i
		}
	}
	return 0
}

// GetPendingAction returns a single action by its ID, including its execution log.
// GET /api/admin/actions/:id
func GetPendingAction(c *gin.Context) {
	actionID := c.Param("id")

	var a PendingAction
	err := db.DB.QueryRow(
		`SELECT id, classification, source, action, reason, status, created_at, resolved_at, resolved_by, execution_log
		 FROM pending_actions WHERE id = ?`, actionID,
	).Scan(&a.ID, &a.Classification, &a.Source, &a.Action, &a.Reason,
		&a.Status, &a.CreatedAt, &a.ResolvedAt, &a.ResolvedBy, &a.ExecutionLog)

	if err == sql.ErrNoRows {
		RespondError(c, http.StatusNotFound, ErrCodeNotFound, "Action not found")
		return
	} else if err != nil {
		slog.Error("[action-gates] Failed to query action", "error", err, "id", actionID)
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to query action")
		return
	}

	c.JSON(http.StatusOK, a)
}
