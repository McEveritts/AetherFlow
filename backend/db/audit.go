package db

import (
	"log"
)

// AuditEntry represents a single admin audit log record.
type AuditEntry struct {
	ID         int    `json:"id"`
	UserID     int    `json:"user_id"`
	Username   string `json:"username"`
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Detail     string `json:"detail"`
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
	CreatedAt  string `json:"created_at"`
}

// RecordAudit inserts an admin action into the audit trail.
// This should be called for any admin-gated destructive or state-changing operation:
//   - action_gate approvals/denials
//   - service start/stop/restart
//   - user role changes
//   - backup operations
//   - OIDC client creation
//   - system updates
func RecordAudit(userID int, username, action, targetType, targetID, detail, ipAddress, userAgent string) {
	if DB == nil {
		return
	}
	_, err := DB.Exec(
		`INSERT INTO admin_audit_log (user_id, username, action, target_type, target_id, detail, ip_address, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		userID, username, action, targetType, targetID, detail, ipAddress, userAgent,
	)
	if err != nil {
		log.Printf("[audit] Failed to record audit entry: action=%s target=%s err=%v", action, targetID, err)
	}
}

// QueryAuditLog retrieves audit entries with optional filtering.
// Returns entries in reverse chronological order (newest first).
func QueryAuditLog(limit, offset int, action, username string) ([]AuditEntry, int, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	// Build query dynamically based on filters
	baseQuery := "FROM admin_audit_log WHERE 1=1"
	args := []interface{}{}

	if action != "" {
		baseQuery += " AND action = ?"
		args = append(args, action)
	}
	if username != "" {
		baseQuery += " AND username = ?"
		args = append(args, username)
	}

	// Total count
	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	if err := DB.QueryRow("SELECT COUNT(*) "+baseQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	// Paginated results
	query := "SELECT id, user_id, username, action, target_type, target_id, detail, ip_address, user_agent, created_at " +
		baseQuery + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	rows, err := DB.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Action, &e.TargetType, &e.TargetID, &e.Detail, &e.IPAddress, &e.UserAgent, &e.CreatedAt); err != nil {
			continue
		}
		entries = append(entries, e)
	}

	return entries, total, nil
}
