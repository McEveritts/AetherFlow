package db

import (
	"database/sql"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

// setupTestDB creates an in-memory SQLite database with the required schema
// for action gate tests. It sets the package-level DB variable directly.
func setupTestDB(t *testing.T) {
	t.Helper()

	var err error
	DB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory SQLite: %v", err)
	}

	// Minimal schema for action gates
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS schema_versions (
			version INTEGER PRIMARY KEY,
			description TEXT,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS pending_actions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			classification TEXT NOT NULL DEFAULT 'warn',
			source TEXT NOT NULL DEFAULT '',
			action TEXT NOT NULL DEFAULT '',
			reason TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL DEFAULT 'pending',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			resolved_at TEXT,
			resolved_by TEXT,
			execution_log TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS admin_audit_log (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER NOT NULL,
			username TEXT NOT NULL,
			action TEXT NOT NULL,
			target_type TEXT NOT NULL DEFAULT '',
			target_id TEXT NOT NULL DEFAULT '',
			detail TEXT NOT NULL DEFAULT '',
			ip_address TEXT NOT NULL DEFAULT '',
			user_agent TEXT NOT NULL DEFAULT '',
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, stmt := range stmts {
		if _, err := DB.Exec(stmt); err != nil {
			t.Fatalf("Schema setup failed: %v", err)
		}
	}

	t.Cleanup(func() {
		DB.Close()
		DB = nil
	})
}

// --- QueueAction Tests ---

func TestQueueAction_SafeBypass(t *testing.T) {
	setupTestDB(t)

	id, needsApproval := QueueAction("safe", "test", "read-metrics", "routine check")
	if id != 0 {
		t.Errorf("Expected id=0 for safe action, got %d", id)
	}
	if needsApproval {
		t.Error("Safe actions should not require approval")
	}

	// Verify nothing was inserted into pending_actions
	var count int
	DB.QueryRow("SELECT COUNT(*) FROM pending_actions").Scan(&count)
	if count != 0 {
		t.Errorf("Expected 0 pending actions for safe classification, got %d", count)
	}
}

func TestQueueAction_WarnQueued(t *testing.T) {
	setupTestDB(t)

	id, needsApproval := QueueAction("warn", "af-heal", "restart:nginx:systemd", "detected crashed")
	if id == 0 {
		t.Error("Expected non-zero id for warn action")
	}
	if !needsApproval {
		t.Error("Warn actions should require approval")
	}

	// Verify the action is in the database with pending status
	var status, source, action string
	err := DB.QueryRow("SELECT status, source, action FROM pending_actions WHERE id = ?", id).Scan(&status, &source, &action)
	if err != nil {
		t.Fatalf("Failed to query inserted action: %v", err)
	}
	if status != "pending" {
		t.Errorf("Expected status='pending', got %q", status)
	}
	if source != "af-heal" {
		t.Errorf("Expected source='af-heal', got %q", source)
	}
	if action != "restart:nginx:systemd" {
		t.Errorf("Expected action='restart:nginx:systemd', got %q", action)
	}
}

func TestQueueAction_CriticalQueued(t *testing.T) {
	setupTestDB(t)

	id, needsApproval := QueueAction("critical", "operator", "delete:service:qbittorrent", "user requested removal")
	if id == 0 {
		t.Error("Expected non-zero id for critical action")
	}
	if !needsApproval {
		t.Error("Critical actions should require approval")
	}
}

func TestIsActionApproved_DefaultPending(t *testing.T) {
	setupTestDB(t)

	id, _ := QueueAction("warn", "test", "restart:test", "test")
	if IsActionApproved(id) {
		t.Error("Newly queued action should not be approved")
	}
}

func TestIsActionApproved_AfterApproval(t *testing.T) {
	setupTestDB(t)

	id, _ := QueueAction("warn", "test", "restart:test", "test")

	// Simulate admin approval
	DB.Exec("UPDATE pending_actions SET status = 'approved' WHERE id = ?", id)

	if !IsActionApproved(id) {
		t.Error("Action should be approved after status update")
	}
}

func TestGetActionStatus_Lifecycle(t *testing.T) {
	setupTestDB(t)

	id, _ := QueueAction("warn", "test", "restart:test", "test")

	// Pending
	if s := GetActionStatus(id); s != "pending" {
		t.Errorf("Expected 'pending', got %q", s)
	}

	// Approved
	DB.Exec("UPDATE pending_actions SET status = 'approved' WHERE id = ?", id)
	if s := GetActionStatus(id); s != "approved" {
		t.Errorf("Expected 'approved', got %q", s)
	}

	// Executed
	MarkActionExecuted(id, "restarted successfully")
	if s := GetActionStatus(id); s != "executed" {
		t.Errorf("Expected 'executed', got %q", s)
	}
}

func TestMarkActionFailed(t *testing.T) {
	setupTestDB(t)

	id, _ := QueueAction("warn", "test", "restart:test", "test")
	DB.Exec("UPDATE pending_actions SET status = 'approved' WHERE id = ?", id)

	MarkActionFailed(id, "systemctl returned exit code 1")
	if s := GetActionStatus(id); s != "failed" {
		t.Errorf("Expected 'failed', got %q", s)
	}
}

func TestGetActionStatus_NonExistent(t *testing.T) {
	setupTestDB(t)

	if s := GetActionStatus(99999); s != "" {
		t.Errorf("Expected empty string for non-existent action, got %q", s)
	}
}

// --- Audit Log Tests ---

func TestRecordAudit_Insert(t *testing.T) {
	setupTestDB(t)

	RecordAudit(1, "admin", "action_approve", "pending_action", "42", "approved restart", "127.0.0.1", "test-agent")

	var count int
	DB.QueryRow("SELECT COUNT(*) FROM admin_audit_log").Scan(&count)
	if count != 1 {
		t.Errorf("Expected 1 audit entry, got %d", count)
	}

	var action, targetType, targetID string
	DB.QueryRow("SELECT action, target_type, target_id FROM admin_audit_log WHERE id = 1").Scan(&action, &targetType, &targetID)
	if action != "action_approve" {
		t.Errorf("Expected action='action_approve', got %q", action)
	}
	if targetType != "pending_action" {
		t.Errorf("Expected target_type='pending_action', got %q", targetType)
	}
	if targetID != "42" {
		t.Errorf("Expected target_id='42', got %q", targetID)
	}
}

func TestQueryAuditLog_Pagination(t *testing.T) {
	setupTestDB(t)

	// Insert several entries
	for i := 0; i < 5; i++ {
		RecordAudit(1, "admin", "action_approve", "pending_action", "1", "", "127.0.0.1", "test")
	}
	for i := 0; i < 3; i++ {
		RecordAudit(1, "admin", "action_reject", "pending_action", "2", "", "127.0.0.1", "test")
	}

	// Unfiltered
	entries, total, err := QueryAuditLog(10, 0, "", "")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if total != 8 {
		t.Errorf("Expected total=8, got %d", total)
	}
	if len(entries) != 8 {
		t.Errorf("Expected 8 entries, got %d", len(entries))
	}

	// Filtered by action
	entries, total, _ = QueryAuditLog(10, 0, "action_reject", "")
	if total != 3 {
		t.Errorf("Expected total=3 for action_reject filter, got %d", total)
	}
	if len(entries) != 3 {
		t.Errorf("Expected 3 entries for action_reject, got %d", len(entries))
	}

	// Pagination
	entries, _, _ = QueryAuditLog(3, 0, "", "")
	if len(entries) != 3 {
		t.Errorf("Expected 3 entries with limit=3, got %d", len(entries))
	}
	entries, _, _ = QueryAuditLog(3, 6, "", "")
	if len(entries) != 2 {
		t.Errorf("Expected 2 entries with offset=6, got %d", len(entries))
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
