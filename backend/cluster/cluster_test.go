package cluster

import (
	"database/sql"
	"os"
	"testing"
	"time"

	"aetherflow/db"

	_ "modernc.org/sqlite"
)

// setupTestDB creates an in-memory SQLite DB with the cluster_nodes table.
func setupTestDB(t *testing.T) {
	t.Helper()
	var err error
	db.DB, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test DB: %v", err)
	}

	_, err = db.DB.Exec(`CREATE TABLE IF NOT EXISTS cluster_nodes (
		id TEXT PRIMARY KEY,
		hostname TEXT NOT NULL,
		address TEXT NOT NULL,
		psk_hash TEXT NOT NULL,
		role TEXT DEFAULT 'worker',
		status TEXT DEFAULT 'offline',
		last_heartbeat TEXT,
		enrolled_at TEXT
	)`)
	if err != nil {
		t.Fatalf("failed to create cluster_nodes table: %v", err)
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}

// ── Enrollment Tests ────────────────────────────────────────────────────

func TestEnrollWorker(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	node, err := cm.EnrollWorker("node-alpha", "alpha", "10.0.0.1:50051", "a-very-secure-psk-that-is-long-enough", "v3.0.0", &WorkerSystemInfo{
		OS: "linux", Arch: "amd64", CPUCores: 4, TotalMemoryBytes: 8 << 30,
	})
	if err != nil {
		t.Fatalf("EnrollWorker returned error: %v", err)
	}

	if node.ID != "node-alpha" {
		t.Errorf("expected ID 'node-alpha', got %q", node.ID)
	}
	if node.Status != "online" {
		t.Errorf("expected status 'online', got %q", node.Status)
	}
	if node.Hostname != "alpha" {
		t.Errorf("expected hostname 'alpha', got %q", node.Hostname)
	}
	if node.SystemInfo == nil || node.SystemInfo.CPUCores != 4 {
		t.Errorf("expected system info with 4 cores")
	}

	// Verify persisted to DB
	var dbID string
	err = db.DB.QueryRow("SELECT id FROM cluster_nodes WHERE id = ?", "node-alpha").Scan(&dbID)
	if err != nil {
		t.Fatalf("node not persisted to DB: %v", err)
	}
}

func TestEnrollWorkerReplace(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	psk := "a-very-secure-psk-that-is-long-enough"
	_, err := cm.EnrollWorker("node-beta", "beta-v1", "10.0.0.2:50051", psk, "v3.0.0", nil)
	if err != nil {
		t.Fatalf("first enrollment failed: %v", err)
	}

	// Re-enroll same ID with updated hostname
	node, err := cm.EnrollWorker("node-beta", "beta-v2", "10.0.0.3:50051", psk, "v3.1.0", nil)
	if err != nil {
		t.Fatalf("re-enrollment failed: %v", err)
	}

	if node.Hostname != "beta-v2" {
		t.Errorf("expected updated hostname 'beta-v2', got %q", node.Hostname)
	}
	if node.Version != "v3.1.0" {
		t.Errorf("expected updated version 'v3.1.0', got %q", node.Version)
	}
}

func TestValidatePSK(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	psk := "a-very-secure-psk-that-is-long-enough"
	cm.EnrollWorker("node-psk", "psk-host", "10.0.0.4:50051", psk, "v3.0.0", nil)

	// Correct PSK
	if !cm.ValidatePSK("node-psk", psk) {
		t.Error("ValidatePSK should return true for correct PSK")
	}

	// Wrong PSK
	if cm.ValidatePSK("node-psk", "wrong-psk") {
		t.Error("ValidatePSK should return false for wrong PSK")
	}

	// Non-existent node
	if cm.ValidatePSK("node-nonexistent", psk) {
		t.Error("ValidatePSK should return false for non-existent node")
	}
}

// ── Heartbeat Tests ─────────────────────────────────────────────────────

func TestUpdateHeartbeat(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	psk := "a-very-secure-psk-that-is-long-enough"
	cm.EnrollWorker("node-hb", "hb-host", "10.0.0.5:50051", psk, "v3.0.0", nil)

	// Simulate heartbeat
	metrics := &WorkerMetrics{
		CPUUsage:    45.2,
		MemUsedGB:   3.5,
		MemTotalGB:  8.0,
		DiskUsedGB:  120.0,
		DiskTotalGB: 500.0,
		Uptime:      "3d 5h",
	}
	services := []WorkerService{
		{Name: "transmission", Status: "running", ManagedBy: "systemd"},
	}

	beforeHB := time.Now()
	cm.UpdateHeartbeat("node-hb", metrics, services)

	node := cm.GetNode("node-hb")
	if node == nil {
		t.Fatal("node not found after heartbeat")
	}
	if node.Status != "online" {
		t.Errorf("expected status 'online', got %q", node.Status)
	}
	if node.LastHeartbeat.Before(beforeHB) {
		t.Error("heartbeat timestamp was not updated")
	}
	if node.Metrics == nil || node.Metrics.CPUUsage != 45.2 {
		t.Error("metrics not updated correctly")
	}
	if len(node.Services) != 1 || node.Services[0].Name != "transmission" {
		t.Error("services not updated correctly")
	}
}

func TestHeartbeatForUnknownNode(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	// Should not panic for unknown node
	cm.UpdateHeartbeat("node-unknown", nil, nil)
	if cm.GetNode("node-unknown") != nil {
		t.Error("unknown node should not be created by heartbeat")
	}
}

func TestHeartbeatTimeout(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	// Enroll a node and then set its heartbeat to the past
	psk := "a-very-secure-psk-that-is-long-enough"
	cm.EnrollWorker("node-stale", "stale-host", "10.0.0.6:50051", psk, "v3.0.0", nil)

	cm.mu.Lock()
	cm.workers["node-stale"].LastHeartbeat = time.Now().Add(-60 * time.Second)
	cm.mu.Unlock()

	// Manually trigger the heartbeat check (like heartbeatMonitor does)
	cm.mu.Lock()
	for id, node := range cm.workers {
		if node.Status == "online" && time.Since(node.LastHeartbeat) > heartbeatTimeout {
			node.Status = "offline"
			db.DB.Exec("UPDATE cluster_nodes SET status = 'offline' WHERE id = ?", id)
		}
	}
	cm.mu.Unlock()

	node := cm.GetNode("node-stale")
	if node.Status != "offline" {
		t.Errorf("expected status 'offline' after timeout, got %q", node.Status)
	}
}

// ── Node Management Tests ───────────────────────────────────────────────

func TestGetNodes(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	psk := "a-very-secure-psk-that-is-long-enough"
	cm.EnrollWorker("node-1", "host-1", "10.0.0.1:50051", psk, "v3.0.0", nil)
	cm.EnrollWorker("node-2", "host-2", "10.0.0.2:50051", psk, "v3.0.0", nil)
	cm.EnrollWorker("node-3", "host-3", "10.0.0.3:50051", psk, "v3.0.0", nil)

	nodes := cm.GetNodes()
	if len(nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(nodes))
	}
}

func TestRemoveWorker(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	psk := "a-very-secure-psk-that-is-long-enough"
	cm.EnrollWorker("node-rm", "rm-host", "10.0.0.7:50051", psk, "v3.0.0", nil)

	err := cm.RemoveWorker("node-rm")
	if err != nil {
		t.Fatalf("RemoveWorker failed: %v", err)
	}

	if cm.GetNode("node-rm") != nil {
		t.Error("node should be nil after removal")
	}

	// Verify removed from DB
	var count int
	db.DB.QueryRow("SELECT COUNT(*) FROM cluster_nodes WHERE id = ?", "node-rm").Scan(&count)
	if count != 0 {
		t.Error("node should be removed from DB")
	}
}

// ── Command Dispatch Tests ──────────────────────────────────────────────

func TestSendAndGetCommand(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	psk := "a-very-secure-psk-that-is-long-enough"
	cm.EnrollWorker("node-cmd", "cmd-host", "10.0.0.8:50051", psk, "v3.0.0", nil)

	cmd := &PendingCommand{
		ID:     "cmd-001",
		Type:   "restart_service",
		Params: map[string]string{"service": "transmission"},
	}

	if !cm.SendCommand("node-cmd", cmd) {
		t.Fatal("SendCommand should return true for enrolled node")
	}

	received := cm.GetPendingCommand("node-cmd")
	if received == nil {
		t.Fatal("GetPendingCommand should return the queued command")
	}
	if received.ID != "cmd-001" || received.Type != "restart_service" {
		t.Errorf("unexpected command: %+v", received)
	}

	// Queue should be empty now
	if cm.GetPendingCommand("node-cmd") != nil {
		t.Error("queue should be empty after retrieval")
	}
}

func TestSendCommandToUnknownNode(t *testing.T) {
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	if cm.SendCommand("node-missing", &PendingCommand{ID: "x"}) {
		t.Error("SendCommand should return false for unknown node")
	}
}

func TestCommandQueueFull(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	psk := "a-very-secure-psk-that-is-long-enough"
	cm.EnrollWorker("node-full", "full-host", "10.0.0.9:50051", psk, "v3.0.0", nil)

	// Fill the queue (capacity = 16)
	for i := 0; i < 16; i++ {
		cm.SendCommand("node-full", &PendingCommand{ID: "fill"})
	}

	// 17th should fail
	if cm.SendCommand("node-full", &PendingCommand{ID: "overflow"}) {
		t.Error("SendCommand should return false when queue is full")
	}
}

// ── Cluster Status Tests ────────────────────────────────────────────────

func TestGetClusterStatus(t *testing.T) {
	setupTestDB(t)
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	psk := "a-very-secure-psk-that-is-long-enough"
	cm.EnrollWorker("node-s1", "s1", "10.0.0.10:50051", psk, "v3.0.0", nil)
	cm.EnrollWorker("node-s2", "s2", "10.0.0.11:50051", psk, "v3.0.0", nil)

	// Update heartbeat with metrics for first node
	cm.UpdateHeartbeat("node-s1", &WorkerMetrics{
		CPUUsage: 60.0, MemUsedGB: 4.0, MemTotalGB: 8.0, DiskUsedGB: 100.0, DiskTotalGB: 500.0,
	}, nil)

	// Mark second node offline
	cm.mu.Lock()
	cm.workers["node-s2"].Status = "offline"
	cm.mu.Unlock()

	status := cm.GetClusterStatus()

	if status["total_nodes"].(int) != 2 {
		t.Errorf("expected 2 total nodes, got %v", status["total_nodes"])
	}
	if status["online"].(int) != 1 {
		t.Errorf("expected 1 online, got %v", status["online"])
	}
	if status["offline"].(int) != 1 {
		t.Errorf("expected 1 offline, got %v", status["offline"])
	}
}

func TestGetClusterStatusEmpty(t *testing.T) {
	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	status := cm.GetClusterStatus()
	if status["total_nodes"].(int) != 0 {
		t.Errorf("empty cluster should have 0 nodes")
	}
}

// ── DB Persistence Tests ────────────────────────────────────────────────

func TestLoadFromDB(t *testing.T) {
	setupTestDB(t)

	// Seed the DB directly
	now := time.Now().Format(time.RFC3339)
	db.DB.Exec(
		"INSERT INTO cluster_nodes (id, hostname, address, psk_hash, role, status, last_heartbeat, enrolled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		"node-persisted", "persisted-host", "10.0.0.20:50051", "fake-hash", "worker", "online", now, now,
	)

	cm := &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}
	cm.loadFromDB()

	node := cm.GetNode("node-persisted")
	if node == nil {
		t.Fatal("node should be loaded from DB")
	}
	if node.Hostname != "persisted-host" {
		t.Errorf("expected hostname 'persisted-host', got %q", node.Hostname)
	}
	// All loaded nodes should start as offline until they heartbeat
	if node.Status != "offline" {
		t.Errorf("loaded nodes should start as 'offline', got %q", node.Status)
	}
}
