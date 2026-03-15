package cluster

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"sync"
	"time"

	"aetherflow/db"

	"golang.org/x/crypto/bcrypt"
)

// WorkerNode represents a registered worker in the cluster.
type WorkerNode struct {
	ID            string            `json:"id"`
	Hostname      string            `json:"hostname"`
	Address       string            `json:"address"`
	Role          string            `json:"role"`
	Status        string            `json:"status"` // "online", "offline", "degraded"
	Version       string            `json:"version"`
	LastHeartbeat time.Time         `json:"last_heartbeat"`
	EnrolledAt    time.Time         `json:"enrolled_at"`
	Metrics       *WorkerMetrics    `json:"metrics,omitempty"`
	Services      []WorkerService   `json:"services,omitempty"`
	SystemInfo    *WorkerSystemInfo `json:"system_info,omitempty"`
}

// WorkerMetrics holds recent metrics from a worker node.
type WorkerMetrics struct {
	CPUUsage     float64   `json:"cpu_usage"`
	MemUsedGB    float64   `json:"mem_used_gb"`
	MemTotalGB   float64   `json:"mem_total_gb"`
	DiskUsedGB   float64   `json:"disk_used_gb"`
	DiskTotalGB  float64   `json:"disk_total_gb"`
	NetRxSpeed   string    `json:"net_rx_speed"`
	NetTxSpeed   string    `json:"net_tx_speed"`
	Uptime       string    `json:"uptime"`
	LoadAverage  []float64 `json:"load_average"`
}

// WorkerService represents a service running on a worker node.
type WorkerService struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	Uptime    string `json:"uptime"`
	ManagedBy string `json:"managed_by"`
}

// WorkerSystemInfo holds static system info sent during registration.
type WorkerSystemInfo struct {
	OS               string `json:"os"`
	Arch             string `json:"arch"`
	CPUCores         int32  `json:"cpu_cores"`
	TotalMemoryBytes int64  `json:"total_memory_bytes"`
	TotalDiskBytes   int64  `json:"total_disk_bytes"`
}

// ClusterManager manages the set of registered worker nodes.
type ClusterManager struct {
	mu      sync.RWMutex
	workers map[string]*WorkerNode
	// Channel for pending commands to specific workers
	commands map[string]chan *PendingCommand
}

// PendingCommand is a command queued for delivery to a worker via heartbeat stream.
type PendingCommand struct {
	ID     string
	Type   string
	Params map[string]string
}

// heartbeatTimeout is the max duration without heartbeat before marking offline.
const heartbeatTimeout = 30 * time.Second

// Manager is the global cluster manager instance.
var Manager *ClusterManager

// Init initializes the cluster manager and loads persisted nodes from DB.
func Init() {
	Manager = &ClusterManager{
		workers:  make(map[string]*WorkerNode),
		commands: make(map[string]chan *PendingCommand),
	}

	// Load persisted nodes from database
	Manager.loadFromDB()

	// Start heartbeat monitor goroutine
	go Manager.heartbeatMonitor()

	log.Println("Cluster manager initialized")
}

// loadFromDB loads previously enrolled workers from the database.
func (cm *ClusterManager) loadFromDB() {
	rows, err := db.DB.Query(
		"SELECT id, hostname, address, role, status, last_heartbeat, enrolled_at FROM cluster_nodes",
	)
	if err != nil {
		log.Printf("Cluster: could not load nodes from DB: %v", err)
		return
	}
	defer rows.Close()

	cm.mu.Lock()
	defer cm.mu.Unlock()

	for rows.Next() {
		var node WorkerNode
		var lastHB, enrolledAt string
		err := rows.Scan(&node.ID, &node.Hostname, &node.Address, &node.Role, &node.Status, &lastHB, &enrolledAt)
		if err != nil {
			log.Printf("Cluster: error scanning node row: %v", err)
			continue
		}
		node.LastHeartbeat, _ = time.Parse(time.RFC3339, lastHB)
		node.EnrolledAt, _ = time.Parse(time.RFC3339, enrolledAt)
		node.Status = "offline" // all nodes start offline until they send a heartbeat
		cm.workers[node.ID] = &node
		cm.commands[node.ID] = make(chan *PendingCommand, 16)
	}

	log.Printf("Cluster: loaded %d nodes from database", len(cm.workers))
}

// GenerateEnrollmentToken creates a new random enrollment token and stores its hash.
func (cm *ClusterManager) GenerateEnrollmentToken() (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(tokenBytes)
	return token, nil
}

// EnrollWorker registers a new worker node with the cluster.
func (cm *ClusterManager) EnrollWorker(id, hostname, address, psk, version string, sysInfo *WorkerSystemInfo) (*WorkerNode, error) {
	// Hash the PSK for storage
	pskHash, err := bcrypt.GenerateFromPassword([]byte(psk), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	node := &WorkerNode{
		ID:            id,
		Hostname:      hostname,
		Address:       address,
		Role:          "worker",
		Status:        "online",
		Version:       version,
		LastHeartbeat: now,
		EnrolledAt:    now,
		SystemInfo:    sysInfo,
	}

	// Persist to database
	_, err = db.DB.Exec(
		`INSERT OR REPLACE INTO cluster_nodes (id, hostname, address, psk_hash, role, status, last_heartbeat, enrolled_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		node.ID, node.Hostname, node.Address, string(pskHash),
		node.Role, node.Status, now.Format(time.RFC3339), now.Format(time.RFC3339),
	)
	if err != nil {
		return nil, err
	}

	cm.mu.Lock()
	cm.workers[id] = node
	cm.commands[id] = make(chan *PendingCommand, 16)
	cm.mu.Unlock()

	log.Printf("Cluster: enrolled worker %s (%s) at %s", id, hostname, address)
	return node, nil
}

// ValidatePSK checks a pre-shared key against the stored hash for a node.
func (cm *ClusterManager) ValidatePSK(nodeID, psk string) bool {
	var pskHash string
	err := db.DB.QueryRow("SELECT psk_hash FROM cluster_nodes WHERE id = ?", nodeID).Scan(&pskHash)
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(pskHash), []byte(psk)) == nil
}

// UpdateHeartbeat updates the heartbeat timestamp and metrics for a worker.
func (cm *ClusterManager) UpdateHeartbeat(nodeID string, metrics *WorkerMetrics, services []WorkerService) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	node, ok := cm.workers[nodeID]
	if !ok {
		return
	}

	node.Status = "online"
	node.LastHeartbeat = time.Now()
	node.Metrics = metrics
	node.Services = services

	// Update DB
	db.DB.Exec(
		"UPDATE cluster_nodes SET status = 'online', last_heartbeat = ? WHERE id = ?",
		node.LastHeartbeat.Format(time.RFC3339), nodeID,
	)
}

// RemoveWorker removes a worker from the cluster.
func (cm *ClusterManager) RemoveWorker(nodeID string) error {
	cm.mu.Lock()
	delete(cm.workers, nodeID)
	if ch, ok := cm.commands[nodeID]; ok {
		close(ch)
		delete(cm.commands, nodeID)
	}
	cm.mu.Unlock()

	_, err := db.DB.Exec("DELETE FROM cluster_nodes WHERE id = ?", nodeID)
	if err != nil {
		return err
	}

	log.Printf("Cluster: removed worker %s", nodeID)
	return nil
}

// GetNodes returns a snapshot of all registered worker nodes.
func (cm *ClusterManager) GetNodes() []*WorkerNode {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	nodes := make([]*WorkerNode, 0, len(cm.workers))
	for _, node := range cm.workers {
		nodes = append(nodes, node)
	}
	return nodes
}

// GetNode returns a single worker node by ID.
func (cm *ClusterManager) GetNode(nodeID string) *WorkerNode {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.workers[nodeID]
}

// SendCommand queues a command for delivery to a worker via heartbeat stream.
func (cm *ClusterManager) SendCommand(nodeID string, cmd *PendingCommand) bool {
	cm.mu.RLock()
	ch, ok := cm.commands[nodeID]
	cm.mu.RUnlock()

	if !ok {
		return false
	}

	select {
	case ch <- cmd:
		return true
	default:
		// Queue full
		return false
	}
}

// GetPendingCommand retrieves the next pending command for a worker (non-blocking).
func (cm *ClusterManager) GetPendingCommand(nodeID string) *PendingCommand {
	cm.mu.RLock()
	ch, ok := cm.commands[nodeID]
	cm.mu.RUnlock()

	if !ok {
		return nil
	}

	select {
	case cmd := <-ch:
		return cmd
	default:
		return nil
	}
}

// GetClusterStatus returns an aggregated overview of the cluster.
func (cm *ClusterManager) GetClusterStatus() map[string]interface{} {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	online := 0
	offline := 0
	totalCPU := 0.0
	totalMemUsed := 0.0
	totalMemTotal := 0.0
	totalDiskUsed := 0.0
	totalDiskTotal := 0.0

	for _, node := range cm.workers {
		if node.Status == "online" {
			online++
			if node.Metrics != nil {
				totalCPU += node.Metrics.CPUUsage
				totalMemUsed += node.Metrics.MemUsedGB
				totalMemTotal += node.Metrics.MemTotalGB
				totalDiskUsed += node.Metrics.DiskUsedGB
				totalDiskTotal += node.Metrics.DiskTotalGB
			}
		} else {
			offline++
		}
	}

	return map[string]interface{}{
		"total_nodes":    len(cm.workers),
		"online":         online,
		"offline":        offline,
		"total_cpu_avg":  totalCPU / float64(max(online, 1)),
		"total_mem_used": totalMemUsed,
		"total_mem_total": totalMemTotal,
		"total_disk_used": totalDiskUsed,
		"total_disk_total": totalDiskTotal,
	}
}

// heartbeatMonitor runs in a goroutine, periodically checking for stale workers.
func (cm *ClusterManager) heartbeatMonitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		cm.mu.Lock()
		for id, node := range cm.workers {
			if node.Status == "online" && time.Since(node.LastHeartbeat) > heartbeatTimeout {
				node.Status = "offline"
				log.Printf("Cluster: worker %s (%s) went offline", id, node.Hostname)
				db.DB.Exec("UPDATE cluster_nodes SET status = 'offline' WHERE id = ?", id)
			}
		}
		cm.mu.Unlock()
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
