package services

import (
	"log"
	"time"

	"aetherflow/db"
)

// InitMetricsRecorder starts a background goroutine that samples system metrics
// every 15 minutes and stores them in the metrics_history table for trend analysis.
func InitMetricsRecorder() {
	go func() {
		// Initial sample after 30 seconds
		time.Sleep(30 * time.Second)
		recordMetricsSnapshot()

		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			recordMetricsSnapshot()
			pruneOldMetrics()
		}
	}()
	log.Println("Metrics recorder initialized (15-minute intervals)")
}

func recordMetricsSnapshot() {
	metrics := GetSystemMetricsCore()

	cpuAvg := metrics.CPUUsage
	memUsed := 0.0
	memTotal := 0.0
	if v, ok := metrics.Memory["used"]; ok {
		memUsed = v
	}
	if v, ok := metrics.Memory["total"]; ok {
		memTotal = v
	}
	diskRead := 0.0
	diskWrite := 0.0
	if v, ok := metrics.DiskIO["read_bytes_sec"]; ok {
		diskRead = v
	}
	if v, ok := metrics.DiskIO["write_bytes_sec"]; ok {
		diskWrite = v
	}
	var netRx, netTx uint64
	if v, ok := metrics.TotalNetBytes["rx"]; ok {
		netRx = v
	}
	if v, ok := metrics.TotalNetBytes["tx"]; ok {
		netTx = v
	}
	loadAvg1 := 0.0
	if len(metrics.LoadAverage) > 0 {
		loadAvg1 = metrics.LoadAverage[0]
	}
	activeConns := 0
	if v, ok := metrics.Network["active_connections"]; ok {
		if n, ok := v.(int); ok {
			activeConns = n
		}
	}

	_, err := db.DB.Exec(
		`INSERT INTO metrics_history (cpu_avg, mem_used_gb, mem_total_gb, disk_read_bps, disk_write_bps, net_rx_bytes, net_tx_bytes, load_avg_1, active_conns)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cpuAvg, memUsed, memTotal, diskRead, diskWrite, netRx, netTx, loadAvg1, activeConns,
	)
	if err != nil {
		log.Printf("Metrics recorder: failed to store snapshot: %v", err)
	}
}

// pruneOldMetrics removes entries older than 30 days.
func pruneOldMetrics() {
	cutoff := time.Now().AddDate(0, 0, -30).Format(time.RFC3339)
	result, err := db.DB.Exec("DELETE FROM metrics_history WHERE timestamp < ?", cutoff)
	if err != nil {
		log.Printf("Metrics recorder: failed to prune old entries: %v", err)
		return
	}
	if rows, _ := result.RowsAffected(); rows > 0 {
		log.Printf("Metrics recorder: pruned %d entries older than 30 days", rows)
	}
}

// MetricsSnapshot represents a single stored metrics sample.
type MetricsSnapshot struct {
	ID           int     `json:"id"`
	Timestamp    string  `json:"timestamp"`
	CPUAvg       float64 `json:"cpu_avg"`
	MemUsedGB    float64 `json:"mem_used_gb"`
	MemTotalGB   float64 `json:"mem_total_gb"`
	DiskReadBPS  float64 `json:"disk_read_bps"`
	DiskWriteBPS float64 `json:"disk_write_bps"`
	NetRxBytes   int64   `json:"net_rx_bytes"`
	NetTxBytes   int64   `json:"net_tx_bytes"`
	LoadAvg1     float64 `json:"load_avg_1"`
	ActiveConns  int     `json:"active_conns"`
}

// GetMetricsHistory returns the last N days of metrics snapshots.
func GetMetricsHistory(days int) ([]MetricsSnapshot, error) {
	cutoff := time.Now().AddDate(0, 0, -days).Format(time.RFC3339)
	rows, err := db.DB.Query(
		"SELECT id, timestamp, cpu_avg, mem_used_gb, mem_total_gb, disk_read_bps, disk_write_bps, net_rx_bytes, net_tx_bytes, load_avg_1, active_conns FROM metrics_history WHERE timestamp >= ? ORDER BY timestamp ASC",
		cutoff,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []MetricsSnapshot
	for rows.Next() {
		var s MetricsSnapshot
		if err := rows.Scan(&s.ID, &s.Timestamp, &s.CPUAvg, &s.MemUsedGB, &s.MemTotalGB, &s.DiskReadBPS, &s.DiskWriteBPS, &s.NetRxBytes, &s.NetTxBytes, &s.LoadAvg1, &s.ActiveConns); err != nil {
			continue
		}
		results = append(results, s)
	}
	return results, nil
}
