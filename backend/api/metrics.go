package api

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"time"

	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// ── Phase 30: Prometheus-compatible Metrics Endpoint ────────────────────
// Exports metrics in Prometheus text exposition format (text/plain; version=0.0.4).
// No external library required — uses native Go runtime metrics + AetherFlow internals.

// HandleMetrics returns Prometheus-compatible metrics.
// GET /metrics
func HandleMetrics(c *gin.Context) {
	var b strings.Builder

	// ── Go Runtime Metrics ──────────────────────────────────────────────
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	writeGauge(&b, "aetherflow_go_goroutines", "Current number of goroutines.", float64(runtime.NumGoroutine()))
	writeGauge(&b, "aetherflow_go_threads", "Current number of OS threads.", float64(runtime.GOMAXPROCS(0)))
	writeGauge(&b, "aetherflow_go_heap_alloc_bytes", "Heap memory in use (bytes).", float64(memStats.HeapAlloc))
	writeGauge(&b, "aetherflow_go_heap_sys_bytes", "Heap memory obtained from OS (bytes).", float64(memStats.HeapSys))
	writeGauge(&b, "aetherflow_go_stack_inuse_bytes", "Stack memory in use (bytes).", float64(memStats.StackInuse))
	writeCounter(&b, "aetherflow_go_gc_total", "Total GC cycles.", float64(memStats.NumGC))
	writeGauge(&b, "aetherflow_go_gc_pause_total_seconds", "Total GC pause time (seconds).", float64(memStats.PauseTotalNs)/1e9)

	// ── Process Metrics ─────────────────────────────────────────────────
	// startTime is defined in health.go and shared across the package.
	writeGauge(&b, "aetherflow_process_uptime_seconds", "Process uptime in seconds.", time.Since(startTime).Seconds())

	// ── System Metrics ──────────────────────────────────────────────────
	sm := services.GetSystemMetricsCore()

	writeGauge(&b, "aetherflow_system_cpu_percent", "System CPU usage percentage.", sm.CPUUsage)

	if mem, ok := sm.Memory["total"]; ok {
		writeGauge(&b, "aetherflow_system_memory_total_bytes", "Total system memory (bytes).", mem*1024*1024)
	}
	if mem, ok := sm.Memory["used"]; ok {
		writeGauge(&b, "aetherflow_system_memory_used_bytes", "Used system memory (bytes).", mem*1024*1024)
	}
	if mem, ok := sm.Memory["percent"]; ok {
		writeGauge(&b, "aetherflow_system_memory_percent", "System memory usage percentage.", mem)
	}

	if ds, ok := sm.DiskSpace["total_gb"]; ok {
		writeGauge(&b, "aetherflow_system_disk_total_bytes", "Total disk space (bytes).", ds*1024*1024*1024)
	}
	if ds, ok := sm.DiskSpace["used_gb"]; ok {
		writeGauge(&b, "aetherflow_system_disk_used_bytes", "Used disk space (bytes).", ds*1024*1024*1024)
	}
	if ds, ok := sm.DiskSpace["used_pct"]; ok {
		writeGauge(&b, "aetherflow_system_disk_percent", "Disk usage percentage.", ds)
	}

	// ── Database Metrics ────────────────────────────────────────────────
	if db.DB != nil {
		stats := db.DB.Stats()
		writeGauge(&b, "aetherflow_db_open_connections", "Current open database connections.", float64(stats.OpenConnections))
		writeGauge(&b, "aetherflow_db_in_use_connections", "Database connections currently in use.", float64(stats.InUse))
		writeGauge(&b, "aetherflow_db_idle_connections", "Idle database connections.", float64(stats.Idle))
		writeCounter(&b, "aetherflow_db_wait_count_total", "Total waits for a database connection.", float64(stats.WaitCount))
		writeGauge(&b, "aetherflow_db_wait_duration_seconds", "Total time blocked waiting for a connection (seconds).", stats.WaitDuration.Seconds())
	}

	// ── Build Info ──────────────────────────────────────────────────────
	b.WriteString("# HELP aetherflow_build_info Build metadata.\n")
	b.WriteString("# TYPE aetherflow_build_info gauge\n")
	fmt.Fprintf(&b, "aetherflow_build_info{go_version=%q,os=%q,arch=%q} 1\n\n",
		runtime.Version(), runtime.GOOS, runtime.GOARCH)

	c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(b.String()))
}

// writeGauge writes a Prometheus gauge metric entry.
func writeGauge(b *strings.Builder, name, help string, value float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n%s %g\n\n", name, help, name, name, value)
}

// writeCounter writes a Prometheus counter metric entry.
func writeCounter(b *strings.Builder, name, help string, value float64) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s counter\n%s %g\n\n", name, help, name, name, value)
}
