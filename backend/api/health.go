package api

import (
	"net/http"
	"time"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

var startTime = time.Now()

// HealthCheck returns a basic server status for load balancers and monitors.
// GET /health — unauthenticated.
// Phase 16: Enhanced with DB health check diagnostics.
// Phase 23 (F-12): Removed Go version, OS, and arch to reduce information disclosure.
func HealthCheck(c *gin.Context) {
	status := "ok"
	dbStatus := "ok"
	var dbLatencyMs int64

	// Phase 16: Use the richer health check that measures latency
	if dbInfo, err := db.DBHealthCheck(); err != nil {
		status = "degraded"
		dbStatus = "unreachable"
	} else {
		if latency, ok := dbInfo["latency_ms"].(int64); ok {
			dbLatencyMs = latency
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":        status,
		"uptime":        time.Since(startTime).String(),
		"version":       "3.1.0",
		"database":      dbStatus,
		"db_latency_ms": dbLatencyMs,
	})
}

// ── Phase 23: Readiness / Liveness Probes ───────────────────────────────

// HealthLive is an ultra-lightweight liveness probe.
// Returns 200 if the Go process is alive. No DB or external checks.
// GET /health/live
func HealthLive(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "alive"})
}

// HealthReady performs a deep readiness check including DB and Redis connectivity.
// Returns 503 if any critical dependency is unreachable.
// GET /health/ready
func HealthReady(c *gin.Context) {
	status := http.StatusOK
	checks := gin.H{}

	// DB check
	if _, err := db.DBHealthCheck(); err != nil {
		checks["database"] = "unreachable"
		status = http.StatusServiceUnavailable
	} else {
		checks["database"] = "ok"
	}

	// Redis check
	if db.RedisClient != nil {
		if err := db.RedisClient.Ping(c.Request.Context()).Err(); err != nil {
			checks["redis"] = "unreachable"
			status = http.StatusServiceUnavailable
		} else {
			checks["redis"] = "ok"
		}
	} else {
		checks["redis"] = "disabled"
	}

	checks["uptime"] = time.Since(startTime).String()

	if status == http.StatusOK {
		checks["status"] = "ready"
	} else {
		checks["status"] = "not_ready"
	}

	c.JSON(status, checks)
}
