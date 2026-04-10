package services

import (
	"context"
	"sync"

	"aetherflow/logging"
)

// subsystemLifecycle provides a centralized cancellation mechanism for all
// background goroutines. This allows the main shutdown sequence to signal
// all subsystems to stop cleanly before closing database and Redis
// connections (Phase 21 — Graceful Shutdown Contract).
var subsystemLifecycle struct {
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func init() {
	subsystemLifecycle.ctx, subsystemLifecycle.cancel = context.WithCancel(context.Background())
}

// SubsystemContext returns the shared context used by all background services.
// Subsystems should select on ctx.Done() alongside their ticker channels
// to exit cleanly during shutdown.
func SubsystemContext() context.Context {
	return subsystemLifecycle.ctx
}

// StopAllSubsystems cancels the shared context, signaling all background
// goroutines to exit their ticker loops. This should be called in the
// shutdown sequence BEFORE closing database connections.
func StopAllSubsystems() {
	subsystemLifecycle.once.Do(func() {
		logging.ForDomain("control", "lifecycle").Info("stopping all background subsystems")
		subsystemLifecycle.cancel()
	})
}
