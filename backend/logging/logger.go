package logging

import (
	"log/slog"
	"os"

	"github.com/gin-gonic/gin"
)

// ── Phase 18: Structured Logging ────────────────────────────────────────
//
// Provides a centralized structured logger using Go's stdlib slog package.
// Zero new dependencies. Output format is:
//   - JSON in production (GIN_MODE=release)
//   - Text in development (default)
//
// Usage:
//   logging.Info("backup completed", "filename", backupName, "size", fileSize)
//   logging.Error("db query failed", "error", err, "table", "users")
//   logging.Warn("missing env var", "key", "GEMINI_API_KEY")

var Logger *slog.Logger

// Init initializes the structured logger based on the current Gin mode.
func Init() {
	var handler slog.Handler

	if gin.Mode() == gin.ReleaseMode {
		// JSON output for production — machine-parseable
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})
	} else {
		// Human-readable text output for development
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
	}

	Logger = slog.New(handler)
	slog.SetDefault(Logger)
}

// ── Convenience wrappers ────────────────────────────────────────────────

// Debug logs a debug-level message with structured key-value pairs.
func Debug(msg string, args ...any) {
	if Logger != nil {
		Logger.Debug(msg, args...)
	}
}

// Info logs an info-level message with structured key-value pairs.
func Info(msg string, args ...any) {
	if Logger != nil {
		Logger.Info(msg, args...)
	}
}

// Warn logs a warn-level message with structured key-value pairs.
func Warn(msg string, args ...any) {
	if Logger != nil {
		Logger.Warn(msg, args...)
	}
}

// Error logs an error-level message with structured key-value pairs.
func Error(msg string, args ...any) {
	if Logger != nil {
		Logger.Error(msg, args...)
	}
}

// WithComponent returns a logger with a pre-set "component" field.
// Useful for subsystem-specific logging:
//
//	l := logging.WithComponent("af-heal")
//	l.Info("service recovered", "service", name)
func WithComponent(component string) *slog.Logger {
	if Logger == nil {
		return slog.Default()
	}
	return Logger.With("component", component)
}

// ForDomain returns a logger tagged with both a "domain" and "component" field.
// This is the primary structured logging entry point for subsystems:
//
//	log := logging.ForDomain("control", "af-heal")
//	log.Info("recovery initiated", "service", name, "tier", "warn")
//
// Standard domains: identity, control, telemetry, storage, network, ai, notifications
func ForDomain(domain, component string) *slog.Logger {
	if Logger == nil {
		return slog.Default()
	}
	return Logger.With("domain", domain, "component", component)
}

// WithRequestID returns a logger tagged with a specific request ID.
func WithRequestID(requestID string) *slog.Logger {
	if Logger == nil {
		return slog.Default()
	}
	return Logger.With("request_id", requestID)
}
