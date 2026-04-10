package api

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
)

// ── Phase 17: Standardized Error Handling ───────────────────────────────

// APIError is the standard error response contract for all AetherFlow endpoints.
// All API errors MUST use this shape for consistency.
type APIError struct {
	Code    string `json:"code"`              // machine-readable: "AUTH_EXPIRED", "QUOTA_EXCEEDED"
	Message string `json:"message"`           // human-readable description
	Details any    `json:"details,omitempty"` // optional structured context
}

// ── Error Code Constants ────────────────────────────────────────────────

const (
	ErrCodeInternal        = "INTERNAL_ERROR"
	ErrCodeBadRequest      = "BAD_REQUEST"
	ErrCodeUnauthorized    = "UNAUTHORIZED"
	ErrCodeForbidden       = "FORBIDDEN"
	ErrCodeNotFound        = "NOT_FOUND"
	ErrCodeConflict        = "CONFLICT"
	ErrCodeRateLimit       = "RATE_LIMIT_EXCEEDED"
	ErrCodeValidation      = "VALIDATION_ERROR"
	ErrCodeQuotaExceeded   = "QUOTA_EXCEEDED"
	ErrCodeAIUnavailable   = "AI_UNAVAILABLE"
	ErrCodeSessionExpired  = "SESSION_EXPIRED"
	ErrCodeSessionHijacked = "SESSION_HIJACKED"
)

// RespondError sends a standardized API error response.
func RespondError(c *gin.Context, status int, code, message string) {
	c.JSON(status, APIError{
		Code:    code,
		Message: message,
	})
}

// RespondErrorWithDetails sends a standardized error with structured context.
func RespondErrorWithDetails(c *gin.Context, status int, code, message string, details any) {
	c.JSON(status, APIError{
		Code:    code,
		Message: message,
		Details: details,
	})
}

// RecoveryMiddleware catches panics in handlers, logs the stack trace,
// and returns a clean 500 response instead of crashing the process.
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				log.Printf("PANIC: %v\n%s", r, stack)
				c.AbortWithStatusJSON(http.StatusInternalServerError, APIError{
					Code:    ErrCodeInternal,
					Message: "An unexpected error occurred",
				})
			}
		}()
		c.Next()
	}
}

// RequestIDMiddleware generates a unique request ID for tracing.
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("%d", time.Now().UnixNano())
		}
		c.Set("request_id", requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}
