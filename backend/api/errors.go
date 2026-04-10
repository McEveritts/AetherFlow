package api

import (
	"fmt"
	"log/slog"
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

// ── Shorthand Error Helpers ─────────────────────────────────────────────
// These auto-set the correct HTTP status and error code for the most common cases.

// BadRequest responds with 400 and BAD_REQUEST code.
func BadRequest(c *gin.Context, message string) {
	RespondError(c, http.StatusBadRequest, ErrCodeBadRequest, message)
}

// NotFoundError responds with 404 and NOT_FOUND code.
func NotFoundError(c *gin.Context, message string) {
	RespondError(c, http.StatusNotFound, ErrCodeNotFound, message)
}

// Unauthorized responds with 401 and UNAUTHORIZED code.
func Unauthorized(c *gin.Context, message string) {
	RespondError(c, http.StatusUnauthorized, ErrCodeUnauthorized, message)
}

// Forbidden responds with 403 and FORBIDDEN code.
func Forbidden(c *gin.Context, message string) {
	RespondError(c, http.StatusForbidden, ErrCodeForbidden, message)
}

// InternalError responds with 500 and INTERNAL_ERROR code.
func InternalError(c *gin.Context, message string) {
	RespondError(c, http.StatusInternalServerError, ErrCodeInternal, message)
}

// ConflictError responds with 409 and CONFLICT code.
func ConflictError(c *gin.Context, message string) {
	RespondError(c, http.StatusConflict, ErrCodeConflict, message)
}

// RecoveryMiddleware catches panics in handlers, logs the stack trace,
// and returns a clean 500 response instead of crashing the process.
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				stack := string(debug.Stack())
				slog.Error("panic recovered", "error", r, "stack", string(stack))
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
