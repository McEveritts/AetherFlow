package api

import (
	"github.com/gin-gonic/gin"
)

// ── Phase 21: Security Headers Middleware ───────────────────────────────
//
// Injects security headers on every response to mitigate XSS, clickjacking,
// and MIME-sniffing attacks. Applied globally at the router level.

// SecurityHeadersMiddleware adds defense-in-depth HTTP headers.
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// CWE-79: Prevent MIME-type sniffing
		c.Header("X-Content-Type-Options", "nosniff")

		// CWE-1021: Prevent clickjacking via iframe embedding
		c.Header("X-Frame-Options", "DENY")

		// CWE-693: Enforce HTTPS-only transport (1 year)
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// CWE-79: Basic XSS protection (legacy browsers)
		c.Header("X-XSS-Protection", "1; mode=block")

		// Content Security Policy — API-appropriate. The frontend is served separately
		// so script-src restrictions here primarily protect the Swagger UI and OIDC flows.
		// We allow 'unsafe-inline' for styles because Swagger injects inline CSS.
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'")

		// Prevent referrer leakage
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Feature policy — disable sensitive browser APIs
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		c.Next()
	}
}
