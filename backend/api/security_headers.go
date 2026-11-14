package api

import (
	"strings"

	"github.com/gin-gonic/gin"
)

func sanitizeCSPHostAuthority(rawHost string) string {
	trimmed := strings.TrimSpace(rawHost)
	if trimmed == "" || len(trimmed) > 255 {
		return ""
	}
	for _, r := range trimmed {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == ':' || r == '[' || r == ']') {
			return ""
		}
	}
	return trimmed
}

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

		reqPath := c.Request.URL.Path
		isHTMLDocRoute := strings.HasPrefix(reqPath, "/swagger") || strings.HasPrefix(reqPath, "/api/v1/swagger")
		if strings.HasPrefix(reqPath, "/api/") && !isHTMLDocRoute {
			c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		} else {
			connectSrc := "connect-src 'self'"
			if host := sanitizeCSPHostAuthority(c.Request.Host); host != "" {
				connectSrc = "connect-src 'self' ws://" + host + " wss://" + host
			}
			c.Header(
				"Content-Security-Policy",
				"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; "+connectSrc+"; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
			)
		}

		// Prevent referrer leakage
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")

		// Feature policy — disable sensitive browser APIs
		c.Header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

		c.Next()
	}
}
