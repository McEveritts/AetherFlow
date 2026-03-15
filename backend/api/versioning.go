package api

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	defaultAPIVersion = "v1"
	apiVersionKey     = "api_version"
)

var (
	supportedAPIVersions = map[string]bool{
		"v1": true,
	}
	vendorAcceptVersionPattern = regexp.MustCompile(`application/vnd\.aetherflow\.(v?\d+)\+json`)
)

func normalizeAPIVersion(raw string) string {
	value := strings.ToLower(strings.TrimSpace(raw))
	value = strings.TrimPrefix(value, "version=")
	value = strings.Trim(value, `"`)
	if value == "" {
		return ""
	}
	if value[0] >= '0' && value[0] <= '9' {
		return "v" + value
	}
	return value
}

func apiVersionFromAcceptHeader(header string) string {
	for _, part := range strings.Split(header, ",") {
		segment := strings.TrimSpace(strings.ToLower(part))
		if segment == "" {
			continue
		}
		if matches := vendorAcceptVersionPattern.FindStringSubmatch(segment); len(matches) == 2 {
			return normalizeAPIVersion(matches[1])
		}
		for _, token := range strings.Split(segment, ";") {
			token = strings.TrimSpace(token)
			if strings.HasPrefix(token, "version=") {
				return normalizeAPIVersion(strings.TrimPrefix(token, "version="))
			}
		}
	}
	return ""
}

func requestedAPIVersion(c *gin.Context, fallback string) string {
	version := normalizeAPIVersion(c.GetHeader("X-API-Version"))
	if version == "" {
		version = apiVersionFromAcceptHeader(c.GetHeader("Accept"))
	}
	if version == "" {
		version = fallback
	}
	return version
}

func setVersionHeaders(c *gin.Context, version string) {
	c.Set(apiVersionKey, version)
	c.Header("X-API-Version", version)
	c.Writer.Header().Add("Vary", "Accept")
	c.Writer.Header().Add("Vary", "X-API-Version")
}

func legacySuccessorPath(path string) string {
	if path == "/api" {
		return "/api/v1"
	}
	if strings.HasPrefix(path, "/api/") {
		return "/api/v1" + strings.TrimPrefix(path, "/api")
	}
	return "/api/v1"
}

// APIVersionMiddleware resolves header-based version requests on legacy /api routes.
func APIVersionMiddleware(defaultVersion string) gin.HandlerFunc {
	return func(c *gin.Context) {
		version := requestedAPIVersion(c, defaultVersion)
		if !supportedAPIVersions[version] {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":             "Unsupported API version",
				"requested_version": version,
				"supported":         []string{defaultAPIVersion},
			})
			return
		}

		setVersionHeaders(c, version)
		c.Header("Deprecation", "true")
		c.Header("Link", fmt.Sprintf("<%s>; rel=\"successor-version\"", legacySuccessorPath(c.Request.URL.Path)))
		c.Next()
	}
}

// ForceAPIVersion pins explicit versioned route groups like /api/v1.
func ForceAPIVersion(version string) gin.HandlerFunc {
	return func(c *gin.Context) {
		setVersionHeaders(c, version)
		c.Next()
	}
}

// GetAPIVersion exposes the resolved API version for handlers that need it.
func GetAPIVersion(c *gin.Context) string {
	if version, ok := c.Get(apiVersionKey); ok {
		if normalized, ok := version.(string); ok && normalized != "" {
			return normalized
		}
	}
	return defaultAPIVersion
}
