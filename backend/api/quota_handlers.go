package api

import (
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

func quotaErrorStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "not found"), strings.Contains(message, "no rows"):
		return http.StatusNotFound
	case strings.Contains(message, "invalid"):
		return http.StatusBadRequest
	case strings.Contains(message, "secret"):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func quotaErrorCode(err error) string {
	if err == nil {
		return ""
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "not found"), strings.Contains(message, "no rows"):
		return ErrCodeNotFound
	case strings.Contains(message, "invalid"):
		return ErrCodeBadRequest
	case strings.Contains(message, "quota"):
		return ErrCodeQuotaExceeded
	default:
		return ErrCodeInternal
	}
}

// QuotaUploadGuard blocks uploads that would exceed the current user's configured quota.
func QuotaUploadGuard() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength <= 0 {
			c.Next()
			return
		}

		rawUserID, exists := c.Get("user_id")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			return
		}
		userID := rawUserID.(int)

		allowed, quota, err := services.HasQuotaHeadroom(userID, c.Request.ContentLength)
		if err != nil {
			slog.Error("quota upload guard check failed", "user_id", userID, "error", err)
			c.Next()
			return
		}

		if !allowed {
			c.AbortWithStatusJSON(http.StatusInsufficientStorage, gin.H{
				"error":           "Upload exceeds the configured filesystem quota",
				"quota_bytes":     quota.QuotaBytes,
				"used_bytes":      quota.UsedBytes,
				"available_bytes": quota.AvailableBytes,
			})
			return
		}

		c.Next()
	}
}


// GetOwnQuota returns the authenticated user's own quota — no URL parameter,
// no IDOR risk. Bound to GET /user/quota.
func GetOwnQuota(c *gin.Context) {
	rawUserID, exists := c.Get("user_id")
	if !exists {
		Unauthorized(c, "Authentication required")
		return
	}
	userID, ok := rawUserID.(int)
	if !ok {
		InternalError(c, "Invalid user context")
		return
	}

	record, err := services.GetUserQuotaRecord(userID)
	if err != nil {
		RespondError(c, quotaErrorStatus(err), quotaErrorCode(err), err.Error())
		return
	}

	c.JSON(http.StatusOK, record)
}

func ListUserQuotas(c *gin.Context) {
	records, err := services.ListUserQuotaRecords()
	if err != nil {
		InternalError(c, "Failed to query quota records")
		return
	}
	c.JSON(http.StatusOK, gin.H{"quotas": records})
}

func UpdateUserQuota(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	var req struct {
		QuotaBytes        int64  `json:"quota_bytes"`
		Quota             string `json:"quota"`
		Source            string `json:"source"`
		BillingProvider   string `json:"billing_provider"`
		BillingExternalID string `json:"billing_external_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	quotaBytes := req.QuotaBytes
	if quotaBytes <= 0 && strings.TrimSpace(req.Quota) != "" {
		parsed, err := services.ParseHumanSize(req.Quota)
		if err != nil {
			BadRequest(c, err.Error())
			return
		}
		quotaBytes = parsed
	}
	if quotaBytes <= 0 {
		BadRequest(c, "quota_bytes or quota is required")
		return
	}

	record, err := services.SetQuotaForUserID(userID, quotaBytes, req.Source, req.BillingProvider, req.BillingExternalID)
	if err != nil {
		RespondError(c, quotaErrorStatus(err), quotaErrorCode(err), err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Quota updated successfully",
		"quota":   record,
	})
}

func RefreshUserQuota(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		BadRequest(c, "Invalid user ID")
		return
	}

	record, err := services.RefreshUserQuotaRecord(userID)
	if err != nil {
		RespondError(c, quotaErrorStatus(err), quotaErrorCode(err), err.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{"quota": record})
}

func HandleBillingWebhook(c *gin.Context) {
	provider := strings.ToLower(strings.TrimSpace(c.Param("provider")))
	switch provider {
	case "whmcs", "blesta":
	default:
		NotFoundError(c, "Unsupported billing provider")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20))
	if err != nil {
		BadRequest(c, "Failed to read webhook body")
		return
	}

	result, err := services.ProcessBillingWebhook(provider, c.Request.Header, body)
	if err != nil {
		RespondError(c, quotaErrorStatus(err), quotaErrorCode(err), err.Error())
		return
	}

	c.JSON(http.StatusOK, result)
}

func ListBillingWebhookEvents(c *gin.Context) {
	limit := 50
	if raw := c.Query("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 200 {
			limit = parsed
		}
	}

	events, err := services.ListBillingWebhookAudits(limit)
	if err != nil {
		InternalError(c, "Failed to load billing webhook events")
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}
