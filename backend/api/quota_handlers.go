package api

import (
	"io"
	"log"
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
			log.Printf("quota upload guard fallback for user %d: %v", userID, err)
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

func GetUserQuota(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	// IDOR protection: users can only view their own quota; admins can view any.
	authedUserID, _ := c.Get("user_id")
	authedRole, _ := c.Get("user_role")
	if authedUserID != userID && authedRole != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden: You can only view your own quota"})
		return
	}

	record, err := services.GetUserQuotaRecord(userID)
	if err != nil {
		c.JSON(quotaErrorStatus(err), gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, record)
}

// GetOwnQuota returns the authenticated user's own quota — no URL parameter,
// no IDOR risk. Bound to GET /user/quota.
func GetOwnQuota(c *gin.Context) {
	rawUserID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}
	userID, ok := rawUserID.(int)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user context"})
		return
	}

	record, err := services.GetUserQuotaRecord(userID)
	if err != nil {
		c.JSON(quotaErrorStatus(err), gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, record)
}

func ListUserQuotas(c *gin.Context) {
	records, err := services.ListUserQuotaRecords()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query quota records"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"quotas": records})
}

func UpdateUserQuota(c *gin.Context) {
	userID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	quotaBytes := req.QuotaBytes
	if quotaBytes <= 0 && strings.TrimSpace(req.Quota) != "" {
		parsed, err := services.ParseHumanSize(req.Quota)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		quotaBytes = parsed
	}
	if quotaBytes <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "quota_bytes or quota is required"})
		return
	}

	record, err := services.SetQuotaForUserID(userID, quotaBytes, req.Source, req.BillingProvider, req.BillingExternalID)
	if err != nil {
		c.JSON(quotaErrorStatus(err), gin.H{"error": err.Error()})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	record, err := services.RefreshUserQuotaRecord(userID)
	if err != nil {
		c.JSON(quotaErrorStatus(err), gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"quota": record})
}

func HandleBillingWebhook(c *gin.Context) {
	provider := strings.ToLower(strings.TrimSpace(c.Param("provider")))
	switch provider {
	case "whmcs", "blesta":
	default:
		c.JSON(http.StatusNotFound, gin.H{"error": "Unsupported billing provider"})
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read webhook body"})
		return
	}

	result, err := services.ProcessBillingWebhook(provider, c.Request.Header, body)
	if err != nil {
		c.JSON(quotaErrorStatus(err), gin.H{"error": err.Error()})
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load billing webhook events"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"events": events})
}
