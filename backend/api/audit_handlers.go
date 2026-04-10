package api

import (
	"net/http"
	"strconv"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

// GetAuditLog returns paginated admin audit log entries.
// GET /api/admin/audit-log?limit=50&offset=0&action=action_approve&username=admin
func GetAuditLog(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	action := c.Query("action")
	username := c.Query("username")

	entries, total, err := db.QueryAuditLog(limit, offset, action, username)
	if err != nil {
		RespondError(c, http.StatusInternalServerError, ErrCodeInternal, "Failed to query audit log")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}
