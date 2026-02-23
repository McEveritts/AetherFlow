package api

import (
	"net/http"

	"aetherflow/services"
	"github.com/gin-gonic/gin"
)

// GetHardwareInfo retrieves deep hardware identification details to populate the UI.
func GetHardwareInfo(c *gin.Context) {
	report := services.GetDetailedHardware()
	c.JSON(http.StatusOK, report)
}
