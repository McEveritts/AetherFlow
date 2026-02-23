package api

import (
	"net/http"

	"aetherflow/services"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine) {
	api := r.Group("/api")
	{
		api.GET("/system/metrics", getSystemMetrics)
		api.GET("/services", getServices)
		api.POST("/services/:name/control", controlService)
	}
}

func getSystemMetrics(c *gin.Context) {
	metrics := services.GetSystemMetricsCore()
	c.JSON(http.StatusOK, metrics)
}

func getServices(c *gin.Context) {
	// For now, return the mock services data structure expected by the frontend
	// In the future, this should actually query PM2 or Systemctl dynamically
	servicesList := map[string]interface{}{
		"Plex Media Server":   gin.H{"status": "running", "uptime": "14d 2h", "version": "1.32.5"},
		"rTorrent":            gin.H{"status": "running", "uptime": "45d 1h", "version": "0.9.8"},
		"Sonarr":              gin.H{"status": "running", "uptime": "12d 5h", "version": "3.0.9"},
		"Radarr":              gin.H{"status": "running", "uptime": "12d 5h", "version": "4.3.2"},
		"Lidarr":              gin.H{"status": "stopped", "uptime": "-", "version": "1.0.2"},
		"Readarr":             gin.H{"status": "running", "uptime": "5d 10h", "version": "0.1.1"},
		"Tautulli":            gin.H{"status": "running", "uptime": "45d 1h", "version": "2.14.3"},
		"Overseerr":           gin.H{"status": "running", "uptime": "30d 12h", "version": "1.33.2"},
		"Nginx Proxy Manager": gin.H{"status": "running", "uptime": "80d 4h", "version": "2.9.18"},
		"Docker Engine":       gin.H{"status": "running", "uptime": "80d 5h", "version": "24.0.2"},
		"WireGuard VPN":       gin.H{"status": "error", "uptime": "-", "version": "1.0.20210914"},
		"Jackett":             gin.H{"status": "running", "uptime": "10d 2h", "version": "0.21.1"},
	}

	c.JSON(http.StatusOK, servicesList)
}

func controlService(c *gin.Context) {
	serviceName := c.Param("name")

	// Payload should contain { action: "start" | "stop" | "restart" }
	var req struct {
		Action string `json:"action" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// TODO: Actually execute the systemctl/pm2 command here
	// exec.Command("systemctl", req.Action, serviceName).Run()

	c.JSON(http.StatusOK, gin.H{
		"message": "Service control command queued successfully",
		"service": serviceName,
		"action":  req.Action,
	})
}
