package api

import (
	"net/http"

	"aetherflow/services"
	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine) {
	apiGroup := r.Group("/api")
	{
		apiGroup.GET("/ws", HandleWebSocket)
		apiGroup.POST("/ai/chat", handleAiChat)

		// Authentication
		apiGroup.GET("/auth/google/login", GoogleLogin)
		apiGroup.GET("/auth/google/callback", GoogleCallback)
		apiGroup.POST("/auth/login", LocalLogin)
		apiGroup.POST("/auth/setup", SetupAdmin)
		apiGroup.GET("/auth/setup/check", CheckSetupNeeded)
		apiGroup.GET("/auth/session", GetSession)
		apiGroup.POST("/auth/logout", Logout)

		// User profile (self-service)
		apiGroup.PUT("/auth/profile", UpdateProfile)
		apiGroup.GET("/user/quota/:id", GetUserQuota)

		// Settings (Open for GET, Admin Only for PUT)
		apiGroup.GET("/settings", GetSettings) // Open so UI can configure

		// File Share
		apiGroup.GET("/fileshare", GetFilesList)
		apiGroup.POST("/fileshare/upload", UploadFile)

		// Backup
		apiGroup.POST("/backup/run", RunBackup)

		// Admin-only routes
		adminGroup := apiGroup.Group("")
		adminGroup.Use(AdminOnly())
		{
			adminGroup.PUT("/settings", updateSettings)

			// User Management
			adminGroup.GET("/users", GetUsers)
			adminGroup.PUT("/users/:id/role", UpdateUserRole)
			adminGroup.DELETE("/users/:id", DeleteUser)
		}

		// Services API
		apiGroup.GET("/services", getServices) // Renamed from GetServices to match existing
		apiGroup.POST("/services/:name/control", controlService) // Renamed from ControlService to match existing

		// Marketplace API
		apiGroup.GET("/marketplace", GetMarketplaceApps) // Kept existing route
		apiGroup.POST("/packages/:id/install", InstallPackage) // Kept existing route
		apiGroup.POST("/packages/:id/uninstall", UninstallPackage) // Kept existing route

		// Updater API
		apiGroup.GET("/system/update/check", CheckUpdate)
		apiGroup.POST("/system/update/run", RunUpdate)

		// System Hardware Stats (Existing)
		apiGroup.GET("/system/hardware", GetHardwareInfo)
		apiGroup.GET("/system/metrics", func(c *gin.Context) {
			// In the future this might call actual sh commands
			// For now, it returns a stub for the frontend to consume
			c.JSON(http.StatusOK, gin.H{
				"cpu": 45.2,
				"memory": gin.H{
					"total": 16,
					"used": 8.5,
					"free": 7.5,
				},
				"disk": gin.H{
					"total": 500,
					"used": 250,
					"free": 250,
				},
				"uptime": "14 days, 2 hours",
			})
		})
	}
}

func getSystemMetrics(c *gin.Context) {
	metrics := services.GetSystemMetricsCore()
	c.JSON(http.StatusOK, metrics)
}

func getServices(c *gin.Context) {
	servicesList := services.GetActiveServices()
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

	err := services.ControlService(serviceName, req.Action)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to " + req.Action + " service: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Service control command executed successfully",
		"service": serviceName,
		"action":  req.Action,
	})
}
