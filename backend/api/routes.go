package api

import (
	"net/http"
	"time"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine) {
	apiGroup := r.Group("/api")
	{
		apiGroup.GET("/ws", HandleWebSocket)
		apiGroup.POST("/ai/chat", handleAiChat)

		// Apply rate limiting: strict on auth endpoints, moderate on general API
		authLimiter := RateLimitMiddleware(5, 1*time.Minute)

		// Authentication (rate-limited to prevent brute force)
		apiGroup.GET("/auth/google/login", GoogleLogin)
		apiGroup.GET("/auth/google/callback", GoogleCallback)
		apiGroup.POST("/auth/login", authLimiter, LocalLogin)
		apiGroup.POST("/auth/setup", authLimiter, SetupAdmin)
		apiGroup.GET("/auth/setup/check", CheckSetupNeeded)
		apiGroup.GET("/auth/session", GetSession)
		apiGroup.POST("/auth/logout", Logout)

		// User profile (self-service)
		apiGroup.PUT("/auth/profile", UpdateProfile)
		apiGroup.GET("/user/quota/:id", GetUserQuota)

		// Settings (Open for GET, Admin Only for PUT)
		apiGroup.GET("/settings", GetSettings) // Open so UI can configure

		// File Share (listing is read-only, upload requires admin)
		apiGroup.GET("/fileshare", GetFilesList)

		// Admin-only routes
		adminGroup := apiGroup.Group("")
		adminGroup.Use(AdminOnly())
		{
			// Backup
			adminGroup.POST("/backup/run", RunBackup)
			adminGroup.GET("/backup/list", GetBackupsList)
			adminGroup.GET("/backup/download/:filename", DownloadBackup)
			adminGroup.POST("/backup/upload/:filename", UploadBackupChunk)

			adminGroup.PUT("/settings", updateSettings)
			adminGroup.POST("/settings/test-ai", TestAiConnection)

			// User Management
			adminGroup.GET("/users", GetUsers)
			adminGroup.PUT("/users/:id/role", UpdateUserRole)
			adminGroup.DELETE("/users/:id", DeleteUser)

			// Service Control (admin-only)
			adminGroup.POST("/services/:name/control", controlService)

			// Package Install/Uninstall (admin-only)
			adminGroup.POST("/packages/:id/install", InstallPackage)
			adminGroup.POST("/packages/:id/uninstall", UninstallPackage)

			// System Update (admin-only)
			adminGroup.POST("/system/update/run", RunUpdate)

			// File Share Upload (admin-only)
			adminGroup.POST("/fileshare/upload", UploadFile)
		}

		// Services API (read-only: public, mutating: admin-only)
		apiGroup.GET("/services", getServices)

		// Marketplace API (read-only: public, mutating: admin-only)
		apiGroup.GET("/marketplace", GetMarketplaceApps)
		apiGroup.GET("/packages/:id/progress", PackageProgress)

		// Updater API (read-only: public, mutating: admin-only)
		apiGroup.GET("/system/update/check", CheckUpdate)

		// System Hardware Stats
		apiGroup.GET("/system/hardware", GetHardwareInfo)
		apiGroup.GET("/system/metrics", getSystemMetrics)
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

// allowedActions is the set of permitted service control actions.
var allowedActions = map[string]bool{"start": true, "stop": true, "restart": true}

func controlService(c *gin.Context) {
	serviceName := c.Param("name")

	var req struct {
		Action    string `json:"action" binding:"required"`
		ManagedBy string `json:"managed_by"` // "pm2" or "systemd" (default)
		Process   string `json:"process"`    // actual process/service name
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate action against allowlist
	if !allowedActions[req.Action] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action. Allowed: start, stop, restart"})
		return
	}

	// Use the process name if provided, otherwise use the URL param
	target := req.Process
	if target == "" {
		target = serviceName
	}

	var err error
	if req.ManagedBy == "pm2" {
		err = services.ControlPM2Service(target, req.Action)
	} else {
		err = services.ControlService(target, req.Action)
	}

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
