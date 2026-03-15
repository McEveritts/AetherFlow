package api

import (
	"net/http"
	"time"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine) {
	legacyAPI := r.Group("/api")
	legacyAPI.Use(APIVersionMiddleware(defaultAPIVersion))
	registerV1Routes(legacyAPI)

	v1API := r.Group("/api/v1")
	v1API.Use(ForceAPIVersion(defaultAPIVersion))
	registerV1Routes(v1API)

	// OIDC Discovery must remain at the root.
	r.GET("/.well-known/openid-configuration", OIDCDiscovery)
}

func registerV1Routes(apiGroup *gin.RouterGroup) {
	apiGroup.GET("/openapi.yaml", GetOpenAPISpec)
	apiGroup.GET("/ws", HandleWebSocket)
	apiGroup.POST("/ai/chat", handleAiChat)
	apiGroup.POST("/ai/support", handleAiSupport)

	authLimiter := RateLimitMiddleware(5, 1*time.Minute)

	apiGroup.GET("/auth/google/login", GoogleLogin)
	apiGroup.GET("/auth/google/callback", GoogleCallback)
	apiGroup.POST("/auth/login", authLimiter, LocalLogin)
	apiGroup.POST("/auth/setup", authLimiter, SetupAdmin)
	apiGroup.GET("/auth/setup/check", CheckSetupNeeded)
	apiGroup.GET("/auth/session", GetSession)
	apiGroup.POST("/auth/logout", Logout)
	apiGroup.PUT("/auth/profile", UpdateProfile)

	apiGroup.GET("/user/quota/:id", GetUserQuota)

	apiGroup.GET("/settings", GetSettings)
	apiGroup.GET("/fileshare", GetFilesList)

	adminGroup := apiGroup.Group("")
	adminGroup.Use(AdminOnly())
	{
		adminGroup.POST("/backup/run", RunBackup)
		adminGroup.GET("/backup/list", GetBackupsList)
		adminGroup.GET("/backup/download/:filename", DownloadBackup)
		adminGroup.POST("/backup/upload/:filename", UploadBackupChunk)

		adminGroup.PUT("/settings", updateSettings)
		adminGroup.POST("/settings/test-ai", TestAiConnection)

		adminGroup.GET("/users", GetUsers)
		adminGroup.PUT("/users/:id/role", UpdateUserRole)
		adminGroup.DELETE("/users/:id", DeleteUser)

		adminGroup.GET("/quotas", ListUserQuotas)
		adminGroup.PUT("/quotas/:id", UpdateUserQuota)
		adminGroup.POST("/quotas/:id/refresh", RefreshUserQuota)
		adminGroup.GET("/billing/webhooks", ListBillingWebhookEvents)

		adminGroup.POST("/services/:name/control", controlService)

		adminGroup.POST("/packages/:id/install", InstallPackage)
		adminGroup.POST("/packages/:id/uninstall", UninstallPackage)

		adminGroup.POST("/system/update/run", RunUpdate)

		adminGroup.POST("/fileshare/upload", QuotaUploadGuard(), UploadFile)

		adminGroup.GET("/cluster/nodes", GetClusterNodes)
		adminGroup.POST("/cluster/enroll", EnrollWorker)
		adminGroup.DELETE("/cluster/nodes/:id", RemoveWorker)
		adminGroup.GET("/cluster/nodes/:id/metrics", GetWorkerMetrics)

		adminGroup.GET("/oidc/clients", GetOIDCClients)
		adminGroup.POST("/oidc/clients", CreateOIDCClient)
		adminGroup.DELETE("/oidc/clients/:id", DeleteOIDCClient)

		adminGroup.POST("/ai/metadata/scan", HandleMetadataScan)
		adminGroup.GET("/ai/metadata/status", HandleMetadataStatus)
		adminGroup.GET("/ai/metadata/results", HandleMetadataResults)
		adminGroup.POST("/ai/bandwidth/analyze", HandleBandwidthAnalyze)
		adminGroup.POST("/ai/bandwidth/apply", HandleBandwidthApply)
		adminGroup.GET("/ai/predictions", HandleGetPredictions)
		adminGroup.POST("/ai/predictions/analyze", HandleAnalyzePredictions)
		adminGroup.GET("/ai/predictions/history", HandleGetMetricsHistory)
		adminGroup.GET("/ai/backup/optimal-window", HandleGetOptimalWindow)
		adminGroup.POST("/ai/backup/schedule", HandleSetBackupSchedule)

		adminGroup.GET("/logs", GetLogs)
		adminGroup.GET("/logs/sources", GetLogSources)
		adminGroup.POST("/logs/bookmarks", BookmarkLog)

		adminGroup.GET("/notifications/rules", GetNotificationRules)
		adminGroup.POST("/notifications/rules", CreateNotificationRule)
		adminGroup.PUT("/notifications/rules/:id", UpdateNotificationRule)
		adminGroup.DELETE("/notifications/rules/:id", DeleteNotificationRule)
		adminGroup.GET("/notifications/channels", GetNotificationChannels)
		adminGroup.POST("/notifications/channels", CreateNotificationChannel)
		adminGroup.POST("/notifications/channels/:id/test", TestNotificationChannel)
		adminGroup.DELETE("/notifications/channels/:id", DeleteNotificationChannel)

		adminGroup.GET("/network/status", GetNetworkStatus)
		adminGroup.GET("/network/wireguard/peers", GetWireGuardPeers)
		adminGroup.POST("/network/wireguard/peers", AddWireGuardPeer)
		adminGroup.DELETE("/network/wireguard/peers/:key", RemoveWireGuardPeer)
		adminGroup.POST("/network/wireguard/keygen", GenerateWireGuardKeys)
		adminGroup.GET("/network/tailscale/status", GetTailscaleStatus)
		adminGroup.GET("/network/tailscale/peers", GetTailscalePeers)
		adminGroup.POST("/network/tailscale/routes", AdvertiseTailscaleRoutes)
	}

	apiGroup.POST("/billing/webhooks/:provider", HandleBillingWebhook)

	apiGroup.GET("/services", getServices)

	apiGroup.GET("/marketplace", GetMarketplaceApps)
	apiGroup.GET("/packages/:id/progress", PackageProgress)

	apiGroup.GET("/system/update/check", CheckUpdate)
	apiGroup.GET("/system/hardware", GetHardwareInfo)
	apiGroup.GET("/system/metrics", getSystemMetrics)

	apiGroup.GET("/oidc/jwks", OIDCJwks)
	apiGroup.GET("/oidc/authorize", OIDCAuthorize)
	apiGroup.POST("/oidc/token", OIDCToken)
	apiGroup.GET("/oidc/userinfo", OIDCUserInfo)
	apiGroup.POST("/oidc/revoke", OIDCRevoke)

	apiGroup.GET("/ws/logs", HandleLogWebSocket)

	apiGroup.GET("/notifications", GetNotifications)
	apiGroup.PUT("/notifications/:id/read", MarkNotificationRead)
	apiGroup.POST("/notifications/dismiss-all", DismissAllNotifications)
}

func getSystemMetrics(c *gin.Context) {
	metrics := services.GetSystemMetricsCore()
	c.JSON(http.StatusOK, metrics)
}

func getServices(c *gin.Context) {
	servicesList := services.GetActiveServices()
	c.JSON(http.StatusOK, servicesList)
}

var allowedActions = map[string]bool{"start": true, "stop": true, "restart": true}

func controlService(c *gin.Context) {
	serviceName := c.Param("name")

	var req struct {
		Action    string `json:"action" binding:"required"`
		ManagedBy string `json:"managed_by"`
		Process   string `json:"process"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !allowedActions[req.Action] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid action. Allowed: start, stop, restart"})
		return
	}

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
