package api

import (
	"net/http"
	"os"
	"strings"
	"time"

	_ "aetherflow/docs"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
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
	// Apply Host Validation to protect against Open Redirects globally
	apiGroup.Use(HostValidationMiddleware())

	// ── Public routes (no authentication required) ──
	publicGroup := apiGroup.Group("/public")
	publicGroup.GET("/openapi.yaml", GetOpenAPISpec)
	publicGroup.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	publicGroup.GET("/csrf-token", issueCSRFToken)

	authLimiter := RateLimitMiddleware(5, 1*time.Minute)

	publicGroup.GET("/auth/google/login", GoogleLogin)
	publicGroup.GET("/auth/google/callback", GoogleCallback)
	publicGroup.POST("/auth/login", authLimiter, LocalLogin)
	publicGroup.POST("/auth/setup", authLimiter, SetupAdmin)
	publicGroup.GET("/auth/setup/check", CheckSetupNeeded)

	publicGroup.POST("/billing/webhooks/:provider", HandleBillingWebhook)

	publicGroup.GET("/marketplace", GetMarketplaceApps)

	publicGroup.GET("/oidc/jwks", OIDCJwks)
	publicGroup.GET("/oidc/authorize", OIDCAuthorize)
	publicGroup.POST("/oidc/token", OIDCToken)
	publicGroup.GET("/oidc/userinfo", OIDCUserInfo)
	publicGroup.POST("/oidc/revoke", OIDCRevoke)

	publicGroup.POST("/oidc/device/authorize", OIDCDeviceAuthorize)

	// ── Authenticated routes (require valid JWT session) ──
	authGroup := apiGroup.Group("/auth")
	authGroup.Use(AuthMiddleware())
	// CSRF protection is ON by default. Set CSRF_DISABLED=true for local dev only.
	if strings.ToLower(os.Getenv("CSRF_DISABLED")) != "true" {
		authGroup.Use(CSRFMiddleware())
	}
	{
		authGroup.GET("/ws", HandleWebSocket)
		authGroup.GET("/ws/ticket", IssueWSTicket)
		authGroup.POST("/oidc/consent", OIDCConsent)
		authGroup.POST("/oidc/device/verify", OIDCDeviceVerify)
		authGroup.POST("/oidc/device/consent", OIDCDeviceConsent)
		authGroup.POST("/ai/chat", handleAiChat)
		authGroup.POST("/ai/support", handleAiSupport)

		authGroup.GET("/session", GetSession)
		authGroup.POST("/logout", Logout)
		authGroup.PUT("/profile", UpdateProfile)

		authGroup.GET("/user/quota", GetOwnQuota)

		authGroup.GET("/settings", GetSettings)
		authGroup.GET("/fileshare", GetFilesList)

		authGroup.GET("/services", getServices)

		authGroup.GET("/packages/:id/progress", PackageProgress)

		authGroup.GET("/system/update/check", CheckUpdate)
		authGroup.GET("/system/hardware", GetHardwareInfo)

		authGroup.GET("/notifications", GetNotifications)
		authGroup.PUT("/notifications/:id/read", MarkNotificationRead)
		authGroup.POST("/notifications/dismiss-all", DismissAllNotifications)

		authGroup.GET("/ws/logs", HandleLogWebSocket)
	}

	// ── Admin routes (require valid JWT session + admin role) ──
	adminGroup := apiGroup.Group("/admin")
	adminGroup.Use(AuthMiddleware(), AdminOnly())
	{
		// Requires admin context (Phase 8)
		adminGroup.POST("/backup/run", RunBackup)
		// Requires admin context (Phase 8)
		adminGroup.GET("/backup/list", GetBackupsList)
		// Requires admin context (Phase 8)
		adminGroup.GET("/backup/download/:filename", DownloadBackup)
		// Requires admin context (Phase 8)
		adminGroup.POST("/backup/upload/:filename", UploadBackupChunk)

		// Requires admin context (Phase 8)
		adminGroup.PUT("/settings", updateSettings)
		// Requires admin context (Phase 8)
		adminGroup.POST("/settings/test-ai", TestAiConnection)

		// Requires admin context (Phase 8)
		adminGroup.GET("/users", GetUsers)
		// Requires admin context (Phase 8)
		adminGroup.PUT("/users/:id/role", UpdateUserRole)
		// Requires admin context (Phase 8)
		adminGroup.DELETE("/users/:id", DeleteUser)

		// Requires admin context (Phase 8)
		adminGroup.GET("/quotas", ListUserQuotas)
		// Requires admin context (Phase 8)
		adminGroup.PUT("/quotas/:id", UpdateUserQuota)
		// Requires admin context (Phase 8)
		adminGroup.POST("/quotas/:id/refresh", RefreshUserQuota)
		// Requires admin context (Phase 8)
		adminGroup.GET("/billing/webhooks", ListBillingWebhookEvents)

		// Requires admin context (Phase 8)
		adminGroup.POST("/services/:name/control", controlService)

		// Requires admin context (Phase 8)
		adminGroup.POST("/packages/:id/install", InstallPackage)
		// Requires admin context (Phase 8)
		adminGroup.POST("/packages/:id/uninstall", UninstallPackage)

		// Requires admin context (Phase 8)
		adminGroup.POST("/system/update/run", RunUpdate)

		// Requires admin context (Phase 8)
		adminGroup.POST("/fileshare/upload", QuotaUploadGuard(), UploadFile)
		// Requires admin context (Phase 8)
		adminGroup.GET("/fileshare/download/:filename", DownloadFile)

		// Requires admin context (Phase 8)
		adminGroup.GET("/cluster/nodes", GetClusterNodes)
		// Requires admin context (Phase 8)
		adminGroup.POST("/cluster/enroll", EnrollWorker)
		// Requires admin context (Phase 8)
		adminGroup.DELETE("/cluster/nodes/:id", RemoveWorker)
		// Requires admin context (Phase 8)
		adminGroup.GET("/cluster/nodes/:id/metrics", GetWorkerMetrics)

		// Requires admin context (Phase 8)
		adminGroup.GET("/oidc/clients", GetOIDCClients)
		// Requires admin context (Phase 8)
		adminGroup.POST("/oidc/clients", CreateOIDCClient)
		// Requires admin context (Phase 8)
		adminGroup.DELETE("/oidc/clients/:id", DeleteOIDCClient)

		// Requires admin context (Phase 8)
		adminGroup.POST("/ai/metadata/scan", HandleMetadataScan)
		// Requires admin context (Phase 8)
		adminGroup.GET("/ai/metadata/status", HandleMetadataStatus)
		// Requires admin context (Phase 8)
		adminGroup.GET("/ai/metadata/results", HandleMetadataResults)
		// Requires admin context (Phase 8)
		adminGroup.POST("/ai/bandwidth/analyze", HandleBandwidthAnalyze)
		// Requires admin context (Phase 8)
		adminGroup.POST("/ai/bandwidth/apply", HandleBandwidthApply)
		// Requires admin context (Phase 8)
		adminGroup.GET("/ai/predictions", HandleGetPredictions)
		// Requires admin context (Phase 8)
		adminGroup.POST("/ai/predictions/analyze", HandleAnalyzePredictions)
		// Requires admin context (Phase 8)
		adminGroup.GET("/ai/predictions/history", HandleGetMetricsHistory)
		// Requires admin context (Phase 8)
		adminGroup.GET("/ai/backup/optimal-window", HandleGetOptimalWindow)
		// Requires admin context (Phase 8)
		adminGroup.POST("/ai/backup/schedule", HandleSetBackupSchedule)

		// Requires admin context (Phase 8)
		adminGroup.GET("/logs", GetLogs)
		// Requires admin context (Phase 8)
		adminGroup.GET("/logs/sources", GetLogSources)
		// Requires admin context (Phase 8)
		adminGroup.POST("/logs/bookmarks", BookmarkLog)
		// Requires admin context (Phase 8)
		adminGroup.GET("/logs/bookmarks", GetBookmarks)

		// Requires admin context (Phase 8)
		adminGroup.GET("/notifications/rules", GetNotificationRules)
		// Requires admin context (Phase 8)
		adminGroup.POST("/notifications/rules", CreateNotificationRule)
		// Requires admin context (Phase 8)
		adminGroup.PUT("/notifications/rules/:id", UpdateNotificationRule)
		// Requires admin context (Phase 8)
		adminGroup.DELETE("/notifications/rules/:id", DeleteNotificationRule)
		// Requires admin context (Phase 8)
		adminGroup.GET("/notifications/channels", GetNotificationChannels)
		// Requires admin context (Phase 8)
		adminGroup.POST("/notifications/channels", CreateNotificationChannel)
		// Requires admin context (Phase 8)
		adminGroup.POST("/notifications/channels/:id/test", TestNotificationChannel)
		// Requires admin context (Phase 8)
		adminGroup.DELETE("/notifications/channels/:id", DeleteNotificationChannel)

		// Requires admin context (Phase 8)
		adminGroup.GET("/network/status", GetNetworkStatus)
		// Requires admin context (Phase 8)
		adminGroup.GET("/network/wireguard/peers", GetWireGuardPeers)
		// Requires admin context (Phase 8)
		adminGroup.POST("/network/wireguard/peers", AddWireGuardPeer)
		// Requires admin context (Phase 8)
		adminGroup.DELETE("/network/wireguard/peers/:key", RemoveWireGuardPeer)
		// Requires admin context (Phase 8)
		adminGroup.POST("/network/wireguard/keygen", GenerateWireGuardKeys)
		// Requires admin context (Phase 8)
		adminGroup.GET("/network/tailscale/status", GetTailscaleStatus)
		// Requires admin context (Phase 8)
		adminGroup.GET("/network/tailscale/peers", GetTailscalePeers)
		// Requires admin context (Phase 8)
		adminGroup.POST("/network/tailscale/routes", AdvertiseTailscaleRoutes)

		// System metrics are admin-only to prevent information disclosure (CWE-284)
		// Requires admin context (Phase 8)
		adminGroup.GET("/system/metrics", getSystemMetrics)
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
