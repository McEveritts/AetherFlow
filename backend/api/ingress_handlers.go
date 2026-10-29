package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"aetherflow/db"
	"aetherflow/models"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// GetIngressConfigs returns all application ingress routing configurations from app_ingress_configs.
func GetIngressConfigs(c *gin.Context) {
	configs, err := db.GetAllAppIngressConfigs()
	if err != nil {
		slog.Error("failed to query ingress configs from app_ingress_configs", "error", err)
		InternalError(c, "Failed to load ingress configurations")
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"configs": configs,
	})
}

// UpdateAppIngressConfig updates or creates an ingress route for a specific application.
// Persists configuration records into the SQLite app_ingress_configs table.
// Synchronizes dynamically with CaddyManager and DNSManager.
func UpdateAppIngressConfig(c *gin.Context) {
	appName := strings.TrimSpace(c.Param("appName"))
	if appName == "" {
		BadRequest(c, "Application name is required")
		return
	}

	var req struct {
		PublicDomain          string `json:"publicDomain"`
		ExternalAccessEnabled bool   `json:"externalAccessEnabled"`
		ListenPort            int    `json:"listenPort"`
		TLSEnabled            bool   `json:"tlsEnabled"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, err.Error())
		return
	}

	// Validate publicDomain format and requirements
	trimmedDomain := strings.TrimSpace(req.PublicDomain)
	if req.ExternalAccessEnabled && trimmedDomain == "" {
		RespondError(c, http.StatusBadRequest, "INVALID_DOMAIN", "Invalid public domain format")
		return
	}
	if req.PublicDomain != "" {
		if req.PublicDomain != trimmedDomain || !domainRegex.MatchString(trimmedDomain) || len(trimmedDomain) > 253 {
			RespondError(c, http.StatusBadRequest, "INVALID_DOMAIN", "Invalid public domain format")
			return
		}
	}

	// Validate listenPort
	listenPort := req.ListenPort
	if listenPort != 0 {
		if listenPort < 1 || listenPort > 65535 {
			RespondError(c, http.StatusBadRequest, "INVALID_PORT", "Listen port must be between 1 and 65535")
			return
		}
	} else {
		// Port not provided (0), resolve from existing configuration or blueprint
		if existing, _ := db.GetAppIngressConfig(appName); existing != nil && existing.ListenPort > 0 {
			listenPort = existing.ListenPort
		} else if bp := services.GetBlueprint(appName); bp != nil && bp.DefaultPort > 0 {
			listenPort = bp.DefaultPort
		}
		if listenPort < 1 || listenPort > 65535 {
			RespondError(c, http.StatusBadRequest, "INVALID_PORT", "Listen port must be between 1 and 65535")
			return
		}
	}

	cfg := models.AppIngressConfig{
		AppName:               appName,
		PublicDomain:          strings.TrimSpace(req.PublicDomain),
		ExternalAccessEnabled: req.ExternalAccessEnabled,
		ListenPort:            listenPort,
		TLSEnabled:            req.TLSEnabled,
	}

	if err := db.SetAppIngressConfig(cfg); err != nil {
		slog.Error("failed to save ingress config", "app", appName, "error", err)
		InternalError(c, "Failed to persist ingress configuration")
		return
	}

	// Hot-sync with Caddy proxy if available
	caddyMgr := services.NewCaddyManager("")
	internalDomain := fmt.Sprintf("%s.aether.local", appName)
	routingState := services.RoutingState{
		AppName:               appName,
		ActivePort:            listenPort,
		PublicDomain:          cfg.PublicDomain,
		InternalDomain:        internalDomain,
		ExternalAccessEnabled: cfg.ExternalAccessEnabled,
	}
	if err := caddyMgr.UpdateAppRoutes(routingState); err != nil {
		slog.Warn("caddy route hot-reload notice", "app", appName, "warning", err)
	}

	// Hot-sync with local DNS manager
	dnsMgr := services.NewDNSManager()
	if err := dnsMgr.AppendOrUpdateDomains([]string{internalDomain}); err != nil {
		slog.Warn("local dns hot-reload notice", "app", appName, "warning", err)
	}

	// Sync blueprint native config and networking DNS providers (Pi-hole / dnsmasq)
	if bp := services.GetBlueprint(appName); bp != nil {
		_, _, _ = services.ApplyBlueprintAppConfig(bp, listenPort)
	}
	_, _ = services.SyncNetworkDNSProviders()

	actorID, _ := c.Get("user_id")
	actorName, _ := c.Get("username")
	aid, _ := actorID.(int)
	aname, _ := actorName.(string)
	db.RecordAudit(aid, aname, "ingress_update", "app", appName, fmt.Sprintf("public_domain=%s, external=%t, port=%d", cfg.PublicDomain, cfg.ExternalAccessEnabled, cfg.ListenPort), c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{
		"message": "Ingress configuration updated successfully",
		"config":  cfg,
	})
}
