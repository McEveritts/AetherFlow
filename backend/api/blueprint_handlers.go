package api

import (
	"fmt"
	"net/http"
	"strings"

	"aetherflow/db"
	"aetherflow/models"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// BlueprintStatusView represents a blueprint enriched with live runtime port and ingress state.
type BlueprintStatusView struct {
	services.AppBlueprint
	ActivePort            int    `json:"active_port"`
	PortReassigned        bool   `json:"port_reassigned"`
	PublicDomain          string `json:"public_domain,omitempty"`
	ExternalAccessEnabled bool   `json:"external_access_enabled"`
	TLSEnabled            bool   `json:"tls_enabled"`
}

// GetBlueprints returns all catalog blueprints merged with live ingress state.
func GetBlueprints(c *gin.Context) {
	bps := services.GetAllBlueprints()
	ingressMap := make(map[string]models.AppIngressConfig)
	if configs, err := db.GetAllAppIngressConfigs(); err == nil {
		for _, cfg := range configs {
			ingressMap[cfg.AppName] = cfg
		}
	}

	views := make([]BlueprintStatusView, 0, len(bps))
	for _, bp := range bps {
		activePort := bp.DefaultPort
		reassigned := false
		var pubDomain string
		var extAccess, tlsEnabled bool

		if ing, exists := ingressMap[bp.AppName]; exists {
			if ing.ListenPort > 0 {
				activePort = ing.ListenPort
				reassigned = activePort != bp.DefaultPort
			}
			pubDomain = ing.PublicDomain
			extAccess = ing.ExternalAccessEnabled
			tlsEnabled = ing.TLSEnabled
		}

		views = append(views, BlueprintStatusView{
			AppBlueprint:          bp,
			ActivePort:            activePort,
			PortReassigned:        reassigned,
			PublicDomain:          pubDomain,
			ExternalAccessEnabled: extAccess,
			TLSEnabled:            tlsEnabled,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"blueprints": views,
	})
}

// GetAppBlueprint returns a specific app's blueprint and live managed configuration.
func GetAppBlueprint(c *gin.Context) {
	appName := strings.TrimSpace(c.Param("appName"))
	if appName == "" {
		BadRequest(c, "Application name is required")
		return
	}

	bp := services.GetBlueprint(appName)
	if bp == nil {
		NotFoundError(c, fmt.Sprintf("Blueprint not found for %s", appName))
		return
	}

	activePort := bp.DefaultPort
	reassigned := false
	var pubDomain string
	var extAccess, tlsEnabled bool

	if ing, err := db.GetAppIngressConfig(bp.AppName); err == nil && ing != nil {
		if ing.ListenPort > 0 {
			activePort = ing.ListenPort
			reassigned = activePort != bp.DefaultPort
		}
		pubDomain = ing.PublicDomain
		extAccess = ing.ExternalAccessEnabled
		tlsEnabled = ing.TLSEnabled
	}

	c.JSON(http.StatusOK, BlueprintStatusView{
		AppBlueprint:          *bp,
		ActivePort:            activePort,
		PortReassigned:        reassigned,
		PublicDomain:          pubDomain,
		ExternalAccessEnabled: extAccess,
		TLSEnabled:            tlsEnabled,
	})
}

// SyncAppBlueprint triggers on-demand blueprint application (dynamic port check,
// config mutation, Caddy route upsert, /etc/hosts registration, and Pi-hole/DNS sync).
func SyncAppBlueprint(c *gin.Context) {
	appName := strings.TrimSpace(c.Param("appName"))
	if appName == "" {
		BadRequest(c, "Application name is required")
		return
	}

	bp := services.GetBlueprint(appName)
	if bp == nil {
		NotFoundError(c, fmt.Sprintf("Blueprint not found for %s", appName))
		return
	}

	res, err := services.ApplyBlueprintPostInstall(bp.AppName, 0)
	if err != nil {
		InternalError(c, fmt.Sprintf("Failed to synchronize blueprint for %s: %v", bp.AppName, err))
		return
	}

	actorID, _ := c.Get("user_id")
	actorName, _ := c.Get("username")
	aid, _ := actorID.(int)
	aname, _ := actorName.(string)
	db.RecordAudit(aid, aname, "blueprint_sync", "app", bp.AppName, fmt.Sprintf("port=%d, domain=%s", res.AllocatedPort, res.InternalDomain), c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{
		"message": "Blueprint synchronized successfully",
		"result":  res,
	})
}
