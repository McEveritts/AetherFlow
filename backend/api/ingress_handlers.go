package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
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
// Synchronizes dynamically with the built-in Subdomain Gateway, Apache2 Certbot SANs, and DNSManager.
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

	// Hot-sync with local DNS manager
	internalDomain := fmt.Sprintf("%s.aether.local", appName)
	dnsMgr := services.NewDNSManager()
	if err := dnsMgr.AppendOrUpdateDomains([]string{internalDomain}); err != nil {
		slog.Warn("local dns hot-reload notice", "app", appName, "warning", err)
	}

	// Sync blueprint native config, networking DNS providers (Pi-hole / dnsmasq), and Apache Let's Encrypt SANs
	if bp := services.GetBlueprint(appName); bp != nil {
		_, _, _ = services.ApplyBlueprintAppConfig(bp, listenPort)
	}
	_, _ = services.SyncNetworkDNSProviders()
	if cfg.ExternalAccessEnabled && cfg.PublicDomain != "" {
		services.TriggerApacheCertSync()
	}

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

// AppSubdomainProxyMiddleware intercepts incoming HTTP and WebSocket requests whose Host
// header matches an installed application's public subdomain (e.g., qbittorrent.example.com)
// or internal domain (<app>.aether.local) and reverse-proxies them directly to 127.0.0.1:<port>.
// This allows Apache2-fronted deployments to transparently route all application subdomains
// through the single AetherFlow gateway port.
func AppSubdomainProxyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetBool("af_subdomain_checked") {
			c.Next()
			return
		}
		c.Set("af_subdomain_checked", true)

		if strings.HasPrefix(c.Request.URL.Path, "/.well-known/acme-challenge/") {
			c.Next()
			return
		}

		cleanHost := strings.ToLower(strings.TrimSpace(c.Request.Host))
		if idx := strings.LastIndex(cleanHost, ":"); idx != -1 && !strings.Contains(cleanHost[idx:], "]") {
			cleanHost = cleanHost[:idx]
		}
		cleanHost = strings.TrimSuffix(cleanHost, ".")
		if cleanHost == "aether.local" || strings.HasSuffix(cleanHost, ".aether.local") {
			isPrivateIP := regexp.MustCompile(`^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|::1$|\[::1\]|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:|fe80:)`).MatchString
			allowed := true
			if remoteAddr := strings.ToLower(strings.TrimSpace(c.Request.RemoteAddr)); remoteAddr != "" {
				remoteIP := remoteAddr
				if idx := strings.LastIndex(remoteIP, ":"); idx != -1 && !strings.Contains(remoteIP[idx:], "]") {
					remoteIP = strings.Trim(remoteIP[:idx], "[]")
				}
				if remoteIP != "" && !isPrivateIP(remoteIP) {
					allowed = false
				}
			}
			if xff := strings.TrimSpace(c.GetHeader("X-Forwarded-For")); xff != "" {
				for _, hop := range strings.Split(xff, ",") {
					hopIP := strings.ToLower(strings.Trim(strings.TrimSpace(hop), "[]"))
					if hopIP == "" || !isPrivateIP(hopIP) {
						allowed = false
						break
					}
				}
			}
			if !allowed {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Internal .aether.local domains are restricted to local network clients"})
				return
			}
		}

		targetPort, appName, matched := services.ResolveAppTargetForHost(c.Request.Host)
		if !matched || targetPort <= 0 {
			c.Next()
			return
		}

		targetURL := &url.URL{
			Scheme: "http",
			Host:   fmt.Sprintf("127.0.0.1:%d", targetPort),
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.FlushInterval = -1
		origDirector := proxy.Director
		incomingHost := c.Request.Host
		upgradeHeader := strings.TrimSpace(c.GetHeader("Upgrade"))
		authenticatedUser := ""
		if _, claims, err := resolveSessionToken(c); err == nil && db.DB != nil {
			if userIDFloat, ok := claims["user_id"].(float64); ok {
				_ = db.DB.QueryRow("SELECT username FROM users WHERE id = ?", int(userIDFloat)).Scan(&authenticatedUser)
			}
		}
		proxy.Director = func(req *http.Request) {
			origDirector(req)
			req.Host = incomingHost
			if upgradeHeader != "" {
				req.Header.Set("Upgrade", upgradeHeader)
				req.Header.Set("Connection", "Upgrade")
			}
			req.Header.Del("X-Aetherflow-User")
			if authenticatedUser != "" {
				req.Header.Set("X-Aetherflow-User", authenticatedUser)
			}
			if req.Header.Get("X-Forwarded-Host") == "" {
				req.Header.Set("X-Forwarded-Host", incomingHost)
			}
			if req.Header.Get("X-Forwarded-Proto") == "" {
				if c.Request.TLS != nil {
					req.Header.Set("X-Forwarded-Proto", "https")
				} else {
					req.Header.Set("X-Forwarded-Proto", "http")
				}
			}
		}
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("subdomain reverse proxy upstream error", "app", appName, "host", incomingHost, "port", targetPort, "error", err)
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprintf(w, `{"error":"bad_gateway","message":"Upstream service %s on port %d is unavailable."}`, appName, targetPort)
		}

		reqCtx, cancel := context.WithCancel(c.Request.Context())
		defer cancel()
		proxy.ServeHTTP(c.Writer, c.Request.WithContext(reqCtx))
		c.Abort()
	}
}

