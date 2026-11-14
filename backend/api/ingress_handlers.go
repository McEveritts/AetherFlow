package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
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

	var input struct {
		PublicDomain          *string `json:"publicDomain"`
		ExternalAccessEnabled *bool   `json:"externalAccessEnabled"`
		ListenPort            *int    `json:"listenPort"`
		TLSEnabled            *bool   `json:"tlsEnabled"`
	}

	if err := c.ShouldBindJSON(&input); err != nil {
		BadRequest(c, err.Error())
		return
	}
	existing, err := db.GetAppIngressConfig(appName)
	if err != nil {
		InternalError(c, "Failed to read existing ingress configuration")
		return
	}
	var req struct {
		PublicDomain          string
		ExternalAccessEnabled bool
		ListenPort            int
		TLSEnabled            bool
	}
	if existing != nil {
		req.PublicDomain = existing.PublicDomain
		req.ExternalAccessEnabled = existing.ExternalAccessEnabled
		req.TLSEnabled = existing.TLSEnabled
	}
	if input.PublicDomain != nil {
		req.PublicDomain = *input.PublicDomain
	}
	if input.ExternalAccessEnabled != nil {
		req.ExternalAccessEnabled = *input.ExternalAccessEnabled
	}
	if existing == nil {
		if input.ExternalAccessEnabled == nil {
			req.ExternalAccessEnabled = strings.TrimSpace(req.PublicDomain) != ""
		}
		if input.TLSEnabled == nil {
			req.TLSEnabled = strings.TrimSpace(req.PublicDomain) != ""
		}
	}
	if input.ListenPort != nil {
		req.ListenPort = *input.ListenPort
	}
	if input.TLSEnabled != nil {
		req.TLSEnabled = *input.TLSEnabled
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

	currentPort := 0
	if existing != nil && existing.ListenPort > 0 {
		currentPort = existing.ListenPort
	} else if bp := services.GetBlueprint(appName); bp != nil {
		currentPort = bp.DefaultPort
	}
	if listenPort != currentPort {
		RespondError(c, http.StatusConflict, "PORT_RECONFIGURATION_UNSUPPORTED", "Native listen-port changes require verified package reconfiguration; the existing mapping was preserved")
		return
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
			isPrivateOrLoopbackIP := func(raw string) bool {
				trimmed := strings.Trim(strings.TrimSpace(raw), "[]")
				if trimmed == "" {
					return false
				}
				ip := net.ParseIP(trimmed)
				if ip == nil {
					return false
				}
				return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
			}
			allowed := true
			if remoteAddr := strings.TrimSpace(c.Request.RemoteAddr); remoteAddr != "" {
				remoteIP := remoteAddr
				if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
					remoteIP = host
				}
				if strings.TrimSpace(remoteIP) != "" && !isPrivateOrLoopbackIP(remoteIP) {
					allowed = false
				}
			}
			if allowed && isTrustedProxyPeer(c) {
				if xri := strings.TrimSpace(c.GetHeader("X-Real-IP")); xri != "" && !isPrivateOrLoopbackIP(xri) {
					allowed = false
				}
				if xff := strings.TrimSpace(c.GetHeader("X-Forwarded-For")); xff != "" {
					for _, hop := range strings.Split(xff, ",") {
						if !isPrivateOrLoopbackIP(hop) {
							allowed = false
							break
						}
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

		incomingHost := c.Request.Host
		upgradeHeader := strings.TrimSpace(c.GetHeader("Upgrade"))
		authenticatedUser := ""
		if _, _, subj, err := resolveSessionTokenWithSubject(c); err == nil {
			authenticatedUser = subj.username
		}
		proxy := &httputil.ReverseProxy{
			FlushInterval: -1,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.SetURL(targetURL)
				pr.Out.Host = incomingHost
				if upgradeHeader != "" {
					pr.Out.Header.Set("Upgrade", upgradeHeader)
					pr.Out.Header.Set("Connection", "Upgrade")
				}
				pr.Out.Header.Del("X-Aetherflow-User")
				if authenticatedUser != "" {
					pr.Out.Header.Set("X-Aetherflow-User", authenticatedUser)
				}
				peerIP := ""
				if host, _, err := net.SplitHostPort(strings.TrimSpace(pr.In.RemoteAddr)); err == nil {
					peerIP = strings.Trim(host, "[]")
				} else if ip := net.ParseIP(strings.Trim(strings.TrimSpace(pr.In.RemoteAddr), "[]")); ip != nil {
					peerIP = ip.String()
				}
				parsedPeer := net.ParseIP(peerIP)
				trustForwarded := parsedPeer != nil && isConfiguredTrustedProxyIP(parsedPeer)
				if !trustForwarded {
					for _, hdr := range []string{
						"Forwarded",
						"X-Forwarded-For",
						"X-Forwarded-Host",
						"X-Forwarded-Proto",
						"X-Forwarded-Port",
						"X-Forwarded-Server",
						"X-Real-IP",
					} {
						pr.Out.Header.Del(hdr)
					}
					if peerIP != "" {
						pr.Out.Header.Set("X-Forwarded-For", peerIP)
						pr.Out.Header.Set("X-Real-IP", peerIP)
					}
					pr.Out.Header.Set("X-Forwarded-Host", incomingHost)
					pr.Out.Header.Set("X-Forwarded-Proto", "http")
					return
				}

				pr.SetXForwarded()
				if priorHost := strings.TrimSpace(pr.In.Header.Get("X-Forwarded-Host")); priorHost != "" {
					pr.Out.Header.Set("X-Forwarded-Host", priorHost)
				} else {
					pr.Out.Header.Set("X-Forwarded-Host", incomingHost)
				}
				switch strings.ToLower(strings.TrimSpace(pr.In.Header.Get("X-Forwarded-Proto"))) {
				case "https":
					pr.Out.Header.Set("X-Forwarded-Proto", "https")
				default:
					pr.Out.Header.Set("X-Forwarded-Proto", "http")
				}
				if realIP := strings.Trim(strings.TrimSpace(pr.In.Header.Get("X-Real-IP")), "[]"); net.ParseIP(realIP) != nil {
					pr.Out.Header.Set("X-Real-IP", realIP)
				} else if peerIP != "" {
					pr.Out.Header.Set("X-Real-IP", peerIP)
				}
			},
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
