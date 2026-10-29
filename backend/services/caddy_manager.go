package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// RoutingState defines the required proxy targets for an application.
type RoutingState struct {
	AppName               string `json:"app_name"`
	ActivePort            int    `json:"active_port"`
	PublicDomain          string `json:"public_domain,omitempty"`
	InternalDomain        string `json:"internal_domain"`
	ExternalAccessEnabled bool   `json:"external_access_enabled"`
}

// CaddyManager handles dynamic route synchronization.
// On Apache2-fronted AetherFlow servers (the default architecture), AetherFlow's
// built-in AppSubdomainProxyMiddleware resolves routes directly from SQLite,
// so Caddy Admin API calls are skipped cleanly when no Caddy listener is active.
type CaddyManager struct {
	APIEndpoint string // e.g. "http://127.0.0.1:2019"
	Optional    bool   // true when using default endpoint without explicit AETHERFLOW_CADDY_ENDPOINT
}

// NewCaddyManager creates a new instance of the ingress gateway manager.
func NewCaddyManager(apiEndpoint string) *CaddyManager {
	optional := false
	if apiEndpoint == "" {
		if envEndpoint := strings.TrimSpace(os.Getenv("AETHERFLOW_CADDY_ENDPOINT")); envEndpoint != "" {
			apiEndpoint = envEndpoint
		} else {
			apiEndpoint = "http://127.0.0.1:2019"
			optional = true
		}
	}
	return &CaddyManager{
		APIEndpoint: apiEndpoint,
		Optional:    optional,
	}
}

// isCaddyReachable performs a fast loopback TCP check when Caddy is optional
// (Apache2 + built-in AppSubdomainProxyMiddleware is primary) to avoid 3s HTTP timeouts.
func (cm *CaddyManager) isCaddyReachable() bool {
	if !cm.Optional {
		return true
	}
	parsed, err := url.Parse(cm.APIEndpoint)
	if err != nil || parsed.Host == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", parsed.Host, 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// buildCaddyRoute constructs a full Caddy HTTP route object with @id, host matcher, and reverse_proxy handler.
func buildCaddyRoute(routeID, domain, dialTarget string) ([]byte, error) {
	route := map[string]interface{}{
		"@id": routeID,
		"match": []map[string]interface{}{
			{
				"host": []string{domain},
			},
		},
		"handle": []map[string]interface{}{
			{
				"handler": "reverse_proxy",
				"upstreams": []map[string]string{
					{"dial": dialTarget},
				},
			},
		},
		"terminal": true,
	}
	return json.Marshal(route)
}

// UpdateAppRoutes hot-reloads or upserts the target routes and ports for an application.
// When Apache2 + AppSubdomainProxyMiddleware is active without a local Caddy listener,
// routing is already live via SQLite and this returns nil immediately.
func (cm *CaddyManager) UpdateAppRoutes(state RoutingState) error {
	if !cm.isCaddyReachable() {
		return nil
	}
	target := fmt.Sprintf("127.0.0.1:%d", state.ActivePort)

	upstreamPayload := []map[string]string{
		{"dial": target},
	}
	body, err := json.Marshal(upstreamPayload)
	if err != nil {
		return err
	}

	internalDomain := state.InternalDomain
	if internalDomain == "" {
		internalDomain = fmt.Sprintf("%s.aether.local", state.AppName)
	}

	// 1. Upsert Internal Switchboard Route
	internalRouteID := fmt.Sprintf("%s_internal", state.AppName)
	internalPath := fmt.Sprintf("/config/apps/http/servers/internal/routes/[@id=%s]/handle/0/upstreams", internalRouteID)
	if err := cm.patchCaddy(internalPath, body); err != nil {
		routeBody, mErr := buildCaddyRoute(internalRouteID, internalDomain, target)
		if mErr != nil {
			return mErr
		}
		if postErr := cm.postCaddy("/config/apps/http/servers/internal/routes", routeBody); postErr != nil {
			return fmt.Errorf("failed to upsert internal route for %s: %w", state.AppName, err)
		}
	}

	// 2. Upsert or Remove Public Gateway Route
	publicRouteID := fmt.Sprintf("%s_public", state.AppName)
	if state.ExternalAccessEnabled && state.PublicDomain != "" {
		publicPath := fmt.Sprintf("/config/apps/http/servers/public/routes/[@id=%s]/handle/0/upstreams", publicRouteID)
		if err := cm.patchCaddy(publicPath, body); err != nil {
			routeBody, mErr := buildCaddyRoute(publicRouteID, state.PublicDomain, target)
			if mErr != nil {
				return mErr
			}
			if postErr := cm.postCaddy("/config/apps/http/servers/public/routes", routeBody); postErr != nil {
				return fmt.Errorf("failed to upsert public route for %s: %w", state.AppName, err)
			}
		} else {
			// Also sync the host matcher in case PublicDomain changed
			hostPayload, _ := json.Marshal([]string{state.PublicDomain})
			hostPath := fmt.Sprintf("/config/apps/http/servers/public/routes/[@id=%s]/match/0/host", publicRouteID)
			_ = cm.patchCaddy(hostPath, hostPayload)
		}
	} else {
		// Remove public route if external access was disabled
		deletePath := fmt.Sprintf("/config/apps/http/servers/public/routes/[@id=%s]", publicRouteID)
		_ = cm.deleteCaddy(deletePath)
	}

	return nil
}

// RemoveAppRoutes deletes both internal and public routes for an uninstalled application.
func (cm *CaddyManager) RemoveAppRoutes(appName string) error {
	cleanName := strings.ToLower(strings.TrimSpace(appName))
	if cleanName == "" {
		return nil
	}
	if !cm.isCaddyReachable() {
		return nil
	}
	internalRouteID := fmt.Sprintf("%s_internal", cleanName)
	publicRouteID := fmt.Sprintf("%s_public", cleanName)

	internalErr := cm.deleteCaddy(fmt.Sprintf("/config/apps/http/servers/internal/routes/[@id=%s]", internalRouteID))
	_ = cm.deleteCaddy(fmt.Sprintf("/config/apps/http/servers/public/routes/[@id=%s]", publicRouteID))
	return internalErr
}

func (cm *CaddyManager) doRequest(method, path string, body []byte) error {
	url := fmt.Sprintf("%s%s", cm.APIEndpoint, path)
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, url, bytes.NewBuffer(body))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		return fmt.Errorf("failed forming %s request: %w", method, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("caddy API connection error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("caddy API returned error status: %d", resp.StatusCode)
	}

	return nil
}

// patchCaddy sends a PATCH request directly to the Caddy admin port.
func (cm *CaddyManager) patchCaddy(path string, body []byte) error {
	return cm.doRequest(http.MethodPatch, path, body)
}

// postCaddy sends a POST request to append a route to a Caddy server routes array.
func (cm *CaddyManager) postCaddy(path string, body []byte) error {
	return cm.doRequest(http.MethodPost, path, body)
}

// deleteCaddy sends a DELETE request to remove a route by @id from Caddy.
func (cm *CaddyManager) deleteCaddy(path string) error {
	return cm.doRequest(http.MethodDelete, path, nil)
}
