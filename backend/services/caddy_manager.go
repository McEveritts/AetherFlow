package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// RoutingState defines the required proxy targets for an application.
type RoutingState struct {
	AppName               string `json:"app_name"`
	ActivePort            int    `json:"active_port"`
	PublicDomain          string `json:"public_domain,omitempty"`
	InternalDomain        string `json:"internal_domain"`
	ExternalAccessEnabled bool   `json:"external_access_enabled"`
}

// CaddyManager handles dynamic JSON updates to Caddy API
type CaddyManager struct {
	APIEndpoint string // e.g. "http://127.0.0.1:2019"
}

// NewCaddyManager creates a new instance of the ingress gateway manager.
func NewCaddyManager(apiEndpoint string) *CaddyManager {
	if apiEndpoint == "" {
		apiEndpoint = "http://127.0.0.1:2019"
	}
	return &CaddyManager{
		APIEndpoint: apiEndpoint,
	}
}

// UpdateAppRoutes hot-reloads the target ports for an application in Caddy.
// It patches replacing the Upstream config for both internal and external routes.
func (cm *CaddyManager) UpdateAppRoutes(state RoutingState) error {
	target := fmt.Sprintf("127.0.0.1:%d", state.ActivePort)

	// Create minimal upstream mutation payload
	upstreamPayload := []map[string]string{
		{"dial": target},
	}

	body, err := json.Marshal(upstreamPayload)
	if err != nil {
		return err
	}

	// 1. Update Internal Switchboard Route
	internalPath := fmt.Sprintf("/config/apps/http/servers/internal/routes/[@id=%s_internal]/handle/0/upstreams", state.AppName)
	if err := cm.patchCaddy(internalPath, body); err != nil {
		return fmt.Errorf("failed to patch internal route for %s: %w", state.AppName, err)
	}

	// 2. Update Public Gateway Route (if ExternalAccessEnabled is true)
	if state.ExternalAccessEnabled && state.PublicDomain != "" {
		publicPath := fmt.Sprintf("/config/apps/http/servers/public/routes/[@id=%s_public]/handle/0/upstreams", state.AppName)
		if err := cm.patchCaddy(publicPath, body); err != nil {
			return fmt.Errorf("failed to patch public route for %s: %w", state.AppName, err)
		}
	}

	return nil
}

// patchCaddy sends a PATCH request directly to the Caddy admin port.
func (cm *CaddyManager) patchCaddy(path string, body []byte) error {
	url := fmt.Sprintf("%s%s", cm.APIEndpoint, path)
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed forming patch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
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
