package api

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"aetherflow/config"
	"aetherflow/db"
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

type TopologyNode struct {
	ID      string `json:"id"`
	Group   int    `json:"group"`
	Status  string `json:"status"` // "running", "stopped", "degraded"
	Details string `json:"details"`
}

type TopologyLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Value  int    `json:"value"`
}

type TopologyResponse struct {
	Nodes []TopologyNode `json:"nodes"`
	Links []TopologyLink `json:"links"`
}

// GetSystemTopology godoc
// @Summary      Get live system topology
// @Description  Returns real live infrastructure topology nodes and links.
// @Tags         system
// @Produce      json
// @Security     ApiKeyAuth
// @Success      200  {object}  TopologyResponse
// @Router       /auth/system/topology [get]
func GetSystemTopology(c *gin.Context) {
	nodes := []TopologyNode{}
	links := []TopologyLink{}

	// 1. AetherFlow API
	apiPort := "8080"
	if config.Cfg != nil && config.Cfg.Port != "" {
		apiPort = config.Cfg.Port
	}
	nodes = append(nodes, TopologyNode{
		ID:      "AetherFlow API",
		Group:   1,
		Status:  "running",
		Details: fmt.Sprintf("Port %s", apiPort),
	})

	// 2. Runner Daemon
	runnerStatus := "stopped"
	runnerDetails := "Socket offline / direct mode"
	if services.IsRunnerAvailable() {
		runnerStatus = "running"
		runnerDetails = services.RunnerSocketPath()
	}
	nodes = append(nodes, TopologyNode{
		ID:      "Runner Daemon",
		Group:   1,
		Status:  runnerStatus,
		Details: runnerDetails,
	})
	links = append(links, TopologyLink{
		Source: "AetherFlow API",
		Target: "Runner Daemon",
		Value:  1,
	})

	// 3. SQLite Database
	dbStatus := "running"
	var journalMode string
	if err := db.DB.QueryRow("PRAGMA journal_mode;").Scan(&journalMode); err != nil {
		dbStatus = "degraded"
		journalMode = "unknown"
	}
	nodes = append(nodes, TopologyNode{
		ID:      "SQLite WAL",
		Group:   2,
		Status:  dbStatus,
		Details: fmt.Sprintf("SQLite (%s mode)", strings.ToUpper(journalMode)),
	})
	links = append(links, TopologyLink{
		Source: "AetherFlow API",
		Target: "SQLite WAL",
		Value:  1,
	})

	// 4. Redis Cache
	redisStatus := "stopped"
	redisDetails := "Disabled / Memory cache active"
	if db.RedisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		if err := db.RedisClient.Ping(ctx).Err(); err == nil {
			redisStatus = "running"
			redisDetails = "Connected"
		} else {
			redisStatus = "degraded"
			redisDetails = "Connection timeout"
		}
	}
	nodes = append(nodes, TopologyNode{
		ID:      "Redis Cache",
		Group:   2,
		Status:  redisStatus,
		Details: redisDetails,
	})
	if redisStatus == "running" {
		links = append(links, TopologyLink{
			Source: "AetherFlow API",
			Target: "Redis Cache",
			Value:  1,
		})
	}

	// 5. Caddy Reverse Proxy
	caddyStatus := "stopped"
	caddyDetails := "Port 443 / 80"
	client := &http.Client{Timeout: 500 * time.Millisecond}
	resp, err := client.Get("http://127.0.0.1:2019/config/")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 500 {
			caddyStatus = "running"
			caddyDetails = "Caddy Admin API active (443 / 80)"
		}
	}
	if caddyStatus == "stopped" {
		st, _, _ := services.GetServiceInfo("caddy")
		if st == "running" {
			caddyStatus = "running"
		} else {
			nst, _, _ := services.GetServiceInfo("nginx")
			if nst == "running" {
				caddyStatus = "running"
				caddyDetails = "Nginx active (443 / 80)"
			}
		}
	}
	nodes = append(nodes, TopologyNode{
		ID:      "Caddy Reverse Proxy",
		Group:   3,
		Status:  caddyStatus,
		Details: caddyDetails,
	})
	links = append(links, TopologyLink{
		Source: "Caddy Reverse Proxy",
		Target: "AetherFlow API",
		Value:  1,
	})

	// 6. Installed and Running App Services
	if pkgs, err := services.GetPackages(); err == nil {
		for _, pkg := range pkgs {
			if pkg.Status == "running" && pkg.Name != "" {
				displayName := pkg.Label
				if displayName == "" {
					displayName = pkg.Name
				}
				detailStr := "Running"
				if ingressCfg, err := db.GetAppIngressConfig(pkg.Name); err == nil && ingressCfg != nil && ingressCfg.ListenPort > 0 {
					detailStr = fmt.Sprintf("Port %d", ingressCfg.ListenPort)
				} else if bp := services.GetBlueprint(pkg.Name); bp != nil && bp.DefaultPort > 0 {
					detailStr = fmt.Sprintf("Port %d", bp.DefaultPort)
				}
				nodes = append(nodes, TopologyNode{
					ID:      displayName,
					Group:   4,
					Status:  "running",
					Details: detailStr,
				})
				links = append(links, TopologyLink{
					Source: "Caddy Reverse Proxy",
					Target: displayName,
					Value:  1,
				})
			}
		}
	}

	c.JSON(http.StatusOK, TopologyResponse{
		Nodes: nodes,
		Links: links,
	})
}
