package services

import (
	"aetherflow/db"
	"aetherflow/models"
	"log/slog"
	"strings"

	"github.com/gin-gonic/gin"
)

// Systemd core services to always check
var systemdCoreServices = map[string]string{
	"AetherFlow API":      "aetherflow-api",
	"AetherFlow Frontend": "aetherflow-frontend",
	"Apache2 Web Server":  "apache2",
}

// GetActiveServices pulls packages from the marketplace JSON,
// and merges OS runtime status info. It also appends core system services.
func GetActiveServices() map[string]interface{} {
	servicesList := make(map[string]interface{})

	// 2. Core Systemd Services
	for displayName, systemdName := range systemdCoreServices {
		status, uptime, version := GetServiceInfo(systemdName)
		managedBy := "systemd"
		// In single-binary architecture, the frontend SPA is embedded directly inside aetherflow-api.
		if systemdName == "aetherflow-frontend" && status == "stopped" {
			if apiSt, apiUp, apiVer := GetServiceInfo("aetherflow-api"); apiSt == "running" {
				status = apiSt
				uptime = apiUp
				version = apiVer
				managedBy = "embedded"
			}
		}
		servicesList[displayName] = gin.H{
			"status":     status,
			"uptime":     uptime,
			"version":    version,
			"managed_by": managedBy,
			"process":    systemdName,
			"id":         systemdName,
		}
	}

	// 3. Get Marketplace Packages — only installed ones
	pkgs, err := GetPackages()
	if err != nil {
		slog.Info("[services] unable to load package catalog", "error", err)
		return servicesList
	}

	ingressMap := make(map[string]models.AppIngressConfig)
	if configs, err := db.GetAllAppIngressConfigs(); err == nil {
		for _, cfg := range configs {
			ingressMap[cfg.AppName] = cfg
		}
	}
	baseDomain := ResolveBaseDomain()

	for _, pkg := range pkgs {
		if pkg.Status != "installed" && pkg.Status != "running" {
			continue
		}

		// Use ServiceName from packages.json if available, else fall back to package name
		serviceName := pkg.ServiceName
		if serviceName == "" {
			serviceName = pkg.Name
		}

		var status, uptime, version string
		managedBy := "systemd"

		status, uptime, version = GetServiceInfo(serviceName)

		if version == "-" {
			if pkg.InstalledVersion != "" {
				version = pkg.InstalledVersion
			} else {
				version = "latest"
			}
		}

		activePort := pkg.DefaultPort
		internalDomain := ""
		if bp := GetBlueprint(pkg.Name); bp != nil {
			internalDomain = bp.InternalDomain
		}
		var publicDomain string
		var externalAccess, tlsEnabled bool
		if ing, ok := ingressMap[pkg.Name]; ok {
			if ing.ListenPort > 0 {
				activePort = ing.ListenPort
			}
			publicDomain = ing.PublicDomain
			externalAccess = ing.ExternalAccessEnabled
			tlsEnabled = ing.TLSEnabled
		}
		if publicDomain == "" && baseDomain != "" && activePort > 0 {
			publicDomain = FormatAppPublicDomain(pkg.Name, baseDomain)
			externalAccess = true
			tlsEnabled = true
		}

		servicesList[pkg.Label] = gin.H{
			"status":                  status,
			"uptime":                  uptime,
			"version":                 version,
			"managed_by":              managedBy,
			"process":                 serviceName,
			"id":                      pkg.Name,
			"default_port":            pkg.DefaultPort,
			"active_port":             activePort,
			"internal_domain":         internalDomain,
			"public_domain":           publicDomain,
			"external_access_enabled": externalAccess,
			"tls_enabled":             tlsEnabled,
			"web_path":                pkg.WebPath,
			"units":                   pkg.SandboxServiceIDs,
		}
	}

	return servicesList
}

// ResolveServiceUnits returns all systemd units associated with a service or package name.
// For multi-unit apps (e.g. deluge -> deluged + deluge-web, prometheus -> prometheus + node_exporter,
// paperless-ngx -> paperless-webserver + paperless-worker + paperless-scheduler, scrutiny -> scrutiny + scrutiny-collector,
// rclone -> rclone + rclone-vfs, recyclarr -> recyclarr + recyclarr.timer),
// this ensures start/stop/restart controls all companion units together.
func ResolveServiceUnits(target string) []string {
	cleanTarget := strings.TrimSuffix(strings.TrimSpace(target), ".service")
	if cleanTarget == "" {
		return nil
	}

	pkgs, err := GetPackages()
	if err == nil {
		for _, pkg := range pkgs {
			svcName := strings.TrimSuffix(strings.TrimSpace(pkg.ServiceName), ".service")
			matched := strings.EqualFold(pkg.Name, cleanTarget) ||
				(svcName != "" && strings.EqualFold(svcName, cleanTarget)) ||
				(strings.EqualFold(pkg.Name, "paperless-ngx") && strings.EqualFold(cleanTarget, "paperless"))

			if !matched {
				for _, u := range pkg.SandboxServiceIDs {
					uRaw := strings.TrimSpace(u)
					uClean := strings.TrimSuffix(uRaw, ".service")
					if strings.EqualFold(uClean, cleanTarget) ||
						strings.EqualFold(uRaw, cleanTarget) ||
						strings.EqualFold(strings.TrimSuffix(uClean, ".timer"), cleanTarget) {
						matched = true
						break
					}
				}
			}

			if matched {
				if len(pkg.SandboxServiceIDs) > 0 {
					units := make([]string, 0, len(pkg.SandboxServiceIDs))
					for _, u := range pkg.SandboxServiceIDs {
						uClean := strings.TrimSuffix(strings.TrimSpace(u), ".service")
						if uClean != "" {
							units = append(units, uClean)
						}
					}
					if len(units) > 0 {
						return units
					}
				}
				if svcName != "" {
					return []string{svcName}
				}
				return []string{pkg.Name}
			}
		}
	}

	switch strings.ToLower(cleanTarget) {
	case "deluge", "deluged", "deluge-web":
		return []string{"deluged", "deluge-web"}
	case "prometheus", "node_exporter":
		return []string{"prometheus", "node_exporter"}
	case "paperless", "paperless-ngx", "paperless-webserver", "paperless-worker", "paperless-scheduler":
		return []string{"paperless-webserver", "paperless-worker", "paperless-scheduler"}
	case "scrutiny", "scrutiny-collector", "scrutiny-collector.timer":
		return []string{"scrutiny", "scrutiny-collector", "scrutiny-collector.timer"}
	case "recyclarr", "recyclarr.timer":
		return []string{"recyclarr", "recyclarr.timer"}
	case "rclone", "rclone-vfs":
		return []string{"rclone", "rclone-vfs"}
	}

	return []string{cleanTarget}
}
