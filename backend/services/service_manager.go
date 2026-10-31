package services

import (
	"aetherflow/db"
	"aetherflow/models"
	"log/slog"
	"os"
	"strings"
	"time"

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

	apiPort := parseValidPort(os.Getenv("PORT"))
	if apiPort <= 0 {
		apiPort = 8080
	}

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

		defaultPort := 0
		activePort := 0
		switch systemdName {
		case "aetherflow-api":
			defaultPort = 8080
			activePort = apiPort
		case "aetherflow-frontend":
			if managedBy == "embedded" {
				defaultPort = 8080
				activePort = apiPort
			} else {
				defaultPort = 3000
				activePort = 3000
			}
		case "apache2":
			defaultPort = 443
			activePort = 443
		}

		servicesList[displayName] = gin.H{
			"status":       status,
			"uptime":       uptime,
			"version":      version,
			"managed_by":   managedBy,
			"process":      systemdName,
			"id":           systemdName,
			"default_port": defaultPort,
			"active_port":  activePort,
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
		if pkg.Status != "installed" && pkg.Status != "running" && pkg.Status != "updating" {
			continue
		}

		if pkg.InstalledVersion == "" && pkg.UpdateCheckedAt == "" && shouldTrackPackage(pkg) {
			TriggerInitialPackageUpdateCheck(pkg.Name)
		}

		// Use ServiceName from packages.json if available, else fall back to package name
		serviceName := pkg.ServiceName
		if serviceName == "" {
			serviceName = pkg.Name
		}

		var status, uptime, version string
		managedBy := "systemd"

		status, uptime, version = GetServiceInfo(serviceName)
		if pkg.Status == "updating" {
			status = "updating"
		}

		if version == "-" {
			if pkg.InstalledVersion != "" {
				version = pkg.InstalledVersion
			} else {
				version = "latest"
			}
		}

		meta := GetAppRuntimeMeta(pkg.Name)
		activePort := pkg.DefaultPort
		if meta.ConfiguredPort > 0 {
			activePort = meta.ConfiguredPort
		}
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

		entry := gin.H{
			"status":                  status,
			"uptime":                  uptime,
			"version":                 version,
			"managed_by":              managedBy,
			"process":                 serviceName,
			"id":                      pkg.Name,
			"default_port":            pkg.DefaultPort,
			"active_port":             activePort,
			"api_key":                 meta.APIKey,
			"internal_domain":         internalDomain,
			"public_domain":           publicDomain,
			"external_access_enabled": externalAccess,
			"tls_enabled":             tlsEnabled,
			"web_path":                pkg.WebPath,
			"units":                   pkg.SandboxServiceIDs,
			"installed_version":       pkg.InstalledVersion,
			"latest_version":          pkg.LatestVersion,
			"update_available":        pkg.UpdateAvailable,
			"update_checked_at":       pkg.UpdateCheckedAt,
			"update_url":              pkg.UpdateURL,
			"update_error":            pkg.UpdateError,
		}

		if jobInfo := GetPackageJobInfo(pkg.Name); jobInfo != nil {
			entry["job_status"] = jobInfo.Status
			entry["progress"] = jobInfo.Progress
			entry["log_line"] = jobInfo.LastLine
			entry["started_at"] = jobInfo.StartedAt.Format(time.RFC3339)
		}

		servicesList[pkg.Label] = entry
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

	pkgs, err := GetPackageCatalog()
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
	case "dispatcharr", "dispatcharr-celery", "dispatcharr-celerybeat":
		return []string{"dispatcharr", "dispatcharr-celery", "dispatcharr-celerybeat"}
	case "novnc", "novnc-xvnc":
		return []string{"novnc", "novnc-xvnc"}
	}

	return []string{cleanTarget}
}
