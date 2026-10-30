package api

import (
	"aetherflow/db"
	"aetherflow/models"
	"aetherflow/services"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func init() {
	services.SetPackageEventBroadcaster(func(pkgId, action, status string, progress int, lastLine string) {
		BroadcastMarketplaceJobEvent(pkgId, action, status, progress, lastLine)
	})
}

type App struct {
	Id                    string  `json:"id"`
	Name                  string  `json:"name"`
	Desc                  string  `json:"desc"`
	Hits                  int     `json:"hits"`
	Category              string  `json:"category"`
	Status                string  `json:"status"`
	DefaultPort           int     `json:"default_port,omitempty"`
	ActivePort            int     `json:"active_port,omitempty"`
	InternalDomain        string  `json:"internal_domain,omitempty"`
	PublicDomain          string  `json:"public_domain,omitempty"`
	ExternalAccessEnabled bool    `json:"external_access_enabled,omitempty"`
	WebPath               string  `json:"web_path,omitempty"`
	Progress              int     `json:"progress"`              // 0-100 estimated install progress
	StartedAt             *string `json:"started_at,omitempty"`  // ISO timestamp when install started
	LogLine               string  `json:"log_line,omitempty"`    // most recent log line
	InstalledVersion      string  `json:"installed_version,omitempty"`
	LatestVersion         string  `json:"latest_version,omitempty"`
	UpdateAvailable       bool    `json:"update_available"`
	UpdateCheckedAt       string  `json:"update_checked_at,omitempty"`
	UpdateURL             string  `json:"update_url,omitempty"`
	UpdateError           string  `json:"update_error,omitempty"`
}

// GetMarketplaceApps returns the list of marketplace apps
func GetMarketplaceApps(c *gin.Context) {
	pkgs, err := services.GetPackages()
	if err != nil {
		InternalError(c, "Failed to load package catalog configuration")
		return
	}

	ingressMap := make(map[string]models.AppIngressConfig)
	if configs, err := db.GetAllAppIngressConfigs(); err == nil {
		for _, cfg := range configs {
			ingressMap[cfg.AppName] = cfg
		}
	}

	baseDomain := services.ResolveBaseDomain()
	apps := []App{}
	for _, p := range pkgs {
		activePort := p.DefaultPort
		internalDomain := ""
		if bp := services.GetBlueprint(p.Name); bp != nil {
			internalDomain = bp.InternalDomain
		}
		var publicDomain string
		var externalAccess bool
		if ing, ok := ingressMap[p.Name]; ok {
			if ing.ListenPort > 0 {
				activePort = ing.ListenPort
			}
			publicDomain = ing.PublicDomain
			externalAccess = ing.ExternalAccessEnabled
		}
		if publicDomain == "" && baseDomain != "" && activePort > 0 {
			publicDomain = services.FormatAppPublicDomain(p.Name, baseDomain)
			if p.Status == "installed" || p.Status == "running" {
				externalAccess = true
			}
		}

		app := App{
			Id:                    p.Name,
			Name:                  p.Label,
			Desc:                  p.Description,
			Hits:                  p.Hits,
			Category:              p.Category,
			Status:                p.Status,
			DefaultPort:           p.DefaultPort,
			ActivePort:            activePort,
			InternalDomain:        internalDomain,
			PublicDomain:          publicDomain,
			ExternalAccessEnabled: externalAccess,
			WebPath:               p.WebPath,
			InstalledVersion:      p.InstalledVersion,
			LatestVersion:         p.LatestVersion,
			UpdateAvailable:       p.UpdateAvailable,
			UpdateCheckedAt:       p.UpdateCheckedAt,
			UpdateURL:             p.UpdateURL,
			UpdateError:           p.UpdateError,
		}

		// Enrich with live progress data if job is active
		if jobInfo := services.GetPackageJobInfo(p.Name); jobInfo != nil {
			app.Progress = jobInfo.Progress
			ts := jobInfo.StartedAt.Format(time.RFC3339)
			app.StartedAt = &ts
			app.LogLine = jobInfo.LastLine
		}

		apps = append(apps, app)
	}

	c.JSON(http.StatusOK, apps)
}

func getPackageById(pkgId string) (*models.Package, error) {
	pkgs, err := services.GetPackages()
	if err != nil {
		return nil, err
	}
	for _, p := range pkgs {
		if p.Name == pkgId {
			return &p, nil
		}
	}
	return nil, nil
}

func InstallPackage(c *gin.Context) {
	pkgId := c.Param("id")
	slog.Info("Received request to INSTALL package", "package", pkgId)

	pkg, err := getPackageById(pkgId)
	if err != nil {
		InternalError(c, "Failed to load package catalog configuration")
		return
	}
	if pkg == nil {
		NotFoundError(c, "Package not found")
		return
	}

	if pkg.Status == "installing" || pkg.Status == "uninstalling" || pkg.Status == "updating" {
		ConflictError(c, "Package is already modifying state")
		return
	}

	scriptName := "installpackage-" + pkg.Name
	if services.ResolvePackageScriptPath("install", scriptName) == "" {
		InternalError(c, "Provisioning script is missing or unreadable on the server")
		return
	}

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	uid, _ := userID.(int)
	uname, _ := username.(string)
	db.RecordAudit(uid, uname, "package_install", "package", pkg.Name, pkg.Label, c.ClientIP(), c.Request.UserAgent())

	// Trigger async install
	go services.RunPackageAction("install", pkg.Name, scriptName, pkg.LockFile)

	c.JSON(http.StatusOK, gin.H{
		"message": "Installation started successfully",
		"package": pkgId,
		"status":  "installing",
	})
}

func UninstallPackage(c *gin.Context) {
	pkgId := c.Param("id")
	slog.Info("Received request to UNINSTALL package", "package", pkgId)

	pkg, err := getPackageById(pkgId)
	if err != nil {
		InternalError(c, "Failed to load package catalog configuration")
		return
	}
	if pkg == nil {
		NotFoundError(c, "Package not found")
		return
	}

	if pkg.Status == "installing" || pkg.Status == "uninstalling" || pkg.Status == "updating" {
		ConflictError(c, "Package is already modifying state")
		return
	}

	scriptName := "removepackage-" + pkg.Name
	if services.ResolvePackageScriptPath("remove", scriptName) == "" {
		InternalError(c, "Tear-down script is missing or unreadable on the server")
		return
	}

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	uid, _ := userID.(int)
	uname, _ := username.(string)
	db.RecordAudit(uid, uname, "package_uninstall", "package", pkg.Name, pkg.Label, c.ClientIP(), c.Request.UserAgent())

	// Trigger async uninstall
	go services.RunPackageAction("remove", pkg.Name, scriptName, pkg.LockFile)

	c.JSON(http.StatusOK, gin.H{
		"message": "Uninstallation started successfully",
		"package": pkgId,
		"status":  "uninstalling",
	})
}

func UpdatePackage(c *gin.Context) {
	pkgId := c.Param("id")
	slog.Info("Received request to UPDATE package", "package", pkgId)

	pkg, err := getPackageById(pkgId)
	if err != nil {
		InternalError(c, "Failed to load package catalog configuration")
		return
	}
	if pkg == nil {
		NotFoundError(c, "Package not found")
		return
	}

	if pkg.Status == "installing" || pkg.Status == "uninstalling" || pkg.Status == "updating" {
		ConflictError(c, "Package is already modifying state")
		return
	}
	if pkg.Status != "installed" {
		ConflictError(c, "Package is not installed")
		return
	}

	scriptName := "installpackage-" + pkg.Name
	if services.ResolvePackageScriptPath("update", scriptName) == "" {
		InternalError(c, "Update script is missing or unreadable on the server")
		return
	}

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	uid, _ := userID.(int)
	uname, _ := username.(string)
	db.RecordAudit(uid, uname, "package_update", "package", pkg.Name, pkg.Label, c.ClientIP(), c.Request.UserAgent())

	// Trigger async update
	go services.RunPackageAction("update", pkg.Name, scriptName, pkg.LockFile)

	c.JSON(http.StatusOK, gin.H{
		"message": "Update started successfully",
		"package": pkgId,
		"status":  "updating",
	})
}

func CheckPackageUpdates(c *gin.Context) {
	records := services.RefreshAllPackageUpdates()
	updatesAvailable := 0
	for _, rec := range records {
		if rec.UpdateAvailable {
			updatesAvailable++
		}
	}
	c.JSON(http.StatusOK, gin.H{
		"message":           "Package update check completed",
		"updates":           records,
		"updates_available": updatesAvailable,
	})
}

func CheckSinglePackageUpdate(c *gin.Context) {
	pkgId := c.Param("id")
	pkg, err := getPackageById(pkgId)
	if err != nil {
		InternalError(c, "Failed to load package catalog configuration")
		return
	}
	if pkg == nil {
		NotFoundError(c, "Package not found")
		return
	}

	services.RefreshPackageUpdateByID(pkg.Name)
	updateMap := services.GetPackageUpdateMap()
	record := updateMap[pkg.Name]

	c.JSON(http.StatusOK, gin.H{
		"message":           "Package update check completed",
		"package":           pkg.Name,
		"update":            record,
		"update_available":  record.UpdateAvailable,
		"installed_version": record.InstalledVersion,
		"latest_version":    record.LatestVersion,
		"update_url":        record.URL,
		"checked_at":        record.CheckedAt,
		"last_error":        record.LastError,
	})
}

// PackageProgress returns real-time progress data for an active install/uninstall
func PackageProgress(c *gin.Context) {
	pkgId := c.Param("id")

	jobInfo := services.GetPackageJobInfo(pkgId)
	if jobInfo == nil {
		c.JSON(http.StatusOK, gin.H{
			"status":   "idle",
			"progress": 0,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":     jobInfo.Status,
		"progress":   jobInfo.Progress,
		"started_at": jobInfo.StartedAt.Format(time.RFC3339),
		"log_line":   jobInfo.LastLine,
		"log_lines":  jobInfo.LogLines,
	})
}
