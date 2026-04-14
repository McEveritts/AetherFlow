package api

import (
	"aetherflow/models"
	"aetherflow/services"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type App struct {
	Id               string  `json:"id"`
	Name             string  `json:"name"`
	Desc             string  `json:"desc"`
	Hits             int     `json:"hits"`
	Category         string  `json:"category"`
	Status           string  `json:"status"`
	Progress         int     `json:"progress"`              // 0-100 estimated install progress
	StartedAt        *string `json:"started_at,omitempty"`  // ISO timestamp when install started
	LogLine          string  `json:"log_line,omitempty"`    // most recent log line
	InstalledVersion string  `json:"installed_version,omitempty"`
	LatestVersion    string  `json:"latest_version,omitempty"`
	UpdateAvailable  bool    `json:"update_available"`
	UpdateCheckedAt  string  `json:"update_checked_at,omitempty"`
	UpdateURL        string  `json:"update_url,omitempty"`
	UpdateError      string  `json:"update_error,omitempty"`
}

// GetMarketplaceApps returns the list of marketplace apps
func GetMarketplaceApps(c *gin.Context) {
	pkgs, err := services.GetPackages()
	if err != nil {
		InternalError(c, "Failed to load package catalog configuration")
		return
	}

	apps := []App{}
	for _, p := range pkgs {
		app := App{
			Id:               p.Name,
			Name:             p.Label,
			Desc:             p.Description,
			Hits:             p.Hits,
			Category:         p.Category,
			Status:           p.Status,
			InstalledVersion: p.InstalledVersion,
			LatestVersion:    p.LatestVersion,
			UpdateAvailable:  p.UpdateAvailable,
			UpdateCheckedAt:  p.UpdateCheckedAt,
			UpdateURL:        p.UpdateURL,
			UpdateError:      p.UpdateError,
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

	if pkg.Status == "installing" || pkg.Status == "uninstalling" {
		ConflictError(c, "Package is already modifying state")
		return
	}

	scriptName := "installpackage-" + pkg.Name
	if services.ResolvePackageScriptPath("install", scriptName) == "" {
		InternalError(c, "Provisioning script is missing or unreadable on the server")
		return
	}

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

	if pkg.Status == "installing" || pkg.Status == "uninstalling" {
		ConflictError(c, "Package is already modifying state")
		return
	}

	scriptName := "removepackage-" + pkg.Name
	if services.ResolvePackageScriptPath("remove", scriptName) == "" {
		InternalError(c, "Tear-down script is missing or unreadable on the server")
		return
	}

	// Trigger async uninstall
	go services.RunPackageAction("remove", pkg.Name, scriptName, pkg.LockFile)

	c.JSON(http.StatusOK, gin.H{
		"message": "Uninstallation started successfully",
		"package": pkgId,
		"status":  "uninstalling",
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
