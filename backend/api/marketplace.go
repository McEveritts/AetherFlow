package api

import (
	"aetherflow/models"
	"aetherflow/services"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type App struct {
	Id        string  `json:"id"`
	Name      string  `json:"name"`
	Desc      string  `json:"desc"`
	Hits      int     `json:"hits"`
	Category  string  `json:"category"`
	Status    string  `json:"status"`
	Progress  int     `json:"progress"`            // 0-100 estimated install progress
	StartedAt *string `json:"started_at,omitempty"` // ISO timestamp when install started
	LogLine   string  `json:"log_line,omitempty"`   // most recent log line
}

// GetMarketplaceApps returns the list of marketplace apps
func GetMarketplaceApps(c *gin.Context) {
	pkgs := services.GetPackages()

	var apps []App
	for _, p := range pkgs {
		app := App{
			Id:       p.Name,
			Name:     p.Label,
			Desc:     p.Description,
			Hits:     p.Hits,
			Category: p.Category,
			Status:   p.Status,
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

func getPackageById(pkgId string) *models.Package {
	pkgs := services.GetPackages()
	for _, p := range pkgs {
		if p.Name == pkgId {
			return &p
		}
	}
	return nil
}

func InstallPackage(c *gin.Context) {
	pkgId := c.Param("id")
	log.Printf("Received request to INSTALL package: %s", pkgId)

	pkg := getPackageById(pkgId)
	if pkg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Package not found"})
		return
	}

	if pkg.Status == "installing" || pkg.Status == "uninstalling" {
		c.JSON(http.StatusConflict, gin.H{"error": "Package is already modifying state"})
		return
	}

	// Trigger async install
	go services.RunPackageAction("install", pkg.Name, "installpackage-"+pkg.Name, pkg.LockFile)

	c.JSON(http.StatusOK, gin.H{
		"message": "Installation started successfully",
		"package": pkgId,
		"status":  "installing",
	})
}

func UninstallPackage(c *gin.Context) {
	pkgId := c.Param("id")
	log.Printf("Received request to UNINSTALL package: %s", pkgId)

	pkg := getPackageById(pkgId)
	if pkg == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Package not found"})
		return
	}

	if pkg.Status == "installing" || pkg.Status == "uninstalling" {
		c.JSON(http.StatusConflict, gin.H{"error": "Package is already modifying state"})
		return
	}

	// Trigger async uninstall
	// Note: According to packages.json, the remove script convention is typically removepackage-pkgname
	go services.RunPackageAction("remove", pkg.Name, "removepackage-"+pkg.Name, pkg.LockFile)

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
