package api

import (
	"aetherflow/models"
	"aetherflow/services"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

type App struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Desc     string `json:"desc"`
	Hits     int    `json:"hits"`
	Category string `json:"category"`
	Status   string `json:"status"` // e.g., "uninstalled", "installed", "installing"
}

// GetMarketplaceApps returns the list of marketplace apps
func GetMarketplaceApps(c *gin.Context) {
	pkgs := services.GetPackages()

	var apps []App
	for _, p := range pkgs {
		apps = append(apps, App{
			Id:       p.Name,
			Name:     p.Label,
			Desc:     p.Description,
			Hits:     p.Hits,
			Category: p.Category,
			Status:   p.Status,
		})
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
