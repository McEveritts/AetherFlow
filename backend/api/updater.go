package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

// GitHubRelease represents the structure of the GitHub Releases API response
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	HtmlUrl string `json:"html_url"`
}

var versionFilePath = "../.version"
var updateScriptPath = "../scripts/update.sh"

func getLocalVersion() string {
	versionBytes, err := os.ReadFile(versionFilePath)
	if err != nil {
		log.Printf("Failed to read version file: %v. Defaulting to v3.0.0", err)
		return "v3.0.0" // Fallback if file doesn't exist
	}
	return strings.TrimSpace(string(versionBytes))
}

// CheckUpdate queries the GitHub API to see if a newer release exists
func CheckUpdate(c *gin.Context) {
	currentVersion := getLocalVersion()

	// Use McEveritts/AetherFlow
	resp, err := http.Get("https://api.github.com/repos/McEveritts/AetherFlow/releases/latest")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reach GitHub API"})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		c.JSON(http.StatusOK, gin.H{
			"updateAvailable": false,
			"currentVersion":  currentVersion,
			"latestVersion":   "Unknown (Rate Limited)",
			"message":         "API rate limit exceeded.",
		})
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read GitHub response"})
		return
	}

	var release GitHubRelease
	if err := json.Unmarshal(bodyBytes, &release); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse GitHub response"})
		return
	}

	// Proper semver comparison: only flag update if remote > local
	updateAvailable := isNewerVersion(currentVersion, release.TagName)

	c.JSON(http.StatusOK, gin.H{
		"updateAvailable": updateAvailable,
		"currentVersion":  currentVersion,
		"latestVersion":   release.TagName,
		"message":         release.Body,
		"url":             release.HtmlUrl,
	})
}

// isNewerVersion returns true if remote is strictly newer than local.
// Handles versions like "v3.1.0", "3.1.0", "v3.2.0-beta".
func isNewerVersion(local, remote string) bool {
	parseVersion := func(v string) (int, int, int) {
		v = strings.TrimPrefix(v, "v")
		// Strip any pre-release suffix (e.g., "-beta", "-rc1")
		if idx := strings.IndexByte(v, '-'); idx != -1 {
			v = v[:idx]
		}
		parts := strings.Split(v, ".")
		major, minor, patch := 0, 0, 0
		if len(parts) >= 1 {
			major, _ = strconv.Atoi(parts[0])
		}
		if len(parts) >= 2 {
			minor, _ = strconv.Atoi(parts[1])
		}
		if len(parts) >= 3 {
			patch, _ = strconv.Atoi(parts[2])
		}
		return major, minor, patch
	}

	lMaj, lMin, lPat := parseVersion(local)
	rMaj, rMin, rPat := parseVersion(remote)

	if rMaj != lMaj {
		return rMaj > lMaj
	}
	if rMin != lMin {
		return rMin > lMin
	}
	return rPat > lPat
}

// RunUpdate initiates the background bash script that pulls code and restarts PM2
func RunUpdate(c *gin.Context) {
	// Execute the update script asynchronously so the HTTP request can complete seamlessly
	go func() {
		log.Println("Initiating over-the-air update sequence...")

		cmd := exec.Command("/bin/bash", updateScriptPath)
		// Redirect output so it doesn't wait on pipes
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			log.Printf("Failed to start update script: %v", err)
			return
		}

		// Optional: wait in goroutine
		err := cmd.Wait()
		if err != nil {
			log.Printf("Update script finished with error: %v", err)
		} else {
			log.Println("Update script finished successfully.")
		}
	}()

	c.JSON(http.StatusOK, gin.H{
		"message": "Update sequence initiated. The dashboard will restart momentarily.",
	})
}
