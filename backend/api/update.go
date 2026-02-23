package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/gin-gonic/gin"
)

// CurrentVersion represents the currently installed version of AetherFlow
const CurrentVersion = "v3.0.1"

// GitHubRelease represents the structure of a release from the GitHub API
type GitHubRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
	HtmlUrl     string `json:"html_url"`
}

// CheckUpdate checks the GitHub API for the latest release
func CheckUpdate(c *gin.Context) {
	// For simulation purposes, we'll pretend the user's repo is armysp/AetherFlow
	// In reality you would configure this in settings or hardcode the origin repo
	url := "https://api.github.com/repos/armysp/AetherFlow/releases/latest"

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to construct update request"})
		return
	}

	// It's good practice to set a custom User-Agent for GitHub APIs
	req.Header.Set("User-Agent", "AetherFlow-Updater")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error requesting GitHub API: %v\n", err)
		// Return a mock payload if offline or rate limited so the UI doesn't crash
		c.JSON(http.StatusOK, gin.H{
			"currentVersion": CurrentVersion,
			"latestVersion":  CurrentVersion, // Fallback implies no update
			"updateAvailable": false,
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusOK, gin.H{
			"currentVersion": CurrentVersion,
			"latestVersion":  CurrentVersion, 
			"updateAvailable": false,
			"message": "Unable to verify. You might be rate-limited by GitHub.",
		})
		return
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse GitHub response"})
		return
	}

	updateAvailable := release.TagName != CurrentVersion

	c.JSON(http.StatusOK, gin.H{
		"currentVersion":  CurrentVersion,
		"latestVersion":   release.TagName,
		"releaseNotes":    release.Body,
		"releaseDate":     release.PublishedAt,
		"url":             release.HtmlUrl,
		"updateAvailable": updateAvailable,
	})
}

// RunUpdate triggers the bash script to pull and restart the application
func RunUpdate(c *gin.Context) {

	// We'll invoke a bash script asynchronously so the API can return a success message
	// before the PM2 process gets killed by the script.
	updateScriptPath := "/opt/AetherFlow/scripts/update.sh"

	if _, err := os.Stat(updateScriptPath); os.IsNotExist(err) {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Update script not found at " + updateScriptPath,
		})
		return
	}

	cmd := exec.Command("bash", updateScriptPath)
	
	// Start it in the background
	if err := cmd.Start(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to initialize update script"})
		return
	}

	// Detach it from this process
	go func() {
		cmd.Wait() // Run in background
	}()

	c.JSON(http.StatusOK, gin.H{
		"message": "Update initiated. AetherFlow services will restart shortly. You may lose connection for a few moments.",
		"status": "updating",
	})
}
