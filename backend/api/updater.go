package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
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

	updateAvailable := currentVersion != release.TagName

	// If the current version contains "dev" or has a structural mismatch, it may be greater,
	// but for this MVP, a simple string comparison inequality indicates an update is available.

	c.JSON(http.StatusOK, gin.H{
		"updateAvailable": updateAvailable,
		"currentVersion":  currentVersion,
		"latestVersion":   release.TagName,
		"message":         release.Body,
		"url":             release.HtmlUrl,
	})
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
