package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aetherflow/db"

	"github.com/gin-gonic/gin"
)

// GitHubRelease represents the structure of the GitHub Releases API response
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	HtmlUrl string `json:"html_url"`
}

var versionFilePath string
var updateScriptPath string

func init() {
	// Resolve script paths relative to the executable directory to prevent
	// CWE-78 attacks from working directory manipulation.
	execPath, err := os.Executable()
	if err != nil {
		slog.Warn("Could not resolve executable path, using relative paths", "error", err)
		versionFilePath = "../.version"
		updateScriptPath = "../scripts/deployment_engine.sh"
		return
	}
	execDir := filepath.Dir(execPath)
	versionFilePath = filepath.Clean(filepath.Join(execDir, "..", ".version"))
	updateScriptPath = filepath.Clean(filepath.Join(execDir, "..", "scripts", "deployment_engine.sh"))
}

// httpClient is a timeout-bound HTTP client for outbound requests.
// Prevents goroutine/thread leaks if the upstream API hangs.
var httpClient = &http.Client{Timeout: 10 * time.Second}

func getLocalVersion() string {
	versionBytes, err := os.ReadFile(versionFilePath)
	if err != nil {
		slog.Warn("failed to read version file, using default", "error", err, "default", "v3.0.0")
		return "v3.0.0" // Fallback if file doesn't exist
	}
	return strings.TrimSpace(string(versionBytes))
}



// GitHubCommit represents the structure of the GitHub Commits API response
type GitHubCommit struct {
	Sha    string `json:"sha"`
	HtmlUrl string `json:"html_url"`
	Commit struct {
		Message string `json:"message"`
	} `json:"commit"`
}

// CheckUpdate queries the GitHub API to see if a newer release exists based on the Update Channel
func CheckUpdate(c *gin.Context) {
	currentVersion := getLocalVersion()

	var channel string
	err := db.DB.QueryRow("SELECT update_channel FROM settings WHERE id = 1").Scan(&channel)
	if err != nil || channel == "" {
		channel = "stable"
	}

	var updateAvailable bool
	var latestVersion string
	var message string
	var htmlUrl string

	if channel == "nightly" {
		resp, err := httpClient.Get("https://api.github.com/repos/McEveritts/AetherFlow/commits/master")
		if err != nil {
			InternalError(c, "Failed to reach GitHub API for nightly")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			var commit GitHubCommit
			bodyBytes, _ := io.ReadAll(resp.Body)
			if err := json.Unmarshal(bodyBytes, &commit); err == nil {
				shortSha := commit.Sha
				if len(shortSha) > 7 {
					shortSha = shortSha[:7]
				}
				latestVersion = "nightly-" + shortSha
				message = commit.Commit.Message
				htmlUrl = commit.HtmlUrl
				// For nightly, if currentVersion isn't the commit sha, it's an update
				updateAvailable = (currentVersion != latestVersion)
			}
		}
	} else if channel == "beta" {
		resp, err := httpClient.Get("https://api.github.com/repos/McEveritts/AetherFlow/releases")
		if err != nil {
			InternalError(c, "Failed to reach GitHub API for releases")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			var releases []GitHubRelease
			bodyBytes, _ := io.ReadAll(resp.Body)
			if err := json.Unmarshal(bodyBytes, &releases); err == nil && len(releases) > 0 {
				latestVersion = releases[0].TagName
				message = releases[0].Body
				htmlUrl = releases[0].HtmlUrl
				updateAvailable = isNewerVersion(currentVersion, latestVersion)
			}
		}
	} else {
		// Stable
		resp, err := httpClient.Get("https://api.github.com/repos/McEveritts/AetherFlow/releases/latest")
		if err != nil {
			InternalError(c, "Failed to reach GitHub API for stable release")
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			var release GitHubRelease
			bodyBytes, _ := io.ReadAll(resp.Body)
			if err := json.Unmarshal(bodyBytes, &release); err == nil {
				latestVersion = release.TagName
				message = release.Body
				htmlUrl = release.HtmlUrl
				updateAvailable = isNewerVersion(currentVersion, latestVersion)
			}
		}
	}

	if latestVersion == "" {
		c.JSON(http.StatusOK, gin.H{
			"updateAvailable": false,
			"currentVersion":  currentVersion,
			"latestVersion":   "Unknown (API Error or Rate Limited)",
			"message":         "Could not fetch latest updates.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"updateAvailable": updateAvailable,
		"currentVersion":  currentVersion,
		"latestVersion":   latestVersion,
		"message":         message,
		"url":             htmlUrl,
	})
}

// isNewerVersion returns true if remote is strictly newer than local.
func isNewerVersion(local, remote string) bool {
	parseVersion := func(v string) (int, int, int) {
		v = strings.TrimPrefix(v, "v")
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

// RunUpdate initiates the background bash script to perform atomic blue/green deployment
func RunUpdate(c *gin.Context) {
	var channel string
	err := db.DB.QueryRow("SELECT update_channel FROM settings WHERE id = 1").Scan(&channel)
	if err != nil || channel == "" {
		channel = "stable"
	}

	// Calculate target (for logging and script mapping)
	go func(ch string) {
		slog.Info("Initiating atomic Blue/Green update sequence...", "channel", ch)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		cmd := exec.CommandContext(ctx, "/bin/bash", updateScriptPath, ch)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Start(); err != nil {
			slog.Error("failed to start deployment engine", "error", err)
			return
		}

		err := cmd.Wait()
		if ctx.Err() == context.DeadlineExceeded {
			slog.Error("deployment script killed after timeout", "timeout", "10m")
		} else if err != nil {
			slog.Info("Deployment script finished with error", "error", err)
		} else {
			slog.Info("Deployment script finished successfully.")
		}
	}(channel)

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	uid, _ := userID.(int)
	uname, _ := username.(string)
	db.RecordAudit(uid, uname, "system_deployment", "engine", "blue_green", "Channel: "+channel, c.ClientIP(), c.Request.UserAgent())

	c.JSON(http.StatusOK, gin.H{
		"message": "Atomic deployment initiated. The system will cleanly transition once builds are complete.",
	})
}
