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
	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

// GitHubRelease represents the structure of the GitHub Releases API response
type GitHubRelease struct {
	TagName string `json:"tag_name"`
	Body    string `json:"body"`
	HtmlUrl string `json:"html_url"`
	Author  struct {
		Login string `json:"login"`
	} `json:"author"`
}

// GitHubCommit represents the structure of the GitHub Commits API response
type GitHubCommit struct {
	Sha     string `json:"sha"`
	HtmlUrl string `json:"html_url"`
	Commit  struct {
		Message string `json:"message"`
	} `json:"commit"`
}

var versionFilePath string
var updateScriptPath string

const githubRepo = "McEveritts/AetherFlow"

func init() {
	// Resolve script paths relative to the executable directory to prevent
	// CWE-78 attacks from working directory manipulation.
	execPath, err := os.Executable()
	if err != nil {
		slog.Warn("Could not resolve executable path, using relative paths", "error", err)
		versionFilePath = "../.version"
		updateScriptPath = "../deploy/release-manager.sh"
		return
	}
	execDir := filepath.Dir(execPath)
	// Support both single-binary layout (/opt/AetherFlow/current/.version) and repo layout (../.version)
	if _, statErr := os.Stat(filepath.Join(execDir, ".version")); statErr == nil {
		versionFilePath = filepath.Clean(filepath.Join(execDir, ".version"))
	} else {
		versionFilePath = filepath.Clean(filepath.Join(execDir, "..", ".version"))
	}
	if resolved := services.ResolveReleaseManagerScript(); resolved != "" {
		updateScriptPath = resolved
	} else {
		updateScriptPath = filepath.Clean(filepath.Join(execDir, "..", "deploy", "release-manager.sh"))
	}
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

// fetchLatestStableRelease gets the latest version via the Releases API,
// ensuring that the release was authored by "McEveritts" and is not a pre-release.
func fetchLatestStableRelease() (tagName, body, htmlUrl string, err error) {
	resp, reqErr := httpClient.Get("https://api.github.com/repos/" + githubRepo + "/releases")
	if reqErr != nil {
		slog.Warn("[updater] releases API request failed", "error", reqErr)
		return "", "", "", reqErr
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		slog.Info("[updater] releases API returned non-200", "status", resp.StatusCode)
		return "", "", "", nil
	}

	var releases []GitHubRelease
	bodyBytes, _ := io.ReadAll(resp.Body)
	if jsonErr := json.Unmarshal(bodyBytes, &releases); jsonErr != nil {
		slog.Error("[updater] failed to parse releases response", "error", jsonErr)
		return "", "", "", jsonErr
	}

	// Find the first release matching criteria
	for _, release := range releases {
		if strings.EqualFold(release.Author.Login, "McEveritts") && !strings.Contains(release.TagName, "-") {
			slog.Info("[updater] resolved latest version via Releases API", "version", release.TagName)
			cleanBody := strings.TrimPrefix(release.Body, "\uFEFF")
			cleanBody = strings.ReplaceAll(cleanBody, "Release Notes ? ", "Release Notes — ")
			return release.TagName, cleanBody, release.HtmlUrl, nil
		}
	}

	slog.Warn("[updater] no stable releases authored by McEveritts found")
	return "", "", "", nil
}

// CheckUpdate queries the GitHub API to see if a newer release exists based on the Update Channel
func CheckUpdate(c *gin.Context) {
	currentVersion := getLocalVersion()

	var channel string
	err := db.DB.QueryRow("SELECT update_channel FROM settings WHERE id = 1").Scan(&channel)
	if err != nil || channel != "nightly" {
		channel = "stable"
	}

	var updateAvailable bool
	var latestVersion string
	var message string
	var htmlUrl string

	switch channel {
	case "nightly":
		for _, branch := range []string{"nightly", "Nightly", "master"} {
			resp, reqErr := httpClient.Get("https://api.github.com/repos/" + githubRepo + "/commits/" + branch)
			if reqErr != nil {
				slog.Error("[updater] nightly commits API request failed", "branch", branch, "error", reqErr)
				continue
			}
			if resp.StatusCode == 200 {
				var commit GitHubCommit
				bodyBytes, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if jsonErr := json.Unmarshal(bodyBytes, &commit); jsonErr == nil && commit.Sha != "" {
					shortSha := commit.Sha
					if len(shortSha) > 7 {
						shortSha = shortSha[:7]
					}
					latestVersion = "nightly-" + shortSha
					message = commit.Commit.Message
					htmlUrl = commit.HtmlUrl
					updateAvailable = (currentVersion != latestVersion)
					break
				}
			} else {
				resp.Body.Close()
				slog.Warn("[updater] nightly commits API returned non-200", "branch", branch, "status", resp.StatusCode)
			}
		}

	default: // "stable"
		tag, releaseBody, url, fetchErr := fetchLatestStableRelease()
		if fetchErr != nil {
			slog.Error("[updater] stable version resolution failed", "error", fetchErr)
		} else if tag != "" {
			latestVersion = tag
			message = releaseBody
			htmlUrl = url
			updateAvailable = isNewerVersion(currentVersion, latestVersion)
		}
	}

	if latestVersion == "" {
		slog.Warn("[updater] could not resolve latest version",
			"channel", channel, "currentVersion", currentVersion)
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
	parseVersion := func(v string) (int, int, int, int) {
		v = strings.TrimPrefix(v, "v")
		if idx := strings.IndexByte(v, '-'); idx != -1 {
			v = v[:idx]
		}
		parts := strings.Split(v, ".")
		major, minor, patch, subpatch := 0, 0, 0, 0
		if len(parts) >= 1 {
			major, _ = strconv.Atoi(parts[0])
		}
		if len(parts) >= 2 {
			minor, _ = strconv.Atoi(parts[1])
		}
		if len(parts) >= 3 {
			if len(parts[2]) > 1 && strings.HasPrefix(parts[2], "0") {
				patch = 0
				subpatch, _ = strconv.Atoi(parts[2])
			} else {
				patch, _ = strconv.Atoi(parts[2])
			}
		}
		return major, minor, patch, subpatch
	}

	lMaj, lMin, lPat, lSub := parseVersion(local)
	rMaj, rMin, rPat, rSub := parseVersion(remote)

	if rMaj != lMaj {
		return rMaj > lMaj
	}
	if rMin != lMin {
		return rMin > lMin
	}
	if rPat != lPat {
		return rPat > lPat
	}
	return rSub > lSub
}

// RunUpdate initiates the background bash script to perform atomic blue/green deployment
func RunUpdate(c *gin.Context) {
	var channel string
	err := db.DB.QueryRow("SELECT update_channel FROM settings WHERE id = 1").Scan(&channel)
	if err != nil || channel != "nightly" {
		channel = "stable"
	}

	// Calculate target (for logging and script mapping)
	go func(ch string) {
		slog.Info("Initiating atomic Blue/Green update sequence...", "channel", ch)

		if services.IsRunnerAvailable() {
			if err := services.DispatchSelfUpdate("deploy", ch); err != nil {
				slog.Error("failed to dispatch self-update via privileged runner", "error", err)
			} else {
				slog.Info("self-update dispatched to privileged runner", "channel", ch)
			}
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()

		cmd := exec.CommandContext(ctx, "/bin/bash", updateScriptPath, "deploy", "--channel", ch)
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
