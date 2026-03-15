package services

import (
	"aetherflow/db"
	"aetherflow/models"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type PackageUpdateRecord struct {
	PackageName      string `json:"package_name"`
	InstalledVersion string `json:"installed_version"`
	LatestVersion    string `json:"latest_version"`
	UpdateAvailable  bool   `json:"update_available"`
	URL              string `json:"update_url"`
	CheckedAt        string `json:"checked_at"`
	LastError        string `json:"last_error"`
}

type gitHubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

type AppUpdateWatcher struct {
	client           *http.Client
	interval         time.Duration
	githubAPIBaseURL string
	callback         func([]string)
}

var (
	AppUpdateWatcherInstance *AppUpdateWatcher

	defaultVersionPattern = regexp.MustCompile(`(?i)\bv?([0-9]+(?:[._:+~-][0-9A-Za-z]+)*)\b`)
	numericVersionPattern = regexp.MustCompile(`\d+`)
)

func defaultUpdateInterval() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("AETHERFLOW_UPDATE_WATCH_INTERVAL")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			return parsed
		}
	}

	return 6 * time.Hour
}

func NewAppUpdateWatcher(client *http.Client, interval time.Duration, callback func([]string)) *AppUpdateWatcher {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	if interval <= 0 {
		interval = defaultUpdateInterval()
	}

	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("AETHERFLOW_GITHUB_API_BASE_URL")), "/")
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}

	return &AppUpdateWatcher{
		client:           client,
		interval:         interval,
		githubAPIBaseURL: baseURL,
		callback:         callback,
	}
}

func InitAppUpdateWatcher(callback func([]string)) {
	if AppUpdateWatcherInstance != nil {
		return
	}

	AppUpdateWatcherInstance = NewAppUpdateWatcher(nil, 0, callback)
	go AppUpdateWatcherInstance.loop()
}

func (w *AppUpdateWatcher) loop() {
	w.RefreshInstalledPackages()

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for range ticker.C {
		w.RefreshInstalledPackages()
	}
}

func shouldTrackPackage(pkg models.Package) bool {
	if pkg.UpdateSource == "" {
		return false
	}

	switch pkg.UpdateSource {
	case "apt":
		return pkg.UpdatePackage != ""
	case "github", "git_tags":
		return len(pkg.VersionCommand) > 0 && (pkg.UpdateRepo != "" || pkg.UpdateRepoURL != "")
	default:
		return len(pkg.VersionCommand) > 0
	}
}

func (w *AppUpdateWatcher) RefreshInstalledPackages() {
	pkgs := GetPackages()
	if len(pkgs) == 0 {
		return
	}

	var changed []string
	for _, pkg := range pkgs {
		if pkg.Status != "installed" && pkg.Status != "running" {
			continue
		}
		if !shouldTrackPackage(pkg) {
			continue
		}

		record, notify, err := w.refreshPackage(pkg)
		if err != nil {
			log.Printf("[updates] %s: %v", pkg.Name, err)
		}
		if record != nil {
			changed = append(changed, pkg.Name)
		}
		if notify && Notifier != nil {
			Notifier.Dispatch(Notification{
				Level:   NotifyInfo,
				Title:   pkg.Label + " update available",
				Message: fmt.Sprintf("Installed %s, latest %s.", record.InstalledVersion, record.LatestVersion),
			})
		}
	}

	if len(changed) > 0 && w.callback != nil {
		w.callback(changed)
	}
}

func RefreshPackageUpdateByID(pkgID string) {
	if pkgID == "" {
		return
	}

	watcher := AppUpdateWatcherInstance
	if watcher == nil {
		watcher = NewAppUpdateWatcher(nil, 0, nil)
	}

	for _, pkg := range GetPackages() {
		if pkg.Name != pkgID || !shouldTrackPackage(pkg) {
			continue
		}

		if _, notify, err := watcher.refreshPackage(pkg); err != nil {
			log.Printf("[updates] refresh %s failed: %v", pkgID, err)
		} else if notify && Notifier != nil {
			updateMap := GetPackageUpdateMap()
			record := updateMap[pkg.Name]
			Notifier.Dispatch(Notification{
				Level:   NotifyInfo,
				Title:   pkg.Label + " update available",
				Message: fmt.Sprintf("Installed %s, latest %s.", record.InstalledVersion, record.LatestVersion),
			})
		}
		return
	}
}

func (w *AppUpdateWatcher) refreshPackage(pkg models.Package) (*PackageUpdateRecord, bool, error) {
	installedVersion, installedErr := detectInstalledVersion(pkg)
	latestVersion, updateURL, latestErr := w.detectLatestVersion(pkg)

	record := PackageUpdateRecord{
		PackageName:      pkg.Name,
		InstalledVersion: installedVersion,
		LatestVersion:    latestVersion,
		UpdateAvailable:  installedErr == nil && latestErr == nil && IsRemoteVersionNewer(installedVersion, latestVersion),
		URL:              updateURL,
		CheckedAt:        time.Now().UTC().Format(time.RFC3339),
	}

	var errParts []string
	if installedErr != nil {
		errParts = append(errParts, "installed version: "+installedErr.Error())
	}
	if latestErr != nil {
		errParts = append(errParts, "latest version: "+latestErr.Error())
	}
	record.LastError = strings.Join(errParts, "; ")

	changed, notify, err := upsertPackageUpdate(record)
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return nil, false, nil
	}

	return &record, notify, nil
}

func detectInstalledVersion(pkg models.Package) (string, error) {
	switch pkg.UpdateSource {
	case "apt":
		cmd := exec.Command("dpkg-query", "-W", "-f=${Version}", pkg.UpdatePackage)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("dpkg-query failed: %w", err)
		}
		version := extractVersion(string(output), pkg.VersionRegex)
		if version == "" {
			return "", fmt.Errorf("unable to parse installed apt version for %s", pkg.Name)
		}
		return version, nil
	default:
		if len(pkg.VersionCommand) == 0 {
			return "", fmt.Errorf("no version command configured")
		}

		cmd := exec.Command(pkg.VersionCommand[0], pkg.VersionCommand[1:]...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("version command failed: %w", err)
		}

		version := extractVersion(string(output), pkg.VersionRegex)
		if version == "" {
			return "", fmt.Errorf("unable to parse version output")
		}
		return version, nil
	}
}

func (w *AppUpdateWatcher) detectLatestVersion(pkg models.Package) (string, string, error) {
	switch pkg.UpdateSource {
	case "apt":
		return detectLatestAptVersion(pkg.UpdatePackage)
	case "github":
		return w.detectLatestGitHubRelease(pkg.UpdateRepo)
	case "git_tags":
		repoURL := pkg.UpdateRepoURL
		if repoURL == "" && pkg.UpdateRepo != "" {
			repoURL = "https://github.com/" + pkg.UpdateRepo + ".git"
		}
		return detectLatestGitTag(repoURL, pkg.UpdateRepo)
	default:
		return "", "", fmt.Errorf("unsupported update source %q", pkg.UpdateSource)
	}
}

func detectLatestAptVersion(packageName string) (string, string, error) {
	cmd := exec.Command("apt-cache", "policy", packageName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("apt-cache failed: %w", err)
	}

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Candidate:") {
			continue
		}

		version := extractVersion(strings.TrimSpace(strings.TrimPrefix(line, "Candidate:")), "")
		if version == "" {
			break
		}

		return version, "", nil
	}

	return "", "", fmt.Errorf("candidate version not found")
}

func (w *AppUpdateWatcher) detectLatestGitHubRelease(repo string) (string, string, error) {
	if repo == "" {
		return "", "", fmt.Errorf("missing GitHub repo")
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/repos/%s/releases/latest", w.githubAPIBaseURL, repo), nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "AetherFlow-Updater")

	resp, err := w.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("GitHub API returned %s", resp.Status)
	}

	var release gitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", fmt.Errorf("decode GitHub release: %w", err)
	}

	version := extractVersion(release.TagName, "")
	if version == "" {
		return "", "", fmt.Errorf("unable to parse GitHub release tag %q", release.TagName)
	}

	return version, release.HTMLURL, nil
}

func detectLatestGitTag(repoURL, repo string) (string, string, error) {
	if repoURL == "" {
		return "", "", fmt.Errorf("missing repository URL")
	}

	cmd := exec.Command("git", "ls-remote", "--tags", "--refs", repoURL)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("git ls-remote failed: %w", err)
	}

	best := ""
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, "refs/tags/") {
			continue
		}

		ref := strings.TrimSpace(line[strings.LastIndex(line, "/")+1:])
		version := extractVersion(ref, "")
		if version == "" {
			continue
		}
		if best == "" || IsRemoteVersionNewer(best, version) {
			best = version
		}
	}

	if best == "" {
		return "", "", fmt.Errorf("no tags discovered")
	}

	repoURL = strings.TrimSuffix(repoURL, ".git")
	if repoURL == "" && repo != "" {
		repoURL = "https://github.com/" + repo
	}

	return best, repoURL + "/releases", nil
}

func extractVersion(raw, customExpr string) string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return ""
	}

	if customExpr != "" {
		re := regexp.MustCompile(customExpr)
		matches := re.FindStringSubmatch(text)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
		}
		if len(matches) == 1 {
			return strings.TrimSpace(matches[0])
		}
	}

	matches := defaultVersionPattern.FindStringSubmatch(text)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	if len(matches) == 1 {
		return strings.TrimSpace(matches[0])
	}

	return ""
}

func normalizeVersionTokens(raw string) []int {
	matches := numericVersionPattern.FindAllString(raw, -1)
	if len(matches) == 0 {
		return nil
	}

	tokens := make([]int, 0, len(matches))
	for _, match := range matches {
		value := 0
		for _, ch := range match {
			value = (value * 10) + int(ch-'0')
		}
		tokens = append(tokens, value)
	}

	return tokens
}

func IsRemoteVersionNewer(local, remote string) bool {
	localTokens := normalizeVersionTokens(local)
	remoteTokens := normalizeVersionTokens(remote)
	if len(localTokens) == 0 || len(remoteTokens) == 0 {
		return false
	}

	maxLen := len(localTokens)
	if len(remoteTokens) > maxLen {
		maxLen = len(remoteTokens)
	}

	for i := 0; i < maxLen; i++ {
		localPart := 0
		remotePart := 0
		if i < len(localTokens) {
			localPart = localTokens[i]
		}
		if i < len(remoteTokens) {
			remotePart = remoteTokens[i]
		}

		if localPart == remotePart {
			continue
		}

		return remotePart > localPart
	}

	return false
}

func upsertPackageUpdate(record PackageUpdateRecord) (bool, bool, error) {
	if db.DB == nil {
		return false, false, nil
	}

	var existing PackageUpdateRecord
	err := db.DB.QueryRow(
		`SELECT package_name, installed_version, latest_version, update_available, update_url, checked_at, last_error
		   FROM app_updates WHERE package_name = ?`,
		record.PackageName,
	).Scan(
		&existing.PackageName,
		&existing.InstalledVersion,
		&existing.LatestVersion,
		&existing.UpdateAvailable,
		&existing.URL,
		&existing.CheckedAt,
		&existing.LastError,
	)
	if err != nil && err != sql.ErrNoRows {
		return false, false, err
	}

	_, err = db.DB.Exec(
		`INSERT INTO app_updates (package_name, installed_version, latest_version, update_available, update_url, checked_at, last_error)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(package_name) DO UPDATE SET
		   installed_version = excluded.installed_version,
		   latest_version = excluded.latest_version,
		   update_available = excluded.update_available,
		   update_url = excluded.update_url,
		   checked_at = excluded.checked_at,
		   last_error = excluded.last_error`,
		record.PackageName,
		record.InstalledVersion,
		record.LatestVersion,
		record.UpdateAvailable,
		record.URL,
		record.CheckedAt,
		record.LastError,
	)
	if err != nil {
		return false, false, err
	}

	changed := existing.PackageName == "" ||
		existing.InstalledVersion != record.InstalledVersion ||
		existing.LatestVersion != record.LatestVersion ||
		existing.UpdateAvailable != record.UpdateAvailable ||
		existing.URL != record.URL ||
		existing.LastError != record.LastError

	notify := changed && !existing.UpdateAvailable && record.UpdateAvailable
	return changed, notify, nil
}

func DeletePackageUpdateRecord(pkgID string) error {
	if db.DB == nil || pkgID == "" {
		return nil
	}

	_, err := db.DB.Exec(`DELETE FROM app_updates WHERE package_name = ?`, pkgID)
	return err
}

func GetPackageUpdateMap() map[string]PackageUpdateRecord {
	if db.DB == nil {
		return nil
	}

	rows, err := db.DB.Query(
		`SELECT package_name, installed_version, latest_version, update_available, update_url, checked_at, last_error
		   FROM app_updates`,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()

	records := make(map[string]PackageUpdateRecord)
	for rows.Next() {
		var record PackageUpdateRecord
		if err := rows.Scan(
			&record.PackageName,
			&record.InstalledVersion,
			&record.LatestVersion,
			&record.UpdateAvailable,
			&record.URL,
			&record.CheckedAt,
			&record.LastError,
		); err != nil {
			continue
		}

		records[record.PackageName] = record
	}

	return records
}
