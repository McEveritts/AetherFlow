package models

type Package struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
	LockFile    string `json:"lock_file"`
	Category    string `json:"category"`

	// Service/runtime metadata
	Hits        int    `json:"hits"`
	Status      string `json:"status"`
	ServiceType string `json:"service_type"`
	ServiceName string `json:"service_name"`

	// Automation metadata loaded from config/package_automation.json
	UpdateSource      string   `json:"update_source,omitempty"`
	UpdateRepo        string   `json:"update_repo,omitempty"`
	UpdateRepoURL     string   `json:"update_repo_url,omitempty"`
	UpdatePackage     string   `json:"update_package,omitempty"`
	VersionCommand    []string `json:"version_command,omitempty"`
	VersionRegex      string   `json:"version_regex,omitempty"`
	SandboxProfile    string   `json:"sandbox_profile,omitempty"`
	SandboxReadWrite  []string `json:"sandbox_rw_paths,omitempty"`
	SandboxServiceIDs []string `json:"sandbox_service_units,omitempty"`

	// Update watcher fields
	InstalledVersion string `json:"installed_version,omitempty"`
	LatestVersion    string `json:"latest_version,omitempty"`
	UpdateAvailable  bool   `json:"update_available"`
	UpdateCheckedAt  string `json:"update_checked_at,omitempty"`
	UpdateURL        string `json:"update_url,omitempty"`
	UpdateError      string `json:"update_error,omitempty"`
}

type PackageAutomation struct {
	UpdateSource      string   `json:"update_source,omitempty"`
	UpdateRepo        string   `json:"update_repo,omitempty"`
	UpdateRepoURL     string   `json:"update_repo_url,omitempty"`
	UpdatePackage     string   `json:"update_package,omitempty"`
	VersionCommand    []string `json:"version_command,omitempty"`
	VersionRegex      string   `json:"version_regex,omitempty"`
	SandboxProfile    string   `json:"sandbox_profile,omitempty"`
	SandboxReadWrite  []string `json:"sandbox_rw_paths,omitempty"`
	SandboxServiceIDs []string `json:"sandbox_service_units,omitempty"`
}
