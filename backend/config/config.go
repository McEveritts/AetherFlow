package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// ── Phase 19: Centralized Configuration Management ─────────────────────
//
// All environment variables SHOULD be read here at startup.
// Runtime code accesses config via the global `Cfg` variable instead of
// calling os.Getenv() directly. This provides:
//   - Fail-fast validation at boot (missing required vars = immediate exit)
//   - Type-safe access (durations, booleans, integers — not strings)
//   - Single source of truth for defaults
//   - Easy auditing of all configuration knobs

// Cfg is the global application configuration, populated once at startup.
var Cfg *AppConfig

// AppConfig holds all application configuration derived from environment variables.
type AppConfig struct {
	// ── Server ──────────────────────────────────────────────────────────
	Port             string
	AllowedHosts     []string
	AllowedCORSOrigin string
	CookieSecure     bool
	CSRFDisabled     bool

	// ── Database ────────────────────────────────────────────────────────
	DBPath        string
	RedisAddr     string
	RedisPassword string

	// ── Auth ────────────────────────────────────────────────────────────
	JWTSecret       string
	AdminEmail      string
	GoogleClientID  string
	GoogleSecret    string
	GoogleRedirect  string

	// ── OIDC ────────────────────────────────────────────────────────────
	OIDCKeyPath string
	OIDCIssuer  string

	// ── AI ──────────────────────────────────────────────────────────────
	GeminiAPIKey string

	// ── Encryption ──────────────────────────────────────────────────────
	AESMasterKey string

	// ── Billing ─────────────────────────────────────────────────────────
	BillingWebhookSecret string
	BillingQuotaPlanMap  string

	// ── Cluster ─────────────────────────────────────────────────────────
	ClusterMode       string // "master", "worker", ""
	ClusterMasterAddr string
	ClusterPSK        string
	ClusterCACert     string
	ClusterServerCert string
	ClusterServerKey  string
	ClusterClientCert string
	ClusterClientKey  string
	GRPCHost          string
	GRPCPort          string

	// ── File Sharing ────────────────────────────────────────────────────
	UploadDir string

	// ── Updates ─────────────────────────────────────────────────────────
	UpdateWatchInterval time.Duration
	GitHubAPIBaseURL    string
}

// Load reads all environment variables into the AppConfig struct.
// Call this once at application startup, after loading .env files.
func Load() {
	cfg := &AppConfig{
		// Server
		Port:              envOr("PORT", "8443"),
		AllowedHosts:      splitCSV(os.Getenv("ALLOWED_HOSTS")),
		AllowedCORSOrigin: os.Getenv("ALLOWED_CORS_ORIGIN"),
		CookieSecure:      strings.ToLower(os.Getenv("COOKIE_SECURE")) != "false",
		CSRFDisabled:      strings.ToLower(os.Getenv("CSRF_DISABLED")) == "true",

		// Database
		DBPath:        envOr("DB_PATH", "aetherflow.db"),
		RedisAddr:     envOr("REDIS_ADDR", "localhost:6379"),
		RedisPassword: os.Getenv("REDIS_PASSWORD"),

		// Auth
		JWTSecret:      os.Getenv("JWT_SECRET"),
		AdminEmail:     os.Getenv("ADMIN_EMAIL"),
		GoogleClientID: os.Getenv("GOOGLE_CLIENT_ID"),
		GoogleSecret:   os.Getenv("GOOGLE_CLIENT_SECRET"),
		GoogleRedirect: os.Getenv("GOOGLE_REDIRECT_URI"),

		// OIDC
		OIDCKeyPath: envOr("OIDC_KEY_PATH", "oidc_rsa.pem"),
		OIDCIssuer:  os.Getenv("OIDC_ISSUER"),

		// AI
		GeminiAPIKey: os.Getenv("GEMINI_API_KEY"),

		// Encryption
		AESMasterKey: os.Getenv("AES_MASTER_KEY"),

		// Billing
		BillingWebhookSecret: coalesce(
			os.Getenv("BILLING_WEBHOOK_SECRET"),
			os.Getenv("WHMCS_WEBHOOK_SECRET"),
			os.Getenv("BLESTA_WEBHOOK_SECRET"),
		),
		BillingQuotaPlanMap: os.Getenv("BILLING_QUOTA_PLAN_MAP"),

		// Cluster
		ClusterMode:       os.Getenv("CLUSTER_MODE"),
		ClusterMasterAddr: os.Getenv("CLUSTER_MASTER_ADDR"),
		ClusterPSK:        os.Getenv("CLUSTER_PSK"),
		ClusterCACert:     os.Getenv("CLUSTER_CA_CERT"),
		ClusterServerCert: os.Getenv("CLUSTER_SERVER_CERT"),
		ClusterServerKey:  os.Getenv("CLUSTER_SERVER_KEY"),
		ClusterClientCert: os.Getenv("CLUSTER_CLIENT_CERT"),
		ClusterClientKey:  os.Getenv("CLUSTER_CLIENT_KEY"),
		GRPCHost:          envOr("GRPC_HOST", "0.0.0.0"),
		GRPCPort:          envOr("GRPC_PORT", "50051"),

		// File Sharing
		UploadDir: envOr("AETHERFLOW_UPLOAD_DIR", "/srv/aetherflow/uploads"),

		// Updates
		UpdateWatchInterval: parseDurationOr("AETHERFLOW_UPDATE_WATCH_INTERVAL", 6*time.Hour),
		GitHubAPIBaseURL:    envOr("AETHERFLOW_GITHUB_API_BASE_URL", "https://api.github.com"),
	}

	Cfg = cfg
	slog.Info("configuration loaded")
	logConfigSummary(cfg)
}

// Validate checks for critical misconfigurations and logs warnings.
// Returns an error only for truly fatal issues.
func Validate() error {
	if Cfg == nil {
		return fmt.Errorf("config.Load() must be called before config.Validate()")
	}

	var warnings []string

	if Cfg.JWTSecret == "" {
		warnings = append(warnings, "JWT_SECRET is empty — sessions will use an insecure default key")
	}

	if Cfg.AESMasterKey == "" {
		warnings = append(warnings, "AES_MASTER_KEY is empty — API keys stored in plaintext")
	}

	if Cfg.BillingWebhookSecret == "" {
		warnings = append(warnings, "No billing webhook secret configured (BILLING_WEBHOOK_SECRET)")
	}

	if len(Cfg.AllowedHosts) == 0 {
		warnings = append(warnings, "ALLOWED_HOSTS is empty — host validation disabled")
	}

	for _, w := range warnings {
		slog.Warn("configuration warning", "issue", w)
	}

	return nil
}

// ── Helpers ─────────────────────────────────────────────────────────────

// envOr returns the environment variable value or a default.
func envOr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// splitCSV splits a comma-separated env var into a trimmed string slice.
func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// coalesce returns the first non-empty string from the arguments.
func coalesce(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseDurationOr parses a duration from an env var or returns a default.
func parseDurationOr(key string, defaultVal time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		slog.Warn("invalid duration in config, using default", "key", key, "value", raw, "default", defaultVal)
		return defaultVal
	}
	return d
}

// logConfigSummary logs a summary of the loaded configuration (masking secrets).
func logConfigSummary(cfg *AppConfig) {
	slog.Info("config summary",
		"port", cfg.Port,
		"db", cfg.DBPath,
		"redis", cfg.RedisAddr,
		"cluster", cfg.ClusterMode,
		"csrf_disabled", cfg.CSRFDisabled,
	)
	if cfg.GoogleClientID != "" {
		slog.Info("Google OAuth enabled", "client_id_prefix", cfg.GoogleClientID[:min(8, len(cfg.GoogleClientID))])
	}
	if cfg.GeminiAPIKey != "" {
		slog.Info("Gemini API key present")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
