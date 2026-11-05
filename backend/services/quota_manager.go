package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"aetherflow/db"
	"aetherflow/models"
)

type UserQuotaRecord struct {
	UserID         int     `json:"user_id"`
	Username       string  `json:"username"`
	QuotaBytes     int64   `json:"quota_bytes"`
	UsedBytes      int64   `json:"used_bytes"`
	AvailableBytes int64   `json:"available_bytes"`
	UsagePct       float64 `json:"usage_pct"`
	Configured     bool    `json:"configured"`
	Status         string  `json:"status"`
	Source         string  `json:"source"`
	UpdatedAt      string  `json:"updated_at,omitempty"`

	// Next.js Frontend DTO Harmonization
	UsedGB     float64 `json:"usedGB"`
	TotalGB    float64 `json:"totalGB"`
	Percentage float64 `json:"percentage"`
}

var humanSizePattern = regexp.MustCompile(`(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgtp]?b)\s*$`)

// safeUsername strictly bounds the character set and length of usernames passed to shell commands.
var safeUsername = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}$`)

// validateUsername rejects names that don't match the strict allowlist.
func validateUsername(name string) error {
	if !safeUsername.MatchString(name) {
		return fmt.Errorf("invalid username format: %q", name)
	}
	return nil
}

// ParseHumanSize converts values like 500GB or 2TB into raw bytes.
func ParseHumanSize(input string) (int64, error) {
	return parseHumanSize(input)
}

func resolveSystemScriptPath(envName, fileName string) string {
	if explicit := strings.TrimSpace(os.Getenv(envName)); explicit != "" {
		return explicit
	}

	candidates := []string{
		filepath.Join("/opt", "AetherFlow", "current", "packages", "system", fileName),
		filepath.Join("/opt", "AetherFlow", "packages", "system", fileName),
		filepath.Join("/usr", "local", "bin", "AetherFlow", "system", fileName),
		filepath.Join("packages", "system", fileName),
		filepath.Join("..", "packages", "system", fileName),
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}

	return filepath.Join("packages", "system", fileName)
}

func setdiskScriptPath() string {
	return resolveSystemScriptPath("AF_SETDISK_PATH", "setdisk")
}

// ExecuteSetQuotaLocal directly invokes the setdisk script on the host.
func ExecuteSetQuotaLocal(username, size string) (string, error) {
	scriptPath := setdiskScriptPath()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "bash", scriptPath, "--username", username, "--size", size, "--json").CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("setdisk failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}
	return string(output), nil
}

func showspaceScriptPath() string {
	return resolveSystemScriptPath("AF_SHOWSPACE_PATH", "showspace")
}

func parseHumanSize(input string) (int64, error) {
	matches := humanSizePattern.FindStringSubmatch(strings.TrimSpace(input))
	if len(matches) != 3 {
		return 0, fmt.Errorf("invalid size %q", input)
	}

	value, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size value %q: %w", matches[1], err)
	}

	unit := strings.ToUpper(matches[2])
	multiplier := float64(1)
	switch unit {
	case "KB":
		multiplier = 1024
	case "MB":
		multiplier = 1024 * 1024
	case "GB":
		multiplier = 1024 * 1024 * 1024
	case "TB":
		multiplier = 1024 * 1024 * 1024 * 1024
	case "PB":
		multiplier = 1024 * 1024 * 1024 * 1024 * 1024
	case "B":
		multiplier = 1
	default:
		return 0, fmt.Errorf("unsupported size unit %q", unit)
	}

	return int64(value * multiplier), nil
}

func humanizeBytes(bytes int64) string {
	type unitDef struct {
		label string
		value int64
	}

	units := []unitDef{
		{"PB", 1024 * 1024 * 1024 * 1024 * 1024},
		{"TB", 1024 * 1024 * 1024 * 1024},
		{"GB", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
		{"KB", 1024},
	}

	for _, unit := range units {
		if bytes >= unit.value {
			if bytes%unit.value == 0 {
				return fmt.Sprintf("%d%s", bytes/unit.value, unit.label)
			}
			return fmt.Sprintf("%.1f%s", float64(bytes)/float64(unit.value), unit.label)
		}
	}

	return fmt.Sprintf("%dB", bytes)
}

func quotaScriptSize(bytes int64) string {
	if bytes <= 0 {
		return "0MB"
	}

	type quotaUnit struct {
		label string
		value int64
	}

	units := []quotaUnit{
		{"TB", 1024 * 1024 * 1024 * 1024},
		{"GB", 1024 * 1024 * 1024},
		{"MB", 1024 * 1024},
	}

	for _, unit := range units {
		if bytes >= unit.value {
			rounded := (bytes + unit.value - 1) / unit.value
			return fmt.Sprintf("%d%s", rounded, unit.label)
		}
	}

	return "1MB"
}

func quotaUsagePct(limit, used int64) float64 {
	if limit <= 0 {
		return 0
	}
	return (float64(used) / float64(limit)) * 100
}

func normalizeQuotaRecord(record UserQuotaRecord) UserQuotaRecord {
	record.Configured = record.QuotaBytes > 0
	record.AvailableBytes = 0
	if record.QuotaBytes > 0 {
		record.AvailableBytes = record.QuotaBytes - record.UsedBytes
		if record.AvailableBytes < 0 {
			record.AvailableBytes = 0
		}
	}
	record.UsagePct = quotaUsagePct(record.QuotaBytes, record.UsedBytes)

	// DTO harmonization for Next.js frontend
	record.UsedGB = float64(record.UsedBytes) / (1024 * 1024 * 1024)
	record.TotalGB = float64(record.QuotaBytes) / (1024 * 1024 * 1024)
	record.Percentage = record.UsagePct

	record.Status = strings.ToLower(strings.TrimSpace(record.Status))
	if record.Status == "" {
		record.Status = "active"
	}
	if record.Source != "manual" && record.Source != "runner" {
		record.Source = "manual"
	}
	return record
}

func lookupUserByID(userID int) (models.User, error) {
	var user models.User
	err := db.DB.QueryRow("SELECT id, username, email, avatar_url, role FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role)
	if err != nil {
		return user, err
	}
	return user, nil
}

func upsertUserQuota(record UserQuotaRecord) error {
	record = normalizeQuotaRecord(record)
	_, err := db.DB.Exec(
		`INSERT INTO user_quotas (
			user_id, username, quota_bytes, used_bytes, status, source, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET
			username = excluded.username,
			quota_bytes = excluded.quota_bytes,
			used_bytes = excluded.used_bytes,
			status = excluded.status,
			source = excluded.source,
			updated_at = CURRENT_TIMESTAMP`,
		record.UserID,
		record.Username,
		record.QuotaBytes,
		record.UsedBytes,
		record.Status,
		record.Source,
	)
	return err
}

func getStoredUserQuota(userID int) (UserQuotaRecord, error) {
	record := UserQuotaRecord{UserID: userID}
	err := db.DB.QueryRow(
		`SELECT user_id, username, quota_bytes, used_bytes, status, source, updated_at
		 FROM user_quotas WHERE user_id = ?`,
		userID,
	).Scan(
		&record.UserID,
		&record.Username,
		&record.QuotaBytes,
		&record.UsedBytes,
		&record.Status,
		&record.Source,
		&record.UpdatedAt,
	)
	if err != nil {
		return record, err
	}
	return normalizeQuotaRecord(record), nil
}

func DetectUserUsageBytes(username string) (int64, error) {
	if err := validateUsername(username); err != nil {
		return 0, fmt.Errorf("DetectUserUsageBytes: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scriptPath := showspaceScriptPath()
	output, err := exec.CommandContext(ctx, "bash", scriptPath, "--user", username, "--json").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("showspace failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}

	var payload struct {
		User  string `json:"user"`
		Bytes int64  `json:"bytes"`
	}
	if err := json.Unmarshal(output, &payload); err != nil {
		return 0, fmt.Errorf("showspace output parse failed: %w", err)
	}
	return payload.Bytes, nil
}

func SetQuotaForUserID(userID int, quotaBytes int64, source string) (UserQuotaRecord, error) {
	user, err := lookupUserByID(userID)
	if err != nil {
		return UserQuotaRecord{}, err
	}

	if err := validateUsername(user.Username); err != nil {
		return UserQuotaRecord{}, fmt.Errorf("SetQuotaForUserID: %w", err)
	}

	quotaArg := quotaScriptSize(quotaBytes)
	if IsRunnerAvailable() {
		if err := DispatchSetQuota(user.Username, quotaArg); err != nil {
			return UserQuotaRecord{}, fmt.Errorf("runner setdisk failed: %w", err)
		}
	} else {
		if _, err := ExecuteSetQuotaLocal(user.Username, quotaArg); err != nil {
			return UserQuotaRecord{}, err
		}
	}

	usedBytes, usageErr := DetectUserUsageBytes(user.Username)
	if usageErr != nil {
		usedBytes = 0
	}

	record := UserQuotaRecord{
		UserID:     user.ID,
		Username:   user.Username,
		QuotaBytes: quotaBytes,
		UsedBytes:  usedBytes,
		Status:     "active",
		Source:     source,
	}
	if record.Source == "" {
		record.Source = "manual"
	}
	if err := upsertUserQuota(record); err != nil {
		return UserQuotaRecord{}, err
	}

	return RefreshUserQuotaRecord(userID)
}

func RefreshUserQuotaRecord(userID int) (UserQuotaRecord, error) {
	user, err := lookupUserByID(userID)
	if err != nil {
		return UserQuotaRecord{}, err
	}

	record := UserQuotaRecord{
		UserID:   user.ID,
		Username: user.Username,
		Status:   "active",
		Source:   "manual",
	}

	if stored, err := getStoredUserQuota(userID); err == nil {
		record = stored
		record.Username = user.Username
	} else if err != sql.ErrNoRows {
		return UserQuotaRecord{}, err
	}

	usedBytes, usageErr := DetectUserUsageBytes(user.Username)
	if usageErr != nil {
		if record.QuotaBytes == 0 {
			return UserQuotaRecord{}, usageErr
		}
	} else {
		record.UsedBytes = usedBytes
	}

	if err := upsertUserQuota(record); err != nil {
		return UserQuotaRecord{}, err
	}
	return normalizeQuotaRecord(record), nil
}

func GetUserQuotaRecord(userID int) (UserQuotaRecord, error) {
	record, err := RefreshUserQuotaRecord(userID)
	if err == nil {
		return record, nil
	}

	// Refresh failed (e.g. showspace unavailable) — fall back to stored or default record.
	user, userErr := lookupUserByID(userID)
	if userErr != nil {
		return UserQuotaRecord{}, userErr
	}
	record = UserQuotaRecord{
		UserID:   user.ID,
		Username: user.Username,
		Status:   "active",
		Source:   "manual",
	}
	if stored, storedErr := getStoredUserQuota(userID); storedErr == nil {
		record = stored
		record.Username = user.Username
	}
	return normalizeQuotaRecord(record), nil
}

func ListUserQuotaRecords() ([]UserQuotaRecord, error) {
	rows, err := db.DB.Query(
		`SELECT
			u.id,
			u.username,
			COALESCE(q.quota_bytes, 0),
			COALESCE(q.used_bytes, 0),
			COALESCE(q.status, 'active'),
			COALESCE(q.source, 'manual'),
			COALESCE(q.updated_at, '')
		FROM users u
		LEFT JOIN user_quotas q ON q.user_id = u.id
		ORDER BY u.username ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []UserQuotaRecord
	for rows.Next() {
		var record UserQuotaRecord
		if err := rows.Scan(
			&record.UserID,
			&record.Username,
			&record.QuotaBytes,
			&record.UsedBytes,
			&record.Status,
			&record.Source,
			&record.UpdatedAt,
		); err != nil {
			return nil, err
		}
		records = append(records, normalizeQuotaRecord(record))
	}

	if records == nil {
		records = []UserQuotaRecord{}
	}
	return records, nil
}

func HasQuotaHeadroom(userID int, incomingBytes int64) (bool, UserQuotaRecord, error) {
	record, err := GetUserQuotaRecord(userID)
	if err != nil {
		return false, UserQuotaRecord{}, err
	}
	if !record.Configured || record.QuotaBytes <= 0 {
		return true, record, nil
	}
	return record.UsedBytes+incomingBytes <= record.QuotaBytes, record, nil
}
