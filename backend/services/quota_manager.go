package services

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"aetherflow/db"
	"aetherflow/models"
)

type UserQuotaRecord struct {
	UserID            int     `json:"user_id"`
	Username          string  `json:"username"`
	QuotaBytes        int64   `json:"quota_bytes"`
	UsedBytes         int64   `json:"used_bytes"`
	AvailableBytes    int64   `json:"available_bytes"`
	UsagePct          float64 `json:"usage_pct"`
	Configured        bool    `json:"configured"`
	Status            string  `json:"status"`
	Source            string  `json:"source"`
	BillingProvider   string  `json:"billing_provider,omitempty"`
	BillingExternalID string  `json:"billing_external_id,omitempty"`
	UpdatedAt         string  `json:"updated_at,omitempty"`
}

type BillingWebhookAudit struct {
	ID         int    `json:"id"`
	Provider   string `json:"provider"`
	EventID    string `json:"event_id"`
	EventType  string `json:"event_type"`
	Username   string `json:"username"`
	QuotaBytes int64  `json:"quota_bytes"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	Payload    string `json:"payload,omitempty"`
	ProcessedAt string `json:"processed_at"`
}

type BillingWebhookResult struct {
	Provider     string          `json:"provider"`
	EventID      string          `json:"event_id"`
	EventType    string          `json:"event_type"`
	Username     string          `json:"username"`
	QuotaBytes   int64           `json:"quota_bytes"`
	Applied      bool            `json:"applied"`
	Status       string          `json:"status"`
	Message      string          `json:"message"`
	Quota        *UserQuotaRecord `json:"quota,omitempty"`
}

type billingEvent struct {
	Provider    string
	EventID     string
	EventType   string
	Username    string
	Email       string
	Plan        string
	ExternalID  string
	QuotaBytes  int64
	Raw         map[string]interface{}
	RawPayload  string
}

var humanSizePattern = regexp.MustCompile(`(?i)^\s*([0-9]+(?:\.[0-9]+)?)\s*([kmgtp]?b)\s*$`)

// ParseHumanSize converts values like 500GB or 2TB into raw bytes.
func ParseHumanSize(input string) (int64, error) {
	return parseHumanSize(input)
}

func resolveSystemScriptPath(envName, fileName string) string {
	if explicit := strings.TrimSpace(os.Getenv(envName)); explicit != "" {
		return explicit
	}

	candidates := []string{
		filepath.Join("packages", "system", fileName),
		filepath.Join("..", "packages", "system", fileName),
		filepath.Join("/opt", "AetherFlow", "packages", "system", fileName),
	}

	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	return filepath.Join("packages", "system", fileName)
}

func setdiskScriptPath() string {
	return resolveSystemScriptPath("AF_SETDISK_PATH", "setdisk")
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
	if record.Status == "" {
		record.Status = "active"
	}
	if record.Source == "" {
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

func lookupUserForBilling(username, email string) (models.User, error) {
	var user models.User
	if username != "" {
		err := db.DB.QueryRow("SELECT id, username, email, avatar_url, role FROM users WHERE username = ?", username).
			Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role)
		if err == nil {
			return user, nil
		}
		if err != sql.ErrNoRows {
			return user, err
		}
	}
	if email != "" {
		err := db.DB.QueryRow("SELECT id, username, email, avatar_url, role FROM users WHERE email = ?", email).
			Scan(&user.ID, &user.Username, &user.Email, &user.AvatarURL, &user.Role)
		if err == nil {
			return user, nil
		}
		if err != sql.ErrNoRows {
			return user, err
		}
	}
	return user, sql.ErrNoRows
}

func upsertUserQuota(record UserQuotaRecord) error {
	record = normalizeQuotaRecord(record)
	_, err := db.DB.Exec(
		`INSERT INTO user_quotas (
			user_id, username, quota_bytes, used_bytes, status, source, billing_provider, billing_external_id, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(user_id) DO UPDATE SET
			username = excluded.username,
			quota_bytes = excluded.quota_bytes,
			used_bytes = excluded.used_bytes,
			status = excluded.status,
			source = excluded.source,
			billing_provider = excluded.billing_provider,
			billing_external_id = excluded.billing_external_id,
			updated_at = CURRENT_TIMESTAMP`,
		record.UserID,
		record.Username,
		record.QuotaBytes,
		record.UsedBytes,
		record.Status,
		record.Source,
		record.BillingProvider,
		record.BillingExternalID,
	)
	return err
}

func getStoredUserQuota(userID int) (UserQuotaRecord, error) {
	record := UserQuotaRecord{UserID: userID}
	err := db.DB.QueryRow(
		`SELECT user_id, username, quota_bytes, used_bytes, status, source, billing_provider, billing_external_id, updated_at
		 FROM user_quotas WHERE user_id = ?`,
		userID,
	).Scan(
		&record.UserID,
		&record.Username,
		&record.QuotaBytes,
		&record.UsedBytes,
		&record.Status,
		&record.Source,
		&record.BillingProvider,
		&record.BillingExternalID,
		&record.UpdatedAt,
	)
	if err != nil {
		return record, err
	}
	return normalizeQuotaRecord(record), nil
}

func DetectUserUsageBytes(username string) (int64, error) {
	scriptPath := showspaceScriptPath()
	output, err := exec.Command("bash", scriptPath, "--user", username, "--json").CombinedOutput()
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

func SetQuotaForUserID(userID int, quotaBytes int64, source, provider, externalID string) (UserQuotaRecord, error) {
	user, err := lookupUserByID(userID)
	if err != nil {
		return UserQuotaRecord{}, err
	}

	quotaArg := quotaScriptSize(quotaBytes)
	scriptPath := setdiskScriptPath()
	output, err := exec.Command("bash", scriptPath, "--username", user.Username, "--size", quotaArg, "--json").CombinedOutput()
	if err != nil {
		return UserQuotaRecord{}, fmt.Errorf("setdisk failed: %w (%s)", err, strings.TrimSpace(string(output)))
	}

	usedBytes, usageErr := DetectUserUsageBytes(user.Username)
	if usageErr != nil {
		usedBytes = 0
	}

	record := UserQuotaRecord{
		UserID:            user.ID,
		Username:          user.Username,
		QuotaBytes:        quotaBytes,
		UsedBytes:         usedBytes,
		Status:            "active",
		Source:            source,
		BillingProvider:   provider,
		BillingExternalID: externalID,
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
			COALESCE(q.billing_provider, ''),
			COALESCE(q.billing_external_id, ''),
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
			&record.BillingProvider,
			&record.BillingExternalID,
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

func billingSecret(provider string) string {
	envKey := strings.ToUpper(provider) + "_WEBHOOK_SECRET"
	if value := strings.TrimSpace(os.Getenv(envKey)); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv("BILLING_WEBHOOK_SECRET"))
}

func verifySharedSecret(expected, actual string) bool {
	return subtle.ConstantTimeCompare([]byte(expected), []byte(actual)) == 1
}

func verifyWebhookHMAC(signature string, body []byte, secret string) bool {
	value := strings.TrimSpace(signature)
	value = strings.TrimPrefix(value, "sha256=")
	value = strings.TrimPrefix(value, "SHA256=")

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)

	if decoded, err := hex.DecodeString(value); err == nil {
		return hmac.Equal(decoded, expected)
	}
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil {
		return hmac.Equal(decoded, expected)
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(value); err == nil {
		return hmac.Equal(decoded, expected)
	}
	return false
}

func VerifyBillingWebhookRequest(provider string, headers http.Header, body []byte) error {
	secret := billingSecret(provider)
	if secret == "" {
		return fmt.Errorf("%s webhook secret is not configured", provider)
	}

	if auth := strings.TrimSpace(headers.Get("Authorization")); strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		if verifySharedSecret(secret, strings.TrimSpace(auth[7:])) {
			return nil
		}
	}

	tokenHeaders := []string{
		"X-AetherFlow-Token",
		"X-Webhook-Token",
		"X-WHMCS-Token",
		"X-BLESTA-Token",
	}
	for _, header := range tokenHeaders {
		if value := strings.TrimSpace(headers.Get(header)); value != "" && verifySharedSecret(secret, value) {
			return nil
		}
	}

	signatureHeaders := []string{
		"X-AetherFlow-Signature",
		"X-Webhook-Signature",
		"X-WHMCS-Signature",
		"X-BLESTA-Signature",
	}
	for _, header := range signatureHeaders {
		if value := strings.TrimSpace(headers.Get(header)); value != "" && verifyWebhookHMAC(value, body, secret) {
			return nil
		}
	}

	return fmt.Errorf("missing or invalid %s webhook signature", provider)
}

func lookupNestedValue(data map[string]interface{}, path string) (interface{}, bool) {
	current := interface{}(data)
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		next, ok := object[segment]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func stringifyValue(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

func firstString(data map[string]interface{}, paths ...string) string {
	for _, path := range paths {
		if value, ok := lookupNestedValue(data, path); ok {
			if stringValue := stringifyValue(value); stringValue != "" {
				return stringValue
			}
		}
	}
	return ""
}

func firstSizeValue(data map[string]interface{}, paths ...string) int64 {
	for _, path := range paths {
		value, ok := lookupNestedValue(data, path)
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case float64:
			if typed > 0 {
				return int64(typed)
			}
		case json.Number:
			if parsed, err := typed.Int64(); err == nil && parsed > 0 {
				return parsed
			}
		case string:
			if parsed, err := parseHumanSize(typed); err == nil && parsed > 0 {
				return parsed
			}
			if numeric, err := strconv.ParseInt(strings.TrimSpace(typed), 10, 64); err == nil && numeric > 0 {
				return numeric
			}
		}
	}
	return 0
}

func quotaBytesFromPlan(plan string) int64 {
	if plan == "" {
		return 0
	}

	raw := strings.TrimSpace(os.Getenv("BILLING_QUOTA_PLAN_MAP"))
	if raw == "" {
		return 0
	}

	var mapping map[string]string
	if err := json.Unmarshal([]byte(raw), &mapping); err != nil {
		return 0
	}

	for key, value := range mapping {
		if strings.EqualFold(strings.TrimSpace(key), strings.TrimSpace(plan)) {
			quotaBytes, err := parseHumanSize(value)
			if err == nil {
				return quotaBytes
			}
		}
	}
	return 0
}

func extractBillingEvent(provider string, body []byte) (billingEvent, error) {
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		return billingEvent{}, err
	}

	eventType := firstString(payload,
		"event_type",
		"event",
		"type",
		"action",
		"name",
	)
	if eventType == "" {
		eventType = "unknown"
	}

	eventID := firstString(payload,
		"event_id",
		"webhook_id",
		"uuid",
		"id",
	)
	if eventID == "" {
		sum := sha256.Sum256(body)
		eventID = hex.EncodeToString(sum[:16])
	}

	username := firstString(payload,
		"username",
		"user.username",
		"service.username",
		"client.username",
		"metadata.username",
		"custom_fields.username",
	)
	email := firstString(payload,
		"email",
		"user.email",
		"client.email",
		"service.email",
	)
	plan := firstString(payload,
		"plan",
		"plan_name",
		"product.name",
		"product_name",
		"service.package",
		"configoptions.diskspace_plan",
	)
	externalID := firstString(payload,
		"service_id",
		"service.id",
		"invoice_id",
		"client_id",
	)
	quotaBytes := firstSizeValue(payload,
		"quota_bytes",
		"disk_bytes",
		"service.quota_bytes",
		"service.disk_bytes",
		"quota",
		"diskspace",
		"service.quota",
		"service.diskspace",
		"configoptions.diskspace",
	)
	if quotaBytes == 0 {
		quotaBytes = quotaBytesFromPlan(plan)
	}

	return billingEvent{
		Provider:   provider,
		EventID:    eventID,
		EventType:  strings.ToLower(eventType),
		Username:   username,
		Email:      email,
		Plan:       plan,
		ExternalID: externalID,
		QuotaBytes: quotaBytes,
		Raw:        payload,
		RawPayload: string(body),
	}, nil
}

func recordBillingWebhookAudit(provider, eventID, eventType, username string, quotaBytes int64, status, errorMessage, payload string) error {
	_, err := db.DB.Exec(
		`INSERT INTO billing_webhook_events (
			provider, event_id, event_type, username, quota_bytes, status, error, payload, processed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(provider, event_id) DO UPDATE SET
			event_type = excluded.event_type,
			username = excluded.username,
			quota_bytes = excluded.quota_bytes,
			status = excluded.status,
			error = excluded.error,
			payload = excluded.payload,
			processed_at = CURRENT_TIMESTAMP`,
		provider,
		eventID,
		eventType,
		username,
		quotaBytes,
		status,
		errorMessage,
		payload,
	)
	return err
}

func updateBillingQuotaStatus(userID int, username, provider, externalID, status string) (UserQuotaRecord, error) {
	record, err := GetUserQuotaRecord(userID)
	if err != nil {
		return UserQuotaRecord{}, err
	}
	record.Username = username
	record.Status = status
	record.BillingProvider = provider
	record.BillingExternalID = externalID
	record.Source = "billing_webhook"
	if err := upsertUserQuota(record); err != nil {
		return UserQuotaRecord{}, err
	}
	return GetUserQuotaRecord(userID)
}

func ProcessBillingWebhook(provider string, headers http.Header, body []byte) (BillingWebhookResult, error) {
	if err := VerifyBillingWebhookRequest(provider, headers, body); err != nil {
		return BillingWebhookResult{}, err
	}

	event, err := extractBillingEvent(provider, body)
	if err != nil {
		return BillingWebhookResult{}, err
	}

	result := BillingWebhookResult{
		Provider:   provider,
		EventID:    event.EventID,
		EventType:  event.EventType,
		Username:   event.Username,
		QuotaBytes: event.QuotaBytes,
		Status:     "received",
		Message:    "Webhook accepted",
	}

	user, userErr := lookupUserForBilling(event.Username, event.Email)
	if userErr == sql.ErrNoRows {
		result.Status = "ignored"
		result.Message = "No local user matched the billing payload"
		recordBillingWebhookAudit(provider, event.EventID, event.EventType, event.Username, event.QuotaBytes, result.Status, result.Message, event.RawPayload)
		return result, nil
	}
	if userErr != nil {
		recordBillingWebhookAudit(provider, event.EventID, event.EventType, event.Username, event.QuotaBytes, "error", userErr.Error(), event.RawPayload)
		return BillingWebhookResult{}, userErr
	}
	result.Username = user.Username

	switch {
	case strings.Contains(event.EventType, "suspend"), strings.Contains(event.EventType, "cancel"), strings.Contains(event.EventType, "terminate"):
		record, err := updateBillingQuotaStatus(user.ID, user.Username, provider, event.ExternalID, "suspended")
		if err != nil {
			recordBillingWebhookAudit(provider, event.EventID, event.EventType, user.Username, event.QuotaBytes, "error", err.Error(), event.RawPayload)
			return BillingWebhookResult{}, err
		}
		result.Status = "suspended"
		result.Message = "Quota record marked as suspended"
		result.Quota = &record
	case event.QuotaBytes > 0:
		record, err := SetQuotaForUserID(user.ID, event.QuotaBytes, "billing_webhook", provider, event.ExternalID)
		if err != nil {
			recordBillingWebhookAudit(provider, event.EventID, event.EventType, user.Username, event.QuotaBytes, "error", err.Error(), event.RawPayload)
			return BillingWebhookResult{}, err
		}
		result.Status = "applied"
		result.Applied = true
		result.Message = "Quota updated from billing event"
		result.Quota = &record
	default:
		record, err := updateBillingQuotaStatus(user.ID, user.Username, provider, event.ExternalID, "active")
		if err != nil {
			recordBillingWebhookAudit(provider, event.EventID, event.EventType, user.Username, event.QuotaBytes, "error", err.Error(), event.RawPayload)
			return BillingWebhookResult{}, err
		}
		result.Status = "recorded"
		result.Message = "Webhook recorded without a quota change"
		result.Quota = &record
	}

	if err := recordBillingWebhookAudit(provider, event.EventID, event.EventType, user.Username, event.QuotaBytes, result.Status, "", event.RawPayload); err != nil {
		return BillingWebhookResult{}, err
	}

	if Notifier != nil {
		message := result.Message
		if result.Quota != nil && result.Quota.Configured {
			message = fmt.Sprintf("%s for %s (%s)", result.Message, result.Username, humanizeBytes(result.Quota.QuotaBytes))
		}
		Notifier.Dispatch(Notification{
			Level:   NotifyInfo,
			Title:   strings.ToUpper(provider) + " billing webhook",
			Message: message,
		})
	}

	return result, nil
}

func ListBillingWebhookAudits(limit int) ([]BillingWebhookAudit, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := db.DB.Query(
		`SELECT id, provider, event_id, event_type, username, quota_bytes, status, error, payload, processed_at
		 FROM billing_webhook_events
		 ORDER BY processed_at DESC
		 LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var audits []BillingWebhookAudit
	for rows.Next() {
		var audit BillingWebhookAudit
		if err := rows.Scan(
			&audit.ID,
			&audit.Provider,
			&audit.EventID,
			&audit.EventType,
			&audit.Username,
			&audit.QuotaBytes,
			&audit.Status,
			&audit.Error,
			&audit.Payload,
			&audit.ProcessedAt,
		); err != nil {
			return nil, err
		}
		audits = append(audits, audit)
	}

	if audits == nil {
		audits = []BillingWebhookAudit{}
	}
	return audits, nil
}
