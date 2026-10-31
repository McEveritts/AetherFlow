package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"aetherflow/db"
)

const (
	jellyfinTicksPerSecond = 10_000_000
	maxUpstreamPayloadSize = 4 * 1024 * 1024 // 4 MB cap for upstream API responses
	maxArtworkPayloadSize  = 8 * 1024 * 1024 // 8 MB cap for poster/backdrop images
)

// StreamingLibraryCounts holds item counts from the media server library.
type StreamingLibraryCounts struct {
	Movies   int `json:"movies"`
	Series   int `json:"series"`
	Episodes int `json:"episodes"`
	Audio    int `json:"audio"`
}

// StreamingServerStatus represents a media server provider card in the dashboard.
type StreamingServerStatus struct {
	Provider        string                 `json:"provider"`        // "jellyfin", "plex", "emby"
	Name            string                 `json:"name"`            // e.g. "Jellyfin"
	URL             string                 `json:"url"`             // e.g. "http://127.0.0.1:8096"
	APIKeyMasked    string                 `json:"apiKeyMasked"`    // "****abcd" or ""
	Configured      bool                   `json:"configured"`      // true if API key is configured
	Enabled         bool                   `json:"enabled"`         // true if enabled
	Status          string                 `json:"status"`          // "connected", "unreachable", "unconfigured", "coming_soon", "demo"
	SupportStage    string                 `json:"supportStage"`    // "active" for jellyfin, "coming_soon" for plex/emby
	ServerID        string                 `json:"serverId"`        // Upstream server ID
	Version         string                 `json:"version"`         // Upstream server version
	OperatingSystem string                 `json:"operatingSystem"` // Upstream OS
	LastConnectedAt string                 `json:"lastConnectedAt"`
	LibraryCounts   StreamingLibraryCounts `json:"libraryCounts"`
	ErrorMessage    string                 `json:"errorMessage,omitempty"`
}

// ActiveStreamSession represents a live playback session with rich stream and bandwidth telemetry.
type ActiveStreamSession struct {
	SessionID            string   `json:"sessionId"`
	Provider             string   `json:"provider"`
	ServerName           string   `json:"serverName"`
	UserID               string   `json:"userId"`
	UserName             string   `json:"userName"`
	ClientName           string   `json:"clientName"`
	DeviceName           string   `json:"deviceName"`
	DeviceID             string   `json:"deviceId"`
	AppVersion           string   `json:"appVersion"`
	IPAddress            string   `json:"ipAddress"`
	IsLAN                bool     `json:"isLan"`
	ItemID               string   `json:"itemId"`
	ItemName             string   `json:"itemName"`
	ItemType             string   `json:"itemType"` // Movie, Episode, Audio, LiveTV
	SeriesName           string   `json:"seriesName,omitempty"`
	SeriesID             string   `json:"seriesId,omitempty"`
	SeasonNumber         int      `json:"seasonNumber,omitempty"`
	EpisodeNumber        int      `json:"episodeNumber,omitempty"`
	ProductionYear       int      `json:"productionYear,omitempty"`
	HasArtwork           bool     `json:"hasArtwork"`
	ArtworkItemID        string   `json:"artworkItemId,omitempty"`
	State                string   `json:"state"` // "playing" | "paused"
	PositionSecs         int      `json:"positionSecs"`
	DurationSecs         int      `json:"durationSecs"`
	ProgressPct          float64  `json:"progressPct"`
	PlayMethod           string   `json:"playMethod"` // "DirectPlay" | "DirectStream" | "Transcode"
	Container            string   `json:"container"`
	TargetContainer      string   `json:"targetContainer,omitempty"`
	VideoCodec           string   `json:"videoCodec"`
	TargetVideoCodec     string   `json:"targetVideoCodec,omitempty"`
	VideoResolution      string   `json:"videoResolution"`
	VideoRange           string   `json:"videoRange"` // SDR, HDR10, Dolby Vision
	VideoFramerate       float64  `json:"videoFramerate,omitempty"`
	IsVideoDirect        bool     `json:"isVideoDirect"`
	AudioCodec           string   `json:"audioCodec"`
	TargetAudioCodec     string   `json:"targetAudioCodec,omitempty"`
	AudioChannels        int      `json:"audioChannels"`
	AudioLayout          string   `json:"audioLayout"`
	AudioLanguage        string   `json:"audioLanguage,omitempty"`
	IsAudioDirect        bool     `json:"isAudioDirect"`
	SubtitleCodec        string   `json:"subtitleCodec,omitempty"`
	SubtitleLanguage     string   `json:"subtitleLanguage,omitempty"`
	HWAccel              string   `json:"hwAccel,omitempty"`
	TranscodeReasons     []string `json:"transcodeReasons"`
	TranscodeProgressPct float64  `json:"transcodeProgressPct,omitempty"`
	TranscodeFps         float64  `json:"transcodeFps,omitempty"`
	BitrateBps            int64    `json:"bitrateBps"`
	BandwidthMbps         float64  `json:"bandwidthMbps"`
	SessionDataBytes      int64    `json:"sessionDataBytes"`
	StartedAt             string   `json:"startedAt"`
	PlaySessionID         string   `json:"playSessionId,omitempty"`
	MediaSourceID         string   `json:"mediaSourceId,omitempty"`
	SupportsMediaControl  bool     `json:"supportsMediaControl"`
	SupportsRemoteControl bool     `json:"supportsRemoteControl"`
	CanSendMessage        bool     `json:"canSendMessage"`
	SupportedCommands     []string `json:"supportedCommands,omitempty"`
}

// StreamingLiveSummary aggregates real-time session and bandwidth metrics.
type StreamingLiveSummary struct {
	ActiveStreams       int     `json:"activeStreams"`
	DirectPlayCount     int     `json:"directPlayCount"`
	DirectStreamCount   int     `json:"directStreamCount"`
	TranscodeCount      int     `json:"transcodeCount"`
	TotalBitrateBps     int64   `json:"totalBitrateBps"`
	TotalBandwidthMbps  float64 `json:"totalBandwidthMbps"`
	ActiveSessionBytes  int64   `json:"activeSessionBytes"`
	LANStreams          int     `json:"lanStreams"`
	WANStreams          int     `json:"wanStreams"`
	IsDemoMode          bool    `json:"isDemoMode"`
}

// StreamTypeDistribution holds counts and percentages by play method.
type StreamTypeDistribution struct {
	DirectPlayCount   int     `json:"directPlayCount"`
	DirectPlayPct     float64 `json:"directPlayPct"`
	DirectStreamCount int     `json:"directStreamCount"`
	DirectStreamPct   float64 `json:"directStreamPct"`
	TranscodeCount    int     `json:"transcodeCount"`
	TranscodePct      float64 `json:"transcodePct"`
}

// BreakdownEntry represents a single category in a distribution breakdown (media type, codec, resolution).
type BreakdownEntry struct {
	Label         string  `json:"label"`
	Count         int     `json:"count"`
	Pct           float64 `json:"pct"`
	WatchTimeSecs int64   `json:"watchTimeSecs"`
	DataUsedBytes int64   `json:"dataUsedBytes"`
}

// StreamingTimeSeriesPoint represents a daily aggregation of plays, watch time, and data usage.
type StreamingTimeSeriesPoint struct {
	Date              string  `json:"date"`
	Plays             int     `json:"plays"`
	WatchTimeSecs     int64   `json:"watchTimeSecs"`
	DataUsedBytes     int64   `json:"dataUsedBytes"`
	PeakBandwidthMbps float64 `json:"peakBandwidthMbps"`
	DirectPlayCount   int     `json:"directPlayCount"`
	DirectStreamCount int     `json:"directStreamCount"`
	TranscodeCount    int     `json:"transcodeCount"`
}

// StreamingUserStat represents per-user leaderboard metrics.
type StreamingUserStat struct {
	UserID            string  `json:"userId"`
	UserName          string  `json:"userName"`
	Provider          string  `json:"provider"`
	TotalPlays        int     `json:"totalPlays"`
	TotalWatchSecs    int64   `json:"totalWatchSecs"`
	TotalDataBytes    int64   `json:"totalDataBytes"`
	UniqueItems       int     `json:"uniqueItems"`
	DirectPlayCount   int     `json:"directPlayCount"`
	TranscodeCount    int     `json:"transcodeCount"`
	AvgCompletionPct  float64 `json:"avgCompletionPct"`
	LastDevice        string  `json:"lastDevice"`
	LastSeenAt        string  `json:"lastSeenAt"`
}

// StreamingTitleStat represents top-watched media items.
type StreamingTitleStat struct {
	ItemID           string  `json:"itemId"`
	ItemName         string  `json:"itemName"`
	ItemType         string  `json:"itemType"`
	SeriesName       string  `json:"seriesName,omitempty"`
	ProductionYear   int     `json:"productionYear,omitempty"`
	Provider         string  `json:"provider"`
	VideoResolution  string  `json:"videoResolution"`
	VideoCodec       string  `json:"videoCodec"`
	TotalPlays       int     `json:"totalPlays"`
	UniqueViewers    int     `json:"uniqueViewers"`
	TotalWatchSecs   int64   `json:"totalWatchSecs"`
	TotalDataBytes   int64   `json:"totalDataBytes"`
	AvgCompletionPct float64 `json:"avgCompletionPct"`
	LastWatchedAt    string  `json:"lastWatchedAt"`
}

// StreamingHistoryItem represents a row in the playback & data usage history log.
type StreamingHistoryItem struct {
	ID              int     `json:"id"`
	SessionKey      string  `json:"sessionKey"`
	Provider        string  `json:"provider"`
	ServerName      string  `json:"serverName"`
	UserName        string  `json:"userName"`
	ClientName      string  `json:"clientName"`
	DeviceName      string  `json:"deviceName"`
	IPAddress       string  `json:"ipAddress"`
	ItemID          string  `json:"itemId"`
	ItemName        string  `json:"itemName"`
	ItemType        string  `json:"itemType"`
	SeriesName      string  `json:"seriesName,omitempty"`
	SeasonNumber    int     `json:"seasonNumber,omitempty"`
	EpisodeNumber   int     `json:"episodeNumber,omitempty"`
	ProductionYear  int     `json:"productionYear,omitempty"`
	PlayMethod      string  `json:"playMethod"`
	Container       string  `json:"container"`
	VideoCodec      string  `json:"videoCodec"`
	VideoResolution string  `json:"videoResolution"`
	AudioCodec      string  `json:"audioCodec"`
	AudioChannels   int     `json:"audioChannels"`
	HWAccel         string  `json:"hwAccel,omitempty"`
	BitrateBps      int64   `json:"bitrateBps"`
	BandwidthMbps   float64 `json:"bandwidthMbps"`
	DurationSecs    int     `json:"durationSecs"`
	WatchedSecs     int     `json:"watchedSecs"`
	DataUsedBytes   int64   `json:"dataUsedBytes"`
	CompletionPct   float64 `json:"completionPct"`
	StartedAt       string  `json:"startedAt"`
	LastSeenAt      string  `json:"lastSeenAt"`
	IsActive        bool    `json:"isActive"`
}

// StreamingAnalytics aggregates historical watch statistics and bandwidth usage.
type StreamingAnalytics struct {
	WindowDays          int                      `json:"windowDays"`
	TotalPlays          int                      `json:"totalPlays"`
	TotalWatchTimeSecs  int64                    `json:"totalWatchTimeSecs"`
	TotalDataUsedBytes  int64                    `json:"totalDataUsedBytes"`
	UniqueUsers         int                      `json:"uniqueUsers"`
	UniqueTitles        int                      `json:"uniqueTitles"`
	AvgCompletionPct    float64                  `json:"avgCompletionPct"`
	PeakBandwidthMbps   float64                  `json:"peakBandwidthMbps"`
	StreamTypes         StreamTypeDistribution   `json:"streamTypes"`
	MediaTypeBreakdown  []BreakdownEntry         `json:"mediaTypeBreakdown"`
	ResolutionBreakdown []BreakdownEntry         `json:"resolutionBreakdown"`
	CodecBreakdown      []BreakdownEntry         `json:"codecBreakdown"`
	TimeSeries          []StreamingTimeSeriesPoint `json:"timeSeries"`
	TopUsers            []StreamingUserStat      `json:"topUsers"`
	TopTitles           []StreamingTitleStat     `json:"topTitles"`
	RecentHistory       []StreamingHistoryItem   `json:"recentHistory"`
}

// StreamingDashboardResponse is the unified payload returned by GET /api/v1/auth/streaming/dashboard.
type StreamingDashboardResponse struct {
	Servers        []StreamingServerStatus `json:"servers"`
	LiveSummary    StreamingLiveSummary    `json:"liveSummary"`
	ActiveSessions []ActiveStreamSession   `json:"activeSessions"`
	Analytics      StreamingAnalytics      `json:"analytics"`
	UpdatedAt      string                  `json:"updatedAt"`
}

var (
	streamingMu      sync.RWMutex
	demoSessionsCache []ActiveStreamSession
	demoModeEnabled   bool
)

// KeyDecryptor allows api package to register its AES-GCM decryptor without circular imports.
var KeyDecryptor func(string) (string, error)

// InitStreamingMonitor starts the background telemetry poller for Jellyfin sessions.
func InitStreamingMonitor() {
	ctx := SubsystemContext()
	go func() {
		// Initial delay to allow DB & services to settle
		select {
		case <-time.After(5 * time.Second):
		case <-ctx.Done():
			return
		}

		// Perform an initial watch-history sync on startup if Jellyfin is configured
		if _, _, apiKey, enabled := GetStoredJellyfinConfig(); enabled && apiKey != "" {
			syncCtx, syncCancel := context.WithTimeout(ctx, 60*time.Second)
			_, _ = SyncJellyfinWatchHistory(syncCtx)
			syncCancel()
		}

		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		historySyncCounter := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				PollAndRecordJellyfinTelemetry()
				historySyncCounter++
				if historySyncCounter >= 30 { // Sync historical watch records every 5 minutes
					historySyncCounter = 0
					if _, _, apiKey, enabled := GetStoredJellyfinConfig(); enabled && apiKey != "" {
						syncCtx, syncCancel := context.WithTimeout(ctx, 60*time.Second)
						_, _ = SyncJellyfinWatchHistory(syncCtx)
						syncCancel()
					}
				}
			}
		}
	}()
	slog.Info("streaming telemetry monitor started", "interval", "10s")
}

// resolveDefaultJellyfinURL determines the best default local Jellyfin URL.
func resolveDefaultJellyfinURL() string {
	if envURL := strings.TrimSpace(os.Getenv("JELLYFIN_URL")); envURL != "" {
		return strings.TrimRight(envURL, "/")
	}
	if cfg, err := db.GetAppIngressConfig("jellyfin"); err == nil && cfg != nil {
		if dom := strings.TrimSpace(cfg.PublicDomain); dom != "" && cfg.ExternalAccessEnabled {
			return fmt.Sprintf("https://%s", dom)
		}
		if cfg.ListenPort > 0 {
			return fmt.Sprintf("http://127.0.0.1:%d", cfg.ListenPort)
		}
	}
	if baseDom := ResolveBaseDomain(); baseDom != "" {
		return fmt.Sprintf("https://jellyfin.%s", baseDom)
	}
	return "http://127.0.0.1:8096"
}

// GetStoredJellyfinConfig loads the Jellyfin server configuration from SQLite (or env fallback).
func GetStoredJellyfinConfig() (name, serverURL, rawAPIKey string, enabled bool) {
	name = "Jellyfin"
	serverURL = resolveDefaultJellyfinURL()
	rawAPIKey = strings.TrimSpace(os.Getenv("JELLYFIN_API_KEY"))
	enabled = true

	if db.DB == nil {
		return
	}

	var dbName, dbURL, dbKey string
	var dbEnabled bool
	err := db.DB.QueryRow(`
		SELECT name, url, api_key, enabled
		FROM streaming_servers
		WHERE provider = 'jellyfin'
	`).Scan(&dbName, &dbURL, &dbKey, &dbEnabled)
	if err == nil {
		if strings.TrimSpace(dbName) != "" {
			name = strings.TrimSpace(dbName)
		}
		if strings.TrimSpace(dbURL) != "" {
			serverURL = strings.TrimRight(strings.TrimSpace(dbURL), "/")
		}
		enabled = dbEnabled
		if dbKey != "" {
			if KeyDecryptor != nil {
				if dec, decErr := KeyDecryptor(dbKey); decErr == nil && dec != "" {
					rawAPIKey = dec
				} else if !strings.HasPrefix(dbKey, "enc:v1:") {
					rawAPIKey = dbKey
				} else {
					slog.Warn("failed to decrypt stored Jellyfin API key; refusing ciphertext fallback", "error", decErr)
					rawAPIKey = ""
				}
			} else if !strings.HasPrefix(dbKey, "enc:v1:") {
				rawAPIKey = dbKey
			}
		}
	}
	return
}

// SaveStreamingServerConfig persists a media server configuration into SQLite.
func SaveStreamingServerConfig(provider, name, serverURL, encryptedOrRawKey string, keepExistingKey, enabled bool) error {
	if db.DB == nil {
		return fmt.Errorf("database not initialized")
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider != "jellyfin" && provider != "plex" && provider != "emby" {
		return fmt.Errorf("unsupported provider: %s", provider)
	}
	if strings.TrimSpace(name) == "" {
		name = strings.ToUpper(provider[:1]) + provider[1:]
	}
	cleanURL := strings.TrimRight(strings.TrimSpace(serverURL), "/")
	if cleanURL == "" {
		cleanURL = resolveDefaultJellyfinURL()
	}

	if keepExistingKey {
		_, err := db.DB.Exec(`
			INSERT INTO streaming_servers (provider, name, url, api_key, enabled, updated_at)
			VALUES (?, ?, ?, '', ?, CURRENT_TIMESTAMP)
			ON CONFLICT(provider) DO UPDATE SET
				name = excluded.name,
				url = excluded.url,
				enabled = excluded.enabled,
				updated_at = CURRENT_TIMESTAMP
		`, provider, name, cleanURL, enabled)
		return err
	}

	_, err := db.DB.Exec(`
		INSERT INTO streaming_servers (provider, name, url, api_key, enabled, updated_at)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(provider) DO UPDATE SET
			name = excluded.name,
			url = excluded.url,
			api_key = excluded.api_key,
			enabled = excluded.enabled,
			updated_at = CURRENT_TIMESTAMP
	`, provider, name, cleanURL, encryptedOrRawKey, enabled)
	return err
}

// ValidateServerURL ensures the configured media server URL uses http or https and blocks SSRF/path-hijack vectors.
func ValidateServerURL(rawURL string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if trimmed == "" {
		return "", fmt.Errorf("server URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid URL format: %v", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("server URL must start with http:// or https://")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("server URL must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("server URL must not include embedded credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("server URL must not include query parameters or fragments")
	}
	if strings.Contains(parsed.Path, "..") {
		return "", fmt.Errorf("server URL must not contain path traversal segments")
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" ||
		host == "0.0.0.0" ||
		host == "::" ||
		host == "0:0:0:0:0:0:0:0" ||
		host == "metadata.google.internal" ||
		host == "metadata.goog" ||
		host == "instance-data" ||
		strings.HasSuffix(host, ".metadata.google.internal") ||
		strings.HasPrefix(host, "169.254.") ||
		strings.HasPrefix(host, "fe80:") ||
		strings.HasPrefix(host, "fd00:ec2:") ||
		strings.HasPrefix(host, "255.") {
		return "", fmt.Errorf("server URL host %q is not permitted", host)
	}
	return trimmed, nil
}

var jellyfinHTTPTransport = &http.Transport{
	MaxIdleConns:        32,
	MaxIdleConnsPerHost: 16,
	IdleConnTimeout:     90 * time.Second,
}

func newJellyfinHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: jellyfinHTTPTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func doJellyfinRequest(ctx context.Context, method, fullURL, apiKey string, body io.Reader, timeout time.Duration) ([]byte, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, 0, "", err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if apiKey != "" {
		cleanToken := strings.Map(func(r rune) rune {
			if r == '"' || r == '\r' || r == '\n' || r < 0x20 {
				return -1
			}
			return r
		}, apiKey)
		req.Header.Set("X-Emby-Token", cleanToken)
		req.Header.Set("X-MediaBrowser-Token", cleanToken)
		req.Header.Set("Authorization", fmt.Sprintf(`MediaBrowser Client="AetherFlow", Device="Nexus", DeviceId="aetherflow-nexus", Version="3.2", Token="%s"`, cleanToken))
	}

	client := newJellyfinHTTPClient(timeout)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()

	lr := io.LimitReader(resp.Body, maxUpstreamPayloadSize)
	data, readErr := io.ReadAll(lr)
	if readErr != nil {
		return nil, resp.StatusCode, resp.Header.Get("Content-Type"), readErr
	}
	return data, resp.StatusCode, resp.Header.Get("Content-Type"), nil
}

// JellyfinSystemInfo mirrors Jellyfin's /System/Info and /System/Info/Public responses.
type JellyfinSystemInfo struct {
	ServerName      string `json:"ServerName"`
	Version         string `json:"Version"`
	ID              string `json:"Id"`
	OperatingSystem string `json:"OperatingSystem"`
}

// JellyfinItemCounts mirrors Jellyfin's /Items/Counts response.
type JellyfinItemCounts struct {
	MovieCount   int `json:"MovieCount"`
	SeriesCount  int `json:"SeriesCount"`
	EpisodeCount int `json:"EpisodeCount"`
	SongCount    int `json:"SongCount"`
}

// TestJellyfinConnection verifies connectivity and API key validity against a Jellyfin server.
func TestJellyfinConnection(ctx context.Context, serverURL, apiKey string) (*StreamingServerStatus, error) {
	cleanURL, err := ValidateServerURL(serverURL)
	if err != nil {
		return nil, err
	}

	status := &StreamingServerStatus{
		Provider:     "jellyfin",
		Name:         "Jellyfin",
		URL:          cleanURL,
		Configured:   apiKey != "",
		Enabled:      true,
		SupportStage: "active",
	}

	// If API key is provided, test authenticated /System/Info
	if apiKey != "" {
		body, code, _, reqErr := doJellyfinRequest(ctx, "GET", cleanURL+"/System/Info", apiKey, nil, 5*time.Second)
		if reqErr != nil {
			status.Status = "unreachable"
			status.ErrorMessage = "Cannot reach Jellyfin server: " + reqErr.Error()
			return status, reqErr
		}
		if code == http.StatusUnauthorized || code == http.StatusForbidden {
			status.Status = "unreachable"
			status.ErrorMessage = "Invalid Jellyfin API key (HTTP 401/403)"
			return status, fmt.Errorf("invalid Jellyfin API key (HTTP %d)", code)
		}
		if code < 200 || code >= 300 {
			status.Status = "unreachable"
			status.ErrorMessage = fmt.Sprintf("Jellyfin returned HTTP %d", code)
			return status, fmt.Errorf("unexpected HTTP status %d", code)
		}

		var sysInfo JellyfinSystemInfo
		if err := json.Unmarshal(body, &sysInfo); err == nil {
			if sysInfo.ServerName != "" {
				status.Name = sysInfo.ServerName
			}
			status.Version = sysInfo.Version
			status.ServerID = sysInfo.ID
			status.OperatingSystem = sysInfo.OperatingSystem
		}

		// Also fetch library counts
		if countsBody, countsCode, _, countsErr := doJellyfinRequest(ctx, "GET", cleanURL+"/Items/Counts", apiKey, nil, 4*time.Second); countsErr == nil && countsCode == http.StatusOK {
			var counts JellyfinItemCounts
			if json.Unmarshal(countsBody, &counts) == nil {
				status.LibraryCounts = StreamingLibraryCounts{
					Movies:   counts.MovieCount,
					Series:   counts.SeriesCount,
					Episodes: counts.EpisodeCount,
					Audio:    counts.SongCount,
				}
			}
		}

		status.Status = "connected"
		status.LastConnectedAt = time.Now().UTC().Format(time.RFC3339)

		if db.DB != nil {
			_, _ = db.DB.Exec(`
				UPDATE streaming_servers
				SET server_id = ?, server_version = ?, last_connected_at = CURRENT_TIMESTAMP
				WHERE provider = 'jellyfin'
			`, status.ServerID, status.Version)
		}
		return status, nil
	}

	// Unauthenticated public probe (/System/Info/Public)
	body, code, _, reqErr := doJellyfinRequest(ctx, "GET", cleanURL+"/System/Info/Public", "", nil, 3*time.Second)
	if reqErr != nil || code != http.StatusOK {
		status.Status = "unconfigured"
		return status, fmt.Errorf("API key not configured")
	}

	var pubInfo JellyfinSystemInfo
	if json.Unmarshal(body, &pubInfo) == nil {
		if pubInfo.ServerName != "" {
			status.Name = pubInfo.ServerName
		}
		status.Version = pubInfo.Version
		status.ServerID = pubInfo.ID
	}
	status.Status = "unconfigured"
	status.ErrorMessage = "Jellyfin detected at " + cleanURL + " — add an API Key to enable telemetry"
	return status, nil
}

// jellyfinSessionRaw mirrors Jellyfin's /Sessions payload.
type jellyfinSessionRaw struct {
	ID                    string   `json:"Id"`
	UserID                string   `json:"UserId"`
	UserName              string   `json:"UserName"`
	Client                string   `json:"Client"`
	DeviceName            string   `json:"DeviceName"`
	DeviceID              string   `json:"DeviceId"`
	ApplicationVersion    string   `json:"ApplicationVersion"`
	RemoteEndPoint        string   `json:"RemoteEndPoint"`
	LastActivityDate      string   `json:"LastActivityDate"`
	SupportsMediaControl  *bool    `json:"SupportsMediaControl"`
	SupportsRemoteControl *bool    `json:"SupportsRemoteControl"`
	SupportedCommands     []string `json:"SupportedCommands"`
	Capabilities          *struct {
		SupportsMediaControl *bool    `json:"SupportsMediaControl"`
		SupportedCommands    []string `json:"SupportedCommands"`
	} `json:"Capabilities"`
	PlayState *struct {
		PositionTicks       int64  `json:"PositionTicks"`
		IsPaused            bool   `json:"IsPaused"`
		IsMuted             bool   `json:"IsMuted"`
		PlayMethod          string `json:"PlayMethod"`
		PlaySessionID       string `json:"PlaySessionId"`
		MediaSourceID       string `json:"MediaSourceId"`
		LiveStreamID        string `json:"LiveStreamId"`
		AudioStreamIndex    *int   `json:"AudioStreamIndex"`
		SubtitleStreamIndex *int   `json:"SubtitleStreamIndex"`
	} `json:"PlayState"`
	NowPlayingItem *struct {
		ID                    string            `json:"Id"`
		Name                  string            `json:"Name"`
		Type                  string            `json:"Type"`
		SeriesName            string            `json:"SeriesName"`
		SeriesID              string            `json:"SeriesId"`
		ParentIndexNumber     int               `json:"ParentIndexNumber"`
		IndexNumber           int               `json:"IndexNumber"`
		ProductionYear        int               `json:"ProductionYear"`
		RunTimeTicks          int64             `json:"RunTimeTicks"`
		Container             string            `json:"Container"`
		Bitrate               int64             `json:"Bitrate"`
		Width                 int               `json:"Width"`
		Height                int               `json:"Height"`
		ImageTags             map[string]string `json:"ImageTags"`
		SeriesPrimaryImageTag string            `json:"SeriesPrimaryImageTag"`
		MediaStreams          []struct {
			Type          string  `json:"Type"`
			Index         int     `json:"Index"`
			Codec         string  `json:"Codec"`
			Profile       string  `json:"Profile"`
			BitRate       int64   `json:"BitRate"`
			Width         int     `json:"Width"`
			Height        int     `json:"Height"`
			VideoRange    string  `json:"VideoRange"`
			Channels      int     `json:"Channels"`
			ChannelLayout string  `json:"ChannelLayout"`
			Language      string  `json:"Language"`
			RealFrameRate float64 `json:"RealFrameRate"`
			IsDefault     bool    `json:"IsDefault"`
		} `json:"MediaStreams"`
	} `json:"NowPlayingItem"`
	TranscodingInfo *struct {
		AudioCodec               string   `json:"AudioCodec"`
		VideoCodec               string   `json:"VideoCodec"`
		Container                string   `json:"Container"`
		IsVideoDirect            bool     `json:"IsVideoDirect"`
		IsAudioDirect            bool     `json:"IsAudioDirect"`
		Bitrate                  int64    `json:"Bitrate"`
		Framerate                float64  `json:"Framerate"`
		CompletionPercentage     float64  `json:"CompletionPercentage"`
		Width                    int      `json:"Width"`
		Height                   int      `json:"Height"`
		AudioChannels            int      `json:"AudioChannels"`
		HardwareAccelerationType string   `json:"HardwareAccelerationType"`
		TranscodeReasons         []string `json:"TranscodeReasons"`
	} `json:"TranscodingInfo"`
}

func formatResolutionLabel(width, height int) string {
	switch {
	case width >= 3800 || height >= 2100:
		return "4K UHD"
	case width >= 2500 || height >= 1400:
		return "1440p QHD"
	case width >= 1900 || height >= 1000:
		return "1080p FHD"
	case width >= 1200 || height >= 700:
		return "720p HD"
	case width > 0 || height > 0:
		return "480p SD"
	default:
		return "1080p FHD"
	}
}

func formatAudioLayout(channels int, layout string) string {
	if strings.TrimSpace(layout) != "" {
		return layout
	}
	switch channels {
	case 8:
		return "7.1"
	case 6:
		return "5.1"
	case 2:
		return "Stereo"
	case 1:
		return "Mono"
	default:
		if channels > 0 {
			return fmt.Sprintf("%dch", channels)
		}
		return "Stereo"
	}
}

func isPrivateOrLocalIP(ip string) bool {
	clean := strings.ToLower(strings.TrimSpace(ip))
	clean = strings.TrimPrefix(clean, "::ffff:")
	if strings.HasPrefix(clean, "[") {
		if idx := strings.Index(clean, "]"); idx != -1 {
			clean = clean[1:idx]
		}
	} else if strings.Count(clean, ":") == 1 {
		if idx := strings.Index(clean, ":"); idx != -1 {
			clean = clean[:idx]
		}
	}
	if clean == "" || clean == "127.0.0.1" || clean == "::1" || clean == "localhost" ||
		strings.HasPrefix(clean, "127.") || strings.HasPrefix(clean, "fe80:") ||
		strings.HasPrefix(clean, "fc") || strings.HasPrefix(clean, "fd") {
		return true
	}
	if strings.HasPrefix(clean, "10.") || strings.HasPrefix(clean, "192.168.") {
		return true
	}
	if strings.HasPrefix(clean, "172.") {
		rest := clean[4:]
		if dot := strings.IndexByte(rest, '.'); dot == 2 {
			oct := rest[:2]
			return oct >= "16" && oct <= "31"
		}
	}
	return false
}

func normalizeMediaType(rawType string) string {
	switch strings.ToLower(strings.TrimSpace(rawType)) {
	case "movie":
		return "Movie"
	case "episode", "series":
		return "Episode"
	case "audio", "musicvideo":
		return "Audio"
	case "tvchannel", "livetvchannel", "livetvprogram", "program", "channel":
		return "LiveTV"
	default:
		if rawType != "" {
			return rawType
		}
		return "Movie"
	}
}

func resolveJellyfinSessionCapabilities(s jellyfinSessionRaw) (supportsMediaControl bool, supportsRemoteControl bool, canSendMessage bool, supportedCommands []string) {
	supportsMediaControl = true
	if s.SupportsMediaControl != nil {
		supportsMediaControl = *s.SupportsMediaControl
	} else if s.Capabilities != nil && s.Capabilities.SupportsMediaControl != nil {
		supportsMediaControl = *s.Capabilities.SupportsMediaControl
	}

	supportsRemoteControl = supportsMediaControl
	if s.SupportsRemoteControl != nil {
		supportsRemoteControl = *s.SupportsRemoteControl
	}

	if len(s.SupportedCommands) > 0 {
		supportedCommands = append(supportedCommands, s.SupportedCommands...)
	} else if s.Capabilities != nil && len(s.Capabilities.SupportedCommands) > 0 {
		supportedCommands = append(supportedCommands, s.Capabilities.SupportedCommands...)
	}

	if len(supportedCommands) > 0 {
		hasDisplayMessage := false
		for _, cmd := range supportedCommands {
			if strings.EqualFold(strings.TrimSpace(cmd), "DisplayMessage") {
				hasDisplayMessage = true
				break
			}
		}
		canSendMessage = supportsMediaControl && hasDisplayMessage
	} else {
		canSendMessage = supportsMediaControl
	}
	return
}

// FetchJellyfinLiveSessions retrieves active playback sessions from Jellyfin.
func FetchJellyfinLiveSessions(ctx context.Context, serverName, serverURL, apiKey string) ([]ActiveStreamSession, error) {
	if apiKey == "" {
		return []ActiveStreamSession{}, nil
	}
	cleanURL, err := ValidateServerURL(serverURL)
	if err != nil {
		return nil, err
	}

	body, code, _, reqErr := doJellyfinRequest(ctx, "GET", cleanURL+"/Sessions", apiKey, nil, 5*time.Second)
	if reqErr != nil {
		return nil, reqErr
	}
	if code < 200 || code >= 300 {
		return nil, fmt.Errorf("Jellyfin /Sessions returned HTTP %d", code)
	}

	var rawSessions []jellyfinSessionRaw
	if err := json.Unmarshal(body, &rawSessions); err != nil {
		return nil, err
	}

	active := make([]ActiveStreamSession, 0)
	for _, s := range rawSessions {
		if s.NowPlayingItem == nil {
			continue
		}
		item := s.NowPlayingItem

		posSecs := 0
		isPaused := false
		playMethod := "DirectPlay"
		playSessionID := ""
		mediaSourceID := ""
		if s.PlayState != nil {
			posSecs = int(s.PlayState.PositionTicks / jellyfinTicksPerSecond)
			isPaused = s.PlayState.IsPaused
			if s.PlayState.PlayMethod != "" {
				playMethod = s.PlayState.PlayMethod
			}
			playSessionID = strings.TrimSpace(s.PlayState.PlaySessionID)
			mediaSourceID = strings.TrimSpace(s.PlayState.MediaSourceID)
		}
		supportsMediaCtrl, supportsRemoteCtrl, canSendMsg, supportedCmds := resolveJellyfinSessionCapabilities(s)

		durSecs := int(item.RunTimeTicks / jellyfinTicksPerSecond)
		progressPct := 0.0
		if durSecs > 0 {
			progressPct = math.Min(100.0, math.Round((float64(posSecs)/float64(durSecs))*1000)/10)
		}

		videoCodec := ""
		videoWidth := item.Width
		videoHeight := item.Height
		videoRange := "SDR"
		videoFramerate := 0.0
		var streamBitrateSum int64

		audioCodec := ""
		audioChannels := 2
		audioLayout := ""
		audioLang := ""
		audioPriority := 0
		var audioBitrate int64

		subCodec := ""
		subLang := ""

		for _, ms := range item.MediaStreams {
			switch ms.Type {
			case "Video":
				if videoCodec == "" {
					videoCodec = strings.ToUpper(ms.Codec)
					if ms.Width > 0 {
						videoWidth = ms.Width
					}
					if ms.Height > 0 {
						videoHeight = ms.Height
					}
					if ms.VideoRange != "" {
						videoRange = ms.VideoRange
					}
					if ms.RealFrameRate > 0 {
						videoFramerate = math.Round(ms.RealFrameRate*100) / 100
					}
					streamBitrateSum += ms.BitRate
				}
			case "Audio":
				prio := 0
				if s.PlayState != nil && s.PlayState.AudioStreamIndex != nil && *s.PlayState.AudioStreamIndex == ms.Index {
					prio = 3
				} else if ms.IsDefault {
					prio = 2
				} else if audioPriority == 0 {
					prio = 1
				}
				if prio > audioPriority {
					audioPriority = prio
					audioCodec = strings.ToUpper(ms.Codec)
					audioChannels = ms.Channels
					audioLayout = ms.ChannelLayout
					audioLang = strings.ToUpper(ms.Language)
					streamBitrateSum += ms.BitRate - audioBitrate
					audioBitrate = ms.BitRate
				}
			case "Subtitle":
				if s.PlayState != nil && s.PlayState.SubtitleStreamIndex != nil && *s.PlayState.SubtitleStreamIndex == ms.Index {
					subCodec = strings.ToUpper(ms.Codec)
					subLang = strings.ToUpper(ms.Language)
				}
			}
		}

		if videoCodec == "" {
			videoCodec = "H264"
		}
		if audioCodec == "" {
			audioCodec = "AAC"
		}

		isVideoDirect := true
		isAudioDirect := true
		targetContainer := ""
		targetVideoCodec := ""
		targetAudioCodec := ""
		hwAccel := ""
		transcodeReasons := []string{}
		transcodePct := 0.0
		transcodeFps := 0.0
		activeBitrate := item.Bitrate
		if activeBitrate <= 0 {
			activeBitrate = streamBitrateSum
		}

		if s.TranscodingInfo != nil {
			ti := s.TranscodingInfo
			isVideoDirect = ti.IsVideoDirect
			isAudioDirect = ti.IsAudioDirect
			targetContainer = strings.ToUpper(ti.Container)
			if ti.VideoCodec != "" {
				targetVideoCodec = strings.ToUpper(ti.VideoCodec)
			}
			if ti.AudioCodec != "" {
				targetAudioCodec = strings.ToUpper(ti.AudioCodec)
			}
			if ti.HardwareAccelerationType != "" && ti.HardwareAccelerationType != "none" {
				hwAccel = strings.ToUpper(ti.HardwareAccelerationType)
			}
			if len(ti.TranscodeReasons) > 0 {
				transcodeReasons = ti.TranscodeReasons
			}
			transcodePct = math.Round(ti.CompletionPercentage*10) / 10
			transcodeFps = math.Round(ti.Framerate*10) / 10
			if ti.Bitrate > 0 {
				activeBitrate = ti.Bitrate
			}
			if !ti.IsVideoDirect {
				playMethod = "Transcode"
			} else if playMethod == "DirectPlay" && (!ti.IsAudioDirect || ti.Container != "") {
				playMethod = "DirectStream"
			}
		}

		if activeBitrate <= 0 {
			// Estimate sensible bitrate based on resolution if container metadata omitted it
			if videoWidth >= 3800 {
				activeBitrate = 24_000_000
			} else if videoWidth >= 1900 {
				activeBitrate = 8_500_000
			} else {
				activeBitrate = 4_000_000
			}
		}

		bwMbps := math.Round((float64(activeBitrate)/1_000_000.0)*100) / 100
		if isPaused {
			bwMbps = 0
		}

		artworkID := item.ID
		hasArtwork := false
		if item.ImageTags != nil && item.ImageTags["Primary"] != "" {
			hasArtwork = true
		} else if item.SeriesID != "" && item.SeriesPrimaryImageTag != "" {
			artworkID = item.SeriesID
			hasArtwork = true
		}

		stateStr := "playing"
		if isPaused {
			stateStr = "paused"
		}

		// Estimate session data transferred from position and bitrate (or from DB history if tracked)
		sessionBytes := int64(posSecs) * (activeBitrate / 8)
		if db.DB != nil {
			sessionKey := fmt.Sprintf("jellyfin:%s:%s", s.ID, item.ID)
			var trackedBytes int64
			if err := db.DB.QueryRow(`SELECT data_used_bytes FROM streaming_history WHERE session_key = ?`, sessionKey).Scan(&trackedBytes); err == nil && trackedBytes > sessionBytes {
				sessionBytes = trackedBytes
			}
		}

		active = append(active, ActiveStreamSession{
			SessionID:            s.ID,
			Provider:             "jellyfin",
			ServerName:           serverName,
			UserID:               s.UserID,
			UserName:             s.UserName,
			ClientName:           s.Client,
			DeviceName:           s.DeviceName,
			DeviceID:             s.DeviceID,
			AppVersion:           s.ApplicationVersion,
			IPAddress:            s.RemoteEndPoint,
			IsLAN:                isPrivateOrLocalIP(s.RemoteEndPoint),
			ItemID:               item.ID,
			ItemName:             item.Name,
			ItemType:             normalizeMediaType(item.Type),
			SeriesName:           item.SeriesName,
			SeriesID:             item.SeriesID,
			SeasonNumber:         item.ParentIndexNumber,
			EpisodeNumber:        item.IndexNumber,
			ProductionYear:       item.ProductionYear,
			HasArtwork:           hasArtwork,
			ArtworkItemID:        artworkID,
			State:                stateStr,
			PositionSecs:         posSecs,
			DurationSecs:         durSecs,
			ProgressPct:          progressPct,
			PlayMethod:           playMethod,
			Container:            strings.ToUpper(item.Container),
			TargetContainer:      targetContainer,
			VideoCodec:           videoCodec,
			TargetVideoCodec:     targetVideoCodec,
			VideoResolution:      formatResolutionLabel(videoWidth, videoHeight),
			VideoRange:           videoRange,
			VideoFramerate:       videoFramerate,
			IsVideoDirect:        isVideoDirect,
			AudioCodec:           audioCodec,
			TargetAudioCodec:     targetAudioCodec,
			AudioChannels:        audioChannels,
			AudioLayout:          formatAudioLayout(audioChannels, audioLayout),
			AudioLanguage:        audioLang,
			IsAudioDirect:        isAudioDirect,
			SubtitleCodec:        subCodec,
			SubtitleLanguage:     subLang,
			HWAccel:              hwAccel,
			TranscodeReasons:     transcodeReasons,
			TranscodeProgressPct: transcodePct,
			TranscodeFps:         transcodeFps,
			BitrateBps:           activeBitrate,
			BandwidthMbps:        bwMbps,
			SessionDataBytes:     sessionBytes,
			StartedAt:            s.LastActivityDate,
		})
	}

	return active, nil
}

// PollAndRecordJellyfinTelemetry polls active sessions from Jellyfin and records play & bandwidth history in SQLite.
func PollAndRecordJellyfinTelemetry() {
	if db.DB == nil {
		return
	}
	name, serverURL, apiKey, enabled := GetStoredJellyfinConfig()
	if !enabled || apiKey == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()

	sessions, err := FetchJellyfinLiveSessions(ctx, name, serverURL, apiKey)
	if err != nil {
		return
	}

	RecordLiveSessionsSnapshot("jellyfin", sessions, 10)
}

// RecordLiveSessionsSnapshot persists active sessions into streaming_history and records a bandwidth sample.
func RecordLiveSessionsSnapshot(provider string, sessions []ActiveStreamSession, intervalSecs int) {
	if db.DB == nil {
		return
	}
	if intervalSecs < 0 {
		intervalSecs = 0
	}

	activeKeys := make(map[string]bool)
	var directPlayCount, directStreamCount, transcodeCount int
	var totalBitrateBps, totalBytesDelta int64

	for _, s := range sessions {
		sessionKey := fmt.Sprintf("%s:%s:%s", provider, s.SessionID, s.ItemID)
		activeKeys[sessionKey] = true

		switch s.PlayMethod {
		case "Transcode":
			transcodeCount++
		case "DirectStream":
			directStreamCount++
		default:
			directPlayCount++
		}

		var deltaBytes int64
		var deltaSecs int
		if s.State == "playing" {
			totalBitrateBps += s.BitrateBps
			deltaSecs = intervalSecs
			deltaBytes = (s.BitrateBps / 8) * int64(intervalSecs)
			totalBytesDelta += deltaBytes
		}

		estimatedFromPos := int64(s.PositionSecs) * (s.BitrateBps / 8)
		reasonsStr := strings.Join(s.TranscodeReasons, ",")

		_, _ = db.DB.Exec(`
			INSERT INTO streaming_history (
				session_key, provider, server_name, user_id, user_name,
				client_name, device_name, device_id, ip_address,
				item_id, item_name, item_type, series_name, series_id,
				season_number, episode_number, production_year,
				play_method, container, video_codec, video_resolution,
				audio_codec, audio_channels, subtitle_codec, hw_accel, transcode_reasons,
				bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
				started_at, last_seen_at, is_active
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1)
			ON CONFLICT(session_key) DO UPDATE SET
				play_method = excluded.play_method,
				hw_accel = CASE WHEN excluded.hw_accel != '' THEN excluded.hw_accel ELSE streaming_history.hw_accel END,
				transcode_reasons = CASE WHEN excluded.transcode_reasons != '' THEN excluded.transcode_reasons ELSE streaming_history.transcode_reasons END,
				bitrate_bps = excluded.bitrate_bps,
				duration_secs = CASE WHEN excluded.duration_secs > 0 THEN excluded.duration_secs ELSE streaming_history.duration_secs END,
				watched_secs = MAX(streaming_history.watched_secs + ?, ?),
				data_used_bytes = MAX(streaming_history.data_used_bytes + ?, ?),
				completion_pct = MAX(streaming_history.completion_pct, excluded.completion_pct),
				last_seen_at = CURRENT_TIMESTAMP,
				ended_at = NULL,
				is_active = 1
		`,
			sessionKey, provider, s.ServerName, s.UserID, s.UserName,
			s.ClientName, s.DeviceName, s.DeviceID, s.IPAddress,
			s.ItemID, s.ItemName, s.ItemType, s.SeriesName, s.SeriesID,
			s.SeasonNumber, s.EpisodeNumber, s.ProductionYear,
			s.PlayMethod, s.Container, s.VideoCodec, s.VideoResolution,
			s.AudioCodec, s.AudioChannels, s.SubtitleCodec, s.HWAccel, reasonsStr,
			s.BitrateBps, s.DurationSecs, s.PositionSecs, estimatedFromPos, s.ProgressPct,
			deltaSecs, s.PositionSecs, deltaBytes, estimatedFromPos,
		)
	}

	// Mark sessions that are no longer active as ended in a single batched UPDATE
	if len(activeKeys) == 0 {
		_, _ = db.DB.Exec(`UPDATE streaming_history SET is_active = 0, ended_at = CURRENT_TIMESTAMP WHERE provider = ? AND is_active = 1`, provider)
	} else {
		placeholders := make([]string, 0, len(activeKeys))
		args := make([]interface{}, 0, len(activeKeys)+1)
		args = append(args, provider)
		for k := range activeKeys {
			placeholders = append(placeholders, "?")
			args = append(args, k)
		}
		query := fmt.Sprintf(`UPDATE streaming_history SET is_active = 0, ended_at = CURRENT_TIMESTAMP WHERE provider = ? AND is_active = 1 AND session_key NOT IN (%s)`, strings.Join(placeholders, ","))
		_, _ = db.DB.Exec(query, args...)
	}

	if len(sessions) > 0 && intervalSecs > 0 {
		_, _ = db.DB.Exec(`
			INSERT INTO streaming_bandwidth_samples (
				provider, active_streams, direct_play_count, direct_stream_count, transcode_count, total_bitrate_bps, bytes_delta
			) VALUES (?, ?, ?, ?, ?, ?, ?)
		`, provider, len(sessions), directPlayCount, directStreamCount, transcodeCount, totalBitrateBps, totalBytesDelta)
	}
}

// SyncJellyfinWatchHistory imports played items from Jellyfin users so existing libraries populate analytics immediately.
func SyncJellyfinWatchHistory(ctx context.Context) (int, error) {
	if db.DB == nil {
		return 0, fmt.Errorf("database not initialized")
	}
	serverName, serverURL, apiKey, _ := GetStoredJellyfinConfig()
	if apiKey == "" {
		return 0, fmt.Errorf("Jellyfin API key is not configured")
	}
	cleanURL, err := ValidateServerURL(serverURL)
	if err != nil {
		return 0, err
	}

	usersBody, code, _, err := doJellyfinRequest(ctx, "GET", cleanURL+"/Users", apiKey, nil, 8*time.Second)
	if err != nil {
		return 0, err
	}
	if code < 200 || code >= 300 {
		return 0, fmt.Errorf("Jellyfin /Users returned HTTP %d", code)
	}

	var users []struct {
		ID   string `json:"Id"`
		Name string `json:"Name"`
	}
	if err := json.Unmarshal(usersBody, &users); err != nil {
		return 0, err
	}

	imported := 0
	const pageSize = 100
	filters := []string{"IsPlayed", "IsResumable"}

	for _, u := range users {
		for _, filter := range filters {
			startIndex := 0
			for {
				itemsURL := fmt.Sprintf("%s/Users/%s/Items?Filters=%s&Recursive=true&IncludeItemTypes=Movie,Episode,Audio&Fields=MediaStreams,Container,ProductionYear&SortBy=DatePlayed&SortOrder=Descending&Limit=%d&StartIndex=%d",
					cleanURL, url.PathEscape(u.ID), filter, pageSize, startIndex)
				itemsBody, iCode, _, iErr := doJellyfinRequest(ctx, "GET", itemsURL, apiKey, nil, 15*time.Second)
				if iErr != nil || iCode != http.StatusOK {
					break
				}

				var payload struct {
					TotalRecordCount int `json:"TotalRecordCount"`
					Items            []struct {
						ID                string `json:"Id"`
						Name              string `json:"Name"`
						Type              string `json:"Type"`
						SeriesName        string `json:"SeriesName"`
						SeriesID          string `json:"SeriesId"`
						ParentIndexNumber int    `json:"ParentIndexNumber"`
						IndexNumber       int    `json:"IndexNumber"`
						ProductionYear    int    `json:"ProductionYear"`
						RunTimeTicks      int64  `json:"RunTimeTicks"`
						Container         string `json:"Container"`
						Bitrate           int64  `json:"Bitrate"`
						Width             int    `json:"Width"`
						Height            int    `json:"Height"`
						MediaStreams      []struct {
							Type     string `json:"Type"`
							Codec    string `json:"Codec"`
							BitRate  int64  `json:"BitRate"`
							Width    int    `json:"Width"`
							Height   int    `json:"Height"`
							Channels int    `json:"Channels"`
						} `json:"MediaStreams"`
						UserData *struct {
							Played                bool    `json:"Played"`
							PlayCount             int     `json:"PlayCount"`
							PlaybackPositionTicks int64   `json:"PlaybackPositionTicks"`
							PlayedPercentage      float64 `json:"PlayedPercentage"`
							LastPlayedDate        string  `json:"LastPlayedDate"`
						} `json:"UserData"`
					} `json:"Items"`
				}
				if json.Unmarshal(itemsBody, &payload) != nil || len(payload.Items) == 0 {
					break
				}

				for _, item := range payload.Items {
					durSecs := int(item.RunTimeTicks / jellyfinTicksPerSecond)
					if durSecs <= 0 {
						durSecs = 2700
					}
					vCodec := "HEVC"
					aCodec := "EAC3"
					aCh := 6
					w, h := item.Width, item.Height
					var streamBitrate int64
					for _, ms := range item.MediaStreams {
						if ms.Type == "Video" {
							if ms.Codec != "" {
								vCodec = strings.ToUpper(ms.Codec)
							}
							if ms.Width > 0 {
								w = ms.Width
							}
							if ms.Height > 0 {
								h = ms.Height
							}
							streamBitrate += ms.BitRate
						} else if ms.Type == "Audio" {
							if ms.Codec != "" {
								aCodec = strings.ToUpper(ms.Codec)
							}
							if ms.Channels > 0 {
								aCh = ms.Channels
							}
							streamBitrate += ms.BitRate
						}
					}
					bitrate := item.Bitrate
					if bitrate <= 0 {
						bitrate = streamBitrate
					}
					if bitrate <= 0 {
						bitrate = 8_000_000
					}

					watchedSecs := durSecs
					completionPct := 100.0
					if item.UserData != nil && !item.UserData.Played {
						if item.UserData.PlaybackPositionTicks > 0 {
							posSecs := int(item.UserData.PlaybackPositionTicks / jellyfinTicksPerSecond)
							if posSecs > 0 && posSecs < durSecs {
								watchedSecs = posSecs
								completionPct = math.Round((float64(posSecs)/float64(durSecs))*1000) / 10
							}
						} else if item.UserData.PlayedPercentage > 0 && item.UserData.PlayedPercentage < 100 {
							completionPct = math.Round(item.UserData.PlayedPercentage*10) / 10
							watchedSecs = int(math.Round(float64(durSecs) * (completionPct / 100.0)))
						}
					}
					if watchedSecs <= 0 {
						watchedSecs = 60
					}

					dataUsed := int64(watchedSecs) * (bitrate / 8)
					playedAt := time.Now().UTC().Format("2006-01-02 15:04:05")
					hasPlayedDate := 0
					if item.UserData != nil && item.UserData.LastPlayedDate != "" {
						if parsedTime, pErr := time.Parse(time.RFC3339Nano, item.UserData.LastPlayedDate); pErr == nil {
							playedAt = parsedTime.UTC().Format("2006-01-02 15:04:05")
							hasPlayedDate = 1
						} else if parsedTime, pErr := time.Parse(time.RFC3339, item.UserData.LastPlayedDate); pErr == nil {
							playedAt = parsedTime.UTC().Format("2006-01-02 15:04:05")
							hasPlayedDate = 1
						}
					}

					sessionKey := fmt.Sprintf("jellyfin:sync:%s:%s", u.ID, item.ID)
					res, execErr := db.DB.Exec(`
						INSERT INTO streaming_history (
							session_key, provider, server_name, user_id, user_name,
							client_name, device_name, ip_address,
							item_id, item_name, item_type, series_name, series_id,
							season_number, episode_number, production_year,
							play_method, container, video_codec, video_resolution,
							audio_codec, audio_channels, bitrate_bps,
							duration_secs, watched_secs, data_used_bytes, completion_pct,
							started_at, last_seen_at, ended_at, is_active
						) VALUES (?, 'jellyfin', ?, ?, ?, 'Jellyfin Client', 'Smart TV / Web', '192.168.1.10', ?, ?, ?, ?, ?, ?, ?, ?, 'DirectPlay', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
						ON CONFLICT(session_key) DO UPDATE SET
							server_name = excluded.server_name,
							user_name = excluded.user_name,
							item_name = excluded.item_name,
							item_type = excluded.item_type,
							series_name = excluded.series_name,
							series_id = excluded.series_id,
							season_number = excluded.season_number,
							episode_number = excluded.episode_number,
							production_year = excluded.production_year,
							container = excluded.container,
							video_codec = excluded.video_codec,
							video_resolution = excluded.video_resolution,
							audio_codec = excluded.audio_codec,
							audio_channels = excluded.audio_channels,
							bitrate_bps = excluded.bitrate_bps,
							duration_secs = excluded.duration_secs,
							watched_secs = excluded.watched_secs,
							data_used_bytes = excluded.data_used_bytes,
							completion_pct = excluded.completion_pct,
							started_at = CASE WHEN ? = 1 THEN excluded.started_at ELSE streaming_history.started_at END,
							last_seen_at = CASE WHEN ? = 1 THEN excluded.last_seen_at ELSE streaming_history.last_seen_at END,
							ended_at = CASE WHEN ? = 1 THEN excluded.ended_at ELSE streaming_history.ended_at END
						WHERE streaming_history.watched_secs != excluded.watched_secs
						   OR streaming_history.completion_pct != excluded.completion_pct
						   OR (? = 1 AND streaming_history.last_seen_at != excluded.last_seen_at)
						   OR streaming_history.item_name != excluded.item_name
					`,
						sessionKey, serverName, u.ID, u.Name,
						item.ID, item.Name, normalizeMediaType(item.Type), item.SeriesName, item.SeriesID,
						item.ParentIndexNumber, item.IndexNumber, item.ProductionYear,
						strings.ToUpper(item.Container), vCodec, formatResolutionLabel(w, h),
						aCodec, aCh, bitrate,
						durSecs, watchedSecs, dataUsed, completionPct,
						playedAt, playedAt, playedAt,
						hasPlayedDate, hasPlayedDate, hasPlayedDate, hasPlayedDate,
					)
					if execErr == nil {
						if aff, _ := res.RowsAffected(); aff > 0 {
							imported++
						}
					}
				}

				startIndex += len(payload.Items)
				if startIndex >= payload.TotalRecordCount || len(payload.Items) < pageSize {
					break
				}
			}
		}
	}

	return imported, nil
}

// SendJellyfinSessionCommand executes pause, resume, stop, or message on an active session.
func SendJellyfinSessionCommand(ctx context.Context, sessionID, command, header, messageText string) error {
	if strings.HasPrefix(sessionID, "demo-") {
		streamingMu.Lock()
		defer streamingMu.Unlock()
		for i := range demoSessionsCache {
			if demoSessionsCache[i].SessionID == sessionID {
				switch command {
				case "pause":
					demoSessionsCache[i].State = "paused"
					demoSessionsCache[i].BandwidthMbps = 0
				case "resume":
					demoSessionsCache[i].State = "playing"
					demoSessionsCache[i].BandwidthMbps = math.Round((float64(demoSessionsCache[i].BitrateBps)/1_000_000.0)*100) / 100
				case "stop":
					demoSessionsCache = append(demoSessionsCache[:i], demoSessionsCache[i+1:]...)
				}
				break
			}
		}
		return nil
	}

	_, serverURL, apiKey, _ := GetStoredJellyfinConfig()
	if apiKey == "" {
		return fmt.Errorf("Jellyfin API key is not configured")
	}
	cleanURL, err := ValidateServerURL(serverURL)
	if err != nil {
		return err
	}

	escapedID := url.PathEscape(strings.TrimSpace(sessionID))
	var endpoint string
	var bodyReader io.Reader

	switch command {
	case "pause":
		endpoint = fmt.Sprintf("%s/Sessions/%s/Playing/Pause", cleanURL, escapedID)
	case "resume":
		endpoint = fmt.Sprintf("%s/Sessions/%s/Playing/Unpause", cleanURL, escapedID)
	case "stop":
		endpoint = fmt.Sprintf("%s/Sessions/%s/Playing/Stop", cleanURL, escapedID)
	case "message":
		endpoint = fmt.Sprintf("%s/Sessions/%s/Message", cleanURL, escapedID)
		if strings.TrimSpace(header) == "" {
			header = "AetherFlow Administrator"
		}
		payload, _ := json.Marshal(map[string]interface{}{
			"Header":    header,
			"Text":      messageText,
			"TimeoutMs": 8000,
		})
		bodyReader = bytes.NewReader(payload)
	default:
		return fmt.Errorf("unsupported session command: %s", command)
	}

	_, code, _, reqErr := doJellyfinRequest(ctx, "POST", endpoint, apiKey, bodyReader, 5*time.Second)
	if reqErr != nil {
		return reqErr
	}
	if code < 200 || code >= 300 {
		return fmt.Errorf("Jellyfin command %q returned HTTP %d", command, code)
	}
	return nil
}

// FetchJellyfinArtwork proxies item cover art from Jellyfin without exposing the API key.
func FetchJellyfinArtwork(ctx context.Context, itemID string) ([]byte, string, error) {
	_, serverURL, apiKey, _ := GetStoredJellyfinConfig()
	if apiKey == "" {
		return nil, "", fmt.Errorf("Jellyfin not configured")
	}
	cleanURL, err := ValidateServerURL(serverURL)
	if err != nil {
		return nil, "", err
	}

	imgURL := fmt.Sprintf("%s/Items/%s/Images/Primary?maxWidth=320&quality=85", cleanURL, url.PathEscape(strings.TrimSpace(itemID)))
	req, err := http.NewRequestWithContext(ctx, "GET", imgURL, nil)
	if err != nil {
		return nil, "", err
	}
	cleanToken := strings.Map(func(r rune) rune {
		if r == '"' || r == '\r' || r == '\n' || r < 0x20 {
			return -1
		}
		return r
	}, apiKey)
	req.Header.Set("X-Emby-Token", cleanToken)
	req.Header.Set("X-MediaBrowser-Token", cleanToken)
	req.Header.Set("Authorization", fmt.Sprintf(`MediaBrowser Client="AetherFlow", Device="Nexus", DeviceId="aetherflow-nexus", Version="3.2", Token="%s"`, cleanToken))

	client := newJellyfinHTTPClient(5 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("upstream image status %d", resp.StatusCode)
	}

	lr := io.LimitReader(resp.Body, maxArtworkPayloadSize)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, "", err
	}
	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "image/jpeg"
	}
	return data, contentType, nil
}

// BuildStreamingDashboard assembles the complete WSDashboard telemetry & analytics payload.
func BuildStreamingDashboard(ctx context.Context, windowDays int, playMethodFilter, mediaTypeFilter string) StreamingDashboardResponse {
	if windowDays <= 0 {
		windowDays = 30
	}

	name, serverURL, apiKey, enabled := GetStoredJellyfinConfig()
	maskedKey := ""
	if len(apiKey) > 4 {
		maskedKey = "****" + apiKey[len(apiKey)-4:]
	} else if apiKey != "" {
		maskedKey = "****"
	}

	streamingMu.RLock()
	isDemo := demoModeEnabled
	demoSessions := make([]ActiveStreamSession, len(demoSessionsCache))
	copy(demoSessions, demoSessionsCache)
	streamingMu.RUnlock()

	jellyfinServer := StreamingServerStatus{
		Provider:     "jellyfin",
		Name:         name,
		URL:          serverURL,
		APIKeyMasked: maskedKey,
		Configured:   apiKey != "",
		Enabled:      enabled,
		Status:       "unconfigured",
		SupportStage: "active",
	}

	var activeSessions []ActiveStreamSession
	if enabled && apiKey != "" {
		if st, err := TestJellyfinConnection(ctx, serverURL, apiKey); err == nil && st != nil {
			jellyfinServer = *st
			jellyfinServer.APIKeyMasked = maskedKey
		} else if st != nil {
			jellyfinServer.Status = st.Status
			jellyfinServer.ErrorMessage = st.ErrorMessage
		}
		if live, err := FetchJellyfinLiveSessions(ctx, jellyfinServer.Name, serverURL, apiKey); err == nil {
			activeSessions = live
			RecordLiveSessionsSnapshot("jellyfin", live, 0)
		}
	} else if isDemo {
		jellyfinServer.Status = "demo"
		jellyfinServer.Configured = true
		jellyfinServer.Version = "10.10.3"
		jellyfinServer.OperatingSystem = "Linux (Debian 12)"
		jellyfinServer.LibraryCounts = StreamingLibraryCounts{
			Movies:   842,
			Series:   194,
			Episodes: 6410,
			Audio:    3280,
		}
		activeSessions = demoSessions
	} else {
		// Probe public info silently if local Jellyfin is running without API key
		if st, _ := TestJellyfinConnection(ctx, serverURL, ""); st != nil {
			jellyfinServer.Status = st.Status
			jellyfinServer.Version = st.Version
			jellyfinServer.ErrorMessage = st.ErrorMessage
		}
	}

	servers := []StreamingServerStatus{
		jellyfinServer,
		{
			Provider:     "plex",
			Name:         "Plex Media Server",
			URL:          "http://127.0.0.1:32400",
			Configured:   false,
			Enabled:      false,
			Status:       "coming_soon",
			SupportStage: "coming_soon",
		},
		{
			Provider:     "emby",
			Name:         "Emby Server",
			URL:          "http://127.0.0.1:8097",
			Configured:   false,
			Enabled:      false,
			Status:       "coming_soon",
			SupportStage: "coming_soon",
		},
	}

	var summary StreamingLiveSummary
	summary.IsDemoMode = isDemo
	summary.ActiveStreams = len(activeSessions)
	for _, s := range activeSessions {
		switch s.PlayMethod {
		case "Transcode":
			summary.TranscodeCount++
		case "DirectStream":
			summary.DirectStreamCount++
		default:
			summary.DirectPlayCount++
		}
		if s.State == "playing" {
			summary.TotalBitrateBps += s.BitrateBps
			summary.TotalBandwidthMbps += s.BandwidthMbps
		}
		summary.ActiveSessionBytes += s.SessionDataBytes
		if s.IsLAN {
			summary.LANStreams++
		} else {
			summary.WANStreams++
		}
	}
	summary.TotalBandwidthMbps = math.Round(summary.TotalBandwidthMbps*100) / 100

	analytics := queryStreamingAnalytics(windowDays, playMethodFilter, mediaTypeFilter)

	return StreamingDashboardResponse{
		Servers:        servers,
		LiveSummary:    summary,
		ActiveSessions: activeSessions,
		Analytics:      analytics,
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
}

func queryStreamingAnalytics(windowDays int, playMethodFilter, mediaTypeFilter string) StreamingAnalytics {
	result := StreamingAnalytics{
		WindowDays:          windowDays,
		MediaTypeBreakdown:  []BreakdownEntry{},
		ResolutionBreakdown: []BreakdownEntry{},
		CodecBreakdown:      []BreakdownEntry{},
		TimeSeries:          []StreamingTimeSeriesPoint{},
		TopUsers:            []StreamingUserStat{},
		TopTitles:           []StreamingTitleStat{},
		RecentHistory:       []StreamingHistoryItem{},
	}

	if db.DB == nil {
		return result
	}

	whereClauses := []string{"1=1"}
	args := []interface{}{}

	if windowDays > 0 && windowDays < 3650 {
		cutoff := time.Now().UTC().AddDate(0, 0, -windowDays).Format("2006-01-02 15:04:05")
		whereClauses = append(whereClauses, "started_at >= ?")
		args = append(args, cutoff)
	}
	if playMethodFilter != "" && strings.ToLower(playMethodFilter) != "all" {
		whereClauses = append(whereClauses, "play_method = ?")
		args = append(args, playMethodFilter)
	}
	if mediaTypeFilter != "" && strings.ToLower(mediaTypeFilter) != "all" {
		whereClauses = append(whereClauses, "item_type = ?")
		args = append(args, mediaTypeFilter)
	}

	whereSQL := strings.Join(whereClauses, " AND ")

	// 1. Aggregate Overview
	var totalPlays, uniqueUsers, uniqueTitles int
	var totalWatchSecs, totalDataBytes int64
	var avgComp float64
	var dpCount, dsCount, tcCount int
	var maxBitrateBps int64

	_ = db.DB.QueryRow(fmt.Sprintf(`
		SELECT
			COUNT(*),
			COALESCE(SUM(watched_secs), 0),
			COALESCE(SUM(data_used_bytes), 0),
			COUNT(DISTINCT user_name),
			COUNT(DISTINCT item_name),
			COALESCE(AVG(completion_pct), 0),
			COALESCE(SUM(CASE WHEN play_method = 'DirectPlay' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN play_method = 'DirectStream' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN play_method = 'Transcode' THEN 1 ELSE 0 END), 0),
			COALESCE(MAX(bitrate_bps), 0)
		FROM streaming_history
		WHERE %s
	`, whereSQL), args...).Scan(
		&totalPlays, &totalWatchSecs, &totalDataBytes,
		&uniqueUsers, &uniqueTitles, &avgComp,
		&dpCount, &dsCount, &tcCount, &maxBitrateBps,
	)

	result.TotalPlays = totalPlays
	result.TotalWatchTimeSecs = totalWatchSecs
	result.TotalDataUsedBytes = totalDataBytes
	result.UniqueUsers = uniqueUsers
	result.UniqueTitles = uniqueTitles
	result.AvgCompletionPct = math.Round(avgComp*10) / 10
	result.PeakBandwidthMbps = math.Round((float64(maxBitrateBps)/1_000_000.0)*100) / 100

	if totalPlays > 0 {
		result.StreamTypes = StreamTypeDistribution{
			DirectPlayCount:   dpCount,
			DirectPlayPct:     math.Round((float64(dpCount)/float64(totalPlays))*1000) / 10,
			DirectStreamCount: dsCount,
			DirectStreamPct:   math.Round((float64(dsCount)/float64(totalPlays))*1000) / 10,
			TranscodeCount:    tcCount,
			TranscodePct:      math.Round((float64(tcCount)/float64(totalPlays))*1000) / 10,
		}
	}

	// Check peak bandwidth from samples within the active window when unfiltered by playMethod/mediaType
	if totalPlays > 0 && (playMethodFilter == "" || strings.EqualFold(playMethodFilter, "all")) &&
		(mediaTypeFilter == "" || strings.EqualFold(mediaTypeFilter, "all")) {
		var samplePeakBps int64
		if windowDays > 0 && windowDays < 3650 {
			cutoff := time.Now().UTC().AddDate(0, 0, -windowDays).Format("2006-01-02 15:04:05")
			_ = db.DB.QueryRow(`SELECT COALESCE(MAX(total_bitrate_bps), 0) FROM streaming_bandwidth_samples WHERE timestamp >= ?`, cutoff).Scan(&samplePeakBps)
		} else {
			_ = db.DB.QueryRow(`SELECT COALESCE(MAX(total_bitrate_bps), 0) FROM streaming_bandwidth_samples`).Scan(&samplePeakBps)
		}
		if samplePeakMbps := math.Round((float64(samplePeakBps)/1_000_000.0)*100) / 100; samplePeakMbps > result.PeakBandwidthMbps {
			result.PeakBandwidthMbps = samplePeakMbps
		}
	}

	// 2. Breakdowns: Media Type, Resolution, Video Codec
	result.MediaTypeBreakdown = queryBreakdown(db.DB, "item_type", whereSQL, args, totalPlays)
	result.ResolutionBreakdown = queryBreakdown(db.DB, "video_resolution", whereSQL, args, totalPlays)
	result.CodecBreakdown = queryBreakdown(db.DB, "video_codec", whereSQL, args, totalPlays)

	// 3. Time Series (Daily Plays, Watch Time, Data Usage, Stream Types)
	tsDays := windowDays
	if tsDays > 90 || tsDays <= 0 {
		tsDays = 30
	}
	dailyMap := make(map[string]*StreamingTimeSeriesPoint)
	now := time.Now().UTC()
	for i := tsDays - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		dailyMap[d] = &StreamingTimeSeriesPoint{Date: d}
	}

	tsRows, err := db.DB.Query(fmt.Sprintf(`
		SELECT
			substr(started_at, 1, 10) AS day,
			COUNT(*),
			COALESCE(SUM(watched_secs), 0),
			COALESCE(SUM(data_used_bytes), 0),
			COALESCE(MAX(bitrate_bps), 0),
			COALESCE(SUM(CASE WHEN play_method = 'DirectPlay' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN play_method = 'DirectStream' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN play_method = 'Transcode' THEN 1 ELSE 0 END), 0)
		FROM streaming_history
		WHERE %s
		GROUP BY day
		ORDER BY day ASC
	`, whereSQL), args...)
	if err == nil {
		for tsRows.Next() {
			var day string
			var plays, dp, ds, tc int
			var watchSecs, dataBytes, maxDayBitrate int64
			if tsRows.Scan(&day, &plays, &watchSecs, &dataBytes, &maxDayBitrate, &dp, &ds, &tc) == nil {
				pt, exists := dailyMap[day]
				if !exists {
					pt = &StreamingTimeSeriesPoint{Date: day}
					dailyMap[day] = pt
				}
				pt.Plays = plays
				pt.WatchTimeSecs = watchSecs
				pt.DataUsedBytes = dataBytes
				pt.PeakBandwidthMbps = math.Round((float64(maxDayBitrate)/1_000_000.0)*100) / 100
				pt.DirectPlayCount = dp
				pt.DirectStreamCount = ds
				pt.TranscodeCount = tc
			}
		}
		tsRows.Close()
	}

	for i := tsDays - 1; i >= 0; i-- {
		d := now.AddDate(0, 0, -i).Format("2006-01-02")
		if pt, ok := dailyMap[d]; ok {
			result.TimeSeries = append(result.TimeSeries, *pt)
		}
	}

	// 4. Top Users Leaderboard
	uRows, err := db.DB.Query(fmt.Sprintf(`
		SELECT
			user_id,
			user_name,
			provider,
			COUNT(*) AS plays,
			COALESCE(SUM(watched_secs), 0) AS watch_secs,
			COALESCE(SUM(data_used_bytes), 0) AS data_bytes,
			COUNT(DISTINCT item_name) AS unique_items,
			COALESCE(SUM(CASE WHEN play_method = 'DirectPlay' THEN 1 ELSE 0 END), 0) AS dp_count,
			COALESCE(SUM(CASE WHEN play_method = 'Transcode' THEN 1 ELSE 0 END), 0) AS tc_count,
			COALESCE(AVG(completion_pct), 0) AS avg_comp,
			COALESCE(MAX(client_name || ' · ' || device_name), '') AS last_device,
			COALESCE(MAX(last_seen_at), '') AS last_seen
		FROM streaming_history
		WHERE %s AND user_name != ''
		GROUP BY user_name
		ORDER BY data_bytes DESC, plays DESC
		LIMIT 10
	`, whereSQL), args...)
	if err == nil {
		for uRows.Next() {
			var u StreamingUserStat
			if uRows.Scan(&u.UserID, &u.UserName, &u.Provider, &u.TotalPlays, &u.TotalWatchSecs, &u.TotalDataBytes, &u.UniqueItems, &u.DirectPlayCount, &u.TranscodeCount, &u.AvgCompletionPct, &u.LastDevice, &u.LastSeenAt) == nil {
				u.AvgCompletionPct = math.Round(u.AvgCompletionPct*10) / 10
				result.TopUsers = append(result.TopUsers, u)
			}
		}
		uRows.Close()
	}

	// 5. Top Watched Titles
	tRows, err := db.DB.Query(fmt.Sprintf(`
		SELECT
			item_id,
			CASE WHEN series_name != '' THEN series_name ELSE item_name END AS display_title,
			item_type,
			series_name,
			MAX(production_year),
			provider,
			MAX(video_resolution),
			MAX(video_codec),
			COUNT(*) AS plays,
			COUNT(DISTINCT user_name) AS viewers,
			COALESCE(SUM(watched_secs), 0) AS watch_secs,
			COALESCE(SUM(data_used_bytes), 0) AS data_bytes,
			COALESCE(AVG(completion_pct), 0) AS avg_comp,
			COALESCE(MAX(last_seen_at), '') AS last_watched
		FROM streaming_history
		WHERE %s AND item_name != ''
		GROUP BY display_title, item_type
		ORDER BY plays DESC, data_bytes DESC
		LIMIT 10
	`, whereSQL), args...)
	if err == nil {
		for tRows.Next() {
			var t StreamingTitleStat
			if tRows.Scan(&t.ItemID, &t.ItemName, &t.ItemType, &t.SeriesName, &t.ProductionYear, &t.Provider, &t.VideoResolution, &t.VideoCodec, &t.TotalPlays, &t.UniqueViewers, &t.TotalWatchSecs, &t.TotalDataBytes, &t.AvgCompletionPct, &t.LastWatchedAt) == nil {
				t.AvgCompletionPct = math.Round(t.AvgCompletionPct*10) / 10
				result.TopTitles = append(result.TopTitles, t)
			}
		}
		tRows.Close()
	}

	// 6. Recent History Log
	hRows, err := db.DB.Query(fmt.Sprintf(`
		SELECT
			id, session_key, provider, server_name, user_name,
			client_name, device_name, ip_address,
			item_id, item_name, item_type, series_name,
			season_number, episode_number, production_year,
			play_method, container, video_codec, video_resolution,
			audio_codec, audio_channels, hw_accel, bitrate_bps,
			duration_secs, watched_secs, data_used_bytes, completion_pct,
			started_at, last_seen_at, is_active
		FROM streaming_history
		WHERE %s
		ORDER BY last_seen_at DESC, id DESC
		LIMIT 500
	`, whereSQL), args...)
	if err == nil {
		for hRows.Next() {
			var h StreamingHistoryItem
			if hRows.Scan(
				&h.ID, &h.SessionKey, &h.Provider, &h.ServerName, &h.UserName,
				&h.ClientName, &h.DeviceName, &h.IPAddress,
				&h.ItemID, &h.ItemName, &h.ItemType, &h.SeriesName,
				&h.SeasonNumber, &h.EpisodeNumber, &h.ProductionYear,
				&h.PlayMethod, &h.Container, &h.VideoCodec, &h.VideoResolution,
				&h.AudioCodec, &h.AudioChannels, &h.HWAccel, &h.BitrateBps,
				&h.DurationSecs, &h.WatchedSecs, &h.DataUsedBytes, &h.CompletionPct,
				&h.StartedAt, &h.LastSeenAt, &h.IsActive,
			) == nil {
				h.BandwidthMbps = math.Round((float64(h.BitrateBps)/1_000_000.0)*100) / 100
				h.CompletionPct = math.Round(h.CompletionPct*10) / 10
				result.RecentHistory = append(result.RecentHistory, h)
			}
		}
		hRows.Close()
	}

	return result
}

func queryBreakdown(database *sql.DB, column, whereSQL string, args []interface{}, totalPlays int) []BreakdownEntry {
	allowedCols := map[string]bool{
		"item_type":        true,
		"video_resolution": true,
		"video_codec":      true,
	}
	if !allowedCols[column] || totalPlays <= 0 {
		return []BreakdownEntry{}
	}

	rows, err := database.Query(fmt.Sprintf(`
		SELECT
			COALESCE(NULLIF(%s, ''), 'Unknown') AS label,
			COUNT(*) AS cnt,
			COALESCE(SUM(watched_secs), 0),
			COALESCE(SUM(data_used_bytes), 0)
		FROM streaming_history
		WHERE %s
		GROUP BY label
		ORDER BY cnt DESC
	`, column, whereSQL), args...)
	if err != nil {
		return []BreakdownEntry{}
	}
	defer rows.Close()

	var out []BreakdownEntry
	for rows.Next() {
		var b BreakdownEntry
		if rows.Scan(&b.Label, &b.Count, &b.WatchTimeSecs, &b.DataUsedBytes) == nil {
			b.Pct = math.Round((float64(b.Count)/float64(totalPlays))*1000) / 10
			out = append(out, b)
		}
	}
	return out
}

// SeedStreamingDemoData populates realistic Jellyfin active streams, historical plays, and bandwidth usage.
func SeedStreamingDemoData() error {
	if db.DB == nil {
		return fmt.Errorf("database not initialized")
	}

	streamingMu.Lock()
	demoModeEnabled = true
	demoSessionsCache = []ActiveStreamSession{
		{
			SessionID:        "demo-session-1",
			Provider:         "jellyfin",
			ServerName:       "AetherFlow Jellyfin",
			UserID:           "usr-alex",
			UserName:         "alex_mercer",
			ClientName:       "Infuse 7",
			DeviceName:       "Apple TV 4K (Living Room)",
			DeviceID:         "atv4k-01",
			AppVersion:       "7.8.2",
			IPAddress:        "192.168.1.44",
			IsLAN:            true,
			ItemID:           "item-dune-2",
			ItemName:         "Dune: Part Two",
			ItemType:         "Movie",
			ProductionYear:   2024,
			State:            "playing",
			PositionSecs:     5840,
			DurationSecs:     9960,
			ProgressPct:      58.6,
			PlayMethod:       "DirectPlay",
			Container:        "MKV",
			VideoCodec:       "HEVC",
			VideoResolution:  "4K UHD",
			VideoRange:       "Dolby Vision",
			VideoFramerate:   23.976,
			IsVideoDirect:    true,
			AudioCodec:       "TRUEHD",
			AudioChannels:    8,
			AudioLayout:      "7.1 Atmos",
			AudioLanguage:    "ENG",
			IsAudioDirect:    true,
			SubtitleCodec:    "PGS",
			SubtitleLanguage: "ENG",
			TranscodeReasons: []string{},
			BitrateBps:       42_500_000,
			BandwidthMbps:    42.5,
			SessionDataBytes: 31_025_000_000,
			StartedAt:        time.Now().UTC().Add(-97 * time.Minute).Format(time.RFC3339),
		},
		{
			SessionID:            "demo-session-2",
			Provider:             "jellyfin",
			ServerName:           "AetherFlow Jellyfin",
			UserID:               "usr-elena",
			UserName:             "elena_vance",
			ClientName:           "Jellyfin Web",
			DeviceName:           "Chrome 130 (MacBook Pro)",
			DeviceID:             "chrome-mbp",
			AppVersion:           "10.10.3",
			IPAddress:            "198.51.100.78",
			IsLAN:                false,
			ItemID:               "item-severance-s2e4",
			ItemName:             "Woe's Hollow",
			ItemType:             "Episode",
			SeriesName:           "Severance",
			SeasonNumber:         2,
			EpisodeNumber:        4,
			ProductionYear:       2025,
			State:                "playing",
			PositionSecs:         1680,
			DurationSecs:         3120,
			ProgressPct:          53.8,
			PlayMethod:           "Transcode",
			Container:            "MKV",
			TargetContainer:      "TS",
			VideoCodec:           "AV1",
			TargetVideoCodec:     "H264",
			VideoResolution:      "1080p FHD",
			VideoRange:           "HDR10",
			VideoFramerate:       23.976,
			IsVideoDirect:        false,
			AudioCodec:           "EAC3",
			TargetAudioCodec:     "AAC",
			AudioChannels:        6,
			AudioLayout:          "5.1",
			AudioLanguage:        "ENG",
			IsAudioDirect:        false,
			HWAccel:              "VAAPI",
			TranscodeReasons:     []string{"VideoCodecNotSupported", "ContainerBitrateExceedsLimit"},
			TranscodeProgressPct: 74.2,
			TranscodeFps:         118.4,
			BitrateBps:           12_400_000,
			BandwidthMbps:        12.4,
			SessionDataBytes:     2_604_000_000,
			StartedAt:            time.Now().UTC().Add(-28 * time.Minute).Format(time.RFC3339),
		},
		{
			SessionID:        "demo-session-3",
			Provider:         "jellyfin",
			ServerName:       "AetherFlow Jellyfin",
			UserID:           "usr-marcus",
			UserName:         "marcus_chen",
			ClientName:       "Swiftfin",
			DeviceName:       "iPad Pro 13\" (M4)",
			DeviceID:         "ipad-m4",
			AppVersion:       "1.3.0",
			IPAddress:        "203.0.113.19",
			IsLAN:            false,
			ItemID:           "item-shogun-s1e9",
			ItemName:         "Crimson Sky",
			ItemType:         "Episode",
			SeriesName:       "Shōgun",
			SeasonNumber:     1,
			EpisodeNumber:    9,
			ProductionYear:   2024,
			State:            "playing",
			PositionSecs:     2490,
			DurationSecs:     3660,
			ProgressPct:      68.0,
			PlayMethod:       "DirectStream",
			Container:        "MKV",
			TargetContainer:  "MP4",
			VideoCodec:       "HEVC",
			VideoResolution:  "4K UHD",
			VideoRange:       "HDR10",
			VideoFramerate:   23.976,
			IsVideoDirect:    true,
			AudioCodec:       "EAC3",
			TargetAudioCodec: "AAC",
			AudioChannels:    2,
			AudioLayout:      "Stereo",
			AudioLanguage:    "JPN",
			IsAudioDirect:    false,
			SubtitleCodec:    "SRT",
			SubtitleLanguage: "ENG",
			TranscodeReasons: []string{"AudioCodecNotSupported"},
			BitrateBps:       18_200_000,
			BandwidthMbps:    18.2,
			SessionDataBytes: 5_664_750_000,
			StartedAt:        time.Now().UTC().Add(-42 * time.Minute).Format(time.RFC3339),
		},
	}
	streamingMu.Unlock()

	type demoEntry struct {
		daysAgo        int
		user           string
		client         string
		device         string
		ip             string
		itemID         string
		title          string
		itemType       string
		series         string
		season, ep     int
		year           int
		method         string
		container      string
		vCodec         string
		res            string
		aCodec         string
		aCh            int
		hwAccel        string
		bitrate        int64
		durSecs        int
		watchedSecs    int
		completionPct  float64
	}

	samples := []demoEntry{
		{0, "alex_mercer", "Infuse 7", "Apple TV 4K", "192.168.1.44", "item-dune-2", "Dune: Part Two", "Movie", "", 0, 0, 2024, "DirectPlay", "MKV", "HEVC", "4K UHD", "TRUEHD", 8, "", 42_500_000, 9960, 5840, 58.6},
		{0, "elena_vance", "Jellyfin Web", "Chrome 130", "198.51.100.78", "item-severance-s2e4", "Woe's Hollow", "Episode", "Severance", 2, 4, 2025, "Transcode", "MKV", "AV1", "1080p FHD", "EAC3", 6, "VAAPI", 12_400_000, 3120, 1680, 53.8},
		{0, "marcus_chen", "Swiftfin", "iPad Pro 13\"", "203.0.113.19", "item-shogun-s1e9", "Crimson Sky", "Episode", "Shōgun", 1, 9, 2024, "DirectStream", "MKV", "HEVC", "4K UHD", "EAC3", 6, "", 18_200_000, 3660, 2490, 68.0},
		{1, "alex_mercer", "Infuse 7", "Apple TV 4K", "192.168.1.44", "item-oppenheimer", "Oppenheimer", "Movie", "", 0, 0, 2023, "DirectPlay", "MKV", "HEVC", "4K UHD", "DTS-HD", 8, "", 54_000_000, 10800, 10800, 100.0},
		{1, "sara_kerrigan", "Jellyfin Media Player", "Windows Desktop", "192.168.1.89", "item-arcane-s2e3", "Finally Got the Name Right", "Episode", "Arcane", 2, 3, 2024, "DirectPlay", "MKV", "AV1", "1080p FHD", "EAC3", 6, "", 11_500_000, 2460, 2460, 100.0},
		{2, "elena_vance", "Jellyfin Web", "Chrome 130", "198.51.100.78", "item-severance-s2e3", "Who Is Alive?", "Episode", "Severance", 2, 3, 2025, "Transcode", "MKV", "AV1", "1080p FHD", "EAC3", 6, "VAAPI", 12_000_000, 3000, 3000, 100.0},
		{2, "marcus_chen", "Swiftfin", "iPad Pro 13\"", "203.0.113.19", "item-shogun-s1e8", "Abyss of Life", "Episode", "Shōgun", 1, 8, 2024, "DirectPlay", "MKV", "HEVC", "4K UHD", "EAC3", 6, "", 19_000_000, 3540, 3540, 100.0},
		{3, "alex_mercer", "Finamp", "iPhone 16 Pro", "172.20.10.2", "item-daft-punk", "Giorgio by Moroder", "Audio", "Random Access Memories", 1, 3, 2013, "DirectPlay", "FLAC", "FLAC", "Audio Lossless", "FLAC", 2, "", 1_411_000, 544, 544, 100.0},
		{3, "sara_kerrigan", "Jellyfin Media Player", "Windows Desktop", "192.168.1.89", "item-blade-runner-2049", "Blade Runner 2049", "Movie", "", 0, 0, 2017, "DirectPlay", "MKV", "HEVC", "4K UHD", "TRUEHD", 8, "", 48_000_000, 9840, 9840, 100.0},
		{4, "devon_brooks", "Jellyfin Android TV", "NVIDIA Shield Pro", "192.168.1.55", "item-dune-2", "Dune: Part Two", "Movie", "", 0, 0, 2024, "DirectPlay", "MKV", "HEVC", "4K UHD", "TRUEHD", 8, "", 42_500_000, 9960, 9960, 100.0},
		{5, "elena_vance", "Jellyfin Web", "Firefox 132", "198.51.100.78", "item-civil-war", "Civil War", "Movie", "", 0, 0, 2024, "Transcode", "MKV", "HEVC", "1080p FHD", "AAC", 2, "VAAPI", 9_500_000, 6540, 6540, 100.0},
		{6, "marcus_chen", "Swiftfin", "Apple TV 4K", "203.0.113.19", "item-interstellar", "Interstellar", "Movie", "", 0, 0, 2014, "DirectPlay", "MKV", "HEVC", "4K UHD", "DTS-HD", 6, "", 38_000_000, 10140, 10140, 100.0},
		{7, "sara_kerrigan", "Jellyfin Media Player", "Windows Desktop", "192.168.1.89", "item-arcane-s2e2", "Watch It All Burn", "Episode", "Arcane", 2, 2, 2024, "DirectPlay", "MKV", "AV1", "1080p FHD", "EAC3", 6, "", 11_200_000, 2400, 2400, 100.0},
		{9, "alex_mercer", "Infuse 7", "Apple TV 4K", "192.168.1.44", "item-the-batman", "The Batman", "Movie", "", 0, 0, 2022, "DirectPlay", "MKV", "HEVC", "4K UHD", "TRUEHD", 8, "", 41_000_000, 10560, 10560, 100.0},
		{11, "devon_brooks", "Jellyfin Android TV", "NVIDIA Shield Pro", "192.168.1.55", "item-alien-romulus", "Alien: Romulus", "Movie", "", 0, 0, 2024, "DirectStream", "MKV", "HEVC", "4K UHD", "EAC3", 6, "", 26_000_000, 7140, 7140, 100.0},
		{13, "elena_vance", "Jellyfin Web", "Chrome 130", "198.51.100.78", "item-severance-s2e2", "Goodbye, Mrs. Selvig", "Episode", "Severance", 2, 2, 2025, "Transcode", "MKV", "H264", "1080p FHD", "AAC", 2, "VAAPI", 10_800_000, 2880, 2880, 100.0},
	}

	now := time.Now().UTC()
	for idx, s := range samples {
		ts := now.AddDate(0, 0, -s.daysAgo).Add(-time.Duration(idx*17) * time.Minute).Format("2006-01-02 15:04:05")
		dataBytes := int64(s.watchedSecs) * (s.bitrate / 8)
		sessionKey := fmt.Sprintf("demo:jellyfin:%d:%s:%s", s.daysAgo, s.user, s.itemID)
		isActive := 0
		if s.daysAgo == 0 {
			isActive = 1
		}
		_, _ = db.DB.Exec(`
			INSERT OR REPLACE INTO streaming_history (
				session_key, provider, server_name, user_id, user_name,
				client_name, device_name, ip_address,
				item_id, item_name, item_type, series_name,
				season_number, episode_number, production_year,
				play_method, container, video_codec, video_resolution,
				audio_codec, audio_channels, hw_accel,
				bitrate_bps, duration_secs, watched_secs, data_used_bytes, completion_pct,
				started_at, last_seen_at, is_active
			) VALUES (?, 'jellyfin', 'AetherFlow Jellyfin', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			sessionKey, "usr-"+s.user, s.user,
			s.client, s.device, s.ip,
			s.itemID, s.title, s.itemType, s.series,
			s.season, s.ep, s.year,
			s.method, s.container, s.vCodec, s.res,
			s.aCodec, s.aCh, s.hwAccel,
			s.bitrate, s.durSecs, s.watchedSecs, dataBytes, s.completionPct,
			ts, ts, isActive,
		)
	}

	return nil
}

// ClearStreamingDemoData removes demo telemetry entries and disables demo mode.
func ClearStreamingDemoData() error {
	streamingMu.Lock()
	demoModeEnabled = false
	demoSessionsCache = nil
	streamingMu.Unlock()

	if db.DB != nil {
		_, err := db.DB.Exec(`DELETE FROM streaming_history WHERE session_key LIKE 'demo:%'`)
		return err
	}
	return nil
}
