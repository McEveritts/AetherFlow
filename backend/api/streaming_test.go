package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"aetherflow/services"

	"github.com/gin-gonic/gin"
)

func TestStreamingDashboard_JellyfinIntegrationAndAnalytics(t *testing.T) {
	setupTestDB(t)
	InitAESKey()

	var pausedCalled bool
	var unpausedCalled bool
	var stopCalled bool
	var activeEncodingDeletedDeviceID string
	var messageReceived string
	var messageHasTimeout bool

	// Spin up a mock Jellyfin server
	mockJellyfin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Emby-Token")
		if r.URL.Path != "/System/Info/Public" && token != "jf-secret-key-9999" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/System/Info", "/System/Info/Public":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"ServerName":      "Nexus Jellyfin",
				"Version":         "10.10.3",
				"Id":              "jf-server-01",
				"OperatingSystem": "Linux",
			})
		case "/Items/Counts":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"MovieCount":   420,
				"SeriesCount":  85,
				"EpisodeCount": 2150,
				"SongCount":    980,
			})
		case "/Sessions":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{
					"Id":                 "sess-live-1",
					"UserId":             "user-1",
					"UserName":           "commander_shepard",
					"Client":             "Infuse",
					"DeviceName":         "Apple TV 4K",
					"DeviceId":           "dev-atv",
					"ApplicationVersion": "7.8",
					"RemoteEndPoint":     "192.168.1.50",
					"LastActivityDate":   "2026-10-29T12:00:00Z",
					"PlayState": map[string]interface{}{
						"PositionTicks": int64(3600) * 10_000_000,
						"IsPaused":      false,
						"PlayMethod":    "Transcode",
					},
					"NowPlayingItem": map[string]interface{}{
						"Id":             "item-mass-effect",
						"Name":           "The Expanse: Finale",
						"Type":           "Episode",
						"SeriesName":     "The Expanse",
						"SeriesId":       "series-expanse",
						"ParentIndexNumber": 6,
						"IndexNumber":    6,
						"ProductionYear": 2022,
						"RunTimeTicks":   int64(4200) * 10_000_000,
						"Container":      "mkv",
						"Bitrate":        28_000_000,
						"Width":          3840,
						"Height":         2160,
						"ImageTags":      map[string]string{"Primary": "tag123"},
						"MediaStreams": []map[string]interface{}{
							{
								"Type":          "Video",
								"Index":         0,
								"Codec":         "hevc",
								"BitRate":       24_000_000,
								"Width":         3840,
								"Height":        2160,
								"VideoRange":    "HDR10",
								"RealFrameRate": 23.976,
							},
							{
								"Type":          "Audio",
								"Index":         1,
								"Codec":         "truehd",
								"BitRate":       4_000_000,
								"Channels":      8,
								"ChannelLayout": "7.1",
								"Language":      "eng",
								"IsDefault":     true,
							},
						},
					},
					"TranscodingInfo": map[string]interface{}{
						"AudioCodec":               "eac3",
						"VideoCodec":               "h264",
						"Container":                "ts",
						"IsVideoDirect":            false,
						"IsAudioDirect":            false,
						"Bitrate":                  16_000_000,
						"Framerate":                62.5,
						"CompletionPercentage":     88.4,
						"HardwareAccelerationType": "vaapi",
						"TranscodeReasons":         []string{"VideoCodecNotSupported", "AudioCodecNotSupported"},
					},
				},
			})
		case "/Users":
			_ = json.NewEncoder(w).Encode([]map[string]interface{}{
				{"Id": "user-1", "Name": "commander_shepard"},
			})
		case "/Users/user-1/Items":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"Items": []map[string]interface{}{
					{
						"Id":             "item-hist-1",
						"Name":           "Blade Runner 2049",
						"Type":           "Movie",
						"ProductionYear": 2017,
						"RunTimeTicks":   int64(9800) * 10_000_000,
						"Container":      "mkv",
						"Bitrate":        40_000_000,
						"Width":          3840,
						"Height":         2160,
						"UserData": map[string]interface{}{
							"PlayCount":      2,
							"LastPlayedDate": "2026-10-28T20:00:00Z",
						},
					},
				},
			})
		case "/Sessions/sess-live-1/Playing/Pause":
			pausedCalled = true
			w.WriteHeader(http.StatusNoContent)
		case "/Sessions/sess-live-1/Playing/Unpause":
			unpausedCalled = true
			w.WriteHeader(http.StatusNoContent)
		case "/Sessions/sess-live-1/Playing/Stop":
			stopCalled = true
			w.WriteHeader(http.StatusNoContent)
		case "/Videos/ActiveEncodings":
			if r.Method == http.MethodDelete {
				activeEncodingDeletedDeviceID = r.URL.Query().Get("deviceId")
				w.WriteHeader(http.StatusNoContent)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		case "/Sessions/sess-live-1/Message":
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if txt, ok := body["Text"].(string); ok {
				messageReceived = txt
			}
			_, messageHasTimeout = body["TimeoutMs"]
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockJellyfin.Close()

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("user_id", 1)
		c.Set("username", "admin")
		c.Set("user_role", "admin")
		c.Next()
	})
	r.PUT("/admin/streaming/servers/:provider", UpdateStreamingServer)
	r.POST("/admin/streaming/servers/test", TestStreamingServer)
	r.POST("/admin/streaming/servers/:provider/sync", SyncStreamingServerHistory)
	r.POST("/admin/streaming/sessions/:sessionId/command", ControlStreamingSession)
	r.POST("/admin/streaming/demo", HandleStreamingDemo)
	r.GET("/auth/streaming/dashboard", GetStreamingDashboard)

	// 1. Reject Plex/Emby configuration in initial Jellyfin-first release
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/streaming/servers/plex", bytes.NewBufferString(`{"url":"http://127.0.0.1:32400"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 when attempting to configure plex early, got %d", w.Code)
		}
	}

	// 2. Save Jellyfin Server Configuration
	{
		payload, _ := json.Marshal(map[string]interface{}{
			"name":    "Nexus Jellyfin",
			"url":     mockJellyfin.URL,
			"apiKey":  "jf-secret-key-9999",
			"enabled": true,
		})
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("PUT", "/admin/streaming/servers/jellyfin", bytes.NewBuffer(payload))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 saving Jellyfin config, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 3. Sync History from Jellyfin
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/admin/streaming/servers/jellyfin/sync", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 syncing Jellyfin history, got %d: %s", w.Code, w.Body.String())
		}
	}

	// 4. Fetch Dashboard Telemetry & Verify Stream + Bandwidth + Play Statistics
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/auth/streaming/dashboard?window=30", nil)
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 from dashboard endpoint, got %d: %s", w.Code, w.Body.String())
		}

		var dash services.StreamingDashboardResponse
		if err := json.Unmarshal(w.Body.Bytes(), &dash); err != nil {
			t.Fatalf("failed to decode dashboard response: %v", err)
		}

		if len(dash.Servers) != 3 {
			t.Fatalf("expected 3 servers (jellyfin, plex, emby), got %d", len(dash.Servers))
		}
		if dash.Servers[0].Provider != "jellyfin" || dash.Servers[0].Status != "connected" {
			t.Fatalf("expected connected jellyfin server, got %+v", dash.Servers[0])
		}
		if dash.Servers[0].LibraryCounts.Movies != 420 {
			t.Fatalf("expected 420 movies in library counts, got %d", dash.Servers[0].LibraryCounts.Movies)
		}
		if dash.Servers[1].Provider != "plex" || dash.Servers[1].Status != "coming_soon" {
			t.Fatalf("expected plex coming_soon, got %+v", dash.Servers[1])
		}
		if dash.Servers[2].Provider != "emby" || dash.Servers[2].Status != "coming_soon" {
			t.Fatalf("expected emby coming_soon, got %+v", dash.Servers[2])
		}

		if dash.LiveSummary.ActiveStreams != 1 || dash.LiveSummary.TranscodeCount != 1 {
			t.Fatalf("unexpected live summary: %+v", dash.LiveSummary)
		}
		if dash.LiveSummary.TotalBandwidthMbps != 16.0 {
			t.Fatalf("expected 16.0 Mbps active bandwidth, got %v", dash.LiveSummary.TotalBandwidthMbps)
		}

		sess := dash.ActiveSessions[0]
		if sess.UserName != "commander_shepard" || sess.VideoCodec != "HEVC" || sess.TargetVideoCodec != "H264" || sess.HWAccel != "VAAPI" {
			t.Fatalf("unexpected active session stream info: %+v", sess)
		}
		if sess.VideoResolution != "4K UHD" || sess.AudioLayout != "7.1" {
			t.Fatalf("unexpected resolution/audio layout: %+v", sess)
		}

		if dash.Analytics.TotalPlays < 2 || dash.Analytics.TotalDataUsedBytes <= 0 {
			t.Fatalf("expected analytics plays >= 2 and positive data usage, got plays=%d bytes=%d", dash.Analytics.TotalPlays, dash.Analytics.TotalDataUsedBytes)
		}
		if len(dash.Analytics.TopUsers) == 0 || dash.Analytics.TopUsers[0].UserName != "commander_shepard" {
			t.Fatalf("expected commander_shepard in top users, got %+v", dash.Analytics.TopUsers)
		}
	}

	// 5. Test Remote Session Control (Pause, Resume, Message, and Stop with ActiveEncodings termination)
	{
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/admin/streaming/sessions/sess-live-1/command", bytes.NewBufferString(`{"command":"pause"}`))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK || !pausedCalled {
			t.Fatalf("expected pause command to succeed, code=%d pausedCalled=%v", w.Code, pausedCalled)
		}

		wResume := httptest.NewRecorder()
		reqResume, _ := http.NewRequest("POST", "/admin/streaming/sessions/sess-live-1/command", bytes.NewBufferString(`{"command":"resume"}`))
		reqResume.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(wResume, reqResume)
		if wResume.Code != http.StatusOK || !unpausedCalled {
			t.Fatalf("expected resume command to succeed, code=%d unpausedCalled=%v", wResume.Code, unpausedCalled)
		}

		w2 := httptest.NewRecorder()
		req2, _ := http.NewRequest("POST", "/admin/streaming/sessions/sess-live-1/command", bytes.NewBufferString(`{"command":"message","message":"Server maintenance in 10m"}`))
		req2.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w2, req2)
		if w2.Code != http.StatusOK || messageReceived != "Server maintenance in 10m" || messageHasTimeout {
			t.Fatalf("expected message command to succeed without TimeoutMs, code=%d msg=%q hasTimeout=%v", w2.Code, messageReceived, messageHasTimeout)
		}

		wStop := httptest.NewRecorder()
		reqStop, _ := http.NewRequest("POST", "/admin/streaming/sessions/sess-live-1/command", bytes.NewBufferString(`{"command":"stop"}`))
		reqStop.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(wStop, reqStop)
		if wStop.Code != http.StatusOK || !stopCalled || activeEncodingDeletedDeviceID != "dev-atv" {
			t.Fatalf("expected stop command to succeed and terminate active encoding, code=%d stopCalled=%v deletedDevice=%q", wStop.Code, stopCalled, activeEncodingDeletedDeviceID)
		}
	}
}
