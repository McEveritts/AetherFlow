use super::client::do_emby_request;
use super::*;
use std::collections::HashMap;
use std::time::Duration;

use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

#[derive(Default)]
struct MockEmbyState {
    command_hits: AtomicUsize,
    active_encoding_delete_hits: AtomicUsize,
    sessions_fail: AtomicBool,
}

#[test]
fn test_emby_url_validation_and_token_sanitization() {
    assert_eq!(
        validate_emby_server_url("http://127.0.0.1:8096/emby/").unwrap(),
        "http://127.0.0.1:8096/emby"
    );
    assert!(validate_emby_server_url("ftp://127.0.0.1:8096").is_err());
    assert!(validate_emby_server_url("http://user:pass@127.0.0.1:8096").is_err());
    assert!(validate_emby_server_url("http://127.0.0.1:8096?api_key=secret").is_err());
    assert!(validate_emby_server_url("http://169.254.169.254/latest").is_err());

    let dirty = "  ab\"cd\r\nef\x071234  ";
    assert_eq!(sanitize_emby_token(dirty), "abcdef1234");
    assert_eq!(mask_emby_api_key(dirty), "****1234");
}

#[test]
fn test_capability_resolution_fails_closed_when_missing_or_partial() {
    // 1. Missing both SupportsMediaControl and SupportsRemoteControl -> must fail closed (false)
    let missing_caps: EmbySessionRaw = serde_json::from_value(serde_json::json!({
        "Id": "sess-missing-caps",
        "Client": "Emby Web",
        "DeviceName": "Firefox",
        "SupportedCommands": ["DisplayMessage"],
        "NowPlayingItem": {
            "Id": "item-1",
            "Name": "Dune",
            "Type": "Movie"
        }
    }))
    .unwrap();
    let ev1 = resolve_emby_session_capabilities(&missing_caps);
    assert!(!ev1.supports_media_control);
    assert!(!ev1.supports_remote_control);
    assert!(!ev1.can_pause);
    assert!(!ev1.can_resume);
    assert!(!ev1.can_stop);
    assert!(!ev1.can_send_message);

    // 2. SupportsRemoteControl=true (standard Emby SessionInfo property), SupportedCommands=[], NowPlayingItem present
    // -> Playback controls allowed, but can_send_message MUST be false (never inferred from empty SupportedCommands!)
    let no_msg_cmd: EmbySessionRaw = serde_json::from_value(serde_json::json!({
        "Id": "sess-no-msg",
        "Client": "Emby Theater",
        "DeviceName": "Shield",
        "SupportsRemoteControl": true,
        "SupportedCommands": ["MoveUp", "Select", "Mute"],
        "NowPlayingItem": {
            "Id": "item-2",
            "Name": "Arrival",
            "Type": "Movie"
        }
    }))
    .unwrap();
    let ev2 = resolve_emby_session_capabilities(&no_msg_cmd);
    assert!(ev2.supports_media_control);
    assert!(ev2.supports_remote_control);
    assert!(ev2.can_pause);
    assert!(ev2.can_resume);
    assert!(ev2.can_stop);
    assert!(!ev2.can_send_message);

    // 3. SupportsRemoteControl=true, SupportedCommands=["DisplayMessage"], but NO NowPlayingItem
    // -> can_send_message is true, but playback controls (pause/resume/stop) are false
    let idle_session: EmbySessionRaw = serde_json::from_value(serde_json::json!({
        "Id": "sess-idle",
        "SupportsRemoteControl": true,
        "SupportedCommands": ["DisplayMessage"]
    }))
    .unwrap();
    let ev3 = resolve_emby_session_capabilities(&idle_session);
    assert!(ev3.supports_media_control);
    assert!(!ev3.can_pause);
    assert!(!ev3.can_resume);
    assert!(!ev3.can_stop);
    assert!(ev3.can_send_message);

    // 4. Conflicting flags: SupportsRemoteControl=true, but Capabilities.SupportsMediaControl=false -> fail closed!
    let conflicting: EmbySessionRaw = serde_json::from_value(serde_json::json!({
        "Id": "sess-conflict",
        "SupportsRemoteControl": true,
        "Capabilities": {
            "SupportsMediaControl": false,
            "SupportedCommands": ["DisplayMessage"]
        },
        "NowPlayingItem": {
            "Id": "item-3",
            "Name": "Blade Runner",
            "Type": "Movie"
        }
    }))
    .unwrap();
    let ev4 = resolve_emby_session_capabilities(&conflicting);
    assert!(!ev4.supports_media_control);
    assert!(!ev4.can_pause);
    assert!(!ev4.can_send_message);
}

#[test]
fn test_session_normalization_preserves_emby_fields_and_rejects_wrong_server_id() {
    let raw: EmbySessionRaw = serde_json::from_value(serde_json::json!({
        "Id": "emby-sess-42",
        "ServerId": "srv-emby-prod",
        "UserId": "u-99",
        "UserName": "claire",
        "Client": "Emby for Apple TV",
        "DeviceName": "Living Room Apple TV",
        "DeviceId": "atv-living-room",
        "ApplicationVersion": "2.1.4",
        "RemoteEndPoint": "192.168.10.25",
        "SupportsRemoteControl": true,
        "SupportedCommands": ["DisplayMessage", "Mute"],
        "PlayState": {
            "PositionTicks": 18_000_000_000i64,
            "IsPaused": false,
            "PlayMethod": "Transcode",
            "PlaySessionId": "ps-777",
            "MediaSourceId": "ms-111",
            "AudioStreamIndex": 1,
            "SubtitleStreamIndex": 2
        },
        "NowPlayingItem": {
            "Id": "ep-101",
            "Name": "Theerton",
            "Type": "Episode",
            "SeriesName": "Silo",
            "SeriesId": "ser-silo",
            "ParentIndexNumber": 2,
            "IndexNumber": 5,
            "ProductionYear": 2025,
            "RunTimeTicks": 36_000_000_000i64,
            "Container": "mkv",
            "Bitrate": 20_000_000i64,
            "Width": 3840,
            "Height": 2160,
            "PrimaryImageTag": "tag-ep-primary",
            "PrimaryImageItemId": "ep-101",
            "MediaStreams": [
                {
                    "Type": "Video",
                    "Index": 0,
                    "Codec": "hevc",
                    "Width": 3840,
                    "Height": 2160,
                    "ColorTransfer": "smpte2084",
                    "AverageFrameRate": 23.976,
                    "BitRate": 18_000_000
                },
                {
                    "Type": "Audio",
                    "Index": 1,
                    "Codec": "eac3",
                    "Channels": 6,
                    "ChannelLayout": "5.1",
                    "Language": "eng",
                    "BitRate": 768_000,
                    "IsDefault": true
                },
                {
                    "Type": "Subtitle",
                    "Index": 2,
                    "Codec": "subrip",
                    "Language": "eng"
                }
            ]
        },
        "TranscodingInfo": {
            "Container": "ts",
            "IsVideoDirect": false,
            "IsAudioDirect": false,
            "VideoCodec": "h264",
            "AudioCodec": "aac",
            "Bitrate": 10_500_000,
            "Framerate": 64.2,
            "CompletionPercentage": 48.6,
            "VideoEncoderHwAccel": "vaapi",
            "TranscodeReasons": ["ContainerBitrateExceedsLimit"]
        }
    }))
    .unwrap();

    // Wrong expected_server_id must fail with WrongIdentity
    let mismatch =
        normalize_emby_session(raw.clone(), "Emby Vault", Some("srv-other-instance"), None);
    assert!(matches!(mismatch, Err(EmbyAdapterError::WrongIdentity(_))));

    // Matching expected_server_id normalizes cleanly into ActiveStreamSession
    let mut tracked = HashMap::new();
    tracked.insert(
        "emby:emby-sess-42:ep-101".to_string(),
        (125_000_000i64, "2026-11-01 22:00:00".to_string()),
    );
    let session = normalize_emby_session(raw, "Emby Vault", Some("srv-emby-prod"), Some(&tracked))
        .unwrap()
        .expect("active session");

    assert_eq!(session.provider, "emby");
    assert_eq!(session.server_name, "Emby Vault");
    assert_eq!(session.session_id, "emby-sess-42");
    assert_eq!(session.user_id, "u-99");
    assert_eq!(session.user_name, "claire");
    assert!(session.is_lan);
    assert_eq!(session.item_type, "Episode");
    assert_eq!(session.position_secs, 1800);
    assert_eq!(session.duration_secs, 3600);
    assert_eq!(session.progress_pct, 50.0);
    assert_eq!(session.play_method, "Transcode");
    assert_eq!(session.video_codec, "HEVC");
    assert_eq!(session.target_video_codec, "H264");
    assert_eq!(session.video_resolution, "4K UHD");
    assert_eq!(session.video_range, "HDR10");
    assert_eq!(session.video_framerate, 23.98);
    assert_eq!(session.audio_codec, "EAC3");
    assert_eq!(session.target_audio_codec, "AAC");
    assert_eq!(session.audio_layout, "5.1");
    assert_eq!(session.subtitle_codec, "SUBRIP");
    assert_eq!(session.hw_accel, "VAAPI");
    assert_eq!(session.bitrate_bps, 10_500_000);
    assert_eq!(session.bandwidth_mbps, 10.5);
    assert_eq!(session.session_data_bytes, 125_000_000);
    assert_eq!(session.started_at, "2026-11-01 22:00:00");
    assert!(session.has_artwork);
    assert_eq!(session.artwork_item_id, "ep-101");
    assert!(session.supports_media_control);
    assert!(session.supports_remote_control);
    assert!(session.can_send_message);
}

#[tokio::test]
async fn test_mock_http_server_validation_and_coming_soon_support_stage() {
    let app = Router::new()
        .route(
            "/System/Info",
            get(|headers: HeaderMap| async move {
                let token = headers
                    .get("X-Emby-Token")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                let auth = headers
                    .get("X-Emby-Authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if token != "valid-emby-key-9876" || !auth.contains("Token=\"valid-emby-key-9876\"")
                {
                    return StatusCode::UNAUTHORIZED.into_response();
                }
                Json(serde_json::json!({
                    "Id": "emby-srv-001",
                    "ServerName": "Aether Emby",
                    "Version": "4.8.10.0",
                    "OperatingSystemDisplayName": "Debian GNU/Linux 12 (bookworm)"
                }))
                .into_response()
            }),
        )
        .route(
            "/Items/Counts",
            get(|| async {
                Json(serde_json::json!({
                    "MovieCount": 310,
                    "SeriesCount": 64,
                    "EpisodeCount": 2410,
                    "SongCount": 980
                }))
            }),
        )
        .route(
            "/System/Info/Public",
            get(|| async {
                Json(serde_json::json!({
                    "Id": "emby-srv-001",
                    "ServerName": "Aether Emby Public",
                    "Version": "4.8.10.0"
                }))
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 1. Authenticated validation succeeds and keeps support_stage = "coming_soon"
    let st = test_emby_connection(&server_url, "valid-emby-key-9876", Some("emby-srv-001"))
        .await
        .expect("valid connection");
    assert_eq!(st.provider, "emby");
    assert_eq!(st.name, "Aether Emby");
    assert_eq!(st.status, "connected");
    assert_eq!(st.support_stage, "coming_soon");
    assert_eq!(st.server_id, "emby-srv-001");
    assert_eq!(st.version, "4.8.10.0");
    assert_eq!(st.operating_system, "Debian GNU/Linux 12 (bookworm)");
    assert_eq!(st.api_key_masked, "****9876");
    assert_eq!(st.library_counts.movies, 310);
    assert_eq!(st.library_counts.series, 64);
    assert_eq!(st.library_counts.episodes, 2410);
    assert_eq!(st.library_counts.audio, 980);

    // 2. Wrong expected_server_id fails closed
    let wrong_id = test_emby_connection(&server_url, "valid-emby-key-9876", Some("wrong-srv-id"))
        .await
        .unwrap_err();
    assert!(matches!(wrong_id, EmbyAdapterError::WrongIdentity(_)));

    // 3. Invalid API key fails with AuthenticationFailed
    let bad_key = test_emby_connection(&server_url, "wrong-key", None)
        .await
        .unwrap_err();
    assert!(matches!(
        bad_key,
        EmbyAdapterError::AuthenticationFailed { status: 401, .. }
    ));

    // 4. Public probe without API key reports unconfigured and coming_soon
    let pub_st = test_emby_connection(&server_url, "", Some("emby-srv-001"))
        .await
        .expect("public discovery");
    assert_eq!(pub_st.status, "unconfigured");
    assert_eq!(pub_st.support_stage, "coming_soon");
    assert_eq!(pub_st.server_id, "emby-srv-001");

    server.abort();
}

#[tokio::test]
async fn test_session_commands_enforce_capabilities_identity_and_no_command_on_failure() {
    let state = Arc::new(MockEmbyState::default());
    let app_state = state.clone();

    let app =
        Router::new()
            .route(
                "/Sessions",
                get(
                    |State(st): State<Arc<MockEmbyState>>, headers: HeaderMap| async move {
                        if headers.get("X-Emby-Token").and_then(|v| v.to_str().ok())
                            != Some("emby-secret")
                        {
                            return StatusCode::UNAUTHORIZED.into_response();
                        }
                        if st.sessions_fail.load(Ordering::SeqCst) {
                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                        }
                        Json(serde_json::json!([
                            {
                                "Id": "sess-full",
                                "ServerId": "srv-emby-1",
                                "UserId": "u1",
                                "UserName": "alex",
                                "Client": "Emby Web",
                                "DeviceName": "Chrome",
                                "DeviceId": "dev-chrome-1",
                                "SupportsRemoteControl": true,
                                "SupportedCommands": ["DisplayMessage"],
                                "PlayState": {
                                    "PositionTicks": 100_000_000,
                                    "IsPaused": false,
                                    "PlayMethod": "Transcode",
                                    "PlaySessionId": "ps-transcode-1"
                                },
                                "NowPlayingItem": {
                                    "Id": "item-1",
                                    "Name": "Interstellar",
                                    "Type": "Movie"
                                },
                                "TranscodingInfo": {
                                    "IsVideoDirect": false,
                                    "IsAudioDirect": true,
                                    "VideoCodec": "h264"
                                }
                            },
                            {
                                "Id": "sess-no-msg",
                                "ServerId": "srv-emby-1",
                                "UserId": "u2",
                                "UserName": "maya",
                                "Client": "Emby Roku",
                                "DeviceName": "Roku Ultra",
                                "DeviceId": "dev-roku",
                                "SupportsRemoteControl": true,
                                "SupportedCommands": ["Mute"],
                                "PlayState": {
                                    "PositionTicks": 50_000_000,
                                    "IsPaused": false,
                                    "PlayMethod": "DirectPlay"
                                },
                                "NowPlayingItem": {
                                    "Id": "item-2",
                                    "Name": "Silo",
                                    "Type": "Episode"
                                }
                            },
                            {
                                "Id": "sess-no-ctrl",
                                "ServerId": "srv-emby-1",
                                "UserId": "u3",
                                "UserName": "liam",
                                "Client": "DLNA",
                                "DeviceName": "TV",
                                "DeviceId": "dev-tv",
                                "SupportsRemoteControl": false,
                                "SupportedCommands": [],
                                "NowPlayingItem": {
                                    "Id": "item-3",
                                    "Name": "Track 1",
                                    "Type": "Audio"
                                }
                            }
                        ]))
                        .into_response()
                    },
                ),
            )
            .route(
                "/Sessions/:id/Playing/:cmd",
                post(
                    |State(st): State<Arc<MockEmbyState>>,
                     axum::extract::Path((_id, _cmd)): axum::extract::Path<(
                        String,
                        String,
                    )>| async move {
                        st.command_hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    },
                ),
            )
            .route(
                "/Sessions/:id/Message",
                post(
                    |State(st): State<Arc<MockEmbyState>>,
                     axum::extract::Path(_id): axum::extract::Path<String>,
                     Json(body): Json<serde_json::Value>| async move {
                        assert_eq!(body["Text"], "Maintenance soon");
                        st.command_hits.fetch_add(1, Ordering::SeqCst);
                        StatusCode::NO_CONTENT
                    },
                ),
            )
            .route(
                "/Videos/ActiveEncodings",
                delete(|State(st): State<Arc<MockEmbyState>>| async move {
                    st.active_encoding_delete_hits
                        .fetch_add(1, Ordering::SeqCst);
                    StatusCode::NO_CONTENT
                }),
            )
            .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 1. Wrong provider target -> rejected before any HTTP command
    let err_prov = send_emby_session_command(
        &server_url,
        "emby-secret",
        &EmbyCommandTarget {
            provider: "jellyfin".to_string(),
            expected_server_id: "srv-emby-1".to_string(),
            session_id: "sess-full".to_string(),
            command: "pause".to_string(),
            header: String::new(),
            message: String::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err_prov, EmbyAdapterError::WrongIdentity(_)));
    assert_eq!(state.command_hits.load(Ordering::SeqCst), 0);

    // 2. Wrong expected_server_id -> rejected before POST command
    let err_sid = send_emby_session_command(
        &server_url,
        "emby-secret",
        &EmbyCommandTarget {
            provider: "emby".to_string(),
            expected_server_id: "srv-wrong-999".to_string(),
            session_id: "sess-full".to_string(),
            command: "pause".to_string(),
            header: String::new(),
            message: String::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err_sid, EmbyAdapterError::WrongIdentity(_)));
    assert_eq!(state.command_hits.load(Ordering::SeqCst), 0);

    // 3. Demo prefix does NOT bypass capability verification (no fake Ok)
    let err_demo = send_emby_session_command(
        &server_url,
        "emby-secret",
        &EmbyCommandTarget {
            provider: "emby".to_string(),
            expected_server_id: "srv-emby-1".to_string(),
            session_id: "demo-sess-01".to_string(),
            command: "pause".to_string(),
            header: String::new(),
            message: String::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err_demo, EmbyAdapterError::SessionNotFound(_)));
    assert_eq!(state.command_hits.load(Ordering::SeqCst), 0);

    // 4. Session without DisplayMessage rejects message command without sending POST
    let err_msg = send_emby_session_command(
        &server_url,
        "emby-secret",
        &EmbyCommandTarget {
            provider: "emby".to_string(),
            expected_server_id: "srv-emby-1".to_string(),
            session_id: "sess-no-msg".to_string(),
            command: "message".to_string(),
            header: "Admin".to_string(),
            message: "Hello".to_string(),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err_msg, EmbyAdapterError::CapabilityDenied(_)));
    assert_eq!(state.command_hits.load(Ordering::SeqCst), 0);

    // 5. Session with SupportsRemoteControl=false rejects pause command without sending POST
    let err_ctrl = send_emby_session_command(
        &server_url,
        "emby-secret",
        &EmbyCommandTarget {
            provider: "emby".to_string(),
            expected_server_id: "srv-emby-1".to_string(),
            session_id: "sess-no-ctrl".to_string(),
            command: "pause".to_string(),
            header: String::new(),
            message: String::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err_ctrl, EmbyAdapterError::CapabilityDenied(_)));
    assert_eq!(state.command_hits.load(Ordering::SeqCst), 0);

    // 6. Valid message command and stop command (with ActiveEncodings cleanup) succeed
    let msg_ok = send_emby_session_command(
        &server_url,
        "emby-secret",
        &EmbyCommandTarget {
            provider: "emby".to_string(),
            expected_server_id: "srv-emby-1".to_string(),
            session_id: "sess-full".to_string(),
            command: "message".to_string(),
            header: "Notice".to_string(),
            message: "Maintenance soon".to_string(),
        },
    )
    .await
    .expect("message command succeeds");
    assert_eq!(msg_ok.command, "message");
    assert_eq!(state.command_hits.load(Ordering::SeqCst), 1);

    let stop_ok = send_emby_session_command(
        &server_url,
        "emby-secret",
        &EmbyCommandTarget {
            provider: "emby".to_string(),
            expected_server_id: "srv-emby-1".to_string(),
            session_id: "sess-full".to_string(),
            command: "stop".to_string(),
            header: String::new(),
            message: String::new(),
        },
    )
    .await
    .expect("stop command succeeds");
    assert!(stop_ok.active_encoding_stopped);
    assert_eq!(state.command_hits.load(Ordering::SeqCst), 2);
    assert_eq!(state.active_encoding_delete_hits.load(Ordering::SeqCst), 1);

    // 7. Upstream HTTP 500 on fresh /Sessions capability check -> fails closed and issues no command
    state.sessions_fail.store(true, Ordering::SeqCst);
    let err_upstream = send_emby_session_command(
        &server_url,
        "emby-secret",
        &EmbyCommandTarget {
            provider: "emby".to_string(),
            expected_server_id: "srv-emby-1".to_string(),
            session_id: "sess-full".to_string(),
            command: "pause".to_string(),
            header: String::new(),
            message: String::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(
        err_upstream,
        EmbyAdapterError::UpstreamStatus { status: 500, .. }
    ));
    assert_eq!(state.command_hits.load(Ordering::SeqCst), 2);

    // 8. Transport failure when target port is unreachable -> fails closed and issues no command
    let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_url = format!("http://{}", closed_listener.local_addr().unwrap());
    drop(closed_listener);

    let err_down = send_emby_session_command(
        &closed_url,
        "emby-secret",
        &EmbyCommandTarget {
            provider: "emby".to_string(),
            expected_server_id: "srv-emby-1".to_string(),
            session_id: "sess-full".to_string(),
            command: "pause".to_string(),
            header: String::new(),
            message: String::new(),
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(err_down, EmbyAdapterError::Transport(_)));
    assert_eq!(state.command_hits.load(Ordering::SeqCst), 2);

    server.abort();
}

#[tokio::test]
async fn test_optional_event_capability_and_redirect_or_oversized_rejection() {
    let app = Router::new()
        .route(
            "/Plugins",
            get(|| async {
                Json(serde_json::json!([
                    {
                        "Id": "plg-1",
                        "Name": "Playback Reporting",
                        "Version": "2.1.0.0"
                    }
                ]))
            }),
        )
        .route(
            "/System/Info",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [(header::LOCATION, "http://127.0.0.1:9999/evil")],
                )
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Optional event capability remains supported=false even when plugin is detected
    let ev_cap = probe_emby_optional_event_capability(&server_url, "emby-key").await;
    assert!(!ev_cap.supported);
    assert!(!ev_cap.verified);
    assert_eq!(ev_cap.plugin_name.as_deref(), Some("Playback Reporting"));
    assert_eq!(ev_cap.status, "unverified_plugin_detected");

    // Redirect response on /System/Info is rejected by Policy::none() / status.is_redirection()
    let redir_err = test_emby_connection(&server_url, "emby-key", None)
        .await
        .unwrap_err();
    assert!(matches!(redir_err, EmbyAdapterError::Transport(_)));

    // Oversized payload is rejected before buffering unbounded memory
    let small_limit_err = do_emby_request(
        reqwest::Method::GET,
        &format!("{}/Plugins", server_url),
        "emby-key",
        None,
        Duration::from_secs(3),
        16, // 16-byte limit
    )
    .await
    .unwrap_err();
    assert!(matches!(
        small_limit_err,
        EmbyAdapterError::PayloadTooLarge { limit_bytes: 16 }
    ));

    server.abort();
}

#[tokio::test]
async fn test_mock_http_live_sessions_artwork_and_honest_item_summaries() {
    let app =
        Router::new()
            .route(
                "/System/Info",
                get(|| async {
                    Json(serde_json::json!({
                        "Id": "emby-srv-hist",
                        "ServerName": "Emby Cinema",
                        "Version": "4.8.10.0"
                    }))
                }),
            )
            .route(
                "/Sessions",
                get(|| async {
                    Json(serde_json::json!([
                        {
                            "Id": "live-1",
                            "ServerId": "emby-srv-hist",
                            "UserId": "usr-1",
                            "UserName": "noah",
                            "Client": "Emby Android",
                            "DeviceName": "Pixel 9",
                            "DeviceId": "px9",
                            "RemoteEndPoint": "10.0.0.42",
                            "SupportsRemoteControl": true,
                            "SupportedCommands": ["DisplayMessage"],
                            "PlayState": {
                                "PositionTicks": 600_000_000i64,
                                "IsPaused": false,
                                "PlayMethod": "DirectPlay"
                            },
                            "NowPlayingItem": {
                                "Id": "mov-99",
                                "Name": "Oppenheimer",
                                "Type": "Movie",
                                "RunTimeTicks": 108_000_000_000i64,
                                "Container": "mkv"
                            }
                        },
                        {
                            "Id": "idle-2",
                            "ServerId": "emby-srv-hist",
                            "UserId": "usr-2",
                            "UserName": "idle-user",
                            "Client": "Emby Web"
                        }
                    ]))
                }),
            )
            .route(
                "/Users",
                get(|| async {
                    Json(serde_json::json!([
                        { "Id": "usr-1", "Name": "noah" }
                    ]))
                }),
            )
            .route(
                "/Users/usr-1/Items",
                get(
                    |axum::extract::Query(params): axum::extract::Query<
                        HashMap<String, String>,
                    >| async move {
                        if params.get("Filters").map(String::as_str) == Some("IsPlayed") {
                            Json(serde_json::json!({
                                "TotalRecordCount": 1,
                                "Items": [
                                    {
                                        "Id": "mov-99",
                                        "Name": "Oppenheimer",
                                        "Type": "Movie",
                                        "ProductionYear": 2023,
                                        "RunTimeTicks": 108_000_000_000i64,
                                        "Container": "mkv",
                                        "Bitrate": 24_000_000i64,
                                        "Width": 3840,
                                        "Height": 2160,
                                        "UserData": {
                                            "Played": true,
                                            "LastPlayedDate": "2026-10-31T21:30:00Z"
                                        }
                                    }
                                ]
                            }))
                        } else {
                            Json(serde_json::json!({
                                "TotalRecordCount": 0,
                                "Items": []
                            }))
                        }
                    },
                ),
            )
            .route(
                "/Items/mov-99/Images/Primary",
                get(|| async {
                    (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "image/webp")],
                        vec![0x52u8, 0x49, 0x46, 0x46],
                    )
                }),
            );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let live = fetch_emby_live_sessions(
        "Emby Cinema",
        &server_url,
        "emby-token",
        Some("emby-srv-hist"),
    )
    .await
    .expect("live sessions");
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].session_id, "live-1");
    assert_eq!(live[0].item_name, "Oppenheimer");

    let summaries = fetch_emby_item_summaries(
        "Emby Cinema",
        &server_url,
        "emby-token",
        Some("emby-srv-hist"),
    )
    .await
    .expect("item summaries");
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0].session_key,
        "emby:emby-srv-hist:sync:usr-1:mov-99"
    );
    assert_eq!(summaries[0].provenance, "item_summary");
    assert_eq!(summaries[0].timestamp_certainty, "last_played");
    assert_eq!(summaries[0].byte_accuracy, "unrecorded");
    assert_eq!(summaries[0].data_used_bytes, 0);
    assert_eq!(summaries[0].watched_secs, 10800);
    assert_eq!(summaries[0].completion_pct, 100.0);

    let art = fetch_emby_artwork(&server_url, "emby-token", "mov-99")
        .await
        .expect("artwork");
    assert_eq!(art.content_type, "image/webp");
    assert_eq!(art.bytes, vec![0x52, 0x49, 0x46, 0x46]);

    server.abort();
}

#[test]
fn test_resolve_default_emby_url_respects_port_8097_tls_scheme_and_custom_listen_port() {
    use super::client::resolve_default_emby_url_from;

    // 1. Default fallback uses Emby's marketplace port 8097 (not Jellyfin's 8096).
    assert_eq!(EMBY_DEFAULT_URL, "http://127.0.0.1:8097");
    assert_eq!(EmbyServerConfig::default().url, "http://127.0.0.1:8097");
    assert_eq!(
        resolve_default_emby_url_from(None, None, ""),
        "http://127.0.0.1:8097"
    );

    // 2. External ingress respects tls_enabled = false vs tls_enabled = true.
    let http_external = af_models::AppIngressConfig {
        app_name: "emby".to_string(),
        public_domain: "emby.example.com".to_string(),
        external_access_enabled: true,
        listen_port: 8097,
        tls_enabled: false,
        ..Default::default()
    };
    assert_eq!(
        resolve_default_emby_url_from(None, Some(&http_external), "fallback.example.com"),
        "http://emby.example.com"
    );

    let https_external = af_models::AppIngressConfig {
        tls_enabled: true,
        ..http_external.clone()
    };
    assert_eq!(
        resolve_default_emby_url_from(None, Some(&https_external), "fallback.example.com"),
        "https://emby.example.com"
    );

    // 3. Local-only ingress uses configured custom listen_port on loopback.
    let custom_local = af_models::AppIngressConfig {
        app_name: "emby".to_string(),
        public_domain: "emby.example.com".to_string(),
        external_access_enabled: false,
        listen_port: 18097,
        tls_enabled: false,
        ..Default::default()
    };
    assert_eq!(
        resolve_default_emby_url_from(None, Some(&custom_local), "fallback.example.com"),
        "http://127.0.0.1:18097"
    );

    // 4. External enabled with empty public_domain falls back to custom listen_port.
    let empty_dom = af_models::AppIngressConfig {
        app_name: "emby".to_string(),
        public_domain: "   ".to_string(),
        external_access_enabled: true,
        listen_port: 18098,
        tls_enabled: true,
        ..Default::default()
    };
    assert_eq!(
        resolve_default_emby_url_from(None, Some(&empty_dom), "fallback.example.com"),
        "http://127.0.0.1:18098"
    );

    // 5. Explicit EMBY_URL override wins and trims trailing slash.
    assert_eq!(
        resolve_default_emby_url_from(
            Some(" http://10.0.0.9:8097/emby/ "),
            Some(&https_external),
            "fallback.example.com"
        ),
        "http://10.0.0.9:8097/emby"
    );
}

#[test]
fn test_get_stored_emby_config_preserves_existing_operator_url_without_rewriting() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    crate::plugins::tests::ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO streaming_servers (provider, name, url, api_key, enabled, server_id)
             VALUES ('emby', 'Operator Emby', 'http://127.0.0.1:8096', 'op-key', 1, 'srv-op')",
            [],
        )
        .unwrap();
    }
    let cfg = get_stored_emby_config();
    assert_eq!(cfg.url, "http://127.0.0.1:8096");
    let stored_url: String = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT url FROM streaming_servers WHERE provider = 'emby'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored_url, "http://127.0.0.1:8096");
}
