use super::*;

#[test]
fn live_transcode_metrics_keep_the_exact_field_order_in_english_and_french() {
    let item: MediaFlowLiveProgress = serde_json::from_value(json!({
        "frame": 120, "fps": 48, "speed": "2.1x", "time": "00:02:30", "size": "412 MiB", "bitrate": "375 kbps"
    })).unwrap();
    assert_eq!(
        format_live_transcode_metrics("en", &item),
        "Frame 120 · 48 fps · 2.1x · 00:02:30 · 412 MiB"
    );
    assert_eq!(
        format_live_transcode_metrics("fr", &item),
        "Cadre 120 · 48 fps · 2.1x · 00:02:30 · 412 MiB"
    );
}

#[test]
fn pipeline_inventory_supports_maps_and_wrapped_arrays() {
    let rows = services(
        &json!({"Sonarr":{"status":"stopped"},"Radarr":{"installed":false,"status":"running"},"ignored":false}),
    );
    assert_eq!(rows.len(), 2);
    let sonarr = rows.iter().find(|row| row["id"] == "sonarr").unwrap();
    assert!(installed(sonarr));
    assert!(!installed(
        rows.iter().find(|row| row["id"] == "radarr").unwrap()
    ));
    assert!(!installed(&json!({"status":"available"})));
    assert_eq!(
        services(&json!({"services":[{"id":"jellyfin","status":"running"}]}))[0]["id"],
        "jellyfin"
    );
}

#[test]
fn application_launch_links_allow_web_routes_and_reject_credential_urls() {
    assert_eq!(
        safe_launch_url(&json!({"web_ui_url":"/apps/sonarr"})),
        Some("/apps/sonarr".into())
    );
    assert_eq!(
        safe_launch_url(&json!({"url":"https://media.example.com"})),
        Some("https://media.example.com".into())
    );
    for url in [
        "javascript:alert(1)",
        "//evil.example.com",
        "https://user:secret@example.com",
        "/\\evil.example.com",
        "file:///etc/passwd",
    ] {
        assert_eq!(safe_launch_url(&json!({"url":url})), None, "{url}");
    }
    assert_eq!(bytes(1024.0), "1.0 KiB");
    assert_eq!(bytes(f64::NAN), "0 B");
}
