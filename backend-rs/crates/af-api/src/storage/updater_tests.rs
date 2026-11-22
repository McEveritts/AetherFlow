use super::updater::{
    check_update, compute_rate_limit_retry_at, nightly_update_available, normalize_update_channel,
    read_update_channel_from_conn, run_update, select_release_for_channel,
    validate_runner_self_update_initiation_payload, GitHubReleaseAuthor, GitHubReleasePayload,
    GitHubUpdateCache,
};
use axum::body::Body;
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
use chrono::{Duration, Utc};

fn sample_releases() -> Vec<GitHubReleasePayload> {
    vec![
        GitHubReleasePayload {
            tag_name: "v4.0.0-experimental".to_string(),
            target_commitish: "experimental".to_string(),
            prerelease: true,
            draft: false,
            body: "\u{FEFF}Release Notes ? Experimental\r\nLine 2".to_string(),
            html_url: "https://github.com/McEveritts/AetherFlow/releases/tag/v4.0.0-experimental"
                .to_string(),
            author: GitHubReleaseAuthor {
                login: "McEveritts".to_string(),
            },
        },
        GitHubReleasePayload {
            tag_name: "v3.3.0-nightly.20261101".to_string(),
            target_commitish: "nightly".to_string(),
            prerelease: true,
            draft: false,
            body: "Nightly build notes".to_string(),
            html_url:
                "https://github.com/McEveritts/AetherFlow/releases/tag/v3.3.0-nightly.20261101"
                    .to_string(),
            author: GitHubReleaseAuthor {
                login: "McEveritts".to_string(),
            },
        },
        GitHubReleasePayload {
            tag_name: "v3.2.7".to_string(),
            target_commitish: "master".to_string(),
            prerelease: false,
            draft: false,
            body: "Stable release notes".to_string(),
            html_url: "https://github.com/McEveritts/AetherFlow/releases/tag/v3.2.7".to_string(),
            author: GitHubReleaseAuthor {
                login: "McEveritts".to_string(),
            },
        },
    ]
}

#[test]
fn update_launch_ack_accepts_only_consistent_terminal_receipts() {
    for success in [true, false] {
        let mut receipt = af_models::SelfUpdateJobStatus {
            status: if success { "succeeded" } else { "failed" }.into(),
            completed: true,
            success,
            job_unit: "aetherflow-self-update-deploy-stable-abcdef12.service".into(),
            error: if success { "" } else { "Fixture failure" }.into(),
            exit_code: Some(if success { 0 } else { 9 }),
        };
        let raw = serde_json::to_string(&receipt).unwrap();
        assert_eq!(
            validate_runner_self_update_initiation_payload(&raw)
                .unwrap()
                .0,
            receipt.job_unit
        );
        receipt.completed = false;
        assert!(validate_runner_self_update_initiation_payload(
            &serde_json::to_string(&receipt).unwrap()
        )
        .is_err());
    }
}

#[test]
fn validate_runner_self_update_initiation_payload_rejects_empty_or_invalid_job_unit() {
    assert!(validate_runner_self_update_initiation_payload("{}").is_err());
    assert!(validate_runner_self_update_initiation_payload(
        r#"{"status":"initiated","completed":false,"job_unit":""}"#
    )
    .is_err());
    assert!(validate_runner_self_update_initiation_payload(
        r#"{"status":"initiated","completed":false,"job_unit":"nginx.service"}"#
    )
    .is_err());
    assert!(validate_runner_self_update_initiation_payload(
        r#"{"status":"failed","completed":false,"job_unit":"aetherflow-self-update-deploy-stable-abcdef12.service"}"#
    )
    .is_err());
    let (unit, engine) = validate_runner_self_update_initiation_payload(
        r#"{"status":"initiated","completed":false,"job_unit":"aetherflow-self-update-deploy-stable-abcdef12.service","engine":"af_release_rust"}"#,
    )
    .expect("valid initiation payload must succeed");
    assert_eq!(
        unit,
        "aetherflow-self-update-deploy-stable-abcdef12.service"
    );
    assert_eq!(engine, "af_release_rust");
}

#[test]
fn test_select_release_for_channel_migrates_legacy_experimental_to_nightly() {
    let releases = sample_releases();

    // Stable selects v3.2.7 and ignores prereleases / hyphenated tags
    let (stable_tag, stable_body, _) =
        select_release_for_channel(&releases, "stable").expect("stable release");
    assert_eq!(stable_tag, "v3.2.7");
    assert_eq!(stable_body, "Stable release notes");

    // Nightly ignores v4.0.0-experimental and selects v3.3.0-nightly.20261101
    let (nightly_tag, nightly_body, _) =
        select_release_for_channel(&releases, "nightly").expect("nightly release");
    assert_eq!(nightly_tag, "v3.3.0-nightly.20261101");
    assert_eq!(nightly_body, "Nightly build notes");

    let (exp_tag, exp_body, _) =
        select_release_for_channel(&releases, "experimental").expect("experimental release");
    assert_eq!(exp_tag, nightly_tag);
    assert_eq!(exp_body, nightly_body);

    // When only experimental and stable releases exist, nightly returns None (so it falls back to branch head)
    let without_nightly = vec![releases[0].clone(), releases[2].clone()];
    assert!(select_release_for_channel(&without_nightly, "nightly").is_none());
}

#[test]
fn test_select_release_for_channel_accepts_automated_nightly() {
    let mut release = sample_releases()[1].clone();
    release.tag_name = "v4.0.0-nightly.123.1".to_string();
    release.target_commitish = "abc1234".to_string();
    release.author.login = "github-actions[bot]".to_string();
    let releases = vec![release.clone()];
    let (tag, _, _) = select_release_for_channel(&releases, "nightly").expect("automated nightly");
    assert_eq!(tag, "v4.0.0-nightly.123.1");
    assert!(select_release_for_channel(&releases, "stable").is_none());
    let (legacy_tag, _, _) = select_release_for_channel(&releases, "experimental").unwrap();
    assert_eq!(legacy_tag, tag);

    release.author.login = "untrusted-author".to_string();
    assert!(select_release_for_channel(&[release], "nightly").is_none());
}

#[test]
fn test_nightly_update_available_semantics() {
    for (current, latest, expected) in [
        ("v3.2.7", "v4.0.0-nightly.123.1", true),
        ("v4.0.0-experimental", "v4.0.0-nightly.123.1", true),
        ("v4.0.0", "v4.0.0-nightly.123.1", true),
        ("nightly-abc1234", "v4.0.0-nightly.123.1", true),
        ("v4.0.0-nightly.122.1", "v4.0.0-nightly.123.1", true),
        ("v4.0.0-nightly.123.1", "v4.0.0-nightly.123.1", false),
        (" V4.0.0-NIGHTLY.123.1 ", "v4.0.0-nightly.123.1", false),
        ("v4.1.0", "v4.0.0-nightly.123.1", false),
        ("v4.1.0-experimental", "v4.0.0-nightly.123.1", false),
        ("v4.0.0", "", false),
    ] {
        assert_eq!(
            nightly_update_available(current, latest),
            expected,
            "{current} -> {latest}"
        );
    }
}

#[test]
fn legacy_experimental_channel_migrates_to_nightly() {
    assert_eq!(normalize_update_channel("experimental"), "nightly");
    assert_eq!(normalize_update_channel(" EXPERIMENTAL "), "nightly");
}

#[test]
fn test_github_update_cache_ttl_and_rate_limit_backoff() {
    let mut cache = GitHubUpdateCache::default();
    let now = Utc::now();
    let url_releases = "https://api.github.com/repos/McEveritts/AetherFlow/releases";
    let url_commits = "https://api.github.com/repos/McEveritts/AetherFlow/commits/experimental";

    cache.reset_if_token_changed("token-a");

    // 1. 200 OK response is cached for 5 minutes
    let ok_headers = HeaderMap::new();
    let res = cache.record_response(
        url_releases,
        200,
        &ok_headers,
        Ok(b"[{\"tag_name\":\"v3.2.7\"}]".to_vec()),
        now,
    );
    assert!(res.is_ok());

    let cached_4m = cache
        .get_cached(url_releases, now + Duration::minutes(4))
        .expect("cached at 4m");
    assert_eq!(cached_4m.unwrap(), b"[{\"tag_name\":\"v3.2.7\"}]".to_vec());

    assert!(
        cache
            .get_cached(url_releases, now + Duration::minutes(6))
            .is_none(),
        "cache entry must expire after 5 minutes"
    );

    // 2. Token change clears cache
    cache.reset_if_token_changed("token-b");
    assert!(cache.get_cached(url_releases, now).is_none());

    // 3. HTTP 403 with X-RateLimit-Remaining: 0 and X-RateLimit-Reset sets global rate-limit backoff
    let mut rl_headers = HeaderMap::new();
    rl_headers.insert("X-RateLimit-Remaining", HeaderValue::from_static("0"));
    let reset_ts = (now + Duration::minutes(10)).timestamp();
    rl_headers.insert(
        "X-RateLimit-Reset",
        HeaderValue::from_str(&reset_ts.to_string()).unwrap(),
    );

    let err = cache
        .record_response(url_releases, 403, &rl_headers, Ok(Vec::new()), now)
        .unwrap_err();
    assert!(err.is_rate_limited());
    assert_eq!(err.retry_at.unwrap().timestamp(), reset_ts);
    assert!(err
        .to_string()
        .starts_with("GitHub API rate limit reached; retry after "));

    // Subsequent requests to ANY GitHub update URL are short-circuited while rate-limited
    let blocked_other_url = cache
        .get_cached(url_commits, now + Duration::minutes(2))
        .expect("rate limit applies across URLs")
        .unwrap_err();
    assert!(blocked_other_url.is_rate_limited());
    assert_eq!(blocked_other_url.retry_at.unwrap().timestamp(), reset_ts);

    // After reset_ts, cache allows requests again
    assert!(cache
        .get_cached(url_commits, now + Duration::minutes(11))
        .is_none());

    // 4. HTTP 429 with Retry-After seconds
    let mut retry_headers = HeaderMap::new();
    retry_headers.insert("Retry-After", HeaderValue::from_static("180"));
    let retry_at_429 = compute_rate_limit_retry_at(429, &retry_headers, now).unwrap();
    assert_eq!(retry_at_429, now + Duration::seconds(180));
}

#[test]
fn read_update_channel_from_conn_propagates_sqlite_errors_and_defaults_missing_row() {
    let empty = rusqlite::Connection::open_in_memory().unwrap();
    empty
        .execute_batch("CREATE TABLE settings (id INTEGER PRIMARY KEY, update_channel TEXT);")
        .unwrap();
    assert_eq!(read_update_channel_from_conn(&empty).unwrap(), "stable");

    empty
        .execute(
            "INSERT INTO settings (id, update_channel) VALUES (1, 'nightly')",
            [],
        )
        .unwrap();
    assert_eq!(read_update_channel_from_conn(&empty).unwrap(), "nightly");

    let broken = rusqlite::Connection::open_in_memory().unwrap();
    assert!(read_update_channel_from_conn(&broken).is_err());
}

#[tokio::test]
async fn run_update_and_check_update_return_internal_error_when_settings_query_fails() {
    if crate::plugins::tests::run_plugin_test_in_subprocess() {
        return;
    }
    crate::plugins::tests::ensure_shared_test_db();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute_batch("DROP TABLE settings;").unwrap();
    }

    assert_eq!(
        check_update().await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/admin/system/update/run")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        run_update(req).await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
}
