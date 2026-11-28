use super::*;

#[test]
fn test_semver_build_metadata_and_debian_ordering() {
    // SemVer 2.0.0 build metadata is ignored for version precedence
    assert!(!is_remote_version_newer("1.0.0", "1.0.0+build.2"));
    assert!(!is_remote_version_newer("1.0.0+build.2", "1.0.0"));
    assert_eq!(
        compare_versions("1.0.0", "1.0.0+build.2"),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        compare_versions("1.0.0+build.2", "1.0.0"),
        std::cmp::Ordering::Equal
    );

    // Prereleases with letter suffix are strictly OLDER than bare release
    assert!(is_remote_version_newer("1.0.0-foo", "1.0.0"));
    assert!(!is_remote_version_newer("1.0.0", "1.0.0-foo"));
    assert_eq!(
        compare_versions("1.0.0-foo", "1.0.0"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_versions("1.0.0", "1.0.0-foo"),
        std::cmp::Ordering::Greater
    );

    assert!(is_remote_version_newer("1.0.0-alpha.1", "1.0.0"));
    assert_eq!(
        compare_versions("1.0.0-alpha.1", "1.0.0"),
        std::cmp::Ordering::Less
    );

    assert!(is_remote_version_newer("1.0.0-rc.1", "1.0.0"));
    assert_eq!(
        compare_versions("1.0.0-rc.1", "1.0.0"),
        std::cmp::Ordering::Less
    );

    // SemVer 2.0.0: numeric prereleases after hyphen (like 1.0.0-1, 1.0.0-0.3.7) are prereleases (LOWER precedence than 1.0.0)
    assert!(is_remote_version_newer("1.0.0-1", "1.0.0"));
    assert!(!is_remote_version_newer("1.0.0", "1.0.0-1"));
    assert_eq!(
        compare_versions("1.0.0-1", "1.0.0"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_versions("1.0.0", "1.0.0-1"),
        std::cmp::Ordering::Greater
    );

    assert!(is_remote_version_newer("1.0.0-0.3.7", "1.0.0"));
    assert_eq!(
        compare_versions("1.0.0-0.3.7", "1.0.0"),
        std::cmp::Ordering::Less
    );

    // Apt mode: Debian package revisions (-1 > bare, +deb11u1 < +deb11u2, +b1 < +b2)
    assert!(is_remote_version_newer_for_source(
        "1.0.0", "1.0.0-1", "apt"
    ));
    assert!(!is_remote_version_newer_for_source(
        "1.0.0-1", "1.0.0", "apt"
    ));
    assert_eq!(
        compare_versions_for_source("1.0.0", "1.0.0-1", "apt"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_versions_for_source("1.0.0-1", "1.0.0", "apt"),
        std::cmp::Ordering::Greater
    );

    assert!(is_remote_version_newer_for_source(
        "1.2.3-1ubuntu1",
        "1.2.3-2ubuntu1",
        "apt"
    ));
    assert_eq!(
        compare_versions_for_source("1.2.3-1ubuntu1", "1.2.3-2ubuntu1", "apt"),
        std::cmp::Ordering::Less
    );

    assert!(is_remote_version_newer_for_source(
        "1.2.3+deb11u1",
        "1.2.3+deb11u2",
        "apt"
    ));
    assert_eq!(
        compare_versions_for_source("1.2.3+deb11u1", "1.2.3+deb11u2", "apt"),
        std::cmp::Ordering::Less
    );
    assert!(is_remote_version_newer_for_source(
        "1.2.3+b1", "1.2.3+b2", "apt"
    ));
    assert_eq!(
        compare_versions_for_source("1.2.3+b1", "1.2.3+b2", "apt"),
        std::cmp::Ordering::Less
    );

    // Release prefixes normalized
    assert_eq!(
        compare_versions("release_1.0.0", "v1.0.0"),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        compare_versions("rel_1.0.0", "1.0.0"),
        std::cmp::Ordering::Equal
    );
    assert_eq!(
        compare_versions("release-1.0.0", "1.0.0+build.1"),
        std::cmp::Ordering::Equal
    );
}

#[test]
fn test_stacked_tag_prefixes_in_extract_version() {
    assert_eq!(extract_version("release-v1.2.3", ""), "1.2.3");
    assert_eq!(extract_version("release_v1.2.3", ""), "1.2.3");
    assert_eq!(extract_version("rel-v1.2.3", ""), "1.2.3");
    assert_eq!(extract_version("rel_v1.2.3", ""), "1.2.3");
    assert_eq!(extract_version("release_1.2.3", ""), "1.2.3");
    assert_eq!(extract_version("v1.2.3", ""), "1.2.3");
}

#[test]
fn test_git_commit_sha_antisymmetry_and_newer() {
    let sha1 = "6e840acbda8d1234567890abcdef1234567890ab";
    let sha2 = "9999999bda8d1234567890abcdef1234567890ab";
    // Distinct commits: compare_versions must be antisymmetric total order
    let ord1 = compare_versions(sha1, sha2);
    let ord2 = compare_versions(sha2, sha1);
    assert_eq!(ord1, ord2.reverse());
    assert_ne!(ord1, std::cmp::Ordering::Equal);

    // Prefix-matching commits are equal
    assert_eq!(compare_versions("6e840ac", sha1), std::cmp::Ordering::Equal);
    assert_eq!(compare_versions(sha1, "6e840ac"), std::cmp::Ordering::Equal);

    // is_remote_version_newer: distinct commit on tracked branch is an update
    assert!(is_remote_version_newer(sha1, sha2));
    assert!(is_remote_version_newer(sha2, sha1));
    // Same/prefix-matching commit is NOT an update
    assert!(!is_remote_version_newer(sha1, "6e840ac"));
    assert!(!is_remote_version_newer("6e840ac", sha1));
}

#[tokio::test]
async fn test_detect_installed_version_fails_closed_when_live_cmd_fails_with_af_version() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-fail-closed-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/test-fail-pkg");
    std::fs::create_dir_all(&opt_dir).unwrap();
    std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "test-fail-pkg".into(),
        // A live command that is guaranteed to fail
        version_command: vec!["/bin/false".into()],
        ..Default::default()
    };

    // Even though .af-version exists with "1.0.0", the configured live probe failed,
    // so detect_installed_version MUST fail closed (Err)
    let res = detect_installed_version(&pkg).await;
    assert!(
        res.is_err(),
        "Expected detect_installed_version to fail closed when live cmd fails"
    );

    let rec = build_package_update_record(
        "test-fail-pkg",
        true,
        res,
        Ok(("1.0.0".to_string(), "https://example.com".to_string())),
        None,
        "2026-11-08T12:00:00Z".to_string(),
    );
    assert_eq!(rec.error, "Installed version could not be confirmed");

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_stale_cache_origin_isolation_and_observed_at_preservation() {
    let origin_a = "https://api.github.com";
    let origin_b = "https://github-enterprise.internal.net";
    let repo = "myorg/myrepo";
    let observed_time = "2026-11-08T09:30:00Z";

    // Insert into cache under origin A
    {
        let mut cache = github_release_cache();
        cache.insert(
            github_release_cache_key(origin_a, repo),
            (
                "2.5.0".to_string(),
                format!("https://github.com/{repo}/releases/tag/v2.5.0"),
                Instant::now() - Duration::from_secs(3600),
                observed_time.to_string(),
            ),
        );
    }

    // Stale lookup under origin B must return None (origin isolation!)
    assert_eq!(get_cached_github_release_stale(origin_b, repo), None);

    // Stale lookup under origin A must return the cached version, URL, and observed_at
    let cached = get_cached_github_release_stale(origin_a, repo);
    assert!(cached.is_some());
    let (v, _u, obs) = cached.unwrap();
    assert_eq!(v, "2.5.0");
    assert_eq!(obs, observed_time);

    // When used in build_package_update_record_for_source with Err and no prior DB record,
    // checked_at is set to observed_time
    let rec = build_package_update_record_for_source(
        origin_a,
        "github",
        repo,
        true,
        Ok("2.4.0".to_string()),
        Err(anyhow::anyhow!("API timeout")),
        None,
        "2026-11-08T12:00:00Z".to_string(),
        "",
    );
    assert_eq!(rec.latest_version, "2.5.0");
    assert_eq!(rec.checked_at, observed_time);

    // When static fallback is used with no prior DB record and no cache hit, checked_at is empty ("")
    let rec_static = build_package_update_record_for_source(
        origin_b,
        "github",
        "threadfin",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("API timeout")),
        None,
        "2026-11-08T12:00:00Z".to_string(),
        "",
    );
    // threadfin has static fallback; since it had no cache hit under origin_b and no prior DB record,
    // checked_at must be empty string
    assert_eq!(rec_static.checked_at, "");
}

#[test]
fn test_source_provenance_validation_invalidates_prev_on_mismatch_or_legacy() {
    let origin_a = "https://api.github.com";
    let origin_b = "https://internal-ghe.example.com";
    let repo_a = "owner/repo-a";
    let repo_b = "owner/repo-b";

    let matching_prev = PackageUpdateRecord {
        package_id: "testpkg".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "1.1.0".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "https://github.com/owner/repo-a/releases/tag/v1.1.0".to_string(),
        error: String::new(),
        source_key: format!("github:{}|{}", normalize_api_origin(origin_a), repo_a),
    };

    // 1. Matching provenance: previous version, URL, checked_at, and update_available are preserved on error
    let expected_key_a = format!("github:{}|{}", normalize_api_origin(origin_a), repo_a);
    let rec_matching = build_package_update_record_for_source(
        origin_a,
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&matching_prev),
        "2026-11-08T12:00:00Z".to_string(),
        &expected_key_a,
    );
    assert_eq!(rec_matching.latest_version, "1.1.0");
    assert_eq!(
        rec_matching.release_url,
        "https://github.com/owner/repo-a/releases/tag/v1.1.0"
    );
    assert_eq!(rec_matching.checked_at, "2026-11-01T00:00:00Z");
    assert!(rec_matching.update_available);

    // 2. Mismatched origin (origin changed from origin_a to origin_b):
    // prev record must be INVALIDATED (treated as None for latest_version/release_url/checked_at/update_available)
    let expected_key_b_origin = format!("github:{}|{}", normalize_api_origin(origin_b), repo_a);
    let rec_mismatched_origin = build_package_update_record_for_source(
        origin_b,
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&matching_prev),
        "2026-11-08T12:00:00Z".to_string(),
        &expected_key_b_origin,
    );
    assert_eq!(rec_mismatched_origin.latest_version, "");
    assert_eq!(rec_mismatched_origin.release_url, "");
    assert_eq!(rec_mismatched_origin.checked_at, "");
    assert!(!rec_mismatched_origin.update_available);

    // 3. Mismatched repo (repo changed from repo_a to repo_b):
    let expected_key_b_repo = format!("github:{}|{}", normalize_api_origin(origin_a), repo_b);
    let rec_mismatched_repo = build_package_update_record_for_source(
        origin_a,
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&matching_prev),
        "2026-11-08T12:00:00Z".to_string(),
        &expected_key_b_repo,
    );
    assert_eq!(rec_mismatched_repo.latest_version, "");
    assert_eq!(rec_mismatched_repo.release_url, "");
    assert_eq!(rec_mismatched_repo.checked_at, "");
    assert!(!rec_mismatched_repo.update_available);

    // 4. Legacy record without source_key (source_key is empty):
    let legacy_prev = PackageUpdateRecord {
        package_id: "testpkg".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "1.1.0".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "https://github.com/owner/repo-a/releases/tag/v1.1.0".to_string(),
        error: String::new(),
        source_key: String::new(), // legacy empty
    };
    let rec_legacy = build_package_update_record_for_source(
        origin_a,
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&legacy_prev),
        "2026-11-08T12:00:00Z".to_string(),
        &expected_key_a,
    );
    assert_eq!(rec_legacy.latest_version, "");
    assert_eq!(rec_legacy.release_url, "");
    assert_eq!(rec_legacy.checked_at, "");
    assert!(!rec_legacy.update_available);
}

#[test]
fn test_fallback_timestamps_for_stale_cache_and_static_fallback() {
    let origin = "https://api.github.com";
    let repo = "demo/fallback-test";
    let cache_obs = "2026-11-07T15:30:00Z";

    // Seed stale cache for repo
    {
        let mut cache = github_release_cache();
        cache.insert(
            github_release_cache_key(origin, repo),
            (
                "3.0.0".to_string(),
                format!("https://github.com/{repo}/releases/tag/v3.0.0"),
                Instant::now() - Duration::from_secs(7200),
                cache_obs.to_string(),
            ),
        );
    }

    // prev record has an old checked_at, but empty latest_version
    let prev_empty_latest = PackageUpdateRecord {
        package_id: "demo-pkg".to_string(),
        installed: true,
        installed_version: "2.9.0".to_string(),
        latest_version: "".to_string(),
        update_available: false,
        checked_at: "2026-11-01T10:00:00Z".to_string(),
        release_url: "".to_string(),
        error: "earlier error".to_string(),
        source_key: format!("github:{}|{}", normalize_api_origin(origin), repo),
    };

    // When upstream errors, but stale cache provides version 3.0.0,
    // checked_at MUST be cache_obs ("2026-11-07T15:30:00Z"), NOT prev.checked_at and NOT now!
    let rec_cache = build_package_update_record_for_source(
        origin,
        "github",
        repo,
        true,
        Ok("2.9.0".to_string()),
        Err(anyhow::anyhow!("503 Service Unavailable")),
        Some(&prev_empty_latest),
        "2026-11-08T18:00:00Z".to_string(),
        &format!("github:{}|{}", normalize_api_origin(origin), repo),
    );
    assert_eq!(rec_cache.latest_version, "3.0.0");
    assert_eq!(rec_cache.checked_at, cache_obs);

    // When upstream errors and static fallback provides version (threadfin),
    // and prev_record had empty latest_version, checked_at MUST be empty string ("")!
    let prev_threadfin_empty = PackageUpdateRecord {
        package_id: "threadfin".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "".to_string(),
        update_available: false,
        checked_at: "2026-11-01T10:00:00Z".to_string(),
        release_url: "".to_string(),
        error: "failed previously".to_string(),
        source_key: format!(
            "github:{}|Threadfin/Threadfin",
            normalize_api_origin(origin)
        ),
    };

    let rec_static = build_package_update_record_for_source(
        origin,
        "github",
        "threadfin",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("GitHub API down")),
        Some(&prev_threadfin_empty),
        "2026-11-08T18:00:00Z".to_string(),
        &format!(
            "github:{}|Threadfin/Threadfin",
            normalize_api_origin(origin)
        ),
    );
    assert!(!rec_static.latest_version.is_empty());
    assert_eq!(rec_static.checked_at, ""); // MUST NOT copy prev.checked_at!
}

#[tokio::test]
async fn test_origin_scoped_rate_limit_cooldowns_isolated() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    clear_github_rate_limits();

    // Start mock origin A: always returns 429 Too Many Requests
    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_a = listener_a.local_addr().unwrap();
    let req_count_a = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let req_count_a_server = req_count_a.clone();
    let server_a = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener_a.accept().await {
            req_count_a_server.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buf = vec![0; 2048];
            let _ = socket.read(&mut buf).await;
            let resp = "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 120\r\nx-ratelimit-resource: core\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    // Start mock origin B: returns 200 OK with release JSON
    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_b = listener_b.local_addr().unwrap();
    let server_b = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener_b.accept().await {
            let mut buf = vec![0; 2048];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"tag_name":"v2.0.0","html_url":"http://mock-b/release"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin_a = format!("http://{addr_a}");
    let origin_b = format!("http://{addr_b}");

    // First call to origin A gets 429 with x-ratelimit-resource: core and records rate limit cooldown
    let res_a = detect_latest_github_release(&client, &origin_a, "owner/repo").await;
    assert!(res_a.is_err());
    assert!(res_a.unwrap_err().to_string().contains("rate limit"));
    assert_eq!(req_count_a.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Subsequent release discovery request to origin A checking "releases" must be suppressed
    // WITHOUT hitting the server, because "core" cooldown is active and shared across buckets!
    let res_a2 = detect_latest_github_release(&client, &origin_a, "owner/repo").await;
    assert!(res_a2.is_err());
    assert!(res_a2
        .unwrap_err()
        .to_string()
        .contains("rate limit backoff active"));
    assert_eq!(req_count_a.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Cooldown checks across origin A buckets
    assert!(is_github_api_rate_limited(&origin_a, "core"));
    assert!(is_github_api_rate_limited(&origin_a, "releases"));
    assert!(is_github_rate_limited_for_origin(&origin_a, "releases"));
    assert!(github_rate_limit_remaining_secs_for_origin(&origin_a, "releases") > 0);

    // Origin B must be COMPLETELY UNAFFECTED!
    assert!(!is_github_api_rate_limited(&origin_b, "core"));
    assert!(!is_github_api_rate_limited(&origin_b, "releases"));
    assert!(!is_github_api_rate_limited(&origin_b, "default"));

    let res_b = detect_latest_github_release(&client, &origin_b, "owner/repo").await;
    assert!(
        res_b.is_ok(),
        "Origin B request must succeed despite Origin A rate limit: {:?}",
        res_b
    );
    let (ver_b, url_b, _) = res_b.unwrap();
    assert_eq!(ver_b, "2.0.0");
    assert_eq!(url_b, "http://mock-b/release");

    server_a.abort();
    server_b.abort();
    clear_github_rate_limits();
}

#[tokio::test]
async fn test_retired_readarr_discovery_preserves_pinned_target() {
    let client = build_github_http_client();
    let pkg = Package {
        name: "readarr".into(),
        update_source: "retired".into(),
        ..Default::default()
    };

    // 1. Older Readarr installation (0.4.17.0) -> latest_version == "0.4.18.2805", update_available == true
    let mut rec_older = build_package_update_record_for_source(
        "https://api.github.com",
        "retired",
        "readarr",
        true,
        Ok("0.4.17.0".to_string()),
        Ok(("0.4.18.2805".to_string(), String::new())),
        None,
        "2026-11-09T00:00:00Z".to_string(),
        "",
    );
    if rec_older.latest_version.is_empty() {
        rec_older.latest_version = "0.4.18.2805".to_string();
    }
    rec_older.update_available = rec_older.installed
        && is_remote_version_newer_for_source(
            &rec_older.installed_version,
            &rec_older.latest_version,
            &pkg.update_source,
        );
    rec_older.error = String::new();
    assert_eq!(rec_older.latest_version, "0.4.18.2805");
    assert!(rec_older.update_available);
    assert_eq!(rec_older.error, "");

    // 2. Up-to-date Readarr installation (0.4.18.2805) -> latest_version == "0.4.18.2805", update_available == false
    let mut rec_uptodate = build_package_update_record_for_source(
        "https://api.github.com",
        "retired",
        "readarr",
        true,
        Ok("0.4.18.2805".to_string()),
        Ok(("0.4.18.2805".to_string(), String::new())),
        None,
        "2026-11-09T00:00:00Z".to_string(),
        "",
    );
    if rec_uptodate.latest_version.is_empty() {
        rec_uptodate.latest_version = "0.4.18.2805".to_string();
    }
    rec_uptodate.update_available = rec_uptodate.installed
        && is_remote_version_newer_for_source(
            &rec_uptodate.installed_version,
            &rec_uptodate.latest_version,
            &pkg.update_source,
        );
    rec_uptodate.error = String::new();
    assert_eq!(rec_uptodate.latest_version, "0.4.18.2805");
    assert!(!rec_uptodate.update_available);
    assert_eq!(rec_uptodate.error, "");

    // Pinned version returned without querying upstream GitHub
    let detected = detect_latest_version(
        &client,
        "https://invalid-host-unreachable.example.com",
        &pkg,
    )
    .await
    .unwrap();
    assert_eq!(detected.0, "0.4.18.2805");
}

#[test]
fn test_fresh_latest_observation_keeps_own_timestamp_when_installed_probe_falls_back() {
    let prev = PackageUpdateRecord {
        package_id: "qbittorrent".to_string(),
        installed: true,
        installed_version: "4.6.0".to_string(),
        latest_version: "4.6.1".to_string(),
        update_available: true,
        checked_at: "2026-11-01T12:00:00Z".to_string(),
        release_url: "https://github.com/qbittorrent/qBittorrent/releases/tag/release-4.6.1"
            .to_string(),
        error: String::new(),
        source_key: "github:https://api.github.com|qbittorrent/qbittorrent|stable".to_string(),
    };

    let rec = build_package_update_record(
        "qbittorrent",
        true,
        Err(anyhow::anyhow!("probe timed out")),
        Ok((
            "4.6.2".to_string(),
            "https://github.com/qbittorrent/qBittorrent/releases/tag/release-4.6.2".to_string(),
        )),
        Some(&prev),
        "2026-11-08T12:00:00Z".to_string(),
    );

    assert_eq!(rec.installed_version, "4.6.0");
    assert_eq!(rec.latest_version, "4.6.2");
    assert_eq!(rec.checked_at, "2026-11-08T12:00:00Z");
    assert_eq!(
        rec.error,
        "Installed version probe returned no output; retaining last known installed version"
    );
}

#[test]
fn test_debian_version_preservation_and_comparison() {
    assert!(is_remote_version_newer_for_source(
        "1.0.0",
        "1.0.0+git1",
        "apt"
    ));
    assert!(!is_remote_version_newer_for_source(
        "1.0.0+git1",
        "1.0.0",
        "apt"
    ));
    assert_eq!(
        compare_debian_versions_str("1.0.0", "1.0.0+git1"),
        std::cmp::Ordering::Less
    );
    assert_eq!(
        compare_debian_versions_str("1.0.0+git1", "1.0.0"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_debian_versions_str("1:1.0-1", "1.0-1"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_debian_versions_str("1.0~rc1-1", "1.0-1"),
        std::cmp::Ordering::Less
    );
}

#[test]
fn test_channel_provenance_and_retained_tag_revalidation() {
    let pkg_nightly = Package {
        name: "testpkg".into(),
        update_source: "github".into(),
        update_repo: "owner/repo".into(),
        update_channel: "nightly".into(),
        ..Default::default()
    };
    let key_nightly = canonical_update_source_key("https://api.github.com", &pkg_nightly);
    assert!(key_nightly.ends_with("|nightly"));

    let pkg_stable = Package {
        name: "testpkg".into(),
        update_source: "github".into(),
        update_repo: "owner/repo".into(),
        update_channel: "stable".into(),
        ..Default::default()
    };
    let key_stable = canonical_update_source_key("https://api.github.com", &pkg_stable);
    assert!(key_stable.ends_with("|stable"));
    assert_ne!(key_nightly, key_stable);

    let prev_nightly = PackageUpdateRecord {
        package_id: "testpkg".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "1.2.0-rc1".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "https://github.com/owner/repo/releases/tag/v1.2.0-rc1".to_string(),
        error: String::new(),
        source_key: key_nightly,
    };

    // When switching to stable channel and upstream fails, prev_nightly is invalidated
    let rec = build_package_update_record_for_source(
        "https://api.github.com",
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("GitHub API down")),
        Some(&prev_nightly),
        "2026-11-08T12:00:00Z".to_string(),
        &key_stable,
    );
    assert_eq!(rec.latest_version, "");
    assert_eq!(rec.checked_at, "");
    assert!(!rec.update_available);

    // When channel == "stable", a prerelease latest_version (1.2.0-rc1 or 1.0.0-1) is not retained on fallback
    let prev_prerelease_on_stable = PackageUpdateRecord {
        package_id: "testpkg".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "1.2.0-rc1".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "".to_string(),
        error: String::new(),
        source_key: key_stable.clone(),
    };
    let rec_filtered = build_package_update_record_for_source(
        "https://api.github.com",
        "github",
        "testpkg",
        true,
        Ok("1.0.0".to_string()),
        Err(anyhow::anyhow!("GitHub API down")),
        Some(&prev_prerelease_on_stable),
        "2026-11-08T12:00:00Z".to_string(),
        &key_stable,
    );
    assert_eq!(rec_filtered.latest_version, "");
    assert_eq!(rec_filtered.checked_at, "");
    assert!(!rec_filtered.update_available);
}

#[tokio::test]
async fn test_git_tag_channel_filtering_and_prerelease_rules() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-git-channel-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let run_git = |args: &[&str]| {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(&temp_dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    };

    run_git(&["init", "-b", "main"]);
    run_git(&["config", "user.email", "test@example.com"]);
    run_git(&["config", "user.name", "Test"]);
    std::fs::write(temp_dir.join("README.md"), "hello").unwrap();
    run_git(&["add", "README.md"]);
    run_git(&["commit", "-m", "initial commit"]);

    // Create tags:
    // v0.9.0 (stable)
    // v1.0.0-0.1 (numeric prerelease)
    // v1.0.0-nightly (arbitrary prerelease)
    run_git(&["tag", "v0.9.0"]);
    run_git(&["tag", "v1.0.0-0.1"]);
    run_git(&["tag", "v1.0.0-nightly"]);

    let repo_url = temp_dir.to_str().unwrap();

    // 1. On "stable" (or ""), numeric prerelease v1.0.0-0.1 and v1.0.0-nightly are ignored -> selects 0.9.0!
    let res_stable = detect_latest_git_tag_for_channel(repo_url, "", "stable").await;
    assert!(
        res_stable.is_ok(),
        "Expected stable tag: {:?}",
        res_stable.err()
    );
    assert_eq!(res_stable.unwrap().0, "0.9.0");

    let res_default = detect_latest_git_tag_for_channel(repo_url, "", "").await;
    assert!(res_default.is_ok());
    assert_eq!(res_default.unwrap().0, "0.9.0");

    // 2. On "prerelease" or "nightly" channel, prereleases are allowed -> selects 1.0.0-nightly
    let res_nightly = detect_latest_git_tag_for_channel(repo_url, "", "nightly").await;
    assert!(res_nightly.is_ok());
    assert_eq!(res_nightly.unwrap().0, "1.0.0-nightly");

    // 3. Repository with ONLY prereleases:
    // Delete v0.9.0
    run_git(&["tag", "-d", "v0.9.0"]);
    run_git(&["tag", "v1.0.0-rc.1"]);

    // On "stable", no stable candidate exists -> MUST RETURN Err (never fall back to prerelease!)
    let res_no_stable = detect_latest_git_tag_for_channel(repo_url, "", "stable").await;
    assert!(
        res_no_stable.is_err(),
        "Expected Err when only prerelease tags exist on stable channel"
    );
    let err_msg = res_no_stable.unwrap_err().to_string();
    assert!(
        err_msg.contains("No stable release tags found"),
        "actual error: {err_msg}"
    );

    // On "rc" or "beta", selects v1.0.0-rc.1
    let res_rc = detect_latest_git_tag_for_channel(repo_url, "", "rc").await;
    assert!(res_rc.is_ok());
    assert_eq!(res_rc.unwrap().0, "1.0.0-rc.1");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_rate_limit_body_only_403_activates_cooldown() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    clear_github_rate_limits();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let req_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let req_count_srv = req_count.clone();

    let server = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            req_count_srv.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut buf = vec![0; 2048];
            let _ = socket.read(&mut buf).await;
            let body = r#"{"message": "API rate limit exceeded for 203.0.113.1."}"#;
            let resp = format!(
                "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let repo = "owner/rate-limited-repo";

    // First call receives 403 with rate limit body and NO rate-limit headers
    let res1 = detect_latest_github_release(&client, &origin, repo).await;
    assert!(res1.is_err());
    let err1 = res1.unwrap_err().to_string();
    assert!(
        err1.contains("rate limit"),
        "expected rate limit error, got: {err1}"
    );
    assert_eq!(req_count.load(std::sync::atomic::Ordering::SeqCst), 1);

    // Cooldown must be recorded across both "releases" and "core"/"default"
    assert!(is_github_rate_limited_for_origin(&origin, "releases"));
    assert!(is_github_api_rate_limited(&origin, "core"));
    assert!(is_github_api_rate_limited(&origin, "default"));

    // Second consecutive release discovery request must be SUPPRESSED without hitting the mock server
    let res2 = detect_latest_github_release(&client, &origin, repo).await;
    assert!(res2.is_err());
    let err2 = res2.unwrap_err().to_string();
    assert!(
        err2.contains("rate limit backoff active"),
        "expected backoff error, got: {err2}"
    );
    assert_eq!(
        req_count.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "Second request must be suppressed and not hit the server!"
    );

    server.abort();
    clear_github_rate_limits();
}

#[test]
fn test_dpkg_differential_ordering() {
    use std::cmp::Ordering::{Equal, Greater, Less};
    let pairs = [
        ("1.0", "1.0.0", Less),
        ("1.0.0", "1.0", Greater),
        ("1.0.0-rc1", "1.0.0", Greater),
        ("1.0.0", "1.0.0-rc1", Less),
        ("1.0.0~rc1", "1.0.0", Less),
        ("1.0.0", "1.0.0~rc1", Greater),
        ("1.0.0+git1", "1.0.0", Greater),
        ("1.0.0", "1.0.0+git1", Less),
        ("1.0.0+b1", "1.0.0", Greater),
        ("1.0.0", "1.0.0+b1", Less),
        ("1:1.0", "2.0", Greater),
        ("2.0", "1:1.0", Less),
        ("1.0-1", "1.0-2", Less),
        ("1.0-2", "1.0-1", Greater),
        ("1.0~beta1~svn1245", "1.0~beta1", Less),
        ("1.0~beta1", "1.0~beta1~svn1245", Greater),
        ("1.0a", "1.0+a", Less),
        ("1.0+a", "1.0a", Greater),
        ("1.0.0+deb11u1", "1.0.0+deb11u2", Less),
        ("1.2.3-1ubuntu1", "1.2.3-2ubuntu1", Less),
        ("0.4.17", "0.4.18.2805", Less),
        ("0.4.18.2805", "0.4.18.2805", Equal),
        ("2:1.0.0", "2:1.0.0", Equal),
        ("1.0.0-1", "1.0.0-1", Equal),
        ("1.0~rc1", "1.0~rc2", Less),
        ("1.0+debug", "1.0", Greater),
        ("1.0-0", "1.0", Equal),
        ("1.0", "1.0-0", Equal),
    ];

    let dpkg_available = std::process::Command::new("dpkg")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let run_dpkg = |v1: &str, v2: &str| -> std::cmp::Ordering {
        let eq = std::process::Command::new("dpkg")
            .args(["--compare-versions", v1, "eq", v2])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if eq {
            return std::cmp::Ordering::Equal;
        }
        let lt = std::process::Command::new("dpkg")
            .args(["--compare-versions", v1, "lt", v2])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if lt {
            return std::cmp::Ordering::Less;
        }
        std::cmp::Ordering::Greater
    };

    for (v1, v2, expected_policy) in pairs {
        let actual = compare_debian_versions_str(v1, v2);
        assert_eq!(
            actual, expected_policy,
            "Debian Policy 5.6.12 mismatch for '{v1}' vs '{v2}': actual={actual:?}, expected={expected_policy:?}"
        );
        if dpkg_available {
            let expected_dpkg = run_dpkg(v1, v2);
            assert_eq!(
                actual, expected_dpkg,
                "Debian dpkg differential mismatch for '{v1}' vs '{v2}': actual={actual:?}, expected(dpkg)={expected_dpkg:?}"
            );
        }
    }
}

#[tokio::test]
async fn test_readarr_failed_installed_probe_preserves_error_and_rejects_admission() {
    use crate::inventory_regressions::{isolated, Fixture};
    if !isolated(
        "workers::tests::provenance_and_channels::test_readarr_failed_installed_probe_preserves_error_and_rejects_admission",
    ) {
        return;
    }
    let _fixture = Fixture::new();
    af_db::init_db().unwrap();
    ensure_app_updates_columns();

    // Seed previous DB record with installed_version = "0.4.17.0"
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO app_updates (package_name, installed_version, latest_version, update_available, update_url, checked_at, last_error, source_key)
             VALUES ('readarr', '0.4.17.0', '0.4.18.2805', 1, '', '2026-11-01T00:00:00Z', '', 'retired:readarr|stable')",
            [],
        ).unwrap();
    }

    let client = build_github_http_client();
    let pkg = Package {
        name: "readarr".into(),
        update_source: "retired".into(),
        // A version_command that fails:
        version_command: vec!["/bin/false".into()],
        ..Default::default()
    };

    let (rec, _notify) = probe_package_update(&client, "https://api.github.com", &pkg).await;

    // Verify last_error / error uses only the fixed safe public summary without raw probe output
    assert_eq!(
        rec.error, "Installed version could not be confirmed",
        "Expected fixed safe installed check failure in error, got: {}",
        rec.error
    );
    assert!(
        !rec.error
            .to_ascii_lowercase()
            .contains("installed version check failed"),
        "Raw installed probe prefix must not leak in error: {}",
        rec.error
    );

    // Crucial requirement: update_available MUST BE FALSE when installed probe fails!
    assert!(
        !rec.update_available,
        "Failed installed probe must NOT allow update_available = true!"
    );

    // Also check DB persisted state:
    let conn = af_db::get_conn().unwrap();
    let (db_avail, db_err): (bool, Option<String>) = conn
        .query_row(
            "SELECT update_available, last_error FROM app_updates WHERE package_name = 'readarr'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert!(!db_avail);
    let db_err_text = db_err.unwrap_or_default();
    assert_eq!(
        db_err_text, "Installed version could not be confirmed",
        "Database last_error must record the fixed safe failure summary"
    );
}

#[test]
fn test_rclone_declarative_discovery_uses_github_source_and_preserves_build_metadata() {
    let pkg = Package {
        name: "rclone".into(),
        update_source: "github".into(),
        update_repo: "rclone/rclone".into(),
        version_command: vec!["rclone".into(), "--version".into()],
        ..Default::default()
    };

    // 1. canonical_update_source_key with DeclarativeRust engine must NOT map to APT
    let (eff_src, _) = effective_update_source_and_apt_package(&pkg);
    assert_eq!(eff_src, "github");

    let key = canonical_update_source_key("https://api.github.com", &pkg);
    assert_eq!(key, "github:https://api.github.com|rclone/rclone|stable");
    assert!(!key.contains("apt:"));

    // 2. extract_version preserves +debug, +git1-1, etc.
    assert_eq!(extract_version("rclone v1.75.2", ""), "1.75.2");
    assert_eq!(extract_version("v1.0.0+debug", ""), "1.0.0+debug");
    assert_eq!(extract_version("release-v1.0.0+git1-1", ""), "1.0.0+git1-1");
    assert_eq!(extract_version("1.0.0+b1", ""), "1.0.0+b1");

    // 3. Exact source key requirement rejects keys missing |<channel>
    let legacy_key = "github:https://api.github.com|rclone/rclone";
    let prev_record = PackageUpdateRecord {
        package_id: "rclone".to_string(),
        installed: true,
        installed_version: "1.74.0".to_string(),
        latest_version: "1.75.2".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "".to_string(),
        error: "".to_string(),
        source_key: legacy_key.to_string(),
    };

    let rec = build_package_update_record_for_source(
        "https://api.github.com",
        "github",
        "rclone/rclone",
        true,
        Ok("1.74.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&prev_record),
        "2026-11-08T00:00:00Z".to_string(),
        &key,
    );
    // Because legacy_key is missing "|stable", exact equality fails and legacy record is rejected!
    assert_eq!(rec.latest_version, "");
    assert_eq!(rec.checked_at, "");
    assert!(!rec.update_available);
}

#[test]
fn test_github_and_github_release_synonyms_and_source_key_normalization() {
    let pkg_github = Package {
        name: "rclone".into(),
        update_source: "github".into(),
        update_repo: "rclone/rclone".into(),
        update_channel: "stable".into(),
        version_command: vec!["rclone".into(), "--version".into()],
        ..Default::default()
    };
    let pkg_github_release = Package {
        name: "rclone".into(),
        update_source: "github_release".into(),
        update_repo: "rclone/rclone".into(),
        update_channel: "stable".into(),
        version_command: vec!["rclone".into(), "--version".into()],
        ..Default::default()
    };

    let key1 = canonical_update_source_key("https://api.github.com", &pkg_github);
    let key2 = canonical_update_source_key("https://api.github.com", &pkg_github_release);
    assert_eq!(key1, "github:https://api.github.com|rclone/rclone|stable");
    assert_eq!(key1, key2);

    let (src1, _) = effective_update_source_and_apt_package(&pkg_github);
    let (src2, _) = effective_update_source_and_apt_package(&pkg_github_release);
    assert_eq!(src1, "github");
    assert_eq!(src2, "github");

    assert!(should_track_package(&pkg_github));
    assert!(should_track_package(&pkg_github_release));
}

#[test]
fn test_recompute_update_available_from_fresh_installed_observation_on_upstream_failure() {
    let prev = PackageUpdateRecord {
        package_id: "testpkg".to_string(),
        installed: true,
        installed_version: "1.0.0".to_string(),
        latest_version: "2.0.0".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "https://github.com/example/testpkg/releases/tag/v2.0.0".to_string(),
        error: String::new(),
        source_key: "github:https://api.github.com|example/testpkg|stable".to_string(),
    };

    let key = "github:https://api.github.com|example/testpkg|stable";

    // Case a: Package upgraded to 2.0.0; upstream fails -> latest_version retained as 2.0.0, update_available recomputed to false!
    let rec_upgraded = build_package_update_record_for_source(
        "https://api.github.com",
        "github",
        "testpkg",
        true,
        Ok("2.0.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&prev),
        "2026-11-08T12:00:00Z".to_string(),
        key,
    );
    assert_eq!(rec_upgraded.latest_version, "2.0.0");
    assert_eq!(rec_upgraded.installed_version, "2.0.0");
    assert!(!rec_upgraded.update_available);
    assert_eq!(rec_upgraded.checked_at, "2026-11-01T00:00:00Z");

    // Case b: Package at 1.5.0; upstream fails -> latest_version retained as 2.0.0, update_available recomputed to true!
    let rec_intermediate = build_package_update_record_for_source(
        "https://api.github.com",
        "github",
        "testpkg",
        true,
        Ok("1.5.0".to_string()),
        Err(anyhow::anyhow!("network unreachable")),
        Some(&prev),
        "2026-11-08T12:00:00Z".to_string(),
        key,
    );
    assert_eq!(rec_intermediate.latest_version, "2.0.0");
    assert_eq!(rec_intermediate.installed_version, "1.5.0");
    assert!(rec_intermediate.update_available);
    assert_eq!(rec_intermediate.checked_at, "2026-11-01T00:00:00Z");
}

#[test]
fn test_explicit_trusted_origin_policy_for_custom_github_enterprise() {
    // 1. Configured GHE origin matches request URL
    assert!(should_attach_github_token(
        "https://ghe.internal.example/api/v3/repos/rclone/rclone/releases/latest",
        "https://ghe.internal.example/api/v3"
    ));

    // 2. Reject untrusted third-party registries even if configured as base
    assert!(!should_attach_github_token(
        "https://pypi.org/pypi/foo/json",
        "https://ghe.internal.example/api/v3"
    ));
    assert!(!should_attach_github_token(
        "https://pypi.org/pypi/foo/json",
        "https://pypi.org"
    ));
    assert!(!should_attach_github_token(
        "https://crates.io/api/v1/crates/foo",
        "https://crates.io"
    ));

    // 3. Reject plain http:// on non-loopback hosts
    assert!(!should_attach_github_token(
        "http://ghe.internal.example/api/v3/repos/a/b",
        "http://ghe.internal.example/api/v3"
    ));

    // 4. Loopback http is permitted
    assert!(should_attach_github_token(
        "http://127.0.0.1:8080/api/v3/repos/a/b",
        "http://127.0.0.1:8080"
    ));
    assert!(should_attach_github_token(
        "http://localhost:9090/repos/a/b",
        "http://localhost:9090"
    ));

    // 5. AF_TRUSTED_GITHUB_ORIGINS environment variable
    std::env::set_var(
        "AF_TRUSTED_GITHUB_ORIGINS",
        "https://extra-ghe.corp.local, https://custom.github.net",
    );
    assert!(should_attach_github_token(
        "https://extra-ghe.corp.local/api/v3/repos/a/b",
        "https://api.github.com"
    ));
    assert!(should_attach_github_token(
        "https://custom.github.net/repos/a/b",
        "https://api.github.com"
    ));
    assert!(!should_attach_github_token(
        "https://untrusted.corp.local/api/v3/repos/a/b",
        "https://api.github.com"
    ));
    std::env::remove_var("AF_TRUSTED_GITHUB_ORIGINS");
}

#[test]
fn test_exact_default_https_port_for_builtin_github_origins() {
    assert!(!should_attach_github_token(
        "https://api.github.com:8443/repos/a/b",
        "https://api.github.com"
    ));
    assert!(should_attach_github_token(
        "https://api.github.com:443/repos/a/b",
        "https://api.github.com"
    ));
    assert!(should_attach_github_token(
        "https://api.github.com:8443/repos/a/b",
        "https://api.github.com:8443"
    ));
}

#[test]
fn test_do_not_collapse_consecutive_hyphens_in_build_metadata() {
    let v1 = extract_version("1.0.0+build--old", "");
    let v2 = extract_version("1.0.0+build--new", "");
    assert_eq!(v1, "1.0.0+build--old");
    assert_eq!(v2, "1.0.0+build--new");
    assert_ne!(v1, v2);
    assert_eq!(
        extract_version_from_text("1.0.0+build--old"),
        "1.0.0+build--old"
    );
    assert_eq!(
        extract_version_from_text("1.0.0+build--new"),
        "1.0.0+build--new"
    );
    assert!(!af_release::lifecycle::versions_match_target(
        "1.0.0+build--old",
        "1.0.0+build--new"
    ));
    assert!(!versions_match_target_internal(
        "1.0.0+build--old",
        "1.0.0+build--new"
    ));
}

#[tokio::test]
async fn test_rclone_update_probe_ignores_unowned_executables() {
    use std::os::unix::fs::PermissionsExt;

    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let root = std::env::temp_dir().join(format!("af-test-rclone-probe-{}", uuid::Uuid::new_v4()));
    let distro = root.join("usr/bin/rclone");
    let managed = root.join("opt/AetherFlow/apps/rclone/rclone");
    for (path, version) in [(&distro, "1.50.0"), (&managed, "1.75.2")] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, format!("#!/bin/sh\necho 'rclone v{version}'\n")).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let previous_root = std::env::var_os("AETHERFLOW_FS_ROOT");
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    let pkg = Package {
        name: "rclone".into(),
        update_source: "github_release".into(),
        version_command: vec![
            "/opt/AetherFlow/apps/rclone/rclone".into(),
            "version".into(),
        ],
        version_regex: r"rclone\s+v?([0-9]+\.[0-9]+\.[0-9]+[^\s]*)".into(),
        ..Default::default()
    };

    let budget = Duration::from_secs(5);
    let unowned = run_live_version_command(&pkg, budget).await;
    std::fs::write(managed.with_file_name(".af-owner"), b"rclone\n").unwrap();
    let owned = run_live_version_command(&pkg, budget).await;
    match previous_root {
        Some(path) => std::env::set_var("AETHERFLOW_FS_ROOT", path),
        None => std::env::remove_var("AETHERFLOW_FS_ROOT"),
    }
    std::fs::remove_dir_all(root).unwrap();

    assert!(unowned.is_err());
    assert_eq!(owned.unwrap(), "1.75.2");
}

#[tokio::test]
async fn test_probe_installed_package_version_strict_requires_independent_runtime_evidence() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-isolated-receipt-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/isolated-pkg");
    std::fs::create_dir_all(&opt_dir).unwrap();
    // Only .af-version exists in isolation, no lock file, no binaries, no systemd units
    std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "isolated-pkg".into(),
        // Empty version_command means no live command probe
        version_command: vec![],
        ..Default::default()
    };

    let res = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res.is_err(),
        "Expected probe_installed_package_version_strict to fail without runtime evidence"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("No independent runtime evidence found alongside .af-version receipt"),
        "Expected 'No independent runtime evidence found alongside .af-version receipt', got: {err_msg}"
    );

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_extract_version_preserves_trailing_hyphens_in_build_metadata() {
    assert_eq!(extract_version("1.0.0+build-", ""), "1.0.0+build-");
    assert_eq!(extract_version("1.0.0+build--", ""), "1.0.0+build--");
    assert_eq!(extract_version("1.0.0-rc1-", ""), "1.0.0-rc1-");
    assert_eq!(extract_version_from_text("1.0.0+build-"), "1.0.0+build-");
    assert_eq!(extract_version_from_text("1.0.0+build--"), "1.0.0+build--");
    assert!(!af_release::lifecycle::versions_match_target(
        "1.0.0+build-",
        "1.0.0+build--"
    ));
}
