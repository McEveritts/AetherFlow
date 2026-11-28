use super::*;

#[tokio::test]
async fn test_wave19_audit_findings_workers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Finding 1: detect_latest_github_release_for_channel fails closed when 10 pages exceeded
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let mut buf = vec![0; 4096];
            let _ = socket.read(&mut buf).await.unwrap_or(0);

            let mut items = Vec::new();
            for i in 1..=GITHUB_RELEASE_PAGE_SIZE {
                items.push(format!(
                    r#"{{"tag_name": "v1.0.{}", "html_url": "https://github.com/org/repo/releases/v1.0.{}", "prerelease": false, "draft": false}}"#,
                    i, i
                ));
            }
            let body = format!("[{}]", items.join(","));
            let next_link = format!("<http://{addr}/repos/test-owner/overflow-repo/releases?per_page=100&page=99>; rel=\"next\"");
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nLink: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                next_link,
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let res = detect_latest_github_release_for_channel(
        &client,
        &origin,
        "test-owner/overflow-repo",
        "stable",
    )
    .await;
    assert!(
        res.is_err(),
        "Must fail closed when release pagination exceeds MAX_RELEASE_PAGES without exhaustion"
    );
    let err_str = res.err().unwrap().to_string();
    assert!(
        err_str.contains("GitHub release pagination exceeded maximum page limit (10) for 'test-owner/overflow-repo'; refusing to cache incomplete release set"),
        "Error message mismatch: {err_str}"
    );

    let cache_key =
        github_release_cache_key_for_channel(&origin, "test-owner/overflow-repo", "stable");
    assert!(
        GITHUB_RELEASE_CACHE
            .lock()
            .unwrap()
            .get(&cache_key)
            .is_none(),
        "Incomplete release scan must not be cached"
    );
    server.abort();

    // Finding 2: sanitize_api_base_for_source_key preserves path case
    assert_eq!(
        sanitize_api_base_for_source_key("https://Git.Example.com/TeamA/api/"),
        "https://git.example.com/TeamA/api"
    );
    assert_eq!(
        sanitize_api_base_for_source_key("https://Git.Example.com/TeamA/api?token=secret#frag"),
        "https://git.example.com/TeamA/api"
    );
    // Fallback when URL parse fails preserves path case and hashes query
    let fallback_input = "invalid url ://Git.Example.com/TeamA/api?foo=bar#frag";
    assert_eq!(
        sanitize_api_base_for_source_key(fallback_input),
        format!(
            "invalid url ://git.example.com/TeamA/api?q#{}",
            sha256_hex_12(b"foo=bar")
        )
    );

    // Finding 4: sanitize_git_remote_url_for_display and normalize_git_remote_url_preserve_path_case
    assert_eq!(
        sanitize_git_remote_url_for_display("git@github.com:Org/Repo.git?token=secret#readme"),
        "ssh://git@github.com/Org/Repo.git"
    );
    assert_eq!(
        normalize_git_remote_url_preserve_path_case(
            "git@github.com:Org/Repo.git?token=secret#readme"
        ),
        format!(
            "ssh://git@github.com/Org/Repo?q#{}",
            sha256_hex_12(b"token=secret")
        )
    );

    // Finding 3: persist_package_update_record / sanitize_source_key_for_persistence preserves ssh:// and cred#...
    let canonical_ssh_key = "git-repo:ssh://Deploy@git.example.com/Team/App.git#main";
    let canonical_cred_key = "git-repo:https://cred#0123456789ab@github.com/org/repo.git#main";
    assert_eq!(
        sanitize_source_key_for_persistence(canonical_ssh_key),
        canonical_ssh_key
    );
    assert_eq!(
        sanitize_source_key_for_persistence(canonical_cred_key),
        canonical_cred_key
    );
    assert_eq!(
        af_release::lifecycle::sanitize_persisted_lifecycle_text(canonical_ssh_key),
        canonical_ssh_key
    );

    // Raw credentials in unnormalized source keys are scrubbed
    let dirty_ssh_key = "git-repo:ssh://Deploy:secretpass@git.example.com/Team/App.git#main";
    let cleaned_ssh = sanitize_source_key_for_persistence(dirty_ssh_key);
    assert!(!cleaned_ssh.contains("secretpass"));
    assert!(cleaned_ssh.contains("cred#"));

    // Test persist_package_update_record preserves canonical ssh and cred keys
    let rec = PackageUpdateRecord {
        package_id: "test-ssh-key-pkg".into(),
        source_key: canonical_ssh_key.into(),
        latest_version: "1.0.0".into(),
        installed_version: "1.0.0".into(),
        release_url: "ssh://Deploy@git.example.com/Team/App.git".into(),
        ..Default::default()
    };
    persist_package_update_record(&rec);
    if let Ok(conn) = af_db::get_conn() {
        let saved_key: String = conn
            .query_row(
                "SELECT source_key FROM app_updates WHERE package_name = ?1",
                params!["test-ssh-key-pkg"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            saved_key, canonical_ssh_key,
            "Persisted source_key must match canonical SSH key"
        );
    }

    // Finding 7: compare_versions and compare_versions_for_source with 7+ digit tags
    assert_eq!(
        compare_versions("10000000", "9000000"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_versions("v10000000", "v9000000"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_versions_for_source("10000000", "9000000", "git"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_versions_for_source("v10000000", "v9000000", "git"),
        std::cmp::Ordering::Greater
    );
    assert!(is_newer_version_scalar_for_source(
        "9000000", "10000000", "git"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "10000000", "9000000", "git"
    ));
}

#[test]
fn test_wave20_builder_b_regressions() {
    // 1. API base cache key and rate limit isolation across base paths (/TeamA/api/v3 vs /TeamB/api/v3)
    let key_a = github_release_cache_key_for_channel(
        "https://ghe.internal/TeamA/api/v3",
        "myorg/repo",
        "stable",
    );
    let key_b = github_release_cache_key_for_channel(
        "https://ghe.internal/TeamB/api/v3",
        "myorg/repo",
        "stable",
    );
    assert_ne!(
        key_a, key_b,
        "Cache keys for /TeamA/api/v3 and /TeamB/api/v3 must be distinct!"
    );
    assert!(key_a.contains("teama/api/v3") || key_a.contains("TeamA/api/v3"));
    assert!(key_b.contains("teamb/api/v3") || key_b.contains("TeamB/api/v3"));

    clear_github_rate_limits();
    let base_a = "https://ghe.internal/TeamA/api/v3";
    let base_b = "https://ghe.internal/TeamB/api/v3";
    record_github_api_rate_limit(base_a, "core", Duration::from_secs(60));
    assert!(is_github_rate_limited_for_origin(base_a, "core"));
    assert!(github_rate_limit_remaining_secs_for_origin(base_a, "core") > 0);
    assert!(!is_github_rate_limited_for_origin(base_b, "core"));
    assert_eq!(
        github_rate_limit_remaining_secs_for_origin(base_b, "core"),
        0
    );
    clear_github_rate_limits();

    // 2. Query-bearing Git source keys (?q#<12-hex>) idempotence on persistence
    let q_key_bare = "git-repo:https://github.com/org/repo.git?q#0123456789ab";
    assert_eq!(sanitize_source_key_for_persistence(q_key_bare), q_key_bare);
    let q_key_branch = "git-repo:https://github.com/org/repo.git?q#0123456789ab#main";
    assert_eq!(
        sanitize_source_key_for_persistence(q_key_branch),
        q_key_branch
    );
    // Repeated persistence calls are strictly idempotent
    assert_eq!(
        sanitize_source_key_for_persistence(&sanitize_source_key_for_persistence(q_key_branch)),
        q_key_branch
    );

    // 3. Cross-repo and off-origin pagination Link validation fail-closed behavior
    let api_base = "https://api.github.com";
    let ghe_base = "https://ghe.internal/api/v3";
    // Same repo, same origin -> allowed
    assert!(validate_github_releases_next_url(
        "https://api.github.com/repos/org/repo/releases?per_page=100&page=2",
        api_base,
        "org/repo"
    ));
    assert!(validate_github_releases_next_url(
        "https://ghe.internal/api/v3/repos/org/repo/releases?per_page=100&page=2",
        ghe_base,
        "org/repo"
    ));
    // Cross-repository -> rejected
    assert!(!validate_github_releases_next_url(
        "https://api.github.com/repos/attacker/evil/releases?per_page=100&page=2",
        api_base,
        "org/repo"
    ));
    assert!(!validate_github_releases_next_url(
        "https://ghe.internal/api/v3/repos/other/repo/releases?per_page=100&page=2",
        ghe_base,
        "org/repo"
    ));
    // Off-origin -> rejected
    assert!(!validate_github_releases_next_url(
        "https://evil.attacker.com/repos/org/repo/releases?per_page=100&page=2",
        api_base,
        "org/repo"
    ));

    // 4. Numeric short Git commit IDs recognized and distinct
    let num_sha1 = "9999999";
    let full_sha = "123456abcdef0123456789abcdef0123456789a";
    let num_sha2 = "1234567";

    // "9999999" vs "123456abcdef..." on "git"
    assert!(is_newer_version_scalar_for_source(
        num_sha1, full_sha, "git"
    ));
    assert!(is_newer_version_scalar_for_source(
        full_sha, num_sha1, "git"
    ));

    // "9999999" vs "1234567" on "git"
    assert!(is_newer_version_scalar_for_source(
        num_sha1, num_sha2, "git"
    ));
    assert!(is_newer_version_scalar_for_source(
        num_sha2, num_sha1, "git"
    ));

    // Prefix match is NOT an update
    let full_matching_9 = "9999999abcdef0123456789abcdef0123456789a";
    assert!(!is_newer_version_scalar_for_source(
        num_sha1,
        full_matching_9,
        "git"
    ));
    assert!(!is_newer_version_scalar_for_source(
        full_matching_9,
        num_sha1,
        "git"
    ));

    // Synthetic commit version rejects pure-numeric short SHA (which are SemVer prereleases)
    assert_eq!(parse_synthetic_commit_version("0.1.0-1234567"), None);
    assert_eq!(
        parse_synthetic_commit_version("0.1.0-6e840ac"),
        Some(("0.1.0", "6e840ac"))
    );
}

#[test]
fn test_wave21_builder_b_regressions() {
    // Finding 3: validate_github_releases_next_url path sensitivity
    let configured_base = "https://git.example.com/TeamA/api/v3";
    // Case mismatch on base path prefix -> rejected
    assert!(!validate_github_releases_next_url(
        "https://git.example.com/teama/api/v3/repos/owner/repo/releases?page=2",
        configured_base,
        "owner/repo"
    ));
    // Case mismatch on repo slug -> accepted (GitHub owner/repo slugs are case-insensitive)
    assert!(validate_github_releases_next_url(
        "https://git.example.com/TeamA/api/v3/repos/Owner/Repo/releases?page=2",
        configured_base,
        "owner/repo"
    ));
    assert!(validate_github_releases_next_url(
        "https://git.example.com/TeamA/api/v3/repos/owner/repo/releases?page=2",
        configured_base,
        "Owner/Repo"
    ));

    // Finding 8: Numeric SemVer prereleases
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-1234567",
        "2.0.0-1234567",
        ""
    ));
    assert!(!is_newer_version_scalar_for_source(
        "2.0.0-1234567",
        "1.0.0-1234567",
        ""
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-1234567",
        "2.0.0-1234567",
        "false"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "2.0.0-1234567",
        "1.0.0-1234567",
        "false"
    ));
    assert!(is_newer_version_scalar("1.0.0-1234567", "2.0.0-1234567"));
    assert!(!is_newer_version_scalar("2.0.0-1234567", "1.0.0-1234567"));

    // Finding 8: Synthetic commit versions comparing differing version bases
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-6e840ac",
        "2.0.0-6e840ac",
        ""
    ));
    assert!(!is_newer_version_scalar_for_source(
        "2.0.0-6e840ac",
        "1.0.0-deadbeef",
        ""
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-6e840ac",
        "2.0.0-6e840ac",
        "false"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "2.0.0-6e840ac",
        "1.0.0-deadbeef",
        "false"
    ));
    assert!(is_newer_version_scalar("1.0.0-6e840ac", "2.0.0-6e840ac"));
    assert!(!is_newer_version_scalar("2.0.0-6e840ac", "1.0.0-deadbeef"));

    // Finding 8: Same version base compares commit SHAs on git provenance
    assert!(!is_newer_version_scalar_for_source(
        "1.0.0-6e840ac",
        "1.0.0-6e840ac",
        "git"
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-6e840ac",
        "1.0.0-deadbeef",
        "git"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "1.0.0-abcdef1",
        "1.0.0-abcdef0",
        "github"
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-abcdef0",
        "1.0.0-abcdef1",
        "github"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "1.0.0-abcdef1",
        "1.0.0-abcdef0",
        ""
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-abcdef0",
        "1.0.0-abcdef1",
        ""
    ));
}

#[tokio::test]
async fn test_wave22_filebot_version_detection_and_update_check() {
    let temp_dir = std::env::temp_dir().join(format!("af-test-filebot-{}", uuid::Uuid::new_v4()));
    let opt_filebot_node = temp_dir.join("opt/filebot-node");
    let server_dir = opt_filebot_node.join("server");
    let opt_filebot = temp_dir.join("opt/filebot");

    std::fs::create_dir_all(&server_dir).unwrap();
    std::fs::create_dir_all(&opt_filebot).unwrap();

    // Node component files
    std::fs::write(server_dir.join("app.js"), "console.log('filebot-node');").unwrap();
    std::fs::write(
        server_dir.join("package.json"),
        r#"{"name":"filebot-node","version":"0.4.7.0"}"#,
    )
    .unwrap();
    std::fs::write(opt_filebot_node.join(".af-version"), "0.4.7.0").unwrap();

    // Separate CLI files in /opt/filebot with version 5.1.6
    std::fs::write(opt_filebot.join("filebot.sh"), "#!/bin/sh\nexit 0").unwrap();
    std::fs::write(opt_filebot.join(".af-version"), "5.1.6").unwrap();

    let install_dir = temp_dir.join("install");
    std::fs::create_dir_all(&install_dir).unwrap();
    std::fs::write(install_dir.join(".filebot.lock"), "").unwrap();

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "filebot".into(),
        lock_file: "/install/.filebot.lock".into(),
        update_source: "github".into(),
        update_repo: "filebot/filebot-node".into(),
        version_command: vec![
            "python3".into(),
            "-c".into(),
            "import json, os, pathlib, sys; root = pathlib.Path((os.environ.get('AETHERFLOW_FS_ROOT') or os.environ.get('AETHERFLOW_INSTALL_ROOT') or '/').strip() or '/'); base = root / 'opt/filebot-node'; sys.exit(1) if not (base / 'server/app.js').is_file() else None; vers = [json.loads(p.read_text(encoding='utf-8')).get('version', '').strip() for p in (base / 'package.json', base / 'server/package.json', base / 'client/package.json') if p.is_file()]; v = next((x for x in vers if x), ''); sys.exit(1) if not v else print(v)".into(),
        ],
        ..Default::default()
    };

    // 1. Receipt verification: must find 0.4.7.0 and NEVER 5.1.6
    let receipt = read_af_version_receipt(&pkg);
    assert_eq!(receipt, Some("0.4.7.0".to_string()));

    // 2. Runtime evidence verification: app.js satisfies runtime evidence
    assert!(has_independent_runtime_evidence(&pkg));

    // 3. Strict installed version probe detects 0.4.7.0
    let installed = probe_installed_package_version_strict(&pkg).await;
    assert!(
        installed.is_ok(),
        "Failed to probe installed version: {:?}",
        installed.err()
    );
    assert_eq!(installed.unwrap(), "0.4.7.0");

    // 4. Live version command executes python probe with active fs_root
    let live_ver = run_live_version_command(&pkg, Duration::from_secs(5)).await;
    assert!(
        live_ver.is_ok(),
        "Live version probe failed: {:?}",
        live_ver.err()
    );
    assert_eq!(live_ver.unwrap().trim(), "0.4.7.0");

    // 5. Update availability: 0.4.8.1 is newer than 0.4.7.0
    assert!(is_remote_version_newer_for_source(
        "0.4.7.0", "0.4.8.1", "github"
    ));

    // 6. Certification match for 0.4.8.1 target
    assert!(af_release::lifecycle::versions_match_target(
        "0.4.8.1", "0.4.8.1"
    ));

    // 7. Update to 0.4.8.1
    std::fs::write(
        server_dir.join("package.json"),
        r#"{"name":"filebot-node","version":"0.4.8.1"}"#,
    )
    .unwrap();
    std::fs::write(opt_filebot_node.join(".af-version"), "0.4.8.1").unwrap();

    let updated_installed = probe_installed_package_version_strict(&pkg).await.unwrap();
    assert_eq!(updated_installed, "0.4.8.1");
    assert!(!is_remote_version_newer_for_source(
        "0.4.8.1", "0.4.8.1", "github"
    ));

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave22_semver_prerelease_provenance_and_numeric() {
    // GitHub release source: SemVer ordering is enforced (downgrades are false)
    assert!(!is_newer_version_scalar_for_source(
        "1.0.0-abcdef1",
        "1.0.0-abcdef0",
        "github"
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-abcdef0",
        "1.0.0-abcdef1",
        "github"
    ));
    assert!(!is_newer_version_scalar_for_source(
        "1.0.0-abcdef1",
        "1.0.0-abcdef0",
        ""
    ));
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-abcdef0",
        "1.0.0-abcdef1",
        ""
    ));

    // Explicit git source: different commit hashes are treated as newer
    assert!(is_newer_version_scalar_for_source(
        "1.0.0-abcdef1",
        "1.0.0-abcdef0",
        "git"
    ));

    // 40-digit numeric prereleases: must not be treated as commit SHAs and must not overflow
    let num40_hi = "1.0.0-1234567890123456789012345678901234567899";
    let num40_lo = "1.0.0-1234567890123456789012345678901234567898";
    assert!(!is_newer_version_scalar_for_source(
        num40_hi, num40_lo, "github"
    ));
    assert!(is_newer_version_scalar_for_source(
        num40_lo, num40_hi, "github"
    ));
    assert!(!is_newer_version_scalar_for_source(num40_hi, num40_lo, ""));
    assert!(is_newer_version_scalar_for_source(num40_lo, num40_hi, ""));

    // 39-digit vs 40-digit numeric prereleases: numerical comparison
    let num39 = "1.0.0-999999999999999999999999999999999999999";
    let num40 = "1.0.0-1000000000000000000000000000000000000000";
    assert!(is_newer_version_scalar_for_source(num39, num40, ""));
    assert!(!is_newer_version_scalar_for_source(num40, num39, ""));

    // is_git_commit_sha matches af_release::lifecycle::is_hex_commit (40-char hex strings or >=7 chars with [a-fA-F])
    assert!(is_git_commit_sha(
        "1234567890123456789012345678901234567890"
    ));
    assert!(is_git_commit_sha(
        "123456789012345678901234567890123456789a"
    ));
    assert!(!is_git_commit_sha("1234567"));
    assert!(is_git_commit_sha("6e840ac"));

    // parse_synthetic_commit_version rejects pure numeric suffixes
    assert_eq!(
        parse_synthetic_commit_version("1.0.0-1234567890123456789012345678901234567890"),
        None
    );
    assert_eq!(parse_synthetic_commit_version("1.0.0-1234567"), None);
    assert_eq!(
        parse_synthetic_commit_version("1.0.0-6e840ac"),
        Some(("1.0.0", "6e840ac"))
    );
}

#[tokio::test]
async fn test_github_package_with_git_checkout_uses_version_command_not_git_head() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir = std::env::temp_dir().join(format!("af-test-gh-git-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/demo-gh");
    std::fs::create_dir_all(&opt_dir).unwrap();
    assert!(std::process::Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(&opt_dir)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(&opt_dir)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(&opt_dir)
        .status()
        .unwrap()
        .success());
    std::fs::write(opt_dir.join(".af-version"), "1.4.2").unwrap();
    assert!(std::process::Command::new("git")
        .args(["add", ".af-version"])
        .current_dir(&opt_dir)
        .status()
        .unwrap()
        .success());
    assert!(std::process::Command::new("git")
        .args(["commit", "-m", "init"])
        .current_dir(&opt_dir)
        .status()
        .unwrap()
        .success());

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);
    let pkg = Package {
        name: "demo-gh".into(),
        update_source: "github".into(),
        version_command: vec!["printf".into(), "%s".into(), "1.4.2".into()],
        ..Default::default()
    };
    let res = probe_installed_package_version_strict(&pkg).await.unwrap();
    assert_eq!(res, "1.4.2");

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_apt_receipt_matches_live_debian_revision() {
    assert!(apt_receipt_matches_live_debian_revision(
        "apt",
        "1.9.1",
        "1.9.1-2+deb13u1"
    ));
    assert!(apt_receipt_matches_live_debian_revision(
        "apt",
        "1.9.1",
        "1:1.9.1-1+b1"
    ));
    assert!(!apt_receipt_matches_live_debian_revision(
        "apt", "1.9.1", "1.9.2-1"
    ));
    assert!(!apt_receipt_matches_live_debian_revision(
        "apt",
        "1.9.1",
        "1.9.1-rc1"
    ));
    assert!(!apt_receipt_matches_live_debian_revision(
        "apt",
        "1.9.1",
        "1.9.1~rc1-1"
    ));
    assert!(!apt_receipt_matches_live_debian_revision(
        "github",
        "1.9.1",
        "1.9.1-2+deb13u1"
    ));
}

#[tokio::test]
async fn test_threadfin_pinned_and_pihole_vendor_discovery_do_not_query_github() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let prev_auto = std::env::var_os("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG");
    let prev_pkgs = std::env::var_os("AETHERFLOW_PACKAGES_CONFIG");
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    std::env::set_var(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        repo_root.join("config/package_automation.json"),
    );
    std::env::set_var(
        "AETHERFLOW_PACKAGES_CONFIG",
        repo_root.join("config/packages.json"),
    );
    struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
    impl Drop for Restore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", v),
                None => std::env::remove_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG"),
            }
            match self.1.take() {
                Some(v) => std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", v),
                None => std::env::remove_var("AETHERFLOW_PACKAGES_CONFIG"),
            }
        }
    }
    let _restore = Restore(prev_auto, prev_pkgs);

    let client = build_github_http_client();
    let catalog = crate::get_package_catalog().unwrap();
    let threadfin = catalog.iter().find(|p| p.name == "threadfin").unwrap();
    let pihole = catalog.iter().find(|p| p.name == "pihole").unwrap();

    assert_eq!(threadfin.update_source, "pinned");
    assert_eq!(threadfin.update_package, "1.2.37");
    assert_eq!(
        canonical_update_source_key("https://api.github.com", threadfin),
        "pinned:1.2.37|stable"
    );

    let (tf_ver, tf_url, _) = detect_latest_version(
        &client,
        "https://invalid-host-unreachable.example.com",
        threadfin,
    )
    .await
    .expect("pinned threadfin must resolve locally without hitting GitHub");
    assert_eq!(tf_ver, "1.2.37");
    assert_eq!(
        tf_url,
        "https://github.com/Threadfin/Threadfin/releases/tag/1.2.37"
    );
    assert!(is_version_newer_for_source("1.2.36", &tf_ver, "pinned"));
    assert!(!is_version_newer_for_source("1.2.37", &tf_ver, "pinned"));

    assert_eq!(pihole.update_source, "vendor");
    assert!(pihole.update_repo.is_empty());
    assert!(should_track_package(pihole));
    assert_eq!(
        canonical_update_source_key("https://api.github.com", pihole),
        "vendor:pihole|stable"
    );

    let (ph_ver, ph_url, _) = detect_latest_version(
        &client,
        "https://invalid-host-unreachable.example.com",
        pihole,
    )
    .await
    .expect("vendor-managed pihole must not query GitHub for exact FTL targets");
    assert!(ph_ver.is_empty());
    assert!(ph_url.is_empty());
    assert!(!is_version_newer_for_source("6.8", &ph_ver, "vendor"));
    assert!(!is_version_newer_for_source("6.8", "6.9", "vendor"));
}

#[tokio::test]
async fn listenarr_prerelease_channel_discovery_and_unsupported_arch_fail_early() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let prev_auto = std::env::var_os("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG");
    let prev_pkgs = std::env::var_os("AETHERFLOW_PACKAGES_CONFIG");
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    std::env::set_var(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        repo_root.join("config/package_automation.json"),
    );
    std::env::set_var(
        "AETHERFLOW_PACKAGES_CONFIG",
        repo_root.join("config/packages.json"),
    );

    struct Restore(Option<std::ffi::OsString>, Option<std::ffi::OsString>);
    impl Drop for Restore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(v) => std::env::set_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", v),
                None => std::env::remove_var("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG"),
            }
            match self.1.take() {
                Some(v) => std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", v),
                None => std::env::remove_var("AETHERFLOW_PACKAGES_CONFIG"),
            }
        }
    }
    let _restore = Restore(prev_auto, prev_pkgs);

    let catalog = crate::get_package_catalog().unwrap();
    assert_eq!(catalog.len(), 77);
    let prerelease_pkgs: Vec<&str> = catalog
        .iter()
        .filter(|p| p.update_channel.eq_ignore_ascii_case("prerelease"))
        .map(|p| p.name.as_str())
        .collect();
    assert_eq!(prerelease_pkgs, vec!["listenarr"]);

    let listenarr = catalog.iter().find(|p| p.name == "listenarr").unwrap();
    assert_eq!(listenarr.update_source, "github");
    assert_eq!(listenarr.update_repo, "Listenarrs/Listenarr");
    assert_eq!(listenarr.update_channel, "prerelease");
    assert_eq!(
        listenarr.version_command,
        vec!["cat".to_string(), "/opt/Listenarr/.af-version".to_string()]
    );
    assert_eq!(
        canonical_update_source_key("https://api.github.com", listenarr),
        "github:https://api.github.com|listenarrs/listenarr|prerelease"
    );

    let valid_sha = "sha256:98ba3e01089554f632fa55f27bba4afe2393579061ca6aea9fb71658c72d2aac";
    let releases_json = serde_json::json!([
        {
            "tag_name": "v1.11.0-canary",
            "html_url": "https://github.com/Listenarrs/Listenarr/releases/tag/v1.11.0-canary",
            "prerelease": true,
            "draft": true,
            "assets": [{
                "name": "listenarr-1.11.0-canary-linux-x64.zip",
                "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/v1.11.0-canary/listenarr-1.11.0-canary-linux-x64.zip",
                "digest": valid_sha
            }]
        },
        {
            "tag_name": "v1.10.7-canary",
            "html_url": "https://github.com/Listenarrs/Listenarr/releases/tag/v1.10.7-canary",
            "prerelease": true,
            "draft": false,
            "assets": [{
                "name": "listenarr-1.10.7-canary-win-x64.zip",
                "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.7-canary/listenarr-1.10.7-canary-win-x64.zip",
                "digest": valid_sha
            }]
        },
        {
            "tag_name": "v1.10.5-canary",
            "html_url": "https://github.com/Listenarrs/Listenarr/releases/tag/v1.10.5-canary",
            "prerelease": true,
            "draft": false,
            "assets": [{
                "name": "listenarr-1.10.5-canary-linux-x64.zip",
                "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.5-canary/listenarr-1.10.5-canary-linux-x64.zip",
                "digest": valid_sha
            }]
        },
        {
            "tag_name": "v1.10.6-canary",
            "html_url": "https://github.com/Listenarrs/Listenarr/releases/tag/v1.10.6-canary",
            "prerelease": true,
            "draft": false,
            "assets": [{
                "name": "listenarr-1.10.6-canary-linux-x64.zip",
                "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.6-canary/listenarr-1.10.6-canary-linux-x64.zip",
                "digest": valid_sha
            }]
        },
        {
            "tag_name": "0.2.71",
            "html_url": "https://github.com/Listenarrs/Listenarr/releases/tag/0.2.71",
            "prerelease": true,
            "draft": false,
            "assets": [{
                "name": "listenarr-0.2.71-linux-x64.zip",
                "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/0.2.71/listenarr-0.2.71-linux-x64.zip",
                "digest": valid_sha
            }]
        }
    ])
    .to_string();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let body_clone = releases_json.clone();
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = vec![0; 4096];
                let _ = socket.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_clone.len(),
                    body_clone
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            }
        }
    });

    let client = build_github_http_client();
    let api_base = format!("http://{addr}");

    // 1. Listenarr on x86_64 selects highest official Linux x64 prerelease, skipping draft & non-x64
    let (latest_ver, latest_url, _) = detect_latest_listenarr_release_for_arch(
        &client,
        &api_base,
        "Listenarrs/Listenarr",
        "prerelease",
        "x86_64",
    )
    .await
    .expect("listenarr x86_64 prerelease discovery must succeed");
    assert_eq!(latest_ver, "1.10.6-canary");
    assert_eq!(
        latest_url,
        "https://github.com/Listenarrs/Listenarr/releases/tag/v1.10.6-canary"
    );
    assert!(is_version_newer_for_source(
        "1.10.5-canary",
        &latest_ver,
        "github"
    ));
    assert!(is_version_newer_for_source("0.2.71", &latest_ver, "github"));
    assert!(is_version_newer_for_source(&latest_ver, "1.10.6", "github"));
    assert!(!is_version_newer_for_source(
        "1.10.6-canary",
        &latest_ver,
        "github"
    ));

    // 2. Stable-channel packages still reject prerelease-only feeds
    let stable_err = detect_latest_github_release_for_channel(
        &client,
        &api_base,
        "Listenarrs/Listenarr",
        "stable",
    )
    .await
    .unwrap_err();
    assert!(
        stable_err
            .to_string()
            .contains("No eligible GitHub release"),
        "{stable_err}"
    );

    // 3. ARM64 fails early BEFORE cache/network access (even against unreachable port 1)
    let arm64_err = detect_latest_listenarr_release_for_arch(
        &client,
        "http://127.0.0.1:1",
        "Listenarrs/Listenarr",
        "prerelease",
        "aarch64",
    )
    .await
    .unwrap_err();
    assert!(
        arm64_err.to_string().contains("arm64") && arm64_err.to_string().contains("Linux x64"),
        "{arm64_err}"
    );

    // 4. Feed with zero linux-x64.zip assets returns an actionable error
    let no_x64_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let no_x64_addr = no_x64_listener.local_addr().unwrap();
    let no_x64_body = serde_json::json!([{
        "tag_name": "v1.10.7-canary",
        "html_url": "https://github.com/Listenarrs/Listenarr/releases/tag/v1.10.7-canary",
        "prerelease": true,
        "draft": false,
        "assets": [{
            "name": "listenarr-1.10.7-canary-osx-arm64.zip",
            "browser_download_url": "https://github.com/Listenarrs/Listenarr/releases/download/v1.10.7-canary/listenarr-1.10.7-canary-osx-arm64.zip",
            "digest": valid_sha
        }]
    }])
    .to_string();
    let no_x64_server = tokio::spawn(async move {
        if let Ok((mut socket, _)) = no_x64_listener.accept().await {
            let mut buf = vec![0; 4096];
            let _ = socket.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                no_x64_body.len(),
                no_x64_body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });
    let no_x64_err = detect_latest_listenarr_release_for_arch(
        &client,
        &format!("http://{no_x64_addr}"),
        "Listenarrs/Listenarr",
        "prerelease",
        "x86_64",
    )
    .await
    .unwrap_err();
    assert!(
        no_x64_err.to_string().contains("linux-x64.zip"),
        "{no_x64_err}"
    );

    server.abort();
    no_x64_server.abort();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_run_live_version_command_apt_preserves_full_debian_revision_and_rejects_config_files()
{
    use crate::inventory_regressions::{isolated, Fixture};
    let name = "workers::tests::wave_regressions::test_run_live_version_command_apt_preserves_full_debian_revision_and_rejects_config_files";
    if !isolated(name) {
        return;
    }

    let fixture = Fixture::new();
    fixture.command(
        "dpkg-query",
        r#"#!/bin/sh
pkg=""
for a in "$@"; do pkg="$a"; done
case "$pkg" in
    transmission-daemon) echo "installed 4.0.6+dfsg-3+deb13u1" ;;
    jellyfin) echo "config-files 10.10.3+deb12" ;;
    *) exit 1 ;;
esac
"#,
    );

    let mut tx_json = Fixture::package("transmission", "systemd", "transmission-daemon");
    tx_json["update_source"] = serde_json::json!("apt");
    tx_json["update_package"] = serde_json::json!("transmission-daemon");
    let tx_pkg: Package = serde_json::from_value(tx_json).unwrap();
    let live_ver = run_live_version_command(&tx_pkg, Duration::from_secs(5))
        .await
        .expect("installed APT package must return full Debian revision");
    assert_eq!(live_ver, "4.0.6+dfsg-3+deb13u1");

    let mut jf_json = Fixture::package("jellyfin", "systemd", "jellyfin");
    jf_json["update_source"] = serde_json::json!("apt");
    jf_json["update_package"] = serde_json::json!("jellyfin");
    let jf_pkg: Package = serde_json::from_value(jf_json).unwrap();
    let err = run_live_version_command(&jf_pkg, Duration::from_secs(5))
        .await
        .expect_err("config-files dpkg status must be rejected");
    assert!(
        err.to_string().contains("not in installed dpkg state"),
        "unexpected error: {err}"
    );
}
