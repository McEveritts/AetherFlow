use super::*;

#[tokio::test]
async fn test_github_release_discovery_rejects_prerelease_on_stable_channel() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = vec![0; 2048];
        let _ = socket.read(&mut buf).await.unwrap();
        // Upstream GitHub returns a release marked with tag "v2.0.0-rc1"
        let body = r#"{"tag_name":"v2.0.0-rc1","html_url":"http://mock/release/v2.0.0-rc1","prerelease":false}"#;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        socket.write_all(resp.as_bytes()).await.unwrap();
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let repo = "owner/prerelease-repo";

    // 1. Stable channel discovery must reject "v2.0.0-rc1"
    let res = detect_latest_github_release_for_channel(&client, &origin, repo, "stable").await;
    assert!(
        res.is_err(),
        "Stable channel must reject prerelease tag: {:?}",
        res
    );
    server.await.unwrap();

    // 2. Must NOT store under "stable" cache
    let stable_key = github_release_cache_key_for_channel(&origin, repo, "stable");
    let cached = github_release_cache().get(&stable_key).cloned();
    assert!(
        cached.is_none(),
        "Stable cache must not contain rejected prerelease: {:?}",
        cached
    );

    // 3. Stale cache fallback for stable channel must return None even if prerelease is in cache
    {
        let mut cache = github_release_cache();
        cache.insert(
            stable_key.clone(),
            (
                "2.0.0-rc1".to_string(),
                "http://mock/url".to_string(),
                Instant::now() - Duration::from_secs(3600),
                "2026-11-08T00:00:00Z".to_string(),
            ),
        );
    }
    assert_eq!(
        get_cached_github_release_stale_for_channel(&origin, repo, "stable"),
        None
    );

    // 4. Fresh cache lookup via detect_latest_github_release_for_channel must also reject cached 2.0.0-rc1
    let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr2 = listener2.local_addr().unwrap();
    let origin2 = format!("http://{addr2}");
    let stable_key2 = github_release_cache_key_for_channel(&origin2, repo, "stable");
    {
        let mut cache = github_release_cache();
        cache.insert(
            stable_key2.clone(),
            (
                "2.0.0-rc1".to_string(),
                "http://mock/url".to_string(),
                Instant::now(),
                "2026-11-08T00:00:00Z".to_string(),
            ),
        );
    }
    let res_cached =
        detect_latest_github_release_for_channel(&client, &origin2, repo, "stable").await;
    assert!(res_cached.is_err());
}

#[tokio::test]
async fn test_mixed_case_stable_rejects_prerelease_and_does_not_pollute_cache() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 2048];
            let _ = socket.read(&mut buf).await.unwrap();
            let body = r#"{"tag_name":"v1.2.3","html_url":"http://mock/release/v1.2.3","prerelease":true}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(resp.as_bytes()).await.unwrap();
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let repo = "owner/mixedcase-stable-repo";

    let res_mixed =
        detect_latest_github_release_for_channel(&client, &origin, repo, "Stable").await;
    assert!(
        res_mixed.is_err(),
        "Stable channel (mixed-case) must reject prerelease:true: {:?}",
        res_mixed
    );

    let res_upper =
        detect_latest_github_release_for_channel(&client, &origin, repo, "STABLE").await;
    assert!(
        res_upper.is_err(),
        "STABLE channel (upper-case) must reject prerelease:true: {:?}",
        res_upper
    );

    server.await.unwrap();

    let stable_key = github_release_cache_key_for_channel(&origin, repo, "stable");
    let cached = github_release_cache().get(&stable_key).cloned();
    assert!(
        cached.is_none(),
        "Stable cache must not contain rejected prerelease: {:?}",
        cached
    );
}

#[test]
fn test_extract_version_preserves_hyphen_only_identifiers() {
    assert_eq!(extract_version("1.0.0--", ""), "1.0.0--");
    assert_eq!(extract_version("1.0.0+--", ""), "1.0.0+--");
    assert_eq!(extract_version("1.0.0+-", ""), "1.0.0+-");
    assert_eq!(extract_version("1.0.0+build-", ""), "1.0.0+build-");
    assert_eq!(extract_version("1.0.0+build--", ""), "1.0.0+build--");
    assert_eq!(extract_version("1.0.0-rc1-", ""), "1.0.0-rc1-");

    assert_eq!(extract_version("1.0.0-", ""), "1.0.0");
    assert_eq!(extract_version("1.0.0+", ""), "1.0.0");
}

#[tokio::test]
async fn test_runtime_evidence_rejects_non_runtime_and_receipt_rejects_symlink_fifo() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-runtime-evidence-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/evidence-pkg");
    std::fs::create_dir_all(&opt_dir).unwrap();

    let version_file = opt_dir.join(".af-version");
    std::fs::write(&version_file, "1.2.3").unwrap();
    std::fs::write(opt_dir.join("install.log"), "Installation finished").unwrap();
    std::fs::write(opt_dir.join("anything.lock"), "lock data").unwrap();

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "evidence-pkg".into(),
        version_command: vec![],
        ..Default::default()
    };

    let res = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res.is_err(),
        "Expected failure without executable runtime files"
    );
    assert!(
        res.unwrap_err()
            .to_string()
            .contains("No independent runtime evidence found"),
        "Should reject non-runtime files as evidence"
    );

    use std::os::unix::fs::PermissionsExt;
    let non_exec_bin = opt_dir.join("non_exec_binary");
    std::fs::write(&non_exec_bin, "#!/bin/sh\necho hi\n").unwrap();
    std::fs::set_permissions(&non_exec_bin, std::fs::Permissions::from_mode(0o644)).unwrap();

    let res2 = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res2.is_err(),
        "Expected failure when binary is not executable (0o644)"
    );

    let symlink_receipt = opt_dir.join("symlink_receipt");
    std::os::unix::fs::symlink(&version_file, &symlink_receipt).unwrap();
    let sym_res = read_receipt_bounded_nofollow(&symlink_receipt);
    assert!(
        sym_res.is_err(),
        "read_receipt_bounded_nofollow must reject symlinks: {:?}",
        sym_res
    );

    let fifo_receipt = opt_dir.join("fifo_receipt");
    let c_fifo = std::ffi::CString::new(fifo_receipt.to_str().unwrap()).unwrap();
    let mkfifo_ret = unsafe { af_release::lifecycle::libc::mkfifo(c_fifo.as_ptr(), 0o644) };
    assert_eq!(mkfifo_ret, 0, "mkfifo failed");
    let fifo_res = read_receipt_bounded_nofollow(&fifo_receipt);
    assert!(
        fifo_res.is_err(),
        "read_receipt_bounded_nofollow must reject FIFOs: {:?}",
        fifo_res
    );

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_stale_or_empty_service_unit_file_rejected_as_runtime_evidence() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-stale-unit-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/stale-service-pkg");
    let systemd_dir = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&opt_dir).unwrap();
    std::fs::create_dir_all(&systemd_dir).unwrap();

    let version_file = opt_dir.join(".af-version");
    std::fs::write(&version_file, "1.2.3").unwrap();

    let service_file = systemd_dir.join("stale-service-pkg.service");

    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "stale-service-pkg".into(),
        lock_file: "/opt/stale-service-pkg/.af-version".into(),
        version_command: vec![],
        ..Default::default()
    };

    // 1. Empty .service file must be rejected
    std::fs::write(&service_file, "").unwrap();
    let res_empty = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_empty.is_err(),
        "Empty .service file must NOT certify runtime"
    );
    let err_msg = res_empty.unwrap_err().to_string();
    assert!(
        err_msg.contains("No independent runtime evidence found"),
        "Expected 'No independent runtime evidence found', got: {err_msg}"
    );

    // 2. .service file with no ExecStart= must be rejected
    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Stale Service\n[Service]\nRestart=always\n",
    )
    .unwrap();
    let res_no_exec = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_no_exec.is_err(),
        ".service with no ExecStart= must NOT certify runtime"
    );

    // 3. .service file with ExecStart= pointing to nonexistent binary must be rejected
    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Stale Service\n[Service]\nExecStart=/usr/local/bin/nonexistent_bin_xyz --flag\n",
    )
    .unwrap();
    let res_nonexistent = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_nonexistent.is_err(),
        ".service with nonexistent binary must NOT certify runtime"
    );

    // 4. .service file with ExecStart= pointing to a non-executable file (0o644) must be rejected
    use std::os::unix::fs::PermissionsExt;
    let non_exec_script = opt_dir.join("daemon.sh");
    std::fs::write(&non_exec_script, "#!/bin/sh\necho running\n").unwrap();
    std::fs::set_permissions(&non_exec_script, std::fs::Permissions::from_mode(0o644)).unwrap();

    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Stale Service\n[Service]\nExecStart=-/opt/stale-service-pkg/daemon.sh\n",
    )
    .unwrap();
    let res_non_exec = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_non_exec.is_err(),
        ".service with non-executable binary must NOT certify runtime"
    );

    // 5. Positive control: when binary becomes executable (0o755), runtime evidence is certified
    std::fs::set_permissions(&non_exec_script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let res_valid = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_valid.is_ok(),
        "Valid executable in ExecStart= should satisfy runtime evidence: {:?}",
        res_valid.err()
    );
    assert_eq!(res_valid.unwrap(), "1.2.3");

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_github_release_discovery_for_prerelease_and_stable_channels() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);

                let (status, body) = if req.contains("/releases/latest") {
                    (
                        "200 OK",
                        r#"{"tag_name":"v1.9.0","html_url":"http://mock/release/v1.9.0","prerelease":false,"draft":false}"#.to_string(),
                    )
                } else if req.contains("/releases?per_page=100") {
                    (
                        "200 OK",
                        r#"[
                            {"tag_name":"v3.0.0-draft","html_url":"http://mock/release/v3.0.0-draft","prerelease":true,"draft":true},
                            {"tag_name":"v2.0.0-beta.1","html_url":"http://mock/release/v2.0.0-beta.1","prerelease":true,"draft":false},
                            {"tag_name":"v1.9.0","html_url":"http://mock/release/v1.9.0","prerelease":false,"draft":false}
                        ]"#.to_string(),
                    )
                } else {
                    ("404 Not Found", r#"{"message":"Not Found"}"#.to_string())
                };

                let resp = format!(
                    "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = socket.write_all(resp.as_bytes()).await;
            });
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let repo = "owner/prerelease-discovery-repo";

    // 1. Beta channel queries /releases?per_page=100, skips draft v3.0.0-draft, discovers v2.0.0-beta.1 over v1.9.0
    let res_beta = detect_latest_github_release_for_channel(&client, &origin, repo, "beta").await;
    assert!(
        res_beta.is_ok(),
        "Beta channel discovery failed: {:?}",
        res_beta.err()
    );
    let (ver_beta, url_beta, _) = res_beta.unwrap();
    assert_eq!(ver_beta, "2.0.0-beta.1");
    assert_eq!(url_beta, "http://mock/release/v2.0.0-beta.1");

    // 2. Nightly channel queries /releases?per_page=100, skips draft, discovers v2.0.0-beta.1 over v1.9.0
    let repo_nightly = "owner/prerelease-discovery-nightly";
    let res_nightly =
        detect_latest_github_release_for_channel(&client, &origin, repo_nightly, "nightly").await;
    assert!(
        res_nightly.is_ok(),
        "Nightly channel discovery failed: {:?}",
        res_nightly.err()
    );
    let (ver_nightly, url_nightly, _) = res_nightly.unwrap();
    assert_eq!(ver_nightly, "2.0.0-beta.1");
    assert_eq!(url_nightly, "http://mock/release/v2.0.0-beta.1");

    // 3. Stable channel queries /releases/latest and selects v1.9.0
    let repo_stable = "owner/prerelease-discovery-stable";
    let res_stable =
        detect_latest_github_release_for_channel(&client, &origin, repo_stable, "stable").await;
    assert!(
        res_stable.is_ok(),
        "Stable channel discovery failed: {:?}",
        res_stable.err()
    );
    let (ver_stable, url_stable, _) = res_stable.unwrap();
    assert_eq!(ver_stable, "1.9.0");
    assert_eq!(url_stable, "http://mock/release/v1.9.0");

    server.abort();
}

#[tokio::test]
async fn test_git_head_cache_isolation_by_remote_url() {
    let repo = "org/app";
    let remote_a = "https://git.provider-a.com/org/app.git";
    let remote_b = "https://git.provider-b.com/org/app.git";

    let key_a = git_head_cache_key(remote_a, repo);
    let key_b = git_head_cache_key(remote_b, repo);
    assert_ne!(
        key_a, key_b,
        "Cache keys must be isolated across different remote URLs"
    );

    let sha_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let sha_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let now = Instant::now();
    let ts = "2026-11-09T00:00:00Z".to_string();

    {
        let mut cache = GIT_REMOTE_HEAD_CACHE.lock().unwrap();
        cache.insert(
            key_a.clone(),
            (
                sha_a.to_string(),
                "http://remote-a/commit".to_string(),
                now,
                ts.clone(),
            ),
        );
        cache.insert(
            key_b.clone(),
            (
                sha_b.to_string(),
                "http://remote-b/commit".to_string(),
                now,
                ts.clone(),
            ),
        );
    }

    let cached_a = GIT_REMOTE_HEAD_CACHE.lock().unwrap().get(&key_a).cloned();
    let cached_b = GIT_REMOTE_HEAD_CACHE.lock().unwrap().get(&key_b).cloned();

    assert_eq!(cached_a.unwrap().0, sha_a);
    assert_eq!(cached_b.unwrap().0, sha_b);
}

#[test]
fn test_tag_allowed_by_channel_preserves_debian_revisions_and_rejects_prereleases() {
    // Stable channel must allow valid Debian package revisions:
    assert!(tag_allowed_by_channel("1:1.2.3-1+b1", "stable"));
    assert!(tag_allowed_by_channel("2.4.5-1ubuntu1", "stable"));
    assert!(tag_allowed_by_channel("1.0.0-1deb12u1", "stable"));
    assert!(tag_allowed_by_channel("1.2.3-1", "stable"));
    assert!(tag_allowed_by_channel("0ubuntu0.22.04.1", "stable"));

    // Stable channel must reject true prereleases:
    assert!(!tag_allowed_by_channel("1.2.3-rc1", "stable"));
    assert!(!tag_allowed_by_channel("1.2.3-beta.1", "stable"));
    assert!(!tag_allowed_by_channel("1.0.0-alpha", "stable"));
    assert!(!tag_allowed_by_channel("1.0.0-nightly.20261109", "stable"));
    assert!(!tag_allowed_by_channel("1.0.0-0.1", "stable"));
    assert!(!tag_allowed_by_channel("1.0.0--", "stable"));

    // Retained APT target preservation on discovery failure:
    let prev_record = PackageUpdateRecord {
        package_id: "deb-pkg".to_string(),
        installed: true,
        installed_version: "1:1.2.3-1".to_string(),
        latest_version: "1:1.2.3-1+b1".to_string(),
        update_available: true,
        checked_at: "2026-11-01T00:00:00Z".to_string(),
        release_url: "".to_string(),
        error: "".to_string(),
        source_key: "apt:deb-pkg|stable".to_string(),
    };

    let rec = build_package_update_record_for_source(
        "",
        "apt",
        "deb-pkg",
        true,
        Ok("1:1.2.3-1".to_string()),
        Err(anyhow::anyhow!("apt repository timeout")),
        Some(&prev_record),
        "2026-11-09T00:00:00Z".to_string(),
        "apt:deb-pkg|stable",
    );

    // Retained target must NOT be cleared because "1:1.2.3-1+b1" is a valid stable revision!
    assert_eq!(rec.latest_version, "1:1.2.3-1+b1");
    assert!(rec.update_available);
    assert_eq!(rec.checked_at, "2026-11-01T00:00:00Z");

    // And check for ubuntu and debian suffixes:
    for deb_ver in ["2.4.5-1ubuntu1", "1.0.0-1deb12u1"] {
        let prev = PackageUpdateRecord {
            package_id: "deb-pkg2".to_string(),
            installed: true,
            installed_version: "1.0.0".to_string(),
            latest_version: deb_ver.to_string(),
            update_available: true,
            checked_at: "2026-11-01T00:00:00Z".to_string(),
            release_url: "".to_string(),
            error: "".to_string(),
            source_key: "apt:deb-pkg2|stable".to_string(),
        };
        let r = build_package_update_record_for_source(
            "",
            "apt",
            "deb-pkg2",
            true,
            Ok("1.0.0".to_string()),
            Err(anyhow::anyhow!("apt repository timeout")),
            Some(&prev),
            "2026-11-09T00:00:00Z".to_string(),
            "apt:deb-pkg2|stable",
        );
        assert_eq!(r.latest_version, deb_ver);
        assert!(r.update_available);
    }
}

#[tokio::test]
async fn test_systemd_unit_validation_execstart_reset_and_missing_script() {
    let _env_guard = TEST_ENV_MUTEX.lock().await;
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-systemd-reset-{}", uuid::Uuid::new_v4()));
    let opt_dir = temp_dir.join("opt/test-svc");
    let systemd_dir = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&opt_dir).unwrap();
    std::fs::create_dir_all(&systemd_dir).unwrap();

    std::fs::write(opt_dir.join(".af-version"), "1.0.0").unwrap();
    std::env::set_var("AETHERFLOW_FS_ROOT", &temp_dir);

    let pkg = Package {
        name: "test-svc".into(),
        lock_file: "/opt/test-svc/.af-version".into(),
        version_command: vec![],
        ..Default::default()
    };

    let service_file = systemd_dir.join("test-svc.service");

    // 1. ExecStart=/bin/true followed by empty ExecStart= reset line must be REJECTED!
    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Test Service\n[Service]\nExecStart=/bin/true\nExecStart=\n",
    )
    .unwrap();
    let res_reset = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_reset.is_err(),
        "Unit file with ExecStart=/bin/true followed by ExecStart= reset MUST be rejected!"
    );

    // 2. ExecStart=/bin/sh /nonexistent/script.sh must be REJECTED because referenced script does not exist!
    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Test Service\n[Service]\nExecStart=/bin/sh /nonexistent/script.sh\n",
    )
    .unwrap();
    let res_missing_script = probe_installed_package_version_strict(&pkg).await;
    assert!(
        res_missing_script.is_err(),
        "Unit file with interpreter pointing to missing script MUST be rejected!"
    );

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[tokio::test]
async fn test_detect_latest_github_release_prerelease_channel_selects_highest_version() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);
            let body = if req_str.contains("repo-pre-beta") {
                r#"[
                    {"tag_name": "v1.9.0-beta", "html_url": "https://github.com/mock/repo/releases/v1.9.0-beta", "prerelease": true},
                    {"tag_name": "v2.0.0-beta.1", "html_url": "https://github.com/mock/repo/releases/v2.0.0-beta.1", "prerelease": true}
                ]"#
            } else {
                r#"[
                    {"tag_name": "v1.9.0-beta", "html_url": "https://github.com/mock/repo/releases/v1.9.0-beta", "prerelease": true},
                    {"tag_name": "v2.0.0", "html_url": "https://github.com/mock/repo/releases/v2.0.0", "prerelease": false}
                ]"#
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");

    // 1. Channel "prerelease" with v1.9.0-beta and v2.0.0
    let res_pre = detect_latest_github_release_for_channel(
        &client,
        &origin,
        "test-owner/repo-pre",
        "prerelease",
    )
    .await
    .unwrap();
    assert_eq!(
        res_pre.0, "2.0.0",
        "prerelease channel must select higher version 2.0.0 over 1.9.0-beta"
    );
    assert_ne!(res_pre.0, "1.9.0-beta");

    // 2. Channel "beta" with v1.9.0-beta and v2.0.0
    let res_beta =
        detect_latest_github_release_for_channel(&client, &origin, "test-owner/repo-beta", "beta")
            .await
            .unwrap();
    assert_eq!(
        res_beta.0, "2.0.0",
        "beta channel must select higher version 2.0.0 over 1.9.0-beta"
    );
    assert_ne!(res_beta.0, "1.9.0-beta");

    // 3. Channel "all" with v1.9.0-beta and v2.0.0
    let res_all =
        detect_latest_github_release_for_channel(&client, &origin, "test-owner/repo-all", "all")
            .await
            .unwrap();
    assert_eq!(
        res_all.0, "2.0.0",
        "all channel must select higher version 2.0.0 over 1.9.0-beta"
    );
    assert_ne!(res_all.0, "1.9.0-beta");

    // 4. Channel "prerelease" with v1.9.0-beta and v2.0.0-beta.1
    let res_pre_beta = detect_latest_github_release_for_channel(
        &client,
        &origin,
        "test-owner/repo-pre-beta",
        "prerelease",
    )
    .await
    .unwrap();
    assert_eq!(
        res_pre_beta.0, "2.0.0-beta.1",
        "prerelease channel must select higher version 2.0.0-beta.1 over 1.9.0-beta"
    );

    server.abort();
}

#[test]
fn test_git_remotes_case_sensitivity_and_normalization() {
    let url1 = "https://Git.Example.com/team/App.git";
    let url2 = "https://git.example.com/team/app.git";
    let url3 = "HTTPS://GIT.EXAMPLE.COM:443/team/App.git";
    let url4 = "https://git.example.com/team/App.git";

    // git_head_cache_key:
    let key1 = git_head_cache_key(url1, "team/App");
    let key2 = git_head_cache_key(url2, "team/app");
    let key3 = git_head_cache_key(url3, "team/App");
    let key4 = git_head_cache_key(url4, "team/App");

    assert_ne!(
        key1, key2,
        "team/App.git and team/app.git must produce distinct git_head_cache_key values"
    );
    assert_eq!(key1, key3, "HTTPS://GIT.EXAMPLE.COM:443/team/App.git and https://Git.Example.com/team/App.git must normalize to same key");
    assert_eq!(key1, key4);

    // canonical_update_source_key:
    let pkg1 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: url1.into(),
        ..Default::default()
    };
    let pkg2 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/app".into(),
        update_repo_url: url2.into(),
        ..Default::default()
    };
    let pkg3 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: url3.into(),
        ..Default::default()
    };
    let pkg4 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: url4.into(),
        ..Default::default()
    };

    let ckey1 = canonical_update_source_key("", &pkg1);
    let ckey2 = canonical_update_source_key("", &pkg2);
    let ckey3 = canonical_update_source_key("", &pkg3);
    let ckey4 = canonical_update_source_key("", &pkg4);

    assert_ne!(
        ckey1, ckey2,
        "canonical_update_source_key must preserve path case and distinguish App vs app"
    );
    assert_eq!(
        ckey1, ckey3,
        "canonical_update_source_key must normalize authority and default port :443"
    );
    assert_eq!(ckey1, ckey4);
}

#[test]
fn test_channel_source_debian_revisions_and_semver_rejection() {
    // 1. Rejected on stable in both tag_allowed_by_channel and is_prerelease_version_for_channel
    assert!(is_prerelease_version_for_channel("1.2.3-foo-1"));
    assert!(is_prerelease_version_for_channel("1.2.3-1.2"));
    assert!(!tag_allowed_by_channel("1.2.3-foo-1", "stable"));
    assert!(!tag_allowed_by_channel("1.2.3-1.2", "stable"));

    // Source-aware for github and git:
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-foo-1",
        "stable",
        "github"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-1.2",
        "stable",
        "github"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-foo-1",
        "stable",
        "git"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-1.2",
        "stable",
        "git"
    ));

    // 2. Allowed on stable for APT / retained targets
    assert!(!is_prerelease_version_for_channel("1:1.2.3-1+b1"));
    assert!(!is_prerelease_version_for_channel("2.4.5-1ubuntu1"));
    assert!(!is_prerelease_version_for_channel("1.0.0-1deb12u1"));
    assert!(!is_prerelease_version_for_channel("1.2.3-1"));

    assert!(tag_allowed_by_channel_for_source(
        "1:1.2.3-1+b1",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "2.4.5-1ubuntu1",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "1.0.0-1deb12u1",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "1.2.3-1", "stable", "apt"
    ));

    assert!(tag_allowed_by_channel("1:1.2.3-1+b1", "stable"));
    assert!(tag_allowed_by_channel("2.4.5-1ubuntu1", "stable"));
    assert!(tag_allowed_by_channel("1.0.0-1deb12u1", "stable"));
    assert!(tag_allowed_by_channel("1.2.3-1", "stable"));
}

#[test]
fn test_systemd_unit_execstart_under_unit_rejected() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-systemd-unit-sec-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let service_file = temp_dir.join("test-invalid.service");
    std::fs::write(
        &service_file,
        "[Unit]\nDescription=Test Service\nExecStart=/bin/true\n[Service]\nTimeoutSec=30\n",
    )
    .unwrap();
    let pkg = Package {
        name: "test-invalid".into(),
        ..Default::default()
    };
    let is_valid = is_valid_systemd_service_unit(&service_file, &pkg);
    assert!(!is_valid, "systemd unit with ExecStart under [Unit] must be rejected by is_valid_systemd_service_unit");

    let bin_true = std::path::Path::new("/bin/true");
    if bin_true.exists() {
        let valid_file = temp_dir.join("test-valid.service");
        std::fs::write(
            &valid_file,
            "[Unit]\nDescription=Test Service\n[Service]\nExecStart=/bin/true\n",
        )
        .unwrap();
        let is_valid_ok = is_valid_systemd_service_unit(&valid_file, &pkg);
        assert!(
            is_valid_ok,
            "systemd unit with ExecStart under [Service] must be accepted"
        );
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_git_remotes_credentials_and_ssh_user_case() {
    let u1 = "Deploy@Git.Example.com:Team/App.git";
    let u2 = "deploy@Git.Example.com:Team/App.git";

    let k1 = git_head_cache_key(u1, "team/App");
    let k2 = git_head_cache_key(u2, "team/App");
    assert_ne!(
        k1, k2,
        "Deploy@host and deploy@host must produce distinct git_head_cache_key values"
    );

    let pkg1 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: u1.into(),
        ..Default::default()
    };
    let pkg2 = Package {
        name: "app".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: u2.into(),
        ..Default::default()
    };
    let ck1 = canonical_update_source_key("", &pkg1);
    let ck2 = canonical_update_source_key("", &pkg2);
    assert_ne!(
        ck1, ck2,
        "Deploy@host and deploy@host must produce distinct canonical_update_source_key values"
    );

    let cred_url = "https://admin:super_secret_token@git.example.com/team/App.git";
    let pkg_cred = Package {
        name: "app-cred".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: cred_url.into(),
        ..Default::default()
    };
    let ckey_cred = canonical_update_source_key("", &pkg_cred);
    let head_key_cred = git_head_cache_key(cred_url, "team/App");
    let disp_url = sanitize_git_remote_url_for_display(cred_url);

    assert!(
        !ckey_cred.contains("super_secret_token"),
        "canonical key must not leak password"
    );
    assert!(!ckey_cred.contains("admin:super_secret_token"));
    assert!(
        !head_key_cred.contains("super_secret_token"),
        "cache key must not leak password"
    );
    assert!(!head_key_cred.contains("admin:super_secret_token"));
    assert!(
        !disp_url.contains("super_secret_token"),
        "display url must not leak password"
    );
    assert!(!disp_url.contains("admin:super_secret_token"));
    assert_eq!(disp_url, "https://git.example.com/team/App.git");

    // Test persistence in SQLite
    let rec = PackageUpdateRecord {
        package_id: "test-cred-pkg".into(),
        release_url: cred_url.into(),
        error: "failed with secret: super_secret_token".into(),
        ..Default::default()
    };
    persist_package_update_record(&rec);
    if let Ok(conn) = af_db::get_conn() {
        let mut stmt = conn
            .prepare("SELECT update_url, last_error FROM app_updates WHERE package_name = ?1")
            .unwrap();
        let mut rows = stmt.query(params!["test-cred-pkg"]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let saved_url: String = row.get(0).unwrap();
            let saved_err: String = row.get(1).unwrap();
            assert!(!saved_url.contains("super_secret_token"));
            assert!(!saved_url.contains("admin:super_secret_token"));
            assert!(!saved_err.contains("super_secret_token"));
        }
    }
}

#[test]
fn test_systemd_unit_validation_case_sensitive_and_no_execstartpre() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-systemd-unit-pre-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();

    let pkg = Package {
        name: "test-pre".into(),
        ..Default::default()
    };

    // 1. ExecStartPre only in [Service] -> invalid!
    let pre_only = temp_dir.join("pre-only.service");
    std::fs::write(
        &pre_only,
        "[Unit]\nDescription=Pre Only\n[Service]\nExecStartPre=/bin/true\n",
    )
    .unwrap();
    assert!(
        !is_valid_systemd_service_unit(&pre_only, &pkg),
        "ExecStartPre alone must not satisfy is_valid_systemd_service_unit"
    );

    // 2. Lowercase execstart= in [Service] -> invalid!
    let lower_only = temp_dir.join("lower-only.service");
    std::fs::write(
        &lower_only,
        "[Unit]\nDescription=Lower Only\n[Service]\nexecstart=/bin/true\n",
    )
    .unwrap();
    assert!(
        !is_valid_systemd_service_unit(&lower_only, &pkg),
        "lowercase execstart= must not satisfy is_valid_systemd_service_unit"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn github_numeric_release_links_keep_the_configured_repository() {
    let base = "https://api.github.com";
    assert_eq!(
        github_releases_next_request_url(
            "https://api.github.com/repositories/17803236/releases?per_page=30&page=2",
            base,
            "rclone/rclone",
        )
        .as_deref(),
        Some("https://api.github.com/repos/rclone/rclone/releases?per_page=30&page=2"),
    );
    assert_eq!(
        github_releases_next_request_url(
            "https://ghe.internal/api/v3/repositories/123/releases?page=3",
            "https://ghe.internal/api/v3",
            "org/repo",
        )
        .as_deref(),
        Some("https://ghe.internal/api/v3/repos/org/repo/releases?per_page=100&page=3"),
    );
    for url in [
        "https://evil.example/repositories/17803236/releases?page=2",
        "https://api.github.com/repos/other/repo/releases?page=2",
        "https://api.github.com/repositories/17803236/issues?page=2",
        "https://api.github.com/repositories/not-an-id/releases?page=2",
        "https://api.github.com/repositories/17803236/releases?page=0",
        "https://api.github.com/repositories/17803236/releases?page=2&page=3",
        "https://api.github.com/repositories/17803236/releases?per_page=0&page=2",
        "https://api.github.com/repositories/17803236/releases?per_page=101&page=2",
        "https://api.github.com/repositories/17803236/releases?per_page=30&per_page=100&page=2",
        "https://api.github.com/repositories/17803236/releases?page=2#fragment",
        "https://user@api.github.com/repositories/17803236/releases?page=2",
    ] {
        assert!(
            github_releases_next_request_url(url, base, "rclone/rclone").is_none(),
            "{url}"
        );
    }
}

#[tokio::test]
async fn github_numeric_release_pagination_observes_the_next_page() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for page in [1, 2] {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            let expected = if page == 1 {
                "GET /repos/owner/numeric-links/releases?per_page=100 HTTP/1.1".to_string()
            } else {
                "GET /repos/owner/numeric-links/releases?per_page=100&page=2 HTTP/1.1".to_string()
            };
            assert!(request.starts_with(&expected), "{request}");
            let body = format!(
                r#"[{{"tag_name":"v{page}.0.0","html_url":"https://github.com/owner/numeric-links/releases/tag/v{page}.0.0"}}]"#
            );
            let link = if page == 1 {
                format!("Link: <http://{addr}/repositories/123/releases?per_page=100&page=2>; rel=\"next\"\r\n")
            } else {
                String::new()
            };
            socket.write_all(format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{link}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            ).as_bytes()).await.unwrap();
        }
    });
    let result = detect_latest_github_release_for_channel(
        &build_github_http_client(),
        &format!("http://{addr}"),
        "owner/numeric-links",
        "stable",
    )
    .await
    .unwrap();
    assert_eq!(result.0, "2.0.0");
    server.await.unwrap();
}

#[tokio::test]
async fn test_github_release_discovery_multi_page_pagination() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);

            let body: String = if req_str.contains("page=2") {
                r#"[{"tag_name": "v2.1.0-beta.1", "html_url": "https://github.com/org/repo/releases/v2.1.0-beta.1", "prerelease": true, "draft": false}]"#.to_string()
            } else {
                let mut items = Vec::new();
                for i in 1..=GITHUB_RELEASE_PAGE_SIZE {
                    items.push(format!(
                        r#"{{"tag_name": "v1.9.{}", "html_url": "https://github.com/org/repo/releases/v1.9.{}", "prerelease": false, "draft": false}}"#,
                        i, i
                    ));
                }
                format!("[{}]", items.join(","))
            };

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
        "test-owner/multi-page-repo",
        "prerelease",
    )
    .await
    .unwrap();
    assert_eq!(
        res.0, "2.1.0-beta.1",
        "Pagination must fetch page 2 and discover higher 2.1.0-beta.1 over page 1's v1.9.100"
    );

    server.abort();
}

#[test]
fn test_retained_git_tags_and_apt_dotted_revisions() {
    // Git tags: 1.2.3-1 is a SemVer prerelease, rejected on stable
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-1", "stable", "git_tags"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.0.0-0.1",
        "stable",
        "git_tags"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-1.2",
        "stable",
        "git_tags"
    ));

    // APT: 1.0.0-0.1, 1.2.3-1.2, 1:1.2.3-1+b1, 1.2.3-1 are valid Debian NMU revisions, preserved on stable!
    assert!(tag_allowed_by_channel_for_source(
        "1.0.0-0.1",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "1.2.3-1.2",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "1:1.2.3-1+b1",
        "stable",
        "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "1.2.3-1", "stable", "apt"
    ));
    assert!(tag_allowed_by_channel_for_source(
        "2.4.5-1ubuntu1",
        "stable",
        "apt"
    ));

    // APT rejects prerelease tags
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-rc1",
        "stable",
        "apt"
    ));
    assert!(!tag_allowed_by_channel_for_source(
        "1.2.3-foo-1",
        "stable",
        "apt"
    ));
}

#[tokio::test]
async fn test_github_release_discovery_stable_channel_scans_pages_and_picks_highest() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);

            let (status, body) = if req_str.contains("/releases/latest") {
                (
                    "HTTP/1.1 200 OK",
                    r#"{"tag_name": "v1.9.4", "html_url": "https://github.com/org/repo/releases/v1.9.4", "prerelease": false, "draft": false}"#,
                )
            } else if req_str.contains("/releases?per_page=100") {
                (
                    "HTTP/1.1 200 OK",
                    r#"[
                        {"tag_name": "v1.9.4", "html_url": "https://github.com/org/repo/releases/v1.9.4", "prerelease": false, "draft": false},
                        {"tag_name": "v2.0.0", "html_url": "https://github.com/org/repo/releases/v2.0.0", "prerelease": false, "draft": false}
                    ]"#,
                )
            } else {
                ("HTTP/1.1 404 Not Found", r#"{"message": "Not Found"}"#)
            };

            let resp = format!(
                "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
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
        "test-owner/backport-repo",
        "stable",
    )
    .await
    .unwrap();
    assert_eq!(
        res.0, "2.0.0",
        "Stable release discovery must scan releases and select higher 2.0.0 over backport 1.9.4"
    );
    assert_eq!(res.1, "https://github.com/org/repo/releases/v2.0.0");

    server.abort();
}

#[tokio::test]
async fn test_github_release_discovery_fails_closed_on_page_2_failure() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };
            let mut buf = vec![0; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);

            let (status, body) = if req_str.contains("page=2") {
                (
                    "HTTP/1.1 500 Internal Server Error",
                    r#"{"message": "Server Error"}"#.to_string(),
                )
            } else {
                let mut items = Vec::new();
                for i in 1..=GITHUB_RELEASE_PAGE_SIZE {
                    items.push(format!(
                        r#"{{"tag_name": "v1.0.{}", "html_url": "https://github.com/org/repo/releases/v1.0.{}", "prerelease": false, "draft": false}}"#,
                        i, i
                    ));
                }
                ("HTTP/1.1 200 OK", format!("[{}]", items.join(",")))
            };

            let resp = format!(
                "{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                status,
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
        }
    });

    let client = build_github_http_client();
    let origin = format!("http://{addr}");
    let repo = "test-owner/fail-page2-repo";

    let res = detect_latest_github_release_for_channel(&client, &origin, repo, "stable").await;
    assert!(
        res.is_err(),
        "Must fail closed when page 2 returns HTTP 500"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg.contains("GitHub API returned 500") || err_msg.contains("on page 2"),
        "error: {err_msg}"
    );

    let cache_key = github_release_cache_key_for_channel(&origin, repo, "stable");
    let cached = github_release_cache().get(&cache_key).cloned();
    assert!(
        cached.is_none(),
        "Incomplete discovery result must NOT be cached!"
    );

    server.abort();
}

#[test]
fn test_canonical_update_source_key_and_persistence_scrub_secrets() {
    // 1. API base with userinfo and query parameters
    let dirty_api =
        "https://user:super_secret_pass@api.github.internal.com:443/v3?token=secret_query#anchor";
    let pkg_github = Package {
        name: "myapp".into(),
        update_source: "github".into(),
        update_repo: "myorg/myapp".into(),
        update_channel: "stable".into(),
        ..Default::default()
    };

    let key = canonical_update_source_key(dirty_api, &pkg_github);
    assert!(
        !key.contains("super_secret_pass"),
        "Key must not contain password: {key}"
    );
    assert!(
        !key.contains("user:"),
        "Key must not contain userinfo: {key}"
    );
    assert!(
        !key.contains("secret_query"),
        "Key must not contain query parameters: {key}"
    );
    assert_eq!(
        key,
        "github:https://api.github.internal.com/v3|myorg/myapp|stable"
    );

    // 2. Git remote URL with query parameters containing secret tokens
    let dirty_git_url =
        "https://git.example.com/team/App.git?token=secret123&access_token=xyz#frag";
    let pkg_git = Package {
        name: "myapp-git".into(),
        update_source: "git".into(),
        update_repo: "team/App".into(),
        update_repo_url: dirty_git_url.into(),
        update_channel: "stable".into(),
        ..Default::default()
    };

    let git_key = canonical_update_source_key("", &pkg_git);
    assert!(
        !git_key.contains("secret123"),
        "Git source key must not contain token: {git_key}"
    );
    assert!(
        !git_key.contains("access_token"),
        "Git source key must not contain access_token: {git_key}"
    );

    let disp_git = sanitize_git_remote_url_for_display(dirty_git_url);
    assert_eq!(disp_git, "https://git.example.com/team/App.git");
    assert!(!disp_git.contains("secret123"));
    assert!(!disp_git.contains("access_token"));

    // 3. Test persist_package_update_record sanitizes source_key, latest_version, installed_version
    let dirty_record = PackageUpdateRecord {
        package_id: "test-scrub-pkg".into(),
        installed: true,
        installed_version: "1.0.0-token=secret_in_version".into(),
        latest_version: "2.0.0-password=secret_in_latest".into(),
        update_available: true,
        checked_at: "2026-11-09T00:00:00Z".into(),
        release_url: "https://git.example.com/repo.git?secret=leak".into(),
        error: "curl -u admin:super_secret_curl https://example.com".into(),
        source_key: "github:https://api.github.com|myorg/myapp|stable?token=secret_in_key".into(),
    };

    persist_package_update_record(&dirty_record);
    if let Ok(conn) = af_db::get_conn() {
        let mut stmt = conn.prepare("SELECT installed_version, latest_version, update_url, last_error, source_key FROM app_updates WHERE package_name = ?1").unwrap();
        let mut rows = stmt.query(params!["test-scrub-pkg"]).unwrap();
        if let Some(row) = rows.next().unwrap() {
            let saved_inst: String = row.get(0).unwrap();
            let saved_latest: String = row.get(1).unwrap();
            let saved_url: String = row.get(2).unwrap();
            let saved_err: String = row.get(3).unwrap();
            let saved_key: String = row.get(4).unwrap();

            assert!(
                !saved_inst.contains("secret_in_version"),
                "installed_version must redact secrets"
            );
            assert!(
                !saved_latest.contains("secret_in_latest"),
                "latest_version must redact secrets"
            );
            assert!(
                !saved_url.contains("leak"),
                "update_url must redact secrets"
            );
            assert!(
                !saved_err.contains("super_secret_curl"),
                "last_error must redact curl user credentials"
            );
            assert!(
                !saved_key.contains("secret_in_key"),
                "source_key must redact secrets"
            );
        }
    }
}

#[test]
fn test_strict_semver_prerelease_rules_for_git_sources() {
    for src in &["github", "github_release", "git", "git_tags"] {
        // Numeric prerelease / hyphen after SemVer:
        assert!(
            !tag_allowed_by_channel_for_source("1.2.3-1", "stable", src),
            "Source {src} must reject 1.2.3-1 on stable"
        );
        assert!(
            !tag_allowed_by_channel_for_source("1.2.3-debug.1", "stable", src),
            "Source {src} must reject 1.2.3-debug.1 on stable"
        );
        assert!(
            !tag_allowed_by_channel_for_source("1.2.3-ubuntu1", "stable", src),
            "Source {src} must reject 1.2.3-ubuntu1 on stable"
        );
        assert!(
            !tag_allowed_by_channel_for_source("1.2.3-deb11u1", "stable", src),
            "Source {src} must reject 1.2.3-deb11u1 on stable"
        );
        assert!(
            tag_allowed_by_channel_for_source("1.2.3", "stable", src),
            "Source {src} must allow 1.2.3 on stable"
        );
    }
}
