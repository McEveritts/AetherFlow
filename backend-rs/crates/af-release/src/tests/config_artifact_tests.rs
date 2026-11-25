use super::{build_synthetic_release_tarball, TempSandbox};
use crate::*;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tar::EntryType;

#[test]
fn test_parse_conf_and_env_file_precedence() {
    let sb = TempSandbox::new("conf-env");
    let conf_file = sb.path().join("release-manager.conf");
    fs::write(
        &conf_file,
        r#"
# Comment line
RELEASES_DIR="${RELEASES_DIR:-/opt/AetherFlow/releases}"
RELEASE_CHANNEL="${RELEASE_CHANNEL:-stable}"
MAX_RELEASES="${MAX_RELEASES:-3}"
SYSTEMD_UNITS_SRC="${SYSTEMD_UNITS_SRC:-${SCRIPT_DIR}/systemd}"
"#,
    )
    .unwrap();

    let mut env_map = HashMap::new();
    env_map.insert("RELEASE_CHANNEL".to_string(), "experimental".to_string());
    env_map.insert("MAX_RELEASES".to_string(), "5".to_string());

    let cfg = ReleaseConfig::load_with_env(Some(&conf_file), &env_map).unwrap();
    assert_eq!(cfg.release_channel, ReleaseChannel::Nightly);
    assert_eq!(cfg.max_releases, 5);
    assert_eq!(cfg.releases_dir, PathBuf::from("/opt/AetherFlow/releases"));
    assert_eq!(cfg.systemd_units_src, sb.path().join("systemd"));

    // Verify read_env_str_value last-wins and quote-stripping rules
    let env_content = r#"
# Database config
DB_PATH="/stale/path.sqlite"
export DB_PATH='/opt/AetherFlow/backend/data/aetherflow.sqlite'
DB_PATH=""
AETHERFLOW_DB_PATH=fallback.sqlite
"#;
    assert_eq!(
        read_env_str_value(env_content, "DB_PATH").as_deref(),
        Some("/opt/AetherFlow/backend/data/aetherflow.sqlite")
    );
    assert_eq!(
        read_env_str_value(env_content, "AETHERFLOW_DB_PATH").as_deref(),
        Some("fallback.sqlite")
    );
}

#[test]
fn test_resolve_db_path_four_tier_precedence() {
    let sb = TempSandbox::new("db-precedence");
    let mut cfg = ReleaseConfig::for_root(sb.path());
    cfg.isolated_root = None;
    fs::create_dir_all(&cfg.env_dir).unwrap();

    let r4 = resolve_db_path(&cfg, None);
    assert_eq!(r4.path, cfg.host_data_dir.join("aetherflow.sqlite"));
    assert_eq!(r4.source, DbPathSource::DataDirDefault);

    let unit_blob = "Environment=GIN_MODE=release \"DB_PATH=/srv/systemd/af.sqlite\"\n";
    let r3 = resolve_db_path(&cfg, Some(unit_blob));
    assert_eq!(r3.path, PathBuf::from("/srv/systemd/af.sqlite"));
    assert_eq!(
        r3.source,
        DbPathSource::SystemdUnit {
            unit: "aetherflow-api".to_string(),
            key: "DB_PATH".to_string()
        }
    );

    fs::write(
        &cfg.host_env_file,
        "AETHERFLOW_DB_PATH=/opt/AetherFlow/backend/data/aetherflow.sqlite\n",
    )
    .unwrap();
    let r2 = resolve_db_path(&cfg, Some(unit_blob));
    assert_eq!(
        r2.path,
        PathBuf::from("/opt/AetherFlow/backend/data/aetherflow.sqlite")
    );
    assert_eq!(
        r2.source,
        DbPathSource::EnvFile {
            path: cfg.host_env_file.clone(),
            key: "AETHERFLOW_DB_PATH".to_string()
        }
    );

    fs::write(
        &cfg.host_env_file,
        "AETHERFLOW_DB_PATH=/opt/secondary.sqlite\nDB_PATH=/opt/primary.sqlite\n",
    )
    .unwrap();
    let r2b = resolve_db_path(&cfg, Some(unit_blob));
    assert_eq!(r2b.path, PathBuf::from("/opt/primary.sqlite"));

    cfg.af_db_path_override = Some(PathBuf::from("/override/af.sqlite"));
    let r1 = resolve_db_path(&cfg, Some(unit_blob));
    assert_eq!(r1.path, PathBuf::from("/override/af.sqlite"));
    assert_eq!(r1.source, DbPathSource::AfDbPathEnv);
}

#[test]
fn test_select_release_tag_all_channels() {
    let sample_json = r#"[
        {"tag_name": "v4.1.0-draft", "target_commitish": "master", "draft": true, "prerelease": false},
        {"tag_name": "experimental", "target_commitish": "experimental", "draft": false, "prerelease": true},
        {"tag_name": "v4.0.1-nightly.20261031", "target_commitish": "nightly", "draft": false, "prerelease": true},
        {"tag_name": "v4.0.0", "target_commitish": "master", "draft": false, "prerelease": false}
    ]"#;

    assert_eq!(
        select_release_tag_from_json(ReleaseChannel::Stable, sample_json).unwrap(),
        "v4.0.0"
    );
    assert_eq!(
        select_release_tag_from_json(ReleaseChannel::Nightly, sample_json).unwrap(),
        "v4.0.1-nightly.20261031"
    );
    assert_eq!(
        select_release_tag_from_json(
            "experimental".parse::<ReleaseChannel>().unwrap(),
            sample_json
        )
        .unwrap(),
        "v4.0.1-nightly.20261031"
    );

    // Fail-closed behavior when JSON is empty: all channels reject unverified fallback tags
    assert!(select_release_tag_from_json(ReleaseChannel::Nightly, "").is_err());
    assert!(
        select_release_tag_from_json("experimental".parse::<ReleaseChannel>().unwrap(), "")
            .is_err()
    );
    assert!(select_release_tag_from_json(ReleaseChannel::Stable, "").is_err());
}

#[test]
fn test_artifact_checksum_and_zip_slip_rejection() {
    let sb = TempSandbox::new("artifact-sec");
    let cfg = ReleaseConfig::for_root(sb.path());

    // 1. Valid archive and SHA256SUMS
    let good_tar = sb.path().join("good.tar.gz");
    let (_, manifest) = build_synthetic_release_tarball(
        &good_tar,
        &cfg.artifact_name,
        &[
            (
                "aetherflow-api",
                b"#!/bin/sh\necho v4\n",
                EntryType::Regular,
            ),
            (".version", b"v4.0.0\n", EntryType::Regular),
            (
                "web/dist/index.html",
                b"synthetic test index",
                EntryType::Regular,
            ),
            (
                "web/dist/app.wasm",
                b"synthetic test wasm",
                EntryType::Regular,
            ),
            ("config/packages.json", b"[]", EntryType::Regular),
        ],
    );
    let digest = verify_artifact_checksum(&good_tar, &manifest, &cfg.artifact_name).unwrap();
    assert_eq!(digest.len(), 64);

    // 2. Tampered checksum must fail with ChecksumMismatch
    let bad_manifest = format!(
        "0000000000000000000000000000000000000000000000000000000000000000  {}\n",
        cfg.artifact_name
    );
    let err = verify_artifact_checksum(&good_tar, &bad_manifest, &cfg.artifact_name).unwrap_err();
    assert!(matches!(err, ReleaseError::ChecksumMismatch { .. }));

    // 3. Archive containing a symlink entry must be rejected
    let symlink_tar = sb.path().join("symlink.tar.gz");
    build_synthetic_release_tarball(
        &symlink_tar,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"binary", EntryType::Regular),
            ("evil-link", b"", EntryType::Symlink),
        ],
    );
    let extract_dir = sb.path().join("extract-symlink");
    let sym_err = extract_and_validate_release_archive(&symlink_tar, &extract_dir, "v4.0.0", &cfg)
        .unwrap_err();
    assert!(matches!(sym_err, ReleaseError::ArchiveExtraction { .. }));

    // 4. Archive missing aetherflow-api binary must be rejected
    let missing_bin_tar = sb.path().join("nobin.tar.gz");
    build_synthetic_release_tarball(
        &missing_bin_tar,
        &cfg.artifact_name,
        &[(".version", b"v4.0.0\n", EntryType::Regular)],
    );
    let extract_nobin = sb.path().join("extract-nobin");
    let nobin_err =
        extract_and_validate_release_archive(&missing_bin_tar, &extract_nobin, "v4.0.0", &cfg)
            .unwrap_err();
    assert!(matches!(nobin_err, ReleaseError::ArtifactVerification(_)));
}

#[test]
fn release_archive_requires_external_frontend_assets_before_manager_staging() {
    let sb = TempSandbox::new("external-frontend-contract");
    let mut cfg = ReleaseConfig::for_root(sb.path());
    let running_manager = sb.path().join("running-release-manager.sh");
    fs::write(&running_manager, b"synthetic running manager").unwrap();
    cfg.stage_script_path = Some(running_manager);

    type ArchiveEntry<'a> = (&'a str, &'a [u8], EntryType);
    type FrontendCase<'a> = (&'a str, &'a [ArchiveEntry<'a>], &'a str);
    let cases: &[FrontendCase<'_>] = &[
        ("missing-dist", &[], "regular directory"),
        (
            "dist-is-file",
            &[("web/dist", b"synthetic non-directory", EntryType::Regular)],
            "regular directory",
        ),
        (
            "missing-index",
            &[("web/dist/app.wasm", b"synthetic wasm", EntryType::Regular)],
            "index.html",
        ),
        (
            "empty-index",
            &[
                ("web/dist/index.html", b"", EntryType::Regular),
                ("web/dist/app.wasm", b"synthetic wasm", EntryType::Regular),
            ],
            "index.html",
        ),
        (
            "index-directory",
            &[
                ("web/dist/index.html", b"", EntryType::Directory),
                ("web/dist/app.wasm", b"synthetic wasm", EntryType::Regular),
            ],
            "index.html",
        ),
        (
            "missing-wasm",
            &[(
                "web/dist/index.html",
                b"synthetic index",
                EntryType::Regular,
            )],
            "*.wasm",
        ),
        (
            "empty-wasm",
            &[
                (
                    "web/dist/index.html",
                    b"synthetic index",
                    EntryType::Regular,
                ),
                ("web/dist/app.wasm", b"", EntryType::Regular),
            ],
            "*.wasm",
        ),
        (
            "nested-wasm-only",
            &[
                (
                    "web/dist/index.html",
                    b"synthetic index",
                    EntryType::Regular,
                ),
                (
                    "web/dist/nested/app.wasm",
                    b"synthetic wasm",
                    EntryType::Regular,
                ),
            ],
            "*.wasm",
        ),
        (
            "wasm-directory",
            &[
                (
                    "web/dist/index.html",
                    b"synthetic index",
                    EntryType::Regular,
                ),
                ("web/dist/app.wasm", b"", EntryType::Directory),
            ],
            "*.wasm",
        ),
    ];
    for &(label, frontend_entries, expected_error) in cases {
        let archive = sb.path().join(format!("{label}.tar.gz"));
        let mut entries: Vec<(&str, &[u8], EntryType)> = vec![
            ("aetherflow-api", b"synthetic api", EntryType::Regular),
            (".version", b"v4.0.0\n", EntryType::Regular),
        ];
        entries.extend_from_slice(frontend_entries);
        let (_, manifest) = build_synthetic_release_tarball(&archive, &cfg.artifact_name, &entries);
        verify_artifact_checksum(&archive, &manifest, &cfg.artifact_name).unwrap();
        let extracted = sb.path().join(format!("extract-{label}"));
        let err = extract_and_validate_release_archive(&archive, &extracted, "v4.0.0", &cfg)
            .expect_err(label);
        assert!(
            matches!(&err, ReleaseError::ArtifactVerification(message) if message.contains(expected_error)),
            "{label}: {err}"
        );
        assert!(
            !extracted.join("deploy/release-manager.sh").exists(),
            "{label}: manager staged before validation"
        );
    }

    // Representative release paths with synthetic contents; these are not production assets.
    let archive = sb.path().join("valid-layout.tar.gz");
    let (_, manifest) = build_synthetic_release_tarball(
        &archive,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"synthetic api", EntryType::Regular),
            ("af", b"synthetic cli", EntryType::Regular),
            ("bin/af", b"synthetic cli", EntryType::Regular),
            (".version", b"v4.0.0\n", EntryType::Regular),
            (
                "web/dist/index.html",
                b"synthetic index",
                EntryType::Regular,
            ),
            ("web/dist/empty.wasm", b"", EntryType::Regular),
            (
                "web/dist/af-web-app_bg-1234.wasm",
                b"synthetic wasm",
                EntryType::Regular,
            ),
            (
                "deploy/release-manager.sh",
                b"synthetic candidate manager",
                EntryType::Regular,
            ),
        ],
    );
    verify_artifact_checksum(&archive, &manifest, &cfg.artifact_name).unwrap();
    let extracted = sb.path().join("extract-valid-layout");
    extract_and_validate_release_archive(&archive, &extracted, "v4.0.0", &cfg).unwrap();
    assert_eq!(
        fs::read(extracted.join("web/dist/index.html")).unwrap(),
        b"synthetic index"
    );
    assert_eq!(
        fs::read(extracted.join("web/dist/af-web-app_bg-1234.wasm")).unwrap(),
        b"synthetic wasm"
    );
    assert_eq!(
        fs::read(extracted.join("deploy/release-manager.sh")).unwrap(),
        b"synthetic candidate manager"
    );
    assert!(extracted.join("af").is_file());
    assert!(extracted.join("bin/af").is_file());
}

#[test]
fn release_archive_rejects_symlinked_frontend_entries() {
    let sb = TempSandbox::new("frontend-archive-symlinks");
    let cfg = ReleaseConfig::for_root(sb.path());
    for link in [
        "web",
        "web/dist",
        "web/dist/index.html",
        "web/dist/app.wasm",
    ] {
        let archive = sb
            .path()
            .join(format!("link-{}.tar.gz", link.replace('/', "-")));
        build_synthetic_release_tarball(
            &archive,
            &cfg.artifact_name,
            &[
                ("aetherflow-api", b"synthetic api", EntryType::Regular),
                (".version", b"v4.0.0\n", EntryType::Regular),
                (link, b"", EntryType::Symlink),
            ],
        );
        let extracted = sb
            .path()
            .join(format!("extract-{}", link.replace('/', "-")));
        let err = extract_and_validate_release_archive(&archive, &extracted, "v4.0.0", &cfg)
            .expect_err(link);
        assert!(
            matches!(&err, ReleaseError::ArchiveExtraction { .. }),
            "{link}: {err}"
        );
    }
}
#[cfg(unix)]
#[test]
fn test_current_unit_source_only_allows_managed_release_link() {
    use std::os::unix::fs::symlink;
    let sandbox = TempSandbox::new("unit-source-link");
    let config = ReleaseConfig::for_root(sandbox.path());
    let release = config.releases_dir.join("1700000003");
    fs::create_dir_all(release.join("deploy/systemd")).unwrap();
    symlink(&release, &config.current_link).unwrap();
    assert_eq!(
        crate::health::packaged_systemd_directory(&config).unwrap(),
        release.join("deploy/systemd")
    );
    fs::remove_file(&config.current_link).unwrap();
    let outside = sandbox.path().join("outside");
    fs::create_dir_all(&outside).unwrap();
    symlink(&outside, &config.current_link).unwrap();
    assert!(crate::health::packaged_systemd_directory(&config).is_err());
    fs::remove_file(&config.current_link).unwrap();
    fs::remove_dir_all(&release).unwrap();
    symlink(&outside, &release).unwrap();
    symlink(&release, &config.current_link).unwrap();
    assert!(crate::health::packaged_systemd_directory(&config).is_err());
    let regular_file = sandbox.path().join("regular");
    fs::write(&regular_file, "not a directory").unwrap();
    assert!(ensure_no_symlink_ancestors(&regular_file.join("child")).is_err());
}

#[test]
fn test_select_release_tag_from_json_channel_isolation() {
    let payload = r#"[
        {"tag_name": "v4.0.0-experimental", "target_commitish": "experimental", "prerelease": true, "draft": false},
        {"tag_name": "v3.99.0-nightly.1", "target_commitish": "nightly", "prerelease": true, "draft": false},
        {"tag_name": "v4.0.0-nightly.110.1", "target_commitish": "nightly", "prerelease": true, "draft": false},
        {"tag_name": "v3.2.7", "target_commitish": "master", "prerelease": false, "draft": false},
        {"tag_name": "v4.0.0", "target_commitish": "master", "prerelease": false, "draft": false}
    ]"#;

    assert_eq!(
        select_release_tag_from_json(ReleaseChannel::Stable, payload).unwrap(),
        "v4.0.0"
    );
    // Nightly must ignore v4.0.0-experimental and pre-v4 v3.99.0-nightly.1, selecting v4.0.0-nightly.110.1
    assert_eq!(
        select_release_tag_from_json(ReleaseChannel::Nightly, payload).unwrap(),
        "v4.0.0-nightly.110.1"
    );
    assert_eq!(
        select_release_tag_from_json("experimental".parse::<ReleaseChannel>().unwrap(), payload)
            .unwrap(),
        "v4.0.0-nightly.110.1"
    );

    // Pre-v4 only payload must fail closed on both channels (no implicit v3 downgrade or "nightly" fallback)
    let v3_only = r#"[
        {"tag_name": "v3.3.0-nightly.1", "target_commitish": "nightly", "prerelease": true, "draft": false},
        {"tag_name": "v3.2.7", "target_commitish": "master", "prerelease": false, "draft": false}
    ]"#;
    assert!(select_release_tag_from_json(ReleaseChannel::Stable, v3_only).is_err());
    assert!(select_release_tag_from_json(ReleaseChannel::Nightly, v3_only).is_err());
}

#[test]
fn test_parse_stable_tag_from_redirect_url_validation() {
    assert_eq!(
        parse_stable_tag_from_redirect_url(
            "https://github.com/McEveritts/AetherFlow/releases/tag/v4.0.0",
            "https://github.com",
            "McEveritts/AetherFlow"
        )
        .unwrap(),
        "v4.0.0"
    );
    // Pre-v4 stable tags must be rejected (no v3 downgrade)
    assert!(parse_stable_tag_from_redirect_url(
        "https://github.com/McEveritts/AetherFlow/releases/tag/v3.2.7",
        "https://github.com",
        "McEveritts/AetherFlow"
    )
    .is_err());
    // Prerelease / hyphenated tags must be rejected by stable redirect parser
    assert!(parse_stable_tag_from_redirect_url(
        "https://github.com/McEveritts/AetherFlow/releases/tag/v4.0.0-experimental",
        "https://github.com",
        "McEveritts/AetherFlow"
    )
    .is_err());
    // Unredirected /releases/latest URL must return Err
    assert!(parse_stable_tag_from_redirect_url(
        "https://github.com/McEveritts/AetherFlow/releases/latest",
        "https://github.com",
        "McEveritts/AetherFlow"
    )
    .is_err());
}

#[test]
fn test_regression_conf_serialization_roundtrip_and_strict_rejection() {
    let sandbox = TempSandbox::new("conf-roundtrip");
    let mut cfg = ReleaseConfig::for_root(sandbox.path());
    cfg.git_branch = "feat/quote\"backslash\\dollar$tick`tab\t".to_string();
    let conf_path = sandbox.path().join("serialized.conf");
    cfg.write_protected_config_file(&conf_path).unwrap();

    let parsed = parse_conf_file(&conf_path).unwrap();
    assert_eq!(
        parsed.get("GIT_BRANCH").map(|val| val.as_str()),
        Some("feat/quote\"backslash\\dollar$tick`tab\t")
    );

    let bad_conf = sandbox.path().join("bad-unterminated.conf");
    fs::write(&bad_conf, "RELEASES_DIR=\"/unterminated\n").unwrap();
    assert!(parse_conf_file(&bad_conf).is_err());

    let bad_sub = sandbox.path().join("bad-cmdsub.conf");
    fs::write(&bad_sub, "RELEASES_DIR=\"$(id)\"\n").unwrap();
    assert!(parse_conf_file(&bad_sub).is_err());
}

#[test]
fn test_regression_isolated_root_db_and_systemd_and_cli_containment() {
    let sandbox = TempSandbox::new("isolated-containment");
    let mut cfg = ReleaseConfig::for_root(sandbox.path());
    fs::create_dir_all(&cfg.env_dir).unwrap();

    let host_blob = "Environment=\"DB_PATH=/var/lib/aetherflow/aetherflow.sqlite\"\n";
    let resolved_default = try_resolve_db_path(&cfg, Some(host_blob)).unwrap();
    assert_eq!(
        resolved_default.path,
        cfg.host_data_dir.join("aetherflow.sqlite")
    );
    assert_eq!(resolved_default.source, DbPathSource::DataDirDefault);

    fs::write(
        &cfg.host_env_file,
        "DB_PATH=/var/lib/aetherflow/outside.sqlite\n",
    )
    .unwrap();
    assert!(try_resolve_db_path(&cfg, None).is_err());

    let inside_a = sandbox.path().join("var/lib/aetherflow/a.sqlite");
    let inside_b = sandbox.path().join("var/lib/aetherflow/b.sqlite");
    fs::write(
        &cfg.host_env_file,
        format!(
            "DB_PATH={}\nAETHERFLOW_DB_PATH={}\n",
            inside_a.display(),
            inside_b.display()
        ),
    )
    .unwrap();
    assert!(try_resolve_db_path(&cfg, None).is_err());

    fs::write(
        &cfg.host_env_file,
        format!("DB_PATH={}\n", inside_a.display()),
    )
    .unwrap();
    let resolved_inside = try_resolve_db_path(&cfg, None).unwrap();
    assert_eq!(resolved_inside.path, inside_a);

    let lock_path = resolve_maintenance_lock_path_for_config(&cfg).unwrap();
    assert_eq!(
        lock_path,
        sandbox.path().join("var/lib/aetherflow/.snapshot.lock")
    );

    let jobs_dir = resolve_self_update_jobs_dir_for_config(&cfg).unwrap();
    assert_eq!(
        jobs_dir,
        sandbox.path().join("var/lib/aetherflow/.self-update-jobs")
    );

    assert!(verify_isolated_systemd_lifecycle_authorized(&cfg).is_err());

    cfg.cli_bin_dir = PathBuf::from("/usr/local/bin");
    assert!(sync_cli_entrypoints(&cfg, "100").is_err());
}

#[cfg(unix)]
#[test]
fn test_prepare_release_permissions_normalizes_modes_and_verifies_binaries() {
    use std::os::unix::fs::PermissionsExt;

    let sb = TempSandbox::new("release-perms");
    let release_dir = sb.path().join("release");
    fs::create_dir_all(release_dir.join("config")).unwrap();
    fs::create_dir_all(release_dir.join("bin")).unwrap();
    fs::write(release_dir.join("aetherflow-api"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(release_dir.join("af"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(release_dir.join("bin/af"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(
        release_dir.join("speedtest-backend"),
        b"#!/bin/sh\nexit 0\n",
    )
    .unwrap();
    fs::write(
        release_dir.join("bin/speedtest-backend"),
        b"#!/bin/sh\nexit 0\n",
    )
    .unwrap();
    fs::write(release_dir.join("af-transcode"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(release_dir.join("bin/af-transcode"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(release_dir.join(".version"), b"v4.0.0\n").unwrap();
    fs::write(release_dir.join("config/app.json"), b"{}").unwrap();

    // Start with restrictive/group-writable permissions to ensure prepare_release_permissions fixes them
    fs::set_permissions(&release_dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(
        release_dir.join("config"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(
        release_dir.join("aetherflow-api"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(release_dir.join("af"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(
        release_dir.join("bin/af"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        release_dir.join("speedtest-backend"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        release_dir.join("bin/speedtest-backend"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        release_dir.join("af-transcode"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        release_dir.join("bin/af-transcode"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    fs::set_permissions(
        release_dir.join(".version"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();

    prepare_release_permissions(&release_dir).unwrap();

    for exec_rel in [
        "aetherflow-api",
        "af",
        "bin/af",
        "speedtest-backend",
        "bin/speedtest-backend",
        "af-transcode",
        "bin/af-transcode",
    ] {
        assert_eq!(
            fs::symlink_metadata(release_dir.join(exec_rel))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "expected 0755 on {exec_rel}"
        );
    }

    assert_eq!(
        fs::symlink_metadata(&release_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        fs::symlink_metadata(release_dir.join("config"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        fs::symlink_metadata(release_dir.join("aetherflow-api"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        fs::symlink_metadata(release_dir.join("af"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert_eq!(
        fs::symlink_metadata(release_dir.join(".version"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[cfg(unix)]
#[test]
fn test_regression_create_dir_all_no_symlinks_preserves_existing_parent_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let sandbox = TempSandbox::new("preserve-parent-mode");
    let sticky_parent = sandbox.path().join("sticky-tmp");
    fs::create_dir_all(&sticky_parent).unwrap();
    fs::set_permissions(&sticky_parent, fs::Permissions::from_mode(0o1777)).unwrap();

    let child_dir = sticky_parent.join("nested-private");
    create_dir_all_no_symlinks(&child_dir, 0o750).unwrap();

    let parent_mode = fs::symlink_metadata(&sticky_parent)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(parent_mode, 0o1777);

    let child_mode = fs::symlink_metadata(&child_dir)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(child_mode, 0o750);
}
#[test]
fn default_release_asset_maps_known_architectures_and_falls_back_to_amd64() {
    assert_eq!(
        default_release_asset_for_arch("x86_64"),
        "aetherflow-linux-amd64.tar.gz"
    );
    assert_eq!(
        default_release_asset_for_arch("aarch64"),
        "aetherflow-linux-arm64.tar.gz"
    );
    assert_eq!(
        default_release_asset_for_arch("arm"),
        "aetherflow-linux-armv7.tar.gz"
    );
    assert_eq!(
        default_release_asset_for_arch("riscv64"),
        "aetherflow-linux-amd64.tar.gz"
    );
    assert_eq!(
        ReleaseConfig::default().artifact_name,
        default_release_asset_for_arch(std::env::consts::ARCH)
    );
}

#[test]
fn verify_deployed_frontend_assets_validates_web_dist_and_allows_binary_only_fixtures() {
    let sb = TempSandbox::new("verify-deployed-frontend");

    // 1. Binary-only fixture without `web/dist` passes cleanly
    let binary_only = sb.path().join("binary-only");
    fs::create_dir_all(&binary_only).unwrap();
    fs::write(binary_only.join("aetherflow-api"), b"bin").unwrap();
    verify_deployed_frontend_assets(&binary_only).unwrap();

    // 2. Valid `web/dist` with non-empty `index.html` and `.wasm` passes
    let valid = sb.path().join("valid-release");
    fs::create_dir_all(valid.join("web/dist")).unwrap();
    fs::write(valid.join("web/dist/index.html"), b"<html></html>").unwrap();
    fs::write(valid.join("web/dist/app.wasm"), b"\0asm\x01\0\0\0").unwrap();
    verify_deployed_frontend_assets(&valid).unwrap();

    // 3. `web/dist` with empty `index.html` fails
    let empty_index = sb.path().join("empty-index");
    fs::create_dir_all(empty_index.join("web/dist")).unwrap();
    fs::write(empty_index.join("web/dist/index.html"), b"").unwrap();
    fs::write(empty_index.join("web/dist/app.wasm"), b"wasm").unwrap();
    assert!(verify_deployed_frontend_assets(&empty_index).is_err());

    // 4. `web/dist` with missing or empty `.wasm` fails
    let empty_wasm = sb.path().join("empty-wasm");
    fs::create_dir_all(empty_wasm.join("web/dist")).unwrap();
    fs::write(empty_wasm.join("web/dist/index.html"), b"<html></html>").unwrap();
    fs::write(empty_wasm.join("web/dist/app.wasm"), b"").unwrap();
    assert!(verify_deployed_frontend_assets(&empty_wasm).is_err());
}

#[cfg(unix)]
#[test]
fn release_archive_supports_af_transcode_and_preserves_legacy_bundle_compatibility() {
    use std::os::unix::fs::PermissionsExt;

    let sb = TempSandbox::new("transcode-bundle-compat");
    let cfg = ReleaseConfig::for_root(sb.path());

    // 1. Modern release bundle containing bin/af-transcode gets 0755 permissions.
    let modern_archive = sb.path().join("modern-with-transcode.tar.gz");
    let (_, modern_manifest) = build_synthetic_release_tarball(
        &modern_archive,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"synthetic api", EntryType::Regular),
            ("bin/af", b"synthetic cli", EntryType::Regular),
            (
                "bin/speedtest-backend",
                b"synthetic speedtest",
                EntryType::Regular,
            ),
            (
                "bin/af-transcode",
                b"synthetic transcode",
                EntryType::Regular,
            ),
            (".version", b"v4.0.0\n", EntryType::Regular),
            (
                "web/dist/index.html",
                b"<html>app</html>",
                EntryType::Regular,
            ),
            ("web/dist/app.wasm", b"\0asm\x01\0\0\0", EntryType::Regular),
        ],
    );
    verify_artifact_checksum(&modern_archive, &modern_manifest, &cfg.artifact_name).unwrap();
    let modern_dir = sb.path().join("extract-modern");
    extract_and_validate_release_archive(&modern_archive, &modern_dir, "v4.0.0", &cfg).unwrap();
    let transcode_meta = fs::symlink_metadata(modern_dir.join("bin/af-transcode")).unwrap();
    assert_eq!(transcode_meta.permissions().mode() & 0o777, 0o755);
    assert!(!modern_dir.join("af-transcode").exists());

    // 2. Older legacy bundle omitting bin/af-transcode remains cleanly installable.
    let legacy_archive = sb.path().join("legacy-without-transcode.tar.gz");
    let (_, legacy_manifest) = build_synthetic_release_tarball(
        &legacy_archive,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"synthetic api", EntryType::Regular),
            ("bin/af", b"synthetic cli", EntryType::Regular),
            (
                "bin/speedtest-backend",
                b"synthetic speedtest",
                EntryType::Regular,
            ),
            (".version", b"v4.0.0\n", EntryType::Regular),
            (
                "web/dist/index.html",
                b"<html>app</html>",
                EntryType::Regular,
            ),
            ("web/dist/app.wasm", b"\0asm\x01\0\0\0", EntryType::Regular),
        ],
    );
    verify_artifact_checksum(&legacy_archive, &legacy_manifest, &cfg.artifact_name).unwrap();
    let legacy_dir = sb.path().join("extract-legacy");
    extract_and_validate_release_archive(&legacy_archive, &legacy_dir, "v4.0.0", &cfg).unwrap();
    assert!(!legacy_dir.join("bin/af-transcode").exists());
    assert_eq!(
        fs::symlink_metadata(legacy_dir.join("aetherflow-api"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );

    // 3. Offline simulation includes executable bin/af-transcode without a root duplicate.
    let offline_dir = sb.path().join("offline-sim");
    simulate_offline_artifact(&offline_dir, &cfg).unwrap();
    assert_eq!(
        fs::symlink_metadata(offline_dir.join("bin/af-transcode"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(!offline_dir.join("af-transcode").exists());
}

#[cfg(unix)]
#[test]
fn test_unified_env_file_precedence_redaction_and_root_only_provenance_bypass() {
    use std::os::unix::fs::PermissionsExt;

    let sb = TempSandbox::new("unified-env-precedence");
    let root = sb.path();
    let etc_dir = root.join("etc/aetherflow");
    fs::create_dir_all(&etc_dir).unwrap();
    let env_file = etc_dir.join("aetherflow.env");
    let secret_token = "ghp_synthetic_env_file_token_1234567890";
    fs::write(
        &env_file,
        format!(
            "HEALTH_ENDPOINT=http://127.0.0.1:9091/health/ready\n\
             AF_GITHUB_TOKEN={secret_token}\n\
             AETHERFLOW_SKIP_PROVENANCE_VERIFY=1\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&env_file, fs::Permissions::from_mode(0o600)).unwrap();

    // 1. Default-fallback release-manager.conf loses to aetherflow.env
    let default_conf = root.join("default-fallback.conf");
    fs::write(
        &default_conf,
        "HEALTH_ENDPOINT=\"${HEALTH_ENDPOINT:-http://127.0.0.1:8080/health/ready}\"\n",
    )
    .unwrap();
    let empty_env = HashMap::new();
    let cfg =
        ReleaseConfig::load_for_root_with_env(Some(root), Some(&default_conf), &empty_env).unwrap();
    assert_eq!(cfg.health_endpoint, "http://127.0.0.1:9091/health/ready");
    assert_eq!(cfg.github_auth_token_str(), Some(secret_token));
    assert!(
        cfg.skip_provenance_verify,
        "trusted 0600 isolated env file should enable skip_provenance_verify"
    );

    // 2. Redaction invariants: secret never appears in Debug, JSON Serialize, or serialized .conf
    let debug_out = format!("{cfg:?}");
    assert!(
        !debug_out.contains(secret_token),
        "Debug output must redact github_auth_token: {debug_out}"
    );
    assert!(debug_out.contains("[REDACTED]"));
    let json_out = serde_json::to_string(&cfg).unwrap();
    assert!(
        !json_out.contains(secret_token),
        "JSON serialization must skip github_auth_token"
    );
    let conf_out = cfg.to_serialized_conf_string();
    assert!(
        !conf_out.contains(secret_token) && !conf_out.contains("AETHERFLOW_SKIP_PROVENANCE_VERIFY"),
        "serialized conf must never persist secrets or provenance bypass"
    );

    // 3. Explicit --config assignment beats aetherflow.env, and process env beats explicit --config
    let explicit_conf = root.join("explicit.conf");
    fs::write(
        &explicit_conf,
        "HEALTH_ENDPOINT=\"http://127.0.0.1:8082/health/ready\"\n",
    )
    .unwrap();
    let cfg_explicit =
        ReleaseConfig::load_for_root_with_env(Some(root), Some(&explicit_conf), &empty_env)
            .unwrap();
    assert_eq!(
        cfg_explicit.health_endpoint,
        "http://127.0.0.1:8082/health/ready"
    );

    let mut proc_env = HashMap::new();
    proc_env.insert(
        "HEALTH_ENDPOINT".to_string(),
        "http://127.0.0.1:8083/health/ready".to_string(),
    );
    proc_env.insert(
        "GITHUB_TOKEN".to_string(),
        "ghp_proc_env_override_token".to_string(),
    );
    let cfg_proc =
        ReleaseConfig::load_for_root_with_env(Some(root), Some(&explicit_conf), &proc_env).unwrap();
    assert_eq!(
        cfg_proc.health_endpoint,
        "http://127.0.0.1:8083/health/ready"
    );
    assert_eq!(
        cfg_proc.github_auth_token_str(),
        Some("ghp_proc_env_override_token")
    );

    // 4. AETHERFLOW_SKIP_ENV_FILES=1 skips aetherflow.env and falls back to default-fallback conf
    let mut skip_env = HashMap::new();
    skip_env.insert("AETHERFLOW_SKIP_ENV_FILES".to_string(), "1".to_string());
    let cfg_skip =
        ReleaseConfig::load_for_root_with_env(Some(root), Some(&default_conf), &skip_env).unwrap();
    assert_eq!(
        cfg_skip.health_endpoint,
        "http://127.0.0.1:8080/health/ready"
    );
    assert_eq!(cfg_skip.github_auth_token_str(), None);
    assert!(!cfg_skip.skip_provenance_verify);

    // 5. Group-writable env file cannot enable AETHERFLOW_SKIP_PROVENANCE_VERIFY
    fs::set_permissions(&env_file, fs::Permissions::from_mode(0o660)).unwrap();
    let cfg_untrusted =
        ReleaseConfig::load_for_root_with_env(Some(root), Some(&default_conf), &empty_env).unwrap();
    assert!(
        !cfg_untrusted.skip_provenance_verify,
        "group-writable env file must not enable AETHERFLOW_SKIP_PROVENANCE_VERIFY"
    );
}

#[cfg(unix)]
#[test]
fn test_stage4_rollback_completes_when_log_retention_service_fails_and_logs_warn() {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let sb = TempSandbox::new("stage4-log-retention-resilience");
    let cfg = ReleaseConfig::for_root(sb.path());
    fs::create_dir_all(&cfg.releases_dir).unwrap();
    fs::create_dir_all(&cfg.data_dir).unwrap();
    fs::create_dir_all(&cfg.env_dir).unwrap();
    fs::create_dir_all(cfg.log_file.parent().unwrap()).unwrap();

    // Seed an active prior release and a healthy database
    let prev_dir = cfg.releases_dir.join("20261120000000");
    fs::create_dir_all(&prev_dir).unwrap();
    fs::write(prev_dir.join("aetherflow-api"), b"#!/bin/sh\nexit 0\n").unwrap();
    fs::write(prev_dir.join(".version"), b"v4.0.0\n").unwrap();
    std::os::unix::fs::symlink(&prev_dir, &cfg.current_link).unwrap();
    let db_path = cfg.data_dir.join(&cfg.sqlite_db);
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE items (id INTEGER PRIMARY KEY); INSERT INTO items VALUES (1);",
    )
    .unwrap();
    drop(conn);

    // Build a synthetic candidate release tarball that fails its health check to trigger Stage 4 rollback
    let tar_path = sb.path().join("candidate.tar.gz");
    let (_, manifest) = build_synthetic_release_tarball(
        &tar_path,
        &cfg.artifact_name,
        &[
            ("aetherflow-api", b"#!/bin/sh\nexit 0\n", EntryType::Regular),
            (".version", b"v4.0.1\n", EntryType::Regular),
            (
                "web/dist/index.html",
                b"<html>candidate</html>",
                EntryType::Regular,
            ),
            ("web/dist/app.wasm", b"\0asm\x01\0\0\0", EntryType::Regular),
        ],
    );
    let provider = super::MockArtifactProvider {
        resolved_tag: Ok("v4.0.1".to_string()),
        archive_source: tar_path,
        manifest_content: manifest,
    };

    // Fake systemctl shim that fails specifically on aetherflow-log-retention.service
    let fake_systemctl = sb.path().join("fake-systemctl");
    fs::write(
        &fake_systemctl,
        "#!/bin/sh\nfor a in \"$@\"; do\n  if [ \"$a\" = \"aetherflow-log-retention.service\" ]; then\n    echo 'simulated log-retention failure' >&2\n    exit 1\n  fi\ndone\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&fake_systemctl, fs::Permissions::from_mode(0o755)).unwrap();

    struct FailingLogRetentionLifecycle {
        fake_systemctl: PathBuf,
    }
    impl LifecycleController for FailingLogRetentionLifecycle {
        fn query_unit_environment(&self, _unit: &str) -> Option<String> {
            None
        }
        fn restart_systemd_units(&self, config: &ReleaseConfig) -> ReleaseResult<()> {
            run_post_restart_log_retention_with_bin(&self.fake_systemctl, config, true);
            Ok(())
        }
        fn stop_database_services(&self, _db_path: &std::path::Path) -> ReleaseResult<()> {
            Ok(())
        }
        fn terminate_legacy_pm2(&self) -> ReleaseResult<()> {
            Ok(())
        }
    }

    // Fail the candidate health probe (triggering Stage 4 rollback), then pass on rollback verification
    struct FailFirstThenHealthyProber {
        calls: AtomicUsize,
    }
    impl HealthProber for FailFirstThenHealthyProber {
        fn check_once(&self, _endpoint: &str) -> ReleaseResult<HealthCheckAttempt> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Ok(HealthCheckAttempt {
                    http_status: 503,
                    body: r#"{"status":"unhealthy"}"#.to_string(),
                })
            } else {
                Ok(HealthCheckAttempt {
                    http_status: 200,
                    body: r#"{"status":"ready"}"#.to_string(),
                })
            }
        }
    }

    let mut test_cfg = cfg.clone();
    test_cfg.health_retries = 1;
    test_cfg.health_interval = std::time::Duration::from_millis(1);

    let engine = ReleaseEngine::new(
        test_cfg.clone(),
        provider,
        FailingLogRetentionLifecycle { fake_systemctl },
        FailFirstThenHealthyProber {
            calls: AtomicUsize::new(0),
        },
    );

    let err = engine
        .execute(&ReleaseOptions {
            command: ReleaseCommand::Deploy,
            channel: ReleaseChannel::Stable,
            dry_run: false,
            offline: false,
            from_source: false,
        })
        .expect_err("expected probe failure followed by clean Stage 4 rollback");
    assert_eq!(
        err.exit_code(),
        ExitCode::HealthProbeFailedRollback,
        "Stage 4 rollback must succeed even when aetherflow-log-retention.service fails; got: {err}"
    );
    assert_eq!(
        fs::read_link(&test_cfg.current_link).unwrap(),
        prev_dir,
        "current symlink must be restored to prior release after Stage 4 rollback"
    );
    let log_text = fs::read_to_string(&test_cfg.log_file).unwrap();
    assert!(
        log_text.contains("\"level\":\"WARN\"")
            && log_text.contains("aetherflow-log-retention.service")
            && log_text.contains("simulated log-retention failure"),
        "structured JSONL log must record WARN for best-effort log-retention failure: {log_text}"
    );
}
