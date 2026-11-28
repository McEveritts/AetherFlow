use super::archive::validate_external_frontend_assets;
use super::provider::is_trusted_github_auth_url;
use super::*;
use crate::config::ReleaseConfig;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};

struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn create_isolated_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "af_release_stage_test_{}_{}_{}",
        label,
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    fs::create_dir_all(&root).expect("create isolated test root");
    root
}

fn base_config(root: &Path) -> ReleaseConfig {
    let cfg = ReleaseConfig {
        releases_dir: root.join("releases"),
        current_link: root.join("current"),
        ..ReleaseConfig::default()
    };
    fs::create_dir_all(&cfg.releases_dir).expect("create releases_dir");
    cfg
}

#[test]
fn external_frontend_validation_rejects_symlinked_components() {
    let root = create_isolated_root("frontend-symlinks");
    let _cleanup = Cleanup(root.clone());
    for component in [
        "web",
        "web/dist",
        "web/dist/index.html",
        "web/dist/app.wasm",
    ] {
        let case = root.join(component.replace('/', "-"));
        let release = case.join("release");
        let dist = release.join("web/dist");
        fs::create_dir_all(&dist).unwrap();
        fs::write(dist.join("index.html"), b"synthetic index").unwrap();
        fs::write(dist.join("app.wasm"), b"synthetic wasm").unwrap();

        let link = release.join(component);
        let target = case.join("synthetic-target");
        fs::rename(&link, &target).unwrap();
        symlink(&target, &link).unwrap();
        let err = validate_external_frontend_assets(&release).expect_err(component);
        assert!(
            matches!(&err, ReleaseError::ArtifactVerification(_)),
            "{component}: {err}"
        );
    }
}

#[test]
fn offline_frontend_placeholders_are_not_deployable_assets() {
    let root = create_isolated_root("offline-frontend-placeholder");
    let _cleanup = Cleanup(root.clone());
    let release = root.join("release");
    let cfg = ReleaseConfig::for_root(&root);

    let expected_dryrun_version = format!(
        "{}-dryrun",
        crate::runtime::runtime_identity().version.trim()
    );
    assert_eq!(
        simulate_offline_artifact(&release, &cfg).unwrap(),
        expected_dryrun_version
    );
    let err = validate_external_frontend_assets(&release)
        .expect_err("dry-run assets must not qualify as a deployable frontend");
    assert!(
        matches!(&err, ReleaseError::ArtifactVerification(message) if message.contains("*.wasm"))
    );
}

#[test]
fn test_stage_running_release_manager_normal_non_symlink_paths() {
    let root = create_isolated_root("normal");
    let mut cfg = base_config(&root);

    let host_deploy = root.join("deploy");
    fs::create_dir_all(&host_deploy).unwrap();
    let script_src = host_deploy.join("release-manager.sh");
    let conf_src = host_deploy.join("release-manager.conf");
    fs::write(&script_src, b"#!/usr/bin/env bash\necho normal\n").unwrap();
    fs::write(&conf_src, b"RELEASE_CHANNEL=experimental\n").unwrap();

    cfg.stage_script_path = Some(script_src);
    cfg.stage_conf_path = Some(conf_src);

    let next_release = cfg.releases_dir.join("v4-next");
    fs::create_dir_all(&next_release).unwrap();

    stage_running_release_manager(&next_release, &cfg).expect("stage normal paths");

    let staged_script = next_release.join("deploy/release-manager.sh");
    let staged_conf = next_release.join("deploy/release-manager.conf");
    assert_eq!(
        fs::read_to_string(&staged_script).unwrap(),
        "#!/usr/bin/env bash\necho normal\n"
    );
    assert_eq!(
        fs::read_to_string(&staged_conf).unwrap(),
        "RELEASE_CHANNEL=experimental\n"
    );
    let script_mode = fs::symlink_metadata(&staged_script)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        script_mode & 0o111,
        0o111,
        "staged script must be executable"
    );

    let staged_verifier = next_release.join("deploy/verify-provenance.py");
    assert!(
        staged_verifier.is_file(),
        "verify-provenance.py must be staged alongside release-manager.sh"
    );
    let verifier_mode = fs::symlink_metadata(&staged_verifier)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        verifier_mode & 0o111,
        0o111,
        "staged verify-provenance.py must be executable"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_stage_running_release_manager_resolves_managed_current_symlink() {
    let root = create_isolated_root("managed_symlink");
    let mut cfg = base_config(&root);

    let active_release = cfg.releases_dir.join("v4-experimental-89017a6-1793518346");
    let active_deploy = active_release.join("deploy");
    fs::create_dir_all(&active_deploy).unwrap();
    fs::write(
        active_deploy.join("release-manager.sh"),
        b"#!/usr/bin/env bash\necho from-current\n",
    )
    .unwrap();
    fs::write(
        active_deploy.join("release-manager.conf"),
        b"RELEASE_CHANNEL=experimental\n",
    )
    .unwrap();

    // Point managed current_link -> active_release
    symlink(&active_release, &cfg.current_link).unwrap();

    // Configure staging sources through /opt/AetherFlow/current/deploy/...
    cfg.stage_script_path = Some(cfg.current_link.join("deploy/release-manager.sh"));
    cfg.stage_conf_path = Some(cfg.current_link.join("deploy/release-manager.conf"));

    let candidate_release = cfg.releases_dir.join("v4-experimental-candidate");
    fs::create_dir_all(&candidate_release).unwrap();

    stage_running_release_manager(&candidate_release, &cfg)
        .expect("stage through managed current symlink must succeed");

    let staged_script = candidate_release.join("deploy/release-manager.sh");
    let staged_conf = candidate_release.join("deploy/release-manager.conf");
    assert_eq!(
        fs::read_to_string(&staged_script).unwrap(),
        "#!/usr/bin/env bash\necho from-current\n"
    );
    assert_eq!(
        fs::read_to_string(&staged_conf).unwrap(),
        "RELEASE_CHANNEL=experimental\n"
    );
    let script_mode = fs::symlink_metadata(&staged_script)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(script_mode & 0o111, 0o111);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_stage_running_release_manager_rejects_outside_root_and_untrusted_symlinks() {
    let root = create_isolated_root("reject_escapes");
    let mut cfg = base_config(&root);

    // 1. Malicious current_link pointing outside releases_dir
    let outside_dir = root.join("outside_escape");
    fs::create_dir_all(outside_dir.join("deploy")).unwrap();
    fs::write(
        outside_dir.join("deploy/release-manager.sh"),
        b"#!/bin/sh\necho pwned\n",
    )
    .unwrap();
    symlink(&outside_dir, &cfg.current_link).unwrap();

    cfg.stage_script_path = Some(cfg.current_link.join("deploy/release-manager.sh"));
    let candidate_release = cfg.releases_dir.join("v4-candidate-1");
    fs::create_dir_all(&candidate_release).unwrap();

    let err = stage_running_release_manager(&candidate_release, &cfg)
        .expect_err("must reject current_link pointing outside releases_dir");
    assert!(matches!(err, ReleaseError::PathValidation { .. }));

    // 2. Valid current_link, but nested symlink inside active release deploy/
    fs::remove_file(&cfg.current_link).unwrap();
    let active_release = cfg.releases_dir.join("v4-active");
    fs::create_dir_all(active_release.join("deploy")).unwrap();
    symlink(
        outside_dir.join("deploy/release-manager.sh"),
        active_release.join("deploy/release-manager.sh"),
    )
    .unwrap();
    symlink(&active_release, &cfg.current_link).unwrap();

    let err_nested = stage_running_release_manager(&candidate_release, &cfg)
        .expect_err("must reject nested symlink inside active release");
    assert!(matches!(err_nested, ReleaseError::PathValidation { .. }));

    // 3. Untrusted symlink ancestor outside current_link
    let untrusted_link = root.join("untrusted_deploy_link");
    symlink(outside_dir.join("deploy"), &untrusted_link).unwrap();
    cfg.stage_script_path = Some(untrusted_link.join("release-manager.sh"));

    let err_untrusted = stage_running_release_manager(&candidate_release, &cfg)
        .expect_err("must reject untrusted symlink ancestor");
    assert!(matches!(err_untrusted, ReleaseError::PathValidation { .. }));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_stage_running_release_manager_missing_source_files_is_noop() {
    let root = create_isolated_root("missing_noop");
    let mut cfg = base_config(&root);

    let active_release = cfg.releases_dir.join("v4-active");
    fs::create_dir_all(&active_release).unwrap();
    symlink(&active_release, &cfg.current_link).unwrap();

    cfg.stage_script_path = Some(cfg.current_link.join("deploy/release-manager.sh"));
    cfg.stage_conf_path = Some(root.join("nonexistent/release-manager.conf"));

    let candidate_release = cfg.releases_dir.join("v4-candidate");
    fs::create_dir_all(&candidate_release).unwrap();

    stage_running_release_manager(&candidate_release, &cfg)
        .expect("missing optional source files should be a clean no-op");
    assert!(!candidate_release.join("deploy/release-manager.sh").exists());
    assert!(!candidate_release
        .join("deploy/verify-provenance.py")
        .exists());
    assert!(!candidate_release
        .join("deploy/release-manager.conf")
        .exists());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_verify_release_provenance_accepts_real_sigstore_bundle_and_rejects_tag_replay() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/sigstore_bundle_nightly_109_1.json");
    let digest = "018a270e2833886b1c59e2f831912c794e2ed66dacf6c2249ab1390fc2d44b26";
    verify_release_provenance(
        "McEveritts/AetherFlow",
        digest,
        "aetherflow-linux-amd64.tar.gz",
        Some("v4.0.0-nightly.109.1"),
        Some(ReleaseChannel::Nightly),
        Some(&fixture),
    )
    .expect("real nightly.109.1 Sigstore bundle must pass verification");

    let replay_err = verify_release_provenance(
        "McEveritts/AetherFlow",
        digest,
        "aetherflow-linux-amd64.tar.gz",
        Some("v4.0.0"),
        Some(ReleaseChannel::Stable),
        Some(&fixture),
    )
    .expect_err("replaying nightly bundle under stable v4.0.0 must fail closed");
    assert!(matches!(replay_err, ReleaseError::ArtifactVerification(_)));
}

#[test]
fn test_round3_strict_nightly_tag_gate_and_trusted_github_auth_host() {
    assert!(is_v4_nightly_release_tag("v4.0.0-nightly.110.1"));
    assert!(is_v4_nightly_release_tag("v4.1.2-Nightly.7"));
    assert!(!is_v4_nightly_release_tag("v4.9.0-rc.1"));
    assert!(!is_v4_nightly_release_tag("v4.0.0-beta.1"));
    assert!(!is_v4_nightly_release_tag("v4.0.0"));
    assert!(!is_v4_nightly_release_tag("v3.2.7-nightly.1.1"));

    let https_api =
        reqwest::Url::parse("https://api.github.com/repos/McEveritts/AetherFlow/releases").unwrap();
    let https_gh =
        reqwest::Url::parse("https://github.com/McEveritts/AetherFlow/releases/latest").unwrap();
    let https_obj = reqwest::Url::parse(
        "https://objects.githubusercontent.com/github-production-release-asset/foo",
    )
    .unwrap();
    let http_downgrade =
        reqwest::Url::parse("http://api.github.com/repos/McEveritts/AetherFlow/releases").unwrap();
    let untrusted_host =
        reqwest::Url::parse("https://evil-mirror.example.com/aetherflow.tar.gz").unwrap();

    assert!(is_trusted_github_auth_url(&https_api));
    assert!(is_trusted_github_auth_url(&https_gh));
    assert!(is_trusted_github_auth_url(&https_obj));
    assert!(!is_trusted_github_auth_url(&http_downgrade));
    assert!(!is_trusted_github_auth_url(&untrusted_host));
}

#[test]
fn test_round7_stage_running_release_manager_preserves_candidate_scripts() {
    let root = create_isolated_root("preserve_candidate_scripts");
    let mut cfg = base_config(&root);

    let active_release = cfg.releases_dir.join("v4-active-old");
    fs::create_dir_all(active_release.join("deploy")).unwrap();
    fs::write(
        active_release.join("deploy/release-manager.sh"),
        b"#!/usr/bin/env bash\necho old-active-rm\n",
    )
    .unwrap();
    fs::write(
        active_release.join("deploy/verify-provenance.py"),
        b"#!/usr/bin/env python3\n# old-active-vp\n",
    )
    .unwrap();
    fs::write(
        active_release.join("deploy/log-retention.py"),
        b"#!/usr/bin/env python3\n# backfilled-lr\n",
    )
    .unwrap();
    fs::write(
        active_release.join("deploy/release-manager.conf"),
        b"RELEASE_CHANNEL=nightly\n",
    )
    .unwrap();
    symlink(&active_release, &cfg.current_link).unwrap();

    cfg.stage_script_path = Some(cfg.current_link.join("deploy/release-manager.sh"));
    cfg.stage_conf_path = Some(cfg.current_link.join("deploy/release-manager.conf"));

    let candidate_release = cfg.releases_dir.join("v4-candidate-new");
    fs::create_dir_all(candidate_release.join("deploy")).unwrap();
    fs::write(
        candidate_release.join("deploy/release-manager.sh"),
        b"#!/usr/bin/env bash\necho new-candidate-rm\n",
    )
    .unwrap();
    fs::write(
        candidate_release.join("deploy/verify-provenance.py"),
        b"#!/usr/bin/env python3\n# new-candidate-vp\n",
    )
    .unwrap();

    stage_running_release_manager(&candidate_release, &cfg)
        .expect("staging must preserve candidate scripts and backfill missing helpers");

    assert_eq!(
        fs::read_to_string(candidate_release.join("deploy/release-manager.sh")).unwrap(),
        "#!/usr/bin/env bash\necho new-candidate-rm\n"
    );
    assert_eq!(
        fs::read_to_string(candidate_release.join("deploy/verify-provenance.py")).unwrap(),
        "#!/usr/bin/env python3\n# new-candidate-vp\n"
    );
    assert_eq!(
        fs::read_to_string(candidate_release.join("deploy/log-retention.py")).unwrap(),
        "#!/usr/bin/env python3\n# backfilled-lr\n"
    );
    assert_eq!(
        fs::read_to_string(candidate_release.join("deploy/release-manager.conf")).unwrap(),
        "RELEASE_CHANNEL=nightly\n"
    );

    for rel in [
        "deploy/release-manager.sh",
        "deploy/verify-provenance.py",
        "deploy/log-retention.py",
    ] {
        let mode = fs::symlink_metadata(candidate_release.join(rel))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755, "{} must have executable 0755 mode", rel);
    }

    let _ = fs::remove_dir_all(&root);
}
