use super::*;

fn merged_usr_aliases(root: &std::path::Path) {
    for alias in ["bin", "sbin", "lib", "lib32", "lib64", "libx32"] {
        let real_dir = root.join("usr").join(alias);
        std::fs::create_dir_all(&real_dir).unwrap();
        std::os::unix::fs::symlink(format!("usr/{alias}"), root.join(alias)).unwrap();
    }
}

fn sonarr_runtime_snap_dirs_in(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    if let Ok(rd) = std::fs::read_dir(root) {
        for ent in rd.flatten() {
            if ent
                .file_name()
                .to_string_lossy()
                .starts_with(".af-rt-snap-sonarr-")
            {
                found.push(ent.path());
            }
        }
    }
    found.sort();
    found
}

#[test]
fn test_wave23_large_sparse_mutable_database_restored_on_mutation_and_deletion() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w23-sparse-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let sonarr_db_dir = temp_dir.join("var/lib/sonarr");
    std::fs::create_dir_all(&sonarr_db_dir).unwrap();
    let db_file = sonarr_db_dir.join("sonarr.db");

    let file_len: u64 = 268_435_457; // 256 MiB + 1
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::File::create(&db_file).unwrap();
        f.write_all(b"OLD_DB01").unwrap();
        f.seek(SeekFrom::Start(file_len - 8)).unwrap();
        f.write_all(b"TRAIL001").unwrap();
        f.set_len(file_len).unwrap();
    }

    // Test part (a): Mutation
    {
        let mut snap = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&db_file)
                .unwrap();
            f.write_all(b"NEW_DB02").unwrap();
            f.seek(SeekFrom::Start(file_len - 8)).unwrap();
            f.write_all(b"TRAILNEW").unwrap();
        }
        assert_eq!(&std::fs::read(&db_file).unwrap()[..8], b"NEW_DB02");

        snap.restore().expect("restore must succeed");

        let restored_meta = std::fs::metadata(&db_file).unwrap();
        assert_eq!(restored_meta.len(), file_len);
        let mut f = std::fs::File::open(&db_file).unwrap();
        let mut head = [0u8; 8];
        use std::io::{Read, Seek, SeekFrom};
        f.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"OLD_DB01");
        f.seek(SeekFrom::Start(file_len - 8)).unwrap();
        let mut tail = [0u8; 8];
        f.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, b"TRAIL001");
    }

    // Test part (b): Deletion
    {
        let mut snap = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();
        std::fs::remove_file(&db_file).unwrap();
        assert!(!db_file.exists());

        snap.restore().expect("restore must succeed");

        assert!(db_file.exists(), "Deleted sonarr.db must be restored");
        let restored_meta = std::fs::metadata(&db_file).unwrap();
        assert_eq!(restored_meta.len(), file_len);
        let mut f = std::fs::File::open(&db_file).unwrap();
        let mut head = [0u8; 8];
        use std::io::{Read, Seek, SeekFrom};
        f.read_exact(&mut head).unwrap();
        assert_eq!(&head, b"OLD_DB01");
        f.seek(SeekFrom::Start(file_len - 8)).unwrap();
        let mut tail = [0u8; 8];
        f.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, b"TRAIL001");
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave23_catalog_footprint_plex_and_mcvnc_unit_restoration() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w23-footprint-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    // Plex footprint: /usr/lib/plexmediaserver/Plex Media Server and /var/lib/plexmediaserver/library.db
    let plex_lib = temp_dir.join("usr/lib/plexmediaserver");
    let plex_var = temp_dir.join("var/lib/plexmediaserver");
    std::fs::create_dir_all(&plex_lib).unwrap();
    std::fs::create_dir_all(&plex_var).unwrap();
    let plex_bin = plex_lib.join("Plex Media Server");
    let plex_db = plex_var.join("library.db");
    std::fs::write(&plex_bin, b"OLD_PLEX_BIN").unwrap();
    std::fs::write(&plex_db, b"OLD_PLEX_DB").unwrap();

    let mut plex_snap = PackageRuntimeSnapshot::capture(
        "plex",
        &["plexmediaserver.service".into()],
        &env_cfg,
        false,
    )
    .unwrap();

    std::fs::write(&plex_bin, b"NEW_PLEX_BIN").unwrap();
    std::fs::write(&plex_db, b"NEW_PLEX_DB").unwrap();
    plex_snap.restore().expect("plex restore must succeed");

    assert_eq!(std::fs::read(&plex_bin).unwrap(), b"OLD_PLEX_BIN");
    assert_eq!(std::fs::read(&plex_db).unwrap(), b"OLD_PLEX_DB");

    // Mcvnc footprint: aliased unit /etc/systemd/system/af-mcvnc.service
    let sysd_dir = temp_dir.join("etc/systemd/system");
    std::fs::create_dir_all(&sysd_dir).unwrap();
    let mcvnc_unit = sysd_dir.join("af-mcvnc.service");
    std::fs::write(&mcvnc_unit, b"OLD_UNIT").unwrap();

    // Capture with &[] units (catalog expands mcvnc -> af-mcvnc.service)
    let mut mcvnc_snap = PackageRuntimeSnapshot::capture("mcvnc", &[], &env_cfg, false).unwrap();
    std::fs::write(&mcvnc_unit, b"NEW_UNIT").unwrap();
    mcvnc_snap.restore().expect("mcvnc restore must succeed");
    assert_eq!(std::fs::read(&mcvnc_unit).unwrap(), b"OLD_UNIT");

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave23_runtime_restore_failure_never_rewinds_embedded_receipt() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w23-receipt-gate-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let opt_sonarr = temp_dir.join("opt/sonarr");
    let var_lib_sonarr = temp_dir.join("var/lib/sonarr");
    std::fs::create_dir_all(&opt_sonarr).unwrap();
    std::fs::create_dir_all(&var_lib_sonarr).unwrap();

    let receipt_file = opt_sonarr.join(".af-version");
    let bin_file = opt_sonarr.join("Sonarr");
    std::fs::write(&receipt_file, b"1.0.0\n").unwrap();
    std::fs::write(&bin_file, b"old").unwrap();

    let mut rt = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false).unwrap();

    // Mutate receipt to 2.0.0 and binary to "new"
    std::fs::write(&receipt_file, b"2.0.0\n").unwrap();
    std::fs::write(&bin_file, b"new").unwrap();

    // Replace var/lib with a regular file blocker to cause Phase 1 preflight failure
    let var_dir = temp_dir.join("var");
    let var_lib = var_dir.join("lib");
    std::fs::remove_dir_all(&var_lib).unwrap();
    std::fs::write(&var_lib, b"blocking regular file").unwrap();

    // Direct rt.restore() must fail
    let res = rt.restore();
    assert!(
        res.is_err(),
        "rt.restore must fail when ancestor is blocked"
    );

    // .af-version MUST still be "2.0.0\n" (never rewound to 1.0.0!)
    let current_receipt = std::fs::read_to_string(&receipt_file).unwrap();
    assert_eq!(
        current_receipt, "2.0.0\n",
        "Receipt must NOT be rewound when runtime restore fails!"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave24_merged_usr_catalog_capture_and_restore() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w24-merged-usr-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).unwrap();
    merged_usr_aliases(&temp_dir);
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let packages_json = manifest_dir.join("../../../config/packages.json");
    let raw = std::fs::read_to_string(&packages_json)
        .unwrap_or_else(|e| panic!("read {}: {e}", packages_json.display()));
    let catalog: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
    let names: Vec<String> = catalog
        .iter()
        .filter_map(|pkg| {
            pkg.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    assert!(
        names.len() >= 70,
        "expected the full catalog, found {}",
        names.len()
    );

    let mut failures = Vec::new();
    for name in &names {
        if let Err(err) = PackageRuntimeSnapshot::capture(name, &[], &env_cfg, false) {
            failures.push(format!("{name}: {err}"));
        }
    }
    assert!(
        failures.is_empty(),
        "merged-/usr capture failures ({}): {failures:?}",
        failures.len()
    );

    let unit_dir = temp_dir.join("usr/lib/systemd/system");
    std::fs::create_dir_all(&unit_dir).unwrap();
    let unit = unit_dir.join("sonarr.service");
    std::fs::write(&unit, b"OLD_UNIT").unwrap();
    let opt_bin = temp_dir.join("opt/sonarr/Sonarr");
    std::fs::create_dir_all(opt_bin.parent().unwrap()).unwrap();
    std::fs::write(&opt_bin, b"OLD_BIN").unwrap();

    let mut snap =
        PackageRuntimeSnapshot::capture("sonarr", &["sonarr.service".into()], &env_cfg, false)
            .expect("sonarr capture on merged-/usr");
    let lib_prefix = temp_dir.join("lib");
    for entry in &snap.entries {
        let target = match entry {
            RuntimeSnapshotEntry::Absent { target_path, .. }
            | RuntimeSnapshotEntry::File { target_path, .. }
            | RuntimeSnapshotEntry::Symlink { target_path, .. }
            | RuntimeSnapshotEntry::Directory { target_path, .. } => target_path,
        };
        assert!(
            !target.starts_with(&lib_prefix),
            "merged-/usr target was not rewritten onto /usr: {}",
            target.display()
        );
    }
    std::fs::write(&unit, b"NEW_UNIT").unwrap();
    std::fs::write(&opt_bin, b"NEW_BIN").unwrap();
    snap.restore().expect("merged-/usr restore");
    assert_eq!(std::fs::read(&unit).unwrap(), b"OLD_UNIT");
    assert_eq!(std::fs::read(&opt_bin).unwrap(), b"OLD_BIN");

    let untrusted = temp_dir.join("untrusted-opt");
    std::fs::create_dir_all(untrusted.join("usr/opt")).unwrap();
    std::os::unix::fs::symlink("usr/opt", untrusted.join("opt")).unwrap();
    let mut bad_env = crate::PackageExecutionEnv::default();
    bad_env.fs_root = Some(untrusted);
    let bad = PackageRuntimeSnapshot::capture("sonarr", &[], &bad_env, false);
    assert!(
        bad.unwrap_err().contains("is a symlink"),
        "non-merged-usr symlinks must still fail closed"
    );

    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave24_installer_footprint_round_trip() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w24-footprint-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());

    let files = [
        (
            "grafana",
            "usr/share/grafana/public/build/app.js",
            "OLD_GRAFANA",
        ),
        (
            "jellyfin",
            "usr/share/jellyfin/web/index.html",
            "OLD_JELLYFIN",
        ),
        ("netdata", "usr/sbin/netdata", "OLD_NETDATA_BIN"),
        (
            "netdata",
            "usr/libexec/netdata/plugins.d/apps.plugin",
            "OLD_NETDATA_PLUGIN",
        ),
        ("kasmvnc", "usr/share/kasmvnc/www/vnc.html", "OLD_KASM_WWW"),
        ("kasmvnc", "usr/bin/Xvnc", "OLD_XVNC"),
    ];
    for (_, rel, body) in files {
        let path = temp_dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, body.as_bytes()).unwrap();
    }

    let mut snaps = Vec::new();
    for pkg in ["grafana", "jellyfin", "netdata", "kasmvnc"] {
        snaps.push((
            pkg,
            PackageRuntimeSnapshot::capture(pkg, &[], &env_cfg, false)
                .unwrap_or_else(|e| panic!("{pkg} capture failed: {e}")),
        ));
    }
    for (_, rel, _) in files {
        let path = temp_dir.join(rel);
        std::fs::write(&path, b"NEW").unwrap();
    }
    for (pkg, mut snap) in snaps {
        snap.restore()
            .unwrap_or_else(|e| panic!("{pkg} restore failed: {e}"));
    }
    for (_, rel, body) in files {
        let path = temp_dir.join(rel);
        assert_eq!(
            std::fs::read(&path).unwrap(),
            body.as_bytes(),
            "round-trip failed for {}",
            path.display()
        );
    }
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave24_unreadable_database_never_yields_partial_snapshot() {
    let temp_dir = std::env::temp_dir().join(format!("af-test-w24-perm-{}", uuid::Uuid::new_v4()));
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());
    let db_dir = temp_dir.join("var/lib/sonarr");
    std::fs::create_dir_all(&db_dir).unwrap();
    let protected = db_dir.join("protected.db");
    std::fs::write(&protected, b"SECRETDB").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o000)).unwrap();

    let euid = unsafe { libc::geteuid() };
    for ignore in [true, false] {
        let captured = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, ignore);
        if euid != 0 {
            let err = captured.expect_err("unreadable database must fail capture");
            assert!(
                err.to_ascii_lowercase().contains("permission"),
                "ignore={ignore} error should be permission denied, got {err}"
            );
            let meta = std::fs::symlink_metadata(&protected)
                .expect("unreadable database must remain on disk");
            assert!(meta.is_file());
            assert_eq!(meta.len(), b"SECRETDB".len() as u64);
            std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(std::fs::read(&protected).unwrap(), b"SECRETDB");
            std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o000)).unwrap();
        } else {
            let mut snap = captured.expect("root can read mode 000");
            std::fs::remove_file(&protected).unwrap();
            snap.restore().expect("root restore keeps the database");
            assert_eq!(std::fs::read(&protected).unwrap(), b"SECRETDB");
            std::fs::write(&protected, b"SECRETDB").unwrap();
            std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
    }
    let _ = std::fs::set_permissions(&protected, std::fs::Permissions::from_mode(0o644));
    let _ = std::fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_wave25_capture_failure_drops_orphan_backup_root() {
    let temp_dir =
        std::env::temp_dir().join(format!("af-test-w25-orphan-{}", uuid::Uuid::new_v4()));
    let snap_recovery = temp_dir.join("var/backups/aetherflow-recovery");
    let snap_staging = temp_dir.join("snap-tmp");
    std::fs::create_dir_all(&snap_staging).unwrap();
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(temp_dir.clone());
    env_cfg.temp_dir = snap_staging.clone();
    env_cfg.recovery_root = Some(snap_recovery.clone());
    let opt = temp_dir.join("opt/sonarr");
    let ro_sub = opt.join("ro-bin");
    let etc = temp_dir.join("etc/sonarr");
    std::fs::create_dir_all(&ro_sub).unwrap();
    std::fs::create_dir_all(&etc).unwrap();
    let readable = opt.join("readable.db");
    let ro_nested = ro_sub.join("helper.bin");
    let unreadable = etc.join("unreadable.db");
    {
        let file = std::fs::File::create(&readable).unwrap();
        file.set_len(1024 * 1024).unwrap();
    }
    std::fs::write(&ro_nested, b"RO_HELPER").unwrap();
    std::fs::write(&unreadable, b"SECRETDB").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&ro_sub, std::fs::Permissions::from_mode(0o500)).unwrap();
    let etc_parent = temp_dir.join("etc");
    let etc_real = temp_dir.join("etc-real");
    std::fs::rename(&etc_parent, &etc_real).unwrap();
    std::os::unix::fs::symlink(&etc_real, &etc_parent).unwrap();
    let err = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
        .expect_err("symlink ancestor must fail capture even as root");
    assert!(
        err.to_ascii_lowercase().contains("symlink"),
        "unexpected capture failure: {err}"
    );
    assert!(
        err.contains("/etc"),
        "failure must follow capture of /opt/sonarr: {err}"
    );
    let after = sonarr_runtime_snap_dirs_in(&snap_recovery);
    assert!(
        after.is_empty(),
        "capture failure left orphaned snapshot directories: {after:?}"
    );
    assert!(
        sonarr_runtime_snap_dirs_in(&snap_staging).is_empty(),
        "capture must not place snapshots under disposable temp_dir"
    );

    std::fs::remove_file(&etc_parent).unwrap();
    std::fs::rename(&etc_real, &etc_parent).unwrap();
    let mut snap = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
        .expect("readable tree captures");
    let preserved = snap.backup_root.clone();
    assert!(preserved.is_dir(), "backup_root must exist before restore");
    assert!(
        preserved.starts_with(&snap_recovery),
        "capture must honor env_cfg.recovery_root ({}) -> got {}",
        snap_recovery.display(),
        preserved.display()
    );
    std::fs::set_permissions(&ro_sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    let opt_parent = temp_dir.join("opt");
    std::fs::remove_dir_all(&opt).unwrap();
    std::fs::remove_dir_all(&opt_parent).unwrap();
    std::fs::write(&opt_parent, b"not-a-directory").unwrap();
    let restore_err = snap
        .restore()
        .expect_err("non-directory ancestor must fail restore");
    assert!(
        snap.preserve_on_drop,
        "incomplete restore must preserve backup_root, err={restore_err}"
    );
    drop(snap);
    assert!(
        preserved.is_dir(),
        "preserve_on_drop must keep {} after Drop",
        preserved.display()
    );
    force_remove_backup_tree(&preserved);
    let _ = std::fs::remove_file(&opt_parent);
    let _ = std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644));
    force_remove_backup_tree(&temp_dir);
}

#[cfg(unix)]
#[test]
fn test_durable_recovery_storage_privileged_policy_validation() {
    use std::os::unix::fs::PermissionsExt;

    let current_uid = unsafe { libc::geteuid() };
    let base = std::env::temp_dir().join(format!(
        "af-durable-recovery-policy-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&base).unwrap();
    let fixture = base.join("fixture");
    std::fs::create_dir_all(&fixture).unwrap();
    let staging = base.join("disposable-staging");
    std::fs::create_dir_all(&staging).unwrap();

    let priv_policy = RecoveryStoragePolicy {
        privileged: true,
        expected_uid: current_uid,
    };

    // 1. Isolated fixture with default recovery_root creates private 0700 dirs under
    //    <fixture>/var/backups/aetherflow-recovery and leaves disposable temp_dir untouched.
    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = Some(fixture.clone());
    env_cfg.temp_dir = staging.clone();
    env_cfg.recovery_root = None;
    let created = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-policy1",
        &env_cfg,
        priv_policy,
        None,
    )
    .expect("isolated fixture privileged recovery root should succeed");
    let expected_recovery_root = fixture.join("var/backups/aetherflow-recovery");
    assert_eq!(created.parent(), Some(expected_recovery_root.as_path()));
    assert_eq!(
        std::fs::symlink_metadata(&expected_recovery_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        std::fs::symlink_metadata(&created)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o700
    );
    assert_eq!(
        std::fs::read_dir(&staging).unwrap().count(),
        0,
        "disposable temp_dir must stay untouched"
    );

    // 2. Reject ephemeral tmp/run roots, protected roots, relative paths, and parent traversal.
    for bad_root in [
        fixture.join("tmp/af-snap"),
        fixture.join("var/tmp/af-snap"),
        fixture.join("var/tmp/aetherflow-scratch"),
        fixture.join("dev/shm/af-snap"),
        fixture.join("run/af-snap"),
        fixture.join("var/run/af-snap"),
        fixture.join("var/backups"),
        fixture.join("var"),
        fixture.join("var/backups/../tmp/af-snap"),
        PathBuf::from("relative/recovery"),
    ] {
        let mut bad_env = env_cfg.clone();
        bad_env.recovery_root = Some(bad_root.clone());
        let err = prepare_runtime_snapshot_backup_root_with_policy(
            ".af-rt-snap-sonarr-bad",
            &bad_env,
            priv_policy,
            None,
        )
        .expect_err(&format!("expected rejection for {}", bad_root.display()));
        assert!(!err.is_empty());
    }

    // 3. Real-host privileged policy rejects ephemeral /tmp, /var/tmp, /var/backups and never
    //    falls back to temp_dir when default /var/backups/aetherflow-recovery fails.
    let real_root_policy = RecoveryStoragePolicy {
        privileged: true,
        expected_uid: 0,
    };
    for bad_host_root in [
        "/tmp/af-priv-snap",
        "/var/tmp/af-priv-snap",
        "/var/tmp/aetherflow-scratch",
        "/dev/shm/af-priv-snap",
        "/run/af-priv-snap",
        "/var/backups",
    ] {
        let mut host_env = crate::PackageExecutionEnv::default();
        host_env.fs_root = None;
        host_env.temp_dir = staging.clone();
        host_env.recovery_root = Some(PathBuf::from(bad_host_root));
        let err = prepare_runtime_snapshot_backup_root_with_policy(
            ".af-rt-snap-sonarr-hostbad",
            &host_env,
            real_root_policy,
            None,
        )
        .expect_err(&format!("expected host rejection for {bad_host_root}"));
        assert!(
            err.contains("persistent storage") || err.contains("protected directory"),
            "unexpected host rejection for {bad_host_root}: {err}"
        );
    }
    if current_uid != 0 {
        let mut host_default_env = crate::PackageExecutionEnv::default();
        host_default_env.fs_root = None;
        host_default_env.temp_dir = staging.clone();
        host_default_env.recovery_root = None;
        let err = prepare_runtime_snapshot_backup_root_with_policy(
            ".af-rt-snap-sonarr-nofallback",
            &host_default_env,
            real_root_policy,
            None,
        )
        .expect_err("privileged real-host mode must fail closed without falling back to temp_dir");
        assert!(!err.is_empty());
        assert_eq!(
            std::fs::read_dir(&staging).unwrap().count(),
            0,
            "privileged real-host failure must not create fallback snapshots in temp_dir"
        );
    }

    // 4. Reject insecure recovery root permissions (0o755 / 0o777) and wrong expected_uid.
    std::fs::set_permissions(
        &expected_recovery_root,
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    let mode_err = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-mode",
        &env_cfg,
        priv_policy,
        None,
    )
    .expect_err("0o755 recovery root must be rejected");
    assert!(
        mode_err.contains("0o700"),
        "unexpected mode error: {mode_err}"
    );
    std::fs::set_permissions(
        &expected_recovery_root,
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();

    let uid_err = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-uid",
        &env_cfg,
        RecoveryStoragePolicy {
            privileged: true,
            expected_uid: current_uid.saturating_add(1),
        },
        None,
    )
    .expect_err("wrong owner uid must be rejected");
    assert!(
        uid_err.contains("owned by uid"),
        "unexpected uid error: {uid_err}"
    );

    // 5. Reject group-writable ancestor under privileged policy.
    let var_backups = fixture.join("var/backups");
    std::fs::set_permissions(&var_backups, std::fs::Permissions::from_mode(0o775)).unwrap();
    let ancestor_err = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-ancestor",
        &env_cfg,
        priv_policy,
        None,
    )
    .expect_err("group-writable ancestor must be rejected under privileged policy");
    assert!(
        ancestor_err.contains("unsafe writable permissions"),
        "unexpected ancestor error: {ancestor_err}"
    );
    std::fs::set_permissions(&var_backups, std::fs::Permissions::from_mode(0o755)).unwrap();

    // 6. Reject symlinked recovery leaf and symlinked ancestor.
    let decoy = base.join("decoy");
    std::fs::create_dir_all(&decoy).unwrap();
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(&expected_recovery_root).unwrap();
    std::os::unix::fs::symlink(&decoy, &expected_recovery_root).unwrap();
    let sym_leaf_err = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-symleaf",
        &env_cfg,
        priv_policy,
        None,
    )
    .expect_err("symlinked recovery root must be rejected");
    assert!(
        sym_leaf_err.to_ascii_lowercase().contains("symlink"),
        "unexpected symlink leaf error: {sym_leaf_err}"
    );

    std::fs::remove_file(&expected_recovery_root).unwrap();
    std::fs::remove_dir(&var_backups).unwrap();
    std::os::unix::fs::symlink(&decoy, &var_backups).unwrap();
    let sym_anc_err = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-symanc",
        &env_cfg,
        priv_policy,
        None,
    )
    .expect_err("symlinked recovery ancestor must be rejected");
    assert!(
        sym_anc_err.to_ascii_lowercase().contains("symlink"),
        "unexpected symlink ancestor error: {sym_anc_err}"
    );

    force_remove_backup_tree(&base);
}

#[cfg(unix)]
#[test]
fn test_durable_recovery_storage_unprivileged_api_fallback_prefers_data_dir() {
    use std::os::unix::fs::PermissionsExt;

    let current_uid = unsafe { libc::geteuid() };
    let unpriv_policy = RecoveryStoragePolicy {
        privileged: false,
        expected_uid: current_uid,
    };

    // Place synthetic DATA_DIR beside test binary (non-ephemeral persistent path) to exercise Mode 4.
    let target_dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join(format!("af-unpriv-dd-{}", uuid::Uuid::new_v4()));
    let data_dir = target_dir.join("data");
    let fallback_tmp =
        std::env::temp_dir().join(format!("af-unpriv-fallback-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::create_dir_all(&fallback_tmp).unwrap();

    let mut env_cfg = crate::PackageExecutionEnv::default();
    env_cfg.fs_root = None;
    env_cfg.recovery_root = None;
    env_cfg.temp_dir = fallback_tmp.clone();

    let persistent_snap = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-unpriv1",
        &env_cfg,
        unpriv_policy,
        Some(&data_dir),
    )
    .expect("unprivileged Mode 4 should prefer persistent DATA_DIR/recovery");
    assert_eq!(
        persistent_snap.parent(),
        Some(data_dir.join("recovery").as_path())
    );
    assert_eq!(
        std::fs::symlink_metadata(data_dir.join("recovery"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::symlink_metadata(&persistent_snap)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    // Without DATA_DIR, unprivileged API fallback still succeeds with private 0o700 dir in temp_dir.
    let fallback_snap = prepare_runtime_snapshot_backup_root_with_policy(
        ".af-rt-snap-sonarr-unpriv2",
        &env_cfg,
        unpriv_policy,
        None,
    )
    .expect("unprivileged Mode 4 without DATA_DIR should fall back to temp_dir");
    assert_eq!(fallback_snap.parent(), Some(fallback_tmp.as_path()));
    assert_eq!(
        std::fs::symlink_metadata(&fallback_snap)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    force_remove_backup_tree(&target_dir);
    force_remove_backup_tree(&fallback_tmp);
}

#[cfg(unix)]
#[test]
fn test_runtime_snapshot_ordinary_cleanup_and_incomplete_rollback_preservation() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!(
        "af-durable-cleanup-preserve-{}",
        uuid::Uuid::new_v4()
    ));
    let env_cfg = crate::PackageExecutionEnv::isolated(&root);
    let live_dir = root.join("var/lib/sonarr");
    std::fs::create_dir_all(&live_dir).unwrap();
    let config = live_dir.join("config.xml");
    std::fs::write(&config, b"<Config>v1</Config>").unwrap();

    // 1. Ordinary capture + drop cleans up the snapshot directory.
    let snap_clean = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
        .expect("capture in isolated root should succeed");
    let clean_backup = snap_clean.backup_root.clone();
    let expected_recovery_root = root.join("var/backups/aetherflow-recovery");
    assert_eq!(
        clean_backup.parent(),
        Some(expected_recovery_root.as_path())
    );
    assert_eq!(
        std::fs::symlink_metadata(&expected_recovery_root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::symlink_metadata(&clean_backup)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert!(
        !root.join("tmp").exists() || sonarr_runtime_snap_dirs_in(&root.join("tmp")).is_empty(),
        "isolated capture must never place snapshots under tmp"
    );
    drop(snap_clean);
    assert!(
        !clean_backup.exists(),
        "ordinary drop must remove snapshot backup directory"
    );

    // 2. Capture + mutate + restore restores live data and cleans up snapshot on drop.
    let mut snap_restore = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
        .expect("second capture should succeed");
    let restore_backup = snap_restore.backup_root.clone();
    std::fs::write(&config, b"<Config>v2-broken</Config>").unwrap();
    snap_restore.restore().expect("restore should succeed");
    assert_eq!(std::fs::read(&config).unwrap(), b"<Config>v1</Config>");
    drop(snap_restore);
    assert!(
        !restore_backup.exists(),
        "clean restore drop must remove snapshot backup directory"
    );

    // 3. Preserved snapshot (e.g. quiesce failure / incomplete rollback) stays intact on drop.
    let mut snap_preserve = PackageRuntimeSnapshot::capture("sonarr", &[], &env_cfg, false)
        .expect("third capture should succeed");
    let preserved_backup = snap_preserve.backup_root.clone();
    snap_preserve.preserve_on_drop = true;
    drop(snap_preserve);
    assert!(
        preserved_backup.is_dir(),
        "preserve_on_drop must keep backup under persistent recovery root"
    );
    assert_eq!(
        preserved_backup.parent(),
        Some(expected_recovery_root.as_path())
    );

    force_remove_backup_tree(&root);
}

#[test]
fn test_apply_legacy_package_environment_sets_persistent_recovery_root_distinct_from_scratch() {
    let _guard = ENV_TEST_MUTEX.lock().unwrap();
    let saved_fs = std::env::var_os("AETHERFLOW_FS_ROOT");
    let saved_install = std::env::var_os("AETHERFLOW_INSTALL_ROOT");
    let saved_recovery = std::env::var_os("AETHERFLOW_RECOVERY_ROOT");
    let saved_af_recovery = std::env::var_os("AF_RECOVERY_ROOT");

    std::env::remove_var("AETHERFLOW_FS_ROOT");
    std::env::remove_var("AETHERFLOW_INSTALL_ROOT");
    std::env::remove_var("AETHERFLOW_RECOVERY_ROOT");
    std::env::remove_var("AF_RECOVERY_ROOT");

    let req = crate::PackageRunnerRequest {
        action: "update".to_string(),
        package_id: "n8n".to_string(),
        script_name: "installpackage-n8n".to_string(),
        app_port: 5678,
        secondary_port: 0,
        delete_data: false,
        expected_target_version: Some("1.90.0".to_string()),
        achieved_version: None,
        lifecycle_job_id: "job-env-check".to_string(),
    };

    let mut host_cmd = tokio::process::Command::new("/bin/true");
    crate::package_executor::apply_legacy_package_environment(&mut host_cmd, &req);
    let host_envs: std::collections::HashMap<_, _> = host_cmd
        .as_std()
        .get_envs()
        .map(|(k, v)| (k.to_os_string(), v.map(|val| val.to_os_string())))
        .collect();
    assert_eq!(
        host_envs.get(std::ffi::OsStr::new("AF_RECOVERY_ROOT")),
        Some(&Some(std::ffi::OsString::from(
            crate::package_executor::DEFAULT_PRIVILEGED_RECOVERY_ROOT
        )))
    );
    assert_eq!(
        host_envs.get(std::ffi::OsStr::new("AF_TRANSACTION_ROOT")),
        Some(&Some(std::ffi::OsString::from(
            crate::package_executor::DEFAULT_PRIVILEGED_RECOVERY_ROOT
        )))
    );
    assert_eq!(
        host_envs.get(std::ffi::OsStr::new("AF_JOB_SCRATCH_ROOT")),
        Some(&Some(std::ffi::OsString::from(
            "/var/tmp/aetherflow-scratch"
        )))
    );
    assert_eq!(
        host_envs.get(std::ffi::OsStr::new("AF_FIXTURE_ROOT")),
        Some(&None),
        "real host runner must strip ambient AF_FIXTURE_ROOT"
    );
    assert_eq!(
        host_envs.get(std::ffi::OsStr::new("TEST_ROOT")),
        Some(&None),
        "real host runner must strip ambient TEST_ROOT"
    );

    let fixture_root = std::env::temp_dir().join("af-legacy-env-fixture");
    std::env::set_var("AETHERFLOW_FS_ROOT", &fixture_root);
    let mut iso_cmd = tokio::process::Command::new("/bin/true");
    crate::package_executor::apply_legacy_package_environment(&mut iso_cmd, &req);
    let iso_envs: std::collections::HashMap<_, _> = iso_cmd
        .as_std()
        .get_envs()
        .map(|(k, v)| (k.to_os_string(), v.map(|val| val.to_os_string())))
        .collect();
    let expected_iso = fixture_root
        .join("var/backups/aetherflow-recovery")
        .into_os_string();
    assert_eq!(
        iso_envs.get(std::ffi::OsStr::new("AF_RECOVERY_ROOT")),
        Some(&Some(expected_iso.clone()))
    );
    assert_eq!(
        iso_envs.get(std::ffi::OsStr::new("AF_TRANSACTION_ROOT")),
        Some(&Some(expected_iso))
    );

    for (key, prev) in [
        ("AETHERFLOW_FS_ROOT", saved_fs),
        ("AETHERFLOW_INSTALL_ROOT", saved_install),
        ("AETHERFLOW_RECOVERY_ROOT", saved_recovery),
        ("AF_RECOVERY_ROOT", saved_af_recovery),
    ] {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}

#[test]
fn test_librespeed_and_novnc_unit_catalog_sandbox_and_snapshot_capture_restore() {
    let _env_lock = ENV_TEST_MUTEX.lock().unwrap();
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let saved_pkgs = std::env::var_os("AETHERFLOW_PACKAGES_CONFIG");
    let saved_auto = std::env::var_os("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG");
    std::env::set_var(
        "AETHERFLOW_PACKAGES_CONFIG",
        repo_root.join("config/packages.json"),
    );
    std::env::set_var(
        "AETHERFLOW_PACKAGE_AUTOMATION_CONFIG",
        repo_root.join("config/package_automation.json"),
    );

    let ls_units = package_service_units("librespeed").unwrap();
    assert!(
        ls_units.iter().any(|u| u == "librespeed.socket"),
        "expected librespeed.socket in {ls_units:?}"
    );
    let novnc_units = package_service_units("novnc").unwrap();
    assert!(
        novnc_units.iter().any(|u| u == "novnc-session"),
        "expected novnc-session in {novnc_units:?}"
    );

    assert!(crate::is_exempt_sandbox_unit("librespeed.socket"));
    assert!(crate::is_exempt_sandbox_unit("novnc-session.service"));
    assert!(crate::is_exempt_sandbox_unit("novnc-xvnc.service"));
    assert!(!crate::is_exempt_sandbox_unit("librespeed.service"));
    assert!(!crate::is_exempt_sandbox_unit("novnc.service"));

    // 1. Pre-socket LibreSpeed snapshot removes newly created socket unit & wants symlink on rollback
    let root = std::env::temp_dir().join(format!("af-test-ls-novnc-snap-{}", uuid::Uuid::new_v4()));
    let systemd_dir = root.join("etc/systemd/system");
    let sockets_wants = systemd_dir.join("sockets.target.wants");
    let multi_wants = systemd_dir.join("multi-user.target.wants");
    std::fs::create_dir_all(&sockets_wants).unwrap();
    std::fs::create_dir_all(&multi_wants).unwrap();
    std::fs::write(systemd_dir.join("librespeed.service"), "legacy-ls-unit\n").unwrap();
    std::fs::write(systemd_dir.join("novnc.service"), "legacy-novnc-unit\n").unwrap();
    std::fs::write(systemd_dir.join("novnc-xvnc.service"), "legacy-xvnc-unit\n").unwrap();
    let env_cfg = crate::PackageExecutionEnv::isolated(&root);

    let mut ls_snap =
        PackageRuntimeSnapshot::capture("librespeed", &ls_units, &env_cfg, false).unwrap();
    let mut novnc_snap =
        PackageRuntimeSnapshot::capture("novnc", &novnc_units, &env_cfg, false).unwrap();

    // Simulate failed cutover creating librespeed.socket + symlink + proxy token and novnc-session.service + symlink
    std::fs::write(systemd_dir.join("librespeed.service"), "new-ls-unit\n").unwrap();
    std::fs::write(systemd_dir.join("librespeed.socket"), "new-ls-socket\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "/etc/systemd/system/librespeed.socket",
        sockets_wants.join("librespeed.socket"),
    )
    .unwrap();
    std::fs::create_dir_all(root.join("etc/aetherflow")).unwrap();
    std::fs::write(
        root.join("etc/aetherflow/librespeed-proxy-token.conf"),
        "token=new\n",
    )
    .unwrap();

    std::fs::write(systemd_dir.join("novnc-session.service"), "new-session\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "/etc/systemd/system/novnc-session.service",
        multi_wants.join("novnc-session.service"),
    )
    .unwrap();

    ls_snap.restore().unwrap();
    novnc_snap.restore().unwrap();

    assert_eq!(
        std::fs::read_to_string(systemd_dir.join("librespeed.service")).unwrap(),
        "legacy-ls-unit\n"
    );
    assert!(!systemd_dir.join("librespeed.socket").exists());
    assert!(std::fs::symlink_metadata(sockets_wants.join("librespeed.socket")).is_err());
    assert!(!root
        .join("etc/aetherflow/librespeed-proxy-token.conf")
        .exists());
    assert!(!systemd_dir.join("novnc-session.service").exists());
    assert!(std::fs::symlink_metadata(multi_wants.join("novnc-session.service")).is_err());

    force_remove_backup_tree(&root);
    for (key, prev) in [
        ("AETHERFLOW_PACKAGES_CONFIG", saved_pkgs),
        ("AETHERFLOW_PACKAGE_AUTOMATION_CONFIG", saved_auto),
    ] {
        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }
}
