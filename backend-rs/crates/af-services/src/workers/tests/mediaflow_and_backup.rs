use super::*;

#[tokio::test]
async fn test_mediaflow_progress_broadcast_and_empty_output_preserves_source() {
    let name =
        "workers::tests::mediaflow_and_backup::test_mediaflow_progress_broadcast_and_empty_output_preserves_source";
    if std::env::var("AF_MEDIAFLOW_TEST_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_TEST_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-mediaflow-test-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    af_db::init_db().unwrap();

    let src_file = root.join("media/movie.mp4");
    fs::write(&src_file, b"original-video-bytes").unwrap();

    // Fake ffmpeg that strips optional file: prefix, exits 0, and writes a 0-byte output file
    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        "#!/bin/sh\nout=\"\"\nfor arg in \"$@\"; do out=\"$arg\"; done\nout=\"${out#file:}\"\n: > \"$out\"\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_ffprobe = root.join("bin/ffprobe");
    fs::write(&fake_ffprobe, "#!/bin/sh\necho 10.0\n").unwrap();
    fs::set_permissions(&fake_ffprobe, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );

    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, None, &src_file);
    }

    let mut rx = subscribe_mediaflow_progress();
    assert!(process_next_mediaflow_job().await);

    let mut events = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        events.push(serde_json::from_str::<serde_json::Value>(&msg).unwrap());
    }
    assert!(events.iter().any(|e| e["status"] == "running"));
    assert!(events.iter().any(|e| e["status"] == "failed"));

    // Source file must remain untouched!
    assert_eq!(fs::read(&src_file).unwrap(), b"original-video-bytes");
    let status: String = af_db::get_conn()
        .unwrap()
        .query_row("SELECT status FROM mediaflow_queue LIMIT 1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(status, "FAILED");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_smart_backup_honors_persisted_next_run_and_acquires_lock() {
    let name = "workers::tests::mediaflow_and_backup::test_smart_backup_honors_persisted_next_run_and_acquires_lock";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    let root = env::temp_dir().join(format!("af-smart-backup-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AETHERFLOW_BACKUP_DIR", root.join("backups"));
    af_db::init_db().unwrap();
    ensure_smart_backup_columns();

    // Future backup_next_run_at must prevent running prematurely
    let future = (Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE settings SET smart_backup_enabled = 'true', smart_backup_hour = ?1, smart_backup_last_run = '', backup_schedule_mode = 'smart', backup_next_run_at = ?2 WHERE id = 1",
            params![Utc::now().hour() as i64, future],
        )
        .unwrap();
    }
    check_and_run_smart_backup();
    assert!(!root.join("backups").exists());

    // Past backup_next_run_at must run and create a verified snapshot
    let past = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "UPDATE settings SET backup_next_run_at = ?1 WHERE id = 1",
            params![past],
        )
        .unwrap();
    }
    check_and_run_smart_backup();
    let backups: Vec<_> = fs::read_dir(root.join("backups"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("sqlite"))
        .collect();
    assert_eq!(backups.len(), 1);

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn mediaflow_recovery_unlinks_only_a_proven_interrupted_publication() {
    use super::mediaflow::{
        publish_intent_filename, MediaflowPublishIntent, MediaflowPublishedOutput,
    };
    let name = "workers::tests::mediaflow_and_backup::mediaflow_recovery_unlinks_only_a_proven_interrupted_publication";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    let root = env::temp_dir().join(format!("af-mf-reconcile-{}", uuid::Uuid::new_v4()));
    let media = root.join("media");
    let trash = media.join(".mediaflow_trash");
    fs::create_dir_all(&trash).unwrap();
    let db = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", &media);
    af_db::init_db().unwrap();

    let unrelated = media.join(".other-encoder.tmp.mkv");
    fs::write(&unrelated, b"unrelated").unwrap();
    for (id, stem, replace_source) in [(91, "original", false), (92, "replaced", true)] {
        let src = media.join(format!("{stem}.mp4"));
        let out = media.join(format!("{stem}_hevc.mkv"));
        let temp_name = format!(".tmp_mediaflow_{id}_{}.mkv", uuid::Uuid::new_v4().simple());
        let temp = media.join(&temp_name);
        fs::write(&src, b"original video").unwrap();
        fs::write(&temp, b"transcoded bytes").unwrap();
        let source = open_and_pin_mediaflow_source(src.to_str().unwrap()).unwrap();
        let output =
            MediaflowPublishedOutput::capture(&fs::File::open(&temp).unwrap(), temp_name).unwrap();
        let marker = trash.join(publish_intent_filename(id));
        let intent = MediaflowPublishIntent {
            job_id: id,
            published_path: out.to_string_lossy().into_owned(),
            trash_entry_name: format!("{id}_{stem}.mp4"),
            new_size: fs::metadata(&temp).unwrap().len() as i64,
            source_fingerprint: source.identity.fingerprint.clone(),
            output: Some(output),
        };
        fs::write(&marker, serde_json::to_vec(&intent).unwrap()).unwrap();
        af_db::get_conn().unwrap().execute(
            "INSERT INTO mediaflow_queue(id,file_path,status,source_fingerprint) VALUES(?1,?2,'PROCESSING',?3)",
            params![id, src.to_str().unwrap(), source.identity.fingerprint],
        ).unwrap();
        fs::hard_link(&temp, &out).unwrap();
        if replace_source {
            let replacement = src.with_extension("new");
            fs::write(&replacement, b"replacement video").unwrap();
            fs::rename(replacement, &src).unwrap();
        }
        reconcile_mediaflow_startup();
        reconcile_mediaflow_startup();
        assert!(!marker.exists());
        assert_eq!(out.exists(), replace_source);
        assert_eq!(temp.exists(), replace_source);
        if replace_source {
            assert_eq!(fs::read(&src).unwrap(), b"replacement video");
            assert_eq!(fs::read(&out).unwrap(), b"transcoded bytes");
        } else {
            assert_eq!(fs::read(&src).unwrap(), b"original video");
            // The next encode can publish at this path without clobbering a file.
            fs::write(&out, b"next attempt").unwrap();
        }
        let status: String = af_db::get_conn()
            .unwrap()
            .query_row(
                "SELECT status FROM mediaflow_queue WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .unwrap();
        let expected = if replace_source {
            "FAILED"
        } else {
            "NEEDS_RESCAN"
        };
        assert_eq!(status, expected);
    }
    assert_eq!(fs::read(unrelated).unwrap(), b"unrelated");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_reconcile_mediaflow_startup_marks_stranded_processing_and_cleans_temps() {
    let name = "workers::tests::mediaflow_and_backup::test_reconcile_mediaflow_startup_marks_stranded_processing_and_cleans_temps";
    if !crate::inventory_regressions::isolated(name) {
        return;
    }
    let root = env::temp_dir().join(format!("af-mf-reconcile-{}", uuid::Uuid::new_v4()));
    let media = root.join("media");
    let trash = media.join(".mediaflow_trash");
    fs::create_dir_all(&trash).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", &media);
    env::set_var("MEDIAFLOW_TRASH_RETENTION_SECS", "0");
    af_db::init_db().unwrap();

    let movie = media.join("sample.mkv");
    fs::write(&movie, b"video").unwrap();
    let stale_tmp = media.join(".tmp_mediaflow_77.mkv");
    fs::write(&stale_tmp, b"partial").unwrap();
    let stale_current = media.join(format!(
        ".tmp_mediaflow_77_{}.mkv",
        uuid::Uuid::new_v4().simple()
    ));
    fs::write(&stale_current, b"partial").unwrap();
    let unrelated = [
        media.join(".other-encoder.tmp.mkv"),
        media.join(".tmp_mediaflow_77_notes.mkv"),
        media.join(".tmp_mediaflow_78.mkv"),
        media.join(".tmp_mediaflow_770.mkv"),
    ];
    for path in &unrelated {
        fs::write(path, b"keep").unwrap();
    }
    let expired_trash = trash.join("77_old.mkv");
    fs::write(&expired_trash, b"trashed").unwrap();
    let expired_meta = trash.join("77_old.mkv.meta.json");
    fs::write(
        &expired_meta,
        serde_json::to_vec(&MediaflowTrashMeta {
            job_id: 77,
            trashed_at_unix: Utc::now().timestamp() - 3600,
            original_name: "old.mkv".to_string(),
        })
        .unwrap(),
    )
    .unwrap();
    let unverified_trash = trash.join("77_unverified.mkv");
    fs::write(&unverified_trash, b"keep-without-meta").unwrap();

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, status) VALUES (77, ?1, 'PROCESSING')",
            params![movie.to_string_lossy().to_string()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, status) VALUES (78, ?1, 'COMPLETED')",
            params![media.join("previous.mkv").to_string_lossy().as_ref()],
        )
        .unwrap();
    }

    reconcile_mediaflow_startup();

    let (status, err_log): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 77",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "FAILED");
    assert_eq!(err_log, "Interrupted by service restart");
    assert!(!stale_tmp.exists());
    assert!(!stale_current.exists());
    for path in &unrelated {
        assert_eq!(fs::read(path).unwrap(), b"keep", "{}", path.display());
    }
    assert!(!expired_trash.exists());
    assert!(!expired_meta.exists());
    assert!(
        unverified_trash.exists(),
        "trash entries lacking verified .meta.json must never be deleted"
    );
    assert!(movie.exists());

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[tokio::test]
async fn test_mediaflow_mid_transcode_source_replacement_preserves_replacement_untouched() {
    let name = "workers::tests::mediaflow_and_backup::test_mediaflow_mid_transcode_source_replacement_preserves_replacement_untouched";
    if std::env::var("AF_MEDIAFLOW_SWAP_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_SWAP_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let root = env::temp_dir().join(format!("af-mf-swap-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    af_db::init_db().unwrap();

    let src_file = root.join("media/movie.mp4");
    fs::write(&src_file, b"original-v1-video-payload").unwrap();

    // Fake ffmpeg verifies pinned `/proc/self/fd/<fd>` input, atomically swaps `movie.mp4` mid-transcode
    // when AF_SWAP_TARGET is set, and writes transcoded bytes into the exclusive 0600 temp file.
    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        "#!/bin/sh\nset -eu\nin_uri=\"\"\nout=\"\"\nprev=\"\"\nfor arg in \"$@\"; do\n  if [ \"$prev\" = \"-i\" ]; then in_uri=\"$arg\"; fi\n  prev=\"$arg\"\n  out=\"$arg\"\ndone\nin_path=\"${in_uri#file:}\"\ncat \"$in_path\" > /dev/null\nif [ -n \"${AF_SWAP_TARGET:-}\" ]; then\n  printf 'upgraded-replacement-4k-remux' > \"${AF_SWAP_TARGET}.new\"\n  mv \"${AF_SWAP_TARGET}.new\" \"$AF_SWAP_TARGET\"\nfi\nout_path=\"${out#file:}\"\nprintf 'transcoded-hevc-stream-payload' > \"$out_path\"\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_ffprobe = root.join("bin/ffprobe");
    fs::write(&fake_ffprobe, "#!/bin/sh\necho 12.0\n").unwrap();
    fs::set_permissions(&fake_ffprobe, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );
    env::set_var("AF_SWAP_TARGET", &src_file);

    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(1), &src_file);
    }

    assert!(process_next_mediaflow_job().await);

    // 1. Replacement file MUST remain completely untouched and never moved into `.mediaflow_trash`!
    assert_eq!(
        fs::read(&src_file).unwrap(),
        b"upgraded-replacement-4k-remux"
    );
    assert!(!root.join("media/movie_hevc.mkv").exists());
    let trash_dir = root.join("media/.mediaflow_trash");
    if trash_dir.exists() {
        assert_eq!(fs::read_dir(&trash_dir).unwrap().count(), 0);
    }
    // No leftover `.tmp_mediaflow_*` files
    let media_entries: Vec<String> = fs::read_dir(root.join("media"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(media_entries, vec!["movie.mp4".to_string()]);

    let (status, err_log): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "FAILED");
    assert_eq!(err_log, MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG);

    // 2. Normal un-swapped job succeeds end-to-end with pinned dirfd + random 0600 temp file
    env::remove_var("AF_SWAP_TARGET");
    let src_ok = root.join("media/clean.mp4");
    fs::write(&src_ok, b"untouched-original-source").unwrap();
    let orig_ino = fs::symlink_metadata(&src_ok).unwrap().ino();
    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(2), &src_ok);
    }
    assert!(process_next_mediaflow_job().await);
    assert!(!src_ok.exists());
    assert_eq!(
        fs::read(root.join("media/clean_hevc.mkv")).unwrap(),
        b"transcoded-hevc-stream-payload"
    );
    let trashed_ino = fs::symlink_metadata(root.join("media/.mediaflow_trash/2_clean.mp4"))
        .unwrap()
        .ino();
    assert_eq!(trashed_ino, orig_ino);

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn test_heal_auto_approve_false_queues_deduplicated_action_and_notifies_all_admins() {
    use crate::inventory_regressions::{isolated, Fixture};
    let name = "workers::tests::mediaflow_and_backup::test_heal_auto_approve_false_queues_deduplicated_action_and_notifies_all_admins";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    let db_path = fixture.root.join("heal-admins.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::remove_var("AF_HEAL_AUTO_APPROVE");
    af_db::init_db().unwrap();

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DELETE FROM users", []).unwrap();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role) VALUES (10, 'admin_a', 'x', 'admin'), (20, 'admin_b', 'x', 'admin'), (30, 'viewer_c', 'x', 'user')",
            [],
        )
        .unwrap();
    }

    fixture.write_packages(&[Fixture::package("fixture", "systemd", "fixture-main")]);
    fixture.command(
        "systemctl",
        "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ncase \"$1 $2\" in 'is-active fixture-main') echo inactive; exit 3;; is-active*) echo active;; show*) printf 'LoadState=loaded\\nType=simple\\n';; *) exit 92;; esac\n",
    );

    let runtime = tokio::runtime::Runtime::new().unwrap();
    *HEAL_STATES.lock().unwrap() = HashMap::new();
    runtime.block_on(perform_heal_check());
    // Second tick must deduplicate pending action and avoid spamming notifications
    runtime.block_on(perform_heal_check());

    let conn = af_db::get_conn().unwrap();
    let pending_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM pending_actions WHERE source = 'af-heal' AND action = 'systemctl restart fixture-main' AND status = 'pending'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending_count, 1);

    let mut notified_uids: Vec<i64> = Vec::new();
    let mut stmt = conn
        .prepare("SELECT user_id FROM notifications ORDER BY user_id ASC")
        .unwrap();
    for uid in stmt
        .query_map([], |r| r.get::<_, i64>(0))
        .unwrap()
        .flatten()
    {
        notified_uids.push(uid);
    }
    assert_eq!(notified_uids, vec![10, 20]);
}

#[cfg(unix)]
#[test]
fn test_heal_suppresses_queued_notification_on_db_write_rejection_and_capacity() {
    use crate::inventory_regressions::{isolated, Fixture};
    let name =
        "workers::tests::mediaflow_and_backup::test_heal_suppresses_queued_notification_on_db_write_rejection_and_capacity";
    if !isolated(name) {
        return;
    }
    let fixture = Fixture::new();
    let db_path = fixture.root.join("heal-persist-guard.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::remove_var("AF_HEAL_AUTO_APPROVE");
    af_db::init_db().unwrap();

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute("DELETE FROM users", []).unwrap();
        conn.execute(
            "INSERT INTO users (id, username, password_hash, role) VALUES (10, 'admin_a', 'x', 'admin'), (20, 'admin_b', 'x', 'admin')",
            [],
        )
        .unwrap();
    }

    fixture.write_packages(&[Fixture::package("fixture", "systemd", "fixture-main")]);
    fixture.command(
        "systemctl",
        "printf '%s\\n' \"$*\" >> \"$AF_STATUS_CALLS\"\ncase \"$1 $2\" in 'is-active fixture-main') echo inactive; exit 3;; is-active*) echo active;; show*) printf 'LoadState=loaded\\nType=simple\\n';; *) exit 92;; esac\n",
    );

    let runtime = tokio::runtime::Runtime::new().unwrap();
    *HEAL_STATES.lock().unwrap() = HashMap::new();

    // 1. DB write rejection must suppress both pending row creation and queued notification.
    af_db::get_conn()
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_heal_pending_insert BEFORE INSERT ON pending_actions \
             BEGIN SELECT RAISE(ABORT, 'fixture write rejection'); END;",
        )
        .unwrap();
    runtime.block_on(perform_heal_check());
    {
        let conn = af_db::get_conn().unwrap();
        assert_eq!(af_db::count_pending_actions().unwrap(), 0);
        let notif_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
            .unwrap();
        assert_eq!(notif_count, 0);
        conn.execute_batch("DROP TRIGGER reject_heal_pending_insert;")
            .unwrap();
    }

    // 2. Hidden older pending rows reaching the 50-pending cap suppress queueing and notification.
    {
        let conn = af_db::get_conn().unwrap();
        for idx in 1..=af_db::MAX_PENDING_ACTIONS {
            conn.execute(
                "INSERT INTO pending_actions (classification, source, action, reason, status, created_at) \
                 VALUES ('warn', 'FlowAI', ?1, 'older pending', 'pending', '2020-01-01')",
                [format!("Restart old-{idx}")],
            )
            .unwrap();
        }
        for idx in 1..=120i64 {
            conn.execute(
                "INSERT INTO pending_actions (classification, source, action, reason, status, created_at) \
                 VALUES ('warn', 'FlowAI', ?1, 'recent executed', 'executed', '2026-01-01')",
                [format!("Restart done-{idx}")],
            )
            .unwrap();
        }
    }
    runtime.block_on(perform_heal_check());
    {
        let conn = af_db::get_conn().unwrap();
        let heal_pending: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_actions WHERE source = 'af-heal' AND status = 'pending'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(heal_pending, 0);
        assert_eq!(
            af_db::count_pending_actions().unwrap(),
            af_db::MAX_PENDING_ACTIONS
        );
        let notif_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
            .unwrap();
        assert_eq!(notif_count, 0);

        // 3. Resolving one pending row frees a slot; heal now commits a positive ID and notifies admins.
        conn.execute(
            "UPDATE pending_actions SET status = 'executed' WHERE id = (SELECT MIN(id) FROM pending_actions WHERE status = 'pending')",
            [],
        )
        .unwrap();
    }
    runtime.block_on(perform_heal_check());
    {
        let conn = af_db::get_conn().unwrap();
        let committed_id: i64 = conn
            .query_row(
                "SELECT id FROM pending_actions WHERE source = 'af-heal' AND action = 'systemctl restart fixture-main' AND status = 'pending'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(committed_id > 0);
        let notif_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM notifications", [], |r| r.get(0))
            .unwrap();
        assert_eq!(notif_count, 2);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn test_mediaflow_3yr_mtime_retention_sigpipe_large_stderr_0644_perms_and_intent_recovery() {
    let name = "workers::tests::mediaflow_and_backup::test_mediaflow_3yr_mtime_retention_sigpipe_large_stderr_0644_perms_and_intent_recovery";
    if std::env::var("AF_MEDIAFLOW_P4_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_P4_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-mf-p4-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    // 7-day retention: 3-year-old source mtime MUST NOT cause immediate pruning!
    env::set_var("MEDIAFLOW_TRASH_RETENTION_SECS", "604800");
    af_db::init_db().unwrap();

    // Fake ffmpeg emits >192 KiB to stderr (proving no SIGPIPE after 64 KiB!) before writing output.
    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        "#!/bin/sh\nset -eu\nout=\"\"\nfor arg in \"$@\"; do out=\"$arg\"; done\nout_path=\"${out#file:}\"\ndd if=/dev/zero bs=1024 count=200 2>/dev/null | tr '\\0' 'E' >&2\nprintf 'END_OF_LARGE_STDERR\\n' >&2\nprintf 'hevc-published-payload-bytes' > \"$out_path\"\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_ffprobe = root.join("bin/ffprobe");
    fs::write(&fake_ffprobe, "#!/bin/sh\necho 10.0\n").unwrap();
    fs::set_permissions(&fake_ffprobe, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );

    // Source media file with 3-year-old mtime and restrictive 0600 permissions
    let src_vintage = root.join("media/classic_film.mp4");
    fs::write(&src_vintage, b"three-year-old-h264-original").unwrap();
    fs::set_permissions(&src_vintage, fs::Permissions::from_mode(0o600)).unwrap();
    let three_years_ago = Utc::now().timestamp() - (3 * 365 * 86_400);
    {
        let c_src = CString::new(src_vintage.as_os_str().as_bytes()).unwrap();
        let ts = libc::timespec {
            tv_sec: three_years_ago as libc::time_t,
            tv_nsec: 0,
        };
        let times = [ts, ts];
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, c_src.as_ptr(), times.as_ptr(), 0) },
            0
        );
    }

    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(10), &src_vintage);
    }

    assert!(process_next_mediaflow_job().await);

    // 1. Published output exists, has mode 0644 (never 0600, never exec/suid), and job is COMPLETED
    let published = root.join("media/classic_film_hevc.mkv");
    assert!(published.is_file());
    let pub_mode = fs::symlink_metadata(&published)
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(pub_mode, 0o644);
    assert_eq!(compute_published_media_mode(0o4755), 0o644);
    assert_eq!(compute_published_media_mode(0o0664), 0o664);

    // 2. Trashed original + .meta.json BOTH survive post-publish prune AND survive process restart!
    let trashed = root.join("media/.mediaflow_trash/10_classic_film.mp4");
    let trashed_meta = root.join("media/.mediaflow_trash/10_classic_film.mp4.meta.json");
    assert!(
        trashed.is_file(),
        "3-year-old media original must NOT be pruned immediately after transcode!"
    );
    assert!(trashed_meta.is_file());
    let meta_mode = fs::symlink_metadata(&trashed_meta)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(meta_mode, 0o600);
    assert!(!root
        .join("media/.mediaflow_trash/.publish_intent_10.json")
        .exists());

    reconcile_mediaflow_startup();
    assert!(
        trashed.is_file(),
        "3-year-old media original must survive startup reconciliation until retention genuinely expires!"
    );

    // Once trashed_at_unix genuinely exceeds retention, both media and .meta.json are pruned cleanly
    fs::write(
        &trashed_meta,
        serde_json::to_vec(&MediaflowTrashMeta {
            job_id: 10,
            trashed_at_unix: Utc::now().timestamp() - 700_000,
            original_name: "classic_film.mp4".to_string(),
        })
        .unwrap(),
    )
    .unwrap();
    prune_mediaflow_trash_dir(
        &root.join("media/.mediaflow_trash"),
        mediaflow_trash_retention(),
    );
    assert!(!trashed.exists());
    assert!(!trashed_meta.exists());

    // 3. Startup reconciliation recovers PROCESSING job to COMPLETED when durable publish_intent + files exist
    let recovered_orig = root.join("media/crash_window.mp4");
    let recovered_pub = root.join("media/crash_window_hevc.mkv");
    let recovered_trash = root.join("media/.mediaflow_trash/11_crash_window.mp4");
    let intent_file = root.join("media/.mediaflow_trash/.publish_intent_11.json");
    fs::write(&recovered_pub, b"completed-before-sqlite-crash").unwrap();
    fs::write(&recovered_trash, b"original-in-trash").unwrap();
    // Legacy publish intent JSON without `source_fingerprint` must still recover cleanly.
    fs::write(
        &intent_file,
        serde_json::to_vec(&serde_json::json!({
            "job_id": 11,
            "published_path": recovered_pub.to_string_lossy().to_string(),
            "trash_entry_name": "11_crash_window.mp4",
            "new_size": 29
        }))
        .unwrap(),
    )
    .unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, original_codec, original_size, status) VALUES (11, ?1, 'h264', 17, 'PROCESSING')",
            params![recovered_orig.to_string_lossy().to_string()],
        )
        .unwrap();
    }

    reconcile_mediaflow_startup();

    let (rec_status, rec_path, rec_size): (String, String, i64) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, file_path, new_size FROM mediaflow_queue WHERE id = 11",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(rec_status, "COMPLETED");
    assert_eq!(rec_path, recovered_pub.to_string_lossy());
    assert_eq!(rec_size, 29);
    assert!(!intent_file.exists());
    assert!(root
        .join("media/.mediaflow_trash/11_crash_window.mp4.meta.json")
        .is_file());

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn test_smart_backup_optimal_window_telemetry_and_utc_hour_alignment() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE metrics_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            cpu_avg REAL DEFAULT 0,
            mem_used_gb REAL DEFAULT 0,
            mem_total_gb REAL DEFAULT 0
        );",
    )
    .unwrap();

    // < 24 samples returns honest heuristic_default with 0.35 confidence at 03:00 UTC
    for h in 0..5 {
        conn.execute(
            "INSERT INTO metrics_history (timestamp, cpu_avg, mem_used_gb, mem_total_gb) VALUES (?1, 40.0, 8.0, 16.0)",
            params![format!("2026-11-18T{h:02}:15:00Z")],
        )
        .unwrap();
    }
    let heuristic = analyze_optimal_backup_window(&conn);
    assert_eq!(heuristic.source, "heuristic_default");
    assert_eq!(heuristic.optimal_hour, 3);
    assert!((heuristic.confidence - 0.35).abs() < 1e-6);

    // >= 24 samples across 24 UTC hours picks lowest combined CPU + memory load hour (05:00 UTC)
    conn.execute("DELETE FROM metrics_history", []).unwrap();
    for h in 0..24 {
        let (cpu, mem_used) = if h == 5 {
            (4.0, 2.0) // 4% CPU, 12.5% RAM -> 8.25% combined
        } else {
            (65.0, 12.0) // 65% CPU, 75% RAM -> 70% combined
        };
        for m in [10, 40] {
            conn.execute(
                "INSERT INTO metrics_history (timestamp, cpu_avg, mem_used_gb, mem_total_gb) VALUES (?1, ?2, ?3, 16.0)",
                params![format!("2026-11-19T{h:02}:{m:02}:00Z"), cpu, mem_used],
            )
            .unwrap();
        }
    }
    let measured = analyze_optimal_backup_window(&conn);
    assert_eq!(measured.source, "metrics_history");
    assert_eq!(measured.optimal_hour, 5);
    assert_eq!(measured.hour, 5);
    assert!(measured.confidence >= 0.75);

    // Next backup alignment: >= 1h in the future, aligned to optimal_hour:00:00 UTC
    let now_before = chrono::DateTime::parse_from_rfc3339("2026-11-20T03:30:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let next_same_day = compute_next_optimal_backup_at(now_before, 5);
    assert_eq!(next_same_day.to_rfc3339(), "2026-11-20T05:00:00+00:00");

    // Within 1h of 05:00 UTC (04:30 UTC) advances to next day's 05:00:00 UTC
    let now_too_close = chrono::DateTime::parse_from_rfc3339("2026-11-20T04:30:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let next_tomorrow = compute_next_optimal_backup_at(now_too_close, 5);
    assert_eq!(next_tomorrow.to_rfc3339(), "2026-11-21T05:00:00+00:00");
}

fn insert_pinned_mediaflow_approved(
    conn: &rusqlite::Connection,
    id: Option<i64>,
    file_path: &Path,
) {
    let pinned = open_and_pin_mediaflow_source(&file_path.to_string_lossy()).unwrap();
    let ident = &pinned.identity;
    let size = i64::try_from(ident.size).unwrap();
    if let Some(job_id) = id {
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, original_codec, original_size, status, source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, source_fingerprint)
             VALUES (?1, ?2, 'h264', ?3, 'APPROVED', ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                job_id,
                pinned.canon_src.to_string_lossy().to_string(),
                size,
                ident.dev as i64,
                ident.ino as i64,
                size,
                ident.mtime_sec,
                ident.mtime_nsec,
                ident.fingerprint,
            ],
        )
        .unwrap();
    } else {
        conn.execute(
            "INSERT INTO mediaflow_queue (file_path, original_codec, original_size, status, source_dev, source_ino, source_size, source_mtime_sec, source_mtime_nsec, source_fingerprint)
             VALUES (?1, 'h264', ?2, 'APPROVED', ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                pinned.canon_src.to_string_lossy().to_string(),
                size,
                ident.dev as i64,
                ident.ino as i64,
                size,
                ident.mtime_sec,
                ident.mtime_nsec,
                ident.fingerprint,
            ],
        )
        .unwrap();
    }
}

#[test]
fn test_mediaflow_default_roots_align_with_systemd_and_retain_explicit_overrides() {
    assert_eq!(
        DEFAULT_MEDIAFLOW_ROOTS,
        &["/mnt", "/media", "/srv", "/data"]
    );
    assert!(!DEFAULT_MEDIAFLOW_ROOTS.contains(&"/home"));

    let default_roots = mediaflow_allowed_roots_from_raw(None);
    let blank_roots = mediaflow_allowed_roots_from_raw(Some("   "));
    assert_eq!(default_roots, blank_roots);
    if let Ok(canon_home) = fs::canonicalize("/home") {
        assert!(
            !default_roots.contains(&canon_home),
            "/home must not be a default MediaFlow candidate root under ProtectHome=read-only"
        );
    }

    let tmp = env::temp_dir().join(format!("af-mf-roots-{}", uuid::Uuid::new_v4()));
    let valid_a = tmp.join("custom-a");
    let valid_b = tmp.join("custom-b");
    let file_not_dir = tmp.join("not-a-dir.mp4");
    fs::create_dir_all(&valid_a).unwrap();
    fs::create_dir_all(&valid_b).unwrap();
    fs::write(&file_not_dir, b"fixture").unwrap();

    let raw = format!(
        "{}, relative/ignored, {}, {}, {}",
        valid_a.display(),
        tmp.join("missing").display(),
        file_not_dir.display(),
        valid_b.display()
    );
    let configured = mediaflow_allowed_roots_from_raw(Some(&raw));
    assert_eq!(
        configured,
        vec![
            fs::canonicalize(&valid_a).unwrap(),
            fs::canonicalize(&valid_b).unwrap(),
        ]
    );

    // Explicit configuration with no valid directories must fail closed instead of widening to defaults.
    let closed = mediaflow_allowed_roots_from_raw(Some("/definitely-nonexistent-mediaflow-root"));
    assert!(closed.is_empty());

    let _ = fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
#[tokio::test]
async fn test_mediaflow_worker_blocks_source_change_and_legacy_rows_before_execution() {
    let name =
        "workers::tests::mediaflow_and_backup::test_mediaflow_worker_blocks_source_change_and_legacy_rows_before_execution";
    if std::env::var("AF_MEDIAFLOW_IDENT_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_IDENT_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-mf-ident-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    af_db::init_db().unwrap();

    let ffmpeg_called = root.join("ffmpeg_was_invoked");
    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        format!(
            "#!/bin/sh\necho invoked > \"{}\"\nexit 0\n",
            ffmpeg_called.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );

    // 1. Atomic file replacement between approval and worker claim -> NEEDS_RESCAN, ffmpeg never spawned.
    let replaced_src = root.join("media/replaced.mp4");
    fs::write(&replaced_src, b"original-scanned-fixture-v1").unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(101), &replaced_src);
    }
    let tmp_swap = root.join("media/replaced.mp4.new");
    fs::write(&tmp_swap, b"new-unreviewed-media-file-v2").unwrap();
    fs::rename(&tmp_swap, &replaced_src).unwrap();

    assert!(process_next_mediaflow_job().await);
    assert!(!ffmpeg_called.exists());
    assert_eq!(
        fs::read(&replaced_src).unwrap(),
        b"new-unreviewed-media-file-v2"
    );
    let (status1, err1): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 101",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status1, "NEEDS_RESCAN");
    assert_eq!(err1, MEDIAFLOW_SOURCE_CHANGED_BEFORE_EXEC_MSG);

    // A write outside the sampled windows changes the inode change time even with mtime restored.
    let edited_src = root.join("media/edited_in_place.mp4");
    let mut edited_contents = vec![b'A'; 1024 * 1024];
    fs::write(&edited_src, &edited_contents).unwrap();
    let mtime = fs::metadata(&edited_src).unwrap().modified().unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(102), &edited_src);
    }
    {
        use std::os::unix::fs::FileExt;

        let offset = 80 * 1024;
        edited_contents[offset] = b'B';
        let file = fs::OpenOptions::new()
            .write(true)
            .open(&edited_src)
            .unwrap();
        file.write_all_at(b"B", offset as u64).unwrap();
        file.set_modified(mtime).unwrap();
    }

    assert!(process_next_mediaflow_job().await);
    assert!(!ffmpeg_called.exists());
    assert_eq!(fs::read(&edited_src).unwrap(), edited_contents);
    let status2: String = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status FROM mediaflow_queue WHERE id = 102",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status2, "NEEDS_RESCAN");

    // 3. Legacy APPROVED row missing persisted identity -> NEEDS_RESCAN without running ffmpeg.
    let legacy_src = root.join("media/legacy_approved.mp4");
    fs::write(&legacy_src, b"legacy-media-fixture-bytes").unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, original_codec, original_size, status) VALUES (103, ?1, 'h264', 26, 'APPROVED')",
            params![legacy_src.to_string_lossy().to_string()],
        )
        .unwrap();
    }
    assert!(process_next_mediaflow_job().await);
    assert!(!ffmpeg_called.exists());
    assert_eq!(
        fs::read(&legacy_src).unwrap(),
        b"legacy-media-fixture-bytes"
    );
    let (status3, err3): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 103",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status3, "NEEDS_RESCAN");
    assert_eq!(err3, MEDIAFLOW_MISSING_IDENTITY_MSG);

    // 4. Startup reconciliation also transitions legacy identity-less PENDING_APPROVAL/APPROVED rows to NEEDS_RESCAN.
    let legacy_pending = root.join("media/legacy_pending.mp4");
    fs::write(&legacy_pending, b"legacy-pending-bytes").unwrap();
    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO mediaflow_queue (id, file_path, original_codec, original_size, status) VALUES (104, ?1, 'h264', 20, 'PENDING_APPROVAL')",
            params![legacy_pending.to_string_lossy().to_string()],
        )
        .unwrap();
    }
    reconcile_mediaflow_startup();
    let status4: String = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status FROM mediaflow_queue WHERE id = 104",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(status4, "NEEDS_RESCAN");

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[tokio::test]
async fn test_mediaflow_mid_transcode_in_place_edit_aborts_publication_safely() {
    let name =
        "workers::tests::mediaflow_and_backup::test_mediaflow_mid_transcode_in_place_edit_aborts_publication_safely";
    if std::env::var("AF_MEDIAFLOW_INPLACE_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_INPLACE_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-mf-inplace-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    af_db::init_db().unwrap();

    let src_file = root.join("media/in_place.mp4");
    fs::write(&src_file, b"original-1111-same-length!").unwrap();

    // Fake ffmpeg overwrites `src_file` IN PLACE (same inode & exact same byte length) mid-transcode.
    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        "#!/bin/sh\nset -eu\nout=\"\"\nfor arg in \"$@\"; do out=\"$arg\"; done\nprintf 'modified-2222-same-length!' > \"$AF_INPLACE_TARGET\"\nout_path=\"${out#file:}\"\nprintf 'transcoded-hevc-output' > \"$out_path\"\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_ffprobe = root.join("bin/ffprobe");
    fs::write(&fake_ffprobe, "#!/bin/sh\necho 10.0\n").unwrap();
    fs::set_permissions(&fake_ffprobe, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );
    env::set_var("AF_INPLACE_TARGET", &src_file);

    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(201), &src_file);
    }

    assert!(process_next_mediaflow_job().await);

    assert_eq!(fs::read(&src_file).unwrap(), b"modified-2222-same-length!");
    assert!(!root.join("media/in_place_hevc.mkv").exists());
    let trash_dir = root.join("media/.mediaflow_trash");
    if trash_dir.exists() {
        assert_eq!(fs::read_dir(&trash_dir).unwrap().count(), 0);
    }
    let (status, err_log): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 201",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "FAILED");
    assert_eq!(err_log, MEDIAFLOW_SOURCE_CHANGED_CONFLICT_MSG);

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[tokio::test]
async fn test_mediaflow_inflight_cancellation_stops_ffmpeg_and_preserves_source() {
    let name =
        "workers::tests::mediaflow_and_backup::test_mediaflow_inflight_cancellation_stops_ffmpeg_and_preserves_source";
    if std::env::var("AF_MEDIAFLOW_CANCEL_CHILD").as_deref() != Ok(name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("AF_MEDIAFLOW_CANCEL_CHILD", name)
            .status()
            .unwrap()
            .success());
        return;
    }
    use std::os::unix::fs::PermissionsExt;

    let root = env::temp_dir().join(format!("af-mf-cancel-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::create_dir_all(root.join("media")).unwrap();
    let db_path = root.join("aetherflow.sqlite");
    for key in ["AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"] {
        env::set_var(key, &db_path);
    }
    env::set_var("AF_ALLOWED_FS_ROOTS", root.join("media"));
    af_db::init_db().unwrap();

    let src_file = root.join("media/long_movie.mp4");
    fs::write(&src_file, b"original-untouched-source-bytes").unwrap();
    let started_marker = root.join("ffmpeg_started");

    let fake_ffmpeg = root.join("bin/ffmpeg");
    fs::write(
        &fake_ffmpeg,
        format!(
            "#!/bin/sh\nout=\"\"\nfor arg in \"$@\"; do out=\"$arg\"; done\nout_path=\"${{out#file:}}\"\nprintf 'partial' > \"$out_path\"\necho started > \"{}\"\nsleep 30\nexit 0\n",
            started_marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_ffmpeg, fs::Permissions::from_mode(0o755)).unwrap();
    let fake_ffprobe = root.join("bin/ffprobe");
    fs::write(&fake_ffprobe, "#!/bin/sh\necho 30.0\n").unwrap();
    fs::set_permissions(&fake_ffprobe, fs::Permissions::from_mode(0o755)).unwrap();
    env::set_var(
        "PATH",
        format!(
            "{}:{}",
            root.join("bin").display(),
            env::var("PATH").unwrap()
        ),
    );

    {
        let conn = af_db::get_conn().unwrap();
        insert_pinned_mediaflow_approved(&conn, Some(301), &src_file);
    }

    let mut rx = subscribe_mediaflow_progress();
    let worker_handle = tokio::spawn(async { process_next_mediaflow_job().await });

    let mut started = false;
    for _ in 0..100 {
        if started_marker.exists() {
            started = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(started, "fake ffmpeg should have started");

    assert_eq!(
        cancel_inflight_mediaflow_job(301),
        CancelInflightOutcome::CancelSignalled
    );
    let processed = tokio::time::timeout(Duration::from_secs(5), worker_handle)
        .await
        .expect("worker must terminate promptly after cancellation")
        .unwrap();
    assert!(processed);

    // Source bytes untouched, no published output, no temp leftovers, no trash entries.
    assert_eq!(
        fs::read(&src_file).unwrap(),
        b"original-untouched-source-bytes"
    );
    assert!(!root.join("media/long_movie_hevc.mkv").exists());
    let media_entries: Vec<String> = fs::read_dir(root.join("media"))
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(media_entries, vec!["long_movie.mp4".to_string()]);

    let (status, err_log): (String, String) = af_db::get_conn()
        .unwrap()
        .query_row(
            "SELECT status, error_log FROM mediaflow_queue WHERE id = 301",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(status, "CANCELLED");
    assert_eq!(err_log, MEDIAFLOW_CANCELLED_MSG);

    let mut events = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        events.push(serde_json::from_str::<serde_json::Value>(&msg).unwrap());
    }
    assert!(events.iter().any(|e| e["status"] == "cancelled"));

    let _ = fs::remove_dir_all(&root);
}
