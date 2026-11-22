use super::{MockRunnerTransport, TempTestDir};
use crate::*;
use rusqlite::Connection;
use std::fs;

#[test]
fn cli_retained_remove_then_explicit_purge_dry_run_and_live() {
    let tmp = TempTestDir::new("cli-retained-then-purge");
    let root = tmp.path();
    let root_str = root.to_string_lossy().into_owned();
    fs::create_dir_all(root.join("install")).unwrap();
    fs::create_dir_all(root.join("etc/rclone")).unwrap();
    fs::create_dir_all(root.join("etc/aetherflow")).unwrap();
    fs::create_dir_all(root.join("var/lib/rclone")).unwrap();
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    fs::create_dir_all(root.join("mnt/remote")).unwrap();

    // Seed post-retained-removal state: .rclone.lock is gone, .rclone.retained + managed config exist,
    // plus unrelated distro/operator files and another package's retained receipt.
    fs::write(
        root.join("install/.rclone.retained"),
        af_models::format_retained_package_receipt("rclone", "2026-11-22T00:00:00Z"),
    )
    .unwrap();
    fs::write(
        root.join("etc/rclone/rclone.conf"),
        b"# AetherFlow managed rclone configuration\n[gdrive]\ntype = drive\n",
    )
    .unwrap();
    fs::write(
        root.join("etc/rclone/rclone.env"),
        b"RCLONE_RC_USER=\"admin\"\nRCLONE_RC_PASS=\"secret\"\n",
    )
    .unwrap();
    fs::write(root.join("var/lib/rclone/state.db"), b"retained-state").unwrap();
    fs::write(root.join("usr/bin/rclone"), b"distro-rclone").unwrap();
    fs::write(root.join("etc/rclone/custom.conf"), b"[custom]\n").unwrap();
    fs::write(root.join("etc/aetherflow/aetherflow.env"), b"KEEP=1\n").unwrap();
    fs::write(root.join("mnt/remote/sentinel"), b"keep-mount-data").unwrap();
    fs::write(
        root.join("install/.sonarr.retained"),
        af_models::format_retained_package_receipt("sonarr", "2026-11-22T00:00:00Z"),
    )
    .unwrap();

    let transport = MockRunnerTransport::default();

    // 1. Ordinary remove without --purge MUST still skip when install lock is gone.
    let ordinary_dry = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "package",
        "remove",
        "rclone",
    ])
    .unwrap();
    let ordinary_env = execute_invocation(&ordinary_dry, &transport);
    assert_eq!(ordinary_env.status, "ok", "{}", ordinary_env.message);
    let ordinary_data = ordinary_env.data.as_ref().unwrap();
    assert_eq!(
        ordinary_data["planned_requests"].as_array().unwrap().len(),
        0
    );
    assert_eq!(
        ordinary_data["skipped_not_installed"],
        serde_json::json!(["rclone"])
    );

    // 2. Explicit `af --dry-run package remove rclone --purge` MUST plan purge (delete_data=true)
    //    without mutating disk or dispatching runner.
    let purge_dry = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "package",
        "remove",
        "rclone",
        "--purge",
    ])
    .unwrap();
    let purge_dry_env = execute_invocation(&purge_dry, &transport);
    assert_eq!(purge_dry_env.status, "ok", "{}", purge_dry_env.message);
    let purge_dry_data = purge_dry_env.data.as_ref().unwrap();
    let planned = purge_dry_data["planned_requests"].as_array().unwrap();
    assert_eq!(planned.len(), 1, "expected purge request: {purge_dry_data}");
    assert_eq!(planned[0]["action"], "remove");
    assert_eq!(planned[0]["package_id"], "rclone");
    assert_eq!(planned[0]["script_name"], "removepackage-rclone");
    assert_eq!(planned[0]["delete_data"], true);
    assert_eq!(
        purge_dry_data["skipped_not_installed"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        purge_dry_data["retained_purge_targets"][0]["package"],
        "rclone"
    );
    assert_eq!(transport.package_calls.lock().unwrap().len(), 0);
    assert!(root.join("install/.rclone.retained").is_file());
    assert!(root.join("etc/rclone/rclone.conf").is_file());

    // 3. `package info rclone` and `package list` surface retained state non-breakingly.
    let info_inv =
        parse_cli_args(["--json", "--root", &root_str, "package", "info", "rclone"]).unwrap();
    let info_env = execute_invocation(&info_inv, &transport);
    assert_eq!(info_env.status, "ok");
    let info_data = info_env.data.as_ref().unwrap();
    assert_eq!(info_data["installed"], false);
    assert_eq!(info_data["retained_receipt_present"], true);
    assert_eq!(info_data["purge_eligibility"], "retained_proven");

    // 4. Live explicit purge dispatches PackageRunnerRequest with delete_data=true.
    let purge_live = parse_cli_args([
        "--json", "--root", &root_str, "package", "remove", "rclone", "--purge",
    ])
    .unwrap();
    let purge_live_env = execute_invocation(&purge_live, &transport);
    assert_eq!(purge_live_env.status, "ok", "{}", purge_live_env.message);
    {
        let calls = transport.package_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].action, "remove");
        assert_eq!(calls[0].package_id, "rclone");
        assert_eq!(calls[0].script_name, "removepackage-rclone");
        assert!(calls[0].delete_data);
    }

    // 5. After managed files & retained receipt are purged, subsequent --purge skips cleanly
    //    even while unrelated files and another package's retained receipt remain on disk.
    fs::remove_file(root.join("install/.rclone.retained")).unwrap();
    fs::remove_file(root.join("etc/rclone/rclone.conf")).unwrap();
    fs::remove_file(root.join("etc/rclone/rclone.env")).unwrap();
    fs::remove_dir_all(root.join("var/lib/rclone")).unwrap();

    let post_purge_dry = parse_cli_args([
        "--json",
        "--dry-run",
        "--root",
        &root_str,
        "package",
        "remove",
        "rclone",
        "--purge",
    ])
    .unwrap();
    let post_purge_env = execute_invocation(&post_purge_dry, &transport);
    assert_eq!(post_purge_env.status, "ok", "{}", post_purge_env.message);
    let post_data = post_purge_env.data.as_ref().unwrap();
    assert_eq!(post_data["planned_requests"].as_array().unwrap().len(), 0);
    assert_eq!(
        post_data["skipped_not_installed"],
        serde_json::json!(["rclone"])
    );
    assert_eq!(
        fs::read(root.join("usr/bin/rclone")).unwrap(),
        b"distro-rclone"
    );
    assert_eq!(
        fs::read(root.join("etc/rclone/custom.conf")).unwrap(),
        b"[custom]\n"
    );
    assert_eq!(
        fs::read(root.join("etc/aetherflow/aetherflow.env")).unwrap(),
        b"KEEP=1\n"
    );
    assert_eq!(
        fs::read(root.join("mnt/remote/sentinel")).unwrap(),
        b"keep-mount-data"
    );
    assert!(root.join("install/.sonarr.retained").is_file());
}

#[test]
fn cli_purge_handles_pre_fix_compatibility_ambiguous_markerless_and_never_managed() {
    let transport = MockRunnerTransport::default();

    // A. Pre-fix retained installation proved by SQLite retained_app_ingress_configs (no .retained file)
    {
        let tmp = TempTestDir::new("cli-prefix-ingress");
        let root = tmp.path();
        let root_str = root.to_string_lossy().into_owned();
        fs::create_dir_all(root.join("install")).unwrap();
        let db_path = root.join("var/lib/aetherflow/aetherflow.sqlite");
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        Connection::open(&db_path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL);
                 INSERT INTO retained_app_ingress_configs VALUES ('rclone', '{\"appName\":\"rclone\",\"listenPort\":5572}');",
            )
            .unwrap();

        let inv = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "package",
            "remove",
            "rclone",
            "--purge",
        ])
        .unwrap();
        let env = execute_invocation(&inv, &transport);
        assert_eq!(env.status, "ok", "{}", env.message);
        let data = env.data.as_ref().unwrap();
        assert_eq!(data["planned_requests"].as_array().unwrap().len(), 1);
        assert_eq!(data["planned_requests"][0]["delete_data"], true);
    }

    // B. Pre-fix retained installation proved by /etc/aetherflow/rclone.env (no .retained file, no DB)
    {
        let tmp = TempTestDir::new("cli-prefix-legacy-env");
        let root = tmp.path();
        let root_str = root.to_string_lossy().into_owned();
        fs::create_dir_all(root.join("etc/aetherflow")).unwrap();
        fs::write(root.join("etc/aetherflow/rclone.env"), b"RCLONE_USER=u\n").unwrap();

        let inv = parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "package",
            "remove",
            "rclone",
            "--purge",
        ])
        .unwrap();
        let env = execute_invocation(&inv, &transport);
        assert_eq!(env.status, "ok", "{}", env.message);
        assert_eq!(
            env.data.as_ref().unwrap()["planned_requests"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    // C. Ambiguous older markerless state (no .lock, no .retained, no DB retention proof,
    //    bare /etc/rclone/rclone.conf without AetherFlow header + pre-fix markerless remove job)
    //    MUST fail closed (exit 4), dispatch nothing, and preserve every file.
    {
        let tmp = TempTestDir::new("cli-ambiguous-markerless");
        let root = tmp.path();
        let root_str = root.to_string_lossy().into_owned();
        fs::create_dir_all(root.join("install")).unwrap();
        fs::create_dir_all(root.join("etc/rclone")).unwrap();
        fs::write(root.join("install/.sonarr.lock"), b"installed\n").unwrap();
        fs::write(
            root.join("etc/rclone/rclone.conf"),
            b"[personal-s3]\ntype = s3\n",
        )
        .unwrap();
        fs::write(root.join("etc/rclone/rclone.env"), b"RCLONE_USER=user\n").unwrap();
        let db_path = root.join("var/lib/aetherflow/aetherflow.sqlite");
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        Connection::open(&db_path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE package_lifecycle_jobs (
                    package_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, action TEXT NOT NULL,
                    status TEXT NOT NULL, started_at TEXT NOT NULL
                );
                INSERT INTO package_lifecycle_jobs VALUES ('rclone','legacy-rm-99','remove','completed','2026-01-01T00:00:00Z');",
            )
            .unwrap();

        // Batch containing an installed package (`sonarr`) + ambiguous (`rclone`) MUST fail
        // closed during preflight BEFORE dispatching `sonarr`.
        let batch_inv = parse_cli_args([
            "--json", "--root", &root_str, "package", "remove", "sonarr", "rclone", "--purge",
        ])
        .unwrap();
        let batch_env = execute_invocation(&batch_inv, &transport);
        assert_eq!(batch_env.status, "error");
        assert_eq!(batch_env.exit_code, 4);
        assert!(
            batch_env.message.contains("Refusing to purge 'rclone'"),
            "{}",
            batch_env.message
        );
        assert!(
            batch_env.message.contains("/etc/rclone/rclone.conf"),
            "{}",
            batch_env.message
        );
        assert!(
            batch_env.message.contains("legacy-rm-99"),
            "{}",
            batch_env.message
        );
        assert_eq!(transport.package_calls.lock().unwrap().len(), 0);
        assert_eq!(
            fs::read(root.join("etc/rclone/rclone.conf")).unwrap(),
            b"[personal-s3]\ntype = s3\n"
        );
    }

    // D. Never-managed installation with unrelated files and another package's retained state
    //    MUST skip cleanly without dispatching runner or touching any files.
    {
        let tmp = TempTestDir::new("cli-never-managed");
        let root = tmp.path();
        let root_str = root.to_string_lossy().into_owned();
        fs::create_dir_all(root.join("install")).unwrap();
        fs::create_dir_all(root.join("usr/bin")).unwrap();
        fs::create_dir_all(root.join("usr/local/bin")).unwrap();
        fs::create_dir_all(root.join("etc/rclone")).unwrap();
        fs::create_dir_all(root.join("etc/aetherflow")).unwrap();
        fs::create_dir_all(root.join("mnt/remote")).unwrap();
        fs::create_dir_all(root.join("usr/bin/rclone.af-backup.foreign")).unwrap();

        fs::write(root.join("usr/bin/rclone"), b"distro").unwrap();
        fs::write(root.join("usr/local/bin/rclone"), b"manual").unwrap();
        fs::write(root.join("etc/rclone/custom.conf"), b"unrelated").unwrap();
        fs::write(root.join("etc/aetherflow/aetherflow.env"), b"ENV=1").unwrap();
        fs::write(root.join("mnt/remote/sentinel"), b"data").unwrap();
        fs::write(
            root.join("usr/bin/rclone.af-backup.foreign/sentinel"),
            b"foreign",
        )
        .unwrap();
        fs::write(
            root.join("install/.sonarr.retained"),
            af_models::format_retained_package_receipt("sonarr", "2026-11-22T00:00:00Z"),
        )
        .unwrap();
        let db_path = root.join("var/lib/aetherflow/aetherflow.sqlite");
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        Connection::open(&db_path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL);
                 INSERT INTO retained_app_ingress_configs VALUES ('sonarr', '{\"appName\":\"sonarr\",\"listenPort\":8989}');",
            )
            .unwrap();

        for dry in [true, false] {
            let mut args = vec!["--json", "--root", &root_str];
            if dry {
                args.push("--dry-run");
            }
            args.extend(["package", "remove", "rclone", "--purge"]);
            let inv = parse_cli_args(args).unwrap();
            let env = execute_invocation(&inv, &transport);
            assert_eq!(env.status, "ok", "{}", env.message);
            let data = env.data.as_ref().unwrap();
            assert_eq!(data["skipped_not_installed"], serde_json::json!(["rclone"]));
            if dry {
                assert_eq!(data["planned_requests"].as_array().unwrap().len(), 0);
            } else {
                assert_eq!(data["receipts"].as_array().unwrap().len(), 0);
            }
        }
        assert_eq!(transport.package_calls.lock().unwrap().len(), 0);
        assert_eq!(fs::read(root.join("usr/bin/rclone")).unwrap(), b"distro");
        assert_eq!(
            fs::read(root.join("etc/rclone/custom.conf")).unwrap(),
            b"unrelated"
        );
        assert!(root.join("install/.sonarr.retained").is_file());
    }

    // E. Catalog allowlist is enforced before skip/inspection & symlink .retained fails closed.
    {
        let tmp = TempTestDir::new("cli-allowlist-and-symlink");
        let root = tmp.path();
        let root_str = root.to_string_lossy().into_owned();
        fs::create_dir_all(root.join("install")).unwrap();

        assert!(parse_cli_args([
            "--json",
            "--dry-run",
            "--root",
            &root_str,
            "package",
            "remove",
            "unlisted-pkg",
            "--purge",
        ])
        .is_err());

        // Direct programmatic command invocation must also enforce allowlist before skip.
        let direct_inv = ParsedInvocation {
            global: GlobalOptions {
                json: true,
                dry_run: true,
                root: Some(root.to_path_buf()),
                ..GlobalOptions::default()
            },
            command: AfCommand::Package(PackageCommand::Remove {
                packages: vec!["unlisted-pkg".to_string()],
                purge: true,
            }),
        };
        let direct_env = execute_invocation(&direct_inv, &transport);
        assert_eq!(direct_env.status, "error");
        assert_eq!(direct_env.exit_code, 2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = root.join("outside.retained");
            fs::write(
                &outside,
                af_models::format_retained_package_receipt("rclone", "2026-11-22T00:00:00Z"),
            )
            .unwrap();
            symlink(&outside, root.join("install/.rclone.retained")).unwrap();
            let sym_inv = parse_cli_args([
                "--json",
                "--dry-run",
                "--root",
                &root_str,
                "package",
                "remove",
                "rclone",
                "--purge",
            ])
            .unwrap();
            let sym_env = execute_invocation(&sym_inv, &transport);
            assert_eq!(sym_env.status, "error");
            assert_eq!(sym_env.exit_code, 4);
            assert!(
                sym_env.message.contains("not a regular file"),
                "{}",
                sym_env.message
            );
        }
        assert_eq!(transport.package_calls.lock().unwrap().len(), 0);
    }
}
