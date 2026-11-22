use super::TempDir;
use crate::*;
use std::ffi::CString;
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::symlink;

#[test]
fn internal_symlink_resolution_supports_nested_directory_and_file_links_with_proven_target_paths() {
    let temp_root = TempDir::new();
    let browser = BrowserFs::open(temp_root.path()).unwrap();

    browser
        .create_directory_all("real/albums/2026/live")
        .unwrap();
    browser.create_directory_all("aliases/music").unwrap();
    fs::write(
        temp_root.path().join("real/albums/2026/live/track01.flac"),
        b"lossless-audio-stream",
    )
    .unwrap();
    fs::write(
        temp_root.path().join("real/albums/2026/notes.txt"),
        b"liner-notes",
    )
    .unwrap();

    symlink(
        "../../real/albums/2026",
        temp_root.path().join("aliases/music/year_link"),
    )
    .unwrap();
    symlink(
        "live/track01.flac",
        temp_root.path().join("real/albums/2026/featured.flac"),
    )
    .unwrap();
    symlink(
        "year_link/featured.flac",
        temp_root.path().join("aliases/music/top_pick.flac"),
    )
    .unwrap();

    assert!(browser.open_file("aliases/music/top_pick.flac").is_err());
    assert!(browser
        .open_file("aliases/music/year_link/notes.txt")
        .is_err());
    assert!(browser.scoped("aliases/music/year_link").is_err());
    assert!(browser.list("aliases/music/year_link").is_err());

    let mut resolved_file = browser
        .open_file_resolving_internal_links("aliases/music/top_pick.flac")
        .unwrap();
    assert_eq!(
        resolved_file.resolved_path,
        "real/albums/2026/live/track01.flac"
    );
    assert_eq!(resolved_file.entry.name, "track01.flac");
    assert_eq!(
        resolved_file.entry.path,
        "real/albums/2026/live/track01.flac"
    );
    assert_eq!(resolved_file.entry.kind, "file");
    assert_eq!(resolved_file.entry.size, 21);
    let mut payload = Vec::new();
    resolved_file.file.read_to_end(&mut payload).unwrap();
    assert_eq!(payload, b"lossless-audio-stream");

    let resolved_meta = browser
        .metadata_resolving_internal_links("aliases/music/top_pick.flac")
        .unwrap();
    assert!(resolved_meta.was_symlink);
    assert_eq!(
        resolved_meta.resolved_path,
        "real/albums/2026/live/track01.flac"
    );
    assert_eq!(resolved_meta.entry.kind, "file");
    assert_eq!(resolved_meta.entry.size, 21);

    let direct_meta = browser
        .metadata_resolving_internal_links("real/albums/2026/notes.txt")
        .unwrap();
    assert!(!direct_meta.was_symlink);
    assert_eq!(direct_meta.resolved_path, "real/albums/2026/notes.txt");
    assert_eq!(direct_meta.entry.kind, "file");
    let redundant_separator_meta = browser
        .metadata_resolving_internal_links("real//albums/2026/notes.txt")
        .unwrap();
    assert!(!redundant_separator_meta.was_symlink);
    assert_eq!(
        redundant_separator_meta.resolved_path,
        direct_meta.resolved_path
    );

    let resolved_dir = browser
        .scoped_resolving_internal_links("aliases/music/year_link/live")
        .unwrap();
    assert_eq!(resolved_dir.resolved_path, "real/albums/2026/live");
    assert_eq!(resolved_dir.entry.name, "live");
    assert_eq!(resolved_dir.entry.path, "real/albums/2026/live");
    assert_eq!(resolved_dir.entry.kind, "directory");

    let scoped_entries = resolved_dir.fs.list("").unwrap();
    assert_eq!(scoped_entries.len(), 1);
    assert_eq!(scoped_entries[0].name, "track01.flac");
    assert_eq!(scoped_entries[0].path, "track01.flac");

    let (listed_via_link, list_target_path) = browser
        .list_resolving_internal_links("aliases/music/year_link")
        .unwrap();
    assert_eq!(list_target_path, "real/albums/2026");
    let listed_paths: Vec<&str> = listed_via_link
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(
        listed_paths,
        vec![
            "real/albums/2026/live",
            "real/albums/2026/featured.flac",
            "real/albums/2026/notes.txt",
        ]
    );
}

#[test]
fn internal_symlink_resolution_rejects_escapes_absolute_links_magiclinks_broken_and_loops() {
    let outside_dir = TempDir::new();
    let outside_file = outside_dir.path().join("outside_secret.txt");
    fs::write(&outside_file, b"external-secret").unwrap();

    let temp_root = TempDir::new();
    let browser = BrowserFs::open(temp_root.path()).unwrap();
    browser.create_directory_all("nested/inner").unwrap();
    fs::write(
        temp_root.path().join("nested/inner/internal.txt"),
        b"internal-ok",
    )
    .unwrap();

    symlink(
        &outside_file,
        temp_root.path().join("nested/abs_outside_file"),
    )
    .unwrap();
    symlink(
        outside_dir.path(),
        temp_root.path().join("nested/abs_outside_dir"),
    )
    .unwrap();

    let internal_abs_target = temp_root.path().join("nested/inner/internal.txt");
    symlink(
        &internal_abs_target,
        temp_root.path().join("nested/abs_in_tree_file"),
    )
    .unwrap();
    symlink(
        temp_root.path().join("nested/inner"),
        temp_root.path().join("nested/abs_in_tree_dir"),
    )
    .unwrap();

    symlink(
        "../../../outside_secret.txt",
        temp_root.path().join("nested/inner/rel_escape_file"),
    )
    .unwrap();
    symlink(
        "../../..",
        temp_root.path().join("nested/inner/rel_escape_dir"),
    )
    .unwrap();
    symlink(
        "../../../nested/inner/internal.txt",
        temp_root.path().join("nested/inner/bounce_outside_root"),
    )
    .unwrap();

    symlink("/proc/self/fd/0", temp_root.path().join("nested/magic_fd0")).unwrap();
    symlink(
        "/proc/self/root",
        temp_root.path().join("nested/magic_root"),
    )
    .unwrap();
    symlink("/proc/self/cwd", temp_root.path().join("nested/magic_cwd")).unwrap();

    symlink(
        "missing_target.txt",
        temp_root.path().join("nested/broken_leaf"),
    )
    .unwrap();
    symlink(
        "missing_dir/sub",
        temp_root.path().join("nested/broken_dir"),
    )
    .unwrap();

    symlink("loop_b", temp_root.path().join("nested/loop_a")).unwrap();
    symlink("loop_a", temp_root.path().join("nested/loop_b")).unwrap();

    for rejected_file in [
        "nested/abs_outside_file",
        "nested/abs_outside_dir/outside_secret.txt",
        "nested/abs_in_tree_file",
        "nested/abs_in_tree_dir/internal.txt",
        "nested/inner/rel_escape_file",
        "nested/inner/rel_escape_dir/outside_secret.txt",
        "nested/inner/bounce_outside_root",
        "nested/magic_fd0",
        "nested/magic_root/etc/passwd",
        "nested/magic_cwd",
        "nested/broken_leaf",
        "nested/broken_dir/file.txt",
        "nested/loop_a",
        "nested/loop_b",
    ] {
        assert!(
            browser
                .open_file_resolving_internal_links(rejected_file)
                .is_err(),
            "open_file_resolving_internal_links must reject {rejected_file}"
        );
        assert!(
            browser
                .metadata_resolving_internal_links(rejected_file)
                .is_err(),
            "metadata_resolving_internal_links must reject {rejected_file}"
        );
    }

    for rejected_dir in [
        "nested/abs_outside_dir",
        "nested/abs_in_tree_dir",
        "nested/inner/rel_escape_dir",
        "nested/magic_root",
        "nested/magic_cwd",
        "nested/broken_dir",
        "nested/loop_a",
    ] {
        assert!(
            browser
                .scoped_resolving_internal_links(rejected_dir)
                .is_err(),
            "scoped_resolving_internal_links must reject {rejected_dir}"
        );
        assert!(
            browser.list_resolving_internal_links(rejected_dir).is_err(),
            "list_resolving_internal_links must reject {rejected_dir}"
        );
    }

    assert_eq!(
        browser
            .open_file_resolving_internal_links("nested/broken_leaf")
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        browser
            .open_file_resolving_internal_links("nested/loop_a")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::ELOOP)
    );
    assert_eq!(fs::read(&outside_file).unwrap(), b"external-secret");
}

#[test]
fn scoped_capability_preserves_confinement_and_supports_parent_policy_target_authorization() {
    let temp_root = TempDir::new();
    let root_fs = BrowserFs::open(temp_root.path()).unwrap();

    root_fs
        .create_directory_all("tenants/alpha/public")
        .unwrap();
    root_fs
        .create_directory_all("tenants/alpha/private")
        .unwrap();
    root_fs.create_directory_all("tenants/beta/shared").unwrap();

    fs::write(
        temp_root.path().join("tenants/alpha/public/readme.txt"),
        b"public-doc",
    )
    .unwrap();
    fs::write(
        temp_root.path().join("tenants/alpha/private/secret.txt"),
        b"alpha-private-secret",
    )
    .unwrap();
    fs::write(
        temp_root.path().join("tenants/beta/shared/beta.txt"),
        b"beta-data",
    )
    .unwrap();

    symlink(
        "../private/secret.txt",
        temp_root
            .path()
            .join("tenants/alpha/public/sneaky_private_link.txt"),
    )
    .unwrap();
    symlink(
        "../../beta/shared/beta.txt",
        temp_root
            .path()
            .join("tenants/alpha/public/cross_tenant_link.txt"),
    )
    .unwrap();

    let alpha_fs = root_fs.scoped("tenants/alpha").unwrap();

    assert!(alpha_fs
        .open_file_resolving_internal_links("public/cross_tenant_link.txt")
        .is_err());

    let resolved_in_alpha = alpha_fs
        .open_file_resolving_internal_links("public/sneaky_private_link.txt")
        .unwrap();
    assert_eq!(resolved_in_alpha.resolved_path, "private/secret.txt");

    let is_allowed_by_mock_policy = |candidate_path: &str| !candidate_path.starts_with("private");
    assert!(is_allowed_by_mock_policy("public/sneaky_private_link.txt"));
    assert!(!is_allowed_by_mock_policy(&resolved_in_alpha.resolved_path));

    let public_only_fs = alpha_fs.scoped("public").unwrap();
    assert!(public_only_fs
        .open_file_resolving_internal_links("sneaky_private_link.txt")
        .is_err());
}

#[test]
fn concurrent_symlink_retarget_race_preserves_scope_confinement_and_target_proof() {
    let outside_dir = TempDir::new();
    fs::write(outside_dir.path().join("escape.txt"), b"outside-escape").unwrap();

    let temp_root = TempDir::new();
    let browser = BrowserFs::open(temp_root.path()).unwrap();
    browser.create_directory_all("allowed").unwrap();
    browser.create_directory_all("restricted").unwrap();
    browser.create_directory_all("links").unwrap();

    fs::write(temp_root.path().join("allowed/doc.txt"), b"allowed-payload").unwrap();
    fs::write(
        temp_root.path().join("restricted/secret.txt"),
        b"restricted-payload",
    )
    .unwrap();

    let active_link = temp_root.path().join("links/race_link.txt");
    symlink("../allowed/doc.txt", &active_link).unwrap();

    let stop_flag = std::sync::atomic::AtomicBool::new(false);
    let root_path_clone = temp_root.path().to_path_buf();
    let outside_file_path = outside_dir.path().join("escape.txt");

    std::thread::scope(|scope| {
        let writer_handle = scope.spawn(|| {
            let link_path = root_path_clone.join("links/race_link.txt");
            let staging_link = root_path_clone.join("links/swap_link.tmp");
            let mut iteration = 0usize;
            while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
                let target_str = match iteration % 3 {
                    0 => "../allowed/doc.txt".to_string(),
                    1 => "../restricted/secret.txt".to_string(),
                    _ => outside_file_path.to_string_lossy().into_owned(),
                };
                let _ = fs::remove_file(&staging_link);
                if symlink(&target_str, &staging_link).is_ok() {
                    let _ = fs::rename(&staging_link, &link_path);
                }
                iteration += 1;
            }
            let _ = fs::remove_file(&staging_link);
        });

        for _ in 0..120 {
            if let Ok(mut resolved) =
                browser.open_file_resolving_internal_links("links/race_link.txt")
            {
                let mut data = Vec::new();
                resolved.file.read_to_end(&mut data).unwrap();
                assert_ne!(data, b"outside-escape");
                match resolved.resolved_path.as_str() {
                    "allowed/doc.txt" => assert_eq!(data, b"allowed-payload"),
                    "restricted/secret.txt" => assert_eq!(data, b"restricted-payload"),
                    unexpected => panic!("unexpected resolved_path: {unexpected}"),
                }
            }
        }

        stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
        writer_handle.join().unwrap();
    });
}

#[test]
fn leaf_symlink_rename_and_unlink_operate_on_link_itself_with_zero_quota_and_preserve_targets() {
    let outside_dir = TempDir::new();
    let external_target = outside_dir.path().join("external_keep.txt");
    fs::write(&external_target, b"external-untouched").unwrap();

    let temp_root = TempDir::new();
    let browser = BrowserFs::open(temp_root.path()).unwrap();
    browser.create_directory_all("dir_a").unwrap();
    browser.create_directory_all("dir_b").unwrap();

    fs::write(
        temp_root.path().join("dir_a/target.txt"),
        b"internal-target-7777777",
    )
    .unwrap();
    fs::write(
        temp_root.path().join("dir_b/existing.txt"),
        b"do-not-clobber",
    )
    .unwrap();

    symlink("target.txt", temp_root.path().join("dir_a/internal_sym")).unwrap();
    symlink(
        &external_target,
        temp_root.path().join("dir_a/external_sym"),
    )
    .unwrap();
    symlink(
        "nonexistent.txt",
        temp_root.path().join("dir_a/dangling_sym"),
    )
    .unwrap();
    symlink(outside_dir.path(), temp_root.path().join("dir_a/dir_sym")).unwrap();

    assert_eq!(
        browser
            .rename("dir_a/internal_sym", "dir_b/moved_sym")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        browser
            .remove_with_size("dir_a/internal_sym")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );

    browser
        .rename_allowing_leaf_symlink("dir_a/internal_sym", "dir_b/moved_internal_sym")
        .unwrap();
    assert!(!temp_root
        .path()
        .join("dir_a/internal_sym")
        .symlink_metadata()
        .is_ok());
    assert!(temp_root
        .path()
        .join("dir_b/moved_internal_sym")
        .symlink_metadata()
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        fs::read(temp_root.path().join("dir_a/target.txt")).unwrap(),
        b"internal-target-7777777"
    );

    assert_eq!(
        browser
            .rename_allowing_leaf_symlink("dir_b/moved_internal_sym", "dir_b/existing.txt")
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        fs::read(temp_root.path().join("dir_b/existing.txt")).unwrap(),
        b"do-not-clobber"
    );

    assert!(browser
        .rename_allowing_leaf_symlink("dir_a/dir_sym/external_keep.txt", "dir_b/stolen.txt")
        .is_err());
    assert!(browser
        .rename_allowing_leaf_symlink("dir_b/moved_internal_sym", "dir_a/dir_sym/placed.txt")
        .is_err());
    assert!(browser
        .remove_with_size_allowing_leaf_symlink("dir_a/dir_sym/external_keep.txt")
        .is_err());

    let quota_delta_internal = browser
        .remove_with_size_allowing_leaf_symlink("dir_b/moved_internal_sym")
        .unwrap();
    assert_eq!(quota_delta_internal, 0);
    assert_eq!(
        fs::read(temp_root.path().join("dir_a/target.txt")).unwrap(),
        b"internal-target-7777777"
    );

    let quota_delta_external = browser
        .remove_with_size_allowing_leaf_symlink("dir_a/external_sym")
        .unwrap();
    assert_eq!(quota_delta_external, 0);
    assert_eq!(fs::read(&external_target).unwrap(), b"external-untouched");

    let quota_delta_dangling = browser
        .remove_with_size_allowing_leaf_symlink("dir_a/dangling_sym")
        .unwrap();
    assert_eq!(quota_delta_dangling, 0);

    browser
        .remove_allowing_leaf_symlink("dir_a/dir_sym")
        .unwrap();
    assert!(outside_dir.path().exists());
    assert_eq!(fs::read(&external_target).unwrap(), b"external-untouched");

    browser.create_directory_all("mixed_tree/sub").unwrap();
    fs::write(temp_root.path().join("mixed_tree/file1.bin"), b"12345").unwrap();
    fs::write(
        temp_root.path().join("mixed_tree/sub/file2.bin"),
        b"123456789",
    )
    .unwrap();
    symlink(
        &external_target,
        temp_root.path().join("mixed_tree/sub/ext_link"),
    )
    .unwrap();
    symlink(
        "../file1.bin",
        temp_root.path().join("mixed_tree/sub/int_link"),
    )
    .unwrap();

    let removed_tree_bytes = browser
        .remove_tree_with_size_allowing_symlinks("mixed_tree")
        .unwrap();
    assert_eq!(removed_tree_bytes, 14);
    assert!(!temp_root.path().join("mixed_tree").exists());
    assert_eq!(fs::read(&external_target).unwrap(), b"external-untouched");
}

#[test]
fn internal_link_resolution_rejects_fifo_and_hardlinked_targets_via_o_path_without_opening_special_files(
) {
    let temp_root = TempDir::new();
    let browser = BrowserFs::open(temp_root.path()).unwrap();
    browser.create_directory_all("dir").unwrap();

    let fifo_path = temp_root.path().join("dir/pipe.fifo");
    let fifo_cstring =
        CString::new(fifo_path.as_os_str().as_bytes()).expect("fifo path should not have NUL");
    let mkfifo_rc = unsafe { libc::mkfifo(fifo_cstring.as_ptr(), 0o600) };
    assert_eq!(mkfifo_rc, 0);

    symlink("pipe.fifo", temp_root.path().join("dir/fifo_link")).unwrap();
    assert_eq!(
        browser
            .metadata_resolving_internal_links("dir/fifo_link")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        browser
            .open_file_resolving_internal_links("dir/fifo_link")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        browser
            .scoped_resolving_internal_links("dir/fifo_link")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );

    let hardlink_source = temp_root.path().join("dir/hard_a.txt");
    let hardlink_alias = temp_root.path().join("dir/hard_b.txt");
    fs::write(&hardlink_source, b"hardlinked-payload").unwrap();
    fs::hard_link(&hardlink_source, &hardlink_alias).unwrap();
    symlink("hard_a.txt", temp_root.path().join("dir/hard_link")).unwrap();

    assert_eq!(
        browser
            .metadata_resolving_internal_links("dir/hard_link")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        browser
            .open_file_resolving_internal_links("dir/hard_link")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
}

#[test]
fn internal_symlink_resolution_traces_every_intermediate_hop_and_preserves_descendant_carveouts() {
    let temp_root = TempDir::new();
    let browser = BrowserFs::open(temp_root.path()).unwrap();

    browser.create_directory_all("docs").unwrap();
    browser.create_directory_all("public_dir/sub").unwrap();
    fs::write(temp_root.path().join("public.txt"), b"public-content").unwrap();
    fs::write(
        temp_root.path().join("public_dir/sub/item.txt"),
        b"item-content",
    )
    .unwrap();

    // Multi-hop chain:
    // folder-link -> docs
    // docs/secret-link -> ../public.txt
    // docs/dir-hop -> ../public_dir
    symlink("docs", temp_root.path().join("folder-link")).unwrap();
    symlink("../public.txt", temp_root.path().join("docs/secret-link")).unwrap();
    symlink("../public_dir", temp_root.path().join("docs/dir-hop")).unwrap();

    let expected_file_trace = vec![
        "folder-link/secret-link".to_string(),
        "docs/secret-link".to_string(),
        "public.txt".to_string(),
    ];

    let mut resolved_file = browser
        .open_file_resolving_internal_links("folder-link/secret-link")
        .unwrap();
    assert_eq!(resolved_file.resolved_path, "public.txt");
    assert_eq!(resolved_file.resolution_paths, expected_file_trace);
    let mut content = Vec::new();
    resolved_file.file.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"public-content");

    let resolved_meta = browser
        .metadata_resolving_internal_links("folder-link/secret-link")
        .unwrap();
    assert!(resolved_meta.was_symlink);
    assert_eq!(resolved_meta.resolved_path, "public.txt");
    assert_eq!(resolved_meta.resolution_paths, expected_file_trace);

    // Policy simulation: deny `docs/secret-link`, allow `folder-link/**` and `public.txt`.
    // Checking `resolution_paths` catches the denied intermediate hop `docs/secret-link`
    // without requiring read permission on every ordinary parent directory.
    let is_allowed = |candidate: &str| candidate != "docs/secret-link";
    assert!(is_allowed("folder-link/secret-link"));
    assert!(is_allowed(&resolved_file.resolved_path));
    assert!(!resolved_file
        .resolution_paths
        .iter()
        .all(|hop| is_allowed(hop)));

    // Directory chain with trailing descendant:
    // folder-link/dir-hop/sub -> docs/dir-hop/sub -> public_dir/sub
    let expected_dir_trace = vec![
        "folder-link/dir-hop/sub".to_string(),
        "docs/dir-hop/sub".to_string(),
        "public_dir/sub".to_string(),
    ];
    let resolved_dir = browser
        .scoped_resolving_internal_links("folder-link/dir-hop/sub")
        .unwrap();
    assert_eq!(resolved_dir.resolved_path, "public_dir/sub");
    assert_eq!(resolved_dir.resolution_paths, expected_dir_trace);

    let dir_meta = browser
        .metadata_resolving_internal_links("folder-link/dir-hop/sub")
        .unwrap();
    assert!(dir_meta.was_symlink);
    assert_eq!(dir_meta.resolved_path, "public_dir/sub");
    assert_eq!(dir_meta.resolution_paths, expected_dir_trace);

    let traced_listing = browser
        .list_with_trace_resolving_internal_links("folder-link/dir-hop/sub")
        .unwrap();
    assert_eq!(traced_listing.resolved_path, "public_dir/sub");
    assert_eq!(traced_listing.resolution_paths, expected_dir_trace);
    assert_eq!(traced_listing.entries.len(), 1);
    assert_eq!(traced_listing.entries[0].path, "public_dir/sub/item.txt");

    let (tuple_entries, tuple_resolved) = browser
        .list_resolving_internal_links("folder-link/dir-hop/sub")
        .unwrap();
    assert_eq!(tuple_resolved, "public_dir/sub");
    assert_eq!(tuple_entries, traced_listing.entries);

    // Direct non-symlink access has empty resolution_paths (ordinary parent directories are not added)
    let direct_file = browser
        .open_file_resolving_internal_links("public_dir/sub/item.txt")
        .unwrap();
    assert_eq!(direct_file.resolved_path, "public_dir/sub/item.txt");
    assert!(direct_file.resolution_paths.is_empty());

    let direct_meta = browser
        .metadata_resolving_internal_links("public_dir/sub/item.txt")
        .unwrap();
    assert!(!direct_meta.was_symlink);
    assert_eq!(direct_meta.resolved_path, "public_dir/sub/item.txt");
    assert!(direct_meta.resolution_paths.is_empty());

    // Regression 1: `deep-link -> real/sub`, `entry-link -> deep-link/../target.txt`
    // Must resolve `real/target.txt`, never record phantom root `target.txt`, and still
    // record `deep-link` so denying `deep-link` blocks traversal.
    browser.create_directory_all("real/sub").unwrap();
    fs::write(temp_root.path().join("real/target.txt"), b"real-target").unwrap();
    symlink("real/sub", temp_root.path().join("deep-link")).unwrap();
    symlink(
        "deep-link/../target.txt",
        temp_root.path().join("entry-link"),
    )
    .unwrap();

    let mut deep1 = browser
        .open_file_resolving_internal_links("entry-link")
        .unwrap();
    assert_eq!(deep1.resolved_path, "real/target.txt");
    assert!(!deep1
        .resolution_paths
        .iter()
        .any(|p| p == "target.txt" || p.contains("..")));
    assert_eq!(
        deep1.resolution_paths,
        vec![
            "entry-link".to_string(),
            "deep-link".to_string(),
            "real/target.txt".to_string(),
        ]
    );
    let mut deep1_bytes = Vec::new();
    deep1.file.read_to_end(&mut deep1_bytes).unwrap();
    assert_eq!(deep1_bytes, b"real-target");

    let deep1_meta = browser
        .metadata_resolving_internal_links("entry-link")
        .unwrap();
    assert_eq!(deep1_meta.resolved_path, "real/target.txt");
    assert_eq!(deep1_meta.resolution_paths, deep1.resolution_paths);

    // Regression 2: `deep-link-2 -> a/b/c`, `entry-link-2 -> deep-link-2/../../file.txt`
    // Must succeed (not fail with false outside-root error) and resolve `a/file.txt`.
    browser.create_directory_all("a/b/c").unwrap();
    fs::write(temp_root.path().join("a/file.txt"), b"a-file").unwrap();
    symlink("a/b/c", temp_root.path().join("deep-link-2")).unwrap();
    symlink(
        "deep-link-2/../../file.txt",
        temp_root.path().join("entry-link-2"),
    )
    .unwrap();

    let mut deep2 = browser
        .open_file_resolving_internal_links("entry-link-2")
        .unwrap();
    assert_eq!(deep2.resolved_path, "a/file.txt");
    assert!(!deep2.resolution_paths.iter().any(|p| p.contains("..")));
    assert_eq!(
        deep2.resolution_paths,
        vec![
            "entry-link-2".to_string(),
            "deep-link-2".to_string(),
            "a/file.txt".to_string(),
        ]
    );
    let mut deep2_bytes = Vec::new();
    deep2.file.read_to_end(&mut deep2_bytes).unwrap();
    assert_eq!(deep2_bytes, b"a-file");

    let deep2_meta = browser
        .metadata_resolving_internal_links("entry-link-2")
        .unwrap();
    assert_eq!(deep2_meta.resolved_path, "a/file.txt");
    assert_eq!(deep2_meta.resolution_paths, deep2.resolution_paths);
}
