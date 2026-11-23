use super::TempDir;
use crate::path::UPLOAD_TEMP_PREFIX;
use crate::*;
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;

#[test]
fn copy_files_and_recursive_directories_enforces_no_overwrite_and_cleans_up_failures() {
    let outside = TempDir::new();
    fs::write(outside.path().join("external.txt"), b"external").unwrap();

    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    bfs.create_directory_all("src/nested/empty_dir").unwrap();
    fs::write(tmp.path().join("src/top.txt"), b"hello").unwrap();
    fs::write(tmp.path().join("src/nested/deep.bin"), b"0123456789").unwrap();
    fs::write(
        tmp.path().join(format!("src/{UPLOAD_TEMP_PREFIX}ignored")),
        b"ignore-staging",
    )
    .unwrap();

    let file_bytes = bfs.copy("src/top.txt", "top_copy.txt").unwrap();
    assert_eq!(file_bytes, 5);
    assert_eq!(fs::read(tmp.path().join("top_copy.txt")).unwrap(), b"hello");

    let dir_bytes = bfs.copy("src", "dst").unwrap();
    assert_eq!(dir_bytes, 15);
    assert_eq!(fs::read(tmp.path().join("dst/top.txt")).unwrap(), b"hello");
    assert_eq!(
        fs::read(tmp.path().join("dst/nested/deep.bin")).unwrap(),
        b"0123456789"
    );
    assert!(tmp.path().join("dst/nested/empty_dir").is_dir());
    assert_eq!(bfs.walk("dst", 100).unwrap().len(), 4);

    // No overwrite of existing file or directory
    assert_eq!(
        bfs.copy("src/top.txt", "top_copy.txt").unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        bfs.copy("src", "dst").unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );
    assert_eq!(
        bfs.copy("src", "src").unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );

    // Reject copying a directory into itself or any descendant
    assert_eq!(
        bfs.copy("src", "src/sub_copy").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        bfs.copy("src", "src/nested/sub_copy").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert!(!tmp.path().join("src/sub_copy").exists());

    // Failure inside recursive directory copy (symlink) must be all-or-nothing and clean up staging
    bfs.create_directory_all("bad_symlink_tree/sub").unwrap();
    fs::write(tmp.path().join("bad_symlink_tree/good.txt"), b"valid-data").unwrap();
    symlink(
        outside.path().join("external.txt"),
        tmp.path().join("bad_symlink_tree/sub/link.txt"),
    )
    .unwrap();
    assert_eq!(
        bfs.copy("bad_symlink_tree", "failed_dst_1")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert!(!tmp.path().join("failed_dst_1").exists());

    // Failure inside recursive directory copy (hardlinked regular file) must clean up staging
    bfs.create_directory_all("bad_hardlink_tree/sub").unwrap();
    fs::write(tmp.path().join("bad_hardlink_tree/good.txt"), b"valid-data").unwrap();
    fs::hard_link(
        outside.path().join("external.txt"),
        tmp.path().join("bad_hardlink_tree/sub/hard.txt"),
    )
    .unwrap();
    assert_eq!(
        bfs.copy("bad_hardlink_tree", "failed_dst_2")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert!(!tmp.path().join("failed_dst_2").exists());

    let root_raw_names: Vec<String> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!root_raw_names
        .iter()
        .any(|n| n.starts_with(UPLOAD_TEMP_PREFIX)));
}

#[test]
fn remove_tree_with_size_deletes_trees_and_reports_partial_bytes_on_error() {
    let outside = TempDir::new();
    let outside_secret = outside.path().join("keep.txt");
    fs::write(&outside_secret, b"must-survive").unwrap();

    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    // Single regular file and full directory tree deletion
    fs::write(tmp.path().join("single.txt"), b"123456").unwrap();
    assert_eq!(bfs.remove_tree_with_size("single.txt").unwrap(), 6);
    assert!(!tmp.path().join("single.txt").exists());

    bfs.create_directory_all("tree/a/b").unwrap();
    bfs.create_directory_all("tree/empty").unwrap();
    fs::write(tmp.path().join("tree/root_file.bin"), b"1234").unwrap();
    fs::write(tmp.path().join("tree/a/mid.bin"), b"12345").unwrap();
    fs::write(tmp.path().join("tree/a/b/leaf.bin"), b"1234567").unwrap();
    assert_eq!(bfs.remove_tree_with_size("tree").unwrap(), 16);
    assert!(!tmp.path().join("tree").exists());

    // Partial deletion accounting when a directory contains valid files and a symlink
    bfs.create_directory_all("partial_sym/sub").unwrap();
    fs::write(tmp.path().join("partial_sym/top.txt"), b"12345").unwrap();
    fs::write(tmp.path().join("partial_sym/sub/nested.txt"), b"12345678").unwrap();
    symlink(&outside_secret, tmp.path().join("partial_sym/sub/a_link")).unwrap();

    let rem_err = bfs.remove_tree_with_size("partial_sym").unwrap_err();
    assert_eq!(rem_err.error.kind(), ErrorKind::PermissionDenied);
    assert_eq!(rem_err.removed_bytes, 13);
    assert!(!tmp.path().join("partial_sym/top.txt").exists());
    assert!(!tmp.path().join("partial_sym/sub/nested.txt").exists());
    assert!(tmp
        .path()
        .join("partial_sym/sub/a_link")
        .symlink_metadata()
        .is_ok());
    assert_eq!(fs::read(&outside_secret).unwrap(), b"must-survive");

    // Partial deletion accounting when a directory contains valid files and a hardlink
    bfs.create_directory_all("partial_hard/sub").unwrap();
    fs::write(tmp.path().join("partial_hard/file1.txt"), b"abcdef").unwrap();
    fs::write(tmp.path().join("partial_hard/sub/file2.txt"), b"0123456789").unwrap();
    fs::hard_link(
        &outside_secret,
        tmp.path().join("partial_hard/sub/a_hardlink.txt"),
    )
    .unwrap();

    let hard_err = bfs.remove_tree_with_size("partial_hard").unwrap_err();
    assert_eq!(hard_err.error.kind(), ErrorKind::PermissionDenied);
    assert_eq!(hard_err.removed_bytes, 16);
    assert!(tmp.path().join("partial_hard/sub/a_hardlink.txt").exists());
    assert_eq!(fs::read(&outside_secret).unwrap(), b"must-survive");
}

#[test]
fn commit_replace_verifies_identity_preserves_offsets_and_maintains_publication_semantics() {
    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    assert_eq!(
        bfs.begin_replace("missing.json").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    bfs.create_directory("dir_target").unwrap();
    assert_eq!(
        bfs.begin_replace("dir_target").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );

    let mut initial = bfs.begin_upload("config.json").unwrap();
    initial.write_all(b"{\"v\":1,\"mode\":\"old\"}").unwrap();
    initial.commit().unwrap();

    assert_eq!(
        bfs.begin_upload("config.json").unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );

    let mut expected_file = bfs.open_file("config.json").unwrap();
    let mut prefix = [0u8; 7];
    expected_file.read_exact(&mut prefix).unwrap();
    assert_eq!(&prefix, b"{\"v\":1,");

    // Atomic replacement with matching dev/ino succeeds
    let mut replacement = bfs.begin_replace("config.json").unwrap();
    replacement
        .write_all(b"{\"v\":2,\"mode\":\"new\"}")
        .unwrap();
    replacement.commit_replace(&expected_file).unwrap();

    // Previously opened file handle retains its own inode and descriptor offset
    let mut rest_of_old = String::new();
    expected_file.read_to_string(&mut rest_of_old).unwrap();
    assert_eq!(rest_of_old, "\"mode\":\"old\"}");

    // Newly opened handle sees the replaced file content
    let mut new_content = String::new();
    bfs.open_file("config.json")
        .unwrap()
        .read_to_string(&mut new_content)
        .unwrap();
    assert_eq!(new_content, "{\"v\":2,\"mode\":\"new\"}");

    // Identity mismatch: expected_file still points to v1 inode while config.json is now v2
    let mut stale_replace = bfs.begin_replace("config.json").unwrap();
    stale_replace.write_all(b"stale-overwrite").unwrap();
    let mismatch_err = stale_replace.commit_replace(&expected_file).unwrap_err();
    assert_eq!(mismatch_err.kind(), ErrorKind::AlreadyExists);

    let mut unchanged = String::new();
    bfs.open_file("config.json")
        .unwrap()
        .read_to_string(&mut unchanged)
        .unwrap();
    assert_eq!(unchanged, "{\"v\":2,\"mode\":\"new\"}");

    // Identity mismatch against a different file's handle
    fs::write(tmp.path().join("other.txt"), b"other").unwrap();
    let other_handle = bfs.open_file("other.txt").unwrap();
    let mut wrong_handle_up = bfs.begin_replace("config.json").unwrap();
    wrong_handle_up.write_all(b"wrong").unwrap();
    assert_eq!(
        wrong_handle_up
            .commit_replace(&other_handle)
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );

    // Target deleted before commit_replace fails with NotFound
    let v2_handle = bfs.open_file("config.json").unwrap();
    let mut deleted_target_up = bfs.begin_replace("config.json").unwrap();
    deleted_target_up.write_all(b"after-delete").unwrap();
    bfs.remove("config.json").unwrap();
    assert_eq!(
        deleted_target_up
            .commit_replace(&v2_handle)
            .unwrap_err()
            .kind(),
        ErrorKind::NotFound
    );
    assert!(!tmp.path().join("config.json").exists());

    // Hardlinked target before commit_replace is rejected with PermissionDenied
    fs::write(tmp.path().join("hard_target.txt"), b"initial").unwrap();
    let hard_expected = bfs.open_file("hard_target.txt").unwrap();
    let mut hard_replace = bfs.begin_replace("hard_target.txt").unwrap();
    hard_replace.write_all(b"replaced").unwrap();
    fs::hard_link(
        tmp.path().join("hard_target.txt"),
        tmp.path().join("hard_alias.txt"),
    )
    .unwrap();
    assert_eq!(
        bfs.begin_replace("hard_target.txt").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        hard_replace
            .commit_replace(&hard_expected)
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        fs::read(tmp.path().join("hard_target.txt")).unwrap(),
        b"initial"
    );
    fs::remove_file(tmp.path().join("hard_alias.txt")).unwrap();

    // Publication semantics: directory sync failure after renameat must still return Ok(())
    let sync_expected = bfs.open_file("hard_target.txt").unwrap();
    let mut sync_replace = bfs.begin_replace("hard_target.txt").unwrap();
    sync_replace
        .write_all(b"published-despite-dir-eio")
        .unwrap();
    sync_replace
        .commit_replace_with_directory_sync(&sync_expected, |_| {
            Err(Error::from_raw_os_error(libc::EIO))
        })
        .unwrap();
    assert_eq!(
        fs::read(tmp.path().join("hard_target.txt")).unwrap(),
        b"published-despite-dir-eio"
    );

    // Ensure no leftover staging files remain
    let raw_names: Vec<String> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!raw_names.iter().any(|n| n.starts_with(UPLOAD_TEMP_PREFIX)));
}

#[test]
fn scoped_opens_confined_subdirectory_and_duplicates_root_when_empty() {
    let outside = TempDir::new();
    fs::write(outside.path().join("outside.txt"), b"outside").unwrap();

    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    bfs.create_directory_all("tenants/alpha/docs").unwrap();
    bfs.create_directory_all("tenants/beta").unwrap();
    fs::write(tmp.path().join("root_secret.txt"), b"root-only").unwrap();
    fs::write(tmp.path().join("tenants/beta/beta.txt"), b"beta-only").unwrap();
    fs::write(tmp.path().join("tenants/alpha/hello.txt"), b"alpha-v1").unwrap();

    // Empty scope duplicates an independent root descriptor that survives dropping the original
    let root_dup = {
        let temp_root = BrowserFs::open(tmp.path()).unwrap();
        let dup = temp_root.scoped("").unwrap();
        assert_ne!(dup.root_fd.as_raw_fd(), temp_root.root_fd.as_raw_fd());
        dup
    };
    assert_eq!(root_dup.metadata("root_secret.txt").unwrap().size, 9);

    // Scoped subdirectory capability is isolated to `tenants/alpha`
    let alpha_fs = bfs.scoped("tenants//alpha/").unwrap();
    let root_meta = alpha_fs.metadata("").unwrap();
    assert_eq!(root_meta.kind, "directory");
    assert_eq!(root_meta.name, "");
    assert_eq!(root_meta.path, "");

    let entries = alpha_fs.list("").unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["docs", "hello.txt"]);

    // Cannot access parent or sibling entries from scoped capability
    assert_eq!(
        alpha_fs.open_file("root_secret.txt").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        alpha_fs.open_file("beta/beta.txt").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        alpha_fs.open_file("../beta/beta.txt").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );
    assert_eq!(
        alpha_fs.scoped("../beta").unwrap_err().kind(),
        ErrorKind::InvalidInput
    );

    // Create and replace inside scoped root affects only the scoped subtree
    let mut up = alpha_fs.begin_upload("docs/guide.md").unwrap();
    up.write_all(b"initial-guide").unwrap();
    up.commit().unwrap();
    assert_eq!(
        fs::read(tmp.path().join("tenants/alpha/docs/guide.md")).unwrap(),
        b"initial-guide"
    );

    let expected = alpha_fs.open_file("hello.txt").unwrap();
    let mut rep = alpha_fs.begin_replace("hello.txt").unwrap();
    rep.write_all(b"alpha-v2").unwrap();
    rep.commit_replace(&expected).unwrap();
    assert_eq!(
        fs::read(tmp.path().join("tenants/alpha/hello.txt")).unwrap(),
        b"alpha-v2"
    );

    // Nested scoping from an already-scoped BrowserFs
    let docs_fs = alpha_fs.scoped("docs").unwrap();
    let docs_list = docs_fs.list("").unwrap();
    assert_eq!(docs_list.len(), 1);
    assert_eq!(docs_list[0].name, "guide.md");
    assert_eq!(docs_list[0].path, "guide.md");

    // Reject missing directories, regular files, and symlinks (leaf or ancestor)
    assert_eq!(
        bfs.scoped("tenants/missing").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert!(bfs.scoped("tenants/alpha/hello.txt").is_err());

    symlink(outside.path(), tmp.path().join("tenants/alpha/sym_dir")).unwrap();
    assert!(bfs.scoped("tenants/alpha/sym_dir").is_err());
    assert!(bfs.scoped("tenants/alpha/sym_dir/child").is_err());
    assert!(alpha_fs.scoped("sym_dir").is_err());
    assert!(alpha_fs.scoped("sym_dir/child").is_err());
}

#[test]
fn replace_file_by_rename_atomically_replaces_verified_target_and_returns_replaced_bytes() {
    let temp_root = TempDir::new();
    let browser = BrowserFs::open(temp_root.path()).unwrap();
    browser.create_directory_all("source").unwrap();
    browser.create_directory_all("target").unwrap();

    fs::write(temp_root.path().join("source/new.txt"), b"replacement-15b").unwrap();
    fs::write(temp_root.path().join("target/old.txt"), b"old-7b!").unwrap();
    fs::write(temp_root.path().join("target/other.txt"), b"other").unwrap();

    let other_handle = browser.open_file("target/other.txt").unwrap();
    assert_eq!(
        browser
            .replace_file_by_rename("source/new.txt", "target/old.txt", &other_handle)
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    assert!(temp_root.path().join("source/new.txt").exists());
    assert_eq!(
        fs::read(temp_root.path().join("target/old.txt")).unwrap(),
        b"old-7b!"
    );

    let expected_handle = browser.open_file("target/old.txt").unwrap();
    let replaced_bytes = browser
        .replace_file_by_rename("source/new.txt", "target/old.txt", &expected_handle)
        .unwrap();
    assert_eq!(replaced_bytes, 7);
    assert!(!temp_root.path().join("source/new.txt").exists());
    assert_eq!(
        fs::read(temp_root.path().join("target/old.txt")).unwrap(),
        b"replacement-15b"
    );

    symlink("old.txt", temp_root.path().join("source/sym.txt")).unwrap();
    let current_handle = browser.open_file("target/old.txt").unwrap();
    assert_eq!(
        browser
            .replace_file_by_rename("source/sym.txt", "target/old.txt", &current_handle)
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
}

#[test]
fn remove_tree_and_empty_dir_clean_orphaned_upload_temp_files_and_subtrees_without_byte_credit() {
    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    // 1. Recursive delete with real files, an orphaned `.af-upload-tmp.*` file,
    // and a nested orphaned `.af-upload-tmp.*` directory subtree (as left by a crashed copy).
    bfs.create_directory_all("victim/nested").unwrap();
    fs::write(tmp.path().join("victim/real.txt"), b"hello").unwrap(); // 5 bytes
    fs::write(tmp.path().join("victim/nested/kept.bin"), b"0123456789").unwrap(); // 10 bytes
    fs::write(
        tmp.path()
            .join(format!("victim/{UPLOAD_TEMP_PREFIX}orphaned-file")),
        b"unstaged-upload-bytes-must-not-be-credited",
    )
    .unwrap();
    let orphan_dir = tmp
        .path()
        .join(format!("victim/nested/{UPLOAD_TEMP_PREFIX}orphaned-dir"));
    fs::create_dir_all(orphan_dir.join("deep/sub")).unwrap();
    fs::write(
        orphan_dir.join("part.bin"),
        b"unstaged-copy-dir-file-payload",
    )
    .unwrap();
    fs::write(
        orphan_dir.join("deep/sub/nested-part.bin"),
        b"deeper-unstaged-copy-payload",
    )
    .unwrap();

    let removed = bfs.remove_tree_with_size("victim").unwrap();
    assert_eq!(
        removed, 15,
        "only accounted user files (5 + 10 bytes) may be credited to removed_bytes"
    );
    assert!(!tmp.path().join("victim").exists());

    // 2. Non-recursive empty-directory removal succeeds with 0 byte credit when only orphaned
    // `.af-upload-tmp.*` files and temp subtrees remain inside the directory.
    bfs.create_directory("appears_empty").unwrap();
    fs::write(
        tmp.path()
            .join(format!("appears_empty/{UPLOAD_TEMP_PREFIX}stale-upload")),
        b"stale-temp-file",
    )
    .unwrap();
    let empty_orphan_sub = tmp
        .path()
        .join(format!("appears_empty/{UPLOAD_TEMP_PREFIX}stale-dir"));
    fs::create_dir_all(empty_orphan_sub.join("inner")).unwrap();
    fs::write(empty_orphan_sub.join("inner/data.bin"), b"stale-temp-tree").unwrap();

    assert!(bfs.list("appears_empty").unwrap().is_empty());
    assert_eq!(bfs.remove_with_size("appears_empty").unwrap(), 0);
    assert!(!tmp.path().join("appears_empty").exists());

    // 3. Non-recursive removal MUST still reject genuinely non-empty directories without
    // deleting sibling orphaned temp entries.
    bfs.create_directory("not_empty").unwrap();
    fs::write(tmp.path().join("not_empty/real.txt"), b"stay").unwrap();
    let sibling_temp = tmp
        .path()
        .join(format!("not_empty/{UPLOAD_TEMP_PREFIX}sibling"));
    fs::write(&sibling_temp, b"leave-untouched").unwrap();

    assert!(bfs.remove_with_size("not_empty").is_err());
    assert!(tmp.path().join("not_empty/real.txt").exists());
    assert!(sibling_temp.exists());
}

#[test]
fn remove_tree_skips_injected_mount_boundary_without_unlinking_mounted_files() {
    use crate::syscall::openat_no_symlinks_no_xdev;
    use std::path::PathBuf;

    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    // Create a user subtree containing a sibling local file, a nested mountpoint (`Media`),
    // and a directly mounted top-level user directory (`user-2`).
    bfs.create_directory_all("user-1/Media/Movies").unwrap();
    bfs.create_directory_all("user-1/Docs").unwrap();
    fs::write(tmp.path().join("user-1/Docs/notes.txt"), b"local-1234").unwrap(); // 10 bytes
    fs::write(tmp.path().join("user-1/Media/keep.mkv"), b"shared-media-1").unwrap();
    fs::write(
        tmp.path().join("user-1/Media/Movies/movie.mkv"),
        b"shared-media-2",
    )
    .unwrap();
    bfs.create_directory_all("user-2/Mounted").unwrap();
    fs::write(tmp.path().join("user-2/Mounted/data.bin"), b"top-mount").unwrap();

    // Inject EXDEV when opening "Media" (simulating Linux openat2 RESOLVE_NO_XDEV on a bind mount).
    let outcome = bfs
        .remove_tree_with_outcome_policy("user-1", true, &|dirfd, name, flags, mode, dev| {
            if name.to_bytes() == b"Media" {
                return Err(std::io::Error::from_raw_os_error(libc::EXDEV));
            }
            openat_no_symlinks_no_xdev(dirfd, name, flags, mode, dev)
        })
        .unwrap();

    assert_eq!(outcome.removed_bytes, 10);
    assert_eq!(outcome.skipped_mount_paths, vec![PathBuf::from("user-1/Media")]);
    assert!(
        !tmp.path().join("user-1/Docs").exists(),
        "non-mounted sibling subtree must still be cleaned"
    );
    assert!(
        tmp.path().join("user-1/Media/keep.mkv").is_file(),
        "files inside mountpoint must never be unlinked"
    );
    assert!(
        tmp.path().join("user-1/Media/Movies/movie.mkv").is_file(),
        "nested files inside mountpoint must never be unlinked"
    );

    // Inject EXDEV directly on the top-level target ("user-2") as if user-2 itself is a mountpoint.
    let top_outcome = bfs
        .remove_tree_with_outcome_policy("user-2", true, &|dirfd, name, flags, mode, dev| {
            if name.to_bytes() == b"user-2" {
                return Err(std::io::Error::from_raw_os_error(libc::EXDEV));
            }
            openat_no_symlinks_no_xdev(dirfd, name, flags, mode, dev)
        })
        .unwrap();
    assert_eq!(top_outcome.removed_bytes, 0);
    assert_eq!(top_outcome.skipped_mount_paths, vec![PathBuf::from("user-2")]);
    assert!(tmp.path().join("user-2/Mounted/data.bin").is_file());

    // Also test st_dev mismatch (simulating ENOSYS fallback where openat2 is unavailable and st_dev differs).
    let dev_mismatch_outcome = bfs
        .remove_tree_with_outcome_policy("user-1", true, &|dirfd, name, flags, mode, dev| {
            let fake_dev = if name.to_bytes() == b"Media" {
                dev.wrapping_add(1)
            } else {
                dev
            };
            openat_no_symlinks_no_xdev(dirfd, name, flags, mode, fake_dev)
        })
        .unwrap();
    assert_eq!(
        dev_mismatch_outcome.skipped_mount_paths,
        vec![PathBuf::from("user-1/Media")]
    );
    assert!(tmp.path().join("user-1/Media/keep.mkv").is_file());
}
