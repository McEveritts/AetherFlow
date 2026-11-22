use super::TempDir;
use crate::dir_ops::MAX_LIST_ENTRIES;
use crate::path::{parse_relative_path, UPLOAD_TEMP_PREFIX};
use crate::*;
use std::ffi::CString;
use std::fs;
use std::io::{Error, ErrorKind, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;

#[test]
fn nested_upload_directories_are_idempotent_and_confined() {
    let tmp = TempDir::new();
    let outside = TempDir::new();
    let filesystem = BrowserFs::open(tmp.path()).unwrap();
    filesystem
        .create_directory_all("albums/live/disc1")
        .unwrap();
    filesystem
        .create_directory_all("albums/live/disc1")
        .unwrap();
    let mut upload = filesystem
        .begin_upload("albums/live/disc1/track.txt")
        .unwrap();
    upload.write_all(b"track").unwrap();
    upload.commit().unwrap();
    assert_eq!(
        filesystem
            .begin_upload("albums/live/disc1/track.txt")
            .unwrap_err()
            .kind(),
        ErrorKind::AlreadyExists
    );
    symlink(outside.path(), tmp.path().join("external")).unwrap();
    assert!(filesystem.create_directory_all("external/escape").is_err());
    assert!(!outside.path().join("escape").exists());
    fs::write(tmp.path().join("plain-file"), b"unchanged").unwrap();
    assert!(filesystem.create_directory_all("plain-file/child").is_err());
    assert_eq!(
        fs::read(tmp.path().join("plain-file")).unwrap(),
        b"unchanged"
    );
    assert!(filesystem.create_directory_all("valid/../invalid").is_err());
    assert!(!tmp.path().join("valid").exists());
}

#[test]
fn removal_reports_bytes_and_rejects_hardlinked_files() {
    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();
    std::fs::write(tmp.path().join("file.txt"), b"payload").unwrap();
    assert_eq!(bfs.remove_with_size("file.txt").unwrap(), 7);
    bfs.create_directory("empty").unwrap();
    assert_eq!(bfs.remove_with_size("empty").unwrap(), 0);
    std::fs::write(tmp.path().join("linked.txt"), b"data").unwrap();
    std::fs::hard_link(tmp.path().join("linked.txt"), tmp.path().join("alias.txt")).unwrap();
    assert_eq!(
        bfs.remove_with_size("linked.txt").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert!(tmp.path().join("linked.txt").exists());
}

#[test]
fn open_rejects_non_directory_and_symlink_root() {
    let tmp = TempDir::new();
    let file_path = tmp.path().join("file.txt");
    fs::write(&file_path, b"hello").unwrap();
    assert!(BrowserFs::open(&file_path).is_err());

    let real_dir = tmp.path().join("real");
    fs::create_dir(&real_dir).unwrap();
    let symlink_root = tmp.path().join("link_root");
    symlink(&real_dir, &symlink_root).unwrap();
    assert!(BrowserFs::open(&symlink_root).is_err());
}

#[test]
fn invalid_paths_and_traversal_are_rejected() {
    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    for bad in [
        "..",
        "../etc/passwd",
        "a/../b",
        "a/../../b",
        ".",
        "./a",
        "a/./b",
        "/abs",
        "/etc/passwd",
        "/",
        "//",
        "a\\b",
        "\\root",
        "a\0b",
        ".af-upload-tmp.1234",
        "nested/.af-upload-tmp.1234",
    ] {
        assert!(bfs.scoped(bad).is_err(), "scoped should reject {bad:?}");
        assert!(bfs.list(bad).is_err(), "list should reject {bad:?}");
        assert!(bfs.metadata(bad).is_err(), "metadata should reject {bad:?}");
        assert!(bfs.walk(bad, 100).is_err(), "walk should reject {bad:?}");
        assert!(
            bfs.create_directory(bad).is_err(),
            "create_directory should reject {bad:?}"
        );
        assert!(bfs.remove(bad).is_err(), "remove should reject {bad:?}");
        assert!(
            bfs.remove_tree_with_size(bad).is_err(),
            "remove_tree_with_size should reject {bad:?}"
        );
        assert!(
            bfs.open_file(bad).is_err(),
            "open_file should reject {bad:?}"
        );
        assert!(
            bfs.begin_upload(bad).is_err(),
            "begin_upload should reject {bad:?}"
        );
        assert!(
            bfs.begin_replace(bad).is_err(),
            "begin_replace should reject {bad:?}"
        );
        assert!(
            bfs.rename(bad, "valid.txt").is_err(),
            "rename from should reject {bad:?}"
        );
        assert!(
            bfs.rename("valid.txt", bad).is_err(),
            "rename to should reject {bad:?}"
        );
        assert!(
            bfs.copy(bad, "valid.txt").is_err(),
            "copy from should reject {bad:?}"
        );
        assert!(
            bfs.copy("valid.txt", bad).is_err(),
            "copy to should reject {bad:?}"
        );
    }

    assert!(bfs.create_directory("").is_err());
    assert!(bfs.remove("").is_err());
    assert_eq!(bfs.remove_tree_with_size("").unwrap_err().removed_bytes, 0);
    assert!(bfs.open_file("").is_err());
    assert!(bfs.begin_upload("").is_err());
    assert!(bfs.begin_replace("").is_err());
    assert!(bfs.rename("", "dest").is_err());
    assert!(bfs.rename("src", "").is_err());
    assert!(bfs.copy("", "dest").is_err());
    assert!(bfs.copy("src", "").is_err());
}

#[test]
fn mkdir_upload_open_rename_remove_roundtrip() {
    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    assert!(bfs.list("").unwrap().is_empty());

    bfs.create_directory("media").unwrap();
    bfs.create_directory("media/movies").unwrap();
    assert_eq!(
        bfs.create_directory("media").unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );

    let upload = bfs.begin_upload("media/movies/clip.bin").unwrap();
    let mut writer = upload.file().unwrap();
    writer.write_all(b"streamed-payload-123").unwrap();
    writer.flush().unwrap();
    drop(writer);

    assert!(bfs.list("media/movies").unwrap().is_empty());
    upload.commit().unwrap();

    let entries = bfs.list("media/movies").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "clip.bin");
    assert_eq!(entries[0].path, "media/movies/clip.bin");
    assert_eq!(entries[0].kind, "file");
    assert_eq!(entries[0].size, 20);
    assert!(entries[0].modified.as_deref().unwrap().contains('T'));

    let serialized = serde_json::to_value(&entries[0]).unwrap();
    assert_eq!(serialized["name"], "clip.bin");
    assert_eq!(serialized["path"], "media/movies/clip.bin");
    assert_eq!(serialized["kind"], "file");
    assert_eq!(serialized["size"], 20);
    assert!(serialized["modified"].is_string());

    let mut reader = bfs.open_file("media/movies/clip.bin").unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"streamed-payload-123");

    bfs.rename("media/movies/clip.bin", "media/clip-renamed.bin")
        .unwrap();
    assert!(bfs.list("media/movies").unwrap().is_empty());

    let media_entries = bfs.list("media").unwrap();
    assert_eq!(media_entries.len(), 2);
    assert_eq!(media_entries[0].name, "movies");
    assert_eq!(media_entries[0].kind, "directory");
    assert_eq!(media_entries[0].path, "media/movies");
    assert_eq!(media_entries[1].name, "clip-renamed.bin");
    assert_eq!(media_entries[1].kind, "file");
    assert_eq!(media_entries[1].path, "media/clip-renamed.bin");

    assert!(bfs.remove("media").is_err());
    bfs.remove("media/movies").unwrap();
    bfs.remove("media/clip-renamed.bin").unwrap();
    bfs.remove("media").unwrap();
    assert!(bfs.list("").unwrap().is_empty());
}

#[test]
fn symlinks_in_ancestor_and_leaf_and_dangling_are_handled_safely() {
    let outside = TempDir::new();
    let outside_secret = outside.path().join("secret.txt");
    fs::write(&outside_secret, b"top-secret").unwrap();

    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    let ancestor_link = tmp.path().join("escape_dir");
    symlink(outside.path(), &ancestor_link).unwrap();

    let leaf_link = tmp.path().join("escape_file.txt");
    symlink(&outside_secret, &leaf_link).unwrap();

    let dangling_link = tmp.path().join("dangling.txt");
    symlink(outside.path().join("nonexistent"), &dangling_link).unwrap();

    let root_entries = bfs.list("").unwrap();
    assert_eq!(root_entries.len(), 3);
    for entry in &root_entries {
        assert_eq!(entry.kind, "symlink");
    }

    assert!(bfs.scoped("escape_dir").is_err());
    assert!(bfs.scoped("escape_dir/sub").is_err());
    assert!(bfs.list("escape_dir").is_err());
    assert!(bfs.metadata("escape_dir/secret.txt").is_err());
    assert!(bfs.walk("escape_dir", 100).is_err());
    assert!(bfs.walk("escape_dir/sub", 100).is_err());
    assert!(bfs.open_file("escape_dir/secret.txt").is_err());
    assert!(bfs.create_directory("escape_dir/new_dir").is_err());
    assert!(bfs.begin_upload("escape_dir/injected.txt").is_err());
    assert!(bfs.begin_replace("escape_dir/secret.txt").is_err());
    assert!(bfs.remove("escape_dir/secret.txt").is_err());
    assert!(bfs.remove_tree_with_size("escape_dir/secret.txt").is_err());
    assert!(bfs.remove_tree_with_size("escape_dir").is_err());
    assert!(bfs.rename("escape_dir/secret.txt", "stolen.txt").is_err());
    assert!(bfs.copy("escape_dir/secret.txt", "stolen.txt").is_err());

    assert!(bfs.scoped("escape_file.txt").is_err());
    assert!(bfs.scoped("dangling.txt").is_err());
    assert!(bfs.open_file("escape_file.txt").is_err());
    assert!(bfs.open_file("dangling.txt").is_err());
    assert!(bfs.begin_upload("escape_file.txt").is_err());
    assert!(bfs.begin_upload("dangling.txt").is_err());
    assert!(bfs.begin_replace("escape_file.txt").is_err());
    assert!(bfs.begin_replace("dangling.txt").is_err());
    assert!(bfs.remove("escape_file.txt").is_err());
    assert!(bfs.remove("dangling.txt").is_err());
    assert!(bfs.remove_tree_with_size("escape_file.txt").is_err());
    assert!(bfs.remove_tree_with_size("dangling.txt").is_err());
    assert!(bfs.rename("escape_file.txt", "moved.txt").is_err());
    assert!(bfs.copy("escape_file.txt", "copied.txt").is_err());
    assert!(bfs.copy("dangling.txt", "copied.txt").is_err());

    fs::write(tmp.path().join("real.txt"), b"real").unwrap();
    assert!(bfs.rename("real.txt", "escape_file.txt").is_err());
    assert!(bfs.rename("real.txt", "dangling.txt").is_err());
    assert!(bfs.rename("real.txt", "escape_dir/real.txt").is_err());
    assert!(bfs.copy("real.txt", "escape_file.txt").is_err());
    assert!(bfs.copy("real.txt", "dangling.txt").is_err());
    assert!(bfs.copy("real.txt", "escape_dir/real.txt").is_err());

    assert_eq!(fs::read(&outside_secret).unwrap(), b"top-secret");
}

#[test]
fn fifo_is_listed_as_other_and_open_file_rejects_without_blocking() {
    let tmp = TempDir::new();
    let fifo_path = tmp.path().join("pipe.fifo");
    let c_fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) };
    assert_eq!(rc, 0);

    let bfs = BrowserFs::open(tmp.path()).unwrap();
    let entries = bfs.list("").unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "pipe.fifo");
    assert_eq!(entries[0].kind, "other");

    let err = bfs.open_file("pipe.fifo").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidInput);

    assert!(bfs.scoped("pipe.fifo").is_err());
    assert_eq!(
        bfs.begin_replace("pipe.fifo").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert!(bfs.remove("pipe.fifo").is_err());
    assert!(bfs.remove_tree_with_size("pipe.fifo").is_err());
    assert!(bfs.rename("pipe.fifo", "renamed.fifo").is_err());
    assert!(bfs.copy("pipe.fifo", "copied.fifo").is_err());
}

#[test]
fn open_file_and_rename_reject_hardlinked_regular_files() {
    let outside = TempDir::new();
    let external_file = outside.path().join("control_plane.db");
    fs::write(&external_file, b"sensitive-control-plane-data").unwrap();

    let tmp = TempDir::new();
    let injected_hardlink = tmp.path().join("exposed.db");
    fs::hard_link(&external_file, &injected_hardlink).unwrap();

    let bfs = BrowserFs::open(tmp.path()).unwrap();
    let err = bfs.open_file("exposed.db").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
    assert_eq!(
        bfs.rename("exposed.db", "renamed_exposed.db")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert!(tmp.path().join("exposed.db").exists());
    assert!(!tmp.path().join("renamed_exposed.db").exists());

    let up = bfs.begin_upload("normal.txt").unwrap();
    up.file().unwrap().write_all(b"single-link").unwrap();
    up.commit().unwrap();

    let mut buf = String::new();
    bfs.open_file("normal.txt")
        .unwrap()
        .read_to_string(&mut buf)
        .unwrap();
    assert_eq!(buf, "single-link");

    fs::hard_link(
        tmp.path().join("normal.txt"),
        tmp.path().join("normal_link.txt"),
    )
    .unwrap();
    assert_eq!(
        bfs.open_file("normal.txt").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        bfs.open_file("normal_link.txt").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        bfs.rename("normal.txt", "normal_moved.txt")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        bfs.rename("normal_link.txt", "normal_link_moved.txt")
            .unwrap_err()
            .kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        bfs.begin_upload("normal.txt").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
    assert_eq!(
        bfs.begin_replace("normal.txt").unwrap_err().kind(),
        ErrorKind::PermissionDenied
    );
}

#[test]
fn rename_and_upload_refuse_to_clobber_existing_targets() {
    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    let up1 = bfs.begin_upload("a.txt").unwrap();
    up1.file().unwrap().write_all(b"first").unwrap();
    up1.commit().unwrap();

    let up2 = bfs.begin_upload("b.txt").unwrap();
    up2.file().unwrap().write_all(b"second").unwrap();
    up2.commit().unwrap();

    let err = bfs.rename("a.txt", "b.txt").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::AlreadyExists);

    let mut content_b = String::new();
    bfs.open_file("b.txt")
        .unwrap()
        .read_to_string(&mut content_b)
        .unwrap();
    assert_eq!(content_b, "second");

    let err = bfs.begin_upload("a.txt").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::AlreadyExists);

    let mut content_a = String::new();
    bfs.open_file("a.txt")
        .unwrap()
        .read_to_string(&mut content_a)
        .unwrap();
    assert_eq!(content_a, "first");

    let race_up1 = bfs.begin_upload("race.txt").unwrap();
    race_up1.file().unwrap().write_all(b"winner").unwrap();

    let race_up2 = bfs.begin_upload("race.txt").unwrap();
    race_up2.file().unwrap().write_all(b"loser").unwrap();

    race_up1.commit().unwrap();
    let err = race_up2.commit().unwrap_err();
    assert_eq!(err.kind(), ErrorKind::AlreadyExists);

    let mut winner_content = String::new();
    bfs.open_file("race.txt")
        .unwrap()
        .read_to_string(&mut winner_content)
        .unwrap();
    assert_eq!(winner_content, "winner");

    let raw_names: Vec<String> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!raw_names.iter().any(|n| n.starts_with(UPLOAD_TEMP_PREFIX)));
}

#[test]
fn dropped_upload_removes_only_its_own_temp_file_and_keeps_stranger_files() {
    let tmp = TempDir::new();
    let stranger = tmp.path().join(".stranger-temp.part");
    let fake_internal = tmp.path().join(format!("{UPLOAD_TEMP_PREFIX}foreign"));
    fs::write(&stranger, b"keep-me").unwrap();
    fs::write(&fake_internal, b"keep-foreign").unwrap();

    let bfs = BrowserFs::open(tmp.path()).unwrap();
    {
        let up = bfs.begin_upload("aborted.txt").unwrap();
        up.file().unwrap().write_all(b"partial").unwrap();

        let listed = bfs.list("").unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, ".stranger-temp.part");
    }

    assert!(!tmp.path().join("aborted.txt").exists());
    assert_eq!(fs::read(&stranger).unwrap(), b"keep-me");
    assert_eq!(fs::read(&fake_internal).unwrap(), b"keep-foreign");

    let remaining_temps: Vec<String> = fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(UPLOAD_TEMP_PREFIX))
        .collect();
    assert_eq!(
        remaining_temps,
        vec![format!("{UPLOAD_TEMP_PREFIX}foreign")]
    );
}

#[test]
fn non_utf8_filenames_are_skipped_without_lossy_collision_and_valid_siblings_are_listed() {
    let tmp = TempDir::new();
    let invalid_name = std::ffi::OsString::from_vec(vec![b'b', b'a', b'd', 0xff, 0xfe]);
    fs::write(tmp.path().join(&invalid_name), b"bad").unwrap();
    fs::write(tmp.path().join("valid-sibling.txt"), b"ok").unwrap();
    fs::create_dir(tmp.path().join("sub")).unwrap();
    fs::write(tmp.path().join("sub").join(&invalid_name), b"nested-bad").unwrap();
    fs::write(tmp.path().join("sub/nested-valid.txt"), b"nested-ok").unwrap();

    let bfs = BrowserFs::open(tmp.path()).unwrap();
    let listed = bfs.list("").unwrap();
    let listed_names: Vec<&str> = listed.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(listed_names, vec!["sub", "valid-sibling.txt"]);
    assert!(!listed_names.iter().any(|name| name.contains("bad")));

    let walked = bfs.walk("", 100).unwrap();
    let walked_paths: Vec<&str> = walked.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        walked_paths,
        vec!["sub", "sub/nested-valid.txt", "valid-sibling.txt"]
    );

    let (resolved_listed, _) = bfs.list_resolving_internal_links("").unwrap();
    assert_eq!(
        resolved_listed
            .iter()
            .map(|e| e.name.as_str())
            .collect::<Vec<_>>(),
        vec!["sub", "valid-sibling.txt"]
    );

    let (searched, truncated) = bfs.walk_for_search("", 100).unwrap();
    assert!(!truncated);
    assert_eq!(
        searched.iter().map(|e| e.path.as_str()).collect::<Vec<_>>(),
        vec!["sub", "valid-sibling.txt", "sub/nested-valid.txt"]
    );
}

#[test]
fn published_upload_remains_successful_when_directory_sync_fails() {
    let tmp = TempDir::new();
    let browser = BrowserFs::open(tmp.path()).unwrap();
    let upload = browser.begin_upload("published.txt").unwrap();
    upload
        .file()
        .unwrap()
        .write_all(b"accounted content")
        .unwrap();
    upload
        .commit_with_directory_sync(|_| Err(Error::from_raw_os_error(libc::EIO)))
        .unwrap();
    assert_eq!(
        fs::read(tmp.path().join("published.txt")).unwrap(),
        b"accounted content"
    );
    assert_eq!(browser.list("").unwrap().len(), 1);
}

#[test]
fn oversized_or_excessively_deep_paths_are_rejected_before_io() {
    assert!(parse_relative_path(&"x".repeat(4097), false).is_err());
    assert!(parse_relative_path(&"x".repeat(256), false).is_err());
    assert!(parse_relative_path(&vec!["x"; 65].join("/"), false).is_err());
    assert_eq!(
        parse_relative_path(&vec!["x"; 64].join("/"), false)
            .unwrap()
            .len(),
        64
    );
}

#[test]
fn repeated_and_concurrent_root_listings_and_walks_have_independent_offsets() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path().join("sub/deep")).unwrap();
    fs::write(tmp.path().join("visible.txt"), b"data").unwrap();
    fs::write(tmp.path().join("sub/deep/leaf.txt"), b"leaf").unwrap();
    let browser = BrowserFs::open(tmp.path()).unwrap();
    for _ in 0..3 {
        assert_eq!(browser.list("").unwrap().len(), 2);
        assert_eq!(browser.walk("", 100).unwrap().len(), 4);
    }
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                assert_eq!(browser.list("").unwrap().len(), 2);
                assert_eq!(browser.walk("", 100).unwrap().len(), 4);
            });
        }
    });
}

#[test]
fn list_enforces_10000_entry_limit() {
    let tmp = TempDir::new();
    for i in 0..=MAX_LIST_ENTRIES {
        let p = tmp.path().join(format!("f_{i:05}"));
        File::create(p).unwrap();
    }

    let bfs = BrowserFs::open(tmp.path()).unwrap();
    let err = bfs.list("").unwrap_err();
    assert_eq!(err.kind(), ErrorKind::Other);
}

#[test]
fn metadata_supports_root_and_entries_without_following_symlinks() {
    let outside = TempDir::new();
    let outside_file = outside.path().join("outside.txt");
    fs::write(&outside_file, b"outside-payload").unwrap();

    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    let root_meta = bfs.metadata("").unwrap();
    assert_eq!(root_meta.name, "");
    assert_eq!(root_meta.path, "");
    assert_eq!(root_meta.kind, "directory");
    assert_eq!(root_meta.size, 0);
    assert!(root_meta.modified.is_some());

    bfs.create_directory_all("docs/guides").unwrap();
    let mut up = bfs.begin_upload("docs/guides/intro.md").unwrap();
    up.write_all(b"# Welcome").unwrap();
    up.commit().unwrap();

    let dir_meta = bfs.metadata("docs//guides/").unwrap();
    assert_eq!(dir_meta.name, "guides");
    assert_eq!(dir_meta.path, "docs/guides");
    assert_eq!(dir_meta.kind, "directory");
    assert_eq!(dir_meta.size, 0);

    let file_meta = bfs.metadata("docs/guides/intro.md").unwrap();
    assert_eq!(file_meta.name, "intro.md");
    assert_eq!(file_meta.path, "docs/guides/intro.md");
    assert_eq!(file_meta.kind, "file");
    assert_eq!(file_meta.size, 9);

    symlink(&outside_file, tmp.path().join("docs/leaf_link")).unwrap();
    symlink(outside.path(), tmp.path().join("docs/dir_link")).unwrap();

    let sym_meta = bfs.metadata("docs/leaf_link").unwrap();
    assert_eq!(sym_meta.name, "leaf_link");
    assert_eq!(sym_meta.path, "docs/leaf_link");
    assert_eq!(sym_meta.kind, "symlink");

    assert!(bfs.metadata("docs/dir_link/outside.txt").is_err());
    assert_eq!(
        bfs.metadata("docs/missing.txt").unwrap_err().kind(),
        ErrorKind::NotFound
    );
}

#[test]
fn walk_returns_descendants_with_full_relative_paths_and_enforces_bounds_and_no_symlink_traversal()
{
    let outside = TempDir::new();
    fs::write(outside.path().join("secret.txt"), b"classified").unwrap();

    let tmp = TempDir::new();
    let bfs = BrowserFs::open(tmp.path()).unwrap();

    assert!(bfs.walk("", 0).unwrap().is_empty());

    bfs.create_directory_all("alpha/beta").unwrap();
    bfs.create_directory_all("gamma").unwrap();
    fs::write(tmp.path().join("root.txt"), b"r").unwrap();
    fs::write(tmp.path().join("alpha/a.txt"), b"aa").unwrap();
    fs::write(tmp.path().join("alpha/beta/b.txt"), b"bbb").unwrap();
    fs::write(
        tmp.path().join(format!("{UPLOAD_TEMP_PREFIX}hidden")),
        b"temp",
    )
    .unwrap();
    symlink(outside.path(), tmp.path().join("alpha/escape_dir")).unwrap();
    symlink(
        outside.path().join("secret.txt"),
        tmp.path().join("alpha/escape_file"),
    )
    .unwrap();

    let all = bfs.walk("", 100).unwrap();
    let paths: Vec<&str> = all.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        paths,
        vec![
            "alpha",
            "alpha/beta",
            "alpha/beta/b.txt",
            "alpha/a.txt",
            "alpha/escape_dir",
            "alpha/escape_file",
            "gamma",
            "root.txt",
        ]
    );
    assert!(!paths.iter().any(|p| p.contains("secret.txt")));
    assert!(!paths.iter().any(|p| p.contains(UPLOAD_TEMP_PREFIX)));

    let sub = bfs.walk("alpha", 100).unwrap();
    let sub_paths: Vec<&str> = sub.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(
        sub_paths,
        vec![
            "alpha/beta",
            "alpha/beta/b.txt",
            "alpha/a.txt",
            "alpha/escape_dir",
            "alpha/escape_file",
        ]
    );
    assert_eq!(sub[1].name, "b.txt");
    assert_eq!(sub[1].size, 3);

    assert_eq!(bfs.walk("alpha", 5).unwrap().len(), 5);
    for limit in 0..5 {
        let err = bfs.walk("alpha", limit).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::Other);
        assert_eq!(err.to_string(), "directory entry limit exceeded");
    }

    assert!(bfs.walk("root.txt", 10).is_err());
    assert!(bfs.walk("alpha/escape_dir", 10).is_err());
    assert!(bfs.walk("alpha/escape_dir/secret.txt", 10).is_err());
}
