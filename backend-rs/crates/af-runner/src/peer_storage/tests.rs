use super::*;
use crate::sandbox_ops::{
    apply_sandbox_dropins_in_dir, is_exempt_sandbox_unit, normalize_systemd_unit,
    render_systemd_sandbox_dropin,
};
use crate::{build_runner_router, dispatch_peer_storage, serve_runner_connections, ENV_TEST_MUTEX};
use serde_json::Value;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

const FAKE_STORAGE_BIN: &str = r##"#!/usr/bin/python3
import json, os, pathlib, signal, subprocess, sys, time

root = pathlib.Path(__file__).resolve().parent.parent
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]

with (root / "commands.jsonl").open("a") as out:
    out.write(json.dumps({"cmd": name, "args": args}) + "\n")

def marker(flag):
    return (root / flag).exists()

def parse_unit_where(unit):
    unit_file = root / "etc" / "systemd" / "system" / unit
    if not unit_file.exists():
        return None
    for line in unit_file.read_text().splitlines():
        if line.startswith("Where="):
            return line.split("=", 1)[1].strip()
    return None

if name == "exportfs":
    if args != ["-ra"]:
        raise RuntimeError(f"unexpected exportfs args: {args}")
    if marker("exportfs-hang"):
        time.sleep(60)
    if marker("exportfs-fail"):
        print("exportfs: simulated persistent failure", file=sys.stderr)
        sys.exit(1)
    if marker("exportfs-fail-next"):
        (root / "exportfs-fail-next").unlink()
        print("exportfs: simulated transient failure", file=sys.stderr)
        sys.exit(1)
    exports_dir = root / "etc" / "exports.d"
    snapshot = {}
    if exports_dir.exists():
        for entry in sorted(exports_dir.iterdir()):
            if entry.is_file() and entry.name.endswith(".exports"):
                snapshot[entry.name] = entry.read_text()
    (root / "live-exports.json").write_text(json.dumps(snapshot, sort_keys=True))
    sys.exit(0)

elif name == "systemctl":
    if args == ["daemon-reload"]:
        if marker("daemon-reload-fail"):
            print("Failed to reload daemon", file=sys.stderr)
            sys.exit(1)
        if marker("daemon-reload-fail-next"):
            (root / "daemon-reload-fail-next").unlink()
            print("Transient daemon-reload failure", file=sys.stderr)
            sys.exit(1)
        (root / "daemon-reloaded").touch()
        sys.exit(0)

    if len(args) != 2:
        raise RuntimeError(f"unexpected systemctl args: {args}")

    action, unit = args[0], args[1]
    if unit != "nfs-server.service" and not (unit.startswith("mnt-af\\x2dpeers-") and unit.endswith(".mount")):
        raise RuntimeError(f"unexpected systemd unit: {unit}")

    if unit == "nfs-server.service":
        if action == "is-active":
            if marker("nfs-server-active"):
                print("active")
                sys.exit(0)
            if marker("nfs-server-failed"):
                print("failed")
                sys.exit(3)
            print("inactive")
            sys.exit(3)
        if action == "enable":
            if marker("nfs-server-enable-fail"):
                print("Failed to enable nfs-server.service", file=sys.stderr)
                sys.exit(1)
            (root / "nfs-server-enabled").touch()
            sys.exit(0)
        if action == "restart":
            if marker("nfs-server-restart-fail"):
                (root / "nfs-server-failed").touch()
                print("Job for nfs-server.service failed", file=sys.stderr)
                sys.exit(1)
            if marker("nfs-server-restart-fail-next"):
                (root / "nfs-server-restart-fail-next").unlink()
                print("Transient nfs-server.service restart failure", file=sys.stderr)
                sys.exit(1)
            (root / "nfs-server-failed").unlink(missing_ok=True)
            (root / "nfs-server-active").touch()
            conf = root / "etc" / "nfs.conf.d" / "aetherflow-peers.conf"
            if conf.exists():
                (root / "live-nfsd.conf").write_text(conf.read_text())
            sys.exit(0)
        raise RuntimeError(f"unexpected nfs-server systemctl action: {args}")

    # Managed peer mount unit
    state_key = unit.replace("\\", "_").replace("/", "_")
    active_flag = root / f"mount-active-{state_key}"
    enabled_flag = root / f"mount-enabled-{state_key}"

    if action == "is-active":
        if active_flag.exists():
            print("active")
            sys.exit(0)
        print("inactive")
        sys.exit(3)
    if action == "start":
        if marker("mount-start-fail"):
            print(f"Job for {unit} failed", file=sys.stderr)
            sys.exit(1)
        where = parse_unit_where(unit)
        if where:
            mp = root / where.lstrip("/")
            mp.mkdir(parents=True, exist_ok=True)
            if marker("mount-populates-sentinel"):
                (mp / ".af-peer-sentinel").write_text("# Managed by AetherFlow Peer Clustering. Do not edit manually.\n")
        active_flag.touch()
        sys.exit(0)
    if action == "stop":
        if marker("mount-stop-fail"):
            print(f"Failed to stop {unit}", file=sys.stderr)
            sys.exit(1)
        where = parse_unit_where(unit)
        if where:
            mp = root / where.lstrip("/")
            sentinel = mp / ".af-peer-sentinel"
            if sentinel.exists():
                sentinel.unlink()
        active_flag.unlink(missing_ok=True)
        sys.exit(0)
    if action == "disable":
        if marker("mount-disable-fail"):
            print(f"Failed to disable {unit}", file=sys.stderr)
            sys.exit(1)
        enabled_flag.unlink(missing_ok=True)
        sys.exit(0)
    if action == "reset-failed":
        sys.exit(0)
    raise RuntimeError(f"unexpected mount systemctl args: {args}")

elif name == "dpkg-query":
    pkg = args[-1]
    if pkg not in ("nfs-kernel-server", "nfs-common"):
        raise RuntimeError(f"unexpected dpkg-query package: {pkg}")
    if marker(f"pkg-{pkg}-installed"):
        print("installed 1:2.8.3-1")
        sys.exit(0)
    print(f"dpkg-query: no packages found matching {pkg}", file=sys.stderr)
    sys.exit(1)

elif name == "apt-get":
    if os.environ.get("DEBIAN_FRONTEND") != "noninteractive":
        print("DEBIAN_FRONTEND must be noninteractive", file=sys.stderr)
        sys.exit(1)
    if "update" in args and marker("apt-update-fail"):
        print("E: Failed to fetch repository metadata", file=sys.stderr)
        sys.exit(100)
    if "install" in args and marker("apt-install-fail"):
        print("E: Unable to locate nfs package", file=sys.stderr)
        sys.exit(100)
    if "install" in args and marker("apt-hang-with-child"):
        if marker("apt-ignore-term"):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen(["/bin/sleep", "60"])
        (root / "apt-child.pid").write_text(str(child.pid))
        (root / "apt-hang-started").touch()
        child.wait()
        sys.exit(0)
    if "install" in args and not marker("apt-install-noop"):
        for pkg in ("nfs-kernel-server", "nfs-common"):
            if pkg in args:
                (root / f"pkg-{pkg}-installed").touch()
    sys.exit(0)

else:
    raise RuntimeError(f"unexpected binary: {name}")
"##;

struct StorageFixture {
    root: PathBuf,
    bin_dir: PathBuf,
}

impl StorageFixture {
    fn new() -> Self {
        let root = env::temp_dir().join(format!("af-peer-storage-{}", uuid::Uuid::new_v4()));
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).expect("create fixture bin dir");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod root");
        let driver = bin_dir.join("driver.py");
        fs::write(&driver, FAKE_STORAGE_BIN).expect("write fake bin");
        fs::set_permissions(&driver, fs::Permissions::from_mode(0o755)).expect("chmod fake bin");
        for tool in ["exportfs", "systemctl", "dpkg-query", "apt-get"] {
            symlink(&driver, bin_dir.join(tool)).expect("symlink fake tool");
        }
        Self { root, bin_dir }
    }

    fn manager(&self) -> PeerStorageManager {
        PeerStorageManager::new_isolated(
            self.root.clone(),
            self.bin_dir.clone(),
            DEFAULT_PEER_TUNNEL_CIDR,
        )
        .expect("build isolated PeerStorageManager")
    }

    fn manager_with_cidr(&self, cidr: &str) -> PeerStorageManager {
        PeerStorageManager::new_isolated(self.root.clone(), self.bin_dir.clone(), cidr)
            .expect("build isolated PeerStorageManager with cidr")
    }

    fn touch_marker(&self, name: &str) {
        fs::write(self.root.join(name), b"").expect("touch marker");
    }

    fn create_export_dir(&self, canonical_abs: &str) -> PathBuf {
        let full = self.root.join(canonical_abs.trim_start_matches('/'));
        fs::create_dir_all(&full).expect("create export dir");
        full
    }

    /// Creates a directory tree under `self.root` with strict 0o755 permissions on every created
    /// component (matching Linux `/etc/...` instead of Rust's umask-dependent `0o777 & ~umask`).
    fn create_system_dir(&self, rel: &str) -> PathBuf {
        let mut cur = self.root.clone();
        for part in rel.trim_start_matches('/').split('/') {
            if part.is_empty() {
                continue;
            }
            cur.push(part);
            if !cur.exists() {
                fs::create_dir(&cur).expect("create system dir");
            }
            fs::set_permissions(&cur, fs::Permissions::from_mode(0o755)).expect("chmod 0755");
        }
        cur
    }

    fn commands(&self) -> Vec<(String, Vec<String>)> {
        let path = self.root.join("commands.jsonl");
        let Ok(raw) = fs::read_to_string(path) else {
            return Vec::new();
        };
        raw.lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let v: Value = serde_json::from_str(line).expect("parse command log json");
                let cmd = v["cmd"].as_str().unwrap_or("").to_string();
                let args = v["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| a.as_str().unwrap_or("").to_string())
                    .collect();
                (cmd, args)
            })
            .collect()
    }

    fn clear_commands(&self) {
        let _ = fs::remove_file(self.root.join("commands.jsonl"));
    }
}

impl Drop for StorageFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn systemd_escape_path_matches_systemd_spec_and_rejects_traversal() {
    let cases = [
        ("/", "-"),
        (
            "/mnt/af-peers/media-2/movies",
            r"mnt-af\x2dpeers-media\x2d2-movies",
        ),
        (
            "/mnt/af-peers/link_1/tv.shows",
            r"mnt-af\x2dpeers-link_1-tv.shows",
        ),
        ("/mnt/af-peers/a/.dot", r"mnt-af\x2dpeers-a-.dot"),
        ("/mnt/af-peers/a/foo:bar", r"mnt-af\x2dpeers-a-foo:bar"),
        ("/mnt/af-peers/a/foo_bar", r"mnt-af\x2dpeers-a-foo_bar"),
        ("/mnt/af-peers/a/foo-bar", r"mnt-af\x2dpeers-a-foo\x2dbar"),
        ("/mnt/af-peers/a/foo+bar", r"mnt-af\x2dpeers-a-foo\x2bbar"),
        ("/mnt/af-peers/a/foo@bar", r"mnt-af\x2dpeers-a-foo\x40bar"),
        ("/mnt/af-peers/a/foo~bar", r"mnt-af\x2dpeers-a-foo\x7ebar"),
        ("/.leading-dot", r"\x2eleading\x2ddot"),
        ("/a/100%real", r"a-100\x25real"),
        ("/a/space dir", r"a-space\x20dir"),
        ("/a/ü", r"a-\xc3\xbc"),
    ];

    for (input, expected) in cases {
        let actual = systemd_escape_path(input).expect("escape valid path");
        assert_eq!(actual, expected, "path={input}");
    }

    // Cross-check against the host's real systemd-escape binary when installed (read-only).
    if Path::new("/usr/bin/systemd-escape").is_file() {
        for (input, expected) in cases {
            let output = std::process::Command::new("/usr/bin/systemd-escape")
                .args(["--path", input])
                .output()
                .expect("run systemd-escape --path");
            assert!(output.status.success(), "systemd-escape failed on {input}");
            let host_escaped = String::from_utf8_lossy(&output.stdout).trim().to_string();
            assert_eq!(
                host_escaped, expected,
                "mismatch vs host systemd-escape for {input}"
            );
        }
    }

    assert_eq!(
        systemd_escape_mount_unit("/mnt/af-peers/media-2/movies").unwrap(),
        r"mnt-af\x2dpeers-media\x2d2-movies.mount"
    );
    assert!(is_managed_peer_mount_unit(
        r"mnt-af\x2dpeers-media\x2d2-movies.mount"
    ));
    assert!(!is_managed_peer_mount_unit("mnt-storage.mount"));
    assert!(!is_managed_peer_mount_unit(
        r"mnt-af\x2dpeers-onlyone.mount"
    ));
    assert!(!is_managed_peer_mount_unit(r"mnt-af\x2dpeers-a-b.service"));
    assert!(!is_managed_peer_mount_unit(
        r"mnt-af\x2dpeers-a-b/evil.mount"
    ));

    for bad in [
        "",
        "relative/path",
        "/mnt/../etc",
        "/mnt/./a",
        "/mnt/af-peers/a\nb",
        "/mnt/af-peers/a\0b",
    ] {
        assert!(
            systemd_escape_path(bad).is_err(),
            "expected error escaping {bad:?}"
        );
    }
}

#[test]
fn validation_rejects_traversal_injection_and_restricted_paths() {
    assert_eq!(
        derive_peer_mount_path("media-2", "movies").unwrap(),
        "/mnt/af-peers/media-2/movies"
    );
    assert_eq!(
        derive_peer_export_file_name("link_01-a").unwrap(),
        "aetherflow-peer-link_01-a.exports"
    );

    for bad_link in ["", "../etc", "a/b", ".hidden", "-dash", "a.b", "a b"] {
        assert!(
            validate_peer_storage_link_id(bad_link).is_err(),
            "should reject link id {bad_link:?}"
        );
    }

    for bad_mount in [
        "/mnt/af-peers",
        "/mnt/af-peers/media-2",
        "/mnt/af-peers/media-2/movies/extra",
        "/mnt/af-peers/media-2/movies/",
        "/mnt/af-peers//media-2/movies",
        "/mnt/af-peers/../etc/passwd",
        "/mnt/af-peers/media-2/..",
        "/mnt/af-peers/media-2/.hidden",
        "/mnt/af-peers/media-2/a..b",
        "/etc/systemd/system",
    ] {
        assert!(
            validate_peer_mount_path(bad_mount).is_err(),
            "should reject mount path {bad_mount:?}"
        );
    }

    for bad_export in [
        "",
        "srv/media",
        "/",
        "/etc",
        "/etc/exports.d",
        "/etc/wireguard",
        "/proc/1",
        "/sys/fs",
        "/dev/shm",
        "/run/aetherflow",
        "/boot/grub",
        "/root/media",
        "/bin",
        "/usr/local",
        "/mnt/af-peers",
        "/mnt/af-peers/media-2/movies",
        "/var/lib/aetherflow",
        "/var/lib/aetherflow/db.sqlite",
        "/opt/AetherFlow/current",
        "/tmp",
        "/var/tmp",
        "/var",
        "/home",
        "/srv/media/",
        "/srv//media",
        "/srv/media/../etc",
        "/srv/media/./movies",
        "/srv/media/movies\n/etc *(rw)",
        "/srv/media/movies\"bad",
        "/srv/media/movies#comment",
        "/srv/media/movies*",
        "/srv/media/Movies:4K",
        "/srv/media/movies\u{85}",
        " /srv/media/movies",
    ] {
        assert!(
            validate_export_path_syntax(bad_export).is_err(),
            "should reject export path {bad_export:?}"
        );
    }

    for good_export in [
        "/srv/media/movies",
        "/srv/media/TV Shows",
        "/mnt/storage/library",
        "/home/alice/media",
        "/var/cache/jellyfin/transcodes",
        "/var/cache/jellyfin/af-tmp",
        "/tmp/af-test-dir/movies",
    ] {
        assert_eq!(
            validate_export_path_syntax(good_export).unwrap(),
            good_export
        );
    }
}

#[test]
fn export_options_and_spec_validation_enforced() {
    let ip_v4: IpAddr = "10.231.0.2".parse().unwrap();
    let specs = validate_export_specs(&[
        PeerStorageExportSpec {
            path: "/srv/media/TV Shows".to_string(),
            writable: true,
            squash_uid: Some(1000),
            squash_gid: Some(1001),
        },
        PeerStorageExportSpec {
            path: "/srv/media/movies".to_string(),
            writable: false,
            squash_uid: None,
            squash_gid: None,
        },
    ])
    .unwrap();
    let rendered = render_exports_file(ip_v4, &specs);
    let expected = format!(
        "{PEER_MANAGED_HEADER}\n\
         \"/srv/media/TV Shows\" 10.231.0.2(rw,all_squash,anonuid=1000,anongid=1001,secure,no_subtree_check)\n\
         /srv/media/movies 10.231.0.2(ro,root_squash,secure,no_subtree_check)\n"
    );
    assert_eq!(rendered, expected);

    // IPv6 renders without brackets in exports(5) and with brackets in NFS What=.
    let ip_v6: IpAddr = "fd00:231::2".parse().unwrap();
    assert_eq!(
        render_export_line(ip_v6, &specs[1]),
        "/srv/media/movies fd00:231::2(ro,root_squash,secure,no_subtree_check)"
    );
    let (what_v6, _, unit_v6) = render_nfs_mount_unit(
        "/mnt/af-peers/peer-v6/movies",
        ip_v6,
        "/srv/media/movies",
        false,
    );
    assert_eq!(what_v6, "[fd00:231::2]:/srv/media/movies");
    assert!(unit_v6.contains("What=[fd00:231::2]:/srv/media/movies\n"));

    // Writable export without squash uid/gid or targeting root is rejected.
    assert!(validate_export_specs(&[PeerStorageExportSpec {
        path: "/srv/media/movies".to_string(),
        writable: true,
        squash_uid: None,
        squash_gid: Some(1000),
    }])
    .is_err());
    assert!(validate_export_specs(&[PeerStorageExportSpec {
        path: "/srv/media/movies".to_string(),
        writable: true,
        squash_uid: Some(0),
        squash_gid: Some(1000),
    }])
    .is_err());
    assert!(validate_export_specs(&[PeerStorageExportSpec {
        path: "/srv/media/movies".to_string(),
        writable: true,
        squash_uid: Some(1000),
        squash_gid: Some(0),
    }])
    .is_err());

    // Read-only export with squash uid/gid set is rejected.
    assert!(validate_export_specs(&[PeerStorageExportSpec {
        path: "/srv/media/movies".to_string(),
        writable: false,
        squash_uid: Some(1000),
        squash_gid: None,
    }])
    .is_err());

    // Duplicate paths rejected.
    assert!(validate_export_specs(&[
        PeerStorageExportSpec {
            path: "/srv/media/movies".to_string(),
            writable: false,
            squash_uid: None,
            squash_gid: None,
        },
        PeerStorageExportSpec {
            path: "/srv/media/movies".to_string(),
            writable: true,
            squash_uid: Some(1000),
            squash_gid: Some(1000),
        },
    ])
    .is_err());
}

#[tokio::test]
async fn write_exports_idempotence_removal_rollback_and_host_preservation() {
    let fx = StorageFixture::new();
    let mgr = fx.manager();

    // Seed unrelated host exports and WireGuard files to prove strict isolation.
    fx.create_system_dir("etc/exports.d");
    fx.create_system_dir("etc/wireguard");
    let host_exports = fx.root.join("etc/exports");
    let custom_dropin = fx.root.join("etc/exports.d/host-custom.exports");
    let wg0_conf = fx.root.join("etc/wireguard/wg0.conf");
    fs::write(&host_exports, "/srv/host 192.168.1.0/24(ro,sync)\n").unwrap();
    fs::write(&custom_dropin, "/srv/custom 10.0.0.2(ro,sync)\n").unwrap();
    fs::write(&wg0_conf, "[Interface]\nListenPort = 51820\n").unwrap();

    fx.create_export_dir("/srv/media/movies");
    fx.create_export_dir("/srv/media/uploads");

    let specs = vec![
        PeerStorageExportSpec {
            path: "/srv/media/movies".to_string(),
            writable: false,
            squash_uid: None,
            squash_gid: None,
        },
        PeerStorageExportSpec {
            path: "/srv/media/uploads".to_string(),
            writable: true,
            squash_uid: Some(1000),
            squash_gid: Some(1000),
        },
    ];

    let resp = mgr
        .write_exports("link-alpha", "10.231.0.2", &specs)
        .await
        .expect("write exports");
    assert_eq!(
        resp.exports_path,
        "/etc/exports.d/aetherflow-peer-link-alpha.exports"
    );
    assert_eq!(resp.export_count, 2);
    assert!(resp.changed);
    assert!(!resp.removed);

    let disk_file = fx
        .root
        .join("etc/exports.d/aetherflow-peer-link-alpha.exports");
    let content = fs::read_to_string(&disk_file).unwrap();
    assert!(content.starts_with(PEER_MANAGED_HEADER));
    assert!(
        content.contains("/srv/media/movies 10.231.0.2(ro,root_squash,secure,no_subtree_check)")
    );
    assert!(content.contains(
        "/srv/media/uploads 10.231.0.2(rw,all_squash,anonuid=1000,anongid=1000,secure,no_subtree_check)"
    ));
    assert_eq!(fs::metadata(&disk_file).unwrap().mode() & 0o777, 0o644);

    // Idempotent repeat.
    let second = mgr
        .write_exports("link-alpha", "10.231.0.2", &specs)
        .await
        .expect("idempotent write exports");
    assert!(!second.changed);
    assert!(!second.removed);

    // Transient exportfs failure rolls back the modified file.
    fx.touch_marker("exportfs-fail-next");
    let err = mgr
        .write_exports("link-alpha", "10.231.0.3", &specs[..1])
        .await
        .unwrap_err();
    assert!(matches!(err, PeerStorageError::Runtime(_)));
    assert_eq!(fs::read_to_string(&disk_file).unwrap(), content);

    // Initial write failure removes newly created file cleanly.
    fx.touch_marker("exportfs-fail-next");
    let err_new = mgr
        .write_exports("link-beta", "10.231.0.4", &specs[..1])
        .await
        .unwrap_err();
    assert!(matches!(err_new, PeerStorageError::Runtime(_)));
    assert!(!fx
        .root
        .join("etc/exports.d/aetherflow-peer-link-beta.exports")
        .exists());

    // Empty exports list removes managed file and refreshes exportfs.
    let emptied = mgr
        .write_exports("link-alpha", "10.231.0.2", &[])
        .await
        .expect("empty exports removes file");
    assert!(emptied.changed);
    assert!(emptied.removed);
    assert_eq!(emptied.export_count, 0);
    assert!(!disk_file.exists());

    // Repeat RemoveExports when absent is an idempotent no-op without calling exportfs.
    fx.clear_commands();
    let noop = mgr
        .remove_exports("link-alpha")
        .await
        .expect("idempotent remove");
    assert!(!noop.changed);
    assert!(!noop.removed);
    assert!(fx.commands().is_empty());

    // Refuse overwriting unmanaged file at managed filename.
    fs::write(&disk_file, "/srv/manual 10.0.0.1(ro)\n").unwrap();
    let conflict = mgr
        .write_exports("link-alpha", "10.231.0.2", &specs[..1])
        .await
        .unwrap_err();
    assert!(
        conflict.is_conflict(),
        "expected Conflict, got {conflict:?}"
    );
    let conflict_rm = mgr.remove_exports("link-alpha").await.unwrap_err();
    assert!(conflict_rm.is_conflict());

    // Reject missing dir, symlink dir, and out-of-CIDR IP.
    let not_found = mgr
        .write_exports(
            "link-gamma",
            "10.231.0.5",
            &[PeerStorageExportSpec {
                path: "/srv/media/does-not-exist".to_string(),
                writable: false,
                squash_uid: None,
                squash_gid: None,
            }],
        )
        .await
        .unwrap_err();
    assert!(not_found.is_not_found());

    symlink(
        fx.root.join("srv/media/movies"),
        fx.root.join("srv/media/symlinked"),
    )
    .unwrap();
    let sym_err = mgr
        .write_exports(
            "link-gamma",
            "10.231.0.5",
            &[PeerStorageExportSpec {
                path: "/srv/media/symlinked".to_string(),
                writable: false,
                squash_uid: None,
                squash_gid: None,
            }],
        )
        .await
        .unwrap_err();
    assert!(sym_err.is_invalid_input());

    let bad_ip = mgr
        .write_exports("link-gamma", "192.168.1.5", &specs[..1])
        .await
        .unwrap_err();
    assert!(bad_ip.is_invalid_input());

    // Verify unrelated host files were untouched.
    assert_eq!(
        fs::read_to_string(&host_exports).unwrap(),
        "/srv/host 192.168.1.0/24(ro,sync)\n"
    );
    assert_eq!(
        fs::read_to_string(&custom_dropin).unwrap(),
        "/srv/custom 10.0.0.2(ro,sync)\n"
    );
    assert_eq!(
        fs::read_to_string(&wg0_conf).unwrap(),
        "[Interface]\nListenPort = 51820\n"
    );
}

#[tokio::test]
async fn configure_nfsd_binds_tunnel_only_idempotence_rollback_and_preservation() {
    let fx = StorageFixture::new();
    let mgr = fx.manager();

    // Seed host /etc/nfs.conf, unrelated nfs.conf.d drop-in, and unrelated nfs-server.service.d drop-in.
    fx.create_system_dir("etc/nfs.conf.d");
    fx.create_system_dir("etc/systemd/system/nfs-server.service.d");
    let main_nfs_conf = fx.root.join("etc/nfs.conf");
    let unrelated_dropin = fx.root.join("etc/nfs.conf.d/99-custom.conf");
    let unrelated_unit_dropin = fx
        .root
        .join("etc/systemd/system/nfs-server.service.d/10-custom.conf");
    fs::write(&main_nfs_conf, "[nfsd]\nthreads=8\n").unwrap();
    fs::write(&unrelated_dropin, "[mountd]\nmanage-gids=y\n").unwrap();
    fs::write(&unrelated_unit_dropin, "[Service]\nTimeoutStartSec=60\n").unwrap();

    let first = mgr
        .configure_nfsd("10.231.0.1")
        .await
        .expect("configure nfsd");
    assert_eq!(first.config_path, "/etc/nfs.conf.d/aetherflow-peers.conf");
    assert_eq!(first.tunnel_ip, "10.231.0.1");
    assert_eq!(first.service_unit, "nfs-server.service");
    assert_eq!(first.service_state, "active");
    assert!(first.changed);

    let conf_file = fx.root.join("etc/nfs.conf.d/aetherflow-peers.conf");
    let expected_conf = format!("{PEER_MANAGED_HEADER}\n[nfsd]\nhost=10.231.0.1\n");
    assert_eq!(fs::read_to_string(&conf_file).unwrap(), expected_conf);
    assert_eq!(fs::metadata(&conf_file).unwrap().mode() & 0o777, 0o644);

    let unit_dropin_file = fx
        .root
        .join("etc/systemd/system/nfs-server.service.d/20-aetherflow-peers.conf");
    let expected_dropin = format!(
        "{PEER_MANAGED_HEADER}\n[Unit]\nAfter=wg-quick@afpeer0.service\nWants=wg-quick@afpeer0.service\n"
    );
    assert_eq!(
        fs::read_to_string(&unit_dropin_file).unwrap(),
        expected_dropin
    );
    assert_eq!(
        fs::metadata(&unit_dropin_file).unwrap().mode() & 0o777,
        0o644
    );

    // Confirm systemctl daemon-reload ran before systemctl restart nfs-server.service.
    let first_cmds = fx.commands();
    let reload_idx = first_cmds
        .iter()
        .position(|(c, a)| c == "systemctl" && a == &vec!["daemon-reload".to_string()])
        .expect("systemctl daemon-reload must run when boot drop-in changes");
    let restart_idx = first_cmds
        .iter()
        .position(|(c, a)| {
            c == "systemctl" && a == &vec!["restart".to_string(), "nfs-server.service".to_string()]
        })
        .expect("systemctl restart nfs-server.service must run");
    assert!(
        reload_idx < restart_idx,
        "daemon-reload ({reload_idx}) must run before restart ({restart_idx})"
    );

    // Idempotent second call when nfs-server is already active skips both daemon-reload and restart.
    fx.clear_commands();
    let second = mgr
        .configure_nfsd("10.231.0.1")
        .await
        .expect("idempotent nfsd");
    assert!(!second.changed);
    assert_eq!(second.service_state, "active");
    let cmds = fx.commands();
    assert!(!cmds
        .iter()
        .any(|(c, a)| c == "systemctl" && a.first().map(String::as_str) == Some("daemon-reload")));
    assert!(!cmds
        .iter()
        .any(|(c, a)| c == "systemctl" && a.first().map(String::as_str) == Some("restart")));

    // Failed restart rolls back aetherflow-peers.conf to the previous working IP while keeping drop-in.
    fx.touch_marker("nfs-server-restart-fail-next");
    let err = mgr.configure_nfsd("10.231.0.9").await.unwrap_err();
    assert!(matches!(err, PeerStorageError::Runtime(_)));
    assert_eq!(fs::read_to_string(&conf_file).unwrap(), expected_conf);
    assert_eq!(
        fs::read_to_string(&unit_dropin_file).unwrap(),
        expected_dropin
    );

    // Refuse out-of-CIDR or network/broadcast tunnel IPs.
    assert!(mgr
        .configure_nfsd("0.0.0.0")
        .await
        .unwrap_err()
        .is_invalid_input());
    assert!(mgr
        .configure_nfsd("10.231.0.0")
        .await
        .unwrap_err()
        .is_invalid_input());
    assert!(mgr
        .configure_nfsd("10.231.255.255")
        .await
        .unwrap_err()
        .is_invalid_input());
    assert!(mgr
        .configure_nfsd("10.231.0.1/16")
        .await
        .unwrap_err()
        .is_invalid_input());

    // Refuse unmanaged file at aetherflow-peers.conf.
    fs::write(&conf_file, "[nfsd]\nhost=0.0.0.0\n").unwrap();
    assert!(mgr
        .configure_nfsd("10.231.0.1")
        .await
        .unwrap_err()
        .is_conflict());
    fs::write(&conf_file, &expected_conf).unwrap();

    // Refuse unmanaged file at nfs-server.service.d/20-aetherflow-peers.conf without modifying conf.
    fs::write(&unit_dropin_file, "[Unit]\nAfter=network.target\n").unwrap();
    assert!(mgr
        .configure_nfsd("10.231.0.2")
        .await
        .unwrap_err()
        .is_conflict());
    assert_eq!(fs::read_to_string(&conf_file).unwrap(), expected_conf);
    assert_eq!(
        fs::read_to_string(&unit_dropin_file).unwrap(),
        "[Unit]\nAfter=network.target\n"
    );

    // Host /etc/nfs.conf and unrelated drop-ins remain untouched.
    assert_eq!(
        fs::read_to_string(&main_nfs_conf).unwrap(),
        "[nfsd]\nthreads=8\n"
    );
    assert_eq!(
        fs::read_to_string(&unrelated_dropin).unwrap(),
        "[mountd]\nmanage-gids=y\n"
    );
    assert_eq!(
        fs::read_to_string(&unrelated_unit_dropin).unwrap(),
        "[Service]\nTimeoutStartSec=60\n"
    );

    // Fresh configure_nfsd failure during daemon-reload rolls back BOTH newly created files cleanly.
    let rb_fx = StorageFixture::new();
    let rb_mgr = rb_fx.manager();
    rb_fx.touch_marker("daemon-reload-fail-next");
    let rb_err = rb_mgr.configure_nfsd("10.231.0.1").await.unwrap_err();
    assert!(matches!(rb_err, PeerStorageError::Runtime(_)));
    assert!(!rb_fx
        .root
        .join("etc/nfs.conf.d/aetherflow-peers.conf")
        .exists());
    assert!(!rb_fx
        .root
        .join("etc/systemd/system/nfs-server.service.d/20-aetherflow-peers.conf")
        .exists());
}

#[tokio::test]
async fn ensure_sentinel_and_probe_sentinel_cover_lifecycle_and_safety() {
    let fx = StorageFixture::new();
    let mgr = fx.manager();

    let dir = fx.create_export_dir("/srv/media/movies");
    let first = mgr
        .ensure_sentinel("/srv/media/movies", false)
        .await
        .expect("create sentinel");
    assert!(first.created);
    assert_eq!(first.sentinel_path, "/srv/media/movies/.af-peer-sentinel");
    let sentinel_disk = dir.join(PEER_SENTINEL_FILE_NAME);
    assert!(sentinel_disk.is_file());
    assert_eq!(fs::metadata(&sentinel_disk).unwrap().mode() & 0o777, 0o644);
    assert!(fs::read_to_string(&sentinel_disk)
        .unwrap()
        .starts_with(PEER_MANAGED_HEADER));

    // Idempotent repeat.
    let second = mgr
        .ensure_sentinel("/srv/media/movies", false)
        .await
        .expect("idempotent sentinel");
    assert!(!second.created);
    assert_eq!(second.owner_uid, first.owner_uid);
    assert_eq!(second.owner_gid, first.owner_gid);

    // Direct non-privileged probe helper succeeds on healthy directory and fails on missing/symlink.
    let ok_probe = probe_sentinel_file(&dir, Duration::from_secs(2)).await;
    assert!(ok_probe.healthy);
    assert!(!ok_probe.timed_out);
    assert!(ok_probe.error.is_none());

    // Unmanaged foreign sentinel content is rejected with Conflict.
    fs::write(&sentinel_disk, "user-created important file\n").unwrap();
    assert!(mgr
        .ensure_sentinel("/srv/media/movies", false)
        .await
        .unwrap_err()
        .is_conflict());

    // Symlink sentinel is rejected both on EnsureSentinel and probe.
    fs::remove_file(&sentinel_disk).unwrap();
    let target = fx.root.join("decoy.txt");
    fs::write(&target, "decoy").unwrap();
    symlink(&target, &sentinel_disk).unwrap();
    assert!(mgr
        .ensure_sentinel("/srv/media/movies", false)
        .await
        .unwrap_err()
        .is_invalid_input());
    let sym_probe = probe_sentinel_file(&dir, Duration::from_secs(2)).await;
    assert!(!sym_probe.healthy);
    assert!(!sym_probe.timed_out);

    // Hard-linked sentinel is rejected by EnsureSentinel.
    fs::remove_file(&sentinel_disk).unwrap();
    fs::write(&target, format!("{PEER_MANAGED_HEADER}\n")).unwrap();
    fs::hard_link(&target, &sentinel_disk).unwrap();
    assert!(mgr
        .ensure_sentinel("/srv/media/movies", false)
        .await
        .unwrap_err()
        .is_invalid_input());

    // ProbeSentinel via manager checks mount path under /mnt/af-peers/<link>/<export>.
    let mp = fx.create_export_dir("/mnt/af-peers/media-2/movies");
    let missing = mgr
        .probe_sentinel("/mnt/af-peers/media-2/movies", Some(1000))
        .await
        .expect("probe missing sentinel");
    assert!(!missing.healthy);
    assert!(!missing.timed_out);

    fs::write(
        mp.join(PEER_SENTINEL_FILE_NAME),
        format!("{PEER_MANAGED_HEADER}\n"),
    )
    .unwrap();
    let present = mgr
        .probe_sentinel("/mnt/af-peers/media-2/movies", Some(1000))
        .await
        .expect("probe present sentinel");
    assert!(present.healthy);
    assert_eq!(
        present.sentinel_path,
        "/mnt/af-peers/media-2/movies/.af-peer-sentinel"
    );

    // Out-of-range timeout_ms rejected.
    assert!(mgr
        .probe_sentinel("/mnt/af-peers/media-2/movies", Some(50))
        .await
        .unwrap_err()
        .is_invalid_input());
    assert!(mgr
        .probe_sentinel("/mnt/af-peers/media-2/movies", Some(60_000))
        .await
        .unwrap_err()
        .is_invalid_input());
}

#[tokio::test]
async fn mount_unit_can_use_full_filename_length() {
    let fx = StorageFixture::new();
    let mgr = fx.manager();
    let mount_path = format!("/mnt/af-peers/a{}/b{}xy", "-".repeat(30), "-".repeat(27));
    let unit = systemd_escape_mount_unit(&mount_path).unwrap();
    assert_eq!(unit.len(), MAX_SYSTEMD_UNIT_NAME_BYTES);

    mgr.write_mount(&mount_path, "10.231.0.2", "/srv/media/movies", false)
        .await
        .expect("write mount with a 255-byte unit filename");
    assert!(fx.root.join("etc/systemd/system").join(unit).is_file());
}

#[tokio::test]
async fn mount_unit_lifecycle_start_stop_remove_rollback_and_preservation() {
    let fx = StorageFixture::new();
    let mgr = fx.manager();

    // Seed unrelated host systemd mount unit.
    fx.create_system_dir("etc/systemd/system");
    let host_unit = fx.root.join("etc/systemd/system/mnt-host-backup.mount");
    fs::write(
        &host_unit,
        "[Mount]\nWhat=/dev/sdb1\nWhere=/mnt/host/backup\n",
    )
    .unwrap();

    let mount_path = "/mnt/af-peers/media-2/movies";
    let expected_unit = r"mnt-af\x2dpeers-media\x2d2-movies.mount";
    let unit_disk = fx.root.join("etc/systemd/system").join(expected_unit);

    let written = mgr
        .write_mount(mount_path, "10.231.0.2", "/srv/media/movies", false)
        .await
        .expect("write ro mount");
    assert_eq!(written.unit_name, expected_unit);
    assert_eq!(written.what, "10.231.0.2:/srv/media/movies");
    assert_eq!(written.fs_type, "nfs4");
    assert!(!written.writable);
    assert!(written.changed);
    assert!(written.options.contains("vers=4.2"));
    assert!(written.options.contains("soft"));
    assert!(written.options.contains("timeo=100"));
    assert!(written.options.contains("retrans=2"));
    assert!(written.options.contains(",ro,"));
    assert!(written.options.contains("_netdev"));
    assert!(written
        .options
        .contains("x-systemd.requires=wg-quick@afpeer0.service"));

    let unit_text = fs::read_to_string(&unit_disk).unwrap();
    assert!(unit_text.starts_with(PEER_MANAGED_HEADER));
    assert!(unit_text.contains("Requires=wg-quick@afpeer0.service\n"));
    assert!(unit_text.contains("PartOf=wg-quick@afpeer0.service\n"));
    assert!(unit_text.contains("Type=nfs4\n"));
    assert!(unit_text.contains("ForceUnmount=yes\n"));
    // Unstarted mount does NOT expose an empty leaf directory to media apps.
    assert!(!fx.root.join("mnt/af-peers/media-2/movies").exists());

    // Idempotent repeat skips daemon-reload.
    fx.clear_commands();
    let repeat = mgr
        .write_mount(mount_path, "10.231.0.2", "/srv/media/movies", false)
        .await
        .expect("idempotent write mount");
    assert!(!repeat.changed);
    assert!(fx.commands().is_empty());

    // Rollback on daemon-reload failure preserves prior unit content.
    fx.touch_marker("daemon-reload-fail-next");
    let reload_err = mgr
        .write_mount(mount_path, "10.231.0.2", "/srv/media/movies", true)
        .await
        .unwrap_err();
    assert!(matches!(reload_err, PeerStorageError::Runtime(_)));
    assert_eq!(fs::read_to_string(&unit_disk).unwrap(), unit_text);

    // StartMount activates the unit and sentinel probe passes.
    fx.touch_marker("mount-populates-sentinel");
    let started = mgr.start_mount(mount_path).await.expect("start mount");
    assert!(started.exists);
    assert!(started.active);
    assert_eq!(started.unit_state, "active");
    let status = mgr.mount_status(mount_path).await.expect("mount status");
    assert!(status.active);
    assert!(
        mgr.probe_sentinel(mount_path, Some(2000))
            .await
            .unwrap()
            .healthy
    );

    // StopMount deactivates the unit AND removes the empty leaf mountpoint dir.
    let stopped = mgr.stop_mount(mount_path).await.expect("stop mount");
    assert!(stopped.exists);
    assert!(!stopped.active);
    assert_eq!(stopped.unit_state, "inactive");
    assert!(
        !fx.root.join("mnt/af-peers/media-2/movies").exists(),
        "empty leaf mountpoint must disappear after StopMount"
    );
    assert!(
        !mgr.probe_sentinel(mount_path, Some(2000))
            .await
            .unwrap()
            .healthy
    );

    // RemoveMount fails safely without unlinking unit if stop fails.
    fx.touch_marker("mount-stop-fail");
    assert!(matches!(
        mgr.remove_mount(mount_path).await.unwrap_err(),
        PeerStorageError::Runtime(_)
    ));
    assert!(unit_disk.exists());
    fs::remove_file(fx.root.join("mount-stop-fail")).unwrap();

    // RemoveMount rolls back unit file if daemon-reload fails after unlink.
    fx.touch_marker("daemon-reload-fail-next");
    assert!(matches!(
        mgr.remove_mount(mount_path).await.unwrap_err(),
        PeerStorageError::Runtime(_)
    ));
    assert_eq!(fs::read_to_string(&unit_disk).unwrap(), unit_text);

    // Clean RemoveMount unlinks unit and prunes empty mount dirs.
    let removed = mgr.remove_mount(mount_path).await.expect("remove mount");
    assert!(removed.removed);
    assert!(removed.stopped);
    assert!(!unit_disk.exists());
    assert!(!fx.root.join("mnt/af-peers/media-2").exists());

    // Idempotent repeat RemoveMount.
    let removed_again = mgr
        .remove_mount(mount_path)
        .await
        .expect("idempotent remove mount");
    assert!(!removed_again.removed);
    assert!(!removed_again.stopped);

    // Refuse unmanaged pre-existing .mount unit at derived filename.
    fs::write(
        &unit_disk,
        "[Mount]\nWhat=foreign\nWhere=/mnt/af-peers/media-2/movies\n",
    )
    .unwrap();
    assert!(mgr
        .write_mount(mount_path, "10.231.0.2", "/srv/media/movies", false)
        .await
        .unwrap_err()
        .is_conflict());
    assert!(mgr.start_mount(mount_path).await.unwrap_err().is_conflict());
    assert!(mgr.stop_mount(mount_path).await.unwrap_err().is_conflict());
    assert!(mgr
        .remove_mount(mount_path)
        .await
        .unwrap_err()
        .is_conflict());

    // Unrelated host unit remains intact.
    assert_eq!(
        fs::read_to_string(&host_unit).unwrap(),
        "[Mount]\nWhat=/dev/sdb1\nWhere=/mnt/host/backup\n"
    );
}

#[tokio::test]
async fn write_bind_mount_validates_source_and_writes_bind_unit() {
    let fx = StorageFixture::new();
    let mgr = fx.manager();

    fx.create_export_dir("/srv/media/movies");
    let mount_path = "/mnt/af-peers/media-2/movies";

    let resp = mgr
        .write_bind_mount("/srv/media/movies", mount_path, false)
        .await
        .expect("write bind mount");
    assert_eq!(resp.unit_name, r"mnt-af\x2dpeers-media\x2d2-movies.mount");
    assert_eq!(resp.what, "/srv/media/movies");
    assert_eq!(resp.fs_type, "none");
    assert_eq!(resp.options, "bind,ro,nosuid,nodev");
    assert!(resp.changed);

    let unit_disk = fx.root.join("etc/systemd/system").join(&resp.unit_name);
    let text = fs::read_to_string(&unit_disk).unwrap();
    assert!(text.contains("Type=none\n"));
    assert!(text.contains("Options=bind,ro,nosuid,nodev\n"));

    // Reject missing or symlinked source_path.
    assert!(mgr
        .write_bind_mount("/srv/media/missing", mount_path, false)
        .await
        .unwrap_err()
        .is_not_found());
    symlink(
        fx.root.join("srv/media/movies"),
        fx.root.join("srv/media/link-movies"),
    )
    .unwrap();
    assert!(mgr
        .write_bind_mount("/srv/media/link-movies", mount_path, false)
        .await
        .unwrap_err()
        .is_invalid_input());
}

#[tokio::test]
async fn ensure_packages_installs_missing_nfs_packages_and_is_idempotent() {
    let fx = StorageFixture::new();
    let mgr = fx.manager();

    // Fresh install: installs both nfs-kernel-server and nfs-common.
    let installed = mgr.ensure_packages().await.expect("install nfs packages");
    assert!(installed.installed);
    assert!(!installed.already_installed);
    assert_eq!(
        installed.packages,
        vec!["nfs-kernel-server".to_string(), "nfs-common".to_string()]
    );
    assert_eq!(
        installed
            .versions
            .get("nfs-kernel-server")
            .map(String::as_str),
        Some("1:2.8.3-1")
    );
    assert_eq!(
        installed.versions.get("nfs-common").map(String::as_str),
        Some("1:2.8.3-1")
    );

    // Already installed: never invokes apt-get.
    fx.clear_commands();
    let already = mgr.ensure_packages().await.expect("already installed");
    assert!(already.installed);
    assert!(already.already_installed);
    assert!(!fx.commands().iter().any(|(c, _)| c == "apt-get"));

    // Partial install: only installs the missing package.
    fs::remove_file(fx.root.join("pkg-nfs-kernel-server-installed")).unwrap();
    fx.clear_commands();
    let partial = mgr.ensure_packages().await.expect("install missing pkg");
    assert!(partial.installed);
    assert!(!partial.already_installed);
    let apt_install = fx
        .commands()
        .into_iter()
        .find(|(c, a)| c == "apt-get" && a.iter().any(|arg| arg == "install"))
        .expect("apt-get install call");
    assert!(apt_install.1.iter().any(|a| a == "nfs-kernel-server"));
    assert!(!apt_install.1.iter().any(|a| a == "nfs-common"));

    // Failure path: apt-get install failure returns Runtime error.
    fs::remove_file(fx.root.join("pkg-nfs-common-installed")).unwrap();
    fx.touch_marker("apt-install-fail");
    assert!(matches!(
        mgr.ensure_packages().await.unwrap_err(),
        PeerStorageError::Runtime(_)
    ));
}

#[tokio::test]
async fn ipv6_tunnel_cidr_supported_across_exports_nfsd_and_mounts() {
    let fx = StorageFixture::new();
    let mgr = fx.manager_with_cidr("fd00:231::/64");
    fx.create_export_dir("/srv/media/movies");

    let nfsd = mgr
        .configure_nfsd("fd00:231::1")
        .await
        .expect("configure ipv6 nfsd");
    assert_eq!(nfsd.tunnel_ip, "fd00:231::1");

    let exp = mgr
        .write_exports(
            "peer-v6",
            "fd00:231::2",
            &[PeerStorageExportSpec {
                path: "/srv/media/movies".to_string(),
                writable: false,
                squash_uid: None,
                squash_gid: None,
            }],
        )
        .await
        .expect("write ipv6 exports");
    assert_eq!(exp.export_count, 1);

    let mnt = mgr
        .write_mount(
            "/mnt/af-peers/peer-v6/movies",
            "fd00:231::2",
            "/srv/media/movies",
            false,
        )
        .await
        .expect("write ipv6 mount");
    assert_eq!(mnt.what, "[fd00:231::2]:/srv/media/movies");
}

#[tokio::test]
async fn runner_unix_socket_dispatch_preserves_typed_responses_and_errors() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let fx = StorageFixture::new();
    let mgr = Arc::new(fx.manager());
    fx.create_export_dir("/srv/media/movies");

    // Use a short socket path under /tmp to stay well below Linux SUN_LEN (108 bytes).
    let sock_dir = PathBuf::from(format!(
        "/tmp/af-ps-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ));
    fs::create_dir_all(&sock_dir).expect("create short sock dir");
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).expect("chmod sock dir");
    let sock_path = sock_dir.join("r.sock");
    let listener = tokio::net::UnixListener::bind(&sock_path).expect("bind test runner sock");
    let app = build_runner_router().layer(Extension(Arc::clone(&mgr)));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = serve_runner_connections(listener, app, async move {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    // Router creation alone must be completely dormant.
    assert!(fx.commands().is_empty());

    let prev_sock = env::var_os("AETHERFLOW_RUNNER_SOCK");
    env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);

    let result = std::panic::AssertUnwindSafe(async {
        let pkgs = dispatch_peer_storage(&PeerStorageRequest::EnsurePackages)
            .await
            .expect("dispatch EnsurePackages")
            .into_packages()
            .expect("packages variant");
        assert!(pkgs.installed);

        let nfsd = dispatch_peer_storage(&PeerStorageRequest::ConfigureNfsd {
            tunnel_ip: "10.231.0.1".to_string(),
        })
        .await
        .expect("dispatch ConfigureNfsd")
        .into_nfsd_configured()
        .expect("nfsd variant");
        assert_eq!(nfsd.service_state, "active");

        let sentinel = dispatch_peer_storage(&PeerStorageRequest::EnsureSentinel {
            path: "/srv/media/movies".to_string(),
            require_non_root_owner: false,
        })
        .await
        .expect("dispatch EnsureSentinel")
        .into_sentinel_ensured()
        .expect("sentinel variant");
        assert!(sentinel.created);

        let exports = dispatch_peer_storage(&PeerStorageRequest::WriteExports {
            link: "media-2".to_string(),
            tunnel_ip: "10.231.0.2".to_string(),
            exports: vec![PeerStorageExportSpec {
                path: "/srv/media/movies".to_string(),
                writable: false,
                squash_uid: None,
                squash_gid: None,
            }],
        })
        .await
        .expect("dispatch WriteExports")
        .into_exports_written()
        .expect("exports variant");
        assert_eq!(exports.export_count, 1);

        fx.touch_marker("mount-populates-sentinel");
        let mount_path = "/mnt/af-peers/media-2/movies".to_string();
        let written = dispatch_peer_storage(&PeerStorageRequest::WriteMount {
            mount_path: mount_path.clone(),
            tunnel_ip: "10.231.0.2".to_string(),
            remote_path: "/srv/media/movies".to_string(),
            writable: false,
        })
        .await
        .expect("dispatch WriteMount")
        .into_mount_written()
        .expect("mount written variant");
        assert_eq!(
            written.unit_name,
            r"mnt-af\x2dpeers-media\x2d2-movies.mount"
        );

        let started = dispatch_peer_storage(&PeerStorageRequest::StartMount {
            mount_path: mount_path.clone(),
        })
        .await
        .expect("dispatch StartMount")
        .into_mount_state()
        .expect("mount state variant");
        assert!(started.active);

        let probed = dispatch_peer_storage(&PeerStorageRequest::ProbeSentinel {
            mount_path: mount_path.clone(),
            timeout_ms: Some(2000),
        })
        .await
        .expect("dispatch ProbeSentinel")
        .into_sentinel_probed()
        .expect("sentinel probe variant");
        assert!(probed.healthy);

        let stopped = dispatch_peer_storage(&PeerStorageRequest::StopMount {
            mount_path: mount_path.clone(),
        })
        .await
        .expect("dispatch StopMount")
        .into_mount_state()
        .expect("mount state variant");
        assert!(!stopped.active);

        let removed = dispatch_peer_storage(&PeerStorageRequest::RemoveMount {
            mount_path: mount_path.clone(),
        })
        .await
        .expect("dispatch RemoveMount")
        .into_mount_removed()
        .expect("mount removed variant");
        assert!(removed.removed);

        // Typed error round-tripping across the Unix socket.
        let invalid = dispatch_peer_storage(&PeerStorageRequest::ConfigureNfsd {
            tunnel_ip: "not-an-ip".to_string(),
        })
        .await
        .unwrap_err();
        assert!(invalid.is_invalid_input(), "got {invalid:?}");

        let not_found = dispatch_peer_storage(&PeerStorageRequest::StartMount {
            mount_path: mount_path.clone(),
        })
        .await
        .unwrap_err();
        assert!(not_found.is_not_found(), "got {not_found:?}");

        let unmanaged = fx
            .root
            .join("etc/systemd/system")
            .join(r"mnt-af\x2dpeers-media\x2d2-movies.mount");
        fs::write(&unmanaged, "[Mount]\nWhat=foreign\n").unwrap();
        let conflict = dispatch_peer_storage(&PeerStorageRequest::RemoveMount { mount_path })
            .await
            .unwrap_err();
        assert!(conflict.is_conflict(), "got {conflict:?}");
    });
    let outcome = futures::FutureExt::catch_unwind(result).await;

    if let Some(prev) = prev_sock {
        env::set_var("AETHERFLOW_RUNNER_SOCK", prev);
    } else {
        env::remove_var("AETHERFLOW_RUNNER_SOCK");
    }
    let _ = shutdown_tx.send(());
    let _ = server.await;
    let _ = fs::remove_dir_all(&sock_dir);
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

#[test]
fn validate_sentinel_owner_rejects_root_when_required() {
    assert!(validate_sentinel_owner("/srv/media/movies", 0, 0, false).is_ok());
    assert!(validate_sentinel_owner("/srv/media/movies", 1000, 1000, true).is_ok());
    assert!(validate_sentinel_owner("/srv/media/movies", 0, 1000, true)
        .unwrap_err()
        .is_invalid_input());
    assert!(validate_sentinel_owner("/srv/media/movies", 1000, 0, true)
        .unwrap_err()
        .is_invalid_input());
    assert!(validate_sentinel_owner("/srv/media/movies", 0, 0, true)
        .unwrap_err()
        .is_invalid_input());
}

#[tokio::test]
async fn timeouts_kill_process_groups_and_rollback_exports() {
    let fx = StorageFixture::new();
    let mgr = fx
        .manager()
        .with_command_timeout(Duration::from_millis(250))
        .with_apt_timeout(Duration::from_millis(300));
    fx.create_export_dir("/srv/media/movies");

    // 1. Hanging exportfs times out and rolls back newly created exports file.
    fx.touch_marker("exportfs-hang");
    let err = mgr
        .write_exports(
            "link-hang",
            "10.231.0.2",
            &[PeerStorageExportSpec {
                path: "/srv/media/movies".to_string(),
                writable: false,
                squash_uid: None,
                squash_gid: None,
            }],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, PeerStorageError::Runtime(_)));
    assert!(err.to_string().contains("timed out"), "got {err}");
    assert!(!fx
        .root
        .join("etc/exports.d/aetherflow-peer-link-hang.exports")
        .exists());

    // 2. Hanging apt-get with SIGTERM-ignoring child is killed via process-group teardown.
    fx.touch_marker("apt-hang-with-child");
    fx.touch_marker("apt-ignore-term");
    let apt_err = mgr.ensure_packages().await.unwrap_err();
    assert!(matches!(apt_err, PeerStorageError::Runtime(_)));
    assert!(apt_err.to_string().contains("timed out"), "got {apt_err}");
    if let Ok(pid_raw) = fs::read_to_string(fx.root.join("apt-child.pid")) {
        if let Ok(pid) = pid_raw.trim().parse::<libc::pid_t>() {
            // Give the kernel a brief window to reap the killed child process.
            let mut dead = false;
            for _ in 0..20 {
                if unsafe { libc::kill(pid, 0) } != 0 {
                    dead = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert!(dead, "apt child process {pid} survived timeout teardown");
        }
    }
}

#[tokio::test]
async fn storage_lock_contention_returns_busy_without_blocking_sentinel_probes() {
    let fx = StorageFixture::new();
    let mgr = fx.manager().with_lock_timeout(Duration::from_millis(120));
    let mp = fx.create_export_dir("/mnt/af-peers/media-2/movies");
    fs::write(
        mp.join(PEER_SENTINEL_FILE_NAME),
        format!("{PEER_MANAGED_HEADER}\n"),
    )
    .unwrap();

    // Hold the exclusive storage write lock directly.
    let (_mem_guard, _file_guard) = mgr.acquire_storage_write_locks(true).await.unwrap();

    // A concurrent mutating request must fail with typed Busy.
    let busy = mgr.configure_nfsd("10.231.0.1").await.unwrap_err();
    assert!(busy.is_busy(), "expected Busy, got {busy:?}");

    // Sentinel probes do NOT acquire the storage mutation lock so they stay responsive.
    let probe = mgr
        .probe_sentinel("/mnt/af-peers/media-2/movies", Some(1000))
        .await
        .expect("probe during held write lock");
    assert!(probe.healthy);
}

#[tokio::test]
async fn symlinked_mount_paths_specifier_escaping_and_uid_ownership_enforced() {
    let fx = StorageFixture::new();
    let mgr = fx.manager();

    // 1. Percent signs in remote_path are escaped to %% in systemd unit files.
    let written = mgr
        .write_mount(
            "/mnt/af-peers/media-2/movies",
            "10.231.0.2",
            "/srv/media/100%real",
            false,
        )
        .await
        .expect("write mount with percent");
    let unit_disk = fx.root.join("etc/systemd/system").join(&written.unit_name);
    let unit_text = fs::read_to_string(&unit_disk).unwrap();
    assert!(unit_text.contains("What=10.231.0.2:/srv/media/100%%real\n"));

    // 2. Non-empty leaf mountpoint directory is never recursively deleted by StopMount.
    let leaf = fx.create_export_dir("/mnt/af-peers/media-2/movies");
    let marker_file = leaf.join("keep.txt");
    fs::write(&marker_file, "preserve").unwrap();
    let _ = mgr
        .stop_mount("/mnt/af-peers/media-2/movies")
        .await
        .expect("stop mount with non-empty leaf");
    assert!(
        marker_file.exists(),
        "non-empty leaf file must be preserved"
    );
    fs::remove_file(&marker_file).unwrap();
    fs::remove_dir(&leaf).unwrap();

    // 3. Symlink at leaf mountpoint is rejected.
    let decoy = fx.create_export_dir("/srv/decoy");
    symlink(&decoy, &leaf).unwrap();
    assert!(mgr
        .start_mount("/mnt/af-peers/media-2/movies")
        .await
        .unwrap_err()
        .is_conflict());
    fs::remove_file(&leaf).unwrap();

    // 4. Symlink at /mnt/af-peers/<link> is rejected.
    fs::remove_dir(fx.root.join("mnt/af-peers/media-2")).unwrap();
    symlink(&decoy, fx.root.join("mnt/af-peers/media-2")).unwrap();
    assert!(mgr
        .write_mount(
            "/mnt/af-peers/media-2/movies",
            "10.231.0.2",
            "/srv/media/movies",
            false,
        )
        .await
        .is_err());

    // 5. Expected UID enforcement rejects directories not owned by expected_uid.
    let wrong_uid = unsafe { libc::geteuid() }.wrapping_add(1);
    let strict_mgr = fx.manager().with_expected_uid(Some(wrong_uid));
    let uid_err = strict_mgr.configure_nfsd("10.231.0.1").await.unwrap_err();
    assert!(matches!(uid_err, PeerStorageError::Runtime(_)));

    // 6. Group- or world-writable managed ancestor directory is rejected.
    let perm_fx = StorageFixture::new();
    let etc_dir = perm_fx.create_system_dir("etc/nfs.conf.d");
    fs::set_permissions(etc_dir.parent().unwrap(), fs::Permissions::from_mode(0o775)).unwrap();
    let perm_err = perm_fx
        .manager()
        .configure_nfsd("10.231.0.1")
        .await
        .unwrap_err();
    assert!(matches!(perm_err, PeerStorageError::Runtime(_)));
    assert!(perm_err.to_string().contains("writable"));
}

#[test]
fn sandbox_policy_exempts_nfs_server_and_peer_mount_units() {
    assert_eq!(
        normalize_systemd_unit(r"mnt-af\x2dpeers-media\x2d2-movies.mount"),
        r"mnt-af\x2dpeers-media\x2d2-movies.mount"
    );
    assert!(is_exempt_sandbox_unit("nfs-server"));
    assert!(is_exempt_sandbox_unit("nfs-server.service"));
    assert!(is_exempt_sandbox_unit(
        r"mnt-af\x2dpeers-media\x2d2-movies.mount"
    ));
    assert!(is_exempt_sandbox_unit(r"mnt-af\x2dpeers-media\x2d2-movies"));
    assert!(!is_exempt_sandbox_unit("mnt-storage.mount"));
    assert!(!is_exempt_sandbox_unit("sonarr.service"));

    let root = env::temp_dir().join(format!("af-p7-sandbox-{}", uuid::Uuid::new_v4()));
    for unit in [
        "nfs-server",
        "nfs-server.service",
        r"mnt-af\x2dpeers-media\x2d2-movies.mount",
    ] {
        assert!(render_systemd_sandbox_dropin("native", unit, &[]).is_empty());
        apply_sandbox_dropins_in_dir(&root, &[unit.to_string()], "native", &[]).unwrap();
    }
    assert!(!root.exists());
}

#[tokio::test]
async fn configure_nfsd_warns_on_unmanaged_etc_exports_without_modifying_it() {
    use tracing::field::{Field, Visit};
    use tracing::instrument::WithSubscriber;
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Level, Metadata, Subscriber};

    #[derive(Clone, Default)]
    struct WarnCapture {
        warnings: Arc<StdMutex<Vec<HashMap<String, String>>>>,
    }

    struct Visitor(HashMap<String, String>);
    impl Visit for Visitor {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_u64(&mut self, field: &Field, value: u64) {
            self.0.insert(field.name().to_string(), value.to_string());
        }
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0
                .insert(field.name().to_string(), format!("{value:?}"));
        }
    }

    impl Subscriber for WarnCapture {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _span: &Id, _values: &Record<'_>) {}
        fn record_follows_from(&self, _span: &Id, _follows: &Id) {}
        fn event(&self, event: &Event<'_>) {
            if *event.metadata().level() == Level::WARN {
                let mut v = Visitor(HashMap::new());
                event.record(&mut v);
                self.warnings
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(v.0);
            }
        }
        fn enter(&self, _span: &Id) {}
        fn exit(&self, _span: &Id) {}
    }

    assert!(parse_active_etc_exports_lines("# comment\n\n   # indented\n").is_empty());
    assert_eq!(
        parse_active_etc_exports_lines(
            "# default Debian header\n\n/srv/lan 192.168.1.0/24(rw,sync)\n  /srv/public *(ro)\n"
        ),
        vec![
            "/srv/lan 192.168.1.0/24(rw,sync)".to_string(),
            "/srv/public *(ro)".to_string(),
        ]
    );

    let fx = StorageFixture::new();
    let mgr = fx.manager();
    fx.create_system_dir("etc");
    let etc_exports = fx.root.join("etc/exports");

    // 1. Comment-only Debian default /etc/exports emits zero warnings.
    let comment_only = "# /etc/exports: default Debian template\n\n   # still a comment\n";
    fs::write(&etc_exports, comment_only).unwrap();
    let cap = WarnCapture::default();
    mgr.configure_nfsd("10.231.0.1")
        .with_subscriber(cap.clone())
        .await
        .expect("configure nfsd with comment-only /etc/exports");
    assert!(
        cap.warnings.lock().unwrap().is_empty(),
        "comment-only /etc/exports must not emit warnings"
    );
    assert_eq!(fs::read_to_string(&etc_exports).unwrap(), comment_only);

    // 2. Active unmanaged LAN export lines emit a clear WARN and leave /etc/exports untouched.
    let active_lan_exports =
        "# Host LAN shares\n/srv/lan 192.168.1.0/24(rw,sync)\n/srv/media *(ro,sync)\n";
    fs::write(&etc_exports, active_lan_exports).unwrap();
    let cap2 = WarnCapture::default();
    mgr.configure_nfsd("10.231.0.1")
        .with_subscriber(cap2.clone())
        .await
        .expect("configure nfsd with unmanaged /etc/exports");
    let warns = cap2.warnings.lock().unwrap().clone();
    assert_eq!(warns.len(), 1, "expected exactly 1 warning, got {warns:?}");
    assert_eq!(
        warns[0].get("etc_exports").map(String::as_str),
        Some("/etc/exports")
    );
    assert_eq!(
        warns[0].get("active_line_count").map(String::as_str),
        Some("2")
    );
    assert_eq!(
        fs::read_to_string(&etc_exports).unwrap(),
        active_lan_exports,
        "/etc/exports must never be modified"
    );
}

#[tokio::test]
async fn probe_sentinel_single_flight_deduplicates_concurrent_hung_mount_probes() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Condvar;

    let coord = Arc::new(SentinelProbeCoordinator::new(4));
    let spawn_count = Arc::new(AtomicUsize::new(0));
    let observed_thread_name: Arc<StdMutex<Option<String>>> = Arc::new(StdMutex::new(None));
    let gate = Arc::new((StdMutex::new(false), Condvar::new()));
    let entered = Arc::new((StdMutex::new(0usize), Condvar::new()));

    let make_blocking_probe = || {
        let spawn_count = Arc::clone(&spawn_count);
        let observed_thread_name = Arc::clone(&observed_thread_name);
        let gate = Arc::clone(&gate);
        let entered = Arc::clone(&entered);
        move |_dir: PathBuf| -> SentinelProbeOutcome {
            spawn_count.fetch_add(1, Ordering::SeqCst);
            *observed_thread_name.lock().unwrap() =
                std::thread::current().name().map(str::to_string);
            {
                let (lock, cvar) = &*entered;
                let mut n = lock.lock().unwrap();
                *n += 1;
                cvar.notify_all();
            }
            let (lock, cvar) = &*gate;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = cvar.wait(released).unwrap();
            }
            Ok(())
        }
    };

    // Launch 3 concurrent probes using lexically equivalent paths for the same hung mount.
    let p1 = {
        let coord = Arc::clone(&coord);
        let probe = make_blocking_probe();
        tokio::spawn(async move {
            coord
                .probe_with(
                    Path::new("/mnt/af-peers/media-2/movies"),
                    "/mnt/af-peers/media-2/movies",
                    Duration::from_millis(120),
                    probe,
                )
                .await
        })
    };
    let p2 = {
        let coord = Arc::clone(&coord);
        let probe = make_blocking_probe();
        tokio::spawn(async move {
            coord
                .probe_with(
                    Path::new("/mnt/af-peers/media-2/movies/"),
                    "/mnt/af-peers/media-2/movies",
                    Duration::from_millis(120),
                    probe,
                )
                .await
        })
    };
    let p3 = {
        let coord = Arc::clone(&coord);
        let probe = make_blocking_probe();
        tokio::spawn(async move {
            coord
                .probe_with(
                    Path::new("/mnt/af-peers//media-2/./movies"),
                    "/mnt/af-peers/media-2/movies",
                    Duration::from_millis(120),
                    probe,
                )
                .await
        })
    };

    let (r1, r2, r3) = tokio::join!(p1, p2, p3);
    for resp in [r1.unwrap(), r2.unwrap(), r3.unwrap()] {
        assert!(!resp.healthy);
        assert!(resp.timed_out);
        assert!(
            resp.error
                .as_deref()
                .unwrap_or("")
                .starts_with("Sentinel probe timed out after"),
            "unexpected error: {:?}",
            resp.error
        );
    }
    assert_eq!(
        spawn_count.load(Ordering::SeqCst),
        1,
        "concurrent probes for the same hung mount must coalesce onto 1 OS thread"
    );
    assert_eq!(
        observed_thread_name.lock().unwrap().as_deref(),
        Some("af-sentinel-probe")
    );

    // A follow-up probe while the original thread is STILL hung also coalesces onto the same thread.
    let r4 = coord
        .probe_with(
            Path::new("/mnt/af-peers/media-2/movies"),
            "/mnt/af-peers/media-2/movies",
            Duration::from_millis(80),
            make_blocking_probe(),
        )
        .await;
    assert!(!r4.healthy);
    assert!(r4.timed_out);
    assert_eq!(
        spawn_count.load(Ordering::SeqCst),
        1,
        "subsequent probe on still-hung mount must not spawn a second OS thread"
    );

    // Unblock the hung OS thread; once it cleans up, a subsequent probe runs fresh and succeeds.
    {
        let (lock, cvar) = &*gate;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let empty = coord.in_flight.lock().unwrap().is_empty()
                && coord.semaphore.available_permits() == 4;
            if empty {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("hung probe thread must clean up single-flight entry and release semaphore permit");

    let r5 = coord
        .probe_with(
            Path::new("/mnt/af-peers/media-2/movies"),
            "/mnt/af-peers/media-2/movies",
            Duration::from_secs(1),
            make_blocking_probe(),
        )
        .await;
    assert!(r5.healthy);
    assert!(!r5.timed_out);
    assert_eq!(spawn_count.load(Ordering::SeqCst), 2);

    // Concurrent probes against a slow-but-healthy mount coalesce and both succeed from 1 thread.
    let slow_spawns = Arc::new(AtomicUsize::new(0));
    let slow_probe = || {
        let slow_spawns = Arc::clone(&slow_spawns);
        move |_dir: PathBuf| -> SentinelProbeOutcome {
            slow_spawns.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(60));
            Ok(())
        }
    };
    let (s1, s2) = tokio::join!(
        coord.probe_with(
            Path::new("/mnt/af-peers/media-2/shows"),
            "/mnt/af-peers/media-2/shows",
            Duration::from_secs(1),
            slow_probe(),
        ),
        coord.probe_with(
            Path::new("/mnt/af-peers/media-2/shows/"),
            "/mnt/af-peers/media-2/shows",
            Duration::from_secs(1),
            slow_probe(),
        ),
    );
    assert!(s1.healthy && !s1.timed_out);
    assert!(s2.healthy && !s2.timed_out);
    assert_eq!(slow_spawns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn probe_sentinel_global_concurrency_cap_bounds_threads_and_preserves_tokio_pool() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Condvar;

    let coord = Arc::new(SentinelProbeCoordinator::new(2));
    let spawn_count = Arc::new(AtomicUsize::new(0));
    let gate_a = Arc::new((StdMutex::new(false), Condvar::new()));
    let gate_b = Arc::new((StdMutex::new(false), Condvar::new()));
    let entered = Arc::new((StdMutex::new(0usize), Condvar::new()));

    let start_hung = |path: &'static str, gate: Arc<(StdMutex<bool>, Condvar)>| {
        let coord = Arc::clone(&coord);
        let spawn_count = Arc::clone(&spawn_count);
        let entered = Arc::clone(&entered);
        tokio::spawn(async move {
            coord
                .probe_with(
                    Path::new(path),
                    path,
                    Duration::from_millis(80),
                    move |_dir| {
                        spawn_count.fetch_add(1, Ordering::SeqCst);
                        {
                            let (lock, cvar) = &*entered;
                            let mut n = lock.lock().unwrap();
                            *n += 1;
                            cvar.notify_all();
                        }
                        let (lock, cvar) = &*gate;
                        let mut released = lock.lock().unwrap();
                        while !*released {
                            released = cvar.wait(released).unwrap();
                        }
                        Ok(())
                    },
                )
                .await
        })
    };

    let ha = start_hung("/mnt/af-peers/peer-a/movies", Arc::clone(&gate_a));
    let hb = start_hung("/mnt/af-peers/peer-b/movies", Arc::clone(&gate_b));

    let (ra, rb) = tokio::join!(ha, hb);
    assert!(ra.unwrap().timed_out);
    assert!(rb.unwrap().timed_out);
    assert_eq!(spawn_count.load(Ordering::SeqCst), 2);
    assert_eq!(coord.semaphore.available_permits(), 0);

    // 3rd distinct mount cannot acquire a permit and returns clean concurrency-limit timeout
    // without spawning another OS thread.
    let rc_limited = coord
        .probe_with(
            Path::new("/mnt/af-peers/peer-c/movies"),
            "/mnt/af-peers/peer-c/movies",
            Duration::from_millis(80),
            {
                let spawn_count = Arc::clone(&spawn_count);
                move |_| {
                    spawn_count.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await;
    assert!(!rc_limited.healthy);
    assert!(rc_limited.timed_out);
    assert_eq!(
        rc_limited.error.as_deref(),
        Some("Sentinel probe concurrency limit reached (other mounts hung)")
    );
    assert_eq!(spawn_count.load(Ordering::SeqCst), 2);

    // Probing an already-hung mount still coalesces onto its existing OS thread without needing
    // a new permit.
    let ra_coalesced = coord
        .probe_with(
            Path::new("/mnt/af-peers/peer-a/movies"),
            "/mnt/af-peers/peer-a/movies",
            Duration::from_millis(60),
            |_| Ok(()),
        )
        .await;
    assert!(!ra_coalesced.healthy);
    assert!(ra_coalesced.timed_out);
    assert!(ra_coalesced
        .error
        .as_deref()
        .unwrap_or("")
        .starts_with("Sentinel probe timed out after"));
    assert_eq!(spawn_count.load(Ordering::SeqCst), 2);

    // Tokio's shared blocking pool stays completely responsive while sentinel slots are saturated.
    let blocking_ok = tokio::time::timeout(
        Duration::from_secs(1),
        tokio::task::spawn_blocking(|| 42usize),
    )
    .await
    .expect("tokio blocking pool must not starve")
    .expect("spawn_blocking join");
    assert_eq!(blocking_ok, 42);

    // Unblock mount A so its permit returns, then mount C probes cleanly.
    {
        let (lock, cvar) = &*gate_a;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
    let rc_ok = coord
        .probe_with(
            Path::new("/mnt/af-peers/peer-c/movies"),
            "/mnt/af-peers/peer-c/movies",
            Duration::from_secs(2),
            |_| Ok(()),
        )
        .await;
    assert!(rc_ok.healthy);
    assert!(!rc_ok.timed_out);

    // Cleanly release mount B before exiting the test.
    {
        let (lock, cvar) = &*gate_b;
        *lock.lock().unwrap() = true;
        cvar.notify_all();
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if coord.semaphore.available_permits() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all permits released cleanly");
}
