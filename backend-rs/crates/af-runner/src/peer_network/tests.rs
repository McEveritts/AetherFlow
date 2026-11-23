use super::*;
use crate::{build_runner_router, dispatch_peer_network, serve_runner_connections, ENV_TEST_MUTEX};
use serde_json::json;
use std::fs;
use std::os::unix::fs::PermissionsExt;

const FAKE_BIN: &str = r##"#!/usr/bin/python3
import base64, ipaddress, json, os, pathlib, signal, subprocess, sys, time

root = pathlib.Path(__file__).resolve().parent.parent
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]

# Record invocations without ever capturing secret stdin or file contents.
with (root / "commands.jsonl").open("a") as out:
    out.write(json.dumps({"cmd": name, "args": args}) + "\n")

def marker(flag):
    return (root / flag).exists()

def wg_conf_path(arg):
    if "/" in arg:
        return pathlib.Path(arg)
    return root / "etc" / "wireguard" / f"{arg}.conf"

def derive_pub(priv_b64):
    raw = base64.b64decode(priv_b64.strip())
    if len(raw) != 32:
        raise ValueError("bad key len")
    # Deterministic 1-to-1 pubkey mapping for tests (flips high bit).
    pub = bytes([(b ^ 0x80) for b in raw])
    return base64.b64encode(pub).decode()

def strip_wg_quick(text):
    out_lines = []
    in_iface = False
    for line in text.splitlines():
        stripped = line.split("#", 1)[0].strip()
        if stripped.startswith("["):
            in_iface = stripped.lower() == "[interface]"
            out_lines.append(stripped)
            continue
        if not stripped:
            continue
        if in_iface and "=" in stripped:
            k = stripped.split("=", 1)[0].strip().lower()
            if k in ("address", "saveconfig", "dns", "postup", "postdown", "mtu", "table"):
                continue
        out_lines.append(stripped)
    return "\n".join(out_lines) + "\n"

def parse_runtime_to_dump(runtime_text):
    priv = ""
    port = "51821"
    peers = []
    cur = None
    in_iface = False
    for line in runtime_text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.lower() == "[interface]":
            in_iface = True
            cur = None
            continue
        if s.lower() == "[peer]":
            in_iface = False
            cur = {"publickey": "", "presharedkey": "(none)", "endpoint": "(none)", "allowedips": "", "persistentkeepalive": "off"}
            peers.append(cur)
            continue
        if "=" in s:
            k, v = [p.strip() for p in s.split("=", 1)]
            kl = k.lower()
            if in_iface:
                if kl == "privatekey":
                    priv = v
                elif kl == "listenport":
                    port = v
            elif cur is not None:
                cur[kl] = v
    pub = derive_pub(priv) if priv else ""
    now_ts = str(int(time.time())) if not marker("stale-handshake") else str(int(time.time()) - 600)
    lines = [f"{priv}\t{pub}\t{port}\toff"]
    for p in peers:
        hs = "0" if marker("no-handshake") else now_ts
        psk = p.get("presharedkey", "(none)")
        ep = p.get("endpoint", "(none)") or "(none)"
        aip = p.get("allowedips", "")
        ka = p.get("persistentkeepalive", "0")
        lines.append(f"{p['publickey']}\t{psk}\t{ep}\t{aip}\t{hs}\t1024\t2048\t{ka}")
    return "\n".join(lines) + "\n"

def parse_iface_addr_from_conf():
    conf = root / "etc" / "wireguard" / "afpeer0.conf"
    if not conf.exists():
        return None
    in_iface = False
    for line in conf.read_text().splitlines():
        s = line.split("#", 1)[0].strip()
        if s.startswith("["):
            in_iface = s.lower() == "[interface]"
            continue
        if in_iface and "=" in s:
            k, v = [p.strip() for p in s.split("=", 1)]
            if k.lower() == "address" and "/" in v:
                ip, pref = v.split("/", 1)
                return (ip.strip(), int(pref.strip()))
    return None

if name == "wg":
    if args == ["--version"]:
        if marker("wg-missing"):
            sys.exit(1)
        print("wireguard-tools v1.0.20210914")
        sys.exit(0)
    if args == ["genkey"]:
        if marker("hang"):
            time.sleep(60)
        if marker("too-much-output"):
            print("A" * 2000000)
            sys.exit(0)
        if marker("genkey-fail"):
            print("genkey error", file=sys.stderr)
            sys.exit(1)
        seed = int((root / "key-seed").read_text().strip()) if marker("key-seed") else 11
        print(base64.b64encode(bytes([seed]) * 32).decode())
        sys.exit(0)
    if args == ["pubkey"]:
        priv = sys.stdin.read().strip()
        if marker("pubkey-fail"):
            print(f"bad private key {priv}", file=sys.stderr)
            sys.exit(1)
        print(derive_pub(priv))
        sys.exit(0)
    if args == ["show", "afpeer0", "dump"]:
        if not marker("afpeer0-up"):
            print("Unable to access interface: No such device", file=sys.stderr)
            sys.exit(1)
        if marker("custom-dump"):
            print((root / "custom-dump").read_text(), end="")
        else:
            print(parse_runtime_to_dump((root / "runtime.conf").read_text()), end="")
        sys.exit(0)
    if args == ["showconf", "afpeer0"]:
        if not marker("afpeer0-up"):
            print("Unable to access interface: No such device", file=sys.stderr)
            sys.exit(1)
        if marker("showconf-fail"):
            print("Operation not permitted", file=sys.stderr)
            sys.exit(1)
        print((root / "runtime.conf").read_text(), end="")
        sys.exit(0)
    if len(args) == 3 and args[0] == "syncconf" and args[1] == "afpeer0":
        staged = pathlib.Path(args[2])
        mode = staged.stat().st_mode & 0o777
        if mode != 0o600:
            print(f"unsafe mode {oct(mode)}", file=sys.stderr)
            sys.exit(1)
        content = staged.read_text()
        if marker("syncconf-slow-ms"):
            ms = int((root / "syncconf-slow-ms").read_text().strip())
            (root / "syncconf-started").touch()
            time.sleep(ms / 1000.0)
        if marker("fail-all-syncconf"):
            print("simulated total syncconf failure", file=sys.stderr)
            sys.exit(1)
        if marker("fail-next-syncconf"):
            (root / "fail-next-syncconf").unlink()
            # Mutate runtime partially before failing so rollback is observable.
            (root / "runtime.conf").write_text(content + "# partial\n")
            print("simulated transient syncconf failure", file=sys.stderr)
            sys.exit(1)
        (root / "runtime.conf").write_text(content)
        if marker("syncconf-slow-ms"):
            (root / "syncconf-finished").touch()
        sys.exit(0)
    raise RuntimeError(f"unexpected wg args: {args}")

elif name == "wg-quick":
    if len(args) == 2 and args[0] == "strip":
        conf = wg_conf_path(args[1])
        text = conf.read_text()
        if marker("fail-strip"):
            # Echo a fake private key line to stderr to verify the runner never leaks it.
            print(f"wg-quick parse error: {text}", file=sys.stderr)
            sys.exit(1)
        print(strip_wg_quick(text), end="")
        sys.exit(0)
    raise RuntimeError(f"unexpected wg-quick args: {args}")

elif name == "systemctl":
    unit = args[-1]
    if unit != "wg-quick@afpeer0.service":
        raise RuntimeError(f"unexpected systemd unit: {unit}")
    if args == ["is-active", unit]:
        if marker("afpeer0-service-active"):
            print("active")
            sys.exit(0)
        if marker("afpeer0-service-failed"):
            print("failed")
            sys.exit(3)
        print("inactive")
        sys.exit(3)
    if args == ["enable", "--now", unit] or args == ["start", unit]:
        if marker("systemctl-start-fail"):
            (root / "afpeer0-service-failed").touch()
            print("Job for wg-quick@afpeer0.service failed.", file=sys.stderr)
            sys.exit(1)
        conf = root / "etc" / "wireguard" / "afpeer0.conf"
        runtime_text = strip_wg_quick(conf.read_text())
        if marker("start-mismatched-live-key"):
            wrong_priv = base64.b64encode(bytes([99]) * 32).decode()
            runtime_text = f"[Interface]\nPrivateKey = {wrong_priv}\nListenPort = 51821\n"
        (root / "runtime.conf").write_text(runtime_text)
        (root / "afpeer0-service-failed").unlink(missing_ok=True)
        (root / "afpeer0-up").touch()
        (root / "afpeer0-service-active").touch()
        (root / "afpeer0-service-enabled").touch()
        sys.exit(0)
    if args == ["disable", "--now", unit] or args == ["stop", unit]:
        if marker("disable-fail"):
            print("Failed to stop wg-quick@afpeer0.service", file=sys.stderr)
            sys.exit(1)
        if not marker("disable-leaves-live"):
            (root / "afpeer0-up").unlink(missing_ok=True)
            (root / "afpeer0-service-active").unlink(missing_ok=True)
        if args[0] == "disable":
            (root / "afpeer0-service-enabled").unlink(missing_ok=True)
        sys.exit(0)
    if args == ["reset-failed", unit]:
        if marker("reset-failed-fail"):
            print("Failed to reset failed state", file=sys.stderr)
            sys.exit(1)
        (root / "afpeer0-service-failed").unlink(missing_ok=True)
        sys.exit(0)
    raise RuntimeError(f"unexpected systemctl args: {args}")

elif name == "ip":
    if args == ["-j", "addr", "show", "dev", "afpeer0"]:
        if not marker("afpeer0-up"):
            print('Device "afpeer0" does not exist.', file=sys.stderr)
            sys.exit(1)
        flags = [] if marker("link-down") else ["POINTOPOINT", "NOARP", "UP", "LOWER_UP"]
        operstate = "DOWN" if marker("link-down") else "UNKNOWN"
        addr = parse_iface_addr_from_conf()
        addr_info = []
        if addr is not None:
            ip_str, pref = addr
            if marker("wrong-prefix"):
                pref = 128 if ":" in ip_str else 32
            fam = "inet6" if ":" in ip_str else "inet"
            entry = {"family": fam, "local": ip_str, "prefixlen": pref, "valid_life_time": 4294967295}
            if marker("addr-tentative"):
                entry["tentative"] = True
            if marker("addr-dadfailed"):
                entry["dadfailed"] = True
            if marker("addr-detached"):
                entry["detached"] = True
            if marker("addr-expired"):
                entry["valid_life_time"] = 0
            addr_info.append(entry)
        print(json.dumps([{"ifname": "afpeer0", "flags": flags, "operstate": operstate, "addr_info": addr_info}]))
        sys.exit(0)
    if len(args) == 6 and args[0] == "-j" and args[1] in ("-4", "-6") and args[2:5] == ["route", "show", "exact"]:
        dst = args[5]
        if not marker("afpeer0-up") or marker("missing-subnet-route"):
            print("[]")
            sys.exit(0)
        if marker("subnet-route-wrong-dev"):
            print(json.dumps([{"dst": dst, "dev": "eth0", "protocol": "kernel", "scope": "link", "flags": []}]))
            sys.exit(0)
        if marker("subnet-route-competing-metric"):
            print(json.dumps([
                {"dst": dst, "dev": "eth0", "protocol": "static", "metric": 10, "flags": []},
                {"dst": dst, "dev": "afpeer0", "protocol": "kernel", "metric": 100, "flags": []},
            ]))
            sys.exit(0)
        if marker("subnet-route-dead"):
            print(json.dumps([{"dst": dst, "dev": "afpeer0", "protocol": "kernel", "flags": ["linkdown"]}]))
            sys.exit(0)
        print(json.dumps([{"dst": dst, "dev": "afpeer0", "protocol": "kernel", "scope": "link", "flags": []}]))
        sys.exit(0)
    if len(args) == 5 and args[0] == "-j" and args[1] in ("-4", "-6") and args[2:4] == ["route", "get"]:
        peer_ip = args[4]
        if marker("peer-route-fail"):
            print("RTNETLINK answers: Network is unreachable", file=sys.stderr)
            sys.exit(2)
        if marker("peer-route-wrong-dev"):
            print(json.dumps([{"dst": peer_ip, "dev": "eth0", "flags": []}]))
            sys.exit(0)
        if marker("peer-route-blackhole"):
            print(json.dumps([{"type": "blackhole", "dst": peer_ip, "dev": "lo", "flags": []}]))
            sys.exit(0)
        if marker("peer-route-local"):
            print(json.dumps([{"type": "local", "dst": peer_ip, "dev": "afpeer0", "flags": []}]))
            sys.exit(0)
        if marker("peer-route-linkdown"):
            print(json.dumps([{"dst": peer_ip, "dev": "afpeer0", "flags": ["linkdown"]}]))
            sys.exit(0)
        if not marker("afpeer0-up"):
            print("RTNETLINK answers: Network is unreachable", file=sys.stderr)
            sys.exit(2)
        print(json.dumps([{"dst": peer_ip, "dev": "afpeer0", "flags": []}]))
        sys.exit(0)
    raise RuntimeError(f"unexpected ip args: {args}")

elif name == "dpkg-query":
    pkg = args[-1]
    if pkg != "wireguard-tools":
        raise RuntimeError(f"unexpected dpkg-query package: {pkg}")
    if marker("wg-pkg-installed"):
        print("installed 1.0.20210914-1.4")
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
    if "install" in args and (marker("apt-fail") or marker("apt-install-fail")):
        print("E: Unable to locate package wireguard-tools", file=sys.stderr)
        sys.exit(100)
    if "install" in args and marker("apt-hang-with-child"):
        if marker("apt-ignore-term"):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen(["/bin/sleep", "60"])
        (root / "apt-child.pid").write_text(str(child.pid))
        (root / "apt-hang-started").touch()
        child.wait()
        sys.exit(0)
    if "install" in args and marker("apt-slow-ms"):
        ms = int((root / "apt-slow-ms").read_text().strip())
        (root / "apt-started").touch()
        time.sleep(ms / 1000.0)
    if "install" in args and "wireguard-tools" in args and not marker("apt-install-noop"):
        (root / "wg-pkg-installed").touch()
        if marker("apt-slow-ms"):
            (root / "apt-finished").touch()
    sys.exit(0)

else:
    raise RuntimeError(f"unexpected binary: {name}")
"##;

fn test_key(seed: u8) -> String {
    STANDARD.encode([seed; 32])
}

fn derived_pub(seed: u8) -> String {
    STANDARD.encode([seed ^ 0x80; 32])
}

struct Fixture {
    root: PathBuf,
    manager: PeerNetworkManager,
}

impl Fixture {
    fn new() -> Self {
        Self::with_network(DEFAULT_PEER_TUNNEL_CIDR, DEFAULT_PEER_WG_PORT)
    }

    fn with_network(cidr: &str, port: u16) -> Self {
        let root = std::env::temp_dir().join(format!("af-peer-net-{}", uuid::Uuid::new_v4()));
        let bin = root.join("bin");
        fs::create_dir_all(root.join("etc/wireguard")).unwrap();
        fs::create_dir_all(root.join("etc/aetherflow/peers")).unwrap();
        fs::create_dir_all(&bin).unwrap();
        // Set explicit production-equivalent modes independent of process umask (e.g., 0002).
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(root.join("etc"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(
            root.join("etc/aetherflow"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::set_permissions(
            root.join("etc/wireguard"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(
            root.join("etc/aetherflow/peers"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        for cmd in ["wg", "wg-quick", "systemctl", "ip", "dpkg-query", "apt-get"] {
            let path = bin.join(cmd);
            fs::write(&path, FAKE_BIN).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let manager = PeerNetworkManager::new_isolated(root.clone(), bin, cidr, port).unwrap();
        Self { root, manager }
    }

    fn init_lifecycle_db(&self) -> (PathBuf, rusqlite::Connection) {
        let cfg = af_release::ReleaseConfig::for_root(&self.root);
        let db_path = af_release::config::try_resolve_db_path(&cfg, None)
            .unwrap()
            .path;
        fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        af_release::lifecycle::initialize_schema(&conn).unwrap();
        (db_path, conn)
    }

    fn maintenance_lock_path(&self) -> PathBuf {
        let cfg = af_release::ReleaseConfig::for_root(&self.root);
        af_release::ensure_interoperable_maintenance_lock_file(&cfg).unwrap()
    }

    fn mark(&self, flag: &str) {
        fs::write(self.root.join(flag), "").unwrap();
    }

    fn unmark(&self, flag: &str) {
        let _ = fs::remove_file(self.root.join(flag));
    }

    fn read_file(&self, rel: &str) -> String {
        fs::read_to_string(self.root.join(rel)).unwrap()
    }

    fn commands(&self) -> Vec<Value> {
        let path = self.root.join("commands.jsonl");
        if !path.exists() {
            return Vec::new();
        }
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn has_temp_files(&self) -> bool {
        let check = |dir: PathBuf| {
            fs::read_dir(dir)
                .map(|entries| {
                    entries.flatten().any(|entry| {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        name.starts_with(".afpeer0-") || name.contains(".tmp.")
                    })
                })
                .unwrap_or(false)
        };
        check(self.root.join("etc/wireguard"))
            || check(self.root.join("etc/aetherflow/peers"))
            || check(self.root.join("etc/aetherflow/peers/.staging"))
    }
}

struct TempSocket {
    path: PathBuf,
}

impl TempSocket {
    fn new(prefix: &str) -> Self {
        let id = uuid::Uuid::new_v4().simple().to_string();
        let path = PathBuf::from("/tmp").join(format!("{prefix}-{}.sock", &id[..12]));
        let _ = fs::remove_file(&path);
        Self { path }
    }
}

impl Drop for TempSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Restore permissions on any altered dirs or 0o000 canary files before cleaning up.
        for rel in [
            "etc",
            "etc/wireguard",
            "etc/aetherflow",
            "etc/aetherflow/peers",
            "etc/aetherflow/peers/tokens",
            "etc/aetherflow/peers/pending",
            "etc/aetherflow/peers/.staging",
        ] {
            let p = self.root.join(rel);
            if p.is_dir() && !p.is_symlink() {
                let _ = fs::set_permissions(&p, fs::Permissions::from_mode(0o755));
            }
        }
        let wg0 = self.root.join("etc/wireguard/wg0.conf");
        if wg0.exists() {
            let _ = fs::set_permissions(&wg0, fs::Permissions::from_mode(0o600));
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn ensure_identity_generates_secure_key_subnet_config_and_is_idempotent() {
    let f = Fixture::new();

    let first = f
        .manager
        .ensure_identity(Some("10.231.0.10"), &[], None, None)
        .await
        .unwrap();
    assert!(first.created);
    assert_eq!(first.interface, "afpeer0");
    assert_eq!(first.public_key, derived_pub(11));
    assert_eq!(first.tunnel_ip, "10.231.0.10");
    assert_eq!(first.tunnel_cidr, "10.231.0.0/16");
    assert_eq!(first.interface_address, "10.231.0.10/16");
    assert_eq!(first.wg_port, 51821);
    assert_eq!(first.service_state, "active");

    let key_path = f.manager.key_path();
    let conf_path = f.manager.config_path();
    assert_eq!(
        fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(&conf_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let key_contents = fs::read_to_string(&key_path).unwrap();
    assert_eq!(key_contents.trim(), test_key(11));

    let conf_contents = fs::read_to_string(&conf_path).unwrap();
    assert!(conf_contents.contains("Address = 10.231.0.10/16\n"));
    assert!(conf_contents.contains("ListenPort = 51821\n"));
    assert!(conf_contents.contains("SaveConfig = false\n"));
    assert!(conf_contents.contains(&format!("PrivateKey = {}\n", test_key(11))));
    assert!(f.root.join("afpeer0-service-enabled").exists());

    // Calling EnsureIdentity again preserves identity idempotently.
    let second = f
        .manager
        .ensure_identity(None, &[], None, None)
        .await
        .unwrap();
    assert!(!second.created);
    assert_eq!(second.public_key, first.public_key);
    assert_eq!(second.tunnel_ip, first.tunnel_ip);
    assert_eq!(second.wg_port, first.wg_port);

    // Requesting a conflicting IP or port against an existing identity fails closed.
    let conflict_ip = f
        .manager
        .ensure_identity(Some("10.231.0.20"), &[], None, None)
        .await
        .unwrap_err();
    assert!(matches!(conflict_ip, PeerNetworkError::Conflict(_)));

    let conflict_port = f
        .manager
        .ensure_identity(None, &[], Some(51822), None)
        .await
        .unwrap_err();
    assert!(matches!(conflict_port, PeerNetworkError::Conflict(_)));
}

#[tokio::test]
async fn configured_cidr_port_avoid_list_and_ipv6_subnets_work() {
    // Tiny /30 IPv4 CIDR has only two usable host IPs: .1 and .2.
    let f4 = Fixture::with_network("10.240.5.0/30", 51901);
    let id4 = f4
        .manager
        .ensure_identity(None, &["10.240.5.1".to_string()], None, None)
        .await
        .unwrap();
    assert_eq!(id4.tunnel_ip, "10.240.5.2");
    assert_eq!(id4.interface_address, "10.240.5.2/30");
    assert_eq!(id4.wg_port, 51901);

    // IPv6 tunnel CIDR with /64 interface prefix and /128 peer AllowedIPs.
    let f6 = Fixture::with_network("fd00:af:1::/64", 51902);
    let id6 = f6
        .manager
        .ensure_identity(Some("fd00:af:1::1"), &[], None, None)
        .await
        .unwrap();
    assert_eq!(id6.interface_address, "fd00:af:1::1/64");
    let added = f6
        .manager
        .add_peer(&derived_pub(22), "2001:db8::99", 51902, "fd00:af:1::2")
        .await
        .unwrap();
    assert!(added.applied_live);
    assert_eq!(added.allowed_ips.as_deref(), Some("fd00:af:1::2/128"));
    assert_eq!(added.endpoint.as_deref(), Some("[2001:db8::99]:51902"));
}

#[test]
fn strip_target_uses_bare_afpeer0_for_default_wireguard_dir() {
    let prod = PeerNetworkManager {
        wg_dir: PathBuf::from(DEFAULT_PEER_WG_DIR),
        state_dir: PathBuf::from(DEFAULT_PEER_STATE_DIR),
        bin: None,
        fs_root: None,
        tunnel_cidr: TunnelCidr::parse_subnet(DEFAULT_PEER_TUNNEL_CIDR).unwrap(),
        wg_port: DEFAULT_PEER_WG_PORT,
        command_timeout: COMMAND_TIMEOUT,
        apt_timeout: APT_STEP_TIMEOUT,
        lock_timeout: CONFIG_LOCK_TIMEOUT,
        package_lock_timeout: PACKAGE_LOCK_TIMEOUT,
        security: FsSecurityPolicy::default_for_process(),
    };
    assert_eq!(prod.strip_target(), "afpeer0");
}

#[tokio::test]
async fn add_peer_set_endpoint_and_remove_peer_sync_live_via_strip_and_syncconf() {
    let f = Fixture::new();
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();

    let peer_pub = derived_pub(21);
    let added = f
        .manager
        .add_peer(&peer_pub, "198.51.100.20", 51821, "10.231.0.2")
        .await
        .unwrap();
    assert!(added.applied_live);
    assert_eq!(added.allowed_ips.as_deref(), Some("10.231.0.2/32"));
    assert_eq!(added.endpoint.as_deref(), Some("198.51.100.20:51821"));

    let saved = fs::read_to_string(f.manager.config_path()).unwrap();
    assert!(saved.contains("Address = 10.231.0.1/16\n"));
    assert!(saved.contains(&format!("PublicKey = {peer_pub}\n")));
    assert!(saved.contains("AllowedIPs = 10.231.0.2/32\n"));
    assert!(saved.contains("Endpoint = 198.51.100.20:51821\n"));
    assert!(saved.contains("PersistentKeepalive = 25\n"));

    let runtime = f.read_file("runtime.conf");
    assert!(runtime.contains(&format!("PublicKey = {peer_pub}")));
    assert!(runtime.contains("AllowedIPs = 10.231.0.2/32"));
    assert!(!runtime.contains("Address ="));
    assert!(!f.has_temp_files());

    // Confirm exact argument-vector sequence: wg-quick strip -> wg syncconf afpeer0 -> ip route get.
    let cmds = f.commands();
    let strip_idx = cmds
        .iter()
        .position(|c| c["cmd"] == "wg-quick" && c["args"][0] == "strip")
        .expect("wg-quick strip must run");
    let sync_idx = cmds
        .iter()
        .position(|c| c["cmd"] == "wg" && c["args"][0] == "syncconf" && c["args"][1] == "afpeer0")
        .expect("wg syncconf afpeer0 must run");
    let route_get_idx = cmds
        .iter()
        .position(|c| {
            c["cmd"] == "ip" && c["args"] == json!(["-j", "-4", "route", "get", "10.231.0.2"])
        })
        .expect("post-sync ip route get must run for newly added peer");
    assert!(strip_idx < sync_idx);
    assert!(sync_idx < route_get_idx);

    // Ensure private key never appeared in command arguments.
    let raw_cmds = f.read_file("commands.jsonl");
    assert!(!raw_cmds.contains(&test_key(11)));

    // Update endpoint to DNS hostname and new port.
    let updated = f
        .manager
        .set_endpoint(&peer_pub, "peer-b.example.net", 52000)
        .await
        .unwrap();
    assert!(updated.applied_live);
    assert_eq!(
        updated.endpoint.as_deref(),
        Some("peer-b.example.net:52000")
    );
    assert_eq!(updated.allowed_ips.as_deref(), Some("10.231.0.2/32"));
    let saved_after_ep = fs::read_to_string(f.manager.config_path()).unwrap();
    assert!(saved_after_ep.contains("Endpoint = peer-b.example.net:52000\n"));
    assert!(!saved_after_ep.contains("198.51.100.20:51821"));
    assert!(saved_after_ep.contains("PersistentKeepalive = 25\n"));
    assert!(f
        .read_file("runtime.conf")
        .contains("Endpoint = peer-b.example.net:52000"));

    // Remove peer.
    let removed = f.manager.remove_peer(&peer_pub).await.unwrap();
    assert!(removed.applied_live);
    let saved_after_rm = fs::read_to_string(f.manager.config_path()).unwrap();
    assert!(!saved_after_rm.contains(&peer_pub));
    assert!(!f.read_file("runtime.conf").contains(&peer_pub));
    assert!(!f.has_temp_files());
}

#[tokio::test]
async fn live_interface_with_host_only_prefix_is_detected_and_blocks_add_peer() {
    let f = Fixture::new();
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();

    // Simulate a kernel interface configured with /32 instead of the /16 subnet route.
    f.mark("wrong-prefix");

    let status = f.manager.status().await.unwrap();
    assert_eq!(status.state, "error");
    assert!(!status.route_prefix_ready);
    assert!(status
        .error
        .as_deref()
        .unwrap_or("")
        .contains("subnet routing"));

    let err = f
        .manager
        .add_peer(&derived_pub(25), "198.51.100.25", 51821, "10.231.0.5")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("subnet routing"));
    assert!(!fs::read_to_string(f.manager.config_path())
        .unwrap()
        .contains(&derived_pub(25)));
}

#[tokio::test]
async fn stopped_interface_persists_peer_changes_without_false_live_sync() {
    let f = Fixture::new();
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();
    f.unmark("afpeer0-up");
    f.unmark("afpeer0-service-active");

    let peer_pub = derived_pub(31);
    let added = f
        .manager
        .add_peer(&peer_pub, "198.51.100.31", 51821, "10.231.0.31")
        .await
        .unwrap();
    assert!(!added.applied_live);
    assert!(added.message.contains("wg-quick@afpeer0.service"));
    assert!(fs::read_to_string(f.manager.config_path())
        .unwrap()
        .contains(&peer_pub));
    assert!(!f
        .commands()
        .iter()
        .any(|c| c["cmd"] == "wg" && c["args"][0] == "syncconf"));
}

#[tokio::test]
async fn failed_syncconf_and_strip_roll_back_runtime_and_persistent_state() {
    let f = Fixture::new();
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();

    let before_conf = fs::read_to_string(f.manager.config_path()).unwrap();
    let before_runtime = f.read_file("runtime.conf");

    // 1. Transient wg syncconf failure rolls back both live runtime and afpeer0.conf.
    f.mark("fail-next-syncconf");
    let err = f
        .manager
        .add_peer(&derived_pub(41), "198.51.100.41", 51821, "10.231.0.41")
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("previous runtime and persistent configuration were restored"));
    assert_eq!(
        fs::read_to_string(f.manager.config_path()).unwrap(),
        before_conf
    );
    assert_eq!(f.read_file("runtime.conf"), before_runtime);
    assert!(!f.has_temp_files());

    // 2. wg-quick strip failure rolls back afpeer0.conf and never leaks PrivateKey from stderr.
    f.mark("fail-strip");
    let strip_err = f
        .manager
        .add_peer(&derived_pub(42), "198.51.100.42", 51821, "10.231.0.42")
        .await
        .unwrap_err();
    assert!(strip_err
        .to_string()
        .contains("previous afpeer0.conf was restored"));
    assert!(!strip_err.to_string().contains(&test_key(11)));
    assert_eq!(
        fs::read_to_string(f.manager.config_path()).unwrap(),
        before_conf
    );
    assert!(!f.has_temp_files());
    f.unmark("fail-strip");

    // 3. Double failure (apply + rollback syncconf both fail) reports incomplete recovery
    //    while still restoring persistent afpeer0.conf.
    f.mark("fail-all-syncconf");
    let double_err = f
        .manager
        .add_peer(&derived_pub(43), "198.51.100.43", 51821, "10.231.0.43")
        .await
        .unwrap_err();
    assert!(double_err.to_string().contains("recovery was incomplete"));
    assert_eq!(
        fs::read_to_string(f.manager.config_path()).unwrap(),
        before_conf
    );
    assert!(!f.has_temp_files());
}

#[tokio::test]
async fn ensure_identity_rolls_back_fresh_files_when_service_activation_fails() {
    let f = Fixture::new();
    f.mark("systemctl-start-fail");

    let err = f
        .manager
        .ensure_identity(Some("10.231.0.9"), &[], None, None)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("rolled back"));
    assert!(!f.manager.config_path().exists());
    assert!(!f.manager.key_path().exists());
    assert!(!f.root.join("afpeer0-service-failed").exists());
}

#[tokio::test]
async fn status_parses_redacted_wg_dump_and_detects_identity_drift() {
    let f = Fixture::new();

    // Not installed state.
    f.mark("wg-missing");
    let missing = f.manager.status().await.unwrap();
    assert!(!missing.installed);
    assert_eq!(missing.state, "not_installed");
    f.unmark("wg-missing");

    // Unconfigured state.
    let unconf = f.manager.status().await.unwrap();
    assert!(unconf.installed);
    assert_eq!(unconf.state, "unconfigured");
    assert!(!unconf.config_available);

    // Running state with live peer.
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();
    let peer_pub = derived_pub(51);
    f.manager
        .add_peer(&peer_pub, "198.51.100.51", 51821, "10.231.0.51")
        .await
        .unwrap();

    // Inject a preshared key into custom dump to prove it is never leaked in status JSON.
    let psk = test_key(99);
    let now = chrono::Utc::now().timestamp();
    fs::write(
        f.root.join("custom-dump"),
        format!(
            "{}\t{}\t51821\toff\n{}\t{}\t198.51.100.51:51821\t10.231.0.51/32\t{}\t4096\t8192\t25\n",
            test_key(11),
            derived_pub(11),
            peer_pub,
            psk,
            now - 10
        ),
    )
    .unwrap();

    let running = f.manager.status().await.unwrap();
    assert_eq!(running.state, "running");
    assert!(running.route_prefix_ready);
    assert_eq!(running.public_key, derived_pub(11));
    assert_eq!(running.peers.len(), 1);
    assert!(running.peers[0].active);
    assert!(running.peers[0].persistent);
    assert!(running.peers[0].present_live);
    assert!(running.peers[0]
        .handshake_age_secs
        .is_some_and(|age| age <= 30));
    let serialized = serde_json::to_string(&running).unwrap();
    assert!(!serialized.contains(&test_key(11)));
    assert!(!serialized.contains(&psk));
    f.unmark("custom-dump");

    // Live vs saved identity mismatch -> error on both Status and mutations (network.rs:820, 926).
    fs::write(
        f.root.join("runtime.conf"),
        format!(
            "[Interface]\nPrivateKey = {}\nListenPort = 51821\n",
            test_key(77)
        ),
    )
    .unwrap();
    let drifted = f.manager.status().await.unwrap();
    assert_eq!(drifted.state, "error");
    assert!(drifted
        .error
        .as_deref()
        .unwrap_or("")
        .contains("differs from afpeer0.conf"));
    let mut_err = f
        .manager
        .add_peer(&derived_pub(52), "198.51.100.52", 51821, "10.231.0.52")
        .await
        .unwrap_err();
    assert!(mut_err
        .to_string()
        .contains("live afpeer0 and saved configuration differ"));

    // Restore runtime, then corrupt afpeer0.key relative to afpeer0.conf.
    fs::write(
        f.root.join("runtime.conf"),
        format!(
            "[Interface]\nPrivateKey = {}\nListenPort = 51821\n",
            test_key(11)
        ),
    )
    .unwrap();
    fs::write(f.manager.key_path(), format!("{}\n", test_key(88))).unwrap();
    let key_drift = f.manager.status().await.unwrap();
    assert_eq!(key_drift.state, "error");
    assert!(key_drift
        .error
        .as_deref()
        .unwrap_or("")
        .contains("afpeer0.key differs"));
}

#[tokio::test]
async fn validation_rejects_bad_keys_endpoints_subnets_and_symlinks() {
    let f = Fixture::new();
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();

    // Bad public keys & self key.
    for bad_key in ["", "not-a-key", &test_key(0), &derived_pub(11)] {
        assert!(f
            .manager
            .add_peer(bad_key, "198.51.100.2", 51821, "10.231.0.2")
            .await
            .is_err());
    }

    // Bad endpoints / ports.
    for (ep, port) in [
        ("", 51821),
        ("198.51.100.2", 0),
        ("--help", 51821),
        ("198.51.100.2:51821", 51821),
        ("bad host", 51821),
        ("host;id", 51821),
        ("host\nPrivateKey=bad", 51821),
        ("[not-ipv6]", 51821),
    ] {
        assert!(
            f.manager
                .add_peer(&derived_pub(61), ep, port, "10.231.0.2")
                .await
                .is_err(),
            "endpoint={ep} port={port}"
        );
    }

    // Bad tunnel IPs (CIDR suffix, multi-list, out-of-subnet, network, broadcast, self IP).
    for bad_ip in [
        "10.231.0.2/32",
        "10.231.0.2/24",
        "0.0.0.0/0",
        "10.231.0.2,10.231.0.3",
        "10.232.0.2",
        "10.231.0.0",
        "10.231.255.255",
        "10.231.0.1",
        "fd00::2",
    ] {
        assert!(
            f.manager
                .add_peer(&derived_pub(62), "198.51.100.2", 51821, bad_ip)
                .await
                .is_err(),
            "bad_ip={bad_ip}"
        );
    }

    // Matching existing peer vs different IP/endpoint conflict vs different peer IP conflict.
    f.manager
        .add_peer(&derived_pub(63), "198.51.100.3", 51821, "10.231.0.3")
        .await
        .unwrap();
    assert!(matches!(
        f.manager
            .add_peer(&derived_pub(63), "198.51.100.3", 51821, "10.231.0.3")
            .await
            .unwrap_err(),
        PeerNetworkError::PeerAlreadyExists(_)
    ));
    assert!(matches!(
        f.manager
            .add_peer(&derived_pub(63), "198.51.100.4", 51821, "10.231.0.4")
            .await
            .unwrap_err(),
        PeerNetworkError::Conflict(_)
    ));
    assert!(matches!(
        f.manager
            .add_peer(&derived_pub(64), "198.51.100.4", 51821, "10.231.0.3")
            .await
            .unwrap_err(),
        PeerNetworkError::TunnelIpConflict(_)
    ));

    // PeerNotFound on missing peers.
    assert!(matches!(
        f.manager.remove_peer(&derived_pub(90)).await.unwrap_err(),
        PeerNetworkError::PeerNotFound(_)
    ));
    assert!(matches!(
        f.manager
            .set_endpoint(&derived_pub(90), "198.51.100.90", 51821)
            .await
            .unwrap_err(),
        PeerNetworkError::PeerNotFound(_)
    ));

    // SaveConfig = true must be rejected.
    let conf_path = f.manager.config_path();
    let orig_conf = fs::read_to_string(&conf_path).unwrap();
    fs::write(
        &conf_path,
        orig_conf.replace("SaveConfig = false", "SaveConfig = true"),
    )
    .unwrap();
    assert!(f
        .manager
        .add_peer(&derived_pub(65), "198.51.100.5", 51821, "10.231.0.5")
        .await
        .unwrap_err()
        .to_string()
        .contains("SaveConfig"));
    fs::write(&conf_path, &orig_conf).unwrap();

    // Symlink at afpeer0.conf cannot redirect reads or writes.
    let outside = f.root.join("outside-target.conf");
    fs::rename(&conf_path, &outside).unwrap();
    std::os::unix::fs::symlink(&outside, &conf_path).unwrap();
    assert!(f
        .manager
        .add_peer(&derived_pub(66), "198.51.100.6", 51821, "10.231.0.6")
        .await
        .is_err());
    assert_eq!(fs::read_to_string(&outside).unwrap(), orig_conf);
}

#[tokio::test]
async fn credential_slots_enforce_permissions_validation_redaction_and_symlink_safety() {
    let f = Fixture::new();

    let link_secret = "af_link_secret_token_0123456789abcdef";
    let grant_secret = "af_grant_secret_token_fedcba9876543210";
    let pending_secret = "af_pending_issuer_token_abcdef0123456789";

    // Manual Debug redacts credential values on both request and read response.
    let write_req = PeerNetworkRequest::WriteCredential {
        slot: PeerCredentialSlot::LinkToken,
        id: "link-alpha_1".to_string(),
        value: link_secret.to_string(),
    };
    assert!(!format!("{write_req:?}").contains(link_secret));
    assert!(format!("{write_req:?}").contains("[REDACTED]"));

    // Write all three typed slots and verify on-disk paths and permissions.
    f.manager
        .write_credential(PeerCredentialSlot::LinkToken, "link-alpha_1", link_secret)
        .await
        .unwrap();
    f.manager
        .write_credential(PeerCredentialSlot::GrantToken, "link-alpha_1", grant_secret)
        .await
        .unwrap();
    f.manager
        .write_credential(
            PeerCredentialSlot::PendingIssuerToken,
            "attempt-001",
            pending_secret,
        )
        .await
        .unwrap();

    let link_path = f
        .root
        .join("etc/aetherflow/peers/tokens/link-alpha_1.token");
    let grant_path = f
        .root
        .join("etc/aetherflow/peers/tokens/link-alpha_1.grant.token");
    let pending_path = f
        .root
        .join("etc/aetherflow/peers/pending/attempt-001.token");

    assert_eq!(
        fs::metadata(&link_path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        fs::metadata(&grant_path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        fs::metadata(&pending_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        fs::metadata(f.root.join("etc/aetherflow/peers/pending"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );

    // Read back and verify Debug/Display redaction on response and PeerCredentialSecret.
    let read_link = f
        .manager
        .read_credential(PeerCredentialSlot::LinkToken, "link-alpha_1")
        .await
        .unwrap();
    assert!(read_link.present);
    assert_eq!(
        read_link.secret().map(PeerCredentialSecret::expose_secret),
        Some(link_secret)
    );
    assert!(!format!("{read_link:?}").contains(link_secret));
    assert!(!format!("{}", read_link.secret().unwrap()).contains(link_secret));
    assert!(!format!("{:?}", read_link.secret().unwrap()).contains(link_secret));

    let read_grant = f
        .manager
        .read_credential(PeerCredentialSlot::GrantToken, "link-alpha_1")
        .await
        .unwrap();
    assert_eq!(
        read_grant.secret().map(PeerCredentialSecret::expose_secret),
        Some(grant_secret)
    );

    let read_pending = f
        .manager
        .read_credential(PeerCredentialSlot::PendingIssuerToken, "attempt-001")
        .await
        .unwrap();
    assert_eq!(
        read_pending
            .secret()
            .map(PeerCredentialSecret::expose_secret),
        Some(pending_secret)
    );

    let missing = f
        .manager
        .read_credential(PeerCredentialSlot::LinkToken, "nonexistent-link")
        .await
        .unwrap();
    assert!(!missing.present);
    assert!(missing.value.is_none());

    // DeleteLinkCredentials clears both link and grant tokens cleanly and is idempotent.
    let deleted_both = f
        .manager
        .delete_link_credentials("link-alpha_1")
        .await
        .unwrap();
    assert!(deleted_both.link_token_deleted);
    assert!(deleted_both.grant_token_deleted);
    assert!(!link_path.exists());
    assert!(!grant_path.exists());
    let deleted_again = f
        .manager
        .delete_link_credentials("link-alpha_1")
        .await
        .unwrap();
    assert!(!deleted_again.link_token_deleted);
    assert!(!deleted_again.grant_token_deleted);

    // Delete pending issuer token.
    let del_pending = f
        .manager
        .delete_credential(PeerCredentialSlot::PendingIssuerToken, "attempt-001")
        .await
        .unwrap();
    assert!(del_pending.deleted);
    assert!(!pending_path.exists());

    // Reject unsafe identifiers (traversal, dots/slot-crossing, flags, empty, oversized).
    let long_id = "a".repeat(65);
    for bad_id in [
        "",
        "../afpeer0",
        "foo/bar",
        "foo\\bar",
        "link.grant",
        ".hidden",
        "-leading-dash",
        "has space",
        "bad\nid",
        long_id.as_str(),
    ] {
        assert!(
            f.manager
                .write_credential(PeerCredentialSlot::LinkToken, bad_id, link_secret)
                .await
                .is_err(),
            "bad_id={bad_id:?}"
        );
        assert!(
            f.manager
                .read_credential(PeerCredentialSlot::LinkToken, bad_id)
                .await
                .is_err(),
            "bad_id={bad_id:?}"
        );
        assert!(
            f.manager
                .delete_credential(PeerCredentialSlot::LinkToken, bad_id)
                .await
                .is_err(),
            "bad_id={bad_id:?}"
        );
    }

    // Reject invalid credential values (empty, whitespace/newlines, oversized).
    let oversized = "x".repeat(MAX_CREDENTIAL_BYTES + 1);
    for bad_val in [
        "",
        "has space",
        "line1\nline2",
        "\0secret",
        oversized.as_str(),
    ] {
        assert!(f
            .manager
            .write_credential(PeerCredentialSlot::LinkToken, "valid-id", bad_val)
            .await
            .is_err());
    }

    // Reject overly permissive files (world-readable 0644 or group-writable 0660) on read
    // and symlinks on read/write/delete.
    let perm_path = f
        .root
        .join("etc/aetherflow/peers/tokens/world-readable.token");
    fs::write(&perm_path, format!("{link_secret}\n")).unwrap();
    fs::set_permissions(&perm_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(f
        .manager
        .read_credential(PeerCredentialSlot::LinkToken, "world-readable")
        .await
        .is_err());
    fs::set_permissions(&perm_path, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(f
        .manager
        .read_credential(PeerCredentialSlot::LinkToken, "world-readable")
        .await
        .is_err());

    let outside = f.root.join("outside-secret.txt");
    fs::write(&outside, "untouched\n").unwrap();
    let sym_path = f.root.join("etc/aetherflow/peers/tokens/sym-link.token");
    std::os::unix::fs::symlink(&outside, &sym_path).unwrap();
    assert!(f
        .manager
        .read_credential(PeerCredentialSlot::LinkToken, "sym-link")
        .await
        .is_err());
    assert!(f
        .manager
        .write_credential(PeerCredentialSlot::LinkToken, "sym-link", link_secret)
        .await
        .is_err());
    assert!(f
        .manager
        .delete_credential(PeerCredentialSlot::LinkToken, "sym-link")
        .await
        .is_err());
    assert_eq!(fs::read_to_string(&outside).unwrap(), "untouched\n");
}

#[tokio::test]
async fn ensure_packages_installs_wireguard_tools_via_apt_and_skips_when_present() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let f = Fixture::new();

    // Missing initially -> runs apt-get update + apt-get install wireguard-tools + dpkg-query verify.
    let installed = f.manager.ensure_packages().await.unwrap();
    assert!(installed.installed);
    assert!(!installed.already_installed);
    assert_eq!(installed.packages, vec!["wireguard-tools".to_string()]);
    assert_eq!(
        installed
            .versions
            .get("wireguard-tools")
            .map(String::as_str),
        Some("1.0.20210914-1.4")
    );

    let cmds = f.commands();
    assert!(
        cmds.iter()
            .any(|c| c["cmd"] == "apt-get"
                && c["args"].as_array().unwrap().contains(&json!("update")))
    );
    assert!(cmds.iter().any(|c| {
        c["cmd"] == "apt-get"
            && c["args"].as_array().unwrap().contains(&json!("install"))
            && c["args"]
                .as_array()
                .unwrap()
                .contains(&json!("wireguard-tools"))
    }));

    // Second call skips apt-get completely.
    let before_count = f.commands().len();
    let second = f.manager.ensure_packages().await.unwrap();
    assert!(second.installed);
    assert!(second.already_installed);
    let new_cmds = &f.commands()[before_count..];
    assert!(!new_cmds.iter().any(|c| c["cmd"] == "apt-get"));
}

#[tokio::test]
async fn bounded_command_timeout_and_oversized_output_fail_safely() {
    let f = Fixture::new();
    let fast_mgr = f
        .manager
        .clone()
        .with_command_timeout(Duration::from_millis(300));

    f.mark("hang");
    let start = std::time::Instant::now();
    let timeout_err = fast_mgr
        .ensure_identity(Some("10.231.0.7"), &[], None, None)
        .await
        .unwrap_err();
    assert!(timeout_err.to_string().contains("timed out"));
    assert!(start.elapsed() < Duration::from_secs(3));
    f.unmark("hang");

    f.mark("too-much-output");
    let size_err = fast_mgr
        .ensure_identity(Some("10.231.0.7"), &[], None, None)
        .await
        .unwrap_err();
    assert!(size_err.to_string().contains("size limit"));
    f.unmark("too-much-output");

    f.mark("pubkey-fail");
    let pub_err = fast_mgr
        .ensure_identity(Some("10.231.0.7"), &[], None, None)
        .await
        .unwrap_err();
    assert!(!pub_err.to_string().contains(&test_key(11)));
}

#[tokio::test]
async fn runner_socket_route_and_dispatch_peer_network_wire_roundtrip() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let f = Fixture::new();
    let sock = TempSocket::new("af-pnet");
    let listener = tokio::net::UnixListener::bind(&sock.path).unwrap();

    // Mount the REAL build_runner_router() with the isolated PeerNetworkManager extension.
    let app = build_runner_router().layer(Extension(Arc::new(f.manager.clone())));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_runner_connections(listener, app, async move {
        let _ = shutdown_rx.await;
    }));

    let prev_sock = env::var("AETHERFLOW_RUNNER_SOCK").ok();
    env::set_var("AETHERFLOW_RUNNER_SOCK", &sock.path);

    let test_result = async {
        // 1. EnsureIdentity over Unix socket returns typed PeerIdentityResponse.
        let identity = dispatch_peer_network(&PeerNetworkRequest::EnsureIdentity {
            tunnel_ip: Some("10.231.1.1".to_string()),
            avoid_tunnel_ips: Vec::new(),
            wg_port: Some(51821),
            tunnel_cidr: None,
        })
        .await?
        .into_identity()?;
        assert_eq!(identity.interface, "afpeer0");
        assert_eq!(identity.tunnel_ip, "10.231.1.1");

        // 2. AddPeer + Status over Unix socket return typed responses.
        let peer_pub = derived_pub(70);
        let added = dispatch_peer_network(&PeerNetworkRequest::AddPeer {
            pubkey: peer_pub.clone(),
            endpoint: "198.51.100.70".to_string(),
            port: 51821,
            tunnel_ip: "10.231.1.2".to_string(),
        })
        .await?
        .into_mutation()?;
        assert!(added.applied_live);

        let status = dispatch_peer_network(&PeerNetworkRequest::Status)
            .await?
            .into_status()?;
        assert_eq!(status.state, "running");
        assert_eq!(status.peers.len(), 1);
        assert!(status.peers[0].present_live);

        // 3. Credential write/read/delete over Unix socket protect secrets from Debug/Display.
        let secret = "socket_roundtrip_secret_token_9876543210";
        dispatch_peer_network(&PeerNetworkRequest::WriteCredential {
            slot: PeerCredentialSlot::LinkToken,
            id: "peer-sock-1".to_string(),
            value: secret.to_string(),
        })
        .await?
        .into_credential_written()?;
        let read_enum = dispatch_peer_network(&PeerNetworkRequest::ReadCredential {
            slot: PeerCredentialSlot::LinkToken,
            id: "peer-sock-1".to_string(),
        })
        .await?;
        assert!(!format!("{read_enum:?}").contains(secret));
        let read = read_enum.into_credential_read()?;
        assert!(!format!("{read:?}").contains(secret));
        assert_eq!(
            read.secret().map(PeerCredentialSecret::expose_secret),
            Some(secret)
        );
        let owned_secret = read.into_secret().unwrap();
        assert!(!format!("{owned_secret}").contains(secret));
        drop(owned_secret);

        let deleted = dispatch_peer_network(&PeerNetworkRequest::DeleteLinkCredentials {
            link_id: "peer-sock-1".to_string(),
        })
        .await?
        .into_link_credentials_deleted()?;
        assert!(deleted.link_token_deleted);

        // 4. Error path preserves typed InvalidInput and redacts secrets cleanly.
        let bad = dispatch_peer_network(&PeerNetworkRequest::WriteCredential {
            slot: PeerCredentialSlot::LinkToken,
            id: "../escape".to_string(),
            value: secret.to_string(),
        })
        .await
        .unwrap_err();
        assert!(matches!(bad, PeerNetworkError::InvalidInput(_)));
        assert!(!bad.to_string().contains(secret));

        Ok::<(), PeerNetworkError>(())
    }
    .await;

    match prev_sock {
        Some(val) => env::set_var("AETHERFLOW_RUNNER_SOCK", val),
        None => env::remove_var("AETHERFLOW_RUNNER_SOCK"),
    }
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;

    test_result.unwrap();
}

#[tokio::test]
async fn dormant_startup_creates_no_files_and_runs_no_commands() {
    let f = Fixture::new();
    let sock = TempSocket::new("af-dorm");
    let listener = tokio::net::UnixListener::bind(&sock.path).unwrap();

    // Build and serve the runner router without invoking /v1/peer-network.
    let app = build_runner_router().layer(Extension(Arc::new(f.manager.clone())));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_runner_connections(listener, app, async move {
        let _ = shutdown_rx.await;
    }));

    // Exercise /v1/health to prove the daemon is alive while peer networking stays dormant.
    let mut stream = tokio::net::UnixStream::connect(&sock.path).await.unwrap();
    stream
        .write_all(b"GET /v1/health HTTP/1.1\r\nHost: unix\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    assert!(response.contains("\"ready\""));

    let _ = shutdown_tx.send(());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert!(!f.manager.config_path().exists());
    assert!(!f.manager.key_path().exists());
    assert!(f.commands().is_empty());
}

#[tokio::test]
async fn peer_network_never_reads_or_writes_wg0_conf() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    for unreadable_wg0 in [false, true] {
        let f = Fixture::new();
        let wg0_path = f.root.join("etc/wireguard/wg0.conf");
        let wg0_canary = format!(
            "[Interface]\nAddress = 10.66.66.1/24\nPrivateKey = {}\nListenPort = 51820\n",
            test_key(2)
        );
        fs::write(&wg0_path, &wg0_canary).unwrap();
        if unreadable_wg0 {
            // Mode 0o000 ensures even an attempted open/read on wg0.conf would fail with EACCES.
            fs::set_permissions(&wg0_path, fs::Permissions::from_mode(0o000)).unwrap();
        } else {
            fs::set_permissions(&wg0_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let mtime_before = fs::metadata(&wg0_path).unwrap().modified().unwrap();

        // Exercise every peer_network operation including rollback and credentials.
        f.manager.ensure_packages().await.unwrap();
        f.manager
            .ensure_identity(Some("10.231.2.1"), &[], None, None)
            .await
            .unwrap();
        let peer_pub = derived_pub(81);
        f.manager
            .add_peer(&peer_pub, "198.51.100.81", 51821, "10.231.2.2")
            .await
            .unwrap();
        f.manager
            .set_endpoint(&peer_pub, "198.51.100.82", 51822)
            .await
            .unwrap();
        f.mark("fail-next-syncconf");
        assert!(f
            .manager
            .add_peer(&derived_pub(82), "198.51.100.83", 51821, "10.231.2.3")
            .await
            .is_err());
        let status = f.manager.status().await.unwrap();
        assert_eq!(status.state, "running");
        f.manager
            .write_credential(
                PeerCredentialSlot::LinkToken,
                "wg0-check",
                "tok_value_12345",
            )
            .await
            .unwrap();
        f.manager
            .read_credential(PeerCredentialSlot::LinkToken, "wg0-check")
            .await
            .unwrap();
        f.manager
            .delete_link_credentials("wg0-check")
            .await
            .unwrap();
        f.manager.remove_peer(&peer_pub).await.unwrap();

        // Verify wg0.conf was never modified or opened, and no command referenced wg0.
        let mtime_after = fs::metadata(&wg0_path).unwrap().modified().unwrap();
        assert_eq!(mtime_before, mtime_after);
        if unreadable_wg0 {
            fs::set_permissions(&wg0_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(fs::read_to_string(&wg0_path).unwrap(), wg0_canary);
        let raw_cmds = f.read_file("commands.jsonl");
        assert!(
            !raw_cmds.contains("wg0"),
            "peer_network invoked a command mentioning wg0: {raw_cmds}"
        );
    }
}

#[tokio::test]
async fn from_env_applies_defaults_and_rejects_unroutable_cidr_or_zero_port() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let prev_cidr = env::var("AF_PEER_TUNNEL_CIDR").ok();
    let prev_port = env::var("AF_PEER_WG_PORT").ok();

    env::remove_var("AF_PEER_TUNNEL_CIDR");
    env::remove_var("AF_PEER_WG_PORT");
    let default_mgr = PeerNetworkManager::from_env().unwrap();
    assert_eq!(default_mgr.tunnel_cidr.network_string(), "10.231.0.0/16");
    assert_eq!(default_mgr.wg_port, 51821);
    assert_eq!(default_mgr.strip_target(), "afpeer0");

    env::set_var("AF_PEER_TUNNEL_CIDR", "10.232.0.0/20");
    env::set_var("AF_PEER_WG_PORT", "51899");
    let custom_mgr = PeerNetworkManager::from_env().unwrap();
    assert_eq!(custom_mgr.tunnel_cidr.network_string(), "10.232.0.0/20");
    assert_eq!(custom_mgr.wg_port, 51899);

    env::set_var("AF_PEER_TUNNEL_CIDR", "10.231.0.1/32");
    assert!(PeerNetworkManager::from_env().is_err());

    env::set_var("AF_PEER_TUNNEL_CIDR", "10.231.0.0/16");
    env::set_var("AF_PEER_WG_PORT", "0");
    assert!(PeerNetworkManager::from_env().is_err());

    match prev_cidr {
        Some(v) => env::set_var("AF_PEER_TUNNEL_CIDR", v),
        None => env::remove_var("AF_PEER_TUNNEL_CIDR"),
    }
    match prev_port {
        Some(v) => env::set_var("AF_PEER_WG_PORT", v),
        None => env::remove_var("AF_PEER_WG_PORT"),
    }
}

#[test]
fn saved_config_rejects_broad_allowed_ips_and_host_only_interface_prefix() {
    let broad_peer = format!(
        "[Interface]\nAddress = 10.231.0.1/16\nPrivateKey = {}\nListenPort = 51821\nSaveConfig = false\n\n[Peer]\nPublicKey = {}\nAllowedIPs = 0.0.0.0/0\n",
        test_key(11),
        derived_pub(20)
    );
    let parsed = PeerWireGuardConfig::parse(&broad_peer).unwrap();
    assert!(parsed.validate_server().is_err());

    let host_only_iface = format!(
        "[Interface]\nAddress = 10.231.0.1/32\nPrivateKey = {}\nListenPort = 51821\nSaveConfig = false\n",
        test_key(11)
    );
    let parsed_host_only = PeerWireGuardConfig::parse(&host_only_iface).unwrap();
    assert!(parsed_host_only.validate_server().is_err());
}

// ============================================================================
// Blocker 1: EnsurePackages with initialized idle DB vs active lifecycle reservation
// ============================================================================

#[tokio::test]
async fn ensure_packages_succeeds_with_initialized_idle_db_and_respects_active_reservation() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;

    // 1. Initialized idle SQLite lifecycle DB: EnsurePackages uses ReservationTarget::System
    //    and succeeds without looking up a nonexistent "wireguard-tools" Marketplace entry.
    let f_idle = Fixture::new();
    let (_db_path, _conn) = f_idle.init_lifecycle_db();
    let installed = f_idle.manager.ensure_packages().await.unwrap();
    assert!(installed.installed);
    assert!(!installed.already_installed);

    // 2. Admitted competing Marketplace lifecycle reservation blocks EnsurePackages with Busy.
    let f_busy = Fixture::new();
    let (_db_path2, mut conn2) = f_busy.init_lifecycle_db();
    let _owner_lease = af_release::lifecycle::admit_job(
        &mut conn2,
        "jellyfin",
        "job-active-1",
        "install",
        "2026-11-23T00:00:00Z",
        &["jellyfin.service".to_string()],
    )
    .unwrap();
    let err = f_busy.manager.ensure_packages().await.unwrap_err();
    assert!(
        err.is_busy(),
        "expected Busy when a Marketplace lifecycle reservation is active, got {err:?}"
    );
    assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!f_busy.commands().iter().any(|c| c["cmd"] == "apt-get"));
}

// ============================================================================
// Blocker 2: Package timeouts, process-group teardown, maintenance lease release,
//            apt step failures, missing post-install result, contention, budgets,
//            and caller disconnect during mutating work
// ============================================================================

#[test]
fn duration_budgets_align_client_deadlines_above_worst_case_server_work() {
    assert!(
        PEER_ENSURE_PACKAGES_CLIENT_TIMEOUT > ENSURE_PACKAGES_MAX_SERVER_DURATION,
        "EnsurePackages client socket timeout ({:?}) must exceed worst-case server work ({:?})",
        PEER_ENSURE_PACKAGES_CLIENT_TIMEOUT,
        ENSURE_PACKAGES_MAX_SERVER_DURATION
    );
    assert!(
        PEER_DEFAULT_CLIENT_TIMEOUT > PEER_MUTATION_MAX_SERVER_DURATION,
        "Default client socket timeout ({:?}) must exceed worst-case mutation work ({:?})",
        PEER_DEFAULT_CLIENT_TIMEOUT,
        PEER_MUTATION_MAX_SERVER_DURATION
    );
    assert_eq!(
        client_timeout_for_request(&PeerNetworkRequest::EnsurePackages),
        PEER_ENSURE_PACKAGES_CLIENT_TIMEOUT
    );
    assert_eq!(
        client_timeout_for_request(&PeerNetworkRequest::Status),
        PEER_DEFAULT_CLIENT_TIMEOUT
    );
}

#[tokio::test]
async fn ensure_packages_timeout_kills_process_group_and_releases_maintenance_lease() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let prev_grace = env::var("AETHERFLOW_ROLLBACK_GRACE_MS").ok();
    env::set_var("AETHERFLOW_ROLLBACK_GRACE_MS", "80");

    let f = Fixture::new();
    let (_db_path, _conn) = f.init_lifecycle_db();
    let lock_path = f.maintenance_lock_path();
    f.mark("apt-hang-with-child");
    f.mark("apt-ignore-term");

    let mgr = f
        .manager
        .clone()
        .with_apt_timeout(Duration::from_millis(250));

    let err = mgr.ensure_packages().await.unwrap_err();
    assert!(
        err.to_string().contains("timed out"),
        "expected apt timeout error, got: {err}"
    );

    // Wait briefly for kernel exit of the SIGKILLed background sleep descendant and verify both
    // the descendant process and the inherited maintenance lock FD are completely gone.
    let child_pid: i32 = fs::read_to_string(f.root.join("apt-child.pid"))
        .expect("fake apt-get must have spawned disposable sleep child")
        .trim()
        .parse()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let stat = fs::read_to_string(format!("/proc/{child_pid}/stat")).unwrap_or_default();
            let alive = stat.rsplit_once(") ").is_some_and(|(_, fields)| {
                !matches!(fields.split_whitespace().next(), Some("Z" | "X"))
            });
            let lease_free =
                af_release::ReleaseLockGuard::acquire(&lock_path, Duration::ZERO).is_ok();
            if !alive && lease_free {
                break;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .expect("process-group teardown must kill descendant and release maintenance lease");

    // Verify PACKAGE_MUTEX and CrossProcessLockGuard were also released cleanly.
    assert!(crate::PACKAGE_MUTEX.try_lock().is_ok());
    let env_cfg = PackageExecutionEnv::isolated(&f.root);
    assert!(CrossProcessLockGuard::try_acquire(&env_cfg, PEER_WG_PACKAGE).is_ok());

    match prev_grace {
        Some(v) => env::set_var("AETHERFLOW_ROLLBACK_GRACE_MS", v),
        None => env::remove_var("AETHERFLOW_ROLLBACK_GRACE_MS"),
    }
}

#[tokio::test]
async fn ensure_packages_handles_apt_step_failures_and_missing_post_install_result() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;

    // 1. apt-get update failure skips install and releases maintenance lease.
    let f1 = Fixture::new();
    let lock1 = f1.maintenance_lock_path();
    f1.mark("apt-update-fail");
    let err1 = f1.manager.ensure_packages().await.unwrap_err();
    assert!(err1.to_string().contains("apt-get update exited"));
    assert!(!f1.commands().iter().any(|c| {
        c["cmd"] == "apt-get" && c["args"].as_array().unwrap().contains(&json!("install"))
    }));
    assert!(af_release::ReleaseLockGuard::acquire(&lock1, Duration::ZERO).is_ok());

    // 2. apt-get install failure releases maintenance lease.
    let f2 = Fixture::new();
    let lock2 = f2.maintenance_lock_path();
    f2.mark("apt-install-fail");
    let err2 = f2.manager.ensure_packages().await.unwrap_err();
    assert!(err2.to_string().contains("apt-get install"));
    assert!(af_release::ReleaseLockGuard::acquire(&lock2, Duration::ZERO).is_ok());

    // 3. apt-get install exits 0 but package still not reported installed by dpkg-query.
    let f3 = Fixture::new();
    let lock3 = f3.maintenance_lock_path();
    f3.mark("apt-install-noop");
    let err3 = f3.manager.ensure_packages().await.unwrap_err();
    assert!(err3.to_string().contains("did not report as installed"));
    assert!(af_release::ReleaseLockGuard::acquire(&lock3, Duration::ZERO).is_ok());
}

#[tokio::test]
async fn ensure_packages_lock_contention_returns_typed_busy_within_bound() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let f = Fixture::new();
    let mgr = f
        .manager
        .clone()
        .with_lock_timeout(Duration::from_millis(120));

    // 1. Contention on PACKAGE_MUTEX.
    {
        let _held = crate::PACKAGE_MUTEX.lock().await;
        let start = std::time::Instant::now();
        let err = mgr.ensure_packages().await.unwrap_err();
        assert!(
            err.is_busy(),
            "expected Busy on PACKAGE_MUTEX contention: {err:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    // 2. Contention on CrossProcessLockGuard flock.
    {
        let env_cfg = PackageExecutionEnv::isolated(&f.root);
        let _held_flock = CrossProcessLockGuard::try_acquire(&env_cfg, "other-pkg").unwrap();
        let start = std::time::Instant::now();
        let err = mgr.ensure_packages().await.unwrap_err();
        assert!(err.is_busy(), "expected Busy on flock contention: {err:?}");
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    // 3. Contention on maintenance lock.
    {
        let lock_path = f.maintenance_lock_path();
        let _held_maint =
            af_release::ReleaseLockGuard::acquire(&lock_path, Duration::ZERO).unwrap();
        let start = std::time::Instant::now();
        let err = mgr.ensure_packages().await.unwrap_err();
        assert!(
            err.is_busy(),
            "expected Busy on maintenance lock contention: {err:?}"
        );
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}

#[tokio::test]
async fn caller_disconnect_during_mutating_rpc_completes_cleanly_and_releases_locks() {
    let f = Fixture::new();
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();
    fs::write(f.root.join("syncconf-slow-ms"), "250").unwrap();

    let sock = TempSocket::new("af-disc");
    let listener = tokio::net::UnixListener::bind(&sock.path).unwrap();
    let app = build_runner_router().layer(Extension(Arc::new(f.manager.clone())));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_runner_connections(listener, app, async move {
        let _ = shutdown_rx.await;
    }));

    let peer_pub = derived_pub(73);
    let body = serde_json::to_string(&PeerNetworkRequest::AddPeer {
        pubkey: peer_pub.clone(),
        endpoint: "198.51.100.73".to_string(),
        port: 51821,
        tunnel_ip: "10.231.0.73".to_string(),
    })
    .unwrap();
    let req_raw = format!(
        "POST /v1/peer-network HTTP/1.1\r\nHost: unix\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    // Send AddPeer and drop the Unix socket as soon as syncconf has started.
    {
        let mut stream = tokio::net::UnixStream::connect(&sock.path).await.unwrap();
        stream.write_all(req_raw.as_bytes()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !f.root.join("syncconf-started").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("syncconf must begin before disconnect");
        // Drop stream here -> caller disconnects mid-mutation!
    }

    // Wait for detached task to finish cleanly and release locks.
    tokio::time::timeout(Duration::from_secs(3), async {
        while !f.root.join("syncconf-finished").exists() {
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .expect("mutating RPC must finish cleanly despite caller disconnect");

    // Subsequent status and mutation immediately succeed without lock hang or partial state.
    f.unmark("syncconf-slow-ms");
    let status = f.manager.status().await.unwrap();
    assert_eq!(status.state, "running");
    assert!(status
        .peers
        .iter()
        .any(|p| p.public_key == peer_pub && p.persistent && p.present_live));
    f.manager
        .add_peer(&derived_pub(74), "198.51.100.74", 51821, "10.231.0.74")
        .await
        .unwrap();

    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}

// ============================================================================
// Blocker 3: Socket HTTP status fidelity, typed errors, malformed JSON sanitization
// ============================================================================

async fn raw_socket_post(sock_path: &Path, path: &str, body: &str) -> (u16, String, String) {
    let mut stream = tokio::net::UnixStream::connect(sock_path).await.unwrap();
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: unix\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).await.unwrap();
    let (headers, resp_body) = raw.split_once("\r\n\r\n").unwrap();
    let status_code: u16 = headers
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status_code, headers.to_string(), resp_body.to_string())
}

#[tokio::test]
async fn socket_preserves_http_statuses_typed_errors_and_sanitizes_malformed_json() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let f = Fixture::new();
    let mgr = f
        .manager
        .clone()
        .with_lock_timeout(Duration::from_millis(120));
    let sock = TempSocket::new("af-pnet-err");
    let listener = tokio::net::UnixListener::bind(&sock.path).unwrap();
    let app = build_runner_router().layer(Extension(Arc::new(mgr.clone())));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve_runner_connections(listener, app, async move {
        let _ = shutdown_rx.await;
    }));

    let prev_sock = env::var("AETHERFLOW_RUNNER_SOCK").ok();
    env::set_var("AETHERFLOW_RUNNER_SOCK", &sock.path);

    let test_result = async {
        // 1. Malformed JSON with embedded secret returns sanitized JSON 400 without echoing parser text.
        let canary_secret = "SUPER_SECRET_MALFORMED_TOKEN_99999";
        let (code, headers, body) = raw_socket_post(
            &sock.path,
            "/v1/peer-network",
            &format!(r#"{{"action":"write_credential","value":"{canary_secret}","bad_field":1}}"#),
        )
        .await;
        assert_eq!(code, 400);
        assert!(headers.to_ascii_lowercase().contains("application/json"));
        assert!(headers
            .to_ascii_lowercase()
            .contains("x-af-peer-error-code: invalid_input"));
        assert!(!body.contains(canary_secret));
        assert!(!body.contains("bad_field"));
        let decoded: RunnerResponse = serde_json::from_str(&body).unwrap();
        assert!(!decoded.success);

        // Also syntax-broken JSON.
        let (code2, _, body2) = raw_socket_post(
            &sock.path,
            "/v1/peer-network",
            &format!("not json {canary_secret}"),
        )
        .await;
        assert_eq!(code2, 400);
        assert!(!body2.contains(canary_secret));
        let decoded2: RunnerResponse = serde_json::from_str(&body2).unwrap();
        assert!(!decoded2.success);

        // 2. Missing identity -> NotFound (404, not_found).
        let no_id = dispatch_peer_network(&PeerNetworkRequest::RemovePeer {
            pubkey: derived_pub(88),
        })
        .await
        .unwrap_err();
        assert!(matches!(no_id, PeerNetworkError::NotFound(_)));
        assert_eq!(no_id.status_code(), StatusCode::NOT_FOUND);

        // Initialize identity and add one peer.
        dispatch_peer_network(&PeerNetworkRequest::EnsureIdentity {
            tunnel_ip: Some("10.231.0.1".to_string()),
            avoid_tunnel_ips: Vec::new(),
            wg_port: Some(51821),
            tunnel_cidr: None,
        })
        .await
        .unwrap();

        let peer_pub = derived_pub(80);
        dispatch_peer_network(&PeerNetworkRequest::AddPeer {
            pubkey: peer_pub.clone(),
            endpoint: "198.51.100.80".to_string(),
            port: 51821,
            tunnel_ip: "10.231.0.80".to_string(),
        })
        .await
        .unwrap();

        // 3. Matching existing peer -> PeerAlreadyExists (409, peer_already_exists).
        let exact_dup = dispatch_peer_network(&PeerNetworkRequest::AddPeer {
            pubkey: peer_pub.clone(),
            endpoint: "198.51.100.80".to_string(),
            port: 51821,
            tunnel_ip: "10.231.0.80".to_string(),
        })
        .await
        .unwrap_err();
        assert!(exact_dup.is_peer_already_exists());
        assert_eq!(exact_dup.status_code(), StatusCode::CONFLICT);

        // 4. Same pubkey with different endpoint/IP -> Conflict (409, conflict).
        let diff_ep = dispatch_peer_network(&PeerNetworkRequest::AddPeer {
            pubkey: peer_pub.clone(),
            endpoint: "198.51.100.99".to_string(),
            port: 51821,
            tunnel_ip: "10.231.0.80".to_string(),
        })
        .await
        .unwrap_err();
        assert!(matches!(diff_ep, PeerNetworkError::Conflict(_)));
        assert_eq!(diff_ep.status_code(), StatusCode::CONFLICT);

        // 5. Different pubkey with colliding IP -> TunnelIpConflict (409, tunnel_ip_conflict).
        let ip_conflict = dispatch_peer_network(&PeerNetworkRequest::AddPeer {
            pubkey: derived_pub(81),
            endpoint: "198.51.100.81".to_string(),
            port: 51821,
            tunnel_ip: "10.231.0.80".to_string(),
        })
        .await
        .unwrap_err();
        assert!(ip_conflict.is_tunnel_ip_conflict());
        assert_eq!(ip_conflict.status_code(), StatusCode::CONFLICT);

        // 6. Missing peer on RemovePeer & SetEndpoint -> PeerNotFound (404, peer_not_found).
        let missing_rm = dispatch_peer_network(&PeerNetworkRequest::RemovePeer {
            pubkey: derived_pub(95),
        })
        .await
        .unwrap_err();
        assert!(missing_rm.is_peer_not_found());
        assert_eq!(missing_rm.status_code(), StatusCode::NOT_FOUND);

        let missing_ep = dispatch_peer_network(&PeerNetworkRequest::SetEndpoint {
            pubkey: derived_pub(95),
            endpoint: "198.51.100.95".to_string(),
            port: 51821,
        })
        .await
        .unwrap_err();
        assert!(missing_ep.is_peer_not_found());

        // 7. Contended lock over Unix socket -> Busy (503, busy).
        let lock = peer_wg_lock_for(&mgr.wg_dir, &mgr.state_dir);
        let _held = lock.write_owned().await;
        let busy_err = dispatch_peer_network(&PeerNetworkRequest::Status)
            .await
            .unwrap_err();
        assert!(busy_err.is_busy());
        assert_eq!(busy_err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        drop(_held);

        Ok::<(), anyhow::Error>(())
    }
    .await;

    match prev_sock {
        Some(val) => env::set_var("AETHERFLOW_RUNNER_SOCK", val),
        None => env::remove_var("AETHERFLOW_RUNNER_SOCK"),
    }
    let _ = shutdown_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    test_result.unwrap();
}

// ============================================================================
// Blocker 4: Kernel routing verification, unavailable address states,
//            unexpected winning interface, and post-sync rollback
// ============================================================================

#[tokio::test]
async fn routing_verification_catches_missing_subnet_unavailable_addr_and_unexpected_interface() {
    let f = Fixture::new();
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();

    // 1. Missing kernel subnet route -> Status error and AddPeer blocked before disk write.
    f.mark("missing-subnet-route");
    let st_missing = f.manager.status().await.unwrap();
    assert_eq!(st_missing.state, "error");
    assert!(!st_missing.route_prefix_ready);
    assert!(st_missing
        .error
        .as_deref()
        .unwrap_or("")
        .contains("missing kernel subnet route"));
    assert!(f
        .manager
        .add_peer(&derived_pub(30), "198.51.100.30", 51821, "10.231.0.30")
        .await
        .is_err());
    f.unmark("missing-subnet-route");

    // 2. Subnet route winning through unexpected interface (eth0) or lower metric.
    for flag in [
        "subnet-route-wrong-dev",
        "subnet-route-competing-metric",
        "subnet-route-dead",
    ] {
        f.mark(flag);
        let st = f.manager.status().await.unwrap();
        assert_eq!(st.state, "error", "flag={flag}");
        assert!(!st.route_prefix_ready, "flag={flag}");
        assert!(
            f.manager
                .add_peer(&derived_pub(31), "198.51.100.31", 51821, "10.231.0.31")
                .await
                .is_err(),
            "flag={flag}"
        );
        f.unmark(flag);
    }

    // 3. Unavailable address states (tentative, dadfailed, detached, expired valid_life_time).
    for flag in [
        "addr-tentative",
        "addr-dadfailed",
        "addr-detached",
        "addr-expired",
    ] {
        f.mark(flag);
        let st = f.manager.status().await.unwrap();
        assert_eq!(st.state, "error", "flag={flag}");
        assert!(!st.route_prefix_ready, "flag={flag}");
        assert!(
            f.manager
                .add_peer(&derived_pub(32), "198.51.100.32", 51821, "10.231.0.32")
                .await
                .is_err(),
            "flag={flag}"
        );
        f.unmark(flag);
    }

    // Confirm no ip command ever referenced wg0.
    assert!(!f.read_file("commands.jsonl").contains("wg0"));
}

#[tokio::test]
async fn add_peer_rolls_back_disk_and_live_config_when_post_sync_route_fails() {
    let f = Fixture::new();
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();

    let before_conf = fs::read_to_string(f.manager.config_path()).unwrap();
    let before_runtime = f.read_file("runtime.conf");

    // Winning route for the newly synced peer resolves via eth0 instead of afpeer0.
    for flag in [
        "peer-route-wrong-dev",
        "peer-route-blackhole",
        "peer-route-local",
        "peer-route-fail",
        "peer-route-linkdown",
    ] {
        f.mark(flag);
        let peer_pub = derived_pub(35);
        let err = f
            .manager
            .add_peer(&peer_pub, "198.51.100.35", 51821, "10.231.0.35")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("previous runtime and persistent configuration were restored"),
            "flag={flag} err={err}"
        );
        assert_eq!(
            fs::read_to_string(f.manager.config_path()).unwrap(),
            before_conf,
            "disk config must be rolled back for flag={flag}"
        );
        assert_eq!(
            f.read_file("runtime.conf"),
            before_runtime,
            "live runtime must be rolled back for flag={flag}"
        );
        assert!(!f.has_temp_files());
        f.unmark(flag);
    }
}

// ============================================================================
// Blocker 5: FD-anchored lock metadata, dir modes, group lookup & missing-leaf symlinks
// ============================================================================

#[tokio::test]
async fn confinement_validates_lock_metadata_dir_modes_group_and_missing_leaf_symlinks() {
    // 1. Lock file non-strict mode (0644, 0660) and symlink lock file are rejected.
    let f_lock = Fixture::new();
    let lock_path = f_lock
        .root
        .join("etc/aetherflow/peers/.aetherflow-peer-network.lock");
    fs::write(&lock_path, "").unwrap();
    for bad_mode in [0o644, 0o660, 0o700] {
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(bad_mode)).unwrap();
        let err = f_lock
            .manager
            .ensure_identity(Some("10.231.0.1"), &[], None, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("non-strict mode"),
            "bad_mode={bad_mode:04o} err={err}"
        );
    }
    fs::remove_file(&lock_path).unwrap();
    let decoy = f_lock.root.join("lock-decoy");
    fs::write(&decoy, "").unwrap();
    std::os::unix::fs::symlink(&decoy, &lock_path).unwrap();
    assert!(f_lock
        .manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .is_err());

    // 2. Owner UID mismatch rejected when expected_uid=Some(0) on non-root fixture.
    if !running_as_root() {
        let f_uid = Fixture::new();
        let root_enforced = f_uid.manager.clone().with_expected_uid(Some(0));
        let err = root_enforced
            .ensure_identity(Some("10.231.0.1"), &[], None, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not owned by expected uid 0"));
    }

    // 3. Required production group lookup failure fails clearly (never falls back to gid 0).
    let f_grp = Fixture::new();
    let missing_grp_mgr = f_grp
        .manager
        .clone()
        .with_required_group_name("af_nonexistent_group_xyz_99999");
    let grp_err = missing_grp_mgr
        .write_credential(PeerCredentialSlot::LinkToken, "link-1", "secret_val_123")
        .await
        .unwrap_err();
    assert!(grp_err.to_string().contains("could not be resolved"));

    // 4. Wrong group GID on group-readable credential file and tokens directory is rejected.
    let f_gid = Fixture::new();
    f_gid
        .manager
        .write_credential(PeerCredentialSlot::LinkToken, "link-g", "secret_val_456")
        .await
        .unwrap();
    let actual_gid = fs::metadata(f_gid.root.join("etc/aetherflow/peers/tokens/link-g.token"))
        .unwrap()
        .gid();
    let wrong_gid_mgr = f_gid
        .manager
        .clone()
        .with_expected_group_gid(actual_gid.wrapping_add(1));
    let gid_err = wrong_gid_mgr
        .read_credential(PeerCredentialSlot::LinkToken, "link-g")
        .await
        .unwrap_err();
    assert!(gid_err.to_string().contains("unexpected group gid"));

    // Also verify the file-level GID check directly when directories are 0700 (no group bits)
    // and only the credential file itself has 0640 with an unexpected GID.
    fs::set_permissions(
        f_gid.root.join("etc/aetherflow/peers"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    fs::set_permissions(
        f_gid.root.join("etc/aetherflow/peers/tokens"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let file_gid_err = wrong_gid_mgr
        .read_credential(PeerCredentialSlot::LinkToken, "link-g")
        .await
        .unwrap_err();
    assert!(file_gid_err
        .to_string()
        .contains("Refusing credential file link-g.token with unexpected group gid"));

    // 5. Unsafe directory modes on ancestor, state, config, tokens, and private (pending) dirs rejected.
    let f_dirs = Fixture::new();
    fs::set_permissions(
        f_dirs.root.join("etc/aetherflow"),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();
    assert!(f_dirs
        .manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap_err()
        .to_string()
        .contains("Refusing writable or privileged ancestor directory"));
    fs::set_permissions(
        f_dirs.root.join("etc/aetherflow"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    fs::set_permissions(
        f_dirs.root.join("etc/aetherflow/peers"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(f_dirs
        .manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap_err()
        .to_string()
        .contains("overly permissive directory"));
    fs::set_permissions(
        f_dirs.root.join("etc/aetherflow/peers"),
        fs::Permissions::from_mode(0o750),
    )
    .unwrap();

    fs::set_permissions(
        f_dirs.root.join("etc/wireguard"),
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(f_dirs
        .manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap_err()
        .to_string()
        .contains("overly permissive directory"));
    fs::set_permissions(
        f_dirs.root.join("etc/wireguard"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();

    let pending_dir = f_dirs.root.join("etc/aetherflow/peers/pending");
    fs::create_dir_all(&pending_dir).unwrap();
    fs::set_permissions(&pending_dir, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(f_dirs
        .manager
        .write_credential(
            PeerCredentialSlot::PendingIssuerToken,
            "att-1",
            "pending_tok_1"
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("overly permissive directory"));

    // 6. Status must NOT bypass component-wise nofollow checks when leaf files are missing.
    let f_sym_wg = Fixture::new();
    let outside_empty = f_sym_wg.root.join("outside-empty");
    fs::create_dir_all(&outside_empty).unwrap();
    fs::remove_dir(f_sym_wg.root.join("etc/wireguard")).unwrap();
    std::os::unix::fs::symlink(&outside_empty, f_sym_wg.root.join("etc/wireguard")).unwrap();
    let st_wg = f_sym_wg.manager.status().await.unwrap();
    assert_eq!(st_wg.state, "error");
    assert!(st_wg
        .error
        .as_deref()
        .unwrap_or("")
        .contains("unsafe or inaccessible directory"));

    let f_sym_state = Fixture::new();
    let outside_empty2 = f_sym_state.root.join("outside-empty-2");
    fs::create_dir_all(&outside_empty2).unwrap();
    fs::remove_dir(f_sym_state.root.join("etc/aetherflow/peers")).unwrap();
    std::os::unix::fs::symlink(
        &outside_empty2,
        f_sym_state.root.join("etc/aetherflow/peers"),
    )
    .unwrap();
    let st_state = f_sym_state.manager.status().await.unwrap();
    assert_eq!(st_state.state, "error");
    assert!(st_state
        .error
        .as_deref()
        .unwrap_or("")
        .contains("unsafe or inaccessible directory"));

    // Dangling symlink at a missing leaf directory must also fail closed in status().
    let f_dangling = Fixture::new();
    fs::remove_dir(f_dangling.root.join("etc/wireguard")).unwrap();
    std::os::unix::fs::symlink(
        f_dangling.root.join("does-not-exist-target"),
        f_dangling.root.join("etc/wireguard"),
    )
    .unwrap();
    let st_dangling = f_dangling.manager.status().await.unwrap();
    assert_eq!(st_dangling.state, "error");
    assert!(st_dangling
        .error
        .as_deref()
        .unwrap_or("")
        .contains("unsafe or inaccessible directory"));
}

// ============================================================================
// Blocker 6: EnsureIdentity post-start live verification, avoid_tunnel_ips on
//            existing config, empty optional CIDR, verified rollback & reset-failed
// ============================================================================

#[tokio::test]
async fn ensure_identity_verifies_stopped_restart_honors_avoid_ips_and_empty_cidr() {
    let f = Fixture::new();
    // Provision on a non-default CIDR (10.232.0.0/20) while manager default is 10.231.0.0/16.
    let initial = f
        .manager
        .ensure_identity(Some("10.232.0.10"), &[], None, Some("10.232.0.0/20"))
        .await
        .unwrap();
    assert!(initial.created);
    assert_eq!(initial.tunnel_ip, "10.232.0.10");

    // 1. Empty/whitespace optional tunnel_cidr is normalized to None (does not conflict!).
    for empty_cidr in ["", "   "] {
        let again = f
            .manager
            .ensure_identity(None, &[], None, Some(empty_cidr))
            .await
            .unwrap();
        assert!(!again.created);
        assert_eq!(again.tunnel_ip, "10.232.0.10");
        assert_eq!(again.tunnel_cidr, "10.232.0.0/20");
    }

    // 2. Existing address appearing in avoid_tunnel_ips returns TunnelIpConflict.
    let avoid_err = f
        .manager
        .ensure_identity(None, &["10.232.0.10".to_string()], None, None)
        .await
        .unwrap_err();
    assert!(avoid_err.is_tunnel_ip_conflict());

    // 3. Previously stopped existing config MUST verify live identity after starting.
    f.unmark("afpeer0-up");
    f.unmark("afpeer0-service-active");
    f.mark("start-mismatched-live-key");
    let drift_err = f
        .manager
        .ensure_identity(None, &[], None, None)
        .await
        .unwrap_err();
    assert!(matches!(drift_err, PeerNetworkError::Conflict(_)));
    assert!(drift_err
        .to_string()
        .contains("live afpeer0 and saved configuration differ"));

    // Once live key matches again, starting the previously stopped config succeeds.
    f.unmark("start-mismatched-live-key");
    f.unmark("afpeer0-up");
    f.unmark("afpeer0-service-active");
    let restarted = f
        .manager
        .ensure_identity(None, &[], None, None)
        .await
        .unwrap();
    assert!(!restarted.created);
    assert_eq!(restarted.public_key, initial.public_key);
    assert_eq!(restarted.service_state, "active");
}

#[tokio::test]
async fn ensure_identity_fresh_activation_rollback_preserves_on_teardown_failure_and_recovers() {
    // 1. Activation fails leaving unit in "failed" state -> verified teardown removes fresh
    //    files, calls systemctl reset-failed, clears failed state, and retry succeeds.
    let f1 = Fixture::new();
    f1.mark("systemctl-start-fail");
    let err1 = f1
        .manager
        .ensure_identity(Some("10.231.0.9"), &[], None, None)
        .await
        .unwrap_err();
    assert!(err1.to_string().contains("rolled back"));
    assert!(!f1.manager.config_path().exists());
    assert!(!f1.manager.key_path().exists());
    assert!(f1
        .commands()
        .iter()
        .any(|c| c["cmd"] == "systemctl"
            && c["args"] == json!(["reset-failed", PEER_WG_SERVICE_UNIT])));
    let st1 = f1.manager.status().await.unwrap();
    assert_eq!(st1.state, "unconfigured");
    assert_eq!(st1.service_state, "inactive");

    f1.unmark("systemctl-start-fail");
    let retry1 = f1
        .manager
        .ensure_identity(Some("10.231.0.9"), &[], None, None)
        .await
        .unwrap();
    assert!(retry1.created);
    assert_eq!(retry1.service_state, "active");

    // 2. Pre-existing afpeer0.key is preserved (only newly created afpeer0.conf removed) on rollback.
    let f2 = Fixture::new();
    let existing_key = test_key(44);
    fs::write(f2.manager.key_path(), format!("{existing_key}\n")).unwrap();
    fs::set_permissions(f2.manager.key_path(), fs::Permissions::from_mode(0o600)).unwrap();
    f2.mark("systemctl-start-fail");
    let err2 = f2
        .manager
        .ensure_identity(Some("10.231.0.10"), &[], None, None)
        .await
        .unwrap_err();
    assert!(err2.to_string().contains("rolled back"));
    assert!(!f2.manager.config_path().exists());
    assert!(f2.manager.key_path().exists());
    assert_eq!(
        fs::read_to_string(f2.manager.key_path()).unwrap().trim(),
        existing_key
    );

    // 3. Partial fresh activation where post-start route check fails AND teardown fails
    //    (disable --now fails or leaves live interface up) -> preserves saved files for recovery
    //    and reports incomplete cleanup; subsequent retry recovers cleanly once fixed.
    for teardown_flag in ["disable-fail", "disable-leaves-live"] {
        let f3 = Fixture::new();
        f3.mark("missing-subnet-route");
        f3.mark(teardown_flag);
        let err3 = f3
            .manager
            .ensure_identity(Some("10.231.0.15"), &[], None, None)
            .await
            .unwrap_err();
        assert!(
            err3.to_string().contains("incomplete"),
            "flag={teardown_flag} err={err3}"
        );
        assert!(
            err3.to_string().contains("preserved"),
            "flag={teardown_flag} err={err3}"
        );
        assert!(
            f3.manager.config_path().exists(),
            "afpeer0.conf must be preserved when teardown fails ({teardown_flag})"
        );
        assert!(
            f3.manager.key_path().exists(),
            "afpeer0.key must be preserved when teardown fails ({teardown_flag})"
        );

        // Fix the underlying route issue and retry -> reconciles preserved config cleanly!
        f3.unmark("missing-subnet-route");
        f3.unmark(teardown_flag);
        let recovered = f3
            .manager
            .ensure_identity(Some("10.231.0.15"), &[], None, None)
            .await
            .unwrap();
        assert!(!recovered.created);
        assert_eq!(recovered.tunnel_ip, "10.231.0.15");
        assert_eq!(recovered.service_state, "active");
    }
}

// ============================================================================
// Blocker 7: present_live, single handshake timing calculation, non-creating
//            status, status/mutation synchronization, and credential overlap
// ============================================================================

#[tokio::test]
async fn status_exposes_present_live_single_handshake_timing_and_stays_non_creating() {
    // 1. Read-only status on a fresh root with missing etc/wireguard and etc/aetherflow/peers
    //    must NOT create any directories or lock files.
    let empty_root = std::env::temp_dir().join(format!("af-peer-ro-{}", uuid::Uuid::new_v4()));
    let bin = empty_root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    fs::set_permissions(&empty_root, fs::Permissions::from_mode(0o755)).unwrap();
    for cmd in ["wg", "wg-quick", "systemctl", "ip", "dpkg-query", "apt-get"] {
        let path = bin.join(cmd);
        fs::write(&path, FAKE_BIN).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let ro_mgr = PeerNetworkManager::new_isolated(
        empty_root.clone(),
        bin,
        DEFAULT_PEER_TUNNEL_CIDR,
        DEFAULT_PEER_WG_PORT,
    )
    .unwrap();
    let ro_status = ro_mgr.status().await.unwrap();
    assert_eq!(ro_status.state, "unconfigured");
    assert!(!empty_root.join("etc").exists());
    let _ = fs::remove_dir_all(&empty_root);

    // 2. Saved-but-live-absent vs saved-and-live vs live-only peers.
    let f = Fixture::new();
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();
    let saved_live_pub = derived_pub(60);
    let saved_absent_pub = derived_pub(61);
    let live_only_pub = derived_pub(62);
    f.manager
        .add_peer(&saved_live_pub, "198.51.100.60", 51821, "10.231.0.60")
        .await
        .unwrap();
    f.manager
        .add_peer(&saved_absent_pub, "198.51.100.61", 51821, "10.231.0.61")
        .await
        .unwrap();

    // Custom live dump contains saved_live_pub (with no handshake yet: active=false, present_live=true)
    // and live_only_pub (active=true, persistent=false, present_live=true), while omitting
    // saved_absent_pub (simulating forced live peer removal -> persistent=true, present_live=false).
    let now = chrono::Utc::now().timestamp();
    fs::write(
        f.root.join("custom-dump"),
        format!(
            "{}\t{}\t51821\toff\n{}\t(none)\t198.51.100.60:51821\t10.231.0.60/32\t0\t10\t20\t25\n{}\t(none)\t198.51.100.62:51821\t10.231.0.62/32\t{}\t30\t40\t25\n",
            test_key(11),
            derived_pub(11),
            saved_live_pub,
            live_only_pub,
            now - 15
        ),
    )
    .unwrap();

    let st = f.manager.status().await.unwrap();
    assert_eq!(st.state, "running");
    assert_eq!(st.peers.len(), 3);

    let p_saved_live = st
        .peers
        .iter()
        .find(|p| p.public_key == saved_live_pub)
        .unwrap();
    assert!(p_saved_live.persistent);
    assert!(p_saved_live.present_live);
    assert!(!p_saved_live.active);
    assert_eq!(p_saved_live.handshake_age_secs, None);

    let p_saved_absent = st
        .peers
        .iter()
        .find(|p| p.public_key == saved_absent_pub)
        .unwrap();
    assert!(p_saved_absent.persistent);
    assert!(!p_saved_absent.present_live);
    assert!(!p_saved_absent.active);
    assert_eq!(p_saved_absent.handshake_age_secs, None);

    let p_live_only = st
        .peers
        .iter()
        .find(|p| p.public_key == live_only_pub)
        .unwrap();
    assert!(!p_live_only.persistent);
    assert!(p_live_only.present_live);
    assert!(p_live_only.active);
    assert!(p_live_only.handshake_age_secs.is_some_and(|age| age <= 180));

    // 3. Deterministic single timing calculation boundary check via parse_wg_dump_at.
    let fixed_now = 1_800_000_000_i64;
    let dump_raw = format!(
        "{}\t{}\t51821\toff\n\
         {}\t(none)\t198.51.100.1:51821\t10.231.0.10/32\t0\t0\t0\t25\n\
         {}\t(none)\t198.51.100.2:51821\t10.231.0.11/32\t{}\t0\t0\t25\n\
         {}\t(none)\t198.51.100.3:51821\t10.231.0.12/32\t{}\t0\t0\t25\n\
         {}\t(none)\t198.51.100.4:51821\t10.231.0.13/32\t{}\t0\t0\t25\n\
         {}\t(none)\t198.51.100.5:51821\t10.231.0.14/32\t{}\t0\t0\t25\n",
        test_key(11),
        derived_pub(11),
        derived_pub(1),
        derived_pub(2),
        fixed_now + 5, // future clock skew -> None, inactive
        derived_pub(3),
        fixed_now, // age 0 -> Some(0), active
        derived_pub(4),
        fixed_now - 180, // exact 180s boundary -> Some(180), active
        derived_pub(5),
        fixed_now - 181, // 181s -> Some(181), inactive
    );
    let parsed = crate::network::parse_wg_dump_at(&dump_raw, fixed_now).unwrap();
    assert_eq!(parsed.peers[0].handshake_age_secs, None);
    assert!(!parsed.peers[0].active);
    assert_eq!(parsed.peers[1].handshake_age_secs, None);
    assert!(!parsed.peers[1].active);
    assert_eq!(parsed.peers[2].handshake_age_secs, Some(0));
    assert!(parsed.peers[2].active);
    assert_eq!(parsed.peers[3].handshake_age_secs, Some(180));
    assert!(parsed.peers[3].active);
    assert_eq!(parsed.peers[4].handshake_age_secs, Some(181));
    assert!(!parsed.peers[4].active);
}

#[tokio::test]
async fn status_synchronizes_with_mutations_and_overlapping_credentials_avoid_cas_failures() {
    let f = Fixture::new();
    f.manager
        .ensure_identity(Some("10.231.0.1"), &[], None, None)
        .await
        .unwrap();

    // 1. Status snapshot overlapping a slow AddPeer waits for the mutation to finish and never
    //    observes a torn saved-but-not-live-yet snapshot.
    fs::write(f.root.join("syncconf-slow-ms"), "250").unwrap();
    let mgr_mut = f.manager.clone();
    let mgr_st = f.manager.clone();
    let peer_pub = derived_pub(68);
    let peer_pub_for_mut = peer_pub.clone();

    let mut_task = tokio::spawn(async move {
        mgr_mut
            .add_peer(&peer_pub_for_mut, "198.51.100.68", 51821, "10.231.0.68")
            .await
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        while !f.root.join("syncconf-started").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();

    // Launch status while add_peer holds the write lock mid-syncconf.
    let status = mgr_st.status().await.unwrap();
    mut_task.await.unwrap().unwrap();
    let observed = status
        .peers
        .iter()
        .find(|p| p.public_key == peer_pub)
        .expect("synchronized status must observe completed mutation");
    assert!(observed.persistent);
    assert!(
        observed.present_live,
        "status must not observe torn saved-but-live-absent state during add_peer"
    );
    f.unmark("syncconf-slow-ms");

    // 2. Overlapping credential write/read/delete retries serialize cleanly with zero CAS errors.
    let mut tasks = Vec::new();
    for i in 0..24 {
        let mgr = f.manager.clone();
        tasks.push(tokio::spawn(async move {
            match i % 4 {
                0 | 1 => mgr
                    .write_credential(
                        PeerCredentialSlot::LinkToken,
                        "overlap-link",
                        &format!("tok_retry_{i}"),
                    )
                    .await
                    .map(|_| ()),
                2 => mgr
                    .read_credential(PeerCredentialSlot::LinkToken, "overlap-link")
                    .await
                    .map(|_| ()),
                _ => mgr
                    .delete_link_credentials("overlap-link")
                    .await
                    .map(|_| ()),
            }
        }));
    }
    for task in tasks {
        task.await
            .unwrap()
            .expect("overlapping credential write/read/delete must not produce CAS failure");
    }
}
