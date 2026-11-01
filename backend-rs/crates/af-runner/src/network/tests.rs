use super::*;
use std::os::unix::fs::PermissionsExt;

const MOCK: &str = r#"#!/usr/bin/python3
import base64,json,pathlib,sys,time
root=pathlib.Path(__file__).resolve().parent.parent
name=pathlib.Path(sys.argv[0]).name
args=sys.argv[1:]
with (root/'commands.jsonl').open('a') as output:
    output.write(json.dumps([name]+args)+'\n')
def load(name): return json.loads((root/name).read_text())
def save(name,value): (root/name).write_text(json.dumps(value))
if name=='wg':
    if args==['--version']:
        sys.exit(1 if (root/'wg-missing').exists() else 0)
    if args==['genkey']:
        if (root/'too-much-output').exists(): print('x'*2000000)
        elif (root/'hang').exists(): time.sleep(60)
        elif (root/'keygen-failure').exists():
            print('genkey failed',file=sys.stderr);sys.exit(1)
        else: print(base64.b64encode(bytes([3])*32).decode())
    elif args==['pubkey']:
        private=sys.stdin.read()
        if (root/'pubkey-failure').exists():
            print('Invalid private key '+private,file=sys.stderr);sys.exit(1)
        print(base64.b64encode(bytes([4])*32).decode())
    elif args==['show','wg0','dump']:
        if not (root/'wg-running').exists():
            print('No such device',file=sys.stderr);sys.exit(1)
        print((root/'dump').read_text(),end='')
    elif args==['showconf','wg0']:
        if not (root/'wg-running').exists(): sys.exit(1)
        print((root/'runtime').read_text(),end='')
    elif args[:2]==['syncconf','wg0']:
        (root/'runtime').write_text(pathlib.Path(args[2]).read_text())
        if (root/'fail-sync').exists():
            (root/'fail-sync').unlink()
            print('simulated partial update failure',file=sys.stderr);sys.exit(1)
        if (root/'fail-all-sync').exists(): sys.exit(1)
    else: raise RuntimeError(args)
elif name=='ip':
    print(json.dumps([{'flags':[] if (root/'link-down').exists() else ['UP']}]))
elif name=='systemctl':
    marker=root/('wg-running' if args[-1]=='wg-quick@wg0.service' else 'ts-running')
    if args[0]=='is-active':
        print('active' if marker.exists() else 'inactive')
        sys.exit(0 if marker.exists() else 3)
    if (root/'service-failure').exists(): sys.exit(1)
    if args[0]=='stop': marker.unlink(missing_ok=True)
    else: marker.touch()
elif name=='tailscale':
    if args==['--version']: sys.exit(0)
    if args==['status','--json']:
        if not (root/'ts-running').exists():
            print('Cannot connect to local tailscaled',file=sys.stderr);sys.exit(1)
        print(json.dumps(load('ts-status')))
    elif args==['debug','prefs']: print(json.dumps(load('ts-prefs')))
    elif args[0]=='set':
        if (root/'set-failure').exists():
            print('Access denied by daemon',file=sys.stderr);sys.exit(1)
        prefs=load('ts-prefs')
        for arg in args[1:]:
            key,value=arg.split('=',1)
            if key=='--advertise-routes':
                prefs['AdvertiseRoutes']=[r for r in prefs['AdvertiseRoutes'] if r in ('0.0.0.0/0','::/0')]+list(filter(None,value.split(',')))
            elif key=='--accept-routes':prefs['RouteAll']=value=='true'
            elif key=='--exit-node':prefs['ExitNodeIP']=value
            elif key=='--exit-node-allow-lan-access':prefs['ExitNodeAllowLANAccess']=value=='true'
            elif key=='--advertise-exit-node':
                prefs['AdvertiseRoutes']=[r for r in prefs['AdvertiseRoutes'] if r not in ('0.0.0.0/0','::/0')]
                if value=='true':prefs['AdvertiseRoutes']+=['0.0.0.0/0','::/0']
            else:raise RuntimeError(key)
        save('ts-prefs',prefs)
    elif args[0]=='login':
        status=load('ts-status');status['BackendState']='NeedsLogin'
        status['AuthURL']='https://login.tailscale.com/a/network-test'
        save('ts-status',status)
        print('To authenticate, visit: '+status['AuthURL'],file=sys.stderr)
        sys.exit(1)
    elif args[0] in ('up','down','logout'):
        status=load('ts-status');status['BackendState']='Running' if args[0]=='up' else 'Stopped' if args[0]=='down' else 'NeedsLogin'
        if args[0]=='up' and (root/'up-state').exists():
            status['BackendState']=(root/'up-state').read_text()
        status['AuthURL']='';save('ts-status',status)
        if args[0]=='up' and status['BackendState']!='Running':sys.exit(1)
    elif args==['netcheck']:print('UDP: true\nIPv4: yes')
    else:raise RuntimeError(args)
elif name=='journalctl':
    print('PrivateKey='+base64.b64encode(bytes([2])*32).decode())
    print('auth=tskey-auth-testsecret')
    print('login=https://login.tailscale.com/a/not-for-logs')
    print('service message')
else:raise RuntimeError(name)
"#;

fn key(value: u8) -> String {
    STANDARD.encode([value; 32])
}
fn initial_config() -> String {
    format!("[Interface]\nAddress = 10.66.66.1/24\nPrivateKey = {}\nListenPort = 51820\nPostUp = keep-my-firewall-rule\n\n[Peer]\n# original comment\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 10.66.66.2/32\n",key(2),key(5),key(6))
}
struct Fixture {
    root: PathBuf,
    manager: Manager,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("af-network-{}", uuid::Uuid::new_v4()));
        let directory = root.join("wireguard");
        let bin = root.join("bin");
        fs::create_dir_all(&directory).unwrap();
        fs::create_dir_all(&bin).unwrap();
        for command in ["wg", "ip", "systemctl", "tailscale", "journalctl"] {
            let path = bin.join(command);
            fs::write(&path, MOCK).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(directory.join("wg0.conf"), initial_config()).unwrap();
        fs::write(
            root.join("runtime"),
            initial_config()
                .replace("Address = 10.66.66.1/24\n", "")
                .replace("PostUp = keep-my-firewall-rule\n", ""),
        )
        .unwrap();
        fs::write(
            root.join("dump"),
            format!(
                "{}\t{}\t51820\toff\n{}\t{}\t(none)\t10.66.66.2/32\t0\t100\t200\t25\n",
                key(2),
                key(4),
                key(5),
                key(6)
            ),
        )
        .unwrap();
        fs::write(root.join("wg-running"), "").unwrap();
        fs::write(root.join("ts-running"), "").unwrap();
        fs::write(root.join("ts-status"),json!({"BackendState":"Running",
            "CurrentTailnet":{"Name":"example.test","MagicDNSEnabled":true},
            "Self":{"ID":"self","HostName":"server","TailscaleIPs":["100.64.0.1"],"Online":true},
            "Peer":{"peer":{"ID":"peer","HostName":"laptop","Online":true,"ExitNodeOption":true,"TailscaleIPs":["100.64.0.2"],"RxBytes":4,"TxBytes":8}}}).to_string()).unwrap();
        fs::write(
            root.join("ts-prefs"),
            json!({"AdvertiseRoutes":["192.168.1.0/24"],
            "RouteAll":false,"ExitNodeIP":"","ExitNodeAllowLANAccess":false,
            "Persist":{"PrivateNodeKey":"tskey-node-never-expose"}})
            .to_string(),
        )
        .unwrap();
        Self {
            root,
            manager: Manager {
                directory,
                bin: Some(bin),
            },
        }
    }
    fn req(&self, action: &str) -> NetworkRunnerRequest {
        NetworkRunnerRequest {
            action: action.into(),
            public_key: key(7),
            ..Default::default()
        }
    }
    fn mark(&self, flag: &str) {
        fs::write(self.root.join(flag), "").unwrap();
    }
    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.root.join(name)).unwrap()
    }
    fn commands(&self) -> Vec<Value> {
        self.read("commands.jsonl")
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn cidrs_validate_family_bounds_and_normalize_host_bits() {
    assert_eq!(
        Cidr::parse("192.168.1.50/24").unwrap().normalized(),
        "192.168.1.0/24"
    );
    assert_eq!(
        Cidr::parse("2001:db8::45/64").unwrap().normalized(),
        "2001:db8::/64"
    );
    assert_eq!(Cidr::parse("10.0.0.1/0").unwrap().normalized(), "0.0.0.0/0");
    for bad in [
        "10.0.0.1/33",
        "::1/129",
        "10.0.0.1/-1",
        "example.com/24",
        "10.0.0.1/24\n--bad",
    ] {
        assert!(Cidr::parse(bad).is_err(), "{bad}");
    }
    assert!(!Cidr::parse("10.0.0.0/8")
        .unwrap()
        .overlaps(&Cidr::parse("::a00:1/128").unwrap()));
}

#[test]
fn allocator_uses_real_subnet_and_all_repeated_allowed_addresses() {
    let text = initial_config().replace(
        "AllowedIPs = 10.66.66.2/32",
        "AllowedIPs = 10.66.66.2/32\nAllowedIPs = 10.66.66.3/32",
    );
    let config = Config::parse(&text).unwrap();
    assert_eq!(config.next_ip().as_deref(), Some("10.66.66.4/32"));
    assert_eq!(
        Config::parse(&text.replace("/24", "/30"))
            .unwrap()
            .next_ip(),
        None
    );
}

#[test]
fn validation_rejects_collisions_server_addresses_injection_and_wrong_subnet() {
    let config = Config::parse(&initial_config()).unwrap();
    for address in [
        "10.0.0.2/32",
        "10.66.66.1/32",
        "10.66.66.2/32",
        "10.66.66.0/32",
        "10.66.66.255/32",
        "10.66.66.3/24",
        "10.66.66.3/32,10.66.66.3/32",
    ] {
        let req = NetworkRunnerRequest {
            public_key: key(7),
            allowed_ips: address.into(),
            ..Default::default()
        };
        assert!(
            build_peer(&config, &req, &Options::default(), false).is_err(),
            "{address}"
        );
    }
    for endpoint in [
        "--help",
        "host:0",
        "host:65536",
        "host;command:22",
        "host:22\nbad",
    ] {
        assert!(validate_endpoint(endpoint).is_err(), "{endpoint}");
    }
    for endpoint in [
        "host.example:51820",
        "192.0.2.5:51820",
        "[2001:db8::1]:51820",
        "",
    ] {
        assert!(validate_endpoint(endpoint).is_ok(), "{endpoint}");
    }
    let req = NetworkRunnerRequest {
        public_key: key(7),
        ..Default::default()
    };
    assert!(build_peer(
        &config,
        &req,
        &Options {
            name: "name\nPrivateKey = bad".into(),
            ..Default::default()
        },
        false
    )
    .is_err());
    assert!(!valid_key(&key(0)));
    assert!(!valid_key(&"a".repeat(44)));
}

#[tokio::test]
async fn health_requires_real_up_link_and_filters_all_private_data() {
    let f = Fixture::new();
    f.mark("link-down");
    let status = f.manager.execute(&f.req("network_status")).await.unwrap();
    assert_eq!(status["wireguard_available"], true);
    assert_eq!(status["wireguard"]["state"], "stopped");
    assert_eq!(status["wireguard"]["peers"][0]["active"], false);
    assert!(!status.to_string().contains(&key(2)));
    assert!(!status.to_string().contains(&key(6)));
    assert!(!status.to_string().contains("tskey-node-never-expose"));
    assert_eq!(status["tailscale"]["magic_dns"], true);
    assert_eq!(status["tailscale"]["peers"][0]["exit_node_option"], true);
    assert_eq!(
        status["tailscale"]["advertised_routes"],
        json!(["192.168.1.0/24"])
    );
}

#[tokio::test]
async fn stopped_daemon_and_invalid_server_config_have_distinct_states() {
    let f = Fixture::new();
    fs::remove_file(f.root.join("ts-running")).unwrap();
    let status = f.manager.tailscale_status().await;
    assert_eq!(status["state"], "stopped");
    assert_eq!(status["backend_state"], "Stopped");
    assert!(status.get("error").is_none());
    fs::write(
        f.manager.config_path(),
        initial_config().replace("Address = 10.66.66.1/24", "Address = 10.66.66.1/99"),
    )
    .unwrap();
    let status = f.manager.wireguard_status().await;
    assert_eq!(status["state"], "error");
    assert!(!status["error"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn added_and_removed_peers_survive_reload_and_restart() {
    let f = Fixture::new();
    let mut req = f.req("wg_add_peer");
    req.options = json!({"name":"Phone"});
    let added = f.manager.execute(&req).await.unwrap();
    assert_eq!(added["peer"]["allowed_ips"], "10.66.66.3/32");
    assert_eq!(added["peer"]["name"], "Phone");
    let persisted = f.manager.read_config().unwrap();
    assert_eq!(persisted.peers.len(), 2);
    assert!(persisted.header.contains("PostUp = keep-my-firewall-rule"));
    assert!(f.read("runtime").contains(&key(7)));
    assert_eq!(
        fs::metadata(f.manager.config_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut remove = f.req("wg_remove_peer");
    remove.public_key = key(5);
    f.manager.execute(&remove).await.unwrap();
    // A service restart consumes only the saved configuration.
    let saved = fs::read_to_string(f.manager.config_path()).unwrap();
    fs::write(f.root.join("runtime"), saved).unwrap();
    let after = f.manager.read_config().unwrap();
    assert_eq!(after.peers.len(), 1);
    assert_eq!(after.peers[0].key(), key(7));
    assert!(!f.read("runtime").contains(&key(5)));
    assert!(!entry_is_temp_name(&f.manager.directory));
}

fn entry_is_temp_name(directory: &Path) -> bool {
    fs::read_dir(directory).unwrap().any(|entry| {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        name.starts_with(".aetherflow-") && name.ends_with(".conf")
    })
}

#[tokio::test]
async fn updates_keep_preshared_keys_and_other_runtime_peers() {
    let f = Fixture::new();
    let extra = format!(
        "\n[Peer]\nPublicKey = {}\nAllowedIPs = 10.66.66.9/32\n",
        key(9)
    );
    fs::write(
        f.root.join("runtime"),
        format!("{}{extra}", f.read("runtime")),
    )
    .unwrap();
    let req = NetworkRunnerRequest {
        action: "wg_update_peer".into(),
        public_key: key(5),
        allowed_ips: "10.66.66.2/32".into(),
        options: json!({"name":"Renamed","persistent_keepalive":0}),
        ..Default::default()
    };
    f.manager.execute(&req).await.unwrap();
    let config = f.manager.read_config().unwrap();
    assert!(config.peers[0]
        .raw
        .contains(&format!("PresharedKey = {}", key(6))));
    assert!(config.peers[0].raw.contains("# original comment"));
    assert_eq!(config.peers[0].name, "Renamed");
    assert!(f.read("runtime").contains(&key(9)));
}

#[tokio::test]
async fn allocation_reserves_live_only_peers_and_edit_can_make_them_persistent() {
    let f = Fixture::new();
    let extra = format!(
        "\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 10.66.66.3/32\n",
        key(9),
        key(10)
    );
    fs::write(
        f.root.join("runtime"),
        format!("{}{extra}", f.read("runtime")),
    )
    .unwrap();
    let added = f.manager.execute(&f.req("wg_add_peer")).await.unwrap();
    assert_eq!(added["peer"]["allowed_ips"], "10.66.66.4/32");
    assert!(f.read("runtime").contains(&key(9)));
    let req = NetworkRunnerRequest {
        action: "wg_update_peer".into(),
        public_key: key(9),
        allowed_ips: "10.66.66.3/32".into(),
        options: json!({"name":"Adopted legacy client"}),
        ..Default::default()
    };
    f.manager.execute(&req).await.unwrap();
    let persisted = f.manager.read_config().unwrap();
    let adopted = persisted
        .peers
        .iter()
        .find(|peer| peer.key() == key(9))
        .unwrap();
    assert_eq!(adopted.name, "Adopted legacy client");
    assert!(adopted.raw.contains(&key(10)));
}

#[tokio::test]
async fn simultaneous_enrollments_get_distinct_persistent_addresses() {
    let f = Fixture::new();
    let first = f.req("wg_add_peer");
    let mut second = f.req("wg_add_peer");
    second.public_key = key(8);
    let (first, second) = tokio::join!(f.manager.execute(&first), f.manager.execute(&second));
    let first = first.unwrap();
    let second = second.unwrap();
    assert_ne!(first["peer"]["allowed_ips"], second["peer"]["allowed_ips"]);
    assert_eq!(f.manager.read_config().unwrap().peers.len(), 3);
}

#[tokio::test]
async fn partial_runtime_failure_rolls_back_and_keeps_persistent_state() {
    let f = Fixture::new();
    let before = f.read("runtime");
    let saved = fs::read_to_string(f.manager.config_path()).unwrap();
    f.mark("fail-sync");
    let error = f.manager.execute(&f.req("wg_add_peer")).await.unwrap_err();
    assert!(error
        .to_string()
        .contains("persistent configuration was preserved"));
    assert_eq!(f.read("runtime"), before);
    assert_eq!(fs::read_to_string(f.manager.config_path()).unwrap(), saved);
    assert!(!entry_is_temp_name(&f.manager.directory));
}

#[tokio::test]
async fn duplicate_keys_and_file_locks_fail_without_side_effects() {
    let f = Fixture::new();
    let mut req = f.req("wg_add_peer");
    req.public_key = key(5);
    assert!(f
        .manager
        .execute(&req)
        .await
        .unwrap_err()
        .to_string()
        .contains("CONFLICT"));
    let _lock = f.manager.file_lock().unwrap();
    let error = f.manager.execute(&f.req("wg_add_peer")).await.unwrap_err();
    assert!(error.to_string().contains("busy"));
    assert_eq!(f.manager.read_config().unwrap().peers.len(), 1);
}

#[tokio::test]
async fn stopped_interface_can_be_configured_without_false_live_success() {
    let f = Fixture::new();
    fs::remove_file(f.root.join("wg-running")).unwrap();
    let result = f.manager.execute(&f.req("wg_add_peer")).await.unwrap();
    assert!(result["message"].as_str().unwrap().contains("start wg0"));
    assert_eq!(f.manager.read_config().unwrap().peers.len(), 2);
    assert!(!f
        .commands()
        .iter()
        .any(|args| args[0] == "wg" && args[1] == "syncconf"));
}

#[tokio::test]
async fn symlinks_and_saveconfig_cannot_redirect_or_overwrite_configuration() {
    let f = Fixture::new();
    let outside = f.root.join("outside");
    fs::rename(f.manager.config_path(), &outside).unwrap();
    std::os::unix::fs::symlink(&outside, f.manager.config_path()).unwrap();
    assert!(f.manager.execute(&f.req("wg_add_peer")).await.is_err());
    assert_eq!(fs::read_to_string(&outside).unwrap(), initial_config());
    fs::remove_file(f.manager.config_path()).unwrap();
    fs::write(
        f.manager.config_path(),
        initial_config().replace("[Interface]", "[Interface]\nSaveConfig = true"),
    )
    .unwrap();
    assert!(f
        .manager
        .execute(&f.req("wg_add_peer"))
        .await
        .unwrap_err()
        .to_string()
        .contains("SaveConfig"));
}

#[tokio::test]
async fn clear_routes_preserves_exit_node_and_unrelated_preferences() {
    let f = Fixture::new();
    let mut prefs: Value = serde_json::from_str(&f.read("ts-prefs")).unwrap();
    prefs["AdvertiseRoutes"] = json!(["0.0.0.0/0", "::/0", "192.168.1.0/24"]);
    prefs["RouteAll"] = json!(true);
    fs::write(f.root.join("ts-prefs"), prefs.to_string()).unwrap();
    f.manager
        .execute(&f.req("tailscale_set_routes"))
        .await
        .unwrap();
    let after: Value = serde_json::from_str(&f.read("ts-prefs")).unwrap();
    assert_eq!(after["AdvertiseRoutes"], json!(["0.0.0.0/0", "::/0"]));
    assert_eq!(after["RouteAll"], true);
    let mut req = f.req("tailscale_set_routes");
    req.routes = vec!["192.168.4.17/24".into(), "2001:db8::12/64".into()];
    let response = f.manager.execute(&req).await.unwrap();
    assert_eq!(
        response["routes"],
        json!(["192.168.4.0/24", "2001:db8::/64"])
    );
}

#[tokio::test]
async fn tailscale_rejects_invalid_routes_and_exit_nodes_before_mutating() {
    let f = Fixture::new();
    for route in ["0.0.0.0/0", "192.168.1.0/33", "--bad", "::/129"] {
        let mut req = f.req("tailscale_set_routes");
        req.routes = vec![route.into()];
        assert!(f.manager.execute(&req).await.is_err());
    }
    let mut req = f.req("tailscale_settings");
    req.options = json!({"exit_node":"192.0.2.1"});
    assert!(f.manager.execute(&req).await.is_err());
    req.options = json!({"exit_node":"100.64.0.2","accept_routes":true});
    f.manager.execute(&req).await.unwrap();
    req.options = json!({"exit_node":""});
    f.manager.execute(&req).await.unwrap();
    let prefs: Value = serde_json::from_str(&f.read("ts-prefs")).unwrap();
    assert_eq!(prefs["ExitNodeIP"], "");
    assert_eq!(prefs["ExitNodeAllowLANAccess"], false);
    assert_eq!(prefs["RouteAll"], true);
}

#[tokio::test]
async fn tailscale_login_returns_valid_url_without_claiming_connected() {
    let f = Fixture::new();
    let mut status: Value = serde_json::from_str(&f.read("ts-status")).unwrap();
    status["BackendState"] = json!("NeedsLogin");
    fs::write(f.root.join("ts-status"), status.to_string()).unwrap();
    let response = f
        .manager
        .execute(&f.req("tailscale_connect"))
        .await
        .unwrap();
    assert_eq!(response["backend_state"], "NeedsLogin");
    assert_eq!(
        response["auth_url"],
        "https://login.tailscale.com/a/network-test"
    );
    for bad in [
        "javascript:alert(1)",
        "http://login.tailscale.com/a/a",
        "https://login.tailscale.com.evil.test/a/a",
        "https://user@login.tailscale.com/a/a",
    ] {
        assert!(!valid_auth_url(bad), "{bad}");
    }
    assert!(valid_auth_url("https://login.tailscale.com/a/example"));
}

#[tokio::test]
async fn stopped_reconnect_verifies_running_approval_and_expired_login_states() {
    for expected in ["Running", "NeedsMachineAuth", "NeedsLogin", "Stopped"] {
        let f = Fixture::new();
        let mut raw: Value = serde_json::from_str(&f.read("ts-status")).unwrap();
        raw["BackendState"] = json!("Stopped");
        fs::write(f.root.join("ts-status"), raw.to_string()).unwrap();
        fs::write(f.root.join("up-state"), expected).unwrap();
        let result = f.manager.execute(&f.req("tailscale_connect")).await;
        if expected == "Stopped" {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("did not reach Running"));
            continue;
        }
        let response = result.unwrap();
        assert_eq!(response["backend_state"], expected);
        assert_eq!(response.get("auth_url").is_some(), expected == "NeedsLogin");
    }
}

#[tokio::test]
async fn service_errors_and_cli_failures_are_not_successes() {
    let f = Fixture::new();
    f.mark("service-failure");
    let mut req = f.req("network_service");
    req.subsystem = "wireguard".into();
    req.options = json!({"service_action":"restart"});
    assert!(f.manager.execute(&req).await.is_err());
    req.options = json!({"service_action":"enable;whoami"});
    assert!(f.manager.execute(&req).await.is_err());
    f.mark("set-failure");
    assert!(f
        .manager
        .execute(&f.req("tailscale_set_routes"))
        .await
        .unwrap_err()
        .to_string()
        .contains("Access denied"));
    f.mark("keygen-failure");
    assert!(f.manager.execute(&f.req("wg_keygen")).await.is_err());
}

#[tokio::test]
async fn keygen_errors_logs_and_oversized_outputs_do_not_expose_secrets() {
    let f = Fixture::new();
    f.mark("pubkey-failure");
    let error = f
        .manager
        .execute(&f.req("wg_keygen"))
        .await
        .unwrap_err()
        .to_string();
    assert!(!error.contains(&key(3)));
    let mut req = f.req("network_diagnostics");
    req.subsystem = "wireguard".into();
    let logs = f.manager.execute(&req).await.unwrap()["logs"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(!logs.contains(&key(2)));
    assert!(!logs.contains("tskey-auth"));
    assert!(!logs.contains("/a/"));
    assert!(logs.contains("service message"));
    f.mark("too-much-output");
    assert!(f
        .manager
        .execute(&f.req("wg_keygen"))
        .await
        .unwrap_err()
        .to_string()
        .contains("size limit"));
}

#[tokio::test]
async fn command_timeout_kills_the_child_and_returns_actionable_failure() {
    let f = Fixture::new();
    f.mark("hang");
    let start = std::time::Instant::now();
    let error = f
        .manager
        .execute(&f.req("wg_keygen"))
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("timed out"));
    assert!(start.elapsed() < Duration::from_secs(12));
}
