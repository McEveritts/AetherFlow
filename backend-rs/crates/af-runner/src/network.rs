//! Privileged VPN operations. Paths and executable arguments are selected here,
//! never supplied by the web control plane.
use af_models::NetworkRunnerRequest;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Mutex;

const INTERFACE: &str = "wg0";
const MAX_BYTES: usize = 1024 * 1024;
const MAX_PEERS: usize = 1024;
#[cfg(test)]
mod tests;
static WG_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
static TS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

async fn mutation_lock(lock: &Mutex<()>) -> Result<tokio::sync::MutexGuard<'_, ()>> {
    tokio::time::timeout(Duration::from_secs(3), lock.lock())
        .await
        .context("VPN configuration is busy; retry shortly")
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Options {
    #[serde(default)]
    name: String,
    persistent_keepalive: Option<u16>,
    #[serde(default)]
    reauth: bool,
    accept_routes: Option<bool>,
    advertise_exit_node: Option<bool>,
    exit_node: Option<String>,
    exit_node_allow_lan_access: Option<bool>,
    #[serde(default)]
    service_action: String,
}

pub fn is_allowed_action(action: &str) -> bool {
    matches!(
        action,
        "network_status"
            | "wg_show"
            | "wg_keygen"
            | "wg_add_peer"
            | "wg_update_peer"
            | "wg_remove_peer"
            | "tailscale_connect"
            | "tailscale_disconnect"
            | "tailscale_logout"
            | "tailscale_set_routes"
            | "tailscale_settings"
            | "network_service"
            | "network_diagnostics"
    )
}

struct Manager {
    directory: PathBuf,
    // Only tests construct a manager with a different executable directory.
    bin: Option<PathBuf>,
}

impl Default for Manager {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("/etc/wireguard"),
            bin: None,
        }
    }
}

struct Output {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

async fn limited_read<R: AsyncRead + Unpin>(reader: R) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_BYTES {
        bail!("Network command output exceeded its size limit");
    }
    Ok(bytes)
}

impl Manager {
    fn program(&self, name: &str) -> PathBuf {
        self.bin
            .as_ref()
            .map_or_else(|| PathBuf::from(name), |bin| bin.join(name))
    }

    async fn output(&self, program: &str, args: &[String], input: Option<&str>) -> Result<Output> {
        let mut child = Command::new(self.program(program))
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("{program} is unavailable; install it from Marketplace"))?;
        let stdout = child.stdout.take().context("Missing command stdout")?;
        let stderr = child.stderr.take().context("Missing command stderr")?;
        let stdin = child.stdin.take();
        let task = async {
            let write_input = async {
                if let (Some(mut pipe), Some(input)) = (stdin, input) {
                    pipe.write_all(input.as_bytes()).await?;
                    pipe.shutdown().await?;
                }
                Ok::<_, anyhow::Error>(())
            };
            let (out, err, _) =
                tokio::try_join!(limited_read(stdout), limited_read(stderr), write_input)?;
            let status = child.wait().await?;
            Ok::<_, anyhow::Error>(Output {
                status,
                stdout: String::from_utf8_lossy(&out).into_owned(),
                stderr: String::from_utf8_lossy(&err).into_owned(),
            })
        };
        match tokio::time::timeout(Duration::from_secs(8), task).await {
            Ok(result) => {
                if result.is_err() {
                    let _ = child.kill().await;
                }
                result
            }
            Err(_) => {
                let _ = child.kill().await;
                bail!("{program} timed out; inspect the VPN service logs")
            }
        }
    }

    async fn run(&self, program: &str, args: &[String], input: Option<&str>) -> Result<String> {
        let out = self.output(program, args, input).await?;
        if !out.status.success() {
            // Key-generation failures must not echo private key material.
            let detail = if program == "wg"
                && args.first().is_some_and(|a| a == "pubkey" || a == "genkey")
            {
                String::new()
            } else {
                redact(&out.stderr).chars().take(1000).collect()
            };
            bail!("{program} failed ({}). {}", out.status, detail.trim());
        }
        Ok(out.stdout)
    }

    async fn installed(&self, program: &str) -> bool {
        self.output(program, &strings(&["--version"]), None)
            .await
            .is_ok_and(|out| out.status.success())
    }

    async fn service_state(&self, provider: &str) -> String {
        let unit = service_unit(provider);
        match self
            .output("systemctl", &strings(&["is-active", unit]), None)
            .await
        {
            Ok(out) if !out.stdout.trim().is_empty() => out.stdout.trim().to_string(),
            _ => "unknown".to_string(),
        }
    }

    fn config_path(&self) -> PathBuf {
        self.directory.join("wg0.conf")
    }

    fn read_config(&self) -> Result<Config> {
        let config = Config::parse(&read_secret(&self.config_path())?)?;
        config.validate_server()?;
        Ok(config)
    }

    fn file_lock(&self) -> Result<ConfigurationLock> {
        let metadata = fs::symlink_metadata(&self.directory)
            .context("WireGuard is not configured; install it from Marketplace")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("WireGuard configuration directory must be a real directory");
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.directory.join(".aetherflow-network.lock"))?;
        lock.try_lock()
            .context("WireGuard configuration is busy; retry shortly")?;
        Ok(ConfigurationLock(lock))
    }

    fn secret_file(&self, contents: &str) -> Result<TemporaryFile> {
        let path = self
            .directory
            .join(format!(".aetherflow-{}.conf", uuid::Uuid::new_v4()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        let temporary = TemporaryFile(path);
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        Ok(temporary)
    }

    fn replace_config(&self, contents: &str) -> Result<()> {
        let temporary = self.secret_file(contents)?;
        fs::rename(&temporary.0, self.config_path())?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}
fn service_unit(provider: &str) -> &'static str {
    if provider == "wireguard" {
        "wg-quick@wg0.service"
    } else {
        "tailscaled.service"
    }
}

fn read_secret(path: &Path) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .context("WireGuard configuration is missing or unreadable; inspect its service logs")?;
    if !file.metadata()?.is_file() {
        bail!("WireGuard configuration is not a regular file");
    }
    let mut contents = String::new();
    file.take((MAX_BYTES + 1) as u64)
        .read_to_string(&mut contents)?;
    if contents.len() > MAX_BYTES {
        bail!("WireGuard configuration is too large");
    }
    Ok(contents)
}

struct TemporaryFile(PathBuf);
impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

struct ConfigurationLock(File);
impl Drop for ConfigurationLock {
    fn drop(&mut self) {
        // Release explicitly: concurrent fork/exec can briefly inherit an open
        // descriptor even with CLOEXEC, extending a close-only flock lifetime.
        let _ = self.0.unlock();
    }
}

fn redact(text: &str) -> String {
    static SECRETS: Lazy<regex::Regex> = Lazy::new(|| {
        regex::Regex::new(r"tskey-[A-Za-z0-9_-]+|[A-Za-z0-9+/]{43}=|https://[^\s]+/a/[^\s]+")
            .expect("constant network redaction expression")
    });
    SECRETS.replace_all(text, "[redacted]").into_owned()
}

fn valid_key(key: &str) -> bool {
    key.len() == 44
        && STANDARD
            .decode(key)
            .is_ok_and(|bytes| bytes.len() == 32 && bytes.iter().any(|b| *b != 0))
}

#[derive(Clone, Debug)]
struct Cidr {
    ip: IpAddr,
    prefix: u8,
}
impl Cidr {
    fn parse(raw: &str) -> Result<Self> {
        let (ip, prefix) = raw
            .trim()
            .split_once('/')
            .context("Invalid CIDR: use address/prefix")?;
        let ip: IpAddr = ip.parse().context("Invalid CIDR IP address")?;
        let prefix: u8 = prefix.parse().context("Invalid CIDR prefix")?;
        if prefix > if ip.is_ipv4() { 32 } else { 128 } {
            bail!("CIDR prefix is out of range");
        }
        Ok(Self { ip, prefix })
    }
    fn bits(&self) -> u128 {
        match self.ip {
            IpAddr::V4(ip) => u32::from(ip) as u128,
            IpAddr::V6(ip) => u128::from(ip),
        }
    }
    fn mask(&self) -> u128 {
        let width = if self.ip.is_ipv4() { 32 } else { 128 };
        if self.prefix == 0 {
            0
        } else {
            u128::MAX << (width - self.prefix)
        }
    }
    fn contains(&self, other: &Self) -> bool {
        self.ip.is_ipv4() == other.ip.is_ipv4()
            && self.bits() & self.mask() == other.bits() & self.mask()
    }
    fn overlaps(&self, other: &Self) -> bool {
        self.contains(other) || other.contains(self)
    }
    fn normalized(&self) -> String {
        let bits = self.bits() & self.mask();
        let ip = if self.ip.is_ipv4() {
            IpAddr::V4(Ipv4Addr::from(bits as u32))
        } else {
            IpAddr::V6(bits.into())
        };
        format!("{ip}/{}", self.prefix)
    }
}

fn cidrs(raw: &str) -> Result<Vec<Cidr>> {
    let values: Vec<_> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if values.len() > 32 {
        bail!("Too many addresses");
    }
    values.into_iter().map(Cidr::parse).collect()
}

#[derive(Clone, Debug)]
struct Peer {
    raw: String,
    fields: HashMap<String, String>,
    name: String,
}
impl Peer {
    fn parse(raw: String) -> Self {
        let fields = fields(&raw);
        let name = raw
            .lines()
            .find_map(|line| {
                line.trim()
                    .strip_prefix("# AetherFlow-Name:")
                    .map(|name| name.trim().to_string())
            })
            .unwrap_or_default();
        Self { raw, fields, name }
    }
    fn key(&self) -> &str {
        self.fields
            .get("publickey")
            .map(String::as_str)
            .unwrap_or("")
    }
    fn json(&self) -> Value {
        json!({"name":self.name,"public_key":self.key(),"persistent":true,
            "allowed_ips":self.fields.get("allowedips").cloned().unwrap_or_default(),
            "endpoint":self.fields.get("endpoint").cloned().unwrap_or_default(),
            "persistent_keepalive":self.fields.get("persistentkeepalive").and_then(|s|s.parse::<u16>().ok()).unwrap_or(0),
            "latest_handshake":"0","transfer_rx":"0","transfer_tx":"0","active":false})
    }
}

fn fields(raw: &str) -> HashMap<String, String> {
    let mut values: HashMap<String, String> = HashMap::new();
    for line in raw.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        if matches!(key.as_str(), "address" | "allowedips") {
            values
                .entry(key)
                .and_modify(|old| {
                    old.push_str(", ");
                    old.push_str(value.trim());
                })
                .or_insert_with(|| value.trim().to_string());
        } else {
            values.insert(key, value.trim().to_string());
        }
    }
    values
}

#[derive(Clone, Debug)]
struct Config {
    header: String,
    peers: Vec<Peer>,
}
impl Config {
    fn reserve_runtime_peers(&mut self, peers: &[Peer]) {
        for peer in peers {
            if let Some(existing) = self.peers.iter_mut().find(|p| p.key() == peer.key()) {
                if let Some(addresses) = peer.fields.get("allowedips") {
                    existing
                        .fields
                        .entry("allowedips".into())
                        .and_modify(|saved| {
                            saved.push_str(", ");
                            saved.push_str(addresses);
                        })
                        .or_insert_with(|| addresses.clone());
                }
            } else {
                self.peers.push(peer.clone());
            }
        }
    }
    fn validate_server(&self) -> Result<()> {
        if self.addresses()?.is_empty() {
            bail!("WireGuard Interface Address is required");
        }
        let values = fields(&self.header);
        if !values.get("privatekey").is_some_and(|key| valid_key(key)) {
            bail!("Invalid WireGuard server private key; repair wg0.conf without changing its identity");
        }
        if values
            .get("listenport")
            .is_some_and(|port| port.parse::<u16>().is_err())
        {
            bail!("Invalid WireGuard listen port");
        }
        Ok(())
    }
    fn parse(raw: &str) -> Result<Self> {
        if raw.len() > MAX_BYTES {
            bail!("WireGuard configuration is too large");
        }
        let mut header = String::new();
        let mut peers: Vec<Peer> = Vec::new();
        let mut current = String::new();
        let mut in_peer = false;
        let mut interface = false;
        for line in raw.lines() {
            let section = line.split('#').next().unwrap_or("").trim();
            if section.starts_with('[') {
                if section.eq_ignore_ascii_case("[Peer]") {
                    if in_peer {
                        peers.push(Peer::parse(std::mem::take(&mut current)));
                    } else {
                        header = std::mem::take(&mut current);
                    }
                    in_peer = true;
                } else if section.eq_ignore_ascii_case("[Interface]") && !interface && !in_peer {
                    interface = true;
                } else {
                    bail!("Unsupported or duplicate WireGuard section");
                }
            }
            current.push_str(line);
            current.push('\n');
        }
        if in_peer {
            peers.push(Peer::parse(current));
        } else {
            header = current;
        }
        if !interface {
            bail!("WireGuard configuration has no Interface section");
        }
        if peers.len() > MAX_PEERS {
            bail!("Too many WireGuard peers");
        }
        let keys: std::collections::HashSet<_> = peers.iter().map(Peer::key).collect();
        if keys.len() != peers.len() || peers.iter().any(|p| !valid_key(p.key())) {
            bail!("WireGuard configuration has invalid or duplicate peer keys");
        }
        if fields(&header)
            .get("saveconfig")
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
        {
            bail!("Disable SaveConfig=true before managing persistent peers in AetherFlow");
        }
        Ok(Self { header, peers })
    }
    fn render(&self) -> String {
        let mut text = self.header.trim_end().to_string();
        text.push('\n');
        for peer in &self.peers {
            text.push('\n');
            text.push_str(peer.raw.trim_end());
            text.push('\n');
        }
        text
    }
    fn addresses(&self) -> Result<Vec<Cidr>> {
        cidrs(
            fields(&self.header)
                .get("address")
                .map(String::as_str)
                .unwrap_or(""),
        )
    }
    fn next_ip(&self) -> Option<String> {
        let addresses = self.addresses().ok()?;
        let subnet = addresses.iter().find(|n| n.ip.is_ipv4() && n.prefix < 31)?;
        let start = (subnet.bits() & subnet.mask()) as u32;
        let broadcast = start | !(subnet.mask() as u32);
        let occupied: Vec<_> = self
            .peers
            .iter()
            .flat_map(|p| {
                cidrs(p.fields.get("allowedips").map(String::as_str).unwrap_or(""))
                    .unwrap_or_default()
            })
            .collect();
        for offset in 1..=65536u32 {
            let Some(candidate) = start.checked_add(offset) else {
                break;
            };
            if candidate >= broadcast {
                break;
            }
            let net = Cidr {
                ip: Ipv4Addr::from(candidate).into(),
                prefix: 32,
            };
            if addresses.iter().any(|a| a.ip == net.ip) || occupied.iter().any(|a| a.contains(&net))
            {
                continue;
            }
            return Some(format!("{}/32", net.ip));
        }
        None
    }
}

fn validate_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.is_empty() {
        return Ok(());
    }
    if endpoint.len() > 260 || endpoint.chars().any(char::is_control) {
        bail!("Invalid endpoint");
    }
    if let Ok(address) = endpoint.parse::<SocketAddr>() {
        if address.port() == 0 {
            bail!("Endpoint port must be between 1 and 65535");
        }
        return Ok(());
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .context("Endpoint must be host:port")?;
    if port.parse::<u16>().ok().is_none_or(|p| p == 0)
        || host.is_empty()
        || host.len() > 253
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
    {
        bail!("Endpoint must be a valid hostname or IP and port");
    }
    Ok(())
}

fn build_peer(
    config: &Config,
    req: &NetworkRunnerRequest,
    options: &Options,
    editing: bool,
) -> Result<Peer> {
    if !valid_key(&req.public_key) {
        bail!("Invalid WireGuard public key; expected 32 bytes of base64");
    }
    if options.name.len() > 80 || options.name.chars().any(char::is_control) {
        bail!("Peer name must be at most 80 bytes with no control characters");
    }
    validate_endpoint(&req.endpoint)?;
    let existing = config
        .peers
        .iter()
        .find(|peer| peer.key() == req.public_key);
    if editing && existing.is_none() {
        bail!("NOT_FOUND: WireGuard peer does not exist");
    }
    if !editing && existing.is_some() {
        bail!("CONFLICT: WireGuard peer already exists");
    }
    if !editing && config.peers.len() >= MAX_PEERS {
        bail!("Peer limit reached");
    }
    let assigned = if req.allowed_ips.trim().is_empty() && !editing {
        config
            .next_ip()
            .context("No unused client addresses in the configured IPv4 subnet")?
    } else {
        req.allowed_ips.trim().to_string()
    };
    let allowed = cidrs(&assigned)?;
    if allowed.is_empty() {
        bail!("Client addresses are required");
    }
    let server = config.addresses()?;
    for (index, address) in allowed.iter().enumerate() {
        if address.prefix != if address.ip.is_ipv4() { 32 } else { 128 }
            || !server.iter().any(|s| s.contains(address))
            || server.iter().any(|s| s.ip == address.ip)
            || allowed[..index].iter().any(|a| a.overlaps(address))
        {
            bail!("Client addresses must be unique host addresses in the configured VPN subnet");
        }
        if address.ip.is_ipv4()
            && server.iter().filter(|s| s.ip.is_ipv4()).any(|s| {
                s.prefix < 31
                    && (address.bits() == s.bits() & s.mask()
                        || address.bits()
                            == ((s.bits() & s.mask()) as u32 | !(s.mask() as u32)) as u128)
            })
        {
            bail!("Network and broadcast addresses cannot be assigned to clients");
        }
        for peer in config
            .peers
            .iter()
            .filter(|peer| peer.key() != req.public_key)
        {
            if cidrs(
                peer.fields
                    .get("allowedips")
                    .map(String::as_str)
                    .unwrap_or(""),
            )?
            .iter()
            .any(|used| used.overlaps(address))
            {
                bail!("CONFLICT: Client address overlaps an existing peer");
            }
        }
    }
    let mut raw = format!(
        "[Peer]\n# AetherFlow-Name: {}\nPublicKey = {}\nAllowedIPs = {}\n",
        options.name.trim(),
        req.public_key,
        allowed
            .iter()
            .map(|n| format!("{}/{}", n.ip, n.prefix))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if !req.endpoint.is_empty() {
        raw.push_str(&format!("Endpoint = {}\n", req.endpoint));
    }
    let keepalive = options.persistent_keepalive.unwrap_or_else(|| {
        existing
            .and_then(|p| p.fields.get("persistentkeepalive"))
            .and_then(|s| s.parse().ok())
            .unwrap_or(25)
    });
    raw.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
    if let Some(peer) = existing {
        // Preserve pre-shared keys and administrator comments/settings.
        for line in peer.raw.lines().skip(1) {
            if line.trim().starts_with("# AetherFlow-Name:") {
                continue;
            }
            let key = line
                .split_once('=')
                .map(|(key, _)| key.trim().to_ascii_lowercase());
            if key.as_deref().is_some_and(|key| {
                matches!(
                    key,
                    "publickey" | "allowedips" | "endpoint" | "persistentkeepalive"
                )
            }) {
                continue;
            }
            raw.push_str(line);
            raw.push('\n');
        }
    }
    Ok(Peer::parse(raw))
}

fn parse_dump(raw: &str, config: Option<&Config>) -> Result<Value> {
    let mut lines = raw.lines();
    let interface: Vec<_> = lines
        .next()
        .context("WireGuard returned no interface data")?
        .split('\t')
        .collect();
    if interface.len() != 4 {
        bail!("Invalid WireGuard interface response");
    }
    let mut peers: Vec<Value> = config
        .map(|c| c.peers.iter().map(Peer::json).collect())
        .unwrap_or_default();
    for line in lines {
        let row: Vec<_> = line.split('\t').collect();
        if row.len() != 8 {
            bail!("Invalid WireGuard peer response");
        }
        let handshake = row[4].parse::<i64>().unwrap_or(0);
        let now = chrono::Utc::now().timestamp();
        let active = handshake > 0 && handshake <= now && now - handshake <= 180;
        let mut peer = peers
            .iter()
            .find(|p| p["public_key"] == row[0])
            .cloned()
            .unwrap_or_else(|| json!({"name":"","public_key":row[0],"persistent":false}));
        peer["endpoint"] = json!(if row[2] == "(none)" { "" } else { row[2] });
        peer["allowed_ips"] = json!(row[3]);
        peer["latest_handshake"] = json!(row[4]);
        peer["transfer_rx"] = json!(row[5]);
        peer["transfer_tx"] = json!(row[6]);
        peer["persistent_keepalive"] = json!(row[7].parse::<u16>().unwrap_or(0));
        peer["active"] = json!(active);
        if let Some(index) = peers.iter().position(|p| p["public_key"] == row[0]) {
            peers[index] = peer;
        } else {
            peers.push(peer);
        }
    }
    Ok(json!({"public_key":interface[1],"listen_port":interface[2],"peers":peers}))
}

impl Manager {
    async fn wireguard_status(&self) -> Value {
        let installed = self.installed("wg").await;
        let service = self.service_state("wireguard").await;
        let mut status = json!({"installed":installed,"state":"not_installed","interface":INTERFACE,
            "public_key":"","listen_port":"","address":[],"peers":[],"service_state":service,
            "config_available":false});
        if !installed {
            return status;
        }
        let exists = self.config_path().exists();
        let config = if exists {
            match self.read_config() {
                Ok(config) => Some(config),
                Err(error) => {
                    status["state"] = json!("error");
                    status["error"] = json!(redact(&error.to_string()));
                    return status;
                }
            }
        } else {
            None
        };
        status["config_available"] = json!(config.is_some());
        status["state"] = json!(if config.is_some() {
            "stopped"
        } else {
            "unconfigured"
        });
        if let Some(config) = &config {
            let values = fields(&config.header);
            status["address"] = json!(config
                .addresses()
                .unwrap_or_default()
                .iter()
                .map(|n| format!("{}/{}", n.ip, n.prefix))
                .collect::<Vec<_>>());
            status["listen_port"] = json!(values.get("listenport").cloned().unwrap_or_default());
            status["next_ip"] = json!(config.next_ip());
            status["peers"] = json!(config.peers.iter().map(Peer::json).collect::<Vec<_>>());
            if let Some(private) = values.get("privatekey").filter(|key| valid_key(key)) {
                match self.run("wg", &strings(&["pubkey"]), Some(private)).await {
                    Ok(public) if valid_key(public.trim()) => {
                        status["public_key"] = json!(public.trim())
                    }
                    _ => {
                        status["state"] = json!("error");
                        status["error"] =
                            json!("Could not derive the configured WireGuard server public key");
                        return status;
                    }
                }
            }
        }
        match self
            .output("wg", &strings(&["show", INTERFACE, "dump"]), None)
            .await
        {
            Ok(out) if out.status.success() => match parse_dump(&out.stdout, config.as_ref()) {
                Ok(live) => {
                    if let Some(saved) = &config {
                        if status["public_key"] != live["public_key"] {
                            status["state"] = json!("error");
                            status["error"]=json!("Live WireGuard server identity differs from wg0.conf; reconcile it before onboarding clients");
                            return status;
                        }
                        let mut reserved = saved.clone();
                        let peers = live["peers"]
                            .as_array()
                            .map(|peers| {
                                peers
                                    .iter()
                                    .map(|peer| {
                                        Peer::parse(format!(
                                            "[Peer]\nPublicKey = {}\nAllowedIPs = {}\n",
                                            peer["public_key"].as_str().unwrap_or(""),
                                            peer["allowed_ips"].as_str().unwrap_or("")
                                        ))
                                    })
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default();
                        reserved.reserve_runtime_peers(&peers);
                        status["next_ip"] = json!(reserved.next_ip());
                    }
                    for field in ["public_key", "listen_port", "peers"] {
                        status[field] = live[field].clone();
                    }
                    match self
                        .run(
                            "ip",
                            &strings(&["-j", "link", "show", "dev", INTERFACE]),
                            None,
                        )
                        .await
                        .and_then(|raw| Ok(serde_json::from_str::<Value>(&raw)?))
                    {
                        Ok(link) => {
                            let up = link
                                .as_array()
                                .and_then(|rows| rows.first())
                                .and_then(|row| row["flags"].as_array())
                                .is_some_and(|flags| flags.iter().any(|flag| flag == "UP"));
                            status["state"] = json!(if up { "running" } else { "stopped" });
                        }
                        Err(error) => {
                            status["state"] = json!("error");
                            status["error"] = json!(redact(&error.to_string()));
                        }
                    }
                }
                Err(error) => {
                    status["state"] = json!("error");
                    status["error"] = json!(error.to_string());
                }
            },
            Ok(out) if service == "active" || service == "failed" => {
                status["state"] = json!("error");
                status["error"] = json!(format!(
                    "wg0 status failed; service is {service}. {}",
                    redact(out.stderr.trim())
                ));
            }
            Err(error) => {
                status["state"] = json!("error");
                status["error"] = json!(redact(&error.to_string()));
            }
            _ => {}
        }
        status
    }

    async fn change_peer(&self, req: &NetworkRunnerRequest, options: &Options) -> Result<Value> {
        let _guard = mutation_lock(&WG_LOCK).await?;
        let _lock = self.file_lock()?;
        let old_text = read_secret(&self.config_path())?;
        let mut config = Config::parse(&old_text)?;
        config.validate_server()?;
        let service = self.service_state("wireguard").await;
        let live = self
            .output("wg", &strings(&["showconf", INTERFACE]), None)
            .await?;
        let old_runtime = if live.status.success() {
            Some(live.stdout)
        } else if service == "active" {
            bail!("Cannot read live WireGuard configuration; no changes were saved");
        } else {
            None
        };
        let mut reserved = config.clone();
        if let Some(runtime) = &old_runtime {
            let live_config = Config::parse(runtime)?;
            reserved.reserve_runtime_peers(&live_config.peers);
            let saved_key = fields(&config.header)
                .get("privatekey")
                .cloned()
                .unwrap_or_default();
            let live_key = fields(&live_config.header)
                .get("privatekey")
                .cloned()
                .unwrap_or_default();
            if saved_key != live_key {
                let saved_public = self
                    .run("wg", &strings(&["pubkey"]), Some(&saved_key))
                    .await?;
                let live_public = self
                    .run("wg", &strings(&["pubkey"]), Some(&live_key))
                    .await?;
                if saved_public.trim() != live_public.trim() {
                    bail!("Invalid server identity: live wg0 and saved configuration differ; reconcile them before changing peers");
                }
            }
        }
        let removing = req.action == "wg_remove_peer";
        let peer = if removing {
            if !valid_key(&req.public_key) {
                bail!("Invalid WireGuard public key");
            }
            if !reserved.peers.iter().any(|p| p.key() == req.public_key) {
                bail!("NOT_FOUND: WireGuard peer does not exist");
            }
            None
        } else {
            Some(build_peer(
                &reserved,
                req,
                options,
                req.action == "wg_update_peer",
            )?)
        };
        config.peers.retain(|p| p.key() != req.public_key);
        if let Some(peer) = &peer {
            config.peers.push(peer.clone());
        }

        let original = if let Some(runtime) = &old_runtime {
            Some(self.secret_file(runtime)?)
        } else {
            None
        };
        if let Some(runtime) = &old_runtime {
            let mut current = Config::parse(runtime)?;
            current.peers.retain(|p| p.key() != req.public_key);
            if let Some(peer) = &peer {
                current.peers.push(peer.clone());
            }
            let staged = self.secret_file(&current.render())?;
            if let Err(error) = self
                .run(
                    "wg",
                    &strings(&["syncconf", INTERFACE, &staged.0.to_string_lossy()]),
                    None,
                )
                .await
            {
                let rollback = self
                    .run(
                        "wg",
                        &strings(&[
                            "syncconf",
                            INTERFACE,
                            &original
                                .as_ref()
                                .expect("runtime backup")
                                .0
                                .to_string_lossy(),
                        ]),
                        None,
                    )
                    .await;
                if rollback.is_err() {
                    bail!("WireGuard update failed and runtime rollback failed; inspect the service. {error}");
                }
                return Err(error
                    .context("WireGuard update failed; persistent configuration was preserved"));
            }
        }
        if let Err(error) = self.replace_config(&config.render()) {
            let disk_restore = self.replace_config(&old_text);
            let runtime_restore = if let Some(original) = &original {
                self.run(
                    "wg",
                    &strings(&["syncconf", INTERFACE, &original.0.to_string_lossy()]),
                    None,
                )
                .await
            } else {
                Ok(String::new())
            };
            if disk_restore.is_err() || runtime_restore.is_err() {
                bail!("WireGuard save failed and recovery was incomplete; inspect wg0 before retrying");
            }
            return Err(error.context("WireGuard save failed; previous state was restored"));
        }
        Ok(
            json!({"message":if old_runtime.is_some() {"WireGuard peer saved"} else {"WireGuard peer saved; start wg0 to activate it"},
            "peer":peer.as_ref().map(Peer::json)}),
        )
    }

    async fn keygen(&self) -> Result<Value> {
        let private = self
            .run("wg", &strings(&["genkey"]), None)
            .await?
            .trim()
            .to_string();
        if !valid_key(&private) {
            bail!("WireGuard returned an invalid private key");
        }
        let public = self
            .run("wg", &strings(&["pubkey"]), Some(&private))
            .await?
            .trim()
            .to_string();
        if !valid_key(&public) {
            bail!("WireGuard returned an invalid public key");
        }
        Ok(json!({"private_key":private,"public_key":public}))
    }

    async fn tailscale_raw(&self) -> Result<Value> {
        let raw = self
            .run("tailscale", &strings(&["status", "--json"]), None)
            .await?;
        let status: Value =
            serde_json::from_str(&raw).context("Invalid Tailscale status response")?;
        if !status.is_object() {
            bail!("Invalid Tailscale status response");
        }
        Ok(status)
    }

    async fn tailscale_status(&self) -> Value {
        let installed = self.installed("tailscale").await;
        let service = self.service_state("tailscale").await;
        let mut status = json!({"installed":installed,"state":"not_installed","backend_state":"Unknown",
            "self":null,"peers":[],"magic_dns":false,"health":[],"advertised_routes":[],
            "accept_routes":false,"advertise_exit_node":false,"exit_node":"",
            "exit_node_allow_lan_access":false,"route_approval":"managed_in_admin_console","service_state":service});
        if !installed {
            return status;
        }
        let raw = match self.tailscale_raw().await {
            Ok(raw) => raw,
            Err(error) => {
                if matches!(service.as_str(), "inactive" | "deactivating") {
                    status["state"] = json!("stopped");
                    status["backend_state"] = json!("Stopped");
                    status["health"] =
                        json!(["Start tailscaled to read preferences and connect this node"]);
                } else {
                    status["state"] = json!("error");
                    status["error"] = json!(redact(&error.to_string()));
                }
                return status;
            }
        };
        let backend = raw["BackendState"].as_str().unwrap_or("Unknown");
        status["backend_state"] = json!(backend);
        status["state"] = json!(match backend {
            "Running" => "running",
            "NeedsLogin" | "NoState" => "needs_login",
            "NeedsMachineAuth" => "needs_approval",
            "Stopped" => "stopped",
            _ => "error",
        });
        if status["state"] == "error" {
            status["error"] = json!(format!(
                "Tailscale reported an unsupported or starting backend state: {backend}"
            ));
        }
        if raw["Self"].is_object() {
            status["self"] = tailscale_peer("self", &raw["Self"]);
        }
        status["peers"] = json!(raw["Peer"]
            .as_object()
            .map(|peers| peers
                .iter()
                .map(|(id, peer)| tailscale_peer(id, peer))
                .collect::<Vec<_>>())
            .unwrap_or_default());
        status["health"] = json!(raw["Health"]
            .as_array()
            .map(|health| health
                .iter()
                .filter_map(Value::as_str)
                .map(redact)
                .collect::<Vec<_>>())
            .unwrap_or_default());
        status["magic_dns"] = json!(raw["CurrentTailnet"]["MagicDNSEnabled"]
            .as_bool()
            .unwrap_or_else(|| raw["MagicDNSSuffix"]
                .as_str()
                .is_some_and(|s| !s.is_empty())));
        status["tailnet_name"] = raw["CurrentTailnet"]["Name"].clone();
        if let Some(url) = raw["AuthURL"].as_str().filter(|url| valid_auth_url(url)) {
            status["auth_url"] = json!(url);
        }
        let prefs = self
            .run("tailscale", &strings(&["debug", "prefs"]), None)
            .await
            .and_then(|text| Ok(serde_json::from_str::<Value>(&text)?));
        match prefs {
            Ok(prefs) if prefs.is_object() => {
                let routes = prefs["AdvertiseRoutes"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                status["advertise_exit_node"] = json!(
                    routes.iter().any(|r| r == "0.0.0.0/0") && routes.iter().any(|r| r == "::/0")
                );
                status["advertised_routes"] = json!(routes
                    .into_iter()
                    .filter(|r| r != "0.0.0.0/0" && r != "::/0")
                    .collect::<Vec<_>>());
                status["accept_routes"] = json!(prefs["RouteAll"].as_bool().unwrap_or(false));
                status["exit_node_allow_lan_access"] =
                    json!(prefs["ExitNodeAllowLANAccess"].as_bool().unwrap_or(false));
                let selected = prefs["ExitNodeIP"]
                    .as_str()
                    .filter(|ip| *ip != "0.0.0.0" && *ip != "::")
                    .unwrap_or("");
                let fallback = status["peers"]
                    .as_array()
                    .and_then(|peers| peers.iter().find(|p| p["exit_node"] == true))
                    .and_then(|peer| peer["tailscale_ip"].as_str())
                    .unwrap_or("");
                status["exit_node"] = json!(if selected.is_empty() {
                    fallback
                } else {
                    selected
                });
            }
            _ => {
                status["state"] = json!("error");
                status["error"]=json!("Tailscale preferences are unavailable; inspect tailscaled and runner permissions");
            }
        }
        status
    }

    async fn tailscale_connect(&self, options: &Options) -> Result<Value> {
        let _guard = mutation_lock(&TS_LOCK).await?;
        let raw = self.tailscale_raw().await?;
        if raw["BackendState"] == "Running" && !options.reauth {
            return Ok(json!({"message":"Tailscale is connected","backend_state":"Running"}));
        }
        if raw["BackendState"] == "NeedsMachineAuth" && !options.reauth {
            return Ok(
                json!({"message":"Approve this device in the Tailscale admin console",
                "backend_state":"NeedsMachineAuth"}),
            );
        }
        if raw["BackendState"] == "Stopped" && !options.reauth {
            // An existing login is resumed without resetting unrelated preferences.
            let up = self
                .output("tailscale", &strings(&["up", "--timeout=3s"]), None)
                .await?;
            let after = self.tailscale_raw().await?;
            if after["BackendState"] == "Running" && up.status.success() {
                return Ok(json!({"message":"Tailscale connected","backend_state":"Running"}));
            }
            if after["BackendState"] == "NeedsMachineAuth" {
                return Ok(
                    json!({"message":"Approve this device in the Tailscale admin console",
                    "backend_state":"NeedsMachineAuth"}),
                );
            }
            if !matches!(after["BackendState"].as_str(), Some("NeedsLogin" | "NoState")) {
                bail!(
                    "Tailscale up did not reach Running state ({}). {}",
                    after["BackendState"].as_str().unwrap_or("Unknown"),
                    redact(&up.stderr)
                );
            }
        }
        let mut args = strings(&["login", "--timeout=3s"]);
        if options.reauth {
            args.push("--force-reauth".to_string());
        }
        let output = self.output("tailscale", &args, None).await?;
        let after = self.tailscale_raw().await?;
        let url = after["AuthURL"]
            .as_str()
            .filter(|url| valid_auth_url(url))
            .map(str::to_string)
            .or_else(|| {
                output
                    .stdout
                    .split_whitespace()
                    .chain(output.stderr.split_whitespace())
                    .find(|url| valid_auth_url(url))
                    .map(str::to_string)
            });
        if let Some(url) = url {
            return Ok(
                json!({"message":"Open the login link to authorize this node","auth_url":url,
                "backend_state":after["BackendState"]}),
            );
        }
        if after["BackendState"] == "Running" && output.status.success() {
            return Ok(json!({"message":"Tailscale connected","backend_state":"Running"}));
        }
        bail!(
            "Tailscale login did not provide an authorization URL. {}",
            redact(&output.stderr)
        );
    }

    async fn tailscale_routes(&self, routes: &[String]) -> Result<Value> {
        let _guard = mutation_lock(&TS_LOCK).await?;
        if routes.len() > 64 {
            bail!("At most 64 subnet routes may be advertised");
        }
        let mut normalized = Vec::new();
        for raw in routes {
            let cidr = Cidr::parse(raw)?;
            if cidr.prefix == 0 {
                bail!("Use the advertise-exit-node setting for default routes");
            }
            let route = cidr.normalized();
            if !normalized.contains(&route) {
                normalized.push(route);
            }
        }
        self.run(
            "tailscale",
            &vec![
                "set".into(),
                format!("--advertise-routes={}", normalized.join(",")),
            ],
            None,
        )
        .await?;
        Ok(
            json!({"message":"Subnet routes saved; approval is managed in the Tailscale admin console","routes":normalized}),
        )
    }

    async fn tailscale_settings(&self, options: &Options) -> Result<Value> {
        let _guard = mutation_lock(&TS_LOCK).await?;
        let mut args = strings(&["set"]);
        if let Some(value) = options.accept_routes {
            args.push(format!("--accept-routes={value}"));
        }
        if let Some(value) = options.advertise_exit_node {
            args.push(format!("--advertise-exit-node={value}"));
        }
        if let Some(value) = &options.exit_node {
            if !value.is_empty() {
                let ip: IpAddr = value
                    .parse()
                    .context("Exit node must be a Tailscale IP address")?;
                let raw = self.tailscale_raw().await?;
                if !raw["Peer"].as_object().is_some_and(|peers| {
                    peers.values().any(|peer| {
                        peer["ExitNodeOption"] == true
                            && peer["Online"] == true
                            && peer["TailscaleIPs"].as_array().is_some_and(|ips| {
                                ips.iter().any(|v| {
                                    v.as_str().and_then(|s| s.parse::<IpAddr>().ok()) == Some(ip)
                                })
                            })
                    })
                }) {
                    bail!("Exit node must be an online device offering exit-node service");
                }
            }
            args.push(format!("--exit-node={value}"));
            if value.is_empty() {
                args.push("--exit-node-allow-lan-access=false".into());
            }
        }
        if let Some(value) = options.exit_node_allow_lan_access {
            if options.exit_node.as_deref() == Some("") && value {
                bail!("Select an exit node before allowing LAN access");
            }
            if options.exit_node.as_deref() != Some("") {
                args.push(format!("--exit-node-allow-lan-access={value}"));
            }
        }
        if args.len() == 1 {
            bail!("No Tailscale settings were supplied");
        }
        self.run("tailscale", &args, None).await?;
        Ok(json!({"message":"Tailscale settings saved"}))
    }

    async fn service(&self, provider: &str, action: &str) -> Result<Value> {
        if !matches!(provider, "wireguard" | "tailscale")
            || !matches!(action, "start" | "stop" | "restart")
        {
            bail!("Invalid VPN service or action");
        }
        let _guard = if provider == "wireguard" {
            mutation_lock(&WG_LOCK).await?
        } else {
            mutation_lock(&TS_LOCK).await?
        };
        self.run(
            "systemctl",
            &strings(&[action, service_unit(provider)]),
            None,
        )
        .await?;
        let actual = self.service_state(provider).await;
        if action != "stop" && actual != "active" {
            bail!("VPN service did not become active: {actual}");
        }
        if action == "stop" && actual == "active" {
            bail!("VPN service is still active");
        }
        Ok(
            json!({"message":format!("{provider} service {action} completed"),"service_state":actual}),
        )
    }

    async fn diagnostics(&self, provider: &str) -> Result<Value> {
        if !matches!(provider, "wireguard" | "tailscale") {
            bail!("Invalid VPN provider");
        }
        let service = self.service_state(provider).await;
        let logs = self
            .run(
                "journalctl",
                &strings(&[
                    "--no-pager",
                    "--lines=80",
                    "--output=short-iso",
                    "--unit",
                    service_unit(provider),
                ]),
                None,
            )
            .await?;
        let mut checks = vec![json!({"name":"Service","detail":service,"ok":service=="active"})];
        for (path, name) in [
            ("/proc/sys/net/ipv4/ip_forward", "IPv4 forwarding"),
            ("/proc/sys/net/ipv6/conf/all/forwarding", "IPv6 forwarding"),
        ] {
            if let Ok(value) = fs::read_to_string(path) {
                checks.push(json!({"name":name,"detail":value.trim(),"ok":value.trim()=="1"}));
            }
        }
        if provider == "wireguard" {
            checks.push(json!({"name":"UDP reachability","detail":"Allow the configured WireGuard UDP port through the host and upstream firewall; peer handshakes verify connectivity."}));
        } else {
            let check = self
                .run("tailscale", &strings(&["netcheck"]), None)
                .await
                .unwrap_or_else(|error| format!("Connectivity check unavailable: {error}"));
            checks.push(json!({"name":"Tailscale connectivity","detail":redact(&check)}));
        }
        Ok(json!({"provider":provider,"service_state":service,
            "logs":redact(&logs).chars().take(32000).collect::<String>(),"checks":checks}))
    }

    async fn execute(&self, req: &NetworkRunnerRequest) -> Result<Value> {
        if !req.args.is_empty() {
            bail!("Arbitrary network command arguments are not accepted");
        }
        let options: Options = if req.options.is_null() {
            Options::default()
        } else {
            serde_json::from_value(req.options.clone()).context("Invalid network options")?
        };
        match req.action.as_str() {
            "network_status" => {
                let (wg, ts) = tokio::join!(self.wireguard_status(), self.tailscale_status());
                Ok(
                    json!({"platform":std::env::consts::OS,"runner_available":true,
                    "checked_at":chrono::Utc::now().to_rfc3339(),"wireguard_available":wg["installed"],
                    "tailscale_available":ts["installed"],"wireguard":wg,"tailscale":ts}),
                )
            }
            "wg_keygen" => self.keygen().await,
            "wg_add_peer" | "wg_update_peer" | "wg_remove_peer" => {
                self.change_peer(req, &options).await
            }
            "tailscale_connect" => self.tailscale_connect(&options).await,
            "tailscale_set_routes" => self.tailscale_routes(&req.routes).await,
            "tailscale_settings" => self.tailscale_settings(&options).await,
            "tailscale_disconnect" | "tailscale_logout" => {
                let _guard = mutation_lock(&TS_LOCK).await?;
                let command = if req.action == "tailscale_logout" {
                    "logout"
                } else {
                    "down"
                };
                self.run("tailscale", &strings(&[command]), None).await?;
                Ok(json!({"message":format!("Tailscale {command} completed")}))
            }
            "network_service" => self.service(&req.subsystem, &options.service_action).await,
            "network_diagnostics" => self.diagnostics(&req.subsystem).await,
            _ => bail!("Unsupported network action"),
        }
    }
}

fn valid_auth_url(url: &str) -> bool {
    reqwest::Url::parse(url).ok().is_some_and(|parsed| {
        parsed.scheme() == "https"
            && parsed.host_str() == Some("login.tailscale.com")
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.port().is_none_or(|port| port == 443)
            && parsed.path().starts_with("/a/")
            && parsed.path().len() > 3
    })
}

fn tailscale_peer(id: &str, peer: &Value) -> Value {
    let ips = peer["TailscaleIPs"].as_array().cloned().unwrap_or_default();
    json!({"id":peer["ID"].as_str().unwrap_or(id),"hostname":peer["HostName"].as_str().unwrap_or(""),
        "dns_name":peer["DNSName"].as_str().unwrap_or(""),"tailscale_ip":ips.first().cloned().unwrap_or(json!("")),
        "tailscale_ips":ips,"os":peer["OS"].as_str().unwrap_or(""),"online":peer["Online"].as_bool().unwrap_or(false),
        "exit_node":peer["ExitNode"].as_bool().unwrap_or(false),"exit_node_option":peer["ExitNodeOption"].as_bool().unwrap_or(false),
        "rx_bytes":peer["RxBytes"].as_u64().unwrap_or(0),"tx_bytes":peer["TxBytes"].as_u64().unwrap_or(0),
        "last_seen":peer["LastSeen"].clone(),"tags":peer["Tags"].as_array().cloned().unwrap_or_default()})
}

pub async fn execute(req: &NetworkRunnerRequest) -> Result<String> {
    let manager = Manager::default();
    if req.action == "wg_show" {
        let output = manager
            .run("wg", &strings(&["show", "all", "dump"]), None)
            .await?;
        let sanitized = output
            .lines()
            .map(|line| {
                let mut columns: Vec<_> = line.split('\t').collect();
                if columns.len() == 5 {
                    columns[1] = "(redacted)";
                }
                if columns.len() == 9 {
                    columns[2] = "(redacted)";
                }
                columns.join("\t")
            })
            .collect::<Vec<_>>()
            .join("\n");
        return Ok(sanitized);
    }
    Ok(serde_json::to_string(&manager.execute(req).await?)?)
}
