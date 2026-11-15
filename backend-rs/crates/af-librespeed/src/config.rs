use anyhow::{anyhow, bail, Context, Result};
use std::env;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/opt/librespeed/settings.toml";
pub const VERSION_STRING: &str = concat!(
    "speedtest-backend ",
    env!("AF_LIBRESPEED_EFFECTIVE_VERSION")
);
pub const DEFAULT_MAX_TELEMETRY_ROWS: usize = 100_000;
pub const DEFAULT_IPINFO_BASE_URL: &str = "https://ipinfo.io";
pub const MAX_CONFIG_AND_PEM_BYTES: usize = 1024 * 1024;

/// Opens `path` with `O_NOFOLLOW | O_CLOEXEC`, verifies via `fstat` that the
/// descriptor is a regular non-world-writable file, and reads at most `max_bytes`.
pub fn read_regular_file_nofollow(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>> {
    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() || ancestor == Path::new("/") {
            break;
        }
        match std::fs::symlink_metadata(ancestor) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    bail!(
                        "refusing symlinked ancestor directory for {label}: {}",
                        ancestor.display()
                    );
                }
                if !meta.is_dir() {
                    bail!(
                        "ancestor path is not a directory for {label}: {}",
                        ancestor.display()
                    );
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "failed to inspect ancestor directory for {label}: {}",
                        ancestor.display()
                    )
                });
            }
        }
    }

    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => f,
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            bail!("refusing symlinked {label}: {}", path.display());
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "{label} does not exist or cannot be read: {}",
                    path.display()
                )
            });
        }
    };

    let meta = file
        .metadata()
        .with_context(|| format!("failed to fstat {label}: {}", path.display()))?;
    if !meta.is_file() {
        bail!("{label} is not a regular file: {}", path.display());
    }
    let mode = meta.permissions().mode();
    if (mode & 0o002) != 0 {
        bail!(
            "refusing world-writable {label} (mode {:04o}): {}",
            mode & 0o7777,
            path.display()
        );
    }

    let cap = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut buf = Vec::with_capacity(usize::try_from(meta.len().min(4096)).unwrap_or(1024));
    file.take(cap)
        .read_to_end(&mut buf)
        .with_context(|| format!("failed reading {label}: {}", path.display()))?;
    if buf.len() > max_bytes {
        bail!(
            "{label} exceeds maximum allowed size of {max_bytes} bytes: {}",
            path.display()
        );
    }
    Ok(buf)
}

#[derive(Clone, PartialEq)]
pub struct Config {
    pub bind_address: String,
    pub listen_port: u16,
    pub url_base: String,
    pub assets_path: PathBuf,
    pub statistics_password: String,
    pub redact_ip_addresses: bool,
    pub database_type: String,
    pub database_file: PathBuf,
    pub enable_id_obfuscation: bool,
    pub enable_tls: bool,
    pub tls_cert_file: PathBuf,
    pub tls_key_file: PathBuf,
    pub trusted_proxies: Vec<IpAddr>,
    pub trusted_proxy_secret: String,
    pub max_telemetry_rows: usize,
    pub server_lat: f64,
    pub server_lng: f64,
    pub ipinfo_api_key: String,
    pub ipinfo_base_url: String,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("bind_address", &self.bind_address)
            .field("listen_port", &self.listen_port)
            .field("url_base", &self.url_base)
            .field("assets_path", &self.assets_path)
            .field(
                "statistics_password",
                &if self.stats_locked() {
                    "[LOCKED]"
                } else {
                    "[REDACTED]"
                },
            )
            .field("redact_ip_addresses", &self.redact_ip_addresses)
            .field("database_type", &self.database_type)
            .field("database_file", &self.database_file)
            .field("enable_id_obfuscation", &self.enable_id_obfuscation)
            .field("enable_tls", &self.enable_tls)
            .field("tls_cert_file", &self.tls_cert_file)
            .field("tls_key_file", &self.tls_key_file)
            .field("trusted_proxies", &self.trusted_proxies)
            .field(
                "trusted_proxy_secret",
                &if self.trusted_proxy_secret.is_empty() {
                    ""
                } else {
                    "[REDACTED]"
                },
            )
            .field("max_telemetry_rows", &self.max_telemetry_rows)
            .field("server_lat", &self.server_lat)
            .field("server_lng", &self.server_lng)
            .field(
                "ipinfo_api_key",
                &if self.ipinfo_api_key.is_empty() {
                    ""
                } else {
                    "[REDACTED]"
                },
            )
            .field("ipinfo_base_url", &self.ipinfo_base_url)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind_address: "127.0.0.1".to_string(),
            listen_port: 8988,
            url_base: String::new(),
            assets_path: PathBuf::from("/opt/librespeed/assets"),
            statistics_password: "PASSWORD".to_string(),
            redact_ip_addresses: false,
            database_type: "sqlite".to_string(),
            database_file: PathBuf::from("/opt/librespeed/speedtest.db"),
            enable_id_obfuscation: false,
            enable_tls: false,
            tls_cert_file: PathBuf::new(),
            tls_key_file: PathBuf::new(),
            trusted_proxies: Vec::new(),
            trusted_proxy_secret: String::new(),
            max_telemetry_rows: DEFAULT_MAX_TELEMETRY_ROWS,
            server_lat: 0.0,
            server_lng: 0.0,
            ipinfo_api_key: String::new(),
            ipinfo_base_url: DEFAULT_IPINFO_BASE_URL.to_string(),
        }
    }
}

impl Config {
    /// Returns true unless `database_type` is `"none"` (case-insensitive) or
    /// Returns true unless telemetry storage is explicitly disabled (`"none"`) or
    /// `database_file` is empty (except for `"memory"`, which runs an in-memory SQLite vault).
    /// Legacy values like `"bolt"` or `""` resolve to SQLite at `database_file`.
    pub fn telemetry_enabled(&self) -> bool {
        let db_type = self.database_type.trim();
        if db_type.eq_ignore_ascii_case("none") {
            return false;
        }
        if db_type.eq_ignore_ascii_case("memory") {
            return true;
        }
        !self.database_file.as_os_str().is_empty()
    }

    pub fn stats_locked(&self) -> bool {
        let trimmed = self.statistics_password.trim();
        trimmed.is_empty() || trimmed == "PASSWORD"
    }

    pub fn validate_listener_security(&self) -> Result<()> {
        validate_url_base(&self.url_base)?;
        let db_type = self.database_type.trim().to_ascii_lowercase();
        match db_type.as_str() {
            "" | "none" | "sqlite" | "bolt" | "memory" => {}
            other => bail!(
                "unsupported database_type {other:?} in settings.toml; speedtest-backend supports only \"sqlite\", \"memory\", or \"none\" to disable telemetry"
            ),
        }
        if !matches!(db_type.as_str(), "" | "none" | "memory")
            && self.database_file.as_os_str().is_empty()
        {
            bail!(
                "database_file must be non-empty in settings.toml when database_type = {db_type:?}"
            );
        }
        if self.enable_tls
            && (self.tls_cert_file.as_os_str().is_empty()
                || self.tls_key_file.as_os_str().is_empty())
        {
            bail!(
                "enable_tls=true requires non-empty tls_cert_file and tls_key_file in settings.toml"
            );
        }
        if self.max_telemetry_rows == 0 {
            bail!("max_telemetry_rows must be greater than 0");
        }
        if !self.server_lat.is_finite() || !(-90.0..=90.0).contains(&self.server_lat) {
            bail!("server_lat must be a finite latitude between -90.0 and 90.0");
        }
        if !self.server_lng.is_finite() || !(-180.0..=180.0).contains(&self.server_lng) {
            bail!("server_lng must be a finite longitude between -180.0 and 180.0");
        }
        if crate::routes::build_safe_ipinfo_lookup_url(
            &self.ipinfo_base_url,
            IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)),
        )
        .is_none()
        {
            bail!(
                "invalid or untrusted ipinfo_base_url {:?}: only https://ipinfo.io or loopback http://127.0.0.1:<port> / http://[::1]:<port> are permitted",
                self.ipinfo_base_url
            );
        }
        Ok(())
    }

    pub fn socket_addr(&self) -> Result<SocketAddr> {
        let raw = self.bind_address.trim();
        let unbracketed = raw
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(raw);
        let addr_str = if unbracketed.is_empty() {
            "0.0.0.0"
        } else {
            unbracketed
        };
        let ip: IpAddr = addr_str
            .parse()
            .with_context(|| format!("invalid bind_address {:?}", self.bind_address))?;
        Ok(SocketAddr::new(ip, self.listen_port))
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let bytes = read_regular_file_nofollow(path, MAX_CONFIG_AND_PEM_BYTES, "settings.toml")?;
        let content = String::from_utf8(bytes)
            .with_context(|| format!("settings.toml is not valid UTF-8 at {}", path.display()))?;
        Self::parse_toml_str(&content)
            .with_context(|| format!("failed to parse settings.toml at {}", path.display()))
    }

    pub fn parse_toml_str(input: &str) -> Result<Self> {
        let mut cfg = Self::default();
        let mut in_root_table = true;

        for (line_num, stmt) in iter_toml_statements(input)? {
            let trimmed = stmt.trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('[') && split_key_value(trimmed).is_none() {
                let header = trimmed;
                if !(header.ends_with(']') && header.len() >= 3) {
                    bail!("line {line_num}: invalid TOML table header {header:?}");
                }
                in_root_table = false;
                continue;
            }

            let Some((raw_key, raw_val)) = split_key_value(trimmed) else {
                bail!("line {line_num}: expected key = value assignment");
            };

            let key =
                parse_key(raw_key).with_context(|| format!("line {line_num}: invalid key"))?;
            let val = parse_value(raw_val.trim())
                .with_context(|| format!("line {line_num}: invalid value for key '{key}'"))?;

            if !in_root_table {
                continue;
            }

            match key.as_str() {
                "bind_address" => {
                    let s = val.into_string("bind_address")?;
                    let s_trimmed = s.trim();
                    cfg.bind_address = if s_trimmed.is_empty() {
                        "0.0.0.0".to_string()
                    } else {
                        s_trimmed.to_string()
                    };
                }
                "listen_port" => {
                    cfg.listen_port = val.into_port("listen_port")?;
                }
                "url_base" => {
                    let s = val.into_string("url_base")?;
                    cfg.url_base = normalize_url_base(&s);
                }
                "assets_path" => {
                    let s = val.into_string("assets_path")?;
                    if !s.trim().is_empty() {
                        cfg.assets_path = PathBuf::from(s);
                    }
                }
                "statistics_password" => {
                    cfg.statistics_password = val.into_string("statistics_password")?;
                }
                "redact_ip_addresses" => {
                    cfg.redact_ip_addresses = val.into_bool("redact_ip_addresses")?;
                }
                "database_type" => {
                    cfg.database_type = val.into_string("database_type")?;
                }
                "database_file" => {
                    cfg.database_file = PathBuf::from(val.into_string("database_file")?);
                }
                "enable_id_obfuscation" => {
                    cfg.enable_id_obfuscation = val.into_bool("enable_id_obfuscation")?;
                }
                "enable_tls" => {
                    cfg.enable_tls = val.into_bool("enable_tls")?;
                }
                "tls_cert_file" => {
                    let s = val.into_string("tls_cert_file")?;
                    cfg.tls_cert_file = PathBuf::from(s.trim());
                }
                "tls_key_file" => {
                    let s = val.into_string("tls_key_file")?;
                    cfg.tls_key_file = PathBuf::from(s.trim());
                }
                "proxyprotocol_port" => {
                    let port = val.into_port("proxyprotocol_port")?;
                    if port != 0 {
                        bail!(
                            "line {line_num}: proxyprotocol_port = {port} is not supported; set proxyprotocol_port = 0 and terminate PROXY protocol at your reverse proxy"
                        );
                    }
                }
                "trusted_proxies" => {
                    cfg.trusted_proxies = val
                        .into_ip_list("trusted_proxies")
                        .with_context(|| format!("line {line_num}: invalid trusted_proxies"))?;
                }
                "trusted_proxy_secret" => {
                    cfg.trusted_proxy_secret =
                        val.into_string("trusted_proxy_secret")?.trim().to_string();
                }
                "max_telemetry_rows" => {
                    cfg.max_telemetry_rows = val.into_positive_usize("max_telemetry_rows")?;
                }
                "server_lat" => {
                    cfg.server_lat = val.into_f64("server_lat")?;
                }
                "server_lng" => {
                    cfg.server_lng = val.into_f64("server_lng")?;
                }
                "ipinfo_api_key" => {
                    cfg.ipinfo_api_key = val.into_string("ipinfo_api_key")?.trim().to_string();
                }
                "ipinfo_base_url" => {
                    let s = val.into_string("ipinfo_base_url")?;
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        cfg.ipinfo_base_url = trimmed.to_string();
                    }
                }
                _ => {
                    // Ignore non-security user-tuning TOML keys gracefully.
                }
            }
        }

        cfg.validate_listener_security()?;
        Ok(cfg)
    }
}

pub fn normalize_url_base(raw: &str) -> String {
    raw.trim().trim_matches('/').to_string()
}

pub fn validate_url_base(normalized: &str) -> Result<()> {
    if normalized.is_empty() {
        return Ok(());
    }
    if normalized.len() > 128 {
        bail!("url_base exceeds maximum length of 128 characters");
    }
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            bail!(
                "invalid url_base {normalized:?}: empty or dot-traversal path segments are not allowed"
            );
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~'))
        {
            bail!(
                "invalid url_base {normalized:?}: only URL-safe path segment characters [A-Za-z0-9._~/-] are permitted"
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliAction {
    Run { config_path: PathBuf },
    PrintVersion,
    PrintHelp,
}

pub fn parse_cli_args<I, S>(args: I) -> Result<CliAction>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut iter = args.into_iter().map(Into::into);
    let _program = iter.next();

    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "-v" | "--version" => return Ok(CliAction::PrintVersion),
            "-h" | "--help" => return Ok(CliAction::PrintHelp),
            "-c" | "--config" => {
                let path = iter
                    .next()
                    .ok_or_else(|| anyhow!("missing path argument after {arg}"))?;
                if path.trim().is_empty() {
                    bail!("empty path argument after {arg}");
                }
                config_path = PathBuf::from(path);
            }
            _ if arg.starts_with("--config=") => {
                let path = arg.trim_start_matches("--config=");
                if path.trim().is_empty() {
                    bail!("empty path argument in --config=");
                }
                config_path = PathBuf::from(path);
            }
            _ if arg.starts_with("-c=") => {
                let path = arg.trim_start_matches("-c=");
                if path.trim().is_empty() {
                    bail!("empty path argument in -c=");
                }
                config_path = PathBuf::from(path);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(CliAction::Run { config_path })
}

pub fn parse_env_cli() -> Result<CliAction> {
    parse_cli_args(env::args())
}

#[derive(Debug, Clone, PartialEq)]
enum TomlScalar {
    Str(String),
    Array(Vec<TomlScalar>),
    InlineTable,
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl TomlScalar {
    fn into_string(self, key: &str) -> Result<String> {
        match self {
            TomlScalar::Str(s) => Ok(s),
            other => bail!("{key} must be a string, got {other:?}"),
        }
    }

    fn into_bool(self, key: &str) -> Result<bool> {
        match self {
            TomlScalar::Bool(b) => Ok(b),
            TomlScalar::Str(s) => match s.trim().to_ascii_lowercase().as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => bail!("{key} must be a boolean, got string {s:?}"),
            },
            other => bail!("{key} must be a boolean, got {other:?}"),
        }
    }

    fn into_port(self, key: &str) -> Result<u16> {
        match self {
            TomlScalar::Int(n) => {
                u16::try_from(n).map_err(|_| anyhow!("{key} out of port range 0..=65535: {n}"))
            }
            TomlScalar::Float(f) if f.is_finite() && f.fract() == 0.0 => {
                let n = f as i64;
                u16::try_from(n).map_err(|_| anyhow!("{key} out of port range 0..=65535: {n}"))
            }
            TomlScalar::Str(s) => s
                .trim()
                .parse::<u16>()
                .map_err(|_| anyhow!("{key} invalid port string: {s:?}")),
            other => bail!("{key} must be an integer port, got {other:?}"),
        }
    }

    fn into_positive_usize(self, key: &str) -> Result<usize> {
        let parsed = match self {
            TomlScalar::Int(n) => usize::try_from(n)
                .map_err(|_| anyhow!("{key} must be a positive integer, got {n}"))?,
            TomlScalar::Str(s) => s
                .trim()
                .replace('_', "")
                .parse::<usize>()
                .map_err(|_| anyhow!("{key} invalid integer string: {s:?}"))?,
            other => bail!("{key} must be a positive integer, got {other:?}"),
        };
        if parsed == 0 {
            bail!("{key} must be greater than 0");
        }
        Ok(parsed)
    }

    fn into_f64(self, key: &str) -> Result<f64> {
        let parsed = match self {
            TomlScalar::Float(f) => f,
            TomlScalar::Int(n) => n as f64,
            TomlScalar::Str(s) => s
                .trim()
                .parse::<f64>()
                .map_err(|_| anyhow!("{key} invalid floating-point string: {s:?}"))?,
            other => bail!("{key} must be a number, got {other:?}"),
        };
        if !parsed.is_finite() {
            bail!("{key} must be a finite number");
        }
        Ok(parsed)
    }

    fn into_ip_list(self, key: &str) -> Result<Vec<IpAddr>> {
        let raw_items: Vec<String> = match self {
            TomlScalar::Str(s) => s
                .split(',')
                .map(str::trim)
                .filter(|tok| !tok.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            TomlScalar::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        TomlScalar::Str(s) => {
                            let t = s.trim();
                            if !t.is_empty() {
                                out.push(t.to_string());
                            }
                        }
                        other => {
                            bail!("expected string element in {key}, got {other:?}")
                        }
                    }
                }
                out
            }
            other => {
                bail!("{key} must be a comma-separated IP string or string array, got {other:?}")
            }
        };

        let mut ips = Vec::with_capacity(raw_items.len());
        for tok in raw_items {
            let ip = crate::redact::parse_ip_token(&tok)
                .ok_or_else(|| anyhow!("invalid IP address {tok:?} in {key}"))?;
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        Ok(ips)
    }
}

/// Scans `input` into logical TOML statements `(start_line_number, cleaned_statement)`,
/// stripping unquoted `#` comments and joining multiline `[ ... ]`, `{ ... }`,
/// `""" ... """`, and `''' ... '''` literals cleanly.
fn iter_toml_statements(input: &str) -> Result<Vec<(usize, String)>> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum QuoteState {
        None,
        Single,
        Double,
        TripleSingle,
        TripleDouble,
    }

    let mut out: Vec<(usize, String)> = Vec::new();
    let mut cur = String::new();
    let mut cur_start_line: usize = 1;
    let mut line_num: usize = 1;
    let mut quote = QuoteState::None;
    let mut bracket_depth: usize = 0;
    let mut brace_depth: usize = 0;

    let bytes = input.as_bytes();
    let mut i: usize = 0;
    while i < bytes.len() {
        let ch = input[i..].chars().next().expect("valid utf8 slice");
        let ch_len = ch.len_utf8();

        if cur.trim().is_empty() && ch != '\n' && ch != '\r' {
            cur_start_line = line_num;
        }

        match quote {
            QuoteState::None => {
                if ch == '#' {
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                if input[i..].starts_with("\"\"\"") {
                    quote = QuoteState::TripleDouble;
                    cur.push_str("\"\"\"");
                    i += 3;
                    continue;
                }
                if input[i..].starts_with("'''") {
                    quote = QuoteState::TripleSingle;
                    cur.push_str("'''");
                    i += 3;
                    continue;
                }
                match ch {
                    '"' => {
                        quote = QuoteState::Double;
                        cur.push(ch);
                    }
                    '\'' => {
                        quote = QuoteState::Single;
                        cur.push(ch);
                    }
                    '[' => {
                        bracket_depth += 1;
                        cur.push(ch);
                    }
                    ']' => {
                        if bracket_depth == 0 {
                            bail!("line {line_num}: unmatched closing ']'");
                        }
                        bracket_depth -= 1;
                        cur.push(ch);
                    }
                    '{' => {
                        brace_depth += 1;
                        cur.push(ch);
                    }
                    '}' => {
                        if brace_depth == 0 {
                            bail!("line {line_num}: unmatched closing '}}'");
                        }
                        brace_depth -= 1;
                        cur.push(ch);
                    }
                    '\n' => {
                        line_num += 1;
                        if bracket_depth == 0 && brace_depth == 0 {
                            let trimmed = cur.trim();
                            if !trimmed.is_empty() {
                                out.push((cur_start_line, trimmed.to_string()));
                            }
                            cur.clear();
                        } else {
                            cur.push(' ');
                        }
                    }
                    '\r' => {}
                    _ => cur.push(ch),
                }
            }
            QuoteState::Double => {
                if ch == '\\' {
                    cur.push(ch);
                    i += ch_len;
                    if i < bytes.len() {
                        let next_ch = input[i..].chars().next().expect("valid utf8");
                        if next_ch == '\n' {
                            line_num += 1;
                        }
                        cur.push(next_ch);
                        i += next_ch.len_utf8();
                    }
                    continue;
                }
                if ch == '\n' {
                    bail!("line {line_num}: unterminated double-quoted string");
                }
                if ch == '"' {
                    quote = QuoteState::None;
                }
                cur.push(ch);
            }
            QuoteState::Single => {
                if ch == '\n' {
                    bail!("line {line_num}: unterminated single-quoted string");
                }
                if ch == '\'' {
                    quote = QuoteState::None;
                }
                cur.push(ch);
            }
            QuoteState::TripleDouble => {
                if ch == '\\' {
                    cur.push(ch);
                    i += ch_len;
                    if i < bytes.len() {
                        let next_ch = input[i..].chars().next().expect("valid utf8");
                        if next_ch == '\n' {
                            line_num += 1;
                        }
                        cur.push(next_ch);
                        i += next_ch.len_utf8();
                    }
                    continue;
                }
                if input[i..].starts_with("\"\"\"") {
                    quote = QuoteState::None;
                    cur.push_str("\"\"\"");
                    i += 3;
                    continue;
                }
                if ch == '\n' {
                    line_num += 1;
                }
                cur.push(ch);
            }
            QuoteState::TripleSingle => {
                if input[i..].starts_with("'''") {
                    quote = QuoteState::None;
                    cur.push_str("'''");
                    i += 3;
                    continue;
                }
                if ch == '\n' {
                    line_num += 1;
                }
                cur.push(ch);
            }
        }

        i += ch_len;
    }

    if quote != QuoteState::None {
        bail!("line {cur_start_line}: unterminated string literal");
    }
    if bracket_depth > 0 {
        bail!("line {cur_start_line}: unterminated array value");
    }
    if brace_depth > 0 {
        bail!("line {cur_start_line}: unterminated inline table");
    }
    let trimmed = cur.trim();
    if !trimmed.is_empty() {
        out.push((cur_start_line, trimmed.to_string()));
    }
    Ok(out)
}

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    let mut bracket_depth = 0usize;

    for (idx, ch) in line.char_indices() {
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '#' if bracket_depth == 0 => return None,
            '=' if bracket_depth == 0 => return Some((&line[..idx], &line[idx + 1..])),
            _ => {}
        }
    }
    None
}

fn parse_key(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("empty key");
    }
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        return serde_json::from_str::<String>(trimmed).context("invalid quoted key");
    }
    if trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2 {
        return Ok(trimmed[1..trimmed.len() - 1].to_string());
    }
    if trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Ok(trimmed.to_string());
    }
    bail!("unexpected characters in key {trimmed:?}");
}

fn split_top_level_commas(inner: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    let mut bracket_depth = 0usize;
    let mut brace_depth = 0usize;

    for (idx, ch) in inner.char_indices() {
        if in_double {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_double = false;
            }
            continue;
        }
        if in_single {
            if ch == '\'' {
                in_single = false;
            }
            continue;
        }
        match ch {
            '"' => in_double = true,
            '\'' => in_single = true,
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            ',' if bracket_depth == 0 && brace_depth == 0 => {
                parts.push(&inner[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(&inner[start..]);
    parts
}

fn parse_value(raw: &str) -> Result<TomlScalar> {
    let raw = raw.trim();
    if raw.is_empty() {
        bail!("empty value");
    }
    if raw.starts_with('{') {
        if !raw.ends_with('}') {
            bail!("unterminated inline table");
        }
        return Ok(TomlScalar::InlineTable);
    }
    if raw.starts_with('[') {
        let inner = raw
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| anyhow!("unterminated array value"))?
            .trim();
        if inner.is_empty() {
            return Ok(TomlScalar::Array(Vec::new()));
        }
        let mut items = Vec::new();
        for part in split_top_level_commas(inner) {
            let trimmed_part = part.trim();
            if trimmed_part.is_empty() {
                continue;
            }
            items.push(parse_value(trimmed_part)?);
        }
        return Ok(TomlScalar::Array(items));
    }
    if let Some(after_triple) = raw.strip_prefix("\"\"\"") {
        let end = after_triple
            .rfind("\"\"\"")
            .ok_or_else(|| anyhow!("unterminated multiline double-quoted string"))?;
        let trailing = after_triple[end + 3..].trim();
        if !trailing.is_empty() {
            bail!("unexpected trailing characters after multiline string: {trailing:?}");
        }
        let body = after_triple[..end]
            .strip_prefix('\n')
            .or_else(|| after_triple[..end].strip_prefix("\r\n"))
            .unwrap_or(&after_triple[..end]);
        let escaped_json = format!(
            "\"{}\"",
            body.replace('\r', "\\r")
                .replace('\n', "\\n")
                .replace('\t', "\\t")
        );
        let decoded =
            serde_json::from_str::<String>(&escaped_json).unwrap_or_else(|_| body.to_string());
        return Ok(TomlScalar::Str(decoded));
    }
    if let Some(after_triple) = raw.strip_prefix("'''") {
        let end = after_triple
            .rfind("'''")
            .ok_or_else(|| anyhow!("unterminated multiline literal string"))?;
        let trailing = after_triple[end + 3..].trim();
        if !trailing.is_empty() {
            bail!("unexpected trailing characters after multiline literal string: {trailing:?}");
        }
        let body = after_triple[..end]
            .strip_prefix('\n')
            .or_else(|| after_triple[..end].strip_prefix("\r\n"))
            .unwrap_or(&after_triple[..end]);
        return Ok(TomlScalar::Str(body.to_string()));
    }
    if raw.starts_with('"') {
        let mut escaped = false;
        let mut end_idx = None;
        for (idx, ch) in raw.char_indices().skip(1) {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                end_idx = Some(idx);
                break;
            }
        }
        let end = end_idx.ok_or_else(|| anyhow!("unterminated double-quoted string"))?;
        let token = &raw[..=end];
        let trailing = raw[end + 1..].trim();
        if !trailing.is_empty() {
            bail!("unexpected trailing characters after string: {trailing:?}");
        }
        let decoded = serde_json::from_str::<String>(token)
            .with_context(|| format!("invalid escaped string {token}"))?;
        return Ok(TomlScalar::Str(decoded));
    }

    if let Some(after_quote) = raw.strip_prefix('\'') {
        let end = after_quote
            .find('\'')
            .ok_or_else(|| anyhow!("unterminated single-quoted string"))?;
        let token = &after_quote[..end];
        let trailing = after_quote[end + 1..].trim();
        if !trailing.is_empty() {
            bail!("unexpected trailing characters after literal string: {trailing:?}");
        }
        return Ok(TomlScalar::Str(token.to_string()));
    }

    let bare = raw.trim();
    if bare == "true" {
        return Ok(TomlScalar::Bool(true));
    }
    if bare == "false" {
        return Ok(TomlScalar::Bool(false));
    }
    let clean_num = bare.replace('_', "");
    if let Ok(i) = clean_num.parse::<i64>() {
        return Ok(TomlScalar::Int(i));
    }
    if let Ok(f) = clean_num.parse::<f64>() {
        return Ok(TomlScalar::Float(f));
    }
    bail!("unrecognized TOML scalar: {bare:?}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_installer_toml_and_escapes() {
        let sample = r#"
# LibreSpeed settings
bind_address="127.0.0.1"
listen_port=8999 # inline comment
url_base="/speedtest/"
proxyprotocol_port=0
server_lat=48.8566
server_lng=2.3522
ipinfo_api_key=""
assets_path='/opt/librespeed/assets'
statistics_password="p@ss\"w\\ord\u0021#notcomment"
redact_ip_addresses=true
database_type="bolt"
database_file="/var/lib/librespeed/speedtest.db"
enable_id_obfuscation=true
custom_tuning = "keep-me"
"#;

        let cfg = Config::parse_toml_str(sample).expect("parse sample");
        assert_eq!(cfg.bind_address, "127.0.0.1");
        assert_eq!(cfg.listen_port, 8999);
        assert_eq!(cfg.url_base, "speedtest");
        assert_eq!(cfg.assets_path, PathBuf::from("/opt/librespeed/assets"));
        assert_eq!(cfg.statistics_password, "p@ss\"w\\ord!#notcomment");
        assert!(cfg.redact_ip_addresses);
        assert_eq!(cfg.database_type, "bolt");
        assert!(cfg.telemetry_enabled());
        assert_eq!(
            cfg.database_file,
            PathBuf::from("/var/lib/librespeed/speedtest.db")
        );
        assert!(cfg.enable_id_obfuscation);
        assert!(!cfg.enable_tls);
        assert!(cfg.trusted_proxies.is_empty());
        assert_eq!(cfg.max_telemetry_rows, DEFAULT_MAX_TELEMETRY_ROWS);
        assert!((cfg.server_lat - 48.8566).abs() < 1e-6);
        assert!((cfg.server_lng - 2.3522).abs() < 1e-6);
        assert_eq!(cfg.ipinfo_api_key, "");
    }

    #[test]
    fn fails_closed_on_incomplete_tls_or_nonzero_proxyprotocol_or_bad_trusted_proxy() {
        assert!(Config::parse_toml_str("enable_tls = true\n").is_err());
        assert!(Config::parse_toml_str(
            "enable_tls = true\ntls_cert_file = \"/etc/ssl/cert.pem\"\n"
        )
        .is_err());
        assert!(Config::parse_toml_str("proxyprotocol_port = 8990\n").is_err());
        assert!(Config::parse_toml_str("max_telemetry_rows = 0\n").is_err());
        assert!(Config::parse_toml_str("trusted_proxies = \"not-an-ip\"\n").is_err());
        assert!(Config::parse_toml_str("database_type = \"postgresql\"\n").is_err());
        assert!(Config::parse_toml_str("database_type = \"mysql\"\n").is_err());
        assert!(
            Config::parse_toml_str("database_type = \"sqlite\"\ndatabase_file = \"\"\n").is_err()
        );
        let padded_pw =
            Config::parse_toml_str("statistics_password = \" PASSWORD \"\n").expect("padded pw");
        assert!(padded_pw.stats_locked());

        let ok = Config::parse_toml_str(
            "enable_tls = true\n\
             tls_cert_file = \"/etc/ssl/cert.pem\"\n\
             tls_key_file = \"/etc/ssl/key.pem\"\n\
             trusted_proxies = [\"127.0.0.1\", \"::1\"]\n\
             max_telemetry_rows = 5000\n",
        )
        .expect("valid security config");
        assert!(ok.enable_tls);
        assert_eq!(ok.trusted_proxies.len(), 2);
        assert_eq!(ok.max_telemetry_rows, 5000);
    }

    #[test]
    fn handles_empty_bind_address_and_none_database() {
        let sample = r#"
bind_address = ""
database_type = "NoNe"
url_base = "///"
listen_port = 18_988
"#;
        let cfg = Config::parse_toml_str(sample).expect("parse");
        assert_eq!(cfg.bind_address, "0.0.0.0");
        assert_eq!(cfg.listen_port, 18988);
        assert_eq!(cfg.url_base, "");
        assert!(!cfg.telemetry_enabled());
    }

    #[test]
    fn empty_database_type_contract_matches_telemetry_enabled() {
        let disabled = Config::parse_toml_str("database_type = \"\"\ndatabase_file = \"\"\n")
            .expect("empty database_type + empty database_file disables telemetry");
        assert!(!disabled.telemetry_enabled());

        let enabled = Config::parse_toml_str(
            "database_type = \"\"\ndatabase_file = \"/var/lib/librespeed/speedtest.db\"\n",
        )
        .expect("empty database_type + path enables SQLite telemetry");
        assert!(enabled.telemetry_enabled());

        assert!(
            Config::parse_toml_str("database_type = \"sqlite\"\ndatabase_file = \"\"\n").is_err(),
            "explicit sqlite database_type with empty database_file must fail closed"
        );
    }

    #[test]
    fn cli_parses_flags() {
        assert_eq!(
            parse_cli_args(["speedtest-backend", "-c", "/tmp/a.toml"]).unwrap(),
            CliAction::Run {
                config_path: PathBuf::from("/tmp/a.toml")
            }
        );
        assert_eq!(
            parse_cli_args(["speedtest-backend", "--config=/tmp/b.toml"]).unwrap(),
            CliAction::Run {
                config_path: PathBuf::from("/tmp/b.toml")
            }
        );
        assert_eq!(
            parse_cli_args(["speedtest-backend", "-v"]).unwrap(),
            CliAction::PrintVersion
        );
        assert_eq!(
            parse_cli_args(["speedtest-backend", "--version"]).unwrap(),
            CliAction::PrintVersion
        );
        assert!(parse_cli_args(["speedtest-backend", "-c"]).is_err());
        assert!(parse_cli_args(["speedtest-backend", "--bogus"]).is_err());
    }

    #[test]
    fn parses_multiline_toml_arrays_comments_and_ignores_unknown_tables() {
        let sample = r#"
bind_address = "127.0.0.1"
listen_port = 8988
trusted_proxies = [
    # Loopback reverse proxy peers
    "127.0.0.1", # IPv4 loopback
    "::1",       # IPv6 loopback
]
trusted_proxy_secret = "deadbeefcafebabe"
unknown_ports = [
    8080,
    8443,
]
unknown_objects = [
    { name = "edge-1", weight = 10 },
    { name = "edge-2", weight = 20 },
]

[tuning]
listen_port = 9999
extra_flags = [
    "fast",
    "zero-copy",
]
"#;
        let cfg = Config::parse_toml_str(sample).expect("multiline TOML must parse cleanly");
        assert_eq!(
            cfg.listen_port, 8988,
            "subtable keys must not override root"
        );
        assert_eq!(
            cfg.trusted_proxies,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap(),
            ]
        );
        assert_eq!(cfg.trusted_proxy_secret, "deadbeefcafebabe");
        assert!(
            !format!("{cfg:?}").contains("deadbeefcafebabe"),
            "Debug impl must redact trusted_proxy_secret"
        );

        assert!(
            Config::parse_toml_str("trusted_proxies = [\n  \"127.0.0.1\",\n").is_err(),
            "unterminated multiline array must fail closed"
        );
    }

    #[test]
    fn load_from_path_rejects_symlinks_and_world_writable_files() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let dir = std::env::temp_dir().join(format!(
            "af-librespeed-cfg-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();

        let real_cfg = dir.join("real.toml");
        fs::write(&real_cfg, "listen_port = 8988\n").unwrap();
        fs::set_permissions(&real_cfg, fs::Permissions::from_mode(0o640)).unwrap();

        let loaded = Config::load_from_path(&real_cfg).expect("regular 0640 config must load");
        assert_eq!(loaded.listen_port, 8988);

        let sym_cfg = dir.join("sym.toml");
        symlink(&real_cfg, &sym_cfg).unwrap();
        let sym_err = Config::load_from_path(&sym_cfg)
            .expect_err("symlinked settings.toml must fail closed")
            .to_string();
        assert!(sym_err.contains("symlink"), "unexpected error: {sym_err}");

        let sym_dir = dir.join("sym_dir");
        symlink(&dir, &sym_dir).unwrap();
        let anc_err = Config::load_from_path(&sym_dir.join("real.toml"))
            .expect_err("symlinked ancestor directory must fail closed")
            .to_string();
        assert!(anc_err.contains("symlink"), "unexpected error: {anc_err}");

        fs::set_permissions(&real_cfg, fs::Permissions::from_mode(0o666)).unwrap();
        let ww_err = Config::load_from_path(&real_cfg)
            .expect_err("world-writable settings.toml must fail closed")
            .to_string();
        assert!(
            ww_err.contains("world-writable"),
            "unexpected error: {ww_err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn supports_memory_database_and_rejects_unsafe_url_base() {
        let mem_cfg = Config::parse_toml_str("database_type = \"memory\"\ndatabase_file = \"\"\n")
            .expect("memory database_type must succeed with empty database_file");
        assert!(mem_cfg.telemetry_enabled());

        let nested_base = Config::parse_toml_str("url_base = \"/api/v1/speedtest/\"\n")
            .expect("multi-segment url_base must parse");
        assert_eq!(nested_base.url_base, "api/v1/speedtest");

        for bad_base in [
            "url_base = \"speed; Domain=evil.example\"\n",
            "url_base = \"../admin\"\n",
            "url_base = \"speed?foo=bar\"\n",
            "url_base = \"speed#frag\"\n",
            "url_base = \"speed//double\"\n",
            "url_base = \"speed with space\"\n",
            "ipinfo_base_url = \"http://169.254.169.254:80\"\n",
            "ipinfo_base_url = \"https://evil.example\"\n",
        ] {
            assert!(
                Config::parse_toml_str(bad_base).is_err(),
                "expected unsafe url_base/ipinfo_base_url to fail closed: {bad_base}"
            );
        }
        let loopback_ipinfo =
            Config::parse_toml_str("ipinfo_base_url = \"http://127.0.0.1:18080\"\n")
                .expect("loopback ipinfo_base_url must parse");
        assert_eq!(loopback_ipinfo.ipinfo_base_url, "http://127.0.0.1:18080");
    }
}
