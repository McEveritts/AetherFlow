use anyhow::{anyhow, bail, Context, Result};
use std::env;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/opt/librespeed/settings.toml";
pub const VERSION_STRING: &str = concat!(
    "speedtest-backend ",
    env!("AF_LIBRESPEED_EFFECTIVE_VERSION")
);
pub const DEFAULT_MAX_TELEMETRY_ROWS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub max_telemetry_rows: usize,
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
            max_telemetry_rows: DEFAULT_MAX_TELEMETRY_ROWS,
        }
    }
}

impl Config {
    /// Returns true unless `database_type` is `"none"` (case-insensitive) or
    /// `database_file` is empty. Legacy values like `"bolt"` or `""` resolve
    /// to SQLite at `database_file`.
    pub fn telemetry_enabled(&self) -> bool {
        !self.database_type.trim().eq_ignore_ascii_case("none")
            && !self.database_file.as_os_str().is_empty()
    }

    pub fn stats_locked(&self) -> bool {
        let trimmed = self.statistics_password.trim();
        trimmed.is_empty() || self.statistics_password == "PASSWORD"
    }

    pub fn validate_listener_security(&self) -> Result<()> {
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
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read settings.toml at {}", path.display()))?;
        Self::parse_toml_str(&content)
            .with_context(|| format!("failed to parse settings.toml at {}", path.display()))
    }

    pub fn parse_toml_str(input: &str) -> Result<Self> {
        let mut cfg = Self::default();

        for (idx, raw_line) in input.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = raw_line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.starts_with('[') && strip_unquoted_comment(trimmed).ends_with(']') {
                continue;
            }

            let Some((raw_key, raw_val)) = split_key_value(trimmed) else {
                bail!("line {line_num}: expected key = value assignment");
            };

            let key =
                parse_key(raw_key).with_context(|| format!("line {line_num}: invalid key"))?;
            let val = parse_value(raw_val.trim())
                .with_context(|| format!("line {line_num}: invalid value for key '{key}'"))?;

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
                "max_telemetry_rows" => {
                    cfg.max_telemetry_rows = val.into_positive_usize("max_telemetry_rows")?;
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
    StrList(Vec<String>),
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

    fn into_ip_list(self, key: &str) -> Result<Vec<IpAddr>> {
        let raw_items: Vec<String> = match self {
            TomlScalar::Str(s) => s
                .split(',')
                .map(str::trim)
                .filter(|tok| !tok.is_empty())
                .map(ToOwned::to_owned)
                .collect(),
            TomlScalar::StrList(items) => items
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
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

fn split_key_value(line: &str) -> Option<(&str, &str)> {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;

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
            '#' => return None,
            '=' => return Some((&line[..idx], &line[idx + 1..])),
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
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Ok(trimmed.to_string());
    }
    bail!("unexpected characters in key {trimmed:?}");
}

fn strip_unquoted_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;

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
            '#' => return line[..idx].trim_end(),
            _ => {}
        }
    }
    line.trim_end()
}

fn parse_value(raw: &str) -> Result<TomlScalar> {
    if raw.is_empty() {
        bail!("empty value");
    }
    if raw.starts_with('[') {
        let stripped = strip_unquoted_comment(raw).trim();
        let inner = stripped
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or_else(|| anyhow!("unterminated array value"))?
            .trim();
        if inner.is_empty() {
            return Ok(TomlScalar::StrList(Vec::new()));
        }
        let mut items = Vec::new();
        for part in inner.split(',') {
            let trimmed_part = part.trim();
            if trimmed_part.is_empty() {
                continue;
            }
            match parse_value(trimmed_part)? {
                TomlScalar::Str(s) => items.push(s),
                other => bail!("expected string element in array, got {other:?}"),
            }
        }
        return Ok(TomlScalar::StrList(items));
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
        if !trailing.is_empty() && !trailing.starts_with('#') {
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
        if !trailing.is_empty() && !trailing.starts_with('#') {
            bail!("unexpected trailing characters after literal string: {trailing:?}");
        }
        return Ok(TomlScalar::Str(token.to_string()));
    }

    let bare = strip_unquoted_comment(raw).trim();
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
}
