use super::*;

pub(in crate::package_executor) fn rewrite_runner_apache_proxy_url_port(
    token: &str,
    listen_port: i32,
    upstream_tls: Option<bool>,
) -> Option<String> {
    for scheme in ["http://", "https://", "ws://", "wss://"] {
        if let Some(rest) = token.strip_prefix(scheme) {
            let out_scheme = match (scheme, upstream_tls) {
                ("http://" | "https://", Some(true)) => "https://",
                ("http://" | "https://", Some(false)) => "http://",
                ("ws://" | "wss://", Some(true)) => "wss://",
                ("ws://" | "wss://", Some(false)) => "ws://",
                _ => scheme,
            };
            for host in ["127.0.0.1:", "localhost:", "0.0.0.0:", "[::1]:"] {
                if let Some(after_host) = rest.strip_prefix(host) {
                    let digit_len = after_host
                        .chars()
                        .take_while(|c| c.is_ascii_digit())
                        .count();
                    if digit_len > 0 {
                        let suffix = &after_host[digit_len..];
                        return Some(format!("{out_scheme}{host}{listen_port}{suffix}"));
                    }
                }
            }
        }
    }
    None
}

pub(in crate::package_executor) fn runner_apache_directory_exists(
    path: &Path,
    fs_root: Option<&Path>,
) -> Result<bool, PackageExecutorError> {
    validate_filesystem_path(path, fs_root)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(PackageExecutorError::VerificationFailed(format!(
            "required Apache configuration directory is not a directory: {}",
            path.display()
        ))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(PackageExecutorError::VerificationFailed(format!(
            "failed to inspect Apache configuration directory {}: {}",
            path.display(),
            err
        ))),
    }
}

pub(in crate::package_executor) fn read_runner_apache_vhost(
    path: &Path,
    fs_root: Option<&Path>,
    allow_enabled_alias: bool,
) -> Result<Option<String>, PackageExecutorError> {
    if let Some(parent) = path.parent() {
        validate_filesystem_path(parent, fs_root)?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if allow_enabled_alias && metadata.file_type().is_symlink() => Ok(None),
        Ok(_) => {
            validate_regular_config_candidate(path, fs_root)?;
            fs::read_to_string(path).map(Some).map_err(|err| {
                PackageExecutorError::VerificationFailed(format!(
                    "failed to read required Apache vhost {}: {}",
                    path.display(),
                    err
                ))
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(PackageExecutorError::VerificationFailed(format!(
            "failed to inspect required Apache vhost {}: {}",
            path.display(),
            err
        ))),
    }
}

pub(in crate::package_executor) fn extract_runner_apache_custom_blocks(
    paths: &[PathBuf],
    fs_root: Option<&Path>,
    sites_en: &Path,
) -> Result<Vec<String>, PackageExecutorError> {
    let mut blocks = Vec::new();
    for path in paths {
        let source = match fs::symlink_metadata(path) {
            Ok(metadata)
                if path.parent() == Some(sites_en) && metadata.file_type().is_symlink() =>
            {
                validate_filesystem_path(sites_en, fs_root)?;
                match fs::canonicalize(path) {
                    Ok(target) => target,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(err) => {
                        return Err(PackageExecutorError::VerificationFailed(format!(
                            "failed to resolve Apache vhost alias {}: {}",
                            path.display(),
                            err
                        )));
                    }
                }
            }
            _ => path.clone(),
        };
        let Some(raw) = read_runner_apache_vhost(&source, fs_root, false)? else {
            continue;
        };
        collect_apache_custom_blocks(&raw, &mut blocks);
    }
    Ok(blocks)
}

pub(in crate::package_executor) fn collect_apache_custom_blocks(
    raw: &str,
    blocks: &mut Vec<String>,
) {
    collect_apache_live_custom_blocks(raw, blocks);
    let pending = raw
        .lines()
        .filter_map(|line| line.strip_prefix(TLS_PENDING_COMMENT))
        .collect::<Vec<_>>()
        .join("\n");
    collect_apache_live_custom_blocks(&pending, blocks);
}

pub(in crate::package_executor) fn collect_apache_live_custom_blocks(
    raw: &str,
    blocks: &mut Vec<String>,
) {
    let mut depth = 0usize;
    let mut section = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        let directive = trimmed
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if depth > 0 {
            if !section.is_empty() {
                section.push(line);
            }
            if directive.starts_with("</") {
                depth -= 1;
            } else if directive.starts_with('<') && trimmed.ends_with('>') {
                depth += 1;
            }
            if depth == 0 && !section.is_empty() {
                let block = section.join("\n");
                if !ACME_HTTP_EXEMPTION.contains(block.trim())
                    && !blocks
                        .iter()
                        .any(|existing| existing.trim() == block.trim())
                {
                    blocks.push(block);
                }
                section.clear();
            }
        } else if directive.starts_with('<')
            && !directive.starts_with("</")
            && directive != "<virtualhost"
            && trimmed.ends_with('>')
        {
            depth = 1;
            if matches!(
                directive.as_str(),
                "<location"
                    | "<locationmatch"
                    | "<directory"
                    | "<directorymatch"
                    | "<files"
                    | "<filesmatch"
                    | "<requireall>"
                    | "<requireany>"
                    | "<requirenone>"
            ) {
                section.push(line);
            }
        } else if matches!(
            directive.as_str(),
            "authtype"
                | "authname"
                | "authuserfile"
                | "authgroupfile"
                | "authbasicprovider"
                | "require"
                | "include"
                | "includeoptional"
        ) && !blocks.iter().any(|block| block.trim() == trimmed)
        {
            blocks.push(line.to_string());
        }
    }
}

pub(crate) fn apache_upstream_tls(
    app: &str,
    fs_root: Option<&Path>,
) -> anyhow::Result<LibreSpeedUpstreamTlsConfig> {
    let rebase = |path: &str| {
        fs_root.map_or_else(
            || PathBuf::from(path),
            |root| root.join(path.trim_start_matches('/')),
        )
    };
    let config = match app {
        "librespeed" => {
            let settings = env::var_os("AETHERFLOW_LIBRESPEED_SETTINGS_PATH")
                .filter(|path| !path.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| rebase("/opt/librespeed/settings.toml"));
            try_librespeed_runner_settings_tls_config(&settings, fs_root)
                .ok_or_else(|| anyhow::anyhow!("cannot verify LibreSpeed upstream TLS settings"))?
        }
        "kasmvnc" => LibreSpeedUpstreamTlsConfig {
            enabled: true,
            ca_cert_file: [
                "/etc/kasmvnc/kasmvnc.crt",
                "/var/lib/kasmvnc/.vnc/aetherflow-cert.pem",
            ]
            .into_iter()
            .find_map(|path| validate_librespeed_apache_ca_cert(path, fs_root)),
        },
        _ => Default::default(),
    };
    anyhow::ensure!(
        !config.enabled || config.ca_cert_file.is_some(),
        "{app} upstream TLS requires a regular, non-symlinked certificate for Apache SSLProxyCACertificateFile pinning"
    );
    Ok(config)
}

// Authenticated internal `.aether.local` reachability allowlist.
// `100.64.0.0/10` (RFC 6598 / Tailscale) is permitted for authenticated internal access
// (matching `proxy_helpers.rs::is_private_or_loopback_ip`), while unauthenticated LAN
// bypass in `af-api` (`is_unauth_local_lan_ip`) unconditionally excludes `100.64.0.0/10`
// and loopback. IPv4 link-local `169.254.0.0/16` is intentionally omitted here at the
// Apache layer to prevent cloud metadata / link-local forwarding ambiguity.
pub(in crate::package_executor) const INTERNAL_NETWORKS: &str =
    "127.0.0.0/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 fc00::/7 fe80::/10";
pub(in crate::package_executor) const APACHE_HTPASSWD: &str = "/etc/apache2/AetherFlow/htpasswd";
pub const GATEWAY_APP_HEADER: &str = "x-aetherflow-external-app";

/// Applications whose public routes require AetherFlow authentication.
pub fn requires_external_app_auth(app: &str) -> bool {
    matches!(
        app,
        "mcvnc"
            | "scrutiny"
            | "prometheus"
            | "flaresolverr"
            | "jackett"
            | "threadfin"
            | "rutorrent"
            | "unmanic"
            | "netdata"
            | "autoscan"
    )
}

pub(in crate::package_executor) fn apache_bcrypt_entry(
    username: &str,
    hash: &str,
) -> Option<String> {
    if !SAFE_USERNAME.is_match(username) || hash.len() != 60 {
        return None;
    }
    let (version, remainder) = hash.split_at_checked(4)?;
    if !matches!(version, "$2a$" | "$2b$" | "$2y$")
        || !remainder
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'$' | b'.' | b'/'))
        || !remainder.as_bytes()[..2].iter().all(u8::is_ascii_digit)
        || remainder.as_bytes()[2] != b'$'
        || remainder.as_bytes()[3..].contains(&b'$')
    {
        return None;
    }
    Some(format!("{username}:$2y${remainder}\n"))
}

pub(in crate::package_executor) fn htpasswd_from_master_file(path: &Path) -> Option<String> {
    let contents = crate::read_confined_text(path, &[]).ok()?;
    let (user, password) = contents.trim_end_matches(['\r', '\n']).split_once(':')?;
    if !SAFE_USERNAME.is_match(user) || password.is_empty() || password.contains(['\r', '\n', '\0'])
    {
        return None;
    }
    // apache2-utils is installed with Apache. Pass the password only on stdin.
    let mut child = std::process::Command::new("/usr/bin/htpasswd")
        .args(["-niBC", "10", user])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let written = child
        .stdin
        .take()
        .is_some_and(|mut input| writeln!(input, "{password}").is_ok());
    let output = child.wait_with_output().ok()?;
    if !written || !output.status.success() {
        return None;
    }
    let output = std::str::from_utf8(&output.stdout).ok()?.trim();
    let (result_user, hash) = output.split_once(':')?;
    (result_user == user)
        .then(|| apache_bcrypt_entry(user, hash))
        .flatten()
}

pub(in crate::package_executor) fn htpasswd_from_admin_database() -> Option<String> {
    let conn = crate::open_runner_state_database(None).ok()?;
    let mut query = conn
        .prepare(
            "SELECT username, password_hash FROM users
         WHERE role = 'admin' AND password_hash != '' AND COALESCE(totp_enabled, 0) = 0
         ORDER BY id",
        )
        .ok()?;
    let rows = query
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .ok()?;
    for (username, hash) in rows.filter_map(Result::ok) {
        if let Some(entry) = apache_bcrypt_entry(&username, &hash) {
            return Some(entry);
        }
    }
    None
}

pub(in crate::package_executor) fn ensure_apache_htpasswd_file(path: &Path) -> anyhow::Result<()> {
    ensure_apache_htpasswd_with(path, || {
        ["/etc/aetherflow/.master.creds", "/root/.master.creds"]
            .into_iter()
            .find_map(|file| htpasswd_from_master_file(Path::new(file)))
            .or_else(htpasswd_from_admin_database)
    })
}

pub(in crate::package_executor) fn ensure_apache_htpasswd_with(
    path: &Path,
    entry: impl FnOnce() -> Option<String>,
) -> anyhow::Result<()> {
    static PROVISION: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = PROVISION.lock().unwrap_or_else(|err| err.into_inner());
    match crate::open_confined_file(path, &[]) {
        Ok(file) if file.metadata()?.len() > 0 => return Ok(()),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let Some(entry) = entry() else {
        anyhow::bail!(
            "{} requires a master credential or an administrator bcrypt hash",
            path.display()
        );
    };
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("htpasswd path has no parent"))?;
    validate_filesystem_path(parent, None)?;
    create_dir_all_0755(parent)?;
    let owner = (unsafe { libc::geteuid() } == 0)
        .then(|| (0, crate::lookup_group_gid("www-data").unwrap_or(0)));
    crate::replace_confined_file(
        path,
        entry.as_bytes(),
        Some(&[]),
        Some(0o640),
        false,
        false,
        owner,
    )?;
    Ok(())
}

pub(in crate::package_executor) fn external_auth_policy(
    app: &str,
    fs_root: Option<&Path>,
) -> anyhow::Result<String> {
    external_auth_policy_for_vhost(app, fs_root, false)
}

pub(in crate::package_executor) fn external_auth_policy_for_vhost(
    app: &str,
    fs_root: Option<&Path>,
    acme: bool,
) -> anyhow::Result<String> {
    if !requires_external_app_auth(app) {
        return Ok(String::new());
    }
    let path = fs_root.map_or_else(
        || PathBuf::from(APACHE_HTPASSWD),
        |root| root.join(APACHE_HTPASSWD.trim_start_matches('/')),
    );
    if fs_root.is_none() && unsafe { libc::geteuid() } == 0 {
        ensure_apache_htpasswd_file(&path)?;
    }
    anyhow::ensure!(
        crate::open_confined_file(&path, &[])
            .and_then(|file| file.metadata())
            .is_ok_and(|meta| meta.len() > 0),
        "external access for {app} requires {APACHE_HTPASSWD}"
    );
    // Apache merges <If> after <Location>. And preserves restrictions already applied
    // to an operator location and also requires the managed credentials there.
    let condition = if acme {
        "%{REQUEST_URI} !~ m#^/\\.well-known/acme-challenge/#"
    } else {
        "true"
    };
    Ok(format!(
        "    <If \"{condition}\">
        AuthType Basic
        AuthName \"AetherFlow\"
        AuthBasicProvider file
        AuthUserFile {APACHE_HTPASSWD}
        AuthMerging And
        Require valid-user
    </If>
"
    ))
}

pub(in crate::package_executor) fn internal_network_policy() -> String {
    format!(
        "    <Proxy \"*\">
        Require ip {INTERNAL_NETWORKS}
    </Proxy>
"
    )
}

pub(in crate::package_executor) fn internal_rewrite_guard() -> String {
    // The vhost rewrite guard also covers any <Location> with its own authz rules
    // and runs before the WebSocket proxy rewrite.
    let networks = INTERNAL_NETWORKS
        .split_whitespace()
        .map(|network| format!("-R '{network}'"))
        .collect::<Vec<_>>()
        .join(" || ");
    format!(
        "    RewriteCond expr \"!({networks})\"
    RewriteRule ^ - [F,L]
"
    )
}

pub(in crate::package_executor) fn apache_tls_pair(
    domain: &str,
    fs_root: Option<&Path>,
) -> Option<(String, String)> {
    if !af_models::valid_ingress_hostname(domain) || domain.ends_with(".aether.local") {
        return None;
    }
    let resolve = |path: &str| {
        let resolved = fs_root.map_or_else(
            || PathBuf::from(path),
            |root| root.join(path.trim_start_matches('/')),
        );
        if let Some(root) = fs_root {
            if !resolved
                .canonicalize()
                .is_ok_and(|path| path.starts_with(root))
            {
                return None;
            }
        }
        fs::metadata(&resolved)
            .is_ok_and(|meta| meta.is_file() && meta.len() > 0)
            .then_some(resolved)
    };
    let live_pair = |name: &str| {
        (
            format!("/etc/letsencrypt/live/{name}/fullchain.pem"),
            format!("/etc/letsencrypt/live/{name}/privkey.pem"),
        )
    };
    let pair_is_valid = |pair: &(String, String)| {
        let (Some(cert), Some(key)) = (resolve(&pair.0), resolve(&pair.1)) else {
            return false;
        };
        tls_certificate_matches_key(&cert, &key)
    };
    let pair = live_pair(domain);
    if pair_is_valid(&pair) {
        return Some(pair);
    }
    if resolve(&pair.0).is_none() {
        let mut ancestor = domain;
        while let Some((_, parent)) = ancestor.split_once('.') {
            if !parent.contains('.') {
                break;
            }
            ancestor = parent;
            let pair = live_pair(parent);
            if let Some(cert) = resolve(&pair.0) {
                if cert_san_covers_domain(&cert, domain) && pair_is_valid(&pair) {
                    return Some(pair);
                }
            }
        }
    }
    [
        (
            format!("/etc/ssl/AetherFlow/{domain}/fullchain.pem"),
            format!("/etc/ssl/AetherFlow/{domain}/privkey.pem"),
        ),
        (
            format!("/etc/ssl/AetherFlow/{domain}.crt"),
            format!("/etc/ssl/AetherFlow/{domain}.key"),
        ),
    ]
    .into_iter()
    .find(pair_is_valid)
}

pub(in crate::package_executor) fn tls_certificate_matches_key(cert: &Path, key: &Path) -> bool {
    let cert = std::process::Command::new("openssl")
        .args(["x509", "-noout", "-checkend", "0", "-pubkey", "-in"])
        .arg(cert)
        .output();
    let Ok(cert) = cert else {
        return false;
    };
    if !cert.status.success() {
        return false;
    }
    let key = std::process::Command::new("openssl")
        .args(["pkey", "-pubout", "-passin", "pass:", "-in"])
        .arg(key)
        .output();
    let Ok(key) = key else {
        return false;
    };
    key.status.success()
        && !key.stdout.is_empty()
        && String::from_utf8_lossy(&cert.stdout)
            .contains(String::from_utf8_lossy(&key.stdout).trim())
}

pub(in crate::package_executor) fn cert_san_covers_domain(cert: &Path, domain: &str) -> bool {
    let Ok(output) = std::process::Command::new("openssl")
        .args(["x509", "-noout", "-ext", "subjectAltName", "-in"])
        .arg(cert)
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let wildcard = domain
        .split_once('.')
        .map(|(_, parent)| format!("*.{parent}"));
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .skip(1)
        .flat_map(|line| line.split(','))
        .filter_map(|san| san.trim().strip_prefix("DNS:"))
        .any(|san| {
            san.eq_ignore_ascii_case(domain)
                || wildcard
                    .as_ref()
                    .is_some_and(|name| san.eq_ignore_ascii_case(name))
        })
}

/// Checks whether a public domain can use an installed TLS certificate and key.
pub fn check_domain_tls_ready(domain: &str, fs_root: Option<&Path>) -> bool {
    apache_tls_pair(domain, fs_root).is_some()
}

pub(in crate::package_executor) const TLS_PENDING_COMMENT: &str = "# af-tls-pending: ";
pub(in crate::package_executor) const ACME_HTTP_EXEMPTION: &str = r#"    Alias /.well-known/acme-challenge /var/www/aetherflow-default/.well-known/acme-challenge
    <Directory /var/www/aetherflow-default/.well-known/acme-challenge>
        Options None
        AllowOverride None
        Require all granted
    </Directory>
    ProxyPass /.well-known/acme-challenge/ !
"#;
pub(in crate::package_executor) const ACME_REWRITE_GUARD: &str = r"    RewriteCond %{REQUEST_URI} !^/\.well-known/acme-challenge/
";

fn apache_gateway_address(bind_host: &str, port: &str) -> Option<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr};

    let bind_host = bind_host.trim();
    let mut address = if let Ok(address) = bind_host.parse::<SocketAddr>() {
        address
    } else {
        let host = bind_host.trim_start_matches('[').trim_end_matches(']');
        let ip = if host.is_empty() {
            IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            host.parse().ok()?
        };
        let port = match port.trim() {
            "" => 8080,
            port => port.parse().ok()?,
        };
        SocketAddr::new(ip, port)
    };
    // Apache and the API run on the same host. Keep credentials on loopback
    // even when the API listens on every interface.
    if address.ip().is_unspecified() {
        address.set_ip(match address {
            SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
            SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
        });
    }
    (address.ip().is_loopback() && address.port() != 0).then_some(address)
}

pub(crate) fn render_managed_apache_vhost(
    req: &af_models::RunnerApacheVhostRequest,
    domain: &str,
    internal: bool,
    upstream: &LibreSpeedUpstreamTlsConfig,
    fs_root: Option<&Path>,
    existing: &[&str],
    legacy: &[&str],
) -> anyhow::Result<String> {
    let mut blocks = Vec::new();
    for raw in existing.iter().chain(legacy) {
        collect_apache_custom_blocks(raw, &mut blocks);
    }
    let external = !internal && !domain.ends_with(".aether.local");
    let mut out = String::new();
    let (port, downstream_tls) = if external && req.tls_enabled {
        out.push_str(&format!(
            "<VirtualHost *:80>\n    ServerName {domain}\n{ACME_HTTP_EXEMPTION}    RewriteEngine On\n{ACME_REWRITE_GUARD}"
        ));
        let Some((cert, key)) = apache_tls_pair(domain, fs_root) else {
            out.push_str("    RewriteRule ^ - [R=503,L]\n    ErrorDocument 503 \"TLS certificate provisioning pending\"\n");
            for line in blocks.iter().flat_map(|block| block.lines()) {
                out.push_str(TLS_PENDING_COMMENT);
                out.push_str(line);
                out.push('\n');
            }
            out.push_str("</VirtualHost>\n");
            return Ok(out);
        };
        out.push_str(&format!(
            "    RewriteRule ^ https://{domain}%{{REQUEST_URI}} [R=308,L]\n</VirtualHost>\n"
        ));
        (443, format!("    SSLEngine On\n    SSLCertificateFile {cert}\n    SSLCertificateKeyFile {key}\n"))
    } else {
        (80, String::new())
    };
    let acme = external && port == 80;
    let acme_http = if acme { ACME_HTTP_EXEMPTION } else { "" };
    let acme_rewrite = if acme { ACME_REWRITE_GUARD } else { "" };
    // Standard external protected apps (including ruTorrent) route through the Rust
    // Subdomain Gateway (`x-aetherflow-external-app`). Legacy `/etc/apache2/AetherFlow/htpasswd`
    // is reserved strictly as a fallback for inherited custom Apache blocks or a
    // non-loopback `BIND_ADDR` where Apache cannot reach the gateway over loopback.
    let gateway = if external && requires_external_app_auth(&req.app_name) && blocks.is_empty() {
        let bind = env::var("BIND_ADDR")
            .or_else(|_| env::var("AETHERFLOW_BIND_ADDR"))
            .unwrap_or_default();
        apache_gateway_address(&bind, &env::var("PORT").unwrap_or_default())
            .filter(|address| i32::from(address.port()) != req.listen_port)
    } else {
        None
    };
    let auth = if internal || gateway.is_some() {
        String::new()
    } else {
        external_auth_policy_for_vhost(&req.app_name, fs_root, acme)?
    };
    let ssl_proxy = upstream
        .ca_cert_file
        .as_ref()
        .filter(|_| gateway.is_none())
        .map_or_else(String::new, |ca_cert| {
            format!(
                "    SSLProxyEngine On
    SSLProxyVerify require
    SSLProxyCACertificateFile {ca_cert}
    SSLProxyCheckPeerCN off
    SSLProxyCheckPeerName off
    SSLProxyCheckPeerExpire off
"
            )
        });
    let (native_http, native_ws) = if upstream.enabled {
        ("https", "wss")
    } else {
        ("http", "ws")
    };
    let native_addr = format!("127.0.0.1:{}", req.listen_port);
    let (http, ws, proxy_addr, gateway_headers, native_reverse) = match gateway {
        Some(address) => (
            "http",
            "ws",
            address.to_string(),
            format!(
                "    ProxyAddHeaders On
    RequestHeader unset Forwarded
    RequestHeader unset X-Forwarded-For
    RequestHeader unset X-Forwarded-Port
    RequestHeader set {GATEWAY_APP_HEADER} {}
",
                req.app_name
            ),
            format!("    ProxyPassReverse / {native_http}://{native_addr}/\n"),
        ),
        None => (
            native_http,
            native_ws,
            native_addr,
            String::new(),
            String::new(),
        ),
    };
    let proto = if internal {
        "http"
    } else {
        "expr=%{REQUEST_SCHEME}"
    };
    let guard = if internal {
        internal_rewrite_guard()
    } else {
        String::new()
    };
    let ip_policy = if internal {
        internal_network_policy()
    } else {
        String::new()
    };
    out.push_str(&format!(
        "<VirtualHost *:{port}>
    ServerName {domain}
{acme_http}{downstream_tls}{ssl_proxy}    ProxyPreserveHost On
    ProxyRequests Off
    RewriteEngine On
{guard}{acme_rewrite}    RewriteCond %{{HTTP:Upgrade}} =websocket [NC]
    RewriteRule /(.*) {ws}://{proxy_addr}/$1 [P,L]
    ProxyPass / {http}://{proxy_addr}/
    ProxyPassReverse / {http}://{proxy_addr}/
{native_reverse}{gateway_headers}    RequestHeader unset X-Real-IP
    RequestHeader unset X-Forwarded-Host
    RequestHeader unset X-Aetherflow-User
    RequestHeader unset Remote-User
    RequestHeader unset X-Forwarded-User
    RequestHeader set X-Real-IP \"%{{REMOTE_ADDR}}s\"
    RequestHeader set X-Forwarded-Proto \"{proto}\"
{ip_policy}"
    ));
    if req.app_name == "librespeed"
        && !blocks
            .iter()
            .any(|block| block.contains("/etc/aetherflow/librespeed-proxy-token.conf"))
    {
        blocks.push("    IncludeOptional /etc/aetherflow/librespeed-proxy-token.conf".to_string());
    }
    for block in blocks {
        out.push_str(&block);
        out.push('\n');
    }
    out.push_str(&auth);
    out.push_str(
        "</VirtualHost>
",
    );
    Ok(out)
}

#[cfg(test)]
#[test]
fn apache_gateway_address_uses_the_api_port_and_loopback_interface() {
    for (bind, port, expected) in [
        ("", "", Some("127.0.0.1:8080")),
        ("0.0.0.0", "18080", Some("127.0.0.1:18080")),
        ("[::]:18443", "8080", Some("[::1]:18443")),
        ("192.0.2.1", "8080", None),
        ("127.0.0.1", "0", None),
    ] {
        assert_eq!(
            apache_gateway_address(bind, port),
            expected.map(|address| address.parse().unwrap())
        );
    }
}

pub(crate) fn update_legacy_apache_vhost(
    raw: &str,
    req: &af_models::RunnerApacheVhostRequest,
    upstream: &LibreSpeedUpstreamTlsConfig,
    fs_root: Option<&Path>,
    external: bool,
) -> anyhow::Result<String> {
    update_legacy_apache_vhost_with_blocks(raw, req, upstream, fs_root, external, &[])
}

pub(in crate::package_executor) fn strip_legacy_duplicate_public_vhosts(
    raw: &str,
    domain: &str,
) -> String {
    static VHOST: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?is)<VirtualHost\s+[^>]+>.*?</VirtualHost\s*>").unwrap());
    VHOST
        .replace_all(raw, |captures: &regex::Captures<'_>| {
            let block = &captures[0];
            let is_domain = |value: &str| value.trim_matches('"').eq_ignore_ascii_case(domain);
            if block.lines().any(|line| {
                let mut words = line.split_whitespace();
                words
                    .next()
                    .is_some_and(|word| word.eq_ignore_ascii_case("ServerName"))
                    && words.next().is_some_and(is_domain)
            }) {
                return String::new();
            }
            block
                .lines()
                .filter_map(|line| {
                    let mut words = line.split_whitespace();
                    if words
                        .next()
                        .is_some_and(|word| word.eq_ignore_ascii_case("ServerAlias"))
                    {
                        let aliases: Vec<_> = words.filter(|name| !is_domain(name)).collect();
                        if aliases.is_empty() {
                            return None;
                        }
                        return Some(format!("    ServerAlias {}", aliases.join(" ")));
                    }
                    Some(line.to_owned())
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .into_owned()
}

pub(in crate::package_executor) fn update_legacy_apache_vhost_with_blocks(
    raw: &str,
    req: &af_models::RunnerApacheVhostRequest,
    upstream: &LibreSpeedUpstreamTlsConfig,
    fs_root: Option<&Path>,
    external: bool,
    blocks: &[String],
) -> anyhow::Result<String> {
    // Package reconciliation can run without the ingress row. An existing
    // managed gateway vhost must continue to let the API resolve that state.
    if external {
        let marker = format!("RequestHeader set {GATEWAY_APP_HEADER} {}", req.app_name);
        if raw.lines().any(|line| line.trim() == marker) {
            return Ok(raw.to_owned());
        }
    }
    let tls = matches!(req.app_name.as_str(), "librespeed" | "kasmvnc").then_some(upstream.enabled);
    let updated = render_or_update_runner_apache_vhost_with_ca(
        Some(raw),
        raw,
        None,
        req.listen_port,
        tls,
        upstream.ca_cert_file.as_deref(),
        blocks,
    );
    let updated = if req.tls_enabled && req.external_access_enabled {
        if let Some(domain) = req.public_domain.as_deref() {
            strip_legacy_duplicate_public_vhosts(&updated, domain)
        } else {
            updated
        }
    } else {
        updated
    };
    static VHOST_END: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)</VirtualHost\s*>").unwrap());
    let mut out = String::new();
    let mut start = 0;
    for close_tag in VHOST_END.find_iter(&updated) {
        let host = &updated[start..close_tag.end()];
        let body = &updated[start..close_tag.start()];
        start = close_tag.end();
        let internal = host.lines().any(|line| {
            let mut words = line.split_whitespace();
            words.next().is_some_and(|word| {
                word.eq_ignore_ascii_case("ServerName") || word.eq_ignore_ascii_case("ServerAlias")
            }) && words.any(|name| {
                name.trim_matches('"')
                    .to_ascii_lowercase()
                    .ends_with(".aether.local")
            })
        });
        if internal && !body.contains(&internal_network_policy()) {
            // Put the vhost rewrite guard ahead of existing proxy rules.
            let open = body
                .to_ascii_lowercase()
                .find("<virtualhost")
                .and_then(|offset| body[offset..].find('>').map(|end| offset + end + 1))
                .unwrap_or_default();
            out.push_str(&body[..open]);
            out.push_str(
                "
    RewriteEngine On
",
            );
            out.push_str(&internal_rewrite_guard());
            out.push_str(&body[open..]);
            out.push_str(&internal_network_policy());
        } else {
            out.push_str(body);
        }
        if external || (!internal && req.external_access_enabled) {
            let auth = external_auth_policy(&req.app_name, fs_root)?;
            if !body.contains(&auth) {
                out.push_str(&auth);
            }
        }
        out.push_str(close_tag.as_str());
    }
    out.push_str(&updated[start..]);
    Ok(out)
}

#[cfg(test)]
pub(in crate::package_executor) fn render_or_update_runner_apache_vhost(
    existing_raw: Option<&str>,
    default_template: &str,
    desired_server_name: Option<&str>,
    listen_port: i32,
    upstream_tls: Option<bool>,
    preserved_blocks: &[String],
) -> String {
    render_or_update_runner_apache_vhost_with_ca(
        existing_raw,
        default_template,
        desired_server_name,
        listen_port,
        upstream_tls,
        None,
        preserved_blocks,
    )
}

pub(in crate::package_executor) fn render_or_update_runner_apache_vhost_with_ca(
    existing_raw: Option<&str>,
    default_template: &str,
    desired_server_name: Option<&str>,
    listen_port: i32,
    upstream_tls: Option<bool>,
    upstream_ca_cert: Option<&str>,
    preserved_blocks: &[String],
) -> String {
    let base = match existing_raw {
        Some(raw) if raw.to_ascii_lowercase().contains("<virtualhost") => {
            let mut out_lines = Vec::new();
            for line in raw.lines() {
                let trimmed = line.trim_start();
                let indent = &line[..line.len() - trimmed.len()];
                let lower = trimmed.to_ascii_lowercase();
                if upstream_tls.is_some()
                    && (lower.starts_with("sslproxyengine ")
                        || lower.starts_with("sslproxyengine\t")
                        || lower.starts_with("sslproxyverify ")
                        || lower.starts_with("sslproxyverify\t")
                        || lower.starts_with("sslproxycacertificatefile ")
                        || lower.starts_with("sslproxycacertificatefile\t")
                        || lower.starts_with("sslproxycheckpeercn ")
                        || lower.starts_with("sslproxycheckpeercn\t")
                        || lower.starts_with("sslproxycheckpeername ")
                        || lower.starts_with("sslproxycheckpeername\t")
                        || lower.starts_with("sslproxycheckpeerexpire ")
                        || lower.starts_with("sslproxycheckpeerexpire\t"))
                {
                    continue;
                }
                if let Some(dom) = desired_server_name {
                    if lower.starts_with("servername ") || lower.starts_with("servername\t") {
                        out_lines.push(format!("{indent}ServerName {dom}"));
                        continue;
                    }
                }
                if lower.starts_with("proxypass ")
                    || lower.starts_with("proxypass\t")
                    || lower.starts_with("proxypassreverse ")
                    || lower.starts_with("proxypassreverse\t")
                    || lower.starts_with("rewriterule ")
                    || lower.starts_with("rewriterule\t")
                {
                    let tokens: Vec<String> = trimmed
                        .split_whitespace()
                        .map(|tok| {
                            rewrite_runner_apache_proxy_url_port(tok, listen_port, upstream_tls)
                                .unwrap_or_else(|| tok.to_string())
                        })
                        .collect();
                    out_lines.push(format!("{indent}{}", tokens.join(" ")));
                } else {
                    out_lines.push(line.to_string());
                }
            }
            if let (Some(true), Some(ca_cert)) = (upstream_tls, upstream_ca_cert) {
                let insert_pos = out_lines
                    .iter()
                    .position(|l| {
                        l.trim()
                            .to_ascii_lowercase()
                            .starts_with("proxypreservehost ")
                    })
                    .or_else(|| {
                        out_lines
                            .iter()
                            .position(|l| l.trim().eq_ignore_ascii_case("</virtualhost>"))
                    })
                    .unwrap_or(out_lines.len());
                let ssl_lines = vec![
                    "    SSLProxyEngine On".to_string(),
                    "    SSLProxyVerify require".to_string(),
                    format!("    SSLProxyCACertificateFile {ca_cert}"),
                    "    SSLProxyCheckPeerCN off".to_string(),
                    "    SSLProxyCheckPeerName off".to_string(),
                    "    SSLProxyCheckPeerExpire off".to_string(),
                ];
                out_lines.splice(insert_pos..insert_pos, ssl_lines);
            }
            let mut joined = out_lines.join("\n");
            joined.push('\n');
            joined
        }
        _ => default_template.to_string(),
    };

    if preserved_blocks.is_empty() {
        return base;
    }

    let mut missing = Vec::new();
    for block in preserved_blocks {
        let trimmed_block = block.trim();
        if !trimmed_block.is_empty() && !base.contains(trimmed_block) {
            missing.push(block.clone());
        }
    }
    if missing.is_empty() {
        return base;
    }

    let mut final_lines = Vec::new();
    let mut inserted = false;
    for line in base.lines() {
        if !inserted && line.trim().eq_ignore_ascii_case("</virtualhost>") {
            for block in &missing {
                final_lines.push(block.clone());
            }
            inserted = true;
        }
        final_lines.push(line.to_string());
    }
    if !inserted {
        for block in &missing {
            final_lines.push(block.clone());
        }
    }
    let mut out = final_lines.join("\n");
    out.push('\n');
    out
}

pub(in crate::package_executor) fn verify_runner_apache_configtest() -> Result<(), String> {
    for bin in [
        "/usr/sbin/apache2ctl",
        "/usr/sbin/apachectl",
        "apache2ctl",
        "apachectl",
    ] {
        match std::process::Command::new(bin).arg("-t").output() {
            Ok(out) => {
                if out.status.success() {
                    return Ok(());
                }
                let stderr = String::from_utf8_lossy(&out.stderr);
                let stdout = String::from_utf8_lossy(&out.stdout);
                return Err(format!("{} {}", stderr.trim(), stdout.trim())
                    .trim()
                    .to_string());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(format!("failed to execute {}: {}", bin, err)),
        }
    }
    Err("no Apache configtest command is available".to_string())
}
