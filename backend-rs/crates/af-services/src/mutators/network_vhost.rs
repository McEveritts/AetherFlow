use super::*;

pub(super) fn validate_dns_domain(domain: &str) -> Result<String, String> {
    let clean = domain.trim().to_lowercase();
    if clean.is_empty() || clean.len() > 253 {
        return Err(format!("invalid domain length: {:?}", domain));
    }
    if clean
        .chars()
        .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        || clean.starts_with('.')
        || clean.ends_with('.')
        || clean.contains("..")
    {
        return Err(format!("invalid domain format: {:?}", domain));
    }
    Ok(clean)
}

pub fn detect_lan_ip_strict() -> Result<String, String> {
    if let Ok(raw_val) = env::var("AETHERFLOW_LAN_IP") {
        af_runner::validate_hosts_ip(&raw_val)
            .map_err(|e| format!("Invalid AETHERFLOW_LAN_IP: {e}"))?;
        return Ok(raw_val);
    }
    if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if socket.connect("1.1.1.1:80").is_ok() {
            if let Ok(std::net::SocketAddr::V4(addr)) = socket.local_addr() {
                let ip = addr.ip();
                if !ip.is_loopback() && !ip.is_unspecified() {
                    return Ok(ip.to_string());
                }
            }
        }
    }
    Ok("127.0.0.1".to_string())
}

pub fn detect_lan_ip() -> String {
    detect_lan_ip_strict().unwrap_or_else(|_| "127.0.0.1".to_string())
}

pub fn remove_dns_provider_domain(domain: &str) -> Result<(), String> {
    af_runner::remove_dns_provider_domain(domain).map_err(|e| e.to_string())
}

pub fn update_pihole_custom_list(
    custom_list_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    af_runner::validate_hosts_ip(lan_ip)
        .map_err(|e| format!("Invalid LAN IP for Pi-hole custom list: {e}"))?;

    let existing = match af_runner::read_dns_provider_text(custom_list_path, true) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "failed to read Pi-hole custom.list {}: {}",
                custom_list_path.display(),
                e
            ))
        }
    };

    let content =
        af_runner::reconcile_pihole_custom_list_content(&existing, lan_ip, domains, false);
    if content == existing && custom_list_path.exists() {
        return Ok(());
    }
    af_runner::write_dns_provider_text(custom_list_path, &content, true)
        .map_err(|error| error.to_string())
}

pub fn update_dnsmasq_conf(
    dnsmasq_conf_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    af_runner::validate_hosts_ip(lan_ip)
        .map_err(|e| format!("Invalid LAN IP for dnsmasq config: {e}"))?;

    let existing = match af_runner::read_dns_provider_text(dnsmasq_conf_path, false) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "failed to read dnsmasq config {}: {}",
                dnsmasq_conf_path.display(),
                e
            ))
        }
    };
    let mut managed: BTreeSet<String> = BTreeSet::new();

    for line in existing.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("address=/") {
            if let Some((dom, _ip)) = rest.split_once('/') {
                if !dom.trim().is_empty() {
                    managed.insert(dom.trim().to_lowercase());
                }
            }
        }
    }

    for d in domains {
        managed.insert(d.to_lowercase());
    }

    let mut lines = vec!["# Automatically managed by AetherFlow Blueprint Engine".to_string()];
    for dom in &managed {
        lines.push(format!("address=/{}/{}", dom, lan_ip));
    }
    let content = format!("{}\n", lines.join("\n"));
    if content == existing && dnsmasq_conf_path.exists() {
        return Ok(());
    }
    af_runner::write_dns_provider_text(dnsmasq_conf_path, &content, false)
        .map_err(|error| error.to_string())
}

pub fn update_dnsmasq_config(
    dnsmasq_conf_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    update_dnsmasq_conf(dnsmasq_conf_path, lan_ip, domains)
}

pub fn update_pihole_toml_hosts(
    toml_path: &Path,
    lan_ip: &str,
    domains: &[String],
) -> Result<(), String> {
    af_runner::validate_hosts_ip(lan_ip)
        .map_err(|e| format!("Invalid LAN IP for Pi-hole pihole.toml: {e}"))?;
    if !toml_path.is_file() {
        return Ok(());
    }
    let existing = af_runner::read_dns_provider_text(toml_path, true)
        .map_err(|e| format!("failed to read {}: {}", toml_path.display(), e))?;

    let normalized_domains: BTreeSet<String> = domains
        .iter()
        .map(|d| d.trim().to_lowercase())
        .filter(|d| !d.is_empty())
        .collect();

    let lines: Vec<String> = existing.lines().map(|l| l.to_string()).collect();
    let mut current_section = String::new();
    let mut dns_start: Option<usize> = None;
    let mut dns_end: usize = lines.len();
    let mut hosts_range: Option<(usize, usize)> = None;
    let mut in_multiline_hosts = false;
    let mut multiline_start = 0usize;

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if in_multiline_hosts {
            if trimmed.contains(']') {
                hosts_range = Some((multiline_start, idx + 1));
                in_multiline_hosts = false;
            }
            continue;
        }
        if trimmed.starts_with('[') && !trimmed.starts_with("[[") {
            if let Some(end) = trimmed.find(']') {
                let sec = trimmed[1..end].trim().to_string();
                if current_section == "dns" && dns_end == lines.len() {
                    dns_end = idx;
                }
                current_section = sec.clone();
                if sec == "dns" && dns_start.is_none() {
                    dns_start = Some(idx);
                }
                continue;
            }
        }
        if current_section == "dns" {
            if let Some(rest) = trimmed.strip_prefix("hosts") {
                let after = rest.trim_start();
                if after.starts_with('=') {
                    if after.contains('[') && after.contains(']') {
                        hosts_range = Some((idx, idx + 1));
                    } else if after.contains('[') {
                        multiline_start = idx;
                        in_multiline_hosts = true;
                    }
                }
            }
        }
    }

    let mut preserved_entries: Vec<String> = Vec::new();
    if let Some((start, end)) = hosts_range {
        let block = lines[start..end].join("\n");
        if let (Some(open), Some(close)) = (block.find('['), block.rfind(']')) {
            let inner = &block[open + 1..close];
            let re_entry = Regex::new(r#""([^"]*)""#).unwrap();
            for cap in re_entry.captures_iter(inner) {
                let entry = cap[1].trim();
                let mut parts = entry.split_whitespace();
                let _ip_part = parts.next();
                let dom_part = parts.next().map(|d| d.to_lowercase());
                if let Some(dom) = dom_part {
                    if !normalized_domains.contains(&dom) && !dom.ends_with(".aether.local") {
                        preserved_entries.push(entry.to_string());
                    }
                }
            }
        }
    }

    for dom in &normalized_domains {
        preserved_entries.push(format!("{lan_ip} {dom}"));
    }

    let rendered_hosts = if preserved_entries.is_empty() {
        "  hosts = []".to_string()
    } else {
        let items: Vec<String> = preserved_entries
            .iter()
            .map(|e| format!("    \"{}\"", e.replace('\"', "\\\"")))
            .collect();
        format!("  hosts = [\n{}\n  ]", items.join(",\n"))
    };

    let mut out_lines = lines.clone();
    if let Some((start, end)) = hosts_range {
        out_lines.splice(start..end, std::iter::once(rendered_hosts));
    } else if dns_start.is_some() {
        out_lines.insert(dns_end, rendered_hosts);
    } else {
        out_lines.push(String::new());
        out_lines.push("[dns]".to_string());
        out_lines.push(rendered_hosts);
    }

    let mut content = out_lines.join("\n");
    if existing.ends_with('\n') || !content.is_empty() {
        content.push('\n');
    }
    if content == existing {
        return Ok(());
    }
    af_runner::write_dns_provider_text(toml_path, &content, true).map_err(|error| error.to_string())
}

/// Synchronizes internal `.aether.local` (and configured public) domains into:
/// 1. `/etc/hosts` (via `af_runner::update_hosts_file_local` or atomic local fallback),
/// 2. `/etc/dnsmasq.d/05-aetherflow-dns.conf` if `/etc/dnsmasq.d` exists (cleaning up legacy duplicates),
/// 3. `/etc/pihole/custom.list` and `/etc/pihole/pihole.toml` (when present) if `/etc/pihole` exists.
pub async fn sync_local_dns_domains(domains: &[String]) -> Result<(), String> {
    if domains.is_empty() {
        return Ok(());
    }

    let lan_ip = detect_lan_ip_strict()?;
    af_runner::validate_hosts_ip(&lan_ip).map_err(|e| format!("Invalid LAN IP: {e}"))?;

    let mut validated: Vec<String> = Vec::with_capacity(domains.len());
    let mut aether_local_domains: Vec<String> = Vec::new();
    for d in domains {
        let clean = validate_dns_domain(d)?;
        if clean.ends_with(".aether.local") {
            aether_local_domains.push(clean.clone());
        }
        validated.push(clean);
    }

    #[cfg(unix)]
    let is_root = {
        extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() == 0 }
    };
    #[cfg(not(unix))]
    let is_root = false;

    let test_override = env::var("AF_HOSTS_FILE").is_ok()
        || env::var("AETHERFLOW_HOSTS_FILE").is_ok()
        || env::var("AETHERFLOW_DNSMASQ_DIR").is_ok()
        || env::var("AETHERFLOW_PIHOLE_DIR").is_ok()
        || env::var("AETHERFLOW_FS_ROOT").is_ok()
        || env::var("AETHERFLOW_CONFIG_ROOT").is_ok();

    if is_root || test_override {
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            // 1. Update /etc/hosts for .aether.local domains locally
            if !aether_local_domains.is_empty() {
                af_runner::update_hosts_file(&aether_local_domains, "127.0.0.1")
                    .map_err(|e| format!("Local DNS synchronization failed: {e}"))?;
            }

            // 2. Consolidate onto canonical /etc/dnsmasq.d/05-aetherflow-dns.conf if directory exists
            let dnsmasq_dir = env::var("AETHERFLOW_DNSMASQ_DIR")
                .ok()
                .map(|s| PathBuf::from(s.trim()))
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| resolve_config_path("/etc/dnsmasq.d"));

            if af_runner::dns_provider_directory_exists(&dnsmasq_dir, false)
                .map_err(|error| error.to_string())?
            {
                let custom_dns_path = dnsmasq_dir.join("05-aetherflow-dns.conf");
                let mut consolidated_domains = validated.clone();
                for legacy_name in ["aetherflow-local.conf", "aetherflow-local-dns.conf"] {
                    let legacy_path = dnsmasq_dir.join(legacy_name);
                    if let Ok(legacy_raw) = af_runner::read_dns_provider_text(&legacy_path, false) {
                        for line in legacy_raw.lines() {
                            if let Some(rest) = line.trim().strip_prefix("address=/") {
                                if let Some((dom, _ip)) = rest.split_once('/') {
                                    let clean = dom.trim().to_lowercase();
                                    if !clean.is_empty() && !consolidated_domains.contains(&clean) {
                                        consolidated_domains.push(clean);
                                    }
                                }
                            }
                        }
                    }
                }
                update_dnsmasq_conf(&custom_dns_path, &lan_ip, &consolidated_domains)?;
                for legacy_name in ["aetherflow-local.conf", "aetherflow-local-dns.conf"] {
                    let legacy_path = dnsmasq_dir.join(legacy_name);
                    af_runner::remove_dns_provider_file(&legacy_path).map_err(|error| {
                        format!("cannot remove legacy dnsmasq configuration: {error}")
                    })?;
                }
            }

            // 3. Write Pi-hole custom.list and pihole.toml (v6) if /etc/pihole exists
            let pihole_dir = env::var("AETHERFLOW_PIHOLE_DIR")
                .ok()
                .map(|s| PathBuf::from(s.trim()))
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| resolve_config_path("/etc/pihole"));

            if af_runner::dns_provider_directory_exists(&pihole_dir, true)
                .map_err(|error| error.to_string())?
            {
                let custom_list = pihole_dir.join("custom.list");
                update_pihole_custom_list(&custom_list, &lan_ip, &validated)?;
                let pihole_toml = pihole_dir.join("pihole.toml");
                if pihole_toml.is_file() {
                    update_pihole_toml_hosts(&pihole_toml, &lan_ip, &validated)?;
                }
            }
            af_runner::sync_adguard_dns(&lan_ip, &validated, false)
                .map_err(|err| format!("AdGuard Home synchronization failed: {err}"))
        })
        .await
        .map_err(|err| err.to_string())??;
    } else {
        run_privileged_hosts_command_with_provider(
            "update",
            "127.0.0.1",
            &aether_local_domains,
            Some(&lan_ip),
            Some(&validated),
        )
        .await?;
    }

    Ok(())
}

/// Fully reconciles internal `.aether.local` domains in `/etc/hosts` against the authoritative complete list of active domains.
pub async fn reconcile_local_dns_domains(authoritative_domains: &[String]) -> Result<(), String> {
    let lan_ip = detect_lan_ip_strict()?;
    af_runner::validate_hosts_ip(&lan_ip).map_err(|e| format!("Invalid LAN IP: {e}"))?;

    let mut aether_local_domains: Vec<String> = Vec::new();
    let mut validated_authoritative: Vec<String> = Vec::with_capacity(authoritative_domains.len());
    for d in authoritative_domains {
        let clean = validate_dns_domain(d)?;
        if clean.ends_with(".aether.local") {
            aether_local_domains.push(clean.clone());
        }
        validated_authoritative.push(clean);
    }

    #[cfg(unix)]
    let is_root = {
        extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() == 0 }
    };
    #[cfg(not(unix))]
    let is_root = false;

    let test_override = env::var("AF_HOSTS_FILE").is_ok()
        || env::var("AETHERFLOW_HOSTS_FILE").is_ok()
        || env::var("AETHERFLOW_DNSMASQ_DIR").is_ok()
        || env::var("AETHERFLOW_PIHOLE_DIR").is_ok()
        || env::var("AETHERFLOW_FS_ROOT").is_ok()
        || env::var("AETHERFLOW_CONFIG_ROOT").is_ok();

    if is_root || test_override {
        tokio::task::spawn_blocking(move || -> Result<(), String> {
            af_runner::reconcile_hosts_file(&aether_local_domains, "127.0.0.1")
                .map_err(|e| format!("Local DNS reconciliation failed: {e}"))?;
            af_runner::sync_dns_provider_files(&lan_ip, &validated_authoritative)
                .map_err(|e| format!("Local DNS provider synchronization failed: {e}"))
        })
        .await
        .map_err(|err| err.to_string())??;
    } else {
        run_privileged_hosts_command_with_provider(
            "reconcile",
            "127.0.0.1",
            &aether_local_domains,
            Some(&lan_ip),
            Some(&validated_authoritative),
        )
        .await?;
    }

    Ok(())
}

/// Executes privileged hosts manipulation via the privileged runner socket daemon.
pub async fn run_privileged_hosts_command(
    action: &str,
    ip: &str,
    domains: &[String],
) -> Result<(), String> {
    run_privileged_hosts_command_with_provider(action, ip, domains, None, None).await
}

pub async fn run_privileged_hosts_command_with_provider(
    action: &str,
    ip: &str,
    domains: &[String],
    provider_ip: Option<&str>,
    provider_domains: Option<&[String]>,
) -> Result<(), String> {
    match action {
        "reconcile" => af_runner::dispatch_hosts_reconcile_with_provider(
            domains,
            ip,
            provider_ip,
            provider_domains,
        )
        .await
        .map_err(|e| format!("privileged runner hosts reconcile failed: {e}")),
        "remove" => af_runner::dispatch_hosts_remove(domains)
            .await
            .map_err(|e| format!("privileged runner hosts remove failed: {e}")),
        _ => af_runner::dispatch_hosts_update_with_provider(domains, provider_ip, provider_domains)
            .await
            .map_err(|e| format!("privileged runner hosts update failed: {e}")),
    }
}

/// Collects all active internal (`.aether.local`) and external (`public_domain` / `<app>.<baseDomain>`)
/// domains for installed apps and synchronizes them to `/etc/hosts`, Pi-hole `custom.list`, and `dnsmasq.d`.
pub async fn sync_network_dns_providers() -> Result<bool, String> {
    let mut domain_set: BTreeSet<String> = BTreeSet::new();
    let base_domain = crate::resolve_base_domain();

    let configs = af_db::get_all_app_ingress_configs().map_err(|error| error.to_string())?;
    let mut configured_public_apps: std::collections::HashSet<String> =
        std::collections::HashSet::new();
    {
        for cfg in configs {
            let app_key = cfg.app_name.trim().to_ascii_lowercase();
            if !app_key.is_empty() {
                domain_set.insert(crate::resolve_app_internal_domain(&cfg.app_name));
            }
            if !cfg.public_domain.trim().is_empty() {
                if !app_key.is_empty() {
                    configured_public_apps.insert(app_key);
                }
                domain_set.insert(cfg.public_domain.trim().to_lowercase());
            } else if !base_domain.is_empty() && cfg.listen_port > 0 {
                let pub_dom = crate::format_app_public_domain(&cfg.app_name, &base_domain);
                if !pub_dom.is_empty() {
                    if !app_key.is_empty() {
                        configured_public_apps.insert(app_key);
                    }
                    domain_set.insert(pub_dom);
                }
            }
        }
    }

    let retained_apps: std::collections::HashSet<String> = af_db::list_retained_app_ingress_names()
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|app| app.trim().to_ascii_lowercase())
        .collect();

    let pkgs = crate::get_packages().map_err(|error| error.to_string())?;
    {
        for p in pkgs {
            if p.status != "installed" {
                continue;
            }
            let app_key = p.name.trim().to_ascii_lowercase();
            if let Some(bp) = crate::get_blueprint(&p.name) {
                if !bp.internal_domain.trim().is_empty() {
                    domain_set.insert(bp.internal_domain.trim().to_lowercase());
                } else {
                    domain_set.insert(format!("{}.aether.local", p.name.to_lowercase()));
                }
                if !base_domain.is_empty()
                    && bp.default_port > 0
                    && !configured_public_apps.contains(&app_key)
                    && !retained_apps.contains(&app_key)
                {
                    let pub_dom = crate::format_app_public_domain(&p.name, &base_domain);
                    if !pub_dom.is_empty() {
                        domain_set.insert(pub_dom);
                    }
                }
            }
        }
    }

    // Always keep the core domain so removing the last app clears stale
    // managed DNS entries instead of skipping synchronization entirely.
    domain_set.insert("aetherflow.aether.local".into());

    let domains: Vec<String> = domain_set.into_iter().collect();
    reconcile_local_dns_domains(&domains).await?;
    sync_local_dns_domains(&domains).await?;
    Ok(true)
}

/// Synchronous compatibility entry point for callers outside an async runtime.
pub fn sync_apache_app_vhost(
    app_name: &str,
    listen_port: i32,
    internal_domain: &str,
    public_domain: &str,
    external_access: bool,
) -> Result<bool, String> {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        if runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| {
                runtime.block_on(sync_apache_app_vhost_async(
                    app_name,
                    listen_port,
                    internal_domain,
                    public_domain,
                    external_access,
                ))
            });
        }
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| err.to_string())?
                    .block_on(sync_apache_app_vhost_async(
                        app_name,
                        listen_port,
                        internal_domain,
                        public_domain,
                        external_access,
                    ))
            })
            .join()
            .map_err(|_| "Apache vhost worker panicked".to_string())?
    })
}

pub async fn sync_apache_app_vhost_async(
    app_name: &str,
    listen_port: i32,
    internal_domain: &str,
    public_domain: &str,
    external_access: bool,
) -> Result<bool, String> {
    let app = app_name.to_owned();
    let ingress = tokio::task::spawn_blocking(move || af_db::get_app_ingress_config(&app))
        .await
        .map_err(|err| err.to_string())?;
    let tls_enabled = match ingress {
        Ok(ingress) => ingress.is_some_and(|ingress| ingress.tls_enabled),
        Err(_) if af_runner::blueprint::has_config_root() => false,
        Err(error) => return Err(error.to_string()),
    };
    if listen_port <= 0 {
        return Ok(false);
    }
    sync_apache_app_vhost_with_tls(
        app_name,
        listen_port,
        internal_domain,
        public_domain,
        external_access,
        tls_enabled,
    )
    .await
    .map_err(|err| err.to_string())?;
    Ok(true)
}

pub(super) async fn sync_apache_app_vhost_with_tls(
    app_name: &str,
    listen_port: i32,
    internal_domain: &str,
    public_domain: &str,
    external_access: bool,
    tls_enabled: bool,
) -> anyhow::Result<()> {
    if listen_port <= 0 {
        return Ok(());
    }
    let apache_dir = resolve_config_path("/etc/apache2");
    let req = af_models::RunnerApacheVhostRequest {
        app_name: app_name.to_string(),
        listen_port,
        internal_domain: (!internal_domain.is_empty()).then(|| internal_domain.to_string()),
        public_domain: (!public_domain.is_empty()).then(|| public_domain.to_string()),
        external_access_enabled: external_access,
        tls_enabled,
        reload_apache: true,
        ..Default::default()
    };

    if apache_dir == Path::new("/etc/apache2")
        && (unsafe { libc::geteuid() } != 0 || af_runner::is_runner_available())
    {
        af_runner::sync_apache_vhost_via_runner(&req).await?;
    } else {
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            runtime.block_on(af_runner::sync_apache_vhost_local(&req, &apache_dir))
        })
        .await??;
    }
    Ok(())
}

async fn remove_apache_app_vhost_inner(app_name: &str) -> anyhow::Result<bool> {
    let app_name_owned = app_name.to_owned();
    let Some((clean_app, apache_dir)) = tokio::task::spawn_blocking(move || {
        let clean_app = af_models::resolve_package_lock_name(&app_name_owned);
        af_runner::get_runner_package_definition(clean_app)?;
        let apache_dir = resolve_config_path("/etc/apache2");
        let avail_dir = apache_dir.join("sites-available");
        let enabled_dir = apache_dir.join("sites-enabled");
        if !avail_dir.exists()
            && !enabled_dir.exists()
            && (apache_dir != Path::new("/etc/apache2")
                || matches!(
                    fs::symlink_metadata(&apache_dir),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound
                ))
        {
            return None;
        }

        let managed_names = [
            format!("aetherflow-app-{clean_app}.conf"),
            format!("aetherflow-ext-{clean_app}.conf"),
            format!("aetherflow-ext-{clean_app}-le-ssl.conf"),
        ];
        let has_managed_or_unreadable = managed_names.iter().any(|name| {
            [avail_dir.join(name), enabled_dir.join(name)]
                .iter()
                .any(|path| {
                    !matches!(
                        fs::symlink_metadata(path),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound
                    )
                })
        });
        if !has_managed_or_unreadable {
            return None;
        }
        Some((clean_app.to_string(), apache_dir))
    })
    .await?
    else {
        return Ok(false);
    };

    let req = af_models::RunnerApacheVhostRequest {
        app_name: clean_app,
        remove_only: true,
        reload_apache: apache_dir == Path::new("/etc/apache2"),
        ..Default::default()
    };

    if apache_dir == Path::new("/etc/apache2")
        && (unsafe { libc::geteuid() } != 0 || af_runner::is_runner_available())
    {
        af_runner::sync_apache_vhost_via_runner(&req).await?;
    } else {
        af_runner::sync_apache_vhost_local(&req, &apache_dir).await?;
    }
    Ok(true)
}

/// Removes AetherFlow-managed Apache vhost files and symlinks (`aetherflow-app-<app>.conf`,
/// `aetherflow-ext-<app>.conf`, `aetherflow-ext-<app>-le-ssl.conf`) for `app_name` during package
/// removal, preserving legacy `<app>.conf` and other applications' vhosts.
pub async fn remove_apache_app_vhost(app_name: &str) -> anyhow::Result<()> {
    remove_apache_app_vhost_inner(app_name).await.map(|_| ())
}

pub async fn remove_apache_app_vhost_async(app_name: &str) -> Result<bool, String> {
    remove_apache_app_vhost_inner(app_name)
        .await
        .map_err(|err| err.to_string())
}

/// Triggers certificate synchronization via the privileged runner `/v1/certbot-sync`,
/// falling back to `/usr/local/bin/af-certbot-sync` only when running directly as root.
pub async fn trigger_apache_cert_sync() {
    if af_runner::is_runner_available() {
        if let Err(err) = af_runner::trigger_certbot_sync_via_runner().await {
            tracing::warn!(error = %err, "runner certbot-sync failed");
        }
    } else if unsafe { libc::geteuid() } == 0 {
        if let Err(err) = af_runner::sync_certbot_and_managed_ingress().await {
            tracing::warn!(error = %err, "direct certbot-sync failed");
        }
    }
}

/// Reconciles installed app routes at startup using saved ingress settings.
pub async fn provision_all_installed_app_subdomains() -> usize {
    provision_installed_app_subdomains(&crate::resolve_base_domain()).await
}

pub(super) async fn provision_installed_app_subdomains(base_domain: &str) -> usize {
    match with_blueprint_admission(async {
        provision_installed_app_subdomains_admitted(base_domain)
            .await
            .map_err(anyhow::Error::msg)
    })
    .await
    {
        Ok(count) => count,
        Err(error) => {
            tracing::error!(detail = %format!("{error:#}"), "installed application subdomain synchronization failed");
            0
        }
    }
}

pub(super) async fn provision_installed_app_subdomains_admitted(
    base_domain: &str,
) -> Result<usize, String> {
    let norm_base = af_db::normalize_base_domain(base_domain);
    let mut updated_count = 0usize;

    let existing_map: HashMap<String, af_models::AppIngressConfig> =
        af_db::get_all_app_ingress_configs()
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|c| (c.app_name.clone(), c))
            .collect();

    let pkgs = crate::get_packages().map_err(|error| error.to_string())?;
    for package in &pkgs {
        if package.status == "installed" {
            with_blueprint_mutation(&package.name, async { Ok(()) })
                .await
                .map_err(|error| format!("{error:#}"))?;
        }
    }
    for package in pkgs
        .iter()
        .filter(|p| p.status == "installed" && p.default_port > 0)
    {
        let existing = existing_map.get(&package.name);
        let cfg = startup_app_ingress_config(package, &norm_base, existing);
        sync_apache_app_vhost_with_tls(
            &cfg.app_name,
            cfg.listen_port,
            &crate::resolve_app_internal_domain(&cfg.app_name),
            &cfg.public_domain,
            cfg.external_access_enabled,
            cfg.tls_enabled,
        )
        .await
        .map_err(|err| err.to_string())?;
        if existing != Some(&cfg) {
            af_db::set_app_ingress_config(&cfg).map_err(|error| error.to_string())?;
        }
        updated_count += 1;
    }

    sync_network_dns_providers().await?;
    trigger_apache_cert_sync().await;
    Ok(updated_count)
}

pub(super) fn startup_app_ingress_config(
    package: &af_models::Package,
    base_domain: &str,
    existing: Option<&AppIngressConfig>,
) -> AppIngressConfig {
    let mut config = existing.cloned().unwrap_or_else(|| AppIngressConfig {
        app_name: package.name.clone(),
        ..Default::default()
    });
    if config.public_domain.trim().is_empty() && !base_domain.is_empty() {
        config.public_domain = crate::format_app_public_domain(&package.name, base_domain);
    }
    if config.listen_port <= 0 {
        config.listen_port = package.default_port;
    }
    config
}
