use super::*;

pub fn validate_hosts_domain(domain: &str) -> Result<String, RunnerError> {
    if domain.is_empty()
        || domain != domain.trim()
        || domain.len() > 253
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
        || domain.chars().any(|c| {
            matches!(
                c,
                ' ' | '\t' | '\r' | '\n' | ';' | '"' | '\'' | '$' | '`' | '\\'
            )
        })
        || domain
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    {
        return Err(RunnerError::InvalidRequest(format!(
            "invalid domain format: {:?}",
            domain
        )));
    }
    Ok(domain.to_string())
}

pub async fn apply_hosts_update(req: HostsUpdateRequest) -> Result<RunnerResponse, RunnerError> {
    tokio::task::spawn_blocking(move || apply_hosts_update_local(req))
        .await
        .map_err(anyhow::Error::from)?
}

fn apply_hosts_update_local(req: HostsUpdateRequest) -> Result<RunnerResponse, RunnerError> {
    let mut domains = req.domains.clone();
    if domains.is_empty() && !req.domain.is_empty() {
        domains.push(req.domain.clone());
    }
    let is_reconcile = req.action.eq_ignore_ascii_case("reconcile");
    let is_remove = req.action.eq_ignore_ascii_case("remove");
    if domains.is_empty() && !is_reconcile {
        return Err(RunnerError::InvalidRequest(
            "no domains specified".to_string(),
        ));
    }

    let ip = if !req.ip.is_empty() {
        validate_hosts_ip(&req.ip)?;
        req.ip.as_str()
    } else {
        "127.0.0.1"
    };

    let mut validated_domains = Vec::with_capacity(domains.len());
    for d in &domains {
        let val = validate_hosts_domain(d)?;
        validated_domains.push(val);
    }

    let effective_provider_ip = if let Some(ref pip) = req.provider_ip {
        validate_hosts_ip(pip)?;
        pip.as_str()
    } else {
        ip
    };

    let mut validated_provider_domains = Vec::new();
    if let Some(ref pdomains) = req.provider_domains {
        for d in pdomains {
            let val = validate_hosts_domain(d)?;
            validated_provider_domains.push(val);
        }
    }
    let effective_provider_domains: &[String] = if req.provider_domains.is_some() {
        &validated_provider_domains
    } else {
        &validated_domains
    };

    if is_reconcile {
        reconcile_hosts_file(&validated_domains, ip)?;
        sync_dns_provider_files_with_mode(effective_provider_ip, effective_provider_domains, true)
            .map_err(RunnerError::from)?;
        Ok(RunnerResponse {
            success: true,
            output: "hosts reconciled".to_string(),
            error: String::new(),
        })
    } else if is_remove {
        update_hosts_file_local(&validated_domains, true).map_err(RunnerError::from)?;
        remove_dns_provider_files(effective_provider_domains).map_err(RunnerError::from)?;
        Ok(RunnerResponse {
            success: true,
            output: "hosts updated".to_string(),
            error: String::new(),
        })
    } else {
        update_hosts_file(&validated_domains, ip)?;
        sync_dns_provider_files_with_mode(effective_provider_ip, effective_provider_domains, false)
            .map_err(RunnerError::from)?;
        Ok(RunnerResponse {
            success: true,
            output: "hosts updated".to_string(),
            error: String::new(),
        })
    }
}

pub(crate) async fn handle_hosts(
    Json(req): Json<HostsRunnerRequest>,
) -> (StatusCode, Json<RunnerResponse>) {
    match apply_hosts_update(req).await {
        Ok(resp) => (StatusCode::OK, Json(resp)),
        Err(e) => {
            let status = match e {
                RunnerError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(RunnerResponse {
                    success: false,
                    output: String::new(),
                    error: e.to_string(),
                }),
            )
        }
    }
}

pub fn filter_hosts_line<F>(line: &str, should_filter_host: F) -> Option<String>
where
    F: Fn(&str) -> bool,
{
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Some(line.to_string());
    }

    // Split off trailing comment if present
    let (body, comment) = match line.split_once('#') {
        Some((b, c)) => (b, Some(c)),
        None => (line, None),
    };

    let mut tokens = body.split_whitespace();
    let ip = match tokens.next() {
        Some(ip) => ip,
        None => return Some(line.to_string()),
    };

    let remaining_hosts: Vec<&str> = tokens.filter(|host| !should_filter_host(host)).collect();

    if remaining_hosts.is_empty() {
        if let Some(c) = comment {
            let inline_comment = format!("#{}", c);
            let trimmed_comment = inline_comment.trim_start();
            if trimmed_comment != "#" && !trimmed_comment[1..].trim().is_empty() {
                return Some(trimmed_comment.to_string());
            }
        }
        None
    } else {
        let hosts_str = remaining_hosts.join("\t");
        let line_content = format!("{}\t{}", ip, hosts_str);
        if let Some(c) = comment {
            Some(format!("{} #{}", line_content, c))
        } else {
            Some(line_content)
        }
    }
}

pub fn remove_hosts_file_at_path(hosts_path: &Path, domains: &[String]) -> anyhow::Result<()> {
    update_hosts_file_at_path(hosts_path, domains, true)
}

pub(crate) fn resolve_hosts_lock_path(hosts_path: &Path) -> PathBuf {
    if hosts_path == Path::new("/etc/hosts") {
        // A shared sticky /var/lock may contain a user-owned legacy lock.
        // Linux protected_regular rejects O_CREAT on that file even for root.
        // Use the runner's protected runtime directory and verified lock opener.
        PathBuf::from("/run/aetherflow/hosts.lock")
    } else {
        hosts_path.with_extension("lock")
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RunnerError {
    #[error("{0}")]
    InvalidRequest(String),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn validate_hosts_ip(ip: &str) -> Result<std::net::IpAddr, RunnerError> {
    if ip.is_empty() || ip != ip.trim() || ip.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(RunnerError::InvalidRequest(
            "Invalid IP address for hosts modification".into(),
        ));
    }
    ip.parse::<std::net::IpAddr>().map_err(|_| {
        RunnerError::InvalidRequest("Invalid IP address for hosts modification".into())
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostsModifyAction<'a> {
    Update { ip: &'a str },
    Remove,
    Reconcile { ip: &'a str },
}

pub fn modify_hosts_file_at_path(
    hosts_path: &Path,
    lock_path: &Path,
    domains: &[String],
    action: HostsModifyAction,
) -> Result<(), RunnerError> {
    let canonical_ip_opt = match action {
        HostsModifyAction::Update { ip } | HostsModifyAction::Reconcile { ip } => {
            let validated_ip = validate_hosts_ip(ip)?;
            let canonical_ip = validated_ip.to_string();
            Some(canonical_ip)
        }
        HostsModifyAction::Remove => None,
    };
    let hosts_lock =
        af_host::HostMaintenanceLockGuard::acquire(lock_path, std::time::Duration::from_secs(10))
            .map_err(|e| {
            anyhow::anyhow!(
                "failed to acquire hosts lock {}: {}",
                lock_path.display(),
                e
            )
        })?;

    let existing = match read_confined_text(hosts_path, &[]) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "failed to read hosts file {}: {}",
                hosts_path.display(),
                e
            )
            .into());
        }
    };

    let is_start_marker = |t: &str| -> bool {
        t == "# BEGIN AETHERFLOW MANAGED BLOCK" || t == "# --- AETHERFLOW INTERNAL DNS ---"
    };
    let is_end_marker = |t: &str| -> bool {
        t == "# END AETHERFLOW MANAGED BLOCK" || t == "# --- END AETHERFLOW INTERNAL DNS ---"
    };

    let chosen_start_marker = if existing.contains("# --- AETHERFLOW INTERNAL DNS ---") {
        "# --- AETHERFLOW INTERNAL DNS ---"
    } else {
        "# BEGIN AETHERFLOW MANAGED BLOCK"
    };
    let chosen_end_marker = if existing.contains("# --- END AETHERFLOW INTERNAL DNS ---") {
        "# --- END AETHERFLOW INTERNAL DNS ---"
    } else {
        "# END AETHERFLOW MANAGED BLOCK"
    };

    let mut outside_lines: Vec<String> = Vec::new();
    let mut managed_comments: Vec<String> = Vec::new();
    let mut existing_managed: Vec<(String, String)> = Vec::new(); // (domain, ip)
    let mut in_block = false;

    for line in existing.lines() {
        let trimmed = line.trim();
        if is_start_marker(trimmed) {
            in_block = true;
            continue;
        }
        if is_end_marker(trimmed) {
            in_block = false;
            continue;
        }

        if in_block {
            if trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with('#') {
                managed_comments.push(line.to_string());
                continue;
            }

            let (code_part, comment_opt) = match line.split_once('#') {
                Some((b, c)) => (b.trim(), Some(c)),
                None => (line.trim(), None),
            };
            let mut tokens = code_part.split_whitespace();
            let line_ip = match tokens.next() {
                Some(ip) => ip,
                None => {
                    if let Some(c) = comment_opt {
                        managed_comments.push(format!("#{}", c));
                    }
                    continue;
                }
            };
            let mut non_aether = Vec::new();
            for tok in tokens {
                if tok.ends_with(".aether.local") {
                    if !existing_managed.iter().any(|(d, _)| d == tok) {
                        existing_managed.push((tok.to_string(), line_ip.to_string()));
                    }
                } else {
                    non_aether.push(tok);
                }
            }
            if !non_aether.is_empty() {
                let line_str = format!("{}\t{}", line_ip, non_aether.join("\t"));
                if let Some(c) = comment_opt {
                    outside_lines.push(format!("{} #{}", line_str, c));
                } else {
                    outside_lines.push(line_str);
                }
            } else if let Some(c) = comment_opt {
                managed_comments.push(format!("#{}", c));
            }
        } else {
            let filter_fn = |tok: &str| -> bool {
                match action {
                    HostsModifyAction::Update { .. } => domains.contains(&tok.to_string()),
                    HostsModifyAction::Remove => domains.contains(&tok.to_string()),
                    HostsModifyAction::Reconcile { .. } => {
                        tok.ends_with(".aether.local") || domains.contains(&tok.to_string())
                    }
                }
            };
            if let Some(filtered) = filter_hosts_line(line, filter_fn) {
                outside_lines.push(filtered);
            }
        }
    }

    let mut final_managed: Vec<(String, String)> = Vec::new();
    match action {
        HostsModifyAction::Update { .. } => {
            let canonical_ip = canonical_ip_opt.as_deref().unwrap_or("");
            for (dom, old_ip) in existing_managed {
                if !domains.contains(&dom) {
                    final_managed.push((dom, old_ip));
                }
            }
            for dom in domains {
                if !final_managed.iter().any(|(d, _)| d == dom) {
                    final_managed.push((dom.clone(), canonical_ip.to_string()));
                }
            }
        }
        HostsModifyAction::Remove => {
            for (dom, old_ip) in existing_managed {
                if !domains.contains(&dom) {
                    final_managed.push((dom, old_ip));
                }
            }
        }
        HostsModifyAction::Reconcile { .. } => {
            let canonical_ip = canonical_ip_opt.as_deref().unwrap_or("");
            for dom in domains {
                if !final_managed.iter().any(|(d, _)| d == dom) {
                    final_managed.push((dom.clone(), canonical_ip.to_string()));
                }
            }
        }
    }

    let mut out = outside_lines.join("\n");
    if !out.ends_with('\n') && !out.is_empty() {
        out.push('\n');
    }
    if !final_managed.is_empty() || !managed_comments.is_empty() {
        out.push_str(chosen_start_marker);
        out.push('\n');
        for c in &managed_comments {
            out.push_str(c);
            out.push('\n');
        }
        for (dom, ip) in &final_managed {
            out.push_str(&format!("{}\t{}\n", ip, dom));
        }
        out.push_str(chosen_end_marker);
        out.push('\n');
    }

    hosts_lock
        .verify_still_active()
        .map_err(anyhow::Error::from)?;
    write_hosts_file_atomically(hosts_path, &out).map_err(RunnerError::from)
}

pub(crate) fn resolve_hosts_file_path() -> PathBuf {
    for key in ["AF_HOSTS_FILE", "AETHERFLOW_HOSTS_FILE"] {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return PathBuf::from(trimmed);
            }
        }
    }
    PathBuf::from("/etc/hosts")
}

pub fn update_hosts_file(domains: &[String], ip: &str) -> Result<(), RunnerError> {
    let validated_ip = validate_hosts_ip(ip)?;
    let canonical_ip = validated_ip.to_string();
    let path = resolve_hosts_file_path();
    let lock_path = resolve_hosts_lock_path(&path);
    update_hosts_file_with_ip_at_path(&path, &lock_path, domains, &canonical_ip, false)
}

pub fn update_hosts_file_local(domains: &[String], remove: bool) -> anyhow::Result<()> {
    let path = resolve_hosts_file_path();
    update_hosts_file_at_path(&path, domains, remove)
}

pub fn update_hosts_file_with_ip_at_path(
    hosts_path: &Path,
    lock_path: &Path,
    domains: &[String],
    ip: &str,
    remove: bool,
) -> Result<(), RunnerError> {
    if remove {
        modify_hosts_file_at_path(hosts_path, lock_path, domains, HostsModifyAction::Remove)
    } else {
        let validated_ip = validate_hosts_ip(ip)?;
        let canonical_ip = validated_ip.to_string();
        modify_hosts_file_at_path(
            hosts_path,
            lock_path,
            domains,
            HostsModifyAction::Update { ip: &canonical_ip },
        )
    }
}

pub fn update_hosts_file_at_path(
    hosts_path: &Path,
    domains: &[String],
    remove: bool,
) -> anyhow::Result<()> {
    let lock_path = resolve_hosts_lock_path(hosts_path);
    if remove {
        modify_hosts_file_at_path(hosts_path, &lock_path, domains, HostsModifyAction::Remove)?;
    } else {
        let validated_ip = validate_hosts_ip("127.0.0.1")?;
        let canonical_ip = validated_ip.to_string();
        modify_hosts_file_at_path(
            hosts_path,
            &lock_path,
            domains,
            HostsModifyAction::Update { ip: &canonical_ip },
        )?;
    }
    Ok(())
}

pub fn reconcile_hosts_file_at_path(
    hosts_path: &Path,
    lock_path: &Path,
    domains: &[String],
    ip: &str,
) -> Result<(), RunnerError> {
    let validated_ip = validate_hosts_ip(ip)?;
    let canonical_ip = validated_ip.to_string();
    modify_hosts_file_at_path(
        hosts_path,
        lock_path,
        domains,
        HostsModifyAction::Reconcile { ip: &canonical_ip },
    )
}

pub fn reconcile_hosts_file(domains: &[String], ip: &str) -> Result<(), RunnerError> {
    let validated_ip = validate_hosts_ip(ip)?;
    let canonical_ip = validated_ip.to_string();
    let path = resolve_hosts_file_path();
    let lock_path = resolve_hosts_lock_path(&path);
    reconcile_hosts_file_at_path(&path, &lock_path, domains, &canonical_ip)
}

pub fn sync_dns_provider_files(ip: &str, domains: &[String]) -> anyhow::Result<()> {
    sync_dns_provider_files_with_mode(ip, domains, true)
}

pub(crate) fn resolve_provider_dir(env_var: &str, default_path: &str) -> PathBuf {
    if let Ok(dir) = env::var(env_var) {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    for root_key in ["AETHERFLOW_CONFIG_ROOT", "AETHERFLOW_FS_ROOT"] {
        if let Ok(root) = env::var(root_key) {
            let root_trim = root.trim();
            if !root_trim.is_empty() {
                let rel = default_path.trim_start_matches(['/', '\\']);
                return Path::new(root_trim).join(rel);
            }
        }
    }
    PathBuf::from(default_path)
}

pub(crate) fn resolve_provider_dir_for_root(
    env_var: &str,
    default_path: &str,
    fs_root: Option<&Path>,
) -> PathBuf {
    if let Some(root) = fs_root {
        if let Ok(dir) = env::var(env_var) {
            let trimmed = dir.trim();
            if !trimmed.is_empty() {
                if let Ok(confined) =
                    af_models::validate_path_within_isolated_root(Path::new(trimmed), root, env_var)
                {
                    return confined;
                }
            }
        }
        let rel = default_path.trim_start_matches(['/', '\\']);
        return root.join(rel);
    }
    resolve_provider_dir(env_var, default_path)
}

fn render_dnsmasq_content(
    existing: Option<&str>,
    canonical_ip: &str,
    domains: &[String],
    is_reconcile: bool,
) -> String {
    let mut domain_set: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    if !is_reconcile {
        if let Some(content) = existing {
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("address=/") {
                    if let Some((dom, ip)) = rest.split_once('/') {
                        let dom_clean = dom.trim().to_ascii_lowercase();
                        if !dom_clean.is_empty() {
                            domain_set.insert(dom_clean, ip.trim().to_string());
                        }
                    }
                }
            }
        }
    }
    for d in domains {
        domain_set.insert(d.trim().to_ascii_lowercase(), canonical_ip.to_string());
    }
    let mut lines = vec!["# Automatically managed by AetherFlow".to_string()];
    for (d, ip) in domain_set {
        lines.push(format!("address=/{}/{}", d, ip));
    }
    lines.push(String::new());
    lines.join("\n")
}

pub fn reconcile_pihole_custom_list_content(
    existing: &str,
    canonical_ip: &str,
    domains: &[String],
    is_reconcile: bool,
) -> String {
    let target_domains: HashSet<String> = domains.iter().map(|d| d.to_ascii_lowercase()).collect();
    let mut emitted_domains: HashSet<String> = HashSet::new();
    let mut out_lines: Vec<String> = Vec::new();

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            out_lines.push(line.to_string());
            continue;
        }
        if trimmed.starts_with('#') {
            if trimmed == "# --- AETHERFLOW MANAGED DNS ---"
                || trimmed == "# --- END AETHERFLOW MANAGED DNS ---"
            {
                continue;
            }
            out_lines.push(line.to_string());
            continue;
        }

        let (entry_part, comment_part) = match line.find('#') {
            Some(idx) => (&line[..idx], Some(&line[idx..])),
            None => (line, None),
        };

        let parts: Vec<&str> = entry_part.split_whitespace().collect();
        if parts.len() < 2 {
            out_lines.push(line.to_string());
            continue;
        }

        let line_ip = parts[0];
        let hostnames = &parts[1..];
        let is_line_tagged_managed = comment_part
            .map(|c| c.contains("aetherflow-managed"))
            .unwrap_or(false);
        let single_host_managed = is_line_tagged_managed && hostnames.len() == 1;

        let mut unmanaged_tokens: Vec<&str> = Vec::new();
        let mut managed_tokens: Vec<&str> = Vec::new();

        for host in hostnames {
            let h_lower = host.to_ascii_lowercase();
            let is_managed = h_lower.ends_with(".aether.local")
                || target_domains.contains(&h_lower)
                || single_host_managed;
            if is_managed {
                managed_tokens.push(host);
            } else {
                unmanaged_tokens.push(host);
            }
        }

        if !unmanaged_tokens.is_empty() {
            let mut preserved_line = format!("{} {}", line_ip, unmanaged_tokens.join(" "));
            if let Some(c) = comment_part {
                let trimmed_c = c.trim();
                if !trimmed_c.is_empty() && trimmed_c != "# aetherflow-managed" {
                    preserved_line.push(' ');
                    preserved_line.push_str(trimmed_c);
                }
            }
            out_lines.push(preserved_line);

            if !is_reconcile {
                for m in managed_tokens {
                    let m_lower = m.to_ascii_lowercase();
                    if !target_domains.contains(&m_lower) && !emitted_domains.contains(&m_lower) {
                        emitted_domains.insert(m_lower);
                        out_lines.push(format!("{} {} # aetherflow-managed", line_ip, m));
                    }
                }
            }
        } else {
            for m in managed_tokens {
                let m_lower = m.to_ascii_lowercase();
                if target_domains.contains(&m_lower) {
                    if !emitted_domains.contains(&m_lower) {
                        emitted_domains.insert(m_lower.clone());
                        let comment = if let Some(c) = comment_part {
                            let trimmed_c = c.trim();
                            if !trimmed_c.is_empty() && trimmed_c != "# aetherflow-managed" {
                                trimmed_c
                            } else {
                                "# aetherflow-managed"
                            }
                        } else {
                            "# aetherflow-managed"
                        };
                        out_lines.push(format!("{} {} {}", canonical_ip, m, comment));
                    }
                } else if !is_reconcile && !emitted_domains.contains(&m_lower) {
                    emitted_domains.insert(m_lower.clone());
                    let comment = if let Some(c) = comment_part {
                        let trimmed_c = c.trim();
                        if !trimmed_c.is_empty() {
                            trimmed_c
                        } else {
                            "# aetherflow-managed"
                        }
                    } else {
                        "# aetherflow-managed"
                    };
                    out_lines.push(format!("{} {} {}", line_ip, m, comment));
                }
            }
        }
    }

    for d in domains {
        let d_lower = d.to_ascii_lowercase();
        if !emitted_domains.contains(&d_lower) {
            emitted_domains.insert(d_lower);
            out_lines.push(format!("{} {} # aetherflow-managed", canonical_ip, d));
        }
    }

    let mut result = out_lines.join("\n");
    if !result.is_empty() {
        result.push('\n');
    }
    result
}

pub fn remove_pihole_custom_list_content(existing: &str, domains_to_remove: &[String]) -> String {
    if domains_to_remove.is_empty() {
        return existing.to_string();
    }
    let lower_remove: HashSet<String> = domains_to_remove
        .iter()
        .map(|d| d.to_ascii_lowercase())
        .collect();

    let mut out_lines: Vec<String> = Vec::new();

    for line in existing.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            out_lines.push(line.to_string());
            continue;
        }

        let (entry_part, comment_part) = match line.find('#') {
            Some(idx) => (&line[..idx], Some(&line[idx..])),
            None => (line, None),
        };

        let parts: Vec<&str> = entry_part.split_whitespace().collect();
        if parts.len() < 2 {
            out_lines.push(line.to_string());
            continue;
        }

        let line_ip = parts[0];
        let hostnames = &parts[1..];

        let mut remaining_hosts: Vec<&str> = Vec::new();
        let mut had_matching = false;

        for host in hostnames {
            let h_lower = host.to_ascii_lowercase();
            if lower_remove.contains(&h_lower) {
                had_matching = true;
            } else {
                remaining_hosts.push(host);
            }
        }

        if !had_matching {
            out_lines.push(line.to_string());
        } else if !remaining_hosts.is_empty() {
            let mut line_str = format!("{} {}", line_ip, remaining_hosts.join(" "));
            if let Some(c) = comment_part {
                let trimmed_c = c.trim();
                if !trimmed_c.is_empty() {
                    line_str.push(' ');
                    line_str.push_str(trimmed_c);
                }
            }
            out_lines.push(line_str);
        }
    }

    let mut result = out_lines.join("\n");
    if !result.is_empty() {
        result.push('\n');
    }
    result
}

pub fn sync_dns_provider_files_for_root(
    ip: &str,
    domains: &[String],
    is_reconcile: bool,
    fs_root: Option<&Path>,
) -> anyhow::Result<()> {
    let validated_ip = validate_hosts_ip(ip)?;
    let canonical_ip = validated_ip.to_string();
    for domain in domains {
        anyhow::ensure!(
            af_models::valid_ingress_hostname(domain),
            "invalid DNS provider domain"
        );
    }
    let dnsmasq_dir =
        resolve_provider_dir_for_root("AETHERFLOW_DNSMASQ_DIR", "/etc/dnsmasq.d", fs_root);
    if dns_provider_directory_exists(&dnsmasq_dir, false)? {
        for conf_name in [
            "aetherflow-local-dns.conf",
            "aetherflow.conf",
            "aetherflow-local.conf",
            "05-aetherflow-dns.conf",
        ] {
            let conf_path = dnsmasq_dir.join(conf_name);
            let existing = match read_dns_provider_text(&conf_path, false) {
                Ok(content) => Some(content),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to read {}: {}",
                        conf_path.display(),
                        e
                    ));
                }
            };
            let payload =
                render_dnsmasq_content(existing.as_deref(), &canonical_ip, domains, is_reconcile);
            write_dns_provider_text(&conf_path, &payload, false)?;
        }
    }

    let pihole_dir = resolve_provider_dir_for_root("AETHERFLOW_PIHOLE_DIR", "/etc/pihole", fs_root);
    if dns_provider_directory_exists(&pihole_dir, true)? {
        let custom_list = pihole_dir.join("custom.list");
        let existing = match read_dns_provider_text(&custom_list, true) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to read {}: {}",
                    custom_list.display(),
                    e
                ));
            }
        };
        let payload =
            reconcile_pihole_custom_list_content(&existing, &canonical_ip, domains, is_reconcile);
        write_dns_provider_text(&custom_list, &payload, true)?;
    }
    adguard_dns::sync_for_root(
        domains,
        adguard_dns::Change::Update {
            ip: &canonical_ip,
            reconcile: is_reconcile,
        },
        fs_root,
    )?;
    Ok(())
}

pub fn sync_dns_provider_files_with_mode(
    ip: &str,
    domains: &[String],
    is_reconcile: bool,
) -> anyhow::Result<()> {
    sync_dns_provider_files_for_root(ip, domains, is_reconcile, None)
}

pub fn sync_adguard_dns(ip: &str, domains: &[String], reconcile: bool) -> anyhow::Result<()> {
    let ip = validate_hosts_ip(ip)?.to_string();
    adguard_dns::sync(domains, adguard_dns::Change::Update { ip: &ip, reconcile })
}

pub fn remove_dns_provider_files(domains: &[String]) -> anyhow::Result<()> {
    if domains.is_empty() {
        return Ok(());
    }
    let lower_domains: std::collections::HashSet<String> =
        domains.iter().map(|d| d.to_ascii_lowercase()).collect();

    let dnsmasq_dir = resolve_provider_dir("AETHERFLOW_DNSMASQ_DIR", "/etc/dnsmasq.d");
    if dns_provider_directory_exists(&dnsmasq_dir, false)? {
        for conf_name in [
            "aetherflow-local-dns.conf",
            "aetherflow.conf",
            "aetherflow-local.conf",
            "05-aetherflow-dns.conf",
        ] {
            let conf_path = dnsmasq_dir.join(conf_name);
            match read_dns_provider_text(&conf_path, false) {
                Ok(content) => {
                    let mut out_lines = Vec::new();
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if let Some(rest) = trimmed.strip_prefix("address=/") {
                            if let Some((dom, _)) = rest.split_once('/') {
                                if lower_domains.contains(&dom.trim().to_ascii_lowercase()) {
                                    continue;
                                }
                            }
                        }
                        out_lines.push(line.to_string());
                    }
                    out_lines.push(String::new());
                    write_dns_provider_text(&conf_path, &out_lines.join("\n"), false)?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to read {}: {}",
                        conf_path.display(),
                        e
                    ));
                }
            }
        }
    }

    let pihole_dir = resolve_provider_dir("AETHERFLOW_PIHOLE_DIR", "/etc/pihole");
    if dns_provider_directory_exists(&pihole_dir, true)? {
        let custom_list = pihole_dir.join("custom.list");
        match read_dns_provider_text(&custom_list, true) {
            Ok(content) => {
                let payload = remove_pihole_custom_list_content(&content, domains);
                if payload != content {
                    write_dns_provider_text(&custom_list, &payload, true)?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to read {}: {}",
                    custom_list.display(),
                    e
                ));
            }
        }
    }
    adguard_dns::sync(domains, adguard_dns::Change::Remove)?;
    Ok(())
}

pub fn remove_dns_provider_domain(domain: &str) -> anyhow::Result<()> {
    remove_dns_provider_files(&[domain.to_string()])
}

pub fn execute_hosts_cli_command(
    action: &str,
    ip: &str,
    domains: &[String],
) -> anyhow::Result<String> {
    if action.eq_ignore_ascii_case("update")
        || action.eq_ignore_ascii_case("reconcile")
        || action.eq_ignore_ascii_case("add")
        || !ip.is_empty()
    {
        validate_hosts_ip(ip)?;
    }
    match action {
        "reconcile" => {
            let validated_ip = validate_hosts_ip(ip)?;
            let canonical_ip = validated_ip.to_string();
            reconcile_hosts_file(domains, &canonical_ip)?;
            sync_dns_provider_files_with_mode(&canonical_ip, domains, true)?;
            Ok(format!(
                "reconciled {} domain(s) to {}",
                domains.len(),
                canonical_ip
            ))
        }
        "update" | "add" => {
            let validated_ip = validate_hosts_ip(ip)?;
            let canonical_ip = validated_ip.to_string();
            update_hosts_file(domains, &canonical_ip)?;
            sync_dns_provider_files_with_mode(&canonical_ip, domains, false)?;
            Ok(format!(
                "updated {} domain(s) to {}",
                domains.len(),
                canonical_ip
            ))
        }
        "remove" => {
            update_hosts_file_local(domains, true)?;
            for d in domains {
                remove_dns_provider_domain(d)?;
            }
            Ok(format!("removed {} domain(s)", domains.len()))
        }
        other => anyhow::bail!(
            "unknown hosts action {:?}, expected reconcile, update, or remove",
            other
        ),
    }
}

pub fn run_hosts_cli(args: &[String]) -> anyhow::Result<String> {
    if args.is_empty() {
        anyhow::bail!("missing hosts action (update, remove, reconcile)");
    }
    let action = args[0].to_ascii_lowercase();
    match action.as_str() {
        "reconcile" => {
            let ip = args.get(1).map(|s| s.as_str()).unwrap_or("127.0.0.1");
            let domains: Vec<String> = if args.len() > 2 {
                args[2..].to_vec()
            } else {
                Vec::new()
            };
            execute_hosts_cli_command("reconcile", ip, &domains)
        }
        "update" | "add" => {
            if args.len() < 2 {
                anyhow::bail!("usage: hosts update <ip> <domain...>");
            }
            let ip = &args[1];
            let domains = args[2..].to_vec();
            execute_hosts_cli_command(&action, ip, &domains)
        }
        "remove" => {
            if args.len() < 2 {
                anyhow::bail!("usage: hosts remove <domain...>");
            }
            let domains = args[1..].to_vec();
            execute_hosts_cli_command("remove", "127.0.0.1", &domains)
        }
        other => anyhow::bail!(
            "unknown hosts action {:?}, expected reconcile, update, or remove",
            other
        ),
    }
}

#[cfg(test)]
mod isolated_root_dns_tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn resolve_provider_dir_for_root_confines_overrides_within_fs_root() {
        let _lock = crate::ENV_TEST_MUTEX.blocking_lock();
        let root = std::env::temp_dir().join(format!("af-hdns-root-{}", Uuid::new_v4()));
        let inside = root.join("custom/dnsmasq.d");
        let outside = std::env::temp_dir().join(format!("af-hdns-out-{}", Uuid::new_v4()));
        let prev = env::var_os("AETHERFLOW_DNSMASQ_DIR");

        env::set_var("AETHERFLOW_DNSMASQ_DIR", &inside);
        assert_eq!(
            resolve_provider_dir_for_root("AETHERFLOW_DNSMASQ_DIR", "/etc/dnsmasq.d", Some(&root)),
            inside
        );

        env::set_var("AETHERFLOW_DNSMASQ_DIR", &outside);
        assert_eq!(
            resolve_provider_dir_for_root("AETHERFLOW_DNSMASQ_DIR", "/etc/dnsmasq.d", Some(&root)),
            root.join("etc/dnsmasq.d")
        );

        env::set_var("AETHERFLOW_DNSMASQ_DIR", root.join("../escape"));
        assert_eq!(
            resolve_provider_dir_for_root("AETHERFLOW_DNSMASQ_DIR", "/etc/dnsmasq.d", Some(&root)),
            root.join("etc/dnsmasq.d")
        );

        match prev {
            Some(v) => env::set_var("AETHERFLOW_DNSMASQ_DIR", v),
            None => env::remove_var("AETHERFLOW_DNSMASQ_DIR"),
        }
    }
}
