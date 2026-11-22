use af_models::AppIngressConfig;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use rusqlite::{params, Connection};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::pool::{get_conn, get_read_conn};
use crate::retained_ingress;

// ─────────────────────────────────────────────────────────────────────────────
// App Ingress Configs & Base Domain
// ─────────────────────────────────────────────────────────────────────────────

struct IngressCache {
    generation: u64,
    configs: Option<Vec<AppIngressConfig>>,
    configs_at: Option<Instant>,
    base_domain: String,
    base_domain_at: Option<Instant>,
}

static INGRESS_CACHE: Lazy<RwLock<IngressCache>> = Lazy::new(|| {
    RwLock::new(IngressCache {
        generation: 0,
        configs: None,
        configs_at: None,
        base_domain: String::new(),
        base_domain_at: None,
    })
});

const INGRESS_CACHE_TTL: Duration = Duration::from_secs(5);

// This hint only sends possible subdomains to authoritative resolution. A
// fingerprint match never grants access.
static BASE_DOMAIN_HINT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn base_domain_fingerprint(domain: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    domain.hash(&mut hasher);
    hasher.finish().max(1)
}

/// A routing hint for passing requests to the control plane. Host validation
/// still compares the complete authority before accepting a request.
pub fn maybe_cached_control_plane_host(host: &str) -> bool {
    let hint = BASE_DOMAIN_HINT.load(std::sync::atomic::Ordering::Acquire);
    if hint == 0 {
        return false;
    }
    base_domain_fingerprint(host) == hint
        || host.split_once('.').is_some_and(|(label, suffix)| {
            matches!(label, "www" | "direct" | "aetherflow")
                && base_domain_fingerprint(suffix) == hint
        })
}

pub fn cached_base_domain() -> Option<String> {
    let cache = INGRESS_CACHE.try_read().ok()?;
    cache
        .base_domain_at
        .filter(|at| at.elapsed() < INGRESS_CACHE_TTL)?;
    Some(cache.base_domain.clone())
}

pub fn matches_cached_ingress_subdomain(host: &str) -> bool {
    let hint = BASE_DOMAIN_HINT.load(std::sync::atomic::Ordering::Acquire);
    hint != 0
        && host.match_indices('.').any(|(offset, _)| {
            base_domain_fingerprint(&host[offset + 1..]) == hint
                && !matches!(&host[..offset], "www" | "direct" | "aetherflow")
        })
}

pub fn invalidate_ingress_cache() {
    if let Ok(mut guard) = INGRESS_CACHE.write() {
        guard.generation = guard.generation.wrapping_add(1);
        guard.configs = None;
        guard.configs_at = None;
        guard.base_domain.clear();
        guard.base_domain_at = None;
    }
}

pub fn normalize_base_domain(raw: &str) -> String {
    let mut s = raw.trim().to_lowercase();
    for prefix in ["https://", "http://"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    if let Some((host, _)) = s.split_once('/') {
        s = host.to_string();
    }
    if let Some((host, _)) = s.split_once(':') {
        s = host.to_string();
    }
    if let Some(rest) = s.strip_prefix("*.") {
        s = rest.to_string();
    }
    s = s.trim_matches('.').to_string();
    if s.is_empty()
        || s == "localhost"
        || s == "aether.local"
        || s.ends_with(".local")
        || !s.contains('.')
    {
        return String::new();
    }
    s
}

pub fn get_base_domain() -> String {
    if let Ok(guard) = INGRESS_CACHE.read() {
        if let Some(at) = guard.base_domain_at {
            if at.elapsed() < INGRESS_CACHE_TTL {
                return guard.base_domain.clone();
            }
        }
    }
    let generation = INGRESS_CACHE
        .read()
        .map(|cache| cache.generation)
        .unwrap_or(0);
    let domain = get_read_conn()
        .ok()
        .and_then(|c| {
            c.query_row(
                "SELECT COALESCE(base_domain, '') FROM settings WHERE id = 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
        })
        .map(|d| normalize_base_domain(&d))
        .unwrap_or_default();

    if let Ok(mut guard) = INGRESS_CACHE.write() {
        if guard.generation == generation {
            guard.base_domain = domain.clone();
            guard.base_domain_at = Some(Instant::now());
            BASE_DOMAIN_HINT.store(
                if domain.is_empty() {
                    0
                } else {
                    base_domain_fingerprint(&domain)
                },
                std::sync::atomic::Ordering::Release,
            );
        }
    }
    domain
}

pub fn set_base_domain(domain: &str) -> anyhow::Result<()> {
    let norm = normalize_base_domain(domain);
    let conn = get_conn()?;
    conn.execute(
        "UPDATE settings SET base_domain = ?1, updated_at = CURRENT_TIMESTAMP WHERE id = 1",
        params![norm],
    )?;
    drop(conn);
    invalidate_ingress_cache();
    get_base_domain();
    Ok(())
}

pub(crate) fn parse_sqlite_dt(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .or_else(|_| {
            chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").map(|ndt| ndt.and_utc())
        })
        .unwrap_or_else(|_| Utc::now())
}

pub fn get_all_app_ingress_configs() -> anyhow::Result<Vec<AppIngressConfig>> {
    let generation = INGRESS_CACHE
        .read()
        .map(|guard| guard.generation)
        .unwrap_or(0);
    if let Ok(guard) = INGRESS_CACHE.read() {
        if let (Some(ref cfgs), Some(at)) = (&guard.configs, guard.configs_at) {
            if at.elapsed() < INGRESS_CACHE_TTL {
                return Ok(cfgs.clone());
            }
        }
    }

    let conn = get_read_conn()?;
    let mut stmt = conn.prepare(
        "SELECT app_name, public_domain, external_access_enabled, listen_port, tls_enabled, \
         COALESCE(CAST(created_at AS TEXT), ''), COALESCE(CAST(updated_at AS TEXT), '') \
         FROM app_ingress_configs ORDER BY app_name ASC",
    )?;
    let rows = stmt.query_map([], |r| {
        let created_raw: String = r.get(5)?;
        let updated_raw: String = r.get(6)?;
        Ok(AppIngressConfig {
            app_name: r.get(0)?,
            public_domain: r.get(1)?,
            external_access_enabled: r.get(2)?,
            listen_port: r.get(3)?,
            tls_enabled: r.get(4)?,
            created_at: parse_sqlite_dt(&created_raw),
            updated_at: parse_sqlite_dt(&updated_raw),
        })
    })?;

    let mut result = Vec::new();
    for r in rows {
        result.push(r?);
    }

    if let Ok(mut guard) = INGRESS_CACHE.write() {
        if guard.generation == generation {
            guard.configs = Some(result.clone());
            guard.configs_at = Some(Instant::now());
        }
    }
    Ok(result)
}

pub fn has_retained_app_ingress_config(app: &str) -> anyhow::Result<bool> {
    let conn = get_read_conn()?;
    let table_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='retained_app_ingress_configs')",
        [], |row| row.get(0),
    )?;
    if !table_exists {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM retained_app_ingress_configs WHERE app_name = ?1)",
        [app],
        |row| row.get(0),
    )?)
}

pub fn get_app_ingress_config(app_name: &str) -> anyhow::Result<Option<AppIngressConfig>> {
    let all = get_all_app_ingress_configs()?;
    Ok(all.into_iter().find(|c| c.app_name == app_name))
}

pub fn set_app_ingress_config(cfg: &AppIngressConfig) -> anyhow::Result<()> {
    let mut conn = get_conn()?;
    retained_ingress::set_config(&mut conn, cfg, None)?;
    invalidate_ingress_cache();
    Ok(())
}

pub fn set_app_ingress_config_for_lifecycle(
    cfg: &AppIngressConfig,
    job_id: &str,
    action: &str,
) -> anyhow::Result<()> {
    set_app_ingress_and_secondary_port_for_lifecycle(cfg, None, job_id, action)
}

pub fn set_app_ingress_and_secondary_port_for_lifecycle(
    cfg: &AppIngressConfig,
    secondary_port: Option<(&str, Option<i32>)>,
    job_id: &str,
    action: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(action, "install" | "reinstall" | "update"),
        "Invalid ingress lifecycle action"
    );
    anyhow::ensure!(
        !job_id.is_empty(),
        "Ingress lifecycle job identity is required"
    );
    let mut conn = get_conn()?;
    retained_ingress::set_config_with_secondary_port(
        &mut conn,
        cfg,
        secondary_port,
        Some((job_id, action)),
    )?;
    invalidate_ingress_cache();
    Ok(())
}

pub(crate) fn write_app_ingress_config(
    conn: &Connection,
    cfg: &AppIngressConfig,
) -> anyhow::Result<()> {
    if cfg.listen_port > 0 {
        let reserved = retained_ingress::list_reserved_ports_excluding(conn, &cfg.app_name)?;
        anyhow::ensure!(
            !reserved.contains(&cfg.listen_port),
            "Listen port {} is already reserved by another application",
            cfg.listen_port
        );
        anyhow::ensure!(
            !retained_ingress::has_active_secondary_port_conflict(
                conn,
                &cfg.app_name,
                cfg.listen_port
            )?,
            "Listen port {} conflicts with an active secondary port for {}",
            cfg.listen_port,
            cfg.app_name
        );
    }
    conn.execute(
        r#"
        INSERT INTO app_ingress_configs (app_name, public_domain, external_access_enabled, listen_port, tls_enabled, updated_at)
        VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
        ON CONFLICT(app_name) DO UPDATE SET
            public_domain = excluded.public_domain,
            external_access_enabled = excluded.external_access_enabled,
            listen_port = CASE WHEN excluded.listen_port > 0 THEN excluded.listen_port ELSE app_ingress_configs.listen_port END,
            tls_enabled = excluded.tls_enabled,
            updated_at = CURRENT_TIMESTAMP
        "#,
        params![
            cfg.app_name,
            cfg.public_domain,
            cfg.external_access_enabled,
            cfg.listen_port,
            cfg.tls_enabled,
        ],
    )?;
    Ok(())
}

pub fn delete_app_ingress_config(app_name: &str) -> anyhow::Result<()> {
    let conn = get_conn()?;
    conn.execute(
        "DELETE FROM app_ingress_configs WHERE app_name = ?1",
        params![app_name],
    )?;
    invalidate_ingress_cache();
    Ok(())
}
