use af_models::{app_metadata::normalize_app_slug as canonical_app, AppIngressConfig};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::collections::BTreeSet;

fn schema(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL);
         CREATE TABLE IF NOT EXISTS app_secondary_ports (
             app_name TEXT NOT NULL,
             port_role TEXT NOT NULL,
             port INTEGER NOT NULL,
             retained INTEGER NOT NULL DEFAULT 0,
             PRIMARY KEY (app_name, port_role)
         );",
    )?;
    Ok(())
}

fn has_table(conn: &Connection, table: &str) -> anyhow::Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [table],
        |row| row.get(0),
    )?)
}

pub(crate) fn has_active_secondary_port_conflict(
    conn: &Connection,
    app: &str,
    port: i32,
) -> anyhow::Result<bool> {
    if port <= 0 || !has_table(conn, "app_secondary_ports")? {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM app_secondary_ports WHERE LOWER(app_name)=LOWER(?1) AND retained=0 AND port=?2)",
        params![canonical_app(app), port],
        |row| row.get(0),
    )?)
}

pub fn load_lifecycle_secondary_port(
    conn: &Connection,
    app: &str,
    role: &str,
) -> anyhow::Result<Option<i32>> {
    let role_clean = role.trim();
    if role_clean.is_empty() || !has_table(conn, "app_secondary_ports")? {
        return Ok(None);
    }
    let port: Option<i32> = conn
        .query_row(
            "SELECT port FROM app_secondary_ports
             WHERE LOWER(app_name)=LOWER(?1) AND port_role=?2 AND port>0
             ORDER BY retained ASC LIMIT 1",
            params![canonical_app(app), role_clean],
            |row| row.get(0),
        )
        .optional()?;
    Ok(port.filter(|p| (1..=65535).contains(p)))
}

fn write_secondary_port_in_tx(
    tx: &Connection,
    app: &str,
    role: &str,
    port: Option<i32>,
    primary_port: i32,
) -> anyhow::Result<()> {
    let role_clean = role.trim();
    anyhow::ensure!(!role_clean.is_empty(), "Secondary port role is required");
    schema(tx)?;
    let canonical = canonical_app(app);
    match port {
        Some(p) if p > 0 => {
            anyhow::ensure!((1..=65535).contains(&p), "Secondary port {p} is invalid");
            anyhow::ensure!(
                primary_port <= 0 || p != primary_port,
                "Secondary port {p} must differ from primary port {primary_port}"
            );
            let reserved = list_reserved_ports_excluding(tx, &canonical)?;
            anyhow::ensure!(
                !reserved.contains(&p),
                "Secondary port {p} is already reserved by another application"
            );
            tx.execute(
                "INSERT INTO app_secondary_ports (app_name, port_role, port, retained)
                 VALUES (?1, ?2, ?3, 0)
                 ON CONFLICT(app_name, port_role) DO UPDATE SET port = excluded.port, retained = 0",
                params![canonical, role_clean, p],
            )?;
        }
        _ => {
            tx.execute(
                "DELETE FROM app_secondary_ports WHERE LOWER(app_name) = LOWER(?1) AND port_role = ?2",
                params![canonical, role_clean],
            )?;
        }
    }
    Ok(())
}

fn check_reservation(
    conn: &Connection,
    app: &str,
    owner: Option<(&str, &str)>,
) -> anyhow::Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs')",
        [], |row| row.get(0),
    )?;
    if !exists {
        anyhow::ensure!(owner.is_none(), "Ingress lifecycle reservation is missing");
        return Ok(());
    }
    let canonical = canonical_app(app);
    let mut statement = conn.prepare(
        "SELECT package_id,job_id,action,status,service_units FROM package_lifecycle_jobs
         WHERE status NOT IN ('completed','failed','interrupted')",
    )?;
    let mut rows = statement.query([])?;
    let mut matched_owner = false;
    while let Some(row) = rows.next()? {
        let package: String = row.get(0)?;
        let units: String = row.get(4)?;
        let aliases: Vec<String> = serde_json::from_str(&units)?;
        if canonical_app(&package) != canonical
            && !aliases
                .iter()
                .any(|alias| canonical_app(alias) == canonical)
        {
            continue;
        }
        let job: String = row.get(1)?;
        let action: String = row.get(2)?;
        let status: String = row.get(3)?;
        let expected_status = match action.as_str() {
            "install" | "reinstall" => "installing",
            "update" => "updating",
            "remove" => "uninstalling",
            _ => anyhow::bail!("Unknown ingress lifecycle action for {package}"),
        };
        anyhow::ensure!(
            status == expected_status,
            "Unknown ingress lifecycle phase for {package}"
        );
        anyhow::ensure!(
            owner.is_some_and(|(identity, requested_action)| !identity.is_empty()
                && identity == job
                && requested_action == action),
            "Application lifecycle reservation is active for {package}"
        );
        matched_owner = true;
    }
    anyhow::ensure!(
        owner.is_none() || matched_owner,
        "Ingress lifecycle reservation is missing or no longer active"
    );
    Ok(())
}

pub(super) fn set_config(
    conn: &mut Connection,
    config: &AppIngressConfig,
    owner: Option<(&str, &str)>,
) -> anyhow::Result<()> {
    set_config_with_secondary_port(conn, config, None, owner)
}

fn invalidate_app_updates_in_tx(
    tx: &Connection,
    package_id: &str,
    require_table: bool,
) -> anyhow::Result<()> {
    if !require_table && !has_table(tx, "app_updates")? {
        return Ok(());
    }
    let clean = package_id.trim();
    let clean_lower = clean.to_ascii_lowercase();
    let lock_alias = af_models::resolve_package_lock_name(&clean_lower);
    tx.execute(
        "DELETE FROM app_updates WHERE LOWER(package_name) IN (LOWER(?1), LOWER(?2))",
        params![clean, lock_alias],
    )?;
    Ok(())
}

fn bump_package_lifecycle_epoch_in_tx(tx: &Connection) -> anyhow::Result<()> {
    tx.execute_batch(
        "CREATE TABLE IF NOT EXISTS system_config (
             key TEXT PRIMARY KEY,
             value TEXT NOT NULL,
             updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
         );",
    )?;
    tx.execute(
        "INSERT INTO system_config (key, value)
         VALUES ('package_lifecycle_epoch', '1')
         ON CONFLICT(key) DO UPDATE SET
             value = CAST((CAST(COALESCE(NULLIF(TRIM(system_config.value), ''), '0') AS INTEGER) + 1) AS TEXT)",
        [],
    )?;
    Ok(())
}

pub(super) fn set_config_with_secondary_port(
    conn: &mut Connection,
    config: &AppIngressConfig,
    secondary_port: Option<(&str, Option<i32>)>,
    owner: Option<(&str, &str)>,
) -> anyhow::Result<()> {
    if let Some((identity, action)) = owner {
        anyhow::ensure!(
            !identity.is_empty() && matches!(action, "install" | "reinstall" | "update"),
            "Invalid ingress lifecycle owner"
        );
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    check_reservation(&tx, &config.app_name, owner)?;
    if let Some((role, sec)) = secondary_port {
        write_secondary_port_in_tx(&tx, &config.app_name, role, sec, config.listen_port)?;
    }
    crate::write_app_ingress_config(&tx, config)?;
    if owner.is_some() {
        invalidate_app_updates_in_tx(&tx, &config.app_name, false)?;
        bump_package_lifecycle_epoch_in_tx(&tx)?;
    }
    tx.commit()?;
    Ok(())
}

fn read_config(conn: &Connection, app: &str) -> anyhow::Result<Option<AppIngressConfig>> {
    Ok(conn
        .query_row(
            "SELECT app_name,public_domain,external_access_enabled,listen_port,tls_enabled,
         COALESCE(CAST(created_at AS TEXT), ''),COALESCE(CAST(updated_at AS TEXT), '')
         FROM app_ingress_configs WHERE app_name=?1",
            [app],
            |row| {
                Ok(AppIngressConfig {
                    app_name: row.get(0)?,
                    public_domain: row.get(1)?,
                    external_access_enabled: row.get(2)?,
                    listen_port: row.get(3)?,
                    tls_enabled: row.get(4)?,
                    created_at: crate::parse_sqlite_dt(&row.get::<_, String>(5)?),
                    updated_at: crate::parse_sqlite_dt(&row.get::<_, String>(6)?),
                })
            },
        )
        .optional()?)
}

pub fn get_retained_app_ingress_config(app: &str) -> anyhow::Result<Option<AppIngressConfig>> {
    let conn = crate::get_read_conn()?;
    read_retained_config(&conn, app)
}

pub fn get_all_retained_app_ingress_configs() -> anyhow::Result<Vec<(String, AppIngressConfig)>> {
    let conn = crate::get_read_conn()?;
    read_all_retained_configs(&conn)
}

pub fn list_retained_app_ingress_names() -> anyhow::Result<Vec<String>> {
    let conn = crate::get_read_conn()?;
    let has_retained: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='retained_app_ingress_configs')",
        [],
        |row| row.get(0),
    )?;
    if !has_retained {
        return Ok(Vec::new());
    }
    let mut stmt =
        conn.prepare("SELECT app_name FROM retained_app_ingress_configs ORDER BY app_name ASC")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut names = Vec::new();
    for row in rows {
        names.push(row?);
    }
    Ok(names)
}

fn read_all_retained_configs(conn: &Connection) -> anyhow::Result<Vec<(String, AppIngressConfig)>> {
    let has_retained: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='retained_app_ingress_configs')",
        [],
        |row| row.get(0),
    )?;
    if !has_retained {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT app_name, config_json FROM retained_app_ingress_configs ORDER BY app_name ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut configs = Vec::new();
    for row in rows {
        let (app_name, raw_json) = row?;
        let parsed: AppIngressConfig = serde_json::from_str(&raw_json)?;
        configs.push((app_name, parsed));
    }
    Ok(configs)
}

pub fn update_retained_app_ingress_config_in_tx(
    tx: &Connection,
    app: &str,
    config: &AppIngressConfig,
) -> anyhow::Result<()> {
    check_reservation(tx, app, None)?;
    schema(tx)?;
    let changed = tx.execute(
        "UPDATE retained_app_ingress_configs SET config_json=?2 WHERE app_name=?1",
        params![app, serde_json::to_string(config)?],
    )?;
    anyhow::ensure!(
        changed == 1,
        "Retained ingress configuration for {app} is missing"
    );
    Ok(())
}

pub fn check_app_ingress_reservation(app: &str) -> anyhow::Result<()> {
    let conn = crate::get_conn()?;
    check_reservation(&conn, app, None)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBaseDomainSync {
    pub previous_base_domain: String,
    pub target_base_domain: String,
    pub source_base_domains: Vec<String>,
}

fn normalize_pending_source_domains(
    previous_base_domain: &str,
    target_base_domain: &str,
    extra_sources: &[String],
) -> Vec<String> {
    let mut domains = Vec::new();
    for candidate in std::iter::once(previous_base_domain)
        .chain(extra_sources.iter().map(String::as_str))
        .chain(std::iter::once(target_base_domain))
    {
        let normalized = crate::normalize_base_domain(candidate);
        if !normalized.is_empty() && !domains.iter().any(|existing| existing == &normalized) {
            domains.push(normalized);
        }
    }
    domains
}

fn has_base_domain_sync_column(conn: &Connection, column: &str) -> anyhow::Result<bool> {
    let mut stmt = conn.prepare("PRAGMA table_info(base_domain_sync_state)")?;
    let exists = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .filter_map(Result::ok)
        .any(|name| name.eq_ignore_ascii_case(column));
    Ok(exists)
}

fn base_domain_sync_schema(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS base_domain_sync_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            previous_base_domain TEXT NOT NULL DEFAULT '',
            target_base_domain TEXT NOT NULL DEFAULT '',
            source_domains_json TEXT NOT NULL DEFAULT '[]',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );",
    )?;
    if !has_base_domain_sync_column(conn, "source_domains_json")? {
        conn.execute(
            "ALTER TABLE base_domain_sync_state ADD COLUMN source_domains_json TEXT NOT NULL DEFAULT '[]'",
            [],
        )?;
    }
    Ok(())
}

pub fn get_pending_base_domain_sync(
    conn: &Connection,
) -> anyhow::Result<Option<PendingBaseDomainSync>> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='base_domain_sync_state')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(None);
    }
    let has_sources = has_base_domain_sync_column(conn, "source_domains_json")?;
    let row: Option<(String, String, String)> = if has_sources {
        conn.query_row(
            "SELECT COALESCE(previous_base_domain, ''), COALESCE(target_base_domain, ''), COALESCE(source_domains_json, '[]')
             FROM base_domain_sync_state WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?
    } else {
        conn.query_row(
            "SELECT COALESCE(previous_base_domain, ''), COALESCE(target_base_domain, '')
             FROM base_domain_sync_state WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, "[]".to_string())),
        )
        .optional()?
    };
    Ok(row.map(|(prev, target, raw_sources)| {
        let previous_base_domain = crate::normalize_base_domain(&prev);
        let target_base_domain = crate::normalize_base_domain(&target);
        let parsed_sources: Vec<String> = serde_json::from_str(&raw_sources).unwrap_or_default();
        let source_base_domains = normalize_pending_source_domains(
            &previous_base_domain,
            &target_base_domain,
            &parsed_sources,
        );
        PendingBaseDomainSync {
            previous_base_domain,
            target_base_domain,
            source_base_domains,
        }
    }))
}

pub fn set_pending_base_domain_sync(
    conn: &Connection,
    previous_base_domain: &str,
    target_base_domain: &str,
    source_base_domains: &[String],
) -> anyhow::Result<()> {
    base_domain_sync_schema(conn)?;
    let prev = crate::normalize_base_domain(previous_base_domain);
    let target = crate::normalize_base_domain(target_base_domain);
    let sources = normalize_pending_source_domains(&prev, &target, source_base_domains);
    let sources_json = serde_json::to_string(&sources)?;
    conn.execute(
        "INSERT INTO base_domain_sync_state (id, previous_base_domain, target_base_domain, source_domains_json, updated_at)
         VALUES (1, ?1, ?2, ?3, CURRENT_TIMESTAMP)
         ON CONFLICT(id) DO UPDATE SET
             previous_base_domain = excluded.previous_base_domain,
             target_base_domain = excluded.target_base_domain,
             source_domains_json = excluded.source_domains_json,
             updated_at = CURRENT_TIMESTAMP",
        params![prev, target, sources_json],
    )?;
    Ok(())
}

pub fn clear_pending_base_domain_sync(conn: &Connection) -> anyhow::Result<()> {
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='base_domain_sync_state')",
        [],
        |row| row.get(0),
    )?;
    if !exists {
        return Ok(());
    }
    conn.execute("DELETE FROM base_domain_sync_state WHERE id = 1", [])?;
    Ok(())
}

fn read_retained_config(conn: &Connection, app: &str) -> anyhow::Result<Option<AppIngressConfig>> {
    let has_retained: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='retained_app_ingress_configs')",
        [],
        |row| row.get(0),
    )?;
    if !has_retained {
        return Ok(None);
    }
    let raw: Option<String> = conn
        .query_row(
            "SELECT config_json FROM retained_app_ingress_configs WHERE app_name=?1",
            [app],
            |row| row.get(0),
        )
        .optional()?;
    raw.map(|raw| serde_json::from_str(&raw).map_err(Into::into))
        .transpose()
}

pub fn load_lifecycle_ingress(
    conn: &Connection,
    app: &str,
) -> anyhow::Result<Option<AppIngressConfig>> {
    match read_config(conn, app)? {
        Some(config) => Ok(Some(config)),
        None => read_retained_config(conn, app),
    }
}

/// Resolve the ingress settings to materialize and persist for a package lifecycle.
pub fn plan_lifecycle_ingress(
    app: &str,
    port: i32,
    base_domain: &str,
    existing: Option<&AppIngressConfig>,
) -> anyhow::Result<Option<AppIngressConfig>> {
    if port <= 0 {
        return Ok(None);
    }
    anyhow::ensure!(
        (1024..=65535).contains(&port),
        "Invalid ingress listen port"
    );

    let public_domain = existing
        .map(|config| config.public_domain.clone())
        .filter(|domain| !domain.trim().is_empty())
        .unwrap_or_else(|| {
            let domain = crate::normalize_base_domain(base_domain);
            if domain.is_empty() {
                return String::new();
            }
            let label: String = app
                .to_ascii_lowercase()
                .chars()
                .map(|character| {
                    if character.is_ascii_alphanumeric() {
                        character
                    } else {
                        '-'
                    }
                })
                .collect();
            format!("{}.{}", label.trim_matches('-'), domain)
        });
    // A configured base domain opts fresh web installs into automatic
    // subdomain ingress. Active and retained policy takes precedence.
    let enable_by_default = !public_domain.is_empty();
    let now = chrono::Utc::now();
    Ok(Some(AppIngressConfig {
        app_name: app.to_owned(),
        external_access_enabled: existing
            .map(|config| config.external_access_enabled)
            .unwrap_or(enable_by_default),
        tls_enabled: existing
            .map(|config| config.tls_enabled)
            .unwrap_or(enable_by_default),
        public_domain,
        listen_port: port,
        created_at: existing.map(|config| config.created_at).unwrap_or(now),
        updated_at: now,
    }))
}

pub fn synchronize_lifecycle_ingress(
    conn: &mut Connection,
    app: &str,
    action: &str,
    job_id: &str,
    port: i32,
    purge: bool,
    base_domain: &str,
) -> anyhow::Result<()> {
    synchronize_lifecycle_ingress_with_secondary_port(
        conn,
        app,
        action,
        job_id,
        port,
        None,
        purge,
        base_domain,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn synchronize_lifecycle_ingress_with_secondary_port(
    conn: &mut Connection,
    app: &str,
    action: &str,
    job_id: &str,
    port: i32,
    secondary_port: Option<(&str, Option<i32>)>,
    purge: bool,
    base_domain: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(!job_id.is_empty(), "Ingress lifecycle identity is required");
    anyhow::ensure!(
        matches!(action, "install" | "reinstall" | "update" | "remove"),
        "Invalid ingress lifecycle action"
    );
    anyhow::ensure!(
        !purge || action == "remove",
        "Purge requires package removal"
    );
    if action == "remove" {
        archive_with_secondary(conn, app, purge, secondary_port, Some((job_id, action)))?;
    } else {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_reservation(&tx, app, Some((job_id, action)))?;
        if let Some((role, sec)) = secondary_port {
            write_secondary_port_in_tx(&tx, app, role, sec, port)?;
        }
        if port > 0 {
            let existing = load_lifecycle_ingress(&tx, app)?;
            if let Some(config) = plan_lifecycle_ingress(app, port, base_domain, existing.as_ref())?
            {
                crate::write_app_ingress_config(&tx, &config)?;
            }
        }
        invalidate_app_updates_in_tx(&tx, app, false)?;
        bump_package_lifecycle_epoch_in_tx(&tx)?;
        tx.commit()?;
    }
    crate::invalidate_ingress_cache();
    Ok(())
}

pub fn archive_app_ingress_config(app: &str, purge: bool) -> anyhow::Result<()> {
    archive_config(app, purge, None)
}

pub fn archive_app_ingress_config_for_lifecycle(
    app: &str,
    purge: bool,
    job_id: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !job_id.is_empty(),
        "Ingress lifecycle job identity is required"
    );
    archive_config(app, purge, Some((job_id, "remove")))
}

fn archive_config(app: &str, purge: bool, owner: Option<(&str, &str)>) -> anyhow::Result<()> {
    let mut conn = crate::get_conn()?;
    archive(&mut conn, app, purge, owner)?;
    crate::invalidate_ingress_cache();
    Ok(())
}

fn archive(
    conn: &mut Connection,
    app: &str,
    purge: bool,
    owner: Option<(&str, &str)>,
) -> anyhow::Result<()> {
    archive_with_secondary(conn, app, purge, None, owner)
}

fn archive_with_secondary(
    conn: &mut Connection,
    app: &str,
    purge: bool,
    secondary_port: Option<(&str, Option<i32>)>,
    owner: Option<(&str, &str)>,
) -> anyhow::Result<()> {
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    check_reservation(&tx, app, owner)?;
    schema(&tx)?;
    let canonical = canonical_app(app);
    if purge {
        tx.execute(
            "DELETE FROM retained_app_ingress_configs WHERE app_name=?1",
            [app],
        )?;
        tx.execute(
            "DELETE FROM app_secondary_ports WHERE LOWER(app_name)=LOWER(?1)",
            [&canonical],
        )?;
    } else {
        if let Some(config) = read_config(&tx, app)? {
            tx.execute(
                "INSERT INTO retained_app_ingress_configs (app_name,config_json) VALUES (?1,?2)
                 ON CONFLICT(app_name) DO UPDATE SET config_json=excluded.config_json",
                params![app, serde_json::to_string(&config)?],
            )?;
        }
        if let Some((role, Some(port))) = secondary_port {
            let role_clean = role.trim();
            if !role_clean.is_empty()
                && (1..=65535).contains(&port)
                && !list_reserved_ports_excluding(&tx, &canonical)?.contains(&port)
            {
                tx.execute(
                    "INSERT INTO app_secondary_ports (app_name, port_role, port, retained)
                     VALUES (?1, ?2, ?3, 1)
                     ON CONFLICT(app_name, port_role) DO UPDATE SET port=excluded.port, retained=1",
                    params![canonical, role_clean, port],
                )?;
            }
        } else {
            tx.execute(
                "UPDATE app_secondary_ports SET retained=1 WHERE LOWER(app_name)=LOWER(?1)",
                [&canonical],
            )?;
        }
    }
    tx.execute("DELETE FROM app_ingress_configs WHERE app_name=?1", [app])?;
    if owner.is_some() {
        invalidate_app_updates_in_tx(&tx, app, true)?;
        bump_package_lifecycle_epoch_in_tx(&tx)?;
    }
    tx.commit()?;
    Ok(())
}

/// Returns all nonzero listen ports persisted or actively reserved by applications
/// other than `app` (comparing canonical application names).
pub fn list_reserved_ports_excluding(
    conn: &Connection,
    app: &str,
) -> anyhow::Result<BTreeSet<i32>> {
    let target = canonical_app(app);
    let mut reserved = BTreeSet::new();

    if has_table(conn, "app_ingress_configs")? {
        let mut stmt = conn.prepare(
            "SELECT app_name, listen_port FROM app_ingress_configs WHERE listen_port > 0",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
        })?;
        for row in rows {
            let (owner_app, port) = row?;
            if port > 0 && canonical_app(&owner_app) != target {
                reserved.insert(port);
            }
        }
    }

    if has_table(conn, "retained_app_ingress_configs")? {
        let mut stmt =
            conn.prepare("SELECT app_name, config_json FROM retained_app_ingress_configs")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (owner_app, raw_json) = row?;
            if canonical_app(&owner_app) != target {
                let port = serde_json::from_str::<AppIngressConfig>(&raw_json)
                    .ok()
                    .map(|cfg| cfg.listen_port)
                    .or_else(|| {
                        serde_json::from_str::<serde_json::Value>(&raw_json)
                            .ok()
                            .and_then(|v| {
                                v.get("listenPort")
                                    .or_else(|| v.get("listen_port"))
                                    .and_then(|n| n.as_i64())
                                    .and_then(|p| i32::try_from(p).ok())
                            })
                    })
                    .unwrap_or(0);
                if port > 0 {
                    reserved.insert(port);
                }
            }
        }
    }

    if has_table(conn, "app_secondary_ports")? {
        let mut stmt =
            conn.prepare("SELECT app_name, port FROM app_secondary_ports WHERE port > 0")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i32>(1)?))
        })?;
        for row in rows {
            let (owner_app, port) = row?;
            if port > 0 && canonical_app(&owner_app) != target {
                reserved.insert(port);
            }
        }
    }

    if has_table(conn, "package_lifecycle_jobs")? {
        let mut stmt = conn.prepare(
            "SELECT package_id, service_units FROM package_lifecycle_jobs WHERE status NOT IN ('completed','failed','interrupted')",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (pkg_id, units_json) = row?;
            if canonical_app(&pkg_id) != target {
                if let Ok(units) = serde_json::from_str::<Vec<String>>(&units_json) {
                    for unit in units {
                        if let Some(port_str) = unit.trim().strip_prefix("port:") {
                            if let Ok(port) = port_str.parse::<i32>() {
                                if port > 0 {
                                    reserved.insert(port);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(reserved)
}

/// Runs `choose(tx, reserved)` inside a single `IMMEDIATE` transaction and, when it
/// returns `Some(port)`, records `port:<port>` on the active `package_lifecycle_jobs`
/// row for `(app, job_id)` before committing.
pub fn reserve_lifecycle_port_in_tx<F>(
    conn: &mut Connection,
    app: &str,
    job_id: &str,
    action: Option<&str>,
    choose: F,
) -> anyhow::Result<Option<i32>>
where
    F: FnOnce(&Connection, &BTreeSet<i32>) -> anyhow::Result<Option<i32>>,
{
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let reserved = list_reserved_ports_excluding(&tx, app)?;
    let chosen = choose(&tx, &reserved)?;
    if let Some(port) = chosen.filter(|&p| (1..=65535).contains(&p)) {
        if !job_id.is_empty() {
            anyhow::ensure!(
                has_table(&tx, "package_lifecycle_jobs")?,
                "Lifecycle job reservation table is missing"
            );
            let target = canonical_app(app);
            let expected_status = action.and_then(|a| match a.trim() {
                "install" | "reinstall" => Some("installing"),
                "update" => Some("updating"),
                "remove" => Some("uninstalling"),
                _ => None,
            });
            let matched: Option<(String, String, String)> = {
                let mut stmt = tx.prepare(
                    "SELECT package_id, status, service_units FROM package_lifecycle_jobs WHERE job_id = ?1",
                )?;
                let mut rows = stmt.query([job_id])?;
                let mut found = None;
                while let Some(row) = rows.next()? {
                    let pkg: String = row.get(0)?;
                    if canonical_app(&pkg) == target {
                        found = Some((pkg, row.get(1)?, row.get(2)?));
                        break;
                    }
                }
                found
            };
            let Some((pkg_id, status, units_json)) = matched else {
                anyhow::bail!("Lifecycle job reservation is missing or no longer active");
            };
            anyhow::ensure!(
                !matches!(status.as_str(), "completed" | "failed" | "interrupted")
                    && expected_status.is_none_or(|exp| status == exp),
                "Lifecycle job reservation is no longer active for {pkg_id}"
            );
            let mut normalized: BTreeSet<String> = serde_json::from_str::<Vec<String>>(&units_json)
                .unwrap_or_default()
                .into_iter()
                .map(|u| {
                    u.trim()
                        .to_ascii_lowercase()
                        .trim_end_matches(".service")
                        .to_owned()
                })
                .filter(|u| !u.is_empty())
                .collect();
            if normalized.insert(format!("port:{port}")) {
                let updated: Vec<String> = normalized.into_iter().collect();
                tx.execute(
                    "UPDATE package_lifecycle_jobs SET service_units=?1 WHERE package_id=?2 AND job_id=?3",
                    params![serde_json::to_string(&updated)?, pkg_id, job_id],
                )?;
            }
        }
    }
    tx.commit()?;
    Ok(chosen)
}

/// Returns all nonzero listen ports persisted or actively reserved by applications
/// other than `app` using the global SQLite connection pool.
pub fn get_reserved_ports_excluding(app: &str) -> anyhow::Result<BTreeSet<i32>> {
    let conn = crate::get_conn()?;
    list_reserved_ports_excluding(&conn, app)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_lookup_accepts_a_database_without_a_retained_ingress_table() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "query_only", true).unwrap();
        assert!(read_retained_config(&conn, "maintainerr")
            .unwrap()
            .is_none());
    }

    #[test]
    fn shared_callbacks_archive_updates_and_restore_custom_ingress_with_real_schema() {
        let mut conn = Connection::open_in_memory().unwrap();
        let config = fixture(&conn);
        conn.execute(
            "INSERT INTO app_updates(package_name) VALUES ('maintainerr')",
            [],
        )
        .unwrap();
        conn.execute("INSERT INTO package_lifecycle_jobs VALUES ('maintainerr','remove-job','remove','uninstalling','[\"af-maintainerr\"]')", []).unwrap();
        synchronize_lifecycle_ingress(
            &mut conn,
            "maintainerr",
            "remove",
            "remove-job",
            0,
            false,
            "",
        )
        .unwrap();
        assert!(read_config(&conn, "maintainerr").unwrap().is_none());
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM app_updates", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
        conn.execute("UPDATE package_lifecycle_jobs SET job_id='install-job',action='install',status='installing'", []).unwrap();
        synchronize_lifecycle_ingress(
            &mut conn,
            "maintainerr",
            "install",
            "install-job",
            config.listen_port,
            false,
            "https://default.example.test/",
        )
        .unwrap();
        let restored = read_config(&conn, "maintainerr").unwrap().unwrap();
        assert_eq!(restored.public_domain, config.public_domain);
        assert_eq!(restored.tls_enabled, config.tls_enabled);
        assert_eq!(
            restored.external_access_enabled,
            config.external_access_enabled
        );
        assert_eq!(restored.listen_port, config.listen_port);
        assert!(synchronize_lifecycle_ingress(
            &mut conn,
            "maintainerr",
            "install",
            "stale-job",
            19000,
            false,
            ""
        )
        .is_err());
        conn.execute("UPDATE package_lifecycle_jobs SET job_id='purge-job',action='remove',status='uninstalling'", []).unwrap();
        synchronize_lifecycle_ingress(&mut conn, "maintainerr", "remove", "purge-job", 0, true, "")
            .unwrap();
        assert!(read_retained_config(&conn, "maintainerr")
            .unwrap()
            .is_none());
    }

    #[test]
    fn missing_required_update_table_rolls_back_entire_removal_callback() {
        let mut conn = Connection::open_in_memory().unwrap();
        fixture(&conn);
        conn.execute("INSERT INTO package_lifecycle_jobs VALUES ('maintainerr','job','remove','uninstalling','[]')", []).unwrap();
        conn.execute_batch("DROP TABLE app_updates").unwrap();
        assert!(synchronize_lifecycle_ingress(
            &mut conn,
            "maintainerr",
            "remove",
            "job",
            0,
            false,
            ""
        )
        .is_err());
        assert!(read_config(&conn, "maintainerr").unwrap().is_some());
        assert!(read_retained_config(&conn, "maintainerr")
            .unwrap()
            .is_none());
    }

    fn fixture(conn: &Connection) -> AppIngressConfig {
        conn.execute_batch("CREATE TABLE app_ingress_configs (
            app_name TEXT PRIMARY KEY,public_domain TEXT,external_access_enabled BOOLEAN,
            listen_port INTEGER,tls_enabled BOOLEAN,created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE package_lifecycle_jobs (package_id TEXT PRIMARY KEY,job_id TEXT,action TEXT,status TEXT,service_units TEXT);
            CREATE TABLE app_updates (package_name TEXT PRIMARY KEY);").unwrap();
        let config = AppIngressConfig {
            app_name: "maintainerr".into(),
            listen_port: 18421,
            public_domain: "custom.example.test".into(),
            external_access_enabled: true,
            tls_enabled: false,
            ..Default::default()
        };
        crate::write_app_ingress_config(conn, &config).unwrap();
        config
    }

    fn retained(conn: &Connection) -> AppIngressConfig {
        let raw: String = conn
            .query_row(
                "SELECT config_json FROM retained_app_ingress_configs WHERE app_name='maintainerr'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    #[test]
    fn ordinary_removal_archives_reinstall_settings_but_purge_deletes_them() {
        let mut conn = Connection::open_in_memory().unwrap();
        let config = fixture(&conn);
        archive(&mut conn, "maintainerr", false, None).unwrap();
        assert!(read_config(&conn, "maintainerr").unwrap().is_none());
        assert_eq!(retained(&conn).public_domain, config.public_domain);
        assert_eq!(retained(&conn).listen_port, config.listen_port);
        assert!(!retained(&conn).tls_enabled);
        archive(&mut conn, "maintainerr", false, None).unwrap();
        assert_eq!(retained(&conn).listen_port, config.listen_port);
        archive(&mut conn, "maintainerr", true, None).unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM retained_app_ingress_configs",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn archive_waits_for_writer_and_retains_latest_committed_row() {
        let path = std::env::temp_dir().join(format!(
            "af-ingress-{}-{}.sqlite",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        let mut writer = Connection::open(&path).unwrap();
        fixture(&writer);
        writer.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        let tx = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE app_ingress_configs SET public_domain='new.example.test',listen_port=19421",
            [],
        )
        .unwrap();
        let mut archiver = Connection::open(&path).unwrap();
        archiver.busy_timeout(std::time::Duration::ZERO).unwrap();
        assert!(archive(&mut archiver, "maintainerr", false, None).is_err());
        tx.commit().unwrap();
        archive(&mut archiver, "maintainerr", false, None).unwrap();
        assert_eq!(retained(&archiver).public_domain, "new.example.test");
        assert_eq!(retained(&archiver).listen_port, 19421);
        assert!(read_config(&archiver, "maintainerr").unwrap().is_none());
        drop(archiver);
        drop(writer);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn teardown_fences_all_setter_aliases_and_only_matching_reinstall_can_restore() {
        let mut conn = Connection::open_in_memory().unwrap();
        let config = fixture(&conn);
        conn.execute("INSERT INTO package_lifecycle_jobs VALUES ('maintainerr','remove-job','remove','uninstalling','[\"af-maintainerr.service\"]')", []).unwrap();
        for alias in [
            "maintainerr",
            "af-maintainerr",
            "af-maintainerr.service",
            " Maintainerr.service ",
        ] {
            let mut attempt = config.clone();
            attempt.app_name = alias.into();
            assert!(set_config(&mut conn, &attempt, None).is_err());
            assert!(set_config(&mut conn, &attempt, Some(("remove-job", "remove"))).is_err());
        }
        assert!(archive(
            &mut conn,
            "maintainerr",
            false,
            Some(("stale-job", "remove"))
        )
        .is_err());
        archive(
            &mut conn,
            "maintainerr",
            false,
            Some(("remove-job", "remove")),
        )
        .unwrap();
        assert!(set_config(&mut conn, &config, None).is_err());
        assert!(read_config(&conn, "maintainerr").unwrap().is_none());
        conn.execute("UPDATE package_lifecycle_jobs SET job_id='install-job',action='install',status='installing'", []).unwrap();
        assert!(set_config(&mut conn, &config, Some(("remove-job", "install"))).is_err());
        assert!(set_config(&mut conn, &config, Some(("install-job", "update"))).is_err());
        let restored = retained(&conn);
        set_config(&mut conn, &restored, Some(("install-job", "install"))).unwrap();
        assert_eq!(
            read_config(&conn, "maintainerr")
                .unwrap()
                .unwrap()
                .listen_port,
            config.listen_port
        );
        conn.execute("UPDATE package_lifecycle_jobs SET status='completed'", [])
            .unwrap();
        assert!(set_config(&mut conn, &config, Some(("install-job", "install"))).is_err());
        set_config(&mut conn, &config, None).unwrap();

        // Old lifecycle rows can lack a recorded unit alias.
        conn.execute(
            "INSERT INTO package_lifecycle_jobs VALUES ('plex','plex-job','remove','uninstalling','[]')",
            [],
        )
        .unwrap();
        assert!(check_reservation(&conn, " PlexMediaServer.service ", None).is_err());
        assert!(check_reservation(&conn, "plexmediaserver", Some(("plex-job", "remove"))).is_ok());
    }

    #[test]
    fn archive_delete_failure_rolls_back_retained_and_active_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        fixture(&conn);
        schema(&conn).unwrap();
        conn.execute_batch("CREATE TRIGGER refuse_delete BEFORE DELETE ON app_ingress_configs BEGIN SELECT RAISE(ABORT,'fixture delete failure'); END;").unwrap();
        assert!(archive(&mut conn, "maintainerr", false, None).is_err());
        assert!(read_config(&conn, "maintainerr").unwrap().is_some());
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM retained_app_ingress_configs",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn afmp003_write_app_ingress_config_and_reserved_ports_prevent_cross_app_port_stealing() {
        let mut conn = Connection::open_in_memory().unwrap();
        let config = fixture(&conn); // maintainerr on port 16246

        let reserved_for_other = list_reserved_ports_excluding(&conn, "sonarr").unwrap();
        assert!(reserved_for_other.contains(&config.listen_port));
        let reserved_for_self = list_reserved_ports_excluding(&conn, "maintainerr").unwrap();
        assert!(!reserved_for_self.contains(&config.listen_port));

        // Another app attempting to claim maintainerr's persisted port must be rejected
        let conflict = AppIngressConfig {
            app_name: "sonarr".into(),
            public_domain: "sonarr.example.test".into(),
            external_access_enabled: true,
            listen_port: config.listen_port,
            tls_enabled: true,
            ..Default::default()
        };
        assert!(set_config(&mut conn, &conflict, None).is_err());

        // Even after maintainerr is removed with data retention, its retained port remains reserved against other apps
        archive(&mut conn, "maintainerr", false, None).unwrap();
        assert!(list_reserved_ports_excluding(&conn, "sonarr")
            .unwrap()
            .contains(&config.listen_port));
        assert!(set_config(&mut conn, &conflict, None).is_err());
    }

    #[test]
    fn base_domain_sync_state_and_retained_updates_handle_legacy_schema_and_reservations() {
        let mut conn = Connection::open_in_memory().unwrap();
        // Legacy DB without base_domain_sync_state or retained_app_ingress_configs
        assert_eq!(get_pending_base_domain_sync(&conn).unwrap(), None);
        assert!(read_all_retained_configs(&conn).unwrap().is_empty());
        clear_pending_base_domain_sync(&conn).unwrap();

        // Legacy 2-column base_domain_sync_state table remains readable on query_only connections
        // and upgrades cleanly when preserving accumulated source domains across retries.
        conn.execute_batch(
            "CREATE TABLE base_domain_sync_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                previous_base_domain TEXT NOT NULL DEFAULT '',
                target_base_domain TEXT NOT NULL DEFAULT '',
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            INSERT INTO base_domain_sync_state (id, previous_base_domain, target_base_domain)
            VALUES (1, 'https://Old.Example.Test/', '*.New.Example.Test');",
        )
        .unwrap();
        conn.pragma_update(None, "query_only", true).unwrap();
        assert_eq!(
            get_pending_base_domain_sync(&conn).unwrap(),
            Some(PendingBaseDomainSync {
                previous_base_domain: "old.example.test".into(),
                target_base_domain: "new.example.test".into(),
                source_base_domains: vec!["old.example.test".into(), "new.example.test".into()],
            })
        );
        conn.pragma_update(None, "query_only", false).unwrap();

        // Pending base-domain sync round-trip + normalization + multi-source preservation
        set_pending_base_domain_sync(
            &conn,
            "https://Old.Example.Test/",
            "Third.Example.Test.",
            &[
                "https://Old.Example.Test/".into(),
                "*.New.Example.Test".into(),
                "new.example.test".into(),
            ],
        )
        .unwrap();
        assert_eq!(
            get_pending_base_domain_sync(&conn).unwrap(),
            Some(PendingBaseDomainSync {
                previous_base_domain: "old.example.test".into(),
                target_base_domain: "third.example.test".into(),
                source_base_domains: vec![
                    "old.example.test".into(),
                    "new.example.test".into(),
                    "third.example.test".into(),
                ],
            })
        );
        clear_pending_base_domain_sync(&conn).unwrap();
        assert_eq!(get_pending_base_domain_sync(&conn).unwrap(), None);

        // Retained update honors active lifecycle reservations
        let mut config = fixture(&conn);
        archive(&mut conn, "maintainerr", false, None).unwrap();
        conn.execute(
            "INSERT INTO package_lifecycle_jobs(package_id,job_id,action,status,service_units)
             VALUES ('maintainerr','job-1','install','installing','[\"af-maintainerr\"]')",
            [],
        )
        .unwrap();
        config.public_domain = "maintainerr.new.example.test".into();
        assert!(update_retained_app_ingress_config_in_tx(&conn, "maintainerr", &config).is_err());

        conn.execute(
            "UPDATE package_lifecycle_jobs SET status='completed' WHERE job_id='job-1'",
            [],
        )
        .unwrap();
        update_retained_app_ingress_config_in_tx(&conn, "maintainerr", &config).unwrap();
        let all = read_all_retained_configs(&conn).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].0, "maintainerr");
        assert_eq!(all[0].1.public_domain, "maintainerr.new.example.test");
    }

    #[test]
    fn secondary_port_lifecycle_swap_retain_downgrade_purge_and_concurrent_allocation() {
        let role = af_models::RCLONE_RC_API_PORT_ROLE;
        let mut conn = Connection::open_in_memory().unwrap();
        fixture(&conn);
        let set_job = |c: &Connection, id: &str, act: &str, st: &str| {
            c.execute(
                "INSERT INTO package_lifecycle_jobs VALUES ('rclone',?1,?2,?3,'[\"rclone\"]')
                 ON CONFLICT(package_id) DO UPDATE SET job_id=excluded.job_id, action=excluded.action, status=excluded.status",
                params![id, act, st],
            )
            .unwrap();
        };

        // 1. Atomic primary + secondary commit blocks other apps and prevents manual self-conflict.
        set_job(&conn, "job-1", "install", "installing");
        synchronize_lifecycle_ingress_with_secondary_port(
            &mut conn,
            "rclone",
            "install",
            "job-1",
            5572,
            Some((role, Some(5573))),
            false,
            "example.test",
        )
        .unwrap();
        set_job(&conn, "job-1", "install", "completed");
        assert_eq!(
            load_lifecycle_secondary_port(&conn, "rclone", role).unwrap(),
            Some(5573)
        );
        let reserved = list_reserved_ports_excluding(&conn, "sonarr").unwrap();
        assert!(reserved.contains(&5572) && reserved.contains(&5573));
        assert!(set_config(
            &mut conn,
            &AppIngressConfig {
                app_name: "sonarr".into(),
                listen_port: 5573,
                ..Default::default()
            },
            None
        )
        .is_err());
        assert!(set_config(
            &mut conn,
            &AppIngressConfig {
                app_name: "rclone".into(),
                listen_port: 5573,
                ..Default::default()
            },
            None
        )
        .is_err());

        // 2. Atomic swap: GUI moves onto old RC port 5573 while RC moves to 17005.
        set_job(&conn, "job-2", "reinstall", "installing");
        synchronize_lifecycle_ingress_with_secondary_port(
            &mut conn,
            "rclone",
            "reinstall",
            "job-2",
            5573,
            Some((role, Some(17005))),
            false,
            "example.test",
        )
        .unwrap();
        assert_eq!(
            read_config(&conn, "rclone").unwrap().unwrap().listen_port,
            5573
        );
        assert_eq!(
            load_lifecycle_secondary_port(&conn, "rclone", role).unwrap(),
            Some(17005)
        );

        // 3. Retained remove marks retained=1 and keeps 17005 reserved; idempotent second retain keeps it.
        set_job(&conn, "job-3", "remove", "uninstalling");
        for _ in 0..2 {
            synchronize_lifecycle_ingress_with_secondary_port(
                &mut conn, "rclone", "remove", "job-3", 0, None, false, "",
            )
            .unwrap();
        }
        let retained_flag: i64 = conn
            .query_row("SELECT retained FROM app_secondary_ports WHERE app_name='rclone' AND port_role='rc_api'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(retained_flag, 1);
        assert!(list_reserved_ports_excluding(&conn, "sonarr")
            .unwrap()
            .contains(&17005));

        // 4. Downgrade to single-port clears secondary port and releases 17005.
        set_job(&conn, "job-4", "reinstall", "installing");
        synchronize_lifecycle_ingress_with_secondary_port(
            &mut conn,
            "rclone",
            "reinstall",
            "job-4",
            5573,
            Some((role, None)),
            false,
            "example.test",
        )
        .unwrap();
        assert_eq!(
            load_lifecycle_secondary_port(&conn, "rclone", role).unwrap(),
            None
        );
        assert!(!list_reserved_ports_excluding(&conn, "sonarr")
            .unwrap()
            .contains(&17005));

        // 5. Pre-fix retained remove seeds retained=1 from pre-remove port; purge deletes it.
        set_job(&conn, "job-5", "remove", "uninstalling");
        synchronize_lifecycle_ingress_with_secondary_port(
            &mut conn,
            "rclone",
            "remove",
            "job-5",
            0,
            Some((role, Some(17006))),
            false,
            "",
        )
        .unwrap();
        assert_eq!(
            load_lifecycle_secondary_port(&conn, "rclone", role).unwrap(),
            Some(17006)
        );
        synchronize_lifecycle_ingress_with_secondary_port(
            &mut conn, "rclone", "remove", "job-5", 0, None, true, "",
        )
        .unwrap();
        assert_eq!(
            load_lifecycle_secondary_port(&conn, "rclone", role).unwrap(),
            None
        );

        // 6. Concurrent atomic allocation across two connections never assigns the same port.
        let path = std::env::temp_dir().join(format!(
            "af-concurrent-ports-{}-{}.db",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let setup = Connection::open(&path).unwrap();
        setup
            .busy_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        fixture(&setup);
        setup.execute_batch(
            "PRAGMA journal_mode=WAL;
             INSERT INTO package_lifecycle_jobs VALUES ('rclone','rc-job','install','installing','[\"rclone\"]');
             INSERT INTO package_lifecycle_jobs VALUES ('sonarr','sn-job','install','installing','[\"sonarr\"]');",
        ).unwrap();
        drop(setup);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let spawn_alloc = |app: &'static str, jid: &'static str, skip: i32| {
            let (p, b) = (path.clone(), barrier.clone());
            std::thread::spawn(move || {
                let mut c = Connection::open(&p).unwrap();
                c.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
                b.wait();
                reserve_lifecycle_port_in_tx(&mut c, app, jid, Some("install"), |_, res| {
                    Ok(std::iter::once(5573)
                        .chain(17000..=17010)
                        .find(|n| *n != skip && !res.contains(n)))
                })
                .unwrap()
                .unwrap()
            })
        };
        let t1 = spawn_alloc("rclone", "rc-job", 5572);
        let t2 = spawn_alloc("sonarr", "sn-job", 0);
        let (rclone_alloc, sonarr_alloc) = (t1.join().unwrap(), t2.join().unwrap());
        assert_ne!(
            rclone_alloc, sonarr_alloc,
            "concurrent allocators must never hand out the same port"
        );
        let check = Connection::open(&path).unwrap();
        let reserved_by_others = list_reserved_ports_excluding(&check, "radarr").unwrap();
        assert!(
            reserved_by_others.contains(&rclone_alloc)
                && reserved_by_others.contains(&sonarr_alloc)
        );
        drop(check);
        for p in [
            path.clone(),
            path.with_extension("db-wal"),
            path.with_extension("db-shm"),
        ] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn lifecycle_commits_atomically_invalidate_alias_updates_and_bump_epoch_in_single_tx() {
        let mut conn = Connection::open_in_memory().unwrap();
        fixture(&conn);

        let read_epoch = |c: &Connection| -> Option<String> {
            if !has_table(c, "system_config").unwrap() {
                return None;
            }
            c.query_row(
                "SELECT value FROM system_config WHERE key = 'package_lifecycle_epoch'",
                [],
                |r| r.get(0),
            )
            .optional()
            .unwrap()
        };

        // 1. Non-lifecycle set_config (owner: None) must NOT delete app_updates or bump epoch.
        conn.execute(
            "INSERT INTO app_updates(package_name) VALUES ('AutoDLIRSSI'), ('radarr')",
            [],
        )
        .unwrap();
        set_config(
            &mut conn,
            &AppIngressConfig {
                app_name: "autodl".into(),
                listen_port: 18501,
                ..Default::default()
            },
            None,
        )
        .unwrap();
        assert_eq!(read_epoch(&conn), None);
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM app_updates", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            2
        );

        // 2. Lifecycle set_config_with_secondary_port (owner: Some) atomically deletes
        //    alias/case-normalized app_updates and bumps package_lifecycle_epoch.
        conn.execute(
            "INSERT INTO package_lifecycle_jobs VALUES ('autodl','upd-1','update','updating','[\"autodlirssi\"]')",
            [],
        )
        .unwrap();
        set_config_with_secondary_port(
            &mut conn,
            &AppIngressConfig {
                app_name: "autodl".into(),
                listen_port: 18502,
                ..Default::default()
            },
            None,
            Some(("upd-1", "update")),
        )
        .unwrap();
        assert_eq!(read_epoch(&conn).as_deref(), Some("1"));
        let remaining: Vec<String> = conn
            .prepare("SELECT package_name FROM app_updates ORDER BY package_name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(remaining, vec!["radarr"]);

        // 3. synchronize_lifecycle_ingress_with_secondary_port with port == 0 (non-web install/update)
        //    also invalidates alias/case-normalized app_updates and bumps epoch atomically.
        conn.execute(
            "INSERT INTO app_updates(package_name) VALUES ('Transmission'), ('transmission-daemon')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO package_lifecycle_jobs VALUES ('transmission-daemon','inst-2','install','installing','[\"transmission\"]')",
            [],
        )
        .unwrap();
        synchronize_lifecycle_ingress_with_secondary_port(
            &mut conn,
            "transmission-daemon",
            "install",
            "inst-2",
            0,
            None,
            false,
            "",
        )
        .unwrap();
        assert_eq!(read_epoch(&conn).as_deref(), Some("2"));
        let remaining_after_install: Vec<String> = conn
            .prepare("SELECT package_name FROM app_updates ORDER BY package_name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(remaining_after_install, vec!["radarr"]);

        // 4. Remove (archive_with_secondary) atomically deletes alias/case-matched app_updates and bumps epoch.
        conn.execute(
            "INSERT INTO app_updates(package_name) VALUES ('AutoDL'), ('autodlirssi')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE package_lifecycle_jobs SET job_id='rm-3', action='remove', status='uninstalling' WHERE package_id='autodl'",
            [],
        )
        .unwrap();
        synchronize_lifecycle_ingress_with_secondary_port(
            &mut conn, "autodl", "remove", "rm-3", 0, None, false, "",
        )
        .unwrap();
        assert_eq!(read_epoch(&conn).as_deref(), Some("3"));
        assert!(read_config(&conn, "autodl").unwrap().is_none());
        let remaining_after_remove: Vec<String> = conn
            .prepare("SELECT package_name FROM app_updates ORDER BY package_name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(remaining_after_remove, vec!["radarr"]);

        // 5. Single-transaction rollback atomicity: if system_config epoch update fails,
        //    the entire lifecycle ingress write + app_updates delete rolls back together.
        conn.execute(
            "INSERT INTO app_updates(package_name) VALUES ('autodlirssi')",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE package_lifecycle_jobs SET job_id='inst-rb', action='install', status='installing' WHERE package_id='autodl'",
            [],
        )
        .unwrap();
        conn.execute_batch(
            "CREATE TRIGGER abort_epoch_bump BEFORE UPDATE ON system_config
             BEGIN SELECT RAISE(ABORT, 'simulated epoch bump failure'); END;",
        )
        .unwrap();
        assert!(synchronize_lifecycle_ingress_with_secondary_port(
            &mut conn,
            "autodl",
            "install",
            "inst-rb",
            18503,
            None,
            false,
            "example.test",
        )
        .is_err());
        assert!(
            read_config(&conn, "autodl").unwrap().is_none(),
            "ingress write must roll back when epoch bump fails in the same transaction"
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM app_updates WHERE LOWER(package_name) = 'autodlirssi'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .unwrap(),
            1,
            "app_updates delete must roll back when epoch bump fails in the same transaction"
        );
        assert_eq!(read_epoch(&conn).as_deref(), Some("3"));
    }
}
