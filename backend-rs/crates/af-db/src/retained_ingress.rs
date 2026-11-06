use af_models::AppIngressConfig;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

fn schema(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS retained_app_ingress_configs (app_name TEXT PRIMARY KEY, config_json TEXT NOT NULL);")?;
    Ok(())
}

fn canonical_app(app: &str) -> String {
    let normalized = app.trim().to_ascii_lowercase();
    match normalized.trim_end_matches(".service") {
        "af-maintainerr" => "maintainerr".into(),
        "af-palate" => "palate".into(),
        "af-kasmvnc" => "kasmvnc".into(),
        "af-mcvnc" => "mcvnc".into(),
        "deluged" | "deluge-web" => "deluge".into(),
        "paperless" | "paperless-webserver" | "paperless-worker" | "paperless-scheduler" => {
            "paperless-ngx".into()
        }
        "dispatcharr-celery" | "dispatcharr-celerybeat" => "dispatcharr".into(),
        "novnc-xvnc" => "novnc".into(),
        "xrdp-sesman" => "xrdp".into(),
        "node_exporter" => "prometheus".into(),
        "rclone-vfs" => "rclone".into(),
        "scrutiny-collector" | "scrutiny-collector.timer" => "scrutiny".into(),
        "recyclarr.timer" => "recyclarr".into(),
        name => name.into(),
    }
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
            "install" => "installing",
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
    if let Some((identity, action)) = owner {
        anyhow::ensure!(
            !identity.is_empty() && matches!(action, "install" | "update"),
            "Invalid ingress lifecycle owner"
        );
    }
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    check_reservation(&tx, &config.app_name, owner)?;
    crate::write_app_ingress_config(&tx, config)?;
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
    let conn = crate::get_conn()?;
    read_retained_config(&conn, app)
}

fn read_retained_config(conn: &Connection, app: &str) -> anyhow::Result<Option<AppIngressConfig>> {
    schema(&conn)?;
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

pub fn synchronize_lifecycle_ingress(
    conn: &mut Connection,
    app: &str,
    action: &str,
    job_id: &str,
    port: i32,
    purge: bool,
    base_domain: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(!job_id.is_empty(), "Ingress lifecycle identity is required");
    anyhow::ensure!(
        matches!(action, "install" | "update" | "remove"),
        "Invalid ingress lifecycle action"
    );
    anyhow::ensure!(
        !purge || action == "remove",
        "Purge requires package removal"
    );
    if action == "remove" {
        archive(conn, app, purge, Some((job_id, action)))?;
    } else {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        check_reservation(&tx, app, Some((job_id, action)))?;
        if port > 0 {
            anyhow::ensure!(
                (1024..=65535).contains(&port),
                "Invalid ingress listen port"
            );
            let existing = load_lifecycle_ingress(&tx, app)?;
            let domain = existing
                .as_ref()
                .map(|config| config.public_domain.clone())
                .filter(|domain| !domain.is_empty())
                .unwrap_or_else(|| {
                    let domain = crate::normalize_base_domain(base_domain);
                    if domain.is_empty() {
                        String::new()
                    } else {
                        let clean: String = app
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
                        format!("{}.{}", clean.trim_matches('-'), domain)
                    }
                });
            let now = chrono::Utc::now();
            let config = AppIngressConfig {
                app_name: app.to_owned(),
                external_access_enabled: existing
                    .as_ref()
                    .map(|config| config.external_access_enabled)
                    .unwrap_or(!domain.is_empty()),
                tls_enabled: existing
                    .as_ref()
                    .map(|config| config.tls_enabled)
                    .unwrap_or(!domain.is_empty()),
                public_domain: domain,
                listen_port: port,
                created_at: existing
                    .as_ref()
                    .map(|config| config.created_at)
                    .unwrap_or(now),
                updated_at: now,
            };
            crate::write_app_ingress_config(&tx, &config)?;
        }
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
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    check_reservation(&tx, app, owner)?;
    schema(&tx)?;
    if purge {
        tx.execute(
            "DELETE FROM retained_app_ingress_configs WHERE app_name=?1",
            [app],
        )?;
    } else if let Some(config) = read_config(&tx, app)? {
        tx.execute(
            "INSERT INTO retained_app_ingress_configs (app_name,config_json) VALUES (?1,?2)
             ON CONFLICT(app_name) DO UPDATE SET config_json=excluded.config_json",
            params![app, serde_json::to_string(&config)?],
        )?;
    }
    tx.execute("DELETE FROM app_ingress_configs WHERE app_name=?1", [app])?;
    if owner.is_some() {
        tx.execute("DELETE FROM app_updates WHERE package_name=?1", [app])?;
    }
    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
