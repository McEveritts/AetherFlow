use super::types::{PluginRegistryState, ACTIVE_PROCESSES};
use af_models::{PLUGIN_PORT_RANGE_END, PLUGIN_PORT_RANGE_START};
use rusqlite::{params, OptionalExtension};
use std::collections::HashSet;
use std::net::TcpListener;

fn default_registry_state(plugin_id: &str) -> PluginRegistryState {
    PluginRegistryState {
        plugin_id: plugin_id.to_string(),
        enabled: false,
        allocated_port: 0,
        token_epoch: 1,
        status: "stopped".to_string(),
        last_health_at: None,
        last_error: String::new(),
    }
}

pub(super) fn try_read_registry_state(plugin_id: &str) -> Result<PluginRegistryState, String> {
    let conn = af_db::get_read_conn()
        .map_err(|err| format!("Failed to open plugin registry database: {err}"))?;
    let state = conn
        .query_row(
            "SELECT plugin_id, enabled, allocated_port, token_epoch, status, last_health_at, COALESCE(last_error, '') \
             FROM plugins_registry WHERE plugin_id = ?1",
            params![plugin_id],
            |r| {
                Ok(PluginRegistryState {
                    plugin_id: r.get(0)?,
                    enabled: r.get(1)?,
                    allocated_port: r.get::<_, i64>(2)?.clamp(0, 65535) as u16,
                    token_epoch: r.get(3)?,
                    status: r.get(4)?,
                    last_health_at: r.get(5).ok().flatten(),
                    last_error: r.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|err| format!("Failed to query plugin registry state: {err}"))?;
    Ok(state.unwrap_or_else(|| default_registry_state(plugin_id)))
}

pub(super) fn read_registry_state(plugin_id: &str) -> PluginRegistryState {
    match try_read_registry_state(plugin_id) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(plugin = %plugin_id, %error, "Falling back to default plugin registry state");
            default_registry_state(plugin_id)
        }
    }
}

pub(super) fn try_update_registry_state(
    plugin_id: &str,
    enabled: bool,
    allocated_port: u16,
    status: &str,
    last_error: &str,
    bump_epoch: bool,
) -> Result<PluginRegistryState, String> {
    let conn = af_db::get_conn()
        .map_err(|err| format!("Failed to open plugin registry database: {err}"))?;
    conn.execute(
        "INSERT OR IGNORE INTO plugins_registry (plugin_id, enabled, allocated_port, token_epoch, status) VALUES (?1, 0, 0, 1, 'stopped')",
        params![plugin_id],
    )
    .map_err(|err| format!("Failed to initialize plugin registry entry: {err}"))?;
    if bump_epoch {
        conn.execute(
            "UPDATE plugins_registry SET enabled = ?1, allocated_port = ?2, status = ?3, last_error = ?4, \
             token_epoch = token_epoch + 1, updated_at = CURRENT_TIMESTAMP WHERE plugin_id = ?5",
            params![enabled, allocated_port as i64, status, last_error, plugin_id],
        )
        .map_err(|err| format!("Failed to update plugin registry entry: {err}"))?;
    } else {
        conn.execute(
            "UPDATE plugins_registry SET enabled = ?1, allocated_port = ?2, status = ?3, last_error = ?4, \
             updated_at = CURRENT_TIMESTAMP WHERE plugin_id = ?5",
            params![enabled, allocated_port as i64, status, last_error, plugin_id],
        )
        .map_err(|err| format!("Failed to update plugin registry entry: {err}"))?;
    }
    drop(conn);
    try_read_registry_state(plugin_id)
}

pub(crate) fn update_registry_state(
    plugin_id: &str,
    enabled: bool,
    allocated_port: u16,
    status: &str,
    last_error: &str,
    bump_epoch: bool,
) -> PluginRegistryState {
    match try_update_registry_state(
        plugin_id,
        enabled,
        allocated_port,
        status,
        last_error,
        bump_epoch,
    ) {
        Ok(state) => state,
        Err(error) => {
            tracing::warn!(plugin = %plugin_id, %error, "Failed to persist plugin registry state");
            read_registry_state(plugin_id)
        }
    }
}

pub(super) fn allocate_plugin_port(
    plugin_id: &str,
    preferred: u16,
    allow_listening_preferred: bool,
) -> Result<u16, String> {
    let mut used_ports = HashSet::new();
    let conn = af_db::get_conn().map_err(|err| {
        format!("Failed to open plugin registry database for port allocation: {err}")
    })?;
    let mut stmt = conn
        .prepare("SELECT plugin_id, allocated_port FROM plugins_registry WHERE allocated_port > 0")
        .map_err(|err| format!("Failed to prepare plugin port query: {err}"))?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map_err(|err| format!("Failed to query allocated plugin ports: {err}"))?;
    for row in rows {
        let (pid, p) = row.map_err(|err| format!("Failed to read allocated plugin port: {err}"))?;
        if pid != plugin_id && (1024..=65535).contains(&p) {
            used_ports.insert(p as u16);
        }
    }
    drop(stmt);
    drop(conn);

    if let Ok(procs) = ACTIVE_PROCESSES.lock() {
        for (pid, proc_entry) in procs.iter() {
            if pid != plugin_id {
                used_ports.insert(proc_entry.port);
            }
        }
    }

    if (PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END).contains(&preferred)
        && !used_ports.contains(&preferred)
        && (allow_listening_preferred || TcpListener::bind(("127.0.0.1", preferred)).is_ok())
    {
        return Ok(preferred);
    }

    for port in PLUGIN_PORT_RANGE_START..=PLUGIN_PORT_RANGE_END {
        if used_ports.contains(&port) {
            continue;
        }
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }

    Err("No available loopback ports in plugin range 21000..21999".to_string())
}
