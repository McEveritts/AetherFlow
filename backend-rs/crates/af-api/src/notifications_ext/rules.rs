use super::models::{CreateRuleReq, UpdateRuleReq};
use crate::auth::api_error;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use rusqlite::params;

fn normalize_rule_level(level: &str) -> Result<String, &'static str> {
    let level = level.trim().to_ascii_lowercase();
    match level.as_str() {
        "info" | "warning" | "critical" => Ok(level),
        _ => Err("Invalid level. Allowed levels are info, warning, and critical"),
    }
}

pub(super) fn percentage_threshold(value: &str) -> Result<f64, &'static str> {
    value
        .trim()
        .parse::<f64>()
        .ok()
        .filter(|threshold| (0.0..=100.0).contains(threshold))
        .ok_or("condition_value must be a finite percentage between 0 and 100")
}

fn validate_rule_condition(condition_type: &str, value: &str) -> Result<(), &'static str> {
    match condition_type {
        "disk_usage" | "cpu_usage" | "memory_usage" => percentage_threshold(value).map(|_| ()),
        // This condition identifies a service by name.
        "service_down" if !value.is_empty() && value.len() <= 128 => Ok(()),
        "service_down" => Err("condition_value must identify a service"),
        _ => Err("Invalid condition_type. Allowed types are disk_usage, cpu_usage, memory_usage, and service_down"),
    }
}

fn rule_validation_error(message: &str) -> Response {
    api_error(StatusCode::BAD_REQUEST, "VALIDATION_ERROR", message)
}

pub async fn create_notification_rule(Json(req): Json<CreateRuleReq>) -> Response {
    if req.name.trim().is_empty() || req.name.trim().len() > 128 {
        return rule_validation_error("Rule name must be between 1 and 128 characters");
    }
    let condition_type = req.condition_type.trim();
    let value = req.condition_value.trim();
    if let Err(message) = validate_rule_condition(condition_type, value) {
        return rule_validation_error(message);
    }
    let level = match normalize_rule_level(&req.level) {
        Ok(level) => level,
        Err(message) => return rule_validation_error(message),
    };

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create rule",
        );
    };

    if conn
        .execute(
            "INSERT INTO notification_rules (name, condition_type, condition_value, level) VALUES (?1, ?2, ?3, ?4)",
            params![req.name.trim(), condition_type, value, level],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create rule",
        );
    }

    let id = conn.last_insert_rowid();
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Rule created",
            "id": id,
        })),
    )
        .into_response()
}

pub async fn update_notification_rule(
    Path(id): Path<i64>,
    Json(req): Json<UpdateRuleReq>,
) -> Response {
    let mut set_clauses: Vec<String> = Vec::new();
    let mut bind_params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(ref name) = req.name {
        let trimmed = name.trim();
        if trimmed.is_empty() || trimmed.len() > 128 {
            return api_error(
                StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                "Rule name must be between 1 and 128 characters",
            );
        }
        bind_params.push(Box::new(trimmed.to_string()));
        set_clauses.push(format!("name = ?{}", bind_params.len()));
    }
    if let Some(ref condition_type) = req.condition_type {
        bind_params.push(Box::new(condition_type.trim().to_string()));
        set_clauses.push(format!("condition_type = ?{}", bind_params.len()));
    }
    if let Some(ref value) = req.condition_value {
        bind_params.push(Box::new(value.trim().to_string()));
        set_clauses.push(format!("condition_value = ?{}", bind_params.len()));
    }
    if let Some(ref level) = req.level {
        let level = match normalize_rule_level(level) {
            Ok(level) => level,
            Err(message) => return rule_validation_error(message),
        };
        bind_params.push(Box::new(level));
        set_clauses.push(format!("level = ?{}", bind_params.len()));
    }
    if let Some(enabled) = req.enabled {
        bind_params.push(Box::new(enabled));
        set_clauses.push(format!("enabled = ?{}", bind_params.len()));
    }

    if set_clauses.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "No fields to update",
        );
    }

    let Ok(mut conn) = af_db::get_conn() else {
        return rule_update_failed();
    };
    let Ok(tx) = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) else {
        return rule_update_failed();
    };
    if req.condition_type.is_some() || req.condition_value.is_some() {
        let current = tx.query_row(
            "SELECT condition_type, condition_value FROM notification_rules WHERE id = ?1",
            [id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        );
        let (current_type, current_value) = match current {
            Ok(condition) => condition,
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Rule not found");
            }
            Err(_) => return rule_update_failed(),
        };
        let condition_type = req
            .condition_type
            .as_deref()
            .unwrap_or(&current_type)
            .trim();
        let value = req
            .condition_value
            .as_deref()
            .unwrap_or(&current_value)
            .trim();
        if let Err(message) = validate_rule_condition(condition_type, value) {
            return rule_validation_error(message);
        }
    }

    bind_params.push(Box::new(id));
    let query = format!(
        "UPDATE notification_rules SET {} WHERE id = ?{}",
        set_clauses.join(", "),
        bind_params.len()
    );

    let param_refs: Vec<&dyn rusqlite::ToSql> = bind_params.iter().map(|b| b.as_ref()).collect();
    match tx.execute(&query, param_refs.as_slice()) {
        Ok(0) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Rule not found"),
        Ok(_) if tx.commit().is_ok() => {
            Json(serde_json::json!({ "message": "Rule updated" })).into_response()
        }
        _ => rule_update_failed(),
    }
}

fn rule_update_failed() -> Response {
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_ERROR",
        "Failed to update rule",
    )
}

pub async fn delete_notification_rule(Path(id): Path<i64>) -> Response {
    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete rule",
        );
    };

    match conn.execute("DELETE FROM notification_rules WHERE id = ?1", params![id]) {
        Ok(0) => api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Rule not found"),
        Ok(_) => Json(serde_json::json!({ "message": "Rule deleted" })).into_response(),
        Err(_) => api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete rule",
        ),
    }
}
