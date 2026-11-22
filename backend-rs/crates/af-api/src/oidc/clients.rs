use super::authorize::is_safe_redirect_uri;
use crate::auth::{api_error, blocking_response, AuthUser};
use crate::ws::extract_client_ip;
use axum::extract::{Path, Request};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use rand::RngCore;
use rusqlite::params;
use sha2::{Digest, Sha256};

pub async fn get_oidc_clients() -> Response {
    blocking_response(get_oidc_clients_blocking).await
}

fn get_oidc_clients_blocking() -> Response {
    let Ok(conn) = af_db::get_read_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to query clients",
        );
    };
    let mut stmt = match conn.prepare(
        "SELECT id, name, redirect_uris, COALESCE(created_at, '') FROM oidc_clients ORDER BY created_at DESC",
    ) {
        Ok(stmt) => stmt,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to query clients",
            );
        }
    };
    let rows = match stmt.query_map([], |r| {
        let uris_raw: String = r.get(2)?;
        let uris: Vec<String> = serde_json::from_str(&uris_raw).unwrap_or_default();
        Ok(serde_json::json!({
            "id": r.get::<_, String>(0)?,
            "name": r.get::<_, String>(1)?,
            "redirect_uris": uris,
            "created_at": r.get::<_, String>(3)?,
        }))
    }) {
        Ok(rows) => rows,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to query clients",
            );
        }
    };
    let mut clients = Vec::new();
    for row in rows {
        match row {
            Ok(client) => clients.push(client),
            Err(_) => {
                return api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "Failed to query clients",
                );
            }
        }
    }
    Json(serde_json::json!({ "clients": clients })).into_response()
}

pub async fn create_oidc_client(req: Request) -> Response {
    let actor = req.extensions().get::<AuthUser>().cloned();
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Ok(bytes) = axum::body::to_bytes(req.into_body(), 64 * 1024).await else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid body");
    };
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return api_error(StatusCode::BAD_REQUEST, "BAD_REQUEST", "Invalid JSON");
    };

    blocking_response(move || create_oidc_client_blocking(actor, ip, ua, body)).await
}

fn create_oidc_client_blocking(
    actor: Option<AuthUser>,
    ip: String,
    ua: String,
    body: serde_json::Value,
) -> Response {
    let name = body
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim();
    let redirect_uris: Vec<String> = body
        .get("redirect_uris")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    if name.is_empty() || redirect_uris.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "name and at least one redirect_uri are required",
        );
    }
    if redirect_uris.iter().any(|u| !is_safe_redirect_uri(u)) {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "redirect_uris must use valid http or https URLs without credentials or fragments",
        );
    }

    let is_public = body
        .get("public")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        || body
            .get("token_endpoint_auth_method")
            .and_then(|v| v.as_str())
            .is_some_and(|m| m.trim().eq_ignore_ascii_case("none"));

    let mut id_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id_bytes);
    let client_id = hex::encode(id_bytes);
    let (client_secret, secret_hash_hex) = if is_public {
        (String::new(), String::new())
    } else {
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        let secret = hex::encode(secret_bytes);
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        (secret, hex::encode(hasher.finalize()))
    };
    let uris_json = serde_json::to_string(&redirect_uris).unwrap_or_else(|_| "[]".to_string());

    let Ok(conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Database unavailable",
        );
    };
    if conn
        .execute(
            "INSERT INTO oidc_clients (id, client_secret_hash, name, redirect_uris) VALUES (?1, ?2, ?3, ?4)",
            params![client_id, secret_hash_hex, name, uris_json],
        )
        .is_err()
    {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to create client",
        );
    }

    drop(conn);
    if let Some(u) = actor {
        af_db::record_audit(
            u.user_id,
            &u.username,
            "oidc_client_create",
            "oidc_client",
            &client_id,
            &format!("name={}", name),
            &ip,
            &ua,
        );
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "name": name,
            "redirect_uris": redirect_uris,
            "message": "Save the client_secret now — it cannot be retrieved later",
        })),
    )
        .into_response()
}

pub async fn delete_oidc_client(Path(client_id): Path<String>, req: Request) -> Response {
    blocking_response(move || delete_oidc_client_blocking(client_id, req)).await
}

fn delete_oidc_client_blocking(client_id: String, req: Request) -> Response {
    if client_id.is_empty() {
        return api_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Client ID is required",
        );
    }
    let actor = req.extensions().get::<AuthUser>().cloned();
    let ip = extract_client_ip(req.headers());
    let ua = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let Ok(mut conn) = af_db::get_conn() else {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to delete client",
        );
    };

    let tx = match conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
        Ok(tx) => tx,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to delete client",
            );
        }
    };

    let affected = match tx.execute("DELETE FROM oidc_clients WHERE id = ?1", params![client_id]) {
        Ok(n) => n,
        Err(_) => {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to delete client",
            );
        }
    };
    if affected == 0 {
        return api_error(StatusCode::NOT_FOUND, "NOT_FOUND", "Client not found");
    }

    for stmt in [
        "UPDATE oidc_refresh_tokens SET revoked = 1 WHERE client_id = ?1",
        "DELETE FROM oidc_auth_codes WHERE client_id = ?1",
        "DELETE FROM oidc_device_codes WHERE client_id = ?1",
        "DELETE FROM oidc_consents WHERE client_id = ?1",
    ] {
        if tx.execute(stmt, params![client_id]).is_err() {
            return api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Failed to revoke client artifacts",
            );
        }
    }
    if tx.commit().is_err() {
        return api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_ERROR",
            "Failed to commit client deletion",
        );
    }

    drop(conn);
    if let Some(u) = actor {
        af_db::record_audit(
            u.user_id,
            &u.username,
            "oidc_client_delete",
            "oidc_client",
            &client_id,
            "",
            &ip,
            &ua,
        );
    }

    Json(serde_json::json!({ "message": "Client deleted and tokens revoked" })).into_response()
}
