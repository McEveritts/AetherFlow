use super::{user_mutation_stripe, validate_mcbrowser_user, McBrowserError};
use crate::auth::AuthUser;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

const ACCOUNT_TABLES: &[(&str, &str)] = &[
    ("mcbrowser_policy_rules", "user_id"),
    ("mcbrowser_preferences", "user_id"),
    ("mcbrowser_policies", "user_id"),
    ("mcbrowser_shares", "owner_user_id"),
    ("mcbrowser_uploads", "user_id"),
    ("active_sessions", "user_id"),
    ("oidc_auth_codes", "user_id"),
    ("oidc_refresh_tokens", "user_id"),
    ("oidc_device_codes", "user_id"),
    ("oidc_consents", "user_id"),
    ("recovery_codes", "user_id"),
    ("user_quotas", "user_id"),
];

fn database_error(_: rusqlite::Error) -> McBrowserError {
    McBrowserError::Internal("Account deletion could not be completed".to_owned())
}

fn delete_account_with_conn(
    connection: &mut Connection,
    caller: &AuthUser,
    target_user_id: i64,
) -> Result<(), McBrowserError> {
    validate_mcbrowser_user(caller)?;
    if target_user_id <= 0 {
        return Err(McBrowserError::BadRequest(
            "Invalid user identity".to_owned(),
        ));
    }
    if caller.role != "admin" {
        return Err(McBrowserError::Forbidden(
            "Admin access required".to_owned(),
        ));
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database_error)?;
    let live_caller: Option<(String, String)> = transaction
        .query_row(
            "SELECT role, username FROM users WHERE id = ?1",
            [caller.user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(database_error)?;
    match live_caller {
        None => {
            return Err(McBrowserError::Unauthorized(
                "User no longer exists".to_owned(),
            ))
        }
        Some((role, username)) if role == "admin" && !username.starts_with("plugin:") => {}
        Some(_) => {
            return Err(McBrowserError::Forbidden(
                "Admin access required".to_owned(),
            ))
        }
    }
    let quota_status: Option<String> = transaction
        .query_row(
            "SELECT COALESCE(status, '') FROM user_quotas WHERE user_id = ?1",
            [caller.user_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)?;
    if quota_status.is_some_and(|status| {
        let status = status.trim();
        !status.is_empty() && !status.eq_ignore_ascii_case("active")
    }) {
        return Err(McBrowserError::Forbidden(
            "Account is not active".to_owned(),
        ));
    }
    let target_role: Option<String> = transaction
        .query_row(
            "SELECT role FROM users WHERE id = ?1",
            [target_user_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(database_error)?;
    let target_role =
        target_role.ok_or_else(|| McBrowserError::NotFound("User not found".to_owned()))?;
    if target_role.eq_ignore_ascii_case("admin") {
        let remaining_admin_count: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM users AS remaining
                 LEFT JOIN user_quotas AS quota ON quota.user_id = remaining.id
                 WHERE remaining.id != ?1 AND remaining.role = 'admin'
                 AND remaining.username NOT LIKE 'plugin:%'
                 AND LOWER(TRIM(COALESCE(quota.status, ''))) IN ('', 'active')",
                [target_user_id],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if remaining_admin_count == 0 {
            return Err(McBrowserError::BadRequest(
                "Cannot delete the last remaining admin.".to_owned(),
            ));
        }
    }
    for (table, owner_column) in ACCOUNT_TABLES {
        let exists: bool = transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
                [table],
                |row| row.get(0),
            )
            .map_err(database_error)?;
        if exists {
            transaction
                .execute(
                    &format!("DELETE FROM {table} WHERE {owner_column} = ?1"),
                    [target_user_id],
                )
                .map_err(database_error)?;
        }
    }
    transaction
        .execute("DELETE FROM users WHERE id = ?1", [target_user_id])
        .map_err(database_error)?;
    transaction.commit().map_err(database_error)
}

pub(crate) async fn delete_account(
    caller: AuthUser,
    target_user_id: i64,
) -> Result<(), McBrowserError> {
    let mutation_guard = user_mutation_stripe(target_user_id).lock_owned().await;
    tokio::task::spawn_blocking(move || {
        let _mutation_guard = mutation_guard;
        let mut connection = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Account deletion database unavailable".to_owned())
        })?;
        delete_account_with_conn(&mut connection, &caller, target_user_id)
    })
    .await
    .map_err(|_| McBrowserError::Internal("Account deletion worker failed".to_owned()))?
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> AuthUser {
        AuthUser {
            user_id: 1,
            username: "admin".to_owned(),
            role: "admin".to_owned(),
            jti: "lifecycle-test".to_owned(),
            plugin_id: None,
            plugin_scopes: Vec::new(),
        }
    }

    fn database() -> Connection {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch(
            "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, role TEXT);
             CREATE TABLE user_quotas (user_id INTEGER PRIMARY KEY, status TEXT);
             INSERT INTO users VALUES (1, 'admin', 'admin'), (2, 'alice', 'user'), (3, 'bob', 'user');",
        ).unwrap();
        connection
    }

    #[test]
    fn deletion_cleans_only_target_metadata_and_never_reuses_identity() {
        let mut connection = database();
        for (table, column) in ACCOUNT_TABLES {
            if *table == "user_quotas" {
                connection
                    .execute(
                        "INSERT INTO user_quotas VALUES (2, 'active'), (3, 'active')",
                        [],
                    )
                    .unwrap();
            } else {
                connection
                    .execute_batch(&format!(
                    "CREATE TABLE {table} ({column} INTEGER); INSERT INTO {table} VALUES (2), (3);"
                ))
                    .unwrap();
            }
        }
        delete_account_with_conn(&mut connection, &caller(), 2).unwrap();
        for (table, column) in ACCOUNT_TABLES {
            let owners: Vec<i64> = connection
                .prepare(&format!("SELECT {column} FROM {table}"))
                .unwrap()
                .query_map([], |row| row.get(0))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            assert_eq!(owners, vec![3], "{table}");
        }
        connection
            .execute(
                "INSERT INTO users (username, role) VALUES ('new', 'user')",
                [],
            )
            .unwrap();
        assert!(connection.last_insert_rowid() > 3);
    }

    #[test]
    fn optional_tables_can_be_absent_and_last_admin_is_protected() {
        let mut connection = database();
        assert!(matches!(
            delete_account_with_conn(&mut connection, &caller(), 1),
            Err(McBrowserError::BadRequest(_))
        ));
        delete_account_with_conn(&mut connection, &caller(), 2).unwrap();
        assert!(matches!(
            delete_account_with_conn(&mut connection, &caller(), 2),
            Err(McBrowserError::NotFound(_))
        ));
    }

    #[test]
    fn failing_cleanup_rolls_back_all_deleted_metadata_and_identity() {
        let mut connection = database();
        connection
            .execute_batch(
                "CREATE TABLE mcbrowser_shares (owner_user_id INTEGER);
             CREATE TABLE mcbrowser_uploads (user_id INTEGER);
             INSERT INTO mcbrowser_shares VALUES (2);
             INSERT INTO mcbrowser_uploads VALUES (2);
             CREATE TRIGGER prevent_upload_delete BEFORE DELETE ON mcbrowser_uploads
             BEGIN SELECT RAISE(ABORT, 'forced failure'); END;",
            )
            .unwrap();
        assert!(matches!(
            delete_account_with_conn(&mut connection, &caller(), 2),
            Err(McBrowserError::Internal(_))
        ));
        for query in [
            "SELECT COUNT(*) FROM users WHERE id = 2",
            "SELECT COUNT(*) FROM mcbrowser_shares",
            "SELECT COUNT(*) FROM mcbrowser_uploads",
        ] {
            assert_eq!(
                connection
                    .query_row(query, [], |row| row.get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }
        assert!(connection.is_autocommit());
    }

    #[test]
    fn caller_claims_do_not_override_live_role_lifecycle_or_plugin_identity() {
        let mut connection = database();
        connection
            .execute("UPDATE users SET role = 'user' WHERE id = 1", [])
            .unwrap();
        assert!(matches!(
            delete_account_with_conn(&mut connection, &caller(), 2),
            Err(McBrowserError::Forbidden(_))
        ));
        connection
            .execute("UPDATE users SET role = 'admin' WHERE id = 1", [])
            .unwrap();
        connection
            .execute("INSERT INTO user_quotas VALUES (1, 'suspended')", [])
            .unwrap();
        assert!(matches!(
            delete_account_with_conn(&mut connection, &caller(), 2),
            Err(McBrowserError::Forbidden(_))
        ));
        connection.execute("DELETE FROM user_quotas", []).unwrap();
        connection
            .execute(
                "UPDATE users SET username = 'plugin:admin' WHERE id = 1",
                [],
            )
            .unwrap();
        assert!(matches!(
            delete_account_with_conn(&mut connection, &caller(), 2),
            Err(McBrowserError::Forbidden(_))
        ));
        connection
            .execute("DELETE FROM users WHERE id = 1", [])
            .unwrap();
        assert!(matches!(
            delete_account_with_conn(&mut connection, &caller(), 2),
            Err(McBrowserError::Unauthorized(_))
        ));
    }

    #[test]
    fn last_usable_admin_protection_excludes_suspended_and_plugin_accounts() {
        let mut connection = database();
        connection
            .execute("UPDATE users SET role = 'admin' WHERE id = 2", [])
            .unwrap();
        connection
            .execute("INSERT INTO user_quotas VALUES (2, 'suspended')", [])
            .unwrap();
        assert!(matches!(
            delete_account_with_conn(&mut connection, &caller(), 1),
            Err(McBrowserError::BadRequest(_))
        ));
        connection.execute("DELETE FROM user_quotas", []).unwrap();
        connection
            .execute(
                "UPDATE users SET username = 'plugin:disabled' WHERE id = 2",
                [],
            )
            .unwrap();
        assert!(matches!(
            delete_account_with_conn(&mut connection, &caller(), 1),
            Err(McBrowserError::BadRequest(_))
        ));
        connection
            .execute(
                "UPDATE users SET username = 'second-admin' WHERE id = 2",
                [],
            )
            .unwrap();
        connection
            .execute("INSERT INTO user_quotas VALUES (1, ' Active ')", [])
            .unwrap();
        delete_account_with_conn(&mut connection, &caller(), 2).unwrap();
        assert!(matches!(
            delete_account_with_conn(&mut connection, &caller(), 1),
            Err(McBrowserError::BadRequest(_))
        ));
    }
}
