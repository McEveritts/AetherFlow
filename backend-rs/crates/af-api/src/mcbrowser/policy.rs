#![allow(dead_code)]

use crate::auth::AuthUser;
use af_files::Entry;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path};
use axum::http::{header, HeaderValue};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use once_cell::sync::Lazy;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::McBrowserError;

pub(super) const MAX_POLICY_BODY_BYTES: usize = 65_536;
pub(super) const MAX_POLICY_RULES: usize = 256;
pub(super) const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
pub(super) const MAX_RELATIVE_PATH_SEGMENTS: usize = 64;
pub(super) const MAX_RELATIVE_SEGMENT_BYTES: usize = 255;

pub(super) const SUPPORTED_LOCALES: &[&str] = &[
    "ar", "bg", "ca", "cs", "da", "de", "de-DE", "de-de", "el", "en", "en-GB", "en-US", "en-gb",
    "en-us", "es", "es-ES", "es-es", "fi", "fr", "fr-FR", "fr-fr", "he", "hi", "hr", "hu", "id",
    "is", "it", "it-IT", "it-it", "ja", "ja-JP", "ja-jp", "ko", "ko-KR", "ko-kr", "lv", "ms", "nb",
    "nl", "nl-BE", "nl-NL", "nl-be", "nl-nl", "no", "pl", "pl-PL", "pl-pl", "pt", "pt-BR", "pt-PT",
    "pt-br", "pt-pt", "ro", "ru", "ru-RU", "ru-ru", "sk", "sv", "sv-SE", "sv-se", "th", "tr",
    "tr-TR", "tr-tr", "uk", "uk-UA", "uk-ua", "vi", "zh", "zh-CN", "zh-HK", "zh-TW", "zh-cn",
    "zh-hk", "zh-tw",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum Permission {
    Read,
    Create,
    Rename,
    Modify,
    Delete,
    Share,
    Download,
    Execute,
}

impl Permission {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Create => "create",
            Self::Rename => "rename",
            Self::Modify => "modify",
            Self::Delete => "delete",
            Self::Share => "share",
            Self::Download => "download",
            Self::Execute => "execute",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyPermissions {
    pub read: bool,
    pub create: bool,
    pub rename: bool,
    pub modify: bool,
    pub delete: bool,
    pub share: bool,
    pub download: bool,
    #[serde(default)]
    pub execute: bool,
}

impl Default for PolicyPermissions {
    fn default() -> Self {
        Self {
            read: true,
            create: true,
            rename: true,
            modify: true,
            delete: true,
            share: true,
            download: true,
            execute: false,
        }
    }
}

impl PolicyPermissions {
    pub(super) const fn allows(&self, permission: Permission) -> bool {
        match permission {
            Permission::Read => self.read,
            Permission::Create => self.create,
            Permission::Rename => self.rename,
            Permission::Modify => self.modify,
            Permission::Delete => self.delete,
            Permission::Share => self.share,
            Permission::Download => self.download,
            Permission::Execute => self.execute,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PathRule {
    pub path: String,
    pub allow: bool,
    #[serde(default)]
    pub regex: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regexp: Option<RuleExpression>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuleExpression {
    pub raw: String,
}

static RULE_REGEX_CACHE: Lazy<Mutex<HashMap<String, Arc<regex::Regex>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn compiled_rule_expression(raw: &str) -> Result<Arc<regex::Regex>, McBrowserError> {
    if raw.len() > 2048 || raw.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Rule expression must contain 1..2048 bytes".to_string(),
        ));
    }
    let mut cache = RULE_REGEX_CACHE
        .lock()
        .map_err(|_| McBrowserError::Internal("Rule expression cache unavailable".to_string()))?;
    if let Some(expression) = cache.get(raw) {
        return Ok(Arc::clone(expression));
    }
    let expression = Arc::new(
        regex::RegexBuilder::new(raw)
            .size_limit(262144)
            .dfa_size_limit(524288)
            .build()
            .map_err(|_| {
                McBrowserError::BadRequest("Invalid or oversized rule expression".to_string())
            })?,
    );
    if cache.len() >= MAX_POLICY_RULES {
        cache.clear();
    }
    cache.insert(raw.to_string(), Arc::clone(&expression));
    Ok(expression)
}

fn normalize_path_rule(rule: PathRule) -> Result<PathRule, McBrowserError> {
    if rule.regex {
        let raw = rule
            .regexp
            .as_ref()
            .map(|expression| expression.raw.as_str())
            .unwrap_or(&rule.path);
        compiled_rule_expression(raw)?;
        let expression = raw.to_string();
        return Ok(PathRule {
            path: rule.path,
            allow: rule.allow,
            regex: true,
            regexp: Some(RuleExpression { raw: expression }),
        });
    }
    if rule.regexp.is_some() {
        return Err(McBrowserError::BadRequest(
            "A rule expression requires regex=true".to_string(),
        ));
    }
    Ok(PathRule {
        path: normalize_rule_path(&rule.path)?,
        allow: rule.allow,
        regex: false,
        regexp: None,
    })
}

fn rule_matches(rule: &PathRule, normalized_path: &str) -> bool {
    if rule.regex {
        let raw = rule
            .regexp
            .as_ref()
            .map(|expression| expression.raw.as_str())
            .unwrap_or(&rule.path);
        return compiled_rule_expression(raw)
            .map(|expression| expression.is_match(&format!("/{normalized_path}")))
            .unwrap_or(!rule.allow);
    }
    path_has_segment_prefix(normalized_path, &rule.path)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyDocument {
    pub permissions: PolicyPermissions,
    #[serde(default)]
    pub rules: Vec<PathRule>,
    #[serde(default)]
    pub scope: String,
}

impl Default for PolicyDocument {
    fn default() -> Self {
        Self {
            permissions: PolicyPermissions::default(),
            rules: Vec::new(),
            scope: String::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum ViewMode {
    List,
    #[serde(alias = "mosaic")]
    Grid,
    #[serde(alias = "mosaic gallery", alias = "mosaic_gallery")]
    Gallery,
}

impl ViewMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Grid => "grid",
            Self::Gallery => "gallery",
        }
    }

    fn from_db_str(raw: &str) -> Result<Self, McBrowserError> {
        match raw {
            "list" => Ok(Self::List),
            "grid" | "mosaic" => Ok(Self::Grid),
            "gallery" | "mosaic gallery" | "mosaic_gallery" => Ok(Self::Gallery),
            _ => Err(McBrowserError::Internal(
                "Invalid persisted view preference".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum SortField {
    Name,
    Size,
    Modified,
}

impl SortField {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Size => "size",
            Self::Modified => "modified",
        }
    }

    fn from_db_str(raw: &str) -> Result<Self, McBrowserError> {
        match raw {
            "name" => Ok(Self::Name),
            "size" => Ok(Self::Size),
            "modified" => Ok(Self::Modified),
            _ => Err(McBrowserError::Internal(
                "Invalid persisted sort preference".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum SortDirection {
    Asc,
    Desc,
}

impl SortDirection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }

    fn from_db_str(raw: &str) -> Result<Self, McBrowserError> {
        match raw {
            "asc" => Ok(Self::Asc),
            "desc" => Ok(Self::Desc),
            _ => Err(McBrowserError::Internal(
                "Invalid persisted sort direction preference".to_string(),
            )),
        }
    }
}

const fn default_natural_sort() -> bool {
    true
}

fn default_editor_theme() -> String {
    "chrome".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreferencesDocument {
    pub view: ViewMode,
    pub sort: SortField,
    pub direction: SortDirection,
    pub show_hidden: bool,
    pub single_click: bool,
    #[serde(default = "default_natural_sort")]
    pub natural_sort: bool,
    #[serde(default)]
    pub redirect_after_copy_move: bool,
    #[serde(default)]
    pub date_format: bool,
    #[serde(
        default = "default_editor_theme",
        alias = "ace_editor_theme",
        alias = "aceEditorTheme"
    )]
    pub editor_theme: String,
    pub locale: String,
}

impl Default for PreferencesDocument {
    fn default() -> Self {
        Self {
            view: ViewMode::List,
            sort: SortField::Name,
            direction: SortDirection::Asc,
            show_hidden: false,
            single_click: false,
            natural_sort: true,
            redirect_after_copy_move: false,
            date_format: false,
            editor_theme: default_editor_theme(),
            locale: "en".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExtraPreferencesJson {
    #[serde(default = "default_natural_sort")]
    natural_sort: bool,
    #[serde(default)]
    redirect_after_copy_move: bool,
    #[serde(default)]
    date_format: bool,
    #[serde(
        default = "default_editor_theme",
        alias = "ace_editor_theme",
        alias = "aceEditorTheme"
    )]
    editor_theme: String,
}

impl Default for ExtraPreferencesJson {
    fn default() -> Self {
        Self {
            natural_sort: default_natural_sort(),
            redirect_after_copy_move: false,
            date_format: false,
            editor_theme: default_editor_theme(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct UsageResponse {
    pub used_bytes: u64,
    pub quota_bytes: u64,
    pub status: String,
}

pub(super) fn router() -> Router {
    Router::new()
        .route("/mcbrowser/policy", get(get_own_policy))
        .route(
            "/mcbrowser/policy/:user_id",
            get(get_user_policy).put(put_user_policy),
        )
        .route(
            "/mcbrowser/preferences",
            get(get_own_preferences).put(put_own_preferences),
        )
        .route("/mcbrowser/usage", get(get_own_usage))
        .layer(DefaultBodyLimit::max(MAX_POLICY_BODY_BYTES))
}

fn no_store_json<T: Serialize>(payload: T) -> Response {
    let mut resp = Json(payload).into_response();
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn extract_auth_user(ext: Option<Extension<AuthUser>>) -> Result<AuthUser, McBrowserError> {
    match ext {
        Some(Extension(user)) => Ok(user),
        None => Err(McBrowserError::Unauthorized(
            "Authentication required".to_string(),
        )),
    }
}

pub(super) fn ensure_policy_tables(conn: &Connection) -> Result<(), McBrowserError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS mcbrowser_policies (
            user_id INTEGER PRIMARY KEY,
            perm_read INTEGER NOT NULL DEFAULT 1,
            perm_create INTEGER NOT NULL DEFAULT 1,
            perm_rename INTEGER NOT NULL DEFAULT 1,
            perm_modify INTEGER NOT NULL DEFAULT 1,
            perm_delete INTEGER NOT NULL DEFAULT 1,
            perm_share INTEGER NOT NULL DEFAULT 1,
            perm_download INTEGER NOT NULL DEFAULT 1,
            perm_execute INTEGER NOT NULL DEFAULT 0,
            scope TEXT NOT NULL DEFAULT '',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS mcbrowser_policy_rules (
            user_id INTEGER NOT NULL,
            rule_order INTEGER NOT NULL,
            path TEXT NOT NULL,
            allow INTEGER NOT NULL,
            PRIMARY KEY (user_id, rule_order)
        );

        CREATE INDEX IF NOT EXISTS idx_mcbrowser_policy_rules_user
            ON mcbrowser_policy_rules(user_id);

        CREATE TABLE IF NOT EXISTS mcbrowser_preferences (
            user_id INTEGER PRIMARY KEY,
            view_mode TEXT NOT NULL DEFAULT 'list',
            sort_field TEXT NOT NULL DEFAULT 'name',
            sort_direction TEXT NOT NULL DEFAULT 'asc',
            show_hidden INTEGER NOT NULL DEFAULT 0,
            single_click INTEGER NOT NULL DEFAULT 0,
            locale TEXT NOT NULL DEFAULT 'en',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .map_err(|_| {
        McBrowserError::Internal("Failed to initialize McBrowser policy tables".to_string())
    })?;
    ensure_policy_column(
        conn,
        "mcbrowser_policy_rules",
        "regex",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_policy_column(conn, "mcbrowser_policy_rules", "expression", "TEXT")?;
    ensure_policy_column(
        conn,
        "mcbrowser_policies",
        "perm_execute",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_policy_column(
        conn,
        "mcbrowser_preferences",
        "extra_json",
        "TEXT NOT NULL DEFAULT '{}'",
    )?;
    Ok(())
}

fn ensure_policy_column(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), McBrowserError> {
    let exists = || -> rusqlite::Result<bool> {
        let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
        let names = statement.query_map([], |row| row.get::<_, String>(1))?;
        for name in names {
            if name? == column {
                return Ok(true);
            }
        }
        Ok(false)
    };
    if exists()
        .map_err(|_| McBrowserError::Internal("Failed to inspect policy schema".to_string()))?
    {
        return Ok(());
    }
    if conn
        .execute_batch(&format!(
            "ALTER TABLE {table} ADD COLUMN {column} {definition}"
        ))
        .is_err()
        && !exists().unwrap_or(false)
    {
        return Err(McBrowserError::Internal(
            "Failed to upgrade policy schema".to_string(),
        ));
    }
    Ok(())
}

fn enforce_relative_bounds(normalized: &str) -> Result<(), McBrowserError> {
    if normalized.is_empty() {
        return Ok(());
    }
    if normalized.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(McBrowserError::BadRequest(
            "Invalid path: path exceeds maximum length of 4096 bytes".to_string(),
        ));
    }
    if normalized.chars().any(char::is_control) {
        return Err(McBrowserError::BadRequest(
            "Invalid path: control characters are not allowed".to_string(),
        ));
    }
    let mut count = 0usize;
    for seg in normalized.split('/') {
        count += 1;
        if count > MAX_RELATIVE_PATH_SEGMENTS {
            return Err(McBrowserError::BadRequest(
                "Invalid path: path exceeds maximum depth of 64 segments".to_string(),
            ));
        }
        if seg.is_empty() || seg.trim().is_empty() {
            return Err(McBrowserError::BadRequest(
                "Invalid path: empty or whitespace-only path segment is not allowed".to_string(),
            ));
        }
        if seg.len() > MAX_RELATIVE_SEGMENT_BYTES {
            return Err(McBrowserError::BadRequest(
                "Invalid path: path segment exceeds 255 bytes".to_string(),
            ));
        }
    }
    Ok(())
}

pub(super) fn normalize_target_path(raw: &str, allow_root: bool) -> Result<String, McBrowserError> {
    let normalized = super::normalize_relative_path(raw, allow_root)?;
    enforce_relative_bounds(&normalized)?;
    Ok(normalized)
}

pub(super) fn normalize_rule_path(raw: &str) -> Result<String, McBrowserError> {
    if !raw.is_empty() && raw.trim().is_empty() {
        return Err(McBrowserError::BadRequest(
            "Invalid rule path: whitespace-only paths are not allowed".to_string(),
        ));
    }
    if raw.contains('*') || raw.contains('?') {
        return Err(McBrowserError::BadRequest(
            "Invalid rule path: wildcard and glob characters ('*', '?') are not supported; rules use segment-aware normalized path prefixes".to_string(),
        ));
    }
    let normalized = super::normalize_relative_path(raw, true)?;
    enforce_relative_bounds(&normalized)?;
    Ok(normalized)
}

pub(super) fn normalize_scope_path(raw: &str) -> Result<String, McBrowserError> {
    if raw.is_empty() {
        return Ok(String::new());
    }
    if raw.trim().is_empty() {
        return Err(McBrowserError::BadRequest(
            "Invalid scope: whitespace-only scope is not allowed".to_string(),
        ));
    }
    if raw.contains('*') || raw.contains('?') {
        return Err(McBrowserError::BadRequest(
            "Invalid scope: wildcard characters are not allowed".to_string(),
        ));
    }
    let normalized = super::normalize_relative_path(raw, false)?;
    enforce_relative_bounds(&normalized)?;
    Ok(normalized)
}

pub(super) fn validate_and_normalize_policy(
    input: PolicyDocument,
) -> Result<PolicyDocument, McBrowserError> {
    if input.rules.len() > MAX_POLICY_RULES {
        return Err(McBrowserError::BadRequest(format!(
            "Policy cannot contain more than {MAX_POLICY_RULES} path rules"
        )));
    }
    let normalized_scope = normalize_scope_path(&input.scope)?;
    let mut normalized_rules = Vec::with_capacity(input.rules.len());
    for rule in input.rules {
        normalized_rules.push(normalize_path_rule(rule)?);
    }
    Ok(PolicyDocument {
        permissions: input.permissions,
        rules: normalized_rules,
        scope: normalized_scope,
    })
}

fn is_valid_editor_theme(theme: &str) -> bool {
    !theme.is_empty()
        && theme.len() <= 64
        && theme.trim() == theme
        && theme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

pub(super) fn validate_preferences(
    prefs: PreferencesDocument,
) -> Result<PreferencesDocument, McBrowserError> {
    let locale = prefs.locale;
    if locale.is_empty() || locale.trim() != locale || !SUPPORTED_LOCALES.contains(&locale.as_str())
    {
        return Err(McBrowserError::BadRequest(
            "Invalid locale preference: locale is not in the supported whitelist".to_string(),
        ));
    }
    let editor_theme = prefs.editor_theme;
    if !is_valid_editor_theme(&editor_theme) {
        return Err(McBrowserError::BadRequest(
            "Invalid editor_theme preference".to_string(),
        ));
    }
    Ok(PreferencesDocument {
        view: prefs.view,
        sort: prefs.sort,
        direction: prefs.direction,
        show_hidden: prefs.show_hidden,
        single_click: prefs.single_click,
        natural_sort: prefs.natural_sort,
        redirect_after_copy_move: prefs.redirect_after_copy_move,
        date_format: prefs.date_format,
        editor_theme,
        locale,
    })
}

pub(super) fn path_has_segment_prefix(target_path: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if target_path == prefix {
        return true;
    }
    target_path.starts_with(prefix) && target_path.as_bytes().get(prefix.len()) == Some(&b'/')
}

pub(super) fn is_strict_ancestor_path(ancestor: &str, descendant: &str) -> bool {
    if ancestor == descendant {
        return false;
    }
    path_has_segment_prefix(descendant, ancestor)
}

fn prefix_specificity(normalized_prefix: &str) -> usize {
    if normalized_prefix.is_empty() {
        0
    } else {
        normalized_prefix.split('/').count()
    }
}

pub(super) fn is_path_allowed_by_rules(rules: &[PathRule], normalized_path: &str) -> bool {
    let mut allowed = true;
    for rule in rules {
        if rule_matches(rule, normalized_path) {
            allowed = rule.allow;
        }
    }
    allowed
}

pub(super) fn has_denied_descendant_rule(rules: &[PathRule], normalized_ancestor: &str) -> bool {
    rules.iter().any(|rule| {
        !rule.regex
            && is_strict_ancestor_path(normalized_ancestor, &rule.path)
            && !is_path_allowed_by_rules(rules, &rule.path)
    })
}

pub(super) fn has_allowed_descendant_rule(rules: &[PathRule], normalized_ancestor: &str) -> bool {
    rules.iter().any(|rule| {
        !rule.regex
            && is_strict_ancestor_path(normalized_ancestor, &rule.path)
            && is_path_allowed_by_rules(rules, &rule.path)
    })
}

pub(super) fn authorize_with_policy(
    policy: &PolicyDocument,
    permission: Permission,
    raw_path: &str,
) -> Result<(), McBrowserError> {
    let normalized_path = normalize_target_path(raw_path, true)?;

    if !policy.permissions.allows(permission) {
        return Err(McBrowserError::Forbidden(format!(
            "McBrowser '{}' permission is disabled for this account",
            permission.as_str()
        )));
    }

    if !is_path_allowed_by_rules(&policy.rules, &normalized_path) {
        return Err(McBrowserError::Forbidden(format!(
            "Access to requested path is denied by user policy for '{}'",
            permission.as_str()
        )));
    }

    if matches!(
        permission,
        Permission::Delete | Permission::Rename | Permission::Modify | Permission::Share
    ) && has_denied_descendant_rule(&policy.rules, &normalized_path)
    {
        return Err(McBrowserError::Forbidden(format!(
            "Cannot '{}' ancestor directory because a descendant path is denied by policy",
            permission.as_str()
        )));
    }

    Ok(())
}

pub(super) fn can_read_or_traverse_directory(
    policy: &PolicyDocument,
    normalized_dir_path: &str,
) -> bool {
    if !policy.permissions.read {
        return false;
    }
    is_path_allowed_by_rules(&policy.rules, normalized_dir_path)
        || has_allowed_descendant_rule(&policy.rules, normalized_dir_path)
}

pub(super) fn is_entry_visible(
    policy: &PolicyDocument,
    normalized_entry_path: &str,
    is_directory: bool,
) -> bool {
    if !policy.permissions.read {
        return false;
    }
    if is_path_allowed_by_rules(&policy.rules, normalized_entry_path) {
        return true;
    }
    is_directory && has_allowed_descendant_rule(&policy.rules, normalized_entry_path)
}

pub(super) fn filter_visible_entries(policy: &PolicyDocument, entries: Vec<Entry>) -> Vec<Entry> {
    if !policy.permissions.read {
        return Vec::new();
    }
    entries
        .into_iter()
        .filter(|entry| {
            let Ok(norm_path) = normalize_target_path(&entry.path, false) else {
                return false;
            };
            is_entry_visible(policy, &norm_path, entry.kind == "directory")
        })
        .collect()
}

#[derive(Debug, Clone)]
struct VerifiedUserState {
    role: String,
    quota_bytes: u64,
    used_bytes: u64,
    status: String,
}

fn verify_active_user_and_quota_conn(
    conn: &Connection,
    user_id: i64,
) -> Result<VerifiedUserState, McBrowserError> {
    if user_id <= 0 {
        return Err(McBrowserError::Unauthorized(
            "Invalid user identity".to_string(),
        ));
    }

    let user_row: Option<(String, String)> = conn
        .query_row(
            "SELECT username, COALESCE(role, 'user') FROM users WHERE id = ?1",
            params![user_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to verify user account state".to_string()))?;

    let Some((username, role)) = user_row else {
        return Err(McBrowserError::Unauthorized(
            "User account not found".to_string(),
        ));
    };

    if role.eq_ignore_ascii_case("plugin") || username.starts_with("plugin:") {
        return Err(McBrowserError::Forbidden(
            "Plugin accounts are not permitted to access McBrowser".to_string(),
        ));
    }

    let quota_row: Option<(i64, i64, String)> = conn
        .query_row(
            "SELECT COALESCE(quota_bytes, 0), COALESCE(used_bytes, 0), COALESCE(status, 'active') \
             FROM user_quotas WHERE user_id = ?1",
            params![user_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to read user storage quota".to_string()))?;

    let (raw_quota_bytes, raw_used_bytes, raw_status) =
        quota_row.unwrap_or((0, 0, "active".to_string()));

    if raw_quota_bytes < 0 {
        return Err(McBrowserError::Internal(
            "Invalid negative storage quota configuration".to_string(),
        ));
    }

    let clean_status = raw_status.trim();
    let normalized_status =
        if clean_status.is_empty() || clean_status.eq_ignore_ascii_case("active") {
            "active".to_string()
        } else {
            return Err(McBrowserError::Forbidden(format!(
                "Storage operations are disabled because user quota status is '{clean_status}'"
            )));
        };

    Ok(VerifiedUserState {
        role,
        quota_bytes: raw_quota_bytes as u64,
        used_bytes: raw_used_bytes.max(0) as u64,
        status: normalized_status,
    })
}

pub(super) fn load_user_policy_conn(
    conn: &Connection,
    user_id: i64,
) -> Result<PolicyDocument, McBrowserError> {
    ensure_policy_tables(conn)?;

    let policy_row: Option<(PolicyPermissions, String)> = conn
        .query_row(
            "SELECT perm_read, perm_create, perm_rename, perm_modify, perm_delete, perm_share, perm_download, scope, perm_execute \
             FROM mcbrowser_policies WHERE user_id = ?1",
            params![user_id],
            |r| {
                Ok((
                    PolicyPermissions {
                        read: r.get::<_, i64>(0)? != 0,
                        create: r.get::<_, i64>(1)? != 0,
                        rename: r.get::<_, i64>(2)? != 0,
                        modify: r.get::<_, i64>(3)? != 0,
                        delete: r.get::<_, i64>(4)? != 0,
                        share: r.get::<_, i64>(5)? != 0,
                        download: r.get::<_, i64>(6)? != 0,
                        execute: r.get::<_, i64>(8)? != 0,
                    },
                    r.get::<_, String>(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to read user file policy".to_string()))?;

    let Some((permissions, raw_scope)) = policy_row else {
        return Ok(PolicyDocument::default());
    };

    let scope = normalize_scope_path(&raw_scope).map_err(|_| {
        McBrowserError::Internal("Persisted user policy scope is invalid".to_string())
    })?;

    let mut stmt = conn
        .prepare(
            "SELECT path, allow, regex, expression FROM mcbrowser_policy_rules \
             WHERE user_id = ?1 ORDER BY rule_order ASC",
        )
        .map_err(|_| {
            McBrowserError::Internal("Failed to prepare policy rules query".to_string())
        })?;

    let rows = stmt
        .query_map(params![user_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? != 0,
                r.get::<_, i64>(2)? != 0,
                r.get::<_, Option<String>>(3)?,
            ))
        })
        .map_err(|_| McBrowserError::Internal("Failed to query policy rules".to_string()))?;

    let mut rules = Vec::new();
    for row_res in rows {
        let (raw_path, allow, regex, expression) = row_res
            .map_err(|_| McBrowserError::Internal("Failed to decode policy rule".to_string()))?;
        let rule = normalize_path_rule(PathRule {
            path: raw_path,
            allow,
            regex,
            regexp: expression.map(|raw| RuleExpression { raw }),
        })
        .map_err(|_| McBrowserError::Internal("Persisted policy rule is invalid".to_string()))?;
        rules.push(rule);
    }

    Ok(PolicyDocument {
        permissions,
        rules,
        scope,
    })
}

pub(super) fn load_target_user_policy_conn(
    conn: &Connection,
    caller_user: &AuthUser,
    target_user_id: i64,
) -> Result<PolicyDocument, McBrowserError> {
    let caller_id = super::validate_mcbrowser_user(caller_user)?;
    if !caller_user.role.eq_ignore_ascii_case("admin") {
        return Err(McBrowserError::Forbidden(
            "Admin access required to inspect user file policies".to_string(),
        ));
    }
    if target_user_id <= 0 {
        return Err(McBrowserError::BadRequest(
            "Invalid target user ID".to_string(),
        ));
    }

    ensure_policy_tables(conn)?;

    let caller_state = verify_active_user_and_quota_conn(conn, caller_id)?;
    if !caller_state.role.eq_ignore_ascii_case("admin") {
        return Err(McBrowserError::Forbidden(
            "Admin access required to inspect user file policies".to_string(),
        ));
    }

    let target_row: Option<(String, String)> = conn
        .query_row(
            "SELECT username, COALESCE(role, 'user') FROM users WHERE id = ?1",
            params![target_user_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| {
            McBrowserError::Internal("Failed to verify target user account".to_string())
        })?;

    let Some((target_username, target_role)) = target_row else {
        return Err(McBrowserError::NotFound(
            "Target user account not found".to_string(),
        ));
    };

    if target_role.eq_ignore_ascii_case("plugin") || target_username.starts_with("plugin:") {
        return Err(McBrowserError::Forbidden(
            "Cannot configure McBrowser policy for plugin accounts".to_string(),
        ));
    }

    load_user_policy_conn(conn, target_user_id)
}

pub(super) fn save_user_policy_conn(
    conn: &Connection,
    caller_user: &AuthUser,
    target_user_id: i64,
    policy: PolicyDocument,
) -> Result<PolicyDocument, McBrowserError> {
    let caller_id = super::validate_mcbrowser_user(caller_user)?;
    if !caller_user.role.eq_ignore_ascii_case("admin") {
        return Err(McBrowserError::Forbidden(
            "Admin access required to modify user file policies".to_string(),
        ));
    }
    if target_user_id <= 0 {
        return Err(McBrowserError::BadRequest(
            "Invalid target user ID".to_string(),
        ));
    }

    let validated = validate_and_normalize_policy(policy)?;
    ensure_policy_tables(conn)?;

    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
        .map_err(|_| McBrowserError::Internal("Failed to start policy transaction".to_string()))?;

    let tx_res = (|| -> Result<PolicyDocument, McBrowserError> {
        let caller_state = verify_active_user_and_quota_conn(conn, caller_id)?;
        if !caller_state.role.eq_ignore_ascii_case("admin") {
            return Err(McBrowserError::Forbidden(
                "Admin access required to modify user file policies".to_string(),
            ));
        }

        let target_row: Option<(String, String)> = conn
            .query_row(
                "SELECT username, COALESCE(role, 'user') FROM users WHERE id = ?1",
                params![target_user_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| {
                McBrowserError::Internal("Failed to verify target user account".to_string())
            })?;

        let Some((target_username, target_role)) = target_row else {
            return Err(McBrowserError::NotFound(
                "Target user account not found".to_string(),
            ));
        };

        if target_role.eq_ignore_ascii_case("plugin") || target_username.starts_with("plugin:") {
            return Err(McBrowserError::Forbidden(
                "Cannot configure McBrowser policy for plugin accounts".to_string(),
            ));
        }

        conn.execute(
            "INSERT INTO mcbrowser_policies (
                user_id, perm_read, perm_create, perm_rename, perm_modify,
                perm_delete, perm_share, perm_download, scope, perm_execute, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, CURRENT_TIMESTAMP)
             ON CONFLICT(user_id) DO UPDATE SET
                perm_read = excluded.perm_read,
                perm_create = excluded.perm_create,
                perm_rename = excluded.perm_rename,
                perm_modify = excluded.perm_modify,
                perm_delete = excluded.perm_delete,
                perm_share = excluded.perm_share,
                perm_download = excluded.perm_download,
                perm_execute = excluded.perm_execute,
                scope = excluded.scope,
                updated_at = CURRENT_TIMESTAMP",
            params![
                target_user_id,
                i64::from(validated.permissions.read),
                i64::from(validated.permissions.create),
                i64::from(validated.permissions.rename),
                i64::from(validated.permissions.modify),
                i64::from(validated.permissions.delete),
                i64::from(validated.permissions.share),
                i64::from(validated.permissions.download),
                &validated.scope,
                i64::from(validated.permissions.execute),
            ],
        )
        .map_err(|_| McBrowserError::Internal("Failed to persist user policy".to_string()))?;

        conn.execute(
            "DELETE FROM mcbrowser_policy_rules WHERE user_id = ?1",
            params![target_user_id],
        )
        .map_err(|_| McBrowserError::Internal("Failed to update policy rules".to_string()))?;

        for (idx, rule) in validated.rules.iter().enumerate() {
            conn.execute(
                "INSERT INTO mcbrowser_policy_rules (user_id, rule_order, path, allow, regex, expression) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    target_user_id,
                    idx as i64,
                    &rule.path,
                    i64::from(rule.allow),
                    i64::from(rule.regex),
                    rule.regexp.as_ref().map(|expression| expression.raw.as_str()),
                ],
            )
            .map_err(|_| McBrowserError::Internal("Failed to persist policy rule".to_string()))?;
        }

        Ok(validated)
    })();

    match tx_res {
        Ok(saved) => {
            conn.execute_batch("COMMIT").map_err(|_| {
                let _ = conn.execute_batch("ROLLBACK");
                McBrowserError::Internal("Failed to commit policy update".to_string())
            })?;
            Ok(saved)
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}

pub(super) fn authorize_with_conn(
    conn: &Connection,
    user: &AuthUser,
    permission: Permission,
    path: &str,
) -> Result<(), McBrowserError> {
    let user_id = super::validate_mcbrowser_user(user)?;
    let _ = verify_active_user_and_quota_conn(conn, user_id)?;
    let policy = load_user_policy_conn(conn, user_id)?;
    authorize_with_policy(&policy, permission, path)
}

pub(super) fn authorize(
    user: &AuthUser,
    permission: Permission,
    path: &str,
) -> Result<(), McBrowserError> {
    let _ = super::validate_mcbrowser_user(user)?;
    let _ = normalize_target_path(path, true)?;
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for policy verification".to_string())
    })?;
    authorize_with_conn(&conn, user, permission, path)
}

pub(super) fn authorize_rename_with_conn(
    conn: &Connection,
    user: &AuthUser,
    from_path: &str,
    to_path: &str,
) -> Result<(), McBrowserError> {
    let user_id = super::validate_mcbrowser_user(user)?;
    let normalized_from = normalize_target_path(from_path, false)?;
    let normalized_to = normalize_target_path(to_path, false)?;
    let _ = verify_active_user_and_quota_conn(conn, user_id)?;
    let policy = load_user_policy_conn(conn, user_id)?;
    authorize_with_policy(&policy, Permission::Rename, &normalized_from)?;
    authorize_with_policy(&policy, Permission::Rename, &normalized_to)?;
    Ok(())
}

pub(super) fn authorize_rename(
    user: &AuthUser,
    from_path: &str,
    to_path: &str,
) -> Result<(), McBrowserError> {
    let _ = super::validate_mcbrowser_user(user)?;
    let _ = normalize_target_path(from_path, false)?;
    let _ = normalize_target_path(to_path, false)?;
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for policy verification".to_string())
    })?;
    authorize_rename_with_conn(&conn, user, from_path, to_path)?;
    let user_id = user.user_id;
    let normalized_from = normalize_target_path(from_path, false)?;
    let normalized_to = normalize_target_path(to_path, false)?;
    let policy = load_user_policy_conn(&conn, user_id)?;
    let filesystem = super::open_configured_user_browser_fs_with_conn(&conn, user_id)?;
    let source = filesystem
        .metadata(&normalized_from)
        .map_err(|error| super::map_fs_io_error(error, "Failed to inspect rename source"))?;
    if source.kind == "directory" {
        let descendants = filesystem.walk(&normalized_from, 10000).map_err(|error| {
            super::map_fs_io_error(error, "Failed to verify rename descendants")
        })?;
        for entry in descendants {
            authorize_with_policy(&policy, Permission::Rename, &entry.path)?;
            let suffix = entry
                .path
                .strip_prefix(&normalized_from)
                .ok_or_else(|| McBrowserError::Internal("Invalid descendant path".to_string()))?;
            authorize_with_policy(
                &policy,
                Permission::Rename,
                &format!("{normalized_to}{suffix}"),
            )?;
        }
    }
    Ok(())
}

pub(super) fn authorize_directory_listing_with_conn(
    conn: &Connection,
    user: &AuthUser,
    dir_path: &str,
) -> Result<PolicyDocument, McBrowserError> {
    let user_id = super::validate_mcbrowser_user(user)?;
    let normalized_dir = normalize_target_path(dir_path, true)?;
    let _ = verify_active_user_and_quota_conn(conn, user_id)?;
    let policy = load_user_policy_conn(conn, user_id)?;
    if !policy.permissions.read {
        return Err(McBrowserError::Forbidden(
            "McBrowser 'read' permission is disabled for this account".to_string(),
        ));
    }
    if !can_read_or_traverse_directory(&policy, &normalized_dir) {
        return Err(McBrowserError::Forbidden(
            "Access to requested directory is denied by user policy".to_string(),
        ));
    }
    Ok(policy)
}

pub(super) fn authorize_directory_listing(
    user: &AuthUser,
    dir_path: &str,
) -> Result<PolicyDocument, McBrowserError> {
    let _ = super::validate_mcbrowser_user(user)?;
    let _ = normalize_target_path(dir_path, true)?;
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for policy verification".to_string())
    })?;
    authorize_directory_listing_with_conn(&conn, user, dir_path)
}

pub(super) fn authorize_and_filter_entries(
    user: &AuthUser,
    dir_path: &str,
    entries: Vec<Entry>,
) -> Result<Vec<Entry>, McBrowserError> {
    let policy = authorize_directory_listing(user, dir_path)?;
    Ok(filter_visible_entries(&policy, entries))
}

pub(super) fn effective_scope_with_conn(
    conn: &Connection,
    user_id: i64,
) -> Result<String, McBrowserError> {
    let _ = verify_active_user_and_quota_conn(conn, user_id)?;
    let policy = load_user_policy_conn(conn, user_id)?;
    Ok(policy.scope)
}

pub(super) fn effective_scope(user_id: i64) -> Result<String, McBrowserError> {
    if user_id <= 0 {
        return Err(McBrowserError::Unauthorized(
            "Invalid user identity".to_string(),
        ));
    }
    let conn = af_db::get_conn().map_err(|_| {
        McBrowserError::Internal("Database unavailable for scope resolution".to_string())
    })?;
    effective_scope_with_conn(&conn, user_id)
}

pub(super) fn load_user_preferences_conn(
    conn: &Connection,
    user_id: i64,
) -> Result<PreferencesDocument, McBrowserError> {
    ensure_policy_tables(conn)?;

    let row: Option<(String, String, String, bool, bool, String, Option<String>)> = conn
        .query_row(
            "SELECT view_mode, sort_field, sort_direction, show_hidden, single_click, locale, extra_json \
             FROM mcbrowser_preferences WHERE user_id = ?1",
            params![user_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, i64>(3)? != 0,
                    r.get::<_, i64>(4)? != 0,
                    r.get::<_, String>(5)?,
                    r.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()
        .map_err(|_| McBrowserError::Internal("Failed to read user preferences".to_string()))?;

    let Some((view_str, sort_str, dir_str, show_hidden, single_click, locale, raw_extra_json)) =
        row
    else {
        return Ok(PreferencesDocument::default());
    };

    let extra = match raw_extra_json.as_deref() {
        None | Some("") | Some("{}") => ExtraPreferencesJson::default(),
        Some(raw) => serde_json::from_str::<ExtraPreferencesJson>(raw).map_err(|_| {
            McBrowserError::Internal("Persisted user preferences extra_json is invalid".to_string())
        })?,
    };

    let prefs = PreferencesDocument {
        view: ViewMode::from_db_str(&view_str)?,
        sort: SortField::from_db_str(&sort_str)?,
        direction: SortDirection::from_db_str(&dir_str)?,
        show_hidden,
        single_click,
        natural_sort: extra.natural_sort,
        redirect_after_copy_move: extra.redirect_after_copy_move,
        date_format: extra.date_format,
        editor_theme: extra.editor_theme,
        locale,
    };

    validate_preferences(prefs).map_err(|_| {
        McBrowserError::Internal("Persisted user preferences failed validation".to_string())
    })
}

pub(super) fn save_user_preferences_conn(
    conn: &Connection,
    user: &AuthUser,
    prefs: PreferencesDocument,
) -> Result<PreferencesDocument, McBrowserError> {
    let user_id = super::validate_mcbrowser_user(user)?;
    let validated = validate_preferences(prefs)?;
    ensure_policy_tables(conn)?;

    let extra_json = serde_json::to_string(&ExtraPreferencesJson {
        natural_sort: validated.natural_sort,
        redirect_after_copy_move: validated.redirect_after_copy_move,
        date_format: validated.date_format,
        editor_theme: validated.editor_theme.clone(),
    })
    .map_err(|_| McBrowserError::Internal("Failed to serialize user preferences".to_string()))?;

    conn.execute_batch("BEGIN IMMEDIATE TRANSACTION")
        .map_err(|_| {
            McBrowserError::Internal("Failed to start preferences transaction".to_string())
        })?;

    let tx_res = (|| -> Result<PreferencesDocument, McBrowserError> {
        let _ = verify_active_user_and_quota_conn(conn, user_id)?;

        conn.execute(
            "INSERT INTO mcbrowser_preferences (
                user_id, view_mode, sort_field, sort_direction,
                show_hidden, single_click, locale, extra_json, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, CURRENT_TIMESTAMP)
             ON CONFLICT(user_id) DO UPDATE SET
                view_mode = excluded.view_mode,
                sort_field = excluded.sort_field,
                sort_direction = excluded.sort_direction,
                show_hidden = excluded.show_hidden,
                single_click = excluded.single_click,
                locale = excluded.locale,
                extra_json = excluded.extra_json,
                updated_at = CURRENT_TIMESTAMP",
            params![
                user_id,
                validated.view.as_str(),
                validated.sort.as_str(),
                validated.direction.as_str(),
                i64::from(validated.show_hidden),
                i64::from(validated.single_click),
                &validated.locale,
                &extra_json,
            ],
        )
        .map_err(|_| McBrowserError::Internal("Failed to persist user preferences".to_string()))?;

        Ok(validated)
    })();

    match tx_res {
        Ok(saved) => {
            conn.execute_batch("COMMIT").map_err(|_| {
                let _ = conn.execute_batch("ROLLBACK");
                McBrowserError::Internal("Failed to commit preferences update".to_string())
            })?;
            Ok(saved)
        }
        Err(err) => {
            let _ = conn.execute_batch("ROLLBACK");
            Err(err)
        }
    }
}

pub(super) fn load_user_usage_conn(
    conn: &Connection,
    user_id: i64,
) -> Result<UsageResponse, McBrowserError> {
    let state = verify_active_user_and_quota_conn(conn, user_id)?;
    Ok(UsageResponse {
        used_bytes: state.used_bytes,
        quota_bytes: state.quota_bytes,
        status: state.status,
    })
}

async fn get_own_policy(auth_ext: Option<Extension<AuthUser>>) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let user_id = match super::validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let res = tokio::task::spawn_blocking(move || -> Result<PolicyDocument, McBrowserError> {
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for policy lookup".to_string())
        })?;
        let _ = verify_active_user_and_quota_conn(&conn, user_id)?;
        load_user_policy_conn(&conn, user_id)
    })
    .await;

    match res {
        Ok(Ok(policy)) => no_store_json(policy),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Policy lookup task failed".to_string()).into_response(),
    }
}

async fn get_user_policy(
    auth_ext: Option<Extension<AuthUser>>,
    Path(raw_target_user_id): Path<String>,
) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(user) => user,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = super::validate_mcbrowser_user(&auth_user) {
        return error.into_response();
    }
    if !auth_user.role.eq_ignore_ascii_case("admin") {
        return McBrowserError::Forbidden(
            "Admin access required to inspect user file policy".to_string(),
        )
        .into_response();
    }

    let Ok(target_user_id) = raw_target_user_id.trim().parse::<i64>() else {
        return McBrowserError::BadRequest("Invalid target user ID".to_string()).into_response();
    };
    if target_user_id <= 0 {
        return McBrowserError::BadRequest("Invalid target user ID".to_string()).into_response();
    }

    let guard = super::user_mutation_stripe(target_user_id)
        .lock_owned()
        .await;

    let result = tokio::task::spawn_blocking(move || -> Result<PolicyDocument, McBrowserError> {
        let _guard = guard;
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for policy lookup".to_string())
        })?;
        load_target_user_policy_conn(&conn, &auth_user, target_user_id)
    })
    .await;

    match result {
        Ok(Ok(policy)) => no_store_json(policy),
        Ok(Err(error)) => error.into_response(),
        Err(_) => McBrowserError::Internal("Policy lookup task failed".to_string()).into_response(),
    }
}

async fn put_user_policy(
    auth_ext: Option<Extension<AuthUser>>,
    Path(raw_target_user_id): Path<String>,
    body: Bytes,
) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    if let Err(e) = super::validate_mcbrowser_user(&auth_user) {
        return e.into_response();
    }
    if !auth_user.role.eq_ignore_ascii_case("admin") {
        return McBrowserError::Forbidden(
            "Admin access required to configure user file policy".to_string(),
        )
        .into_response();
    }

    let Ok(target_user_id) = raw_target_user_id.trim().parse::<i64>() else {
        return McBrowserError::BadRequest("Invalid target user ID".to_string()).into_response();
    };
    if target_user_id <= 0 {
        return McBrowserError::BadRequest("Invalid target user ID".to_string()).into_response();
    }

    if body.len() > MAX_POLICY_BODY_BYTES {
        return McBrowserError::PayloadTooLarge("Policy request body is too large".to_string())
            .into_response();
    }

    let parsed: PolicyDocument = match serde_json::from_slice(&body) {
        Ok(doc) => doc,
        Err(_) => {
            return McBrowserError::BadRequest(
                "Invalid policy JSON payload or unsupported fields".to_string(),
            )
            .into_response();
        }
    };

    let validated = match validate_and_normalize_policy(parsed) {
        Ok(doc) => doc,
        Err(e) => return e.into_response(),
    };

    let guard = super::user_mutation_stripe(target_user_id)
        .lock_owned()
        .await;

    let res = tokio::task::spawn_blocking(move || -> Result<PolicyDocument, McBrowserError> {
        let _guard = guard;
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for policy update".to_string())
        })?;
        save_user_policy_conn(&conn, &auth_user, target_user_id, validated)
    })
    .await;

    match res {
        Ok(Ok(saved)) => no_store_json(saved),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Policy update task failed".to_string()).into_response(),
    }
}

async fn get_own_preferences(auth_ext: Option<Extension<AuthUser>>) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let user_id = match super::validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let res =
        tokio::task::spawn_blocking(move || -> Result<PreferencesDocument, McBrowserError> {
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal("Database unavailable for preferences lookup".to_string())
            })?;
            let _ = verify_active_user_and_quota_conn(&conn, user_id)?;
            load_user_preferences_conn(&conn, user_id)
        })
        .await;

    match res {
        Ok(Ok(prefs)) => no_store_json(prefs),
        Ok(Err(e)) => e.into_response(),
        Err(_) => {
            McBrowserError::Internal("Preferences lookup task failed".to_string()).into_response()
        }
    }
}

async fn put_own_preferences(auth_ext: Option<Extension<AuthUser>>, body: Bytes) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let user_id = match super::validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    if body.len() > MAX_POLICY_BODY_BYTES {
        return McBrowserError::PayloadTooLarge(
            "Preferences request body is too large".to_string(),
        )
        .into_response();
    }

    let parsed: PreferencesDocument = match serde_json::from_slice(&body) {
        Ok(doc) => doc,
        Err(_) => {
            return McBrowserError::BadRequest(
                "Invalid preferences JSON payload or unsupported fields".to_string(),
            )
            .into_response();
        }
    };

    let validated = match validate_preferences(parsed) {
        Ok(doc) => doc,
        Err(e) => return e.into_response(),
    };

    let guard = super::user_mutation_stripe(user_id).lock_owned().await;

    let res =
        tokio::task::spawn_blocking(move || -> Result<PreferencesDocument, McBrowserError> {
            let _guard = guard;
            let conn = af_db::get_conn().map_err(|_| {
                McBrowserError::Internal("Database unavailable for preferences update".to_string())
            })?;
            save_user_preferences_conn(&conn, &auth_user, validated)
        })
        .await;

    match res {
        Ok(Ok(saved)) => no_store_json(saved),
        Ok(Err(e)) => e.into_response(),
        Err(_) => {
            McBrowserError::Internal("Preferences update task failed".to_string()).into_response()
        }
    }
}

async fn get_own_usage(auth_ext: Option<Extension<AuthUser>>) -> Response {
    let auth_user = match extract_auth_user(auth_ext) {
        Ok(u) => u,
        Err(e) => return e.into_response(),
    };
    let user_id = match super::validate_mcbrowser_user(&auth_user) {
        Ok(id) => id,
        Err(e) => return e.into_response(),
    };

    let res = tokio::task::spawn_blocking(move || -> Result<UsageResponse, McBrowserError> {
        let conn = af_db::get_conn().map_err(|_| {
            McBrowserError::Internal("Database unavailable for usage lookup".to_string())
        })?;
        load_user_usage_conn(&conn, user_id)
    })
    .await;

    match res {
        Ok(Ok(usage)) => no_store_json(usage),
        Ok(Err(e)) => e.into_response(),
        Err(_) => McBrowserError::Internal("Usage lookup task failed".to_string()).into_response(),
    }
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod policy_tests;
