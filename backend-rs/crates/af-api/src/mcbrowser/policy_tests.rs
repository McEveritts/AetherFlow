use super::*;
use crate::auth::{csrf_middleware, AuthUser};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware;
use http_body_util::BodyExt;
use rand::Rng;
use std::fs;
use std::path::PathBuf;
use tower::ServiceExt;

struct IsolatedTestDb {
    dir: PathBuf,
}

impl IsolatedTestDb {
    fn new() -> Self {
        let mut rng = rand::thread_rng();
        for _ in 0..64 {
            let token: u128 = rng.gen();
            let dir = std::env::temp_dir().join(format!("af-mcbrowser-policy-db-{token:032x}"));
            if fs::create_dir(&dir).is_ok() {
                let db_file = dir.join("test.sqlite");
                std::env::set_var("DB_PATH", &db_file);
                af_db::init_db().expect("initialize isolated test sqlite db");
                return Self { dir };
            }
        }
        panic!("failed to allocate isolated test sqlite directory");
    }
}

impl Drop for IsolatedTestDb {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn setup_in_memory_conn() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE user_quotas (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            quota_bytes INTEGER DEFAULT 0,
            used_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            source TEXT DEFAULT 'manual',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        "#,
    )
    .unwrap();
    ensure_policy_tables(&conn).unwrap();
    conn
}

fn make_user(user_id: i64, username: &str, role: &str) -> AuthUser {
    AuthUser {
        user_id,
        username: username.to_string(),
        role: role.to_string(),
        jti: format!("jti-{user_id}"),
        plugin_id: None,
        plugin_scopes: Vec::new(),
    }
}

fn make_entry(name: &str, path: &str, kind: &str) -> Entry {
    Entry {
        name: name.to_string(),
        path: path.to_string(),
        kind: kind.to_string(),
        size: if kind == "file" { 128 } else { 0 },
        modified: Some("2026-11-01T00:00:00Z".to_string()),
    }
}

#[test]
fn default_policy_allows_standard_file_ops_without_execute_and_enforces_user_lifecycle() {
    let conn = setup_in_memory_conn();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'alice', 'user'), (2, 'bob', 'user')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status) \
         VALUES (1, 'alice', 1048576, 512, 'active'), (2, 'bob', 1048576, 0, 'suspended')",
        [],
    )
    .unwrap();

    let alice = make_user(1, "alice", "user");
    let policy = load_user_policy_conn(&conn, 1).unwrap();
    assert_eq!(policy, PolicyDocument::default());
    assert_eq!(effective_scope_with_conn(&conn, 1).unwrap(), "");

    let serialized = serde_json::to_value(&policy).unwrap();
    assert_eq!(serialized["permissions"]["execute"], false);
    assert!(matches!(
        authorize_with_conn(&conn, &alice, Permission::Execute, "media/clip.mp4"),
        Err(McBrowserError::Forbidden(_))
    ));

    for perm in [
        Permission::Read,
        Permission::Create,
        Permission::Rename,
        Permission::Modify,
        Permission::Delete,
        Permission::Share,
        Permission::Download,
    ] {
        authorize_with_conn(&conn, &alice, perm, "media/clip.mp4").unwrap();
    }

    // Suspended quota lifecycle must fail closed
    let bob = make_user(2, "bob", "user");
    assert!(matches!(
        authorize_with_conn(&conn, &bob, Permission::Read, "file.txt"),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        effective_scope_with_conn(&conn, 2),
        Err(McBrowserError::Forbidden(_))
    ));

    // Missing user in SQLite must fail closed with Unauthorized
    let ghost = make_user(999, "ghost", "user");
    assert!(matches!(
        authorize_with_conn(&conn, &ghost, Permission::Read, "file.txt"),
        Err(McBrowserError::Unauthorized(_))
    ));

    // Plugin tokens are always denied even if user_id is valid
    let mut plugin_user = make_user(1, "alice", "admin");
    plugin_user.plugin_id = Some("radarr".to_string());
    assert!(matches!(
        authorize_with_conn(&conn, &plugin_user, Permission::Read, "file.txt"),
        Err(McBrowserError::Forbidden(_))
    ));
}

#[test]
fn safe_action_permission_migrates_default_off_and_requires_explicit_admin_opt_in() {
    let conn = setup_in_memory_conn();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'member', 'user')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO mcbrowser_policies (user_id, scope) VALUES (2, 'team')",
        [],
    )
    .unwrap();
    conn.execute_batch("ALTER TABLE mcbrowser_policies DROP COLUMN perm_execute")
        .unwrap();
    ensure_policy_tables(&conn).unwrap();
    ensure_policy_tables(&conn).unwrap();
    let migrated = load_user_policy_conn(&conn, 2).unwrap();
    assert_eq!(migrated.scope, "team");
    assert!(!migrated.permissions.execute);
    assert!(migrated.permissions.read);
    let legacy: PolicyDocument = serde_json::from_str(
        r#"{"permissions":{"read":true,"create":true,"rename":true,"modify":true,"delete":true,"share":true,"download":true},"rules":[],"scope":"team"}"#,
    )
    .unwrap();
    assert!(!legacy.permissions.execute);
    let admin = make_user(1, "admin", "admin");
    let member = make_user(2, "member", "user");
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Execute, "allowed.txt"),
        Err(McBrowserError::Forbidden(_))
    ));
    let mut enabled = migrated;
    enabled.permissions.execute = true;
    enabled.rules.push(PathRule {
        path: "private".to_string(),
        allow: false,
        regex: false,
        regexp: None,
    });
    assert!(matches!(
        save_user_policy_conn(&conn, &member, 2, enabled.clone()),
        Err(McBrowserError::Forbidden(_))
    ));
    save_user_policy_conn(&conn, &admin, 2, enabled).unwrap();
    assert!(load_user_policy_conn(&conn, 2).unwrap().permissions.execute);
    authorize_with_conn(&conn, &member, Permission::Execute, "allowed.txt").unwrap();
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Execute, "private/secret.txt"),
        Err(McBrowserError::Forbidden(_))
    ));
    let mut plugin = member.clone();
    plugin.plugin_id = Some("worker".to_string());
    assert!(matches!(
        authorize_with_conn(&conn, &plugin, Permission::Execute, "allowed.txt"),
        Err(McBrowserError::Forbidden(_))
    ));
    conn.execute(
        "INSERT INTO user_quotas (user_id, username, status) VALUES (2, 'member', 'suspended')",
        [],
    )
    .unwrap();
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Execute, "allowed.txt"),
        Err(McBrowserError::Forbidden(_))
    ));
}

#[test]
fn per_operation_permission_flags_are_enforced_independently() {
    let conn = setup_in_memory_conn();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'viewer', 'user')",
        [],
    )
    .unwrap();

    let admin = make_user(1, "admin", "admin");
    let viewer = make_user(2, "viewer", "user");

    let custom_policy = PolicyDocument {
        permissions: PolicyPermissions {
            read: true,
            create: false,
            rename: false,
            modify: false,
            delete: false,
            share: false,
            download: true,
            execute: false,
        },
        rules: Vec::new(),
        scope: String::new(),
    };

    save_user_policy_conn(&conn, &admin, 2, custom_policy).unwrap();

    authorize_with_conn(&conn, &viewer, Permission::Read, "docs/guide.pdf").unwrap();
    authorize_with_conn(&conn, &viewer, Permission::Download, "docs/guide.pdf").unwrap();

    for denied_perm in [
        Permission::Create,
        Permission::Rename,
        Permission::Modify,
        Permission::Delete,
        Permission::Share,
        Permission::Execute,
    ] {
        assert!(
            matches!(
                authorize_with_conn(&conn, &viewer, denied_perm, "docs/guide.pdf"),
                Err(McBrowserError::Forbidden(_))
            ),
            "expected {denied_perm:?} to be forbidden"
        );
    }
}

#[test]
fn segment_aware_prefix_rules_deny_overrides_and_ancestor_protections() {
    let conn = setup_in_memory_conn();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'member', 'user')",
        [],
    )
    .unwrap();

    let admin = make_user(1, "admin", "admin");
    let member = make_user(2, "member", "user");

    // 1. Segment-aware prefix: "a" must not match "ab"
    // 2. Specificity & carve-outs:
    //    - "a" is denied, "a/allowed" is allowed, "a/allowed/secret" is denied
    //    - "conflict" has both allow=true and allow=false -> deny overrides allow
    //    - "work/locked" is denied under allowed "work" -> ancestor "work" cannot be deleted/renamed
    let policy = PolicyDocument {
        permissions: PolicyPermissions::default(),
        rules: vec![
            PathRule {
                regex: false,
                regexp: None,
                path: "a".to_string(),
                allow: false,
            },
            PathRule {
                regex: false,
                regexp: None,
                path: "a/allowed".to_string(),
                allow: true,
            },
            PathRule {
                regex: false,
                regexp: None,
                path: "a/allowed/secret".to_string(),
                allow: false,
            },
            PathRule {
                regex: false,
                regexp: None,
                path: "conflict".to_string(),
                allow: true,
            },
            PathRule {
                regex: false,
                regexp: None,
                path: "conflict".to_string(),
                allow: false,
            },
            PathRule {
                regex: false,
                regexp: None,
                path: "work/locked".to_string(),
                allow: false,
            },
        ],
        scope: String::new(),
    };

    save_user_policy_conn(&conn, &admin, 2, policy).unwrap();

    // Segment awareness: "ab" and "ab/file.txt" are not matched by rule "a"
    authorize_with_conn(&conn, &member, Permission::Read, "ab").unwrap();
    authorize_with_conn(&conn, &member, Permission::Delete, "ab/file.txt").unwrap();

    // Direct access to "a" and "a/other.txt" is denied
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Read, "a"),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Read, "a/other.txt"),
        Err(McBrowserError::Forbidden(_))
    ));

    // Carve-out "a/allowed" is permitted, while "a/allowed/secret" is denied
    authorize_with_conn(&conn, &member, Permission::Read, "a/allowed").unwrap();
    authorize_with_conn(&conn, &member, Permission::Create, "a/allowed/notes.txt").unwrap();
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Read, "a/allowed/secret"),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        authorize_with_conn(
            &conn,
            &member,
            Permission::Download,
            "a/allowed/secret/key.pem"
        ),
        Err(McBrowserError::Forbidden(_))
    ));

    // Cannot delete or rename "a/allowed" because descendant "a/allowed/secret" is denied
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Delete, "a/allowed"),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        authorize_rename_with_conn(&conn, &member, "a/allowed", "a/moved"),
        Err(McBrowserError::Forbidden(_))
    ));

    // Equal-specificity conflict: deny overrides allow
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Read, "conflict"),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Read, "conflict/item.txt"),
        Err(McBrowserError::Forbidden(_))
    ));

    // Ancestor "work" can be read and new siblings created, but cannot be deleted or renamed
    authorize_with_conn(&conn, &member, Permission::Read, "work").unwrap();
    authorize_with_conn(&conn, &member, Permission::Create, "work/open.txt").unwrap();
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Delete, "work"),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        authorize_rename_with_conn(&conn, &member, "work", "work_backup"),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        authorize_rename_with_conn(&conn, &member, "ab/file.txt", "work/locked/file.txt"),
        Err(McBrowserError::Forbidden(_))
    ));

    // Ancestor directory visibility and per-entry filtering:
    // Root "" and "a" can be listed so the user can traverse to "a/allowed"
    let loaded_policy = authorize_directory_listing_with_conn(&conn, &member, "").unwrap();
    let root_entries = vec![
        make_entry("a", "a", "directory"),
        make_entry("ab", "ab", "directory"),
        make_entry("conflict", "conflict", "directory"),
        make_entry("work", "work", "directory"),
    ];
    let visible_root = filter_visible_entries(&loaded_policy, root_entries);
    let visible_root_names: Vec<&str> = visible_root.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(visible_root_names, vec!["a", "ab", "work"]);

    // Listing "a" is allowed as an ancestor of "a/allowed", but hides "a/hidden_dir" and "a/file.txt"
    let a_policy = authorize_directory_listing_with_conn(&conn, &member, "a").unwrap();
    let a_entries = vec![
        make_entry("allowed", "a/allowed", "directory"),
        make_entry("hidden_dir", "a/hidden_dir", "directory"),
        make_entry("file.txt", "a/file.txt", "file"),
    ];
    let visible_a = filter_visible_entries(&a_policy, a_entries);
    assert_eq!(visible_a.len(), 1);
    assert_eq!(visible_a[0].path, "a/allowed");

    // Listing "conflict" (no allowed descendants) is denied
    assert!(matches!(
        authorize_directory_listing_with_conn(&conn, &member, "conflict"),
        Err(McBrowserError::Forbidden(_))
    ));
}

#[test]
fn policy_and_preferences_validation_rejects_invalid_inputs_and_enforces_scopes() {
    let conn = setup_in_memory_conn();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'user2', 'user')",
        [],
    )
    .unwrap();

    let admin = make_user(1, "admin", "admin");
    let regular = make_user(2, "user2", "user");

    // Non-admin cannot save policy
    assert!(matches!(
        save_user_policy_conn(&conn, &regular, 2, PolicyDocument::default()),
        Err(McBrowserError::Forbidden(_))
    ));

    // Target user must exist
    assert!(matches!(
        save_user_policy_conn(&conn, &admin, 999, PolicyDocument::default()),
        Err(McBrowserError::NotFound(_))
    ));

    // Invalid scopes (host paths, traversal, wildcards, temp prefix) are rejected
    for bad_scope in [
        "/var/lib/aetherflow",
        "../escape",
        "sub/../../escape",
        "./local",
        "back\\slash",
        "   ",
        "glob/*",
        "question?",
        ".af-upload-tmp.123",
    ] {
        let doc = PolicyDocument {
            permissions: PolicyPermissions::default(),
            rules: Vec::new(),
            scope: bad_scope.to_string(),
        };
        assert!(
            matches!(
                save_user_policy_conn(&conn, &admin, 2, doc),
                Err(McBrowserError::BadRequest(_))
            ),
            "scope {bad_scope:?} should be rejected"
        );
    }

    // Invalid rule paths are rejected
    for bad_rule_path in [
        "/etc/passwd",
        "../secret",
        "a/b/*",
        "file?.txt",
        "   ",
        "dir\\file",
        ".af-upload-tmp.999",
    ] {
        let doc = PolicyDocument {
            permissions: PolicyPermissions::default(),
            rules: vec![PathRule {
                regex: false,
                regexp: None,
                path: bad_rule_path.to_string(),
                allow: false,
            }],
            scope: String::new(),
        };
        assert!(
            matches!(
                save_user_policy_conn(&conn, &admin, 2, doc),
                Err(McBrowserError::BadRequest(_))
            ),
            "rule path {bad_rule_path:?} should be rejected"
        );
    }

    // Valid relative scope and rule path are normalized and persisted per user
    let valid_doc = PolicyDocument {
        permissions: PolicyPermissions::default(),
        rules: vec![PathRule {
            regex: false,
            regexp: None,
            path: "team//private/".to_string(),
            allow: false,
        }],
        scope: "projects//alpha/".to_string(),
    };
    let saved = save_user_policy_conn(&conn, &admin, 2, valid_doc).unwrap();
    assert_eq!(saved.scope, "projects/alpha");
    assert_eq!(saved.rules[0].path, "team/private");
    assert_eq!(
        effective_scope_with_conn(&conn, 2).unwrap(),
        "projects/alpha"
    );
    // Admin's own scope remains independent ("")
    assert_eq!(effective_scope_with_conn(&conn, 1).unwrap(), "");

    // Preferences whitelist and isolation
    assert_eq!(
        load_user_preferences_conn(&conn, 2).unwrap(),
        PreferencesDocument::default()
    );
    let updated_prefs = PreferencesDocument {
        view: ViewMode::Grid,
        sort: SortField::Modified,
        direction: SortDirection::Desc,
        show_hidden: true,
        single_click: true,
        natural_sort: false,
        redirect_after_copy_move: true,
        date_format: true,
        editor_theme: "monokai".to_string(),
        locale: "en-US".to_string(),
    };
    save_user_preferences_conn(&conn, &regular, updated_prefs.clone()).unwrap();
    assert_eq!(load_user_preferences_conn(&conn, 2).unwrap(), updated_prefs);
    assert_eq!(
        load_user_preferences_conn(&conn, 1).unwrap(),
        PreferencesDocument::default()
    );

    // Invalid locale is rejected
    for bad_locale in ["", "   ", "en_US", "invalid-locale", "<script>", " en"] {
        let mut bad_prefs = updated_prefs.clone();
        bad_prefs.locale = bad_locale.to_string();
        assert!(matches!(
            save_user_preferences_conn(&conn, &regular, bad_prefs),
            Err(McBrowserError::BadRequest(_))
        ));
    }

    for bad_theme in [
        "",
        "   ",
        " chrome",
        "bad theme",
        "<script>",
        "a".repeat(65).as_str(),
    ] {
        let mut bad_prefs = updated_prefs.clone();
        bad_prefs.editor_theme = bad_theme.to_string();
        assert!(matches!(
            save_user_preferences_conn(&conn, &regular, bad_prefs),
            Err(McBrowserError::BadRequest(_))
        ));
    }
}

#[test]
fn ordered_regex_rules_persist_last_match_wins_and_reject_invalid_patterns() {
    let conn = setup_in_memory_conn();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'member', 'user')",
        [],
    )
    .unwrap();

    let admin = make_user(1, "admin", "admin");
    let member = make_user(2, "member", "user");

    let policy = PolicyDocument {
        permissions: PolicyPermissions::default(),
        rules: vec![
            PathRule {
                path: "/logs/.*\\.log$".to_string(),
                allow: false,
                regex: true,
                regexp: None,
            },
            PathRule {
                path: "public-logs".to_string(),
                allow: true,
                regex: true,
                regexp: Some(RuleExpression {
                    raw: "^/logs/public-.*\\.log$".to_string(),
                }),
            },
            PathRule {
                path: "logs/public-secret.log".to_string(),
                allow: false,
                regex: false,
                regexp: None,
            },
            PathRule {
                path: "override-secret".to_string(),
                allow: true,
                regex: true,
                regexp: Some(RuleExpression {
                    raw: "^/logs/public-secret\\.log$".to_string(),
                }),
            },
        ],
        scope: String::new(),
    };

    let saved = save_user_policy_conn(&conn, &admin, 2, policy).unwrap();
    let loaded = load_user_policy_conn(&conn, 2).unwrap();
    assert_eq!(loaded, saved);
    assert_eq!(loaded.rules.len(), 4);
    assert_eq!(
        loaded.rules[0].regexp,
        Some(RuleExpression {
            raw: "/logs/.*\\.log$".to_string()
        })
    );
    assert_eq!(
        loaded.rules[1].regexp,
        Some(RuleExpression {
            raw: "^/logs/public-.*\\.log$".to_string()
        })
    );
    assert!(!loaded.rules[2].regex);
    assert_eq!(loaded.rules[2].regexp, None);

    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Read, "logs/error.log"),
        Err(McBrowserError::Forbidden(_))
    ));
    authorize_with_conn(&conn, &member, Permission::Read, "logs/public-access.log").unwrap();
    authorize_with_conn(&conn, &member, Permission::Read, "logs/public-secret.log").unwrap();

    let reversed_policy = PolicyDocument {
        permissions: PolicyPermissions::default(),
        rules: vec![
            PathRule {
                path: "allow-log".to_string(),
                allow: true,
                regex: true,
                regexp: Some(RuleExpression {
                    raw: "^/logs/audit\\.log$".to_string(),
                }),
            },
            PathRule {
                path: "deny-all-logs".to_string(),
                allow: false,
                regex: true,
                regexp: Some(RuleExpression {
                    raw: "^/logs/.*\\.log$".to_string(),
                }),
            },
        ],
        scope: String::new(),
    };
    save_user_policy_conn(&conn, &admin, 2, reversed_policy).unwrap();
    assert!(matches!(
        authorize_with_conn(&conn, &member, Permission::Read, "logs/audit.log"),
        Err(McBrowserError::Forbidden(_))
    ));

    for invalid_rule in [
        PathRule {
            path: "[unclosed".to_string(),
            allow: false,
            regex: true,
            regexp: None,
        },
        PathRule {
            path: String::new(),
            allow: false,
            regex: true,
            regexp: None,
        },
        PathRule {
            path: "valid".to_string(),
            allow: false,
            regex: true,
            regexp: Some(RuleExpression {
                raw: "a".repeat(2049),
            }),
        },
        PathRule {
            path: "docs".to_string(),
            allow: false,
            regex: false,
            regexp: Some(RuleExpression {
                raw: "^/docs$".to_string(),
            }),
        },
    ] {
        let bad_doc = PolicyDocument {
            permissions: PolicyPermissions::default(),
            rules: vec![invalid_rule],
            scope: String::new(),
        };
        assert!(matches!(
            save_user_policy_conn(&conn, &admin, 2, bad_doc),
            Err(McBrowserError::BadRequest(_))
        ));
    }
}

#[test]
fn preferences_backwards_compatible_migration_and_view_aliases() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user'
        );
        CREATE TABLE user_quotas (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            quota_bytes INTEGER DEFAULT 0,
            used_bytes INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            source TEXT DEFAULT 'manual',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE mcbrowser_preferences (
            user_id INTEGER PRIMARY KEY,
            view_mode TEXT NOT NULL DEFAULT 'list',
            sort_field TEXT NOT NULL DEFAULT 'name',
            sort_direction TEXT NOT NULL DEFAULT 'asc',
            show_hidden INTEGER NOT NULL DEFAULT 0,
            single_click INTEGER NOT NULL DEFAULT 0,
            locale TEXT NOT NULL DEFAULT 'en',
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO users (id, username, role) VALUES (1, 'legacy', 'user'), (2, 'gallery_user', 'user');
        INSERT INTO mcbrowser_preferences (user_id, view_mode, sort_field, sort_direction, show_hidden, single_click, locale)
        VALUES (1, 'mosaic', 'name', 'asc', 1, 0, 'pt-br'),
               (2, 'mosaic gallery', 'size', 'desc', 0, 1, 'nl-BE');
        "#,
    )
    .unwrap();

    let legacy_prefs = load_user_preferences_conn(&conn, 1).unwrap();
    assert_eq!(legacy_prefs.view, ViewMode::Grid);
    assert!(legacy_prefs.show_hidden);
    assert!(!legacy_prefs.single_click);
    assert!(legacy_prefs.natural_sort);
    assert!(!legacy_prefs.redirect_after_copy_move);
    assert!(!legacy_prefs.date_format);
    assert_eq!(legacy_prefs.editor_theme, "chrome");
    assert_eq!(legacy_prefs.locale, "pt-br");

    let gallery_prefs = load_user_preferences_conn(&conn, 2).unwrap();
    assert_eq!(gallery_prefs.view, ViewMode::Gallery);
    assert_eq!(gallery_prefs.sort, SortField::Size);
    assert_eq!(gallery_prefs.direction, SortDirection::Desc);
    assert!(gallery_prefs.single_click);
    assert_eq!(gallery_prefs.locale, "nl-BE");

    let parsed_mosaic: PreferencesDocument = serde_json::from_str(
        r#"{"view":"mosaic","sort":"name","direction":"asc","show_hidden":false,"single_click":false,"locale":"en"}"#,
    )
    .unwrap();
    assert_eq!(parsed_mosaic.view, ViewMode::Grid);
    assert!(parsed_mosaic.natural_sort);
    assert!(!parsed_mosaic.redirect_after_copy_move);
    assert!(!parsed_mosaic.date_format);
    assert_eq!(parsed_mosaic.editor_theme, "chrome");

    let parsed_gallery: PreferencesDocument = serde_json::from_str(
        r#"{"view":"mosaic gallery","sort":"name","direction":"asc","show_hidden":false,"single_click":false,"natural_sort":false,"redirect_after_copy_move":true,"date_format":true,"editor_theme":"dracula","locale":"sv-se"}"#,
    )
    .unwrap();
    assert_eq!(parsed_gallery.view, ViewMode::Gallery);
    assert!(!parsed_gallery.natural_sort);
    assert!(parsed_gallery.redirect_after_copy_move);
    assert!(parsed_gallery.date_format);
    assert_eq!(parsed_gallery.editor_theme, "dracula");
    assert_eq!(parsed_gallery.locale, "sv-se");
}

#[tokio::test]
async fn http_routes_enforce_auth_csrf_admin_policy_preferences_and_usage() {
    let _guard = super::super::TEST_DATABASE_LOCK.lock().await;
    let _db = IsolatedTestDb::new();

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES (1, 'admin', 'admin'), (2, 'alice', 'user'), (3, 'frozen', 'user')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status) \
             VALUES (1, 'admin', 0, 0, 'active'), \
                    (2, 'alice', 10000, 2048, 'active'), \
                    (3, 'frozen', 10000, 512, 'suspended')",
            [],
        )
        .unwrap();
    }

    let admin = make_user(1, "admin", "admin");
    let alice = make_user(2, "alice", "user");
    let frozen = make_user(3, "frozen", "user");

    // 1. Unauthenticated requests fail closed with 401
    let unauth_resp = router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Cookie CSRF middleware blocks PUT without matching X-CSRF-Token
    if !std::env::var("CSRF_DISABLED").is_ok_and(|v| v.eq_ignore_ascii_case("true")) {
        let csrf_router = Router::new()
            .merge(router())
            .layer(middleware::from_fn(csrf_middleware))
            .layer(Extension(alice.clone()));
        let csrf_resp = csrf_router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/mcbrowser/preferences")
                    .header("content-type", "application/json")
                    .header("cookie", "aetherflow_session=tok")
                    .body(Body::from(
                        r#"{"view":"grid","sort":"name","direction":"asc","show_hidden":false,"single_click":false,"locale":"en"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(csrf_resp.status(), StatusCode::FORBIDDEN);
    }

    // 3. Non-admin PUT /mcbrowser/policy/2 is forbidden
    let non_admin_put = router()
        .layer(Extension(alice.clone()))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mcbrowser/policy/2")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"permissions":{"read":true,"create":true,"rename":true,"modify":true,"delete":false,"share":true,"download":true},"rules":[],"scope":""}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(non_admin_put.status(), StatusCode::FORBIDDEN);

    let bad_exec_put = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mcbrowser/policy/2")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"permissions":{"read":true,"create":true,"rename":true,"modify":true,"delete":true,"share":true,"download":true,"shell":true},"rules":[],"scope":""}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_exec_put.status(), StatusCode::BAD_REQUEST);

    // 5. Admin configures Alice's policy via PUT /mcbrowser/policy/2
    let admin_put = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mcbrowser/policy/2")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"permissions":{"read":true,"create":true,"rename":false,"modify":true,"delete":false,"share":false,"download":true},"rules":[{"path":"private//vault","allow":false}],"scope":"tenant/alice"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(admin_put.status(), StatusCode::OK);

    // 6. Alice reads her policy via GET /mcbrowser/policy
    let alice_get_policy = router()
        .layer(Extension(alice.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/policy")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(alice_get_policy.status(), StatusCode::OK);
    let body_bytes = alice_get_policy
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let alice_policy: PolicyDocument = serde_json::from_slice(&body_bytes).unwrap();
    assert!(!alice_policy.permissions.delete);
    assert!(!alice_policy.permissions.rename);
    assert_eq!(alice_policy.scope, "tenant/alice");
    assert_eq!(
        alice_policy.rules,
        vec![PathRule {
            regex: false,
            regexp: None,
            path: "private/vault".to_string(),
            allow: false
        }]
    );

    // Verify top-level authorize(), authorize_rename(), authorize_directory_listing(),
    // authorize_and_filter_entries(), and effective_scope() against the global pool
    assert_eq!(effective_scope(2).unwrap(), "tenant/alice");
    assert_eq!(effective_scope(1).unwrap(), "");
    authorize(&alice, Permission::Read, "public/readme.md").unwrap();
    assert!(matches!(
        authorize(&alice, Permission::Delete, "public/readme.md"),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        authorize(&alice, Permission::Read, "private/vault/secret.txt"),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        authorize_rename(&alice, "public/readme.md", "public/renamed.md"),
        Err(McBrowserError::Forbidden(_))
    ));
    let dir_policy = authorize_directory_listing(&alice, "private").unwrap();
    assert!(!dir_policy.permissions.delete);
    let filtered = authorize_and_filter_entries(
        &alice,
        "private",
        vec![
            make_entry("vault", "private/vault", "directory"),
            make_entry("open.txt", "private/open.txt", "file"),
        ],
    )
    .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].path, "private/open.txt");

    // 7. Preferences GET/PUT and unknown field rejection
    let bad_prefs_put = router()
        .layer(Extension(alice.clone()))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mcbrowser/preferences")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"view":"grid","sort":"name","direction":"asc","show_hidden":true,"single_click":false,"locale":"en","extra":123}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_prefs_put.status(), StatusCode::BAD_REQUEST);

    let ok_prefs_put = router()
        .layer(Extension(alice.clone()))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mcbrowser/preferences")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"view":"grid","sort":"size","direction":"desc","show_hidden":true,"single_click":true,"locale":"fr-FR"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_prefs_put.status(), StatusCode::OK);

    let alice_get_prefs = router()
        .layer(Extension(alice.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/preferences")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(alice_get_prefs.status(), StatusCode::OK);
    let prefs_bytes = alice_get_prefs
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let prefs_doc: PreferencesDocument = serde_json::from_slice(&prefs_bytes).unwrap();
    assert_eq!(prefs_doc.view, ViewMode::Grid);
    assert_eq!(prefs_doc.sort, SortField::Size);
    assert_eq!(prefs_doc.direction, SortDirection::Desc);
    assert!(prefs_doc.show_hidden);
    assert!(prefs_doc.single_click);
    assert_eq!(prefs_doc.locale, "fr-FR");

    // 8. Usage endpoint returns active usage and fails closed on suspended user
    let usage_resp = router()
        .layer(Extension(alice.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/usage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(usage_resp.status(), StatusCode::OK);
    let usage_bytes = usage_resp.into_body().collect().await.unwrap().to_bytes();
    let usage_doc: UsageResponse = serde_json::from_slice(&usage_bytes).unwrap();
    assert_eq!(
        usage_doc,
        UsageResponse {
            used_bytes: 2048,
            quota_bytes: 10000,
            status: "active".to_string(),
        }
    );

    let frozen_usage = router()
        .layer(Extension(frozen))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/usage")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(frozen_usage.status(), StatusCode::FORBIDDEN);
}

#[test]
fn target_user_policy_lookup_enforces_live_db_admin_and_target_constraints_on_same_conn() {
    let conn = setup_in_memory_conn();
    conn.execute(
        "INSERT INTO users (id, username, role) VALUES \
         (1, 'admin', 'admin'), \
         (2, 'alice', 'user'), \
         (3, 'demoted_admin', 'user'), \
         (4, 'suspended_admin', 'admin'), \
         (5, 'plugin:sonarr', 'plugin')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status) VALUES \
         (1, 'admin', 0, 0, 'active'), \
         (2, 'alice', 10000, 512, 'suspended'), \
         (3, 'demoted_admin', 0, 0, 'active'), \
         (4, 'suspended_admin', 0, 0, 'suspended')",
        [],
    )
    .unwrap();

    let admin = make_user(1, "admin", "admin");
    let alice = make_user(2, "alice", "user");
    let demoted_claim = make_user(3, "demoted_admin", "admin");
    let suspended_admin = make_user(4, "suspended_admin", "admin");
    let ghost_admin = make_user(999, "ghost_admin", "admin");

    assert!(matches!(
        load_target_user_policy_conn(&conn, &alice, 2),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        load_target_user_policy_conn(&conn, &demoted_claim, 2),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        load_target_user_policy_conn(&conn, &suspended_admin, 2),
        Err(McBrowserError::Forbidden(_))
    ));
    assert!(matches!(
        load_target_user_policy_conn(&conn, &ghost_admin, 2),
        Err(McBrowserError::Unauthorized(_))
    ));
    assert!(matches!(
        load_target_user_policy_conn(&conn, &admin, 0),
        Err(McBrowserError::BadRequest(_))
    ));
    assert!(matches!(
        load_target_user_policy_conn(&conn, &admin, -7),
        Err(McBrowserError::BadRequest(_))
    ));
    assert!(matches!(
        load_target_user_policy_conn(&conn, &admin, 404),
        Err(McBrowserError::NotFound(_))
    ));
    assert!(matches!(
        load_target_user_policy_conn(&conn, &admin, 5),
        Err(McBrowserError::Forbidden(_))
    ));

    let default_target_policy = load_target_user_policy_conn(&conn, &admin, 2).unwrap();
    assert_eq!(default_target_policy, PolicyDocument::default());

    let custom_policy = PolicyDocument {
        permissions: PolicyPermissions {
            read: true,
            create: false,
            rename: true,
            modify: false,
            delete: false,
            share: true,
            download: true,
            execute: false,
        },
        rules: vec![
            PathRule {
                path: "media/archive".to_string(),
                allow: false,
                regex: false,
                regexp: None,
            },
            PathRule {
                path: "public-archive".to_string(),
                allow: true,
                regex: true,
                regexp: Some(RuleExpression {
                    raw: "^/media/archive/public-.*\\.zip$".to_string(),
                }),
            },
        ],
        scope: "workspaces/alice".to_string(),
    };
    let saved_policy = save_user_policy_conn(&conn, &admin, 2, custom_policy.clone()).unwrap();
    let loaded_policy = load_target_user_policy_conn(&conn, &admin, 2).unwrap();
    assert_eq!(loaded_policy, saved_policy);
    assert_eq!(loaded_policy, custom_policy);
}

#[tokio::test]
async fn admin_get_user_policy_http_route_enforces_live_db_and_max_size_one_pool() {
    let _guard = super::super::TEST_DATABASE_LOCK.lock().await;
    let _db = IsolatedTestDb::new();

    {
        let conn = af_db::get_conn().unwrap();
        conn.execute(
            "INSERT INTO users (id, username, role) VALUES \
             (1, 'admin', 'admin'), \
             (2, 'alice', 'user'), \
             (3, 'demoted', 'user'), \
             (4, 'plugin:radarr', 'plugin')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO user_quotas (user_id, username, quota_bytes, used_bytes, status) VALUES \
             (1, 'admin', 0, 0, 'active'), \
             (2, 'alice', 10000, 1024, 'suspended'), \
             (3, 'demoted', 10000, 0, 'active')",
            [],
        )
        .unwrap();
    }

    let admin = make_user(1, "admin", "admin");
    let alice = make_user(2, "alice", "user");
    let demoted_claim = make_user(3, "demoted", "admin");

    let unauth_get = router()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/policy/2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_get.status(), StatusCode::UNAUTHORIZED);

    let non_admin_get = router()
        .layer(Extension(alice.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/policy/2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(non_admin_get.status(), StatusCode::FORBIDDEN);

    let demoted_admin_get = router()
        .layer(Extension(demoted_claim))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/policy/2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(demoted_admin_get.status(), StatusCode::FORBIDDEN);

    for invalid_target in ["0", "-3", "not-a-number"] {
        let bad_target_resp = router()
            .layer(Extension(admin.clone()))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/mcbrowser/policy/{invalid_target}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_target_resp.status(), StatusCode::BAD_REQUEST);
    }

    let missing_target_resp = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/policy/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing_target_resp.status(), StatusCode::NOT_FOUND);

    let plugin_target_resp = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/policy/4")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(plugin_target_resp.status(), StatusCode::FORBIDDEN);

    let put_resp = router()
        .layer(Extension(admin.clone()))
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/mcbrowser/policy/2")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"permissions":{"read":true,"create":false,"rename":true,"modify":false,"delete":false,"share":true,"download":true},"rules":[{"path":"vault//secret","allow":false,"regex":false},{"path":"^/vault/secret/public\\.txt$","allow":true,"regex":true,"regexp":{"raw":"^/vault/secret/public\\.txt$"}}],"scope":"teams//ops/"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    let get_resp = router()
        .layer(Extension(admin))
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcbrowser/policy/2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_resp.status(), StatusCode::OK);
    assert_eq!(
        get_resp.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-store"
    );
    let get_bytes = get_resp.into_body().collect().await.unwrap().to_bytes();
    let get_json: serde_json::Value = serde_json::from_slice(&get_bytes).unwrap();
    assert_eq!(get_json["permissions"]["execute"], false);
    let loaded_doc: PolicyDocument = serde_json::from_slice(&get_bytes).unwrap();
    assert_eq!(loaded_doc.scope, "teams/ops");
    assert!(!loaded_doc.permissions.create);
    assert!(!loaded_doc.permissions.modify);
    assert!(!loaded_doc.permissions.delete);
    assert!(loaded_doc.permissions.read);
    assert!(loaded_doc.permissions.rename);
    assert!(loaded_doc.permissions.share);
    assert!(loaded_doc.permissions.download);
    assert_eq!(
        loaded_doc.rules,
        vec![
            PathRule {
                path: "vault/secret".to_string(),
                allow: false,
                regex: false,
                regexp: None,
            },
            PathRule {
                path: "^/vault/secret/public\\.txt$".to_string(),
                allow: true,
                regex: true,
                regexp: Some(RuleExpression {
                    raw: "^/vault/secret/public\\.txt$".to_string(),
                }),
            },
        ]
    );
}
