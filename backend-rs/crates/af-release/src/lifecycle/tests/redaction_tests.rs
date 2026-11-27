use super::super::*;
use super::fixture;

#[test]
fn test_persisting_lifecycle_outcome_sanitizes_credentials_and_secrets() {
    let (root, _, _database, mut conn) = fixture();
    let lease = admit_job_with_target(
        &mut conn,
        "testpkg",
        "job-secret-1",
        "update",
        "2026-11-08T12:00:00Z",
        &[],
        Some("password:secret"),
    )
    .unwrap();

    finish_job_with_diagnostics(
        &conn,
        "testpkg",
        "job-secret-1",
        "update",
        false,
        LifecycleJobDiagnostics {
            failure_category: "configuration",
            failed_stage: Some("install_stage"),
            exit_code: Some(1),
            sanitized_summary: Some("password='prefix\nPERSISTED_QUOTE_CANARY' curl -u operator:\" PERSISTED_QUOTE_CANARY\" --verbose; failed connecting with Bearer supersecret and curl -u admin:hunter2 https://example.com"),
            expected_target_version: Some("password:secret"),
            achieved_version: Some("0.9.0"),
            ..Default::default()
        },
    )
    .unwrap();

    let history = get_lifecycle_history(&conn, "testpkg", 10).unwrap();
    assert_eq!(history.len(), 1);
    let record = &history[0];

    let summary = record.sanitized_summary.as_deref().unwrap();
    assert!(summary.contains("[REDACTED]"));
    assert!(!summary.contains("supersecret"));
    assert!(!summary.contains("hunter2"));
    assert!(!summary.contains("PERSISTED_QUOTE_CANARY"));

    let expected = record.expected_target_version.as_deref().unwrap();
    assert!(expected.contains("[REDACTED]"));
    assert!(!expected.contains("password:secret"));

    drop(lease);
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_sanitize_persisted_lifecycle_text_quoted_credentials() {
    assert_eq!(
        sanitize_persisted_lifecycle_text("password=\"first SECRET_TAIL\""),
        "password=[REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("secret='multi word secret'"),
        "secret=[REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("\"password\": \"first SECRET_TAIL\""),
        "\"password\": [REDACTED]"
    );
    let sample = "config with password=\"first SECRET_TAIL\" and secret='multi word secret' and \"password\": \"first SECRET_TAIL\" done";
    let sanitized = sanitize_persisted_lifecycle_text(sample);
    assert!(!sanitized.contains("SECRET_TAIL"));
    assert!(!sanitized.contains("multi word secret"));
    assert!(sanitized.contains("password=[REDACTED]"));
    assert!(sanitized.contains("secret=[REDACTED]"));
    assert!(sanitized.contains("\"password\": [REDACTED]"));
}
#[test]
fn test_sensitive_credentials_redaction_and_job_recording() {
    let sample1 = r#"{"db_password": "my_super_secret_db_pw"}"#;
    let sanitized1 = sanitize_persisted_lifecycle_text(sample1);
    assert!(!sanitized1.contains("my_super_secret_db_pw"));
    assert!(sanitized1.contains(r#"{"db_password": [REDACTED]}"#));

    let sample2 = "db_password=my_super_secret_db_pw";
    let sanitized2 = sanitize_persisted_lifecycle_text(sample2);
    assert!(!sanitized2.contains("my_super_secret_db_pw"));
    assert_eq!(sanitized2, "db_password=[REDACTED]");

    let sample3 = r#"admin_secret="first \"escaped_quote_secret\" tail_secret""#;
    let sanitized3 = sanitize_persisted_lifecycle_text(sample3);
    assert!(!sanitized3.contains("escaped_quote_secret"));
    assert!(!sanitized3.contains("tail_secret"));
    assert_eq!(sanitized3, "admin_secret=[REDACTED]");

    let sample4 = r#"{"secret": "first \"escaped_quote_secret\" tail_secret"}"#;
    let sanitized4 = sanitize_persisted_lifecycle_text(sample4);
    assert!(!sanitized4.contains("escaped_quote_secret"));
    assert!(!sanitized4.contains("tail_secret"));
    assert!(sanitized4.contains(r#"{"secret": [REDACTED]}"#));

    let (root, _, _database, mut conn) = fixture();
    let lease = admit_job_with_target(
        &mut conn,
        "testpkg-creds",
        "job-cred-1",
        "update",
        "2026-11-09T08:00:00Z",
        &[],
        Some("1.0.0"),
    )
    .unwrap();

    let diagnostic_summary =
        format!("failure with {sample1} and {sample2} and {sample3} and {sample4}");
    record_completed_lifecycle_job(
        &conn,
        "testpkg-creds",
        "job-cred-1",
        "update",
        Some(&diagnostic_summary),
        Some("1.0.0"),
        Some("1.0.0"),
    )
    .unwrap();

    let history = get_lifecycle_history(&conn, "testpkg-creds", 10).unwrap();
    assert_eq!(history.len(), 1);
    let record = &history[0];
    let summary = record.sanitized_summary.as_deref().unwrap();
    assert!(!summary.contains("my_super_secret_db_pw"));
    assert!(!summary.contains("escaped_quote_secret"));
    assert!(!summary.contains("tail_secret"));
    assert!(summary.contains("[REDACTED]"));

    drop(lease);
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_sanitize_curl_credentials_with_intervening_flags_and_quotes() {
    let cmd1 = "curl -s -u admin:synthetic-secret http://127.0.0.1:5572/core/version";
    let sanitized1 = sanitize_persisted_lifecycle_text(cmd1);
    assert!(!sanitized1.contains("synthetic-secret"));
    assert_eq!(
        sanitized1,
        "curl -s -u [REDACTED] http://127.0.0.1:5572/core/version"
    );

    let cmd2 = r#"curl -fsSL --user "admin:my secret" http://localhost"#;
    let sanitized2 = sanitize_persisted_lifecycle_text(cmd2);
    assert!(!sanitized2.contains("my secret"));
    assert_eq!(sanitized2, "curl -fsSL --user [REDACTED] http://localhost");

    let cmd3 = "curl --user=admin:secret_pass http://localhost";
    let sanitized3 = sanitize_persisted_lifecycle_text(cmd3);
    assert!(!sanitized3.contains("secret_pass"));
    assert_eq!(sanitized3, "curl --user=[REDACTED] http://localhost");

    let cmd4 = "curl -u=admin:secret_pass http://localhost";
    let sanitized4 = sanitize_persisted_lifecycle_text(cmd4);
    assert!(!sanitized4.contains("secret_pass"));
    assert_eq!(sanitized4, "curl -u=[REDACTED] http://localhost");
}
#[test]
fn test_sanitize_curl_attached_credentials_and_commas() {
    let cmd1 = "curl -uadmin:synthetic-secret http://localhost";
    let sanitized1 = sanitize_persisted_lifecycle_text(cmd1);
    assert!(!sanitized1.contains("synthetic-secret"));
    assert_eq!(sanitized1, "curl -u[REDACTED] http://localhost");

    let cmd2 = "curl -s -uadmin:part1,part2 http://localhost";
    let sanitized2 = sanitize_persisted_lifecycle_text(cmd2);
    assert!(!sanitized2.contains("part1"));
    assert!(!sanitized2.contains("part2"));
    assert_eq!(sanitized2, "curl -s -u[REDACTED] http://localhost");

    let cmd3 = "curl --user=admin:part1,part2 http://localhost";
    let sanitized3 = sanitize_persisted_lifecycle_text(cmd3);
    assert!(!sanitized3.contains("part1"));
    assert!(!sanitized3.contains("part2"));
    assert_eq!(sanitized3, "curl --user=[REDACTED] http://localhost");

    let cmd4 = "curl -u admin:sec1,sec2 http://localhost";
    let sanitized4 = sanitize_persisted_lifecycle_text(cmd4);
    assert!(!sanitized4.contains("sec1"));
    assert!(!sanitized4.contains("sec2"));
    assert_eq!(sanitized4, "curl -u [REDACTED] http://localhost");

    let cmd5 = "curl -fsSL -uadmin:secret http://localhost";
    let sanitized5 = sanitize_persisted_lifecycle_text(cmd5);
    assert!(!sanitized5.contains("secret"));
    assert_eq!(sanitized5, "curl -fsSL -u[REDACTED] http://localhost");
}
#[test]
fn test_sanitize_curl_and_kv_edge_cases() {
    assert_eq!(
        sanitize_persisted_lifecycle_text("curl -uadmin https://example.com"),
        "curl -u[REDACTED] https://example.com"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("curl -uadmin:secret https://example.com"),
        "curl -u[REDACTED] https://example.com"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("curl -u admin:part1,part2 https://example.com"),
        "curl -u [REDACTED] https://example.com"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("password=part1,part2"),
        "password=[REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("password: part1,part2"),
        "password: [REDACTED]"
    );
}

#[test]
fn test_wave19_audit_findings_lifecycle_sanitization_and_ordering() {
    // Finding 5: continuation tokens with '=' and ':'
    assert_eq!(
        sanitize_persisted_lifecycle_text("password: part1,part2=SECRET"),
        "password: [REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("token=part1,part2=SECRET; next=ok"),
        "token=[REDACTED]; next=ok"
    );

    // Finding 3: passwordless ssh:// and cred#... preserved, while other credentials redacted
    assert_eq!(
        sanitize_persisted_lifecycle_text(
            "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
        ),
        "git-repo:ssh://Deploy@git.example.com/Team/App.git#main"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("git-repo:ssh://git@github.com/org/repo.git#main"),
        "git-repo:ssh://git@github.com/org/repo.git#main"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text(
            "git-repo:https://cred#0123456789ab@github.com/org/repo.git#main"
        ),
        "git-repo:https://cred#0123456789ab@github.com/org/repo.git#main"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("ssh://user:pass@host/repo.git"),
        "ssh://[REDACTED]@host/repo.git"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("https://user:pass@host/repo.git"),
        "https://[REDACTED]@host/repo.git"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("https://token@host/repo.git"),
        "https://[REDACTED]@host/repo.git"
    );

    // Finding 6: Build metadata with +dfsg-1 is not classified as prerelease on Git / GitHub
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3+dfsg-1",
        Some("git")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3+dfsg-1",
        Some("github")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3+20130313144700",
        Some("git")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3+build-4",
        Some("git")
    ));
    // Build metadata (+...) does NOT affect prerelease classification on non-APT sources
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3+dev.1",
        Some("git")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3+debug",
        Some("git")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3+dirty",
        Some("git")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "1.2.3+wip",
        Some("git")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "v1.2.3+rc.1",
        Some("git")
    ));
    assert!(!is_prerelease_version_for_channel_with_source(
        "v1.2.3+rc.1",
        None
    ));
    assert!(is_prerelease_version_for_channel_with_source(
        "1.2.3-1",
        Some("git")
    ));

    // Finding 7: 7+ digit numeric version tags compared numerically, not as hex commit hashes
    assert_eq!(
        compare_versions("10000000", "9000000"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_versions("v10000000", "v9000000"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_versions("20261109", "9999999"),
        std::cmp::Ordering::Greater
    );
    // Real hex commit hashes still compared lexically
    assert_eq!(
        compare_versions("deadbeef", "cafebabe"),
        std::cmp::Ordering::Greater
    );
    assert_eq!(
        compare_versions("09abcdef", "10000000"),
        std::cmp::Ordering::Less
    );
}

#[test]
fn test_nested_secret_redaction() {
    assert_eq!(
        sanitize_persisted_lifecycle_text(r#"password: {"value":"CANARY_SECRET"}"#),
        "password: [REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text(r#""password": {"value":"CANARY_SECRET"}"#),
        "\"password\": [REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text(r#"secret=["CANARY_SECRET"]"#),
        "secret=[REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text(r#"password={"nested":{"secret":"CANARY_SECRET"}}"#),
        "password=[REDACTED]"
    );
    let sample =
        r#"diagnostics: {"auth": {"token": "CANARY_SECRET"}, "password": ["NESTED_SECRET"]}"#;
    let sanitized = sanitize_persisted_lifecycle_text(sample);
    assert!(!sanitized.contains("CANARY_SECRET"));
    assert!(!sanitized.contains("NESTED_SECRET"));
}
#[test]
fn test_wave21_nested_containers_and_multiline_redaction() {
    // 3-level nested object
    let sample_3level = r#"{"secret": {"level1": {"level2": {"level3": "CANARY_LEVEL3"}}}}"#;
    let sanitized_3level = sanitize_persisted_lifecycle_text(sample_3level);
    assert!(!sanitized_3level.contains("CANARY_LEVEL3"));
    assert_eq!(sanitized_3level, r#"{"secret": [REDACTED]}"#);

    // 4-level nested object
    let sample_4level =
        r#"{"password": {"level1": {"level2": {"level3": {"level4": "CANARY_LEVEL4"}}}}}"#;
    let sanitized_4level = sanitize_persisted_lifecycle_text(sample_4level);
    assert!(!sanitized_4level.contains("CANARY_LEVEL4"));
    assert_eq!(sanitized_4level, r#"{"password": [REDACTED]}"#);

    // Multiline pretty-printed JSON object
    let sample_multiline = "{\n  \"api_key\": {\n    \"level1\": {\n      \"level2\": {\n        \"key\": \"CANARY_MULTILINE\"\n      }\n    }\n  }\n}";
    let sanitized_multiline = sanitize_persisted_lifecycle_text(sample_multiline);
    assert!(!sanitized_multiline.contains("CANARY_MULTILINE"));
    assert!(sanitized_multiline.contains("\"api_key\": [REDACTED]"));

    // Multiline scalar value after sensitive key
    let sample_scalar_multiline = "{\n  \"api_key\":\n    \"CANARY_SCALAR\"\n}";
    let sanitized_scalar_multiline = sanitize_persisted_lifecycle_text(sample_scalar_multiline);
    assert!(!sanitized_scalar_multiline.contains("CANARY_SCALAR"));
    assert!(sanitized_scalar_multiline.contains("[REDACTED]"));

    // Truncated / unclosed container
    let sample_truncated = "diagnostics: password: {\"level1\": {\"level2\": \"CANARY_TRUNCATED\"";
    let sanitized_truncated = sanitize_persisted_lifecycle_text(sample_truncated);
    assert!(!sanitized_truncated.contains("CANARY_TRUNCATED"));
    assert!(sanitized_truncated.contains("password: [REDACTED]"));

    // redact_sensitive_nested_containers direct invocation
    let direct_redacted = redact_sensitive_nested_containers(sample_3level);
    assert!(!direct_redacted.contains("CANARY_LEVEL3"));
    assert_eq!(direct_redacted, r#"{"secret": [REDACTED]}"#);
}

#[test]
fn test_wave22_scalar_redaction() {
    let cases = [
        "Cookie: session=CANARY_COOKIE",
        "Set-Cookie: sid=CANARY_COOKIE; HttpOnly",
        "session=CANARY_SESSION",
        "session_id=CANARY_SESSION",
        "cookie=CANARY_COOKIE",
        r#"{"webhook_url":"https://example.test/CANARY_HOOK"}"#,
        r#"{"webhook":"CANARY_WEBHOOK"}"#,
        "webhook_secret=CANARY_HOOK",
        "pass=CANARY_PASSWORD",
        r#"{"pass":"CANARY_PASSWORD"}"#,
        "db_pass=CANARY_PASSWORD",
        "Proxy-Authorization: Basic CANARY_PROXY",
        "X-Api-Key: CANARY_API_KEY",
        "X-Auth-Token: CANARY_AUTH_TOKEN",
        "Authorization: Bearer CANARY_AUTH",
        "\"Cookie: session=CANARY_COOKIE\"",
    ];

    for c in cases {
        let redacted = sanitize_persisted_lifecycle_text(c);
        assert!(
            !redacted.contains("CANARY_"),
            "Redacted output for '{c}' still contains CANARY_: '{redacted}'"
        );
        assert!(
            redacted.contains("[REDACTED]"),
            "Redacted output for '{c}' must contain [REDACTED]: '{redacted}'"
        );
    }

    // Verify preservation of non-secret prose/keys
    let preserved = r#"{"bypass": true, "status": "passed"}"#;
    assert_eq!(sanitize_persisted_lifecycle_text(preserved), preserved);

    let prose = "compass heading is north and bypass compression";
    assert_eq!(sanitize_persisted_lifecycle_text(prose), prose);
}

#[test]
fn test_w22_s01_escaped_quote_and_multi_header_sanitization() {
    // 1. Escaped double-quotes inside header value
    let cmd1 = r#"curl -H "Cookie: sid=\"COOKIE_CANARY\"" https://example.invalid"#;
    let out1 = sanitize_persisted_lifecycle_text(cmd1);
    assert!(!out1.contains("COOKIE_CANARY"));
    assert!(out1.contains("https://example.invalid"));
    assert_eq!(
        out1,
        r#"curl -H "Cookie: [REDACTED]" https://example.invalid"#
    );

    // 2. Set-Cookie with attributes and inner escaped quote
    let cmd2 = r#"curl -H "Set-Cookie: sid=\"COOKIE_CANARY\"; Secure" https://example.invalid"#;
    let out2 = sanitize_persisted_lifecycle_text(cmd2);
    assert!(!out2.contains("COOKIE_CANARY"));
    assert!(out2.contains("https://example.invalid"));
    assert_eq!(
        out2,
        r#"curl -H "Set-Cookie: [REDACTED]" https://example.invalid"#
    );

    // 3. Single-quoted header value with double quotes and escaped single quotes
    let cmd3a = "curl -H 'Cookie: sid=\"COOKIE_CANARY\"' https://example.invalid";
    let out3a = sanitize_persisted_lifecycle_text(cmd3a);
    assert!(!out3a.contains("COOKIE_CANARY"));
    assert!(out3a.contains("https://example.invalid"));
    assert_eq!(
        out3a,
        "curl -H 'Cookie: [REDACTED]' https://example.invalid"
    );

    let cmd3b = r"curl -H 'Cookie: sid=\'COOKIE_CANARY\'' https://example.invalid";
    let out3b = sanitize_persisted_lifecycle_text(cmd3b);
    assert!(!out3b.contains("COOKIE_CANARY"));
    assert!(out3b.contains("https://example.invalid"));
    assert_eq!(
        out3b,
        "curl -H 'Cookie: [REDACTED]' https://example.invalid"
    );

    // 4. JSON-serialized string with escaped inner quotes
    let cmd4 = r#"{"cmd":"curl -H \"Cookie: sid=\\\"COOKIE_CANARY\\\"\" https://example.invalid"}"#;
    let out4 = sanitize_persisted_lifecycle_text(cmd4);
    assert!(!out4.contains("COOKIE_CANARY"));
    assert!(out4.contains("https://example.invalid"), "{out4}");
    assert_eq!(
        out4,
        r#"{"cmd":"curl -H \"Cookie: [REDACTED]\" https://example.invalid"}"#
    );

    // 5. Multiple headers on the same line
    let cmd5 = r#"curl -H "Cookie: sid=\"CANARY_1\"" -H "X-Api-Key: \"CANARY_2\"" https://example.invalid"#;
    let out5 = sanitize_persisted_lifecycle_text(cmd5);
    assert!(!out5.contains("CANARY_1"));
    assert!(!out5.contains("CANARY_2"));
    assert!(out5.contains("https://example.invalid"));
    assert_eq!(
        out5,
        r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: [REDACTED]" https://example.invalid"#
    );

    // Multiple headers without inner escaped quotes on same line
    let cmd5b =
        r#"curl -H "Cookie: sid=CANARY_1" -H "X-Api-Key: CANARY_2" https://example.invalid"#;
    let out5b = sanitize_persisted_lifecycle_text(cmd5b);
    assert!(!out5b.contains("CANARY_1"));
    assert!(!out5b.contains("CANARY_2"));
    assert!(out5b.contains("https://example.invalid"));
    assert_eq!(
        out5b,
        r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: [REDACTED]" https://example.invalid"#
    );
}

#[test]
fn test_w24_structured_masking_grammar() {
    let scalars = [
        r#"password=\"SECRET words\""#,
        r#"api_key=\"SECRET words\""#,
        r#"client_secret=\"SECRET words\""#,
        r#"session=\"SECRET words\""#,
        r#"webhook=\"SECRET words\""#,
        r#"rclone_rc_pass=\"SECRET words\""#,
    ];
    for sample in scalars {
        let out = sanitize_persisted_lifecycle_text(sample);
        assert!(!out.contains("SECRET"), "scalar leaked: {sample} -> {out}");
        assert!(
            out.contains("[REDACTED]"),
            "scalar missing mask: {sample} -> {out}"
        );
        assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
    }

    let flags = [
        "--password SECRET word",
        "--token SECRET word",
        "--api-key SECRET word",
        "--cookie SECRET word",
        "--session SECRET word",
        "--webhook SECRET word",
        r#"--password=\"SECRET words\""#,
        "--password=SECRET",
        "--token=SECRET",
    ];
    for sample in flags {
        let out = sanitize_persisted_lifecycle_text(sample);
        assert!(!out.contains("SECRET"), "flag leaked: {sample} -> {out}");
        assert!(
            out.contains("[REDACTED]"),
            "flag missing mask: {sample} -> {out}"
        );
        assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
    }

    let raw_user = r#"curl --user=\"admin:SECRET words\" https://example.invalid"#;
    let raw_out = sanitize_persisted_lifecycle_text(raw_user);
    assert!(!raw_out.contains("SECRET"), "curl user leaked: {raw_out}");
    assert!(raw_out.contains("https://example.invalid"), "{raw_out}");
    assert_eq!(raw_out, "curl --user=[REDACTED] https://example.invalid");

    let mut encoded = r#"curl --user="admin:SECRET words" https://example.invalid"#.to_string();
    for depth in 1..=4 {
        encoded = serde_json::to_string(&encoded).unwrap();
        let wrapped = format!(r#"{{"command":{encoded}}}"#);
        let out = sanitize_persisted_lifecycle_text(&wrapped);
        assert!(
            !out.contains("SECRET"),
            "depth {depth} leaked: {wrapped} -> {out}"
        );
        assert!(
            out.contains("https://example.invalid"),
            "depth {depth}: {out}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|err| panic!("depth {depth} json: {err}: {out}"));
        assert!(parsed.get("command").is_some(), "{out}");
        assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
    }

    let diag = r#"AF_DIAG_FAILURE={"stage": "password=[REDACTED]\"SECRET words\\\"", "exit_code": 17, "category": "installer", "summary": "--user [REDACTED]\"user:SECRET words\\\""}"#;
    let diag_out = sanitize_persisted_lifecycle_text(diag);
    assert!(!diag_out.contains("SECRET"), "diag leaked: {diag_out}");
    let json = diag_out
        .split_once("AF_DIAG_FAILURE=")
        .map(|(_, rest)| rest)
        .unwrap_or("");
    let parsed: serde_json::Value =
        serde_json::from_str(json).unwrap_or_else(|err| panic!("diag json: {err}: {json}"));
    assert_eq!(parsed["exit_code"], 17);
    assert_eq!(parsed["category"], "installer");
    assert!(!parsed.to_string().contains("SECRET"));
    assert_eq!(sanitize_persisted_lifecycle_text(&diag_out), diag_out);

    let preserved = "bypass=visible passed=true monkey=1";
    assert_eq!(sanitize_persisted_lifecycle_text(preserved), preserved);
}

#[test]
fn test_w25_escape_aware_scalar_and_unicode_keys() {
    let exact = [
        ("password=SENTINEL", "password=[REDACTED]"),
        ("password=[REDACTED]SENTINEL", "password=[REDACTED]"),
        (
            "curl --password [REDACTED]SENTINEL --verbose",
            "curl --password [REDACTED] --verbose",
        ),
        (
            "curl -uoperator:SENTINEL https://example.invalid",
            "curl -u[REDACTED] https://example.invalid",
        ),
        (r#"{"password":123456789}"#, r#"{"password":"[REDACTED]"}"#),
        ("password:'SENTINEL'", "password:[REDACTED]"),
        (
            r"curl --password prefix\ SENTINEL --verbose",
            "curl --password [REDACTED] --verbose",
        ),
        ("password=already,SENTINEL", "password=[REDACTED]"),
        (
            r"curl --password $'SENTINEL' https://example.invalid",
            "curl --password [REDACTED] https://example.invalid",
        ),
        (
            r#"curl --password $"SENTINEL" https://example.invalid"#,
            "curl --password [REDACTED] https://example.invalid",
        ),
        (
            r#"curl --password prefix"SENTINEL" https://example.invalid"#,
            "curl --password [REDACTED] https://example.invalid",
        ),
        (
            r"curl --password prefix'SENTINEL' https://example.invalid",
            "curl --password [REDACTED] https://example.invalid",
        ),
        (
            r"curl --user operator:prefix\ SENTINEL https://example.invalid",
            "curl --user [REDACTED] https://example.invalid",
        ),
        (r"password=prefix\;SENTINEL", "password=[REDACTED]"),
        (r"password=prefix\\;SENTINEL", "password=[REDACTED]"),
        (
            r#"{"command":"curl --password prefix\\ SENTINEL --verbose"}"#,
            r#"{"command":"curl --password [REDACTED] --verbose"}"#,
        ),
        (
            r#"{"command":"curl --password prefix\ SENTINEL --verbose"}"#,
            r#"{"command":"curl --password [REDACTED] --verbose"}"#,
        ),
        (
            r#"{"pass\u0077ord":"SENTINEL"}"#,
            r#"{"password":[REDACTED]}"#,
        ),
        (
            r#"{"pass\\u0077ord":"SENTINEL"}"#,
            r#"{"password":[REDACTED]}"#,
        ),
    ];
    for (sample, expected) in exact {
        let out = sanitize_persisted_lifecycle_text(sample);
        assert_eq!(out, expected, "sample={sample}");
        assert!(!out.contains("SENTINEL"), "{out}");
        assert!(!out.contains("123456789"), "{out}");
        assert_eq!(
            sanitize_persisted_lifecycle_text(&out),
            out,
            "idempotent: {sample}"
        );
        if sample.contains("--verbose") {
            assert!(out.contains("--verbose"), "{out}");
        }
        if sample.contains("https://example.invalid") {
            assert!(out.contains("https://example.invalid"), "{out}");
        }
        if expected.starts_with(r#"{"command""#) || expected.starts_with(r#"{"password":""#) {
            serde_json::from_str::<serde_json::Value>(&out)
                .unwrap_or_else(|err| panic!("json {err}: {out}"));
        }
    }

    let containers = [
        r#"{"Credentials":{"plain":"SENTINEL"}}"#,
        r#"{"credentials":{"a":{"b":{"c":{"plain":"SENTINEL"}}}}}"#,
        r#"{"credentials":[{"a":[{"plain":"SENTINEL"}]}]}"#,
    ];
    for sample in containers {
        let out = sanitize_persisted_lifecycle_text(sample);
        assert!(!out.contains("SENTINEL"), "{sample} -> {out}");
        assert!(!out.contains("plain"), "{sample} -> {out}");
        assert!(out.contains("[REDACTED]"), "{out}");
        assert_eq!(sanitize_persisted_lifecycle_text(&out), out, "{out}");
    }

    let header = r#"curl -H \"Cookie: sid=\"SENTINEL\"\" https://example.invalid"#;
    let header_out = sanitize_persisted_lifecycle_text(header);
    assert!(!header_out.contains("SENTINEL"), "{header_out}");
    assert!(
        header_out.contains("https://example.invalid"),
        "{header_out}"
    );
    assert!(header_out.contains("[REDACTED]"), "{header_out}");
    assert_eq!(sanitize_persisted_lifecycle_text(&header_out), header_out);

    let kept = r#"{"na\u006de":"visible"}"#;
    assert_eq!(sanitize_persisted_lifecycle_text(kept), kept);
}

#[test]
fn test_wave1a_crate01_utf8_escape_boundaries_never_panic() {
    let exact_cases = [
        ("password=\\é", "password=[REDACTED]"),
        ("password=\\\\é", "password=[REDACTED]"),
        ("password=\\é next=ok", "password=[REDACTED] next=ok"),
        ("password=\\中", "password=[REDACTED]"),
        ("password=\\🚀", "password=[REDACTED]"),
        (
            "password=prefix\\éSECRET_TAIL --verbose",
            "password=[REDACTED] --verbose",
        ),
        (
            "password=\"\\éSECRET_TAIL\" --verbose",
            "password=[REDACTED] --verbose",
        ),
        (
            "password='\\🚀SECRET_TAIL' --verbose",
            "password=[REDACTED] --verbose",
        ),
        (
            r#"password=\"\éSECRET_TAIL\" --verbose"#,
            "password=[REDACTED] --verbose",
        ),
        (
            "curl --password \\🚀SECRET_TAIL --verbose",
            "curl --password [REDACTED] --verbose",
        ),
        (
            "curl --user admin:\\éSECRET_TAIL https://example.invalid",
            "curl --user [REDACTED] https://example.invalid",
        ),
    ];

    for (sample, expected) in exact_cases {
        let persisted = sanitize_persisted_lifecycle_text(sample);
        assert_eq!(persisted, expected, "persisted sample={sample:?}");
        assert!(!persisted.contains("SECRET_TAIL"), "{persisted}");
        assert_eq!(
            sanitize_persisted_lifecycle_text(&persisted),
            persisted,
            "persisted idempotency: {sample:?}"
        );

        let projected = diagnostic_projection::redact_secrets(sample);
        assert_eq!(projected, expected, "projected sample={sample:?}");
        assert!(!projected.contains("SECRET_TAIL"), "{projected}");
        assert_eq!(
            diagnostic_projection::redact_secrets(&projected),
            projected,
            "projected idempotency: {sample:?}"
        );
    }

    let structured_utf8_cases = [
        r#"{"password":"prefix\\éSECRET_TAIL"}"#,
        r#"{"pass\u0077ord":"\\🚀SECRET_TAIL"}"#,
        "password={\"nested\":\"\\éSECRET_TAIL\"} --verbose",
        "token=[\\🚀,\"\\éSECRET_TAIL\"] --verbose",
        "Cookie: sid=\\éSECRET_TAIL",
        "curl -H \"Cookie: sid=\\\"\\éSECRET_TAIL\\\"\" https://example.invalid",
        r#"curl -H \\"Cookie: sid=\"\éSECRET_TAIL\" --verbose"#,
    ];
    for sample in structured_utf8_cases {
        let persisted = sanitize_persisted_lifecycle_text(sample);
        assert!(
            !persisted.contains("SECRET_TAIL"),
            "persisted leaked for {sample:?} -> {persisted:?}"
        );
        assert!(
            persisted.contains("[REDACTED]"),
            "persisted missing marker for {sample:?} -> {persisted:?}"
        );
        assert_eq!(sanitize_persisted_lifecycle_text(&persisted), persisted);

        let projected = diagnostic_projection::redact_secrets(sample);
        assert!(
            !projected.contains("SECRET_TAIL"),
            "projected leaked for {sample:?} -> {projected:?}"
        );
        assert!(
            projected.contains("[REDACTED]"),
            "projected missing marker for {sample:?} -> {projected:?}"
        );
        assert_eq!(diagnostic_projection::redact_secrets(&projected), projected);
    }

    // Verify full persistence path (`finish_job_with_diagnostics`) does not panic on `\ + UTF-8`.
    let (root, _, _database, mut conn) = fixture();
    let lease = admit_job_with_target(
        &mut conn,
        "utf8pkg",
        "job-utf8-1",
        "update",
        "2026-11-26T12:00:00Z",
        &[],
        Some("password=\\éSECRET_TARGET"),
    )
    .unwrap();
    finish_job_with_diagnostics(
        &conn,
        "utf8pkg",
        "job-utf8-1",
        "update",
        false,
        LifecycleJobDiagnostics {
            failure_category: "installer",
            failed_stage: Some("token=\\🚀SECRET_STAGE"),
            exit_code: Some(1),
            sanitized_summary: Some("stderr: password=\\éSECRET_SUMMARY --verbose"),
            expected_target_version: Some("password=\\中SECRET_EXPECTED"),
            achieved_version: Some("0.9.0"),
            ..Default::default()
        },
    )
    .unwrap();
    let history = get_lifecycle_history(&conn, "utf8pkg", 10).unwrap();
    assert_eq!(history.len(), 1);
    assert!(!history[0]
        .sanitized_summary
        .as_deref()
        .unwrap_or("")
        .contains("SECRET_SUMMARY"));
    assert!(!history[0]
        .failed_stage
        .as_deref()
        .unwrap_or("")
        .contains("SECRET_STAGE"));
    assert!(!history[0]
        .expected_target_version
        .as_deref()
        .unwrap_or("")
        .contains("SECRET_EXPECTED"));
    assert!(!history[0]
        .expected_target_version
        .as_deref()
        .unwrap_or("")
        .contains("SECRET_TARGET"));
    let job_expected: Option<String> = conn
        .query_row(
            "SELECT expected_target_version FROM package_lifecycle_jobs WHERE package_id='utf8pkg' AND job_id='job-utf8-1'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!job_expected
        .as_deref()
        .unwrap_or("")
        .contains("SECRET_EXPECTED"));
    assert!(!job_expected
        .as_deref()
        .unwrap_or("")
        .contains("SECRET_TARGET"));
    drop(lease);
    drop(conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_wave1a_crate01_utf8_combinatorial_fuzz_sweep() {
    let prefixes = [
        "password=",
        "token: ",
        "--password ",
        "curl -u ",
        "Bearer ",
        "Digest ",
    ];
    let scalars = ["é", "Ω", "中", "🚀", "👨‍👩‍👧‍👦"];
    let wrappers = [
        ("", ""),
        ("\"", "\""),
        ("'", "'"),
        ("\\\"", "\\\""),
        ("{", "}"),
        ("[", "]"),
    ];
    let tails = ["", " --verbose"];

    for prefix in prefixes {
        for scalar in scalars {
            for bs_count in 0..=2 {
                let slashes = "\\".repeat(bs_count);
                for (open, close) in wrappers {
                    for tail in tails {
                        let sample = format!("{prefix}{open}{slashes}{scalar}CANARY{close}{tail}");
                        let persisted = sanitize_persisted_lifecycle_text(&sample);
                        let projected = diagnostic_projection::redact_secrets(&sample);
                        let regexed = diagnostic_projection::redact_secrets_regex(&sample);
                        assert!(
                            !persisted.contains("CANARY"),
                            "persisted leaked CANARY for {sample:?} -> {persisted:?}"
                        );
                        assert!(
                            !projected.contains("CANARY"),
                            "projected leaked CANARY for {sample:?} -> {projected:?}"
                        );
                        assert!(
                            !regexed.contains("CANARY"),
                            "redact_secrets_regex leaked CANARY for {sample:?} -> {regexed:?}"
                        );
                        assert_eq!(
                            sanitize_persisted_lifecycle_text(&persisted),
                            persisted,
                            "persisted idempotency failed for {sample:?}"
                        );
                        assert_eq!(
                            diagnostic_projection::redact_secrets(&projected),
                            projected,
                            "projected idempotency failed for {sample:?}"
                        );
                        assert_eq!(
                            diagnostic_projection::redact_secrets_regex(&regexed),
                            regexed,
                            "redact_secrets_regex idempotency failed for {sample:?}"
                        );
                    }
                }
            }
        }
    }

    // Exercise quoted/escaped HTTP headers with embedded UTF-8 escapes and balanced closing quotes.
    let header_quotes = [("\"", "\""), ("\\\"", "\\\""), ("\\\\\"", "\\\"")];
    for (pre, post) in header_quotes {
        for scalar in scalars {
            for bs_count in 0..=2 {
                let slashes = "\\".repeat(bs_count);
                let sample = format!(
                    "curl -H {pre}Cookie: sid={slashes}{scalar}CANARY{post} https://example.invalid"
                );
                let expected =
                    format!("curl -H {pre}Cookie: [REDACTED]{post} https://example.invalid");
                let persisted = sanitize_persisted_lifecycle_text(&sample);
                let projected = diagnostic_projection::redact_secrets(&sample);
                assert_eq!(persisted, expected, "persisted header {sample:?}");
                assert_eq!(projected, expected, "projected header {sample:?}");
                assert_eq!(sanitize_persisted_lifecycle_text(&persisted), persisted);
                assert_eq!(diagnostic_projection::redact_secrets(&projected), projected);
            }
        }
    }

    // Exercise every valid UTF-8 prefix truncation (and malformed unbalanced quotes) without panicking.
    let truncation_samples = [
        "password=\\éCANARY --verbose",
        "password=\\\\中CANARY",
        "password=\\\\\\🚀CANARY",
        "password=\"\\éCANARY\" --verbose",
        "password='\\🚀CANARY' --verbose",
        r#"password=\"\éCANARY\" --verbose"#,
        "password={\"k\":\"\\éCANARY\"} --verbose",
        "token=[\\🚀,\"\\中CANARY\"]",
        "curl -u admin:\\éCANARY https://example.invalid",
        "\"Cookie: \"éCANARY\" --verbose",
        "\"Cookie: sid=\\\"\\éCANARY\\\"\" https://example.invalid",
        r#"\\"Cookie: sid=\"\🚀CANARY\" --verbose"#,
        "Bearer \\éCANARY\nDigest \\🚀CANARY",
        "Bearer \\\"éCANARY",
        "Digest username=\"\\éCANARY\", response=\"\\🚀CANARY\"",
        "Digest username=\\\"admin\\\", response=\\\"\\éCANARY",
    ];
    for sample in truncation_samples {
        for (idx, _) in sample.char_indices() {
            let truncated = &sample[..idx];
            let p1 = sanitize_persisted_lifecycle_text(truncated);
            assert_eq!(
                sanitize_persisted_lifecycle_text(&p1),
                p1,
                "persisted 1-step idempotency failed for {truncated:?} -> {p1:?}"
            );
            let r1 = diagnostic_projection::redact_secrets(truncated);
            assert_eq!(
                diagnostic_projection::redact_secrets(&r1),
                r1,
                "projected 1-step idempotency failed for {truncated:?} -> {r1:?}"
            );
            let x1 = diagnostic_projection::redact_secrets_regex(truncated);
            assert_eq!(
                diagnostic_projection::redact_secrets_regex(&x1),
                x1,
                "regexed 1-step idempotency failed for {truncated:?} -> {x1:?}"
            );
            if truncated.contains("CANARY") {
                assert!(
                    !p1.contains("CANARY"),
                    "persisted leaked truncated {truncated:?} -> {p1:?}"
                );
                assert!(
                    !r1.contains("CANARY"),
                    "projected leaked truncated {truncated:?} -> {r1:?}"
                );
                assert!(
                    !x1.contains("CANARY"),
                    "regexed leaked truncated {truncated:?} -> {x1:?}"
                );
            }
        }
    }
}

#[test]
fn test_wave1a_closing_header_quote_len_and_escaped_header_boundaries() {
    // Direct unit tests for closing_header_quote_len across all escape depths & defensive bounds.
    assert_eq!(closing_header_quote_len("\" --verbose", 0, "\""), 1);
    assert_eq!(closing_header_quote_len("' --verbose", 0, "'"), 1);
    assert_eq!(closing_header_quote_len(r#"\" --verbose"#, 0, r#"\""#), 2);
    assert_eq!(closing_header_quote_len(r#"\\" --verbose"#, 0, r#"\\""#), 3);
    // Partial escape depth: pre has 2 backslashes (`\\"`), closing quote has 1 backslash (`\"`).
    assert_eq!(
        closing_header_quote_len(r#"sid=\"val\" --verbose"#, 9, r#"\\""#),
        2
    );
    // Zero-backslash closing quote for escaped pre.
    assert_eq!(closing_header_quote_len("sid=\" --verbose", 4, r#"\""#), 1);
    // Fallback multi-byte UTF-8 char when rest does not begin with pre or quote_ch.
    assert_eq!(closing_header_quote_len("é", 0, "\""), 2);
    assert_eq!(closing_header_quote_len("🚀", 0, "\""), 4);
    // Empty pre, out-of-bounds, and mid-UTF-8-char indices must never panic under panic="abort".
    assert_eq!(closing_header_quote_len("abc\"", 0, ""), 0);
    assert_eq!(closing_header_quote_len("é\"", 1, "\""), 0);
    assert_eq!(closing_header_quote_len("abc", 99, "\""), 0);
    assert!(!has_matching_secret_quote(b"abc", 99, 0));

    // Multi-parameter escaped Cookie and Authorization: Digest headers must not close early at inner commas.
    let c1 = r#"curl -H \\"Cookie: a=\"1\", sid=\"SECRET_COOKIE\"\\" https://example.invalid"#;
    let c1_expected = r#"curl -H \\"Cookie: [REDACTED]\\" https://example.invalid"#;
    assert_eq!(sanitize_persisted_lifecycle_text(c1), c1_expected);
    assert_eq!(diagnostic_projection::redact_secrets(c1), c1_expected);

    let c2 = r#"curl -H \\"Authorization: Digest username=\"admin\", response=\"SECRET_HEX\"\\" https://example.invalid"#;
    assert_eq!(
        sanitize_persisted_lifecycle_text(c2),
        r#"curl -H \\"Authorization: [REDACTED]\\" https://example.invalid"#
    );
    assert_eq!(
        diagnostic_projection::redact_secrets(c2),
        r#"curl -H \\"Authorization: Digest [REDACTED]\\" https://example.invalid"#
    );

    let c3 = r#"curl -H \"Cookie: a="1", sid=SECRET_COOKIE\" https://example.invalid"#;
    let c3_expected = r#"curl -H \"Cookie: [REDACTED]\" https://example.invalid"#;
    assert_eq!(sanitize_persisted_lifecycle_text(c3), c3_expected);
    assert_eq!(diagnostic_projection::redact_secrets(c3), c3_expected);

    let c4 = r#"curl -H \\"Cookie: a=\"1\", b=\"SECRET_LEAK\" --verbose"#;
    let c4_expected = r#"curl -H \\"Cookie: [REDACTED]\" --verbose"#;
    assert_eq!(sanitize_persisted_lifecycle_text(c4), c4_expected);
    assert_eq!(diagnostic_projection::redact_secrets(c4), c4_expected);

    let c5 = r#"{\"hdr\":\"Cookie: sid=SECRET\",\"ok\":true}"#;
    let c5_expected = r#"{\"hdr\":\"Cookie: [REDACTED]\",\"ok\":true}"#;
    assert_eq!(sanitize_persisted_lifecycle_text(c5), c5_expected);
    assert_eq!(diagnostic_projection::redact_secrets(c5), c5_expected);

    // ANSI-C `$'...'` / `$"..."` scalars starting with delimiter characters must not truncate after `$`.
    for ansi_case in [
        "curl --password $',SECRET' --verbose",
        "curl --password $':SECRET' --verbose",
        "curl --password $';SECRET' --verbose",
        "curl --password $'&SECRET' --verbose",
        "curl --password $'}SECRET' --verbose",
        "curl --password $']SECRET' --verbose",
        "curl --password $\",SECRET\" --verbose",
        "curl --password prefix$',SECRET' --verbose",
    ] {
        let p = sanitize_persisted_lifecycle_text(ansi_case);
        assert_eq!(
            p, "curl --password [REDACTED] --verbose",
            "persisted: {ansi_case}"
        );
        let r = diagnostic_projection::redact_secrets(ansi_case);
        assert_eq!(
            r, "curl --password [REDACTED] --verbose",
            "projected: {ansi_case}"
        );
    }

    // Container-shaped CLI/curl secrets must be redacted in persisted lifecycle text too.
    assert_eq!(
        sanitize_persisted_lifecycle_text("curl --password {éCANARY} --verbose"),
        "curl --password [REDACTED] --verbose"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("curl -u [éCANARY] https://example.invalid"),
        "curl -u [REDACTED] https://example.invalid"
    );
}

#[test]
fn test_wave1a_crate05_secret_auth_header_re_anchor_and_whitespace() {
    let cases = [
        ("Bearer supersecret", "Bearer [REDACTED]"),
        ("bearer supersecret", "bearer [REDACTED]"),
        ("Basic dXNlcjpwYXNz", "Basic [REDACTED]"),
        ("Basic admin:supersecret", "Basic [REDACTED]"),
        ("Token tok_12345", "Token [REDACTED]"),
        ("Digest resp_abcdef", "Digest [REDACTED]"),
        (
            "Digest username=\"admin\", response=\"deadbeef\"",
            "Digest [REDACTED]",
        ),
        (
            "Digest username=\"admin\", realm=\"r\", response=\"deadbeef\" --verbose",
            "Digest [REDACTED] --verbose",
        ),
        (" Bearer supersecret", " Bearer [REDACTED]"),
        ("  Bearer   supersecret", "  Bearer   [REDACTED]"),
        ("\tBasic\t\tdXNlcjpwYXNz", "\tBasic\t\t[REDACTED]"),
        (
            "failed with Bearer\tsupersecret in header",
            "failed with Bearer\t[REDACTED] in header",
        ),
        (
            "line1\nBearer sec1\nBasic  sec2\nToken\tsec3\nDigest sec4",
            "line1\nBearer [REDACTED]\nBasic  [REDACTED]\nToken\t[REDACTED]\nDigest [REDACTED]",
        ),
        // Cross-line `\n` must never bridge a line-ending scheme word onto next line's credential.
        (
            "failed to parse token\nBearer supersecret_jwt_123",
            "failed to parse token\nBearer [REDACTED]",
        ),
        (
            "invalid token\nBasic dXNlcjpwYXNz",
            "invalid token\nBasic [REDACTED]",
        ),
        (
            "failed to verify digest\nBasic dXNlcjpwYXNz",
            "failed to verify digest\nBasic [REDACTED]",
        ),
        (
            "unsupported scheme: Bearer\nBearer supersecret_jwt_123",
            "unsupported scheme: Bearer\nBearer [REDACTED]",
        ),
        // Multi-quoted auth credentials must not bridge across closing/opening quotes.
        ("\"Bearer supersecret\"", "\"Bearer [REDACTED]\""),
        ("'Token  tok_12345'", "'Token  [REDACTED]'"),
        (
            r#"failed: "Bearer sec1" and "Bearer SECRET2""#,
            r#"failed: "Bearer [REDACTED]" and "Bearer [REDACTED]""#,
        ),
        (
            "'Token tok_1' 'Token SECRET2'",
            "'Token [REDACTED]' 'Token [REDACTED]'",
        ),
        // Non-identifier delimiters `=`, `(`, `[`, `{`.
        ("(Bearer supersecret)", "(Bearer [REDACTED])"),
        ("hdr=Bearer supersecret", "hdr=Bearer [REDACTED]"),
        ("[Token tok_12345]", "[Token [REDACTED]]"),
        ("{Digest dig_12345}", "{Digest [REDACTED]}"),
        (
            "err;Digest\tdig_123,Basic   b64==",
            "err;Digest\t[REDACTED],Basic   [REDACTED]",
        ),
        ("Bearer \"quoted secret\" tail", "Bearer [REDACTED] tail"),
        ("Bearer prefix[REDACTED]suffix", "Bearer [REDACTED]"),
        ("[Token prefix[inner]suffix]", "[Token [REDACTED]]"),
        (
            "Bearer sec1 Bearer sec2",
            "Bearer [REDACTED] Bearer [REDACTED]",
        ),
    ];

    for (input, expected) in cases {
        let regex_out = diagnostic_projection::redact_secrets_regex(input);
        assert_eq!(
            regex_out, expected,
            "redact_secrets_regex mismatch for {input:?}"
        );
        assert_eq!(
            diagnostic_projection::redact_secrets_regex(&regex_out),
            regex_out,
            "redact_secrets_regex not idempotent for {input:?}"
        );

        let full_out = diagnostic_projection::redact_secrets(input);
        assert_eq!(full_out, expected, "redact_secrets mismatch for {input:?}");
        assert_eq!(
            diagnostic_projection::redact_secrets(&full_out),
            full_out,
            "redact_secrets not idempotent for {input:?}"
        );
    }

    // Verify persisted lifecycle text shares full auth-scheme parity (no leaks or whitespace loss).
    assert_eq!(
        sanitize_persisted_lifecycle_text("unsupported scheme: Bearer\nBearer supersecret_jwt_123"),
        "unsupported scheme: Bearer\nBearer [REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("Basic admin:supersecret"),
        "Basic [REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("Bearer [REDACTED]SUPER_SECRET"),
        "Bearer [REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("Bearer \"quoted secret\""),
        "Bearer [REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("Digest username=\"admin\", response=\"deadbeef\""),
        "Digest [REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("bearer\t\tsupersecret"),
        "bearer\t\t[REDACTED]"
    );

    // Valid JSON with escaped Authorization: Digest header must remain valid JSON and idempotent.
    let json_digest = r#"{"cmd":"curl -H \"Authorization: Digest username=\\\"admin\\\", response=\\\"SECRET_HEX\\\"\" https://example.invalid"}"#;
    let json_digest_out = diagnostic_projection::redact_secrets(json_digest);
    assert!(!json_digest_out.contains("SECRET_HEX"), "{json_digest_out}");
    assert!(
        json_digest_out.contains("https://example.invalid"),
        "{json_digest_out}"
    );
    serde_json::from_str::<serde_json::Value>(&json_digest_out)
        .unwrap_or_else(|err| panic!("broken JSON ({err}): {json_digest_out}"));
    assert_eq!(
        diagnostic_projection::redact_secrets(&json_digest_out),
        json_digest_out
    );

    // Already-redacted tokens (including multi-quoted arrays and lowercase [REDACTED_url]) stay verbatim.
    for already in [
        "Bearer [REDACTED]",
        "  Bearer   [REDACTED]",
        "\"Bearer [REDACTED]\"",
        r#""Bearer [REDACTED]", "Bearer [REDACTED]""#,
        r#"["Bearer [REDACTED]", "Bearer [REDACTED]"]"#,
        "Token [REDACTED_URL]",
        "Token [REDACTED_url]",
        "Basic \"[REDACTED]\"",
    ] {
        assert_eq!(
            diagnostic_projection::redact_secrets_regex(already),
            already
        );
        assert_eq!(diagnostic_projection::redact_secrets(already), already);
        assert_eq!(sanitize_persisted_lifecycle_text(already), already);
    }

    // Non-delimited identifier suffixes, cross-line directives, and trailing scheme prose must not corrupt.
    for benign in [
        "myBearer stay_visible",
        "auth_token stay_visible",
        "x-digest stay_visible",
        "subBasic stay_visible",
        "failed to refresh token\nexit_code=1",
        "<Location /private>\n    AuthType Basic\n    Require ip 192.0.2.0/24\n</Location>",
        r#"{"error": "expected Bearer ", "status": 401}"#,
        r#"{"outer":"{\"a\":\"Bearer \"}","other":"\"x\""}"#,
        r#"{"outer":"{\"a\":\"Bearer \",\"b\":\"ok\"}"}"#,
    ] {
        assert_eq!(diagnostic_projection::redact_secrets_regex(benign), benign);
        assert_eq!(diagnostic_projection::redact_secrets(benign), benign);
        assert_eq!(sanitize_persisted_lifecycle_text(benign), benign);
    }
}

#[test]
fn test_wave1a_r2_audit_regressions_closed_header_keys_ansi_c_and_auth_glued_suffixes() {
    // 1. Single-quoted / closed-quote sensitive HTTP header keys must NEVER bypass redaction.
    let single_quoted = "{'Authorization': 'SUPER_SECRET', 'Cookie': 'sid=COOKIE_SECRET', 'Set-Cookie': 'sid=SET_SECRET', 'Proxy-Authorization': 'CUSTOM_SECRET', 'X-Api-Key': 'KEY_SECRET', 'X-Auth-Token': 'TOK_SECRET'}";
    for out in [
        diagnostic_projection::redact_secrets(single_quoted),
        diagnostic_projection::redact_secrets_regex(single_quoted),
        sanitize_persisted_lifecycle_text(single_quoted),
    ] {
        for secret in [
            "SUPER_SECRET",
            "COOKIE_SECRET",
            "SET_SECRET",
            "CUSTOM_SECRET",
            "KEY_SECRET",
            "TOK_SECRET",
        ] {
            assert!(!out.contains(secret), "leaked {secret} in {out:?}");
        }
    }

    // 2. Passwords ending in literal `$` inside JSON/quoted strings must not corrupt JSON or leak adjacent keys.
    for (json_dollar, expected_persisted) in [
        (
            r#"{"stage":"password=hunter2$"}"#,
            r#"{"stage":"password=[REDACTED]"}"#,
        ),
        (
            r#"{"stage":"password=hunter2$","api_key":"TOP_SECRET_123"}"#,
            r#"{"stage":"password=[REDACTED]","api_key":[REDACTED]}"#,
        ),
        (
            r#"{"stage": "password=$", "rc": 1}"#,
            r#"{"stage": "password=[REDACTED]", "rc": 1}"#,
        ),
        (
            r#"{"stage": "password=myP@ss$", "token": "SUPER_SECRET"}"#,
            r#"{"stage": "password=[REDACTED]", "token": [REDACTED]}"#,
        ),
    ] {
        let p = sanitize_persisted_lifecycle_text(json_dollar);
        let r = diagnostic_projection::redact_secrets(json_dollar);
        assert_eq!(p, expected_persisted, "persisted: {json_dollar}");
        assert!(!r.contains("hunter2"), "{json_dollar} -> {r}");
        assert!(!r.contains("myP@ss"), "{json_dollar} -> {r}");
        assert!(!r.contains("TOP_SECRET_123"), "{json_dollar} -> {r}");
        assert!(!r.contains("SUPER_SECRET"), "{json_dollar} -> {r}");
        serde_json::from_str::<serde_json::Value>(&r)
            .unwrap_or_else(|err| panic!("broken projected JSON ({err}) for {json_dollar}: {r}"));
        if !expected_persisted.contains(":[REDACTED]")
            && !expected_persisted.contains(": [REDACTED]")
        {
            serde_json::from_str::<serde_json::Value>(&p).unwrap_or_else(|err| {
                panic!("broken persisted JSON ({err}) for {json_dollar}: {p}")
            });
        }
    }
    let non_json_dollar = r#"err="password=hunter2$", "api_key": "TOP_SECRET_123""#;
    assert!(!diagnostic_projection::redact_secrets(non_json_dollar).contains("TOP_SECRET_123"));
    assert!(!sanitize_persisted_lifecycle_text(non_json_dollar).contains("TOP_SECRET_123"));
    let non_json_space = r#"note="password=myP@ss$" "token"="SUPER_SECRET""#;
    assert!(!diagnostic_projection::redact_secrets(non_json_space).contains("SUPER_SECRET"));
    assert!(!sanitize_persisted_lifecycle_text(non_json_space).contains("SUPER_SECRET"));

    // 3. JSON-escaped ANSI-C quotes with delimiter-leading secrets must redact cleanly.
    let json_ansi = r#"{"cmd":"curl --password $\",SECRET\" --verbose"}"#;
    let json_ansi_p = sanitize_persisted_lifecycle_text(json_ansi);
    assert_eq!(
        json_ansi_p,
        r#"{"cmd":"curl --password [REDACTED] --verbose"}"#
    );
    serde_json::from_str::<serde_json::Value>(&json_ansi_p).unwrap();

    // 4. Glued auth suffixes, truncated escaped quotes, quote-bridging prose, and RFC 7235/7616 Digest.
    let auth_cases = [
        ("Bearer [REDACTED_URL]SECRET_TAIL", "Bearer [REDACTED]"),
        (r#"Bearer [REDACTED]\"SECRET_TAIL\""#, "Bearer [REDACTED]"),
        (r#"Bearer [REDACTED]"SECRET_TAIL""#, "Bearer [REDACTED]"),
        ("Bearer [REDACTED]'SECRET_TAIL'", "Bearer [REDACTED]"),
        (r#"Bearer "[REDACTED]"SECRET_TAIL"#, "Bearer [REDACTED]"),
        (r#"Bearer prefix"SECRET_TAIL""#, "Bearer [REDACTED]"),
        (r#"Bearer {x}"SECRET_TAIL""#, "Bearer [REDACTED]"),
        ("Bearer {x}SECRET_TAIL", "Bearer [REDACTED]"),
        ("Bearer [a]SECRET", "Bearer [REDACTED]"),
        ("Bearer $'SECRET'", "Bearer [REDACTED]"),
        ("Bearer $\"SECRET\"", "Bearer [REDACTED]"),
        (r#"Bearer \"SUPER_SECRET_TOKEN"#, "Bearer [REDACTED]"),
        (
            r#"{"msg":"Bearer \"eyJhbGciOiJIUzI1NiJ9.TRUNCATED_SECRET"#,
            r#"{"msg":"Bearer [REDACTED]"#,
        ),
        (
            r#"failed: "expected Bearer " and "Bearer SUPER_SECRET_JWT""#,
            r#"failed: "expected Bearer " and "Bearer [REDACTED]""#,
        ),
        (
            r#"failed: \"Bearer \" and \"Bearer SUPER_SECRET_JWT\""#,
            r#"failed: \"Bearer \" and \"Bearer [REDACTED]\""#,
        ),
        (
            r#"Digest username="admin", response = "deadbeefSECRET""#,
            "Digest [REDACTED]",
        ),
        (
            r#"Digest username = "admin", response = "deadbeefcafebabe""#,
            "Digest [REDACTED]",
        ),
        (
            "Digest username*=UTF-8''admin_user, realm=\"api\", response=\"deadbeefcafebabe\"",
            "Digest [REDACTED]",
        ),
        (
            r#"Digest username=\"admin\", response=\"SECRET_TRUNCATED"#,
            "Digest [REDACTED]",
        ),
        (r#"Digest response=\"SECRET_TRUNCATED"#, "Digest [REDACTED]"),
        (
            "Bearer [unclosed\nstatus=ok\nmore=info",
            "Bearer [REDACTED]\nstatus=ok\nmore=info",
        ),
        (
            "failed: Bearer {unclosed\nstatus=ok\nexit_code=0",
            "failed: Bearer [REDACTED]\nstatus=ok\nexit_code=0",
        ),
        (
            "Bearer {sec}Token stay_visible",
            "Bearer [REDACTED] stay_visible",
        ),
        (
            "(Bearer sec1)Token stay_visible",
            "(Bearer [REDACTED])Token stay_visible",
        ),
    ];
    for (input, expected) in auth_cases {
        let r = diagnostic_projection::redact_secrets(input);
        let x = diagnostic_projection::redact_secrets_regex(input);
        let p = sanitize_persisted_lifecycle_text(input);
        assert_eq!(r, expected, "redact_secrets: {input:?}");
        assert_eq!(x, expected, "redact_secrets_regex: {input:?}");
        assert_eq!(p, expected, "sanitize_persisted_lifecycle_text: {input:?}");
        assert_eq!(diagnostic_projection::redact_secrets(&r), r);
        assert_eq!(diagnostic_projection::redact_secrets_regex(&x), x);
        assert_eq!(sanitize_persisted_lifecycle_text(&p), p);
    }

    // 5. Escaped headers at end of JSON strings, inner escaped JSON/URLs, and JSON arrays.
    let end_of_json = r#"{"cmd":"curl https://example.invalid -H \"Cookie: sid=SECRET\"","exit_code":1,"stage":"install"}"#;
    let end_expected = r#"{"cmd":"curl https://example.invalid -H \"Cookie: [REDACTED]\"","exit_code":1,"stage":"install"}"#;
    assert_eq!(sanitize_persisted_lifecycle_text(end_of_json), end_expected);
    assert_eq!(
        diagnostic_projection::redact_secrets(end_of_json),
        end_expected
    );
    serde_json::from_str::<serde_json::Value>(&sanitize_persisted_lifecycle_text(end_of_json))
        .unwrap();

    let double_encoded = r#"{"payload":"{\"cmd\":\"curl https://example.invalid -H \\\"Cookie: sid=SECRET\\\"\",\"ok\":true}"}"#;
    let double_expected = r#"{"payload":"{\"cmd\":\"curl https://example.invalid -H \\\"Cookie: [REDACTED]\\\"\",\"ok\":true}"}"#;
    assert_eq!(
        sanitize_persisted_lifecycle_text(double_encoded),
        double_expected
    );
    assert_eq!(
        diagnostic_projection::redact_secrets(double_encoded),
        double_expected
    );

    for header_leak_case in [
        r#"curl -H \"Cookie: prefs={\"theme\":\"dark\"}, sid=SECRET_COOKIE\" https://example.invalid"#,
        r#"curl -H \"Cookie: list=[\"a\"], sid=SECRET_COOKIE\" https://example.invalid"#,
        r#"curl -H \"Cookie: a=\"1\", \"b\"=\"SECRET_COOKIE\"\" https://example.invalid"#,
        r#"curl -H \"Cookie: next=\"https://example.invalid\", sid=SECRET_COOKIE\" https://api.invalid"#,
        r#"curl -H \"Cookie: ref="https://example.com", sid=SECRET_COOKIE\" localhost:8080"#,
        r#"curl -H \\"Cookie: ref=\"https://example.com\", sid=\"SECRET_COOKIE\"\\" localhost:8080"#,
    ] {
        let p = sanitize_persisted_lifecycle_text(header_leak_case);
        let r = diagnostic_projection::redact_secrets(header_leak_case);
        assert!(
            !p.contains("SECRET_COOKIE"),
            "persisted leaked: {header_leak_case} -> {p}"
        );
        assert!(
            !r.contains("SECRET_COOKIE"),
            "projected leaked: {header_leak_case} -> {r}"
        );
    }

    let json_arr =
        r#"["curl -H \"Cookie: sid=SECRET_COOKIE\" localhost:8080", "https://example.com", 17]"#;
    let json_arr_p = sanitize_persisted_lifecycle_text(json_arr);
    assert!(!json_arr_p.contains("SECRET_COOKIE"), "{json_arr_p}");
    serde_json::from_str::<serde_json::Value>(&json_arr_p)
        .unwrap_or_else(|err| panic!("broken JSON array ({err}): {json_arr_p}"));

    // 6. is_complete_redacted_header must agree with is_header_quote_terminator on bare header commas,
    // reject closed-quote keys, and enforce escape_depth on closing backslashes.
    assert!(!is_complete_redacted_header(
        r#"\"Cookie: "#,
        r#"[REDACTED]", sid=SECRET\""#
    ));
    assert!(!is_complete_redacted_header(
        "\"Cookie\": ",
        r#"[REDACTED]\" --verbose SECRET""#
    ));
    assert!(!is_complete_redacted_header(
        "\"Cookie: ",
        r#"[REDACTED]\" --verbose SECRET""#
    ));
    assert!(!is_complete_redacted_header(
        "\"Authorization\": ",
        r#"[REDACTED]" --flag SECRET_TAIL""#
    ));
}

#[test]
fn test_wave1a_r3_audit_regressions_quotestack_headers_ansi_c_digest_and_containers() {
    // 1. QuoteStack even-backslash strings (`C:\\`), plural/non-ASCII apostrophes, and stray escaped quotes.
    for (input, secret) in [
        (r#"{"path":"C:\\"} Bearer "SUPER_SECRET""#, "SUPER_SECRET"),
        (
            r#"{"path":"C:\\","msg":"expected Bearer ","api_key": "SUPER_SECRET_KEY"}"#,
            "SUPER_SECRET_KEY",
        ),
        (
            r#"{"a": "foo\\", "b": "got Bearer SECRET1", "c": "Bearer SECRET2"}"#,
            "SECRET2",
        ),
        (
            r#"path="C:\\" msg="expected Bearer " hdr="Bearer SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"{"path": "C:\\dir\\"} Digest username="admin", response="SUPER_SECRET_HEX""#,
            "SUPER_SECRET_HEX",
        ),
        (
            r#"{"msg": "users' auth failed: Bearer 'SUPER_SECRET'"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"café's auth failed: Bearer 'SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            r#"users' error: Bearer 'SUPER_SECRET_TOKEN'"#,
            "SUPER_SECRET_TOKEN",
        ),
        (
            r#"users' request failed: 'expected Bearer ' and 'Bearer SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            r#"café's request failed: 'expected Bearer ' and 'Bearer SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "users' Digest username='admin', response='SECRET_HEX'"}"#,
            "SECRET_HEX",
        ),
        (
            r#"msg: unexpected \" near Bearer \"SUPER_SECRET_TOKEN\""#,
            "SUPER_SECRET_TOKEN",
        ),
    ] {
        for out in [
            sanitize_persisted_lifecycle_text(input),
            diagnostic_projection::redact_secrets(input),
            diagnostic_projection::redact_secrets_regex(input),
        ] {
            assert!(
                !out.contains(secret),
                "leaked {secret} in {input:?} -> {out:?}"
            );
            assert!(
                !out.contains("SECRET1"),
                "leaked SECRET1 in {input:?} -> {out:?}"
            );
        }
    }
    let benign_bs_json = r#"{"path":"C:\\","msg":"expected Bearer ", "ok": true}"#;
    assert_eq!(
        sanitize_persisted_lifecycle_text(benign_bs_json),
        benign_bs_json
    );
    assert_eq!(
        diagnostic_projection::redact_secrets(benign_bs_json),
        benign_bs_json
    );
    assert_eq!(
        diagnostic_projection::redact_secrets_regex(benign_bs_json),
        benign_bs_json
    );
    let bs_valid_json =
        r#"{"path": "C:\\", "msg": "expected Bearer ", "hdr": "Bearer SUPER_SECRET"}"#;
    let bs_p = sanitize_persisted_lifecycle_text(bs_valid_json);
    assert_eq!(
        bs_p,
        r#"{"path": "C:\\", "msg": "expected Bearer ", "hdr": "Bearer [REDACTED]"}"#
    );
    serde_json::from_str::<serde_json::Value>(&bs_p).unwrap();

    // 2. Same-line `token Bearer <jwt>` / `token Basic <b64>` / `token Digest ...` prefix collisions.
    for (input, expected) in [
        (
            "invalid token Bearer eyJhbGciOiJIUzI1NiJ9.SUPER_SECRET",
            "invalid token Bearer [REDACTED]",
        ),
        (
            "invalid token Basic dXNlcjpwYXNz",
            "invalid token Basic [REDACTED]",
        ),
        (
            r#"auth token Digest username="admin", response="SUPER_SECRET_HEX""#,
            "auth token Digest [REDACTED]",
        ),
        (
            "invalid token\t\tBearer SUPER_SECRET",
            "invalid token\t\tBearer [REDACTED]",
        ),
    ] {
        for out in [
            sanitize_persisted_lifecycle_text(input),
            diagnostic_projection::redact_secrets(input),
            diagnostic_projection::redact_secrets_regex(input),
        ] {
            assert_eq!(out, expected, "same-line auth collision for {input:?}");
        }
        assert_eq!(sanitize_persisted_lifecycle_text(expected), expected);
        assert_eq!(diagnostic_projection::redact_secrets(expected), expected);
        assert_eq!(
            diagnostic_projection::redact_secrets_regex(expected),
            expected
        );
    }

    // 3. Escaped HTTP headers: multi-entry inner JSON containers, non-JSON comma followers,
    // higher-depth partial fallback, and unmatched `{` inside JSON-ending headers.
    for (input, secret) in [
        (
            r#"curl -H \"Cookie: list=[\"a\", \"SECRET_COOKIE\"]\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"X-Api-Key: {\"a\":\"1\", \"b\":\"SECRET_KEY\"}\" https://example.invalid"#,
            "SECRET_KEY",
        ),
        (
            r#"curl -H \"Cookie: prefs={\"theme\":\"dark\",\"v\":\"1\"}, sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"{"log": "curl -H \\\"Cookie: list=[\\\"a\\\",\\\"SECRET_COOKIE\\\"]\\\" https://example.invalid"}"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", 2fa_sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", true_sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", false_sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", null_sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", {\"sid\":\"SECRET_COOKIE\"}\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Authorization: Digest username=\"admin\", 2fa=1, response=\"SECRET_HEX\"\" https://example.invalid"#,
            "SECRET_HEX",
        ),
        (
            r#"curl -H \\"Cookie: a="1" https://example.com; sid=\"SECRET_LEAK\" --verbose"#,
            "SECRET_LEAK",
        ),
    ] {
        for out in [
            sanitize_persisted_lifecycle_text(input),
            diagnostic_projection::redact_secrets(input),
            diagnostic_projection::redact_secrets_regex(input),
        ] {
            assert!(
                !out.contains(secret),
                "header leak {secret} for {input:?} -> {out:?}"
            );
        }
    }
    let unmatched_brace_hdr = r#"{"exit_code": 1, "cmd": "curl -H \"X-Api-Key: my{SECRET\""}"#;
    let ub_p = sanitize_persisted_lifecycle_text(unmatched_brace_hdr);
    let ub_r = diagnostic_projection::redact_secrets(unmatched_brace_hdr);
    assert!(!ub_p.contains("SECRET") && !ub_r.contains("SECRET"));
    serde_json::from_str::<serde_json::Value>(&ub_p)
        .unwrap_or_else(|e| panic!("broken JSON ({e}): {ub_p}"));
    serde_json::from_str::<serde_json::Value>(&ub_r)
        .unwrap_or_else(|e| panic!("broken JSON ({e}): {ub_r}"));

    // 4. Context-aware ANSI-C quote opener: no false positives on `$`-ending passwords and
    // no false negatives on delimiter-leading ANSI-C secrets across all pipelines.
    for (input, secret) in [
        (
            r#"err="password=hunter2$" and "api_key": "SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"err="password=hunter2$"; "api_key": "SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"err="password=hunter2$", rc=1, "api_key": "SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"note="password=myP@ss$" msg="pass: SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"note="password=myP@ss$" hdr="Bearer SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"["password=hunter2$", 1, "Bearer SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (
            r#"["password=hunter2$", 1, "pass: SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl --password $',\nSECRET_TAIL' --verbose"#,
            "SECRET_TAIL",
        ),
        (
            r#"curl --password $',\tSUPER_SECRET' --verbose"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl --password $',{SECRET_TAIL}' --verbose"#,
            "SECRET_TAIL",
        ),
        (
            r#"curl --password $'} SECRET_TAIL' --verbose"#,
            "SECRET_TAIL",
        ),
        (
            r#"curl --password $'],SECRET_TAIL' --verbose"#,
            "SECRET_TAIL",
        ),
        (
            r#"curl --password $', "SECRET_TAIL"' --verbose"#,
            "SECRET_TAIL",
        ),
        (
            r#"curl -u admin:$':123SUPER_SECRET' https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd":"curl --password $\",\nSECRET_TAIL\" --verbose"}"#,
            "SECRET_TAIL",
        ),
        (
            r#"{"cmd":"curl --password $\",\tSUPER_SECRET\" --verbose"}"#,
            "SUPER_SECRET",
        ),
    ] {
        for out in [
            sanitize_persisted_lifecycle_text(input),
            diagnostic_projection::redact_secrets(input),
        ] {
            assert!(
                !out.contains(secret),
                "ANSI-C leak {secret} for {input:?} -> {out:?}"
            );
            assert!(
                !out.contains("hunter2"),
                "leaked hunter2 in {input:?} -> {out:?}"
            );
        }
    }
    for valid_json in [
        r#"["password=hunter2$", 1, "ok"]"#,
        r#"["password=hunter2$", 123, "ok"]"#,
        r#"{"password=$": "val"}"#,
        r#"{"cmd":"curl --password $\",\nSECRET_TAIL\" --verbose"}"#,
        r#"{"cmd":"curl --password $\",\tSUPER_SECRET\" --verbose"}"#,
    ] {
        let p = sanitize_persisted_lifecycle_text(valid_json);
        let r = diagnostic_projection::redact_secrets(valid_json);
        serde_json::from_str::<serde_json::Value>(&p)
            .unwrap_or_else(|e| panic!("persisted broke JSON ({e}) for {valid_json}: {p}"));
        serde_json::from_str::<serde_json::Value>(&r)
            .unwrap_or_else(|e| panic!("projected broke JSON ({e}) for {valid_json}: {r}"));
    }

    // 5. Unquoted Bearer/Digest values on closed-quote/KV/CLI keys + balanced delegation.
    for (input, expected) in [
        (
            "{'Authorization': Bearer SUPER_SECRET}",
            "{'Authorization': Bearer [REDACTED]}",
        ),
        (
            "auth_token: Bearer SUPER_SECRET",
            "auth_token: Bearer [REDACTED]",
        ),
        ("token=Bearer SUPER_SECRET_JWT", "token=Bearer [REDACTED]"),
        (
            r#"my_token: Digest username="admin", response="SECRET_HEX""#,
            "my_token: Digest [REDACTED]",
        ),
        (
            "curl --token Bearer SUPER_SECRET",
            "curl --token Bearer [REDACTED]",
        ),
    ] {
        assert_eq!(
            sanitize_persisted_lifecycle_text(input),
            expected,
            "persisted: {input}"
        );
        assert_eq!(
            diagnostic_projection::redact_secrets(input),
            expected,
            "projected: {input}"
        );
        assert_eq!(
            diagnostic_projection::redact_secrets_regex(input),
            expected,
            "regex: {input}"
        );
    }
    assert_eq!(
        diagnostic_projection::redact_balanced_structured_secrets(
            r#"token=Digest username="admin", response="SUPER_SECRET_HEX""#
        ),
        "token=Digest [REDACTED]"
    );

    // 6. Escaped-quote enclosing_delim, RFC 7616/7235 Digest, glued Digest tails, embedded `\"`.
    for (input, expected) in [
        (
            r#"log: \"Digest username="admin", response="SECRET_HEX"\""#,
            r#"log: \"Digest [REDACTED]\""#,
        ),
        (
            r#"log: \"Bearer "SECRET_TOKEN"\""#,
            r#"log: \"Bearer [REDACTED]\""#,
        ),
        (
            r#"'Digest username*=UTF-8\'\'admin_user, realm="api", response="SECRET_HEX"'"#,
            "'Digest [REDACTED]'",
        ),
        (
            r#"Digest realm="api", , response="SECRET_HEX""#,
            "Digest [REDACTED]",
        ),
        (
            r#"Digest realm="api", opaque=, response="SECRET_HEX""#,
            "Digest [REDACTED]",
        ),
        (
            r#"Digest username="admin", response=a"SECRET""#,
            "Digest [REDACTED]",
        ),
        (r#"Digest username="admin"SECRET_TAIL"#, "Digest [REDACTED]"),
        (
            r#"Bearer [REDACTED]\"SUPER_SECRET_TAIL"#,
            "Bearer [REDACTED]",
        ),
        (r#"Basic admin:p\"SUPER_SECRET"#, "Basic [REDACTED]"),
    ] {
        assert_eq!(
            sanitize_persisted_lifecycle_text(input),
            expected,
            "persisted: {input}"
        );
        assert_eq!(
            diagnostic_projection::redact_secrets(input),
            expected,
            "projected: {input}"
        );
        assert_eq!(
            diagnostic_projection::redact_secrets_regex(input),
            expected,
            "regex: {input}"
        );
    }
    for (json_input, expected_persisted, expected_projected) in [
        (
            r#"{"msg": "Basic admin:p\"ssword"}"#,
            r#"{"msg": "Basic [REDACTED]"}"#,
            r#"{"msg":"Basic [REDACTED]"}"#,
        ),
        (
            r#"{"note": "failed with Bearer part1\"SUPER_SECRET"}"#,
            r#"{"note": "failed with Bearer [REDACTED]"}"#,
            r#"{"note":"failed with Bearer [REDACTED]"}"#,
        ),
    ] {
        assert_eq!(
            sanitize_persisted_lifecycle_text(json_input),
            expected_persisted
        );
        assert_eq!(
            diagnostic_projection::redact_secrets(json_input),
            expected_projected
        );
        assert_eq!(
            diagnostic_projection::redact_secrets_regex(json_input),
            expected_persisted
        );
    }

    // 7. JSON-escaped containers & unclosed inner quotes preserve valid JSON and prevent adjacent leaks.
    for valid_json in [
        r#"{"msg": "Bearer {\"a\":\"b\"}", "ok": true}"#,
        r#"{"outer": {"cmd": "Bearer {\"a\":\"SUPER_SECRET\"}"}, "note": "ok"}"#,
        r#"{"cmd": "curl --password {\"a\":\"SUPER_SECRET\"} --verbose", "exit_code": 1}"#,
        r#"{"cmd": "curl --password {\"a\":\"val with } brace\"} --verbose", "exit_code": 1}"#,
        r#"{"msg": "Bearer {unclosed", "api_key": "} SUPER_SECRET"}"#,
        r#"{"msg": "Bearer 'TRUNCATED", "api_key": "a' SUPER_SECRET"}"#,
        r#"{"err": "Bearer tok'1", "status": 401}"#,
        r#"{"msg": "Bearer 'unclosed", "ok": true}"#,
    ] {
        let p = sanitize_persisted_lifecycle_text(valid_json);
        let r = diagnostic_projection::redact_secrets(valid_json);
        assert!(!p.contains("SUPER_SECRET") && !r.contains("SUPER_SECRET"));
        assert!(!p.contains("brace") && !r.contains("brace"));
        if !p.contains(":[REDACTED]") && !p.contains(": [REDACTED]") {
            serde_json::from_str::<serde_json::Value>(&p)
                .unwrap_or_else(|e| panic!("persisted broke JSON ({e}) for {valid_json}: {p}"));
        }
        serde_json::from_str::<serde_json::Value>(&r)
            .unwrap_or_else(|e| panic!("projected broke JSON ({e}) for {valid_json}: {r}"));
    }

    // 8. Glued [REDACTED_URL], lowercase [REDACTED_url], closed-quote header keys, and regex escaped keys.
    assert_eq!(
        sanitize_persisted_lifecycle_text("curl --password [REDACTED_URL]SECRET_TAIL"),
        "curl --password [REDACTED]"
    );
    assert_eq!(
        diagnostic_projection::redact_secrets("curl --password [REDACTED_URL]SECRET_TAIL"),
        "curl --password [REDACTED]"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("webhook_url=[REDACTED_url]"),
        "webhook_url=[REDACTED_url]"
    );
    assert_eq!(
        diagnostic_projection::redact_secrets("webhook_url=[REDACTED_url]"),
        "webhook_url=[REDACTED_url]"
    );
    for glued_hdr in [
        r#"{"Authorization": [REDACTED]" --flag SECRET_TAIL"}"#,
        r#"{"Authorization": [REDACTED]"}SECRET_TAIL"}"#,
        r#""Cookie": [REDACTED]\" --verbose SECRET_TAIL""#,
    ] {
        assert!(!sanitize_persisted_lifecycle_text(glued_hdr).contains("SECRET_TAIL"));
        assert!(!diagnostic_projection::redact_secrets(glued_hdr).contains("SECRET_TAIL"));
    }
    let escaped_auth_json = r#"{\"Authorization\": \"SUPER_SECRET\"}"#;
    assert!(
        !diagnostic_projection::redact_secrets_regex(escaped_auth_json).contains("SUPER_SECRET")
    );
    assert!(!diagnostic_projection::redact_secrets(escaped_auth_json).contains("SUPER_SECRET"));
}

#[test]
fn test_wave1a_r4_audit_regressions_parity_escaped_quotes_headers_containers_and_linear_time() {
    // 1. Overflow-safe helper boundary checks (`usize::MAX`).
    assert!(quote_closes_enclosing(b"a\"bc", usize::MAX));
    assert!(!has_matching_secret_quote(b"\"", usize::MAX, 0));
    assert!(is_ansi_c_quote_opener(b"$", usize::MAX).is_none());

    // 2. Empty assignments, empty CLI flags, and even-backslash trailing values inside JSON/quoted strings.
    for (input, secret, expect_valid_json) in [
        (
            r#"{"stage": "password=", "api_key": "SUPER_SECRET"}"#,
            Some("SUPER_SECRET"),
            true,
        ),
        (
            r#"{"cmd": "curl --password ", "api_key": "SUPER_SECRET"}"#,
            Some("SUPER_SECRET"),
            true,
        ),
        (r#"{"flag": "-u", "ok": true}"#, None, true),
        (
            r#"{"args": ["-u", "Bearer SUPER_SECRET"]}"#,
            Some("SUPER_SECRET"),
            true,
        ),
        (
            r#"{"log": "args: \"--password \", \"password: SUPER_SECRET\""}"#,
            Some("SUPER_SECRET"),
            true,
        ),
        (r#"{"stage": "password=\\", "ok": true}"#, None, true),
        (
            r#"a="password=\\" api_key=" SUPER_SECRET""#,
            Some("SUPER_SECRET"),
            false,
        ),
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(input)),
            ("projected", diagnostic_projection::redact_secrets(input)),
            ("regex", diagnostic_projection::redact_secrets_regex(input)),
        ] {
            if let Some(sec) = secret {
                assert!(
                    !out.contains(sec),
                    "{label} leaked {sec} for {input:?} -> {out:?}"
                );
            }
            if expect_valid_json && !out.contains(":[REDACTED]") && !out.contains(": [REDACTED]") {
                serde_json::from_str::<serde_json::Value>(&out)
                    .unwrap_or_else(|e| panic!("{label} broke JSON ({e}) for {input:?}: {out}"));
            }
            assert_eq!(
                match label {
                    "persisted" => sanitize_persisted_lifecycle_text(&out),
                    "projected" => diagnostic_projection::redact_secrets(&out),
                    _ => diagnostic_projection::redact_secrets_regex(&out),
                },
                out,
                "{label} not 1-step idempotent for {input:?} -> {out:?}"
            );
        }
    }

    // 3. `enclosing_delim` with `\"` inside `'...'`, inner `\\\"` inside `\"...\"`, and partial inner quotes.
    for (input, secret) in [
        (r#"{"msg": "Bearer 'foo\" SECRET_TAIL'"}"#, "SECRET_TAIL"),
        (
            r#"{"msg": "Digest username='foo\" SECRET_TAIL', response='SECRET_HEX'"}"#,
            "SECRET_HEX",
        ),
        (
            r#"{"cmd": "curl --password=\"foo\\\" SECRET_TAIL\" https://example.invalid"}"#,
            "SECRET_TAIL",
        ),
        (
            r#"{\"password\": \"first \\\"INNER_SECRET\\\" TAIL_SECRET\"}"#,
            "TAIL_SECRET",
        ),
        (r#"password=\"a"SECRET_TAIL\""#, "SECRET_TAIL"),
        (
            r#"log: \"cmd: password=\\\"part1 "SECRET_TAIL\\\"\""#,
            "SECRET_TAIL",
        ),
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(input)),
            ("projected", diagnostic_projection::redact_secrets(input)),
            ("regex", diagnostic_projection::redact_secrets_regex(input)),
        ] {
            assert!(
                !out.contains(secret),
                "{label} leaked {secret} for {input:?} -> {out:?}"
            );
            assert!(
                !out.contains("INNER_SECRET"),
                "{label} leaked INNER_SECRET for {input:?} -> {out:?}"
            );
            assert_eq!(
                match label {
                    "persisted" => sanitize_persisted_lifecycle_text(&out),
                    "projected" => diagnostic_projection::redact_secrets(&out),
                    _ => diagnostic_projection::redact_secrets_regex(&out),
                },
                out,
                "{label} not 1-step idempotent for {input:?} -> {out:?}"
            );
        }
    }

    // 4. Stray quotes, apostrophes, and remaining-quote parity before whitespace-leading secrets.
    for (input, secret) in [
        (
            r#"{"stderr": "syntax error near \": Bearer \" SUPER_SECRET\""}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"stderr": "syntax error near \": curl --password prefix\" SUPER_SECRET\" --verbose"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"err: " {"a": "expected Bearer ", "b": "Bearer SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"err: unexpected \" in msg="expected Bearer " hdr="Bearer SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"note: users\' error; msg='expected Bearer ' hdr='Bearer SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            r#"err: unexpected \" in note="password=myP@ss$" api_key=" SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"cmd='echo a'x msg='expected Bearer ' hdr='Bearer SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            r#"error: expected ' near Bearer ' SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            r#"error: expected ' near Bearer ' secret_pass' --verbose"#,
            "secret_pass",
        ),
        (
            r#"doin' auth failed: Bearer ' SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (r#""foo"Bearer " SUPER_SECRET""#, "SUPER_SECRET"),
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(input)),
            ("projected", diagnostic_projection::redact_secrets(input)),
            ("regex", diagnostic_projection::redact_secrets_regex(input)),
        ] {
            assert!(
                !out.contains(secret),
                "{label} leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                match label {
                    "persisted" => sanitize_persisted_lifecycle_text(&out),
                    "projected" => diagnostic_projection::redact_secrets(&out),
                    _ => diagnostic_projection::redact_secrets_regex(&out),
                },
                out,
                "{label} not 1-step idempotent for {input:?} -> {out:?}"
            );
        }
    }

    // 5. Escaped HTTP headers: quoted `}`/`]` inside containers, comma lists, literals/objects,
    // glued `[REDACTED]` header tails, unmatched `{` inside JSON/CLI, even-backslash values, and
    // mixed-depth `\\"` Digest headers.
    for (input, secret) in [
        (
            r#"curl -H \"X-Api-Key: {\"a\":\"foo}\", \"b\":\"SECRET_KEY\"}\" https://example.invalid"#,
            "SECRET_KEY",
        ),
        (
            r#"curl -H \"Cookie: list=[\"a]\", \"SECRET_COOKIE\"]\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Authorization: Custom \"a\", \"b\", \"SECRET_TOKEN\"\" https://example.invalid"#,
            "SECRET_TOKEN",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", 123, sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", true, sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", {\"b\":1}, sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: [REDACTED]" --verbose SECRET_TAIL\" localhost:8080"#,
            "SECRET_TAIL",
        ),
        (
            r#"{"cmd": "curl -H \"Cookie: sid=my{SECRET\" ", "ok": true}"#,
            "SECRET",
        ),
        (
            r#"{"cmd": "curl -H \"X-Api-Key: my{SECRET\" localhost:8080", "other": 1}"#,
            "SECRET",
        ),
        (
            r#"curl -H \\"Authorization: Digest username=\"admin\", response=\"SECRET\"\" --verbose"#,
            "SECRET",
        ),
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(input)),
            ("projected", diagnostic_projection::redact_secrets(input)),
            ("regex", diagnostic_projection::redact_secrets_regex(input)),
        ] {
            assert!(
                !out.contains(secret),
                "{label} leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                match label {
                    "persisted" => sanitize_persisted_lifecycle_text(&out),
                    "projected" => diagnostic_projection::redact_secrets(&out),
                    _ => diagnostic_projection::redact_secrets_regex(&out),
                },
                out,
                "{label} not 1-step idempotent for {input:?} -> {out:?}"
            );
        }
    }
    for valid_header_json in [
        r#"{"cmd": "curl -H \"Cookie: sid=my{SECRET\" ", "ok": true}"#,
        r#"{"cmd": "curl -H \"X-Api-Key: my{SECRET\" localhost:8080", "other": 1}"#,
        r#"{"log": "{\"hdr\":\"X-Api-Key: abc\\\\\", \"ok\": true}"}"#,
    ] {
        let p = sanitize_persisted_lifecycle_text(valid_header_json);
        let r = diagnostic_projection::redact_secrets(valid_header_json);
        assert!(!p.contains("SECRET") && !r.contains("SECRET"));
        assert!(!p.contains("abc") && !r.contains("abc"));
        serde_json::from_str::<serde_json::Value>(&p)
            .unwrap_or_else(|e| panic!("persisted broke JSON ({e}): {p}"));
        serde_json::from_str::<serde_json::Value>(&r)
            .unwrap_or_else(|e| panic!("projected broke JSON ({e}): {r}"));
    }
    assert_eq!(
        sanitize_persisted_lifecycle_text(
            r#"curl -H \"Cookie: sid=abc\\\\\" https://example.invalid"#
        ),
        r#"curl -H \"Cookie: [REDACTED]\" https://example.invalid"#
    );

    // 6. Nested containers, mismatched `{{]`, multiline quoted containers, and `redact_secrets_regex` parity.
    for (input, secret, expect_json) in [
        (
            r#"{"msg": "password={unclosed", "api_key": "} SUPER_SECRET"}"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"msg": "password={{]", "api_key": "} SUPER_SECRET"}"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"log="password={unclosed" api_key="} SUPER_SECRET""#,
            "SUPER_SECRET",
            false,
        ),
        (
            r#"log="password={unclosed" msg="Bearer }SUPER_SECRET""#,
            "SUPER_SECRET",
            false,
        ),
        (
            "log=\"password={unclosed\n\" api_key=\"} SUPER_SECRET\"",
            "SUPER_SECRET",
            false,
        ),
        (
            "log=\"password={unclosed\n\" msg=\"Bearer }SUPER_SECRET\"",
            "SUPER_SECRET",
            false,
        ),
        (
            r#"{"cmd": "curl --password={\"a\":\"SECRET\"} --verbose", "exit_code": 1}"#,
            "SECRET",
            true,
        ),
        (
            r#"{"password": {"a": "}", "b": "SUPER_SECRET"}}"#,
            "SUPER_SECRET",
            true,
        ),
        (r#"{'password': 'SUPER SECRET'}"#, "SUPER SECRET", false),
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(input)),
            ("projected", diagnostic_projection::redact_secrets(input)),
            ("regex", diagnostic_projection::redact_secrets_regex(input)),
        ] {
            assert!(
                !out.contains(secret),
                "{label} leaked {secret} for {input:?} -> {out:?}"
            );
            if expect_json && !out.contains(":[REDACTED]") && !out.contains(": [REDACTED]") {
                serde_json::from_str::<serde_json::Value>(&out)
                    .unwrap_or_else(|e| panic!("{label} broke JSON ({e}) for {input:?}: {out}"));
            }
            assert_eq!(
                match label {
                    "persisted" => sanitize_persisted_lifecycle_text(&out),
                    "projected" => diagnostic_projection::redact_secrets(&out),
                    _ => diagnostic_projection::redact_secrets_regex(&out),
                },
                out,
                "{label} not 1-step idempotent for {input:?} -> {out:?}"
            );
        }
    }

    // 7. RFC 7616/7235 Digest (`UTF-8''`, empty `""`, `[REDACTED]` continuation), `curl --user Bearer`,
    // and `[REDACTED_URL]` parity.
    for (input, expected) in [
        (
            r#"'Digest username*=UTF-8''admin_user, realm="api", response="SECRET_HEX"'"#,
            "'Digest [REDACTED]'",
        ),
        (
            r#"msg="Digest realm=\"\", response=\"SECRET_HEX\"""#,
            r#"msg="Digest [REDACTED]""#,
        ),
        (
            r#"Digest [REDACTED], response="SUPER_SECRET_HEX""#,
            "Digest [REDACTED]",
        ),
        (
            "curl --user Bearer SUPER_SECRET",
            "curl --user Bearer [REDACTED]",
        ),
        ("password=[REDACTED_URL],SECRET_TAIL", "password=[REDACTED]"),
        ("(Bearer [REDACTED_URL])", "(Bearer [REDACTED_URL])"),
        ("webhook_url=[REDACTED_Url]", "webhook_url=[REDACTED_Url]"),
        (
            "failed on --url=https://example.com",
            "failed on --url=https://example.com",
        ),
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(input)),
            ("projected", diagnostic_projection::redact_secrets(input)),
            ("regex", diagnostic_projection::redact_secrets_regex(input)),
        ] {
            assert_eq!(out, expected, "{label} mismatch for {input:?}");
            assert_eq!(
                match label {
                    "persisted" => sanitize_persisted_lifecycle_text(&out),
                    "projected" => diagnostic_projection::redact_secrets(&out),
                    _ => diagnostic_projection::redact_secrets_regex(&out),
                },
                out,
                "{label} idempotency failed for {input:?}"
            );
        }
    }
    let escaped_url_note = r#"{"note":"webhook_url=[REDACTED_URL]\" https://example.invalid"}"#;
    assert_eq!(
        sanitize_persisted_lifecycle_text(escaped_url_note),
        escaped_url_note
    );
    assert_eq!(
        diagnostic_projection::redact_secrets_regex(escaped_url_note),
        escaped_url_note
    );
    let escaped_url_proj = diagnostic_projection::redact_secrets(escaped_url_note);
    serde_json::from_str::<serde_json::Value>(&escaped_url_proj).unwrap();
    assert_eq!(
        diagnostic_projection::redact_secrets(&escaped_url_proj),
        escaped_url_proj
    );

    // 8. Strictly linear-time O(N) scaling against adversarial repeated headers (including
    // escape_depth > 15), repeated inner escaped quotes, repeated curl flags, and unclosed containers.
    let repeated_headers = format!("curl{}", " -H \"Cookie: sid=123\"".repeat(3_000));
    let repeated_partial = r#"\\"Cookie: x" -a "#.repeat(3_000);
    let repeated_deep_escape = format!("{}\"Cookie: x\\\" -a ", "\\".repeat(16)).repeat(2_000);
    let repeated_inner_escaped = format!(r#"password=\\\"{}\\\""#, r#"\" "#.repeat(4_000));
    let repeated_curl_attached = "curl\"-u1;".repeat(3_000);
    let repeated_bare_u = "-ua".repeat(3_000);
    let repeated_dollar_u = " -u$a{".repeat(3_000);
    let repeated_url_u = " -u[REDACTED_URL]{".repeat(3_000);
    let repeated_unclosed = format!("{}\n", "password={".repeat(3_000));
    let repeated_prefixed_unclosed = format!("{}\n", "password=a{ ".repeat(3_000));

    let started = std::time::Instant::now();
    for payload in [
        &repeated_headers,
        &repeated_partial,
        &repeated_deep_escape,
        &repeated_inner_escaped,
        &repeated_curl_attached,
        &repeated_bare_u,
        &repeated_dollar_u,
        &repeated_url_u,
        &repeated_unclosed,
        &repeated_prefixed_unclosed,
    ] {
        let p = sanitize_persisted_lifecycle_text(payload);
        let r = diagnostic_projection::redact_secrets(payload);
        let x = diagnostic_projection::redact_secrets_regex(payload);
        assert!(!p.is_empty() && !r.is_empty() && !x.is_empty());
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(5),
        "redaction pipelines exceeded linear-time budget: {elapsed:?}"
    );
}

#[test]
fn test_wave1a_r5_audit_regressions_multiline_headers_quotes_urls_digest_curl_json_and_idempotency()
{
    // 1. Multiline / obs-fold HTTP headers must never leak across any entry point.
    for (input, secret) in [
        ("X-Api-Key:\n  SUPER_SECRET_KEY", "SUPER_SECRET_KEY"),
        ("X-Api-Key: \nSUPER_SECRET_KEY", "SUPER_SECRET_KEY"),
        ("X-Api-Key:\r\n\tSUPER_SECRET_KEY", "SUPER_SECRET_KEY"),
        (
            "Cookie:\n  a=1; sid=SUPER_SECRET_COOKIE",
            "SUPER_SECRET_COOKIE",
        ),
        (
            "Set-Cookie:\n  sid=SUPER_SECRET_COOKIE",
            "SUPER_SECRET_COOKIE",
        ),
        ("X-Auth-Token:\n  SUPER_SECRET_TOK", "SUPER_SECRET_TOK"),
        ("Authorization:\n  Custom SUPER_SECRET", "SUPER_SECRET"),
        (
            "Proxy-Authorization:\n  Custom SUPER_SECRET",
            "SUPER_SECRET",
        ),
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(input)),
            ("projected", diagnostic_projection::redact_secrets(input)),
            ("regex", diagnostic_projection::redact_secrets_regex(input)),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets(input),
            ),
        ] {
            assert!(
                !out.contains(secret),
                "{label} leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                match label {
                    "persisted" => sanitize_persisted_lifecycle_text(&out),
                    "projected" => diagnostic_projection::redact_secrets(&out),
                    "regex" => diagnostic_projection::redact_secrets_regex(&out),
                    _ => diagnostic_projection::redact_balanced_structured_secrets(&out),
                },
                out,
                "{label} idempotency failed for {input:?} -> {out:?}"
            );
        }
    }

    // 2. Local quote-closing grammar (no global line-parity poisoning from trailing apostrophes,
    // truncated lines, later stray quotes, same-depth `\"`+`\'` nesting, or empty `""` in containers).
    for (input, secret) in [
        (
            r#"{"err": "'expected Bearer ' 'Bearer SUPER_SECRET' for users' session"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"log": "msg='password=' 'api_key': 'SUPER_SECRET' for users' session"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"["expected Bearer ", "Bearer SUPER_SECRET", "truncated"#,
            "SUPER_SECRET",
        ),
        (
            r#"msg="password=" "api_key": "SUPER_SECRET" note="unclosed"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"log": "stage=\"password=secret1\" api_key=\"part1 SUPER_SECRET\" err=unexpected \""}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": "env 'password=secret1' 'api_key=part1 SUPER_SECRET' && echo users'"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"stage="password=secret1" api_key="part1 SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"password": ",SECRET_TAIL", "msg": "truncated"#,
            "SECRET_TAIL",
        ),
        (r#"password=':SECRET_TAIL' note=users'"#, "SECRET_TAIL"),
        (r#"Bearer ":SECRET_TAIL" note="truncated"#, "SECRET_TAIL"),
        (
            r#"curl -u admin:":SECRET_TAIL" note="truncated"#,
            "SECRET_TAIL",
        ),
        (
            r#"{"stderr": "syntax error near \": curl --password prefix\",SECRET_TAIL\" --verbose"}"#,
            "SECRET_TAIL",
        ),
        (
            r#"{"msg": "err ': password=\"'\"' SECRET_TAIL'"}"#,
            "SECRET_TAIL",
        ),
        (
            r#"{"msg": "err \": curl --password 'a\" SECRET_TAIL' --verbose"}"#,
            "SECRET_TAIL",
        ),
        (
            r#"{"cmd": "echo \"foo \'expected Bearer \' \'Bearer SUPER_SECRET\'\""}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": "echo \"foo \'password=\' \'api_key\': \'SUPER_SECRET\'\""}"#,
            "SUPER_SECRET",
        ),
        (
            r#"error near ": password=["", "SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (
            r#"error near ": password={"k": " SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            "cmd=\"failed: password={\n  \"k\": \"\",\n  \"v\": \"SUPER_SECRET\"\n}\"",
            "SUPER_SECRET",
        ),
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(input)),
            ("projected", diagnostic_projection::redact_secrets(input)),
            ("regex", diagnostic_projection::redact_secrets_regex(input)),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets(input),
            ),
        ] {
            assert!(
                !out.contains(secret),
                "{label} leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                match label {
                    "persisted" => sanitize_persisted_lifecycle_text(&out),
                    "projected" => diagnostic_projection::redact_secrets(&out),
                    "regex" => diagnostic_projection::redact_secrets_regex(&out),
                    _ => diagnostic_projection::redact_balanced_structured_secrets(&out),
                },
                out,
                "{label} idempotency failed for {input:?} -> {out:?}"
            );
        }
    }

    // 3. Escaped/quoted HTTP headers: cross-header cache poisoning, unmatched `{`, bash quote
    // concatenation, inner same-depth `\"...\"` pairs, and adjacent key idempotency.
    for (input, secret) in [
        (
            r#"curl -H \"Cookie: a={1"}SUPER_SECRET\" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \\"Cookie: x={{1"} -H \\"Cookie: a="1"}SUPER_SECRET\\" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \\"Cookie: x{'y\" -a -H \\"Cookie: a=\"1\" -x sid=SECRET_COOKIE\\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H "X-Api-Key: "'SUPER_SECRET' https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H "X-Api-Key: ""SUPER_SECRET" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H "Cookie: a="1" sid=SECRET_COOKIE" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", \"b\":SUPER_SECRET\" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\"}SUPER_SECRET\" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \"Cookie: a=\"1\", \"k\":\"v\", sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: note=\"foo\" -x sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (
            r#"curl -H \"Cookie: ref=\"https://a.test\" https://b.test sid=SECRET_COOKIE\" https://example.invalid"#,
            "SECRET_COOKIE",
        ),
        (r#""X-Api-Key: SECRET"api_key": Cookie: SECRET2"#, "SECRET2"),
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(input)),
            ("projected", diagnostic_projection::redact_secrets(input)),
            ("regex", diagnostic_projection::redact_secrets_regex(input)),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets(input),
            ),
        ] {
            assert!(
                !out.contains(secret),
                "{label} leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                match label {
                    "persisted" => sanitize_persisted_lifecycle_text(&out),
                    "projected" => diagnostic_projection::redact_secrets(&out),
                    "regex" => diagnostic_projection::redact_secrets_regex(&out),
                    _ => diagnostic_projection::redact_balanced_structured_secrets(&out),
                },
                out,
                "{label} idempotency failed for {input:?} -> {out:?}"
            );
        }
    }

    // 4. Cross-field URL authority bridging, glued marker suffixes (`]`, `}`, `)`, `,`, unclosed `"`),
    // backtick/angle-bracket/pipe auth delimiters, Digest edge cases, greedy curl combo & ANSI-C,
    // multiline KV-prefixed auth schemes, and direct `redact_balanced_structured_secrets` / `redact_secrets_regex`.
    for (input, secret) in [
        (
            r#"["https://example.com","-uadmin:p@SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"endpoint":"https://example.com","api_key":"admin@SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            "url=https://example.com;password=admin@SUPER_SECRET",
            "SUPER_SECRET",
        ),
        ("password=[REDACTED]]SUPER_SECRET", "SUPER_SECRET"),
        ("password=[REDACTED]}SUPER_SECRET", "SUPER_SECRET"),
        ("password=[REDACTED_URL])SECRET_TAIL", "SECRET_TAIL"),
        ("Bearer [REDACTED]]SUPER_SECRET", "SUPER_SECRET"),
        ("Bearer [REDACTED])SUPER_SECRET", "SUPER_SECRET"),
        ("Bearer [REDACTED],SUPER_SECRET", "SUPER_SECRET"),
        (
            r#"password=[REDACTED]" https://internal.corp/SECRET_TOKEN"#,
            "SECRET_TOKEN",
        ),
        (
            "failed: header `Bearer eyJhbGciOiJIUzI1NiJ9.SUPER_SECRET` rejected",
            "SUPER_SECRET",
        ),
        (
            "invalid <Basic dXNlcjpwYXNz> in upstream response",
            "dXNlcjpwYXNz",
        ),
        ("stage=auth|Bearer SUPER_SECRET", "SUPER_SECRET"),
        (
            r#"Digest , username="admin", response="SUPER_SECRET_HEX""#,
            "SUPER_SECRET_HEX",
        ),
        (
            r#"Digest username="admin", x+ext=1, response="SUPER_SECRET_HEX""#,
            "SUPER_SECRET_HEX",
        ),
        (
            r#"err="header failed: Digest username="admin", response=" SECRET_HEX"""#,
            "SECRET_HEX",
        ),
        (
            r#"{"log": "err \": Digest realm=\" \", response=\"SECRET_HEX\""}"#,
            "SECRET_HEX",
        ),
        (r#""Digest x=""Bearer SUPER_SECRET""#, "SUPER_SECRET"),
        (
            "curl -suMYSECRETu: https://api.example.invalid",
            "MYSECRETu",
        ),
        (
            "curl -fuMYTOKENu123:pass https://api.example.invalid",
            "MYTOKENu",
        ),
        (
            "curl -su$'SUPER_SECRET' https://example.invalid",
            "SUPER_SECRET",
        ),
        (" -u$'SUPER_SECRET' https://example.invalid", "SUPER_SECRET"),
        (
            "curl \\\n  -u$'sk_live_SUPER_SECRET' https://api.stripe.com",
            "SUPER_SECRET",
        ),
        (
            "curl -su[REDACTED_URL]SECRET_TAIL https://example.invalid",
            "SECRET_TAIL",
        ),
        ("password=Bearer \"line1\nSUPER_SECRET\"", "SUPER_SECRET"),
        (
            "password=Token {\n  \"k\": \"SUPER_SECRET\"\n}",
            "SUPER_SECRET",
        ),
        ("Cookie: sid=SUPER_SECRET", "SUPER_SECRET"),
        (r#"{"pass\u0077ord": "SUPER_SECRET"}"#, "SUPER_SECRET"),
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(input)),
            ("projected", diagnostic_projection::redact_secrets(input)),
            ("regex", diagnostic_projection::redact_secrets_regex(input)),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets(input),
            ),
        ] {
            assert!(
                !out.contains(secret),
                "{label} leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                match label {
                    "persisted" => sanitize_persisted_lifecycle_text(&out),
                    "projected" => diagnostic_projection::redact_secrets(&out),
                    "regex" => diagnostic_projection::redact_secrets_regex(&out),
                    _ => diagnostic_projection::redact_balanced_structured_secrets(&out),
                },
                out,
                "{label} idempotency failed for {input:?} -> {out:?}"
            );
        }
    }

    // 5. Valid JSON preservation, `user=admin:secret` pair parity, 1-step idempotency, and benign preservation.
    let benign_url_email = r#"{"endpoint":"https://example.com","email":"admin@example.com"}"#;
    assert_eq!(
        sanitize_persisted_lifecycle_text(benign_url_email),
        benign_url_email
    );
    assert_eq!(
        diagnostic_projection::redact_secrets(benign_url_email),
        benign_url_email
    );
    assert_eq!(
        diagnostic_projection::redact_secrets_regex(benign_url_email),
        benign_url_email
    );

    let user_json = r#"{"user": "admin:SUPER_SECRET"}"#;
    let user_proj = diagnostic_projection::redact_secrets(user_json);
    assert!(!user_proj.contains("SUPER_SECRET"));
    serde_json::from_str::<serde_json::Value>(&user_proj)
        .unwrap_or_else(|e| panic!("redact_secrets broke user JSON ({e}): {user_proj}"));
    let user_regex = diagnostic_projection::redact_secrets_regex(user_json);
    assert!(!user_regex.contains("SUPER_SECRET"));
    serde_json::from_str::<serde_json::Value>(&user_regex)
        .unwrap_or_else(|e| panic!("redact_secrets_regex broke user JSON ({e}): {user_regex}"));
    assert!(!sanitize_persisted_lifecycle_text(user_json).contains("SUPER_SECRET"));

    let benign_sa = r#"{"user": "system:serviceaccount:default:app"}"#;
    assert_eq!(diagnostic_projection::redact_secrets(benign_sa), benign_sa);
    assert_eq!(sanitize_persisted_lifecycle_text(benign_sa), benign_sa);

    for user_case in [
        r#"cmd: user=\"admin:SUPER_SECRET\""#,
        r#"user="my user:SUPER_SECRET""#,
        r#"{"msg": "user=admin:SUPER_SECRET"}"#,
    ] {
        let p = sanitize_persisted_lifecycle_text(user_case);
        let r = diagnostic_projection::redact_secrets(user_case);
        let x = diagnostic_projection::redact_secrets_regex(user_case);
        assert!(!p.contains("SUPER_SECRET"), "persisted: {p}");
        assert!(!r.contains("SUPER_SECRET"), "projected: {r}");
        assert!(!x.contains("SUPER_SECRET"), "regex: {x}");
        if user_case.starts_with('{') {
            serde_json::from_str::<serde_json::Value>(&p).unwrap();
            serde_json::from_str::<serde_json::Value>(&r).unwrap();
            serde_json::from_str::<serde_json::Value>(&x).unwrap();
        }
    }

    // `redact_secrets` 1-step idempotency on invalid-to-valid JSON & `\u0020` decoding on pass 1.
    for idem_case in [
        r#"{"password": [REDACTED]}"#,
        r#"{"password": [REDACTED_URL]}"#,
        r#"{"password": secret, "note": "Bearer\u0020SECRET2"}"#,
        r#"curl Token Digest "password":,--user=="#,
        r#"KEY=\\"\"\"password\":}-u--user=[REDACTED_url]"#,
    ] {
        for (label, out) in [
            ("persisted", sanitize_persisted_lifecycle_text(idem_case)),
            (
                "projected",
                diagnostic_projection::redact_secrets(idem_case),
            ),
            (
                "regex",
                diagnostic_projection::redact_secrets_regex(idem_case),
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets(idem_case),
            ),
        ] {
            assert!(
                !out.contains("SECRET2"),
                "{label} pass 1 leaked SECRET2 for {idem_case:?} -> {out:?}"
            );
            let again = match label {
                "persisted" => sanitize_persisted_lifecycle_text(&out),
                "projected" => diagnostic_projection::redact_secrets(&out),
                "regex" => diagnostic_projection::redact_secrets_regex(&out),
                _ => diagnostic_projection::redact_balanced_structured_secrets(&out),
            };
            assert_eq!(
                again, out,
                "{label} failed 1-step idempotency for {idem_case:?}: pass1={out:?}, pass2={again:?}"
            );
        }
    }

    // Negative JSON numeric passwords, uppercase env comma-lists, and benign preservation.
    let neg_json = r#"{"password": -123}"#;
    let neg_p = sanitize_persisted_lifecycle_text(neg_json);
    assert_eq!(neg_p, r#"{"password": "[REDACTED]"}"#);
    serde_json::from_str::<serde_json::Value>(&neg_p).unwrap();
    assert_eq!(
        diagnostic_projection::redact_secrets_regex("MY_KEY=part1,part2"),
        "MY_KEY=[REDACTED]"
    );
    assert_eq!(
        diagnostic_projection::redact_secrets("sort_key=asc"),
        "sort_key=asc"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("author=alice"),
        "author=alice"
    );
    assert_eq!(
        diagnostic_projection::redact_secrets(r#"{"author": "alice"}"#),
        r#"{"author": "alice"}"#
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text("curl -s https://example.com; ls -ltu /opt/app"),
        "curl -s https://example.com; ls -ltu /opt/app"
    );
    assert_eq!(
        diagnostic_projection::redact_secrets("curl -s https://example.com; ls -ltu /opt/app"),
        "curl -s https://example.com; ls -ltu /opt/app"
    );
}

#[test]
fn test_wave1a_r6_audit_regressions_all_entry_points_json_validity_benign_and_linear_time() {
    // 1. Cross-entry-point leak regressions across persisted, projected, regex, balanced, and diagnostic.
    let parity_cases: &[(&str, &str, bool)] = &[
        // (input, secret, applies_to_balanced)
        // P0-1: allow_comma_list adjacent credential keys, auth schemes, and CLI flags
        ("password=foo,Bearer SUPER_SECRET", "SUPER_SECRET", true),
        ("password=foo,token: SUPER_SECRET", "SUPER_SECRET", true),
        ("password=foo,--token SUPER_SECRET", "SUPER_SECRET", true),
        ("password=foo,api_key=SUPER_SECRET", "SUPER_SECRET", true),
        (
            "curl -u admin:pass,Bearer SUPER_SECRET",
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"msg": "password=foo,Bearer SUPER_SECRET"}"#,
            "SUPER_SECRET",
            true,
        ),
        // P0-2: multi-underscore _pass / _auth / _KEY
        ("prod_db_pass=SUPER_SECRET", "SUPER_SECRET", true),
        (r#"{"prod_db_pass": "SUPER_SECRET"}"#, "SUPER_SECRET", true),
        ("prod_api_auth=SUPER_SECRET", "SUPER_SECRET", true),
        ("DB_SIGNING_KEY=SUPER_SECRET", "SUPER_SECRET", true),
        ("PROD_DB_PASS=SUPER_SECRET", "SUPER_SECRET", true),
        // P0-3 / Carbon P0-1: quote-wrapped multi-word assignments, curl, auth-scheme, truncated, colon headers
        (
            r#"curl -H "X-Api-Token: part1 SUPER_SECRET" https://example.com"#,
            "SUPER_SECRET",
            true,
        ),
        (r#"env "api_key=part1 SUPER_SECRET"#, "SUPER_SECRET", true),
        (r#"env 'api_key=part1 SUPER_SECRET"#, "SUPER_SECRET", true),
        (
            "curl '--user=admin:part1 SUPER_SECRET' https://example.invalid",
            "SUPER_SECRET",
            true,
        ),
        (
            "curl '-uadmin:part1 SUPER_SECRET' https://example.invalid",
            "SUPER_SECRET",
            true,
        ),
        (
            "env 'password=Bearer tok1 SUPER_SECRET'",
            "SUPER_SECRET",
            true,
        ),
        (
            "env 'password=basic word SUPER_SECRET'",
            "SUPER_SECRET",
            true,
        ),
        (
            "env 'password=[REDACTED] SUPER_SECRET'",
            "SUPER_SECRET",
            true,
        ),
        // P0-4: QuoteStack parity inversion (shell quote concat + stray quotes)
        (
            "cmd=foo'bar=' msg='expected Bearer ' hdr='Bearer SUPER_SECRET'",
            "SUPER_SECRET",
            true,
        ),
        (
            r#"err: " msg="expected Bearer " hdr="Bearer SUPER_SECRET""#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"msg": "err: \" msg=\"expected Bearer \" hdr=\"Bearer SUPER_SECRET\""}"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"err: " msg="password=" hdr="Bearer SUPER_SECRET""#,
            "SUPER_SECRET",
            true,
        ),
        // Team 8 P0-2 / Neon P1-5: colon/space-leading quoted secrets under stray quotes
        (
            r#"error near ": password=":SUPER_SECRET""#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"error near ": password={"k": ":x", "v": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"error near ": Digest username="admin", response=":SUPER_SECRET_HEX""#,
            "SUPER_SECRET_HEX",
            true,
        ),
        (r#"sh -c "password=":SUPER_SECRET"""#, "SUPER_SECRET", true),
        (
            r#"error: expected " near Bearer " dXNlcjpwYXNz==""#,
            "dXNlcjpwYXNz==",
            true,
        ),
        (
            r#"error: expected " near Basic " admin:SUPER_SECRET""#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"error: expected " near password=" -SUPER_SECRET""#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"error: expected " near password=" SUPER_SECRET ""#,
            "SUPER_SECRET",
            true,
        ),
        // Escaped & unescaped HTTP header inner quotes & multi-partial fallbacks
        (
            r#"curl -H "Cookie: note=" hello"; sid=SUPER_SECRET_COOKIE" https://example.invalid"#,
            "SUPER_SECRET_COOKIE",
            true,
        ),
        (
            r#"curl -H "X-Api-Key: "";SUPER_SECRET" https://example.invalid"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -H "Cookie: a="'1'" sid=SUPER_SECRET""#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -H "X-Api-Key: "" SUPER_SECRET""#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -H "Cookie: a=""1"" sid=SUPER_SECRET""#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -H "Cookie: a=" ", sid=SUPER_SECRET" https://example.invalid"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -H \"Cookie: note="foo", "ok": true, sid=SUPER_SECRET\" localhost:8080"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -H \"Cookie: a="1", 2, sid=SUPER_SECRET\" localhost:8080"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -H \"Cookie: note="foo", "ok": true, sid=SUPER_SECRET"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -H \"Cookie: a=\" -x \", sid=SUPER_SECRET\" https://example.invalid"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -H \"Cookie: a=\" https://example.com\", sid=SUPER_SECRET\" https://api.invalid"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -H \"Cookie: ref=\" https://a.test\"; sid=SUPER_SECRET_COOKIE\" https://example.invalid"#,
            "SUPER_SECRET_COOKIE",
            true,
        ),
        (
            r#"curl -H \\"Cookie: a=\"1\" -x sid=\"SUPER_SECRET\" --verbose"#,
            "SUPER_SECRET",
            true,
        ),
        // curl --proxy-user, backslash continuation, bs >= 2 ANSI-C, bash-concat
        (
            "curl --proxy-user admin:SUPER_SECRET https://example.invalid",
            "SUPER_SECRET",
            true,
        ),
        (
            "curl \\\n  -su admin:SUPER_SECRET https://example.invalid",
            "SUPER_SECRET",
            true,
        ),
        (
            "curl \\\n  -fsSLu admin:SUPER_SECRET https://example.invalid",
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -su$\\\"SUPER_SECRET\\\" https://example.invalid"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"curl -suadmin"":"SUPER_SECRET" https://example.invalid"#,
            "SUPER_SECRET",
            true,
        ),
        (
            "curl -suadmin'':SUPER_SECRET https://example.invalid",
            "SUPER_SECRET",
            true,
        ),
        // Trailing -/. container keys, CLI separators, Digest tchar, multiline escaped quotes, user=u:p, Unicode scoped keys
        (
            r#"{"password-": {"nested": "SUPER_SECRET"}}"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"api_key.": {"nested": "SUPER_SECRET"}}"#,
            "SUPER_SECRET",
            true,
        ),
        (
            "password-={\n  \"a\": \"SUPER_SECRET\"\n}",
            "SUPER_SECRET",
            true,
        ),
        ("echo ok;--token SUPER_SECRET", "SUPER_SECRET", true),
        ("echo ok&&--password SUPER_SECRET", "SUPER_SECRET", true),
        ("(--password SUPER_SECRET)", "SUPER_SECRET", true),
        (
            r#"Digest username="admin", 2fa=1, response="SUPER_SECRET""#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"Digest username="admin", _ext=1, response="SUPER_SECRET""#,
            "SUPER_SECRET",
            true,
        ),
        (
            "password=\\\\\\\"line1\\\"\nSUPER_SECRET_LINE2\\\\\\\"",
            "SUPER_SECRET_LINE2",
            true,
        ),
        ("user=admin:part1,SUPER_SECRET", "SUPER_SECRET", true),
        (
            r#"{"cmd": "user=\\\"my user:SUPER_SECRET\\\""}"#,
            "SUPER_SECRET",
            true,
        ),
        (r#"{"user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET", true),
        (
            r#"{"app/pass\u0070hrase": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"k8s.io/pass\u0077ord": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
            true,
        ),
        ("pwd=SUPER_SECRET", "SUPER_SECRET", true),
        (r#"{"passphrase": "SUPER_SECRET"}"#, "SUPER_SECRET", true),
        ("access_key=SUPER_SECRET", "SUPER_SECRET", true),
        ("auth_key=SUPER_SECRET", "SUPER_SECRET", true),
        // URL credentials: username-as-token, RFC 3986 sub-delims, raw @
        (
            "https://ghp_1234567890abcdef:x-oauth-basic@github.com/org/repo.git",
            "ghp_1234567890abcdef",
            false,
        ),
        (
            "https://admin:sec;SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:sec,SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:sec'SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:my@SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
            false,
        ),
    ];

    for &(input, secret, check_balanced) in parity_cases {
        let p = sanitize_persisted_lifecycle_text(input);
        let r = diagnostic_projection::redact_secrets(input);
        let x = diagnostic_projection::redact_secrets_regex(input);
        let b = diagnostic_projection::redact_balanced_structured_secrets(input);
        let d = af_models::secret_redaction::redact_diagnostic(input);

        for (label, out) in [
            ("persisted", p.as_str()),
            ("projected", r.as_str()),
            ("regex", x.as_str()),
            ("diagnostic", d.as_ref()),
        ] {
            assert!(
                !out.contains(secret),
                "{label} leaked {secret} for {input:?} -> {out:?}"
            );
        }
        if check_balanced {
            assert!(
                !b.contains(secret),
                "balanced leaked {secret} for {input:?} -> {b:?}"
            );
            assert_eq!(
                diagnostic_projection::redact_balanced_structured_secrets(&b),
                b,
                "balanced idempotency failed for {input:?} -> {b:?}"
            );
        }
        assert_eq!(
            sanitize_persisted_lifecycle_text(&p),
            p,
            "persisted idempotency failed for {input:?} -> {p:?}"
        );
        assert_eq!(
            diagnostic_projection::redact_secrets(&r),
            r,
            "projected idempotency failed for {input:?} -> {r:?}"
        );
        assert_eq!(
            diagnostic_projection::redact_secrets_regex(&x),
            x,
            "regex idempotency failed for {input:?} -> {x:?}"
        );
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&d),
            d,
            "diagnostic idempotency failed for {input:?} -> {d:?}"
        );
    }

    // 2. Direct `redact_json_value` scoped keys parity.
    let mut scoped_val = serde_json::json!({
        "/config/pwd": "SUPER_SECRET_1",
        "app/passphrase": "SUPER_SECRET_2",
        "http/cookie": "SUPER_SECRET_3",
        "auth/session": "SUPER_SECRET_4",
        "ci/webhook": "SUPER_SECRET_5",
        "api/auth": "SUPER_SECRET_6",
        "aws/access_key_id": "SUPER_SECRET_7",
        "source_key": "github:org/repo",
        "sort_key": "asc"
    });
    assert!(diagnostic_projection::redact_json_value(&mut scoped_val));
    for key in [
        "/config/pwd",
        "app/passphrase",
        "http/cookie",
        "auth/session",
        "ci/webhook",
        "api/auth",
        "aws/access_key_id",
    ] {
        assert_eq!(scoped_val[key], "[REDACTED]", "key {key} not redacted");
    }
    assert_eq!(scoped_val["source_key"], "github:org/repo");
    assert_eq!(scoped_val["sort_key"], "asc");

    // 3. Valid JSON preservation on scoped sensitive keys & 1-step idempotency edge cases.
    for json_input in [
        r#"{"/config/pwd": {"v": "SUPER_SECRET"}}"#,
        r#"{"/config/password": 123456}"#,
        r#"{"msg": "password=foo,Bearer SUPER_SECRET"}"#,
        r#"{"msg": "err: \" msg=\"expected Bearer \" hdr=\"Bearer SUPER_SECRET\""}"#,
    ] {
        let r = diagnostic_projection::redact_secrets(json_input);
        let x = diagnostic_projection::redact_secrets_regex(json_input);
        let b = diagnostic_projection::redact_balanced_structured_secrets(json_input);
        for (label, out) in [("projected", &r), ("regex", &x), ("balanced", &b)] {
            assert!(!out.contains("SUPER_SECRET"), "{label} leaked: {out}");
            assert!(!out.contains("123456"), "{label} leaked number: {out}");
            serde_json::from_str::<serde_json::Value>(out).unwrap_or_else(|e| {
                panic!("{label} broke valid JSON ({e}) for {json_input:?} -> {out:?}")
            });
        }
    }

    for idem_case in [
        r#"https://user:password="a "@example.com"#,
        r#"err: " msg="password=" hdr="Bearer SUPER_SECRET""#,
        "[REDACTED_url]--password username=SECRET\\\\\\\"\n,$\\\"\"password\": Bearer \n[REDACTED_URL]--password ://",
    ] {
        for (label, out, again) in [
            (
                "persisted",
                sanitize_persisted_lifecycle_text(idem_case),
                sanitize_persisted_lifecycle_text(&sanitize_persisted_lifecycle_text(idem_case)),
            ),
            (
                "projected",
                diagnostic_projection::redact_secrets(idem_case),
                diagnostic_projection::redact_secrets(&diagnostic_projection::redact_secrets(
                    idem_case,
                )),
            ),
            (
                "regex",
                diagnostic_projection::redact_secrets_regex(idem_case),
                diagnostic_projection::redact_secrets_regex(
                    &diagnostic_projection::redact_secrets_regex(idem_case),
                ),
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets(idem_case),
                diagnostic_projection::redact_balanced_structured_secrets(
                    &diagnostic_projection::redact_balanced_structured_secrets(idem_case),
                ),
            ),
        ] {
            assert_eq!(
                again, out,
                "{label} failed 1-step idempotency for {idem_case:?}: pass1={out:?} pass2={again:?}"
            );
        }
    }

    // 4. Benign preservation: passwordless ssh://, sort_key/source_key JSON, even-backslash `\\"` containers & Bearer.
    let ssh_url = "git-repo:ssh://git@github.com/org/repo.git#main";
    assert_eq!(sanitize_persisted_lifecycle_text(ssh_url), ssh_url);
    assert_eq!(diagnostic_projection::redact_secrets(ssh_url), ssh_url);
    assert_eq!(
        diagnostic_projection::redact_secrets_regex(ssh_url),
        ssh_url
    );

    let benign_keys_json = r#"{"source_key": "github:org/repo", "sort_key": "asc"}"#;
    assert_eq!(
        diagnostic_projection::redact_secrets(benign_keys_json),
        benign_keys_json
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text(r#"password={a: \\"val", b: 1} benign_after=1"#),
        "password=[REDACTED] benign_after=1"
    );
    assert_eq!(
        diagnostic_projection::redact_secrets(r#"password={a: \\"val", b: 1} benign_after=1"#),
        "password=[REDACTED] benign_after=1"
    );
    assert_eq!(
        sanitize_persisted_lifecycle_text(r#"Bearer \\"SECRET" --verbose"#),
        "Bearer [REDACTED] --verbose"
    );
    assert_eq!(
        diagnostic_projection::redact_secrets(r#"Bearer \\"SECRET" --verbose"#),
        "Bearer [REDACTED] --verbose"
    );

    // 5. Strictly linear-time O(N) scaling across ALL previously quadratic R6 triggers
    // (adaptive `n` doubling until `d1 >= 15ms` with high `max_n` and unconditional `ratio < 3.2`).
    type ScalingCase = (&'static str, fn(usize) -> String, usize, usize);
    let scaling_factories: &[ScalingCase] = &[
        (
            "hdr_suppressed_1",
            |n| format!("{}{{a\\\\\"}}", r#"\\"Cookie: x\" -a "#.repeat(n)),
            1_000,
            256_000,
        ),
        (
            "hdr_suppressed_2",
            |n| format!("{}-z", r#"\\"Cookie: x{\\",true}\" -x "#.repeat(n)),
            1_000,
            256_000,
        ),
        (
            "utf8_comma",
            |n| format!("password={}", "é\",x\"".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "bs_u0020",
            |n| format!("\"{}u0020\":1", "\\".repeat(n)),
            8_000,
            2_048_000,
        ),
        ("esc_space_u", |n| r#"\ -ua"#.repeat(n), 2_500, 512_000),
        ("esc_quote_u", |n| r#"\"-ua"#.repeat(n), 2_500, 512_000),
        (
            "curl_esc_su",
            |n| format!("curl{}", r#"\ -sua"#.repeat(n)),
            2_500,
            512_000,
        ),
        ("user_brace", |n| "user={".repeat(n), 2_500, 512_000),
        ("user_bracket", |n| "user=[".repeat(n), 2_500, 512_000),
        (
            "user_esc_space",
            |n| r#"user=a\ "#.repeat(n),
            2_500,
            512_000,
        ),
        (
            "user_esc_colon",
            |n| r#"user=a\ :\ "#.repeat(n),
            2_500,
            512_000,
        ),
    ];
    let run_all_five = |p: &str| -> usize {
        let op = sanitize_persisted_lifecycle_text(p);
        let or = diagnostic_projection::redact_secrets(p);
        let ox = diagnostic_projection::redact_secrets_regex(p);
        let ob = diagnostic_projection::redact_balanced_structured_secrets(p);
        let od = af_models::secret_redaction::redact_diagnostic(p);
        assert!(
            !op.is_empty() && !or.is_empty() && !ox.is_empty() && !ob.is_empty() && !od.is_empty()
        );
        op.len() + or.len() + ox.len() + ob.len() + od.len()
    };
    let started = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in scaling_factories {
        assert_adaptive_linear_scaling(name, "all5", make_payload, start_n, max_n, run_all_five);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(45),
        "R6 linear-time scaling payloads exceeded budget: {elapsed:?}"
    );
}

fn assert_adaptive_linear_scaling(
    name: &str,
    ep: &str,
    make_payload: fn(usize) -> String,
    start_n: usize,
    max_n: usize,
    run: impl Fn(&str) -> usize,
) {
    let mut n = start_n;
    let (mut d1, mut d2, p1, p2) = loop {
        let p1 = make_payload(n);
        let t1 = std::time::Instant::now();
        let len1 = run(std::hint::black_box(&p1));
        let d1 = t1.elapsed();
        assert!(len1 > 0);
        if d1 >= std::time::Duration::from_millis(15) || n >= max_n {
            let p2 = make_payload(n * 2);
            let t2 = std::time::Instant::now();
            let len2 = run(std::hint::black_box(&p2));
            let d2 = t2.elapsed();
            assert!(len2 > 0);
            break (d1, d2, p1, p2);
        }
        n *= 2;
    };
    let mut ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
    if ratio >= 3.2 || d1 < std::time::Duration::from_millis(5) {
        let mut s1 = [std::time::Duration::ZERO; 3];
        let mut s2 = [std::time::Duration::ZERO; 3];
        for (slot1, slot2) in s1.iter_mut().zip(s2.iter_mut()) {
            let t1 = std::time::Instant::now();
            assert!(run(std::hint::black_box(&p1)) > 0);
            *slot1 = t1.elapsed();
            let t2 = std::time::Instant::now();
            assert!(run(std::hint::black_box(&p2)) > 0);
            *slot2 = t2.elapsed();
        }
        s1.sort_unstable();
        s2.sort_unstable();
        d1 = s1[1];
        d2 = s2[1];
        ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
    }
    assert!(
        ratio < 3.2,
        "{name} [{ep}] showed superlinear scaling at n={n} (2n={}): d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)",
        n * 2
    );
}

#[test]
fn test_wave1a_r7_audit_regressions_compact_json_pipeline_order_headers_argv_unicode_and_linear_time(
) {
    // 1. Secret redaction + 1-step idempotency parity across all 5 af-release/af-models entry points.
    let secret_cases: &[(&str, &str)] = &[
        (
            r#"{"args":["password=SUPER_SECRET",1],"api_key":"SECOND_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"args":["password=SUPER_SECRET",1],"api_key":"SECOND_SECRET"}"#,
            "SECOND_SECRET",
        ),
        (
            r#"{"args":["password=SUPER_SECRET",1],"api_key":"SECOND_SECRET""#,
            "SECOND_SECRET",
        ),
        (
            "https://ghp_SUPER_SECRET_TOKEN:pass={x@github.com/org/repo",
            "ghp_SUPER_SECRET_TOKEN",
        ),
        (
            "https://ghp_SUPER_SECRET_TOKEN:pass=x@github.com/org/repo",
            "ghp_SUPER_SECRET_TOKEN",
        ),
        (
            "https://ghp_SUPER_SECRET_TOKEN:Cookie:x@github.com/org/repo",
            "ghp_SUPER_SECRET_TOKEN",
        ),
        (
            r#"curl -H \"X-Api-Key: {\"a\":\" https://a.test/SUPER_SECRET\"}\" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \"Cookie: x={\"a\":\" https://a.test\"}, sid=SUPER_SECRET\" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \"X-Api-Key: {\"a\":\" -x SUPER_SECRET\"}\" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \"X-Api-Key: \" -x SUPER_SECRET\"\" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \\"Cookie: unclosed -H \\"X-Api-Key: a=\"1\" -b sid=SUPER_SECRET\\" --verbose"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \\\"Cookie: note=\"foo\", \"ok\": true, sid=SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \\"Cookie: a=\"1\" -x sid=SUPER_SECRET --verbose"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H \"X-Api-Key: foo \" -x \", SUPER_SECRET\" https://example.invalid"#,
            "SUPER_SECRET",
        ),
        (
            r#"err: " failed: Set-Cookie: a="1"; sid=SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (r#"path=C:\\"ok" password="; SUPER_SECRET""#, "SUPER_SECRET"),
        (r#"path=C:\\"ok" password=": SUPER_SECRET""#, "SUPER_SECRET"),
        (r#"path=C:\\"ok" password="& SUPER_SECRET""#, "SUPER_SECRET"),
        (
            r#"err: " near Basic " dXNlcjpwYXN=" --header "Accept: */*""#,
            "dXNlcjpwYXN=",
        ),
        (
            r#"error: expected " near Bearer " }SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"error: expected " near password=" sid=SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"error: expected " near Bearer " a=SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"error: expected " near webhook_url=" https://hooks.slack.com/SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"error: expected " near password=" ,SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"error: expected " near password=" SUPER_SECRET:""#,
            "SUPER_SECRET",
        ),
        (
            r#"error near ": password=": SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"error near ": password="; SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"error near ": password="& SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"error near ": password="' SUPER_SECRET'""#,
            "SUPER_SECRET",
        ),
        (
            r#"https://a:password="x";'@b.com/ Bearer ' ,SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://a:APP_KEY="x";'@b.com/ APP_KEY=' ,SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://a:user="x:y";'@b.com/ https://c:APP_KEY=' ,x'"'";'@d.com/ Bearer ' ,SUPER_SECRET'"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -H "Content-Type: application/json; charset=utf-8" -su admin:SUPER_SECRET https://api.example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl password="a;b" -su admin:SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl user="a:b;c" -su admin:SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl APP_KEY="a;b" -su admin:SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            r#"docker run -e "APP_KEY=part1 SUPER_SECRET" alpine"#,
            "SUPER_SECRET",
        ),
        ("env 'APP_KEY=part1 SUPER_SECRET'", "SUPER_SECRET"),
        (r#"{"APP_KEY": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"OPENAI_KEY": "sk-SUPER_SECRET"}"#, "SUPER_SECRET"),
        ("APP_KEY: SUPER_SECRET", "SUPER_SECRET"),
        (r#""APP_KEY"="SUPER_SECRET""#, "SUPER_SECRET"),
        (r#"APP_KEY={"nested": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        ("env 'api_key=;SUPER_SECRET'", "SUPER_SECRET"),
        ("env 'api_key=&SUPER_SECRET'", "SUPER_SECRET"),
        (
            r#"curl -H "X-Api-Token: ;SUPER_SECRET" https://example.com"#,
            "SUPER_SECRET",
        ),
        (r#"docker run -e "password=} SUPER_SECRET""#, "SUPER_SECRET"),
        ("curl '--user=;admin:SUPER_SECRET'", "SUPER_SECRET"),
        ("env 'api_key=[REDACTED];SUPER_SECRET'", "SUPER_SECRET"),
        (
            r#"curl -H "X-Api-Token: [REDACTED], SUPER_SECRET" https://example.com"#,
            "SUPER_SECRET",
        ),
        ("env 'api_key=line1\nSUPER_SECRET'", "SUPER_SECRET"),
        (
            "docker run -e \"PRIVATE_KEY=-----BEGIN KEY-----\nSUPER_SECRET\n-----END KEY-----\"",
            "SUPER_SECRET",
        ),
        (
            r#"{"aws:secretsmanager:password": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"urn:app:password": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"password/v1": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"{"vault/password/primary": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"/secret/val": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"secret value": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{\"password/v1\": \"SUPER_SECRET\"}"#, "SUPER_SECRET"),
        (r#"{"@password": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"$secret": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"café_token": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        ("tool --secret-key SUPER_SECRET --verbose", "SUPER_SECRET"),
        ("tool --authorization SUPER_SECRET --verbose", "SUPER_SECRET"),
        ("tool --bearer SUPER_SECRET --verbose", "SUPER_SECRET"),
        ("tool --db_password SUPER_SECRET --verbose", "SUPER_SECRET"),
        ("tool --api-token-v2 SUPER_SECRET --verbose", "SUPER_SECRET"),
        (
            "curl --oauth2-bearer SUPER_SECRET https://api.example.com",
            "SUPER_SECRET",
        ),
        ("cmd --access_token SUPER_SECRET --verbose", "SUPER_SECRET"),
        ("log:--user admin:SUPER_SECRET", "SUPER_SECRET"),
        ("cmd=--proxy-user=admin:SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl -4u admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl -6su admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl -usk_live_SUPER_SECRET https://api.stripe.com",
            "SUPER_SECRET",
        ),
        (
            r#"{"args": ["pg_dump", "--password", "SUPER_SECRET"]}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"args": ["curl", "--user", "admin:SUPER_SECRET", "https://example.com"]}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"args": ["curl", "-u", "admin:SUPER_SECRET", "https://example.com"]}"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl "-u" "admin:SUPER_SECRET" https://example.com"#,
            "SUPER_SECRET",
        ),
        (
            "curl -H \"Cookie: a=1;\nsid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        ("Cookie: a=1;\n  sid=SUPER_SECRET", "SUPER_SECRET"),
        (
            "Authorization: Digest username=\"admin\",\n  realm=\"api\",\n  response=\"SUPER_SECRET_HEX\"",
            "SUPER_SECRET_HEX",
        ),
        ("Authorization: Bearer\n  SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl -u \\\n  admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "pg_dump --password \\\n  SUPER_SECRET --verbose",
            "SUPER_SECRET",
        ),
        ("PASSWORD=\\\nSUPER_SECRET", "SUPER_SECRET"),
        ("Bearer \\\n  SUPER_SECRET", "SUPER_SECRET"),
        (
            "https://a:12345,foo=SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "https://admin:1234,dXNlcjpwYXNz==@example.com/api",
            "dXNlcjpwYXNz==",
        ),
        (
            "https://admin:12345''SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (r#"user=admin"":"SUPER_SECRET""#, "SUPER_SECRET"),
        ("user=admin'':SUPER_SECRET", "SUPER_SECRET"),
        (r#"{"app+pass\u0077ord": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{'pass\u0077ord': 'SUPER_SECRET'}"#, "SUPER_SECRET"),
        (r#"{"café/pass\u0077ord": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"[0]/pass\u0077ord": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"\u0022password\u0022": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"\u0027password\u0027": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"pass\u0077ord=SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"{"note": "Bearer\u0020SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"msg": "password\u003dSUPER_SECRET"}"#, "SUPER_SECRET"),
        ("Bearer ;SUPER_SECRET", "SUPER_SECRET"),
    ];
    for &(input, secret) in secret_cases {
        for (label, f) in [
            (
                "persisted",
                sanitize_persisted_lifecycle_text as fn(&str) -> String,
            ),
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "regex",
                diagnostic_projection::redact_secrets_regex as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
            (
                "diagnostic",
                (|s: &str| af_models::secret_redaction::redact_diagnostic(s).into_owned())
                    as fn(&str) -> String,
            ),
        ] {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R7 {label} leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R7 {label} failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
    }

    // Long >260-byte escaped header inner quote (no 256-byte lookahead cliff).
    let long_hdr = format!(
        r#"curl -H \"Cookie: a=\" -x {}\", sid=SUPER_SECRET\" https://example.invalid"#,
        "a".repeat(260)
    );
    for out in [
        sanitize_persisted_lifecycle_text(&long_hdr),
        diagnostic_projection::redact_secrets(&long_hdr),
        diagnostic_projection::redact_secrets_regex(&long_hdr),
        diagnostic_projection::redact_balanced_structured_secrets(&long_hdr),
    ] {
        assert!(!out.contains("SUPER_SECRET"), "long_hdr leaked: {out:?}");
    }

    // 2. Valid RFC 8259 JSON preservation on compact arrays, spaced JSON, header keys, and mismatched escapes.
    for valid_json in [
        r#"{"args":["password=SUPER_SECRET",1],"api_key":"SECOND_SECRET"}"#,
        r#"{"args":["password=[REDACTED]",1],"exit_code":0}"#,
        r#"{"msg": "prefix Cookie: [REDACTED]" , "ok": true}"#,
        r#"{"msg": "prefix Cookie: [REDACTED]" }"#,
        r#"{"msg": "prefix Cookie: sid=SUPER_SECRET" , "ok": true}"#,
        r#"{"Cookie: sid=123": "hello", "status": 200}"#,
        r#"{"X-Api-Key: SECRET": "hello", "status": 200}"#,
        r#"{"urn:app:password": "SUPER_SECRET"}"#,
        r#"{"@password": "SUPER_SECRET"}"#,
        r#"{"@token": {"id": "SUPER_SECRET"}}"#,
        r#"{"$secret": "SUPER_SECRET"}"#,
        r#"{"café_token": "SUPER_SECRET"}"#,
        r#"{"msg": "password\": 1", "ok": true}"#,
        r#"{"\u0022password\u0022": "SUPER_SECRET"}"#,
        r#"{"args": ["pg_dump", "--password", "SUPER_SECRET"]}"#,
        r#"{"args": ["curl", "-u", "admin:SUPER_SECRET", "https://example.com"]}"#,
    ] {
        for (label, f) in [
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "regex",
                diagnostic_projection::redact_secrets_regex as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(valid_json);
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R7 {label} broke valid JSON ({e}) for {valid_json:?} -> {out:?}")
            });
            assert_eq!(f(&out), out, "R7 {label} JSON idempotency failed");
        }
    }

    // 3. Specific 1-step idempotency + benign preservation reproducers.
    for idem in [
        r#""password":[REDACTED_URL]"password":x"#,
        r#""password":[REDACTED_url]"password":x"#,
        "https://admin::'@example.com Cookie: sid=SECRET', 'ok': true",
        "\"🚀\n\"password\": [REDACTED_URL]'",
        "'\\u0077\ntoken: >\t:Digest user=@example.com>👨\u{200d}👩\u{200d}👧\u{200d}👦",
    ] {
        for f in [
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
            diagnostic_projection::redact_secrets as fn(&str) -> String,
            diagnostic_projection::redact_secrets_regex as fn(&str) -> String,
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ] {
            let p1 = f(idem);
            assert_eq!(f(&p1), p1, "R7 1-step idempotency failed for {idem:?}");
        }
    }
    for benign in [
        "['https://example.com:8443','admin@example.com']",
        r#"{"args":["password=[REDACTED]",1],"exit_code":0}"#,
    ] {
        assert_eq!(sanitize_persisted_lifecycle_text(benign), benign);
        assert_eq!(diagnostic_projection::redact_secrets(benign), benign);
        assert_eq!(diagnostic_projection::redact_secrets_regex(benign), benign);
        assert_eq!(
            diagnostic_projection::redact_balanced_structured_secrets(benign),
            benign
        );
    }
    assert_eq!(
        sanitize_persisted_lifecycle_text(r#"Digest a=\\"SECRET" --verbose"#),
        "Digest [REDACTED] --verbose"
    );
    assert_eq!(
        diagnostic_projection::redact_secrets(r#"Digest a=\\"SECRET" --verbose"#),
        "Digest [REDACTED] --verbose"
    );

    // 4. Adaptive per-entry-point O(N) linear scaling on R7 + R8 DoS triggers
    // (high `max_n` + `d1 >= 15ms` without `d2 < 20ms` bypass).
    type R7Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r7_scaling: &[R7Scaling] = &[
        ("user_colon", |n| "user=:".repeat(n), 2_000, 512_000),
        ("user_system", |n| "user=system:".repeat(n), 2_000, 512_000),
        ("user_http", |n| "user=http:".repeat(n), 2_000, 512_000),
        (
            "user_lead_bs_sp",
            |n| r#"user=\ :\ "#.repeat(n),
            2_000,
            512_000,
        ),
        (
            "user_quoted_sys",
            |n| r#"user="system:""#.repeat(n),
            2_000,
            512_000,
        ),
        (
            "r8_argv_dollar_brace",
            |n| format!("\"{}\":", "'-u' ${".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r8_argv_bs_brace",
            |n| format!("'{}' :", r#""-u" \a{ "#.repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r8_argv_ansi_brace",
            |n| format!("'{}' :", r#""-u" $"a"{ "#.repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r8_user_cont_nl",
            |n| format!("{}a:b", "user=\\\n".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r8_user_dollar_brace",
            |n| format!("'{}a:' :", r#"user=$"a"{ "#.repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r8_user_sp_colon_brace",
            |n| format!("'{}' :", r#"user=a" :x"{ "#.repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r8_hdr_pure_cli_tail",
            |n| format!(r#"curl -H \\"Cookie: {}bad"#, r#"https://a\" "#.repeat(n)),
            2_000,
            512_000,
        ),
        (
            "hdr_d0_sq",
            |n| format!("'{}", "\"Cookie: x';'".repeat(n)),
            1_000,
            256_000,
        ),
        (
            "hdr_d0_dq",
            |n| format!("\"{}", "'Cookie: \"; \"".repeat(n)),
            1_000,
            256_000,
        ),
        (
            "curl_su_bracket",
            |n| format!("curl{}", "\"-su[".repeat(n)),
            2_000,
            512_000,
        ),
        ("curl_pipe_bracket", |n| "|-u[".repeat(n), 2_000, 512_000),
        (
            "json_127_arr",
            |n| format!("{}{}", "[".repeat(127), r#"{"a":1},"#.repeat(n)),
            500,
            256_000,
        ),
    ];
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps_scale: [RedactorEntry; 5] = [
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        ("regex", diagnostic_projection::redact_secrets_regex),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
    ];
    let started_r7 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r7_scaling {
        for &(ep, f) in &eps_scale {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }
    assert!(
        started_r7.elapsed() < std::time::Duration::from_secs(90),
        "R7+R8 linear-time budget exceeded: {:?}",
        started_r7.elapsed()
    );
}

#[test]
fn test_wave1a_r8_audit_regressions_urls_json_escapes_multiline_headers_argv_unicode_and_idempotency(
) {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 5] = [
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        ("regex", diagnostic_projection::redact_secrets_regex),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
    ];

    for (input, secret) in [
        ("https://alice.smith:12345;x=SUPER_SECRET@example.com/api", "SUPER_SECRET"),
        ("https://alice.smith:12345;'SUPER_SECRET@example.com/api", "SUPER_SECRET"),
        ("https://localhost:12345,x=SUPER_SECRET@example.com/api", "SUPER_SECRET"),
        ("https://john.doe:1234,foo=SUPER_SECRET@example.com/api", "SUPER_SECRET"),
        ("https://user;name:SUPER_SECRET@example.com/api", "SUPER_SECRET"),
        ("https://tok;SUPER_SECRET@github.com/org/repo", "SUPER_SECRET"),
        (r#"https:\/\/admin:SUPER_SECRET@example.com\/api"#, "SUPER_SECRET"),
        ("{\n  \"args\": [\n    \"curl\",\n    \"-usk_live_SUPER_SECRET\"\n  ]\n}", "SUPER_SECRET"),
        ("{\n  \"args\": [\n    \"curl\",\n    \"-su\",\n    \"admin:SUPER_SECRET\"\n  ]\n}", "SUPER_SECRET"),
        ("[\n  \"pg_dump\",\n  \"--password\",\n  \"SUPER_SECRET\"\n]", "SUPER_SECRET"),
        ("[\"pg_dump\", \"--password\"\n, \"SUPER_SECRET\"]", "SUPER_SECRET"),
        ("curl -H \"Cookie: a=1;\nb=\"2\";\nsid=SUPER_SECRET\" https://example.com", "SUPER_SECRET"),
        ("err: \\\\\\\"Cookie: broken\ncurl -H \"Cookie: a=1;\nsid=SUPER_SECRET\" https://example.com", "SUPER_SECRET"),
        (r#"curl -H \\"Cookie: a=\"1\" https://example.com\"sid=SUPER_SECRET"#, "SUPER_SECRET"),
        ("Authorization: Bearer \"line1\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("Cookie: \"sid=line1\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("Authorization: Bearer \\\nSUPER_SECRET", "SUPER_SECRET"),
        ("Cookie: a=1;\\\nSUPER_SECRET", "SUPER_SECRET"),
        ("Cookie: part1\\\nSUPER_SECRET", "SUPER_SECRET"),
        ("Authorization: Digest username=\"a\",\\\nresponse=\"SUPER_SECRET\"", "SUPER_SECRET"),
        ("X-Api-Key:\n\nSUPER_SECRET", "SUPER_SECRET"),
        ("Cookie:\n\n  sid=SUPER_SECRET", "SUPER_SECRET"),
        (r#"{"Cookie: sid=123": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"curl -H "Cookie: a":SUPER_SECRET""#, "SUPER_SECRET"),
        (r#"{"a\"password": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"password\/v1": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"token_\u00e9": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"error: {"password\/v1": "SUPER_SECRET""#, "SUPER_SECRET"),
        (r#"{"password=1": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"pass\u0077ord=1": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"user\u003dBearer\u0020SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"user\u003aToken\u0009SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"user\u003dBasic\u0020admin:SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"Basic\u003aToken\u0009SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"Bearer\u0009SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"{"\u0075ser": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{'\u0075ser': 'admin:SUPER_SECRET'}"#, "SUPER_SECRET"),
        (r#"{"a;pass\u0077ord": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"a\"pass\u0077ord": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"--pass\u0077ord SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"curl --\u0075ser admin:SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"\u0042earer SUPER_SECRET"#, "SUPER_SECRET"),
        ("user=\\\nadmin:SUPER_SECRET", "SUPER_SECRET"),
        (r#"user=a" "b:SUPER_SECRET"#, "SUPER_SECRET"),
        ("pg_dump --password \\\n  \\\n  SUPER_SECRET --verbose", "SUPER_SECRET"),
        ("Digest username=\"admin\", \\\n  response=\"SUPER_SECRET_HEX\"", "SUPER_SECRET_HEX"),
        (r#"{"masterPass": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"rclonePass": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"rcloneRcPass": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"v1.APP_KEY": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        ("tool --APP_KEY SUPER_SECRET", "SUPER_SECRET"),
        (r#"tool "--APP_KEY" "SUPER_SECRET""#, "SUPER_SECRET"),
    ] {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R8 {label} leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R8 {label} 1-step idempotency failed for {input:?} -> {out:?}"
            );
        }
    }

    // Valid RFC 8259 JSON preservation across projected + balanced
    let long_arr = format!(r#"["password=SUPER_SECRET",{{"k":"{}"}}]"#, "a".repeat(300));
    let long_hdr = format!(
        r#"{{"a":"prefix Cookie: sid=SUPER_SECRET","{}":1}}"#,
        "k".repeat(300)
    );
    for raw in [
        r#"{"prefix Cookie: sid=SECRET": "hello"}"#,
        r#"{"prefix Authorization: Bearer SECRET": "hello"}"#,
        r#"{"\"Cookie: sid=SECRET\"": "hello"}"#,
        r#"{"'Cookie: sid=SECRET'": "hello"}"#,
        r#"{"a\"password": "SUPER_SECRET"}"#,
        r#"{"a\\password": "SUPER_SECRET"}"#,
        r#"{"a\npassword": "SUPER_SECRET"}"#,
        r#"{"password=1": "SUPER_SECRET"}"#,
        r#"{"vault\/password": "SUPER_SECRET"}"#,
        r#"{"HKLM\\password": "SUPER_SECRET"}"#,
        r#"{"caf\u00e9/password": "SUPER_SECRET"}"#,
        r#"["Cookie: sid=SUPER_SECRET",{"k":"v"},1]"#,
        r#"["password='SUPER_SECRET",{"k":"it's ok"}]"#,
        long_arr.as_str(),
        long_hdr.as_str(),
    ] {
        for (label, out) in [
            ("projected", diagnostic_projection::redact_secrets(raw)),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets(raw),
            ),
        ] {
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R8 {label} broke valid JSON ({e}) for {raw:?} -> {out:?}");
            });
        }
    }

    // Specific 1-step idempotency & benign preservation regressions
    for raw in [
        r#"' "Bearer a-'1", Cookie: sid=1", "ok": true"#,
        "user='password':,SECRET",
        "\"password\":[REDACTED]\\'\nx",
    ] {
        for &(label, f) in &eps {
            let p1 = f(raw);
            assert_eq!(f(&p1), p1, "R8 {label} idempotency failed for {raw:?}");
        }
    }
    for &(label, f) in &eps {
        assert_eq!(
            f("https://example.com:8443,admin@example.com"),
            "https://example.com:8443,admin@example.com",
            "R8 {label} over-redacted CSV URL + email"
        );
    }
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        assert_eq!(
            f(r#"curl -H C:\\"Cookie: sid=SUPER_SECRET" https://example.com"#),
            r#"curl -H C:\\"Cookie: [REDACTED]" https://example.com"#,
            "R8 {label} truncated Windows even-backslash quoted header tail"
        );
        assert_eq!(
            f(r#"["Cookie: sid=SUPER_SECRET",{"k":"v"},1]"#),
            r#"["Cookie: [REDACTED]",{"k":"v"},1]"#,
            "R8 {label} corrupted sibling JSON array element"
        );
    }
    assert!(diagnostic_projection::is_already_redacted(
        r#"\\\"[REDACTED]\\\""#
    ));
}

fn r9_make_exp_json(depth: usize) -> String {
    let mut cur = r#"{"password":"sec"}"#.to_string();
    for _ in 0..depth {
        let escaped: String = cur
            .bytes()
            .map(|b| match b {
                b'\\' => r"\u005c".to_string(),
                b'"' => r"\u0022".to_string(),
                _ => (b as char).to_string(),
            })
            .collect();
        cur = format!(r#"{{"a":"{escaped}"}}"#);
    }
    cur
}

fn r9_odd_bs_redacted_url(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 64);
    let mut k = 0usize;
    while s.len() < target_bytes {
        s.push_str("password=[REDACTED]");
        s.extend(std::iter::repeat_n('\\', 17 + 2 * k));
        s.push_str("\" https://a ");
        k += 1;
    }
    s
}

fn r9_odd_bs_kv_quote(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 64);
    let mut k = 0usize;
    while s.len() < target_bytes {
        s.push_str("password=");
        s.extend(std::iter::repeat_n('\\', 17 + 2 * k));
        s.push_str("\"a\\\" ");
        k += 1;
    }
    s
}

fn r9_odd_bs_sq_flag(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 64);
    let mut k = 0usize;
    while s.len() < target_bytes {
        s.push_str("'--x' ");
        s.extend(std::iter::repeat_n('\\', 17 + 2 * k));
        s.push_str("\" ");
        k += 1;
    }
    s
}

fn r9_odd_bs_dq_flag(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 64);
    let mut k = 0usize;
    while s.len() < target_bytes {
        s.push_str("\"--a\" ");
        s.extend(std::iter::repeat_n('\\', 17 + 2 * k));
        s.push_str("\" ");
        k += 1;
    }
    s
}

fn r9_odd_bs_curl_u(target_bytes: usize) -> String {
    let mut s = String::with_capacity(target_bytes + 64);
    let mut k = 0usize;
    while s.len() < target_bytes {
        s.push_str("curl \"-u\" ");
        s.extend(std::iter::repeat_n('\\', 17 + 2 * k));
        s.push_str("\" ");
        k += 1;
    }
    s
}

fn r9_benign_nested_u005c_json(target_bytes: usize) -> String {
    let depth = ((target_bytes / 24) as f64).sqrt() as usize;
    let mut shell = r#"{"msg":"@"}"#.to_string();
    for _ in 0..depth {
        let escaped: String = shell
            .bytes()
            .map(|b| match b {
                b'\\' => r"\u005c".to_string(),
                b'"' => r"\u0022".to_string(),
                _ => (b as char).to_string(),
            })
            .collect();
        shell = format!(r#"{{"a":"{escaped}"}}"#);
    }
    shell.replacen('@', &"x".repeat(target_bytes / 2), 1)
}

#[test]
fn test_wave1a_r9_r10_audit_regressions() {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 4] = [
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
    ];

    // 1. Zero plaintext secret leak + strict 1-step idempotency across ALL 4 entry points
    // covering Team 8 (F-01..F-12), Neon R9 (F-01..F-11), and Carbon R9 (F-01..F-09).
    let secret_cases: &[(&str, &str)] = &[
        // Team 8 F-02, F-05A/B, F-06, F-07, F-08, F-09A..D, F-10, F-11
        (r#"user='"':SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"{"x.user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"db-user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"a\"user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"a,\"password": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"{"a,\"password": "SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            "[\"curl\",\n\"--password\", \"SUPER_SECRET\"],\n\"-su\",\n\"benign_arg\"",
            "SUPER_SECRET",
        ),
        (
            "https://ghp_SUPER_SECRET.v1;user=foo@github.com/org/repo",
            "ghp_SUPER_SECRET",
        ),
        (
            "https://ghp_SUPER_SECRET.v1;password=x@github.com/org/repo",
            "ghp_SUPER_SECRET",
        ),
        (
            "url=https://example.com;password=admin@SUPER_SECRET",
            "SUPER_SECRET",
        ),
        (r#"pg_dump --password\u0020SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"curl --user\u0020admin:SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"{"a,\"pass\u0077ord": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:SUPER_SECRET\u0040example.com"}"#,
            "SUPER_SECRET",
        ),
        (
            "[\"pg_dump\",\n \\\"--password\\\",\n \\\"SUPER_SECRET\\\"]",
            "SUPER_SECRET",
        ),
        (
            "[\"pg_dump\", \"--password\", \"line1\nSUPER_SECRET\"]",
            "SUPER_SECRET",
        ),
        ("curl -u=\nadmin:SUPER_SECRET", "SUPER_SECRET"),
        ("curl --user=\nsk_live_SUPER_SECRET", "SUPER_SECRET"),
        (r#"["pg_dump", "--password", 123456789]"#, "123456789"),
        (
            r#"cmd C:\\"api_key=part1 SUPER_SECRET" --verbose"#,
            "SUPER_SECRET",
        ),
        (r#"user=admin\ :SUPER_SECRET"#, "SUPER_SECRET"),
        // Neon R9 F-01, F-02, F-03, F-04, F-05, F-06, F-10, F-11
        (
            r#"{"\"Cookie: {sid=SUPER_SECRET\"": true}"#,
            "SUPER_SECRET",
        ),
        (r#"["Cookie: {sid=SUPER_SECRET", ["ok"]]"#, "SUPER_SECRET"),
        (
            r#"{"api_key": {"cmd": "Cookie: {sid=SUPER_SECRET"}, "args": "ok"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"["Cookie: [sid=SUPER_SECRET", {"ok": 1}, 2]"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"hdr": "Cookie: {sid=SUPER_SECRET", "next": [1, 2]}"#,
            "SUPER_SECRET",
        ),
        (r#"{"a, \"password\": 1": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"{"a{\"password}": "SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"a\"password\"b": {"v": "SUPER_SECRET"}}"#,
            "SUPER_SECRET",
        ),
        (
            "{\"a\\\"password\\\"b\": {\n  \"v\": \"SUPER_SECRET\"\n}}",
            "SUPER_SECRET",
        ),
        (
            r#"{"a, \"password\": 1": {"v": "SUPER_SECRET"}}"#,
            "SUPER_SECRET",
        ),
        ("Bearer {\n  \"tok\": \"SUPER_SECRET\"\n}", "SUPER_SECRET"),
        ("Bearer [\n  \"SUPER_SECRET\"\n]", "SUPER_SECRET"),
        ("Bearer \"line1\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("Bearer 'line1\nSUPER_SECRET'", "SUPER_SECRET"),
        ("Cookie: a=1;\n  b=2\n  sid=SUPER_SECRET", "SUPER_SECRET"),
        (
            "Cookie: a=1;\n  b=\"line2\nSUPER_SECRET\"",
            "SUPER_SECRET",
        ),
        (
            "Authorization: Bearer\n  \"line1\nSUPER_SECRET\"",
            "SUPER_SECRET",
        ),
        (
            r#""Bearer \\ Digest username=\"admin\", response=\"SUPER_SECRET\"""#,
            "SUPER_SECRET",
        ),
        (
            r#"Bearer \ Digest username="admin", response="SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (r#"["pg_dump", "--password", "SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"{"args": ["pg_dump", "--password", 987654321]}"#,
            "987654321",
        ),
        (
            r#"{"args": ["pg_dump", "--password", {"sec": "SUPER_SECRET"}]}"#,
            "SUPER_SECRET",
        ),
        (
            r#"["pg_dump", "--pass\u0077ord", "SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (r#"tool \u002d\u002dpassword SUPER_SECRET"#, "SUPER_SECRET"),
        (
            "[\n  \"pg_dump\",\n  \"--password\",\n  \"SEC1_CANARY\", \"--token\",\n  \"SUPER_SECRET\"\n]",
            "SEC1_CANARY",
        ),
        (
            "[\n  \"pg_dump\",\n  \"--password\",\n  \"SEC1_CANARY\", \"--token\",\n  \"SUPER_SECRET\"\n]",
            "SUPER_SECRET",
        ),
        (
            "{\\\"args\\\": [\n  \\\"pg_dump\\\",\n  \\\"--password\\\",\n  \\\"SUPER_SECRET\\\"\n]}",
            "SUPER_SECRET",
        ),
        (
            "curl \"-u\" \"admin:line1\nSUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        (
            r#"{"msg":"https:\\/\\/admin:SUPER_SECRET@example.com"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"https:\\/\\/admin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"https\u003a//admin:SUPER_SECRET@example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"u":"https://admin:my\"SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            "https://admin:my}SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        ("--password=\nSUPER_SECRET", "SUPER_SECRET"),
        (r#"{"rclone_rcPass": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        ("password=\"line1\nline2\"\\\nSUPER_SECRET", "SUPER_SECRET"),
        // Carbon R9 F-01, F-02, F-06, F-07, F-08, F-09 #1 & #2
        (
            "https://example.com,https://admin:hUnt3r2_pR0d@example.com",
            "hUnt3r2_pR0d",
        ),
        (
            "https://example.com;https://admin:hUnt3r2_pR0d@example.com",
            "hUnt3r2_pR0d",
        ),
        (
            "https://example.com:8443,https://admin:hUnt3r2_pR0d@example.com",
            "hUnt3r2_pR0d",
        ),
        (
            r#"{"urls":"https://example.com,https://admin:hUnt3r2_pR0d@example.com"}"#,
            "hUnt3r2_pR0d",
        ),
        (
            "https://u1:p1@https://u2:hUnt3r2_pR0d@example.com",
            "hUnt3r2_pR0d",
        ),
        (
            r#"{"error: password=hUnt3r2_pR0d": "failed"}"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"{"cmd --password hUnt3r2_pR0d": "failed"}"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"{"note Bearer 'hUnt3r2_pR0d": "it's ok"}"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"{"error: password=FIRST_SECRET": "SECOND_SECRET"}"#,
            "FIRST_SECRET",
        ),
        (
            r#"{"error: password=FIRST_SECRET": "SECOND_SECRET"}"#,
            "SECOND_SECRET",
        ),
        (
            r#"{"cmd --password FIRST_SECRET": "SECOND_SECRET"}"#,
            "FIRST_SECRET",
        ),
        (
            r#"{"cmd --password FIRST_SECRET": "SECOND_SECRET"}"#,
            "SECOND_SECRET",
        ),
        (
            r#"{"curl -u 'admin:hUnt3r2_pR0d": "it's ok"}"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"["pg_dump", "--pass\u0077ord", "hUnt3r2_pR0d"]"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"pg_dump "--pass\u0077ord" "hUnt3r2_pR0d""#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"{"endpoint": "https://admin:hUnt3r2_pR0d\u0040example.com/api"}"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"https:\u002f\u002fadmin:hUnt3r2_pR0d@example.com"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"curl \u002du admin:hUnt3r2_pR0d https://example.com"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"curl -\u0075 admin:hUnt3r2_pR0d https://example.com"#,
            "hUnt3r2_pR0d",
        ),
        (
            r#"curl -u\u0020admin:hUnt3r2_pR0d https://example.com"#,
            "hUnt3r2_pR0d",
        ),
        (r#"password \u003d hUnt3r2_pR0d"#, "hUnt3r2_pR0d"),
        (r#"password \u003a hUnt3r2_pR0d"#, "hUnt3r2_pR0d"),
        (
            "curl -H \"Cookie: a=1\nb=2\" \\\n  -su admin:hUnt3r2_pR0d https://example.com",
            "hUnt3r2_pR0d",
        ),
        (
            "[\"curl\",\n{\"password\": {\n  \"v\": \"sec1_secret\"\n}},\n\"-su\",\n\"admin:hUnt3r2_pR0d\"]",
            "sec1_secret",
        ),
        (
            "[\"curl\",\n{\"password\": {\n  \"v\": \"sec1_secret\"\n}},\n\"-su\",\n\"admin:hUnt3r2_pR0d\"]",
            "hUnt3r2_pR0d",
        ),
        (
            "curl --password=\nsec1_secret \\\n  -su admin:hUnt3r2_pR0d https://example.com",
            "sec1_secret",
        ),
        (
            "curl --password=\nsec1_secret \\\n  -su admin:hUnt3r2_pR0d https://example.com",
            "hUnt3r2_pR0d",
        ),
        ("--password=\nhUnt3r2_pR0d", "hUnt3r2_pR0d"),
        (
            "[\n\"password\": \"sec1_secret\"]\n\"--password\"\n, \"visible_item\"",
            "sec1_secret",
        ),
        (
            r#"{"https://admin:hUnt3r2_pR0d\u0040example.com": "https://u:p\u0040example.com", "password": pw1}"#,
            "hUnt3r2_pR0d",
        ),
    ];

    for &(input, secret) in secret_cases {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R9/R10 {label} leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R9/R10 {label} failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
    }

    // Explicit Team 8 F-06 & Carbon F-09 #1/#2 1-step idempotency + benign line retention checks.
    for (idem_input, forbidden, kept) in [
        (
            "[\"curl\",\n\"--password\", \"sec1\"],\n\"-su\",\n\"benign_arg\"",
            "sec1",
            "benign_arg",
        ),
        (
            "[\n\"password\": \"sec1\"]\n\"--password\"\n, \"visible_item\"",
            "sec1",
            "visible_item",
        ),
    ] {
        for &(label, f) in &eps {
            let p1 = f(idem_input);
            assert!(
                !p1.contains(forbidden),
                "R9/R10 {label} leaked {forbidden} on {idem_input:?} -> {p1:?}"
            );
            assert!(
                p1.contains(kept),
                "R9/R10 {label} over-redacted {kept} on {idem_input:?} -> {p1:?}"
            );
            assert_eq!(
                f(&p1),
                p1,
                "R9/R10 {label} 1-step idempotency failed on {idem_input:?} -> {p1:?}"
            );
        }
    }

    // 2. Valid RFC 8259 JSON preservation on BOTH `redact_secrets` & `redact_balanced_structured_secrets`
    // plus sibling preservation checks.
    let valid_json_cases: &[&str] = &[
        // Neon F-01..F-04, F-05 #5, F-06, F-10, F-11
        r#"{"\"Cookie: {sid=1\"": true}"#,
        r#"{"\"Cookie: {sid=SUPER_SECRET\"": true}"#,
        r#"["Cookie: {sid=SECRET", ["ok"]]"#,
        r#"{"api_key": {"cmd": "Cookie: {sid=SECRET"}, "args": "ok"}"#,
        r#"["Cookie: [sid=SUPER_SECRET", {"ok": 1}, 2]"#,
        r#"{"hdr": "Cookie: {sid=SUPER_SECRET", "next": [1, 2]}"#,
        r#"{"a, \"password\": 1": "SUPER_SECRET"}"#,
        r#"{"a,\"password": "SUPER_SECRET", "ok": true}"#,
        r#"{"a{\"password}": "SUPER_SECRET", "ok": true}"#,
        r#"{"a\"password\"b": {"v": "SUPER_SECRET"}}"#,
        "{\"a\\\"password\\\"b\": {\n  \"v\": \"SUPER_SECRET\"\n}}",
        r#"{"a, \"password\": 1": {"v": "SUPER_SECRET"}}"#,
        r#""Bearer \\ Digest username=\"admin\", response=\"SUPER_SECRET\"""#,
        r#"{"args": ["pg_dump", "--password", 987654321]}"#,
        r#"["pg_dump", "--password", 123456789]"#,
        r#"{"args": ["pg_dump", "--password", {"sec": "SUPER_SECRET"}]}"#,
        r#"["pg_dump", "--pass\u0077ord", "SUPER_SECRET"]"#,
        "[\n  \"pg_dump\",\n  \"--password\",\n  \"SEC1\", \"--token\",\n  \"SUPER_SECRET\"\n]",
        r#"{"msg":"https:\\/\\/admin:SUPER_SECRET@example.com"}"#,
        r#"{"u":"https://admin:my\"SUPER_SECRET@example.com/api"}"#,
        r#"{"rclone_rcPass": "SUPER_SECRET"}"#,
        // Team 8 F-05A/B, F-08
        r#"{"x.user": "admin:SUPER_SECRET"}"#,
        r#"{"db-user": "admin:SUPER_SECRET"}"#,
        r#"{"a\"user": "admin:SUPER_SECRET"}"#,
        r#"{"a,\"password": "SUPER_SECRET"}"#,
        r#"{"a,\"pass\u0077ord": "SUPER_SECRET"}"#,
        r#"{"url": "https://admin:SUPER_SECRET\u0040example.com"}"#,
        // Carbon F-01, F-02, F-06, F-07, F-08
        r#"{"urls":"https://example.com,https://admin:hUnt3r2_pR0d@example.com"}"#,
        r#"{"error: password=hUnt3r2_pR0d": "failed"}"#,
        r#"{"cmd --password hUnt3r2_pR0d": "failed"}"#,
        r#"{"note Bearer 'hUnt3r2_pR0d": "it's ok"}"#,
        r#"{"error: password=FIRST_SECRET": "SECOND_SECRET"}"#,
        r#"{"curl -u 'admin:hUnt3r2_pR0d": "it's ok"}"#,
        r#"{"endpoint": "https://admin:hUnt3r2_pR0d\u0040example.com/api"}"#,
        "[\"curl\",\n{\"password\": {\n  \"v\": \"sec1\"\n}},\n\"-su\",\n\"admin:hUnt3r2_pR0d\"]",
    ];

    for &raw in valid_json_cases {
        serde_json::from_str::<serde_json::Value>(raw)
            .unwrap_or_else(|e| panic!("test fixture must be valid RFC 8259 JSON ({e}): {raw:?}"));
        for (label, f) in [
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(raw);
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R9/R10 {label} broke valid RFC 8259 JSON ({e}) for {raw:?} -> {out:?}")
            });
            assert_eq!(
                f(&out),
                out,
                "R9/R10 {label} JSON 1-step idempotency failed for {raw:?} -> {out:?}"
            );
        }
    }

    // Sibling preservation checks on Neon F-02 & Carbon F-06 reproducers.
    let sib_arr = r#"["Cookie: {sid=SECRET", ["ok"]]"#;
    let sib_obj = r#"{"api_key": {"cmd": "Cookie: {sid=SECRET"}, "args": "ok"}"#;
    let sib_key_sq = r#"{"curl -u 'admin:hUnt3r2_pR0d": "it's ok"}"#;
    for (label, f) in [
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let out_arr = f(sib_arr);
        assert!(
            !out_arr.contains("SECRET"),
            "{label} leaked SECRET: {out_arr:?}"
        );
        let parsed_arr: serde_json::Value = serde_json::from_str(&out_arr).unwrap();
        assert_eq!(
            parsed_arr.as_array().map(Vec::len),
            Some(2),
            "{label} lost sibling element on {sib_arr:?} -> {out_arr:?}"
        );
        assert_eq!(parsed_arr[1], serde_json::json!(["ok"]));

        let out_obj = f(sib_obj);
        assert!(
            !out_obj.contains("SECRET"),
            "{label} leaked SECRET: {out_obj:?}"
        );
        let parsed_obj: serde_json::Value = serde_json::from_str(&out_obj).unwrap();
        assert_eq!(
            parsed_obj.get("args"),
            Some(&serde_json::json!("ok")),
            "{label} destroyed sibling args field on {sib_obj:?} -> {out_obj:?}"
        );

        let out_sq = f(sib_key_sq);
        assert!(
            !out_sq.contains("hUnt3r2_pR0d"),
            "{label} leaked hUnt3r2_pR0d: {out_sq:?}"
        );
        let parsed_sq: serde_json::Value = serde_json::from_str(&out_sq).unwrap();
        assert_eq!(
            parsed_sq.as_object().and_then(|m| m.values().next()),
            Some(&serde_json::json!("it's ok")),
            "{label} corrupted value on {sib_key_sq:?} -> {out_sq:?}"
        );
    }
    let persisted_sib_arr = sanitize_persisted_lifecycle_text(sib_arr);
    assert!(
        !persisted_sib_arr.contains("SECRET") && persisted_sib_arr.contains(r#"["ok"]"#),
        "persisted corrupted sibling array: {persisted_sib_arr:?}"
    );
    let persisted_sib_obj = sanitize_persisted_lifecycle_text(sib_obj);
    assert!(
        !persisted_sib_obj.contains("SECRET") && persisted_sib_obj.contains(r#""args": "ok""#),
        "persisted corrupted sibling object field: {persisted_sib_obj:?}"
    );

    // 3. Benign preservation checks across ALL 4 entry points + targeted tail/URL preservation.
    for benign in [
        "sort_key",
        "bypass",
        r#"{"sort_key": "asc", "bypass": true}"#,
        "auth_token stay_visible",
        "refresh_token expired during sync",
        "sha256_digest verified ok",
        r#"{"flag": "-u", "ok": true}"#,
        "['https://example.com:8443','admin@example.com']",
        "https://example.com:8443,admin@example.com",
        "url=https://example.com;email=admin@example.com",
        r#"{"user": "system:serviceaccount:default:app"}"#,
    ] {
        for &(label, f) in &eps {
            assert_eq!(
                f(benign),
                benign,
                "R9/R10 {label} over-redacted benign input {benign:?}"
            );
        }
    }
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let semi_pw = f("url=https://example.com;password=admin@SUPER_SECRET");
        assert!(
            !semi_pw.contains("SUPER_SECRET") && semi_pw.contains("https://example.com"),
            "R9/R10 {label} mishandled semicolon URL+password: {semi_pw:?}"
        );
        let win_kv = f(r#"cmd C:\\"api_key=part1 SUPER_SECRET" --verbose"#);
        assert!(
            !win_kv.contains("SUPER_SECRET") && win_kv.ends_with(" --verbose"),
            "R9/R10 {label} truncated Windows even-backslash KV tail: {win_kv:?}"
        );
    }

    // 4. Carbon F-04 `make_exp_json(15)` (< 20ms) + adaptive-n linear scaling (`ratio < 3.2`)
    // across ALL new R9 DoS vectors.
    let exp15 = r9_make_exp_json(15);
    for &(label, f) in &eps {
        let (best_elapsed, out) = (0..3)
            .map(|_| {
                let t = std::time::Instant::now();
                let o = f(std::hint::black_box(&exp15));
                (t.elapsed(), o)
            })
            .min_by_key(|(d, _)| *d)
            .unwrap();
        assert!(
            best_elapsed < std::time::Duration::from_millis(20),
            "R9/R10 {label} exceeded 20ms budget on make_exp_json(15): {best_elapsed:?}"
        );
        assert_eq!(
            f(&out),
            out,
            "R9/R10 {label} make_exp_json(15) failed 1-step idempotency"
        );
        if label == "projected" {
            assert!(
                !out.contains("sec"),
                "projected leaked inner secret in make_exp_json(15): {out:?}"
            );
        }
        if label == "projected" || label == "balanced" {
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R9/R10 {label} broke valid JSON on make_exp_json(15): {e}")
            });
        }
    }

    type R9Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r9_scaling: &[R9Scaling] = &[
        (
            "r9_url_dot_comma",
            |n| format!("https://a.b{}", ",a".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r9_url_dot_semi",
            |n| format!("https://a.b{}", ";x".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r9_url_nodot_semi_eq",
            |n| format!("https://a{}", ";a=1".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r9_url_nodot_comma_eq",
            |n| format!("https://a{}", ",x=1".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r9_user_sq_dq_brace",
            |n| r#"user='"':x{ "#.repeat(n),
            2_000,
            512_000,
        ),
        (
            "r9_user_quotes_urn_brace",
            |n| r#"user='u""""""""""""""""""""rn':{ "#.repeat(n),
            1_000,
            256_000,
        ),
        (
            "r9_curl_attached_cross_quote",
            |n| format!("'{}\"' :x", "(-ua{".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r9_odd_bs_redacted_url",
            r9_odd_bs_redacted_url,
            16_384,
            2_097_152,
        ),
        ("r9_odd_bs_kv_quote", r9_odd_bs_kv_quote, 16_384, 2_097_152),
        ("r9_odd_bs_sq_flag", r9_odd_bs_sq_flag, 16_384, 2_097_152),
        ("r9_odd_bs_dq_flag", r9_odd_bs_dq_flag, 16_384, 2_097_152),
        ("r9_odd_bs_curl_u", r9_odd_bs_curl_u, 16_384, 2_097_152),
        (
            "r9_benign_nested_u005c_json",
            r9_benign_nested_u005c_json,
            8_192,
            524_288,
        ),
        (
            "r9_json_126_amp",
            |n| format!("{}{}1]", "[1,".repeat(126), "1,".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r9_odd_bs_nested_json",
            |n| format!(r#"{}\"password": {{"v": 1}}"#, r#"\"a"#.repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r9_odd_bs_scalar_json",
            |n| format!(r#"{}\"password": "sec""#, r#"\"a"#.repeat(n)),
            2_000,
            512_000,
        ),
    ];

    let started_r9 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r9_scaling {
        for &(ep, f) in &eps {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }
    assert!(
        started_r9.elapsed() < std::time::Duration::from_secs(90),
        "R9/R10 linear-time budget exceeded: {:?}",
        started_r9.elapsed()
    );
}

fn r11_make_nested_u005c_json(depth: usize, inner: &str) -> String {
    let mut cur = inner.to_string();
    for _ in 0..depth {
        let mut escaped = String::with_capacity(cur.len() + 32);
        for ch in cur.chars() {
            match ch {
                '\\' => escaped.push_str(r"\u005c"),
                '"' => escaped.push_str(r"\u0022"),
                _ => escaped.push(ch),
            }
        }
        cur = format!(r#"{{"a":"{escaped}"}}"#);
    }
    cur
}

#[test]
fn test_wave1a_r11_audit_regressions() {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 4] = [
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
    ];

    // 1. P0 UTF-8 boundary slice safety across all 4 entry points (Team 8 F-01/F-02, Neon P0-1/P0-2, Carbon F-01)
    let utf8_no_panic_cases = [
        "[\"cmd\", \"--password\",\n{\"é\": 1}   ",
        "[\"--password\",\n{\"é\":1}   ",
        r#"\u0022password\u0022:\u0022🚀\u0022"#,
        r#"\u0022password\u0022:\u0022é\u0022"#,
        r#"\u0022password\u0022:\u0022éab\u0022"#,
        r#"\u0022password\u0022:\u0022a🚀\u0022"#,
        r#"\u0022password\u0022:\u0022abcd🚀\u0022"#,
        r#"\u0022password\u0022:\u0022aéaa\u0022"#,
        r#"{"a\u0022password\u0022:\u0022🚀\u0022":"ok"}"#,
        r#"{"msg": "\\u0022password\\u0022:\\u0022é\\u0022"}"#,
        r#"{"msg": "\\u0022password\\u0022:\\u0022🚀\\u0022"}"#,
        r#"{"msg": "\\u0022password\\u0022:\\u0022éab\\u0022"}"#,
        r#"{"msg": "\\u0022password\\u0022:\\u0022abcd🚀\\u0022"}"#,
        r#"{"\u0022password\u0022:\u0022é\u0022": "x"}"#,
        r#"{"\u0022password\u0022:\u0022a🚀\u0022": "x"}"#,
    ];
    for raw in utf8_no_panic_cases {
        for &(label, f) in &eps {
            let out = f(raw);
            assert_eq!(
                f(&out),
                out,
                "R11 UTF-8 1-step idempotency failed [{label}] on {raw:?}"
            );
        }
    }

    // 18-level nested UTF-8 / inner-escaped-quote / numeric JSON (Neon P0-2 + P1-8)
    let exp18_utf8 = r11_make_nested_u005c_json(18, r#"{"password":"é_SUPER_SECRET_🚀"}"#);
    let exp18_escq = r11_make_nested_u005c_json(18, r#"{"password":"a\"SUPER_SECRET"}"#);
    let exp18_num = r11_make_nested_u005c_json(18, r#"{"password":987654321}"#);
    for (nested, secret) in [
        (&exp18_utf8, "SUPER_SECRET"),
        (&exp18_escq, "SUPER_SECRET"),
        (&exp18_num, "987654321"),
    ] {
        for &(label, f) in &eps {
            let out = f(nested);
            assert!(
                !out.contains(secret),
                "R11 depth-18 [{label}] leaked {secret}: {out:?}"
            );
            assert_eq!(f(&out), out, "R11 depth-18 [{label}] idempotency failed");
            if label == "projected" || label == "balanced" {
                serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                    panic!("R11 depth-18 [{label}] broke valid JSON: {e}");
                });
            }
        }
    }

    // 2. Zero plaintext secret leak + 1-step idempotency across ALL 4 entry points for all R10 audit findings
    let long_url_u0040 = format!(
        "https://admin:{}SUPER_SECRET\\u0040example.com",
        "a".repeat(520)
    );
    let long_curl_u0075 = format!("curl --{}u0075ser admin:SUPER_SECRET", "\\".repeat(520));
    let long_user_json_key = format!(r#"{{"{}-user": "admin:SUPER_SECRET"}}"#, "a".repeat(300));

    let secret_cases: Vec<(&str, &str)> = vec![
        // Team 8 F-01 / Neon P0-1 ASCII multiline container with trailing spaces
        (
            "[\"cmd\", \"--password\",\n{ \n  \"v\": \"SUPER_SECRET\"\n}]",
            "SUPER_SECRET",
        ),
        (
            "[\"--password\",\n{ \n  \"v\": \"SUPER_SECRET\"\n}\n]",
            "SUPER_SECRET",
        ),
        // Neon P1-1
        (
            r#"{"msg": "['pg_dump', '--password', 123456789]"}"#,
            "123456789",
        ),
        (
            r#"{"msg": "['pg_dump', '--password', {'v': 'SUPER_SECRET'}]"}"#,
            "SUPER_SECRET",
        ),
        (long_user_json_key.as_str(), "SUPER_SECRET"),
        // Neon P1-2 marker-prefixed multiline quote bypass
        ("password=[REDACTED]\"\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("password=[REDACTED]'\nSUPER_SECRET'", "SUPER_SECRET"),
        ("password=\"[REDACTED]\"\"\nSUPER_SECRET\"", "SUPER_SECRET"),
        (
            "curl --password [REDACTED]\"\nSUPER_SECRET\"",
            "SUPER_SECRET",
        ),
        // Team 8 F-03/F-04 & Neon P1-3 multiline quoted headers & obs-fold
        (
            "curl -H \"Cookie: a=1;\nb=\" 2\";\nsid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl -H \"Cookie: a=1;\nb=\",2\";\nsid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl -H \"Cookie: a=1\n\"note\" sid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        (
            "Cookie: a=1;\n  b=\"line2\n  sid=SUPER_SECRET",
            "SUPER_SECRET",
        ),
        ("Cookie: a=1;\n  b=\"line2\\\nSUPER_SECRET", "SUPER_SECRET"),
        ("curl -H \"Cookie: a=1;\n  sid=SUPER_SECRET", "SUPER_SECRET"),
        ("curl -H \"Cookie: a=1\n  sid=SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl -H \"Authorization: Bearer part1\n  SUPER_SECRET",
            "SUPER_SECRET",
        ),
        // Carbon F-02 & Neon P1-4 multiline Bearer containers & quotes
        (
            "Bearer [\nBearer {\n  \"v\": \"SUPER_SECRET\"\n}\nstatus=ok",
            "SUPER_SECRET",
        ),
        ("Bearer \"part1\nSUPER_SECRET", "SUPER_SECRET"),
        ("Bearer {\n  \"tok\": \"SUPER_SECRET\"", "SUPER_SECRET"),
        // Neon P1-5 CLI flag `=` spacing
        (
            "curl -u= admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl --user= sk_live_SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl --proxy-user= sk_live_SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        ("curl -u= \nadmin:SUPER_SECRET", "SUPER_SECRET"),
        ("curl --password= \nSUPER_SECRET", "SUPER_SECRET"),
        ("curl --password=\t\nSUPER_SECRET", "SUPER_SECRET"),
        // Neon P1-6 & Carbon F-08 escaped JSON argv non-strings, escaped `\"` keys, suffixed ALL-CAPS `*_KEY`
        (
            r#"{"msg": "[\"pg_dump\", \"--password\", 987654321]"}"#,
            "987654321",
        ),
        (
            r#"{"log": "[\"pg_dump\", \"--password\", 987654321]"}"#,
            "987654321",
        ),
        (
            r#"exec [\"pg_dump\", \"--password\", 987654321]"#,
            "987654321",
        ),
        (
            r#"{"msg": "[\"pg_dump\", \"--password\", {\"v\": \"SUPER_SECRET\"}]"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"exec [\"pg_dump\", \"--password\", {\"v\": \"SUPER_SECRET\"}]"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "{\"password\\\"b\":\"SUPER_SECRET\"}"}"#,
            "SUPER_SECRET",
        ),
        (
            "APP_KEY.v1=SUPER_SECRET_1 APP_KEY-prod=SUPER_SECRET_2",
            "SUPER_SECRET_1",
        ),
        (
            "APP_KEY.v1=SUPER_SECRET_1 APP_KEY-prod=SUPER_SECRET_2",
            "SUPER_SECRET_2",
        ),
        // Team 8 F-05, Neon P1-7, Carbon F-04/F-05 URL authority `}`, sub-delim heuristics, Unicode URLs
        (
            "https://admin:p}}SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "https://admin:p}:SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "https://admin:p},SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://ghp_SUPER_SECRET.v1;foo@github.com"}"#,
            "ghp_SUPER_SECRET",
        ),
        (
            r#"{"url": "https://alice.smith:1234;SUPER_SECRET@example.com"}"#,
            "SUPER_SECRET",
        ),
        (
            "https://ghp-SUPER-SECRET.v1;password=x@github.com",
            "ghp-SUPER-SECRET",
        ),
        (
            r#"https:\u002f\/admin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"https:\u002f/admin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"endpoint": "https:\u002f/admin:SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"ssh://admin\u003aSUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:my'SUPER_SECRET\u0040example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"u":"https://admin:my\"SUPER_SECRET\u0040example.com"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"endpoint": "https://admin:my\"SUPER_SECRET\u0040example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:p@ss_SUPER_SECRET\u0040example.com/api"#,
            "ss_SUPER_SECRET",
        ),
        (
            r#"{"endpoint": "https://admin:p\u0040ss_SUPER_SECRET\u0040example.com/api"}"#,
            "ss_SUPER_SECRET",
        ),
        (long_url_u0040.as_str(), "SUPER_SECRET"),
        // Team 8 F-06/F-09/F-10, Neon P1-8/P2-1, Carbon F-08 #2
        (
            r#"\u0022password\u0022:\u0022a\u005cu0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (r#"\u0022password\u0022: 987654321"#, "987654321"),
        (
            r#"\u0022my password\u0022:\u0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022user\u0022:\u0022admin:SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\u0022password\u0022: \u0022SUPER_SECRET\u0022"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\u0022password\u0022: \u0022SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\u0022Bearer SUPER_SECRET\u0022"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"db-\u0075ser": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"db-\u0075ser=admin:SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"db-user\u003dadmin:SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"{"user": "admin\u003aSUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"user-1": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"user-name": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"["curl", "-s\u0075", "admin:SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -s\u0075 admin:SUPER_SECRET https://example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl \u002dsu admin:SUPER_SECRET https://example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -su\u0020admin:SUPER_SECRET https://example.com"#,
            "SUPER_SECRET",
        ),
        (r#"msg\u0020Bearer SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"foo\u003aBearer SUPER_SECRET"#, "SUPER_SECRET"),
        (long_curl_u0075.as_str(), "SUPER_SECRET"),
        ("Authorization: Bearer\tSUPER_SECRET", "SUPER_SECRET"),
        // Neon P1-9/P1-10 & Carbon F-06/F-07
        (
            r#"user=\"system:foo user=admin:SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            r#"user="system:foo user=admin:SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            r#"{\"user\": \"system:foo user=admin:SUPER_SECRET\"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"user": "system:foo user=admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            "{\n  \"user\":\n    \"admin:sec1_canary\", \"api_key\":\n    \"SUPER_SECRET\"\n}",
            "sec1_canary",
        ),
        (
            "{\n  \"user\":\n    \"admin:sec1_canary\", \"api_key\":\n    \"SUPER_SECRET\"\n}",
            "SUPER_SECRET",
        ),
        ("password=\\\n\"part1\"\\\nSUPER_SECRET", "SUPER_SECRET"),
        (
            "x = \"[\\\"curl\\\",\n\\\"-su\\\", \\\"admin:SUPER_SECRET\\\"]\"",
            "SUPER_SECRET",
        ),
        (
            "users' job failed: [\"curl\",\n  \"-su\",\n  \"admin:SUPER_SECRET\"\n]",
            "SUPER_SECRET",
        ),
    ];

    for (input, secret) in secret_cases {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R11 [{label}] leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R11 [{label}] failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
    }

    // 3. Valid RFC 8259 JSON preservation + Carbon F-03 / Neon P1-1 sibling & structure checks
    let valid_json_r11: Vec<&str> = vec![
        r#"{"a\u0022password\u0022:\u0022🚀\u0022":"ok"}"#,
        r#"{"msg": "\\u0022password\\u0022:\\u0022é\\u0022"}"#,
        r#"{"msg": "\\u0022password\\u0022:\\u0022🚀\\u0022"}"#,
        r#"{"msg": "\\u0022password\\u0022:\\u0022abcd🚀\\u0022"}"#,
        r#"{"\u0022password\u0022:\u0022é\u0022": "x"}"#,
        r#"{"\u0022password\u0022:\u0022a🚀\u0022": "x"}"#,
        r#"{"msg": "['pg_dump', '--password', 123456789]"}"#,
        r#"{"msg": "['pg_dump', '--password', {'v': 'SUPER_SECRET'}]"}"#,
        long_user_json_key.as_str(),
        r#"["'Cookie: a=1", {"msg": "x' https://example.com"}]"#,
        r#"["'Cookie: a=1", "'Cookie: a=2", "'Cookie: a=3", "'Cookie: a=4", "Authorization: Basic dXNlcjpwYXNz="]"#,
        r#"["'Cookie: a=1", "'Cookie: a=2", "'Cookie: a=3", "'Cookie: a=4", "Authorization: Basic dXNlcjpwYXNz=", "keep_me"]"#,
        r#"{"msg": "[\"pg_dump\", \"--password\", 987654321]"}"#,
        r#"{"msg": "[\"pg_dump\", \"--password\", {\"v\": \"SUPER_SECRET\"}]"}"#,
        r#"{"msg": "{\"password\\\"b\":\"SUPER_SECRET\"}"}"#,
        r#"{"url": "https://ghp_SUPER_SECRET.v1;foo@github.com"}"#,
        r#"{"url": "https://alice.smith:1234;SUPER_SECRET@example.com"}"#,
        r#"{"endpoint": "https:\u002f/admin:SUPER_SECRET@example.com/api"}"#,
        r#"{"u":"https://admin:my\"SUPER_SECRET\u0040example.com"}"#,
        r#"{"endpoint": "https://admin:my\"SUPER_SECRET\u0040example.com/api"}"#,
        r#"{"endpoint": "https://admin:p\u0040ss_SUPER_SECRET\u0040example.com/api"}"#,
        r#"{"msg": "\u0022password\u0022: \u0022SUPER_SECRET\u0022"}"#,
        r#"{"outer": "{\u0022password\u0022: \u0022SUPER_SECRET\u0022}"}"#,
        r#"{"msg": "\u0022Bearer SUPER_SECRET\u0022"}"#,
        r#"{"db-\u0075ser": "admin:SUPER_SECRET"}"#,
        r#"{"user": "admin\u003aSUPER_SECRET"}"#,
        r#"{"user-1": "admin:SUPER_SECRET"}"#,
        r#"{"user-name": "admin:SUPER_SECRET"}"#,
        r#"["curl", "-s\u0075", "admin:SUPER_SECRET"]"#,
        r#"{"user": "system:foo user=admin:SUPER_SECRET"}"#,
        "{\n  \"user\":\n    \"admin:sec1\", \"api_key\":\n    \"SUPER_SECRET\"\n}",
    ];
    for raw in valid_json_r11 {
        serde_json::from_str::<serde_json::Value>(raw)
            .unwrap_or_else(|e| panic!("R11 fixture must be valid JSON ({e}): {raw:?}"));
        for (label, f) in [
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(raw);
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R11 [{label}] broke valid JSON ({e}) for {raw:?} -> {out:?}")
            });
            assert_eq!(f(&out), out, "R11 [{label}] JSON idempotency failed");
        }
    }
    // Neon P1-1: persisted must also keep valid JSON on single-quoted argv inside JSON string
    for raw in [
        r#"{"msg": "['pg_dump', '--password', 123456789]"}"#,
        r#"{"msg": "['pg_dump', '--password', {'v': 'SUPER_SECRET'}]"}"#,
    ] {
        let out_p = sanitize_persisted_lifecycle_text(raw);
        serde_json::from_str::<serde_json::Value>(&out_p).unwrap_or_else(|e| {
            panic!("R11 persisted broke valid JSON ({e}) for {raw:?} -> {out_p:?}")
        });
    }

    // Carbon F-03 explicit sibling checks
    let cf03_j1 = r#"["'Cookie: a=1", {"msg": "x' https://example.com"}]"#;
    let cf03_j3 = r#"["'Cookie: a=1", "'Cookie: a=2", "'Cookie: a=3", "'Cookie: a=4", "Authorization: Basic dXNlcjpwYXNz=", "keep_me"]"#;
    for (label, f) in [
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let v1: serde_json::Value = serde_json::from_str(&f(cf03_j1)).unwrap();
        assert_eq!(
            v1[1],
            serde_json::json!({"msg": "x' https://example.com"}),
            "R11 [{label}] corrupted Carbon F-03 j1 sibling"
        );
        let out3 = f(cf03_j3);
        assert!(!out3.contains("dXNlcjpwYXNz="));
        let v3: serde_json::Value = serde_json::from_str(&out3).unwrap();
        assert_eq!(
            v3.as_array().map(Vec::len),
            Some(6),
            "R11 [{label}] dropped sibling in Carbon F-03 j3: {out3:?}"
        );
        assert_eq!(v3[5], serde_json::json!("keep_me"));

        // Team 8 F-09: tab after auth scheme preserved in header redaction
        let tab_hdr = f("Authorization: Bearer\tSUPER_SECRET");
        assert!(
            tab_hdr.starts_with("Authorization: Bearer") && !tab_hdr.contains("SUPER_SECRET"),
            "R11 [{label}] dropped Bearer prefix on tab separator: {tab_hdr:?}"
        );
    }

    // 4. Benign preservation: Carbon F-09 (`-AMozillaUbuntu`), Neon P2-2 (unclosed `Bearer {`), Carbon F-02 (`status=ok`)
    let curl_ua = r#"{"args": ["curl", "-AMozillaUbuntu", "https://example.com"]}"#;
    for &(label, f) in &eps {
        assert_eq!(
            f(curl_ua),
            curl_ua,
            "R11 [{label}] over-redacted benign curl -AMozillaUbuntu argv"
        );
    }
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let p2_2 = f("Bearer {\nbenign_line_1=ok\nbenign_line_2={\"x\":1}");
        assert!(
            p2_2.contains("benign_line_1=ok") && p2_2.contains("benign_line_2={\"x\":1}"),
            "R11 [{label}] over-redacted trailing lines after unclosed Bearer {{: {p2_2:?}"
        );
        let cf02 = f("Bearer [\nBearer {\n  \"v\": \"SUPER_SECRET\"\n}\nstatus=ok");
        assert!(
            !cf02.contains("SUPER_SECRET") && cf02.contains("status=ok"),
            "R11 [{label}] mishandled Carbon F-02 trailing status=ok: {cf02:?}"
        );
    }

    // 5. Adaptive linear-time O(N) scaling across all new R10/R11 DoS vectors
    type R11Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r11_scaling: &[R11Scaling] = &[
        (
            "r11_bearer_unclosed_then_balanced",
            |n| format!("{}Bearer {{\n\"v\":\"s\"\n}}", "Bearer [\n".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r11_bearer_nested_unclosed_one_close",
            |n| format!("{}}}", "Bearer {\n".repeat(n)),
            2_000,
            512_000,
        ),
        (
            "r11_user_unclosed_exempt_flood",
            |n| r#"user=\"system:foo "#.repeat(n),
            2_000,
            512_000,
        ),
        (
            "r11_long_user_json_key",
            |n| format!(r#"{{"{}-user":"admin:sec"}}"#, "a".repeat(n)),
            4_000,
            1_024_000,
        ),
        (
            "r11_url_password_close_braces",
            |n| format!("https://a:p{}}}@h", "}".repeat(n)),
            4_000,
            1_024_000,
        ),
    ];
    let started_r11 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r11_scaling {
        for &(ep, f) in &eps {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }
    assert!(
        started_r11.elapsed() < std::time::Duration::from_secs(90),
        "R11 linear-time budget exceeded: {:?}",
        started_r11.elapsed()
    );
}

#[test]
fn test_wave1a_r12_audit_regressions() {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 4] = [
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
    ];

    let long_u0022_key_1 = format!(
        r#"\u0022{}_password\u0022:\u0022SUPER_SECRET\u0022"#,
        "a".repeat(130)
    );
    let long_u0022_key_2 = format!(
        r#"{{"outer": "{{\\u0022{}_password\\u0022: \\u0022SUPER_SECRET\\u0022}}"}}"#,
        "x".repeat(130)
    );
    let long_short_curl_json = format!(
        r#"["curl", "-s{}u0075", "admin:SUPER_SECRET"]"#,
        "\\".repeat(520)
    );

    // 1. Zero plaintext secret leak + 1-step idempotency across ALL 4 entry points
    // covering Team 8 (F-01..F-12), Neon R11 (F-01..F-14), and Carbon R11 (F-01..F-09).
    let secret_cases: Vec<(&str, &str)> = vec![
        // Team 8 F-03 / Neon F-04 / Carbon F-02: URL passwords with `\"`/`"` + delimiter, `',`, `/\/`, `\\/\\/`
        (
            r#"{"url": "https://admin:p\";SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p\":SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p\",SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p\"}SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"u": "https://admin:my\"'SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:p";SUPER_SECRET@example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            "'https://admin:p',SUPER_SECRET@example.com'",
            "SUPER_SECRET",
        ),
        (
            r#"https:/\\/admin:SUPER_SECRET@example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\"url\": \"https:\\\\/\\\\/admin:SUPER_SECRET@example.com\"}"}"#,
            "SUPER_SECRET",
        ),
        // Neon F-05 & F-11: second URL with `\u003a`/`\u002f` + `;password=x@localhost` / `[::1]`
        (
            r#"https://example.com,https\u003a//admin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://example.com;https:\u002f/admin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://example.com,https:\u002f\u002fadmin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            "https://ghp-SUPER-SECRET.v1;password=x@localhost",
            "ghp-SUPER-SECRET",
        ),
        (
            "https://ghp-SUPER-SECRET.v1;password=x@[::1]",
            "ghp-SUPER-SECRET",
        ),
        // Team 8 F-04 & Neon F-03: space-containing `user` JSON values & `user=..., user` keys
        (r#"{"user": "my user:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"{"msg": "{\u0022user\u0022:\u0022my user:SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"user=1, user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"{"user=admin:SEC1_CANARY, user": "admin:SUPER_SECRET"}"#,
            "SEC1_CANARY",
        ),
        (
            r#"{"user=admin:SEC1_CANARY, user": "admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"[{"user=admin:SEC_CANARY, user":"expected Cookie: "}]"#,
            "SEC_CANARY",
        ),
        // Team 8 F-05 & Neon F-06: `redact_diagnostic` multiline quoted auth & `curl -u'...'`
        ("Bearer \"\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("Bearer \"line1\"\\\nSUPER_SECRET", "SUPER_SECRET"),
        ("curl -u'admin:line1\nSUPER_SECRET'", "SUPER_SECRET"),
        ("curl -su'admin:line1\nSUPER_SECRET'", "SUPER_SECRET"),
        ("curl -U'admin:line1\nSUPER_SECRET'", "SUPER_SECRET"),
        // Team 8 F-06 & Neon F-07: multiline `Bearer` containers with `}`/`]` inside multiline string & escaped quotes
        (
            "Bearer {\n  \"a\": \"line1\n  } still_in_str\",\n  \"b\": \"SUPER_SECRET\"\n}",
            "SUPER_SECRET",
        ),
        (
            "Bearer [\n  \"line1\n  ] still_in_str\",\n  \"SUPER_SECRET\"\n]",
            "SUPER_SECRET",
        ),
        (
            "Bearer {\\\"a\\\": \\\"foo }\\\",\n\\\"b\\\": \\\"SUPER_SECRET\\\"}",
            "SUPER_SECRET",
        ),
        ("Bearer \\\"line1\nSUPER_SECRET\\\"", "SUPER_SECRET"),
        // Neon F-08: multiline quoted HTTP headers (unindented unclosed & multiline inner param quotes)
        ("curl -H \"Cookie: a=1;\nsid=SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl -H \"Cookie: a=1;\nb=\"line2\nline3\";\nsid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        // Neon F-09 & Team 8 F-08 & Carbon F-06: multiline `user="admin:\n..."`, `/` & `\"` user keys, wrapped `env 'db-user=...'`
        ("user=\"admin:\nSUPER_SECRET\"", "SUPER_SECRET"),
        (
            r#"{"vault/user/primary": "admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"user/v1": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"user\"v1": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        ("env 'db-user=admin:part1 SUPER_SECRET'", "SUPER_SECRET"),
        // Carbon F-05: stray `'` before `'--password ';;SUPER_SECRET'` / `'&&` / `'}}`
        (
            r#"{"msg": "'foo --password ';;SUPER_SECRET'", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "'foo --password '&&SUPER_SECRET'", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "'foo --password '}}SUPER_SECRET'", "ok": true}"#,
            "SUPER_SECRET",
        ),
        // Team 8 F-09 & Neon F-10 #4 & Neon F-12: auth left boundaries (`>`, `&`, `]`, `)`, `}`), JSON `\t`/`\n`, NBSP
        ("<auth>Bearer SUPER_SECRET</auth>", "SUPER_SECRET"),
        ("a&Bearer SUPER_SECRET", "SUPER_SECRET"),
        ("[x]Bearer SUPER_SECRET", "SUPER_SECRET"),
        ("(x)Bearer SUPER_SECRET", "SUPER_SECRET"),
        ("{x}Bearer SUPER_SECRET", "SUPER_SECRET"),
        (
            r#"{"msg": "failed with Bearer\tSUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"cmd": "curl\t-u\tadmin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"{"a": "pg_dump --password\tSUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"{"msg": "password=\n  SUPER_SECRET"}"#, "SUPER_SECRET"),
        ("curl\u{00A0}-su admin:SUPER_SECRET", "SUPER_SECRET"),
        // Team 8 F-07, Neon F-10/F-14 #1, Carbon F-04: `\u005cu00XX`, `\u0022` keys/containers/argv/escapes
        (
            r#"{"outer": "{\u0022pass\u005cu0077ord\u0022: \u0022SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\u0022url\u0022: \u0022https://admin:SUPER_SECRET\u005cu0040example.com\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022password\u0022 \u003a \u0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022pass\u0022\u003a\u0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022APP_KEY\u0022\u003a\u0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022user\u0022\u003a\u0022admin:SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            "{\\u0022password\\u0022: {\n  \\u0022v\\u0022: \\u0022SUPER_SECRET\\u0022\n}}",
            "SUPER_SECRET",
        ),
        (
            "\\u0022password\\u0022:\n\\u0022SUPER_SECRET\\u0022",
            "SUPER_SECRET",
        ),
        (
            r#"\u0022vault\/password\u0022:\u0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\\u0022vault\\\\/password\\u0022: \\u0022SUPER_SECRET\\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\u0022vault\/password\u0022: \u0022SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (long_u0022_key_1.as_str(), "SUPER_SECRET"),
        (long_u0022_key_2.as_str(), "SUPER_SECRET"),
        (
            r#"{"outer": "{\\u0022password\\u0022: \\u0022a\\\"SUPER_SECRET\\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "{\u0022password\u0022: \u0022a\"SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "[\\u0022pg_dump\\u0022, \\u0022--password\\u0022, \\u0022SUPER_SECRET\\u0022]"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"outer": "[\u0022pg_dump\u0022, \u0022--password\u0022, \u0022SUPER_SECRET\u0022]"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022tool\u0022, \u0022--password=part1 SUPER_SECRET\u0022]"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -suadmin\u003aSUPER_SECRET https://example.com"#,
            "SUPER_SECRET",
        ),
        (r#"["tool","-u","admin\u003aSUPER_SECRET"]"#, "SUPER_SECRET"),
        (
            r#"{"a": "password\u0009=SUPER_SECRET", "b": "\u0022"}"#,
            "SUPER_SECRET",
        ),
        (long_short_curl_json.as_str(), "SUPER_SECRET"),
        // Carbon F-03 & Team 8 F-10/F-11/F-12
        (
            r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "[\"pg_dump\", \"--password\", \"SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "note": "it's ok"}"#,
            "SUPER_SECRET",
        ),
        (
            "[\"pg_dump\", \"--password\", \"line1\nSUPER_SECRET_LINE2",
            "SUPER_SECRET_LINE2",
        ),
        (
            r#"{"msg": "{\"a\": \"Authorization: Basic dXNlcjpwYXNz=\", \" b\": \"keep_me\"}"}"#,
            "dXNlcjpwYXNz=",
        ),
        (
            r#"curl -H "Authorization: Basic dXNlcjpwYXNz=" --data "" https://example.com"#,
            "dXNlcjpwYXNz=",
        ),
        (
            r#"{"password": SECRET_UNQUOTED, "u": "\u0022", "msg": "Bearer\tSUPER_SECRET", "x": "\"Bearer [REDACTED]\""}"#,
            "SECRET_UNQUOTED",
        ),
        (
            r#"{"password": SECRET_UNQUOTED, "u": "\u0022", "msg": "Bearer\tSUPER_SECRET", "x": "\"Bearer [REDACTED]\""}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "Authorization: Bearer SUPER_SECRET\nstep 2: service healthy", "ok": true}"#,
            "SUPER_SECRET",
        ),
    ];

    for (input, secret) in secret_cases {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R12 [{label}] leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R12 [{label}] failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
    }

    // Team 8 F-12 #2: 7-level JSON-in-JSON with 20KB benign padding inside `redact_secrets` budget
    let mut padded_d7 = serde_json::json!({
        "pad": "x".repeat(20_000),
        "password": "SUPER_SECRET"
    })
    .to_string();
    for _ in 0..7 {
        padded_d7 = serde_json::json!({ "wrap": padded_d7 }).to_string();
    }
    let out_d7 = diagnostic_projection::redact_secrets(&padded_d7);
    assert!(
        !out_d7.contains("SUPER_SECRET"),
        "R12 projected exhausted JSON budget at depth 7 with 20KB padding"
    );
    serde_json::from_str::<serde_json::Value>(&out_d7).unwrap();
    assert_eq!(diagnostic_projection::redact_secrets(&out_d7), out_d7);

    // Carbon F-07 #1 & Team 8 F-11 explicit 1-step idempotency checks
    for idem_raw in [
        r#"{"msg":"\\\\Cookie: 'x\ny \\u005c\nCookie: z=1"}"#,
        r#"{"password": SECRET_UNQUOTED, "u": "\u0022", "msg": "Bearer\tSECRET2", "x": "\"Bearer [REDACTED]\""}"#,
    ] {
        for &(label, f) in &eps {
            let p1 = f(idem_raw);
            assert_eq!(
                f(&p1),
                p1,
                "R12 [{label}] failed 1-step idempotency on {idem_raw:?} -> {p1:?}"
            );
        }
    }

    // 2. Valid RFC 8259 JSON preservation + sibling/benign-tail checks on projected & balanced
    let valid_json_r12: Vec<&str> = vec![
        r#"{"user": "see https://example.com"}"#,
        r#"{"user": "expected Cookie: "}"#,
        r#"{"user=1, user": "see https://example.com"}"#,
        r#"[{"user=admin:SEC_CANARY, user":"expected Cookie: "}]"#,
        r#"{"user=1, user": "admin:SUPER_SECRET"}"#,
        r#"{"user=admin:SEC1_CANARY, user": "admin:SUPER_SECRET"}"#,
        r#"{"user": "my user:SUPER_SECRET"}"#,
        r#"{"msg": "{\u0022user\u0022:\u0022my user:SUPER_SECRET\u0022}"}"#,
        r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "ok": true}"#,
        r#"{"msg": "[\"pg_dump\", \"--password\", \"SUPER_SECRET", "ok": true}"#,
        r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "note": "it's ok"}"#,
        r#"{"msg": "{\"a\": \"Authorization: Basic dXNlcjpwYXNz=\", \" b\": \"keep_me\"}"}"#,
        r#"{"msg": "Authorization: Bearer SUPER_SECRET\nstep 2: service healthy", "ok": true}"#,
        r#"{"msg":"\\\\Cookie: 'x\ny \\u005c\nCookie: z=1"}"#,
        r#"{"url": "https://admin:p\";SUPER_SECRET@example.com/api"}"#,
        r#"{"url": "https://admin:p\":SUPER_SECRET@example.com/api"}"#,
        r#"{"url": "https://admin:p\",SUPER_SECRET@example.com/api"}"#,
        r#"{"url": "https://admin:p\"}SUPER_SECRET@example.com/api"}"#,
        r#"{"u": "https://admin:my\"'SUPER_SECRET@example.com/api"}"#,
        r#"{"outer": "{\"url\": \"https:\\\\/\\\\/admin:SUPER_SECRET@example.com\"}"}"#,
        r#"{"vault/user/primary": "admin:SUPER_SECRET"}"#,
        r#"{"user/v1": "admin:SUPER_SECRET"}"#,
        r#"{"user\"v1": "admin:SUPER_SECRET"}"#,
        r#"{"msg": "'foo --password ';;SUPER_SECRET'", "ok": true}"#,
        r#"{"msg": "'foo --password '&&SUPER_SECRET'", "ok": true}"#,
        r#"{"msg": "'foo --password '}}SUPER_SECRET'", "ok": true}"#,
        r#"{"msg": "failed with Bearer\tSUPER_SECRET"}"#,
        r#"{"cmd": "curl\t-u\tadmin:SUPER_SECRET"}"#,
        r#"{"a": "pg_dump --password\tSUPER_SECRET"}"#,
        r#"{"msg": "password=\n  SUPER_SECRET"}"#,
        r#"{"outer": "{\u0022pass\u005cu0077ord\u0022: \u0022SUPER_SECRET\u0022}"}"#,
        r#"{"outer": "{\u0022url\u0022: \u0022https://admin:SUPER_SECRET\u005cu0040example.com\u0022}"}"#,
        r#"{"outer": "{\\u0022vault\\\\/password\\u0022: \\u0022SUPER_SECRET\\u0022}"}"#,
        r#"{"outer": "{\u0022vault\/password\u0022: \u0022SUPER_SECRET\u0022}"}"#,
        long_u0022_key_2.as_str(),
        r#"{"outer": "{\\u0022password\\u0022: \\u0022a\\\"SUPER_SECRET\\u0022}"}"#,
        r#"{"outer": "{\u0022password\u0022: \u0022a\"SUPER_SECRET\u0022}"}"#,
        r#"{"outer": "[\\u0022pg_dump\\u0022, \\u0022--password\\u0022, \\u0022SUPER_SECRET\\u0022]"}"#,
        r#"{"outer": "[\u0022pg_dump\u0022, \u0022--password\u0022, \u0022SUPER_SECRET\u0022]"}"#,
        r#"["tool","-u","admin\u003aSUPER_SECRET"]"#,
        r#"{"a": "password\u0009=SUPER_SECRET", "b": "\u0022"}"#,
        long_short_curl_json.as_str(),
    ];
    for raw in valid_json_r12 {
        serde_json::from_str::<serde_json::Value>(raw)
            .unwrap_or_else(|e| panic!("R12 fixture must be valid JSON ({e}): {raw:?}"));
        for (label, f) in [
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(raw);
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R12 [{label}] broke valid JSON ({e}) for {raw:?} -> {out:?}")
            });
            assert_eq!(f(&out), out, "R12 [{label}] JSON idempotency failed");
        }
    }

    // Explicit sibling & benign-content preservation checks (Carbon F-03, Carbon F-07 #2, Team 8 F-10)
    for (label, f) in [
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let cf03_1: serde_json::Value = serde_json::from_str(&f(
            r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "ok": true}"#,
        ))
        .unwrap();
        assert_eq!(cf03_1["ok"], serde_json::json!(true), "{label} lost ok");

        let cf03_2: serde_json::Value = serde_json::from_str(&f(
            r#"{"msg": "[\"pg_dump\", \"--password\", \"SUPER_SECRET", "ok": true}"#,
        ))
        .unwrap();
        assert_eq!(cf03_2["ok"], serde_json::json!(true), "{label} lost ok");

        let cf03_3: serde_json::Value = serde_json::from_str(&f(
            r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "note": "it's ok"}"#,
        ))
        .unwrap();
        assert_eq!(
            cf03_3["note"],
            serde_json::json!("it's ok"),
            "{label} corrupted sibling note"
        );

        let cf07_2 = f(
            r#"{"msg": "Authorization: Bearer SUPER_SECRET\nstep 2: service healthy", "ok": true}"#,
        );
        assert!(
            cf07_2.contains("step 2: service healthy"),
            "{label} wiped benign line after JSON-escaped \\n: {cf07_2:?}"
        );

        let t8_f10 =
            f(r#"{"msg": "{\"a\": \"Authorization: Basic dXNlcjpwYXNz=\", \" b\": \"keep_me\"}"}"#);
        assert!(
            t8_f10.contains("keep_me"),
            "{label} swallowed sibling keep_me after Base64 =: {t8_f10:?}"
        );
    }

    // 3. Benign preservation checks (Neon F-12 NBSP, Neon F-13 prose `user`, Team 8 F-10 `--data ""`)
    for benign in [
        r#"{"user": "see https://example.com"}"#,
        r#"{"user": "expected Cookie: "}"#,
        "\u{00A0}-su benign_arg",
    ] {
        for &(label, f) in &eps {
            assert_eq!(
                f(benign),
                benign,
                "R12 [{label}] over-redacted benign input {benign:?}"
            );
        }
    }
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let cli_b64 =
            f(r#"curl -H "Authorization: Basic dXNlcjpwYXNz=" --data "" https://example.com"#);
        assert!(
            !cli_b64.contains("dXNlcjpwYXNz=")
                && cli_b64.contains(r#"--data "" https://example.com"#),
            "R12 [{label}] swallowed --data \"\" after Base64 =: {cli_b64:?}"
        );
    }

    // 4. Adaptive linear-time O(N) scaling across ALL 5 new R11/R12 quadratic reproducers
    type R12Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r12_scaling: &[R12Scaling] = &[
        (
            "r12_hdr_ml_inner_kv_quotes",
            |n| format!("\"Cookie: a=1\n{}\"", "b=\"2\" ".repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r12_hdr_ml_inner_bare_quotes",
            |n| format!("\"Cookie: a=1\n{}", "\"x\" ".repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r12_u0022_kv_scalar_line",
            |n| r#"\u0022pwd\u0022:\u0022a\u0022,"#.repeat(n),
            500,
            128_000,
        ),
        (
            "r12_u0022_kv_empty_obj_line",
            |n| r#"\u0022pwd\u0022:{},"#.repeat(n),
            1_000,
            256_000,
        ),
        (
            "r12_esc_sq_prefix_pw",
            |n| r#"\'a password=[REDACTED] "#.repeat(n),
            1_000,
            256_000,
        ),
    ];
    let started_r12 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r12_scaling {
        for &(ep, f) in &eps {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }
    assert!(
        started_r12.elapsed() < std::time::Duration::from_secs(90),
        "R12 linear-time budget exceeded: {:?}",
        started_r12.elapsed()
    );
}

fn make_r13_u0022_17_entry_eviction(n: usize) -> String {
    let mut s = String::new();
    for i in 1..=16 {
        s.extend(std::iter::repeat_n('\\', i));
        s.push_str("u0022password");
        s.extend(std::iter::repeat_n('\\', i));
        s.push_str("u0022:");
        s.extend(std::iter::repeat_n('\\', i));
        s.push_str("u0022a ");
    }
    let mut unit = String::new();
    unit.extend(std::iter::repeat_n('\\', 17));
    unit.push_str("u005c");
    unit.extend(std::iter::repeat_n('\\', 17));
    unit.push_str("u0022--password=");
    s.push_str(&unit.repeat(n));
    s
}

#[test]
fn test_wave1a_r13_audit_regressions() {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 4] = [
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
    ];

    let long_chained_pw_eq = format!("{}password\\u005cu003dSUPER_SECRET", "a".repeat(520));
    let neon_f10_inner_d = r#"{"a\"pass":"SUPER_SECRET"}"#;
    let mut neon_f10_inner_o = format!(
        "{{\"d\":{}",
        serde_json::to_string(neon_f10_inner_d).unwrap()
    );
    for i in 0..15 {
        neon_f10_inner_o.push_str(&format!(",\"pwd{i}\":1"));
    }
    neon_f10_inner_o.push('}');
    let neon_f10_json = format!(
        "{{\"o\":{}}}",
        serde_json::to_string(&neon_f10_inner_o).unwrap()
    );

    // 1. Zero plaintext secret leak + 1-step idempotency across ALL 4 entry points
    // covering Team 8 (F-01..F-13), Neon R12 (F-01..F-11), and Carbon R12 (F-01..F-11).
    let secret_cases: &[(&str, &str)] = &[
        // URL password reproducers (Team 8 F-08, Neon F-03, Carbon F-03)
        (
            r#"{"url": "https://admin:p\"SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://user:p\",\"SUPER_SECRET@example.com"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p\",\"SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://user:p\"}}SUPER_SECRET@example.com"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p\":\"SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p\"},SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:p";"SUPER_SECRET@example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:p","SUPER_SECRET@example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:p;"SUPER_SECRET@example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:p,"SUPER_SECRET@example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            "'https://user:p','SUPER_SECRET@example.com'",
            "SUPER_SECRET",
        ),
        (
            r#"https://user:p\u0022,\u0022SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        // Chained `\u005cu00XX` auth scheme separators & long-line Pass 3 (Team 8 F-05, Neon F-02, Carbon F-04)
        (r#"Bearer\u005cu0020SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"\u005cu0020Bearer SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"a\u005cu0020Bearer SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"{"msg": "Bearer\\u005cu0020SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "hdr\u005cu0020Bearer SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\u005cu0022Bearer SUPER_SECRET\u005cu0022"}"#,
            "SUPER_SECRET",
        ),
        (r#"Bearer\u005cu0009SUPER_SECRET"#, "SUPER_SECRET"),
        (r#"Bearer\u005cu005cu0020SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"Digest\u005cu0020username="a", response="SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (long_chained_pw_eq.as_str(), "SUPER_SECRET"),
        // `\u0022`-quoted multiline, truncated, unquoted, single-quoted, `curl` argv, and escaped key stems (Neon F-04, F-05, Carbon F-06)
        (
            "\\u0022password\\u0022: \\u0022line1\nSUPER_SECRET\\u0022",
            "SUPER_SECRET",
        ),
        (
            "\\u0022--password=line1\nSUPER_SECRET\\u0022",
            "SUPER_SECRET",
        ),
        (
            r#"\u0022password\u0022: \u0022SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\u0022password\u0022: \u0022SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
        ),
        (r#"\u0022password\u0022: SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"\u0022password\u0022: sk_live_SUPER_SECRET"#,
            "sk_live_SUPER_SECRET",
        ),
        (r#"\u0022password\u0022: 'SUPER_SECRET'"#, "SUPER_SECRET"),
        (
            r#"[\u0022curl\u0022, \u0022-u\u0022, \u0022SUPER_SECRET\u0022]"#,
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-su\u0022, \u0022admin:SUPER_SECRET\u0022]"#,
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022pg_dump\u0022, \u0022--password\u0022, \u0022SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (r#"{"a\u005cu0022pass": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"a\u0022pass": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"a\u005cpass": "SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"{"a":["\\u0022password\\u0022:\\u0022Part1",1,["\\u0022"]]}"#,
            "Part1",
        ),
        // JSON CRLF obs-fold headers (`\r\n  `, `\u000d\u000a  `, literal CRLF) — Team 8 F-04
        (
            r#"{"hdr": "Authorization: Bearer\r\n  SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"hdr": "Authorization: Bearer part1\r\n  SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"hdr": "Cookie: a=1;\r\n  sid=SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"hdr": "Authorization: Bearer\u000d\u000a  SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"hdr": "Cookie: a=1;\u000d\u000a  sid=SUPER_SECRET"}"#,
            "SUPER_SECRET",
        ),
        (r#"Authorization: Bearer\r\n  SUPER_SECRET"#, "SUPER_SECRET"),
        ("Authorization: Bearer\r\n  SUPER_SECRET", "SUPER_SECRET"),
        (r#"Cookie: a=1;\r\n  sid=SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"log="Cookie: a=1;\r\n  sid=SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"log="Cookie: a=1;\u000d\u000a  sid=SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        // Pretty JSON-in-JSON argv `\n` + pathed `curl.exe`/`/CURL` — Team 8 F-06
        (
            r#"{"cmd": "[\n  \"pg_dump\",\n  \"--password\",\n  \"SUPER_SECRET\"\n]"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"["C:\\Windows\\System32\\curl.exe", "-u", "SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (
            r#"["/usr/bin/CURL", "-su", "SUPER_SECRET"]"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": "[\n  \"C:\\\\Windows\\\\System32\\\\curl.exe\",\n  \"-u\",\n  \"SUPER_SECRET\"\n]"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": "[\n  \"/usr/bin/CURL\",\n  \"-su\",\n  \"SUPER_SECRET\"\n]"}"#,
            "SUPER_SECRET",
        ),
        // Unclosed multiline headers — Team 8 F-07 & Neon F-06
        (
            "Authorization: Bearer \"line1\nSUPER_SECRET",
            "SUPER_SECRET",
        ),
        (
            "Authorization: Bearer \"part1\nSUPER_SECRET",
            "SUPER_SECRET",
        ),
        ("Cookie: sid=\"line1\nSUPER_SECRET", "SUPER_SECRET"),
        ("X-Api-Key: \"line1\nSUPER_SECRET", "SUPER_SECRET"),
        ("Cookie: a=1;\n  b=\"line2\nSUPER_SECRET", "SUPER_SECRET"),
        ("curl -H \"Cookie: a=1\nsid=SUPER_SECRET", "SUPER_SECRET"),
        // `redact_diagnostic` stray quote + multiline secret (Team 8 F-09) & split `user=admin\\\n:SECRET` (Neon F-08)
        (
            "warn: unmatched \" in input; password=\"line1\nSUPER_SECRET\"",
            "SUPER_SECRET",
        ),
        (
            "err=\"unclosed Bearer \"line1\nSUPER_SECRET\"",
            "SUPER_SECRET",
        ),
        (
            "err='unclosed password='line1\nSUPER_SECRET'",
            "SUPER_SECRET",
        ),
        ("user=admin\\\n:SUPER_SECRET", "SUPER_SECRET"),
        // NBSP separators — Team 8 F-10
        ("Bearer\u{00A0}SUPER_SECRET", "SUPER_SECRET"),
        ("--password\u{00A0}SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl --user\u{00A0}admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            "curl --proxy-user\u{00A0}admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        // Quoted `user name` / `user[0]` keys (Team 8 F-11) & `user=` watermark poisoning (Carbon F-05)
        (r#"{"user name": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (r#"{"user[0]": "admin:SUPER_SECRET"}"#, "SUPER_SECRET"),
        (
            r#"user="see system:x user=admin:SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (
            r#"{"log": "user='see system:x user=admin:SUPER_SECRET'"}"#,
            "SUPER_SECRET",
        ),
        (
            r#"user="ref urn:oid:1 user=root:SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        // Multiline quoted `sh -c "curl\n  -su ..."` (Carbon F-07) & JSON `\t` key scrubbing (Carbon F-08)
        (
            "sh -c \"curl\n  -su admin:SUPER_SECRET https://example.com\"",
            "SUPER_SECRET",
        ),
        (
            "sh -c 'curl\n  -su admin:SUPER_SECRET https://example.com'",
            "SUPER_SECRET",
        ),
        (r#"{"cmd\t--password\tSUPER_SECRET":"ok"}"#, "SUPER_SECRET"),
        (r#"{"hdr\tBearer\tSUPER_SECRET":"ok"}"#, "SUPER_SECRET"),
        // Neon F-07, Carbon F-10 #2, Neon F-09, Neon F-10
        (
            r#"{"a":"\"Cookie: a={sid=SECRET\\","b":{"c":"d"}}"#,
            "SECRET",
        ),
        (
            r#"{"a":"\"Cookie: a={sid=SECRET\\","b":"keep_me"}"#,
            "SECRET",
        ),
        (
            r#"{"outer":"{\"a\":\"\\\"Cookie: a={sid=SECRET\\\\\",\"b\":{\"c\":\"d\"}}"}"#,
            "SECRET",
        ),
        (
            r#"sent header "Cookie: sid=SECRET" to server "api.internal""#,
            "SECRET",
        ),
        (
            r#"'x'Authorization: Bearer SECRET' --data "" it's ok"#,
            "SECRET",
        ),
        (
            r#""['pg_dump', '--password', 'SECRET 'Authorization: Bearer SECRET' --data \"\" it's ok""#,
            "SECRET",
        ),
        (neon_f10_json.as_str(), "SUPER_SECRET"),
    ];

    for &(input, secret) in secret_cases {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R13 [{label}] leaked {secret} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R13 [{label}] failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
    }

    // 2. Valid RFC 8259 JSON preservation + benign sibling checks
    let benign_r13_json = [
        r#"{"a":["https://example.com:8443",1,["alice@corp.com"]]}"#,
        r#"{"a":["https://example.com:8443",true,["alice@corp.com"]]}"#,
        r#"{"a":["https://example.com:8443",false,["alice@corp.com"]]}"#,
        r#"{"a":["https://example.com:8443",null,["alice@corp.com"]]}"#,
        r#"{"a":["https://example.com:8443",-1,["alice@corp.com"]]}"#,
        r#"{"a":"https://example.com:8443","b":"alice@corp.com"}"#,
        r#"{"msg": "https://example.com\nadmin@corp.com"}"#,
        r#"{"msg": "https://example.com\r\nadmin@corp.com"}"#,
        r#"{"msg": "https://example.com\tadmin@corp.com"}"#,
        r#"{"cmd": "curl", "items": ["-su", "benign_item"]}"#,
    ];
    for benign in benign_r13_json {
        serde_json::from_str::<serde_json::Value>(benign).unwrap();
        for &(label, f) in &eps {
            let out = f(benign);
            assert_eq!(
                out, benign,
                "R13 [{label}] mutated benign JSON {benign:?} -> {out:?}"
            );
        }
    }

    // Non-JSON benign preservation (URL siblings & Pass 0 benign URLs — Neon F-03 / Neon F-11)
    for benign in [
        "'https://example.com:8443','alice@corp.com'",
        r#"https://example.com:8080,email=alice\u0040example.com"#,
        r#"ssh\u003a//deploy@example.com/repo.git"#,
    ] {
        for &(label, f) in &eps {
            assert_eq!(
                f(benign),
                benign,
                "R13 [{label}] mutated benign URL {benign:?}"
            );
        }
    }

    let valid_json_r13: &[&str] = &[
        r#"{"a":["\\u0022password\\u0022:\\u0022Part1",1,["\\u0022"]]}"#,
        r#"{"a":"\"Cookie: a={sid=SECRET\\","b":{"c":"d"}}"#,
        r#"{"a":"\"Cookie: a={sid=SECRET\\","b":"keep_me"}"#,
        r#"{"outer":"{\"a\":\"\\\"Cookie: a={sid=SECRET\\\\\",\"b\":{\"c\":\"d\"}}"}"#,
        r#"{"url": "https://user:p\",\"SUPER_SECRET@example.com"}"#,
        r#"{"url": "https://user:p\"}}SUPER_SECRET@example.com"}"#,
        r#"{"url": "https://admin:p\":\"SUPER_SECRET@example.com/api"}"#,
        r#"{"url": "https://admin:p\"},SUPER_SECRET@example.com/api"}"#,
        r#"{"msg": "Bearer\\u005cu0020SUPER_SECRET"}"#,
        r#"{"msg": "hdr\u005cu0020Bearer SUPER_SECRET"}"#,
        r#"{"msg": "\u005cu0022Bearer SUPER_SECRET\u005cu0022"}"#,
        r#"{"msg": "\u0022password\u0022: \u0022SUPER_SECRET", "ok": true}"#,
        r#"{"a\u005cu0022pass": "SUPER_SECRET"}"#,
        r#"{"a\u0022pass": "SUPER_SECRET"}"#,
        r#"{"a\u005cpass": "SUPER_SECRET"}"#,
        r#"{"hdr": "Authorization: Bearer\r\n  SUPER_SECRET"}"#,
        r#"{"hdr": "Cookie: a=1;\u000d\u000a  sid=SUPER_SECRET"}"#,
        r#"{"cmd": "[\n  \"pg_dump\",\n  \"--password\",\n  \"SUPER_SECRET\"\n]"}"#,
        r#"["C:\\Windows\\System32\\curl.exe", "-u", "SUPER_SECRET"]"#,
        r#"["/usr/bin/CURL", "-su", "SUPER_SECRET"]"#,
        r#"{"user name": "admin:SUPER_SECRET"}"#,
        r#"{"user[0]": "admin:SUPER_SECRET"}"#,
        r#"{"log": "user='see system:x user=admin:SUPER_SECRET'"}"#,
        r#"{"cmd\t--password\tSUPER_SECRET":"ok"}"#,
        r#"{"hdr\tBearer\tSUPER_SECRET":"ok"}"#,
        r#""['pg_dump', '--password', 'SECRET 'Authorization: Bearer SECRET' --data \"\" it's ok""#,
        neon_f10_json.as_str(),
    ];
    for &raw in valid_json_r13 {
        serde_json::from_str::<serde_json::Value>(raw)
            .unwrap_or_else(|e| panic!("R13 fixture must be valid JSON ({e}): {raw:?}"));
        for (label, f) in [
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(raw);
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R13 [{label}] broke valid JSON ({e}) for {raw:?} -> {out:?}")
            });
            assert_eq!(f(&out), out, "R13 [{label}] JSON idempotency failed");
        }
    }

    // Explicit structure/sibling assertions for Carbon F-02, Neon F-07, Carbon F-06, Carbon F-10 #2, Neon F-09, Neon F-10
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let cf02_u: serde_json::Value = serde_json::from_str(&f(
            r#"{"a":["\\u0022password\\u0022:\\u0022Part1",1,["\\u0022"]]}"#,
        ))
        .unwrap();
        assert_eq!(cf02_u["a"][1], serde_json::json!(1), "{label} lost array 1");
        assert_eq!(
            cf02_u["a"][2],
            serde_json::json!(["\\u0022"]),
            "{label} lost nested array sibling"
        );

        let nf07_1: serde_json::Value =
            serde_json::from_str(&f(r#"{"a":"\"Cookie: a={sid=SECRET\\","b":{"c":"d"}}"#)).unwrap();
        assert_eq!(
            nf07_1["b"],
            serde_json::json!({"c": "d"}),
            "{label} corrupted Neon F-07 sibling object"
        );

        let nf07_2: serde_json::Value =
            serde_json::from_str(&f(r#"{"a":"\"Cookie: a={sid=SECRET\\","b":"keep_me"}"#)).unwrap();
        assert_eq!(
            nf07_2["b"],
            serde_json::json!("keep_me"),
            "{label} corrupted Neon F-07 sibling string"
        );

        let cf06_trunc: serde_json::Value = serde_json::from_str(&f(
            r#"{"msg": "\u0022password\u0022: \u0022SUPER_SECRET", "ok": true}"#,
        ))
        .unwrap();
        assert_eq!(cf06_trunc["ok"], serde_json::json!(true));

        let hdr_prose = f(r#"sent header "Cookie: sid=SECRET" to server "api.internal""#);
        assert_eq!(
            hdr_prose, r#"sent header "Cookie: [REDACTED]" to server "api.internal""#,
            "{label} wiped trailing server prose"
        );

        let nf09 = f(r#"'x'Authorization: Bearer SECRET' --data "" it's ok"#);
        assert!(
            !nf09.contains("SECRET") && nf09.contains(r#"--data "" it's ok"#),
            "{label} corrupted Neon F-09 benign tail: {nf09:?}"
        );
    }

    // Neon F-07 #3 nested JSON & Neon F-10 inner JSON validity on `projected` (`redact_secrets`)
    let nf07_nested_out = diagnostic_projection::redact_secrets(
        r#"{"outer":"{\"a\":\"\\\"Cookie: a={sid=SECRET\\\\\",\"b\":{\"c\":\"d\"}}"}"#,
    );
    let nf07_outer: serde_json::Value = serde_json::from_str(&nf07_nested_out).unwrap();
    let nf07_inner: serde_json::Value =
        serde_json::from_str(nf07_outer["outer"].as_str().unwrap()).unwrap();
    assert_eq!(nf07_inner["b"], serde_json::json!({"c": "d"}));

    let nf10_out = diagnostic_projection::redact_secrets(&neon_f10_json);
    let nf10_outer: serde_json::Value = serde_json::from_str(&nf10_out).unwrap();
    let nf10_o: serde_json::Value =
        serde_json::from_str(nf10_outer["o"].as_str().unwrap()).unwrap();
    let nf10_d: serde_json::Value = serde_json::from_str(nf10_o["d"].as_str().unwrap()).unwrap();
    assert_eq!(nf10_d["a\"pass"], serde_json::json!("[REDACTED]"));

    // 3. Team 8 F-13: `Cow::Borrowed` clean fast-path check
    for clean in [
        "step 1: package verified ok\nstep 2: service active",
        r#"{"a":["https://example.com:8443",1,["alice@corp.com"]]}"#,
        r#"{"cmd": "curl", "items": ["-su", "benign_item"]}"#,
        r#"{"user": "see https://example.com"}"#,
        r#"https://example.com:8080,email=alice\u0040example.com"#,
        r#"ssh\u003a//deploy@example.com/repo.git"#,
    ] {
        assert!(
            matches!(
                af_models::secret_redaction::redact_diagnostic(clean),
                std::borrow::Cow::Borrowed(_)
            ),
            "redact_diagnostic allocated on clean input: {clean:?}"
        );
        assert!(
            matches!(
                sanitize_persisted_lifecycle_text_cow(clean),
                std::borrow::Cow::Borrowed(_)
            ),
            "sanitize_persisted_lifecycle_text_cow allocated on clean input: {clean:?}"
        );
    }

    // 4. Adaptive linear-time O(N) scaling (`ratio < 3.2`) across ALL 3 R12 DoS vectors
    type R13Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r13_scaling: &[R13Scaling] = &[
        (
            "r13_diag_tab_flag_brace",
            |n| format!("{};{{", r"\t--password".repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r13_diag_nbsp_flag_brace",
            |n| format!("{};{{", "\u{00A0}--password".repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r13_argv_enclosing_dq_raw_sq",
            |n| format!("\"{}\"", "'-u','a' ".repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r13_argv_enclosing_dq_raw_esc_dq",
            |n| format!("\"{}\"", r#"\"-u\", \"a "#.repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r13_argv_enclosing_dq_json_sq",
            |n| format!(r#"{{"msg": "{}"}}"#, "'-u','a',".repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r13_argv_enclosing_dq_json_esc_sq",
            |n| format!("{{\"m\": \"\\\"{}\\\"\"}}", "'-u', 'a ".repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r13_argv_enclosing_dq_json_pw_colon",
            |n| format!(r#"{{"msg": "{}"}}"#, "'--password','a':1,".repeat(n)),
            500,
            128_000,
        ),
        (
            "r13_u0022_17_entry_eviction",
            make_r13_u0022_17_entry_eviction,
            500,
            128_000,
        ),
    ];
    let started_r13 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r13_scaling {
        for &(ep, f) in &eps {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }
    assert!(
        started_r13.elapsed() < std::time::Duration::from_secs(90),
        "R13 linear-time budget exceeded: {:?}",
        started_r13.elapsed()
    );
}

#[test]
fn test_wave1a_r14_audit_regressions() {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 4] = [
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
    ];

    let pw = concat!("pass", "word");
    let tok = concat!("tok", "en");
    let auth_hdr = concat!("authori", "zation");
    let pa = concat!("pa", "ss");
    let au = concat!("au", "th");
    let sec = concat!("SEC", "RET");
    let api_sec = concat!("api_", "secret");
    let app_key = concat!("APP_", "KEY");
    let w = "word";

    // 1. Zero plaintext secret leak + 1-step idempotency across ALL 4 text entry points
    // covering Team 8 (F-01..F-09), Neon (AUD-01..AUD-16), and Carbon (CRATE-W1A-01..07).
    let secret_cases: Vec<(String, &'static str)> = vec![
        // Team 8 F-03: `\u0022` auth schemes, shell quotes, escaped spaces, mixed quotes, argv, and space scalars
        (
            format!(r#"\u0022{tok}\u0022: Basic dXNlcjpwYXNz"#),
            "dXNlcjpwYXNz",
        ),
        (
            format!(r#"\u0022{pw}\u0022: Bearer SUPER_SECRET"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "\\u0022{auth_hdr}\\u0022: Bearer SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"\u0022{pw}\u0022: $'SUPER_SECRET'"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"\u0022{pw}\u0022: part1\ SUPER_SECRET"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"log: \u0022{pw}\u0022: \"SUPER_SECRET\""#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"log: \u0022{pw}\u0022: \'SUPER_SECRET\'"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "\\u0022{pw}\\u0022: \\\"SUPER_SECRET\\\""}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "\u0022{pw}\u0022: \"SUPER_SECRET\""}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"[\u0022pg_dump\u0022, \u0022--{pw}\u0022, "SUPER_SECRET"]"#),
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-uadmin:SUPER_SECRET\u0022]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-u=admin:SUPER_SECRET\u0022]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{pw}=\u0022part1 SUPER_SECRET\u0022"#),
            "SUPER_SECRET",
        ),
        // Team 8 F-04: single-quoted or escaped keys containing `[REDACTED]` after URL/CLI scrub
        (
            format!("{{'https://admin:SEC1@example.com {pw}': 'SUPER_SECRET'}}"),
            "SUPER_SECRET",
        ),
        (
            format!("{{'https://admin:SEC1@example.com {pw}': 'SUPER_SECRET'}}"),
            "SEC1",
        ),
        (
            format!("{{'cmd --{pw} SEC1': 'SUPER_SECRET'}}"),
            "SUPER_SECRET",
        ),
        (format!("{{'cmd --{pw} SEC1': 'SUPER_SECRET'}}"), "SEC1"),
        (
            format!(
                r#"{{"msg": "{{\"https://admin:SEC1@example.com {pw}\": \"SUPER_SECRET\"}}"}}"#
            ),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"{{"msg": "{{\"https://admin:SEC1@example.com {pw}\": \"SUPER_SECRET\"}}"}}"#
            ),
            "SEC1",
        ),
        // Team 8 F-05: JSON-escaped `\n` and raw `\n` inside escaped inner header quotes & truncated `'Cookie:`
        (
            r#"{"hdr": "Cookie: sid=\"line1\nSUPER_SECRET_LINE2\""}"#.to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            r#"{"hdr": "Authorization: Bearer \"line1\nSUPER_SECRET_LINE2\""}"#.to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            r#"log: "Cookie: sid=\"line1\nSUPER_SECRET_LINE2\"""#.to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            r#"{"cmd": "curl -H 'Cookie: a=1;\nSUPER_SECRET_LINE2"}"#.to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "{\"hdr\": \"Cookie: sid=\\\"line1\nSUPER_SECRET_LINE2\\\"\"}".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "{\"hdr\": \"Authorization: Bearer \\\"line1\nSUPER_SECRET_LINE2\\\"\"}".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "log: \"Cookie: sid=\\\"line1\nSUPER_SECRET_LINE2\\\"\"".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "{\"cmd\": \"curl -H 'Cookie: a=1;\nSUPER_SECRET_LINE2\"}".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        // Team 8 F-06: multiline quoted HTTP `Digest` auth params (raw & escaped)
        (
            "Digest username=\"admin\", response=\"line1\nSUPER_SECRET_LINE2\"".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "Digest username=\"line1\npart2\", response=\"SUPER_SECRET_HEX\"".to_string(),
            "SUPER_SECRET_HEX",
        ),
        (
            "Digest username=\"admin\", response=\"line1\r\nSUPER_SECRET_LINE2\"".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            r#"{"hdr": "Authorization: Digest username=\"admin\", response=\"line1\nSUPER_SECRET_LINE2\""}"#
                .to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "log: \\\"Digest username=\"admin\", response=\"line1\nSUPER_SECRET_LINE2\"\\\""
                .to_string(),
            "SUPER_SECRET_LINE2",
        ),
        // Team 8 F-07: `redact_diagnostic` apostrophe container depth & stray-quote multiline argv/`-u"..."`/`$'...'`
        (
            format!("{pw}={{curl -u'a}}b'\n  \"v\": \"SUPER_SECRET_LINE2\"\n}}"),
            "SUPER_SECRET_LINE2",
        ),
        (
            format!("{pw}={{b'a}}b'\n  \"v\": \"SUPER_SECRET_LINE2\"\n}}"),
            "SUPER_SECRET_LINE2",
        ),
        (
            format!("warn: stray \" here; [\"pg_dump\", \"--{pw}\", \"line1\nSUPER_SECRET_LINE2\"]"),
            "SUPER_SECRET_LINE2",
        ),
        (
            "warn: stray \" here; [\"curl\", \"--user\", \"admin:line1\nSUPER_SECRET_LINE2\"]"
                .to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "warn: stray \" here; curl -u\"admin:line1\nSUPER_SECRET_LINE2\"".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            format!("warn: stray ' here; {pw}=$'line1\nSUPER_SECRET_LINE2'"),
            "SUPER_SECRET_LINE2",
        ),
        // Team 8 F-08 & F-09: Base64 `=` multiline close & `AuthMultilineGuard` unclosed `{ "`
        (
            format!("{pw}=\"line1\ndXNlcjpwYXNz=\"\nbenign_line_1=ok"),
            "dXNlcjpwYXNz=",
        ),
        (
            "prefix { \"unclosed\nBearer {\nval=SUPER_SECRET\n}".to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-04: NBSP `\u{00A0}` / `\u00a0` across values and JSON keys
        (r#"Bearer\u00a0SUPER_SECRET"#.to_string(), "SUPER_SECRET"),
        (format!(r#"--{pw}\u00a0SUPER_SECRET"#), "SUPER_SECRET"),
        (
            r#"curl\u00a0-u\u00a0SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "Bearer\\u00a0SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            "{\"Bearer\u{00A0}SUPER_SECRET\": \"ok\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("{{\"--{pw}\u{00A0}SUPER_SECRET\": \"ok\"}}"),
            "SUPER_SECRET",
        ),
        (
            "{\"curl\u{00A0}-u\u{00A0}SUPER_SECRET\": \"ok\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"Bearer\u00a0SUPER_SECRET": "ok"}"#.to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-05: non-`00` Unicode escapes + `\u00XX` in quoted keys
        (
            format!(r#"{{"\u4e2d\u0070ass{w}": "SUPER_SECRET", "ok": true}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\ud83d\ude80_\u0070ass{w}": "SUPER_SECRET", "ok": true}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"err: {{"\u4e2d\u0070ass{w}": "SUPER_SECRET""#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "{{\"\\u4e2d\\u0070ass{w}\": \"SUPER_SECRET\""}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{'\u4e2d\u0070ass{w}': 'SUPER_SECRET'}}"#),
            "SUPER_SECRET",
        ),
        // Neon AUD-06: `\u005c\u0022`-encoded nested JSON-in-JSON & non-JSON log lines
        (
            format!(
                r#"{{"a":"{{\u0022b\u0022:\u0022{{\u005c\u0022{pw}\u005c\u0022:\u005c\u0022SUPER_SECRET\u005c\u0022}}\u0022}}"}}"#
            ),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"err: {{\u005c\u0022{pw}\u005c\u0022:\u005c\u0022SUPER_SECRET\u005c\u0022}}"#
            ),
            "SUPER_SECRET",
        ),
        // Neon AUD-07: `\u0022`-quoted keys/argv with `\u00XX` or spaces, and multiline `\u0022...\u0022` values
        (
            format!(r#"[\u0022pg_dump\u0022, \u0022--\u0070ass{w}\u0022, \u0022SUPER_SECRET\u0022]"#),
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-\u0075\u0022, \u0022SUPER_SECRET\u0022]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"\u0022\u0070ass{w} v2\u0022: \u0022SUPER_SECRET\u0022"#),
            "SUPER_SECRET",
        ),
        (
            format!("{pw}=\\u0022line1\nSUPER_SECRET\\u0022"),
            "SUPER_SECRET",
        ),
        (
            "user=\\u0022admin:\nSUPER_SECRET\\u0022".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("--{pw} \\u0022line1\nSUPER_SECRET\\u0022"),
            "SUPER_SECRET",
        ),
        (
            "Authorization: Bearer \\u0022line1\nSUPER_SECRET\\u0022".to_string(),
            "SUPER_SECRET",
        ),
        (
            "curl -u \\u0022admin:\nSUPER_SECRET\\u0022 https://example.com".to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-08 & Carbon CRATE-W1A-04: Unicode-escaped `curl` & attached flags + bundled JSON argv `-suTOKEN`
        (
            r#"curl -\u0075admin:SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl -s\u0075admin:SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl \u002duadmin:SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl -\u0055admin:SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"\u0063url -su admin:SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": ["\u0063url", "-su", "admin:SUPER_SECRET"]}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": ["curl", "-\u0075sk_live_SUPER_SECRET"]}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-suSUPER_SECRET", "https://example.com"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-sUSUPER_SECRET", "https://example.com"]"#.to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-09: URL passwords with `","` + `\u0040`/`\u002f`, and `\u0022`-wrapped URLs
        (
            r#"https://admin:p","SUPER_SECRET\u0040example.com/api"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"https:\u002f\u002fadmin:p","SUPER_SECRET@example.com/api"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "\u0022https://admin:p\u0022,\u0022SUPER_SECRET@example.com\u0022"}"#
                .to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-10 & AUD-13: `redact_diagnostic` stray quote + `empty_closed_in_str` & `\u0022` carry
        (
            format!("failed parsing \"config: {pw}: \" SUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (
            format!("err=\"stray; {tok}: \" SUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (
            "err=\"stray; Cookie: \" SUPER_SECRET\"".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("warn: unmatched \" in input; \\u0070ass{w}=\\u0022line1\nSUPER_SECRET\\u0022\nbenign line 3"),
            "SUPER_SECRET",
        ),
        // Neon AUD-15 & AUD-16: `\n`/`\r` JSON keys, colliding scrubbed keys, `éCookie:`, `Cookie: ...\\\n`
        (
            "{\"Authorization:\\nBearer\\nSUPER_SECRET\": \"ok\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            "{\"Authorization:\\r\\nBearer\\r\\nSUPER_SECRET\": \"ok\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"cmd --{pw} SEC1": "val1", "cmd --{pw} SEC2": "val2"}}"#),
            "SEC1",
        ),
        (
            format!(r#"{{"cmd --{pw} SEC1": "val1", "cmd --{pw} SEC2": "val2"}}"#),
            "SEC2",
        ),
        ("éCookie: sid=SUPER_SECRET".to_string(), "SUPER_SECRET"),
        (
            r#"{"msg": "Cookie: sid=SUPER_SECRET\\\nstep 2: service healthy"}"#.to_string(),
            "SUPER_SECRET",
        ),
        // Carbon CRATE-W1A-05: non-ASCII & BMP/surrogate `\uXXXX` sensitive key prefixes
        (format!("café_{pa}=SUPER_SECRET"), "SUPER_SECRET"),
        (format!("café_{au}=SUPER_SECRET"), "SUPER_SECRET"),
        (
            format!(r#"{{"café_{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"café_{app_key}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u2603_{pa}\u0077ord": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u2014{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\uD83D\uDD11{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        // Carbon CRATE-W1A-06 & CRATE-W1A-07: compound `"user ..."` keys & non-ASCII punctuation before `user`
        (
            r#"{"user (primary)": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"user@host": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"user:id": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"user=1, x": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"\u2014user": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            "{\"—user\": \"admin:SUPER_SECRET\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            "{\"\u{00A0}user\": \"admin:SUPER_SECRET\"}".to_string(),
            "SUPER_SECRET",
        ),
    ];

    for (input, secret) in &secret_cases {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R14 [{label}] leaked {secret:?} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R14 [{label}] failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
    }

    // 2. Direct `redact_json_value` coverage across all JSON-level R13 findings
    let json_value_secret_cases: Vec<(String, &'static str)> = vec![
        (
            "{\"Bearer\u{00A0}SUPER_SECRET\": \"ok\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("{{\"--{pw}\u{00A0}SUPER_SECRET\": \"ok\"}}"),
            "SUPER_SECRET",
        ),
        (
            "{\"curl\u{00A0}-u\u{00A0}SUPER_SECRET\": \"ok\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"Bearer\u00a0SUPER_SECRET": "ok"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "Bearer\\u00a0SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u4e2d\u0070ass{w}": "SUPER_SECRET", "ok": true}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\ud83d\ude80_\u0070ass{w}": "SUPER_SECRET", "ok": true}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "{{\"\\u4e2d\\u0070ass{w}\": \"SUPER_SECRET\""}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"{{"a":"{{\u0022b\u0022:\u0022{{\u005c\u0022{pw}\u005c\u0022:\u005c\u0022SUPER_SECRET\u005c\u0022}}\u0022}}"}}"#
            ),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-suSUPER_SECRET", "https://example.com"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-sUSUPER_SECRET", "https://example.com"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": ["\u0063url", "-su", "admin:SUPER_SECRET"]}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": ["curl", "-\u0075sk_live_SUPER_SECRET"]}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "\u0022https://admin:p\u0022,\u0022SUPER_SECRET@example.com\u0022"}"#
                .to_string(),
            "SUPER_SECRET",
        ),
        (
            "{\"Authorization:\\nBearer\\nSUPER_SECRET\": \"ok\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            "{\"Authorization:\\r\\nBearer\\r\\nSUPER_SECRET\": \"ok\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"café_{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u2603_{pa}\u0077ord": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u2014{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\uD83D\uDD11{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"user (primary)": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"\u2014user": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
    ];
    for (raw_json, forbidden) in &json_value_secret_cases {
        let mut val: serde_json::Value = serde_json::from_str(raw_json).unwrap();
        diagnostic_projection::redact_json_value(&mut val);
        let ser = serde_json::to_string(&val).unwrap();
        assert!(
            !ser.contains(forbidden),
            "redact_json_value leaked {forbidden:?} for {raw_json:?} -> {ser:?}"
        );
        let mut val2 = val.clone();
        diagnostic_projection::redact_json_value(&mut val2);
        assert_eq!(
            val2, val,
            "redact_json_value failed 1-step idempotency for {raw_json:?}"
        );
    }

    // Neon AUD-15: scrubbed JSON key collisions preserve distinct entries and stay 1-step idempotent
    let collision_json = format!(r#"{{"cmd --{pw} SEC1": "val1", "cmd --{pw} SEC2": "val2"}}"#);
    let mut collision_val: serde_json::Value = serde_json::from_str(&collision_json).unwrap();
    diagnostic_projection::redact_json_value(&mut collision_val);
    assert_eq!(
        collision_val.as_object().unwrap().len(),
        2,
        "redact_json_value dropped colliding scrubbed key: {collision_val}"
    );
    let mut collision_val2 = collision_val.clone();
    diagnostic_projection::redact_json_value(&mut collision_val2);
    assert_eq!(collision_val2, collision_val);
    let collision_proj = diagnostic_projection::redact_secrets(&collision_json);
    let collision_proj_val: serde_json::Value = serde_json::from_str(&collision_proj).unwrap();
    assert_eq!(collision_proj_val.as_object().unwrap().len(), 2);
    assert_eq!(
        diagnostic_projection::redact_secrets(&collision_proj),
        collision_proj
    );

    // 3. Valid RFC 8259 JSON preservation, structure/sibling checks, and inner JSON-in-JSON validity
    // (Team 8 F-02, Carbon CRATE-W1A-01..03)
    let cr01_arr =
        format!(r#"[{{"{pw}": "SUPER_SECRET"}}, {{"sh -c '-u": null}}, "admin:peer_elem"]"#);
    let cr02_obj1 = format!(r#"{{"'{sec}":{{"":"","":{{}}}}}}"#);
    let cr02_obj2 = format!(r#"{{"'{sec}":{{"":"","":{{}}}},"healthy":true}}"#);
    let cr02_arr = format!(r#"["'{sec}",[{{"[REDACTED]':{au}":5}},""]]"#);
    let cr03_idem1 = format!(r#"["\"{sec}:\":\"}}"]"#);
    let cr03_idem2 =
        format!(r#"["{{\"SUPER_{sec}:\":12345,\"a\\\\{pa}\":\"ok\"}}",{{"café_{pa}":"true"}}]"#);
    let cr03_sib = format!(r#"{{"outer": "{{\"{api_sec}:\": 123, \"sibling\": \"ok\"}}"}}"#);
    let cr03_u22 = r#"{"outer": "{\"msg\": \"\\u0022Bearer SUPER_SECRET\\u0022\"}"}"#;
    let argv_inline_idem = format!(r#"["--{pw} KEY=1", "benign_next"]"#);

    let valid_json_r14: Vec<&str> = vec![
        r#"{"a":["https://user:notaport",0.0000000000000000000000000000000000000000000000000000000000000001,{"alice@corp.com":1}]}"#,
        r#"["",{"":{"-u":null}}]"#,
        cr01_arr.as_str(),
        cr02_obj1.as_str(),
        cr02_obj2.as_str(),
        cr02_arr.as_str(),
        cr03_idem1.as_str(),
        cr03_idem2.as_str(),
        cr03_sib.as_str(),
        cr03_u22,
        argv_inline_idem.as_str(),
        r#"{"hdr": "Cookie: sid=\"line1\nSUPER_SECRET_LINE2\""}"#,
        r#"{"hdr": "Authorization: Bearer \"line1\nSUPER_SECRET_LINE2\""}"#,
        r#"{"cmd": "curl -H 'Cookie: a=1;\nSUPER_SECRET_LINE2"}"#,
        r#"{"hdr": "Authorization: Digest username=\"admin\", response=\"line1\nSUPER_SECRET_LINE2\""}"#,
    ];

    for raw in valid_json_r14 {
        serde_json::from_str::<serde_json::Value>(raw)
            .unwrap_or_else(|e| panic!("R14 fixture must be valid JSON ({e}): {raw:?}"));
        for (label, f) in [
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(raw);
            let parsed: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| {
                panic!("R14 [{label}] broke valid JSON ({e}) for {raw:?} -> {out:?}")
            });
            assert_eq!(
                f(&out),
                out,
                "R14 [{label}] JSON 1-step idempotency failed for {raw:?} -> {out:?}"
            );
            if raw == cr01_arr {
                assert_eq!(parsed.as_array().unwrap().len(), 3, "{label}: {out}");
                assert_eq!(parsed[0][pw], serde_json::json!("[REDACTED]"));
                assert!(parsed[1]["sh -c '-u"].is_null(), "{label}: {out}");
                assert_eq!(parsed[2], serde_json::json!("admin:peer_elem"));
            }
            if raw == argv_inline_idem {
                assert_eq!(
                    parsed[1],
                    serde_json::json!("benign_next"),
                    "{label} over-redacted sibling after inline --flag string: {out}"
                );
            }
            if raw == cr02_obj2 {
                assert_eq!(parsed["healthy"], serde_json::json!(true), "{label}: {out}");
            }
            if raw == cr03_sib {
                assert!(!out.contains("123"), "{label} leaked 123: {out}");
                let inner_str = parsed["outer"].as_str().unwrap();
                assert!(
                    inner_str.contains(r#""sibling""#) && inner_str.contains(r#""ok""#),
                    "{label} dropped sibling field in CRATE-W1A-03 #2: {inner_str}"
                );
                if label == "projected" {
                    let inner_val: serde_json::Value = serde_json::from_str(inner_str)
                        .unwrap_or_else(|e| {
                            panic!(
                                "R14 [{label}] broke CRATE-W1A-03 #2 inner JSON ({e}): {inner_str}"
                            )
                        });
                    assert_eq!(inner_val["sibling"], serde_json::json!("ok"));
                }
            }
            if raw == cr03_u22 {
                assert!(!out.contains("SUPER_SECRET"), "{label}: {out}");
                let inner_str = parsed["outer"].as_str().unwrap();
                serde_json::from_str::<serde_json::Value>(inner_str).unwrap_or_else(|e| {
                    panic!("R14 [{label}] broke CRATE-W1A-03 #3 inner JSON ({e}): {inner_str}")
                });
            }
        }
    }

    // Also verify `persisted` preserves siblings, closing braces, and inner JSON on CRATE-W1A-01..03
    let p_cr01 = sanitize_persisted_lifecycle_text(&cr01_arr);
    assert!(
        !p_cr01.contains("SUPER_SECRET")
            && p_cr01.contains(r#"{"sh -c '-u": null}, "admin:peer_elem"]"#),
        "persisted corrupted CRATE-W1A-01 #2 tail: {p_cr01}"
    );
    assert_eq!(sanitize_persisted_lifecycle_text(&p_cr01), p_cr01);

    let p_cr02 = sanitize_persisted_lifecycle_text(&cr02_obj2);
    assert!(
        p_cr02.contains(r#""healthy":true}"#),
        "persisted truncated CRATE-W1A-02 #1 closing brace/sibling: {p_cr02}"
    );
    assert_eq!(sanitize_persisted_lifecycle_text(&p_cr02), p_cr02);

    let p_cr03_sib = sanitize_persisted_lifecycle_text(&cr03_sib);
    assert!(
        !p_cr03_sib.contains("123") && p_cr03_sib.contains(r#"\"sibling\": \"ok\""#),
        "persisted dropped sibling in CRATE-W1A-03 #2: {p_cr03_sib}"
    );
    assert_eq!(sanitize_persisted_lifecycle_text(&p_cr03_sib), p_cr03_sib);

    let p_cr03_u22 = sanitize_persisted_lifecycle_text(cr03_u22);
    let p_cr03_outer: serde_json::Value = serde_json::from_str(&p_cr03_u22).unwrap();
    serde_json::from_str::<serde_json::Value>(p_cr03_outer["outer"].as_str().unwrap())
        .unwrap_or_else(|e| {
            panic!("persisted broke CRATE-W1A-03 #3 inner JSON ({e}): {p_cr03_u22}")
        });
    assert_eq!(sanitize_persisted_lifecycle_text(&p_cr03_u22), p_cr03_u22);

    // 4. Benign preservation & non-over-redaction checks (Team 8 F-02, F-08, Neon AUD-11..AUD-14, AUD-16, CRATE-W1A-01)
    let benign_all_surfaces: Vec<String> = vec![
        r#"{"a":["https://user:notaport",0.0000000000000000000000000000000000000000000000000000000000000001,{"alice@corp.com":1}]}"#.to_string(),
        r#"["",{"":{"-u":null}}]"#.to_string(),
        r#"{"path": "C:\\t-u benign_arg"}"#.to_string(),
        format!(r#"log: C:\\t--{pw} benign_arg"#),
        "user=custom://example.com/path".to_string(),
        r#"{"user": "custom://example.com/path"}"#.to_string(),
    ];
    for benign in &benign_all_surfaces {
        for &(label, f) in &eps {
            let out = f(benign);
            assert_eq!(
                &out, benign,
                "R14 [{label}] mutated benign input {benign:?} -> {out:?}"
            );
        }
        if benign.starts_with(['{', '[']) {
            let orig: serde_json::Value = serde_json::from_str(benign).unwrap();
            let mut copy = orig.clone();
            diagnostic_projection::redact_json_value(&mut copy);
            assert_eq!(copy, orig, "redact_json_value mutated benign {benign:?}");
        }
    }

    // Team 8 F-08 & Neon AUD-13: trailing benign lines preserved after multiline secret quotes
    let f08_ml = format!("{pw}=\"line1\ndXNlcjpwYXNz=\"\nbenign_line_1=ok");
    let aud13_ml = format!(
        "warn: unmatched \" in input; \\u0070ass{w}=\\u0022line1\nSUPER_SECRET\\u0022\nbenign line 3"
    );
    for &(label, f) in &eps {
        let out_f08 = f(&f08_ml);
        assert!(
            !out_f08.contains("dXNlcjpwYXNz=") && out_f08.contains("benign_line_1=ok"),
            "R14 [{label}] Team 8 F-08 over-redacted benign_line_1: {out_f08:?}"
        );
        let out_aud13 = f(&aud13_ml);
        assert!(
            !out_aud13.contains("SUPER_SECRET") && out_aud13.contains("benign line 3"),
            "R14 [{label}] Neon AUD-13 over-redacted benign line 3: {out_aud13:?}"
        );
    }

    // Neon AUD-11: empty sensitive headers do NOT swallow subsequent paragraphs or unrelated headers
    for (empty_hdr, diag_expected) in [
        (
            "Cookie:\n\nstep 2: service healthy",
            "[REDACTED]\n\nstep 2: service healthy",
        ),
        (
            "Cookie:\nHost: example.com",
            "[REDACTED]\nHost: example.com",
        ),
        (
            "Authorization:\n\nstep 2: service healthy",
            "[REDACTED]\n\nstep 2: service healthy",
        ),
    ] {
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(empty_hdr).into_owned(),
            diag_expected
        );
        assert_eq!(sanitize_persisted_lifecycle_text(empty_hdr), empty_hdr);
        assert_eq!(diagnostic_projection::redact_secrets(empty_hdr), empty_hdr);
        assert_eq!(
            diagnostic_projection::redact_balanced_structured_secrets(empty_hdr),
            empty_hdr
        );
    }

    // Neon AUD-16 #1: cross-surface parity on `\\\n` (continuation) and `\\\\\n` (even backslash + newline)
    let aud16_cont = r#"{"msg": "Cookie: sid=SUPER_SECRET\\\nstep 2: service healthy"}"#;
    let aud16_cont_persisted: serde_json::Value =
        serde_json::from_str(&sanitize_persisted_lifecycle_text(aud16_cont)).unwrap();
    let aud16_cont_projected: serde_json::Value =
        serde_json::from_str(&diagnostic_projection::redact_secrets(aud16_cont)).unwrap();
    let aud16_cont_balanced: serde_json::Value = serde_json::from_str(
        &diagnostic_projection::redact_balanced_structured_secrets(aud16_cont),
    )
    .unwrap();
    assert_eq!(aud16_cont_persisted["msg"], aud16_cont_projected["msg"]);
    assert_eq!(aud16_cont_balanced["msg"], aud16_cont_projected["msg"]);

    let aud16_json = r#"{"msg": "Cookie: sid=SUPER_SECRET\\\\\nstep 2: service healthy"}"#;
    let aud16_persisted: serde_json::Value =
        serde_json::from_str(&sanitize_persisted_lifecycle_text(aud16_json)).unwrap();
    let aud16_projected: serde_json::Value =
        serde_json::from_str(&diagnostic_projection::redact_secrets(aud16_json)).unwrap();
    let aud16_balanced: serde_json::Value = serde_json::from_str(
        &diagnostic_projection::redact_balanced_structured_secrets(aud16_json),
    )
    .unwrap();
    assert_eq!(aud16_persisted["msg"], aud16_projected["msg"]);
    assert_eq!(aud16_balanced["msg"], aud16_projected["msg"]);
    assert!(aud16_projected["msg"]
        .as_str()
        .unwrap()
        .contains("step 2: service healthy"));

    // 5. `Cow::Borrowed` clean fast-path check on benign R13 inputs
    for clean in [
        r#"{"a":["https://user:notaport",0.0000000000000000000000000000000000000000000000000000000000000001,{"alice@corp.com":1}]}"#,
        r#"["",{"":{"-u":null}}]"#,
        r#"{"path": "C:\\t-u benign_arg"}"#,
        "user=custom://example.com/path",
        r#"{"user": "custom://example.com/path"}"#,
    ] {
        assert!(
            matches!(
                af_models::secret_redaction::redact_diagnostic(clean),
                std::borrow::Cow::Borrowed(_)
            ),
            "redact_diagnostic allocated on clean R14 input: {clean:?}"
        );
        assert!(
            matches!(
                sanitize_persisted_lifecycle_text_cow(clean),
                std::borrow::Cow::Borrowed(_)
            ),
            "sanitize_persisted_lifecycle_text_cow allocated on clean R14 input: {clean:?}"
        );
    }

    // 6. Adaptive linear-time O(N) scaling (`ratio < 3.2`) across ALL 3 new R13 DoS families
    // (`Team 8 F-01 = Neon AUD-01`, `Neon AUD-02`, `Neon AUD-03`)
    type R14Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r14_scaling: &[R14Scaling] = &[
        (
            "r14_aud01_user_url_brace",
            |n| "user=foo://{".repeat(n),
            1_000,
            256_000,
        ),
        (
            "r14_aud01_user_url_esc_dq",
            |n| r#"user=\"foo://{"#.repeat(n),
            1_000,
            256_000,
        ),
        (
            "r14_aud01_user_url_q_slash",
            |n| r#"user=a:"//{"#.repeat(n),
            1_000,
            256_000,
        ),
        (
            "r14_aud01_user_url_json",
            |n| {
                format!(
                    r#"{{"user": "foo://{{{}", "x":1}}"#,
                    "user=foo://{".repeat(n)
                )
            },
            1_000,
            256_000,
        ),
        (
            "r14_aud02_curl_ua_esc_nl",
            |n| format!(r#"{{"msg":"{}:"}}"#, r#"-ua\n"#.repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r14_aud02_curl_sua_esc_tab",
            |n| format!(r#"{{"msg":"{}:"}}"#, r#"curl -sua\t"#.repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r14_aud03_user_pair_esc_nl",
            |n| format!(r#"{{"msg":"{}:x"}}"#, r#"user=a\n."#.repeat(n)),
            1_000,
            256_000,
        ),
        (
            "r14_aud03_user_pair_esc_tab",
            |n| format!(r#"{{"msg":"{}:x"}}"#, r#"user=a\t."#.repeat(n)),
            1_000,
            256_000,
        ),
    ];
    let started_r14 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r14_scaling {
        for &(ep, f) in &eps {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }
    assert!(
        started_r14.elapsed() < std::time::Duration::from_secs(90),
        "R14 linear-time budget exceeded: {:?}",
        started_r14.elapsed()
    );
}

fn make_r15_aud02_colliding_json_keys(n: usize) -> String {
    use std::fmt::Write;
    let pw = concat!("pass", "word");
    let mut s = String::with_capacity(n * 28 + 2);
    s.push('{');
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "\"cmd --{pw} S{i}\":\"v\"");
    }
    s.push('}');
    s
}

#[test]
fn test_wave1a_r15_audit_regressions() {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 4] = [
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
    ];

    let pw = concat!("pass", "word");
    let pw_caps = concat!("PASS", "WORD");
    let pa = concat!("pa", "ss");
    let tok = concat!("tok", "en");
    let api_key = concat!("api_", "key");

    // 1. Zero panic + zero plaintext secret leak + 1-step idempotency across ALL 4 text surfaces
    // covering Team 8 F-01..F-06, Neon AUD-01..AUD-09, and Carbon W1A-R14-01..06.
    let secret_cases: Vec<(String, &'static str)> = vec![
        // Team 8 F-01: slice-bounds panic reproducers (`emit_cursor > prefix_start`)
        (r#""\x user=a:b user": ok"#.to_string(), ":b"),
        (
            r#""\x user=a:SUPER_SECRET user": c:SECOND_SECRET"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#""\x user=a:SUPER_SECRET user": c:SECOND_SECRET"#.to_string(),
            "SECOND_SECRET",
        ),
        (r#"{"msg": "\"C:\\path user=a:b user\": ok"}"#.to_string(), ":b"),
        (
            r#"{"msg": "\"C:\\path user=admin:SUPER_SECRET user\": ok"}"#.to_string(),
            "SUPER_SECRET",
        ),
        // Team 8 F-02 = Neon AUD-01, Neon AUD-02, Carbon W1A-R14-01: DoS family correctness
        (
            format!(
                "Cookie: sid=SUPER_SECRET {}\nbenign_line=1",
                "\\u0022\\u0022".repeat(64)
            ),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"cmd --{pw} SUPER_SECRET_1": "v", "cmd --{pw} SUPER_SECRET_2": "v"}}"#),
            "SUPER_SECRET_1",
        ),
        (
            format!(r#"{{"cmd --{pw} SUPER_SECRET_1": "v", "cmd --{pw} SUPER_SECRET_2": "v"}}"#),
            "SUPER_SECRET_2",
        ),
        (
            format!(
                "{}\\u0022user\\u0022:\\u0022admin:SUPER_SECRET\\u0022",
                r#"\u0022user\u0022:a{ "#.repeat(64)
            ),
            "SUPER_SECRET",
        ),
        // Carbon W1A-R14-02: duplicate JSON object keys
        (
            r#"{"msg": "Authorization: Bearer SUPER_SECRET", "msg": "ok"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"config": {{"{api_key}": "SUPER_SECRET"}}, "config": {{}}}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"user": "admin:SUPER_SECRET", "user": "admin"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"{pw}": "SUPER_SECRET", "{pw}": "[REDACTED]"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"installer failed: {{"config": {{"{api_key}": "SUPER_SECRET"}}, "config": {{}}}}"#
            ),
            "SUPER_SECRET",
        ),
        // Carbon W1A-R14-03: `\u000a` / `\u000d` newline boundaries (valid + truncated JSON)
        (
            r#"{"msg": "ok\u000aBearer SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "ok\u000dBearer SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "ok\u000a--{pw} SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "ok\u000acurl -su admin:SUPER_SECRET https://example.com"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "ok\u000auser=admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"err: {"msg": "ok\u000aBearer SUPER_SECRET""#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"err: {{"msg": "ok\u000d--{pw} SUPER_SECRET""#),
            "SUPER_SECRET",
        ),
        (
            r#"err: {"msg": "ok\u000acurl -su admin:SUPER_SECRET https://example.com""#
                .to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"err: {"msg": "ok\u000duser=admin:SUPER_SECRET""#.to_string(),
            "SUPER_SECRET",
        ),
        // Carbon W1A-R14-04: JSON-escaped POSIX `\\\n` continuations in scalar secrets (valid + truncated)
        (
            format!("{{\"cmd\": \"pg_dump --{pw} part1\\\\\\nSUPER_SECRET\"}}"),
            "SUPER_SECRET",
        ),
        (
            "{\"cmd\": \"curl -u admin:\\\\\\nSUPER_SECRET https://example.com\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("{{\"env\": \"{pw_caps}=part1\\\\\\nSUPER_SECRET\"}}"),
            "SUPER_SECRET",
        ),
        (
            format!("err: {{\"cmd\": \"pg_dump --{pw} part1\\\\\\nSUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (
            "err: {\"cmd\": \"curl -u admin:\\\\\\nSUPER_SECRET https://example.com\"".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("err: {{\"env\": \"{pw_caps}=part1\\\\\\nSUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        // Carbon W1A-R14-05: multiline sibling object following quoted Cookie header
        (
            "[\"Cookie: sid=SUPER_SECRET\",{\"a\":\"1\",\n\"b\":2}]".to_string(),
            "SUPER_SECRET",
        ),
        (
            "[\"Cookie: sid=SUPER_SECRET\",{\"a\":\"1\",\n\"b\":1e500}]".to_string(),
            "SUPER_SECRET",
        ),
        // Carbon W1A-R14-06: `\u005c\u0075XXXX` escape chains in JSON object keys (1-step idempotency)
        (
            format!(r#"{{"{pw}_\\u005c\\u00750041": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"Bearer SUPER_SECRET \\u005c\\u00750041": 1}"#.to_string(),
            "SUPER_SECRET",
        ),
        // Team 8 F-03 = Neon AUD-04: escaped-tab `\t` auth-scheme chaining
        (r#"Bearer\tBearer SUPER_SECRET"#.to_string(), "SUPER_SECRET"),
        (r#"Basic\tBearer SUPER_SECRET"#.to_string(), "SUPER_SECRET"),
        (format!(r#"{tok}\tBearer SUPER_SECRET"#), "SUPER_SECRET"),
        (r#"Digest\tBearer SUPER_SECRET"#.to_string(), "SUPER_SECRET"),
        (
            format!(r#"invalid {tok}\tBearer SUPER_SECRET"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "invalid {tok}\\tBearer SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        // Team 8 F-04: NBSP (`\u{00A0}` & `\u00a0`) before/after `=`/`:` on KV + `user:pass`
        (format!("{pw}\u{00A0}=SUPER_SECRET"), "SUPER_SECRET"),
        (format!("{pw}\\u00a0=SUPER_SECRET"), "SUPER_SECRET"),
        (
            format!("\"{pw}\"\u{00A0}: \"SUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (format!("{api_key}\u{00A0}: SUPER_SECRET"), "SUPER_SECRET"),
        ("user=\u{00A0}admin:SUPER_SECRET".to_string(), "SUPER_SECRET"),
        ("user:\u{00A0}admin:SUPER_SECRET".to_string(), "SUPER_SECRET"),
        ("user\u{00A0}=admin:SUPER_SECRET".to_string(), "SUPER_SECRET"),
        (
            "user=\u{00A0}\"admin:SUPER_SECRET\"".to_string(),
            "SUPER_SECRET",
        ),
        (r#"user=\u00a0admin:SUPER_SECRET"#.to_string(), "SUPER_SECRET"),
        (r#"user\u00a0=admin:SUPER_SECRET"#.to_string(), "SUPER_SECRET"),
        (
            r#"{"msg": "user\u00a0=\u00a0admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        // Team 8 F-05: JSON argv `["tool", "-u", ...]` with `\u003a` / `\u0020`
        (
            r#"["tool", "-u", "admin\\u003aSUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["tool", "-u", "Bearer\\u0020SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["tool", "-u", "admin\u003aSUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["tool", "-u", "Bearer\u0020SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        // Team 8 F-06: multiline `\u0022` / `\u003a` carry-state leaks
        (
            format!("[\\u0022pg_dump\\u0022, \\u0022--{pw}\\u0022,\n  \\u0022SUPER_SECRET\\u0022]"),
            "SUPER_SECRET",
        ),
        (
            "{\n  \"user\":\n  \"admin\\u003aSUPER_SECRET\"\n}".to_string(),
            "SUPER_SECRET",
        ),
        (
            "err: {\n  \"user\":\n  \"admin\\u003aSUPER_SECRET\"".to_string(),
            "SUPER_SECRET",
        ),
        (
            "[\"curl\", \"-u\",\n  \"admin\\u003aSUPER_SECRET\"]".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("{pw}=\n  \\u0022line1\nSUPER_SECRET_LINE2\\u0022"),
            "SUPER_SECRET_LINE2",
        ),
        (
            "Cookie:\n  \\u0022line1\nSUPER_SECRET_LINE2\\u0022".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        // Neon AUD-03: URL password containing `@` followed by `,`, `;`, `'`, `"`, `{`, `}` + JSON
        (
            "https://admin:p@ss,SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
        ),
        (
            "https://admin:p@ss;SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
        ),
        (
            "https://admin:p@ss'SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
        ),
        (
            "https://admin:p@ss\"SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
        ),
        (
            "https://admin:p@ss{SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
        ),
        (
            "https://admin:p@ss}SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p@ss;SUPER_SECRET@example.com/api"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p@ss,SUPER_SECRET@example.com/api"}"#.to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-05: JSON-serialized folded `Digest` header (`\n  `, `\r\n  `, `\t`, `\\\n`)
        (
            r#"{"err": "Digest username=\"alice\",\n  response=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"err": "Digest username=\"alice\",\r\n  response=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"err": "Digest username=\"alice\",\tresponse=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"err": "Digest username=\"alice\",\\\nresponse=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-06: Unicode punctuation & escaped whitespace before auth, KV, `user=`, `--flag`
        ("—Bearer SUPER_SECRET".to_string(), "SUPER_SECRET"),
        ("“Bearer SUPER_SECRET”".to_string(), "SUPER_SECRET"),
        ("«Bearer SUPER_SECRET»".to_string(), "SUPER_SECRET"),
        (
            r#"{"msg": "\u2014Bearer SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (format!(r#"\u0020{pa}=SUPER_SECRET"#), "SUPER_SECRET"),
        (format!(r#"\u0009{pa}=SUPER_SECRET"#), "SUPER_SECRET"),
        (format!(r#"\u00a0{pa}=SUPER_SECRET"#), "SUPER_SECRET"),
        (r#"\u0020user=admin:SUPER_SECRET"#.to_string(), "SUPER_SECRET"),
        (format!(r#"\u0020--{pw} SUPER_SECRET"#), "SUPER_SECRET"),
        (format!(r#"\u2014{pa}=SUPER_SECRET"#), "SUPER_SECRET"),
        (
            format!(r#"{{"msg": "\u0020{pa}=SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "\\u0020{pa}=SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        // Neon AUD-07: standalone `","` and unquoted even-backslash `\\"` URL `\u0040` Pass-0 normalization
        (
            r#""https://admin:p","SUPER_SECRET\u0040example.com/api""#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"https://admin:p\\"SUPER_SECRET\u0040example.com/api"#.to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-08: `curl -b`, `-b<cookie>`, `-sb`, `["curl", "-b", ...]`
        (
            "curl -b sid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
        ),
        (
            "curl -b SUPER_SECRET_COOKIE https://example.com".to_string(),
            "SUPER_SECRET_COOKIE",
        ),
        (
            "curl -bsid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
        ),
        (
            "curl -sb sid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
        ),
        (
            "curl -sbsid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-b", "sid=SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-b", "SUPER_SECRET_COOKIE"]"#.to_string(),
            "SUPER_SECRET_COOKIE",
        ),
        (
            r#"["curl", "-bsid=SUPER_SECRET", "https://example.com"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-sb", "SUPER_SECRET_COOKIE"]"#.to_string(),
            "SUPER_SECRET_COOKIE",
        ),
        // Neon AUD-09: multiline quoted HTTP headers ending in Base64 `=` padding
        (
            "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\" https://example.com\nstep 2: status=\"ok\""
                .to_string(),
            "dXNlcjpwYXNz=",
        ),
        (
            "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\" -H \"Accept: application/json\" https://example.com"
                .to_string(),
            "dXNlcjpwYXNz=",
        ),
        (
            "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\"\nbenign_line=1".to_string(),
            "dXNlcjpwYXNz=",
        ),
    ];

    for (input, secret) in &secret_cases {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R15 [{label}] leaked {secret:?} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R15 [{label}] failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
    }

    // 2. Direct `redact_json_value` & `redact_embedded_json_spans` coverage across all JSON R14 findings
    let json_value_cases: Vec<(String, &'static str)> = vec![
        (
            r#"{"msg": "\"C:\\path user=a:b user\": ok"}"#.to_string(),
            ":b",
        ),
        (
            format!(r#"{{"{pw}_\\u005c\\u00750041": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"Bearer SUPER_SECRET \\u005c\\u00750041": 1}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "invalid {tok}\\tBearer SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "ok\u000aBearer SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "ok\u000a--{pw} SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "ok\u000acurl -su admin:SUPER_SECRET https://example.com"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "ok\u000auser=admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("{{\"cmd\": \"pg_dump --{pw} part1\\\\\\nSUPER_SECRET\"}}"),
            "SUPER_SECRET",
        ),
        (
            "{\"cmd\": \"curl -u admin:\\\\\\nSUPER_SECRET https://example.com\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("{{\"env\": \"{pw_caps}=part1\\\\\\nSUPER_SECRET\"}}"),
            "SUPER_SECRET",
        ),
        (
            "[\"Cookie: sid=SUPER_SECRET\",{\"a\":\"1\",\n\"b\":2}]".to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["tool", "-u", "admin\\u003aSUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["tool", "-u", "Bearer\\u0020SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            "{\n  \"user\":\n  \"admin\\u003aSUPER_SECRET\"\n}".to_string(),
            "SUPER_SECRET",
        ),
        (
            "[\"curl\", \"-u\",\n  \"admin\\u003aSUPER_SECRET\"]".to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"url": "https://admin:p@ss;SUPER_SECRET@example.com/api"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"err": "Digest username=\"alice\",\n  response=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\u2014Bearer SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "\u0020{pa}=SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-b", "sid=SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-b", "SUPER_SECRET_COOKIE"]"#.to_string(),
            "SUPER_SECRET_COOKIE",
        ),
        (
            r#"["curl", "-bsid=SUPER_SECRET", "https://example.com"]"#.to_string(),
            "SUPER_SECRET",
        ),
    ];
    for (raw_json, forbidden) in &json_value_cases {
        let mut val: serde_json::Value = serde_json::from_str(raw_json).unwrap();
        diagnostic_projection::redact_json_value(&mut val);
        let ser = serde_json::to_string(&val).unwrap();
        assert!(
            !ser.contains(forbidden),
            "R15 redact_json_value leaked {forbidden:?} for {raw_json:?} -> {ser:?}"
        );
        let mut val2 = val.clone();
        diagnostic_projection::redact_json_value(&mut val2);
        assert_eq!(
            val2, val,
            "R15 redact_json_value failed 1-step idempotency for {raw_json:?}"
        );
    }

    // Neon AUD-02 correctness: 64 colliding scrubbed JSON object keys preserve all 64 entries
    let aud02_64 = make_r15_aud02_colliding_json_keys(64);
    let mut aud02_val: serde_json::Value = serde_json::from_str(&aud02_64).unwrap();
    diagnostic_projection::redact_json_value(&mut aud02_val);
    assert_eq!(aud02_val.as_object().unwrap().len(), 64);
    let aud02_proj = diagnostic_projection::redact_secrets(&aud02_64);
    assert!(!aud02_proj.contains("S0") && !aud02_proj.contains("S63"));
    let aud02_proj_val: serde_json::Value = serde_json::from_str(&aud02_proj).unwrap();
    assert_eq!(aud02_proj_val.as_object().unwrap().len(), 64);
    assert_eq!(
        diagnostic_projection::redact_secrets(&aud02_proj),
        aud02_proj
    );

    // Carbon W1A-R14-02: `redact_embedded_json_spans` across all duplicate-key reproducers
    for dup_embedded in [
        format!(
            r#"installer failed: {{"config": {{"{api_key}": "SUPER_SECRET"}}, "config": {{}}}}"#
        ),
        r#"err: {"msg": "Authorization: Bearer SUPER_SECRET", "msg": "ok"} tail"#.to_string(),
        r#"err: {"user": "admin:SUPER_SECRET", "user": "admin"} tail"#.to_string(),
        format!(r#"err: {{"{pw}": "SUPER_SECRET", "{pw}": "[REDACTED]"}} tail"#),
    ] {
        let emb_out = diagnostic_projection::redact_embedded_json_spans(&dup_embedded);
        assert!(
            !emb_out.contains("SUPER_SECRET"),
            "redact_embedded_json_spans leaked duplicate-key secret: {dup_embedded:?} -> {emb_out:?}"
        );
        assert_eq!(
            diagnostic_projection::redact_embedded_json_spans(&emb_out),
            emb_out,
            "redact_embedded_json_spans not idempotent on {dup_embedded:?}"
        );
    }

    // 3. Valid RFC 8259 JSON validity & sibling preservation (`Team 8 F-01`, `W1A-R14-02..06`, `AUD-05`)
    let w14_05_j1 = "[\"Cookie: sid=SUPER_SECRET\",{\"a\":\"1\",\n\"b\":2}]".to_string();
    let valid_json_r15: Vec<String> = vec![
        r#"{"msg": "\"C:\\path user=a:b user\": ok"}"#.to_string(),
        r#"{"msg": "Authorization: Bearer SUPER_SECRET", "msg": "ok"}"#.to_string(),
        format!(r#"{{"config": {{"{api_key}": "SUPER_SECRET"}}, "config": {{}}}}"#),
        r#"{"user": "admin:SUPER_SECRET", "user": "admin"}"#.to_string(),
        format!(r#"{{"{pw}": "SUPER_SECRET", "{pw}": "[REDACTED]"}}"#),
        r#"{"msg": "ok\u000aBearer SUPER_SECRET"}"#.to_string(),
        format!(r#"{{"msg": "ok\u000a--{pw} SUPER_SECRET"}}"#),
        r#"{"msg": "ok\u000acurl -su admin:SUPER_SECRET https://example.com"}"#.to_string(),
        r#"{"msg": "ok\u000auser=admin:SUPER_SECRET"}"#.to_string(),
        format!("{{\"cmd\": \"pg_dump --{pw} part1\\\\\\nSUPER_SECRET\"}}"),
        "{\"cmd\": \"curl -u admin:\\\\\\nSUPER_SECRET https://example.com\"}".to_string(),
        format!("{{\"env\": \"{pw_caps}=part1\\\\\\nSUPER_SECRET\"}}"),
        w14_05_j1.clone(),
        format!(r#"{{"{pw}_\\u005c\\u00750041": "SUPER_SECRET"}}"#),
        r#"{"Bearer SUPER_SECRET \\u005c\\u00750041": 1}"#.to_string(),
        format!(r#"{{"msg": "invalid {tok}\\tBearer SUPER_SECRET"}}"#),
        r#"["tool", "-u", "admin\\u003aSUPER_SECRET"]"#.to_string(),
        r#"["tool", "-u", "Bearer\\u0020SUPER_SECRET"]"#.to_string(),
        r#"{"url": "https://admin:p@ss;SUPER_SECRET@example.com/api"}"#.to_string(),
        r#"{"err": "Digest username=\"alice\",\n  response=\"SUPER_SECRET\""}"#.to_string(),
        r#"{"err": "Digest username=\"alice\",\r\n  response=\"SUPER_SECRET\""}"#.to_string(),
        r#"{"err": "Digest username=\"alice\",\tresponse=\"SUPER_SECRET\""}"#.to_string(),
        r#"{"err": "Digest username=\"alice\",\\\nresponse=\"SUPER_SECRET\""}"#.to_string(),
        r#"{"msg": "\u2014Bearer SUPER_SECRET"}"#.to_string(),
        r#"["curl", "-b", "sid=SUPER_SECRET"]"#.to_string(),
        r#"{"user@host":"[REDACTED_url]\"café's -uBearer ://\n\""}"#.to_string(),
    ];
    for raw in &valid_json_r15 {
        serde_json::from_str::<serde_json::Value>(raw).unwrap();
        for (label, f) in [
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(raw);
            let parsed: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| {
                panic!("R15 [{label}] broke valid JSON ({e}) for {raw:?} -> {out:?}")
            });
            assert_eq!(
                f(&out),
                out,
                "R15 [{label}] JSON idempotency failed: {raw:?}"
            );
            if raw == &w14_05_j1 {
                assert_eq!(parsed[1]["a"], serde_json::json!("1"), "{label}: {out}");
                assert_eq!(parsed[1]["b"], serde_json::json!(2), "{label}: {out}");
            }
        }
    }

    // Also verify `persisted` preserves valid RFC 8259 JSON on string-wrapped R15 cases (`W1A-R14-03..05`, `AUD-05`, `F-01`)
    for raw in [
        r#"{"msg": "\"C:\\path user=a:b user\": ok"}"#.to_string(),
        r#"{"msg": "ok\u000aBearer SUPER_SECRET"}"#.to_string(),
        format!(r#"{{"msg": "ok\u000a--{pw} SUPER_SECRET"}}"#),
        r#"{"msg": "ok\u000acurl -su admin:SUPER_SECRET https://example.com"}"#.to_string(),
        r#"{"msg": "ok\u000auser=admin:SUPER_SECRET"}"#.to_string(),
        format!("{{\"cmd\": \"pg_dump --{pw} part1\\\\\\nSUPER_SECRET\"}}"),
        "{\"cmd\": \"curl -u admin:\\\\\\nSUPER_SECRET https://example.com\"}".to_string(),
        format!("{{\"env\": \"{pw_caps}=part1\\\\\\nSUPER_SECRET\"}}"),
        w14_05_j1.clone(),
        r#"{"err": "Digest username=\"alice\",\n  response=\"SUPER_SECRET\""}"#.to_string(),
        r#"{"err": "Digest username=\"alice\",\r\n  response=\"SUPER_SECRET\""}"#.to_string(),
        r#"{"err": "Digest username=\"alice\",\tresponse=\"SUPER_SECRET\""}"#.to_string(),
        r#"{"err": "Digest username=\"alice\",\\\nresponse=\"SUPER_SECRET\""}"#.to_string(),
    ] {
        let out = sanitize_persisted_lifecycle_text(&raw);
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| {
            panic!("R15 [persisted] broke valid JSON ({e}) for {raw:?} -> {out:?}")
        });
        assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
        if raw == w14_05_j1 {
            assert_eq!(parsed[1]["a"], serde_json::json!("1"));
            assert_eq!(parsed[1]["b"], serde_json::json!(2));
        }
    }

    // Carbon W1A-R14-05 `1e500` out-of-f64-range exponent: preserves RFC 8259 JSON & sibling `"a":"1"`
    let w14_05_j2 = "[\"Cookie: sid=SUPER_SECRET\",{\"a\":\"1\",\n\"b\":1e500}]";
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let out = f(w14_05_j2);
        assert_eq!(
            out, "[\"Cookie: [REDACTED]\",{\"a\":\"1\",\n\"b\":1e500}]",
            "R15 [{label}] corrupted W1A-R14-05 1e500 JSON: {out:?}"
        );
        assert_eq!(f(&out), out);
    }

    // 4. Benign preservation, Neon AUD-03/08/09 non-over-redaction, & Team 8 F-08 `Cow::Borrowed`
    assert!(matches!(
        af_models::secret_redaction::redact_diagnostic("INFO: Service started OK"),
        std::borrow::Cow::Borrowed(_)
    ));

    let win_path_raw = format!("C:\\t{pa}=visible");
    let win_path_esc = format!("C:\\\\t{pa}=visible");
    let win_path_json = format!(r#"{{"path": "C:\\t{pa}=visible"}}"#);
    let benign_r15: Vec<String> = vec![
        "INFO: Service started OK".to_string(),
        win_path_raw,
        win_path_esc,
        win_path_json,
        "git checkout -b feature".to_string(),
        "curl -B https://example.com".to_string(),
        r#"{"cmd": "curl", "items": ["-b", "benign_item"]}"#.to_string(),
    ];
    for benign in &benign_r15 {
        for &(label, f) in &eps {
            let out = f(benign);
            assert_eq!(
                &out, benign,
                "R15 [{label}] mutated benign input {benign:?} -> {out:?}"
            );
        }
        assert!(
            matches!(
                af_models::secret_redaction::redact_diagnostic(benign),
                std::borrow::Cow::Borrowed(_)
            ),
            "redact_diagnostic allocated on clean R15 input: {benign:?}"
        );
        assert!(
            matches!(
                sanitize_persisted_lifecycle_text_cow(benign),
                std::borrow::Cow::Borrowed(_)
            ),
            "sanitize_persisted_lifecycle_text_cow allocated on clean R15 input: {benign:?}"
        );
        if benign.starts_with(['{', '[']) {
            let orig: serde_json::Value = serde_json::from_str(benign).unwrap();
            let mut copy = orig.clone();
            diagnostic_projection::redact_json_value(&mut copy);
            assert_eq!(copy, orig, "redact_json_value mutated benign {benign:?}");
        }
    }

    // Neon AUD-03: exact URL authority scrub without leaking `ss,` tail & preserving benign `,next`
    for sep in [',', ';', '\'', '"', '{', '}'] {
        let u = format!("https://admin:p@ss{sep}SUPER_SECRET@example.com/api");
        for (label, f) in [
            (
                "persisted",
                sanitize_persisted_lifecycle_text as fn(&str) -> String,
            ),
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            assert_eq!(
                f(&u),
                "https://[REDACTED]@example.com/api",
                "R15 [{label}] AUD-03 failed for sep={sep:?}"
            );
        }
    }
    assert_eq!(
        diagnostic_projection::redact_secrets("https://admin:SUPER_SECRET@example.com,next_item"),
        "https://[REDACTED]@example.com,next_item"
    );

    // Neon AUD-09: multiline quoted HTTP headers ending in Base64 `=` preserve trailing URL/flags/lines
    let aud09_m1 =
        "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\" https://example.com\nstep 2: status=\"ok\"";
    let aud09_m2 =
        "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\" -H \"Accept: application/json\" https://example.com";
    let aud09_m3 = "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\"\nbenign_line=1";
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let o1 = f(aud09_m1);
        assert!(
            o1.contains("https://example.com") && o1.contains("step 2: status=\"ok\""),
            "R15 [{label}] AUD-09 m1 over-redacted: {o1:?}"
        );
        let o2 = f(aud09_m2);
        assert!(
            o2.contains("-H \"Accept: application/json\" https://example.com"),
            "R15 [{label}] AUD-09 m2 over-redacted: {o2:?}"
        );
        let o3 = f(aud09_m3);
        assert!(
            o3.contains("\"\nbenign_line=1"),
            "R15 [{label}] AUD-09 m3 over-redacted: {o3:?}"
        );
    }
    assert!(
        af_models::secret_redaction::redact_diagnostic(aud09_m3).contains("benign_line=1"),
        "redact_diagnostic AUD-09 m3 swallowed benign_line=1"
    );

    // 5. Team 8 F-07 = Neon AUD-10: `failure_category` sanitized on write AND tampered/legacy read
    {
        let (root, _, _database, mut conn) = fixture();
        let lease = admit_job_with_target(
            &mut conn,
            "testpkg-r15",
            "job-r15-cat",
            "update",
            "2026-11-27T08:00:00Z",
            &[],
            Some("1.0.0"),
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "testpkg-r15",
            "job-r15-cat",
            "update",
            false,
            LifecycleJobDiagnostics {
                failure_category: "https://admin:SUPER_SECRET_CAT@example.com",
                failed_stage: Some("install_stage"),
                exit_code: Some(1),
                sanitized_summary: Some(
                    r#"{"err": "Digest username=\"alice\",\n  response=\"SUPER_SECRET_DIGEST\""}"#,
                ),
                expected_target_version: Some(
                    r#"{"msg": "Bearer SUPER_SECRET_DUP", "msg": "1.0.0"}"#,
                ),
                ..Default::default()
            },
        )
        .unwrap();

        let raw_cat: String = conn
            .query_row(
                "SELECT failure_category FROM package_lifecycle_history WHERE job_id = 'job-r15-cat'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let raw_sum: String = conn
            .query_row(
                "SELECT sanitized_summary FROM package_lifecycle_history WHERE job_id = 'job-r15-cat'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            !raw_cat.contains("SUPER_SECRET_CAT"),
            "raw SQLite cat leaked: {raw_cat}"
        );
        assert!(
            !raw_sum.contains("SUPER_SECRET_DIGEST"),
            "raw SQLite Digest summary leaked: {raw_sum}"
        );

        conn.execute(
            "UPDATE package_lifecycle_history SET failure_category = 'Bearer TAMPERED_CAT_SECRET' WHERE job_id = 'job-r15-cat'",
            [],
        )
        .unwrap();
        let hist = get_lifecycle_history(&conn, "testpkg-r15", 5).unwrap();
        assert_eq!(hist.len(), 1);
        assert!(!hist[0].failure_category.contains("TAMPERED_CAT_SECRET"));
        assert!(hist[0].failure_category.contains("[REDACTED]"));
        assert!(!hist[0]
            .expected_target_version
            .as_deref()
            .unwrap()
            .contains("SUPER_SECRET_DUP"));

        drop(lease);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    // 6. Adaptive linear-time O(N) scaling (`ratio < 3.2`) across ALL 3 R14 DoS vectors
    // (`Team 8 F-02 = Neon AUD-01`, `Neon AUD-02`, `Carbon W1A-R14-01`)
    type R15Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r15_scaling: &[R15Scaling] = &[
        (
            "r15_aud01_cookie_u0022_pairs",
            |n| format!("Cookie: x{}\nbenign", "\\u0022\\u0022".repeat(n)),
            400,
            64_000,
        ),
        (
            "r15_aud01_cookie_u0022_delim_pairs",
            |n| format!("Cookie: x={}\nbenign", "\\u0022\\u0022".repeat(n)),
            400,
            64_000,
        ),
        (
            "r15_aud02_colliding_json_keys",
            make_r15_aud02_colliding_json_keys,
            200,
            16_000,
        ),
        (
            "r15_w1a_r14_01_u0022_user_bare_brace",
            |n| r#"\u0022user\u0022:a{ "#.repeat(n),
            250,
            64_000,
        ),
        (
            "r15_w1a_r14_01_u0022_user_bare_brace_json",
            |n| format!(r#"{{"msg":"{}"}}"#, r#"\\u0022user\\u0022:a{ "#.repeat(n)),
            250,
            64_000,
        ),
    ];
    let started_r15 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r15_scaling {
        for &(ep, f) in &eps {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }
    assert_adaptive_linear_scaling(
        "r15_aud02_embedded_json_spans",
        "embedded_json",
        |n| format!("err: {}", make_r15_aud02_colliding_json_keys(n)),
        200,
        16_000,
        |p| diagnostic_projection::redact_embedded_json_spans(p).len(),
    );
    assert!(
        started_r15.elapsed() < std::time::Duration::from_secs(90),
        "R15 linear-time budget exceeded: {:?}",
        started_r15.elapsed()
    );
}

fn drop_json_value_iteratively_for_test(val: serde_json::Value) {
    let mut stack = vec![val];
    while let Some(cur) = stack.pop() {
        match cur {
            serde_json::Value::Object(map) => {
                for (_, v) in map {
                    if matches!(
                        v,
                        serde_json::Value::Object(_) | serde_json::Value::Array(_)
                    ) {
                        stack.push(v);
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    if matches!(
                        v,
                        serde_json::Value::Object(_) | serde_json::Value::Array(_)
                    ) {
                        stack.push(v);
                    }
                }
            }
            _ => {}
        }
    }
}

fn make_r16_f03_u0022_containers(n: usize) -> String {
    let sec = concat!("sec", "ret");
    format!("\\u0022{sec}\\u0022: {{\\u0022a\\u0022: \\u0022x\\u0022}}, ").repeat(n)
}

fn make_r16_f08_truncated_sq_argv(n: usize) -> String {
    let pw = concat!("pass", "word");
    let unit = format!("['pg_dump', '--{pw}', 'x'], ");
    format!("\"{}\n'tail", unit.repeat(n))
}

#[test]
fn test_wave1a_r16_audit_regressions() {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 4] = [
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
    ];

    let pw = concat!("pass", "word");
    let pw_caps = concat!("PASS", "WORD");
    let pa = concat!("pa", "ss");
    let au = concat!("au", "th");
    let sec = concat!("sec", "ret");
    let key_caps = concat!("KE", "Y");
    let tok = concat!("tok", "en");
    let hdr_x_api = concat!("X-Api-", "Key");
    let hdr_x_auth = concat!("X-Auth-", "Token");
    let hdr_proxy = concat!("Proxy-Authori", "zation");
    let hdr_auth = concat!("Authori", "zation");
    let u0070_pw = concat!("\\u00750070ass", "word");

    // 1. Carbon W1A-AUD-01: 2 MiB thread stack safety on deep `redact_json_value`
    // (`Value::Object` depth 3,500 leaf redaction + sensitive subtree drop, `Value::Array` depth 10,000)
    std::thread::Builder::new()
        .name("w1a-r16-2mib-stack".to_string())
        .stack_size(2 * 1024 * 1024)
        .spawn(move || {
            // (a) Deep `Value::Object` depth 3,500 with secret leaf
            let mut deep_obj =
                serde_json::Value::String(format!("{hdr_auth}: Bearer SUPER_SECRET_OBJ_3500"));
            for _ in 0..3_500 {
                let mut m = serde_json::Map::new();
                m.insert("a".to_string(), deep_obj);
                deep_obj = serde_json::Value::Object(m);
            }
            assert!(diagnostic_projection::redact_json_value(&mut deep_obj));
            {
                let mut cur = &deep_obj;
                for _ in 0..3_500 {
                    cur = &cur["a"];
                }
                let leaf = cur.as_str().expect("leaf string");
                assert!(!leaf.contains("SUPER_SECRET_OBJ_3500"), "leaf={leaf:?}");
                assert!(leaf.contains("[REDACTED]"), "leaf={leaf:?}");
            }
            assert!(
                !diagnostic_projection::redact_json_value(&mut deep_obj),
                "redact_json_value must be 1-step idempotent on deep Object"
            );
            drop_json_value_iteratively_for_test(deep_obj);

            // (b) Sensitive key holding a depth 3,500 `Value::Object` dropped iteratively without overflow
            let mut nested_sub = serde_json::Value::String("INNER_SUBTREE_SECRET".to_string());
            for _ in 0..3_500 {
                let mut m = serde_json::Map::new();
                m.insert("sub".to_string(), nested_sub);
                nested_sub = serde_json::Value::Object(m);
            }
            let mut sens_root_map = serde_json::Map::new();
            sens_root_map.insert(pw.to_string(), nested_sub);
            let mut sens_root = serde_json::Value::Object(sens_root_map);
            assert!(diagnostic_projection::redact_json_value(&mut sens_root));
            assert_eq!(sens_root[pw], serde_json::json!("[REDACTED]"));
            assert!(!diagnostic_projection::redact_json_value(&mut sens_root));

            // (c) Deep `Value::Array` depth 10,000 with secret leaf
            let mut deep_arr =
                serde_json::Value::String(format!("{hdr_auth}: Bearer SUPER_SECRET_ARR_10000"));
            for _ in 0..10_000 {
                deep_arr = serde_json::Value::Array(vec![deep_arr]);
            }
            assert!(diagnostic_projection::redact_json_value(&mut deep_arr));
            {
                let mut cur = &deep_arr;
                for _ in 0..10_000 {
                    cur = &cur[0];
                }
                let leaf = cur.as_str().expect("array leaf string");
                assert!(!leaf.contains("SUPER_SECRET_ARR_10000"), "leaf={leaf:?}");
                assert!(leaf.contains("[REDACTED]"), "leaf={leaf:?}");
            }
            assert!(
                !diagnostic_projection::redact_json_value(&mut deep_arr),
                "redact_json_value must be 1-step idempotent on deep Array"
            );
            drop_json_value_iteratively_for_test(deep_arr);
        })
        .expect("spawn 2 MiB stack thread")
        .join()
        .expect("2 MiB stack thread must not overflow");

    // 2. All R15 audit findings (`Team 8 F-01..F-09`, `Neon AUD-01..AUD-07`, `Carbon W1A-AUD-02..07`)
    // across ALL 4 surfaces (`diag`, `persisted`, `projected`, `balanced`) + 1-step idempotency.
    let w1a_aud02_repro3 = serde_json::json!({
        "payload": format!(
            "{{\"pad\":\"{}\",\"\\u0022k\":1,\"\\t{pa}\":\"SUPER_SECRET_777888\"}}",
            "\\\"x\\\"".repeat(80)
        )
    })
    .to_string();
    let long_user_260 = "a".repeat(260);

    let mut secret_cases: Vec<(String, &'static str)> = vec![
        // Carbon W1A-AUD-02: JSON control escapes before word-bounded keys
        (format!(r#"{{"\t{pa}": "SUPER_SECRET"}}"#), "SUPER_SECRET"),
        (format!(r#"{{"\n{au}": "SUPER_SECRET"}}"#), "SUPER_SECRET"),
        (format!(r#"{{"\b{pa}": "SUPER_SECRET"}}"#), "SUPER_SECRET"),
        (format!(r#"{{"\f{pa}": "SUPER_SECRET"}}"#), "SUPER_SECRET"),
        (
            format!(r#"{{"\r{key_caps}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u0009{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u000a{au}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u001b{key_caps}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u0000{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"\tuser": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (format!(r#"err: {{"\t{pa}": "SUPER_SECRET""#), "SUPER_SECRET"),
        (format!(r#"err: {{"\b{pa}": "SUPER_SECRET""#), "SUPER_SECRET"),
        (format!(r#"err: {{"\f{pa}": "SUPER_SECRET""#), "SUPER_SECRET"),
        (
            format!(r#"err: {{"\u0009{pa}": "SUPER_SECRET""#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"payload="{{\"\\t{pa}\": \"SUPER_SECRET\"}}""#),
            "SUPER_SECRET",
        ),
        (w1a_aud02_repro3.clone(), "SUPER_SECRET_777888"),
        // Carbon W1A-AUD-03: stray quote inside bracketed log prefix before embedded JSON
        (
            format!(r#"[info: 5" disk] {{"{pw}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"[info: 5" disk] {{"\t{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"[5" disk] {{"{pw}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"[12345 5" disk] {{"\t{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        // Carbon W1A-AUD-04: multiline JSON name-separators (`"key"\n  : value`)
        (
            format!("{{\n  \"{pw}\"\n  : \"SUPER_SECRET\"\n}}"),
            "SUPER_SECRET",
        ),
        (
            format!("{{\"{sec}\"\n: {{\"raw\": \"SUPER_SECRET\"}}}}"),
            "SUPER_SECRET",
        ),
        (
            "{\n  \"user\"\n  : \"admin:SUPER_SECRET\"\n}".to_string(),
            "SUPER_SECRET",
        ),
        // Carbon W1A-AUD-05: NBSP / U+3000 continuation boundary
        (
            format!("{pw_caps}=\\\nfirst\u{00A0}--{tok}=\nSUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!("{pw_caps}=\\\nfirst\u{00A0}{pw}={{\n  \"raw\": \"SUPER_SECRET\"\n}}"),
            "SUPER_SECRET",
        ),
        (
            format!("{pw_caps}=\\\nfirst\u{3000}--{tok}=\nSUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!("{pw_caps}=\\\nfirst\u{3000}{pw}={{\n  \"raw\": \"SUPER_SECRET\"\n}}"),
            "SUPER_SECRET",
        ),
        // Neon AUD-01 = Team 8 F-05: Unicode-escaped curl `-b` / `-sb` / `-Ib` / `\u002db` & `\u0022` argv
        (
            r#"curl -\u0062 SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl -s\u0062 SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl -I\u0062 SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl \u002db SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl -\u0062SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl -\u0062=SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": "curl -\\u0062 SUPER_SECRET https://example.com"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"err: ["curl", "-\u0062", "SUPER_SECRET""#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-\u0062", "SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "\u002db", "SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-\u0062SUPER_SECRET\u0022, \u0022https://example.com\u0022]"#
                .to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-\u0075SUPER_SECRET\u0022, \u0022https://example.com\u0022]"#
                .to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-02: raw & JSON-escaped `Authorization: Bearer/Basic/Digest\n...`
        (
            format!("{hdr_auth}: Bearer\nSUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!("{hdr_auth}: Bearer \nSUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!("{hdr_auth}: Basic\ndXNlcjpwYXNz"),
            "dXNlcjpwYXNz",
        ),
        (
            format!("{hdr_auth}: Digest\nusername=\"a\", response=\"SUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "{hdr_auth}: Bearer\nSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "{hdr_auth}: Bearer \nSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "{hdr_auth}: Basic\ndXNlcjpwYXNz"}}"#),
            "dXNlcjpwYXNz",
        ),
        (
            format!(
                r#"{{"msg": "{hdr_auth}: Digest\nusername=\"a\", response=\"SUPER_SECRET\""}}"#
            ),
            "SUPER_SECRET",
        ),
        // Neon AUD-03 = Team 8 F-02: standalone quoted URL passwords with 2+ `","` sequences
        (
            r#""https://admin:p1","p2","SUPER_SECRET@example.com""#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#""https://admin:p1","@a","SUPER_SECRET@example.com""#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#""https://admin:p@1","a","SUPER_SECRET@example.com""#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\"https://admin:p1\",\"p2\",\"SUPER_SECRET@example.com\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\"https://admin:p1\",\"@a\",\"SUPER_SECRET@example.com\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-04: multiline ANSI-C `$'...'` / `$"..."` continuations
        (format!("{pw}=\n$'line1\nSUPER_SECRET'"), "SUPER_SECRET"),
        (format!("{pw}=\\\n$'line1\nSUPER_SECRET'"), "SUPER_SECRET"),
        (format!("{pw}=\n$\"line1\nSUPER_SECRET\""), "SUPER_SECRET"),
        ("user=\n$'admin:\nSUPER_SECRET'".to_string(), "SUPER_SECRET"),
        (
            "user=\\\n$'admin:\nSUPER_SECRET'".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("--{tok} \\\n$'line1\nSUPER_SECRET'"),
            "SUPER_SECRET",
        ),
        (
            format!("{hdr_auth}: Bearer \\\n$'line1\nSUPER_SECRET'"),
            "SUPER_SECRET",
        ),
        (
            "curl -u \\\n$'admin:\nSUPER_SECRET'".to_string(),
            "SUPER_SECRET",
        ),
        (
            "curl -b \\\n$'line1\nSUPER_SECRET'".to_string(),
            "SUPER_SECRET",
        ),
        // Team 8 F-01 & Neon AUD-05: NBSP / newline before `:` on headers & non-NBSP Unicode whitespace
        (format!("{hdr_x_api}\u{00A0}: SUPER_SECRET"), "SUPER_SECRET"),
        (
            "Cookie\u{00A0}: a=1; sid=SUPER_SECRET".to_string(),
            "SUPER_SECRET",
        ),
        (format!("{hdr_x_api}\n: SUPER_SECRET"), "SUPER_SECRET"),
        (format!("{hdr_x_api}\r\n: SUPER_SECRET"), "SUPER_SECRET"),
        ("Bearer\u{3000}SUPER_SECRET".to_string(), "SUPER_SECRET"),
        ("Bearer\u{2000}SUPER_SECRET".to_string(), "SUPER_SECRET"),
        ("Bearer\u{2003}SUPER_SECRET".to_string(), "SUPER_SECRET"),
        ("Bearer\u{202F}SUPER_SECRET".to_string(), "SUPER_SECRET"),
        ("Bearer\u{205F}SUPER_SECRET".to_string(), "SUPER_SECRET"),
        (format!("--{tok}\u{3000}SUPER_SECRET"), "SUPER_SECRET"),
        (format!("{pw}\u{3000}=\u{3000}SUPER_SECRET"), "SUPER_SECRET"),
        (format!("{pw}\u{2003}=\u{2003}SUPER_SECRET"), "SUPER_SECRET"),
        // Team 8 F-03: truncated & mixed-quote `\u0022`-encoded sensitive containers
        (
            format!(
                r#"{{"payload": "{{\\u0022{sec}\\u0022: {{\\u0022a\\u0022: \\u0022SUPER_SECRET"}}"#
            ),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{\u0022{sec}\u0022: {{\u0022a\u0022: \u0022SUPER_SECRET"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{\u0022{sec}\u0022: {{"a": "SUPER_SECRET"}}}}"#),
            "SUPER_SECRET",
        ),
        // Team 8 F-04: double-encoded `\u005c\u0075XXXX` user:pass & `\u0022` keys/argv
        (
            r#"{"user": "admin\\u005c\\u0075003aSUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{\u0022\u005c{u0070_pw}\u0022: \u0022SUPER_SECRET\u0022}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"[\u0022pg_dump\u0022, \u0022--\u005c{u0070_pw}=SUPER_SECRET\u0022, \u0022ok\u0022]"#
            ),
            "SUPER_SECRET",
        ),
        // Team 8 F-06: CRLF `obs-fold` header continuation lines without `;`/`,`
        (
            format!("{hdr_x_api}: part1\r\n  part2_SUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            "Cookie: a=1\r\n  sid=SUPER_SECRET".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("{hdr_auth}: Bearer part1\r\n  part2_SUPER_SECRET"),
            "SUPER_SECRET",
        ),
        // Team 8 F-07: unclosed `\u0022` and `\"` opened on `obs-fold` continuation lines
        (
            "Cookie: a=1;\n  b=\\u0022line2\nSUPER_SECRET\\u0022".to_string(),
            "SUPER_SECRET",
        ),
        (
            "Cookie: a=1;\n  b=\\\"line2\nSUPER_SECRET\\\"".to_string(),
            "SUPER_SECRET",
        ),
        // Neon AUD-06: 260-byte username before `\u003a`
        (
            format!("user={long_user_260}\\u003aSUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"user": "{long_user_260}\u003aSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"user": "{long_user_260}\\u003aSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        // Team 8 F-08: truncated multiline single-quoted argv inside enclosing `"`
        (
            format!("\"log: ['pg_dump', '--{pw}', 'line1\nSUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "err: \" ['pg_dump', '--{pw}', 'line1\nSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
    ];

    // Neon AUD-02: JSON-escaped `\n`, `\r\n`, and `\u000a` across ALL 6 sensitive HTTP headers
    // (valid JSON, truncated JSON, and `1e500` JSON)
    for hdr in [
        hdr_x_api,
        "Cookie",
        "Set-Cookie",
        hdr_x_auth,
        hdr_proxy,
        hdr_auth,
    ] {
        secret_cases.push((
            format!(r#"{{"msg": "{hdr}: \nSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ));
        secret_cases.push((
            format!(r#"{{"msg": "{hdr}: \r\nSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ));
        secret_cases.push((
            format!(r#"{{"msg": "{hdr}: \u000aSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ));
        secret_cases.push((
            format!(r#"err: {{"msg": "{hdr}: \nSUPER_SECRET""#),
            "SUPER_SECRET",
        ));
        secret_cases.push((
            format!(r#"err: {{"msg": "{hdr}: \u000aSUPER_SECRET""#),
            "SUPER_SECRET",
        ));
        secret_cases.push((
            format!(r#"{{"msg": "{hdr}: \nSUPER_SECRET", "n": 1e500}}"#),
            "SUPER_SECRET",
        ));
    }

    for (input, secret) in &secret_cases {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R16 [{label}] leaked {secret:?} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R16 [{label}] failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
    }

    // 3. Direct `redact_json_value` & `redact_embedded_json_spans` + RFC 8259 JSON validity
    let mut valid_json_r16: Vec<(String, &'static str)> = vec![
        (format!(r#"{{"\t{pa}": "SUPER_SECRET"}}"#), "SUPER_SECRET"),
        (format!(r#"{{"\n{au}": "SUPER_SECRET"}}"#), "SUPER_SECRET"),
        (format!(r#"{{"\b{pa}": "SUPER_SECRET"}}"#), "SUPER_SECRET"),
        (format!(r#"{{"\f{pa}": "SUPER_SECRET"}}"#), "SUPER_SECRET"),
        (
            format!(r#"{{"\r{key_caps}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u0009{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u000a{au}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u001b{key_caps}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"\u0000{pa}": "SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"\tuser": "admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (w1a_aud02_repro3.clone(), "SUPER_SECRET_777888"),
        (
            format!("{{\n  \"{pw}\"\n  : \"SUPER_SECRET\"\n}}"),
            "SUPER_SECRET",
        ),
        (
            format!("{{\"{sec}\"\n: {{\"raw\": \"SUPER_SECRET\"}}}}"),
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": "curl -\\u0062 SUPER_SECRET https://example.com"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-\u0062", "SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "\u002db", "SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "{hdr_auth}: Bearer\nSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "{hdr_auth}: Basic\ndXNlcjpwYXNz"}}"#),
            "dXNlcjpwYXNz",
        ),
        (
            format!(
                r#"{{"msg": "{hdr_auth}: Digest\nusername=\"a\", response=\"SUPER_SECRET\""}}"#
            ),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\"https://admin:p1\",\"p2\",\"SUPER_SECRET@example.com\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "\"https://admin:p1\",\"@a\",\"SUPER_SECRET@example.com\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"{{"payload": "{{\\u0022{sec}\\u0022: {{\\u0022a\\u0022: \\u0022SUPER_SECRET"}}"#
            ),
            "SUPER_SECRET",
        ),
        (
            r#"{"user": "admin\\u005c\\u0075003aSUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"user": "{long_user_260}\u003aSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"user": "{long_user_260}\\u003aSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg": "err: \" ['pg_dump', '--{pw}', 'line1\nSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
    ];
    for hdr in [
        hdr_x_api,
        "Cookie",
        "Set-Cookie",
        hdr_x_auth,
        hdr_proxy,
        hdr_auth,
    ] {
        valid_json_r16.push((
            format!(r#"{{"msg": "{hdr}: \nSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ));
        valid_json_r16.push((
            format!(r#"{{"msg": "{hdr}: \r\nSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ));
        valid_json_r16.push((
            format!(r#"{{"msg": "{hdr}: \u000aSUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ));
    }

    for (raw_json, forbidden) in &valid_json_r16 {
        let mut val: serde_json::Value = serde_json::from_str(raw_json).unwrap();
        diagnostic_projection::redact_json_value(&mut val);
        let ser = serde_json::to_string(&val).unwrap();
        assert!(
            !ser.contains(forbidden),
            "R16 redact_json_value leaked {forbidden:?} for {raw_json:?} -> {ser:?}"
        );
        let mut val2 = val.clone();
        assert!(
            !diagnostic_projection::redact_json_value(&mut val2),
            "R16 redact_json_value returned true on 2nd pass for {raw_json:?}"
        );
        assert_eq!(
            val2, val,
            "R16 redact_json_value failed 1-step idempotency for {raw_json:?}"
        );

        for (label, f) in [
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(raw_json);
            assert!(
                !out.contains(forbidden),
                "R16 [{label}] leaked {forbidden:?} for {raw_json:?} -> {out:?}"
            );
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R16 [{label}] broke valid JSON ({e}) for {raw_json:?} -> {out:?}")
            });
            assert_eq!(f(&out), out, "R16 [{label}] JSON idempotency: {raw_json:?}");
        }
    }

    // Also verify `persisted` preserves valid outer JSON on string-wrapped R16 containers (`Team 8 F-03`, `F-08`, `Neon AUD-02`, `W1A-AUD-02` #3)
    for raw_json in [
        w1a_aud02_repro3,
        format!(
            r#"{{"payload": "{{\\u0022{sec}\\u0022: {{\\u0022a\\u0022: \\u0022SUPER_SECRET"}}"#
        ),
        format!(r#"{{"msg": "err: \" ['pg_dump', '--{pw}', 'line1\nSUPER_SECRET"}}"#),
        format!(r#"{{"msg": "{hdr_x_api}: \nSUPER_SECRET"}}"#),
        format!(r#"{{"msg": "{hdr_auth}: Bearer\nSUPER_SECRET"}}"#),
        r#"{"msg": "\"https://admin:p1\",\"p2\",\"SUPER_SECRET@example.com\""}"#.to_string(),
    ] {
        let out = sanitize_persisted_lifecycle_text(&raw_json);
        assert!(
            !out.contains("SUPER_SECRET"),
            "R16 [persisted] leaked for {raw_json:?} -> {out:?}"
        );
        serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
            panic!("R16 [persisted] broke valid outer JSON ({e}) for {raw_json:?} -> {out:?}")
        });
        assert_eq!(sanitize_persisted_lifecycle_text(&out), out);
    }

    // Carbon W1A-AUD-03: direct `redact_embedded_json_spans` verification
    for emb in [
        format!(r#"[info: 5" disk] {{"{pw}": "SUPER_SECRET"}}"#),
        format!(r#"[info: 5" disk] {{"\t{pa}": "SUPER_SECRET"}}"#),
        format!(r#"[5" disk] {{"{pw}": "SUPER_SECRET"}}"#),
        format!(r#"[12345 5" disk] {{"\t{pa}": "SUPER_SECRET"}}"#),
    ] {
        let out = diagnostic_projection::redact_embedded_json_spans(&emb);
        assert!(
            !out.contains("SUPER_SECRET"),
            "R16 redact_embedded_json_spans leaked for {emb:?} -> {out:?}"
        );
        assert!(out.starts_with('[') && out.contains("5\" disk]"));
        assert_eq!(
            diagnostic_projection::redact_embedded_json_spans(&out),
            out,
            "R16 redact_embedded_json_spans idempotency failed for {emb:?}"
        );
    }

    // 4. Benign preservation across ALL 4 surfaces (`W1A-AUD-02`, `W1A-AUD-04`, `W1A-AUD-07`,
    // `Neon AUD-01`, `Neon AUD-03`, `Neon AUD-07`, `Team 8 F-09`)
    let benign_all_4: Vec<String> = vec![
        format!("C:\\t{pa}=visible"),
        format!("C:\\\\t{pa}=visible"),
        format!("C:\\b{pa}=visible"),
        format!("C:\\f{pa}=visible"),
        format!(r#"{{"path": "C:\\t{pa}=visible"}}"#),
        format!(r#"{{"\\t{pa}": "visible"}}"#),
        "{\n  \"name\"\n  : \"alice\"\n}".to_string(),
        "git checkout -b feature".to_string(),
        "curl -B https://example.com".to_string(),
        r#"{"cmd": "curl", "items": ["-b", "benign_item"]}"#.to_string(),
        r#""https://example.com:8443","admin@example.com""#.to_string(),
        r#"{"cmd": "curl https://example.com\nrsync -b backup.tar"}"#.to_string(),
        format!(r#"{{"{key_caps}\u0061": "benign_val"}}"#),
        format!(r#"{{"{key_caps}\u0061": {{"a": 1}}}}"#),
    ];
    for benign in &benign_all_4 {
        for &(label, f) in &eps {
            let out = f(benign);
            assert_eq!(
                &out, benign,
                "R16 [{label}] mutated benign input {benign:?} -> {out:?}"
            );
        }
        assert!(
            matches!(
                af_models::secret_redaction::redact_diagnostic(benign),
                std::borrow::Cow::Borrowed(_)
            ),
            "redact_diagnostic allocated on benign R16 input: {benign:?}"
        );
        assert!(
            matches!(
                sanitize_persisted_lifecycle_text_cow(benign),
                std::borrow::Cow::Borrowed(_)
            ),
            "sanitize_persisted_lifecycle_text_cow allocated on benign R16 input: {benign:?}"
        );
        if benign.starts_with(['{', '[']) {
            let orig: serde_json::Value = serde_json::from_str(benign).unwrap();
            let mut copy = orig.clone();
            assert!(!diagnostic_projection::redact_json_value(&mut copy));
            assert_eq!(copy, orig, "redact_json_value mutated benign {benign:?}");
        }
    }

    // Neon AUD-07: benign empty sensitive headers followed by JSON-escaped `\n` & bare `Bearer\nHost:`
    let aud07_cookie_json = r#"{"msg": "Cookie:\nHost: example.com"}"#;
    let aud07_xapi_json = format!(r#"{{"msg": "{hdr_x_api}:\n\nstep 2: service healthy"}}"#);
    let aud07_bearer_raw = format!("{hdr_auth}: Bearer\nHost: example.com");
    let aud07_bearer_json = format!(r#"{{"msg": "{hdr_auth}: Bearer\nHost: example.com"}}"#);
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        for b in [
            aud07_cookie_json,
            aud07_xapi_json.as_str(),
            aud07_bearer_raw.as_str(),
            aud07_bearer_json.as_str(),
        ] {
            let out = f(b);
            assert_eq!(
                out, b,
                "R16 [{label}] AUD-07 mutated benign empty header {b:?} -> {out:?}"
            );
        }
    }
    assert_eq!(
        af_models::secret_redaction::redact_diagnostic(&aud07_bearer_raw),
        "[REDACTED]\nHost: example.com",
        "redact_diagnostic must preserve Host line after bare Authorization: Bearer"
    );

    // 5. Neon AUD-02 two-stage SQLite write->read & Carbon W1A-AUD-06 metadata sanitization
    {
        let (root, _, _database, mut conn) = fixture();
        let started_secret = "2026-11-27T10:00:00Z https://admin:START_AT_SECRET_R16@example.com";
        let unit_secret = format!("app --{pw}=UNIT_SECRET_R16");
        let lease = admit_job_with_target(
            &mut conn,
            "testpkg-r16",
            "job-r16-two-stage",
            "update",
            started_secret,
            &[unit_secret, "sonarr.service".to_string()],
            Some(&format!(r#"{{"\t{pa}": "TARGET_TAB_SECRET_R16"}}"#)),
        )
        .unwrap();

        let stage_json = format!(r#"{{"{pw}": "STAGE_JSON_SECRET_R16"}}"#);
        let two_stage_sum = format!(r#"{{"msg": "{hdr_x_api}: \nTWO_STAGE_SUM_SECRET_R16"}}"#);
        let fin_secret = format!("2026-11-27T10:01:00Z {hdr_auth}: Bearer FIN_AT_SECRET_R16");
        finish_job_with_diagnostics(
            &conn,
            "testpkg-r16",
            "job-r16-two-stage",
            "update",
            false,
            LifecycleJobDiagnostics {
                failure_category: "install_failed",
                failed_stage: Some(&stage_json),
                exit_code: Some(1),
                sanitized_summary: Some(&two_stage_sum),
                achieved_version: Some(aud07_cookie_json),
                finished_at: Some(&fin_secret),
                ..Default::default()
            },
        )
        .unwrap();

        let (raw_stage, raw_sum, raw_ach): (String, String, String) = conn
            .query_row(
                "SELECT failed_stage, sanitized_summary, achieved_version FROM package_lifecycle_history WHERE job_id = 'job-r16-two-stage'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(!raw_stage.contains("STAGE_JSON_SECRET_R16"));
        serde_json::from_str::<serde_json::Value>(&raw_stage).unwrap();
        assert!(!raw_sum.contains("TWO_STAGE_SUM_SECRET_R16"));
        serde_json::from_str::<serde_json::Value>(&raw_sum).unwrap();
        assert_eq!(raw_ach, aud07_cookie_json);

        let hist = get_lifecycle_history(&conn, "testpkg-r16", 5).unwrap();
        assert_eq!(hist.len(), 1);
        assert!(!hist[0].started_at.contains("START_AT_SECRET_R16"));
        assert!(!hist[0].finished_at.contains("FIN_AT_SECRET_R16"));
        assert!(hist[0]
            .service_units
            .iter()
            .all(|u| !u.to_ascii_lowercase().contains("unit_secret_r16")));
        assert!(!hist[0]
            .sanitized_summary
            .as_deref()
            .unwrap()
            .contains("TWO_STAGE_SUM_SECRET_R16"));
        serde_json::from_str::<serde_json::Value>(hist[0].failed_stage.as_deref().unwrap())
            .unwrap();

        drop(lease);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    // 6. Adaptive linear-time O(N) scaling across all new R16 watermarked/cached paths
    type R16Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r16_scaling: &[R16Scaling] = &[
        (
            "r16_aud03_repeated_q_comma_url",
            |n| format!("\"https://admin:p{}@example.com\"", "\",\"a".repeat(n)),
            300,
            64_000,
        ),
        (
            "r16_aud06_repeated_user_no_u003a",
            |n| "user=abcdefghij ".repeat(n),
            400,
            64_000,
        ),
        (
            "r16_f03_repeated_u0022_containers",
            make_r16_f03_u0022_containers,
            250,
            32_000,
        ),
        (
            "r16_aud03_bracketed_stray_quotes",
            |n| "[info: 5\" disk] ".repeat(n),
            400,
            64_000,
        ),
        (
            "r16_f07_obs_fold_u0022_cont",
            |n| format!("Cookie: a=1;\n{}", "  b=\\u0022x\\u0022;\n".repeat(n)),
            300,
            32_000,
        ),
        (
            "r16_f08_truncated_sq_argv",
            make_r16_f08_truncated_sq_argv,
            250,
            32_000,
        ),
    ];
    let started_r16 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r16_scaling {
        for &(ep, f) in &eps {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }
    assert_adaptive_linear_scaling(
        "r16_aud03_embedded_bracketed_stray_quotes",
        "embedded_json",
        |n| "[info: 5\" disk] ".repeat(n),
        400,
        64_000,
        |p| diagnostic_projection::redact_embedded_json_spans(p).len(),
    );
    // 7. R16 fuzzer 1-step idempotency regression (`\u000d` / `\u000a` after auth marker inside enclosing `"`)
    for fuzz_idem_case in [
        "\"Cookie: Digest SUPER_SECRET\\u000d|&",
        "\"Cookie: Digest SUPER_SECRET\\u000a|&",
        "éab[REDACTED]curl -b \\nautha=1\\\nX-Api-Key\n: \u{a0}\\u001bBearer {\n\"\\u0077)Cookie\u{a0}: Digest -AMozillaUbuntuuser=\\u0000“Bearer \\u2014\\u000d|&",
    ] {
        for &(label, f) in &eps {
            let p1 = f(fuzz_idem_case);
            let p2 = f(&p1);
            assert_eq!(
                p1, p2,
                "R16 [{label}] failed 1-step idempotency for {fuzz_idem_case:?}: p1={p1:?} vs p2={p2:?}"
            );
            assert!(
                !p1.contains("SUPER_SECRET"),
                "R16 [{label}] leaked secret for {fuzz_idem_case:?} -> {p1:?}"
            );
        }
    }

    assert!(
        started_r16.elapsed() < std::time::Duration::from_secs(90),
        "R16 linear-time budget exceeded: {:?}",
        started_r16.elapsed()
    );
}

fn make_r17_unclosed_bracket_prefix_json(n: usize) -> String {
    let pw = concat!("pass", "word");
    format!("{}{{\"{pw}\":\"s\"}}", "[\"5 inch] ".repeat(n))
}

fn make_r17_composite_u005c_u0022(n: usize) -> String {
    let pw = concat!("pass", "word");
    format!(
        "{pw}={}\nbenign",
        "\\u005c\\u0022x\\u005c\\u0022 ".repeat(n)
    )
}

#[test]
fn test_wave1a_r17_audit_regressions() {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 4] = [
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
    ];

    let pw = concat!("pass", "word");
    let pa = concat!("pa", "ss");
    let sec = concat!("sec", "ret");
    let tok = concat!("tok", "en");
    let toks = concat!("tok", "ens");
    let hdr_x_api = concat!("X-Api-", "Key");
    let hdr_x_auth = concat!("X-Auth-", "Token");
    let hdr_proxy = concat!("Proxy-Authori", "zation");
    let hdr_auth = concat!("Authori", "zation");

    // 1. Every R16 finding (`Team 8 F-01..F-08`, `Neon F-01..F-12`, `Carbon W1A-R16-01..05`)
    // across ALL 4 text surfaces (`diag`, `persisted`, `projected`, `balanced`), verifying zero
    // leaks, 1-step idempotency `f(f(x)) == f(x)`, and two-stage `persisted -> projected` safety.
    let secret_cases: Vec<(String, &'static str)> = vec![
        // Team 8 F-01: `\u0022`-quoted keys/argv with JSON ws escapes, `\n\n`, Unicode HWS, & backslash scalars
        (
            format!(r#"{{"msg":"{{\\u0022{pw}\\u0022:\\n\\u0022SUPER_SECRET\\u0022}}"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg":"{{\\u0022{pw}\\u0022:\\r\\n\\u0022SUPER_SECRET\\u0022}}"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"msg":"{{\\u0022{pw}\\u0022:\\t\\u0022SUPER_SECRET\\u0022}}"}}"#),
            "SUPER_SECRET",
        ),
        (
            format!("[\\u0022pg_dump\\u0022,\n\\u0022--{pw}\\u0022,\n\\u0022SUPER_SECRET\\u0022]"),
            "SUPER_SECRET",
        ),
        (
            format!("{{\\u0022{pw}\\u0022:\n\n\\u0022SUPER_SECRET\\u0022}}"),
            "SUPER_SECRET",
        ),
        (
            format!("{{\\u0022{pw}\\u0022:\u{00A0}\\u0022SUPER_SECRET\\u0022}}"),
            "SUPER_SECRET",
        ),
        (
            format!("{{\\u0022{pw}\\u0022:\u{3000}\\u0022SUPER_SECRET\\u0022}}"),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{\u0022{pw}\u0022: \u0053UPER_SECRET}}"#),
            "UPER_SECRET",
        ),
        (
            format!(r#"{{\u0022{pw}\u0022: \CANARY_BS_SEC}}"#),
            "CANARY_BS_SEC",
        ),
        // Team 8 F-02 = Carbon W1A-R16-01: Quoted CLI flags & argv separated by Unicode HWS
        (
            format!("pg_dump \"--{pw}\"\u{3000}\"SUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (
            format!("pg_dump \"--{pw}\"\u{3000}SUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!("pg_dump \"--{pw}\"\u{2003}SUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!("pg_dump \"--{pw}\"\u{202F}\"SUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (
            format!("pg_dump \"--{pw}\"\u{205F}\"SUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (
            format!("pg_dump \"--{pw}\"\u{1680}SUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!("pg_dump \"--{pw}\"\u{00A0}\"SUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (
            format!("pg_dump \"--{pw}\"\u{00A0}CANARY_SEC"),
            "CANARY_SEC",
        ),
        (
            "curl \"-u\"\u{3000}\"admin:SUPER_SECRET\"".to_string(),
            "SUPER_SECRET",
        ),
        (
            "curl \"--user\"\u{3000}\"admin:SUPER_SECRET\"".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("[\"pg_dump\", \"--{pw}\",\u{00A0}\"SUPER_SECRET\"]"),
            "SUPER_SECRET",
        ),
        (
            format!("[\"pg_dump\", \"--{pw}\"\u{3000}, \"SUPER_SECRET\"]"),
            "SUPER_SECRET",
        ),
        // Team 8 F-03: Surface 3 multiline bare auth schemes inside valid RFC 8259 JSON
        (
            r#"{"msg": "Bearer \nSUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "Digest \nusername=\"a\", response=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        // Team 8 F-04: `\u005c\u0022`-opened multiline secrets
        (
            format!("\"{pw}\":\n\\u005c\\u0022LINE1_SECRET\nLINE2_SECRET\\u005c\\u0022"),
            "LINE1_SECRET",
        ),
        (
            format!("\"{pw}\":\n\\u005c\\u0022LINE1_SECRET\nLINE2_SECRET\\u005c\\u0022"),
            "LINE2_SECRET",
        ),
        (
            format!("{pw}=\\u005c\\u0022part1 SUPER_SECRET\\u005c\\u0022\nstep 2: service healthy"),
            "SUPER_SECRET",
        ),
        // Team 8 F-05: Escaped-quote JSON keys with `\u{3000}` / `\t` & trailing `Digest\t`
        (
            format!("{{\"{pa}=KEY_CANARY \\\"{pw}\": Bearer\u{3000}VAL_CANARY}}"),
            "KEY_CANARY",
        ),
        (
            format!("{{\"{pa}=KEY_CANARY \\\"{pw}\": Bearer\u{3000}VAL_CANARY}}"),
            "VAL_CANARY",
        ),
        (
            format!("{{\"{pa}=KEY_CANARY \\\"{pw}\": Bearer\tVAL_CANARY}}"),
            "KEY_CANARY",
        ),
        (
            format!("{{\"{pa}=KEY_CANARY \\\"{pw}\": Bearer\tVAL_CANARY}}"),
            "VAL_CANARY",
        ),
        (
            format!(r#"{{"{pa}=KEY_CANARY \"{pw}": Bearer\tVAL_CANARY}}"#),
            "KEY_CANARY",
        ),
        (
            format!(r#"{{"{pa}=KEY_CANARY \"{pw}": Bearer\tVAL_CANARY}}"#),
            "VAL_CANARY",
        ),
        (
            format!("{{\"{pw}\": Digest\tusername=\"a\", response=\"SUPER_SECRET\"}}"),
            "SUPER_SECRET",
        ),
        (
            format!(r#"{{"{pw}": Digest\tusername="a", response="SUPER_SECRET"}}"#),
            "SUPER_SECRET",
        ),
        // Neon F-01: `\u005c` chains with embedded credentials & bounded `\u005c\u0075` chains
        (
            format!("user=\"{}admin:SUPER_SECRET\"", "\\u005c".repeat(64)),
            "SUPER_SECRET",
        ),
        (format!("{pw}\\u005c=SUPER_SECRET"), "SUPER_SECRET"),
        (
            format!("{pw}{}=SUPER_SECRET", "\\u005c".repeat(64)),
            "SUPER_SECRET",
        ),
        (
            r#"{"user": "admin\\u005c\\u005c\\u0075003aSUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(
                "\"👨\u{200d}👩\u{200d}👧\u{200d}👦--{tok}\u{3000}café's \"\\x user=a:b user\": \t{pa}\\u0022{pw}\\u0022:\\u0022"
            ),
            "SUPER_SECRET",
        ),
        // Neon F-02: LF (`\n`) and Unicode HWS obs-fold HTTP header continuations
        (
            format!("{hdr_x_api}: part1\n  part2_SUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!("{hdr_auth}: Bearer part1\n  part2_SUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            "Cookie: a=1\n  sid=SUPER_SECRET".to_string(),
            "SUPER_SECRET",
        ),
        (
            "Set-Cookie: a=1\n  sid=SUPER_SECRET".to_string(),
            "SUPER_SECRET",
        ),
        (
            format!("{hdr_x_auth}: part1\n  part2_SUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!("{hdr_proxy}: Basic dXNlcgo=\n  part2_SUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            format!("{hdr_auth}: Bearer [REDACTED]\n  SUPER_SECRET"),
            "SUPER_SECRET",
        ),
        (
            "Cookie: [REDACTED]\n  sid=SUPER_SECRET".to_string(),
            "SUPER_SECRET",
        ),
        (
            "Cookie: a=1\r\n\u{00A0}sid=SUPER_SECRET".to_string(),
            "SUPER_SECRET",
        ),
        (
            "Cookie: a=1;\n\u{00A0}sid=SUPER_SECRET".to_string(),
            "SUPER_SECRET",
        ),
        (
            "Cookie: a=1\n\u{3000}sid=SUPER_SECRET".to_string(),
            "SUPER_SECRET",
        ),
        // Neon F-03: `CurlCmdTracker` / `diag_line_has_curl_user` escaped JSON/quotes inside `"`
        (
            r#"err="curl -d '{\"a\":\"v\"}' -b SUPER_SECRET_CURL""#.to_string(),
            "SUPER_SECRET_CURL",
        ),
        (
            r#"{"cmd": "curl -d '{\"a\":\"v\"}' -b SUPER_SECRET_CURL2"}"#.to_string(),
            "SUPER_SECRET_CURL2",
        ),
        (
            r#"err="curl -d \"a\",\"b\" -su admin:SUPER_SECRET_ESC_C""#.to_string(),
            "SUPER_SECRET_ESC_C",
        ),
        // Neon F-04: `redact_diagnostic` multiline carry across `[REDACTED]` line
        (
            format!("{pw}=\"line1\n[REDACTED]\nSUPER_SECRET_R1\""),
            "SUPER_SECRET_R1",
        ),
        (
            format!("{sec}={{\n[REDACTED]\n  \"v\": \"SUPER_SECRET_R2\"\n}}"),
            "SUPER_SECRET_R2",
        ),
        (
            format!("{toks}=[\n[REDACTED]\n  \"SUPER_SECRET_R3\"\n]"),
            "SUPER_SECRET_R3",
        ),
        // Neon F-05: HTTP `Digest` auth credentials (NBSP, `\u0022`/`\u0027` with spaces, `=\n`, `username*=`, `domain=`)
        (
            "Digest username=\"alice\",\u{00A0}response=\"SECRET_DIGEST_NBSP\"".to_string(),
            "SECRET_DIGEST_NBSP",
        ),
        (
            r#"Digest realm=\u0022My Realm\u0022, response=\u0022SUPER_SECRET_D_U22SP\u0022"#
                .to_string(),
            "SUPER_SECRET_D_U22SP",
        ),
        (
            r#"Digest realm=\u0027My Realm\u0027, response=\u0027SUPER_SECRET_D_U27SP\u0027"#
                .to_string(),
            "SUPER_SECRET_D_U27SP",
        ),
        (
            "Digest username=\n  \"alice\", response=\"SECRET_DIGEST_NL\"".to_string(),
            "SECRET_DIGEST_NL",
        ),
        (
            format!("{hdr_auth}: Digest\nusername*=UTF-8''alice, response=\"SECRET_DIGEST_USTAR\""),
            "SECRET_DIGEST_USTAR",
        ),
        (
            format!("{hdr_auth}: Digest\ndomain=\"/api\", response=\"SECRET_DIGEST_DOM\""),
            "SECRET_DIGEST_DOM",
        ),
        // Neon F-06: `\u0022`-prefixed space-separated CLI flags, `curl`, and `\u003d` argv
        (
            format!(r#"\u0022--{pw} SECRET_U22_SP\u0022"#),
            "SECRET_U22_SP",
        ),
        (
            r#"\u0022curl -b SECRET_U22_B\u0022"#.to_string(),
            "SECRET_U22_B",
        ),
        (
            format!(
                r#"[\u0022curl\u0022, \u0022--{pw}\u003dSUPER_SECRET\u0022, \u0022https://example.com\u0022]"#
            ),
            "SUPER_SECRET",
        ),
        // Neon F-07 = Carbon W1A-R16-04: Full Rust Unicode whitespace parity + JSON escapes
        (
            "Bearer\u{000B}SUPER_SECRET_VT".to_string(),
            "SUPER_SECRET_VT",
        ),
        (
            "Bearer\u{000C}SUPER_SECRET_FF".to_string(),
            "SUPER_SECRET_FF",
        ),
        (
            "Bearer\u{0085}SUPER_SECRET_NEL".to_string(),
            "SUPER_SECRET_NEL",
        ),
        (
            "Bearer\u{2028}SUPER_SECRET_LS".to_string(),
            "SUPER_SECRET_LS",
        ),
        (
            "Bearer\u{2029}SUPER_SECRET_PS".to_string(),
            "SUPER_SECRET_PS",
        ),
        (
            format!("--{pw}\u{000B}SUPER_SECRET_CVT"),
            "SUPER_SECRET_CVT",
        ),
        (
            format!("--{pw}\u{2028}SUPER_SECRET_CLS"),
            "SUPER_SECRET_CLS",
        ),
        (
            "curl\u{000C}-b\u{000C}SUPER_SECRET_CFF".to_string(),
            "SUPER_SECRET_CFF",
        ),
        (
            r#"{"msg": "Bearer\u2028CANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"{"msg": "Bearer\u2029CANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"{"msg": "Bearer\u000bCANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"{"msg": "Bearer\u000cCANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"{"msg": "Bearer\u0085CANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        // Neon F-08: `curl` `-E` / `--cert` / `--proxy-cert` `<cert>:<passphrase>` and `-#u`
        (
            "curl -E client.p12:SUPER_SECRET_CERT https://example.com".to_string(),
            "SUPER_SECRET_CERT",
        ),
        (
            "curl -sE client.p12:SUPER_SECRET_SCERT https://example.com".to_string(),
            "SUPER_SECRET_SCERT",
        ),
        (
            "curl --cert client.p12:SUPER_SECRET_LCERT https://example.com".to_string(),
            "SUPER_SECRET_LCERT",
        ),
        (
            "curl --cert=client.p12:SUPER_SECRET_ECERT https://example.com".to_string(),
            "SUPER_SECRET_ECERT",
        ),
        (
            "curl --proxy-cert proxy.p12:SUPER_SECRET_PCERT https://example.com".to_string(),
            "SUPER_SECRET_PCERT",
        ),
        (
            "curl --proxy-cert=proxy.p12:SUPER_SECRET_EPCERT https://example.com".to_string(),
            "SUPER_SECRET_EPCERT",
        ),
        (
            "curl -#u admin:SUPER_SECRET_HASH https://example.com".to_string(),
            "SUPER_SECRET_HASH",
        ),
        // Carbon W1A-R16-02: Unpaired UTF-16 surrogates (`\ud800`..`\udfff`) in quoted keys
        (
            r#"{"\ud800user": "admin:CANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        (format!(r#"{{"\ud800{pw}": "CANARY_SEC"}}"#), "CANARY_SEC"),
        (format!(r#"{{"\udc00{pw}": "CANARY_SEC"}}"#), "CANARY_SEC"),
        (format!(r#"{{"\udfff{sec}": "CANARY_SEC"}}"#), "CANARY_SEC"),
        (
            format!(r#"{{"\ud800{pw}": {{"v": "CANARY_SEC"}}}}"#),
            "CANARY_SEC",
        ),
        (format!(r#"'\ud800{pw}': 'CANARY_SEC'"#), "CANARY_SEC"),
        // Carbon W1A-R16-03 + Neon F-10 part 2: Unclosed-quote bracketed/braced prefixes & `\u002f` curl
        (format!(r#"["5 inch] {{"{pw}": "CANARY_S1"}}"#), "CANARY_S1"),
        (
            format!(r#"{{"5 inch}} {{"{pw}": "CANARY_S1"}}"#),
            "CANARY_S1",
        ),
        (
            format!(r#"[true, "5 inch] {{"{pw}": "CANARY_S1"}}"#),
            "CANARY_S1",
        ),
        (
            format!(r#"log ["msg: {{"{pw}": "SUPER_SECRET_OPEN4"}}"#),
            "SUPER_SECRET_OPEN4",
        ),
        (
            r#"["5 inch] ["\u002fusr\u002fbin\u002fcurl", "-b", "CANARY_SEC"]"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"["\u002fusr\u002fbin\u002fcurl", "-b", "CANARY_SEC"]"#.to_string(),
            "CANARY_SEC",
        ),
        // Neon F-12 part 2: `{password=SECRET}\u{00A0}status=ok`
        (
            format!("{{{pw}=SUPER_SECRET}}\u{00A0}status=ok"),
            "SUPER_SECRET",
        ),
    ];

    for (input, secret) in &secret_cases {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R17 [{label}] leaked {secret:?} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R17 [{label}] failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
        let persisted_once = sanitize_persisted_lifecycle_text(input);
        let projected_after = diagnostic_projection::redact_secrets(&persisted_once);
        assert!(
            !projected_after.contains(secret),
            "R17 two-stage leaked {secret:?} for {input:?} -> {projected_after:?}"
        );
    }

    // 2. Direct `redact_json_value` & valid RFC 8259 JSON preservation across `projected` & `balanced`
    let valid_json_r17: Vec<(String, &'static str)> = vec![
        (
            format!(r#"{{"msg":"{{\\u0022{pw}\\u0022:\\n\\u0022SUPER_SECRET\\u0022}}"}}"#),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "Bearer \nSUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "Digest \nusername=\"a\", response=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"cmd": "curl -d '{\"a\":\"v\"}' -b SUPER_SECRET_CURL2"}"#.to_string(),
            "SUPER_SECRET_CURL2",
        ),
        (
            r#"{"user": "admin\\u005c\\u005c\\u0075003aSUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"msg": "Bearer\u2028CANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"{"msg": "Bearer\u2029CANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"{"msg": "Bearer\u000bCANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"{"msg": "Bearer\u000cCANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"{"msg": "Bearer\u0085CANARY_SEC"}"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"["\u002fusr\u002fbin\u002fcurl", "-b", "CANARY_SEC"]"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"["curl", "-E", "client.p12:CANARY_SEC", "https://example.com"]"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"["curl", "--cert", "client.p12:CANARY_SEC", "https://example.com"]"#.to_string(),
            "CANARY_SEC",
        ),
        (
            r#"["curl", "-#u", "admin:CANARY_SEC", "https://example.com"]"#.to_string(),
            "CANARY_SEC",
        ),
    ];

    for (raw_json, forbidden) in &valid_json_r17 {
        let mut val: serde_json::Value = serde_json::from_str(raw_json).unwrap();
        assert!(
            diagnostic_projection::redact_json_value(&mut val),
            "R17 redact_json_value must report modification for {raw_json:?}"
        );
        let ser = serde_json::to_string(&val).unwrap();
        assert!(
            !ser.contains(forbidden),
            "R17 redact_json_value leaked {forbidden:?} for {raw_json:?} -> {ser:?}"
        );
        let mut val2 = val.clone();
        assert!(
            !diagnostic_projection::redact_json_value(&mut val2),
            "R17 redact_json_value returned true on 2nd pass for {raw_json:?}"
        );
        assert_eq!(val2, val);

        for (label, f) in [
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(raw_json);
            assert!(
                !out.contains(forbidden),
                "R17 [{label}] leaked {forbidden:?} for {raw_json:?} -> {out:?}"
            );
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R17 [{label}] broke valid JSON ({e}) for {raw_json:?} -> {out:?}")
            });
            assert_eq!(f(&out), out, "R17 [{label}] JSON idempotency: {raw_json:?}");
        }
    }

    // 3. Direct `redact_embedded_json_spans` verification (`Carbon W1A-R16-03` & `Neon F-10 part 2`)
    for (emb, prefix, forbidden) in [
        (
            format!(r#"["5 inch] {{"{pw}": "CANARY_S1"}}"#),
            "[\"5 inch] ",
            "CANARY_S1",
        ),
        (
            format!(r#"{{"5 inch}} {{"{pw}": "CANARY_S1"}}"#),
            "{\"5 inch} ",
            "CANARY_S1",
        ),
        (
            format!(r#"[true, "5 inch] {{"{pw}": "CANARY_S1"}}"#),
            "[true, \"5 inch] ",
            "CANARY_S1",
        ),
        (
            format!(r#"log ["msg: {{"{pw}": "SUPER_SECRET_OPEN4"}}"#),
            "log [\"msg: ",
            "SUPER_SECRET_OPEN4",
        ),
        (
            r#"["5 inch] ["\u002fusr\u002fbin\u002fcurl", "-b", "CANARY_SEC"]"#.to_string(),
            "[\"5 inch] ",
            "CANARY_SEC",
        ),
    ] {
        let out = diagnostic_projection::redact_embedded_json_spans(&emb);
        assert!(
            !out.contains(forbidden),
            "R17 redact_embedded_json_spans leaked {forbidden:?} for {emb:?} -> {out:?}"
        );
        assert!(
            out.starts_with(prefix),
            "R17 redact_embedded_json_spans altered prefix {prefix:?}: {out:?}"
        );
        serde_json::from_str::<serde_json::Value>(&out[prefix.len()..]).unwrap_or_else(|e| {
            panic!("R17 redact_embedded_json_spans emitted invalid embedded JSON ({e}): {out:?}")
        });
        assert_eq!(
            diagnostic_projection::redact_embedded_json_spans(&out),
            out,
            "R17 redact_embedded_json_spans idempotency failed for {emb:?}"
        );
    }

    // 4. Benign preservation & exact non-overconsumption checks across all surfaces
    let benign_all_4: Vec<&str> = vec![
        "curl https://example.com\n-b feature-branch",
        "curl https://example.com;-b feature-branch",
        "https://example.com\u{00A0}alice@corp.com",
        "https://example.com\u{3000}alice@corp.com",
        "https://example.com\u{00A0}alice@example.com",
        r#"{"\u0075ser": "alice"}"#,
        r#"{"msg": "{\"\\u0075ser\": \"alice\"}"}"#,
        "curl -E /etc/ssl/client.pem",
        "curl -E /etc/ssl/client.pem https://example.com",
        "curl --cert /etc/ssl/client.pem https://example.com",
        r#"["curl", "-E", "/etc/ssl/client.pem", "https://example.com"]"#,
        r#"{"cmd": "curl", "items": ["-b", "benign_item"]}"#,
    ];
    for benign in benign_all_4 {
        for &(label, f) in &eps {
            let out = f(benign);
            assert_eq!(
                out, benign,
                "R17 [{label}] mutated benign input {benign:?} -> {out:?}"
            );
        }
        assert!(
            matches!(
                af_models::secret_redaction::redact_diagnostic(benign),
                std::borrow::Cow::Borrowed(_)
            ),
            "redact_diagnostic allocated on benign R17 input: {benign:?}"
        );
        assert!(
            matches!(
                sanitize_persisted_lifecycle_text_cow(benign),
                std::borrow::Cow::Borrowed(_)
            ),
            "sanitize_persisted_lifecycle_text_cow allocated on benign R17 input: {benign:?}"
        );
        if benign.starts_with(['{', '[']) {
            let orig: serde_json::Value = serde_json::from_str(benign).unwrap();
            let mut copy = orig.clone();
            assert!(!diagnostic_projection::redact_json_value(&mut copy));
            assert_eq!(copy, orig, "redact_json_value mutated benign {benign:?}");
        }
    }

    // Team 8 F-03 benign JSON multiline bare `Bearer \nHost:` / `\n\n` preservation
    for benign_json_auth in [
        r#"{"msg": "Bearer \nHost: example.com"}"#,
        r#"{"msg": "Bearer \n\nstep 2: service healthy"}"#,
    ] {
        for (label, f) in [
            (
                "persisted",
                sanitize_persisted_lifecycle_text as fn(&str) -> String,
            ),
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            assert_eq!(
                f(benign_json_auth),
                benign_json_auth,
                "R17 [{label}] over-redacted benign multiline bare Bearer JSON {benign_json_auth:?}"
            );
        }
    }

    // Neon F-12 part 1: standalone CR `Cookie:\rHost: example.com` preserves `Host: example.com`
    assert_eq!(
        af_models::secret_redaction::redact_diagnostic("Cookie:\rHost: example.com"),
        "[REDACTED]\rHost: example.com",
        "redact_diagnostic must preserve Host header after standalone CR"
    );
    for &(label, f) in &eps {
        let cr_out = f("Cookie:\rHost: example.com");
        assert!(
            cr_out.contains("Host: example.com"),
            "R17 [{label}] destroyed Host header after standalone CR: {cr_out:?}"
        );
        assert_eq!(f(&cr_out), cr_out);
    }

    // Neon F-12 part 2: `{password=SECRET}\u{00A0}status=ok` preserves closing `}` + tail
    let f12_brace_nbsp = format!("{{{pw}=SUPER_SECRET}}\u{00A0}status=ok");
    let f12_brace_expected = format!("{{{pw}=[REDACTED]}}\u{00A0}status=ok");
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        assert_eq!(
            f(&f12_brace_nbsp),
            f12_brace_expected,
            "R17 [{label}] consumed closing brace before NBSP"
        );
    }

    // Team 8 F-04: `password=\u005c\u0022part1 SUPER_SECRET\u005c\u0022\nstep 2: service healthy`
    // closes cleanly and preserves `\nstep 2: service healthy` across all 4 surfaces
    let f04_close_sample =
        format!("{pw}=\\u005c\\u0022part1 SUPER_SECRET\\u005c\\u0022\nstep 2: service healthy");
    for &(label, f) in &eps {
        let out = f(&f04_close_sample);
        assert!(
            !out.contains("SUPER_SECRET"),
            "R17 [{label}] leaked: {out:?}"
        );
        assert!(
            out.ends_with("\nstep 2: service healthy"),
            "R17 [{label}] swallowed benign trailing line after \\u005c\\u0022: {out:?}"
        );
        assert_eq!(f(&out), out);
    }

    // Neon F-06: `[\u0022curl\u0022, \u0022--password\u003dSECRET\u0022, \u0022https://example.com\u0022]`
    // preserves trailing `, \u0022https://example.com\u0022]`
    let f06_u003d_argv = format!(
        r#"[\u0022curl\u0022, \u0022--{pw}\u003dSUPER_SECRET\u0022, \u0022https://example.com\u0022]"#
    );
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let out = f(&f06_u003d_argv);
        assert!(
            !out.contains("SUPER_SECRET"),
            "R17 [{label}] leaked: {out:?}"
        );
        assert!(
            out.contains(r#", \u0022https://example.com\u0022]"#),
            "R17 [{label}] swallowed trailing argv element: {out:?}"
        );
        assert_eq!(f(&out), out);
    }

    // 5. SQLite Persistence Regressions (`Neon F-10` >128 deep JSON, `Carbon W1A-R16-01/02`,
    // `Team 8 F-08` fallback `expected_target_version`, `Neon F-11` tampered identity columns)
    {
        let (root, _, _database, mut conn) = fixture();

        // (a) Neon F-10 part 1: >128-deep valid RFC 8259 JSON keeps quoted `"[REDACTED]"`
        let deep_json = format!(
            "{{\"{pw}\":\"SECRET_DEEP_SQL_R17\",\"deep\":{}1{}}}",
            "{\"a\":".repeat(130),
            "}".repeat(130)
        );
        let lease_deep = admit_job_with_target(
            &mut conn,
            "pkg-r17-deep",
            "job-r17-deep",
            "update",
            "2026-11-27T12:00:00Z",
            &[],
            Some("1.0.0"),
        )
        .unwrap();
        record_completed_lifecycle_job(
            &conn,
            "pkg-r17-deep",
            "job-r17-deep",
            "update",
            Some(&deep_json),
            Some("1.0.0"),
            Some("1.0.0"),
        )
        .unwrap();
        let raw_deep_sum: String = conn
            .query_row(
                "SELECT sanitized_summary FROM package_lifecycle_history WHERE job_id = 'job-r17-deep'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let expected_quoted = format!("\"{pw}\":\"[REDACTED]\"");
        let forbidden_unquoted = format!("\"{pw}\":[REDACTED]");
        assert!(!raw_deep_sum.contains("SECRET_DEEP_SQL_R17"));
        assert!(raw_deep_sum.contains(&expected_quoted));
        assert!(!raw_deep_sum.contains(&forbidden_unquoted));

        // (b) Carbon W1A-R16-01 & W1A-R16-02: Unicode HWS quoted CLI flag + lone surrogate key never reach SQLite
        let surr_target = format!(r#"{{"\ud800{pw}": "SQLITE_SURR_TARGET_R17"}}"#);
        let hws_summary = format!("pg_dump \"--{pw}\"\u{3000}SQLITE_HWS_SUM_R17");
        let lease_surr = admit_job_with_target(
            &mut conn,
            "pkg-r17-surr",
            "job-r17-surr",
            "update",
            "2026-11-27T12:01:00Z",
            &[],
            Some(&surr_target),
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "pkg-r17-surr",
            "job-r17-surr",
            "update",
            false,
            LifecycleJobDiagnostics {
                failure_category: "install_failed",
                sanitized_summary: Some(&hws_summary),
                finished_at: Some("2026-11-27T12:02:00Z"),
                ..Default::default()
            },
        )
        .unwrap();
        let (raw_surr_exp, raw_hws_sum): (String, String) = conn
            .query_row(
                "SELECT expected_target_version, sanitized_summary FROM package_lifecycle_history WHERE job_id = 'job-r17-surr'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(!raw_surr_exp.contains("SQLITE_SURR_TARGET_R17"));
        assert!(!raw_hws_sum.contains("SQLITE_HWS_SUM_R17"));

        // (c) Team 8 F-08: fallback history insert preserves `expected_target_version` from `package_lifecycle_jobs`
        let lease_fb = admit_job_with_target(
            &mut conn,
            "pkg-r17-fb",
            "job-r17-fb",
            "update",
            "2026-11-27T12:03:00Z",
            &[],
            Some("5.2.0"),
        )
        .unwrap();
        conn.execute(
            "DELETE FROM package_lifecycle_history WHERE package_id = 'pkg-r17-fb' AND job_id = 'job-r17-fb'",
            [],
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "pkg-r17-fb",
            "job-r17-fb",
            "update",
            true,
            LifecycleJobDiagnostics {
                expected_target_version: None,
                achieved_version: Some("5.2.0"),
                finished_at: Some("2026-11-27T12:04:00Z"),
                ..Default::default()
            },
        )
        .unwrap();
        let fb_hist = get_lifecycle_history(&conn, "pkg-r17-fb", 5).unwrap();
        assert_eq!(fb_hist.len(), 1);
        assert_eq!(fb_hist[0].expected_target_version.as_deref(), Some("5.2.0"));

        // (d) Neon F-11: tampered `job_id`, `action`, `status` scrubbed on read
        let tamper_jid = "job Bearer TAMPER_JID_R17";
        let tamper_act = format!("update {pw}=TAMPER_ACT_R17");
        let tamper_st = format!("failed {tok}=TAMPER_ST_R17");
        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at, retention_state
            ) VALUES ('pkg-r17-tamper', ?1, ?2, ?3, '2026-11-27T12:05:00Z', '2026-11-27T12:06:00Z', 'retained')",
            rusqlite::params![tamper_jid, tamper_act, tamper_st],
        )
        .unwrap();
        let tamper_hist = get_lifecycle_history(&conn, "pkg-r17-tamper", 5).unwrap();
        assert_eq!(tamper_hist.len(), 1);
        assert!(!tamper_hist[0].job_id.contains("TAMPER_JID_R17"));
        assert!(!tamper_hist[0].action.contains("TAMPER_ACT_R17"));
        assert!(!tamper_hist[0].status.contains("TAMPER_ST_R17"));

        conn.execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at, retention_state
            ) VALUES ('pkg-r17-ret', ?1, ?2, 'completed', '2026-11-27T12:07:00Z', '2026-11-27T12:08:00Z', 'retained')",
            rusqlite::params![tamper_jid, tamper_act],
        )
        .unwrap();
        let ret_rec = query_package_retention_history(&conn, "pkg-r17-ret")
            .unwrap()
            .expect("retention record");
        assert!(!ret_rec.job_id.contains("TAMPER_JID_R17"));
        assert!(!ret_rec.action.contains("TAMPER_ACT_R17"));
        assert_eq!(ret_rec.status, "completed");

        drop(lease_fb);
        drop(lease_surr);
        drop(lease_deep);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    // 6. Adaptive linear-time O(N) scaling (`ratio < 3.2`) for `user="\u005c"*N`,
    // `{"user": "\\u005c"*N}` (`redact_json_value` + text surfaces), `["5 inch] *N`
    // (`redact_embedded_json_spans` & `redact_secrets` + all surfaces), `-E /etc/ssl/client.pem`,
    // `username*=`, and `\u005c\u0022`.
    type R17Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r17_scaling: &[R17Scaling] = &[
        (
            "r17_f01_user_u005c_chain",
            |n| format!("user=\"{}\"", "\\u005c".repeat(n)),
            400,
            64_000,
        ),
        (
            "r17_f01_json_user_u005c_chain",
            |n| format!("{{\"user\":\"{}\"}}", "\\\\u005c".repeat(n)),
            400,
            64_000,
        ),
        (
            "r17_r16_03_unclosed_bracket_prefix",
            |n| "[\"5 inch] ".repeat(n),
            400,
            64_000,
        ),
        (
            "r17_r16_03_unclosed_bracket_prefix_json",
            make_r17_unclosed_bracket_prefix_json,
            400,
            64_000,
        ),
        (
            "r17_f08_curl_cert_pem",
            |n| format!("curl {}", "-E /etc/ssl/client.pem ".repeat(n)),
            400,
            64_000,
        ),
        (
            "r17_f05_digest_username_star",
            |n| format!("Digest {}", "username*=UTF-8''alice, ".repeat(n)),
            400,
            64_000,
        ),
        (
            "r17_f04_composite_u005c_u0022",
            make_r17_composite_u005c_u0022,
            300,
            32_000,
        ),
    ];
    let started_r17 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r17_scaling {
        for &(ep, f) in &eps {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }
    assert_adaptive_linear_scaling(
        "r17_f01_redact_json_value_user_u005c",
        "redact_json_value",
        |n| format!("{{\"user\":\"{}\"}}", "\\\\u005c".repeat(n)),
        400,
        64_000,
        |p| {
            let mut v: serde_json::Value = serde_json::from_str(p).unwrap();
            usize::from(diagnostic_projection::redact_json_value(&mut v))
                + v["user"].as_str().map_or(0, str::len)
        },
    );
    assert_adaptive_linear_scaling(
        "r17_r16_03_embedded_unclosed_bracket_prefix",
        "embedded_json",
        |n| "[\"5 inch] ".repeat(n),
        400,
        64_000,
        |p| diagnostic_projection::redact_embedded_json_spans(p).len(),
    );
    assert_adaptive_linear_scaling(
        "r17_r16_03_embedded_unclosed_bracket_prefix_json",
        "embedded_json",
        make_r17_unclosed_bracket_prefix_json,
        400,
        64_000,
        |p| diagnostic_projection::redact_embedded_json_spans(p).len(),
    );

    assert!(
        started_r17.elapsed() < std::time::Duration::from_secs(90),
        "R17 linear-time budget exceeded: {:?}",
        started_r17.elapsed()
    );
}

fn make_r18_f2_u0022_containers(n: usize) -> String {
    let sec = concat!("sec", "ret");
    format!("{sec}: {{\\u0022a\\u0022: \\u0022}}\\u0022, \\u0022v\\u0022: \\u0022s\\u0022}}, ")
        .repeat(n)
}

fn make_r18_f7_header_quote_cache(n: usize) -> String {
    format!(
        "\"Cookie: a\n\n{}\n\"bar",
        "x=\"Cookie: b\n\nc\"\n".repeat(n)
    )
}

#[test]
fn test_wave1a_r18_audit_regressions() {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 4] = [
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
    ];

    let pw = concat!("pass", "word");
    let pa = concat!("pa", "ss");
    let sec = concat!("sec", "ret");
    let toks = concat!("tok", "ens");
    let hdr_x_api = concat!("X-Api-", "Key");
    let hdr_proxy = concat!("Proxy-Authori", "zation");
    let hdr_auth = concat!("Authori", "zation");

    // 1. Every R17 finding (`Team 8 F1..F9`, `Neon AUD-01..06`, `Carbon W1A-R17-01..06`)
    // across ALL 4 text surfaces (`diag`, `persisted`, `projected`, `balanced`), verifying zero
    // leaks, 1-step idempotency `f(f(x)) == f(x)`, and two-stage `persisted -> projected` safety.
    let secret_cases: Vec<(String, &'static str)> = vec![
        // Team 8 F1: Eliminate fail-open `no_colon_until = text.len()` budget watermarks
        (
            format!(
                "{}{} user=admin:SUPER_SECRET_F1A",
                "user=a\\ system:{ ".repeat(10),
                "x".repeat(400)
            ),
            "SUPER_SECRET_F1A",
        ),
        (
            format!(
                "{}{} curl -uadmin:SUPER_SECRET_F1A_U",
                "user=a\\ system:{ ".repeat(10),
                "x".repeat(400)
            ),
            "SUPER_SECRET_F1A_U",
        ),
        (
            format!(
                "{}{} --cert client.pem:PASSPHRASE_SECRET_F1B",
                "--cert=http://{ ".repeat(10),
                "x".repeat(400)
            ),
            "PASSPHRASE_SECRET_F1B",
        ),
        (
            format!(
                "{}{} curl --proxy-cert proxy.pem:PASSPHRASE_SECRET_F1C",
                "--cert=http://{ ".repeat(10),
                "x".repeat(400)
            ),
            "PASSPHRASE_SECRET_F1C",
        ),
        (
            format!(
                "{}{} curl -E client.pem:PASSPHRASE_SECRET_F1D",
                "--cert=http://{ ".repeat(10),
                "x".repeat(400)
            ),
            "PASSPHRASE_SECRET_F1D",
        ),
        (
            format!(
                "{}{} --cert=client.pem:PASSPHRASE_SECRET_F1E",
                "--cert=\\a{ ".repeat(10),
                "x".repeat(400)
            ),
            "PASSPHRASE_SECRET_F1E",
        ),
        // Team 8 F2: `\u0022` / `\u0027` / `\u005c\u0022` quotes inside sensitive containers
        (
            format!(
                "{sec}: {{\n  \\u0022a\\u0022: \\u0022}}\\u0022,\n  \\u0022val\\u0022: \\u0022SUPER_SECRET_F2A\\u0022\n}}"
            ),
            "SUPER_SECRET_F2A",
        ),
        (
            format!(
                "{sec}: {{\\u0022a\\u0022: \\u0022}}\\u0022, \\u0022val\\u0022: \\u0022SUPER_SECRET_F2B\\u0022}}"
            ),
            "SUPER_SECRET_F2B",
        ),
        (
            format!(
                "{sec}: {{\\u0027a\\u0027: \\u0027}}\\u0027, \\u0027val\\u0027: \\u0027SUPER_SECRET_F2C\\u0027}}"
            ),
            "SUPER_SECRET_F2C",
        ),
        (
            format!(
                "{sec}: {{\\u005c\\u0022a\\u005c\\u0022: \\u005c\\u0022}}\\u005c\\u0022, \\u005c\\u0022val\\u005c\\u0022: \\u005c\\u0022SUPER_SECRET_F2D\\u005c\\u0022}}"
            ),
            "SUPER_SECRET_F2D",
        ),
        (
            "Bearer { \\u0022a\\u0022: \\u0022}\\u0022, \\u0022val\\u0022: \\u0022SUPER_SECRET_F2E\\u0022 }"
                .to_string(),
            "SUPER_SECRET_F2E",
        ),
        (
            "Bearer {\n  \\u0022a\\u0022: \\u0022}\\u0022,\n  \\u0022val\\u0022: \\u0022SUPER_SECRET_F2F\\u0022\n}"
                .to_string(),
            "SUPER_SECRET_F2F",
        ),
        (
            format!("{toks}: [\\u0022]\\u0022, \\u0022SUPER_SECRET_F2G\\u0022]"),
            "SUPER_SECRET_F2G",
        ),
        // Team 8 F3 = Neon AUD-02 = Carbon W1A-R17-03: `\u003a` on curl cert flags & quoted `"-u"`
        // + Carbon W1A-R17-06 Windows drive-letter cert path with passphrase
        (
            r#"curl --cert client.p12\u003aSECRET_CERT_01 https://example.com"#.to_string(),
            "SECRET_CERT_01",
        ),
        (
            r#"curl --cert=client.p12\u003aCANARY_CERT_EQ https://example.com"#.to_string(),
            "CANARY_CERT_EQ",
        ),
        (
            r#"curl --proxy-cert proxy.p12\u003aSECRET_CERT_02 https://example.com"#.to_string(),
            "SECRET_CERT_02",
        ),
        (
            r#"curl --proxy-cert=proxy.p12\u003aSECRET_CERT_03 https://example.com"#.to_string(),
            "SECRET_CERT_03",
        ),
        (
            r#"curl -E client.p12\u003aCANARY_CERT_E https://example.com"#.to_string(),
            "CANARY_CERT_E",
        ),
        (
            r#"curl -Eclient.p12\u003aSECRET_CERT_04 https://example.com"#.to_string(),
            "SECRET_CERT_04",
        ),
        (
            r#"curl -sE client.p12\u003aSECRET_CERT_05 https://example.com"#.to_string(),
            "SECRET_CERT_05",
        ),
        (
            r#"curl -sEclient.p12\u003aSECRET_CERT_06 https://example.com"#.to_string(),
            "SECRET_CERT_06",
        ),
        (
            r#"curl --cert client.p12\u005cu003aSECRET_CERT_07 https://example.com"#.to_string(),
            "SECRET_CERT_07",
        ),
        (
            r#"["curl", "--cert=client.p12\\u003aSEC_CJ2"]"#.to_string(),
            "SEC_CJ2",
        ),
        (
            r#"{"cmd":"curl --cert client.p12\\u003aSEC_CJ1 https://example.com"}"#.to_string(),
            "SEC_CJ1",
        ),
        (
            r#"{"cmd": "curl -E client.p12\\u003aCANARY_CERT_JSON https://example.com"}"#
                .to_string(),
            "CANARY_CERT_JSON",
        ),
        (
            r#"["curl", "-Eclient.p12\\u003aSEC_CJ5"]"#.to_string(),
            "SEC_CJ5",
        ),
        (r#""-u" "admin\u003aSEC_QU2""#.to_string(), "SEC_QU2"),
        (
            r#"curl -E C:\certs\client.p12:CANARY_WIN_CERT1 https://example.com"#.to_string(),
            "CANARY_WIN_CERT1",
        ),
        (
            r#"["curl", "--cert", "C:\\certs\\client.p12:CANARY_WIN_CERT2"]"#.to_string(),
            "CANARY_WIN_CERT2",
        ),
        // Team 8 F4: `\u003a` inside quoted `user="a,b\u003a..."` & composite `\u005c\u0022` pairs
        (r#"user="a,b\u003aSUPER_SECRET_F4A""#.to_string(), "SUPER_SECRET_F4A"),
        (r#"user="a;b\u003aSUPER_SECRET_F4B""#.to_string(), "SUPER_SECRET_F4B"),
        (
            r#"["-u", "a,b\u003aSUPER_SECRET_F4C"]"#.to_string(),
            "SUPER_SECRET_F4C",
        ),
        (
            r#"{"args": ["-u", "a,b\\u003aSUPER_SECRET_F4D"]}"#.to_string(),
            "SUPER_SECRET_F4D",
        ),
        (
            r#"{\u005c\u0022user\u005c\u0022: \u005c\u0022admin\u003aSUPER_SECRET_F4E\u005c\u0022}"#
                .to_string(),
            "SUPER_SECRET_F4E",
        ),
        (
            r#"[\u005c\u0022-u\u005c\u0022, \u005c\u0022admin\u003aSUPER_SECRET_F4F\u005c\u0022]"#
                .to_string(),
            "SUPER_SECRET_F4F",
        ),
        // Team 8 F5: Inner `'...'` before JSON-escaped `\n`/`\r` in quoted HTTP headers
        (
            r#"Err("Cookie: sid='line1\nSUPER_SECRET_F5A'")"#.to_string(),
            "SUPER_SECRET_F5A",
        ),
        (
            r#"Err("Cookie: sid='line1\rSUPER_SECRET_F5B'")"#.to_string(),
            "SUPER_SECRET_F5B",
        ),
        (
            r#"{"hdr": "Cookie: sid='line1\nSUPER_SECRET_F5C'"}"#.to_string(),
            "SUPER_SECRET_F5C",
        ),
        (
            format!(r#"Err("{hdr_auth}: Bearer 'line1\nSUPER_SECRET_F5D'")"#),
            "SUPER_SECRET_F5D",
        ),
        (
            format!(r#"{{"hdr": "{hdr_auth}: Bearer 'line1\nSUPER_SECRET_F5E'"}}"#),
            "SUPER_SECRET_F5E",
        ),
        // Team 8 F6: Opening-line odd-escaped quotes `\"` / `\'` in `extend_obs_fold_header_end`
        (
            "Cookie: a=\\\"line1\nSUPER_SECRET_F6A\\\"".to_string(),
            "SUPER_SECRET_F6A",
        ),
        (
            format!("{hdr_auth}: Bearer \\\"line1\nSUPER_SECRET_F6B\\\""),
            "SUPER_SECRET_F6B",
        ),
        (
            format!("{hdr_x_api}: a=\\'line1\nSUPER_SECRET_F6C\\'"),
            "SUPER_SECRET_F6C",
        ),
        // Team 8 F7: `HeaderLineQuoteCache::multiline_no_close_until` cache poisoning
        (
            "\"Cookie: a\n\nx=\"Cookie: b\n\nSUPER_SECRET_F7\"\n\"bar".to_string(),
            "SUPER_SECRET_F7",
        ),
        // Team 8 F9 curl argv container
        (
            r#"["curl", "--cert", "/etc/ssl/client.pem", "-u", {"x": "SUPER_SECRET_F9C"}]"#
                .to_string(),
            "SUPER_SECRET_F9C",
        ),
        // Neon AUD-01: ASCII VT `0x0B` / FF `0x0C` / BS `0x08` in JSON keys & RFC 8259 `\f` / `\b`
        (
            r#"{"Bearer\u000bSECRET_VT_01": "ok"}"#.to_string(),
            "SECRET_VT_01",
        ),
        (
            r#"{"note\u000cBasic\u000cSEC_NVT4": "ok"}"#.to_string(),
            "SEC_NVT4",
        ),
        (
            r#"{"curl\u000b-b\u000bSEC_NVT5": "ok"}"#.to_string(),
            "SEC_NVT5",
        ),
        (r#"{"Basic\fSEC_KF1":"ok"}"#.to_string(), "SEC_KF1"),
        (r#"{"curl\f-u\fSEC_KF3":"ok"}"#.to_string(), "SEC_KF3"),
        (r#"{"msg":"Bearer\fSEC_F1"}"#.to_string(), "SEC_F1"),
        (format!(r#"{{"msg":"--{pw}\fSEC_F4"}}"#), "SEC_F4"),
        (r#"{"msg":"curl\f-u\fadmin:SEC_F5"}"#.to_string(), "SEC_F5"),
        (r#"{"msg":"ok\bBearer SEC_B1"}"#.to_string(), "SEC_B1"),
        ("{\"Bearer\x0bSEC_LVT1\": \"ok\"}".to_string(), "SEC_LVT1"),
        (
            format!(
                "{{\"msg\":\"Bearer\\fSEC_DF1\",\"d\":{}1{}}}",
                "{\"a\":".repeat(130),
                "}".repeat(130)
            ),
            "SEC_DF1",
        ),
        // Neon AUD-03: Double-escaped Unicode chains (`\u005c\u0075XXXX`)
        (
            r#"https://admin:SECRET_URL_02\u005c\u00750040example.com/path"#.to_string(),
            "SECRET_URL_02",
        ),
        (
            r#"{"url":"https://admin:SEC_UU8\\u005c\\u00750040example.com/p"}"#.to_string(),
            "SEC_UU8",
        ),
        (
            r#"https:\u005c\u0075002f\u005c\u0075002fadmin:SECRET_URL_03@example.com/path"#
                .to_string(),
            "SECRET_URL_03",
        ),
        (
            r#"ssh://git\u005c\u0075003aSECRET_URL_09@github.com/org/repo"#.to_string(),
            "SECRET_URL_09",
        ),
        (r#"\u005c\u00750042earer SEC_UU4"#.to_string(), "SEC_UU4"),
        (r#"Bearer\u005c\u00750020SEC_UU5"#.to_string(), "SEC_UU5"),
        (
            r#"Cookie\u005c\u0075003a sid=SEC_U5H2"#.to_string(),
            "SEC_U5H2",
        ),
        (format!(r#"{pw}\u005c\u0075003dSEC_U5E1"#), "SEC_U5E1"),
        (format!(r#"\u005c\u0075002d-{pw} SEC_U5F1"#), "SEC_U5F1"),
        (
            r#"\u005c\u00750063url -b sid=SEC_U5C1 https://example.com"#.to_string(),
            "SEC_U5C1",
        ),
        (
            format!(r#"\u005c\u00750022{pw}\u005c\u00750022: "SEC_U5Q1""#),
            "SEC_U5Q1",
        ),
        // Neon AUD-04: Multiline HTTP `Authorization`/`Proxy-Authorization` (`Digest`/bare-scheme blank lines) & `Cookie`
        (
            format!("{hdr_auth}: Digest\nusername=\"alice\",\nresponse=\"SEC_DG1\""),
            "SEC_DG1",
        ),
        (
            format!("{hdr_proxy}: Digest\nusername=\"alice\",\nresponse=\"SEC_DG_PROXY\""),
            "SEC_DG_PROXY",
        ),
        (
            format!("{hdr_auth}: Digest username=\"alice\",\nresponse=\"SEC_DG2\""),
            "SEC_DG2",
        ),
        (
            format!(r#"{{"h":"{hdr_auth}: Digest\nusername=\"alice\",\nresponse=\"SEC_DG8\""}}"#),
            "SEC_DG8",
        ),
        ("Cookie: a=1;\nsid=SEC_CK1".to_string(), "SEC_CK1"),
        ("Set-Cookie: a=1;\nsid=SEC_CK2".to_string(), "SEC_CK2"),
        (format!("{hdr_auth}: Bearer\n\nSEC_BR1"), "SEC_BR1"),
        (
            format!("{hdr_auth}: Basic\n\ndXNlcjpTRUNfQkFTMQ=="),
            "dXNlcjpTRUNfQkFTMQ==",
        ),
        (format!("{hdr_proxy}: Bearer\n\nSEC_PBR1"), "SEC_PBR1"),
        (
            format!(r#"{{"h":"{hdr_auth}: Bearer\n\nSEC_JBL1"}}"#),
            "SEC_JBL1",
        ),
        // Neon AUD-05: Multiline `curl --cert` / `--proxy-cert` / `-E` / `-sE` passphrases
        (
            "curl --cert=\nclient.p12:SEC_CM1 https://example.com".to_string(),
            "SEC_CM1",
        ),
        (
            "curl --proxy-cert=\nproxy.p12:SEC_CM2 https://example.com".to_string(),
            "SEC_CM2",
        ),
        (
            "curl -E=\nclient.p12:SEC_CM3 https://example.com".to_string(),
            "SEC_CM3",
        ),
        (
            "curl -sE=\nclient.p12:SEC_CM4 https://example.com".to_string(),
            "SEC_CM4",
        ),
        (
            "curl --cert \\\nclient.p12:SEC_CM5 https://example.com".to_string(),
            "SEC_CM5",
        ),
        (
            "curl --proxy-cert \\\nproxy.p12:SEC_CM6 https://example.com".to_string(),
            "SEC_CM6",
        ),
        (
            "curl -E \\\nclient.p12:SEC_CM7 https://example.com".to_string(),
            "SEC_CM7",
        ),
        (
            "curl -sE \\\nclient.p12:SEC_CM8 https://example.com".to_string(),
            "SEC_CM8",
        ),
        (
            "curl --cert client.p12\\\n:SEC_CM9 https://example.com".to_string(),
            "SEC_CM9",
        ),
        (
            "curl --cert \nclient.p12:SEC_CM11 https://example.com".to_string(),
            "SEC_CM11",
        ),
        // Neon AUD-06: Even `open_bs >= 2` in `redact_quoted_argv_flags_cow`
        (
            format!(r#"["a", \\"--{pw}\\", \\"SEC_EB2", "benign_tail"]"#),
            "SEC_EB2",
        ),
        // Carbon W1A-R17-01: Quoted CLI flags & JSON-argv separated by `\uXXXX` ws or `\u002c` comma
        (
            format!(r#"pg_dump "--{pw}"\u0020"CANARY_QFLAG1""#),
            "CANARY_QFLAG1",
        ),
        (
            format!(r#"pg_dump "--{pw}"\u0009"CANARY_QFLAG2""#),
            "CANARY_QFLAG2",
        ),
        (
            format!(r#"pg_dump "--{pw}"\u00a0"CANARY_QFLAG3""#),
            "CANARY_QFLAG3",
        ),
        (
            format!(r#"pg_dump "--{pw}"\u3000"CANARY_QFLAG4""#),
            "CANARY_QFLAG4",
        ),
        (
            format!(r#"["pg_dump", "--{pw}",\u00a0"CANARY_QFLAG5"]"#),
            "CANARY_QFLAG5",
        ),
        (
            format!(r#"["pg_dump", "--{pw}"\u002c "CANARY_QFLAG6"]"#),
            "CANARY_QFLAG6",
        ),
        (
            format!(r#"{{"cmd": "pg_dump \"--{pw}\"\\u00a0\"CANARY_QFLAG7\""}}"#),
            "CANARY_QFLAG7",
        ),
        // Carbon W1A-R17-02: `Digest` auth credentials with `\uXXXX` parameter separators
        (
            r#"Digest username="alice",\u0020response="CANARY_DIGEST1""#.to_string(),
            "CANARY_DIGEST1",
        ),
        (
            r#"Digest username="alice",\u00a0response="CANARY_DIGEST2""#.to_string(),
            "CANARY_DIGEST2",
        ),
        (
            r#"Digest username="alice"\u002c response="CANARY_DIGEST3""#.to_string(),
            "CANARY_DIGEST3",
        ),
        (
            r#"Digest username="alice", response\u003d"CANARY_DIGEST4""#.to_string(),
            "CANARY_DIGEST4",
        ),
        (
            r#"{"hdr": "Digest username=\"alice\",\\u0020response=\"CANARY_DIGEST5\""}"#
                .to_string(),
            "CANARY_DIGEST5",
        ),
    ];

    for (input, secret) in &secret_cases {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R18 [{label}] leaked {secret:?} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R18 [{label}] failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
        let persisted_once = sanitize_persisted_lifecycle_text(input);
        let projected_after = diagnostic_projection::redact_secrets(&persisted_once);
        assert!(
            !projected_after.contains(secret),
            "R18 two-stage leaked {secret:?} for {input:?} -> {projected_after:?}"
        );
    }

    // Team 8 F9 `redact_diagnostic` direct check on non-curl `"-u",{` prefix + trailing `"-u",{x:SECRET`
    let f9_diag_tail = format!("{} \"-u\",{{x:SUPER_SECRET_F9_DIAG", "\"-u\",{".repeat(64));
    let f9_diag_out = af_models::secret_redaction::redact_diagnostic(&f9_diag_tail);
    assert!(
        !f9_diag_out.contains("SUPER_SECRET_F9_DIAG"),
        "R18 [diag] F9 leaked trailing secret: {f9_diag_out:?}"
    );
    assert_eq!(
        af_models::secret_redaction::redact_diagnostic(&f9_diag_out),
        f9_diag_out
    );

    // 2. Direct `redact_json_value` & valid RFC 8259 JSON preservation across `projected` & `balanced`
    let valid_json_r18: Vec<(String, &'static str)> = vec![
        (
            r#"{"Bearer\u000bSECRET_VT_01": "ok"}"#.to_string(),
            "SECRET_VT_01",
        ),
        (
            r#"{"note\u000cBasic\u000cSEC_NVT4": "ok"}"#.to_string(),
            "SEC_NVT4",
        ),
        (
            r#"{"curl\u000b-b\u000bSEC_NVT5": "ok"}"#.to_string(),
            "SEC_NVT5",
        ),
        (r#"{"Basic\fSEC_KF1":"ok"}"#.to_string(), "SEC_KF1"),
        (r#"{"curl\f-u\fSEC_KF3":"ok"}"#.to_string(), "SEC_KF3"),
        (r#"{"msg":"Bearer\fSEC_F1"}"#.to_string(), "SEC_F1"),
        (format!(r#"{{"msg":"--{pw}\fSEC_F4"}}"#), "SEC_F4"),
        (r#"{"msg":"curl\f-u\fadmin:SEC_F5"}"#.to_string(), "SEC_F5"),
        (r#"{"msg":"ok\bBearer SEC_B1"}"#.to_string(), "SEC_B1"),
        (
            r#"["curl", "--cert=client.p12\\u003aSEC_CJ2"]"#.to_string(),
            "SEC_CJ2",
        ),
        (
            r#"{"cmd":"curl --cert client.p12\\u003aSEC_CJ1 https://example.com"}"#.to_string(),
            "SEC_CJ1",
        ),
        (
            r#"{"cmd": "curl -E client.p12\\u003aCANARY_CERT_JSON https://example.com"}"#
                .to_string(),
            "CANARY_CERT_JSON",
        ),
        (
            r#"["curl", "-Eclient.p12\\u003aSEC_CJ5"]"#.to_string(),
            "SEC_CJ5",
        ),
        (
            r#"["curl", "--cert", "C:\\certs\\client.p12:CANARY_WIN_CERT2"]"#.to_string(),
            "CANARY_WIN_CERT2",
        ),
        (
            r#"{"args": ["-u", "a,b\\u003aSUPER_SECRET_F4D"]}"#.to_string(),
            "SUPER_SECRET_F4D",
        ),
        (
            r#"{"hdr": "Cookie: sid='line1\nSUPER_SECRET_F5C'"}"#.to_string(),
            "SUPER_SECRET_F5C",
        ),
        (
            format!(r#"{{"hdr": "{hdr_auth}: Bearer 'line1\nSUPER_SECRET_F5E'"}}"#),
            "SUPER_SECRET_F5E",
        ),
        (
            r#"{"url":"https://admin:SEC_UU8\\u005c\\u00750040example.com/p"}"#.to_string(),
            "SEC_UU8",
        ),
        (
            format!(r#"{{"h":"{hdr_auth}: Digest\nusername=\"alice\",\nresponse=\"SEC_DG8\""}}"#),
            "SEC_DG8",
        ),
        (
            format!(r#"{{"h":"{hdr_auth}: Bearer\n\nSEC_JBL1"}}"#),
            "SEC_JBL1",
        ),
        (
            format!(r#"{{"cmd": "pg_dump \"--{pw}\"\\u00a0\"CANARY_QFLAG7\""}}"#),
            "CANARY_QFLAG7",
        ),
        (
            r#"{"hdr": "Digest username=\"alice\",\\u0020response=\"CANARY_DIGEST5\""}"#
                .to_string(),
            "CANARY_DIGEST5",
        ),
    ];

    for (raw_json, forbidden) in &valid_json_r18 {
        let mut val: serde_json::Value = serde_json::from_str(raw_json).unwrap();
        assert!(
            diagnostic_projection::redact_json_value(&mut val),
            "R18 redact_json_value must report modification for {raw_json:?}"
        );
        let ser = serde_json::to_string(&val).unwrap();
        assert!(
            !ser.contains(forbidden),
            "R18 redact_json_value leaked {forbidden:?} for {raw_json:?} -> {ser:?}"
        );
        let mut val2 = val.clone();
        assert!(
            !diagnostic_projection::redact_json_value(&mut val2),
            "R18 redact_json_value returned true on 2nd pass for {raw_json:?}"
        );
        assert_eq!(val2, val);

        for (label, f) in [
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(raw_json);
            assert!(
                !out.contains(forbidden),
                "R18 [{label}] leaked {forbidden:?} for {raw_json:?} -> {out:?}"
            );
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R18 [{label}] broke valid JSON ({e}) for {raw_json:?} -> {out:?}")
            });
            assert_eq!(f(&out), out, "R18 [{label}] JSON idempotency: {raw_json:?}");
        }
    }

    // 3. Direct `redact_embedded_json_spans` verification on R17 embedded JSON findings
    for (emb, prefix, forbidden) in [
        (
            r#"installer error: {"hdr": "Cookie: sid='line1\nSUPER_SECRET_EMB1'"}"#.to_string(),
            "installer error: ",
            "SUPER_SECRET_EMB1",
        ),
        (
            r#"err: {"Bearer\u000bSECRET_VT_EMB2": "ok"}"#.to_string(),
            "err: ",
            "SECRET_VT_EMB2",
        ),
        (
            r#"err: {"Basic\fSEC_KF_EMB3": "ok"}"#.to_string(),
            "err: ",
            "SEC_KF_EMB3",
        ),
        (
            r#"err: ["curl", "--cert=client.p12\\u003aSEC_CJ_EMB4"]"#.to_string(),
            "err: ",
            "SEC_CJ_EMB4",
        ),
        (
            r#"err: {"url": "https://admin:SEC_UU8_EMB5\\u005c\\u00750040example.com/p"}"#
                .to_string(),
            "err: ",
            "SEC_UU8_EMB5",
        ),
        (
            format!(r#"err: {{"cmd": "pg_dump \"--{pw}\"\\u00a0\"CANARY_QFLAG_EMB6\""}}"#),
            "err: ",
            "CANARY_QFLAG_EMB6",
        ),
        (
            r#"err: {"hdr": "Digest username=\"alice\",\\u0020response=\"CANARY_DIGEST_EMB7\""}"#
                .to_string(),
            "err: ",
            "CANARY_DIGEST_EMB7",
        ),
    ] {
        let out = diagnostic_projection::redact_embedded_json_spans(&emb);
        assert!(
            !out.contains(forbidden),
            "R18 redact_embedded_json_spans leaked {forbidden:?} for {emb:?} -> {out:?}"
        );
        assert!(
            out.starts_with(prefix),
            "R18 redact_embedded_json_spans altered prefix {prefix:?}: {out:?}"
        );
        serde_json::from_str::<serde_json::Value>(&out[prefix.len()..]).unwrap_or_else(|e| {
            panic!("R18 redact_embedded_json_spans emitted invalid embedded JSON ({e}): {out:?}")
        });
        assert_eq!(
            diagnostic_projection::redact_embedded_json_spans(&out),
            out,
            "R18 redact_embedded_json_spans idempotency failed for {emb:?}"
        );
    }

    // 4. Benign preservation & exact non-overconsumption checks across all surfaces
    let win_bpass = format!(r#"C:\b{pa}=visible"#);
    let win_fpass = format!(r#"C:\f{pa}=visible"#);
    let benign_all_4: Vec<&str> = vec![
        r#"curl -E C:\certs\client.pem https://example.com"#,
        r#"["curl", "--cert", "C:\\certs\\client.pem"]"#,
        r#"curl --cert C:/certs/client.pem https://example.com"#,
        win_bpass.as_str(),
        win_fpass.as_str(),
        "curl --cert \nbenign_line=1",
    ];
    for benign in benign_all_4 {
        for &(label, f) in &eps {
            let out = f(benign);
            assert_eq!(
                out, benign,
                "R18 [{label}] mutated benign input {benign:?} -> {out:?}"
            );
        }
        assert!(
            matches!(
                af_models::secret_redaction::redact_diagnostic(benign),
                std::borrow::Cow::Borrowed(_)
            ),
            "redact_diagnostic allocated on benign R18 input: {benign:?}"
        );
        assert!(
            matches!(
                sanitize_persisted_lifecycle_text_cow(benign),
                std::borrow::Cow::Borrowed(_)
            ),
            "sanitize_persisted_lifecycle_text_cow allocated on benign R18 input: {benign:?}"
        );
        if benign.starts_with(['{', '[']) {
            let orig: serde_json::Value = serde_json::from_str(benign).unwrap();
            let mut copy = orig.clone();
            assert!(!diagnostic_projection::redact_json_value(&mut copy));
            assert_eq!(copy, orig, "redact_json_value mutated benign {benign:?}");
            let emb_benign = format!("log: {benign}");
            assert_eq!(
                diagnostic_projection::redact_embedded_json_spans(&emb_benign),
                emb_benign,
                "redact_embedded_json_spans mutated benign {emb_benign:?}"
            );
        }
    }

    // Neon AUD-06: `["a", \\"--password\\", \\"SEC_EB2", "benign_tail"]` preserves `", "benign_tail"]`
    let aud06_sample = format!(r#"["a", \\"--{pw}\\", \\"SEC_EB2", "benign_tail"]"#);
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let out = f(&aud06_sample);
        assert!(
            !out.contains("SEC_EB2"),
            "R18 [{label}] AUD-06 leaked SEC_EB2: {out:?}"
        );
        assert!(
            out.ends_with(r#", "benign_tail"]"#),
            "R18 [{label}] AUD-06 over-redacted benign_tail to EOF: {out:?}"
        );
        assert_eq!(f(&out), out);
    }

    // Neon AUD-04 benign blank-line headers (`X-Api-Key:\n\nstep 2: service healthy`, `Authorization: Bearer\n\nHost: example.com`)
    let benign_xapi_blank = format!("{hdr_x_api}:\n\nstep 2: service healthy");
    let benign_bearer_blank = format!("{hdr_auth}: Bearer\n\nHost: example.com");
    for (sample, must_keep) in [
        (benign_xapi_blank.as_str(), "\n\nstep 2: service healthy"),
        (benign_bearer_blank.as_str(), "\n\nHost: example.com"),
    ] {
        let d_out = af_models::secret_redaction::redact_diagnostic(sample);
        assert!(
            d_out.ends_with(must_keep),
            "R18 [diag] over-redacted blank-line continuation {sample:?} -> {d_out:?}"
        );
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&d_out),
            d_out
        );
        for (label, f) in [
            (
                "persisted",
                sanitize_persisted_lifecycle_text as fn(&str) -> String,
            ),
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            assert_eq!(
                f(sample),
                sample,
                "R18 [{label}] over-redacted benign blank-line header {sample:?}"
            );
        }
    }

    // 5. Adaptive linear-time O(N) scaling (`ratio < 3.2`) for `F1a`, `F1b`, `F8a`, `F8b`, `F9`,
    // `AUD-03` (`\u005c\u0075`), `F2` (`\u0022` containers), and `F7` (`HeaderLineQuoteCache`).
    type R18Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r18_scaling: &[R18Scaling] = &[
        (
            "r18_f1a_user_esc_sp_system_brace",
            |n| "user=a\\ system:{ ".repeat(n),
            400,
            64_000,
        ),
        (
            "r18_f1b_cert_http_brace",
            |n| "--cert=http://{ ".repeat(n),
            400,
            64_000,
        ),
        (
            "r18_f8a_quoted_cert_brace",
            |n| "\"--cert\" {".repeat(n),
            400,
            64_000,
        ),
        (
            "r18_f8a_quoted_proxy_cert_brace",
            |n| "\"--proxy-cert\" {".repeat(n),
            400,
            64_000,
        ),
        (
            "r18_f8a_curl_quoted_e_brace",
            |n| format!("curl {}", "\"-E\" {".repeat(n)),
            400,
            64_000,
        ),
        (
            "r18_f8b_cert_bs_brace",
            |n| "--cert=\\a{".repeat(n),
            400,
            64_000,
        ),
        (
            "r18_f8b_proxy_cert_bs_brace",
            |n| "--proxy-cert=\\a{".repeat(n),
            400,
            64_000,
        ),
        (
            "r18_f8b_curl_e_bs_brace",
            |n| format!("curl {}", "-E\\a{".repeat(n)),
            400,
            64_000,
        ),
        (
            "r18_f9a_quoted_cert_comma_brace",
            |n| "\"--cert\",{".repeat(n),
            400,
            64_000,
        ),
        (
            "r18_f9b_curl_quoted_e_comma_brace",
            |n| format!("curl {}", "\"-E\",{".repeat(n)),
            400,
            64_000,
        ),
        (
            "r18_f9c_quoted_u_comma_brace_tail_pair",
            |n| format!("{} \"-u\",{{x:y", "\"-u\",{".repeat(n)),
            400,
            64_000,
        ),
        (
            "r18_aud03_double_escaped_u005c_u0075",
            |n| "foo=\\u005c\\u00750041\\u005c\\u0075003a ".repeat(n),
            300,
            32_000,
        ),
        (
            "r18_f2_u0022_containers",
            make_r18_f2_u0022_containers,
            250,
            32_000,
        ),
        (
            "r18_f7_header_quote_cache",
            make_r18_f7_header_quote_cache,
            250,
            32_000,
        ),
    ];
    let started_r18 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r18_scaling {
        for &(ep, f) in &eps {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }

    assert!(
        started_r18.elapsed() < std::time::Duration::from_secs(120),
        "R18 linear-time budget exceeded: {:?}",
        started_r18.elapsed()
    );

    // 6. R18 fuzzer `case=14452` 1-step idempotency & unquoted-newline header regressions
    for (fuzz_in, secret) in [
        (
            format!("{hdr_x_api}:\nDigest \\u000d-s\\u0062 APP_KEY.v1=SUPER_SECRET_IDEM1"),
            "SUPER_SECRET_IDEM1",
        ),
        (
            format!(
                "username*=-sb [REDACTED]--user=\\\\\"curl -E {hdr_x_api}:\nDigest \\u000d-s\\u0062 APP_KEY.v1=-AMozillaUbuntup@ss,--{pw}= \néabSUPER_SECRET_IDEM2\\u005c\\u00750041\u{8})\\u2014\\nauth{hdr_x_api}: "
            ),
            "SUPER_SECRET_IDEM2",
        ),
        (
            format!("{hdr_x_api}:\nDigest \r  -sb APP_KEY.v1=SUPER_SECRET_IDEM3"),
            "SUPER_SECRET_IDEM3",
        ),
        (
            format!("{hdr_x_api}: \\nstep 2 SUPER_SECRET_UNQUOTED_NL"),
            "SUPER_SECRET_UNQUOTED_NL",
        ),
    ] {
        for &(label, f) in &eps {
            let p1 = f(&fuzz_in);
            let p2 = f(&p1);
            assert!(
                !p1.contains(secret),
                "R18 [{label}] leaked {secret:?} for {fuzz_in:?} -> {p1:?}"
            );
            assert_eq!(
                p1, p2,
                "R18 [{label}] failed 1-step idempotency for {fuzz_in:?}:\n  p1={p1:?}\n  p2={p2:?}"
            );
        }
    }
}

fn make_r19_p1_2_u0027_scalars(n: usize) -> String {
    let pw = concat!("pass", "word");
    format!("{pw}=\\u0027part1 sec\\u0027 ").repeat(n)
}

fn make_r19_p1_2_u0027_unclosed(n: usize) -> String {
    let pw = concat!("pass", "word");
    format!("{pw}=\\u0027unclosed ").repeat(n)
}

fn make_r19_p1_2_u0027_argv(n: usize) -> String {
    let pw = concat!("pass", "word");
    format!(
        "[{}]",
        format!("\\u0027--{pw}\\u0027, \\u0027sec\\u0027, ").repeat(n)
    )
}

fn make_r19_p1_3_diag_carry_mixed(n: usize) -> String {
    let pw = concat!("pass", "word");
    format!("{pw}=\nfoo; [\"curl\", \"--cert\",\n\"C:\\\\certs\\\\client.pem\"]\n").repeat(n)
}

fn make_r19_p1_6_digest_eq_nl(n: usize) -> String {
    let h = concat!("Authori", "zation");
    format!("{h}: Digest username=\"a\", response=\n\"sec\"\nHost: example.com\n").repeat(n)
}

fn make_r19_p1_8_sq_bs_auth_json(n: usize) -> String {
    let h = concat!("Authori", "zation");
    let unit = format!("{{\"\":\"'\\\\'{h}:\"}},\"'}}\",");
    format!("[{}]", unit.repeat(n).trim_end_matches(','))
}

fn make_r19_p2_1_folded_header_unclosed_brace(n: usize) -> String {
    let pw = concat!("pass", "word");
    format!("Cookie: a=1;\n{}", format!("  b=2; {pw}={{\n").repeat(n))
}

#[test]
fn test_wave1a_r19_audit_regressions() {
    type RedactorEntry = (&'static str, fn(&str) -> String);
    let eps: [RedactorEntry; 4] = [
        ("diag", |s| {
            af_models::secret_redaction::redact_diagnostic(s).into_owned()
        }),
        ("persisted", sanitize_persisted_lifecycle_text),
        ("projected", diagnostic_projection::redact_secrets),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets,
        ),
    ];

    let pw = concat!("pass", "word");
    let pa = concat!("pa", "ss");
    let tok = concat!("tok", "en");
    let toks = concat!("tok", "ens");
    let hdr_auth = concat!("Authori", "zation");
    let hdr_proxy = concat!("Proxy-Authori", "zation");

    let deep_prefix = "{\"a\":".repeat(135);
    let deep_suffix = "}".repeat(135);

    // 1. All 10 R18 blind-audit findings (`R18-P1-1..P1-8`, `R18-P2-1`, `R18-P3-1`) secret
    // cases across all 4 `af-models`/`af-release` surfaces (`diag`, `persisted`, `projected`,
    // `balanced`), checking zero leaks, 1-step idempotency, and two-stage `persisted -> projected`.
    let secret_cases: Vec<(String, &'static str)> = vec![
        // R18-P1-1: `--cert`/`--proxy-cert`/`-E`/`-sE` newline / JSON `\n` / `\u000a` / `\u000d`
        (
            "curl --cert\nclient.p12:SUPER_SECRET_R19_1".to_string(),
            "SUPER_SECRET_R19_1",
        ),
        (
            "curl --proxy-cert\nclient.p12:SUPER_SECRET_R19_1B".to_string(),
            "SUPER_SECRET_R19_1B",
        ),
        (
            "curl -E\nclient.p12:SUPER_SECRET_R19_1C".to_string(),
            "SUPER_SECRET_R19_1C",
        ),
        (
            "curl -sE\nclient.p12:SUPER_SECRET_R19_1D".to_string(),
            "SUPER_SECRET_R19_1D",
        ),
        (
            "curl --cert\r\nclient.p12:SUPER_SECRET_R19_1E".to_string(),
            "SUPER_SECRET_R19_1E",
        ),
        (
            "curl --cert\n  client.p12:SUPER_SECRET_R19_1F".to_string(),
            "SUPER_SECRET_R19_1F",
        ),
        (
            "curl -sE\r\n  client.p12:SUPER_SECRET_R19_1G".to_string(),
            "SUPER_SECRET_R19_1G",
        ),
        (
            r#"{"cmd": "curl --cert\nclient.p12:SUPER_SECRET_R19_2"}"#.to_string(),
            "SUPER_SECRET_R19_2",
        ),
        (
            r#"{"cmd": "curl --proxy-cert\nclient.p12:SUPER_SECRET_R19_2B"}"#.to_string(),
            "SUPER_SECRET_R19_2B",
        ),
        (
            r#"{"cmd": "curl -E\nclient.p12:SUPER_SECRET_R19_2C"}"#.to_string(),
            "SUPER_SECRET_R19_2C",
        ),
        (
            r#"{"cmd": "curl -sE\nclient.p12:SUPER_SECRET_R19_2D"}"#.to_string(),
            "SUPER_SECRET_R19_2D",
        ),
        (
            r#"{"cmd": "curl --cert\r\nclient.p12:SUPER_SECRET_R19_2E"}"#.to_string(),
            "SUPER_SECRET_R19_2E",
        ),
        (
            r#"{"cmd": "curl --cert\u000aclient.p12:SUPER_SECRET_R19_2F"}"#.to_string(),
            "SUPER_SECRET_R19_2F",
        ),
        (
            r#"{"cmd": "curl -E\u000dclient.p12:SUPER_SECRET_R19_2G"}"#.to_string(),
            "SUPER_SECRET_R19_2G",
        ),
        (
            r#"["sh", "-c", "curl --cert\nclient.p12:SUPER_SECRET_R19_3"]"#.to_string(),
            "SUPER_SECRET_R19_3",
        ),
        (
            format!(
                "{deep_prefix}{{\"cmd\":\"curl --cert\\nclient.p12:SUPER_SECRET_R19_3_DEEP1\"}}{deep_suffix}"
            ),
            "SUPER_SECRET_R19_3_DEEP1",
        ),
        (
            format!(
                "{deep_prefix}{{\"cmd\":\"curl --cert\\u000aclient.p12:SUPER_SECRET_R19_3_DEEP2\"}}{deep_suffix}"
            ),
            "SUPER_SECRET_R19_3_DEEP2",
        ),
        (
            "curl --cert\\u000aclient.p12:SUPER_SECRET_R19_4".to_string(),
            "SUPER_SECRET_R19_4",
        ),
        (
            "curl --cert\\u000dclient.p12:SUPER_SECRET_R19_4B".to_string(),
            "SUPER_SECRET_R19_4B",
        ),
        // R18-P1-2: `\u0027` single-quote symmetry across scalar/auth/cookie/user/cert/argv
        (
            format!("{pw}=\\u0027part1 SUPER_SECRET_R19_5\\u0027"),
            "SUPER_SECRET_R19_5",
        ),
        (
            format!("{pw}=\\u0027line1\nSUPER_SECRET_R19_6\\u0027"),
            "SUPER_SECRET_R19_6",
        ),
        (
            "Bearer \\u0027tok1 SUPER_SECRET_R19_7\\u0027".to_string(),
            "SUPER_SECRET_R19_7",
        ),
        (
            "Cookie: sid=\\u0027line1\nSUPER_SECRET_R19_8\\u0027".to_string(),
            "SUPER_SECRET_R19_8",
        ),
        (
            "user=\\u0027my user:SUPER_SECRET_R19_9\\u0027".to_string(),
            "SUPER_SECRET_R19_9",
        ),
        (
            "user=\\u0027admin:\nSUPER_SECRET_R19_10\\u0027".to_string(),
            "SUPER_SECRET_R19_10",
        ),
        (
            format!(r#"{{"msg": "{pw}=\u0027part1 SUPER_SECRET_R19_11\u0027"}}"#),
            "SUPER_SECRET_R19_11",
        ),
        (
            format!(r#"{{"msg": "{pw}=\\u0027part1 SUPER_SECRET_R19_11B\\u0027"}}"#),
            "SUPER_SECRET_R19_11B",
        ),
        (
            r#"{"msg": "Bearer \u0027part1 SUPER_SECRET_R19_12\u0027"}"#.to_string(),
            "SUPER_SECRET_R19_12",
        ),
        (
            r#"{"msg": "Bearer \\u0027part1 SUPER_SECRET_R19_12B\\u0027"}"#.to_string(),
            "SUPER_SECRET_R19_12B",
        ),
        (
            format!("[\\u0027pg_dump\\u0027, \\u0027--{pw}\\u0027, \\u0027SUPER_SECRET_R19_13\\u0027]"),
            "SUPER_SECRET_R19_13",
        ),
        (
            "[\\u0027curl\\u0027, \\u0027-b\\u0027, \\u0027sid=SUPER_SECRET_R19_14\\u0027]"
                .to_string(),
            "SUPER_SECRET_R19_14",
        ),
        (
            "curl --cert \\u0027my cert.p12:SUPER_SECRET_R19_14B\\u0027 https://example.com"
                .to_string(),
            "SUPER_SECRET_R19_14B",
        ),
        // R18-P1-3: `redact_diagnostic` unified carry-state across Sections 3a/3b/4/5b/6
        (
            format!("curl --cert\nclient.p12:SEC1; {pw}=\nSUPER_SECRET_R19_16"),
            "SUPER_SECRET_R19_16",
        ),
        (
            format!("curl --cert\nclient.p12:SUPER_SECRET_R19_16A; {pw}=\nSEC2"),
            "SUPER_SECRET_R19_16A",
        ),
        (
            "curl --cert\n\\u0022client.p12:line2\nSUPER_SECRET_R19_17\\u0022".to_string(),
            "SUPER_SECRET_R19_17",
        ),
        (
            "curl --cert\n\\u0027client.p12:line2\nSUPER_SECRET_R19_17B\\u0027".to_string(),
            "SUPER_SECRET_R19_17B",
        ),
        (
            "curl --cert\n$'client.p12:line2\nSUPER_SECRET_R19_18'".to_string(),
            "SUPER_SECRET_R19_18",
        ),
        (
            format!("[\"--{pw}\",\n123]; {pw}=\"line2\nSUPER_SECRET_R19_19\""),
            "SUPER_SECRET_R19_19",
        ),
        (
            format!("[\"--{tok}\",\n123, \"{pw}\": \"line2\nSUPER_SECRET_R19_19B\"\n]"),
            "SUPER_SECRET_R19_19B",
        ),
        (
            format!("[\"--{pw}\",\n{{\"a\":1}}]; user=\nadmin:SUPER_SECRET_R19_19C"),
            "SUPER_SECRET_R19_19C",
        ),
        (
            format!(
                "[\"--{pw}\",\ntrue]; {hdr_auth}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_19D\""
            ),
            "SUPER_SECRET_R19_19D",
        ),
        (
            format!("Cookie: a=1;\n  b=2; {pw}=\nSUPER_SECRET_R19_20"),
            "SUPER_SECRET_R19_20",
        ),
        (
            format!("{hdr_auth}: Digest username=\"a\",\n  realm=\"b\"; {pw}=\nSUPER_SECRET_R19_20B"),
            "SUPER_SECRET_R19_20B",
        ),
        (
            format!("{pw}=\nfoo; [\"curl\", \"--cert\",\n\"client.p12:SUPER_SECRET_R19_S6A\"]"),
            "SUPER_SECRET_R19_S6A",
        ),
        (
            format!("{pw}=\nfoo; Cookie: a=1;\n  sid=SUPER_SECRET_R19_S6B"),
            "SUPER_SECRET_R19_S6B",
        ),
        (
            format!("{pw}=\nfoo; Cookie:\n  sid=SUPER_SECRET_R19_S6C"),
            "SUPER_SECRET_R19_S6C",
        ),
        (
            format!(
                "{pw}=\nfoo; {hdr_auth}: Digest username=\"alice\",\n  response=\"SUPER_SECRET_R19_S6D\""
            ),
            "SUPER_SECRET_R19_S6D",
        ),
        (
            format!(
                "{pw}=\nfoo; {hdr_auth}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_S6E\""
            ),
            "SUPER_SECRET_R19_S6E",
        ),
        (
            format!("{pw}=\nfoo; curl --cert\nclient.p12:SUPER_SECRET_R19_S6F"),
            "SUPER_SECRET_R19_S6F",
        ),
        // R18-P1-4: `ssh://` URL with `\u003a`
        (
            "ssh://admin\\u003aSUPER_SECRET_R19_21@example.com".to_string(),
            "SUPER_SECRET_R19_21",
        ),
        (
            r#"{"url": "ssh://admin\u003aSUPER_SECRET_R19_22@example.com"}"#.to_string(),
            "SUPER_SECRET_R19_22",
        ),
        (
            r#"{"url": "ssh://admin\\u003aSUPER_SECRET_R19_22B@example.com"}"#.to_string(),
            "SUPER_SECRET_R19_22B",
        ),
        // R18-P1-5: Multiline quoted `--cert`/`-E` and `user=` with `\n` before `:`
        (
            "curl --cert \"client.p12\n:SUPER_SECRET_R19_23\"".to_string(),
            "SUPER_SECRET_R19_23",
        ),
        (
            "curl -E \"client.p12\n:SUPER_SECRET_R19_24\"".to_string(),
            "SUPER_SECRET_R19_24",
        ),
        (
            "user=\"admin\n:SUPER_SECRET_R19_25\"".to_string(),
            "SUPER_SECRET_R19_25",
        ),
        (
            "curl --proxy-cert 'proxy.p12\n:SUPER_SECRET_R19_25B'".to_string(),
            "SUPER_SECRET_R19_25B",
        ),
        (
            "curl -sE \"C:\\certs\\client.p12\n:SUPER_SECRET_R19_25C\"".to_string(),
            "SUPER_SECRET_R19_25C",
        ),
        (
            "user=\\u0027admin\n:SUPER_SECRET_R19_25D\\u0027".to_string(),
            "SUPER_SECRET_R19_25D",
        ),
        // R18-P1-6: `Authorization:` / `Proxy-Authorization:` Digest broken after `=`
        (
            format!("{hdr_auth}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_26\""),
            "SUPER_SECRET_R19_26",
        ),
        (
            format!("{hdr_proxy}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_26B\""),
            "SUPER_SECRET_R19_26B",
        ),
        (
            format!(
                r#"{{"h": "{hdr_auth}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_27\""}}"#
            ),
            "SUPER_SECRET_R19_27",
        ),
        (
            format!(
                r#"{{"h": "{hdr_proxy}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_27B\""}}"#
            ),
            "SUPER_SECRET_R19_27B",
        ),
        // R18-P1-7: UTF-16 surrogate pairs `\ud83d\ude80` before keywords/flags/assignments
        (
            r#"{"msg": "\ud83d\ude80Bearer SUPER_SECRET_R19_28"}"#.to_string(),
            "SUPER_SECRET_R19_28",
        ),
        (
            r#"err: {"msg": "\ud83d\ude80Bearer SUPER_SECRET_R19_29""#.to_string(),
            "SUPER_SECRET_R19_29",
        ),
        (
            format!(r#"err: {{"msg": "\ud83d\ude80{pa}=SUPER_SECRET_R19_30""#),
            "SUPER_SECRET_R19_30",
        ),
        (
            format!(r#"err: {{"msg": "\ud83d\ude80--{pw} SUPER_SECRET_R19_31""#),
            "SUPER_SECRET_R19_31",
        ),
        (
            format!(r#"{{"msg": "\ud83d\ude80{pa}=SUPER_SECRET_R19_31B"}}"#),
            "SUPER_SECRET_R19_31B",
        ),
        (
            format!(r#"{{"msg": "\ud83d\ude80--{pw} SUPER_SECRET_R19_31C"}}"#),
            "SUPER_SECRET_R19_31C",
        ),
        (
            r#"{"msg": "curl \ud83d\ude80-u admin:SUPER_SECRET_R19_31D"}"#.to_string(),
            "SUPER_SECRET_R19_31D",
        ),
        (
            format!(
                "{deep_prefix}{{\"msg\":\"\\ud83d\\ude80Bearer SUPER_SECRET_R19_31_DEEP\"}}{deep_suffix}"
            ),
            "SUPER_SECRET_R19_31_DEEP",
        ),
        (
            format!(
                "{deep_prefix}{{\"msg\":\"\\ud83d\\ude80--{pw} SUPER_SECRET_R19_31_DEEP2\"}}{deep_suffix}"
            ),
            "SUPER_SECRET_R19_31_DEEP2",
        ),
        // R18-P2-1: Unclosed `{`/`[` container on folded HTTP header line
        (
            format!("Cookie: a=1;\n  b=2; {pw}={{\n\"k\":\"SUPER_SECRET_R19_32\"\n}}"),
            "SUPER_SECRET_R19_32",
        ),
        (
            format!("Cookie: a=1;\n  b=2; {toks}=[\n\"SUPER_SECRET_R19_32B\"\n]"),
            "SUPER_SECRET_R19_32B",
        ),
    ];

    for (input, secret) in &secret_cases {
        for &(label, f) in &eps {
            let out = f(input);
            assert!(
                !out.contains(secret),
                "R19 [{label}] leaked {secret:?} for {input:?} -> {out:?}"
            );
            assert_eq!(
                f(&out),
                out,
                "R19 [{label}] failed 1-step idempotency for {input:?} -> {out:?}"
            );
        }
        let persisted_once = sanitize_persisted_lifecycle_text(input);
        let projected_after = diagnostic_projection::redact_secrets(&persisted_once);
        assert!(
            !projected_after.contains(secret),
            "R19 two-stage leaked {secret:?} for {input:?} -> {projected_after:?}"
        );
    }

    // 2. Direct `redact_json_value` & valid RFC 8259 JSON preservation on R19 valid JSON inputs
    let valid_json_r19: Vec<(String, &'static str)> = vec![
        (
            r#"{"cmd": "curl --cert\nclient.p12:SUPER_SECRET_R19_2"}"#.to_string(),
            "SUPER_SECRET_R19_2",
        ),
        (
            r#"{"cmd": "curl --proxy-cert\nclient.p12:SUPER_SECRET_R19_2B"}"#.to_string(),
            "SUPER_SECRET_R19_2B",
        ),
        (
            r#"{"cmd": "curl -E\nclient.p12:SUPER_SECRET_R19_2C"}"#.to_string(),
            "SUPER_SECRET_R19_2C",
        ),
        (
            r#"{"cmd": "curl -sE\nclient.p12:SUPER_SECRET_R19_2D"}"#.to_string(),
            "SUPER_SECRET_R19_2D",
        ),
        (
            r#"{"cmd": "curl --cert\r\nclient.p12:SUPER_SECRET_R19_2E"}"#.to_string(),
            "SUPER_SECRET_R19_2E",
        ),
        (
            r#"{"cmd": "curl --cert\u000aclient.p12:SUPER_SECRET_R19_2F"}"#.to_string(),
            "SUPER_SECRET_R19_2F",
        ),
        (
            r#"["sh", "-c", "curl --cert\nclient.p12:SUPER_SECRET_R19_3"]"#.to_string(),
            "SUPER_SECRET_R19_3",
        ),
        (
            format!(r#"{{"msg": "{pw}=\u0027part1 SUPER_SECRET_R19_11\u0027"}}"#),
            "SUPER_SECRET_R19_11",
        ),
        (
            format!(r#"{{"msg": "{pw}=\\u0027part1 SUPER_SECRET_R19_11B\\u0027"}}"#),
            "SUPER_SECRET_R19_11B",
        ),
        (
            r#"{"msg": "Bearer \u0027part1 SUPER_SECRET_R19_12\u0027"}"#.to_string(),
            "SUPER_SECRET_R19_12",
        ),
        (
            r#"{"msg": "Bearer \\u0027part1 SUPER_SECRET_R19_12B\\u0027"}"#.to_string(),
            "SUPER_SECRET_R19_12B",
        ),
        (
            r#"{"url": "ssh://admin\u003aSUPER_SECRET_R19_22@example.com"}"#.to_string(),
            "SUPER_SECRET_R19_22",
        ),
        (
            r#"{"url": "ssh://admin\\u003aSUPER_SECRET_R19_22B@example.com"}"#.to_string(),
            "SUPER_SECRET_R19_22B",
        ),
        (
            format!(
                r#"{{"h": "{hdr_auth}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_27\""}}"#
            ),
            "SUPER_SECRET_R19_27",
        ),
        (
            r#"{"msg": "\ud83d\ude80Bearer SUPER_SECRET_R19_28"}"#.to_string(),
            "SUPER_SECRET_R19_28",
        ),
        (
            format!(r#"{{"msg": "\ud83d\ude80{pa}=SUPER_SECRET_R19_31B"}}"#),
            "SUPER_SECRET_R19_31B",
        ),
        (
            format!(r#"{{"msg": "\ud83d\ude80--{pw} SUPER_SECRET_R19_31C"}}"#),
            "SUPER_SECRET_R19_31C",
        ),
        // R19 fuzzer-discovered JSON validity regressions (`cert_nl_pre`/`edash_pre` at string start
        // + Pass 4 `\\u0027` before `key=`/`--flag`/`Bearer` inside JSON strings)
        (
            r#"{"cmd": "--cert\\u000aclient.p12:SUPER_SECRET_R19_FUZZ_A1"}"#.to_string(),
            "SUPER_SECRET_R19_FUZZ_A1",
        ),
        (
            r#"{"cmd": "--cert\\u000dclient.p12:SUPER_SECRET_R19_FUZZ_A2"}"#.to_string(),
            "SUPER_SECRET_R19_FUZZ_A2",
        ),
        (
            r#"["curl", "--cert\\u000aclient.p12:SUPER_SECRET_R19_FUZZ_A3"]"#.to_string(),
            "SUPER_SECRET_R19_FUZZ_A3",
        ),
        (
            r#"["curl", "-E\\u000aclient.p12:SUPER_SECRET_R19_FUZZ_A4"]"#.to_string(),
            "SUPER_SECRET_R19_FUZZ_A4",
        ),
        (
            r#"["curl", "-\\u0045\\u000aclient.p12:SUPER_SECRET_R19_FUZZ_A5"]"#.to_string(),
            "SUPER_SECRET_R19_FUZZ_A5",
        ),
        (
            r#"{"x.user": "--cert\\u000a\\udc00'Cookie: sid=SUPER_SECRET_R19_FUZZ_A6"}"#
                .to_string(),
            "SUPER_SECRET_R19_FUZZ_A6",
        ),
        (
            format!(r#"{{"msg": "\\u0027{pw}=SUPER_SECRET_R19_FUZZ_B1\\u0027"}}"#),
            "SUPER_SECRET_R19_FUZZ_B1",
        ),
        (
            format!(r#"{{"msg": "\\u0027--{pw}=SUPER_SECRET_R19_FUZZ_B2\\u0027"}}"#),
            "SUPER_SECRET_R19_FUZZ_B2",
        ),
        (
            r#"{"msg": "\\u0027Bearer SUPER_SECRET_R19_FUZZ_B3\\u0027"}"#.to_string(),
            "SUPER_SECRET_R19_FUZZ_B3",
        ),
        (
            format!(r#"["\f{pa}\\u0027APP_KEY.v1=SUPER_SECRET_R19_FUZZ_B4", "ok"]"#),
            "SUPER_SECRET_R19_FUZZ_B4",
        ),
    ];

    for (raw_json, forbidden) in &valid_json_r19 {
        let mut val: serde_json::Value = serde_json::from_str(raw_json).unwrap();
        assert!(
            diagnostic_projection::redact_json_value(&mut val),
            "R19 redact_json_value must report modification for {raw_json:?}"
        );
        let ser = serde_json::to_string(&val).unwrap();
        assert!(
            !ser.contains(forbidden),
            "R19 redact_json_value leaked {forbidden:?} for {raw_json:?} -> {ser:?}"
        );
        let mut val2 = val.clone();
        assert!(
            !diagnostic_projection::redact_json_value(&mut val2),
            "R19 redact_json_value returned true on 2nd pass for {raw_json:?}"
        );
        assert_eq!(val2, val);

        for (label, f) in [
            (
                "persisted",
                sanitize_persisted_lifecycle_text as fn(&str) -> String,
            ),
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(raw_json);
            assert!(
                !out.contains(forbidden),
                "R19 [{label}] leaked {forbidden:?} for {raw_json:?} -> {out:?}"
            );
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R19 [{label}] broke valid JSON ({e}) for {raw_json:?} -> {out:?}")
            });
            assert_eq!(f(&out), out, "R19 [{label}] JSON idempotency: {raw_json:?}");
        }
    }

    // >128-deep valid JSON integrity check across `persisted`, `projected`, `balanced`
    for (deep_in, forbidden) in [
        (
            format!(
                "{deep_prefix}{{\"cmd\":\"curl --cert\\nclient.p12:SUPER_SECRET_R19_DEEP_A\"}}{deep_suffix}"
            ),
            "SUPER_SECRET_R19_DEEP_A",
        ),
        (
            format!(
                "{deep_prefix}{{\"msg\":\"\\ud83d\\ude80Bearer SUPER_SECRET_R19_DEEP_B\"}}{deep_suffix}"
            ),
            "SUPER_SECRET_R19_DEEP_B",
        ),
        (
            format!(
                "{deep_prefix}{{\"cmd\":\"--cert\\\\u000aclient.p12:SUPER_SECRET_R19_DEEP_C\"}}{deep_suffix}"
            ),
            "SUPER_SECRET_R19_DEEP_C",
        ),
        (
            format!(
                "{deep_prefix}{{\"msg\":\"\\\\u0027{pw}=SUPER_SECRET_R19_DEEP_D\\\\u0027\"}}{deep_suffix}"
            ),
            "SUPER_SECRET_R19_DEEP_D",
        ),
    ] {
        for (label, f) in [
            (
                "persisted",
                sanitize_persisted_lifecycle_text as fn(&str) -> String,
            ),
            (
                "projected",
                diagnostic_projection::redact_secrets as fn(&str) -> String,
            ),
            (
                "balanced",
                diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
            ),
        ] {
            let out = f(&deep_in);
            assert!(
                !out.contains(forbidden),
                "R19 [{label}] deep JSON leaked {forbidden:?}"
            );
            assert!(
                out.starts_with(&deep_prefix) && out.ends_with(&deep_suffix),
                "R19 [{label}] deep JSON wrapper corrupted: {out:?}"
            );
            let inner = &out[deep_prefix.len()..out.len() - deep_suffix.len()];
            serde_json::from_str::<serde_json::Value>(inner).unwrap_or_else(|e| {
                panic!("R19 [{label}] deep inner JSON invalid ({e}): {inner:?}")
            });
            assert_eq!(f(&out), out);
        }
    }

    // 3. `R18-P1-8`: `'\\'Authorization:` and multi-field object variants inside JSON strings
    // must remain valid `serde_json::Value` JSON across ALL surfaces + >128-deep JSON + 1-step idempotent!
    let p1_8_exact = format!("{{\"\":[{{\"\":\"'\\\\'{hdr_auth}:\"}},\"'}}\"]}}");
    let p1_8_multi1 =
        format!("{{\"a\":\"'\\\\'{hdr_auth}:\",\"b\":\"'}}\",\"c\":\"ok\",\"d\":[1,2]}}");
    let p1_8_multi2 = format!(
        "{{\"a\":\"'\\\\'{hdr_proxy}:\",\"b\":\"'}}\",\"c\":\"\\\\'Cookie:\",\"d\":\"'\"}}"
    );
    let p1_8_multi3 = r#"{"x":[{"k":"'\\'Set-Cookie:"},{"m":"'}"}],"y":"ok"}"#.to_string();
    for p1_8_doc in [&p1_8_exact, &p1_8_multi1, &p1_8_multi2, &p1_8_multi3] {
        serde_json::from_str::<serde_json::Value>(p1_8_doc).unwrap();
        for &(label, f) in &eps {
            let out = f(p1_8_doc);
            serde_json::from_str::<serde_json::Value>(&out).unwrap_or_else(|e| {
                panic!("R19 P1-8 [{label}] corrupted valid JSON ({e}) for {p1_8_doc:?} -> {out:?}")
            });
            assert_eq!(
                f(&out),
                out,
                "R19 P1-8 [{label}] failed 1-step idempotency for {p1_8_doc:?}"
            );
        }
        let deep_p1_8 = format!("{deep_prefix}{p1_8_doc}{deep_suffix}");
        for &(label, f) in &eps {
            let out = f(&deep_p1_8);
            assert!(
                out.starts_with(&deep_prefix) && out.ends_with(&deep_suffix),
                "R19 P1-8 [{label}] corrupted >128-deep JSON wrapper: {out:?}"
            );
            let inner = &out[deep_prefix.len()..out.len() - deep_suffix.len()];
            serde_json::from_str::<serde_json::Value>(inner).unwrap_or_else(|e| {
                panic!("R19 P1-8 [{label}] corrupted >128-deep inner JSON ({e}): {inner:?}")
            });
            assert_eq!(f(&out), out);
        }
    }
    let p1_8_with_secret = format!(
        "{{\"a\":\"'\\\\'{hdr_auth}: Bearer SUPER_SECRET_R19_P1_8S\",\"b\":\"'}}\",\"c\":\"ok\"}}"
    );
    for (label, f) in [
        (
            "persisted",
            sanitize_persisted_lifecycle_text as fn(&str) -> String,
        ),
        (
            "projected",
            diagnostic_projection::redact_secrets as fn(&str) -> String,
        ),
        (
            "balanced",
            diagnostic_projection::redact_balanced_structured_secrets as fn(&str) -> String,
        ),
    ] {
        let out = f(&p1_8_with_secret);
        assert!(!out.contains("SUPER_SECRET_R19_P1_8S"), "{out:?}");
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| {
            panic!("R19 P1-8 [{label}] secret-bearing JSON corrupted ({e}): {out:?}")
        });
        assert_eq!(parsed["b"], "'}");
        assert_eq!(parsed["c"], "ok");
        assert_eq!(f(&out), out);
    }

    // 4. Direct `redact_embedded_json_spans` verification on R18 embedded JSON findings
    for (emb, prefix, forbidden) in [
        (
            r#"installer error: {"cmd": "curl --cert\nclient.p12:SUPER_SECRET_R19_EMB1"}"#
                .to_string(),
            "installer error: ",
            "SUPER_SECRET_R19_EMB1",
        ),
        (
            r#"err: ["sh", "-c", "curl --cert\nclient.p12:SUPER_SECRET_R19_EMB2"]"#.to_string(),
            "err: ",
            "SUPER_SECRET_R19_EMB2",
        ),
        (
            r#"err: {"msg": "\ud83d\ude80Bearer SUPER_SECRET_R19_EMB3"}"#.to_string(),
            "err: ",
            "SUPER_SECRET_R19_EMB3",
        ),
        (
            r#"err: {"url": "ssh://admin\u003aSUPER_SECRET_R19_EMB4@example.com"}"#.to_string(),
            "err: ",
            "SUPER_SECRET_R19_EMB4",
        ),
        (
            format!(
                r#"err: {{"h": "{hdr_auth}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_EMB5\""}}"#
            ),
            "err: ",
            "SUPER_SECRET_R19_EMB5",
        ),
    ] {
        let out = diagnostic_projection::redact_embedded_json_spans(&emb);
        assert!(
            !out.contains(forbidden),
            "R19 redact_embedded_json_spans leaked {forbidden:?} for {emb:?} -> {out:?}"
        );
        assert!(
            out.starts_with(prefix),
            "R19 redact_embedded_json_spans altered prefix {prefix:?}: {out:?}"
        );
        serde_json::from_str::<serde_json::Value>(&out[prefix.len()..]).unwrap_or_else(|e| {
            panic!("R19 redact_embedded_json_spans emitted invalid embedded JSON ({e}): {out:?}")
        });
        assert_eq!(
            diagnostic_projection::redact_embedded_json_spans(&out),
            out,
            "R19 redact_embedded_json_spans idempotency failed for {emb:?}"
        );
    }

    // 5. Benign preservation & exact post-quote / post-header / post-separator checks
    let benign_all_4: &[&str] = &[
        // R18-P1-1 benign cert paths
        "curl --cert\n/etc/ssl/client.pem",
        "curl --cert\nC:\\certs\\client.pem",
        r#"{"cmd": "curl --cert\n/etc/ssl/client.pem"}"#,
        r#"{"cmd": "curl --cert\nC:\\certs\\client.pem"}"#,
        // R18-P1-4 passwordless ssh://
        "ssh://git@github.com",
        "ssh://git@github.com:2222/org/repo.git",
        r#"{"url": "ssh://git@github.com"}"#,
        // R18-P1-5 benign multiline quotes without passphrase colon + unquoted newline before colon
        "user=\"alice\nbob\"",
        "curl --cert \"C:\\certs\nclient.pem\"",
        "curl --cert client.p12\n:not_passphrase",
        // R18-P3-1 shell separators resetting `saw_curl` in JSON argv arrays
        r#"["curl", "https://example.com", "&&", "git", "checkout", "-b", "feature-branch"]"#,
        r#"["curl", "https://example.com", "||", "git", "checkout", "-b", "feature-branch"]"#,
        r#"["curl", "https://example.com", ";", "git", "checkout", "-b", "feature-branch"]"#,
        r#"["curl", "https://example.com", "|", "git", "checkout", "-b", "feature-branch"]"#,
        "[\n  \"curl\",\n  \"https://example.com\",\n  \"&&\",\n  \"git\",\n  \"checkout\",\n  \"-b\",\n  \"feature-branch\"\n]",
    ];
    for &benign in benign_all_4 {
        for &(label, f) in &eps {
            let out = f(benign);
            assert_eq!(
                out, benign,
                "R19 [{label}] mutated benign input {benign:?} -> {out:?}"
            );
        }
        if benign.starts_with(['{', '[']) {
            let orig: serde_json::Value = serde_json::from_str(benign).unwrap();
            let mut copy = orig.clone();
            assert!(!diagnostic_projection::redact_json_value(&mut copy));
            assert_eq!(
                copy, orig,
                "R19 redact_json_value mutated benign {benign:?}"
            );
            let emb_benign = format!("log: {benign}");
            assert_eq!(
                diagnostic_projection::redact_embedded_json_spans(&emb_benign),
                emb_benign,
                "R19 redact_embedded_json_spans mutated benign {emb_benign:?}"
            );
        }
    }

    // Partial-benign preservation checks (secret redacted AND benign tail/sibling preserved)
    let p1_2_post_quote =
        format!("{pw}=\\u0027line1\nSUPER_SECRET_R19_15\\u0027\nbenign status line");
    let p1_3_s6_win_cert =
        format!("{pw}=\nfoo; [\"curl\", \"--cert\",\n\"C:\\\\certs\\\\client.pem\"]");
    let p1_6_host_after_digest = format!(
        "{hdr_auth}: Digest username=\"alice\", response=\"SUPER_SECRET_R19_DG_HOST\"\nHost: example.com"
    );
    let p1_6_host_after_nl_digest = format!(
        "{hdr_auth}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_DG_NL_HOST\"\nHost: example.com"
    );
    let p3_1_mixed_argv = r#"["curl", "-b", "sid=SUPER_SECRET_R19_PRE_SEP", "https://example.com", "&&", "git", "checkout", "-b", "feature-branch"]"#;
    let p1_2_u0027_eq_argv =
        format!("[\\u0027--{pw}=SUPER_SECRET_R19_FUZZ_B5\\u0027, \\u0027keep_arg\\u0027]");
    let p2_1_folded_then_benign_json = "Cookie: a=1;\n  b=2\n{\"ok\":true}";
    let p2_1_folded_secret_then_benign_json = format!(
        "Cookie: a=1;\n  b=2; {pw}={{\n\"k\":\"SUPER_SECRET_R19_32_TAIL\"\n}}\n{{\"ok\":true}}"
    );

    for &(label, f) in &eps {
        let o_p2_b = f(p2_1_folded_then_benign_json);
        assert!(
            o_p2_b.ends_with("\n{\"ok\":true}"),
            "R19 [{label}] P2-1 swallowed trailing {{\"ok\":true}}: {o_p2_b:?}"
        );
        assert_eq!(f(&o_p2_b), o_p2_b);

        let o_p2_s = f(&p2_1_folded_secret_then_benign_json);
        assert!(
            !o_p2_s.contains("SUPER_SECRET_R19_32_TAIL"),
            "R19 [{label}] {o_p2_s:?}"
        );
        assert!(
            o_p2_s.ends_with("\n{\"ok\":true}"),
            "R19 [{label}] P2-1 swallowed trailing {{\"ok\":true}} after closed brace: {o_p2_s:?}"
        );
        assert_eq!(f(&o_p2_s), o_p2_s);
        let o_q = f(&p1_2_post_quote);
        assert!(
            !o_q.contains("SUPER_SECRET_R19_15"),
            "R19 [{label}] {o_q:?}"
        );
        assert!(
            o_q.ends_with("\nbenign status line"),
            "R19 [{label}] P1-2 swallowed post-\\u0027 benign line: {o_q:?}"
        );
        assert_eq!(f(&o_q), o_q);

        let o_w = f(&p1_3_s6_win_cert);
        assert!(!o_w.contains("foo"), "R19 [{label}] {o_w:?}");
        assert!(
            o_w.contains(r#""C:\\certs\\client.pem""#),
            "R19 [{label}] P1-3 Section 6 over-redacted benign Windows cert path: {o_w:?}"
        );
        assert_eq!(f(&o_w), o_w);

        let o_h1 = f(&p1_6_host_after_digest);
        assert!(
            !o_h1.contains("SUPER_SECRET_R19_DG_HOST"),
            "R19 [{label}] {o_h1:?}"
        );
        assert!(
            o_h1.ends_with("\nHost: example.com"),
            "R19 [{label}] P1-6 swallowed Host header: {o_h1:?}"
        );
        assert_eq!(f(&o_h1), o_h1);

        let o_h2 = f(&p1_6_host_after_nl_digest);
        assert!(
            !o_h2.contains("SUPER_SECRET_R19_DG_NL_HOST"),
            "R19 [{label}] {o_h2:?}"
        );
        assert!(
            o_h2.ends_with("\nHost: example.com"),
            "R19 [{label}] P1-6 swallowed Host header after response=\\n: {o_h2:?}"
        );
        assert_eq!(f(&o_h2), o_h2);

        let o_m = f(p3_1_mixed_argv);
        assert!(
            !o_m.contains("SUPER_SECRET_R19_PRE_SEP"),
            "R19 [{label}] {o_m:?}"
        );
        if label != "diag" {
            assert!(
                o_m.contains("feature-branch"),
                "R19 [{label}] P3-1 over-redacted feature-branch after &&: {o_m:?}"
            );
            let o_u27_eq = f(&p1_2_u0027_eq_argv);
            assert!(
                !o_u27_eq.contains("SUPER_SECRET_R19_FUZZ_B5"),
                "{o_u27_eq:?}"
            );
            assert!(
                o_u27_eq.contains("keep_arg"),
                "R19 [{label}] P1-2 over-redacted keep_arg after \\u0027--flag=...\\u0027: {o_u27_eq:?}"
            );
            assert_eq!(f(&o_u27_eq), o_u27_eq);
        }
        assert_eq!(f(&o_m), o_m);
    }

    // 6. SQLite Persistence Check (`R18-P1-6` Digest `response=\n"..."` + `R18-P1-1`/`P1-7`/`P1-8`)
    {
        let (root, _, _database, mut conn) = fixture();
        let digest_sql_summary = format!(
            "{hdr_auth}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_SQL_26\"\nHost: example.com"
        );
        let digest_sql_target = format!(
            r#"{{"h": "{hdr_auth}: Digest username=\"alice\", response=\n\"SUPER_SECRET_R19_SQL_27\"", "surr": "\ud83d\ude80Bearer SUPER_SECRET_R19_SQL_28", "q": {{"":[{{"":"'\\'{hdr_auth}:"}},"'}}"]}}}}"#
        );
        let lease_sql = admit_job_with_target(
            &mut conn,
            "pkg-r19-digest",
            "job-r19-digest",
            "update",
            "2026-11-27T18:00:00Z",
            &[],
            Some(&digest_sql_target),
        )
        .unwrap();
        finish_job_with_diagnostics(
            &conn,
            "pkg-r19-digest",
            "job-r19-digest",
            "update",
            false,
            LifecycleJobDiagnostics {
                failure_category: "install_failed",
                sanitized_summary: Some(&digest_sql_summary),
                expected_target_version: Some(&digest_sql_target),
                finished_at: Some("2026-11-27T18:01:00Z"),
                ..Default::default()
            },
        )
        .unwrap();

        let (raw_exp, raw_sum): (String, String) = conn
            .query_row(
                "SELECT expected_target_version, sanitized_summary FROM package_lifecycle_history WHERE job_id = 'job-r19-digest'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(!raw_sum.contains("SUPER_SECRET_R19_SQL_26"), "{raw_sum:?}");
        assert!(raw_sum.contains("Host: example.com"), "{raw_sum:?}");
        assert!(!raw_exp.contains("SUPER_SECRET_R19_SQL_27"), "{raw_exp:?}");
        assert!(!raw_exp.contains("SUPER_SECRET_R19_SQL_28"), "{raw_exp:?}");
        serde_json::from_str::<serde_json::Value>(&raw_exp)
            .unwrap_or_else(|e| panic!("SQLite persisted R19 JSON corrupted ({e}): {raw_exp:?}"));

        let hist = get_lifecycle_history(&conn, "pkg-r19-digest", 5).unwrap();
        assert_eq!(hist.len(), 1);
        let proj_sum = hist[0].sanitized_summary.as_deref().unwrap();
        let proj_exp = hist[0].expected_target_version.as_deref().unwrap();
        assert!(!proj_sum.contains("SUPER_SECRET_R19_SQL_26"));
        assert!(proj_sum.contains("Host: example.com"));
        assert!(!proj_exp.contains("SUPER_SECRET_R19_SQL_27"));
        assert!(!proj_exp.contains("SUPER_SECRET_R19_SQL_28"));

        drop(lease_sql);
        drop(conn);
        std::fs::remove_dir_all(root).unwrap();
    }

    // 7. Adaptive linear-time O(N) scaling (`ratio < 3.2`) across all R19 scanners
    type R19Scaling = (&'static str, fn(usize) -> String, usize, usize);
    let r19_scaling: &[R19Scaling] = &[
        (
            "r19_p1_1_cert_nl_benign_pem",
            |n| format!("curl {}", "--cert\n/etc/ssl/client.pem ".repeat(n)),
            400,
            64_000,
        ),
        (
            "r19_p1_1_json_cert_nl_benign",
            |n| {
                format!(
                    r#"{{"cmd":"curl {}"}}"#,
                    r#"--cert\n/etc/ssl/client.pem "#.repeat(n)
                )
            },
            400,
            64_000,
        ),
        (
            "r19_p1_2_u0027_scalars",
            make_r19_p1_2_u0027_scalars,
            400,
            64_000,
        ),
        (
            "r19_p1_2_u0027_unclosed_flood",
            make_r19_p1_2_u0027_unclosed,
            400,
            64_000,
        ),
        ("r19_p1_2_u0027_argv", make_r19_p1_2_u0027_argv, 300, 32_000),
        (
            "r19_p1_3_diag_carry_mixed",
            make_r19_p1_3_diag_carry_mixed,
            300,
            32_000,
        ),
        (
            "r19_p1_4_ssh_u003a_urls",
            |n| "ssh://admin\\u003asec@example.com ssh://git@github.com ".repeat(n),
            400,
            64_000,
        ),
        (
            "r19_p1_5_ml_cert_unclosed_dq_colon",
            |n| format!("{} :tail", "curl --cert \"a\n".repeat(n)),
            400,
            64_000,
        ),
        (
            "r19_p1_5_ml_user_unclosed_dq_colon",
            |n| format!("{} :tail", "user=\"alice\n".repeat(n)),
            400,
            64_000,
        ),
        (
            "r19_p1_5_ml_cert_u0027_colon",
            |n| format!("{} :tail", "curl --cert \\u0027a\n".repeat(n)),
            400,
            64_000,
        ),
        (
            "r19_p1_6_digest_eq_nl",
            make_r19_p1_6_digest_eq_nl,
            300,
            32_000,
        ),
        (
            "r19_p1_7_utf16_surrogates_json",
            |n| {
                format!(
                    r#"{{"msg":"{}"}}"#,
                    r#"\ud83d\ude80Bearer sec \ud83d\ude80ok "#.repeat(n)
                )
            },
            300,
            32_000,
        ),
        (
            "r19_p1_8_sq_bs_auth_json",
            make_r19_p1_8_sq_bs_auth_json,
            300,
            32_000,
        ),
        (
            "r19_p2_1_folded_header_unclosed_brace",
            make_r19_p2_1_folded_header_unclosed_brace,
            300,
            32_000,
        ),
        (
            "r19_p3_1_curl_sep_git_argv",
            |n| {
                format!(
                    "[{}]",
                    r#""curl","https://example.com","&&","git","checkout","-b","feature","#
                        .repeat(n)
                        .trim_end_matches(',')
                )
            },
            300,
            32_000,
        ),
    ];

    let started_r19 = std::time::Instant::now();
    for &(name, make_payload, start_n, max_n) in r19_scaling {
        for &(ep, f) in &eps {
            assert_adaptive_linear_scaling(name, ep, make_payload, start_n, max_n, |p| f(p).len());
        }
    }
    assert!(
        started_r19.elapsed() < std::time::Duration::from_secs(120),
        "R19 linear-time budget exceeded: {:?}",
        started_r19.elapsed()
    );
}
