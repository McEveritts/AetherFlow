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
