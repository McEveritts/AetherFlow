use super::*;

#[test]
fn test_secret_redaction_comprehensive() {
    let input = r#"{"access_token": "secret_tok_123", "refresh_token": "ref_456", "private_key": "priv_key_789"}"#;
    let redacted = redact_secrets(input);
    assert!(!redacted.contains("secret_tok_123"));
    assert!(!redacted.contains("ref_456"));
    assert!(!redacted.contains("priv_key_789"));
    assert!(redacted.contains("[REDACTED]"));

    let kv_input = "access_token: tok_abc; refresh-token = ref_xyz; 'private_key': 'key_123'; auth_token=auth999; session_token: sess111";
    let kv_redacted = redact_secrets(kv_input);
    assert!(!kv_redacted.contains("tok_abc"));
    assert!(!kv_redacted.contains("ref_xyz"));
    assert!(!kv_redacted.contains("key_123"));
    assert!(!kv_redacted.contains("auth999"));
    assert!(!kv_redacted.contains("sess111"));
    assert!(kv_redacted.contains("[REDACTED]"));

    // Escaped quotes and backslashes inside JSON
    let escaped_input = r#"{"password": "my\"super\\secret"}"#;
    let escaped_redacted = redact_secrets(escaped_input);
    assert!(!escaped_redacted.contains("super"));
    assert!(!escaped_redacted.contains("secret"));
    assert!(escaped_redacted.contains("[REDACTED]"));

    // Nested JSON objects and multiline JSON secrets
    let nested_multiline = "{\n  \"service\": \"auth\",\n  \"config\": {\n    \"api_key\": \"nested_key_xyz\",\n    \"user_password\": \"multi\\nline\\\"secret\"\n  }\n}";
    let nested_redacted = redact_secrets(nested_multiline);
    assert!(!nested_redacted.contains("nested_key_xyz"));
    assert!(!nested_redacted.contains("multi\\nline"));
    assert!(nested_redacted.contains("[REDACTED]"));

    // Truncated JSON string at end of line
    let truncated_json = r#"error payload: {"password": "partial_secret_without_end"#;
    let trunc_redacted = redact_secrets(truncated_json);
    assert!(!trunc_redacted.contains("partial_secret"));
    assert!(trunc_redacted.contains("[REDACTED]"));

    // Key-value pairs with escaped quotes
    let kv_escaped = r#"password="my\"escaped\\pass" token='another\'tok'"#;
    let kv_esc_redacted = redact_secrets(kv_escaped);
    assert!(!kv_esc_redacted.contains("escaped"));
    assert!(!kv_esc_redacted.contains("another"));
    assert!(kv_esc_redacted.contains("[REDACTED]"));
}

#[test]
fn test_multi_span_embedded_json_and_compound_keys_redaction() {
    // Multi-span embedded JSON on a single line
    let multi_json = r#"req={"user_password":"secret1"} resp={"api_token":"secret2"}"#;
    let multi_redacted = redact_secrets(multi_json);
    assert!(!multi_redacted.contains("secret1"));
    assert!(!multi_redacted.contains("secret2"));
    assert!(multi_redacted.contains(r#"{"user_password":"[REDACTED]"}"#));
    assert!(multi_redacted.contains(r#"{"api_token":"[REDACTED]"}"#));

    // Fallback non-JSON or malformed JSON with compound keys and escaped quotes
    let malformed = r#"user_password="pw\"1" and db_secret=sec2 github_token="tok3""#;
    let malformed_redacted = redact_secrets(malformed);
    assert!(!malformed_redacted.contains(r#"pw\"1"#));
    assert!(!malformed_redacted.contains("sec2"));
    assert!(!malformed_redacted.contains("tok3"));
    assert!(malformed_redacted.contains("[REDACTED]"));

    // Compound keys in KV and colon formats
    let compound = "admin_passwd: pass1; x_api_key=key2; rclone_rc_pass: rc3; master_pass=mp4; private_key_pem=pem5";
    let compound_redacted = redact_secrets(compound);
    assert!(!compound_redacted.contains("pass1"));
    assert!(!compound_redacted.contains("key2"));
    assert!(!compound_redacted.contains("rc3"));
    assert!(!compound_redacted.contains("mp4"));
    assert!(!compound_redacted.contains("pem5"));
    assert!(compound_redacted.contains("[REDACTED]"));
}

#[test]
fn test_secret_key_context_across_json_boundaries_and_auth_credentials() {
    // 1. Secret key preceding JSON object or array across boundary
    let prefix_obj = r#"password={"raw":"my_secret_123"}"#;
    let red_prefix_obj = redact_secrets(prefix_obj);
    assert!(!red_prefix_obj.contains("my_secret_123"));
    assert!(red_prefix_obj.contains("[REDACTED]"));

    let prefix_arr = r#"secret: ["tok1", "tok2"]"#;
    let red_prefix_arr = redact_secrets(prefix_arr);
    assert!(!red_prefix_arr.contains("tok1"));
    assert!(!red_prefix_arr.contains("tok2"));
    assert!(red_prefix_arr.contains("[REDACTED]"));

    let prefix_quoted = r#""api_token": {"nested": "secret_abc"}"#;
    let red_prefix_quoted = redact_secrets(prefix_quoted);
    assert!(!red_prefix_quoted.contains("secret_abc"));
    assert!(red_prefix_quoted.contains("[REDACTED]"));

    // 2. HTTP Basic Auth / Bearer / Token / Digest
    let basic_auth = "Authorization: Basic dXNlcjpwYXNz";
    let red_basic = redact_secrets(basic_auth);
    assert!(!red_basic.contains("dXNlcjpwYXNz"));
    assert!(red_basic.contains("Basic [REDACTED]"));

    let raw_basic = "header: Basic dXNlcjpwYXNz";
    let red_raw_basic = redact_secrets(raw_basic);
    assert!(!red_raw_basic.contains("dXNlcjpwYXNz"));
    assert!(red_raw_basic.contains("Basic [REDACTED]"));

    // 3. curl -u / --user / CLI flags
    let curl_u = "curl -u admin:mysecret123 http://example.com/api";
    let red_curl_u = redact_secrets(curl_u);
    assert!(!red_curl_u.contains("mysecret123"));
    assert!(red_curl_u.contains("curl -u [REDACTED]"));

    let curl_user_quoted = "curl --user \"admin:mysecret123\" http://example.com";
    let red_curl_user = redact_secrets(curl_user_quoted);
    assert!(!red_curl_user.contains("mysecret123"));
    assert!(red_curl_user.contains("curl --user [REDACTED]"));

    let cli_pass = "program --pass mysecret123 --other flag";
    let red_cli_pass = redact_secrets(cli_pass);
    assert!(!red_cli_pass.contains("mysecret123"));
    assert!(red_cli_pass.contains("--pass [REDACTED]"));

    let cli_rc_pass = "rclone --rc-pass secret_rc_pass --rc-user user";
    let red_cli_rc = redact_secrets(cli_rc_pass);
    assert!(!red_cli_rc.contains("secret_rc_pass"));
    assert!(red_cli_rc.contains("--rc-pass [REDACTED]"));

    // 4. Embedded in non-sensitive JSON string values
    let json_with_embedded =
        r#"{"status":"executing","log":"running curl -u admin:mysecret123 http://test"}"#;
    let red_json_embedded = redact_secrets(json_with_embedded);
    assert!(!red_json_embedded.contains("mysecret123"));
    assert!(red_json_embedded.contains("curl -u [REDACTED]"));
}

#[test]
fn test_redact_secrets_idempotent() {
    let inputs = [
        "Authorization: Basic dXNlcjpwYXNz",
        "curl -u admin:mysecret123 http://example.com/api",
        "program --pass mysecret123 --other flag",
        r#"{"password": "secret", "token": "tok123"}"#,
        "password=mysecret and db_secret=dbsec",
        "PASS=mysecret",
    ];
    for input in inputs {
        let once = redact_secrets(input);
        let twice = redact_secrets(&once);
        assert_eq!(
            once, twice,
            "redact_secrets must be idempotent for input: {input}"
        );
    }
}

#[test]
fn test_strict_redaction_without_embedded_marker_bypass() {
    // Direct is_already_redacted unit tests
    assert!(!is_already_redacted("admin:prefix[REDACTED]suffix"));
    assert!(!is_already_redacted("Bearer prefix[REDACTED]suffix"));
    assert!(!is_already_redacted(
        "\"password\": \"prefix[REDACTED]suffix\""
    ));
    assert!(!is_already_redacted("prefix[REDACTED]suffix"));
    assert!(!is_already_redacted(
        "https://admin:prefix[REDACTED]suffix@example.com/api"
    ));
    assert!(!is_already_redacted("[REDACTED]something"));
    assert!(!is_already_redacted("something[REDACTED]"));

    assert!(is_already_redacted("[REDACTED]"));
    assert!(is_already_redacted("\"[REDACTED]\""));
    assert!(is_already_redacted("'[REDACTED]'"));
    assert!(is_already_redacted("\"\"[REDACTED]\"\""));
    assert!(is_already_redacted("[REDACTED_URL]"));
    assert!(is_already_redacted("Basic [REDACTED]"));
    assert!(is_already_redacted("Bearer [REDACTED]"));
    assert!(is_already_redacted("Token [REDACTED]"));
    assert!(is_already_redacted("Digest [REDACTED]"));
    assert!(is_already_redacted("Bearer \"[REDACTED]\""));

    // 1. admin:prefix[REDACTED]suffix in curl credentials
    let curl_in = "curl -u admin:prefix[REDACTED]suffix https://example.com/api";
    let curl_red = redact_secrets(curl_in);
    assert!(!curl_red.contains("prefix"));
    assert!(!curl_red.contains("suffix"));
    assert!(!curl_red.contains("admin:prefix"));
    assert_eq!(curl_red, "curl -u [REDACTED] https://example.com/api");
    assert_eq!(
        redact_secrets(&curl_red),
        curl_red,
        "curl redaction must be idempotent"
    );

    // 2. Bearer prefix[REDACTED]suffix in auth header
    let bearer_in = "Authorization: Bearer prefix[REDACTED]suffix";
    let bearer_red = redact_secrets(bearer_in);
    assert!(!bearer_red.contains("prefix"));
    assert!(!bearer_red.contains("suffix"));
    assert_eq!(bearer_red, "Authorization: Bearer [REDACTED]");
    assert_eq!(
        redact_secrets(&bearer_red),
        bearer_red,
        "Bearer redaction must be idempotent"
    );

    let standalone_bearer = "Bearer prefix[REDACTED]suffix";
    let sb_red = redact_secrets(standalone_bearer);
    assert!(!sb_red.contains("prefix"));
    assert!(!sb_red.contains("suffix"));
    assert_eq!(sb_red, "Bearer [REDACTED]");
    assert_eq!(
        redact_secrets(&sb_red),
        sb_red,
        "Standalone Bearer redaction must be idempotent"
    );

    // 3. "password": "prefix[REDACTED]suffix" in JSON and KV
    let json_in = r#"{"password": "prefix[REDACTED]suffix"}"#;
    let json_red = redact_secrets(json_in);
    assert!(!json_red.contains("prefix"));
    assert!(!json_red.contains("suffix"));
    assert_eq!(json_red, r#"{"password":"[REDACTED]"}"#);
    assert_eq!(
        redact_secrets(&json_red),
        json_red,
        "JSON password redaction must be idempotent"
    );

    let raw_kv_in = r#""password": "prefix[REDACTED]suffix""#;
    let raw_kv_red = redact_secrets(raw_kv_in);
    assert!(!raw_kv_red.contains("prefix"));
    assert!(!raw_kv_red.contains("suffix"));
    assert_eq!(raw_kv_red, r#""password": "[REDACTED]""#);
    assert_eq!(
        redact_secrets(&raw_kv_red),
        raw_kv_red,
        "Raw KV password redaction must be idempotent"
    );

    // 4. https://admin:prefix[REDACTED]suffix@example.com/api in URL credentials
    let url_in = "https://admin:prefix[REDACTED]suffix@example.com/api";
    let url_red = redact_secrets(url_in);
    assert!(!url_red.contains("prefix"));
    assert!(!url_red.contains("suffix"));
    assert_eq!(url_red, "https://admin:[REDACTED]@example.com/api");
    assert_eq!(
        redact_secrets(&url_red),
        url_red,
        "URL credential redaction must be idempotent"
    );
}

#[test]
fn test_marker_prefixed_secrets_do_not_leak_suffix_and_are_idempotent() {
    let cases = [
        "password: [REDACTED]suffix",
        "\"password\": \"[REDACTED]suffix\"",
        "password=[REDACTED]suffix",
        "Authorization: Bearer [REDACTED]suffix",
        "Authorization: Basic [REDACTED]suffix",
        "curl -u [REDACTED]suffix",
        "curl -u admin:[REDACTED]suffix",
        "--password [REDACTED]suffix",
        "--token=[REDACTED]suffix",
        "SECRET_KEY=[REDACTED]suffix",
        "API_KEY=[REDACTED]suffix",
        "https://user:[REDACTED]suffix@example.com/path",
        "https://admin:[REDACTED]suffix@example.com/api",
    ];

    for case in cases {
        let redacted = redact_secrets(case);
        assert!(
            !redacted.contains("suffix"),
            "Redacted output for '{case}' must not contain 'suffix', got: '{redacted}'"
        );
        let second_pass = redact_secrets(&redacted);
        assert_eq!(
            second_pass, redacted,
            "Redaction must be idempotent for case '{case}' (got '{redacted}' vs '{second_pass}')"
        );
    }

    let genuine_redacted_cases = [
        "password: [REDACTED]",
        "\"password\": \"[REDACTED]\"",
        "Authorization: Bearer [REDACTED]",
        "Authorization: Basic [REDACTED]",
        "curl -u [REDACTED]",
        "API_KEY=[REDACTED]",
        "https://[REDACTED]@example.com/api",
    ];

    for case in genuine_redacted_cases {
        let redacted = redact_secrets(case);
        assert_eq!(
            redacted, case,
            "Genuine already-redacted input '{case}' must remain unchanged, got: '{redacted}'"
        );
        assert_eq!(
            redact_secrets(&redacted),
            case,
            "Subsequent redactions must remain idempotent for '{case}'"
        );
    }
}

#[test]
fn test_json_prefixed_secrets_do_not_leak_suffix_and_are_idempotent() {
    let exact_cases = [
        ("password: [true]suffix", "password: [REDACTED]"),
        ("password: [1, 2, 3]suffix", "password: [REDACTED]"),
        ("password: {\"a\": 1}suffix", "password: [REDACTED]"),
        (
            "password: {\"token\": \"abc\"}suffix",
            "password: [REDACTED]",
        ),
        ("secret=[true]suffix", "secret=[REDACTED]"),
        ("--password=[true]suffix", "--password=[REDACTED]"),
        (
            "Authorization: Bearer [true]suffix",
            "Authorization: Bearer [REDACTED]",
        ),
    ];

    for (input, expected) in exact_cases {
        let redacted = redact_secrets(input);
        assert_eq!(
            redacted, expected,
            "Input '{input}' must redact to '{expected}', got '{redacted}'"
        );
        assert!(
            !redacted.contains("suffix"),
            "Redacted output for '{input}' must not contain 'suffix', got '{redacted}'"
        );
        let second_pass = redact_secrets(&redacted);
        assert_eq!(
            second_pass, redacted,
            "Redaction must be idempotent for '{input}' (got '{redacted}' vs '{second_pass}')"
        );
    }

    // Standalone JSON: {"user": "admin", "password": "[true]suffix"}
    let standalone_json = r#"{"user": "admin", "password": "[true]suffix"}"#;
    let standalone_redacted = redact_secrets(standalone_json);
    assert!(
        !standalone_redacted.contains("suffix"),
        "Standalone JSON output must not contain 'suffix', got '{standalone_redacted}'"
    );
    assert!(
        standalone_redacted.contains(r#""password":"[REDACTED]""#)
            || standalone_redacted.contains(r#""password": "[REDACTED]""#),
        "Standalone JSON password must be redacted, got '{standalone_redacted}'"
    );
    let standalone_second = redact_secrets(&standalone_redacted);
    assert_eq!(
        standalone_second, standalone_redacted,
        "Standalone JSON redaction must be idempotent"
    );

    // Additional compound and valid JSON prefix cases
    let extra_cases = [
        (
            "Authorization: Basic [true]suffix",
            "Authorization: Basic [REDACTED]",
        ),
        ("curl -u [true]suffix", "curl -u [REDACTED]"),
        ("curl -u admin:[true]suffix", "curl -u [REDACTED]"),
        ("SECRET_KEY=[true]suffix", "SECRET_KEY=[REDACTED]"),
        ("API_KEY=[true]suffix", "API_KEY=[REDACTED]"),
        ("\"password\": [true]suffix", "\"password\": \"[REDACTED]\""),
        ("secret: [1, 2]suffix", "secret: [REDACTED]"),
        ("secret=[1,2]suffix", "secret=[REDACTED]"),
        ("--password [true]suffix", "--password [REDACTED]"),
        (
            "Authorization: Bearer [1, 2, 3]suffix",
            "Authorization: Bearer [REDACTED]",
        ),
        (
            "Authorization: Bearer {\"a\": 1}suffix",
            "Authorization: Bearer [REDACTED]",
        ),
    ];

    for (input, expected) in extra_cases {
        let redacted = redact_secrets(input);
        assert_eq!(
            redacted, expected,
            "Extra input '{input}' must redact to '{expected}', got '{redacted}'"
        );
        assert!(
            !redacted.contains("suffix"),
            "Redacted output for '{input}' must not contain 'suffix', got '{redacted}'"
        );
        let second = redact_secrets(&redacted);
        assert_eq!(
            second, redacted,
            "Extra input '{input}' redaction must be idempotent"
        );
    }
}

#[test]
fn test_nested_balanced_structured_secrets_do_not_leak_suffix_and_are_idempotent() {
    let cases = [
        ("password: {\"a\":{\"x\":1}}suffix", "password: [REDACTED]"),
        (
            "password: {\"a\":{\"b\":{\"c\":[1,{\"d\":2}]}}}suffix",
            "password: [REDACTED]",
        ),
        ("password: [[true, [false]]]suffix", "password: [REDACTED]"),
        ("secret={\"a\":{\"x\":1}}suffix", "secret=[REDACTED]"),
        (
            "--password={\"a\":{\"x\":1}}suffix",
            "--password=[REDACTED]",
        ),
        (
            "Authorization: Bearer {\"a\":{\"x\":1}}suffix",
            "Authorization: Bearer [REDACTED]",
        ),
    ];

    for (input, expected) in cases {
        let redacted = redact_secrets(input);
        assert_eq!(
            redacted, expected,
            "Input '{input}' must redact to '{expected}', got '{redacted}'"
        );
        assert!(
            !redacted.contains("suffix"),
            "Redacted output for '{input}' must not contain 'suffix', got '{redacted}'"
        );
        assert!(
            !redacted.contains("}suffix"),
            "Redacted output for '{input}' must not contain '}}suffix', got '{redacted}'"
        );
        let second_pass = redact_secrets(&redacted);
        assert_eq!(
            second_pass, redacted,
            "Redaction must be idempotent for '{input}'"
        );
    }

    // Test valid JSON preservation
    let json_input = r#"{"user": "admin", "password": {"a":{"x":1}}}"#;
    let json_redacted = redact_secrets(json_input);
    assert!(
        !json_redacted.contains("\"x\":1"),
        "Secret object must be redacted from JSON, got '{json_redacted}'"
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&json_redacted).expect("Redacted JSON must remain valid JSON");
    assert_eq!(parsed["user"], "admin");
    assert_eq!(parsed["password"], "[REDACTED]");

    let second_json = redact_secrets(&json_redacted);
    assert_eq!(
        second_json, json_redacted,
        "JSON redaction must be idempotent"
    );
}

#[test]
fn test_wave22_scalar_redaction_package_jobs() {
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
        "--session=CANARY_SESSION",
        "--webhook-url=https://example.test/CANARY_HOOK",
        "--cookie=CANARY_COOKIE",
        "SESSION=CANARY_SESSION",
        "COOKIE=CANARY_COOKIE",
        "WEBHOOK=CANARY_WEBHOOK",
    ];

    for c in cases {
        let redacted = redact_secrets(c);
        assert!(
            !redacted.contains("CANARY_"),
            "Redacted output for '{c}' still contains CANARY_: '{redacted}'"
        );
        assert!(
            redacted.contains("[REDACTED]"),
            "Redacted output for '{c}' must contain [REDACTED]: '{redacted}'"
        );
        assert_eq!(
            redact_secrets(&redacted),
            redacted,
            "Redaction must be idempotent for '{c}'"
        );
    }

    // Verify preservation of non-secret prose/keys
    let preserved = r#"{"bypass": true, "status": "passed"}"#;
    assert_eq!(redact_secrets(preserved), preserved);

    let prose = "compass heading is north and bypass compression";
    assert_eq!(redact_secrets(prose), prose);
}

#[test]
fn test_w22_s01_escaped_quote_and_multi_header_sanitization_services() {
    // 1. Escaped double-quotes inside header value
    let cmd1 = r#"curl -H "Cookie: sid=\"COOKIE_CANARY\"" https://example.invalid"#;
    let out1 = redact_secrets(cmd1);
    assert!(!out1.contains("COOKIE_CANARY"));
    assert!(out1.contains("https://example.invalid"));
    assert_eq!(
        out1,
        r#"curl -H "Cookie: [REDACTED]" https://example.invalid"#
    );
    assert_eq!(redact_secrets(&out1), out1);

    // 2. Set-Cookie with attributes and inner escaped quote
    let cmd2 = r#"curl -H "Set-Cookie: sid=\"COOKIE_CANARY\"; Secure" https://example.invalid"#;
    let out2 = redact_secrets(cmd2);
    assert!(!out2.contains("COOKIE_CANARY"));
    assert!(out2.contains("https://example.invalid"));
    assert_eq!(
        out2,
        r#"curl -H "Set-Cookie: [REDACTED]" https://example.invalid"#
    );
    assert_eq!(redact_secrets(&out2), out2);

    // 3. Single-quoted header value with double quotes and escaped single quotes
    let cmd3a = "curl -H 'Cookie: sid=\"COOKIE_CANARY\"' https://example.invalid";
    let out3a = redact_secrets(cmd3a);
    assert!(!out3a.contains("COOKIE_CANARY"));
    assert!(out3a.contains("https://example.invalid"));
    assert_eq!(
        out3a,
        "curl -H 'Cookie: [REDACTED]' https://example.invalid"
    );
    assert_eq!(redact_secrets(&out3a), out3a);

    let cmd3b = r"curl -H 'Cookie: sid=\'COOKIE_CANARY\'' https://example.invalid";
    let out3b = redact_secrets(cmd3b);
    assert!(!out3b.contains("COOKIE_CANARY"));
    assert!(out3b.contains("https://example.invalid"));
    assert_eq!(
        out3b,
        "curl -H 'Cookie: [REDACTED]' https://example.invalid"
    );
    assert_eq!(redact_secrets(&out3b), out3b);

    // 4. JSON-serialized string with escaped inner quotes
    let cmd4 = r#"{"cmd":"curl -H \"Cookie: sid=\\\"COOKIE_CANARY\\\"\" https://example.invalid"}"#;
    let out4 = redact_secrets(cmd4);
    assert!(!out4.contains("COOKIE_CANARY"));
    assert!(out4.contains("https://example.invalid"));
    assert_eq!(
        out4,
        r#"{"cmd":"curl -H \"Cookie: [REDACTED]\" https://example.invalid"}"#
    );
    assert_eq!(redact_secrets(&out4), out4);

    // 5. Multiple headers on the same line
    let cmd5 = r#"curl -H "Cookie: sid=\"CANARY_1\"" -H "X-Api-Key: \"CANARY_2\"" https://example.invalid"#;
    let out5 = redact_secrets(cmd5);
    assert!(!out5.contains("CANARY_1"));
    assert!(!out5.contains("CANARY_2"));
    assert!(out5.contains("https://example.invalid"));
    assert_eq!(
        out5,
        r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: [REDACTED]" https://example.invalid"#
    );
    assert_eq!(redact_secrets(&out5), out5);

    // Multiple headers without inner escaped quotes on same line
    let cmd5b =
        r#"curl -H "Cookie: sid=CANARY_1" -H "X-Api-Key: CANARY_2" https://example.invalid"#;
    let out5b = redact_secrets(cmd5b);
    assert!(!out5b.contains("CANARY_1"));
    assert!(!out5b.contains("CANARY_2"));
    assert!(out5b.contains("https://example.invalid"));
    assert_eq!(
        out5b,
        r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: [REDACTED]" https://example.invalid"#
    );
    assert_eq!(redact_secrets(&out5b), out5b);
}

#[test]
fn test_w24_structured_masking_grammar_package_jobs() {
    let scalars = [
        r#"password=\"SECRET words\""#,
        r#"api_key=\"SECRET words\""#,
        r#"client_secret=\"SECRET words\""#,
        r#"session=\"SECRET words\""#,
        r#"webhook=\"SECRET words\""#,
        r#"rclone_rc_pass=\"SECRET words\""#,
    ];
    for sample in scalars {
        let out = redact_secrets(sample);
        assert!(!out.contains("SECRET"), "scalar leaked: {sample} -> {out}");
        assert!(
            out.contains("[REDACTED]"),
            "scalar missing mask: {sample} -> {out}"
        );
        assert_eq!(
            redact_secrets(&out),
            out,
            "scalar not idempotent: {sample} -> {out}"
        );
    }

    let flags = [
        "--password SECRET word",
        "--token SECRET word",
        "--api-key SECRET word",
        "--cookie SECRET word",
        "--session SECRET word",
        "--webhook SECRET word",
        r#"--password=\"SECRET words\""#,
        "--user=\"user:SECRET words\"",
        "curl --user=\"admin:SECRET words\" https://example.invalid",
        "curl --user=admin:SECRET https://example.invalid",
        "curl -u=admin:SECRET https://example.invalid",
    ];
    for sample in flags {
        let out = redact_secrets(sample);
        assert!(!out.contains("SECRET"), "flag leaked: {sample} -> {out}");
        assert!(
            out.contains("[REDACTED]"),
            "flag missing mask: {sample} -> {out}"
        );
        assert!(
            !sample.contains("https://example.invalid") || out.contains("https://example.invalid"),
            "url dropped: {sample} -> {out}"
        );
        assert_eq!(
            redact_secrets(&out),
            out,
            "flag not idempotent: {sample} -> {out}"
        );
    }

    let mut encoded = r#"curl --user="admin:SECRET words" https://example.invalid"#.to_string();
    for depth in 1..=4 {
        encoded = serde_json::to_string(&encoded).unwrap();
        let wrapped = format!(r#"{{"command":{encoded}}}"#);
        let out = redact_secrets(&wrapped);
        assert!(
            !out.contains("SECRET"),
            "depth {depth} leaked: {wrapped} -> {out}"
        );
        assert!(
            out.contains("https://example.invalid"),
            "depth {depth}: {out}"
        );
        serde_json::from_str::<serde_json::Value>(&out)
            .unwrap_or_else(|err| panic!("depth {depth} json: {err}: {out}"));
        assert_eq!(
            redact_secrets(&out),
            out,
            "depth {depth} not idempotent: {out}"
        );
    }

    let diag = r#"AF_DIAG_FAILURE={"stage": "password=[REDACTED]\"SECRET words\\\"", "exit_code": 17, "category": "installer", "summary": "--user [REDACTED]\"user:SECRET words\\\""}"#;
    let diag_out = redact_secrets(diag);
    assert!(!diag_out.contains("SECRET"), "diag leaked: {diag_out}");
    let json = diag_out
        .split_once("AF_DIAG_FAILURE=")
        .map(|(_, rest)| rest)
        .unwrap_or("");
    let parsed: serde_json::Value =
        serde_json::from_str(json).unwrap_or_else(|err| panic!("diag json: {err}: {json}"));
    assert_eq!(parsed["exit_code"], 17, "diag_out={diag_out}");
    assert_eq!(parsed["category"], "installer");
    assert!(!parsed.to_string().contains("SECRET"));
    assert_eq!(redact_secrets(&diag_out), diag_out);

    let preserved = "bypass=visible passed=true monkey=1";
    assert_eq!(redact_secrets(preserved), preserved);
}

#[test]
fn test_quote_boundaries_are_masked_through_runner_persistence_and_projection() {
    let cases = [
        "password=\" QUOTED_CANARY\"",
        "password=prefix\" QUOTED_CANARY\"",
        "curl -u operator:\" QUOTED_CANARY\" --verbose",
        "password='prefix\nQUOTED_CANARY'\nX-Api-Key: ordinary",
        "password=[REDACTED]\" QUOTED_CANARY\"",
        "password=[REDACTED_URL]QUOTED_CANARY",
        "password=[REDACTED_url]\" QUOTED_CANARY\"",
    ];
    for sample in cases {
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(sample);
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(sample);
        let projected = redact_secrets(sample);
        let chained = redact_secrets(&af_release::lifecycle::sanitize_persisted_lifecycle_text(
            &runner,
        ));
        for result in [&runner, &persisted, &projected, &chained] {
            assert!(
                !result.contains("QUOTED_CANARY"),
                "{sample:?} -> {result:?}"
            );
            assert!(!redact_secrets(result).contains("QUOTED_CANARY"));
            assert!(
                !af_runner::package_lifecycle::sanitize_lifecycle_field(result)
                    .contains("QUOTED_CANARY")
            );
        }
    }
}

#[test]
fn test_release_gate_sensitive_key_grammar_across_boundaries() {
    for prefix in ["database", &"x".repeat(125), &"x".repeat(512)] {
        for key in ["Password", "Cookie", "Session", "Webhook", "Authorization"] {
            for escape_depth in [0, 1, 2, 4, 8] {
                let encoded_key = if escape_depth == 0 {
                    key.to_string()
                } else {
                    format!(
                        "{}u00{:02x}{}",
                        "\\".repeat(escape_depth),
                        key.as_bytes()[0],
                        &key[1..]
                    )
                };
                for value in [
                    r#""GRAMMAR_CANARY""#,
                    r#"{"value":"GRAMMAR_CANARY"}"#,
                    r#"["GRAMMAR_CANARY"]"#,
                ] {
                    let mut input = format!(r#""{prefix}{encoded_key}Encoded":{value}"#);
                    for _ in 0..3 {
                        for (boundary, result) in [
                            (
                                "runner",
                                af_runner::package_lifecycle::sanitize_lifecycle_field(&input),
                            ),
                            (
                                "persistence",
                                af_release::lifecycle::sanitize_persisted_lifecycle_text(&input),
                            ),
                            ("projection", redact_secrets(&input)),
                        ] {
                            assert!(
                                !result.contains("GRAMMAR_CANARY"),
                                "{boundary}: {input:?} -> {result:?}"
                            );
                            assert!(!redact_secrets(&result).contains("GRAMMAR_CANARY"));
                        }
                        input =
                            format!("AF_DIAG_FAILURE={}", serde_json::json!({"summary": input}));
                    }
                }
            }
        }
    }
}

#[test]
fn test_release_gate_receipt_preserves_closed_header_commands() {
    for tail in [
        "--verbose",
        "--retry 2",
        "-X GET",
        "-H \"Accept: application/json\"",
    ] {
        let command =
            format!("curl -H \"Authorization: [REDACTED]\" {tail} https://example.invalid");
        let mut input = command.clone();
        for _ in 0..3 {
            let sanitized = redact_secrets(&input);
            assert!(
                sanitized.contains("https://example.invalid"),
                "{input:?} -> {sanitized:?}"
            );
            assert!(
                sanitized.contains(tail.split_whitespace().next().unwrap()),
                "{sanitized:?}"
            );
            assert_eq!(redact_secrets(&sanitized), sanitized);
            input = format!("AF_DIAG_FAILURE={}", serde_json::json!({"summary": input}));
        }
    }
}

#[test]
fn test_final_gate_escaped_fragments_and_marked_headers() {
    let long_key = format!(
        r#""{}Pass\u0077ordEncoded":"FRAGMENT_CANARY""#,
        "x".repeat(125)
    );
    let samples = [
        long_key.as_str(),
        r#""databaseCookieEncoded":"FRAGMENT_CANARY""#,
        r#""databaseSessionEncoded":"FRAGMENT_CANARY""#,
        r#""incomingWebhookEncoded":"FRAGMENT_CANARY""#,
        r#""databasePasswordEncoded":"FRAGMENT_CANARY""#,
        r#""databasePass\u0077ordEncoded":"FRAGMENT_CANARY""#,
        r#""databasePass\\u0077ordEncoded":"FRAGMENT_CANARY""#,
        r#"{"databasePass\u0077ordEncoded":"FRAGMENT_CANARY"}"#,
        r#""databasePass\u0077ordEncoded":{"value":"FRAGMENT_CANARY"}"#,
        r#""databasePass\u0077ordEncoded":["FRAGMENT_CANARY""#,
        "Cookie: [REDACTED] sid=FRAGMENT_CANARY",
        "Authorization: [REDACTED] FRAGMENT_CANARY",
        "X-Api-Key: [REDACTED] FRAGMENT_CANARY",
        "Cookie: [REDACTED_URL] sid=FRAGMENT_CANARY",
        r#"Cookie: [REDACTED]" --verbose FRAGMENT_CANARY"#,
        r#"Authorization: [REDACTED]\" --retry FRAGMENT_CANARY"#,
        "Cookie: [REDACTED]' https://example.invalid/FRAGMENT_CANARY",
    ];
    for sample in samples {
        let receipt = format!(
            "AF_DIAG_FAILURE={}",
            serde_json::json!({
                "stage": "installer", "exit_code": 1, "summary": sample,
            })
        );
        for input in [sample, receipt.as_str()] {
            let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
            let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
            let projected = redact_secrets(input);
            let chained = redact_secrets(
                &af_release::lifecycle::sanitize_persisted_lifecycle_text(&runner),
            );
            for (boundary, result) in [
                ("runner", &runner),
                ("persistence", &persisted),
                ("projection", &projected),
                ("chain", &chained),
            ] {
                assert!(
                    !result.contains("FRAGMENT_CANARY"),
                    "{boundary}: {input:?} -> {result:?}"
                );
                assert!(!redact_secrets(result).contains("FRAGMENT_CANARY"));
            }
            let connection = Connection::open_in_memory().unwrap();
            af_release::lifecycle::initialize_schema(&connection).unwrap();
            connection.execute_batch(
                "INSERT INTO package_lifecycle_jobs (package_id,job_id,action,status,started_at) VALUES ('sonarr','fixture','update','updating','fixture');
                 INSERT INTO package_lifecycle_history (package_id,job_id,action,status,started_at) VALUES ('sonarr','fixture','update','updating','fixture');"
            ).unwrap();
            af_release::lifecycle::finish_job_with_diagnostics(
                &connection,
                "sonarr",
                "fixture",
                "update",
                false,
                af_release::lifecycle::LifecycleJobDiagnostics {
                    failure_category: "installer",
                    failed_stage: Some("fixture"),
                    exit_code: Some(1),
                    sanitized_summary: Some(input),
                    finished_at: Some("fixture"),
                    ..Default::default()
                },
            )
            .unwrap();
            for query in [
                "SELECT sanitized_summary FROM package_lifecycle_jobs WHERE job_id='fixture'",
                "SELECT sanitized_summary FROM package_lifecycle_history WHERE job_id='fixture'",
            ] {
                let summary: String = connection.query_row(query, [], |row| row.get(0)).unwrap();
                assert!(
                    !summary.contains("FRAGMENT_CANARY"),
                    "{input:?} -> {summary:?}"
                );
            }
        }
    }
    let benign = r#""displayN\u0061me":"visible" bypass=visible passed=true monkey=1"#;
    assert_eq!(redact_secrets(benign), benign);
    let command =
        r#"curl -H "Cookie: [REDACTED]" -H "X-Api-Key: FRAGMENT_CANARY" https://example.invalid"#;
    let sanitized = redact_secrets(command);
    assert!(!sanitized.contains("FRAGMENT_CANARY"));
    assert!(sanitized.contains("https://example.invalid"));
    assert_eq!(redact_secrets(&sanitized), sanitized);
}

#[test]
fn test_w25_escape_aware_scalar_and_unicode_keys_package_jobs() {
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
            r#"{"password":"[REDACTED]"}"#,
        ),
        (
            r#"{"pass\\u0077ord":"SENTINEL"}"#,
            r#"{"password":"[REDACTED]"}"#,
        ),
    ];
    for (sample, expected) in exact {
        let out = redact_secrets(sample);
        assert_eq!(out, expected, "sample={sample}");
        assert!(!out.contains("SENTINEL"), "{out}");
        assert!(!out.contains("123456789"), "{out}");
        assert_eq!(redact_secrets(&out), out, "idempotent: {sample}");
        if sample.contains("--verbose") {
            assert!(out.contains("--verbose"), "{out}");
        }
        if sample.contains("https://example.invalid") {
            assert!(out.contains("https://example.invalid"), "{out}");
        }
        if expected.starts_with('{') {
            serde_json::from_str::<serde_json::Value>(&out)
                .unwrap_or_else(|err| panic!("json {err}: {out}"));
        }

        let sanitized = af_release::lifecycle::sanitize_persisted_lifecycle_text(sample);
        assert!(
            !sanitized.contains("SENTINEL"),
            "sanitize leaked: {sample} -> {sanitized}"
        );
        assert!(
            !sanitized.contains("123456789"),
            "sanitize leaked number: {sample} -> {sanitized}"
        );
        let chained = redact_secrets(&sanitized);
        assert!(
            !chained.contains("SENTINEL"),
            "chain leaked: {sample} -> {sanitized} -> {chained}"
        );
        assert!(
            !chained.contains("123456789"),
            "chain leaked number: {chained}"
        );
        assert_eq!(
            redact_secrets(&chained),
            chained,
            "chain idempotent: {chained}"
        );
        if sample.contains("--verbose") {
            assert!(chained.contains("--verbose"), "{chained}");
        }
        if sample.contains("https://example.invalid") {
            assert!(chained.contains("https://example.invalid"), "{chained}");
        }
    }

    let containers = [
        (r#"{"Credentials":{"plain":"SENTINEL"}}"#, "Credentials"),
        (
            r#"{"credentials":{"a":{"b":{"c":{"plain":"SENTINEL"}}}}}"#,
            "credentials",
        ),
        (
            r#"{"credentials":[{"a":[{"plain":"SENTINEL"}]}]}"#,
            "credentials",
        ),
    ];
    for (sample, key) in containers {
        let out = redact_secrets(sample);
        assert!(!out.contains("SENTINEL"), "{sample} -> {out}");
        assert!(!out.contains("plain"), "{sample} -> {out}");
        let parsed: serde_json::Value =
            serde_json::from_str(&out).unwrap_or_else(|err| panic!("json {err}: {out}"));
        assert_eq!(parsed[key], "[REDACTED]", "{out}");
        assert_eq!(redact_secrets(&out), out, "{out}");

        let sanitized = af_release::lifecycle::sanitize_persisted_lifecycle_text(sample);
        assert!(
            !sanitized.contains("SENTINEL"),
            "sanitize leaked: {sanitized}"
        );
        let chained = redact_secrets(&sanitized);
        assert!(
            !chained.contains("SENTINEL"),
            "chain leaked: {sanitized} -> {chained}"
        );
        assert_eq!(redact_secrets(&chained), chained, "{chained}");
    }

    let header = r#"curl -H \"Cookie: sid=\"SENTINEL\"\" https://example.invalid"#;
    let header_out = redact_secrets(header);
    assert!(!header_out.contains("SENTINEL"), "{header_out}");
    assert!(
        header_out.contains("https://example.invalid"),
        "{header_out}"
    );
    assert!(header_out.contains("[REDACTED]"), "{header_out}");
    assert_eq!(redact_secrets(&header_out), header_out);
    let header_chain = redact_secrets(&af_release::lifecycle::sanitize_persisted_lifecycle_text(
        header,
    ));
    assert!(!header_chain.contains("SENTINEL"), "{header_chain}");
    assert!(
        header_chain.contains("https://example.invalid"),
        "{header_chain}"
    );

    let kept = r#"{"na\u006de":"visible"}"#;
    assert_eq!(redact_secrets(kept), kept);
    assert_eq!(
        af_release::lifecycle::sanitize_persisted_lifecycle_text(kept),
        kept
    );
}
