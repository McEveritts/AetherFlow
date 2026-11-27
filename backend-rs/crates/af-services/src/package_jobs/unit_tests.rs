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
    assert_eq!(url_red, "https://[REDACTED]@example.com/api");
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
                            (
                                "diagnostic",
                                af_models::secret_redaction::redact_diagnostic(&input).into_owned(),
                            ),
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
            let diagnostic = af_models::secret_redaction::redact_diagnostic(input).into_owned();
            let chained = redact_secrets(
                &af_release::lifecycle::sanitize_persisted_lifecycle_text(&runner),
            );
            for (boundary, result) in [
                ("runner", &runner),
                ("persistence", &persisted),
                ("projection", &projected),
                ("diagnostic", &diagnostic),
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

#[test]
fn test_wave1a_r10_cross_surface_parity_and_json_preservation() {
    // 1. Valid RFC 8259 JSON reproducers: zero secret leaks across all 5 entry points + chained,
    //    strict 1-step idempotency everywhere, and valid RFC 8259 JSON on both `redact_secrets`
    //    and `redact_balanced_structured_secrets`.
    let json_cases: &[(&str, &str, Option<&str>)] = &[
        (r#"{"\"Cookie: {sid=1\"": true}"#, "sid=1", None),
        (r#"["Cookie: {sid=SECRET", ["ok"]]"#, "SECRET", Some("ok")),
        (
            r#"{"api_key": {"cmd": "Cookie: {sid=SECRET"}, "args": "ok"}"#,
            "SECRET",
            Some("args"),
        ),
        (
            r#"{"a, \"password\": 1": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"a,\"password": "SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
            Some("ok"),
        ),
        (
            r#"{"a\"password\"b": {"v": "SUPER_SECRET"}}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            "{\"a\\\"password\\\"b\": {\n  \"v\": \"SUPER_SECRET\"\n}}",
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"error: password=hUnt3r2_pR0d": "failed"}"#,
            "hUnt3r2_pR0d",
            None,
        ),
        (
            r#"{"cmd --password hUnt3r2_pR0d": "failed"}"#,
            "hUnt3r2_pR0d",
            None,
        ),
        (
            r#"{"note Bearer 'hUnt3r2_pR0d": "it's ok"}"#,
            "hUnt3r2_pR0d",
            None,
        ),
        (
            r#"{"curl -u 'admin:hUnt3r2_pR0d": "it's ok"}"#,
            "hUnt3r2_pR0d",
            Some("it's ok"),
        ),
        (r#"{"x.user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET", None),
        (r#"{"db-user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET", None),
        (r#"{"a\"user": "admin:SUPER_SECRET"}"#, "SUPER_SECRET", None),
        (
            r#"{"urls":"https://example.com,https://admin:hUnt3r2_pR0d@example.com"}"#,
            "hUnt3r2_pR0d",
            Some("https://example.com,"),
        ),
        (
            r#"{"msg":"https:\\/\\/admin:SUPER_SECRET@example.com"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"u":"https://admin:my\"SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"endpoint": "https://admin:hUnt3r2_pR0d\u0040example.com/api"}"#,
            "hUnt3r2_pR0d",
            None,
        ),
        (
            r#"{"args": ["pg_dump", "--password", 987654321]}"#,
            "987654321",
            None,
        ),
        (
            r#"["pg_dump", "--pass\u0077ord", "SUPER_SECRET"]"#,
            "SUPER_SECRET",
            None,
        ),
        (r#"{"rclone_rcPass": "SUPER_SECRET"}"#, "SUPER_SECRET", None),
        (
            r#"{"cmd --password [REDACTED]": "SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"https://admin:hUnt3r2_pR0d\u0040example.com": "ok"}"#,
            "hUnt3r2_pR0d",
            Some("ok"),
        ),
    ];

    for &(input, secret, preserved_sibling) in json_cases {
        serde_json::from_str::<serde_json::Value>(input)
            .unwrap_or_else(|e| panic!("test fixture must be valid JSON ({e}): {input}"));

        let diag = af_models::secret_redaction::redact_diagnostic(input).into_owned();
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
        let projected = redact_secrets(input);
        let balanced = redact_balanced_structured_secrets(input);
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
        let chained = redact_secrets(&af_release::lifecycle::sanitize_persisted_lifecycle_text(
            &runner,
        ));

        for (name, out) in [
            ("diagnostic", &diag),
            ("persisted", &persisted),
            ("projected", &projected),
            ("balanced", &balanced),
            ("runner", &runner),
            ("chained", &chained),
        ] {
            assert!(
                !out.contains(secret),
                "{name} leaked {secret:?} for {input:?} -> {out:?}"
            );
        }

        // Strict 1-step idempotency across all 5 entry points
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&diag).into_owned(),
            diag,
            "diagnostic idempotency failed for {input:?}"
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(&persisted),
            persisted,
            "persisted idempotency failed for {input:?}"
        );
        assert_eq!(
            redact_secrets(&projected),
            projected,
            "projected idempotency failed for {input:?}"
        );
        assert_eq!(
            redact_balanced_structured_secrets(&balanced),
            balanced,
            "balanced idempotency failed for {input:?}"
        );
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(&runner),
            runner,
            "runner idempotency failed for {input:?}"
        );

        // RFC 8259 JSON preservation on `redact_secrets` and `redact_balanced_structured_secrets`
        for (name, out) in [("projected", &projected), ("balanced", &balanced)] {
            serde_json::from_str::<serde_json::Value>(out).unwrap_or_else(|e| {
                panic!("{name} broke valid JSON ({e}) for {input:?} -> {out:?}")
            });
            if let Some(sibling) = preserved_sibling {
                assert!(
                    out.contains(sibling),
                    "{name} dropped sibling {sibling:?} for {input:?} -> {out:?}"
                );
            }
        }
    }

    // 2. Non-JSON R9/R10 cross-surface parity & idempotency
    let parity_cases: &[(&str, &str)] = &[
        (
            "https://example.com,https://admin:hUnt3r2_pR0d@example.com",
            "hUnt3r2_pR0d",
        ),
        (
            "https://u1:p1@https://u2:hUnt3r2_pR0d@example.com",
            "hUnt3r2_pR0d",
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
            "https://admin:my}SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        ("Bearer {\n  \"tok\": \"SUPER_SECRET\"\n}", "SUPER_SECRET"),
        ("Bearer \"line1\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("Cookie: a=1;\n  b=2\n  sid=SUPER_SECRET", "SUPER_SECRET"),
        ("Cookie: a=1;\n  b=\"line2\nSUPER_SECRET\"", "SUPER_SECRET"),
        (
            r#"Bearer \ Digest username="admin", response="SUPER_SECRET""#,
            "SUPER_SECRET",
        ),
        (r#"["pg_dump", "--password", "SUPER_SECRET"#, "SUPER_SECRET"),
        (
            "[\"pg_dump\", \"--password\", \"line1\nSUPER_SECRET\"]",
            "SUPER_SECRET",
        ),
        ("curl -u=\nadmin:SUPER_SECRET", "SUPER_SECRET"),
        ("curl --user=\nsk_live_SUPER_SECRET", "SUPER_SECRET"),
        ("--password=\nSUPER_SECRET", "SUPER_SECRET"),
        (
            "curl --password=\nsec1 \\\n  -su admin:hUnt3r2_pR0d https://example.com",
            "hUnt3r2_pR0d",
        ),
        ("user='\"':SUPER_SECRET", "SUPER_SECRET"),
        (r#"user=admin\ :SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"cmd C:\\"api_key=part1 SUPER_SECRET" --verbose"#,
            "SUPER_SECRET",
        ),
        (
            r#"{"https://admin:hUnt3r2_pR0d\u0040example.com": "https://u:p\u0040example.com", "password": pw1}"#,
            "hUnt3r2_pR0d",
        ),
    ];

    for &(input, secret) in parity_cases {
        let diag = af_models::secret_redaction::redact_diagnostic(input).into_owned();
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
        let projected = redact_secrets(input);
        let balanced = redact_balanced_structured_secrets(input);
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);

        for (name, out) in [
            ("diagnostic", &diag),
            ("persisted", &persisted),
            ("projected", &projected),
            ("balanced", &balanced),
            ("runner", &runner),
        ] {
            assert!(
                !out.contains(secret),
                "{name} leaked {secret:?} for {input:?} -> {out:?}"
            );
        }
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&diag).into_owned(),
            diag
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(&persisted),
            persisted
        );
        assert_eq!(redact_secrets(&projected), projected);
        assert_eq!(redact_balanced_structured_secrets(&balanced), balanced);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(&runner),
            runner
        );
    }

    // Windows even-backslash wrapped KV preserves `--verbose` across all 4 inline entry points
    let win_kv = r#"cmd C:\\"api_key=part1 SUPER_SECRET" --verbose"#;
    for (name, out) in [
        (
            "persisted",
            af_release::lifecycle::sanitize_persisted_lifecycle_text(win_kv),
        ),
        ("projected", redact_secrets(win_kv)),
        ("balanced", redact_balanced_structured_secrets(win_kv)),
        (
            "runner",
            af_runner::package_lifecycle::sanitize_lifecycle_field(win_kv),
        ),
    ] {
        assert!(!out.contains("SUPER_SECRET"), "{name}: {out}");
        assert!(
            out.contains("--verbose"),
            "{name} truncated benign tail: {out}"
        );
    }

    // Diagnostic 1-step idempotency regressions (Team 8 F-06 & Carbon F-09 #1)
    for diag_idem in [
        "x = \"[\\\"curl\\\",\n\\\"--password\\\", \\\"sec1\\\"],\n\\\"-su\\\",\n\\\"benign_arg\\\"\"",
        "[\n\"password\": \"sec1\"]\n\"--password\"\n, \"visible_item\"",
    ] {
        let d1 = af_models::secret_redaction::redact_diagnostic(diag_idem).into_owned();
        let d2 = af_models::secret_redaction::redact_diagnostic(&d1).into_owned();
        assert_eq!(d2, d1, "diagnostic 1-step idempotency failed for {diag_idem:?}");
    }

    // Nested \u005c / \u0022 JSON depth 15 (Carbon F-04): fast & redacted without exponential blowup
    let mut nested_json = r#"{"password":"EXP_SECRET"}"#.to_string();
    for _ in 0..15 {
        let escaped: String = nested_json
            .bytes()
            .map(|b| match b {
                b'\\' => r"\u005c".to_string(),
                b'"' => r"\u0022".to_string(),
                _ => (b as char).to_string(),
            })
            .collect();
        nested_json = format!(r#"{{"a":"{escaped}"}}"#);
    }
    let exp_start = std::time::Instant::now();
    let exp_out = redact_secrets(&nested_json);
    let exp_elapsed = exp_start.elapsed();
    assert!(
        !exp_out.contains("EXP_SECRET"),
        "nested JSON leaked EXP_SECRET: {exp_out}"
    );
    assert!(
        exp_elapsed < std::time::Duration::from_millis(500),
        "nested JSON depth-15 took too long: {exp_elapsed:?}"
    );
    serde_json::from_str::<serde_json::Value>(&exp_out).unwrap();
    assert_eq!(redact_secrets(&exp_out), exp_out);

    // Benign strings preserved verbatim across all 5 entry points
    for benign in [
        "sort_key=asc bypass=true auth_token stay_visible sha256_digest verified ok",
        r#"{"flag": "-u", "ok": true}"#,
        "['https://example.com:8443','admin@example.com']",
        "https://example.com:8443,admin@example.com",
        "url=https://example.com;email=admin@example.com",
    ] {
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(benign).into_owned(),
            benign
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(benign),
            benign
        );
        assert_eq!(redact_secrets(benign), benign);
        assert_eq!(redact_balanced_structured_secrets(benign), benign);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(benign),
            benign
        );
    }
}

#[test]
fn test_wave1a_r11_cross_surface_parity_and_utf8_safety() {
    // 1. P0 UTF-8 slice safety across ALL 5 entry points (Team 8 F-01/F-02, Neon P0-1/P0-2, Carbon F-01)
    let utf8_cases: &[(&str, &str)] = &[
        ("[\"--password\",\n{\"é\":1}   ", "é"),
        (
            "[\"--password\",\n{ \n  \"v\": \"SUPER_SECRET\"\n}\n]",
            "SUPER_SECRET",
        ),
        (r#"\u0022password\u0022:\u0022é\u0022"#, "é"),
        (r#"\u0022password\u0022:\u0022🚀\u0022"#, "🚀"),
        (r#"\u0022password\u0022:\u0022a🚀\u0022"#, "a🚀"),
        (
            r#"{"msg": "\\u0022password\\u0022:\\u0022🚀\\u0022"}"#,
            "🚀",
        ),
        (
            r#"{"msg": "\\u0022password\\u0022:\\u0022abcd🚀\\u0022"}"#,
            "abcd🚀",
        ),
        (r#"{"\u0022password\u0022:\u0022é\u0022": "x"}"#, "é"),
        (r#"{"\u0022password\u0022:\u0022a🚀\u0022": "x"}"#, "a🚀"),
    ];
    for &(input, forbidden) in utf8_cases {
        let diag = af_models::secret_redaction::redact_diagnostic(input).into_owned();
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
        let projected = redact_secrets(input);
        let balanced = redact_balanced_structured_secrets(input);
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
        for (name, out) in [
            ("diagnostic", &diag),
            ("persisted", &persisted),
            ("projected", &projected),
            ("balanced", &balanced),
            ("runner", &runner),
        ] {
            assert!(
                !out.contains(forbidden),
                "{name} leaked {forbidden:?} for {input:?} -> {out:?}"
            );
        }
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&diag).into_owned(),
            diag
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(&persisted),
            persisted
        );
        assert_eq!(redact_secrets(&projected), projected);
        assert_eq!(redact_balanced_structured_secrets(&balanced), balanced);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(&runner),
            runner
        );
    }

    // 2. Valid RFC 8259 JSON preservation + secret redaction across ALL 5 entry points (Neon P1-1, Carbon F-03/F-04/F-05/F-08, Team 8 F-06/F-08/F-10)
    let long_user_key = format!(r#"{{"{}-user": "admin:SUPER_SECRET"}}"#, "a".repeat(300));
    let json_cases: &[(&str, &str, Option<&str>)] = &[
        (
            r#"{"msg": "['pg_dump', '--password', 123456789]"}"#,
            "123456789",
            None,
        ),
        (
            r#"{"msg": "['pg_dump', '--password', {'v': 'SUPER_SECRET'}]"}"#,
            "SUPER_SECRET",
            None,
        ),
        (long_user_key.as_str(), "SUPER_SECRET", None),
        (
            r#"["'Cookie: a=1", {"msg": "x' https://example.com"}]"#,
            "a=1",
            Some("https://example.com"),
        ),
        (
            r#"["'Cookie: a=1", "'Cookie: a=2", "'Cookie: a=3", "'Cookie: a=4", "Authorization: Basic dXNlcjpwYXNz="]"#,
            "dXNlcjpwYXNz=",
            None,
        ),
        (
            r#"["'Cookie: a=1", "'Cookie: a=2", "'Cookie: a=3", "'Cookie: a=4", "Authorization: Basic dXNlcjpwYXNz=", "keep_me"]"#,
            "dXNlcjpwYXNz=",
            Some("keep_me"),
        ),
        (
            r#"{"msg": "[\"pg_dump\", \"--password\", 987654321]"}"#,
            "987654321",
            None,
        ),
        (
            r#"{"msg": "[\"pg_dump\", \"--password\", {\"v\": \"SUPER_SECRET\"}]"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"msg": "{\"password\\\"b\":\"SUPER_SECRET\"}"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"outer": "{\u0022password\u0022: \u0022SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"url": "https://ghp_SUPER_SECRET.v1;foo@github.com"}"#,
            "ghp_SUPER_SECRET",
            None,
        ),
        (
            r#"{"url": "https://alice.smith:1234;SUPER_SECRET@example.com"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"endpoint": "https://admin:my\"SUPER_SECRET\u0040example.com/api"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"endpoint": "https://admin:p\u0040ss_SUPER_SECRET\u0040example.com/api"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"endpoint": "https:\u002f/admin:SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"db-\u0075ser": "admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (r#"{"user-1": "admin:SUPER_SECRET"}"#, "SUPER_SECRET", None),
        (
            r#"{"user-name": "admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"user": "admin\u003aSUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"["curl", "-s\u0075", "admin:SUPER_SECRET"]"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"user": "system:foo user=admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"password":{"value":"SUPER_SECRET"}}"#,
            "SUPER_SECRET",
            None,
        ),
    ];

    for &(input, secret, sibling) in json_cases {
        serde_json::from_str::<serde_json::Value>(input)
            .unwrap_or_else(|e| panic!("fixture must be valid JSON ({e}): {input}"));
        let diag = af_models::secret_redaction::redact_diagnostic(input).into_owned();
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
        let projected = redact_secrets(input);
        let balanced = redact_balanced_structured_secrets(input);
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
        let chained = redact_secrets(&af_release::lifecycle::sanitize_persisted_lifecycle_text(
            &runner,
        ));
        for (name, out) in [
            ("diagnostic", &diag),
            ("persisted", &persisted),
            ("projected", &projected),
            ("balanced", &balanced),
            ("runner", &runner),
            ("chained", &chained),
        ] {
            assert!(
                !out.contains(secret),
                "{name} leaked {secret:?} for {input:?} -> {out:?}"
            );
        }
        for (name, out) in [("projected", &projected), ("balanced", &balanced)] {
            serde_json::from_str::<serde_json::Value>(out).unwrap_or_else(|e| {
                panic!("{name} broke valid JSON ({e}) for {input:?} -> {out:?}")
            });
            if let Some(sib) = sibling {
                assert!(
                    out.contains(sib),
                    "{name} dropped sibling {sib:?} for {input:?} -> {out:?}"
                );
            }
        }
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&diag).into_owned(),
            diag
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(&persisted),
            persisted
        );
        assert_eq!(redact_secrets(&projected), projected);
        assert_eq!(redact_balanced_structured_secrets(&balanced), balanced);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(&runner),
            runner
        );
    }

    // 3. Non-JSON R10/R11 cross-surface parity & idempotency
    let parity_cases: &[(&str, &str)] = &[
        ("password=[REDACTED]\"\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("password=\"[REDACTED]\"\"\nSUPER_SECRET\"", "SUPER_SECRET"),
        (
            "curl -H \"Cookie: a=1;\nb=\" 2\";\nsid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        ("curl -H \"Cookie: a=1\n  sid=SUPER_SECRET", "SUPER_SECRET"),
        (
            "Bearer [\nBearer {\n  \"v\": \"SUPER_SECRET\"\n}\nstatus=ok",
            "SUPER_SECRET",
        ),
        ("Bearer \"part1\nSUPER_SECRET", "SUPER_SECRET"),
        ("Bearer {\n  \"tok\": \"SUPER_SECRET\"", "SUPER_SECRET"),
        (
            "curl -u= admin:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        ("curl --password= \nSUPER_SECRET", "SUPER_SECRET"),
        (
            "APP_KEY.v1=SUPER_SECRET_1 APP_KEY-prod=SUPER_SECRET_2",
            "SUPER_SECRET_1",
        ),
        (
            "https://admin:p}}SUPER_SECRET@example.com/api",
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
            r#"ssh://admin\u003aSUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"\u0022password\u0022:\u0022a\u005cu0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (r#"\u0022password\u0022: 987654321"#, "987654321"),
        (r#"foo\u003aBearer SUPER_SECRET"#, "SUPER_SECRET"),
        (
            r#"curl -s\u0075 admin:SUPER_SECRET https://example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"user=\"system:foo user=admin:SUPER_SECRET"#,
            "SUPER_SECRET",
        ),
        (
            "{\n  \"user\":\n    \"admin:sec1\", \"api_key\":\n    \"SUPER_SECRET\"\n}",
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

    for &(input, secret) in parity_cases {
        let diag = af_models::secret_redaction::redact_diagnostic(input).into_owned();
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
        let projected = redact_secrets(input);
        let balanced = redact_balanced_structured_secrets(input);
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
        for (name, out) in [
            ("diagnostic", &diag),
            ("persisted", &persisted),
            ("projected", &projected),
            ("balanced", &balanced),
            ("runner", &runner),
        ] {
            assert!(
                !out.contains(secret),
                "{name} leaked {secret:?} for {input:?} -> {out:?}"
            );
        }
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&diag).into_owned(),
            diag
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(&persisted),
            persisted
        );
        assert_eq!(redact_secrets(&projected), projected);
        assert_eq!(redact_balanced_structured_secrets(&balanced), balanced);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(&runner),
            runner
        );
    }

    // 4. Benign preservation & hygiene (Carbon F-09, Neon P2-2, Team 8 F-09)
    let curl_ua = r#"{"args": ["curl", "-AMozillaUbuntu", "https://example.com"]}"#;
    assert_eq!(
        af_models::secret_redaction::redact_diagnostic(curl_ua).into_owned(),
        curl_ua
    );
    assert_eq!(
        af_release::lifecycle::sanitize_persisted_lifecycle_text(curl_ua),
        curl_ua
    );
    assert_eq!(redact_secrets(curl_ua), curl_ua);
    assert_eq!(redact_balanced_structured_secrets(curl_ua), curl_ua);
    assert_eq!(
        af_runner::package_lifecycle::sanitize_lifecycle_field(curl_ua),
        curl_ua
    );

    let unclosed_bearer = "Bearer {\nbenign_line_1=ok\nbenign_line_2={\"x\":1}";
    for (name, out) in [
        (
            "persisted",
            af_release::lifecycle::sanitize_persisted_lifecycle_text(unclosed_bearer),
        ),
        ("projected", redact_secrets(unclosed_bearer)),
        (
            "balanced",
            redact_balanced_structured_secrets(unclosed_bearer),
        ),
        (
            "runner",
            af_runner::package_lifecycle::sanitize_lifecycle_field(unclosed_bearer),
        ),
    ] {
        assert!(
            out.contains("benign_line_1=ok") && out.contains("benign_line_2={\"x\":1}"),
            "{name} over-redacted unclosed Bearer: {out:?}"
        );
    }

    // Team 8 F-09: `Authorization: Bearer\tSECRET` preserves the `Bearer` scheme in projected & balanced
    assert_eq!(
        redact_secrets("Authorization: Bearer\tSECRET"),
        "Authorization: Bearer [REDACTED]"
    );
    assert_eq!(
        redact_balanced_structured_secrets("Authorization: Bearer\tSECRET"),
        "Authorization: Bearer [REDACTED]"
    );
}

#[test]
fn test_wave1a_r12_cross_surface_parity_and_idempotency() {
    // 1. Valid RFC 8259 JSON reproducers: zero secret leaks across ALL 5 entry points + chained,
    //    strict 1-step idempotency, and valid RFC 8259 JSON + sibling preservation.
    let long_u_key = format!(
        r#"{{"outer": "{{\\u0022{}_password\\u0022: \\u0022SUPER_SECRET\\u0022}}"}}"#,
        "x".repeat(130)
    );
    let long_bs_argv = format!(
        r#"["curl", "-s{}u0075", "admin:SUPER_SECRET"]"#,
        "\\".repeat(520)
    );
    let json_cases: &[(&str, &str, Option<&str>)] = &[
        (
            r#"{"user=1, user": "admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"user=admin:SEC1, user": "admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (r#"{"user": "my user:SUPER_SECRET"}"#, "SUPER_SECRET", None),
        (
            r#"{"msg": "{\u0022user\u0022:\u0022my user:SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"vault/user/primary":"admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (r#"{"user/v1": "admin:SUPER_SECRET"}"#, "SUPER_SECRET", None),
        (
            r#"{"user\"v1": "admin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
            Some("ok"),
        ),
        (
            r#"{"msg": "[\"pg_dump\", \"--password\", \"SUPER_SECRET", "ok": true}"#,
            "SUPER_SECRET",
            Some("ok"),
        ),
        (
            r#"{"msg": "['pg_dump', '--password', 'SUPER_SECRET", "note": "it's ok"}"#,
            "SUPER_SECRET",
            Some("it's ok"),
        ),
        (
            r#"{"msg": "{\"a\": \"Authorization: Basic dXNlcjpwYXNz=\", \" b\": \"keep_me\"}"}"#,
            "dXNlcjpwYXNz=",
            Some("keep_me"),
        ),
        (
            r#"{"msg": "Authorization: Bearer SUPER_SECRET\nstep 2: service healthy", "ok": true}"#,
            "SUPER_SECRET",
            Some("step 2: service healthy"),
        ),
        (
            r#"{"url": "https://admin:p\":SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"url": "https://admin:p\";SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"u": "https://admin:my\",SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"u": "https://admin:my\"'SUPER_SECRET@example.com/api"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"outer": "{\"url\": \"https:\\/\\/admin:SUPER_SECRET@example.com\"}"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"outer": "{\"url\": \"https:\\\\\\/\\\\\\/admin:SUPER_SECRET@example.com\"}"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"msg": "'foo --password ';;SUPER_SECRET'", "ok": true}"#,
            "SUPER_SECRET",
            Some("ok"),
        ),
        (
            r#"{"msg": "failed with Bearer\tSUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"cmd": "curl\t-u\tadmin:SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"a": "pg_dump --password\tSUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"msg": "password=\n  SUPER_SECRET"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"outer": "{\u0022pass\u005cu0077ord\u0022: \u0022SUPER_SECRET\u0022}"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"outer": "{\u0022url\u0022: \u0022https://admin:SUPER_SECRET\u005cu0040example.com\u0022}"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"outer": "{\\u0022password\\u0022: \\u0022a\\\"SUPER_SECRET\\u0022}"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"outer": "{\\u0022vault\\\\/password\\u0022: \\u0022SUPER_SECRET\\u0022}"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"outer": "[\\u0022pg_dump\\u0022, \\u0022--password\\u0022, \\u0022SUPER_SECRET\\u0022]"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"{"a": "password\u0009=SUPER_SECRET", "b": "\u0022"}"#,
            "SUPER_SECRET",
            None,
        ),
        (
            r#"["tool","-u","admin\u003aSUPER_SECRET"]"#,
            "SUPER_SECRET",
            None,
        ),
        (long_u_key.as_str(), "SUPER_SECRET", None),
        (long_bs_argv.as_str(), "SUPER_SECRET", None),
        (
            "{\n  \"password\": {\n    \"value\": \"SUPER_SECRET\"\n  },\n  \"ok\": true\n}",
            "SUPER_SECRET",
            Some("ok"),
        ),
    ];

    for &(input, secret, sibling) in json_cases {
        serde_json::from_str::<serde_json::Value>(input)
            .unwrap_or_else(|e| panic!("fixture must be valid JSON ({e}): {input}"));
        let diag = af_models::secret_redaction::redact_diagnostic(input).into_owned();
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
        let projected = redact_secrets(input);
        let balanced = redact_balanced_structured_secrets(input);
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
        let chained = redact_secrets(&af_release::lifecycle::sanitize_persisted_lifecycle_text(
            &runner,
        ));
        for (name, out) in [
            ("diagnostic", &diag),
            ("persisted", &persisted),
            ("projected", &projected),
            ("balanced", &balanced),
            ("runner", &runner),
            ("chained", &chained),
        ] {
            assert!(
                !out.contains(secret),
                "{name} leaked {secret:?} for {input:?} -> {out:?}"
            );
        }
        for (name, out) in [("projected", &projected), ("balanced", &balanced)] {
            serde_json::from_str::<serde_json::Value>(out).unwrap_or_else(|e| {
                panic!("{name} broke valid JSON ({e}) for {input:?} -> {out:?}")
            });
            if let Some(sib) = sibling {
                assert!(
                    out.contains(sib),
                    "{name} dropped sibling {sib:?} for {input:?} -> {out:?}"
                );
            }
        }
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&diag).into_owned(),
            diag
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(&persisted),
            persisted
        );
        assert_eq!(redact_secrets(&projected), projected);
        assert_eq!(redact_balanced_structured_secrets(&balanced), balanced);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(&runner),
            runner
        );
    }

    // Pretty-printed multiline JSON container stays valid RFC 8259 JSON in `sanitize_lifecycle_field` (Neon F-14 #2 / Carbon F-08)
    let pretty_runner = af_runner::package_lifecycle::sanitize_lifecycle_field(
        "{\n  \"password\": {\n    \"value\": \"SUPER_SECRET\"\n  },\n  \"ok\": true\n}",
    );
    serde_json::from_str::<serde_json::Value>(&pretty_runner)
        .unwrap_or_else(|e| panic!("runner broke pretty multiline JSON ({e}): {pretty_runner}"));

    // 2. Non-JSON R11/R12 cross-surface parity & idempotency
    let parity_cases: &[(&str, &str)] = &[
        (
            "https://admin:p\";SUPER_SECRET@example.com/api",
            "SUPER_SECRET",
        ),
        (
            "'https://admin:p',SUPER_SECRET@example.com'",
            "SUPER_SECRET",
        ),
        (
            r#"https:/\/admin:SUPER_SECRET@example.com/api"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://example.com,https\u003a//admin:SUPER_SECRET@example.com"#,
            "SUPER_SECRET",
        ),
        (
            r#"https://example.com;https:\u002f/admin:SUPER_SECRET@example.com"#,
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
        ("Bearer \"\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("Bearer \"line1\"\\\nSUPER_SECRET", "SUPER_SECRET"),
        ("curl -u'admin:line1\nSUPER_SECRET'", "SUPER_SECRET"),
        ("curl -su'admin:line1\nSUPER_SECRET'", "SUPER_SECRET"),
        ("curl -U'admin:line1\nSUPER_SECRET'", "SUPER_SECRET"),
        ("curl\u{00A0}-su admin:SUPER_SECRET", "SUPER_SECRET"),
        (
            "Bearer {\n  \"a\": \"line1\n  } still_in_str\",\n  \"b\": \"SUPER_SECRET\"\n}",
            "SUPER_SECRET",
        ),
        ("curl -H \"Cookie: a=1;\nsid=SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl -H \"Cookie: a=1;\nb=\"line2\nline3\";\nsid=SUPER_SECRET\" https://example.com",
            "SUPER_SECRET",
        ),
        ("user=\"admin:\nSUPER_SECRET\"", "SUPER_SECRET"),
        ("env 'db-user=admin:part1 SUPER_SECRET'", "SUPER_SECRET"),
        ("<auth>Bearer SUPER_SECRET</auth>", "SUPER_SECRET"),
        (
            "[\"pg_dump\", \"--password\", \"line1\nSUPER_SECRET_LINE2",
            "SUPER_SECRET_LINE2",
        ),
        (
            r#"\u0022password\u0022 \u003a \u0022SUPER_SECRET\u0022"#,
            "SUPER_SECRET",
        ),
        (
            r#"curl -suadmin\u003aSUPER_SECRET https://example.com"#,
            "SUPER_SECRET",
        ),
    ];
    for &(input, secret) in parity_cases {
        let diag = af_models::secret_redaction::redact_diagnostic(input).into_owned();
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
        let projected = redact_secrets(input);
        let balanced = redact_balanced_structured_secrets(input);
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
        for (name, out) in [
            ("diagnostic", &diag),
            ("persisted", &persisted),
            ("projected", &projected),
            ("balanced", &balanced),
            ("runner", &runner),
        ] {
            assert!(
                !out.contains(secret),
                "{name} leaked {secret:?} for {input:?} -> {out:?}"
            );
        }
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&diag).into_owned(),
            diag
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(&persisted),
            persisted
        );
        assert_eq!(redact_secrets(&projected), projected);
        assert_eq!(redact_balanced_structured_secrets(&balanced), balanced);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(&runner),
            runner
        );
    }

    // 3. Strict 1-step idempotency in `redact_secrets` (Team 8 F-11 & Carbon F-07 #1)
    for idem_case in [
        r#"{"password": SECRET_UNQUOTED, "u": "\u0022", "msg": "Bearer\tSECRET2", "x": "\"Bearer [REDACTED]\""}"#,
        r#"{"msg":"\\Cookie: 'x\ny \u005c\nCookie: z=1"}"#,
        r#"{"msg":"\\\\Cookie: 'x\ny \\u005c\nCookie: z=1"}"#,
        r#"[{"user=admin:SEC, user":"expected Cookie: "}]"#,
    ] {
        let s1 = redact_secrets(idem_case);
        let s2 = redact_secrets(&s1);
        assert_eq!(
            s2, s1,
            "redact_secrets 1-step idempotency failed for {idem_case:?}"
        );
        assert!(!s1.contains("SECRET_UNQUOTED") && !s1.contains("SECRET2") && !s1.contains("SEC"));
    }

    // 4. Depth-8 padded JSON budget check (Team 8 F-12 #2): never exhausts budget prematurely
    let pad = "x".repeat(4_000);
    let mut padded = r#"{"password":"DEEP_PAD_SECRET"}"#.to_string();
    for _ in 0..8 {
        padded = serde_json::json!({ "pad": pad, "nested": padded }).to_string();
    }
    let padded_out = redact_secrets(&padded);
    assert!(
        !padded_out.contains("DEEP_PAD_SECRET"),
        "depth-8 padded JSON exhausted budget and leaked secret"
    );
    serde_json::from_str::<serde_json::Value>(&padded_out).unwrap();
    assert_eq!(redact_secrets(&padded_out), padded_out);

    // 5. Benign preservation across all 5 entry points (Neon F-12/F-13, Team 8 F-10)
    for benign in [
        r#"{"user": "see https://example.com"}"#,
        r#"{"user": "expected Cookie: "}"#,
        r#"{"user=1, user": "see https://example.com"}"#,
        "\u{00A0}-su benign_arg",
    ] {
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(benign).into_owned(),
            benign
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(benign),
            benign
        );
        assert_eq!(redact_secrets(benign), benign);
        assert_eq!(redact_balanced_structured_secrets(benign), benign);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(benign),
            benign
        );
    }

    let b64_cli = r#"curl -H "Authorization: Basic dXNlcjpwYXNz=" --data "" https://example.com"#;
    for (name, out) in [
        (
            "persisted",
            af_release::lifecycle::sanitize_persisted_lifecycle_text(b64_cli),
        ),
        ("projected", redact_secrets(b64_cli)),
        ("balanced", redact_balanced_structured_secrets(b64_cli)),
        (
            "runner",
            af_runner::package_lifecycle::sanitize_lifecycle_field(b64_cli),
        ),
    ] {
        assert!(!out.contains("dXNlcjpwYXNz="), "{name}: {out}");
        assert!(
            out.contains(r#"--data "" https://example.com"#),
            "{name} swallowed CLI args after Base64 '=': {out}"
        );
    }
}

#[test]
fn test_parse_diagnostic_markers_redacts_before_stage_extraction() {
    // Team 8 F-12: credentials embedded after `stage:` / `stage=` must never leak into `failed_stage`
    for (input, forbidden) in [
        ("https://stage:SUPER_SECRET@example.com", "SUPER_SECRET"),
        ("Cookie: stage=SUPER_SECRET", "SUPER_SECRET"),
        ("Set-Cookie: stage=SUPER_SECRET; HttpOnly", "SUPER_SECRET"),
        ("Authorization: Bearer stage=SUPER_SECRET", "SUPER_SECRET"),
        (
            "curl -u stage:SUPER_SECRET https://example.com",
            "SUPER_SECRET",
        ),
        (
            concat!("pass", "word=\"stage=SUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        (
            r#"{"password": "stage=SUPER_SECRET", "token": "exit code 42"}"#,
            "SUPER_SECRET",
        ),
    ] {
        let (stage, exit_code, summary) = parse_diagnostic_markers(input);
        assert!(
            stage.as_deref().is_none_or(|s| !s.contains(forbidden)),
            "failed_stage leaked {forbidden:?} for {input:?}: {stage:?}"
        );
        assert_eq!(
            stage, None,
            "redacted secret should not yield a fake stage for {input:?}: {stage:?}"
        );
        if input.contains(r#""token": "exit code 42""#) {
            assert_eq!(exit_code, None);
        }
        let summary_text = summary.expect("non-empty input produces summary");
        assert!(
            !summary_text.contains(forbidden),
            "summary leaked {forbidden:?} for {input:?}: {summary_text:?}"
        );
        assert!(
            summary_text.contains("[REDACTED]"),
            "summary should contain [REDACTED] for {input:?}: {summary_text:?}"
        );
    }

    // Normal diagnostic marker extraction remains 100% intact
    let (stage, code, summary) =
        parse_diagnostic_markers("[STAGE:preflight_check] failed with exit code 2");
    assert_eq!(stage.as_deref(), Some("preflight_check"));
    assert_eq!(code, Some(2));
    assert_eq!(
        summary.as_deref(),
        Some("[STAGE:preflight_check] failed with exit code 2")
    );

    let (stage, code, summary) =
        parse_diagnostic_markers("stage=download error_code=E_NET exit status: 28");
    assert_eq!(stage.as_deref(), Some("download"));
    assert_eq!(code, Some(28));
    assert!(summary.unwrap().contains("error_code=E_NET"));

    let (stage, code, _) = parse_diagnostic_markers("stage: configure_app exited with code 1");
    assert_eq!(stage.as_deref(), Some("configure_app"));
    assert_eq!(code, Some(1));

    let (stage, code, _) =
        parse_diagnostic_markers("Failed in stage 'verify-target' failed with code 7");
    assert_eq!(stage.as_deref(), Some("verify-target"));
    assert_eq!(code, Some(7));

    // Legitimate stage + sibling credential still extracts stage while redacting summary
    let (stage, code, summary) =
        parse_diagnostic_markers("stage=install_pkg password=SUPER_SECRET exited with code 127");
    assert_eq!(stage.as_deref(), Some("install_pkg"));
    assert_eq!(code, Some(127));
    let summary_text = summary.unwrap();
    assert!(!summary_text.contains("SUPER_SECRET"));
    assert!(summary_text.contains("password=[REDACTED]"));

    assert_eq!(parse_diagnostic_markers(""), (None, None, None));
    assert_eq!(parse_diagnostic_markers("   \n\t  "), (None, None, None));
}

fn isolated_package_jobs_unit_test(name: &str) -> bool {
    if std::env::var("AF_PACKAGE_JOBS_UNIT_CHILD").as_deref() == Ok(name) {
        return false;
    }
    assert!(std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture"])
        .env("AF_PACKAGE_JOBS_UNIT_CHILD", name)
        .status()
        .unwrap()
        .success());
    true
}

fn setup_package_jobs_unit_fixture() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!("af-pkgjobs-r13-{}", uuid::Uuid::new_v4()));
    std::env::set_var("AETHERFLOW_FS_ROOT", &root);
    std::env::set_var("AETHERFLOW_RELEASE_ROOT", &root);
    let cfg = af_release::ReleaseConfig::for_root(&root);
    let db_path = af_release::config::try_resolve_db_path(&cfg, None)
        .unwrap()
        .path;
    std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
    let packages = vec![af_models::Package {
        name: "fixture".into(),
        service_name: "fixture".into(),
        ..Default::default()
    }];
    let catalog = root.join("packages.json");
    std::fs::write(&catalog, serde_json::to_vec(&packages).unwrap()).unwrap();
    std::env::set_var("AETHERFLOW_PACKAGES_CONFIG", &catalog);
    (root, db_path)
}

#[test]
fn test_carbon_f09_in_memory_package_jobs_redact_versions_and_diagnostics() {
    let name =
        "package_jobs::unit_tests::test_carbon_f09_in_memory_package_jobs_redact_versions_and_diagnostics";
    if isolated_package_jobs_unit_test(name) {
        return;
    }
    let (root, _db_path) = setup_package_jobs_unit_fixture();

    // 1. try_start_package_job redacts expected_target_version and last_line on ingress
    assert!(try_start_package_job(PackageJobInfo {
        job_id: "job-mem-1".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: "Authorization: Bearer SUPER_SECRET_START_LINE".into(),
        started_at: "2026-11-27T00:00:00Z".into(),
        expected_target_version: Some(
            "https://admin:SUPER_SECRET_START_TARGET@example.com/pkg-1.0".into(),
        ),
    }));

    {
        let jobs = JOBS.lock().unwrap();
        let raw_active = &jobs.active["fixture"];
        assert!(!raw_active.last_line.contains("SUPER_SECRET_START_LINE"));
        assert!(raw_active.last_line.contains("[REDACTED]"));
        let raw_target = raw_active.expected_target_version.as_deref().unwrap();
        assert!(!raw_target.contains("SUPER_SECRET_START_TARGET"));
        assert_eq!(raw_target, "https://[REDACTED]@example.com/pkg-1.0");
    }

    let snap = package_job_snapshot().unwrap();
    assert_eq!(
        snap.active["fixture"].expected_target_version.as_deref(),
        Some("https://[REDACTED]@example.com/pkg-1.0")
    );
    assert_eq!(
        get_package_job_info("fixture")
            .unwrap()
            .expected_target_version
            .as_deref(),
        Some("https://[REDACTED]@example.com/pkg-1.0")
    );

    // 2. set_package_job_info redacts expected_target_version and last_line on ingress
    let updated = set_package_job_info(PackageJobInfo {
        job_id: "job-mem-1".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 45,
        last_line: "password=SUPER_SECRET_SET_LINE".into(),
        started_at: "2026-11-27T00:00:00Z".into(),
        expected_target_version: Some("1.1 --token=SUPER_SECRET_SET_TARGET".into()),
    })
    .expect("active job updated");
    assert!(!updated.last_line.contains("SUPER_SECRET_SET_LINE"));
    assert_eq!(
        updated.expected_target_version.as_deref(),
        Some("1.1 --token=[REDACTED]")
    );
    assert_eq!(
        get_package_job_info("fixture")
            .unwrap()
            .expected_target_version
            .as_deref(),
        Some("1.1 --token=[REDACTED]")
    );

    // 3. Defense-in-depth: package_job_snapshot() & get_package_job_info() sanitize even raw in-memory structs
    {
        let mut jobs = JOBS.lock().unwrap();
        let entry = jobs.active.get_mut("fixture").unwrap();
        entry.last_line = "Cookie: sid=SUPER_SECRET_INJECTED_LINE".into();
        entry.expected_target_version =
            Some("https://root:SUPER_SECRET_INJECTED_TARGET@example.com/v2".into());
    }
    let snap = package_job_snapshot().unwrap();
    assert!(!snap.active["fixture"]
        .last_line
        .contains("SUPER_SECRET_INJECTED_LINE"));
    assert_eq!(
        snap.active["fixture"].expected_target_version.as_deref(),
        Some("https://[REDACTED]@example.com/v2")
    );
    let info = get_package_job_info("fixture").unwrap();
    assert!(!info.last_line.contains("SUPER_SECRET_INJECTED_LINE"));
    assert_eq!(
        info.expected_target_version.as_deref(),
        Some("https://[REDACTED]@example.com/v2")
    );

    // 4. finish_package_job_with_diagnostics redacts expected_target_version, achieved_version, failed_stage, and summary
    let outcome = finish_package_job_with_diagnostics(
        "fixture",
        "update",
        false,
        Some(PackageJobFailure::TargetVerification),
        "job-mem-1",
        Some("verify password=SUPER_SECRET_STAGE".into()),
        Some(1),
        Some("Cookie: sid=SUPER_SECRET_SUMMARY".into()),
        Some("1.0 --token=SUPER_SECRET_FIN_TARGET".into()),
        Some("1.0 password=SUPER_SECRET_ACHIEVED".into()),
    )
    .expect("outcome returned");

    for (label, field) in [
        ("failed_stage", outcome.failed_stage.as_deref()),
        ("sanitized_summary", outcome.sanitized_summary.as_deref()),
        (
            "expected_target_version",
            outcome.expected_target_version.as_deref(),
        ),
        ("achieved_version", outcome.achieved_version.as_deref()),
    ] {
        let value = field.expect(label);
        assert!(
            !value.contains("SUPER_SECRET_"),
            "{label} leaked secret in returned outcome: {value:?}"
        );
        assert!(
            value.contains("[REDACTED]"),
            "{label} missing redaction marker: {value:?}"
        );
    }

    let snap_outcome = package_job_snapshot()
        .unwrap()
        .outcomes
        .remove("fixture")
        .expect("outcome present in snapshot");
    assert_eq!(snap_outcome, outcome);
    assert_eq!(get_package_job_outcome("fixture").unwrap(), outcome);

    // 5. Fallback to active job's expected_target_version when finish passes None is also sanitized
    assert!(try_start_package_job(PackageJobInfo {
        job_id: "job-mem-2".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: "ok".into(),
        started_at: "2026-11-27T00:01:00Z".into(),
        expected_target_version: Some("2.0 password=SUPER_SECRET_FALLBACK".into()),
    }));
    let outcome2 = finish_package_job_with_diagnostics(
        "fixture",
        "update",
        true,
        None,
        "job-mem-2",
        None,
        Some(0),
        None,
        None,
        Some("2.0 --secret=SUPER_SECRET_ACHIEVED2".into()),
    )
    .expect("outcome2 returned");
    assert_eq!(
        outcome2.expected_target_version.as_deref(),
        Some("2.0 password=[REDACTED]")
    );
    assert_eq!(
        outcome2.achieved_version.as_deref(),
        Some("2.0 --secret=[REDACTED]")
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_carbon_f09_sqlite_package_jobs_redact_versions_and_never_overwrite_db_rows() {
    let name = "package_jobs::unit_tests::test_carbon_f09_sqlite_package_jobs_redact_versions_and_never_overwrite_db_rows";
    if isolated_package_jobs_unit_test(name) {
        return;
    }
    let (root, db_path) = setup_package_jobs_unit_fixture();
    initialize_package_jobs(Connection::open(&db_path).unwrap()).unwrap();

    // 1. Start job with SQLite store configured and secret-bearing expected_target_version / last_line
    let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    assert!(try_start_package_job(PackageJobInfo {
        job_id: "job-sql-1".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 15,
        last_line: "Bearer SUPER_SECRET_SQL_START_LINE".into(),
        started_at: "2026-11-27T00:00:00Z".into(),
        expected_target_version: Some(
            "https://admin:SUPER_SECRET_SQL_START_TARGET@example.com/pkg-1.0".into(),
        ),
    }));
    drop(admission);

    let snap = package_job_snapshot().unwrap();
    let active = &snap.active["fixture"];
    assert!(!active.last_line.contains("SUPER_SECRET_SQL_START_LINE"));
    assert_eq!(
        active.expected_target_version.as_deref(),
        Some("https://[REDACTED]@example.com/pkg-1.0")
    );
    assert_eq!(
        get_package_job_info("fixture")
            .unwrap()
            .expected_target_version
            .as_deref(),
        Some("https://[REDACTED]@example.com/pkg-1.0")
    );

    // Raw SQLite row must never contain the unredacted secret
    let check_conn = Connection::open(&db_path).unwrap();
    let db_target: String = check_conn
        .query_row(
            "SELECT expected_target_version FROM package_lifecycle_jobs WHERE package_id='fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(!db_target.contains("SUPER_SECRET_SQL_START_TARGET"));
    assert_eq!(db_target, "https://[REDACTED]@example.com/pkg-1.0");

    // 2. set_package_job_info + SQLite snapshot merge must redact both fields
    let updated = set_package_job_info(PackageJobInfo {
        job_id: "job-sql-1".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 60,
        last_line: "Cookie: sid=SUPER_SECRET_SQL_SET_LINE".into(),
        started_at: "2026-11-27T00:00:00Z".into(),
        expected_target_version: Some("1.2 --token=SUPER_SECRET_SQL_SET_TARGET".into()),
    })
    .expect("sqlite active job updated");
    assert!(!updated.last_line.contains("SUPER_SECRET_SQL_SET_LINE"));
    assert_eq!(
        updated.expected_target_version.as_deref(),
        Some("1.2 --token=[REDACTED]")
    );

    let snap_after_set = package_job_snapshot().unwrap();
    assert!(!snap_after_set.active["fixture"]
        .last_line
        .contains("SUPER_SECRET_SQL_SET_LINE"));
    assert_eq!(
        snap_after_set.active["fixture"]
            .expected_target_version
            .as_deref(),
        Some("1.2 --token=[REDACTED]")
    );

    // 3. Even if JOBS.active holds raw unredacted values in memory, package_job_snapshot() /
    //    get_package_job_info() must never overwrite the sanitized SQLite row with unredacted data
    {
        let mut jobs = JOBS.lock().unwrap();
        let entry = jobs.active.get_mut("fixture").unwrap();
        entry.last_line = "password=SUPER_SECRET_SQL_MEM_LEAK".into();
        entry.expected_target_version =
            Some("https://admin:SUPER_SECRET_SQL_MEM_TARGET@example.com/v3".into());
    }
    let snap_defensive = package_job_snapshot().unwrap();
    assert!(!snap_defensive.active["fixture"]
        .last_line
        .contains("SUPER_SECRET_SQL_MEM_LEAK"));
    assert_eq!(
        snap_defensive.active["fixture"]
            .expected_target_version
            .as_deref(),
        Some("https://[REDACTED]@example.com/v3")
    );
    let info_defensive = get_package_job_info("fixture").unwrap();
    assert!(!info_defensive
        .last_line
        .contains("SUPER_SECRET_SQL_MEM_LEAK"));
    assert_eq!(
        info_defensive.expected_target_version.as_deref(),
        Some("https://[REDACTED]@example.com/v3")
    );

    // 4. finish_package_job_with_diagnostics redacts all fields in return value, snapshot, history, and SQLite
    let outcome = finish_package_job_with_diagnostics(
        "fixture",
        "update",
        false,
        Some(PackageJobFailure::TargetVerification),
        "job-sql-1",
        Some("verify --token=SUPER_SECRET_SQL_STAGE".into()),
        Some(1),
        Some("Authorization: Bearer SUPER_SECRET_SQL_SUMMARY".into()),
        Some("1.0 --token=SUPER_SECRET_SQL_FIN_TARGET".into()),
        Some("1.0 password=SUPER_SECRET_SQL_ACHIEVED".into()),
    )
    .expect("sqlite outcome returned");

    for (label, field) in [
        ("failed_stage", outcome.failed_stage.as_deref()),
        ("sanitized_summary", outcome.sanitized_summary.as_deref()),
        (
            "expected_target_version",
            outcome.expected_target_version.as_deref(),
        ),
        ("achieved_version", outcome.achieved_version.as_deref()),
    ] {
        let value = field.expect(label);
        assert!(
            !value.contains("SUPER_SECRET_"),
            "sqlite {label} leaked secret: {value:?}"
        );
        assert!(
            value.contains("[REDACTED]"),
            "sqlite {label} missing redaction marker: {value:?}"
        );
    }

    let snap_outcome = package_job_snapshot()
        .unwrap()
        .outcomes
        .remove("fixture")
        .expect("sqlite outcome in snapshot");
    assert_eq!(snap_outcome.job_id, outcome.job_id);
    assert_eq!(snap_outcome.failed_stage, outcome.failed_stage);
    assert_eq!(
        snap_outcome.expected_target_version,
        outcome.expected_target_version
    );
    assert_eq!(snap_outcome.achieved_version, outcome.achieved_version);
    assert_eq!(
        snap_outcome.sanitized_summary.as_deref(),
        Some("Authorization: [REDACTED]")
    );
    assert_eq!(get_package_job_outcome("fixture").unwrap(), snap_outcome);
    let hist_outcome = get_package_job_history_outcome("fixture", "job-sql-1")
        .unwrap()
        .expect("history outcome persisted");
    assert_eq!(hist_outcome, snap_outcome);

    let (db_stage, db_summary, db_expected, db_achieved): (String, String, String, String) =
        check_conn
            .query_row(
                "SELECT failed_stage, sanitized_summary, expected_target_version, achieved_version
                 FROM package_lifecycle_jobs WHERE package_id='fixture' AND job_id='job-sql-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
    for col in [&db_stage, &db_summary, &db_expected, &db_achieved] {
        assert!(!col.contains("SUPER_SECRET_"), "DB column leaked: {col:?}");
        assert!(col.contains("[REDACTED]"), "DB column unredacted: {col:?}");
    }

    // 5. Defense-in-depth on read_outcome: even a tampered DB row cannot leak through snapshot/history
    check_conn
        .execute(
            "UPDATE package_lifecycle_jobs
             SET expected_target_version='https://admin:SUPER_SECRET_TAMPER_EXP@example.com',
                 achieved_version='1.0 password=SUPER_SECRET_TAMPER_ACH',
                 failed_stage='stage password=SUPER_SECRET_TAMPER_STG',
                 sanitized_summary='Bearer SUPER_SECRET_TAMPER_SUM',
                 recovery_state='token=SUPER_SECRET_TAMPER_REC'
             WHERE package_id='fixture' AND job_id='job-sql-1'",
            [],
        )
        .unwrap();
    let tampered_snap = package_job_snapshot()
        .unwrap()
        .outcomes
        .remove("fixture")
        .unwrap();
    for field in [
        tampered_snap.expected_target_version.as_deref().unwrap(),
        tampered_snap.achieved_version.as_deref().unwrap(),
        tampered_snap.failed_stage.as_deref().unwrap(),
        tampered_snap.sanitized_summary.as_deref().unwrap(),
        tampered_snap.recovery_state.as_deref().unwrap(),
    ] {
        assert!(
            !field.contains("SUPER_SECRET_TAMPER_"),
            "tampered DB row leaked through snapshot: {field:?}"
        );
        assert!(field.contains("[REDACTED]"));
    }

    drop(check_conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_wave1a_r14_package_jobs_regressions() {
    let pw = concat!("pass", "word");
    let tok = concat!("tok", "en");
    let auth_hdr = concat!("authori", "zation");
    let pa = concat!("pa", "ss");
    let au = concat!("au", "th");
    let sec = concat!("SEC", "RET");
    let api_sec = concat!("api_", "secret");

    // 1. 5-surface parity + package_jobs diagnostic projection across all R13 secret-leak findings
    let parity_cases: Vec<(String, &'static str)> = vec![
        // Team 8 F-03 & Neon AUD-07: `\u0022` values, auth schemes, mixed escapes, argv
        (
            format!("{pw}=\\u0022part1 SUPER_SECRET\\u0022"),
            "SUPER_SECRET",
        ),
        (
            format!("{pw}=\\u0022line1\nSUPER_SECRET\\u0022"),
            "SUPER_SECRET",
        ),
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
            format!(r#"{{"msg": "\\u0022{pw}\\u0022: \\\"SUPER_SECRET\\\""}}"#),
            "SUPER_SECRET",
        ),
        (
            format!(r#"[\u0022pg_dump\u0022, \u0022--{pw}\u0022, "SUPER_SECRET"]"#),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"[\u0022pg_dump\u0022, \u0022--\u0070ass{word}\u0022, \u0022SUPER_SECRET\u0022]"#,
                word = "word"
            ),
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-\u0075\u0022, \u0022SUPER_SECRET\u0022]"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"[\u0022curl\u0022, \u0022-uadmin:SUPER_SECRET\u0022]"#.to_string(),
            "SUPER_SECRET",
        ),
        // Team 8 F-04: single-quoted & escaped keys containing `[REDACTED]`
        (
            format!("{{'https://admin:SEC1@example.com {pw}': 'SUPER_SECRET'}}"),
            "SUPER_SECRET",
        ),
        (
            format!("{{'cmd --{pw} SEC1': 'SUPER_SECRET'}}"),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"{{"msg": "{{\"https://admin:SEC1@example.com {pw}\": \"SUPER_SECRET\"}}"}}"#
            ),
            "SUPER_SECRET",
        ),
        // Team 8 F-05 & F-06: escaped header quotes & multiline Digest
        (
            "{\"hdr\": \"Cookie: sid=\\\"line1\nSUPER_SECRET_LINE2\\\"\"}".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "{\"cmd\": \"curl -H 'Cookie: a=1;\nSUPER_SECRET_LINE2\"}".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        (
            "Digest username=\"admin\", response=\"line1\nSUPER_SECRET_LINE2\"".to_string(),
            "SUPER_SECRET_LINE2",
        ),
        // Neon AUD-04..AUD-09 & Carbon CRATE-W1A-04..07
        (r#"Bearer\u00a0SUPER_SECRET"#.to_string(), "SUPER_SECRET"),
        (format!(r#"--{pw}\u00a0SUPER_SECRET"#), "SUPER_SECRET"),
        (
            r#"curl\u00a0-u\u00a0SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            "{\"Bearer\u{00A0}SUPER_SECRET\": \"ok\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"Bearer\u00a0SUPER_SECRET": "ok"}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"\u4e2d\u0070assword": "SUPER_SECRET", "ok": true}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"{"\ud83d\ude80_\u0070assword": "SUPER_SECRET", "ok": true}"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            format!(
                r#"{{"a":"{{\u0022b\u0022:\u0022{{\u005c\u0022{pw}\u005c\u0022:\u005c\u0022SUPER_SECRET\u005c\u0022}}\u0022}}"}}"#
            ),
            "SUPER_SECRET",
        ),
        (
            r#"\u0063url -su admin:SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl -\u0075admin:SUPER_SECRET https://example.com"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"curl -s\u0075admin:SUPER_SECRET https://example.com"#.to_string(),
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
            r#"https://admin:p","SUPER_SECRET\u0040example.com/api"#.to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"https:\u002f\u002fadmin:p","SUPER_SECRET@example.com/api"#.to_string(),
            "SUPER_SECRET",
        ),
        (format!("café_{pa}=SUPER_SECRET"), "SUPER_SECRET"),
        (format!("café_{au}=SUPER_SECRET"), "SUPER_SECRET"),
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
        // Neon AUD-10: stray quote + empty_closed_in_str
        (
            format!("failed parsing \"config: {pw}: \" SUPER_SECRET\""),
            "SUPER_SECRET",
        ),
        // Neon AUD-16: non-ASCII boundary before Cookie header
        ("éCookie: sid=SUPER_SECRET".to_string(), "SUPER_SECRET"),
    ];

    for (input, secret) in &parity_cases {
        let diag = af_models::secret_redaction::redact_diagnostic(input).into_owned();
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
        let projected = redact_secrets(input);
        let balanced = redact_balanced_structured_secrets(input);
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
        let summary = sanitize_diagnostic_summary(input, 512);
        let (_stage, _code, parsed_summary) = parse_diagnostic_markers(input);

        for (name, out) in [
            ("diagnostic", &diag),
            ("persisted", &persisted),
            ("projected", &projected),
            ("balanced", &balanced),
            ("runner", &runner),
            ("summary", &summary),
        ] {
            assert!(
                !out.contains(secret),
                "{name} leaked {secret:?} for {input:?} -> {out:?}"
            );
        }
        assert!(
            parsed_summary
                .as_deref()
                .is_none_or(|s| !s.contains(secret)),
            "parse_diagnostic_markers leaked {secret:?} for {input:?} -> {parsed_summary:?}"
        );
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&diag).into_owned(),
            diag
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(&persisted),
            persisted
        );
        assert_eq!(redact_secrets(&projected), projected);
        assert_eq!(redact_balanced_structured_secrets(&balanced), balanced);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(&runner),
            runner
        );
    }

    // 2. `redact_json_value` regressions (Neon AUD-04, AUD-08, AUD-09, AUD-15)
    for (raw_json, forbidden) in [
        (
            "{\"Bearer\u{00A0}SUPER_SECRET\": \"ok\"}".to_string(),
            "SUPER_SECRET",
        ),
        (
            r#"["curl", "-suSUPER_SECRET", "https://example.com"]"#.to_string(),
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
    ] {
        let mut v: serde_json::Value = serde_json::from_str(&raw_json).unwrap();
        redact_json_value(&mut v);
        let ser = serde_json::to_string(&v).unwrap();
        assert!(
            !ser.contains(forbidden),
            "redact_json_value leaked {forbidden:?} for {raw_json:?} -> {ser:?}"
        );
    }

    // Neon AUD-15: colliding scrubbed keys must NOT silently drop entries
    let collision_json = format!(r#"{{"cmd --{pw} SEC1": "val1", "cmd --{pw} SEC2": "val2"}}"#);
    let mut collision_v: serde_json::Value = serde_json::from_str(&collision_json).unwrap();
    redact_json_value(&mut collision_v);
    assert_eq!(
        collision_v.as_object().unwrap().len(),
        2,
        "scrubbed key collision dropped an entry: {collision_v}"
    );
    let collision_proj = redact_secrets(&collision_json);
    let collision_parsed: serde_json::Value = serde_json::from_str(&collision_proj).unwrap();
    assert_eq!(collision_parsed.as_object().unwrap().len(), 2);
    assert_eq!(redact_secrets(&collision_proj), collision_proj);

    // 3. Valid RFC 8259 JSON preservation & idempotency (Team 8 F-02, Carbon CRATE-W1A-01..03)
    for valid_json in [
        r#"{"a":["https://user:notaport",0.0000000000000000000000000000000000000000000000000000000000000001,{"alice@corp.com":1}]}"#.to_string(),
        r#"["",{"":{"-u":null}}]"#.to_string(),
        format!(r#"{{"'{sec}":{{"":"","":{{}}}}}}"#),
        format!(r#"["'{sec}",[{{"[REDACTED]':{au}":5}},""]]"#),
        format!(r#"["\"{sec}:\":\"}}"]"#),
        format!(r#"{{"outer": "{{\"{api_sec}:\": 123, \"sibling\": \"ok\"}}"}}"#),
        r#"{"outer": "{\"msg\": \"\\u0022Bearer SUPER_SECRET\\u0022\"}"}"#.to_string(),
    ] {
        let out = redact_secrets(&valid_json);
        assert!(
            !out.contains("SUPER_SECRET"),
            "redact_secrets leaked on {valid_json:?} -> {out:?}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap_or_else(|e| {
            panic!("redact_secrets broke valid JSON ({e}) for {valid_json:?} -> {out:?}")
        });
        assert_eq!(
            redact_secrets(&out),
            out,
            "redact_secrets non-idempotent on {valid_json:?} -> {out:?}"
        );
        if valid_json.contains(r#"\"sibling\": \"ok\""#) {
            let inner = parsed["outer"].as_str().unwrap();
            let inner_v: serde_json::Value = serde_json::from_str(inner).unwrap();
            assert_eq!(inner_v["sibling"], "ok");
        }
        if valid_json.contains(r#"\\u0022Bearer"#) {
            let inner = parsed["outer"].as_str().unwrap();
            serde_json::from_str::<serde_json::Value>(inner).unwrap_or_else(|e| {
                panic!("redact_secrets broke inner JSON ({e}): {inner}")
            });
        }
    }

    // Carbon CRATE-W1A-01 #2: `'-u` inside an object key must not corrupt surrounding array/object
    let cr01_arr =
        format!(r#"[{{"{pw}": "SUPER_SECRET"}}, {{"sh -c '-u": null}}, "admin:SUPER_SECRET"]"#);
    let cr01_out = redact_secrets(&cr01_arr);
    let cr01_parsed: serde_json::Value = serde_json::from_str(&cr01_out)
        .unwrap_or_else(|e| panic!("redact_secrets broke CRATE-W1A-01 #2 JSON ({e}): {cr01_out}"));
    assert_eq!(cr01_parsed.as_array().unwrap().len(), 3);
    assert_eq!(cr01_parsed[0][pw], "[REDACTED]");
    assert!(cr01_parsed[1]["sh -c '-u"].is_null());
    assert_eq!(redact_secrets(&cr01_out), cr01_out);

    // 4. Benign preservation across all 5 surfaces (Neon AUD-11, AUD-12, AUD-14)
    for benign in [
        r#"{"path": "C:\\t-u benign_arg"}"#.to_string(),
        format!(r#"log: C:\\t--{pw} benign_arg"#),
        "user=custom://example.com/path".to_string(),
    ] {
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&benign).into_owned(),
            benign,
            "diag altered benign {benign:?}"
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(&benign),
            benign,
            "persisted altered benign {benign:?}"
        );
        assert_eq!(
            redact_secrets(&benign),
            benign,
            "projected altered benign {benign:?}"
        );
        assert_eq!(
            redact_balanced_structured_secrets(&benign),
            benign,
            "balanced altered benign {benign:?}"
        );
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(&benign),
            benign,
            "runner altered benign {benign:?}"
        );
    }
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
            diag_expected,
            "diag over-redacted trailing line on {empty_hdr:?}"
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(empty_hdr),
            empty_hdr
        );
        assert_eq!(redact_secrets(empty_hdr), empty_hdr);
        assert_eq!(redact_balanced_structured_secrets(empty_hdr), empty_hdr);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(empty_hdr),
            empty_hdr
        );
    }

    // 5. Adaptive-n linear scaling on all 3 R13 DoS vectors (`AUD-01`, `AUD-02`, `AUD-03`)
    type SvcScalingCase = (&'static str, fn(usize) -> String, usize, usize);
    let scaling: &[SvcScalingCase] = &[
        (
            "aud01_user_url_brace",
            |n| "user=foo://{".repeat(n),
            1_000,
            16_000,
        ),
        (
            "aud02_attached_curl_esc_nl",
            |n| format!(r#"{{"msg":"{}:"}}"#, r#"-ua\n"#.repeat(n)),
            1_000,
            16_000,
        ),
        (
            "aud03_user_pair_esc_nl",
            |n| format!(r#"{{"msg":"{}:x"}}"#, r#"user=a\n."#.repeat(n)),
            1_000,
            16_000,
        ),
    ];
    for &(name, make_payload, start_n, max_n) in scaling {
        let mut n = start_n;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = redact_secrets(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if d1 >= std::time::Duration::from_millis(15) || n >= max_n {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = redact_secrets(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            ratio < 3.2,
            "package_jobs {name} showed superlinear scaling at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }
}

#[test]
fn test_wave1a_r15_package_jobs_regressions() {
    let pw = concat!("pass", "word");
    let pw_upper = concat!("PASS", "WORD");
    let pa = concat!("pa", "ss");
    let tok = concat!("tok", "en");
    let api_key = concat!("api_", "key");

    // 1. Team 8 F-01 P0 panic reproducers across all 5 surfaces + sanitize_diagnostic_summary
    for (input, must_be_json) in [
        (r#""\x user=a:b user": ok"#, false),
        (r#"{"msg": "\"C:\\path user=a:b user\": ok"}"#, true),
        (r#""\x user=a:b user": c:d"#, false),
    ] {
        let diag = af_models::secret_redaction::redact_diagnostic(input).into_owned();
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
        let projected = redact_secrets(input);
        let balanced = redact_balanced_structured_secrets(input);
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
        let summary = sanitize_diagnostic_summary(input, 512);
        for (name, out) in [
            ("diagnostic", &diag),
            ("persisted", &persisted),
            ("projected", &projected),
            ("balanced", &balanced),
            ("runner", &runner),
            ("summary", &summary),
        ] {
            assert!(
                !out.contains("a:b"),
                "R15 Team 8 F-01 {name} leaked a:b for {input:?} -> {out:?}"
            );
        }
        if must_be_json {
            for (name, out) in [("projected", &projected), ("balanced", &balanced)] {
                serde_json::from_str::<serde_json::Value>(out).unwrap_or_else(|e| {
                    panic!("R15 Team 8 F-01 {name} broke JSON ({e}) for {input:?} -> {out:?}")
                });
            }
        }
        assert_eq!(redact_secrets(&projected), projected);
        assert_eq!(redact_balanced_structured_secrets(&balanced), balanced);
    }

    // 2. Carbon W1A-R14-02: duplicate JSON keys across redact_secrets, sanitize_diagnostic_summary,
    //    and redact_embedded_json_spans (must never return raw unparsed input with overwritten secrets)
    let dup_json_cases = [
        r#"{"msg": "Authorization: Bearer SUPER_SECRET", "msg": "ok"}"#.to_string(),
        format!(r#"{{"config": {{"{api_key}": "SUPER_SECRET"}}, "config": {{}}}}"#),
        r#"{"user": "admin:SUPER_SECRET", "user": "admin"}"#.to_string(),
        format!(r#"{{"{pw}": "SUPER_SECRET", "{pw}": "[REDACTED]"}}"#),
    ];
    for input in &dup_json_cases {
        let proj = redact_secrets(input);
        let sum = sanitize_diagnostic_summary(input, 4096);
        let emb = redact_embedded_json_spans(input);
        for (name, out) in [
            ("redact_secrets", &proj),
            ("summary", &sum),
            ("embedded", &emb),
        ] {
            assert!(
                !out.contains("SUPER_SECRET"),
                "R15 W1A-R14-02 {name} leaked overwritten duplicate key for {input:?} -> {out:?}"
            );
            serde_json::from_str::<serde_json::Value>(out).unwrap_or_else(|e| {
                panic!("R15 W1A-R14-02 {name} broke JSON ({e}) for {input:?} -> {out:?}")
            });
        }
        assert_eq!(redact_secrets(&proj), proj);
    }
    let embedded_dup = format!(
        r#"installer failed: {{"config": {{"{api_key}": "SUPER_SECRET"}}, "config": {{}}}}"#
    );
    let embedded_dup_out = redact_embedded_json_spans(&embedded_dup);
    assert!(
        !embedded_dup_out.contains("SUPER_SECRET"),
        "R15 W1A-R14-02 redact_embedded_json_spans leaked: {embedded_dup_out}"
    );
    assert_eq!(
        redact_embedded_json_spans(&embedded_dup_out),
        embedded_dup_out
    );
    let embedded_dup_sum = sanitize_diagnostic_summary(&embedded_dup, 4096);
    assert!(
        !embedded_dup_sum.contains("SUPER_SECRET"),
        "R15 W1A-R14-02 sanitize_diagnostic_summary leaked: {embedded_dup_sum}"
    );

    // 3. 5-surface parity + package_jobs projection across all R14 secret-leak findings
    let parity_cases: Vec<(String, &'static str, bool)> = vec![
        // Team 8 F-03 = Neon AUD-04: escaped-tab auth-scheme chains
        (
            r#"Bearer\tBearer SUPER_SECRET"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"Basic\tBearer SUPER_SECRET"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            format!(r#"{tok}\tBearer SUPER_SECRET"#),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"Digest\tBearer SUPER_SECRET"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            format!(r#"invalid {tok}\tBearer SUPER_SECRET"#),
            "SUPER_SECRET",
            false,
        ),
        (
            format!(r#"{{"msg": "invalid {tok}\\tBearer SUPER_SECRET"}}"#),
            "SUPER_SECRET",
            true,
        ),
        // Team 8 F-04: NBSP around `=` / `:`
        (format!("{pw}\u{00A0}=SUPER_SECRET"), "SUPER_SECRET", false),
        (format!("{pw}\\u00a0=SUPER_SECRET"), "SUPER_SECRET", false),
        (
            format!("\"{pw}\"\u{00A0}: \"SUPER_SECRET\""),
            "SUPER_SECRET",
            false,
        ),
        (
            format!("{api_key}\u{00A0}: SUPER_SECRET"),
            "SUPER_SECRET",
            false,
        ),
        (
            "user=\u{00A0}admin:SUPER_SECRET".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "user:\u{00A0}admin:SUPER_SECRET".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "user\u{00A0}=admin:SUPER_SECRET".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "user=\u{00A0}\"admin:SUPER_SECRET\"".to_string(),
            "SUPER_SECRET",
            false,
        ),
        // Team 8 F-05: valid JSON argv `-u` with `\u003a` / `\u0020`
        (
            r#"["tool", "-u", "admin\u003aSUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"["tool", "-u", "Bearer\u0020SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        // Carbon W1A-R14-03: JSON `\u000a` / `\u000d` boundaries
        (
            r#"{"msg": "ok\u000aBearer SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            format!(r#"{{"msg": "ok\u000a--{pw} SUPER_SECRET"}}"#),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"msg": "ok\u000acurl -su admin:SUPER_SECRET https://example.com"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"msg": "ok\u000auser=admin:SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"err: {"msg": "ok\u000aBearer SUPER_SECRET""#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            format!(r#"err: {{"msg": "ok\u000d--{pw} SUPER_SECRET""#),
            "SUPER_SECRET",
            false,
        ),
        // Carbon W1A-R14-04: JSON-escaped POSIX line continuations (`\\\n` / `\\\r\n`)
        (
            format!("{{\"cmd\": \"pg_dump --{pw} part1\\\\\\nSUPER_SECRET\"}}"),
            "SUPER_SECRET",
            true,
        ),
        (
            format!("{{\"cmd\": \"pg_dump --{pw} part1\\\\\\r\\nSUPER_SECRET\"}}"),
            "SUPER_SECRET",
            true,
        ),
        (
            "{\"cmd\": \"curl -u admin:\\\\\\nSUPER_SECRET https://example.com\"}".to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            format!("{{\"env\": \"{pw_upper}=part1\\\\\\nSUPER_SECRET\"}}"),
            "SUPER_SECRET",
            true,
        ),
        (
            format!("err: {{\"cmd\": \"pg_dump --{pw} part1\\\\\\nSUPER_SECRET\""),
            "SUPER_SECRET",
            false,
        ),
        // Neon AUD-03: URL password containing `@` followed by `,`, `;`, `'`, `"`, `{`, `}`
        (
            "https://admin:p@ss,SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:p@ss;SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:p@ss'SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"https://admin:p@ss"SUPER_SECRET@example.com/api"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:p@ss{SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "https://admin:p@ss}SUPER_SECRET@example.com/api".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"{"url": "https://admin:p@ss;SUPER_SECRET@example.com/api"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        // Neon AUD-05: JSON-serialized folded HTTP Digest header
        (
            r#"{"err": "Digest username=\"alice\",\n  response=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"err": "Digest username=\"alice\",\r\n  response=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"err": "Digest username=\"alice\",\tresponse=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            r#"{"err": "Digest username=\"alice\",\\\nresponse=\"SUPER_SECRET\""}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        // Neon AUD-06: Unicode delimiters & escaped-whitespace bypass
        ("—Bearer SUPER_SECRET".to_string(), "SUPER_SECRET", false),
        ("“Bearer SUPER_SECRET”".to_string(), "SUPER_SECRET", false),
        (
            r#"{"msg": "\u2014Bearer SUPER_SECRET"}"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (format!(r#"\u0020{pa}=SUPER_SECRET"#), "SUPER_SECRET", false),
        (format!(r#"\u0009{pa}=SUPER_SECRET"#), "SUPER_SECRET", false),
        (format!(r#"\u00a0{pa}=SUPER_SECRET"#), "SUPER_SECRET", false),
        (
            r#"\u0020user=admin:SUPER_SECRET"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            format!(r#"\u0020--{pw} SUPER_SECRET"#),
            "SUPER_SECRET",
            false,
        ),
        (format!(r#"\u2014{pa}=SUPER_SECRET"#), "SUPER_SECRET", false),
        (
            format!(r#"{{"msg": "\u0020{pa}=SUPER_SECRET"}}"#),
            "SUPER_SECRET",
            true,
        ),
        // Neon AUD-07: URL `\u0040` Pass-0 standalone `","` and unquoted `\\"`
        (
            r#""https://admin:p","SUPER_SECRET\u0040example.com/api""#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"https://admin:p\\"SUPER_SECRET\u0040example.com/api"#.to_string(),
            "SUPER_SECRET",
            false,
        ),
        // Neon AUD-08: `curl -b` / `-b<cookie>` / `-sb`
        (
            "curl -b sid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            r#"["curl", "-b", "sid=SUPER_SECRET"]"#.to_string(),
            "SUPER_SECRET",
            true,
        ),
        (
            "curl -bsid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
            false,
        ),
        (
            "curl -sb sid=SUPER_SECRET https://example.com".to_string(),
            "SUPER_SECRET",
            false,
        ),
    ];

    for (input, secret, must_be_json) in &parity_cases {
        let diag = af_models::secret_redaction::redact_diagnostic(input).into_owned();
        let persisted = af_release::lifecycle::sanitize_persisted_lifecycle_text(input);
        let projected = redact_secrets(input);
        let balanced = redact_balanced_structured_secrets(input);
        let runner = af_runner::package_lifecycle::sanitize_lifecycle_field(input);
        let summary = sanitize_diagnostic_summary(input, 512);

        for (name, out) in [
            ("diagnostic", &diag),
            ("persisted", &persisted),
            ("projected", &projected),
            ("balanced", &balanced),
            ("runner", &runner),
            ("summary", &summary),
        ] {
            assert!(
                !out.contains(secret),
                "R15 {name} leaked {secret:?} for {input:?} -> {out:?}"
            );
        }
        if *must_be_json {
            for (name, out) in [("projected", &projected), ("balanced", &balanced)] {
                serde_json::from_str::<serde_json::Value>(out).unwrap_or_else(|e| {
                    panic!("R15 {name} broke JSON ({e}) for {input:?} -> {out:?}")
                });
            }
        }
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&diag).into_owned(),
            diag
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(&persisted),
            persisted
        );
        assert_eq!(redact_secrets(&projected), projected);
        assert_eq!(redact_balanced_structured_secrets(&balanced), balanced);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(&runner),
            runner
        );
    }

    // 4. Team 8 F-06: multiline `\u0022` / `\u003a` carry-state leaks in `redact_diagnostic`
    for (input, forbidden) in [
        (
            format!("[\\u0022pg_dump\\u0022, \\u0022--{pw}\\u0022,\n  \\u0022SUPER_SECRET\\u0022]"),
            "SUPER_SECRET",
        ),
        (
            "{\n  \"user\":\n  \"admin\\u003aSUPER_SECRET\"\n}".to_string(),
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
    ] {
        let d1 = af_models::secret_redaction::redact_diagnostic(&input).into_owned();
        assert!(
            !d1.contains(forbidden),
            "R15 Team 8 F-06 diag leaked {forbidden:?} for {input:?} -> {d1:?}"
        );
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(&d1).into_owned(),
            d1
        );
    }

    // 5. Carbon W1A-R14-05 (multiline sibling object after Cookie header) & W1A-R14-06 (idempotency)
    let w14_05_j1 = "[\"Cookie: sid=SUPER_SECRET\",{\"a\":\"1\",\n\"b\":2}]";
    for (name, out) in [
        ("projected", redact_secrets(w14_05_j1)),
        ("balanced", redact_balanced_structured_secrets(w14_05_j1)),
        (
            "persisted",
            af_release::lifecycle::sanitize_persisted_lifecycle_text(w14_05_j1),
        ),
        (
            "runner",
            af_runner::package_lifecycle::sanitize_lifecycle_field(w14_05_j1),
        ),
    ] {
        assert!(!out.contains("SUPER_SECRET"), "{name}: {out}");
        let parsed: serde_json::Value = serde_json::from_str(&out)
            .unwrap_or_else(|e| panic!("R15 W1A-R14-05 {name} broke JSON ({e}): {out}"));
        assert_eq!(parsed[1]["a"], "1", "{name}: {out}");
        assert_eq!(parsed[1]["b"], 2, "{name}: {out}");
    }
    let w14_05_j2 = "[\"Cookie: sid=SUPER_SECRET\",{\"a\":\"1\",\n\"b\":1e500}]";
    let w14_05_j2_proj = redact_secrets(w14_05_j2);
    assert!(!w14_05_j2_proj.contains("SUPER_SECRET"));
    assert!(
        w14_05_j2_proj.contains(r#"{"a":"1","#) && w14_05_j2_proj.contains(r#""b":1e500}"#),
        "R15 W1A-R14-05 1e500 clobbered sibling: {w14_05_j2_proj}"
    );
    assert_eq!(redact_secrets(&w14_05_j2_proj), w14_05_j2_proj);

    for w14_06 in [
        format!(r#"{{"{pw}_\\u005c\\u00750041": "SUPER_SECRET"}}"#),
        r#"{"Bearer SUPER_SECRET \\u005c\\u00750041": 1}"#.to_string(),
    ] {
        let y1 = redact_secrets(&w14_06);
        let y2 = redact_secrets(&y1);
        assert!(!y1.contains("SUPER_SECRET"), "W1A-R14-06 leaked: {y1}");
        assert_eq!(
            y1, y2,
            "W1A-R14-06 redact_secrets non-idempotent: {y1} vs {y2}"
        );
        let s1 = sanitize_diagnostic_summary(&w14_06, 4096);
        let s2 = sanitize_diagnostic_summary(&s1, 4096);
        assert_eq!(s1, s2, "W1A-R14-06 summary non-idempotent: {s1} vs {s2}");
        let mut v1: serde_json::Value = serde_json::from_str(&w14_06).unwrap();
        redact_json_value(&mut v1);
        let mut v2 = v1.clone();
        redact_json_value(&mut v2);
        assert_eq!(v1, v2, "W1A-R14-06 redact_json_value non-idempotent");
    }

    // 6. Neon AUD-08 benign preservation & Neon AUD-09 Base64 `=` padding preservation
    for benign in [
        "git checkout -b feature",
        "curl -B https://example.com",
        r#"{"cmd": "curl", "items": ["-b", "benign_item"]}"#,
    ] {
        assert_eq!(
            af_models::secret_redaction::redact_diagnostic(benign).into_owned(),
            benign
        );
        assert_eq!(
            af_release::lifecycle::sanitize_persisted_lifecycle_text(benign),
            benign
        );
        assert_eq!(redact_secrets(benign), benign);
        assert_eq!(redact_balanced_structured_secrets(benign), benign);
        assert_eq!(
            af_runner::package_lifecycle::sanitize_lifecycle_field(benign),
            benign
        );
    }

    for (aud09, must_keep) in [
        (
            "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\" https://example.com\nstep 2: status=\"ok\"",
            "step 2: status=\"ok\"",
        ),
        (
            "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\" -H \"Accept: application/json\" https://example.com",
            "-H \"Accept: application/json\"",
        ),
        (
            "curl -H \"Authorization: Basic\ndXNlcjpwYXNz=\"\nbenign_line=1",
            "benign_line=1",
        ),
    ] {
        for (name, out) in [
            (
                "persisted",
                af_release::lifecycle::sanitize_persisted_lifecycle_text(aud09),
            ),
            ("projected", redact_secrets(aud09)),
            ("balanced", redact_balanced_structured_secrets(aud09)),
            (
                "runner",
                af_runner::package_lifecycle::sanitize_lifecycle_field(aud09),
            ),
        ] {
            assert!(!out.contains("dXNlcjpwYXNz"), "{name}: {out}");
            assert!(
                out.contains(must_keep),
                "R15 AUD-09 {name} swallowed {must_keep:?}: {out}"
            );
        }
    }

    // 7. Adaptive-n linear scaling across all 3 R14 DoS vectors (AUD-01, AUD-02, W1A-R14-01)
    type R15SvcScalingCase = (&'static str, fn(usize) -> String, usize, usize);
    let scaling: &[R15SvcScalingCase] = &[
        (
            "r15_aud01_u0022_pairs",
            |n| format!("Cookie: x {}\nbenign", "\\u0022\\u0022".repeat(n)),
            1_000,
            16_000,
        ),
        (
            "r15_aud02_colliding_json_keys",
            |n| {
                let pw_k = concat!("pass", "word");
                let mut s = String::with_capacity(n * 28);
                s.push('{');
                for i in 0..n {
                    if i > 0 {
                        s.push(',');
                    }
                    s.push_str(&format!("\"cmd --{pw_k} S{i}\":\"v\""));
                }
                s.push('}');
                s
            },
            200,
            3_200,
        ),
        (
            "r15_w14_01_u0022_user_brace",
            |n| r#"\u0022user\u0022:a{ "#.repeat(n),
            1_000,
            16_000,
        ),
    ];
    for &(name, make_payload, start_n, max_n) in scaling {
        let mut n = start_n;
        let (d1, d2) = loop {
            let p1 = make_payload(n);
            let t1 = std::time::Instant::now();
            let o1 = redact_secrets(&p1);
            let d1 = t1.elapsed();
            assert!(!o1.is_empty());
            if name == "r15_aud02_colliding_json_keys" {
                let parsed: serde_json::Value = serde_json::from_str(&o1).unwrap();
                assert_eq!(parsed.as_object().unwrap().len(), n);
                assert!(!o1.contains("S0"));
            }
            if d1 >= std::time::Duration::from_millis(15) || n >= max_n {
                let p2 = make_payload(n * 2);
                let t2 = std::time::Instant::now();
                let o2 = redact_secrets(&p2);
                let d2 = t2.elapsed();
                assert!(!o2.is_empty());
                break (d1, d2);
            }
            n *= 2;
        };
        let ratio = d2.as_secs_f64() / d1.as_secs_f64().max(1e-6);
        assert!(
            ratio < 3.2,
            "package_jobs {name} showed superlinear scaling at n={n}: d1={d1:?}, d2={d2:?} (ratio={ratio:.2}x)"
        );
    }
}

#[test]
fn test_wave1a_r15_duplicate_json_keys_try_start_and_snapshot() {
    let name =
        "package_jobs::unit_tests::test_wave1a_r15_duplicate_json_keys_try_start_and_snapshot";
    if isolated_package_jobs_unit_test(name) {
        return;
    }
    let (root, db_path) = setup_package_jobs_unit_fixture();
    initialize_package_jobs(Connection::open(&db_path).unwrap()).unwrap();

    let api_key = concat!("api_", "key");
    let dup_last_line = r#"{"msg": "Authorization: Bearer DUP_START_LINE_R15", "msg": "ok"}"#;
    let dup_target =
        format!(r#"{{"config": {{"{api_key}": "DUP_START_TARGET_R15"}}, "config": {{}}}}"#);
    let dup_summary = r#"{"user": "admin:DUP_FINISH_SUM_R15", "user": "admin"}"#;

    let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    assert!(try_start_package_job(PackageJobInfo {
        job_id: "job-dup-r15".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 20,
        last_line: dup_last_line.into(),
        started_at: "2026-11-27T02:00:00Z".into(),
        expected_target_version: Some(dup_target),
    }));
    drop(admission);

    let info = get_package_job_info("fixture").expect("active job info");
    assert!(
        !info.last_line.contains("DUP_START_LINE_R15"),
        "get_package_job_info leaked duplicate-key last_line: {}",
        info.last_line
    );
    serde_json::from_str::<serde_json::Value>(&info.last_line).unwrap();
    let target = info.expected_target_version.as_deref().unwrap();
    assert!(
        !target.contains("DUP_START_TARGET_R15"),
        "get_package_job_info leaked duplicate-key expected_target_version: {target}"
    );
    serde_json::from_str::<serde_json::Value>(target).unwrap();

    let snap = package_job_snapshot().unwrap();
    assert!(!snap.active["fixture"]
        .last_line
        .contains("DUP_START_LINE_R15"));
    assert!(!snap.active["fixture"]
        .expected_target_version
        .as_deref()
        .unwrap()
        .contains("DUP_START_TARGET_R15"));

    let outcome = finish_package_job_with_diagnostics(
        "fixture",
        "update",
        false,
        Some(PackageJobFailure::Installer),
        "job-dup-r15",
        Some("installer".into()),
        Some(1),
        Some(dup_summary.into()),
        None,
        None,
    )
    .expect("outcome");
    let out_summary = outcome.sanitized_summary.as_deref().unwrap();
    assert!(
        !out_summary.contains("DUP_FINISH_SUM_R15"),
        "finish_package_job_with_diagnostics leaked duplicate-key summary: {out_summary}"
    );
    serde_json::from_str::<serde_json::Value>(out_summary).unwrap();

    let check_conn = Connection::open(&db_path).unwrap();
    let history = af_release::lifecycle::get_lifecycle_history(&check_conn, "fixture", 5).unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].failure_category, "installer");
    assert!(!history[0]
        .expected_target_version
        .as_deref()
        .unwrap()
        .contains("DUP_START_TARGET_R15"));
    assert!(!history[0]
        .sanitized_summary
        .as_deref()
        .unwrap()
        .contains("DUP_FINISH_SUM_R15"));

    drop(check_conn);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_wave1a_r16_surface_parity_and_tampered_metadata_snapshot_history() {
    let name =
        "package_jobs::unit_tests::test_wave1a_r16_surface_parity_and_tampered_metadata_snapshot_history";
    if isolated_package_jobs_unit_test(name) {
        return;
    }

    let pw = concat!("pass", "word");
    let pa = concat!("pa", "ss");
    let au = concat!("au", "th");
    let tok = concat!("tok", "en");

    // 1. Cross-surface sanity for Team 8 F-09, Neon AUD-05, Carbon W1A-AUD-02/03/07
    assert_eq!(
        redact_secrets(r#"{"cmd": "curl https://example.com\nrsync -b backup.tar"}"#),
        r#"{"cmd": "curl https://example.com\nrsync -b backup.tar"}"#
    );
    assert_eq!(
        redact_secrets(r#"{"KEY\u0061": "benign_val"}"#),
        r#"{"KEY\u0061": "benign_val"}"#
    );
    for (input, must_preserve_json) in [
        ("Bearer\u{3000}SUPER_SECRET_R16".to_string(), false),
        (format!("--{tok}\u{3000}SUPER_SECRET_R16"), false),
        (format!("{pw}\u{3000}=\u{3000}SUPER_SECRET_R16"), false),
        (format!(r#"{{"\t{pa}": "SUPER_SECRET_R16"}}"#), true),
        (format!(r#"{{"\n{au}": "SUPER_SECRET_R16"}}"#), true),
        (format!(r#"{{"\b{pa}": "SUPER_SECRET_R16"}}"#), true),
        (format!(r#"{{"\f{pa}": "SUPER_SECRET_R16"}}"#), true),
        (r#"{"\rKEY": "SUPER_SECRET_R16"}"#.to_string(), true),
        (r#"{"\tuser": "admin:SUPER_SECRET_R16"}"#.to_string(), true),
        (format!(r#"err: {{"\t{pa}": "SUPER_SECRET_R16""#), false),
        (
            format!(r#"payload="{{\"\\t{pa}\": \"SUPER_SECRET_R16\"}}""#),
            false,
        ),
        (
            format!(r#"[info: 5" disk] {{"{pw}": "SUPER_SECRET_R16"}}"#),
            false,
        ),
        (
            format!(r#"[info: 5" disk] {{"\t{pa}": "SUPER_SECRET_R16"}}"#),
            false,
        ),
    ] {
        let once = redact_secrets(&input);
        assert!(
            !once.contains("SUPER_SECRET_R16"),
            "services R16 leaked for {input:?} -> {once:?}"
        );
        if must_preserve_json {
            serde_json::from_str::<serde_json::Value>(&once).unwrap_or_else(|e| {
                panic!("services R16 broke JSON ({e}) for {input:?} -> {once:?}")
            });
        }
        assert_eq!(redact_secrets(&once), once);
    }

    // 2. Carbon W1A-AUD-06 + Neon AUD-02 + Carbon W1A-AUD-03 across package_job_snapshot
    //    and get_package_job_history_outcome
    let (root, db_path) = setup_package_jobs_unit_fixture();
    initialize_package_jobs(Connection::open(&db_path).unwrap()).unwrap();

    let dirty_started = format!("2026-11-27T03:00:00Z --{pw}=START_SVC_SECRET_R16");
    let two_stage_summary = r#"{"msg": "X-Api-Key: \nTWO_STAGE_SVC_SECRET_R16"}"#;
    let stage_json = format!(r#"{{"{pw}": "STAGE_SVC_SECRET_R16"}}"#);

    let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    assert!(try_start_package_job(PackageJobInfo {
        job_id: "job-r16-svc".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: format!(r#"[info: 5" disk] {{"\t{pa}": "LINE_AUD03_R16"}}"#),
        started_at: dirty_started,
        expected_target_version: Some("3.0.0".into()),
    }));
    drop(admission);

    let snap_active = package_job_snapshot().unwrap();
    let active_info = &snap_active.active["fixture"];
    assert!(!active_info.started_at.contains("START_SVC_SECRET_R16"));
    assert!(active_info.started_at.contains("2026-11-27T03:00:00Z"));
    assert!(!active_info.last_line.contains("LINE_AUD03_R16"));

    let outcome = finish_package_job_with_diagnostics(
        "fixture",
        "update",
        false,
        Some(PackageJobFailure::Installer),
        "job-r16-svc",
        Some(stage_json),
        Some(1),
        Some(two_stage_summary.to_string()),
        None,
        None,
    )
    .expect("outcome");
    assert!(!outcome.started_at.contains("START_SVC_SECRET_R16"));
    assert!(!outcome
        .failed_stage
        .as_deref()
        .unwrap()
        .contains("STAGE_SVC_SECRET_R16"));
    serde_json::from_str::<serde_json::Value>(outcome.failed_stage.as_deref().unwrap()).unwrap();
    assert!(!outcome
        .sanitized_summary
        .as_deref()
        .unwrap()
        .contains("TWO_STAGE_SVC_SECRET_R16"));
    serde_json::from_str::<serde_json::Value>(outcome.sanitized_summary.as_deref().unwrap())
        .unwrap();

    // Verify normal ISO timestamps stay intact on history read before tampering
    let clean_hist_out = get_package_job_history_outcome("fixture", "job-r16-svc")
        .unwrap()
        .expect("history outcome");
    assert!(!clean_hist_out
        .sanitized_summary
        .as_deref()
        .unwrap()
        .contains("TWO_STAGE_SVC_SECRET_R16"));
    assert!(
        chrono::DateTime::parse_from_rfc3339(&clean_hist_out.finished_at).is_ok(),
        "normal RFC3339 finished_at must be preserved: {}",
        clean_hist_out.finished_at
    );

    // Seed out-of-band tampered started_at / finished_at / W1A-AUD-03 summary in SQLite
    let tamper_conn = Connection::open(&db_path).unwrap();
    let tamper_started = format!("2026-11-27 --{pw}=START_TAMPER_SVC_R16");
    let tamper_finished = format!("2026-11-27 --{tok}=FIN_TAMPER_SVC_R16");
    let tamper_summary = format!(r#"[info: 5" disk] {{"\t{pa}": "TAMPER_AUD03_SVC_R16"}}"#);
    tamper_conn
        .execute(
            "UPDATE package_lifecycle_jobs SET started_at=?1, finished_at=?2, sanitized_summary=?3 WHERE package_id='fixture' AND job_id='job-r16-svc'",
            params![tamper_started, tamper_finished, tamper_summary],
        )
        .unwrap();
    tamper_conn
        .execute(
            "UPDATE package_lifecycle_history SET started_at=?1, finished_at=?2, sanitized_summary=?3 WHERE package_id='fixture' AND job_id='job-r16-svc'",
            params![tamper_started, tamper_finished, tamper_summary],
        )
        .unwrap();
    drop(tamper_conn);

    let snap_tampered = package_job_snapshot().unwrap();
    let snap_out = &snap_tampered.outcomes["fixture"];
    assert!(!snap_out.started_at.contains("START_TAMPER_SVC_R16"));
    assert!(snap_out.started_at.contains("[REDACTED]"));
    assert!(!snap_out.finished_at.contains("FIN_TAMPER_SVC_R16"));
    assert!(snap_out.finished_at.contains("[REDACTED]"));
    assert!(!snap_out
        .sanitized_summary
        .as_deref()
        .unwrap()
        .contains("TAMPER_AUD03_SVC_R16"));

    let hist_tampered = get_package_job_history_outcome("fixture", "job-r16-svc")
        .unwrap()
        .expect("tampered history outcome");
    assert!(!hist_tampered.started_at.contains("START_TAMPER_SVC_R16"));
    assert!(hist_tampered.started_at.contains("[REDACTED]"));
    assert!(!hist_tampered.finished_at.contains("FIN_TAMPER_SVC_R16"));
    assert!(hist_tampered.finished_at.contains("[REDACTED]"));
    assert!(!hist_tampered
        .sanitized_summary
        .as_deref()
        .unwrap()
        .contains("TAMPER_AUD03_SVC_R16"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_wave1a_r17_tampered_identity_fields_and_surface_parity() {
    let name =
        "package_jobs::unit_tests::test_wave1a_r17_tampered_identity_fields_and_surface_parity";
    if isolated_package_jobs_unit_test(name) {
        return;
    }

    let pw = concat!("pass", "word");
    let tok = concat!("tok", "en");

    // 1. Direct sanitize_job_info & sanitize_job_outcome Neon F-11 verification
    let clean_info = sanitize_job_info(PackageJobInfo {
        job_id: "job-clean-r17".into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 25,
        last_line: "Downloading update...".into(),
        started_at: "2026-11-27T05:00:00Z".into(),
        expected_target_version: Some("3.2.0".into()),
    });
    assert_eq!(clean_info.job_id, "job-clean-r17");
    assert_eq!(clean_info.action, "update");
    assert_eq!(clean_info.status, "updating");

    let dirty_info = sanitize_job_info(PackageJobInfo {
        job_id: "job Bearer INFO_JOBID_R17".into(),
        package_id: "fixture".into(),
        action: format!("update {pw}=INFO_ACTION_R17"),
        status: format!("updating {tok}=INFO_STATUS_R17"),
        progress: 25,
        last_line: "ok".into(),
        started_at: "2026-11-27T05:00:00Z".into(),
        expected_target_version: None,
    });
    assert!(!dirty_info.job_id.contains("INFO_JOBID_R17"));
    assert!(dirty_info.job_id.contains("[REDACTED]"));
    assert!(!dirty_info.action.contains("INFO_ACTION_R17"));
    assert!(dirty_info.action.contains("[REDACTED]"));
    assert!(!dirty_info.status.contains("INFO_STATUS_R17"));
    assert!(dirty_info.status.contains("[REDACTED]"));

    let dirty_outcome = sanitize_job_outcome(PackageJobOutcome {
        job_id: "job Bearer OUT_JOBID_R17".into(),
        package_id: "fixture".into(),
        action: format!("update {pw}=OUT_ACTION_R17"),
        status: format!("failed {tok}=OUT_STATUS_R17"),
        message: "Operation failed.".into(),
        started_at: "2026-11-27T05:00:00Z".into(),
        finished_at: "2026-11-27T05:01:00Z".into(),
        failed_stage: None,
        exit_code: Some(1),
        sanitized_summary: None,
        expected_target_version: None,
        achieved_version: None,
        recovery_state: None,
    });
    assert!(!dirty_outcome.job_id.contains("OUT_JOBID_R17"));
    assert!(dirty_outcome.job_id.contains("[REDACTED]"));
    assert!(!dirty_outcome.action.contains("OUT_ACTION_R17"));
    assert!(dirty_outcome.action.contains("[REDACTED]"));
    assert!(!dirty_outcome.status.contains("OUT_STATUS_R17"));
    assert!(dirty_outcome.status.contains("[REDACTED]"));

    // 2. Live SQLite tampered job_id / action / status through package_job_snapshot
    //    and get_package_job_history_outcome (Neon F-11)
    let (root, db_path) = setup_package_jobs_unit_fixture();
    initialize_package_jobs(Connection::open(&db_path).unwrap()).unwrap();

    let tamper_job_id = "job Bearer SQL_JOBID_R17";
    let tamper_action = format!("update {pw}=SQL_ACTION_R17");
    let tamper_active_status = format!("updating {tok}=SQL_STATUS_R17");

    let seed_conn = Connection::open(&db_path).unwrap();
    seed_conn
        .execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, finished_at
            ) VALUES ('fixture', ?1, ?2, ?3, '2026-11-27T05:02:00Z', '')",
            params![tamper_job_id, tamper_action, tamper_active_status],
        )
        .unwrap();
    seed_conn
        .execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at
            ) VALUES ('fixture', ?1, ?2, 'failed', '2026-11-27T05:02:00Z', '2026-11-27T05:03:00Z')",
            params![tamper_job_id, tamper_action],
        )
        .unwrap();
    drop(seed_conn);

    let snap_active = package_job_snapshot().unwrap();
    let active = &snap_active.active["fixture"];
    assert!(!active.job_id.contains("SQL_JOBID_R17"));
    assert!(active.job_id.contains("[REDACTED]"));
    assert!(!active.action.contains("SQL_ACTION_R17"));
    assert!(active.action.contains("[REDACTED]"));
    assert!(!active.status.contains("SQL_STATUS_R17"));
    assert!(active.status.contains("[REDACTED]"));

    let hist_out = get_package_job_history_outcome("fixture", tamper_job_id)
        .unwrap()
        .expect("tampered history outcome");
    assert!(!hist_out.job_id.contains("SQL_JOBID_R17"));
    assert!(hist_out.job_id.contains("[REDACTED]"));
    assert!(!hist_out.action.contains("SQL_ACTION_R17"));
    assert!(hist_out.action.contains("[REDACTED]"));
    assert_eq!(hist_out.status, "failed");

    // 3. Cross-surface sanity in af-services redact_secrets for R17 fixes
    for input in [
        r#"err="curl -d '{\"a\":\"v\"}' -b SUPER_SECRET_SVC_R17""#.to_string(),
        format!("{pw}=\\u005c\\u0022part1 SUPER_SECRET_SVC_R17\\u005c\\u0022\nstep 2: ok"),
        "Bearer\u{000B}SUPER_SECRET_SVC_R17".to_string(),
        "curl -#u admin:SUPER_SECRET_SVC_R17 https://example.com".to_string(),
        "curl -E client.p12:SUPER_SECRET_SVC_R17 https://example.com".to_string(),
        format!(r#"{{"\ud800{pw}": "SUPER_SECRET_SVC_R17"}}"#),
    ] {
        let once = redact_secrets(&input);
        assert!(
            !once.contains("SUPER_SECRET_SVC_R17"),
            "services R17 leaked for {input:?} -> {once:?}"
        );
        assert_eq!(redact_secrets(&once), once);
    }
    assert_eq!(
        redact_secrets("curl -E /etc/ssl/client.pem https://example.com"),
        "curl -E /etc/ssl/client.pem https://example.com"
    );
    assert_eq!(
        redact_secrets("curl https://example.com\n-b feature-branch"),
        "curl https://example.com\n-b feature-branch"
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_wave1a_r18_tampered_package_id_and_identity_consistency() {
    let name =
        "package_jobs::unit_tests::test_wave1a_r18_tampered_package_id_and_identity_consistency";
    if isolated_package_jobs_unit_test(name) {
        return;
    }

    let pw = concat!("pass", "word");
    let tok = concat!("tok", "en");

    // 1. Direct sanitize_job_info & sanitize_job_outcome scrub package_id
    let dirty_info = sanitize_job_info(PackageJobInfo {
        job_id: "job-pkg-info-r18".into(),
        package_id: "radarr Bearer CANARY_INFO_PKG_R18".into(),
        action: "install".into(),
        status: "installing".into(),
        progress: 10,
        last_line: "ok".into(),
        started_at: "2026-11-27T12:00:00Z".into(),
        expected_target_version: None,
    });
    assert!(!dirty_info.package_id.contains("CANARY_INFO_PKG_R18"));
    assert!(dirty_info.package_id.contains("[REDACTED]"));

    let dirty_out = sanitize_job_outcome(PackageJobOutcome {
        job_id: "job-pkg-out-r18".into(),
        package_id: format!("sonarr --{pw}=CANARY_OUT_PKG_R18"),
        action: "update".into(),
        status: "completed".into(),
        message: "Operation completed.".into(),
        started_at: "2026-11-27T12:00:00Z".into(),
        finished_at: "2026-11-27T12:01:00Z".into(),
        failed_stage: None,
        exit_code: Some(0),
        sanitized_summary: None,
        expected_target_version: None,
        achieved_version: None,
        recovery_state: None,
    });
    assert!(!dirty_out.package_id.contains("CANARY_OUT_PKG_R18"));
    assert!(dirty_out.package_id.contains("[REDACTED]"));

    // 2. Carbon W1A-R17-04 / Neon AUD-07: live SQLite tampered package_id scrubbed on BOTH
    //    map keys and struct fields in package_job_snapshot() & get_package_job_history_outcome().
    let (root, db_path) = setup_package_jobs_unit_fixture();
    initialize_package_jobs(Connection::open(&db_path).unwrap()).unwrap();

    let tampered_active_pkg = "radarr Bearer CANARY_ACTIVE_PKG_R18";
    let tampered_done_pkg = format!("sonarr --{pw}=CANARY_DONE_PKG_R18");
    let seed_conn = Connection::open(&db_path).unwrap();
    seed_conn
        .execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, finished_at
            ) VALUES (?1, 'job-tamper-active-r18', 'install', 'installing', '2026-11-27T12:05:00Z', '')",
            params![tampered_active_pkg],
        )
        .unwrap();
    seed_conn
        .execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, finished_at
            ) VALUES (?1, 'job-tamper-done-r18', 'update', 'completed', '2026-11-27T12:05:00Z', '2026-11-27T12:06:00Z')",
            params![tampered_done_pkg],
        )
        .unwrap();
    seed_conn
        .execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at
            ) VALUES (?1, 'job-tamper-done-r18', 'update', 'completed', '2026-11-27T12:05:00Z', '2026-11-27T12:06:00Z')",
            params![tampered_done_pkg],
        )
        .unwrap();
    drop(seed_conn);

    // Re-initialize from tampered DB to also exercise JobRegistry::refresh directly.
    initialize_package_jobs(Connection::open(&db_path).unwrap()).unwrap();
    let snap = package_job_snapshot().unwrap();
    assert!(
        snap.active
            .keys()
            .all(|k| !k.contains("CANARY_ACTIVE_PKG_R18")),
        "active map keys leaked tampered package_id: {:?}",
        snap.active.keys().collect::<Vec<_>>()
    );
    assert!(
        snap.active
            .values()
            .all(|v| !v.package_id.contains("CANARY_ACTIVE_PKG_R18")),
        "active values leaked tampered package_id"
    );
    let sanitized_active_key = redact_secrets(tampered_active_pkg);
    assert!(
        snap.active.contains_key(&sanitized_active_key),
        "expected sanitized active key {sanitized_active_key:?}"
    );

    assert!(
        snap.outcomes
            .keys()
            .all(|k| !k.contains("CANARY_DONE_PKG_R18")),
        "outcomes map keys leaked tampered package_id: {:?}",
        snap.outcomes.keys().collect::<Vec<_>>()
    );
    assert!(
        snap.outcomes
            .values()
            .all(|v| !v.package_id.contains("CANARY_DONE_PKG_R18")),
        "outcomes values leaked tampered package_id"
    );
    let sanitized_done_key = redact_secrets(&tampered_done_pkg);
    assert!(
        snap.outcomes.contains_key(&sanitized_done_key),
        "expected sanitized outcome key {sanitized_done_key:?}"
    );

    let hist_out = get_package_job_history_outcome(&tampered_done_pkg, "job-tamper-done-r18")
        .unwrap()
        .expect("tampered package_id history outcome");
    assert!(!hist_out.package_id.contains("CANARY_DONE_PKG_R18"));
    assert!(hist_out.package_id.contains("[REDACTED]"));

    // Clean up tampered active row before F10 lifecycle flow.
    let cleanup_conn = Connection::open(&db_path).unwrap();
    cleanup_conn
        .execute("DELETE FROM package_lifecycle_jobs", [])
        .unwrap();
    drop(cleanup_conn);
    initialize_package_jobs(Connection::open(&db_path).unwrap()).unwrap();

    // 3. Team 8 F10: tainted custom job_id matches consistently across start, progress update,
    //    lease take, finish, snapshot, and history lookup without leaving an orphaned active job.
    let tainted_job_id = format!("job-{tok}=CANARY_F10_R18");
    let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    assert!(try_start_package_job(PackageJobInfo {
        job_id: tainted_job_id.clone(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 10,
        last_line: "starting".into(),
        started_at: "2026-11-27T12:10:00Z".into(),
        expected_target_version: Some("4.0.0".into()),
    }));
    drop(admission);

    let active_info = get_package_job_info("fixture").expect("active job info");
    assert!(!active_info.job_id.contains("CANARY_F10_R18"));
    assert!(active_info.job_id.contains("[REDACTED]"));

    let updated = set_package_job_info(PackageJobInfo {
        job_id: tainted_job_id.clone(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 55,
        last_line: "halfway".into(),
        started_at: "2026-11-27T12:10:00Z".into(),
        expected_target_version: Some("4.0.0".into()),
    })
    .expect("set_package_job_info must match tainted job_id");
    assert_eq!(updated.progress, 55);
    assert!(!updated.job_id.contains("CANARY_F10_R18"));

    let lease = take_package_job_lease("fixture", &tainted_job_id)
        .expect("take_package_job_lease must match tainted job_id");

    let finished = finish_package_job("fixture", "update", true, "done", &tainted_job_id)
        .expect("finish_package_job must match tainted job_id");
    assert_eq!(finished.status, "completed");
    assert!(!finished.job_id.contains("CANARY_F10_R18"));
    assert!(finished.job_id.contains("[REDACTED]"));
    drop(lease);

    let after_finish_snap = package_job_snapshot().unwrap();
    assert!(
        !after_finish_snap.active.contains_key("fixture"),
        "tainted job_id must not leave an orphaned active job"
    );
    assert_eq!(after_finish_snap.outcomes["fixture"].status, "completed");
    assert!(!after_finish_snap.outcomes["fixture"]
        .job_id
        .contains("CANARY_F10_R18"));

    let f10_hist = get_package_job_history_outcome("fixture", &tainted_job_id)
        .unwrap()
        .expect("history outcome must match tainted job_id");
    assert_eq!(f10_hist.status, "completed");
    assert!(!f10_hist.job_id.contains("CANARY_F10_R18"));
    assert!(f10_hist.job_id.contains("[REDACTED]"));

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn test_wave1a_r19_canonical_identity_parity_and_tampered_service_units() {
    let name =
        "package_jobs::unit_tests::test_wave1a_r19_canonical_identity_parity_and_tampered_service_units";
    if isolated_package_jobs_unit_test(name) {
        return;
    }

    let pw = concat!("pass", "word");
    let (root, db_path) = setup_package_jobs_unit_fixture();
    initialize_package_jobs(Connection::open(&db_path).unwrap()).unwrap();

    // 1. Carbon F4 + Team 8 F7 part 2: Authorization: Bearer job_id preserves exact write/read
    //    identity parity across start, snapshot, set_package_job_info, lease take, finish, and history.
    let raw_auth_job_id = "job Authorization: Bearer CANARY_AUTH_JID_R19";
    let expected_canonical_jid =
        af_release::lifecycle::LifecycleJobDiagnostics::sanitize_persisted_text(raw_auth_job_id);
    assert!(!expected_canonical_jid.contains("CANARY_AUTH_JID_R19"));

    let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    assert!(try_start_package_job(PackageJobInfo {
        job_id: raw_auth_job_id.into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 20,
        last_line: "downloading release".into(),
        started_at: "2026-11-27T15:00:00Z".into(),
        expected_target_version: Some("5.1.0".into()),
    }));
    drop(admission);

    // package_job_snapshot() must match local active job against SQLite row, preserving live progress & last_line!
    let snap = package_job_snapshot().unwrap();
    let active = snap.active.get("fixture").expect("active fixture job");
    assert_eq!(active.job_id, expected_canonical_jid);
    assert_eq!(
        active.progress, 20,
        "snapshot lost live progress due to job_id divergence"
    );
    assert_eq!(active.last_line, "downloading release");

    let updated = set_package_job_info(PackageJobInfo {
        job_id: raw_auth_job_id.into(),
        package_id: "fixture".into(),
        action: "update".into(),
        status: "updating".into(),
        progress: 65,
        last_line: "applying package".into(),
        started_at: "2026-11-27T15:00:00Z".into(),
        expected_target_version: Some("5.1.0".into()),
    })
    .expect("set_package_job_info must match canonical Authorization job_id");
    assert_eq!(updated.progress, 65);
    assert_eq!(updated.job_id, expected_canonical_jid);

    let lease = take_package_job_lease("fixture", raw_auth_job_id)
        .expect("take_package_job_lease must match canonical Authorization job_id");

    let finished = finish_package_job_with_diagnostics(
        "fixture",
        "update",
        true,
        None,
        raw_auth_job_id,
        None,
        Some(0),
        Some("completed cleanly".into()),
        Some("5.1.0".into()),
        Some("5.1.0".into()),
    )
    .expect("finish_package_job_with_diagnostics must match canonical Authorization job_id");
    assert_eq!(finished.status, "completed");
    assert_eq!(finished.job_id, expected_canonical_jid);
    drop(lease);

    let after_finish = package_job_snapshot().unwrap();
    assert!(
        !after_finish.active.contains_key("fixture"),
        "Authorization job_id must not leave an orphaned active job"
    );
    assert_eq!(
        after_finish.outcomes["fixture"].job_id,
        expected_canonical_jid
    );

    let hist_by_raw = get_package_job_history_outcome("fixture", raw_auth_job_id)
        .unwrap()
        .expect("history lookup by raw Authorization job_id");
    assert_eq!(hist_by_raw.job_id, expected_canonical_jid);
    let hist_by_canonical = get_package_job_history_outcome("fixture", &expected_canonical_jid)
        .unwrap()
        .expect("history lookup by canonical Authorization job_id");
    assert_eq!(hist_by_canonical.job_id, expected_canonical_jid);

    // 2. Malformed JSON package_id identity parity across JobRegistry, snapshot, and history
    let malformed_pkg = format!(r#"err {{"{pw}": "CANARY_MALFORMED_PKG_R19""#);
    let canonical_malformed_pkg =
        af_release::lifecycle::LifecycleJobDiagnostics::sanitize_persisted_text(&malformed_pkg);
    assert!(!canonical_malformed_pkg.contains("CANARY_MALFORMED_PKG_R19"));

    let seed_conn = Connection::open(&db_path).unwrap();
    seed_conn
        .execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, finished_at
            ) VALUES (?1, 'job-malformed-r19', 'update', 'completed', '2026-11-27T15:05:00Z', '2026-11-27T15:06:00Z')",
            params![canonical_malformed_pkg],
        )
        .unwrap();
    seed_conn
        .execute(
            "INSERT INTO package_lifecycle_history (
                package_id, job_id, action, status, started_at, finished_at
            ) VALUES (?1, 'job-malformed-r19', 'update', 'completed', '2026-11-27T15:05:00Z', '2026-11-27T15:06:00Z')",
            params![canonical_malformed_pkg],
        )
        .unwrap();
    drop(seed_conn);

    initialize_package_jobs(Connection::open(&db_path).unwrap()).unwrap();
    let malformed_snap = package_job_snapshot().unwrap();
    assert!(
        malformed_snap
            .outcomes
            .contains_key(&canonical_malformed_pkg),
        "malformed JSON package_id outcome key diverged: {:?}",
        malformed_snap.outcomes.keys().collect::<Vec<_>>()
    );
    assert_eq!(
        get_package_job_outcome(&malformed_pkg)
            .expect("get_package_job_outcome by raw malformed JSON package_id")
            .package_id,
        canonical_malformed_pkg
    );
    let malformed_hist = get_package_job_history_outcome(&malformed_pkg, "job-malformed-r19")
        .unwrap()
        .expect("history outcome by raw malformed JSON package_id");
    assert_eq!(malformed_hist.package_id, canonical_malformed_pkg);

    // 3. Carbon F5: tampered non-array service_units row in SQLite never breaks admission check
    let tamper_conn = Connection::open(&db_path).unwrap();
    tamper_conn
        .execute("DELETE FROM package_lifecycle_jobs", [])
        .unwrap();
    tamper_conn
        .execute(
            "INSERT INTO package_lifecycle_jobs (
                package_id, job_id, action, status, started_at, service_units
            ) VALUES ('fixture', 'job-tamper-units-r19', 'update', 'updating', '2026-11-27T15:10:00Z', ?1)",
            params![r#""Bearer CANARY_TAMPER_UNITS_SVC_R19""#],
        )
        .unwrap();
    drop(tamper_conn);

    initialize_package_jobs(Connection::open(&db_path).unwrap()).unwrap();
    let admission = af_runner::acquire_lifecycle_admission_lock(Some(&root)).unwrap();
    assert!(
        !try_start_package_job(PackageJobInfo {
            job_id: "job-overlap-tamper-r19".into(),
            package_id: "fixture".into(),
            action: "update".into(),
            status: "updating".into(),
            progress: 5,
            last_line: "attempting overlap".into(),
            started_at: "2026-11-27T15:11:00Z".into(),
            expected_target_version: None,
        }),
        "active row with tampered service_units must still block overlapping start cleanly"
    );
    drop(admission);

    std::fs::remove_dir_all(root).unwrap();
}
