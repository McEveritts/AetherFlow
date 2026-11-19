//! Keep lazy-loaded locale catalogs interchangeable with the English fallback.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const CATALOGS: [(&str, &str); 6] = [
    (
        "en",
        include_str!("../../../../af-web-core/catalogs/en.json"),
    ),
    (
        "de",
        include_str!("../../../../af-web-core/catalogs/de.json"),
    ),
    (
        "dk",
        include_str!("../../../../af-web-core/catalogs/dk.json"),
    ),
    (
        "es",
        include_str!("../../../../af-web-core/catalogs/es.json"),
    ),
    (
        "fr",
        include_str!("../../../../af-web-core/catalogs/fr.json"),
    ),
    (
        "zh",
        include_str!("../../../../af-web-core/catalogs/zh.json"),
    ),
];

const INVARIANT_BRAND_KEYS: &[&str] = &[
    "Jellyfin",
    "Plex",
    "Emby",
    "Tautulli",
    "Jellystat",
    "Tailscale",
    "WireGuard",
    "Discord",
    "Slack",
    "Telegram",
    "Gotify",
    "ntfy",
    "Gemini",
    "OpenAI",
    "Claude",
    "Ollama",
    "Sonarr",
    "Radarr",
    "Prowlarr",
    "Bazarr",
    "Lidarr",
    "Readarr",
    "qBittorrent",
    "SABnzbd",
    "Grafana",
    "Prometheus",
    "AetherFlow",
    "AetherMarketplace",
    "FlowAI",
    "MagicDNS",
    "Anthropic",
    "Google",
    "LM Studio",
    "OAuth",
    "OIDC",
    "mTLS",
    "HTTP",
    "HTTPS",
    "VPN",
    "API",
    "DNS",
    "SSH",
    "JSON",
    "CSV",
    "ETag",
    "SHA-256",
    "Tus-Resumable",
    "If-Match",
    "Upload-Checksum",
    "Upload-Length",
    "Upload-Metadata",
    "Upload-Offset",
    "Upload-Path",
    "Upload-Status",
    "X-Chunk-Index",
    "X-Total-Chunks",
    "X-Upload-Conflict",
    "X-Upload-ID",
];

fn leaves(value: &Value, prefix: &str, output: &mut BTreeMap<String, String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                let key = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                leaves(value, &key, output);
            }
        }
        Value::String(value) => {
            output.insert(prefix.to_owned(), value.clone());
        }
        _ => panic!("catalog leaf must be a string: {prefix}"),
    }
}

fn placeholders(value: &str) -> BTreeSet<&str> {
    value
        .split('{')
        .skip(1)
        .map(|part| {
            part.split_once('}')
                .expect("unclosed translation placeholder")
                .0
        })
        .collect()
}

#[test]
fn all_catalogs_have_matching_keys_placeholders_and_translated_nonempty_values() {
    // Actual international names, never sentences or generic UI terminology.
    let brand_names = [
        "Anthropic Claude",
        "Google Gemini",
        "LM Studio",
        "ntfy (webhook)",
        "Tailscale Mesh VPN",
        "WireGuard (wg0) VPN",
    ];
    let mut english = BTreeMap::new();
    for (locale, json) in CATALOGS {
        let mut translated = BTreeMap::new();
        leaves(
            &serde_json::from_str::<Value>(json).unwrap(),
            "",
            &mut translated,
        );
        if locale == "en" {
            english = translated.clone();
        }
        assert_eq!(
            translated.keys().collect::<Vec<_>>(),
            english.keys().collect::<Vec<_>>(),
            "key parity: {locale}"
        );
        for (key, value) in translated {
            assert!(!value.trim().is_empty(), "empty value: {locale}/{key}");
            assert_eq!(
                placeholders(&value),
                placeholders(&english[&key]),
                "placeholder parity: {locale}/{key}"
            );
            assert!(
                locale == "en"
                    || value != english[&key]
                    || value.split_whitespace().count() < 2
                    || brand_names.contains(&value.as_str()),
                "untranslated English phrase: {locale}/{key}: {value}"
            );
        }
    }
}

#[test]
fn brand_names_and_compound_messages_preserve_canonical_spelling() {
    let forbidden = [
        "Gelée",
        "Qualle",
        "medusa",
        "果冻",
        "plexo",
        "Échelle arrière",
        "échelle arrière",
        "Haleskala",
        "Halevægt",
        "Escala de cola",
        "escala de cola",
        "尾鳞",
        "AlambreGuardia",
        "线卫",
        "Zwietracht",
        "Uenighed",
        "Discordia",
        "Discorde",
        "不和谐",
        "Locker",
        "Slap",
        "Flojo",
        "Mou",
        "松弛",
        "Zwillinge",
        "Tvillingerne",
        "Géminis",
        "Gémeaux",
        "双子座",
        "Abierto AI",
        "claudio",
        "克劳德",
        "克洛德",
        "奥拉玛",
        "奥拉马",
    ];
    let mut english = BTreeMap::new();
    leaves(
        &serde_json::from_str(CATALOGS[0].1).unwrap(),
        "",
        &mut english,
    );
    for (locale, json) in CATALOGS {
        let mut catalog = BTreeMap::new();
        leaves(&serde_json::from_str(json).unwrap(), "", &mut catalog);
        for &brand in INVARIANT_BRAND_KEYS {
            assert_eq!(
                catalog.get(brand).map(String::as_str),
                Some(brand),
                "{locale}/{brand}"
            );
        }
        for (key, value) in &catalog {
            for bad in forbidden {
                let found = if bad == "Mou" {
                    value
                        .split(|c: char| !c.is_alphabetic())
                        .any(|word| word == bad)
                } else {
                    value.contains(bad)
                };
                assert!(!found, "mistranslated brand: {locale}/{key}: {value}");
            }
            for &brand in INVARIANT_BRAND_KEYS {
                let contains_brand = |text: &str| {
                    text.match_indices(brand).any(|(at, _)| {
                        !text[..at].ends_with(|c: char| c.is_ascii_alphanumeric())
                            && !text[at + brand.len()..]
                                .starts_with(|c: char| c.is_ascii_alphanumeric())
                    })
                };
                if contains_brand(&english[key]) {
                    assert!(
                        contains_brand(value),
                        "missing canonical brand: {locale}/{key}: {value}"
                    );
                }
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum Token {
    Word(String),
    Literal(String),
    Symbol(char),
}

// A small lexer keeps comments and strings containing example code out of the
// scan. Raw strings, escaped quotes, nested comments and character literals are
// consumed as units before looking for translation calls or component props.
fn tokens(source: &str) -> Vec<Token> {
    let mut output = Vec::new();
    let bytes = source.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let rest = &source[at..];
        if rest.starts_with("//") {
            at += rest.find('\n').unwrap_or(rest.len());
        } else if rest.starts_with("/*") {
            at += 2;
            let mut depth = 1;
            while at < bytes.len() && depth > 0 {
                if source[at..].starts_with("/*") {
                    depth += 1;
                    at += 2;
                } else if source[at..].starts_with("*/") {
                    depth -= 1;
                    at += 2;
                } else {
                    at += source[at..].chars().next().unwrap().len_utf8();
                }
            }
        } else if bytes[at] == b'r' && {
            let hashes = rest[1..].bytes().take_while(|&b| b == b'#').count();
            bytes.get(at + 1 + hashes) == Some(&b'"')
        } {
            let hashes = rest[1..].bytes().take_while(|&b| b == b'#').count();
            let start = at + 2 + hashes;
            let closing = format!("\"{}", "#".repeat(hashes));
            let end = start
                + source[start..]
                    .find(&closing)
                    .expect("raw string terminator");
            output.push(Token::Literal(source[start..end].into()));
            at = end + closing.len();
        } else if bytes[at] == b'"' {
            let start = at;
            at += 1;
            while at < bytes.len() {
                match bytes[at] {
                    b'\\' => at += 2,
                    b'"' => {
                        at += 1;
                        break;
                    }
                    _ => at += 1,
                }
            }
            let literal = &source[start..at];
            output.push(Token::Literal(
                serde_json::from_str(literal)
                    .unwrap_or_else(|_| literal[1..literal.len() - 1].to_string()),
            ));
        } else if bytes[at] == b'\'' && {
            let mut chars = rest[1..].chars();
            let first = chars.next();
            if first == Some('\\') {
                chars.next();
            }
            chars.next() == Some('\'')
        } {
            at += 1;
            if bytes[at] == b'\\' {
                at += 1;
            }
            at += source[at..].chars().next().unwrap().len_utf8() + 1;
        } else if bytes[at].is_ascii_alphabetic() || bytes[at] == b'_' {
            let end = at
                + rest
                    .bytes()
                    .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                    .count();
            output.push(Token::Word(source[at..end].into()));
            at = end;
        } else {
            let ch = rest.chars().next().unwrap();
            if !ch.is_whitespace() {
                output.push(Token::Symbol(ch));
            }
            at += ch.len_utf8();
        }
    }
    output
}

fn source_keys(source: &str) -> BTreeSet<String> {
    let tokens = tokens(source);
    let mut keys = BTreeSet::new();
    for (index, token) in tokens.iter().enumerate() {
        let Token::Word(name) = token else { continue };
        if [
            "tt",
            "tt_with",
            "ui_t",
            "t",
            "t_with",
            "toast",
            "toast_with",
        ]
        .contains(&name.as_str())
            && tokens.get(index + 1) == Some(&Token::Symbol('('))
        {
            let mut argument = index + 2;
            if ["tt", "tt_with", "ui_t"].contains(&name.as_str())
                && !matches!(tokens.get(argument), Some(Token::Literal(_)))
            {
                let mut depth = 0usize;
                while let Some(token) = tokens.get(argument) {
                    match token {
                        Token::Symbol(',') if depth == 0 => {
                            argument += 1;
                            break;
                        }
                        Token::Symbol(')') if depth == 0 => break,
                        Token::Symbol('(' | '[' | '{') => depth += 1,
                        Token::Symbol(')' | ']' | '}') => depth -= 1,
                        _ => {}
                    }
                    argument += 1;
                }
            }
            if let Some(Token::Literal(key)) = tokens.get(argument) {
                if !key.is_empty() {
                    keys.insert(key.clone());
                }
            }
        }
        if name == "EmptyState" && index > 0 && tokens[index - 1] == Token::Symbol('<') {
            let mut at = index + 1;
            while at + 2 < tokens.len() && tokens[at] != Token::Symbol('>') {
                if matches!(&tokens[at], Token::Word(name) if name == "title" || name == "description")
                    && tokens[at + 1] == Token::Symbol('=')
                {
                    if let Token::Literal(key) = &tokens[at + 2] {
                        if !key.is_empty() {
                            keys.insert(key.clone());
                        }
                    }
                }
                at += 1;
            }
        }
    }
    keys
}

#[test]
fn static_translation_keys_exist_in_the_english_catalog() {
    fn scan(path: &std::path::Path, catalog: &BTreeMap<String, String>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                scan(&path, catalog);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                for key in source_keys(&std::fs::read_to_string(&path).unwrap()) {
                    assert!(
                        catalog.contains_key(&key),
                        "missing static key in {}: {key}",
                        path.display()
                    );
                }
            }
        }
    }
    let mut catalog = BTreeMap::new();
    leaves(
        &serde_json::from_str(CATALOGS[0].1).unwrap(),
        "",
        &mut catalog,
    );
    for (key, value) in &catalog {
        if key.contains('{') {
            assert_eq!(
                placeholders(key),
                placeholders(value),
                "placeholders changed in {key}"
            );
        }
    }
    let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    scan(&crate_root.join("src"), &catalog);
    scan(&crate_root.join("../af-web-ui/src"), &catalog);
}

#[test]
fn source_scanner_handles_literals_comments_and_component_attributes() {
    let keys = source_keys(
        r###"
        // tt(context, "not a key")
        /* context.t("not a key either"); /* nested */ */
        let sample = "tt(context, \"sample\")";
        tt(context, "Quoted \"label\"");
        tt_with(context, r#"Raw label"#, &[]);
        context.t("Context key"); context.t_with("Parameter key", &[]);
        ui_t("UI key"); context.toast("Toast key", false);
        <EmptyState title="Empty title" description="Empty description" />
        tt(context, &dynamic_key);
    "###,
    );
    assert_eq!(
        keys,
        [
            "Quoted \"label\"",
            "Raw label",
            "Context key",
            "Parameter key",
            "UI key",
            "Toast key",
            "Empty title",
            "Empty description"
        ]
        .map(String::from)
        .into()
    );
}
