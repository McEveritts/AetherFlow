use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const DESIGN_DOC_REF: &str = "docs/design-system.md";

/// Shrinking Commit-1 allowlist for Tailwind blur classes in Rust templates.
/// Commit 2 removes `backdrop-blur` from `shell.rs` and `grid.rs` and clears this list.
const BLUR_ALLOWLIST: &[&str] = &[];

/// Shrinking Commit-1 allowlist for `<dialog class="af-modal glass-card">`.
/// Commit 2 removes `glass-card` from `Modal` in `primitives.rs` and clears this list.
const OVERLAY_CARD_ALLOWLIST: &[&str] = &[];

/// Shrinking per-commit ratchet for legacy `.glass-*`, `.obs-tab-pill`, and
/// `.obs-telemetry-surface` template classes across `af-web-ui` and `af-web-app`.
/// Commit 1 locks to the exact 61 currently unmigrated files; Commits 2–4 shrink
/// this list to empty, and Commit 5 deletes the allowlist completely.
const LEGACY_CLASS_ALLOWLIST: &[&str] = &[
    "crates/af-web-app/src/tabs/ai_chat.rs",
    "crates/af-web-app/src/tabs/cluster/grants.rs",
    "crates/af-web-app/src/tabs/cluster/mod.rs",
    "crates/af-web-app/src/tabs/cluster/pairing.rs",
    "crates/af-web-app/src/tabs/cluster/peers.rs",
    "crates/af-web-app/src/tabs/cluster/storage.rs",
    "crates/af-web-app/src/tabs/cluster/transcode.rs",
    "crates/af-web-app/src/tabs/fileshare/local_storage.rs",
    "crates/af-web-app/src/tabs/fileshare/policy_audit.rs",
    "crates/af-web-app/src/tabs/fileshare/shares.rs",
    "crates/af-web-app/src/tabs/mcbrowser/actions.rs",
    "crates/af-web-app/src/tabs/mcbrowser/editor.rs",
    "crates/af-web-app/src/tabs/mcbrowser/events.rs",
    "crates/af-web-app/src/tabs/mcbrowser/helpers.rs",
    "crates/af-web-app/src/tabs/mcbrowser/mod.rs",
    "crates/af-web-app/src/tabs/mcbrowser/policy_audit.rs",
    "crates/af-web-app/src/tabs/mcbrowser/toolbar.rs",
    "crates/af-web-app/src/tabs/mcbrowser/transfers.rs",
    "crates/af-web-app/src/tabs/mediaflow.rs",
    "crates/af-web-app/src/tabs/network/mod.rs",
    "crates/af-web-app/src/tabs/network/tailscale.rs",
    "crates/af-web-app/src/tabs/network/tailscale_ingress.rs",
    "crates/af-web-app/src/tabs/network/wireguard.rs",
    "crates/af-web-app/src/tabs/streaming/administration.rs",
    "crates/af-web-app/src/tabs/streaming/analytics.rs",
    "crates/af-web-app/src/tabs/streaming/connections.rs",
    "crates/af-web-app/src/tabs/streaming/history.rs",
    "crates/af-web-app/src/tabs/streaming/imports.rs",
    "crates/af-web-app/src/tabs/streaming/live.rs",
    "crates/af-web-app/src/tabs/streaming/mod.rs",
    "crates/af-web-app/src/tabs/streaming/portability.rs",
    "crates/af-web-app/src/tabs/streaming/reconciliation.rs",
];

fn frontend_rs_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("frontend-rs root")
        .to_path_buf()
}

fn read_input_css() -> String {
    let path = frontend_rs_root().join("styles/input.css");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

/// Strips CSS `/* ... */` block comments while preserving newlines so line numbers
/// remain exact for diagnostics, and respecting single/double quoted strings.
fn strip_css_comments(css: &str) -> String {
    let bytes = css.as_bytes();
    let mut out = String::with_capacity(css.len());
    let mut i = 0;
    let mut in_string: Option<u8> = None;

    while i < bytes.len() {
        let b = bytes[i];
        if let Some(quote) = in_string {
            out.push(b as char);
            if b == b'\\' && i + 1 < bytes.len() {
                out.push(bytes[i + 1] as char);
                i += 2;
                continue;
            }
            if b == quote {
                in_string = None;
            }
            i += 1;
            continue;
        }

        if b == b'"' || b == b'\'' {
            in_string = Some(b);
            out.push(b as char);
            i += 1;
            continue;
        }

        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            out.push(' ');
            out.push(' ');
            i += 2;
            while i < bytes.len() {
                if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    break;
                }
                if bytes[i] == b'\n' {
                    out.push('\n');
                } else {
                    out.push(' ');
                }
                i += 1;
            }
            continue;
        }

        out.push(b as char);
        i += 1;
    }

    out
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", dir.display()))
        .map(|entry| entry.expect("dir entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn all_template_rs_files() -> Vec<(String, PathBuf)> {
    let root = frontend_rs_root();
    let mut paths = Vec::new();
    collect_rs_files(&root.join("crates/af-web-ui/src"), &mut paths);
    collect_rs_files(&root.join("crates/af-web-app/src"), &mut paths);
    let mut normalized: Vec<(String, PathBuf)> = paths
        .into_iter()
        .map(|path| {
            let rel = path
                .strip_prefix(&root)
                .expect("relative to frontend-rs")
                .to_string_lossy()
                .replace('\\', "/");
            (rel, path)
        })
        .collect();
    normalized.sort_by(|a, b| a.0.cmp(&b.0));
    normalized
}

fn split_top_level_commas(input: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut paren_depth: usize = 0;
    let mut bracket_depth: usize = 0;
    let mut in_string: Option<char> = None;
    let mut escaped = false;

    for (idx, ch) in input.char_indices() {
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                in_string = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => in_string = Some(ch),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if paren_depth == 0 && bracket_depth == 0 => {
                parts.push(&input[start..idx]);
                start = idx + 1;
            }
            _ => {}
        }
    }
    parts.push(&input[start..]);
    parts
}

fn extract_block_bodies(css: &str, target_selector: &str) -> Vec<String> {
    let mut bodies = Vec::new();
    let mut depth: usize = 0;
    let mut header = String::new();
    let mut current_body = String::new();
    let mut capturing = false;
    let mut capture_depth: usize = 0;
    let mut in_string: Option<char> = None;
    let mut escaped = false;

    for ch in css.chars() {
        if let Some(quote) = in_string {
            if capturing {
                current_body.push(ch);
            } else if depth == 0 {
                header.push(ch);
            }
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                in_string = None;
            }
            continue;
        }

        if ch == '"' || ch == '\'' {
            in_string = Some(ch);
            if capturing {
                current_body.push(ch);
            } else if depth == 0 {
                header.push(ch);
            }
            continue;
        }

        match ch {
            '{' => {
                depth += 1;
                if depth == 1 {
                    let normalized = header
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    let matches = split_top_level_commas(&normalized)
                        .into_iter()
                        .any(|sel| sel.trim() == target_selector);
                    if matches {
                        capturing = true;
                        capture_depth = depth;
                        current_body.clear();
                    }
                    header.clear();
                } else if capturing {
                    current_body.push(ch);
                }
            }
            '}' => {
                if capturing && depth == capture_depth {
                    bodies.push(std::mem::take(&mut current_body));
                    capturing = false;
                } else if capturing {
                    current_body.push(ch);
                }
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    header.clear();
                }
            }
            ';' => {
                if capturing {
                    current_body.push(ch);
                } else if depth == 0 {
                    header.clear();
                }
            }
            _ => {
                if capturing {
                    current_body.push(ch);
                } else if depth == 0 {
                    header.push(ch);
                }
            }
        }
    }

    bodies
}

fn extract_af_tokens(block_body: &str) -> BTreeSet<String> {
    let mut tokens = BTreeSet::new();
    for raw_decl in block_body.split(';') {
        let decl = raw_decl.trim();
        if let Some((name, _value)) = decl.split_once(':') {
            let prop = name.trim();
            if prop.starts_with("--af-")
                && prop
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            {
                tokens.insert(prop.to_string());
            }
        }
    }
    tokens
}

fn selector_starts_with_class(selector: &str, class_name: &str) -> bool {
    if let Some(rest) = selector.strip_prefix(class_name) {
        rest.is_empty()
            || rest.starts_with(':')
            || rest.starts_with('.')
            || rest.starts_with('[')
            || rest.starts_with(' ')
            || rest.starts_with('>')
            || rest.starts_with('+')
            || rest.starts_with('~')
    } else {
        false
    }
}

fn line_has_token_boundary(line: &str, needle: &str) -> bool {
    let bytes = line.as_bytes();
    let mut start = 0;
    while let Some(offset) = line[start..].find(needle) {
        let idx = start + offset;
        let end = idx + needle.len();
        let prev_ok = idx == 0 || !is_css_ident_char(bytes[idx - 1]);
        let next_ok = end == bytes.len() || !is_css_ident_char(bytes[end]);
        if prev_ok && next_ok {
            return true;
        }
        start = idx + 1;
    }
    false
}

fn is_css_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

#[test]
fn css_forbids_glass_and_legacy_atmosphere_rules() {
    let raw_css = read_input_css();
    let css = strip_css_comments(&raw_css);
    let mut violations = Vec::new();

    let forbidden_patterns: &[(&str, &str, &str)] = &[
        (
            "no-backdrop-filter",
            "backdrop-filter",
            "Use opaque semantic surfaces (--af-surface-card, --af-surface-overlay, --af-bg-chrome)",
        ),
        (
            "no-webkit-backdrop-filter",
            "-webkit-backdrop-filter",
            "Use opaque semantic surfaces (--af-surface-card, --af-surface-overlay, --af-bg-chrome)",
        ),
        (
            "no-mask-composite-rim",
            "mask-composite",
            "Use flat 1px semantic borders (--af-border-card, --af-border-overlay)",
        ),
        (
            "no-webkit-mask-composite-rim",
            "-webkit-mask-composite",
            "Use flat 1px semantic borders (--af-border-card, --af-border-overlay)",
        ),
        (
            "no-chromatic-tokens",
            "--obs-chromatic-",
            "Use flat semantic border/surface tokens (--af-border-card, --af-surface-card)",
        ),
        (
            "no-specular-tokens",
            "--obs-specular-",
            "Use flat semantic border tokens (--af-border-card, --af-border-control)",
        ),
        (
            "no-card-lift-token",
            "--obs-card-lift",
            "Default .af-card is static; opt into .af-card-interactive for clickable tiles",
        ),
        (
            "no-card-lift-attr",
            "data-card-lift",
            "Card hover lift is retired; remove data-card-lift selectors",
        ),
        (
            "no-aurora-opacity-attr",
            "data-aurora-opacity",
            "Legacy aurora background is retired; use flat --af-bg-canvas",
        ),
        (
            "no-aurora-animation-attr",
            "data-aurora-animation",
            "Legacy aurora animation is retired; use flat --af-bg-canvas",
        ),
        (
            "no-grain-attr",
            "data-grain",
            "Legacy tactile grain overlay is retired; use flat --af-bg-canvas",
        ),
        (
            "no-aurora-keyframes",
            "obs-aurora-shift",
            "Legacy aurora animation is retired; delete obs-aurora-shift keyframes",
        ),
        (
            "no-fractal-noise",
            "fractalNoise",
            "Legacy SVG noise overlay is retired; use solid --af-bg-canvas",
        ),
        (
            "no-primary-hover-scale",
            "scale3d(1.025",
            "Use flat fill hover (--af-accent-bg-hover) on .af-btn-primary without scale transforms",
        ),
        (
            "no-legacy-light-class-selector",
            ".light ",
            "Scope all light-theme overrides exclusively to html[data-theme=\"light\"]",
        ),
        (
            "no-legacy-html-light-selector",
            "html.light",
            "Scope all light-theme overrides exclusively to html[data-theme=\"light\"]",
        ),
        (
            "no-raw-white-hairline-06",
            "rgba(255, 255, 255, 0.06)",
            "Use var(--af-border-hairline) instead of hardcoded dark-only white hairlines",
        ),
        (
            "no-raw-white-hairline-07",
            "rgba(255, 255, 255, 0.07)",
            "Use var(--af-border-hairline) instead of hardcoded dark-only white hairlines",
        ),
        (
            "no-raw-white-hairline-06-compact",
            "rgba(255,255,255,0.06)",
            "Use var(--af-border-hairline) instead of hardcoded dark-only white hairlines",
        ),
        (
            "no-raw-white-hairline-07-compact",
            "rgba(255,255,255,0.07)",
            "Use var(--af-border-hairline) instead of hardcoded dark-only white hairlines",
        ),
        (
            "no-dead-obsidian-classes",
            ".glass-panel",
            "Use Tier 3 .af-popover / .af-modal or Tier 2 .af-card",
        ),
        (
            "no-dead-obsidian-classes",
            ".glass-hero",
            "Use Tier 2 .af-card or Tier 1 .af-canvas-section",
        ),
        (
            "no-dead-obsidian-classes",
            ".obs-sidebar-surface",
            "Use opaque .af-sidebar chrome",
        ),
        (
            "no-dead-obsidian-classes",
            ".obs-metric-strip",
            "Use .af-hairline-grid",
        ),
        (
            "no-dead-obsidian-classes",
            ".obs-vitals-grid",
            "Use .af-hairline-grid",
        ),
        (
            "no-dead-nextjs-root",
            "#__next",
            "Next.js root selector is obsolete in the Rust WASM SPA",
        ),
        (
            "no-dead-prototype-scroller",
            ".prototype-scroller",
            "Use .obs-scroller",
        ),
    ];

    for (idx, line) in css.lines().enumerate() {
        let line_no = idx + 1;
        for &(rule, pattern, replacement) in forbidden_patterns {
            if line.contains(pattern) {
                violations.push(format!(
                    "[{rule}] frontend-rs/styles/input.css:{line_no} matched `{pattern}` — {replacement} (see {DESIGN_DOC_REF})"
                ));
            }
        }
    }

    // Verify canonical flat component classes are declared inside `@layer components`
    // and never declared as unlayered base component rules outside `@layer components`.
    let required_layered_classes = [
        ".af-card",
        ".af-btn",
        ".af-input",
        ".af-canvas-section",
        ".af-modal",
    ];
    let mut found_in_layer: BTreeSet<&str> = BTreeSet::new();
    let mut depth: usize = 0;
    let mut layer_components_depth: Option<usize> = None;
    let mut header = String::new();
    let mut header_start_line: usize = 1;
    let mut line_no: usize = 1;
    let mut in_string: Option<char> = None;
    let mut escaped = false;

    for ch in css.chars() {
        if ch == '\n' {
            line_no += 1;
        }
        if let Some(quote) = in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == quote {
                in_string = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            in_string = Some(ch);
            continue;
        }

        match ch {
            '{' => {
                depth += 1;
                let normalized = header
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                if normalized == "@layer components" && layer_components_depth.is_none() {
                    layer_components_depth = Some(depth);
                } else if !normalized.starts_with('@') {
                    let inside_components = layer_components_depth.is_some();
                    for sel in split_top_level_commas(&normalized)
                        .into_iter()
                        .map(str::trim)
                    {
                        for &cls in &required_layered_classes {
                            if selector_starts_with_class(sel, cls) {
                                if inside_components {
                                    found_in_layer.insert(cls);
                                } else {
                                    violations.push(format!(
                                        "[unlayered-component-rule] frontend-rs/styles/input.css:{header_start_line} declares `{sel}` outside `@layer components` — move base `{cls}` rules into `@layer components` so Tailwind utilities compose cleanly (see {DESIGN_DOC_REF})"
                                    ));
                                }
                            }
                        }
                    }
                }
                header.clear();
            }
            '}' => {
                if layer_components_depth == Some(depth) {
                    layer_components_depth = None;
                }
                depth = depth.saturating_sub(1);
                header.clear();
            }
            ';' => {
                header.clear();
            }
            _ => {
                if header.trim().is_empty() && !ch.is_whitespace() {
                    header_start_line = line_no;
                }
                header.push(ch);
            }
        }
    }

    for &cls in &required_layered_classes {
        if !found_in_layer.contains(cls) {
            violations.push(format!(
                "[missing-layered-component] frontend-rs/styles/input.css is missing `{cls}` inside `@layer components` — define `{cls}` inside `@layer components` (see {DESIGN_DOC_REF})"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "Flat design CSS contract violations ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

#[test]
fn semantic_tokens_have_complete_dark_light_parity() {
    let css = strip_css_comments(&read_input_css());

    let root_bodies = extract_block_bodies(&css, ":root");
    let light_bodies = extract_block_bodies(&css, r#"html[data-theme="light"]"#);

    assert!(
        !root_bodies.is_empty(),
        "[semantic-token-dark-light-parity] frontend-rs/styles/input.css is missing a `:root` semantic token block (see {DESIGN_DOC_REF})"
    );
    assert_eq!(
        light_bodies.len(),
        1,
        "[semantic-token-dark-light-parity] frontend-rs/styles/input.css must define exactly one `html[data-theme=\"light\"]` semantic token block, found {} (see {DESIGN_DOC_REF})",
        light_bodies.len()
    );

    let mut dark_tokens = BTreeSet::new();
    for body in &root_bodies {
        dark_tokens.extend(extract_af_tokens(body));
    }
    let mut light_tokens = BTreeSet::new();
    for body in &light_bodies {
        light_tokens.extend(extract_af_tokens(body));
    }

    assert!(
        dark_tokens.len() >= 46,
        "[semantic-token-dark-light-parity] `:root` defines only {} `--af-*` tokens; expected all >= 46 Section A semantic tokens (see {DESIGN_DOC_REF})",
        dark_tokens.len()
    );

    let missing_in_light: Vec<&String> = dark_tokens.difference(&light_tokens).collect();
    let missing_in_dark: Vec<&String> = light_tokens.difference(&dark_tokens).collect();

    let mut violations = Vec::new();
    for token in missing_in_light {
        violations.push(format!(
            "[semantic-token-dark-light-parity] token `{token}` defined in `:root` is missing from `html[data-theme=\"light\"]` — add its WCAG AA light-theme counterpart in frontend-rs/styles/input.css (see {DESIGN_DOC_REF})"
        ));
    }
    for token in missing_in_dark {
        violations.push(format!(
            "[semantic-token-dark-light-parity] token `{token}` defined in `html[data-theme=\"light\"]` is missing from `:root` — add its WCAG AA dark-theme counterpart in frontend-rs/styles/input.css (see {DESIGN_DOC_REF})"
        ));
    }

    assert!(
        violations.is_empty(),
        "Semantic token parity violations ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

#[test]
fn rust_templates_forbid_blur_and_dead_classes() {
    let dead_classes: &[(&str, &str)] = &[
        ("glass-panel", "Use Tier 3 .af-popover / .af-modal or Tier 2 .af-card"),
        ("glass-hero", "Use Tier 2 .af-card or Tier 1 .af-canvas-section"),
        ("obs-sidebar-surface", "Use opaque .af-sidebar chrome"),
        ("obs-metric-strip", "Use .af-hairline-grid"),
        ("obs-vitals-grid", "Use .af-hairline-grid"),
    ];
    let blur_patterns = ["backdrop-blur", "backdrop-saturate"];

    let blur_allowlist: BTreeSet<&str> = BLUR_ALLOWLIST.iter().copied().collect();
    let mut blur_found_files: BTreeSet<String> = BTreeSet::new();
    let mut violations = Vec::new();

    for (rel, path) in all_template_rs_files() {
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        for (idx, line) in src.lines().enumerate() {
            let line_no = idx + 1;
            for &(dead, replacement) in dead_classes {
                if line_has_token_boundary(line, dead) {
                    violations.push(format!(
                        "[no-dead-obsidian-class] frontend-rs/{rel}:{line_no} uses retired `{dead}` — {replacement} (see {DESIGN_DOC_REF})"
                    ));
                }
            }
            for &blur in &blur_patterns {
                if line.contains(blur) {
                    blur_found_files.insert(rel.clone());
                    if !blur_allowlist.contains(rel.as_str()) {
                        violations.push(format!(
                            "[no-template-backdrop-blur] frontend-rs/{rel}:{line_no} uses `{blur}` — replace with opaque `bg-[var(--af-bg-chrome)]` or `.af-surface-overlay` (see {DESIGN_DOC_REF})"
                        ));
                    }
                }
            }
        }
    }

    for &allowed in BLUR_ALLOWLIST {
        if !blur_found_files.contains(allowed) {
            violations.push(format!(
                "[stale-blur-allowlist] `{allowed}` in BLUR_ALLOWLIST no longer uses `backdrop-blur` — remove it from BLUR_ALLOWLIST in frontend-rs/crates/af-web-ui/tests/design_contract.rs to tighten the CI ratchet (see {DESIGN_DOC_REF})"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "Rust template blur/dead-class contract violations ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

#[test]
fn legacy_glass_class_ratchet_matches_allowlist() {
    let legacy_replacements: &[(&str, &str)] = &[
        ("glass-button-primary", ".af-btn-primary"),
        ("glass-button", ".af-btn"),
        ("glass-card", ".af-card (or .af-card-interactive / .af-surface-inset)"),
        ("glass-input", ".af-input"),
        ("obs-tab-pill", ".af-tab-pill / .af-tab-pill-active"),
        ("obs-telemetry-surface", ".af-canvas-section"),
    ];

    // Confirm allowlist itself stays strictly sorted and deduplicated.
    for pair in LEGACY_CLASS_ALLOWLIST.windows(2) {
        assert!(
            pair[0] < pair[1],
            "[allowlist-order] LEGACY_CLASS_ALLOWLIST must be strictly sorted and deduplicated (`{}` >= `{}`)",
            pair[0],
            pair[1]
        );
    }

    let allowlist: BTreeSet<&str> = LEGACY_CLASS_ALLOWLIST.iter().copied().collect();
    let mut hits_by_file: BTreeMap<String, Vec<(usize, &str, &str)>> = BTreeMap::new();

    for (rel, path) in all_template_rs_files() {
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        for (idx, line) in src.lines().enumerate() {
            let line_no = idx + 1;
            for &(legacy, replacement) in legacy_replacements {
                if line.contains(legacy) {
                    hits_by_file
                        .entry(rel.clone())
                        .or_default()
                        .push((line_no, legacy, replacement));
                }
            }
        }
    }

    let mut violations = Vec::new();
    for (rel, hits) in &hits_by_file {
        if !allowlist.contains(rel.as_str()) {
            for &(line_no, legacy, replacement) in hits {
                violations.push(format!(
                    "[legacy-glass-class-ratchet] frontend-rs/{rel}:{line_no} uses unlisted legacy class `{legacy}` — migrate to {replacement} (see {DESIGN_DOC_REF})"
                ));
            }
        }
    }

    for &allowed in LEGACY_CLASS_ALLOWLIST {
        if !hits_by_file.contains_key(allowed) {
            violations.push(format!(
                "[stale-legacy-allowlist] `{allowed}` in LEGACY_CLASS_ALLOWLIST has zero remaining legacy classes — remove it from LEGACY_CLASS_ALLOWLIST in frontend-rs/crates/af-web-ui/tests/design_contract.rs to lock the ratchet (see {DESIGN_DOC_REF})"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "Legacy glass class ratchet violations ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
}

#[test]
fn overlays_never_combine_with_card_classes() {
    let strict_overlays = ["af-popover", "af-toast"];
    let allowlisted_overlays = ["af-modal", "af-drawer"];
    let card_classes = ["glass-card", "af-card"];

    let allowlist: BTreeSet<&str> = OVERLAY_CARD_ALLOWLIST.iter().copied().collect();
    let mut allowlist_hits: BTreeSet<String> = BTreeSet::new();
    let mut violations = Vec::new();

    for (rel, path) in all_template_rs_files() {
        let src = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
        for (idx, line) in src.lines().enumerate() {
            let line_no = idx + 1;
            let matched_card = card_classes
                .iter()
                .copied()
                .find(|card| line_has_token_boundary(line, card));
            let Some(card) = matched_card else {
                continue;
            };

            for &overlay in &strict_overlays {
                if line_has_token_boundary(line, overlay) {
                    violations.push(format!(
                        "[overlay-card-separation] frontend-rs/{rel}:{line_no} combines Tier 3 `{overlay}` with Tier 2 `{card}` — use `{overlay}` alone for opaque floating surfaces (see {DESIGN_DOC_REF})"
                    ));
                }
            }

            for &overlay in &allowlisted_overlays {
                if line_has_token_boundary(line, overlay) {
                    allowlist_hits.insert(rel.clone());
                    if !allowlist.contains(rel.as_str()) {
                        violations.push(format!(
                            "[overlay-card-separation] frontend-rs/{rel}:{line_no} combines Tier 3 `{overlay}` with Tier 2 `{card}` — use `{overlay}` alone for opaque floating surfaces (see {DESIGN_DOC_REF})"
                        ));
                    }
                }
            }
        }
    }

    for &allowed in OVERLAY_CARD_ALLOWLIST {
        if !allowlist_hits.contains(allowed) {
            violations.push(format!(
                "[stale-overlay-card-allowlist] `{allowed}` in OVERLAY_CARD_ALLOWLIST no longer combines `.af-modal` with `.glass-card`/`.af-card` — remove it from OVERLAY_CARD_ALLOWLIST in frontend-rs/crates/af-web-ui/tests/design_contract.rs (see {DESIGN_DOC_REF})"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "Overlay/card separation contract violations ({}):\n{}",
        violations.len(),
        violations.join("\n")
    );
}
