use serde_json::Value;
use std::sync::LazyLock;
#[cfg(target_arch = "wasm32")]
use std::{collections::BTreeMap, sync::RwLock};

pub const LOCALES: [&str; 6] = ["en", "de", "dk", "es", "fr", "zh"];

/// Catalog identifiers are stable application preferences; document language
/// tags follow BCP 47 (Danish uses `da`, even though its catalog is `dk`).
pub fn bcp47_tag(locale: &str) -> &'static str {
    match locale {
        "dk" => "da",
        "de" => "de",
        "es" => "es",
        "fr" => "fr",
        "zh" => "zh",
        _ => "en",
    }
}
#[cfg(not(target_arch = "wasm32"))]
static CATALOGS: LazyLock<Vec<Value>> = LazyLock::new(|| {
    [
        include_str!("../catalogs/en.json"),
        include_str!("../catalogs/de.json"),
        include_str!("../catalogs/dk.json"),
        include_str!("../catalogs/es.json"),
        include_str!("../catalogs/fr.json"),
        include_str!("../catalogs/zh.json"),
    ]
    .iter()
    .map(|s| serde_json::from_str(s).expect("validated embedded catalog"))
    .collect()
});

// English is the immediate fallback. Other locales stay outside the WASM
// bundle and are shared by all consumers after the first successful fetch.
#[cfg(target_arch = "wasm32")]
static EN_CATALOG: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("../catalogs/en.json")).expect("validated English catalog")
});
#[cfg(target_arch = "wasm32")]
static LOADED_CATALOGS: LazyLock<RwLock<BTreeMap<String, Value>>> =
    LazyLock::new(|| RwLock::new(BTreeMap::new()));

pub async fn ensure_locale_loaded(locale: &str) -> Result<bool, String> {
    if !LOCALES.contains(&locale) {
        return Err(format!("Unsupported locale: {locale}"));
    }
    #[cfg(target_arch = "wasm32")]
    {
        if locale == "en"
            || LOADED_CATALOGS
                .read()
                .map_err(|_| "Locale cache unavailable")?
                .contains_key(locale)
        {
            return Ok(false);
        }
        let window = web_sys::window().ok_or_else(|| "Browser window unavailable".to_string())?;
        let init = web_sys::RequestInit::new();
        init.set_cache(web_sys::RequestCache::NoStore);
        let resp_val = wasm_bindgen_futures::JsFuture::from(
            window.fetch_with_str_and_init(&format!("/locales/{locale}.json"), &init),
        )
        .await
        .map_err(|err| format!("Could not load {locale} catalog: {err:?}"))?;
        let response: web_sys::Response = wasm_bindgen::JsCast::dyn_into(resp_val)
            .map_err(|_| format!("Invalid fetch response for {locale} catalog"))?;
        if response.status() != 200 {
            return Err(format!(
                "Could not load {locale} catalog: HTTP {}",
                response.status()
            ));
        }
        let text_promise = response
            .text()
            .map_err(|err| format!("Could not read {locale} catalog body: {err:?}"))?;
        let text_val = wasm_bindgen_futures::JsFuture::from(text_promise)
            .await
            .map_err(|err| format!("Could not read {locale} catalog: {err:?}"))?;
        let text = text_val
            .as_string()
            .ok_or_else(|| format!("Invalid UTF-8 string in {locale} catalog"))?;
        let catalog: Value = serde_json::from_str(&text)
            .map_err(|error| format!("Invalid {locale} catalog: {error}"))?;
        if !catalog.is_object() {
            return Err(format!("Invalid {locale} catalog: expected a JSON object"));
        }
        let mut loaded = LOADED_CATALOGS
            .write()
            .map_err(|_| "Locale cache unavailable")?;
        // Two callers can finish the same fetch; only the first changes cache.
        if loaded.contains_key(locale) {
            return Ok(false);
        }
        loaded.insert(locale.to_string(), catalog);
        Ok(true)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Ok(false)
    }
}

fn lookup<'a>(catalog: &'a Value, key: &str) -> Option<&'a str> {
    catalog.get(key).and_then(Value::as_str).or_else(|| {
        key.split('.')
            .try_fold(catalog, |v, k| v.get(k))
            .and_then(Value::as_str)
    })
}
pub fn translate(locale: &str, key: &str) -> String {
    #[cfg(target_arch = "wasm32")]
    {
        if let Ok(loaded) = LOADED_CATALOGS.read() {
            if let Some(text) = loaded.get(locale).and_then(|catalog| lookup(catalog, key)) {
                return text.to_string();
            }
        }
        lookup(&EN_CATALOG, key).unwrap_or(key).to_string()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let index = LOCALES.iter().position(|l| *l == locale).unwrap_or(0);
        lookup(&CATALOGS[index], key)
            .or_else(|| lookup(&CATALOGS[0], key))
            .unwrap_or(key)
            .into()
    }
}
pub fn translate_with(locale: &str, key: &str, params: &[(&str, &str)]) -> String {
    params
        .iter()
        .fold(translate(locale, key), |text, (key, value)| {
            text.replace(&format!("{{{key}}}"), value)
        })
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn catalog_locales_map_to_valid_document_language_tags() {
        assert_eq!(bcp47_tag("dk"), "da");
        for locale in ["en", "de", "es", "fr", "zh"] {
            assert_eq!(bcp47_tag(locale), locale);
        }
        assert_eq!(bcp47_tag(""), "en");
        assert_eq!(bcp47_tag("unknown"), "en");
    }

    #[test]
    fn public_routes_and_onboarding_preserve_english_acceptance_selectors() {
        for (key, expected) in [
            ("Login.accessNexus", "Access Nexus"),
            ("Login.createAdmin", "Create Admin Account"),
            ("Login.chooseUsername", "Choose a Username"),
            ("Login.choosePassword", "Choose a Password (min 8 chars)"),
            ("Login.createEnter", "Create Account & Enter"),
            ("Login.username", "Username"),
            ("Login.password", "Password"),
            ("Login.unlock", "Unlock the Aether"),
            ("Login.google", "Continue with Google OAuth"),
            ("Routes.consentHeading", "Operator Action Required"),
            ("Consent.scopes", "Requested Scopes"),
            ("Consent.grant", "Grant Authorization"),
            ("Consent.deny", "Deny Access"),
            ("Routes.shareHeading", "Shared Resource"),
            ("Share.passwordRequired", "Password required"),
            ("Share.password", "Share password"),
            ("Share.unlock", "Unlock share"),
            ("Share.preview", "Preview"),
            ("Common.download", "Download"),
            ("Onboarding.title", "Welcome to AetherFlow"),
            ("Onboarding.continue", "Continue"),
            ("Onboarding.enterDashboard", "Enter Dashboard"),
            ("Shell.skipToContent", "Skip to content"),
            ("Common.closeDialog", "Close dialog"),
            ("Common.cancel", "Cancel"),
            ("Common.confirm", "Confirm"),
        ] {
            assert_eq!(translate("en", key), expected);
            for locale in LOCALES {
                assert_ne!(translate(locale, key), key, "{locale}: {key}");
            }
        }
    }

    fn leaf_keys(catalog: &Value, prefix: &str) -> BTreeSet<String> {
        match catalog {
            Value::Object(entries) => {
                assert!(!entries.is_empty(), "Empty section: {prefix}");
                entries
                    .iter()
                    .flat_map(|(key, value)| {
                        let path = if prefix.is_empty() {
                            key.clone()
                        } else {
                            format!("{prefix}.{key}")
                        };
                        leaf_keys(value, &path)
                    })
                    .collect()
            }
            Value::String(text) => {
                assert!(!text.trim().is_empty(), "Empty translation: {prefix}");
                BTreeSet::from([prefix.to_string()])
            }
            _ => panic!("Translation must be a nonempty string: {prefix}"),
        }
    }

    #[test]
    fn all_six_catalogs_have_exact_nonempty_leaf_key_parity() {
        let english = leaf_keys(&CATALOGS[0], "");
        assert!(
            english.len() >= 1650,
            "The unified shell, tab, and UI catalog must stay complete"
        );
        for (locale, catalog) in LOCALES.iter().zip(CATALOGS.iter()) {
            assert_eq!(leaf_keys(catalog, ""), english, "Key mismatch in {locale}");
        }
    }

    #[test]
    fn interpolation_placeholders_match_in_every_locale() {
        fn placeholders(text: &str) -> BTreeSet<&str> {
            text.split('{')
                .skip(1)
                .filter_map(|part| part.split_once('}').map(|(key, _)| key))
                .collect()
        }
        for key in leaf_keys(&CATALOGS[0], "") {
            let expected = placeholders(lookup(&CATALOGS[0], &key).unwrap());
            for (locale, catalog) in LOCALES.iter().zip(CATALOGS.iter()) {
                assert_eq!(
                    placeholders(lookup(catalog, &key).unwrap()),
                    expected,
                    "{locale}: {key}"
                );
            }
        }
        assert_eq!(
            translate_with("en", "McBrowser.transfers", &[("count", "3")]),
            "Transfers (3)"
        );
        assert_eq!(
            translate_with("fr", "McBrowser.transfers", &[("count", "3")]),
            "Transferts (3)"
        );
    }

    #[test]
    fn secondary_tab_translations_preserve_english_acceptance_headings() {
        for (key, label) in [
            (
                "Settings.navigationLocalization",
                "Navigation & Localization",
            ),
            ("Settings.systemUpdates", "System Updates"),
            ("Overview.liveTelemetry", "Live Telemetry"),
            ("Services.corePlatform", "Core Platform"),
            ("Fileshare.localStorage", "Local Storage"),
            ("Fileshare.publicShareLinks", "Public Share Links"),
            ("Common.saveChanges", "Save changes"),
        ] {
            assert_eq!(translate("en", key), label);
        }
        assert_eq!(
            translate("fr", "Settings.navigationLocalization"),
            "Navigation et localisation"
        );
        for locale in LOCALES {
            for key in [
                "Settings.generalLocalization",
                "Settings.hapticFeedback",
                "McBrowser.newFolder",
                "Overview.cpuUtilization",
                "Services.managedApplications",
                "Marketplace.categoryCloud",
                "Fileshare.usedCapacity",
            ] {
                assert_ne!(translate(locale, key), key, "{locale}");
            }
        }
    }

    #[test]
    fn catalogs_are_valid_and_nonempty() {
        assert_eq!(CATALOGS.len(), 6);
        for catalog in CATALOGS.iter() {
            assert!(!catalog.as_object().unwrap().is_empty());
        }
    }
    #[test]
    fn missing_locale_and_key_fall_back() {
        assert_eq!(translate("xx", "not.present"), "not.present");
        assert_eq!(
            translate("xx", "Settings.title"),
            translate("en", "Settings.title")
        );
    }
    #[test]
    fn literal_keys_with_dots_take_precedence_over_nested_paths() {
        let catalog = serde_json::json!({
            "Some.sentence.": "Literal sentence",
            "Section.label": "Literal label",
            "Section": { "label": "Nested label", "other": "Nested fallback" }
        });
        assert_eq!(lookup(&catalog, "Some.sentence."), Some("Literal sentence"));
        assert_eq!(lookup(&catalog, "Section.label"), Some("Literal label"));
        assert_eq!(lookup(&catalog, "Section.other"), Some("Nested fallback"));
        assert_eq!(lookup(&catalog, "missing"), None);
    }
    #[test]
    fn editor_catalog_contract_and_french_technical_labels_are_complete() {
        for (locale, catalog) in LOCALES.iter().zip(CATALOGS.iter()) {
            for key in [
                "Decrease font size",
                "Increase font size",
                "Font {size}px",
                "Copy",
                "Cut",
                "Paste",
                "Find",
                "Markdown preview",
                "Replace",
                "Regular expression",
                "Match case",
                "Find next",
                "Replace all",
                "Editor text",
                "Line {line}, Col {col} · {count} lines",
                "Clipboard unavailable",
                "Clipboard updated",
                "Clipboard read denied",
                "Invalid regular expression",
                "No matches",
                "Match selected",
                "Replaced {count} matches",
                "Close dialog",
            ] {
                assert!(lookup(catalog, key).is_some(), "{locale}: {key}");
            }
        }
        assert_eq!(
            translate("fr", "Interface breakdown"),
            "Détail par interface"
        );
        assert_eq!(
            translate("fr", "Search services"),
            "Rechercher des services"
        );
        assert_eq!(
            translate("fr", "Overview.percentUtilization"),
            "Taux d'utilisation"
        );
        assert_eq!(
            translate("fr", "Overview.bytesPerSecond"),
            "Octets par seconde"
        );
    }
    #[test]
    fn navigation_catalogs_keep_english_accessible_names_and_translate_live_labels() {
        for (key, english) in [
            ("overview", "Overview"),
            ("services", "Services"),
            ("marketplace", "Marketplace"),
            ("settings", "Settings"),
        ] {
            assert_eq!(translate("en", &format!("Navigation.{key}")), english);
        }
        for locale in LOCALES {
            for key in [
                "overview",
                "inbox",
                "services",
                "marketplace",
                "mcbrowser",
                "fileshare",
                "streaming",
                "mediaflow",
                "ai",
                "network",
                "cluster",
                "users",
                "audit",
                "settings",
                "notifications",
                "quotas",
            ] {
                let key = format!("Navigation.{key}");
                assert_ne!(translate(locale, &key), key, "{locale}");
            }
        }
        assert_eq!(translate("de", "Navigation.overview"), "Übersicht");
        assert_eq!(
            translate_with("en", "Shell.pendingActions", &[("count", "3")]),
            "3 pending actions"
        );
        assert_ne!(
            translate("fr", "Shell.logout"),
            translate("en", "Shell.logout")
        );
    }
}
