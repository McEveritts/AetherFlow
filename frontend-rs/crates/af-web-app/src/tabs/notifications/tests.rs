use super::*;

#[test]
fn notification_display_follows_locale_and_keeps_action_fields_raw() {
    let owner = Owner::new();
    owner.with(|| {
        let context = crate::state::AppContext::new();
        let raw =
            json!({"id":17,"level":"warning","read":false,"status":"unread","title":"Archive"});
        let rows = Memo::new(move |_| {
            context.locale.get();
            context.catalog_revision.get();
            notification_row(context, raw.clone())
        });
        for (locale, level, read) in [
            ("en", "Warning", "Unread"),
            ("de", "Warnung", "Ungelesen"),
            ("dk", "Advarsel", "Ulæst"),
            ("es", "Advertencia", "No leído"),
            ("fr", "Avertissement", "Non lu"),
            ("zh", "警告", "未读"),
        ] {
            context.locale.set(locale.into());
            context.catalog_revision.update(|revision| *revision += 1);
            let row = rows.get();
            assert_eq!(row["level_label"], level);
            assert_eq!(row["read_label"], read);
            assert_eq!(row["id"], 17);
            assert_eq!(row["level"], "warning");
            assert_eq!(row["read"], false);
            assert_eq!(row["status"], "unread");
            assert_eq!(row["title"], "Archive");
        }
        assert_eq!(
            notification_row(context, json!({"severity":"critical","status":"read"}))["read_label"],
            "已读"
        );
    });
}

#[test]
fn channel_save_keeps_intervening_edits_and_the_dialog_open() {
    let mut draft = FormDraft::new(channel_form());
    draft.edit("name", json!("Operations")).unwrap();
    draft
        .edit("webhook_url", json!("https://example.com/hook"))
        .unwrap();
    let sent = draft.value().unwrap();
    draft.edit("name", json!("Operations alerts")).unwrap();
    draft.acknowledge_saved(&sent, channel_form()).unwrap();
    let has_newer_edits = draft.is_dirty();
    assert!(has_newer_edits);
    assert_eq!(draft.value().unwrap()["name"], "Operations alerts");
    assert_eq!(draft.value().unwrap()["webhook_url"], "");
}

#[test]
fn rule_save_keeps_intervening_edits_for_creates_and_updates() {
    for baseline in [
        rule_form(),
        json!({"name":"Existing","condition_type":"service_down","condition_value":"jellyfin","level":"warning","enabled":true}),
    ] {
        let mut draft = FormDraft::new(baseline);
        draft.edit("name", json!("Submitted rule")).unwrap();
        let sent = draft.value().unwrap();
        draft.edit("name", json!("Newer rule name")).unwrap();
        draft.acknowledge_saved(&sent, sent.clone()).unwrap();
        assert!(draft.is_dirty());
        assert_eq!(draft.value().unwrap()["name"], "Newer rule name");
    }
}

#[test]
fn created_rule_acknowledges_normalized_values_and_keeps_newer_edits() {
    let mut draft = FormDraft::new(rule_form());
    for (field, value) in [
        ("name", json!("  CPU saturation  ")),
        ("condition_type", json!("cpu_usage")),
        ("condition_value", json!(" 75 ")),
        ("level", json!(" ")),
        ("enabled", json!(false)),
    ] {
        draft.edit(field, value).unwrap();
    }
    let sent = draft.value().unwrap();
    draft.edit("condition_value", json!("90")).unwrap();
    let (id, baseline) = saved_rule(None, &sent, &json!({"id":42})).unwrap();
    assert_eq!(id, 42);
    assert_eq!(baseline["name"], "CPU saturation");
    assert_eq!(baseline["condition_value"], "75");
    assert_eq!(baseline["level"], "warning");
    assert_eq!(baseline["enabled"], true);
    draft.acknowledge_saved(&sent, baseline).unwrap();
    assert_eq!(draft.value().unwrap()["condition_value"], "90");
    assert_eq!(draft.value().unwrap()["name"], "CPU saturation");
    assert!(draft.is_dirty());
    draft.reset();
    assert_eq!(draft.value().unwrap()["condition_value"], "75");
    assert!(!draft.is_dirty());
}

#[test]
fn updated_rule_keeps_its_existing_identity_and_unmodified_submitted_values() {
    let sent = json!({"name":"  Existing  ","condition_type":"cpu_usage","condition_value":" 90 ","level":"warning","enabled":false});
    assert_eq!(
        saved_rule(Some(7), &sent, &json!({"id":42})),
        Some((7, sent))
    );
}

#[test]
fn created_rule_requires_a_positive_integer_identity() {
    for response in [
        json!({}),
        json!({"id":0}),
        json!({"id":-1}),
        json!({"id":"42"}),
    ] {
        assert!(saved_rule(None, &rule_form(), &response).is_none());
    }
}

#[test]
fn threshold_alerts_reject_invalid_or_nonfinite_percentages() {
    let mut rule = rule_form();
    rule["name"] = json!("CPU saturation");
    rule["condition_type"] = json!("cpu_usage");
    for threshold in ["0", "-1", "100.1", "NaN", "inf", ""] {
        rule["condition_value"] = json!(threshold);
        assert!(validate_rule(&rule).is_err(), "{threshold}");
    }
    for threshold in ["0.1", "75", "100", " 90 "] {
        rule["condition_value"] = json!(threshold);
        assert_eq!(validate_rule(&rule), Ok(()));
    }
}

#[test]
fn service_rules_require_a_name_and_target_without_percentage_parsing() {
    let mut rule = rule_form();
    rule["condition_value"] = json!("jellyfin.service");
    assert!(validate_rule(&rule).is_err());
    rule["name"] = json!("Media server offline");
    assert_eq!(validate_rule(&rule), Ok(()));
    rule["condition_value"] = json!(" ");
    assert!(validate_rule(&rule).is_err());
}
