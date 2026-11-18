use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Server truth and field-level edits are independent. Refreshes cannot overwrite
/// user input. Fields use JSON pointers, e.g. `/language` or `/network/port`.
#[derive(Clone, Debug)]
pub struct FormDraft<T> {
    baseline: T,
    edits: BTreeMap<String, Value>,
    // Include explicit reversions so an in-flight save cannot erase them.
    touched: BTreeMap<String, Value>,
}

impl<T: Serialize + DeserializeOwned + Clone> FormDraft<T> {
    pub fn new(baseline: T) -> Self {
        Self {
            baseline,
            edits: BTreeMap::new(),
            touched: BTreeMap::new(),
        }
    }
    pub fn baseline(&self) -> &T {
        &self.baseline
    }
    pub fn is_dirty(&self) -> bool {
        !self.edits.is_empty()
    }
    pub fn dirty_fields(&self) -> impl Iterator<Item = &str> {
        self.edits.keys().map(String::as_str)
    }
    pub fn value(&self) -> Result<T, serde_json::Error> {
        let mut value = serde_json::to_value(&self.baseline)?;
        for (path, edit) in &self.edits {
            if let Some(field) = value.pointer_mut(path) {
                *field = edit.clone();
            }
        }
        serde_json::from_value(value)
    }
    /// Validate the edit against T before retaining it. Unknown fields fail closed.
    pub fn edit(&mut self, field: &str, edit: Value) -> Result<(), String> {
        let path = if field.starts_with('/') {
            field.to_string()
        } else {
            format!("/{field}")
        };
        let baseline = serde_json::to_value(&self.baseline).map_err(|e| e.to_string())?;
        let mut candidate = serde_json::to_value(self.value().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let target = candidate
            .pointer_mut(&path)
            .ok_or_else(|| format!("Unknown draft field {field}"))?;
        *target = edit.clone();
        serde_json::from_value::<T>(candidate).map_err(|e| e.to_string())?;
        self.touched.insert(path.clone(), edit.clone());
        if baseline.pointer(&path) == Some(&edit) {
            self.edits.remove(&path);
        } else {
            self.edits.insert(path, edit);
        }
        Ok(())
    }
    pub fn apply_server_refresh(&mut self, server: T) {
        let server_json = serde_json::to_value(&server).ok();
        // Once a clean field follows a refresh away from an earlier explicit
        // value, that old input must never be resurrected by a later save ACK.
        self.touched.retain(|path, edit| {
            self.edits.contains_key(path)
                || server_json.as_ref().and_then(|value| value.pointer(path)) == Some(&*edit)
        });
        self.baseline = server;
    }
    pub fn mark_saved(&mut self, server: T) {
        self.baseline = server;
        self.edits.clear();
        self.touched.clear();
    }
    /// Use for asynchronous saves: acknowledge only edits present in the sent
    /// snapshot, retaining keystrokes made while the request was in flight.
    pub fn acknowledge_saved(&mut self, sent: &T, server: T) -> Result<(), serde_json::Error> {
        let before = self.value()?;
        let current_json = serde_json::to_value(&before)?;
        let sent_json = serde_json::to_value(sent)?;
        let server_json = serde_json::to_value(&server)?;
        // Only explicit user input is eligible: an unrelated server refresh
        // must not become an edit merely because it differs from the snapshot.
        let edits = self
            .touched
            .iter()
            .filter_map(|(path, edit)| {
                let current = current_json.pointer(path)?;
                (current == edit
                    && sent_json.pointer(path) != Some(current)
                    && server_json.pointer(path) != Some(current))
                .then(|| (path.clone(), current.clone()))
            })
            .collect();
        self.baseline = server;
        self.edits = edits;
        self.touched = self.edits.clone();
        Ok(())
    }
    pub fn reset(&mut self) {
        self.edits.clear();
        self.touched.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn refresh_preserves_dirty_and_updates_clean_fields() {
        let mut draft = FormDraft::new(json!({"name":"old","port":80}));
        draft.edit("name", json!("typing")).unwrap();
        draft.apply_server_refresh(json!({"name":"remote","port":443}));
        assert_eq!(draft.value().unwrap(), json!({"name":"typing","port":443}));
        assert_eq!(draft.baseline()["name"], "remote");
    }
    #[test]
    fn reverting_edit_is_clean() {
        let mut draft = FormDraft::new(json!({"x":1}));
        draft.edit("x", json!(2)).unwrap();
        draft.edit("x", json!(1)).unwrap();
        assert!(!draft.is_dirty());
    }
    #[test]
    fn saved_server_truth_wins() {
        let mut draft = FormDraft::new(json!({"x":1}));
        draft.edit("x", json!(2)).unwrap();
        draft.mark_saved(json!({"x":3}));
        assert!(!draft.is_dirty());
        assert_eq!(draft.value().unwrap()["x"], 3);
    }
    #[test]
    fn refresh_does_not_clear_dirty_even_when_temporarily_equal() {
        let mut draft = FormDraft::new(json!({"x":1}));
        draft.edit("x", json!(2)).unwrap();
        draft.apply_server_refresh(json!({"x":2}));
        draft.apply_server_refresh(json!({"x":3}));
        assert_eq!(draft.value().unwrap()["x"], 2);
    }
    #[test]
    fn edits_during_save_are_preserved() {
        let mut draft = FormDraft::new(json!({"name":"a","port":80}));
        draft.edit("name", json!("b")).unwrap();
        let sent = draft.value().unwrap();
        draft.edit("name", json!("c")).unwrap();
        draft.edit("port", json!(443)).unwrap();
        draft
            .acknowledge_saved(&sent, json!({"name":"B","port":80}))
            .unwrap();
        assert_eq!(draft.value().unwrap(), json!({"name":"c","port":443}));
    }
    #[test]
    fn unchanged_submitted_edits_follow_canonical_response() {
        let mut draft = FormDraft::new(json!({"x":1}));
        draft.edit("x", json!(2)).unwrap();
        let sent = draft.value().unwrap();
        draft.acknowledge_saved(&sent, json!({"x":20})).unwrap();
        assert_eq!(draft.value().unwrap()["x"], 20);
        assert!(!draft.is_dirty());
    }
    #[test]
    fn baseline_reverting_edit_during_save_is_preserved() {
        let original = json!({"name":"original"});
        let mut draft = FormDraft::new(original.clone());
        draft.edit("name", json!("submitted")).unwrap();
        let sent = draft.value().unwrap();
        draft.edit("name", json!("original")).unwrap();
        assert!(!draft.is_dirty());
        draft.acknowledge_saved(&sent, sent.clone()).unwrap();
        assert_eq!(draft.value().unwrap(), original);
        assert!(draft.is_dirty());
        assert_eq!(draft.dirty_fields().collect::<Vec<_>>(), vec!["/name"]);
    }
    #[test]
    fn save_acknowledgement_does_not_turn_background_refreshes_into_edits() {
        let mut draft = FormDraft::new(json!({"name":"original","port":80}));
        draft.edit("name", json!("submitted")).unwrap();
        let sent = draft.value().unwrap();
        draft.apply_server_refresh(json!({"name":"original","port":443}));
        draft.acknowledge_saved(&sent, sent.clone()).unwrap();
        assert_eq!(draft.value().unwrap(), sent);
        assert!(!draft.is_dirty());
    }
    #[test]
    fn clean_reversions_follow_background_refreshes() {
        let mut draft = FormDraft::new(json!({"name":"original"}));
        draft.edit("name", json!("typing")).unwrap();
        draft.edit("name", json!("original")).unwrap();
        draft.apply_server_refresh(json!({"name":"remote"}));
        let sent = draft.value().unwrap();
        draft.acknowledge_saved(&sent, sent.clone()).unwrap();
        assert_eq!(draft.value().unwrap(), sent);
        assert!(!draft.is_dirty());
    }
    #[test]
    fn refreshed_clean_fields_do_not_resurrect_historical_input_after_a_save() {
        let mut draft = FormDraft::new(json!({"name":"original","port":80}));
        draft.edit("port", json!(81)).unwrap();
        draft.edit("port", json!(80)).unwrap();
        draft.apply_server_refresh(json!({"name":"original","port":443}));
        draft.edit("name", json!("submitted")).unwrap();
        let sent = draft.value().unwrap();
        draft.apply_server_refresh(json!({"name":"original","port":80}));
        draft.acknowledge_saved(&sent, sent.clone()).unwrap();
        assert_eq!(draft.value().unwrap(), sent);
        assert!(!draft.is_dirty());
    }
    #[test]
    fn edits_already_matching_the_saved_response_are_clean() {
        let mut draft = FormDraft::new(json!({"name":"original"}));
        draft.edit("name", json!("submitted")).unwrap();
        let sent = draft.value().unwrap();
        draft.edit("name", json!("canonical")).unwrap();
        draft
            .acknowledge_saved(&sent, json!({"name":"canonical"}))
            .unwrap();
        assert_eq!(draft.value().unwrap()["name"], "canonical");
        assert!(!draft.is_dirty());
    }
    #[test]
    fn nested_fields_and_reset() {
        let mut draft = FormDraft::new(json!({"nested":{"x":1,"y":2}}));
        draft.edit("/nested/x", json!(3)).unwrap();
        draft.apply_server_refresh(json!({"nested":{"x":9,"y":8}}));
        assert_eq!(draft.value().unwrap()["nested"], json!({"x":3,"y":8}));
        draft.reset();
        assert_eq!(draft.value().unwrap()["nested"]["x"], 9);
    }
    #[test]
    fn typed_invalid_and_unknown_edits_are_rejected() {
        #[derive(Clone, serde::Serialize, serde::Deserialize)]
        struct Form {
            port: u16,
        }
        let mut draft = FormDraft::new(Form { port: 80 });
        assert!(draft.edit("port", json!("bad")).is_err());
        assert!(draft.edit("missing", json!(2)).is_err());
        assert!(!draft.is_dirty());
    }
}
