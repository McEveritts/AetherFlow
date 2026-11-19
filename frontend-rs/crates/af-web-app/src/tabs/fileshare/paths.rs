//! Host and scoped path validation and directory navigation helpers.
use serde_json::Value;
pub(crate) fn encode(value: &str) -> String {
    js_sys::encode_uri_component(value)
        .as_string()
        .unwrap_or_default()
}

pub(crate) fn text(row: &Value, key: &str) -> String {
    row[key].as_str().unwrap_or_default().to_owned()
}

pub(crate) fn relative_path(raw: &str, allow_root: bool) -> Result<String, String> {
    if raw.starts_with('/') || raw.contains('\\') || raw.chars().any(char::is_control) {
        return Err("Use a relative path without control characters or backslashes.".into());
    }
    let parts: Vec<_> = raw.split('/').filter(|part| !part.is_empty()).collect();
    if parts.iter().any(|part| {
        matches!(*part, "." | "..") || part.starts_with(".af-upload-tmp.") || part.len() > 255
    }) || parts.len() > 64
        || raw.len() > 4096
    {
        return Err("Path contains a reserved segment or exceeds the supported length.".into());
    }
    let path = parts.join("/");
    if !allow_root && path.is_empty() {
        return Err("Choose a file or folder below your root.".into());
    }
    Ok(path)
}

pub(super) fn absolute_path(raw: &str) -> Result<String, String> {
    let path = raw.trim();
    if !path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path.len() > 4096
    {
        return Err("Enter an absolute directory path without control characters.".into());
    }
    let mut parts = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    Ok(format!("/{}", parts.join("/")))
}
pub(crate) fn parent_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    trimmed
        .rsplit_once('/')
        .map(|(parent, _)| if parent.is_empty() { "/" } else { parent })
        .unwrap_or("/")
        .to_owned()
}
pub(super) fn child_path(path: &str, name: &str) -> Result<String, String> {
    if name.is_empty()
        || matches!(name, "." | "..")
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err("The server returned an invalid directory name.".into());
    }
    absolute_path(&format!("{}/{name}", path.trim_end_matches('/')))
}
pub(super) fn directory_names(value: &Value) -> Vec<String> {
    if let Some(directories) = value["directories"].as_array() {
        return directories
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
    }
    value["entries"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|entry| entry["is_dir"] == true || entry["isDir"] == true)
        .filter_map(|entry| entry["name"].as_str())
        .map(str::to_owned)
        .collect()
}
