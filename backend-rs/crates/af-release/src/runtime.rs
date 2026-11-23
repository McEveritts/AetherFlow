use once_cell::sync::Lazy;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeIdentity {
    pub version: String,
    pub executable: PathBuf,
}

static RUNTIME_IDENTITY: Lazy<RuntimeIdentity> =
    Lazy::new(|| identity_for_executable(&std::env::current_exe().unwrap_or_default()));

pub fn runtime_identity() -> &'static RuntimeIdentity {
    &RUNTIME_IDENTITY
}

/// Resolves the runtime application version, honoring `<isolated_root>/opt/AetherFlow/current/.version`
/// when an isolated `--root` is supplied and otherwise falling back to [`runtime_identity()`].
pub fn runtime_version_for_root(isolated_root: Option<&Path>) -> String {
    if let Some(root) = isolated_root {
        let candidate = root.join("opt/AetherFlow/current/.version");
        if let Ok(raw) = fs::read_to_string(&candidate) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return trimmed.to_string();
            }
        }
    }
    runtime_identity().version.clone()
}

fn identity_for_executable(executable: &Path) -> RuntimeIdentity {
    let executable = fs::canonicalize(executable).unwrap_or_else(|_| executable.to_path_buf());
    let version = executable
        .parent()
        .and_then(|parent| fs::read_to_string(parent.join(".version")).ok())
        .map(|version| version.trim().to_string())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| format!("v{}", env!("CARGO_PKG_VERSION")));
    RuntimeIdentity {
        version,
        executable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_version_does_not_follow_selected_release() {
        let root = std::env::temp_dir().join(format!("af-runtime-{}", uuid::Uuid::new_v4()));
        let running = root.join("running");
        let candidate = root.join("candidate");
        fs::create_dir_all(&running).unwrap();
        fs::create_dir_all(&candidate).unwrap();
        fs::write(running.join("aetherflow-api"), b"running").unwrap();
        fs::write(running.join(".version"), "v4.0.0-nightly.77.1\n").unwrap();
        fs::write(candidate.join(".version"), "v4.0.0-nightly.80.1\n").unwrap();
        let identity = identity_for_executable(&running.join("aetherflow-api"));
        assert_eq!(identity.version, "v4.0.0-nightly.77.1");
        fs::write(candidate.join(".version"), "v4.0.0-nightly.81.1\n").unwrap();
        assert_eq!(identity.version, "v4.0.0-nightly.77.1");
        assert_eq!(identity.executable.parent(), Some(running.as_path()));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_runtime_metadata_uses_build_version_not_current_symlink() {
        let identity = identity_for_executable(Path::new("/nonexistent/af-runtime-test/binary"));
        assert_eq!(identity.version, format!("v{}", env!("CARGO_PKG_VERSION")));
    }
}
