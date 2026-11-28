//! Bounded command capture with supervised process-group cleanup (`SEC-02`).
//!
//! Re-exports the crate-DAG-lowest process-group supervisor from
//! [`af_release::process_group`] so `af-runner` and `af-release` share a single
//! tracked implementation.

pub use af_release::process_group::*;

#[cfg(test)]
mod static_lint_tests {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Wave 1B-migrated `af-runner` production modules that MUST NOT contain any
    /// raw `Command::{output,spawn,status}()` invocations.
    const WAVE_1B_MIGRATED_MODULES: &[&str] = &[
        "app_metadata/handlers.rs",
        "bounded_command.rs",
        "daemon.rs",
        "network_quota_handlers.rs",
        "package_executor/stream_dispatch.rs",
        "package_lifecycle/admitted_snapshots.rs",
        "package_lifecycle/backend.rs",
        "plugins/handlers.rs",
        "plugins/isolation.rs",
        "sandbox_ops.rs",
        "self_update.rs",
        "systemctl_handlers.rs",
    ];

    /// Explicit allowlist of non-Wave-1B `af-runner` modules with legacy raw
    /// `Command` call sites scheduled for retirement in Waves 3-5.
    const WAVE_3_TO_5_ALLOWLIST: &[&str] = &[
        "adguard_dns.rs",
        "blueprint/apply.rs",
        "ingress_vhost.rs",
        "network.rs",
        "package_executor/apache_ingress/vhost_render.rs",
        "package_executor/command_env.rs",
        "package_executor/declarative_recipes/rclone_helpers.rs",
        "package_executor/declarative_recipes/readiness_and_fetch.rs",
        "package_lifecycle/probe_command.rs",
        "peer_network.rs",
        "peer_storage.rs",
        "plugins.rs",
        "quota.rs",
    ];

    fn is_test_only_file(rel: &str) -> bool {
        let name = Path::new(rel)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("");
        matches!(
            name,
            "tests.rs"
                | "lifecycle_tests.rs"
                | "native_catalog_regressions.rs"
                | "receipt_security_regressions.rs"
                | "teardown_regressions.rs"
                | "legacy_stream_output.rs"
                | "version_verification_tests.rs"
        ) || rel.contains("/tests/")
            || rel.contains("/version_verification_tests/")
    }

    fn collect_rs_files(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .expect("read af-runner/src")
            .flatten()
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, root, out);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                let rel = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, path));
            }
        }
    }

    /// Strips `#[cfg(test)]` / `#[cfg(all(test, ...))]` items, comments, and
    /// string literals from Rust source so only production code tokens remain.
    fn strip_tests_comments_and_strings(src: &str) -> String {
        let bytes = src.as_bytes();
        let len = bytes.len();
        let mut out = String::with_capacity(len);
        let mut i = 0;

        while i < len {
            // Line comment
            if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'/' {
                while i < len && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            // Nested block comment
            if i + 1 < len && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                let mut depth = 1usize;
                i += 2;
                while i + 1 < len && depth > 0 {
                    if bytes[i] == b'/' && bytes[i + 1] == b'*' {
                        depth += 1;
                        i += 2;
                    } else if bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        depth -= 1;
                        i += 2;
                    } else {
                        if bytes[i] == b'\n' {
                            out.push('\n');
                        }
                        i += 1;
                    }
                }
                continue;
            }
            // Raw string literal r#*"..."#* or br#*"..."#*
            if (bytes[i] == b'r' || (bytes[i] == b'b' && i + 1 < len && bytes[i + 1] == b'r'))
                && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_')
            {
                let start = if bytes[i] == b'b' { i + 2 } else { i + 1 };
                let mut hashes = 0usize;
                let mut j = start;
                while j < len && bytes[j] == b'#' {
                    hashes += 1;
                    j += 1;
                }
                if j < len && bytes[j] == b'"' {
                    j += 1;
                    while j < len {
                        if bytes[j] == b'\n' {
                            out.push('\n');
                        }
                        if bytes[j] == b'"' {
                            let mut close_hashes = 0usize;
                            while j + 1 + close_hashes < len
                                && close_hashes < hashes
                                && bytes[j + 1 + close_hashes] == b'#'
                            {
                                close_hashes += 1;
                            }
                            if close_hashes == hashes {
                                j += 1 + hashes;
                                break;
                            }
                        }
                        j += 1;
                    }
                    out.push_str("\"\"");
                    i = j;
                    continue;
                }
            }
            // Regular string literal "..."
            if bytes[i] == b'"' {
                i += 1;
                while i < len {
                    if bytes[i] == b'\\' && i + 1 < len {
                        if bytes[i + 1] == b'\n' {
                            out.push('\n');
                        }
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'\n' {
                        out.push('\n');
                    }
                    if bytes[i] == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                out.push_str("\"\"");
                continue;
            }
            // Char literal 'x' or '\x' (avoid stripping lifetimes like `'a`)
            if bytes[i] == b'\'' {
                if i + 2 < len && bytes[i + 1] != b'\\' && bytes[i + 2] == b'\'' {
                    i += 3;
                    out.push_str("''");
                    continue;
                }
                if i + 3 < len && bytes[i + 1] == b'\\' {
                    let mut j = i + 2;
                    while j < len && bytes[j] != b'\'' && bytes[j] != b'\n' {
                        j += 1;
                    }
                    if j < len && bytes[j] == b'\'' {
                        i = j + 1;
                        out.push_str("''");
                        continue;
                    }
                }
            }
            out.push(bytes[i] as char);
            i += 1;
        }

        // Now drop any item annotated with `#[cfg(test)]` or `#[cfg(all(test, ...))]`.
        let mut filtered = String::with_capacity(out.len());
        let ob = out.as_bytes();
        let olen = ob.len();
        let mut idx = 0;
        while idx < olen {
            if ob[idx] == b'#' && idx + 1 < olen && ob[idx + 1] == b'[' {
                let attr_start = idx;
                let mut j = idx + 2;
                let mut bracket_depth = 1usize;
                while j < olen && bracket_depth > 0 {
                    match ob[j] {
                        b'[' => bracket_depth += 1,
                        b']' => bracket_depth -= 1,
                        _ => {}
                    }
                    j += 1;
                }
                let attr = &out[attr_start..j];
                let compact: String = attr.chars().filter(|c| !c.is_whitespace()).collect();
                let is_cfg_test = compact == "#[cfg(test)]"
                    || compact.starts_with("#[cfg(all(test,")
                    || (compact.starts_with("#[cfg(all(") && compact.contains(",test"));
                if is_cfg_test {
                    // Advance past additional attributes and skip the annotated item
                    // (either terminated by `;` or balanced `{ ... }`).
                    let mut k = j;
                    loop {
                        while k < olen && ob[k].is_ascii_whitespace() {
                            if ob[k] == b'\n' {
                                filtered.push('\n');
                            }
                            k += 1;
                        }
                        if k + 1 < olen && ob[k] == b'#' && ob[k + 1] == b'[' {
                            let mut bd = 1usize;
                            k += 2;
                            while k < olen && bd > 0 {
                                match ob[k] {
                                    b'[' => bd += 1,
                                    b']' => bd -= 1,
                                    b'\n' => filtered.push('\n'),
                                    _ => {}
                                }
                                k += 1;
                            }
                            continue;
                        }
                        break;
                    }
                    let mut brace_depth = 0usize;
                    let mut saw_brace = false;
                    while k < olen {
                        let ch = ob[k];
                        if ch == b'\n' {
                            filtered.push('\n');
                        }
                        if ch == b'{' {
                            brace_depth += 1;
                            saw_brace = true;
                        } else if ch == b'}' {
                            brace_depth = brace_depth.saturating_sub(1);
                            if saw_brace && brace_depth == 0 {
                                k += 1;
                                break;
                            }
                        } else if ch == b';' && !saw_brace {
                            k += 1;
                            break;
                        }
                        k += 1;
                    }
                    idx = k;
                    continue;
                }
            }
            filtered.push(ob[idx] as char);
            idx += 1;
        }
        filtered
    }

    fn find_raw_command_calls(prod_code: &str) -> Vec<(usize, String)> {
        let mut hits = Vec::new();
        // Track whether the production portion of this file constructs or
        // imports a `Command` (either `std::process::Command` or
        // `tokio::process::Command`), so unrelated `.status()` calls on HTTP
        // responses in files without `Command` never cause false positives.
        let uses_command = prod_code.contains("Command::new")
            || prod_code.contains("process::Command")
            || prod_code.contains("-> Command");
        if !uses_command {
            return hits;
        }

        let lines: Vec<&str> = prod_code.lines().collect();
        for (line_idx, line) in lines.iter().enumerate() {
            for method in [".output()", ".spawn()", ".status()"] {
                let mut search_from = 0;
                while let Some(pos) = line[search_from..].find(method) {
                    let abs_pos = search_from + pos;
                    search_from = abs_pos + method.len();
                    let before = line[..abs_pos].trim_end();
                    let ident: String = before
                        .chars()
                        .rev()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect();
                    // Exclude non-Command zero-arg `.status()` / `.output()` methods
                    // (HTTP responses and `PeerNetworkManager::status()`).
                    if method == ".status()"
                        && matches!(
                            ident.as_str(),
                            "resp" | "res" | "r" | "gh_resp" | "response" | "self"
                        )
                    {
                        continue;
                    }
                    hits.push((line_idx + 1, line.trim().to_string()));
                }
            }
        }
        hits
    }

    #[test]
    fn wave1b_migrated_runner_modules_ban_raw_command_execution() {
        let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs_files(&src_root, &src_root, &mut files);

        let migrated: BTreeSet<&str> = WAVE_1B_MIGRATED_MODULES.iter().copied().collect();
        let allowlist: BTreeSet<&str> = WAVE_3_TO_5_ALLOWLIST.iter().copied().collect();

        // Ensure migrated modules and Wave 3-5 allowlist are strictly disjoint.
        let overlap: Vec<_> = migrated.intersection(&allowlist).copied().collect();
        assert!(
            overlap.is_empty(),
            "Wave 1B migrated modules must not appear in the Wave 3-5 allowlist: {overlap:?}"
        );

        let mut seen_migrated = BTreeSet::new();
        let mut seen_allowlist_hits = BTreeSet::new();
        let mut violations = Vec::new();

        for (rel, path) in &files {
            if is_test_only_file(rel) {
                continue;
            }
            if migrated.contains(rel.as_str()) {
                seen_migrated.insert(rel.as_str());
            }
            let raw = fs::read_to_string(path).expect("read source file");
            let prod = strip_tests_comments_and_strings(&raw);
            let hits = find_raw_command_calls(&prod);
            if hits.is_empty() {
                continue;
            }
            if allowlist.contains(rel.as_str()) {
                seen_allowlist_hits.insert(rel.as_str());
                continue;
            }
            for (line_no, snippet) in hits {
                violations.push(format!("{rel}:{line_no}: {snippet}"));
            }
        }

        // Every Wave 1B module must exist on disk.
        let missing_migrated: Vec<_> = migrated.difference(&seen_migrated).copied().collect();
        assert!(
            missing_migrated.is_empty(),
            "Missing expected Wave 1B migrated module(s): {missing_migrated:?}"
        );

        // No unallowlisted file (especially none of WAVE_1B_MIGRATED_MODULES) may call raw Command::{output,spawn,status}().
        assert!(
            violations.is_empty(),
            "Raw Command::{{output,spawn,status}}() is banned in Wave 1B-migrated and new af-runner modules; use bounded_command::{{output,output_with_stdin,output_blocking,spawn_streaming}}:\n{}",
            violations.join("\n")
        );

        // Every Wave 3-5 allowlist entry must still match a real legacy call site
        // so retired entries are promptly removed in Waves 3-5.
        let stale_allowlist: Vec<_> = allowlist
            .difference(&seen_allowlist_hits)
            .copied()
            .collect();
        assert!(
            stale_allowlist.is_empty(),
            "Stale Wave 3-5 allowlist entries with no remaining raw Command calls (remove from allowlist): {stale_allowlist:?}"
        );
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io;
    use std::path::Path;
    use std::time::Duration;
    use tokio::process::Command;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/bash");
        command.args(["-c", script]);
        command
    }

    async fn wait_for(path: &Path) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while !path.exists() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_commands_release_inherited_locks_before_returning() {
        let test =
            "bounded_command::tests::completed_commands_release_inherited_locks_before_returning";
        if std::env::var("AF_COMPLETED_COMMAND_TEST_CHILD").as_deref() != Ok(test) {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture"])
                .env("AF_COMPLETED_COMMAND_TEST_CHILD", test)
                .status()
                .unwrap()
                .success());
            return;
        }
        let root =
            std::env::temp_dir().join(format!("af-command-release-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let lock = root.join("maintenance.lock");
        for iteration in 0..256 {
            let guard = af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
            let mut command = shell(if iteration % 2 == 0 {
                "exit 0"
            } else {
                "exit 7"
            });
            guard.preserve_in_child(command.as_std_mut()).unwrap();
            drop(guard);
            let result = output(command, Duration::from_secs(2), 1024).await.unwrap();
            assert_eq!(
                result.status.code(),
                Some(if iteration % 2 == 0 { 0 } else { 7 })
            );
            let released = af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO);
            assert!(
                released.is_ok(),
                "completed command retained its lock: {released:?}"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn captures_nonzero_status_and_refuses_unbounded_output() {
        let out = output(
            shell("printf ok; printf diagnostic >&2; exit 7"),
            Duration::from_secs(2),
            1024,
        )
        .await
        .unwrap();
        assert_eq!(out.status.code(), Some(7));
        assert_eq!(out.stdout, b"ok");
        assert_eq!(out.stderr, b"diagnostic");
        for script in ["yes", "yes >&2"] {
            let error = output(shell(script), Duration::from_secs(2), 64)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn timeout_and_cancellation_kill_descendants_and_release_guard_only_after_cleanup() {
        for cancel in [false, true] {
            let root = std::env::temp_dir().join(format!("af-command-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&root).unwrap();
            let lock = root.join("maintenance.lock");
            let pid_file = root.join("child.pid");
            let guard = af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).unwrap();
            let script = "sleep 60 & echo $! > \"$AF_CHILD_PID\"; wait";
            let mut command = shell(script);
            command.env("AF_CHILD_PID", &pid_file);
            guard.preserve_in_child(command.as_std_mut()).unwrap();
            let task = tokio::spawn(output(command, Duration::from_millis(200), 1024));
            wait_for(&pid_file).await;
            let child: i32 = std::fs::read_to_string(&pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            drop(guard);
            assert!(af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).is_err());
            if cancel {
                task.abort();
                let _ = task.await;
            } else {
                assert_eq!(
                    task.await.unwrap().unwrap_err().kind(),
                    io::ErrorKind::TimedOut
                );
            }
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    let stat =
                        std::fs::read_to_string(format!("/proc/{child}/stat")).unwrap_or_default();
                    let alive = stat
                        .rsplit_once(") ")
                        .is_some_and(|(_, fields)| !fields.starts_with("Z "));
                    if !alive
                        && af_release::ReleaseLockGuard::acquire(&lock, Duration::ZERO).is_ok()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    #[tokio::test]
    async fn child_retaining_a_pipe_after_leader_exit_is_still_bounded() {
        let error = output(shell("sleep 60 & exit 0"), Duration::from_millis(100), 1024)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn successful_command_with_closed_stdio_background_descendant_kills_group_before_return()
    {
        let root = std::env::temp_dir().join(format!("af-command-succ-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let pid_file = root.join("descendant.pid");
        let mut command =
            shell("nohup sleep 60 >/dev/null 2>&1 </dev/null & echo $! > \"$AF_BG_PID\"; exit 0");
        command.env("AF_BG_PID", &pid_file);
        let out = output(command, Duration::from_secs(2), 1024).await.unwrap();
        assert!(out.status.success());
        let child_pid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let stat = std::fs::read_to_string(format!("/proc/{child_pid}/stat")).unwrap_or_default();
        let alive = stat.rsplit_once(") ").is_some_and(|(_, fields)| {
            !matches!(fields.split_whitespace().next(), Some("Z" | "X"))
        });
        assert!(
            !alive,
            "background descendant pid={child_pid} stayed alive after successful bounded_command::output return"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
