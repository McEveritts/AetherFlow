use std::{collections::BTreeSet, io, path::Path, sync::Mutex};

use anyhow::{ensure, Context, Result};

const CONFIG: &str = "/opt/AdGuardHome/AdGuardHome.yaml";
const USERS: &[&str] = &["adguardhome"];

pub(crate) enum Change<'a> {
    Update { ip: &'a str, reconcile: bool },
    Remove,
}

fn managed_domain(domain: &str) -> bool {
    domain
        .strip_suffix(".aether.local")
        .is_some_and(|app| !app.contains('.'))
        && af_models::valid_ingress_hostname(domain)
}

fn is_yaml_content(line: &str) -> bool {
    let trimmed = line.trim();
    !trimmed.is_empty() && !trimmed.starts_with('#')
}

fn indentation(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

fn yaml_key(line: &str, key: &str) -> bool {
    line.trim_start()
        .split_once(':')
        .is_some_and(|(name, _)| name == key)
}

/// Edits only the block sequence emitted by AdGuard Home. Keeping the other
/// lines verbatim preserves configuration the runner does not manage.
fn reconcile_rewrites(raw: &str, domains: &[String], change: Change<'_>) -> Result<String> {
    let domains: BTreeSet<String> = domains
        .iter()
        .map(|domain| domain.to_ascii_lowercase())
        .filter(|domain| managed_domain(domain))
        .collect();
    let additions = match change {
        Change::Update { ip, .. } if !domains.is_empty() => Some(ip),
        _ => None,
    };
    let mut lines: Vec<String> = raw.lines().map(str::to_owned).collect();
    let Some(filtering) = lines
        .iter()
        .position(|line| indentation(line) == 0 && yaml_key(line, "filtering"))
    else {
        if let Some(ip) = additions {
            lines.push("filtering:".into());
            lines.push("  rewrites:".into());
            append_rewrites(&mut lines, &domains, 2, ip);
            return Ok(with_newline(lines));
        }
        return Ok(raw.to_owned());
    };
    let filtering_value = yaml_value(&lines[filtering]);
    ensure!(
        filtering_value.is_empty() || filtering_value == "{}",
        "unsupported AdGuard Home filtering mapping"
    );
    let filtering_end = (filtering + 1..lines.len())
        .find(|&idx| is_yaml_content(&lines[idx]) && indentation(&lines[idx]) == 0)
        .unwrap_or(lines.len());
    let indent = lines[filtering + 1..filtering_end]
        .iter()
        .filter(|line| is_yaml_content(line))
        .map(|line| indentation(line))
        .min()
        .unwrap_or(2);
    let Some(rewrites) = (filtering + 1..filtering_end)
        .find(|&idx| indentation(&lines[idx]) == indent && yaml_key(&lines[idx], "rewrites"))
    else {
        if let Some(ip) = additions {
            let mut block = vec![format!("{}rewrites:", " ".repeat(indent))];
            append_rewrites(&mut block, &domains, indent, ip);
            lines[filtering] = "filtering:".into();
            lines.splice(filtering_end..filtering_end, block);
            return Ok(with_newline(lines));
        }
        return Ok(raw.to_owned());
    };
    let suffix = yaml_value(&lines[rewrites]);
    ensure!(
        suffix.is_empty() || suffix == "[]" || suffix == "null",
        "unsupported AdGuard Home rewrites sequence"
    );
    let end = (rewrites + 1..filtering_end)
        .find(|&idx| {
            let line = &lines[idx];
            is_yaml_content(line)
                && indentation(line) <= indent
                && !line.trim_start().starts_with("- ")
        })
        .unwrap_or(filtering_end);
    let sequence = &lines[rewrites + 1..end];
    let item_indent = sequence
        .iter()
        .find(|line| is_yaml_content(line))
        .map(|line| indentation(line))
        .unwrap_or(indent);
    let starts: Vec<usize> = sequence
        .iter()
        .enumerate()
        .filter_map(|(idx, line)| {
            (indentation(line) == item_indent && line.trim_start().starts_with("- ")).then_some(idx)
        })
        .collect();
    ensure!(
        sequence.iter().position(|line| is_yaml_content(line)) == starts.first().copied(),
        "invalid AdGuard Home rewrites sequence"
    );
    ensure!(
        suffix.is_empty() || starts.is_empty(),
        "invalid AdGuard Home inline rewrites"
    );

    let mut kept = Vec::new();
    let mut removed = false;
    let mut has_entries = false;
    kept.extend_from_slice(&sequence[..starts.first().copied().unwrap_or(sequence.len())]);
    for (index, &start) in starts.iter().enumerate() {
        let item = &sequence[start..starts.get(index + 1).copied().unwrap_or(sequence.len())];
        let domain = item
            .iter()
            .enumerate()
            .map(|(idx, line)| {
                if idx == 0 {
                    line.trim_start().trim_start_matches("- ")
                } else {
                    line
                }
            })
            .find(|line| yaml_key(line, "domain"))
            .map(|line| {
                yaml_value(line)
                    .trim_matches(['\'', '"'])
                    .trim_end_matches('.')
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        if managed_domain(&domain)
            && (matches!(
                change,
                Change::Update {
                    reconcile: true,
                    ..
                }
            ) || domains.contains(&domain))
        {
            removed = true;
            kept.extend(item.iter().filter(|line| !is_yaml_content(line)).cloned());
        } else {
            has_entries = true;
            kept.extend_from_slice(item);
        }
    }
    if let Some(ip) = additions {
        append_rewrites(&mut kept, &domains, item_indent, ip);
        has_entries = true;
    } else if !removed {
        return Ok(raw.to_owned());
    }
    let emptiness = if has_entries { "" } else { " []" };
    lines[rewrites] = format!("{}rewrites:{emptiness}", " ".repeat(indent));
    lines.splice(rewrites + 1..end, kept);
    Ok(with_newline(lines))
}

fn yaml_value(line: &str) -> &str {
    line.split_once(':').map_or("", |(_, value)| {
        value.split('#').next().unwrap_or_default().trim()
    })
}

fn append_rewrites(lines: &mut Vec<String>, domains: &BTreeSet<String>, indent: usize, ip: &str) {
    let spaces = " ".repeat(indent);
    for domain in domains {
        lines.push(format!("{spaces}- domain: {domain}"));
        lines.push(format!("{spaces}  answer: {ip:?}"));
    }
}

fn with_newline(mut lines: Vec<String>) -> String {
    lines.push(String::new());
    lines.join("\n")
}

fn update_config(
    path: &Path,
    domains: &[String],
    change: Change<'_>,
    reload: impl FnOnce() -> Result<()>,
) -> Result<()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|err| err.into_inner());
    let current = match crate::read_confined_text(path, USERS) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).context("cannot read AdGuard Home configuration"),
    };
    let updated = reconcile_rewrites(&current, domains, change)?;
    if current != updated {
        crate::replace_confined_text(path, &updated, USERS, false, false)?;
        if let Err(error) = reload() {
            crate::replace_confined_text(path, &current, USERS, false, false).with_context(
                || format!("{error:#}; failed to restore AdGuard Home configuration"),
            )?;
            return Err(error);
        }
    }
    Ok(())
}

pub(crate) fn sync(domains: &[String], change: Change<'_>) -> Result<()> {
    let path = crate::resolve_runner_fs_path(CONFIG);
    update_config(&path, domains, change, || {
        if path == Path::new(CONFIG) {
            let status = std::process::Command::new("/usr/bin/systemctl")
                .args(["reload-or-restart", "adguardhome.service"])
                .status()
                .context("cannot reload AdGuard Home")?;
            ensure!(status.success(), "AdGuard Home reload or restart failed");
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn reconciles_managed_rewrites_and_is_idempotent() {
        let raw = "dns:\n  port: 53\nfiltering:\n  rewrites:\n  - domain: stale.aether.local\n    answer: 192.0.2.10\n  - answer: custom.example\n    domain: '*.example.test'\n  protection_enabled: true\n";
        let domains = ["app.aether.local".into(), "public.example.test".into()];
        let change = || Change::Update {
            ip: "2001:db8::1",
            reconcile: true,
        };
        let edited = reconcile_rewrites(raw, &domains, change()).unwrap();
        assert!(!edited.contains("stale.aether.local"));
        assert!(edited.contains("- answer: custom.example\n    domain: '*.example.test'"));
        assert!(edited.contains("- domain: app.aether.local\n    answer: \"2001:db8::1\""));
        assert!(edited.ends_with("  protection_enabled: true\n"));
        assert_eq!(
            edited,
            reconcile_rewrites(&edited, &domains, change()).unwrap()
        );
        let removed = reconcile_rewrites(&edited, &domains, Change::Remove).unwrap();
        assert!(!removed.contains("app.aether.local"));
        assert!(removed.contains("custom.example"));
    }

    #[test]
    fn reloads_on_change_and_rejects_symlink_and_hardlink() {
        let root = std::env::temp_dir().join(format!("af-adguard-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let config = root.join("AdGuardHome.yaml");
        let raw = "filtering:\n  rewrites: []\n";
        std::fs::write(&config, raw).unwrap();
        let domains = ["app.aether.local".into()];
        let change = || Change::Update {
            ip: "192.0.2.12",
            reconcile: false,
        };
        let reloads = Cell::new(0);
        for _ in 0..2 {
            update_config(&config, &domains, change(), || {
                reloads.set(reloads.get() + 1);
                Ok(())
            })
            .unwrap();
        }
        assert_eq!(reloads.get(), 1);
        let symlink = root.join("symlink");
        std::os::unix::fs::symlink(&config, &symlink).unwrap();
        assert!(update_config(&symlink, &domains, change(), || Ok(())).is_err());
        std::fs::hard_link(&config, root.join("hardlink")).unwrap();
        assert!(update_config(&config, &domains, change(), || Ok(())).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
