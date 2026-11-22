use super::*;

pub(super) fn step_progress_meta(step: &DeclarativeStep) -> (u8, &str) {
    match step {
        DeclarativeStep::AptUpdate {
            progress_pct,
            description,
        }
        | DeclarativeStep::AptInstall {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::AptPurge {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::AptRemove {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::EnsureSystemUser {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::PurgeSystemUser {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::EnsureDirectories {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::ProbeSshPort {
            progress_pct,
            description,
        }
        | DeclarativeStep::GenerateSelfSignedTlsCert {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::CaptureDpkgVersion {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::EnsureThreadfinConfig {
            progress_pct,
            description,
        }
        | DeclarativeStep::InstallRcloneBinary {
            progress_pct,
            description,
        }
        | DeclarativeStep::RemoveRcloneFiles {
            progress_pct,
            description,
        }
        | DeclarativeStep::ResolveGitHubReleaseTag {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::DownloadAndExtractTarGz {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::DownloadBinary {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::MergeIniSettings {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::WriteTemplateFile {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::WriteSystemdUnit {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::Systemctl {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::PurgeSystemdUnit {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::UnmountPaths {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::RemovePaths {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::RunCommand {
            progress_pct,
            description,
            ..
        }
        | DeclarativeStep::WaitForHttpReady {
            progress_pct,
            description,
            ..
        } => (*progress_pct, description.as_str()),
    }
}

pub(super) fn format_znc_major_minor(version: &str) -> String {
    let clean = version.trim().trim_start_matches('v');
    let without_epoch = match clean.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.bytes().all(|b| b.is_ascii_digit()) => {
            rest
        }
        _ => clean,
    };
    let core = without_epoch
        .split(['-', '+', '~'])
        .find(|part| part.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .unwrap_or(without_epoch);
    let mut parts = core.split('.');
    match (parts.next(), parts.next()) {
        (Some(major), Some(minor))
            if !major.is_empty()
                && !minor.is_empty()
                && major.chars().all(|c| c.is_ascii_digit()) =>
        {
            let minor_digits: String = minor.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !minor_digits.is_empty() {
                format!("{}.{}", major, minor_digits)
            } else {
                "1.9".to_string()
            }
        }
        _ => "1.9".to_string(),
    }
}

pub(super) fn add_missing_rclone_env_aliases(mut content: String) -> String {
    let settings = af_models::parse_key_value_env_str(&content);
    for (key, other) in [
        ("RCLONE_RC_USER", "RCLONE_USER"),
        ("RCLONE_USER", "RCLONE_RC_USER"),
        ("RCLONE_RC_PASS", "RCLONE_PASS"),
        ("RCLONE_PASS", "RCLONE_RC_PASS"),
    ] {
        if let Some(value) = settings.get(other).filter(|_| !settings.contains_key(key)) {
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            let escaped = escape_systemd_env_quoted(value);
            content.push_str(&format!("{key}=\"{escaped}\"\n"));
        }
    }
    content
}

pub(super) fn update_preserved_rclone_env_pass(existing: &str, raw_pass: &str) -> String {
    let escaped = escape_systemd_env_quoted(raw_pass);
    static RCLONE_PASS_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?m)^[ \t]*(RCLONE_RC_PASS|RCLONE_PASS)[ \t]*=.*$").unwrap());
    let mut out = RCLONE_PASS_RE
        .replace_all(existing, |caps: &regex::Captures<'_>| {
            format!("{}=\"{}\"", &caps[1], escaped)
        })
        .into_owned();
    for key in ["RCLONE_RC_PASS", "RCLONE_PASS"] {
        if !af_models::parse_key_value_env_str(&out).contains_key(key) {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&format!("{key}=\"{escaped}\"\n"));
        }
    }
    out
}

pub(super) fn parse_semver_tuple(raw: &str) -> Option<(u64, u64, u64)> {
    let clean = raw.trim().trim_start_matches('v');
    let core = clean.split(['-', '+']).next().unwrap_or(clean);
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    let patch = parts.next().unwrap_or("0").parse::<u64>().ok()?;
    Some((major, minor, patch))
}

pub(super) fn is_semver_strictly_greater(a: &str, b: &str) -> bool {
    match (parse_semver_tuple(a), parse_semver_tuple(b)) {
        (Some(ta), Some(tb)) => ta > tb,
        _ => false,
    }
}

pub(super) fn is_downgrade_allowed() -> bool {
    env::var("AF_ALLOW_DOWNGRADE")
        .ok()
        .map(|v| {
            let trimmed = v.trim();
            trimmed == "1" || trimmed.eq_ignore_ascii_case("true")
        })
        .unwrap_or(false)
}

pub(super) fn merge_ini_settings(
    original: &str,
    section: &str,
    settings: &[(String, String)],
) -> String {
    let mut remaining = settings.to_vec();
    let mut output = String::new();
    let mut in_section = false;
    let mut found_section = false;
    for line in original.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            if in_section {
                for (key, value) in remaining.drain(..) {
                    output.push_str(&format!("    {key} = {value}\n"));
                }
            }
            in_section = trimmed == format!("[{section}]");
            found_section |= in_section;
        }
        if in_section {
            if let Some((key, _)) = trimmed.split_once('=') {
                if let Some((managed_key, value)) = settings
                    .iter()
                    .find(|(managed_key, _)| managed_key == key.trim())
                {
                    let indentation = &line[..line.len() - line.trim_start().len()];
                    if let Some((lhs, _)) = line.split_once('=') {
                        if lhs.ends_with(' ') || lhs.ends_with('\t') {
                            output.push_str(&format!("{lhs}= {value}\n"));
                        } else {
                            output.push_str(&format!("{indentation}{managed_key} = {value}\n"));
                        }
                    } else {
                        output.push_str(&format!("{indentation}{managed_key} = {value}\n"));
                    }
                    remaining.retain(|(pending, _)| pending != managed_key);
                    continue;
                }
            }
        }
        output.push_str(line);
        output.push('\n');
    }
    if !found_section {
        output.push_str(&format!("\n[{section}]\n"));
    }
    for (key, value) in remaining {
        output.push_str(&format!("    {key} = {value}\n"));
    }
    output
}

pub(super) fn escape_systemd_env_quoted(val: &str) -> String {
    let mut out = String::with_capacity(val.len() + 8);
    for ch in val.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            other => out.push(other),
        }
    }
    out
}

pub(super) fn interpolate_template(template: &str, vars: &HashMap<String, String>) -> String {
    let mut out = template.to_string();
    for (k, v) in vars {
        let placeholder = format!("{{{{{}}}}}", k);
        out = out.replace(&placeholder, v);
        let angle_placeholder = format!("<{}>", k);
        out = out.replace(&angle_placeholder, v);
    }
    out
}

/// Classic RFB / TigerVNC fixed DES obfuscation key (`[23, 82, 107, 6, 35, 78, 88, 7]`).
const TIGERVNC_FIXED_KEY: [u8; 8] = [23, 82, 107, 6, 35, 78, 88, 7];

const DES_IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const DES_FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const DES_PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const DES_PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const DES_SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const DES_E: [u8; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

const DES_P: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const DES_SBOX: [[[u8; 16]; 4]; 8] = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
];

fn des_permute(src: u64, src_bits: u8, table: &[u8]) -> u64 {
    let mut dst = 0u64;
    for (i, &pos) in table.iter().enumerate() {
        let bit = (src >> (src_bits - pos)) & 1;
        dst |= bit << (table.len() - 1 - i);
    }
    dst
}

fn des_subkeys_vnc() -> [u64; 16] {
    let mut rev_key = [0u8; 8];
    for (i, &b) in TIGERVNC_FIXED_KEY.iter().enumerate() {
        rev_key[i] = b.reverse_bits();
    }
    let key_u64 = u64::from_be_bytes(rev_key);
    let cd = des_permute(key_u64, 64, &DES_PC1);
    let mut c = ((cd >> 28) & 0x0fff_ffff) as u32;
    let mut d = (cd & 0x0fff_ffff) as u32;
    let mut subkeys = [0u64; 16];
    for (round, &shift) in DES_SHIFTS.iter().enumerate() {
        c = ((c << shift) | (c >> (28 - shift))) & 0x0fff_ffff;
        d = ((d << shift) | (d >> (28 - shift))) & 0x0fff_ffff;
        let combined = ((c as u64) << 28) | (d as u64);
        subkeys[round] = des_permute(combined, 56, &DES_PC2);
    }
    subkeys
}

fn des_feistel(r: u32, k: u64) -> u32 {
    let er = des_permute(r as u64, 32, &DES_E) ^ k;
    let mut s_out = 0u32;
    for (i, sbox) in DES_SBOX.iter().enumerate() {
        let chunk = ((er >> (42 - 6 * i)) & 0x3f) as u8;
        let row = (((chunk >> 5) & 1) << 1) | (chunk & 1);
        let col = (chunk >> 1) & 0x0f;
        let val = sbox[row as usize][col as usize];
        s_out = (s_out << 4) | (val as u32);
    }
    des_permute(s_out as u64, 32, &DES_P) as u32
}

fn des_block_crypt(block: [u8; 8], decrypt: bool) -> [u8; 8] {
    let subkeys = des_subkeys_vnc();
    let ip = des_permute(u64::from_be_bytes(block), 64, &DES_IP);
    let mut l = (ip >> 32) as u32;
    let mut r = (ip & 0xffff_ffff) as u32;
    for i in 0..16 {
        let k = if decrypt { subkeys[15 - i] } else { subkeys[i] };
        let next_l = r;
        let next_r = l ^ des_feistel(r, k);
        l = next_l;
        r = next_r;
    }
    let preoutput = ((r as u64) << 32) | (l as u64);
    des_permute(preoutput, 64, &DES_FP).to_be_bytes()
}

/// Obfuscates a plaintext password into the 8-byte binary format expected by
/// TigerVNC `Xtigervnc -PasswordFile` (`vncpasswd -f` / `rfb::obfuscate`).
pub fn encode_tigervnc_passwd(password: &str) -> [u8; 8] {
    let mut plain = [0u8; 8];
    let bytes = password.as_bytes();
    let take = bytes.len().min(8);
    plain[..take].copy_from_slice(&bytes[..take]);
    des_block_crypt(plain, false)
}

/// Deobfuscates an 8-byte TigerVNC `PasswordFile` block into its UTF-8 password prefix
/// (up to 8 characters, stripping trailing NUL padding), returning `None` if `obfuscated`
/// is not 8 bytes or does not decode to valid UTF-8.
pub fn decode_tigervnc_passwd(obfuscated: &[u8]) -> Option<String> {
    let block: [u8; 8] = obfuscated.try_into().ok()?;
    let decrypted = des_block_crypt(block, true);
    let end = decrypted.iter().position(|&b| b == 0).unwrap_or(8);
    if decrypted[end..].iter().any(|&b| b != 0) {
        return None;
    }
    std::str::from_utf8(&decrypted[..end])
        .ok()
        .map(str::to_string)
}

pub(super) fn append_log_line(log_file_path: &Path, line: &str) {
    if validate_filesystem_path(log_file_path, None).is_err() {
        return;
    }
    if let Ok(mut f) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file_path)
    {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let _ = libc::flock(f.as_raw_fd(), libc::LOCK_SH);
            }
        }
        let _ = writeln!(f, "[{}] {}", Utc::now().format("%Y-%m-%d %H:%M:%S"), line);
        let _ = f.flush();
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let _ = libc::flock(f.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// Mirrors the legacy installer's certificate expansion after writing the install lock.
pub(super) fn trigger_certbot_sync_best_effort() {
    if !["/usr/local/bin/af-certbot-sync", "/usr/bin/af-certbot-sync"]
        .iter()
        .any(|path| Path::new(path).is_file())
    {
        return;
    }
    tokio::spawn(async {
        if let Err(err) = crate::sync_certbot_and_managed_ingress().await {
            tracing::warn!(error = %err, "post-install certbot sync failed");
        }
    });
}

pub(super) fn extract_binaries_from_targz(
    archive_path: &Path,
    dest_dir: &Path,
    wanted_binaries: &[String],
    binary_mode: u32,
    require_elf_magic: bool,
    journal: &mut RollbackJournal,
) -> Result<(), PackageExecutorError> {
    validate_filesystem_path(archive_path, journal.fs_root.as_deref())?;
    validate_filesystem_path(dest_dir, journal.fs_root.as_deref())?;

    let file = File::open(archive_path)?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    let mut found: HashMap<String, bool> =
        wanted_binaries.iter().map(|b| (b.clone(), false)).collect();

    for entry_res in archive.entries().map_err(|e| {
        PackageExecutorError::ArtifactVerification(format!("invalid tar.gz archive: {}", e))
    })? {
        let mut entry = entry_res.map_err(|e| {
            PackageExecutorError::ArtifactVerification(format!("corrupt tar entry: {}", e))
        })?;
        let entry_type = entry.header().entry_type();
        let entry_path = entry
            .path()
            .map_err(|e| PackageExecutorError::ArtifactVerification(e.to_string()))?
            .into_owned();

        // Reject any entry containing '..'
        if entry_path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "archive contains path traversal entry: {}",
                entry_path.display()
            )));
        }

        // Reject symlinks, hardlinks, FIFOs, or device nodes inside archives
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "archive contains disallowed link entry: {}",
                entry_path.display()
            )));
        }

        let Some(fname) = entry_path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !found.contains_key(fname) {
            continue;
        }
        if !matches!(
            entry_type,
            tar::EntryType::Regular | tar::EntryType::GNUSparse
        ) {
            return Err(PackageExecutorError::SecurityViolation(format!(
                "archive target '{}' is not a regular file",
                entry_path.display()
            )));
        }

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        if require_elf_magic && (buf.len() < 4 || buf[..4] != [0x7f, b'E', b'L', b'F']) {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "archive member '{}' is not a valid ELF binary",
                fname
            )));
        }

        let target = dest_dir.join(fname);
        validate_filesystem_path(&target, journal.fs_root.as_deref())?;
        journal.stage_file_mutation(&target)?;
        write_file_atomic_with_mode_bounded(
            &target,
            &buf,
            binary_mode,
            journal.fs_root.as_deref(),
        )?;
        found.insert(fname.to_string(), true);
    }

    for (bin_name, was_found) in found {
        if !was_found {
            return Err(PackageExecutorError::ArtifactVerification(format!(
                "expected binary '{}' was not found inside archive {}",
                bin_name,
                archive_path.display()
            )));
        }
    }

    Ok(())
}

pub(super) fn apply_sandbox_in_root_with_journal(
    pkg_id: &str,
    systemd_root: &Path,
    mut journal: Option<&mut RollbackJournal>,
    fs_root: Option<&Path>,
) -> Result<String, PackageExecutorError> {
    validate_filesystem_path(systemd_root, fs_root)?;

    let pkg = crate::get_runner_package_definition(pkg_id).unwrap_or_else(|| af_models::Package {
        name: pkg_id.to_string(),
        service_type: "systemd".to_string(),
        service_name: pkg_id.to_string(),
        sandbox_profile: "native".to_string(),
        sandbox_read_write: vec![format!("/var/lib/{}", pkg_id)],
        sandbox_service_ids: vec![format!("{}.service", pkg_id)],
        ..Default::default()
    });

    if !pkg.service_type.is_empty() && pkg.service_type != "systemd" {
        return Ok("sandbox skipped (non-systemd service)".to_string());
    }
    if pkg.sandbox_profile.is_empty() {
        return Ok("sandbox skipped (no profile configured)".to_string());
    }

    let mut units = pkg.sandbox_service_ids.clone();
    if units.is_empty() && !pkg.service_name.is_empty() {
        units.push(pkg.service_name.clone());
    }
    if units.is_empty() {
        units.push(pkg_id.to_string());
    }

    for raw_unit in &units {
        let norm = normalize_unit_filename(raw_unit);
        let dropin_dir = systemd_root.join(format!("{}.d", norm));
        validate_filesystem_path(&dropin_dir, fs_root)?;
        let dropin_aether = dropin_dir.join("aetherflow-sandbox.conf");
        let dropin_10 = dropin_dir.join("10-aetherflow-sandbox.conf");
        validate_filesystem_path(&dropin_aether, fs_root)?;
        validate_filesystem_path(&dropin_10, fs_root)?;

        if !norm.ends_with(".service")
            || pkg.sandbox_profile == "privileged"
            || pkg.sandbox_profile == "none"
            || crate::is_exempt_sandbox_unit(&norm)
        {
            if let Some(ref mut j) = journal {
                if dropin_aether.exists() {
                    j.stage_file_mutation(&dropin_aether)?;
                }
                if dropin_10.exists() {
                    j.stage_file_mutation(&dropin_10)?;
                }
            }
            let _ = fs::remove_file(&dropin_aether);
            let _ = fs::remove_file(&dropin_10);
            continue;
        }
        create_dir_all_0755(&dropin_dir)?;
        validate_filesystem_path(&dropin_dir, fs_root)?;
        let content = crate::render_systemd_sandbox_dropin_in_root(
            &pkg.sandbox_profile,
            &norm,
            &pkg.sandbox_read_write,
            Some(systemd_root),
            fs_root,
        );
        if let Some(ref mut j) = journal {
            j.stage_file_mutation(&dropin_aether)?;
            j.stage_file_mutation(&dropin_10)?;
        }
        write_file_atomic_with_mode_bounded(&dropin_aether, content.as_bytes(), 0o644, fs_root)?;
        write_file_atomic_with_mode_bounded(&dropin_10, content.as_bytes(), 0o644, fs_root)?;
    }

    Ok("sandbox applied".to_string())
}

pub(super) fn collect_package_version_receipt_logical_paths(
    pkg: &af_models::Package,
    pkg_id: &str,
) -> Vec<String> {
    static AF_VERSION_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(/[A-Za-z0-9_./-]*/\.af-version)").unwrap());
    let mut paths = Vec::new();
    for token in &pkg.version_command {
        for cap in AF_VERSION_RE.captures_iter(token) {
            if let Some(m) = cap.get(1) {
                let p = m.as_str().to_string();
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
    }
    for prefix in ["/var/lib", "/etc", "/opt"] {
        let candidate = format!("{}/{}/.af-version", prefix, pkg_id);
        if !paths.contains(&candidate) {
            paths.push(candidate);
        }
        if !pkg.name.is_empty() && pkg.name != pkg_id {
            let alt = format!("{}/{}/.af-version", prefix, pkg.name);
            if !paths.contains(&alt) {
                paths.push(alt);
            }
        }
    }
    paths
}

pub(super) fn resolve_package_sandbox_roots(
    install_root: Option<&Path>,
) -> (Option<PathBuf>, PathBuf) {
    let effective_root: Option<PathBuf> = install_root.map(Path::to_path_buf).or_else(|| {
        env::var("AETHERFLOW_INSTALL_ROOT")
            .or_else(|_| env::var("AETHERFLOW_PACKAGE_FS_ROOT"))
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty() && v != "/")
            .map(PathBuf::from)
    });
    let systemd_root = env::var("AETHERFLOW_SYSTEMD_ROOT")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| match effective_root.as_deref() {
            Some(root) => root.join("etc/systemd/system"),
            None => PathBuf::from("/etc/systemd/system"),
        });
    (effective_root, systemd_root)
}

/// Ensures systemd sandbox drop-ins (`aetherflow-sandbox.conf` and `10-aetherflow-sandbox.conf`)
/// are written on `"install"`, `"reinstall"`, and `"update"`, and removed (along with stale
/// `.af-version` receipts) on `"remove"` / `"uninstall"` across both synthetic roots and live `/`.
pub fn ensure_package_sandbox_dropin_under_root(
    install_root: Option<&Path>,
    pkg_id: &str,
    action: &str,
) -> Result<(), PackageExecutorError> {
    ensure_package_sandbox_dropin_under_root_with_journal(install_root, pkg_id, action, None)
}

pub(crate) fn ensure_package_sandbox_dropin_under_root_with_journal(
    install_root: Option<&Path>,
    pkg_id: &str,
    action: &str,
    journal: Option<&mut RollbackJournal>,
) -> Result<(), PackageExecutorError> {
    let (effective_root, systemd_root) = resolve_package_sandbox_roots(install_root);

    let action_lower = action.trim().to_ascii_lowercase();
    match action_lower.as_str() {
        "install" | "reinstall" | "update" => {
            apply_sandbox_in_root_with_journal(
                pkg_id,
                &systemd_root,
                journal,
                effective_root.as_deref(),
            )?;
        }
        "remove" | "uninstall" => {
            if let Some(pkg) = crate::get_runner_package_definition(pkg_id) {
                let mut units = pkg.sandbox_service_ids.clone();
                if units.is_empty() && !pkg.service_name.is_empty() {
                    units.push(pkg.service_name.clone());
                }
                if units.is_empty() {
                    units.push(pkg_id.to_string());
                }
                for raw_unit in &units {
                    let norm = normalize_unit_filename(raw_unit);
                    let dropin_dir = systemd_root.join(format!("{}.d", norm));
                    let _ = fs::remove_file(dropin_dir.join("aetherflow-sandbox.conf"));
                    let _ = fs::remove_file(dropin_dir.join("10-aetherflow-sandbox.conf"));
                    if let Ok(mut entries) = fs::read_dir(&dropin_dir) {
                        if entries.next().is_none() {
                            let _ = fs::remove_dir(&dropin_dir);
                        }
                    }
                }
                for logical_version_path in
                    collect_package_version_receipt_logical_paths(&pkg, pkg_id)
                {
                    let resolved = match effective_root.as_deref() {
                        Some(root) => root.join(logical_version_path.trim_start_matches('/')),
                        None => PathBuf::from(&logical_version_path),
                    };
                    let _ = fs::remove_file(resolved);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Unified Runner Stream Dispatcher (Declarative Rust + Legacy Bash Fallback)
// -----------------------------------------------------------------------------

/// Validates that `script_name` canonically matches `package_id` and `action`
/// so one package's request can never resolve or execute another package's script.
pub fn script_matches_package_identity(action: &str, package_id: &str, script_name: &str) -> bool {
    let pkg = package_id.trim().to_ascii_lowercase();
    let script = Path::new(script_name.trim())
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if pkg.is_empty() || script.is_empty() {
        return false;
    }

    let prefixes: &[&str] = match action.trim().to_ascii_lowercase().as_str() {
        "install" | "reinstall" => &["installpackage-"],
        "remove" | "uninstall" => &["removepackage-"],
        "update" => &["updatepackage-", "installpackage-"],
        _ => return false,
    };

    let Some(script_stem) = prefixes.iter().find_map(|p| script.strip_prefix(p)) else {
        return false;
    };
    if script_stem.is_empty() {
        return false;
    }

    let mut allowed_stems = vec![pkg.as_str()];
    match pkg.as_str() {
        "calibre-web" => allowed_stems.push("calibreweb"),
        "calibreweb" => allowed_stems.push("calibre-web"),
        "uptime-kuma" => allowed_stems.push("uptimekuma"),
        "uptimekuma" => allowed_stems.push("uptime-kuma"),
        "pyload-ng" => allowed_stems.push("pyload"),
        "pyload" => allowed_stems.push("pyload-ng"),
        "adguard-home" => allowed_stems.push("adguardhome"),
        "adguardhome" => allowed_stems.push("adguard-home"),
        _ => {}
    }

    if allowed_stems.contains(&script_stem) {
        return true;
    }

    // Allow synthetic non-catalog test fixtures (e.g. `package_id = "fixture"` with
    // `installpackage-overflow-fixture` or `installpackage-hillclimb-<uuid>`) in isolated tests.
    pkg == "fixture"
        && (script_stem.ends_with("-fixture")
            || script_stem.starts_with("fixture-")
            || script_stem.starts_with("hillclimb-")
            || script_stem.starts_with("polling-"))
}

/// Resolves whether a `PackageRunnerRequest` can be satisfied by either a built-in
/// declarative Rust recipe or a legacy Bash script on disk.
pub fn can_resolve_package_operation(action: &str, pkg_id: &str, script_name: &str) -> bool {
    if PackageAction::parse(action).is_none() {
        return false;
    }
    if !script_matches_package_identity(action, pkg_id, script_name) {
        return false;
    }
    if select_package_engine(pkg_id) == PackageEngineMode::DeclarativeRust {
        return true;
    }
    resolve_package_script_path(action, script_name).is_some()
}

/// Streams a declarative recipe's [`PackageProgressEvent`] wire lines incrementally as each
/// step emits them, without waiting for the entire recipe to finish before yielding.
pub fn execute_declarative_recipe_stream<R>(
    executor: Arc<DeclarativePackageExecutor<R>>,
    recipe: DeclarativePackageRecipe,
    action: PackageAction,
    cancel: CancellationToken,
) -> impl futures::Stream<Item = Result<String, std::io::Error>> + Send
where
    R: CommandRunner + 'static,
{
    async_stream::stream! {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let exec_handle = tokio::spawn(async move {
            executor
                .execute_recipe(&recipe, action, cancel, move |ev| {
                    let _ = tx.send(format!("{}\n", ev.to_wire_line()));
                })
                .await
        });

        while let Some(line) = rx.recv().await {
            yield Ok(line);
        }

        match exec_handle.await {
            Ok(Ok(_outcome)) => {}
            Ok(Err(err)) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:{}\n", err));
            }
            Err(join_err) => {
                yield Ok(format!("__RUNNER_EXIT_ERROR__:declarative task failed: {}\n", join_err));
            }
        }
    }
}

/// Parses master username and password from JSON credential stores, `/install/.aetherflow.conf`,
/// `/etc/aetherflow/master.Indexed`, or `/root/.aetherflow_master`.
pub(super) fn parse_master_credentials_content(raw: &str) -> (Option<String>, Option<String>) {
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(raw) {
        let user = val
            .get("username")
            .or_else(|| val.get("user"))
            .or_else(|| val.get("MASTER_USER"))
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let pass = val
            .get("password")
            .or_else(|| val.get("passwd"))
            .or_else(|| val.get("pass"))
            .or_else(|| val.get("MASTER_PASS"))
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .and_then(|s| af_db::decrypt_secret_if_needed(s).ok())
            .filter(|s| !s.is_empty() && s != "adminadmin");
        return (user, pass);
    }

    let mut user: Option<String> = None;
    let mut pass: Option<String> = None;
    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("MASTER_USER=")
            .or_else(|| line.strip_prefix("username="))
        {
            let v = rest.trim().trim_matches('"').trim_matches('\'').trim();
            if !v.is_empty() {
                user = Some(v.to_string());
            }
            continue;
        }
        if let Some(rest) = line
            .strip_prefix("MASTER_PASS=")
            .or_else(|| line.strip_prefix("password="))
            .or_else(|| line.strip_prefix("passwd="))
        {
            let v = rest.trim().trim_matches('"').trim_matches('\'').trim();
            if !v.is_empty() && v != "adminadmin" {
                pass = Some(v.to_string());
            }
            continue;
        }
        if user.is_none() && pass.is_none() && !line.contains('=') {
            if let Some((u, p)) = line.split_once(':') {
                let u = u.trim();
                let p = p.trim();
                if !u.is_empty() {
                    user = Some(u.to_string());
                }
                if !p.is_empty() && p != "adminadmin" {
                    pass = Some(p.to_string());
                }
            } else {
                user = Some(line.to_string());
            }
        }
    }
    (user, pass)
}

/// Resolves `(MASTER_USER, MASTER_PASS)` from process environment or credential files,
/// generating and persisting a cryptographically unique fallback secret when absent.
/// Fails closed if an existing encrypted `.master.creds` cannot be decrypted or if
/// configured `AES_MASTER_KEY` encryption fails, preventing silent plaintext clobbering.
pub(crate) fn try_resolve_master_credentials(
    fs_root: Option<&Path>,
) -> anyhow::Result<(String, String)> {
    let env_user = env::var("AETHERFLOW_MASTER_USER")
        .or_else(|_| env::var("MASTER_USER"))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    let env_pass = env::var("AETHERFLOW_MASTER_PASS")
        .or_else(|_| env::var("MASTER_PASS"))
        .or_else(|_| env::var("AF_PASS"))
        .or_else(|_| env::var("AETHERFLOW_VNC_PASSWORD"))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && v != "adminadmin");

    if let Some(pass) = env_pass {
        return Ok((env_user.unwrap_or_else(|| "admin".to_string()), pass));
    }

    let rebase_path = |logical: &str| -> PathBuf {
        let p = Path::new(logical);
        match fs_root {
            Some(root) => {
                if p.starts_with(root) {
                    p.to_path_buf()
                } else if logical.starts_with('/') {
                    root.join(logical.trim_start_matches('/'))
                } else {
                    p.to_path_buf()
                }
            }
            None => p.to_path_buf(),
        }
    };

    let persist_path = match env::var("AETHERFLOW_MASTER_CREDS_FILE") {
        Ok(custom) if !custom.trim().is_empty() => rebase_path(custom.trim()),
        _ => rebase_path("/var/lib/aetherflow/.master.creds"),
    };

    let mut candidate_paths = Vec::new();
    if let Ok(custom_file) = env::var("AETHERFLOW_MASTER_CREDS_FILE") {
        let trimmed = custom_file.trim();
        if !trimmed.is_empty() {
            candidate_paths.push(rebase_path(trimmed));
        }
    }
    for default_logical in [
        "/var/lib/aetherflow/.master.creds",
        "/opt/AetherFlow/backend/data/.master.creds",
        "/etc/aetherflow/master.Indexed",
        "/install/.aetherflow.conf",
        "/root/.aetherflow_master",
    ] {
        candidate_paths.push(rebase_path(default_logical));
    }

    let mut file_user: Option<String> = None;
    let mut file_pass: Option<String> = None;
    for candidate in candidate_paths {
        if let Ok(contents) = fs::read_to_string(&candidate) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&contents) {
                for field in ["password", "passwd", "pass", "MASTER_PASS", "ha1"] {
                    if let Some(raw_secret) = val.get(field).and_then(|v| v.as_str()) {
                        let trimmed_secret = raw_secret.trim();
                        if trimmed_secret.starts_with("enc:v1:") {
                            af_db::decrypt_secret_if_needed(trimmed_secret).map_err(|err| {
                                anyhow::anyhow!(
                                    "refusing to overwrite undecryptable master credentials at {}: {}",
                                    candidate.display(),
                                    err
                                )
                            })?;
                        }
                    }
                }
            } else if contents.contains("enc:v1:") {
                anyhow::bail!(
                    "refusing to overwrite corrupted encrypted master credentials at {}",
                    candidate.display()
                );
            }
            let (u, p) = parse_master_credentials_content(&contents);
            if file_user.is_none() {
                file_user = u;
            }
            if file_pass.is_none() && p.is_some() {
                file_pass = p;
                break;
            }
        }
    }

    let master_user = env_user
        .or(file_user)
        .unwrap_or_else(|| "admin".to_string());
    let master_pass = match file_pass {
        Some(pass) => pass,
        None => {
            if let Ok(existing_persist) = fs::read_to_string(&persist_path) {
                if existing_persist.contains("enc:v1:") {
                    anyhow::bail!(
                        "refusing to overwrite existing encrypted master credentials at {}",
                        persist_path.display()
                    );
                }
            }
            let generated = format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            let stored_password = af_db::encrypt_secret_if_configured(&generated)?;
            let ha1 = hex::encode(af_models::md5::md5_digest(
                format!("{master_user}:Welcome to AetherFlow:{generated}").as_bytes(),
            ));
            let payload = serde_json::json!({
                "username": master_user,
                "password": stored_password,
                "ha1": af_db::encrypt_secret_if_configured(&ha1)?,
            })
            .to_string();
            let owner = if fs_root.is_none() && unsafe { libc::geteuid() } == 0 {
                Some((
                    crate::lookup_passwd_uid_reentrant("aetherflow")
                        .ok_or_else(|| anyhow::anyhow!("aetherflow user is unavailable"))?,
                    crate::lookup_group_gid("aetherflow")
                        .ok_or_else(|| anyhow::anyhow!("aetherflow group is unavailable"))?,
                ))
            } else {
                None
            };
            write_file_atomic_with_file_owner(
                &persist_path,
                payload.as_bytes(),
                0o600,
                fs_root,
                owner,
            )?;
            generated
        }
    };
    Ok((master_user, master_pass))
}

#[cfg(test)]
pub(super) fn resolve_master_credentials(fs_root: Option<&Path>) -> (String, String) {
    try_resolve_master_credentials(fs_root)
        .expect("resolve_master_credentials failed in test fixture")
}

/// Updates listening/scrape port in-place on preserved package configuration files
/// without clobbering existing operator credentials or custom settings.
pub(super) fn update_preserved_template_port(
    logical_path: &str,
    existing: &str,
    _rendered: &str,
    app_port: &str,
) -> Option<String> {
    match logical_path {
        "/etc/default/quasselcore" => {
            static QUASSEL_PORT_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r#"(?m)^([ \t]*PORT[ \t]*=[ \t]*)(?:"[0-9]+"|'[0-9]+'|[0-9]+)([ \t]*)$"#)
                    .unwrap()
            });
            if QUASSEL_PORT_RE.is_match(existing) {
                let replacement = format!("${{1}}\"{}\"${{2}}", app_port);
                Some(
                    QUASSEL_PORT_RE
                        .replace_all(existing, replacement.as_str())
                        .into_owned(),
                )
            } else {
                None
            }
        }
        "/var/lib/znc/configs/znc.conf" => {
            static ZNC_PORT_RE: Lazy<Regex> =
                Lazy::new(|| Regex::new(r"(?m)^[ \t]*Port[ \t]*=[ \t]*\d+([ \t]*)$").unwrap());
            if ZNC_PORT_RE.is_match(existing) {
                let replacement = format!("    Port = {}$1", app_port);
                Some(
                    ZNC_PORT_RE
                        .replace(existing, replacement.as_str())
                        .into_owned(),
                )
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Whether a request explicitly asks a removal to purge retained application
/// data. Install and update never purge, and the runner's own `DELETE_DATA`
/// environment is deliberately ignored so a stray daemon setting cannot turn
/// every ordinary uninstall into a destructive one.
pub(crate) fn package_request_deletes_data(req: &PackageRunnerRequest) -> bool {
    req.delete_data && req.action == "remove"
}
