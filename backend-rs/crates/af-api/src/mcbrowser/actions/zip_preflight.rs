use super::*;

pub fn detect_archive_format_from_path(path: &str) -> Result<ArchiveFormat, McBrowserError> {
    let lower = path.trim().to_ascii_lowercase();
    let compound = [
        (".tar.gz", ArchiveFormat::TarGz),
        (".tgz", ArchiveFormat::TarGz),
        (".tar.bz2", ArchiveFormat::TarBz2),
        (".tbz2", ArchiveFormat::TarBz2),
        (".tar.xz", ArchiveFormat::TarXz),
        (".txz", ArchiveFormat::TarXz),
        (".tar.lz4", ArchiveFormat::TarLz4),
        (".tlz4", ArchiveFormat::TarLz4),
        (".tar.sz", ArchiveFormat::TarSz),
        (".tsz", ArchiveFormat::TarSz),
        (".tar.br", ArchiveFormat::TarBr),
        (".tbr", ArchiveFormat::TarBr),
        (".tar.zst", ArchiveFormat::TarZst),
        (".tzst", ArchiveFormat::TarZst),
        (".zip", ArchiveFormat::Zip),
        (".tar", ArchiveFormat::Tar),
    ];
    for (suffix, fmt) in compound {
        if lower.ends_with(suffix) && lower.len() > suffix.len() {
            return Ok(fmt);
        }
    }
    Err(McBrowserError::BadRequest(
        "Unsupported archive filename extension: expected .zip, .tar, .tar.gz (.tgz), .tar.bz2 (.tbz2), .tar.xz (.txz), .tar.lz4 (.tlz4), .tar.sz (.tsz), .tar.br (.tbr), or .tar.zst (.tzst)".to_string(),
    ))
}

pub fn validate_extract_entry_relative_path(
    raw_name: &str,
) -> Result<(String, bool), McBrowserError> {
    if raw_name.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Archive contains an entry with an empty name".to_string(),
        ));
    }
    if raw_name.as_bytes().contains(&0) || raw_name.chars().any(char::is_control) {
        return Err(McBrowserError::BadRequest(
            "Archive entry name contains NUL or control characters".to_string(),
        ));
    }
    if raw_name.starts_with('/') || raw_name.contains('\\') || raw_name.contains(':') {
        return Err(McBrowserError::BadRequest(
            "Archive entry name contains forbidden absolute, backslash, or drive characters"
                .to_string(),
        ));
    }

    let is_dir_hint = raw_name.ends_with('/');
    let trimmed = raw_name.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Archive entry resolves to root directory".to_string(),
        ));
    }

    for segment in trimmed.split('/') {
        if segment.is_empty() || segment.trim().is_empty() {
            return Err(McBrowserError::BadRequest(
                "Archive entry contains an empty or whitespace-only path segment".to_string(),
            ));
        }
        if segment == "." || segment == ".." {
            return Err(McBrowserError::BadRequest(
                "Archive entry contains path traversal segments".to_string(),
            ));
        }
        if segment.starts_with(".af-upload-tmp.") || segment == ".af-upload-staging" {
            return Err(McBrowserError::BadRequest(
                "Archive entry uses a reserved staging filename".to_string(),
            ));
        }
    }

    let normalized = policy::normalize_target_path(trimmed, false)?;
    let _ = validate_archive_entry_name(&normalized)?;
    Ok((normalized, is_dir_hint))
}

pub(super) fn check_compression_ratio(
    archive_compressed_size: u64,
    expanded_bytes: u64,
) -> Result<(), McBrowserError> {
    if expanded_bytes <= ACTION_COMPRESSION_RATIO_GRACE_BYTES {
        return Ok(());
    }
    let baseline = archive_compressed_size.max(1);
    let max_allowed = baseline
        .saturating_mul(MAX_ACTION_EXTRACT_COMPRESSION_RATIO)
        .saturating_add(ACTION_COMPRESSION_RATIO_GRACE_BYTES);
    if expanded_bytes > max_allowed {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "Archive decompression ratio exceeds maximum safety limit ({MAX_ACTION_EXTRACT_COMPRESSION_RATIO}:1)"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn preflight_authorize_and_check_destination_entry(
    conn: &Connection,
    _bfs: &BrowserFs,
    user: &AuthUser,
    destination_dir: &str,
    rel_entry_path: &str,
    seen_files: &mut HashSet<String>,
    seen_dirs: &mut HashSet<String>,
    is_dir: bool,
) -> Result<String, McBrowserError> {
    let full_target = format!("{destination_dir}/{rel_entry_path}");
    let normalized_target = policy::normalize_target_path(&full_target, false)?;

    let mut prefix = destination_dir.to_string();
    let segments: Vec<&str> = rel_entry_path.split('/').collect();
    for (idx, seg) in segments.iter().enumerate() {
        prefix = format!("{prefix}/{seg}");
        let is_last = idx + 1 == segments.len();
        if !is_last || is_dir {
            if seen_files.contains(&prefix) {
                return Err(McBrowserError::BadRequest(format!(
                    "Archive contains conflicting file and directory paths at '{rel_entry_path}'"
                )));
            }
            if is_last && is_dir && !seen_dirs.insert(prefix.clone()) {
                return Err(McBrowserError::BadRequest(format!(
                    "Archive contains duplicate directory entry '{rel_entry_path}'"
                )));
            }
            seen_dirs.insert(prefix.clone());
            policy::authorize_with_conn(conn, user, Permission::Execute, &prefix)?;
            policy::authorize_with_conn(conn, user, Permission::Create, &prefix)?;
        } else {
            if seen_dirs.contains(&prefix) || !seen_files.insert(prefix.clone()) {
                return Err(McBrowserError::BadRequest(format!(
                    "Archive contains duplicate or conflicting entry path '{rel_entry_path}'"
                )));
            }
            policy::authorize_with_conn(conn, user, Permission::Execute, &prefix)?;
            policy::authorize_with_conn(conn, user, Permission::Create, &prefix)?;
        }
    }

    Ok(normalized_target)
}

const ZIP_LOCAL_FILE_HEADER_SIG: u32 = 0x04034b50;
const ZIP_CENTRAL_DIR_HEADER_SIG: u32 = 0x02014b50;
const ZIP_EOCD_SIG: u32 = 0x06054b50;
const ZIP_EOCD64_SIG: u32 = 0x06064b50;
const ZIP_EOCD64_LOCATOR_SIG: u32 = 0x07064b50;
pub const MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES: u64 = 8 * 1024 * 1024;
const ZIP_ADMISSION_READ_LIMIT_BYTES: u64 = MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES + 131_072;

#[derive(Debug, Clone, Copy)]
pub(super) struct ZipDirectoryAdmission {
    entries: usize,
    offset: u64,
    size: u64,
}

pub(super) struct AdmittedZipReader {
    file: File,
    directory_end: u64,
    footer: [u8; 98],
    position: u64,
    length: u64,
}

impl AdmittedZipReader {
    fn new(file: File, admission: ZipDirectoryAdmission) -> io::Result<Self> {
        let directory_end = admission
            .offset
            .checked_add(admission.size)
            .ok_or_else(|| {
                io::Error::new(ErrorKind::InvalidData, "ZIP directory extent overflow")
            })?;
        let length = directory_end.checked_add(98).ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "ZIP metadata extent overflow")
        })?;
        let mut footer = [0u8; 98];
        footer[0..4].copy_from_slice(&ZIP_EOCD64_SIG.to_le_bytes());
        footer[4..12].copy_from_slice(&44u64.to_le_bytes());
        footer[12..14].copy_from_slice(&45u16.to_le_bytes());
        footer[14..16].copy_from_slice(&45u16.to_le_bytes());
        footer[24..32].copy_from_slice(&(admission.entries as u64).to_le_bytes());
        footer[32..40].copy_from_slice(&(admission.entries as u64).to_le_bytes());
        footer[40..48].copy_from_slice(&admission.size.to_le_bytes());
        footer[48..56].copy_from_slice(&admission.offset.to_le_bytes());
        footer[56..60].copy_from_slice(&ZIP_EOCD64_LOCATOR_SIG.to_le_bytes());
        footer[64..72].copy_from_slice(&directory_end.to_le_bytes());
        footer[72..76].copy_from_slice(&1u32.to_le_bytes());
        footer[76..80].copy_from_slice(&ZIP_EOCD_SIG.to_le_bytes());
        footer[84..86].copy_from_slice(&u16::MAX.to_le_bytes());
        footer[86..88].copy_from_slice(&u16::MAX.to_le_bytes());
        footer[88..92].copy_from_slice(&u32::MAX.to_le_bytes());
        footer[92..96].copy_from_slice(&u32::MAX.to_le_bytes());
        Ok(Self {
            file,
            directory_end,
            footer,
            position: 0,
            length,
        })
    }
}

impl Read for AdmittedZipReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.length || buffer.is_empty() {
            return Ok(0);
        }
        let bytes_read = if self.position < self.directory_end {
            let limit = (self.directory_end - self.position).min(buffer.len() as u64) as usize;
            self.file.seek(SeekFrom::Start(self.position))?;
            self.file.read(&mut buffer[..limit])?
        } else {
            let footer_offset = (self.position - self.directory_end) as usize;
            let limit = (self.footer.len() - footer_offset).min(buffer.len());
            buffer[..limit].copy_from_slice(&self.footer[footer_offset..footer_offset + limit]);
            limit
        };
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

impl Seek for AdmittedZipReader {
    fn seek(&mut self, offset: SeekFrom) -> io::Result<u64> {
        let position = match offset {
            SeekFrom::Start(position) => i128::from(position),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
        };
        self.position = u64::try_from(position)
            .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "ZIP seek is out of bounds"))?;
        Ok(self.position)
    }
}

pub(super) fn map_zip_io_error(err: io::Error, default_msg: &str) -> McBrowserError {
    match err.kind() {
        ErrorKind::TimedOut => McBrowserError::RequestTimeout(
            "ExtractArchive exceeded maximum execution time".to_string(),
        ),
        ErrorKind::FileTooLarge => McBrowserError::PayloadTooLarge(
            "ZIP archive metadata or stream exceeds safety limit".to_string(),
        ),
        _ => McBrowserError::BadRequest(default_msg.to_string()),
    }
}

pub(super) fn skip_exact_bounded<R: Read>(
    reader: &mut R,
    mut remaining: u64,
) -> Result<(), McBrowserError> {
    let mut scratch = [0u8; 4096];
    while remaining > 0 {
        let step = (remaining as usize).min(scratch.len());
        reader
            .read_exact(&mut scratch[..step])
            .map_err(|e| map_zip_io_error(e, "Truncated ZIP central directory"))?;
        remaining -= step as u64;
    }
    Ok(())
}

pub(super) fn preflight_zip_raw_headers_for_encryption(
    file: &mut File,
    file_len: u64,
    deadline: Instant,
) -> Result<ZipDirectoryAdmission, McBrowserError> {
    check_action_deadline(deadline, "ExtractArchive ZIP admission")?;
    if file_len < 22 {
        return Err(McBrowserError::BadRequest(
            "Corrupt or truncated ZIP archive".to_string(),
        ));
    }

    let cloned = file
        .try_clone()
        .map_err(|e| map_fs_io_error(e, "Failed to clone ZIP descriptor for admission"))?;
    let mut reader = BoundedDeadlineReader::new(
        cloned,
        ZIP_ADMISSION_READ_LIMIT_BYTES,
        deadline,
        "ExtractArchive ZIP admission",
    );

    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| map_zip_io_error(e, "Failed to seek ZIP archive"))?;
    let mut sig_buf = [0u8; 4];
    reader
        .read_exact(&mut sig_buf)
        .map_err(|e| map_zip_io_error(e, "Corrupt or unreadable ZIP header"))?;
    let first_sig = u32::from_le_bytes(sig_buf);
    if first_sig != ZIP_LOCAL_FILE_HEADER_SIG && first_sig != ZIP_EOCD_SIG {
        return Err(McBrowserError::BadRequest(
            "Invalid ZIP archive signature".to_string(),
        ));
    }
    if first_sig == ZIP_LOCAL_FILE_HEADER_SIG {
        let mut lfh_rest = [0u8; 26];
        reader
            .read_exact(&mut lfh_rest)
            .map_err(|e| map_zip_io_error(e, "Truncated ZIP local file header"))?;
        let flags = u16::from_le_bytes([lfh_rest[2], lfh_rest[3]]);
        let method = u16::from_le_bytes([lfh_rest[4], lfh_rest[5]]);
        if (flags & 0x0001) != 0 || (flags & 0x0040) != 0 || method == 99 {
            return Err(McBrowserError::BadRequest(
                "Encrypted ZIP archive entries are not supported".to_string(),
            ));
        }
    }

    let tail_len = file_len.min(65_577) as usize;
    let tail_start = file_len.saturating_sub(tail_len as u64);
    reader
        .seek(SeekFrom::Start(tail_start))
        .map_err(|e| map_zip_io_error(e, "Failed to seek ZIP central directory"))?;
    let mut tail = vec![0u8; tail_len];
    reader
        .read_exact(&mut tail)
        .map_err(|e| map_zip_io_error(e, "Failed to read ZIP central directory"))?;

    let mut eocd_pos: Option<usize> = None;
    if tail.len() >= 22 {
        for idx in (0..=tail.len() - 22).rev() {
            if u32::from_le_bytes([tail[idx], tail[idx + 1], tail[idx + 2], tail[idx + 3]])
                == ZIP_EOCD_SIG
            {
                let comment_len = u16::from_le_bytes([tail[idx + 20], tail[idx + 21]]) as usize;
                if idx + 22 + comment_len == tail.len() {
                    eocd_pos = Some(idx);
                    break;
                }
            }
        }
    }

    let Some(eocd_idx) = eocd_pos else {
        return Err(McBrowserError::BadRequest(
            "Missing or corrupt ZIP end of central directory record".to_string(),
        ));
    };

    let eocd_abs_offset = tail_start + (eocd_idx as u64);
    let disk_number = u16::from_le_bytes([tail[eocd_idx + 4], tail[eocd_idx + 5]]);
    let cd_disk_number = u16::from_le_bytes([tail[eocd_idx + 6], tail[eocd_idx + 7]]);
    let disk_entries_16 = u16::from_le_bytes([tail[eocd_idx + 8], tail[eocd_idx + 9]]);
    let total_entries_16 = u16::from_le_bytes([tail[eocd_idx + 10], tail[eocd_idx + 11]]);
    let cd_size_32 = u32::from_le_bytes([
        tail[eocd_idx + 12],
        tail[eocd_idx + 13],
        tail[eocd_idx + 14],
        tail[eocd_idx + 15],
    ]);
    let cd_offset_32 = u32::from_le_bytes([
        tail[eocd_idx + 16],
        tail[eocd_idx + 17],
        tail[eocd_idx + 18],
        tail[eocd_idx + 19],
    ]);

    let has_zip64_locator = eocd_idx >= 20
        && (cd_offset_32 == u32::MAX
            || cd_size_32 == u32::MAX
            || u64::from(cd_offset_32) + u64::from(cd_size_32) <= eocd_abs_offset - 20)
        && u32::from_le_bytes([
            tail[eocd_idx - 20],
            tail[eocd_idx - 19],
            tail[eocd_idx - 18],
            tail[eocd_idx - 17],
        ]) == ZIP_EOCD64_LOCATOR_SIG;

    let requires_zip64 = disk_number == u16::MAX
        || cd_disk_number == u16::MAX
        || disk_entries_16 == u16::MAX
        || total_entries_16 == u16::MAX
        || cd_size_32 == u32::MAX
        || cd_offset_32 == u32::MAX;

    let (declared_entries, cd_size, cd_offset, cd_upper_bound) = if has_zip64_locator
        || requires_zip64
    {
        if !has_zip64_locator || eocd_abs_offset < 20 {
            return Err(McBrowserError::BadRequest(
                "Missing or corrupt ZIP64 end of central directory locator".to_string(),
            ));
        }
        let loc_idx = eocd_idx - 20;
        let locator_abs_offset = eocd_abs_offset - 20;
        let z64_cd_disk = u32::from_le_bytes([
            tail[loc_idx + 4],
            tail[loc_idx + 5],
            tail[loc_idx + 6],
            tail[loc_idx + 7],
        ]);
        let z64_eocd_offset = u64::from_le_bytes([
            tail[loc_idx + 8],
            tail[loc_idx + 9],
            tail[loc_idx + 10],
            tail[loc_idx + 11],
            tail[loc_idx + 12],
            tail[loc_idx + 13],
            tail[loc_idx + 14],
            tail[loc_idx + 15],
        ]);
        let z64_total_disks = u32::from_le_bytes([
            tail[loc_idx + 16],
            tail[loc_idx + 17],
            tail[loc_idx + 18],
            tail[loc_idx + 19],
        ]);
        if z64_cd_disk != 0 || (z64_total_disks != 0 && z64_total_disks != 1) {
            return Err(McBrowserError::BadRequest(
                "Multi-disk ZIP64 archives are not supported".to_string(),
            ));
        }
        if (disk_number != 0 && disk_number != u16::MAX)
            || (cd_disk_number != 0 && cd_disk_number != u16::MAX)
        {
            return Err(McBrowserError::BadRequest(
                "Multi-disk ZIP archives are not supported".to_string(),
            ));
        }
        if z64_eocd_offset.checked_add(56).is_none() || z64_eocd_offset + 56 > locator_abs_offset {
            return Err(McBrowserError::BadRequest(
                "Invalid or out-of-bounds ZIP64 EOCD offset".to_string(),
            ));
        }

        reader
            .seek(SeekFrom::Start(z64_eocd_offset))
            .map_err(|e| map_zip_io_error(e, "Failed to seek ZIP64 EOCD record"))?;
        let mut z64_buf = [0u8; 56];
        reader
            .read_exact(&mut z64_buf)
            .map_err(|e| map_zip_io_error(e, "Truncated ZIP64 EOCD record"))?;

        if u32::from_le_bytes([z64_buf[0], z64_buf[1], z64_buf[2], z64_buf[3]]) != ZIP_EOCD64_SIG {
            return Err(McBrowserError::BadRequest(
                "Invalid ZIP64 EOCD signature".to_string(),
            ));
        }
        let z64_record_size = u64::from_le_bytes(z64_buf[4..12].try_into().unwrap());
        if z64_record_size < 44 {
            return Err(McBrowserError::BadRequest(
                "Malformed ZIP64 EOCD record size".to_string(),
            ));
        }
        let z64_total_record_bytes = 12u64.checked_add(z64_record_size).ok_or_else(|| {
            McBrowserError::BadRequest("ZIP64 EOCD record size overflow".to_string())
        })?;
        let z64_end = z64_eocd_offset
            .checked_add(z64_total_record_bytes)
            .ok_or_else(|| McBrowserError::BadRequest("ZIP64 EOCD span overflow".to_string()))?;
        if z64_end > locator_abs_offset {
            return Err(McBrowserError::BadRequest(
                "ZIP64 EOCD record overlaps locator".to_string(),
            ));
        }

        let z64_disk_num = u32::from_le_bytes(z64_buf[16..20].try_into().unwrap());
        let z64_cd_disk_num = u32::from_le_bytes(z64_buf[20..24].try_into().unwrap());
        if z64_disk_num != 0 || z64_cd_disk_num != 0 {
            return Err(McBrowserError::BadRequest(
                "Multi-disk ZIP64 archives are not supported".to_string(),
            ));
        }

        let z64_disk_entries = u64::from_le_bytes(z64_buf[24..32].try_into().unwrap());
        let z64_total_entries = u64::from_le_bytes(z64_buf[32..40].try_into().unwrap());
        let z64_cd_size = u64::from_le_bytes(z64_buf[40..48].try_into().unwrap());
        let z64_cd_offset = u64::from_le_bytes(z64_buf[48..56].try_into().unwrap());

        if z64_disk_entries != z64_total_entries {
            return Err(McBrowserError::BadRequest(
                "Split central directory ZIP64 archives are not supported".to_string(),
            ));
        }
        if disk_entries_16 != u16::MAX && (disk_entries_16 as u64) != z64_disk_entries {
            return Err(McBrowserError::BadRequest(
                "Mismatched ZIP64 central directory entry counts".to_string(),
            ));
        }
        if total_entries_16 != u16::MAX && (total_entries_16 as u64) != z64_total_entries {
            return Err(McBrowserError::BadRequest(
                "Mismatched ZIP64 total entry counts".to_string(),
            ));
        }
        if cd_size_32 != u32::MAX && (cd_size_32 as u64) != z64_cd_size {
            return Err(McBrowserError::BadRequest(
                "Mismatched ZIP64 central directory size".to_string(),
            ));
        }
        if cd_offset_32 != u32::MAX && (cd_offset_32 as u64) != z64_cd_offset {
            return Err(McBrowserError::BadRequest(
                "Mismatched ZIP64 central directory offset".to_string(),
            ));
        }

        (
            z64_total_entries,
            z64_cd_size,
            z64_cd_offset,
            z64_eocd_offset,
        )
    } else {
        if disk_number != 0 || cd_disk_number != 0 || disk_entries_16 != total_entries_16 {
            return Err(McBrowserError::BadRequest(
                "Multi-disk ZIP archives are not supported".to_string(),
            ));
        }
        (
            total_entries_16 as u64,
            cd_size_32 as u64,
            cd_offset_32 as u64,
            eocd_abs_offset,
        )
    };

    if declared_entries == 0 {
        return Err(McBrowserError::BadRequest(
            "Archive contains no entries".to_string(),
        ));
    }
    if declared_entries > MAX_ACTION_ARCHIVE_ENTRIES as u64 {
        return Err(McBrowserError::BadRequest(format!(
            "Archive entry count ({declared_entries}) exceeds maximum limit of {MAX_ACTION_ARCHIVE_ENTRIES}"
        )));
    }
    if cd_size == 0 {
        return Err(McBrowserError::BadRequest(
            "Corrupt ZIP central directory size".to_string(),
        ));
    }
    if cd_size > MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "ZIP central directory size ({cd_size} bytes) exceeds maximum limit of {MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES} bytes"
        )));
    }
    let cd_end = cd_offset.checked_add(cd_size).ok_or_else(|| {
        McBrowserError::BadRequest("ZIP central directory offset overflow".to_string())
    })?;
    if cd_end > cd_upper_bound || cd_end > file_len {
        return Err(McBrowserError::BadRequest(
            "ZIP central directory span is out of bounds".to_string(),
        ));
    }

    reader
        .seek(SeekFrom::Start(cd_offset))
        .map_err(|e| map_zip_io_error(e, "Failed to seek ZIP central directory"))?;

    let mut consumed = 0u64;
    let mut actual_entries = 0usize;
    let mut header_buf = [0u8; 46];
    let mut extra_buf = Vec::new();

    while consumed < cd_size {
        check_action_deadline(deadline, "ExtractArchive ZIP admission")?;
        if cd_size - consumed < 46 {
            return Err(McBrowserError::BadRequest(
                "Truncated or misaligned ZIP central directory entry".to_string(),
            ));
        }
        actual_entries = actual_entries.saturating_add(1);
        if actual_entries > MAX_ACTION_ARCHIVE_ENTRIES {
            return Err(McBrowserError::BadRequest(format!(
                "Archive entry count ({actual_entries}) exceeds maximum limit of {MAX_ACTION_ARCHIVE_ENTRIES}"
            )));
        }

        reader
            .read_exact(&mut header_buf)
            .map_err(|e| map_zip_io_error(e, "Truncated ZIP central directory header"))?;
        let sig = u32::from_le_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
        if sig != ZIP_CENTRAL_DIR_HEADER_SIG {
            return Err(McBrowserError::BadRequest(
                "Invalid ZIP central directory entry signature".to_string(),
            ));
        }

        let flags = u16::from_le_bytes([header_buf[8], header_buf[9]]);
        let method = u16::from_le_bytes([header_buf[10], header_buf[11]]);
        if (flags & 0x0001) != 0 || (flags & 0x0040) != 0 || method == 99 {
            return Err(McBrowserError::BadRequest(
                "Encrypted ZIP archive entries are not supported".to_string(),
            ));
        }

        let comp_32 = u32::from_le_bytes([
            header_buf[20],
            header_buf[21],
            header_buf[22],
            header_buf[23],
        ]);
        let uncomp_32 = u32::from_le_bytes([
            header_buf[24],
            header_buf[25],
            header_buf[26],
            header_buf[27],
        ]);
        let name_len = u16::from_le_bytes([header_buf[28], header_buf[29]]) as u64;
        let extra_len = u16::from_le_bytes([header_buf[30], header_buf[31]]) as usize;
        let comment_len = u16::from_le_bytes([header_buf[32], header_buf[33]]) as u64;
        let disk_start_16 = u16::from_le_bytes([header_buf[34], header_buf[35]]);
        let lfh_offset_32 = u32::from_le_bytes([
            header_buf[42],
            header_buf[43],
            header_buf[44],
            header_buf[45],
        ]);

        let entry_total_len = 46u64 + name_len + (extra_len as u64) + comment_len;
        if consumed + entry_total_len > cd_size {
            return Err(McBrowserError::BadRequest(
                "ZIP central directory entry extends past central directory boundary".to_string(),
            ));
        }

        skip_exact_bounded(&mut reader, name_len)?;
        extra_buf.resize(extra_len, 0);
        if extra_len > 0 {
            reader
                .read_exact(&mut extra_buf)
                .map_err(|e| map_zip_io_error(e, "Truncated ZIP central directory extra field"))?;
        }
        skip_exact_bounded(&mut reader, comment_len)?;

        let mut lfh_offset = lfh_offset_32 as u64;
        let mut disk_start = disk_start_16 as u32;
        let need_uncomp_64 = uncomp_32 == u32::MAX;
        let need_comp_64 = comp_32 == u32::MAX;
        let need_offset_64 = lfh_offset_32 == u32::MAX;
        let need_disk_64 = disk_start_16 == u16::MAX;

        {
            let mut found_z64_extra = false;
            let mut pos = 0usize;
            while pos + 4 <= extra_buf.len() {
                let header_id = u16::from_le_bytes([extra_buf[pos], extra_buf[pos + 1]]);
                let data_size =
                    u16::from_le_bytes([extra_buf[pos + 2], extra_buf[pos + 3]]) as usize;
                pos += 4;
                if pos + data_size > extra_buf.len() {
                    return Err(McBrowserError::BadRequest(
                        "Malformed ZIP central directory extra field".to_string(),
                    ));
                }
                if header_id == 0x0001 {
                    if found_z64_extra {
                        return Err(McBrowserError::BadRequest(
                            "Duplicate ZIP64 extended information extra field".to_string(),
                        ));
                    }
                    let field = &extra_buf[pos..pos + data_size];
                    let mut fpos = 0usize;
                    if need_uncomp_64 {
                        if fpos + 8 > field.len() {
                            return Err(McBrowserError::BadRequest(
                                "Truncated ZIP64 uncompressed size in extra field".to_string(),
                            ));
                        }
                        fpos += 8;
                    }
                    if need_comp_64 {
                        if fpos + 8 > field.len() {
                            return Err(McBrowserError::BadRequest(
                                "Truncated ZIP64 compressed size in extra field".to_string(),
                            ));
                        }
                        fpos += 8;
                    }
                    if need_offset_64 {
                        if fpos + 8 > field.len() {
                            return Err(McBrowserError::BadRequest(
                                "Truncated ZIP64 local header offset in extra field".to_string(),
                            ));
                        }
                        lfh_offset = u64::from_le_bytes(field[fpos..fpos + 8].try_into().unwrap());
                        fpos += 8;
                    }
                    if need_disk_64 {
                        if fpos + 4 > field.len() {
                            return Err(McBrowserError::BadRequest(
                                "Truncated ZIP64 disk number in extra field".to_string(),
                            ));
                        }
                        disk_start = u32::from_le_bytes(field[fpos..fpos + 4].try_into().unwrap());
                    }
                    found_z64_extra = true;
                }
                pos += data_size;
            }
            if !found_z64_extra
                && (need_uncomp_64 || need_comp_64 || need_offset_64 || need_disk_64)
            {
                return Err(McBrowserError::BadRequest(
                    "Missing required ZIP64 extended information extra field".to_string(),
                ));
            }
        }

        if disk_start != 0 {
            return Err(McBrowserError::BadRequest(
                "Multi-disk ZIP archive entries are not supported".to_string(),
            ));
        }
        if lfh_offset.checked_add(30).is_none() || lfh_offset + 30 > cd_offset {
            return Err(McBrowserError::BadRequest(
                "ZIP entry local header offset is out of bounds".to_string(),
            ));
        }

        consumed += entry_total_len;
    }

    if actual_entries as u64 != declared_entries {
        return Err(McBrowserError::BadRequest(
            "ZIP central directory entry count does not match declared EOCD count".to_string(),
        ));
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|e| map_fs_io_error(e, "Failed to rewind ZIP archive"))?;
    Ok(ZipDirectoryAdmission {
        entries: actual_entries,
        offset: cd_offset,
        size: cd_size,
    })
}

pub(super) fn open_admitted_zip_archive(
    archive_file: &mut File,
    archive_size: u64,
    deadline: Instant,
    context: &'static str,
) -> Result<
    (
        zip::ZipArchive<BoundedDeadlineReader<AdmittedZipReader>>,
        usize,
    ),
    McBrowserError,
> {
    let admission = preflight_zip_raw_headers_for_encryption(archive_file, archive_size, deadline)?;
    let reader = archive_file
        .try_clone()
        .map_err(|e| map_fs_io_error(e, "Failed to clone archive descriptor"))?;
    let max_zip_read_bytes = archive_size
        .saturating_mul(4)
        .saturating_add(MAX_ACTION_ZIP_CENTRAL_DIRECTORY_BYTES)
        .saturating_add(1024 * 1024);
    let admitted_reader = AdmittedZipReader::new(reader, admission)
        .map_err(|error| map_zip_io_error(error, "Failed to bind admitted ZIP metadata"))?;
    let bounded_reader =
        BoundedDeadlineReader::new(admitted_reader, max_zip_read_bytes, deadline, context);
    let zip = zip::ZipArchive::with_config(
        zip::read::Config {
            archive_offset: zip::read::ArchiveOffset::Known(0),
        },
        bounded_reader,
    )
    .map_err(|err| {
        if Instant::now() > deadline {
            return McBrowserError::RequestTimeout(
                "ExtractArchive exceeded maximum execution time".to_string(),
            );
        }
        if let zip::result::ZipError::Io(io_err) = &err {
            if io_err.kind() == ErrorKind::TimedOut {
                return McBrowserError::RequestTimeout(
                    "ExtractArchive exceeded maximum execution time".to_string(),
                );
            }
            if io_err.kind() == ErrorKind::FileTooLarge {
                return McBrowserError::PayloadTooLarge(
                    "ZIP archive read stream exceeds safety limit".to_string(),
                );
            }
        }
        let msg = err.to_string();
        if msg.to_ascii_lowercase().contains("password")
            || msg.to_ascii_lowercase().contains("encrypt")
        {
            McBrowserError::BadRequest("Encrypted ZIP archives are not supported".to_string())
        } else {
            McBrowserError::BadRequest(format!("Invalid or corrupt ZIP archive: {msg}"))
        }
    })?;

    let entry_count = zip.len();
    if entry_count == 0 {
        return Err(McBrowserError::BadRequest(
            "Archive contains no entries".to_string(),
        ));
    }
    if zip.offset() != 0 || zip.central_directory_start() != admission.offset {
        return Err(McBrowserError::BadRequest(
            "ZIP decoder did not retain admitted directory identity".to_string(),
        ));
    }
    if entry_count > MAX_ACTION_ARCHIVE_ENTRIES || entry_count != admission.entries {
        return Err(McBrowserError::BadRequest(format!(
            "Archive entry count ({entry_count}) exceeds maximum limit of {MAX_ACTION_ARCHIVE_ENTRIES} or mismatches central directory admission"
        )));
    }
    Ok((zip, entry_count))
}

pub(super) fn is_zip_unix_symlink_or_special(unix_mode: Option<u32>) -> bool {
    let Some(mode) = unix_mode else {
        return false;
    };
    let file_type = mode & libc::S_IFMT;
    if file_type == 0 {
        return false;
    }
    file_type != libc::S_IFREG && file_type != libc::S_IFDIR
}

#[derive(Debug, Clone)]
pub(super) struct ZipPreflightItem {
    pub(super) index: usize,
    pub(super) target_path: String,
    pub(super) is_dir: bool,
    pub(super) declared_uncompressed: u64,
}

pub(super) fn preflight_zip_archive(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    archive_file: &mut File,
    archive_size: u64,
    destination_dir: &str,
    deadline: Instant,
) -> Result<Vec<ZipPreflightItem>, McBrowserError> {
    let (mut zip, entry_count) = open_admitted_zip_archive(
        archive_file,
        archive_size,
        deadline,
        "ExtractArchive ZIP preflight",
    )?;

    let mut seen_files = HashSet::new();
    let mut seen_dirs = HashSet::new();
    let mut total_declared_uncompressed: u64 = 0;
    let mut total_actual_uncompressed = 0_u64;
    let mut buffer = [0_u8; ACTION_IO_BUF_BYTES];
    let mut items = Vec::with_capacity(entry_count);

    for idx in 0..entry_count {
        check_action_deadline(deadline, "ExtractArchive preflight")?;
        let mut entry = zip.by_index(idx).map_err(|err| {
            if let zip::result::ZipError::Io(io_err) = &err {
                if io_err.kind() == ErrorKind::TimedOut {
                    return McBrowserError::RequestTimeout(
                        "ExtractArchive exceeded maximum execution time".to_string(),
                    );
                }
                if io_err.kind() == ErrorKind::FileTooLarge {
                    return McBrowserError::PayloadTooLarge(
                        "ZIP archive read stream exceeds safety limit".to_string(),
                    );
                }
            }
            let msg = err.to_string();
            if msg.to_ascii_lowercase().contains("password")
                || msg.to_ascii_lowercase().contains("encrypt")
            {
                McBrowserError::BadRequest(
                    "Encrypted ZIP archive entries are not supported".to_string(),
                )
            } else {
                McBrowserError::BadRequest(format!("Malformed ZIP archive entry: {msg}"))
            }
        })?;

        if entry.encrypted() {
            return Err(McBrowserError::BadRequest(
                "Encrypted ZIP archive entries are not supported".to_string(),
            ));
        }

        if entry.is_symlink() || is_zip_unix_symlink_or_special(entry.unix_mode()) {
            return Err(McBrowserError::BadRequest(
                "Archive contains forbidden symlink or special device entry".to_string(),
            ));
        }

        let raw_name_bytes = entry.name_raw();
        let raw_name = std::str::from_utf8(raw_name_bytes).map_err(|_| {
            McBrowserError::BadRequest("Archive entry name is not valid UTF-8".to_string())
        })?;

        let (rel_path, is_dir_hint) = validate_extract_entry_relative_path(raw_name)?;
        let is_dir = entry.is_dir() || is_dir_hint;

        let declared_size = entry.size();
        let compressed_size = entry.compressed_size();
        if is_dir && declared_size > 0 {
            return Err(McBrowserError::BadRequest(
                "Archive directory entry cannot carry file payload bytes".to_string(),
            ));
        }
        if !is_dir {
            if declared_size > MAX_ACTION_EXTRACT_ENTRY_BYTES {
                return Err(McBrowserError::PayloadTooLarge(format!(
                    "Archive entry '{rel_path}' size ({declared_size} bytes) exceeds per-entry limit of {MAX_ACTION_EXTRACT_ENTRY_BYTES} bytes"
                )));
            }
            check_compression_ratio(compressed_size.max(1), declared_size)?;
            total_declared_uncompressed = total_declared_uncompressed.saturating_add(declared_size);
            if total_declared_uncompressed > MAX_ACTION_EXTRACT_TOTAL_BYTES {
                return Err(McBrowserError::PayloadTooLarge(format!(
                    "Archive total uncompressed size exceeds maximum limit of {MAX_ACTION_EXTRACT_TOTAL_BYTES} bytes"
                )));
            }
            check_compression_ratio(archive_size, total_declared_uncompressed)?;
        }

        let target_path = preflight_authorize_and_check_destination_entry(
            conn,
            bfs,
            user,
            destination_dir,
            &rel_path,
            &mut seen_files,
            &mut seen_dirs,
            is_dir,
        )?;

        let mut actual_size = 0_u64;
        loop {
            check_action_deadline(deadline, "ExtractArchive preflight")?;
            let count = entry.read(&mut buffer).map_err(|error| {
                if error.kind() == ErrorKind::TimedOut {
                    McBrowserError::RequestTimeout(
                        "ExtractArchive exceeded maximum execution time".to_string(),
                    )
                } else if error.kind() == ErrorKind::FileTooLarge {
                    McBrowserError::PayloadTooLarge(
                        "ZIP archive read stream exceeds safety limit".to_string(),
                    )
                } else {
                    McBrowserError::BadRequest(format!("Corrupt ZIP entry stream: {error}"))
                }
            })?;
            if count == 0 {
                break;
            }
            actual_size = actual_size.saturating_add(count as u64);
            total_actual_uncompressed = total_actual_uncompressed.saturating_add(count as u64);
            if actual_size > MAX_ACTION_EXTRACT_ENTRY_BYTES
                || total_actual_uncompressed > MAX_ACTION_EXTRACT_TOTAL_BYTES
            {
                return Err(McBrowserError::PayloadTooLarge(
                    "ZIP expanded bytes exceed extraction safety limits".to_string(),
                ));
            }
            check_compression_ratio(compressed_size.max(1), actual_size)?;
            check_compression_ratio(archive_size, total_actual_uncompressed)?;
        }
        if actual_size != declared_size {
            return Err(McBrowserError::BadRequest(
                "ZIP entry expanded size does not match its declared size".to_string(),
            ));
        }

        items.push(ZipPreflightItem {
            index: idx,
            target_path,
            is_dir,
            declared_uncompressed: declared_size,
        });
    }

    Ok(items)
}
