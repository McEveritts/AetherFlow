use super::*;

pub(super) fn open_tar_stream_decoder<'a>(
    format: ArchiveFormat,
    reader: Box<dyn Read + 'a>,
) -> Result<Box<dyn Read + 'a>, McBrowserError> {
    match format {
        ArchiveFormat::Tar => Ok(reader),
        ArchiveFormat::TarGz => Ok(Box::new(GzDecoder::new(reader))),
        ArchiveFormat::TarBz2 => Ok(Box::new(bzip2::read::BzDecoder::new(reader))),
        ArchiveFormat::TarXz => Ok(Box::new(xz2::read::XzDecoder::new(reader))),
        ArchiveFormat::TarLz4 => Ok(Box::new(lz4_flex::frame::FrameDecoder::new(reader))),
        ArchiveFormat::TarSz => Ok(Box::new(snap::read::FrameDecoder::new(reader))),
        ArchiveFormat::TarBr => Ok(Box::new(brotli::Decompressor::new(
            reader,
            ACTION_IO_BUF_BYTES,
        ))),
        ArchiveFormat::TarZst => {
            let dec = zstd::stream::read::Decoder::new(reader).map_err(|e| {
                McBrowserError::BadRequest(format!("Invalid zstd stream header: {e}"))
            })?;
            Ok(Box::new(dec))
        }
        ArchiveFormat::Zip => Err(McBrowserError::Internal(
            "Unexpected ZIP format in tar decoder".to_string(),
        )),
    }
}

pub(super) fn is_allowed_tar_entry_type(
    entry_type: tar::EntryType,
) -> Result<Option<bool>, McBrowserError> {
    if entry_type == tar::EntryType::Regular
        || entry_type == tar::EntryType::Continuous
        || entry_type.as_byte() == 0
    {
        return Ok(Some(false));
    }
    if entry_type == tar::EntryType::Directory {
        return Ok(Some(true));
    }
    if entry_type == tar::EntryType::XHeader || entry_type == tar::EntryType::XGlobalHeader {
        return Ok(None);
    }
    if entry_type == tar::EntryType::GNULongName {
        return Ok(None);
    }
    Err(McBrowserError::BadRequest(format!(
        "Archive contains forbidden entry type {:?} (symlinks, hardlinks, and special devices are prohibited)",
        entry_type
    )))
}

#[allow(clippy::too_many_arguments)]
pub(super) fn preflight_tar_archive(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    archive_file: &mut File,
    archive_size: u64,
    format: ArchiveFormat,
    destination_dir: &str,
    deadline: Instant,
) -> Result<(usize, u64), McBrowserError> {
    archive_file
        .seek(SeekFrom::Start(0))
        .map_err(|e| map_fs_io_error(e, "Failed to seek archive for preflight"))?;
    let reader = archive_file
        .try_clone()
        .map_err(|e| map_fs_io_error(e, "Failed to clone archive handle"))?;

    let bounded_source = BoundedDeadlineReader::new(
        reader,
        MAX_ACTION_EXTRACT_ARCHIVE_SOURCE_BYTES,
        deadline,
        "ExtractArchive source read",
    );
    let decoder = open_tar_stream_decoder(format, Box::new(bounded_source))?;
    let max_tar_stream_bytes = MAX_ACTION_EXTRACT_TOTAL_BYTES
        .saturating_add((MAX_ACTION_ARCHIVE_ENTRIES as u64) * 2048)
        .saturating_add(1024 * 1024);
    let bounded_decompressed = BoundedDeadlineReader::new(
        decoder,
        max_tar_stream_bytes,
        deadline,
        "ExtractArchive stream decompression",
    );

    let mut archive = tar::Archive::new(bounded_decompressed);
    let entries = archive.entries().map_err(|e| {
        McBrowserError::BadRequest(format!("Invalid or corrupt tar archive header: {e}"))
    })?;

    let mut seen_files = HashSet::new();
    let mut seen_dirs = HashSet::new();
    let mut total_uncompressed: u64 = 0;
    let mut entry_count: usize = 0;
    let mut copy_buf = vec![0u8; ACTION_IO_BUF_BYTES];

    for entry_res in entries {
        check_action_deadline(deadline, "ExtractArchive preflight")?;
        let mut entry = entry_res.map_err(|err| match err.kind() {
            ErrorKind::TimedOut => McBrowserError::RequestTimeout(
                "ExtractArchive exceeded maximum execution time".to_string(),
            ),
            ErrorKind::FileTooLarge => McBrowserError::PayloadTooLarge(
                "Archive decompressed stream exceeds safety limit".to_string(),
            ),
            _ => McBrowserError::BadRequest(format!("Corrupt tar archive entry: {err}")),
        })?;

        let entry_type = entry.header().entry_type();
        let Some(is_dir_header) = is_allowed_tar_entry_type(entry_type)? else {
            continue;
        };

        if let Some(link_bytes) = entry.link_name_bytes() {
            if !link_bytes.is_empty() {
                return Err(McBrowserError::BadRequest(
                    "Archive entry specifies a link target (symlinks and hardlinks are prohibited)"
                        .to_string(),
                ));
            }
        }

        entry_count = entry_count.saturating_add(1);
        if entry_count > MAX_ACTION_ARCHIVE_ENTRIES {
            return Err(McBrowserError::BadRequest(format!(
                "Archive exceeds maximum entry count limit of {MAX_ACTION_ARCHIVE_ENTRIES}"
            )));
        }

        let raw_header_bytes = entry.header().path_bytes();
        let raw_header_str = std::str::from_utf8(&raw_header_bytes).map_err(|_| {
            McBrowserError::BadRequest("Archive entry path is not valid UTF-8".to_string())
        })?;
        let raw_path_bytes = entry.path_bytes();
        let raw_path_str = std::str::from_utf8(&raw_path_bytes).map_err(|_| {
            McBrowserError::BadRequest("Archive entry path is not valid UTF-8".to_string())
        })?;

        if !raw_header_str.is_empty() && raw_header_str != "././@LongLink" {
            let _ = validate_extract_entry_relative_path(raw_header_str)?;
        }
        let (rel_path, is_dir_hint) = validate_extract_entry_relative_path(raw_path_str)?;
        let is_dir = is_dir_header || is_dir_hint;

        let declared_size = entry
            .header()
            .size()
            .map_err(|_| McBrowserError::BadRequest("Invalid tar entry size header".to_string()))?;

        if is_dir && declared_size > 0 {
            return Err(McBrowserError::BadRequest(
                "Archive directory entry cannot carry file payload bytes".to_string(),
            ));
        }

        let _ = preflight_authorize_and_check_destination_entry(
            conn,
            bfs,
            user,
            destination_dir,
            &rel_path,
            &mut seen_files,
            &mut seen_dirs,
            is_dir,
        )?;

        if !is_dir {
            if declared_size > MAX_ACTION_EXTRACT_ENTRY_BYTES {
                return Err(McBrowserError::PayloadTooLarge(format!(
                    "Archive entry '{rel_path}' size ({declared_size} bytes) exceeds per-entry limit of {MAX_ACTION_EXTRACT_ENTRY_BYTES} bytes"
                )));
            }

            let mut entry_actual: u64 = 0;
            loop {
                check_action_deadline(deadline, "ExtractArchive preflight")?;
                match entry.read(&mut copy_buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        entry_actual = entry_actual.saturating_add(n as u64);
                        total_uncompressed = total_uncompressed.saturating_add(n as u64);
                        if entry_actual > MAX_ACTION_EXTRACT_ENTRY_BYTES {
                            return Err(McBrowserError::PayloadTooLarge(format!(
                                "Archive entry '{rel_path}' exceeds per-entry limit of {MAX_ACTION_EXTRACT_ENTRY_BYTES} bytes"
                            )));
                        }
                        if total_uncompressed > MAX_ACTION_EXTRACT_TOTAL_BYTES {
                            return Err(McBrowserError::PayloadTooLarge(format!(
                                "Archive total expanded size exceeds limit of {MAX_ACTION_EXTRACT_TOTAL_BYTES} bytes"
                            )));
                        }
                        check_compression_ratio(archive_size, total_uncompressed)?;
                    }
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(e) if e.kind() == ErrorKind::TimedOut => {
                        return Err(McBrowserError::RequestTimeout(
                            "ExtractArchive exceeded maximum execution time".to_string(),
                        ));
                    }
                    Err(e) if e.kind() == ErrorKind::FileTooLarge => {
                        return Err(McBrowserError::PayloadTooLarge(
                            "Archive decompressed stream exceeds safety limit".to_string(),
                        ));
                    }
                    Err(e) => {
                        return Err(McBrowserError::BadRequest(format!(
                            "Corrupt compressed stream in archive entry '{rel_path}': {e}"
                        )));
                    }
                }
            }
            if entry_actual != declared_size {
                return Err(McBrowserError::BadRequest(
                    "Tar entry payload does not match its declared size".to_string(),
                ));
            }
        }
    }

    if entry_count == 0 {
        return Err(McBrowserError::BadRequest(
            "Archive contains no extractable entries".to_string(),
        ));
    }

    Ok((entry_count, total_uncompressed))
}

pub(super) fn ensure_extracted_parent_dirs(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    destination_dir: &str,
    rel_entry_path: &str,
    known_dirs: &mut HashSet<String>,
    created_dirs_count: &mut usize,
) -> Result<(), McBrowserError> {
    let mut prefix = destination_dir.to_string();
    let segments: Vec<&str> = rel_entry_path.split('/').collect();
    if segments.len() <= 1 {
        return Ok(());
    }
    for seg in &segments[..segments.len() - 1] {
        prefix = format!("{prefix}/{seg}");
        if known_dirs.contains(&prefix) {
            continue;
        }
        policy::authorize_with_conn(conn, user, Permission::Execute, &prefix)?;
        policy::authorize_with_conn(conn, user, Permission::Create, &prefix)?;
        bfs.create_directory(&prefix)
            .map_err(|e| map_fs_io_error(e, "Failed to create extracted subdirectory"))?;
        known_dirs.insert(prefix.clone());
        *created_dirs_count = created_dirs_count.saturating_add(1);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn stream_extract_single_file<R: Read>(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    user_id: i64,
    target_path: &str,
    mut entry_reader: R,
    archive_size: u64,
    expected_entry_size: u64,
    total_extracted_bytes: &mut u64,
    reserved_quota_bytes: &mut u64,
    deadline: Instant,
) -> Result<u64, McBrowserError> {
    policy::authorize_with_conn(conn, user, Permission::Execute, target_path)?;
    policy::authorize_with_conn(conn, user, Permission::Create, target_path)?;

    let pending = bfs
        .begin_upload(target_path)
        .map_err(|e| map_fs_io_error(e, "Failed to stage extracted file"))?;
    let mut staging_file = pending
        .file()
        .map_err(|e| map_fs_io_error(e, "Failed to open extracted staging file"))?;
    check_fd_free_space(staging_file.as_raw_fd(), 65_536)?;

    let mut buf = vec![0u8; ACTION_IO_BUF_BYTES];
    let mut entry_written: u64 = 0;

    loop {
        check_action_deadline(deadline, "ExtractArchive")?;
        match entry_reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                entry_written = entry_written.saturating_add(n as u64);
                if entry_written > MAX_ACTION_EXTRACT_ENTRY_BYTES {
                    return Err(McBrowserError::PayloadTooLarge(format!(
                        "Extracted file '{target_path}' exceeds maximum entry size of {MAX_ACTION_EXTRACT_ENTRY_BYTES} bytes"
                    )));
                }
                let next_total = total_extracted_bytes.saturating_add(n as u64);
                if next_total > MAX_ACTION_EXTRACT_TOTAL_BYTES {
                    return Err(McBrowserError::PayloadTooLarge(format!(
                        "Extracted archive exceeds maximum total expanded size of {MAX_ACTION_EXTRACT_TOTAL_BYTES} bytes"
                    )));
                }
                check_compression_ratio(archive_size, next_total)?;

                staging_file
                    .write_all(&buf[..n])
                    .map_err(|e| map_fs_io_error(e, "Failed to write extracted file bytes"))?;
                *total_extracted_bytes = next_total;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::TimedOut => {
                return Err(McBrowserError::RequestTimeout(
                    "ExtractArchive exceeded maximum execution time".to_string(),
                ));
            }
            Err(e) if e.kind() == ErrorKind::FileTooLarge => {
                return Err(McBrowserError::PayloadTooLarge(
                    "Extracted archive stream exceeds maximum size limit".to_string(),
                ));
            }
            Err(e) => {
                return Err(McBrowserError::BadRequest(format!(
                    "Failed to decompress archive entry '{target_path}': {e}"
                )));
            }
        }
    }

    if entry_written != expected_entry_size {
        return Err(McBrowserError::BadRequest(
            "Archive entry payload size changed after preflight".to_string(),
        ));
    }

    staging_file
        .flush()
        .map_err(|e| map_fs_io_error(e, "Failed to flush extracted file"))?;
    drop(staging_file);

    if entry_written > 0 {
        reserve_user_quota_atomic(conn, user_id, entry_written)?;
    }
    *reserved_quota_bytes = reserved_quota_bytes.saturating_add(entry_written);

    if let Err(commit_err) = pending.commit() {
        if entry_written > 0 && release_user_quota_conn(conn, user_id, entry_written).is_ok() {
            *reserved_quota_bytes = reserved_quota_bytes.saturating_sub(entry_written);
        }
        return Err(map_fs_io_error(
            commit_err,
            "Failed to publish extracted file",
        ));
    }

    Ok(entry_written)
}

pub(super) fn rollback_partial_extraction(
    conn: &Connection,
    bfs: &BrowserFs,
    user_id: i64,
    destination_dir: &str,
    reserved_quota_bytes: u64,
) -> bool {
    match bfs.remove_tree_with_size(destination_dir) {
        Ok(removed_bytes) => {
            let to_release = removed_bytes.min(reserved_quota_bytes);
            if to_release > 0 && release_user_quota_conn(conn, user_id, to_release).is_err() {
                return false;
            }
            removed_bytes >= reserved_quota_bytes
        }
        Err(removal_err) => {
            let confirmed_removed = removal_err.removed_bytes.min(reserved_quota_bytes);
            if confirmed_removed > 0 {
                let _ = release_user_quota_conn(conn, user_id, confirmed_removed);
            }
            false
        }
    }
}

pub fn execute_extract_archive_with_conn(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    raw_archive_path: &str,
    raw_destination_dir: &str,
) -> Result<ExtractArchiveActionResult, McBrowserError> {
    let user_id = validate_mcbrowser_user(user)?;
    let archive_path = policy::normalize_target_path(raw_archive_path, false)?;
    let destination_dir = policy::normalize_target_path(raw_destination_dir, false)?;
    let _ = validate_archive_entry_name(&destination_dir)?;
    let deadline = Instant::now() + MAX_ACTION_DURATION;

    if archive_path == destination_dir
        || destination_dir.starts_with(&format!("{archive_path}/"))
        || archive_path.starts_with(&format!("{destination_dir}/"))
    {
        return Err(McBrowserError::BadRequest(
            "Archive path and destination directory must not overlap".to_string(),
        ));
    }

    policy::authorize_with_conn(conn, user, Permission::Execute, &destination_dir)?;
    policy::authorize_with_conn(conn, user, Permission::Create, &destination_dir)?;

    let _ = load_active_quota_conn(conn, user_id, 0)?;

    let (mut archive_file, _entry, resolved_archive_path) = open_authorized_action_file_with_conn(
        conn,
        user,
        bfs,
        &archive_path,
        &[Permission::Execute, Permission::Read],
    )?;

    if resolved_archive_path == destination_dir
        || destination_dir.starts_with(&format!("{resolved_archive_path}/"))
    {
        return Err(McBrowserError::BadRequest(
            "Resolved archive path and destination directory must not overlap".to_string(),
        ));
    }

    let format = detect_archive_format_from_path(&archive_path)
        .or_else(|_| detect_archive_format_from_path(&resolved_archive_path))?;

    let archive_meta = archive_file
        .metadata()
        .map_err(|e| map_fs_io_error(e, "Failed to inspect archive metadata"))?;
    let archive_size = archive_meta.len();
    if archive_size == 0 {
        return Err(McBrowserError::BadRequest(
            "Archive file is empty".to_string(),
        ));
    }
    if archive_size > MAX_ACTION_EXTRACT_ARCHIVE_SOURCE_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "Archive file size ({archive_size} bytes) exceeds maximum extraction source limit of {MAX_ACTION_EXTRACT_ARCHIVE_SOURCE_BYTES} bytes"
        )));
    }

    match bfs.metadata(&destination_dir) {
        Ok(_) => {
            return Err(McBrowserError::Conflict(format!(
                "Extraction destination '{destination_dir}' already exists"
            )));
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(map_fs_io_error(
                err,
                "Failed to inspect extraction destination",
            ));
        }
    }

    let mut parent_dirs_to_create: Vec<String> = Vec::new();
    if let Some((parent_path, _)) = destination_dir.rsplit_once('/') {
        let mut prefix = String::new();
        for seg in parent_path.split('/') {
            prefix = if prefix.is_empty() {
                seg.to_string()
            } else {
                format!("{prefix}/{seg}")
            };
            match bfs.metadata(&prefix) {
                Ok(existing) if existing.kind == "directory" => {}
                Ok(_) => {
                    return Err(McBrowserError::Conflict(format!(
                        "Ancestor path '{prefix}' exists and is not a directory"
                    )));
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {
                    policy::authorize_with_conn(conn, user, Permission::Execute, &prefix)?;
                    policy::authorize_with_conn(conn, user, Permission::Create, &prefix)?;
                    parent_dirs_to_create.push(prefix.clone());
                }
                Err(err) => {
                    return Err(map_fs_io_error(
                        err,
                        "Failed to inspect destination ancestor directory",
                    ));
                }
            }
        }
    }

    let (zip_plan, tar_entry_count, expanded_bytes) = if format == ArchiveFormat::Zip {
        let plan = preflight_zip_archive(
            conn,
            bfs,
            user,
            &mut archive_file,
            archive_size,
            &destination_dir,
            deadline,
        )?;
        let expanded_bytes = plan
            .iter()
            .map(|item| item.declared_uncompressed)
            .sum::<u64>();
        (Some(plan), None, expanded_bytes)
    } else {
        let (entry_count, expanded_bytes) = preflight_tar_archive(
            conn,
            bfs,
            user,
            &mut archive_file,
            archive_size,
            format,
            &destination_dir,
            deadline,
        )?;
        (None, Some(entry_count), expanded_bytes)
    };
    load_active_quota_conn(conn, user_id, expanded_bytes)?;

    let audit = crate::mcbrowser::events::record_pending_intent_with_conn(
        conn,
        user,
        crate::mcbrowser::events::McBrowserEventTrigger::UploadCompleted,
        &destination_dir,
        None,
        0,
    )?;
    for (created_count, ancestor) in parent_dirs_to_create.iter().enumerate() {
        if let Err(error) = bfs.create_directory(ancestor) {
            let mut removed_all = true;
            for created in parent_dirs_to_create[..created_count].iter().rev() {
                removed_all &= bfs.remove(created).is_ok();
            }
            if removed_all {
                let _ = crate::mcbrowser::events::finalize_event_failed_with_conn(
                    conn,
                    &audit.event.event_id,
                    Some("EXTRACTION_DESTINATION_FAILED"),
                );
            }
            return Err(map_fs_io_error(
                error,
                "Failed to create extraction destination parent directory",
            ));
        }
    }
    if let Err(error) = bfs.create_directory(&destination_dir) {
        let mut removed_all = true;
        for created in parent_dirs_to_create.iter().rev() {
            removed_all &= bfs.remove(created).is_ok();
        }
        if removed_all {
            let _ = crate::mcbrowser::events::finalize_event_failed_with_conn(
                conn,
                &audit.event.event_id,
                Some("EXTRACTION_DESTINATION_FAILED"),
            );
        }
        return Err(map_fs_io_error(
            error,
            "Failed to create extraction destination directory",
        ));
    }

    let mut known_dirs = HashSet::new();
    let mut extracted_files: usize = 0;
    let mut extracted_directories: usize = 0;
    let mut total_extracted_bytes: u64 = 0;
    let mut reserved_quota_bytes: u64 = 0;

    let extraction_outcome: Result<(), McBrowserError> = (|| {
        if let Some(items) = zip_plan {
            let (mut zip, replay_count) = open_admitted_zip_archive(
                &mut archive_file,
                archive_size,
                deadline,
                "ExtractArchive ZIP replay",
            )?;
            if replay_count != items.len() {
                return Err(McBrowserError::BadRequest(
                    "Archive entry count changed after preflight".to_string(),
                ));
            }

            for item in items {
                check_action_deadline(deadline, "ExtractArchive")?;
                let rel_inside = item
                    .target_path
                    .strip_prefix(&format!("{destination_dir}/"))
                    .ok_or_else(|| {
                        McBrowserError::Internal("Invalid extraction target path".to_string())
                    })?;

                ensure_extracted_parent_dirs(
                    conn,
                    bfs,
                    user,
                    &destination_dir,
                    rel_inside,
                    &mut known_dirs,
                    &mut extracted_directories,
                )?;

                if item.is_dir {
                    if !known_dirs.contains(&item.target_path) {
                        policy::authorize_with_conn(
                            conn,
                            user,
                            Permission::Execute,
                            &item.target_path,
                        )?;
                        policy::authorize_with_conn(
                            conn,
                            user,
                            Permission::Create,
                            &item.target_path,
                        )?;
                        bfs.create_directory(&item.target_path).map_err(|e| {
                            map_fs_io_error(e, "Failed to create archive directory")
                        })?;
                        known_dirs.insert(item.target_path.clone());
                        extracted_directories = extracted_directories.saturating_add(1);
                    }
                } else {
                    let entry = zip.by_index(item.index).map_err(|err| {
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
                            McBrowserError::BadRequest(format!(
                                "Failed to open ZIP entry '{}': {msg}",
                                item.target_path
                            ))
                        }
                    })?;

                    if entry.is_symlink() || is_zip_unix_symlink_or_special(entry.unix_mode()) {
                        return Err(McBrowserError::BadRequest(
                            "Archive contains forbidden symlink or special entry".to_string(),
                        ));
                    }

                    stream_extract_single_file(
                        conn,
                        bfs,
                        user,
                        user_id,
                        &item.target_path,
                        entry,
                        archive_size,
                        item.declared_uncompressed,
                        &mut total_extracted_bytes,
                        &mut reserved_quota_bytes,
                        deadline,
                    )?;
                    extracted_files = extracted_files.saturating_add(1);
                }
            }
        } else {
            archive_file
                .seek(SeekFrom::Start(0))
                .map_err(|e| map_fs_io_error(e, "Failed to seek tar archive"))?;
            let bounded_source = BoundedDeadlineReader::new(
                archive_file,
                MAX_ACTION_EXTRACT_ARCHIVE_SOURCE_BYTES,
                deadline,
                "ExtractArchive source read",
            );
            let decoder = open_tar_stream_decoder(format, Box::new(bounded_source))?;
            let max_tar_stream_bytes = MAX_ACTION_EXTRACT_TOTAL_BYTES
                .saturating_add((MAX_ACTION_ARCHIVE_ENTRIES as u64) * 2048)
                .saturating_add(1024 * 1024);
            let bounded_decompressed = BoundedDeadlineReader::new(
                decoder,
                max_tar_stream_bytes,
                deadline,
                "ExtractArchive stream decompression",
            );

            let mut archive = tar::Archive::new(bounded_decompressed);
            let entries = archive.entries().map_err(|e| {
                McBrowserError::BadRequest(format!("Failed to read tar entries: {e}"))
            })?;

            let mut replayed_entries = 0_usize;
            for entry_res in entries {
                check_action_deadline(deadline, "ExtractArchive")?;
                let entry = entry_res.map_err(|error| match error.kind() {
                    ErrorKind::TimedOut => McBrowserError::RequestTimeout(
                        "ExtractArchive exceeded maximum execution time".to_string(),
                    ),
                    ErrorKind::FileTooLarge => McBrowserError::PayloadTooLarge(
                        "Archive decompressed stream exceeds safety limit".to_string(),
                    ),
                    _ => McBrowserError::BadRequest(format!(
                        "Corrupt tar entry during extraction: {error}"
                    )),
                })?;

                let entry_type = entry.header().entry_type();
                let Some(is_dir_header) = is_allowed_tar_entry_type(entry_type)? else {
                    continue;
                };
                replayed_entries = replayed_entries.saturating_add(1);
                if replayed_entries > MAX_ACTION_ARCHIVE_ENTRIES {
                    return Err(McBrowserError::PayloadTooLarge(
                        "Archive replay exceeds entry count limit".to_string(),
                    ));
                }
                let raw_header = entry.header().path_bytes();
                let raw_header = std::str::from_utf8(&raw_header).map_err(|_| {
                    McBrowserError::BadRequest("Archive entry path is not valid UTF-8".to_string())
                })?;
                if !raw_header.is_empty() && raw_header != "././@LongLink" {
                    validate_extract_entry_relative_path(raw_header)?;
                }
                if let Some(link_bytes) = entry.link_name_bytes() {
                    if !link_bytes.is_empty() {
                        return Err(McBrowserError::BadRequest(
                            "Archive entry specifies a link target".to_string(),
                        ));
                    }
                }

                let raw_path_bytes = entry.path_bytes();
                let raw_path_str = std::str::from_utf8(&raw_path_bytes).map_err(|_| {
                    McBrowserError::BadRequest("Archive entry path is not valid UTF-8".to_string())
                })?;
                let (rel_path, is_dir_hint) = validate_extract_entry_relative_path(raw_path_str)?;
                let is_dir = is_dir_header || is_dir_hint;
                let target_path =
                    policy::normalize_target_path(&format!("{destination_dir}/{rel_path}"), false)?;

                ensure_extracted_parent_dirs(
                    conn,
                    bfs,
                    user,
                    &destination_dir,
                    &rel_path,
                    &mut known_dirs,
                    &mut extracted_directories,
                )?;

                if is_dir {
                    if !known_dirs.contains(&target_path) {
                        policy::authorize_with_conn(conn, user, Permission::Execute, &target_path)?;
                        policy::authorize_with_conn(conn, user, Permission::Create, &target_path)?;
                        bfs.create_directory(&target_path).map_err(|e| {
                            map_fs_io_error(e, "Failed to create archive directory")
                        })?;
                        known_dirs.insert(target_path);
                        extracted_directories = extracted_directories.saturating_add(1);
                    }
                } else {
                    let expected_entry_size = entry.header().size().map_err(|_| {
                        McBrowserError::BadRequest("Invalid replayed tar entry size".to_string())
                    })?;
                    stream_extract_single_file(
                        conn,
                        bfs,
                        user,
                        user_id,
                        &target_path,
                        entry,
                        archive_size,
                        expected_entry_size,
                        &mut total_extracted_bytes,
                        &mut reserved_quota_bytes,
                        deadline,
                    )?;
                    extracted_files = extracted_files.saturating_add(1);
                }
            }
            if Some(replayed_entries) != tar_entry_count {
                return Err(McBrowserError::BadRequest(
                    "Archive entry count changed after preflight".to_string(),
                ));
            }
        }
        Ok(())
    })();

    if let Err(err) = extraction_outcome {
        let mut removed_all =
            rollback_partial_extraction(conn, bfs, user_id, &destination_dir, reserved_quota_bytes);
        for anc in parent_dirs_to_create.iter().rev() {
            removed_all &= bfs.remove(anc).is_ok();
        }
        if removed_all {
            let _ = crate::mcbrowser::events::finalize_event_failed_with_conn(
                conn,
                &audit.event.event_id,
                Some("EXTRACTION_ROLLED_BACK"),
            );
        }
        return Err(err);
    }

    crate::mcbrowser::events::finalize_published_mutation_with_conn(
        conn,
        &audit,
        None,
        None,
        total_extracted_bytes.min(i64::MAX as u64) as i64,
    );
    Ok(ExtractArchiveActionResult {
        archive_path,
        destination_dir,
        format: format.algo_id().to_string(),
        extracted_files,
        extracted_directories,
        extracted_bytes: total_extracted_bytes,
    })
}
