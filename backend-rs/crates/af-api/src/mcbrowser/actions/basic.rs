use super::*;

pub(super) fn open_authorized_action_file_with_conn(
    conn: &Connection,
    user: &AuthUser,
    bfs: &BrowserFs,
    path: &str,
    permissions: &[Permission],
) -> Result<(File, Entry, String), McBrowserError> {
    for &perm in permissions {
        policy::authorize_with_conn(conn, user, perm, path)?;
    }

    match bfs.open_file(path) {
        Ok(file) => {
            let meta = file
                .metadata()
                .map_err(|e| map_fs_io_error(e, "Failed to inspect file metadata"))?;
            let entry = bfs.metadata(path).unwrap_or_else(|_| Entry {
                name: path.rsplit('/').next().unwrap_or(path).to_string(),
                path: path.to_string(),
                kind: "file".to_string(),
                size: meta.len(),
                modified: None,
            });
            Ok((file, entry, path.to_string()))
        }
        Err(direct_err) => {
            if let Ok(meta_entry) = bfs.metadata(path) {
                if meta_entry.kind == "directory" {
                    return Err(McBrowserError::BadRequest(format!(
                        "Expected a regular file at '{path}', found a directory"
                    )));
                }
            }
            let ResolvedFile {
                file,
                resolved_path,
                resolution_paths,
                entry,
            } = bfs
                .open_file_resolving_internal_links(path)
                .map_err(|_| map_fs_io_error(direct_err, "Failed to open file"))?;

            for hop in &resolution_paths {
                for &perm in permissions {
                    policy::authorize_with_conn(conn, user, perm, hop)?;
                }
            }
            for &perm in permissions {
                policy::authorize_with_conn(conn, user, perm, &resolved_path)?;
            }
            Ok((file, entry, resolved_path))
        }
    }
}

pub(super) fn check_action_deadline(
    deadline: Instant,
    action_label: &str,
) -> Result<(), McBrowserError> {
    if Instant::now() > deadline {
        return Err(McBrowserError::RequestTimeout(format!(
            "{action_label} exceeded maximum execution time of {} seconds",
            MAX_ACTION_DURATION.as_secs()
        )));
    }
    Ok(())
}

pub(super) struct BoundedDeadlineReader<R> {
    inner: R,
    bytes_read: u64,
    max_bytes: u64,
    deadline: Instant,
    context: &'static str,
}

impl<R> BoundedDeadlineReader<R> {
    pub(super) fn new(inner: R, max_bytes: u64, deadline: Instant, context: &'static str) -> Self {
        Self {
            inner,
            bytes_read: 0,
            max_bytes,
            deadline,
            context,
        }
    }
}

impl<R: Read> Read for BoundedDeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if Instant::now() > self.deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("{} timed out", self.context),
            ));
        }
        let n = self.inner.read(buf)?;
        self.bytes_read = self.bytes_read.saturating_add(n as u64);
        if self.bytes_read > self.max_bytes {
            return Err(io::Error::new(
                ErrorKind::FileTooLarge,
                format!(
                    "{} exceeded maximum byte limit of {} bytes",
                    self.context, self.max_bytes
                ),
            ));
        }
        Ok(n)
    }
}

impl<R: Seek> Seek for BoundedDeadlineReader<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        if Instant::now() > self.deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                format!("{} timed out", self.context),
            ));
        }
        self.inner.seek(pos)
    }
}

pub(super) struct CappedDeadlineWriter<W> {
    inner: W,
    written: u64,
    max_bytes: u64,
    quota_capped: bool,
    deadline: Instant,
}

impl<W> CappedDeadlineWriter<W> {
    pub(super) fn new(inner: W, max_bytes: u64, quota_capped: bool, deadline: Instant) -> Self {
        Self {
            inner,
            written: 0,
            max_bytes,
            quota_capped,
            deadline,
        }
    }
}

impl<W: Write> Write for CappedDeadlineWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if Instant::now() > self.deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "archive write timed out",
            ));
        }
        let next_written = self.written.saturating_add(buf.len() as u64);
        if next_written > self.max_bytes {
            let kind = if self.quota_capped {
                ErrorKind::PermissionDenied
            } else {
                ErrorKind::FileTooLarge
            };
            return Err(io::Error::new(
                kind,
                if self.quota_capped {
                    "archive output exceeds available user storage quota"
                } else {
                    "archive output exceeds maximum allowed size"
                },
            ));
        }
        let n = self.inner.write(buf)?;
        self.written = self.written.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if Instant::now() > self.deadline {
            return Err(io::Error::new(
                ErrorKind::TimedOut,
                "archive flush timed out",
            ));
        }
        self.inner.flush()
    }
}

pub fn execute_compute_checksums_with_conn(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    raw_path: &str,
    raw_algorithms: &[String],
) -> Result<ComputeChecksumsActionResult, McBrowserError> {
    let _ = validate_mcbrowser_user(user)?;
    let normalized_path = policy::normalize_target_path(raw_path, false)?;
    let algorithms = parse_action_checksum_algorithms(raw_algorithms)?;
    let deadline = Instant::now() + MAX_ACTION_DURATION;

    let (file, _entry, _resolved_path) = open_authorized_action_file_with_conn(
        conn,
        user,
        bfs,
        &normalized_path,
        &[Permission::Execute, Permission::Read],
    )?;

    let meta = file
        .metadata()
        .map_err(|e| map_fs_io_error(e, "Failed to inspect file for checksum"))?;
    let size = meta.len();
    if size > MAX_ACTION_CHECKSUM_FILE_BYTES {
        return Err(McBrowserError::PayloadTooLarge(format!(
            "File size ({size} bytes) exceeds maximum checksum limit of {MAX_ACTION_CHECKSUM_FILE_BYTES} bytes"
        )));
    }

    let reader = BoundedDeadlineReader::new(
        file,
        MAX_ACTION_CHECKSUM_FILE_BYTES,
        deadline,
        "ComputeChecksums",
    );
    let checksums = compute_checksums_from_reader(reader, &algorithms).map_err(|err| {
        if err.kind() == ErrorKind::TimedOut {
            McBrowserError::RequestTimeout(
                "ComputeChecksums exceeded maximum execution time".to_string(),
            )
        } else if err.kind() == ErrorKind::FileTooLarge {
            McBrowserError::PayloadTooLarge(
                "File grew beyond maximum checksum size limit during read".to_string(),
            )
        } else {
            map_fs_io_error(err, "Failed to compute file checksums")
        }
    })?;

    Ok(ComputeChecksumsActionResult {
        path: normalized_path,
        size,
        checksums,
    })
}

pub fn execute_inspect_media_metadata_with_conn(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    raw_path: &str,
) -> Result<InspectMediaMetadataActionResult, McBrowserError> {
    let _ = validate_mcbrowser_user(user)?;
    let normalized_path = policy::normalize_target_path(raw_path, false)?;
    let deadline = Instant::now() + MAX_ACTION_DURATION;

    policy::authorize_with_conn(conn, user, Permission::Execute, &normalized_path)?;
    policy::authorize_with_conn(conn, user, Permission::Read, &normalized_path)?;

    let resolved = bfs
        .metadata_resolving_internal_links(&normalized_path)
        .map_err(|error| map_fs_io_error(error, "Failed to inspect media metadata"))?;
    for path in resolved
        .resolution_paths
        .iter()
        .chain(std::iter::once(&resolved.resolved_path))
    {
        policy::authorize_with_conn(conn, user, Permission::Execute, path)?;
        policy::authorize_with_conn(conn, user, Permission::Read, path)?;
    }
    let mut entry = resolved.entry;

    let mut content_type = None;
    let mut resolution = None;
    let mut subtitles = Vec::new();

    if entry.kind == "file" {
        match open_authorized_action_file_with_conn(
            conn,
            user,
            bfs,
            &normalized_path,
            &[Permission::Execute, Permission::Read],
        ) {
            Ok((mut file, verified_entry, _)) => {
                entry = verified_entry;
                if let Ok(meta) = file.metadata() {
                    entry.size = meta.len();
                    entry.modified = meta.modified().ok().map(|modified| {
                        chrono::DateTime::<chrono::Utc>::from(modified).to_rfc3339()
                    });
                }
                let mut sig = [0u8; 64];
                if let Ok(n) = file.read(&mut sig) {
                    content_type = media_type(&normalized_path, &sig[..n]).map(str::to_owned);
                }
                check_action_deadline(deadline, "InspectMediaMetadata")?;
                if content_type.as_deref().is_some_and(is_image_content_type) {
                    resolution = read_image_dimensions_from_file(&normalized_path, &mut file).ok();
                }
                check_action_deadline(deadline, "InspectMediaMetadata")?;
                if is_video_extension(&normalized_path) {
                    let discovered = discover_subtitles_in_fs(bfs, &normalized_path, |path| {
                        [Permission::Read, Permission::Execute]
                            .into_iter()
                            .all(|permission| {
                                policy::authorize_with_conn(conn, user, permission, path).is_ok()
                            })
                    })?;
                    check_action_deadline(deadline, "InspectMediaMetadata")?;
                    subtitles = discovered;
                }
            }
            Err(McBrowserError::Forbidden(err)) => return Err(McBrowserError::Forbidden(err)),
            Err(err) => return Err(err),
        }
    }

    check_action_deadline(deadline, "InspectMediaMetadata")?;
    entry.path = normalized_path.clone();
    entry.name = normalized_path
        .rsplit('/')
        .next()
        .unwrap_or(&normalized_path)
        .to_string();
    Ok(InspectMediaMetadataActionResult {
        path: entry.path,
        name: entry.name,
        kind: entry.kind,
        content_type,
        size: entry.size,
        modified: entry.modified,
        resolution,
        subtitles,
    })
}

pub fn execute_create_archive_with_conn(
    conn: &Connection,
    bfs: &BrowserFs,
    user: &AuthUser,
    source_paths: &[String],
    raw_destination_path: &str,
    raw_format: &str,
) -> Result<CreateArchiveActionResult, McBrowserError> {
    let user_id = validate_mcbrowser_user(user)?;
    let format = ArchiveFormat::parse(raw_format)?;
    let destination_path = policy::normalize_target_path(raw_destination_path, false)?;
    let _ = validate_archive_entry_name(&destination_path)?;
    let deadline = Instant::now() + MAX_ACTION_DURATION;

    policy::authorize_with_conn(conn, user, Permission::Execute, &destination_path)?;
    policy::authorize_with_conn(conn, user, Permission::Create, &destination_path)?;

    match bfs.metadata(&destination_path) {
        Ok(_) => {
            return Err(McBrowserError::Conflict(format!(
                "Archive destination '{destination_path}' already exists"
            )));
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(map_fs_io_error(
                err,
                "Failed to inspect archive destination",
            ));
        }
    }

    for source in source_paths {
        let normalized_source = policy::normalize_target_path(source, false)?;
        for permission in [Permission::Execute, Permission::Read, Permission::Download] {
            policy::authorize_with_conn(conn, user, permission, &normalized_source)?;
        }
    }

    let plan = crate::mcbrowser::operations::collect_archive_plan_for_user_with_conn(
        conn,
        bfs,
        user,
        source_paths,
    )?;

    if plan.is_empty() {
        return Err(McBrowserError::BadRequest(
            "Archive plan produced no entries".to_string(),
        ));
    }
    if plan.len() > MAX_ACTION_ARCHIVE_ENTRIES {
        return Err(McBrowserError::BadRequest(format!(
            "Archive exceeds maximum action entry limit of {MAX_ACTION_ARCHIVE_ENTRIES}"
        )));
    }

    let dst_prefix = format!("{destination_path}/");
    let mut total_source_bytes: u64 = 0;

    for item in &plan {
        check_action_deadline(deadline, "CreateArchive")?;
        if item.fs_path == destination_path
            || item.fs_path.starts_with(&dst_prefix)
            || destination_path.starts_with(&format!("{}/", item.fs_path))
            || item.resolved_path == destination_path
            || item.resolved_path.starts_with(&dst_prefix)
            || item.resolved_path.is_empty()
            || destination_path.starts_with(&format!("{}/", item.resolved_path))
        {
            return Err(McBrowserError::BadRequest(
                "Archive destination path cannot overlap with source paths".to_string(),
            ));
        }
        for source_path in &item.authorization_paths {
            policy::authorize_with_conn(conn, user, Permission::Execute, source_path)?;
            policy::authorize_with_conn(conn, user, Permission::Read, source_path)?;
        }

        if !item.is_dir {
            total_source_bytes = total_source_bytes.saturating_add(item.source_size);
            if total_source_bytes > MAX_ACTION_CREATE_ARCHIVE_SOURCE_BYTES {
                return Err(McBrowserError::PayloadTooLarge(format!(
                    "Total source file size exceeds maximum CreateArchive limit of {MAX_ACTION_CREATE_ARCHIVE_SOURCE_BYTES} bytes"
                )));
            }
        }
    }

    let quota_snapshot = load_active_quota_conn(conn, user_id, 0)?;
    let (max_output_bytes, quota_capped) = if quota_snapshot.quota_bytes > 0 {
        let remaining = quota_snapshot
            .quota_bytes
            .saturating_sub(quota_snapshot.used_bytes)
            .max(0) as u64;
        if remaining == 0 {
            return Err(McBrowserError::QuotaExceeded(
                "Storage quota exceeded. Free up space or contact an administrator.".to_string(),
            ));
        }
        if remaining < MAX_ACTION_CREATE_ARCHIVE_OUTPUT_BYTES {
            (remaining, true)
        } else {
            (MAX_ACTION_CREATE_ARCHIVE_OUTPUT_BYTES, false)
        }
    } else {
        (MAX_ACTION_CREATE_ARCHIVE_OUTPUT_BYTES, false)
    };

    let mut parent_dirs_to_create: Vec<String> = Vec::new();
    if let Some((parent_path, _)) = destination_path.rsplit_once('/') {
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
                        "Failed to inspect archive destination ancestor directory",
                    ));
                }
            }
        }
    }

    let audit = crate::mcbrowser::events::record_pending_intent_with_conn(
        conn,
        user,
        crate::mcbrowser::events::McBrowserEventTrigger::UploadCompleted,
        &destination_path,
        None,
        0,
    )?;
    let quota_cleanup_complete = std::cell::Cell::new(true);
    let fail_unpublished = |error: McBrowserError, created_dirs: &[String]| {
        let mut cleanup_complete = quota_cleanup_complete.get();
        for directory in created_dirs.iter().rev() {
            if let Err(cleanup_error) = bfs.remove(directory) {
                if cleanup_error.kind() != ErrorKind::NotFound {
                    cleanup_complete = false;
                }
            }
        }
        if cleanup_complete {
            let _ = crate::mcbrowser::events::finalize_event_failed_with_conn(
                conn,
                &audit.event.event_id,
                Some("ARCHIVE_NOT_PUBLISHED"),
            );
        }
        error
    };
    for (created_count, ancestor) in parent_dirs_to_create.iter().enumerate() {
        if let Err(error) = bfs.create_directory(ancestor) {
            return Err(fail_unpublished(
                map_fs_io_error(
                    error,
                    "Failed to create archive destination parent directory",
                ),
                &parent_dirs_to_create[..created_count],
            ));
        }
    }

    let pending = match bfs.begin_upload(&destination_path) {
        Ok(pending) => pending,
        Err(error) => {
            return Err(fail_unpublished(
                map_fs_io_error(error, "Failed to stage destination archive"),
                &parent_dirs_to_create,
            ));
        }
    };
    let staging_file = match pending.file() {
        Ok(file) => file,
        Err(error) => {
            drop(pending);
            return Err(fail_unpublished(
                map_fs_io_error(error, "Failed to access archive staging descriptor"),
                &parent_dirs_to_create,
            ));
        }
    };
    if let Err(err) = check_fd_free_space(staging_file.as_raw_fd(), total_source_bytes.max(4096)) {
        drop(staging_file);
        drop(pending);
        return Err(fail_unpublished(err, &parent_dirs_to_create));
    }

    let mut capped_writer =
        CappedDeadlineWriter::new(staging_file, max_output_bytes, quota_capped, deadline);

    if let Err(write_err) = write_archive_to_writer(bfs, &plan, format, &mut capped_writer) {
        drop(capped_writer);
        drop(pending);
        let error = match write_err.kind() {
            ErrorKind::TimedOut => McBrowserError::RequestTimeout(
                "CreateArchive exceeded maximum execution time".to_string(),
            ),
            ErrorKind::PermissionDenied
                if write_err
                    .to_string()
                    .contains("available user storage quota") =>
            {
                McBrowserError::QuotaExceeded(
                    "Created archive exceeds available user storage quota".to_string(),
                )
            }
            ErrorKind::FileTooLarge => McBrowserError::PayloadTooLarge(format!(
                "Created archive exceeds maximum allowed size of {MAX_ACTION_CREATE_ARCHIVE_OUTPUT_BYTES} bytes"
            )),
            _ => map_fs_io_error(write_err, "Failed to stream archive to staging file"),
        };
        return Err(fail_unpublished(error, &parent_dirs_to_create));
    }

    let archive_bytes = capped_writer.written;
    drop(capped_writer);

    if let Err(err) =
        policy::authorize_with_conn(conn, user, Permission::Execute, &destination_path).and_then(
            |()| policy::authorize_with_conn(conn, user, Permission::Create, &destination_path),
        )
    {
        drop(pending);
        return Err(fail_unpublished(err, &parent_dirs_to_create));
    }
    if archive_bytes > 0 {
        if let Err(err) = reserve_user_quota_atomic(conn, user_id, archive_bytes) {
            drop(pending);
            return Err(fail_unpublished(err, &parent_dirs_to_create));
        }
    }

    if let Err(commit_err) = pending.commit() {
        if archive_bytes > 0 {
            quota_cleanup_complete
                .set(release_user_quota_conn(conn, user_id, archive_bytes).is_ok());
        }
        return Err(fail_unpublished(
            map_fs_io_error(commit_err, "Failed to publish archive file"),
            &parent_dirs_to_create,
        ));
    }

    crate::mcbrowser::events::finalize_published_mutation_with_conn(
        conn,
        &audit,
        None,
        None,
        archive_bytes.min(i64::MAX as u64) as i64,
    );
    Ok(CreateArchiveActionResult {
        destination_path,
        format: format.algo_id().to_string(),
        entry_count: plan.len(),
        archive_bytes,
    })
}
