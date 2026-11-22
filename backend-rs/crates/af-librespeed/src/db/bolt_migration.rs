use super::{
    enforce_retention_on_conn, parse_timestamp_epoch_ms, ulid_suffix_blob, NewTelemetryRecord,
};
use crate::ulid::canonicalize_ulid;
use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

pub(super) const BBOLT_MAGIC: u32 = 0xED0C_DAED;
pub(super) const BBOLT_VERSION: u32 = 2;
pub(super) const BBOLT_PAGE_HEADER_BYTES: usize = 16;
pub(super) const BBOLT_BRANCH_FLAG: u16 = 0x01;
pub(super) const BBOLT_LEAF_FLAG: u16 = 0x02;
pub(super) const BBOLT_META_FLAG: u16 = 0x04;
pub(super) const BBOLT_BUCKET_LEAF_FLAG: u32 = 0x01;
const MAX_BOLTDB_PAGE_SPAN_BYTES: usize = 16 * 1024 * 1024;
const MAX_BOLTDB_CUMULATIVE_READ_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_BOLTDB_TREE_DEPTH: usize = 16;
const MAX_BOLTDB_VISITED_PAGES: usize = 1_048_576;

#[derive(Debug, Clone, Copy)]
struct BoltMeta {
    page_size: usize,
    root_pgid: u64,
    txid: u64,
}

pub(super) fn fnv1a_64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn parse_bbolt_meta(page: &[u8]) -> Option<BoltMeta> {
    if page.len() < 80 {
        return None;
    }
    let flags = u16::from_le_bytes(page[8..10].try_into().ok()?);
    if flags != BBOLT_META_FLAG {
        return None;
    }
    let magic = u32::from_le_bytes(page[16..20].try_into().ok()?);
    let version = u32::from_le_bytes(page[20..24].try_into().ok()?);
    if magic != BBOLT_MAGIC || version != BBOLT_VERSION {
        return None;
    }
    let page_size = u32::from_le_bytes(page[24..28].try_into().ok()?) as usize;
    if !page_size.is_power_of_two() || !(1024..=65_536).contains(&page_size) {
        return None;
    }
    let root_pgid = u64::from_le_bytes(page[32..40].try_into().ok()?);
    let txid = u64::from_le_bytes(page[64..72].try_into().ok()?);
    let checksum = u64::from_le_bytes(page[72..80].try_into().ok()?);
    if fnv1a_64(&page[16..72]) != checksum {
        return None;
    }
    Some(BoltMeta {
        page_size,
        root_pgid,
        txid,
    })
}

fn select_best_bbolt_meta(data: &[u8]) -> Option<BoltMeta> {
    let meta0 = parse_bbolt_meta(data);
    let mut meta1: Option<BoltMeta> = None;
    if let Some(m0) = meta0 {
        if data.len() >= m0.page_size.saturating_add(80) {
            meta1 = parse_bbolt_meta(&data[m0.page_size..]);
        }
    } else {
        for cand_ps in [4096usize, 8192, 16_384, 32_768, 65_536, 1024, 2048] {
            if data.len() >= cand_ps.saturating_add(80) {
                if let Some(m1) = parse_bbolt_meta(&data[cand_ps..]) {
                    if m1.page_size == cand_ps {
                        meta1 = Some(m1);
                        break;
                    }
                }
            }
        }
    }

    match (meta0, meta1) {
        (Some(m0), Some(m1)) => {
            if m1.txid > m0.txid {
                Some(m1)
            } else {
                Some(m0)
            }
        }
        (Some(m0), None) => Some(m0),
        (None, Some(m1)) => Some(m1),
        (None, None) => None,
    }
}

fn clamp_imported_utf8(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_string()
}

fn extract_json_field_ci(
    map: &serde_json::Map<String, serde_json::Value>,
    aliases: &[&str],
) -> String {
    for &alias in aliases {
        if let Some(v) = map.get(alias) {
            match v {
                serde_json::Value::String(s) => return s.clone(),
                serde_json::Value::Number(n) => return n.to_string(),
                _ => {}
            }
        }
    }
    for (k, v) in map {
        if aliases.iter().any(|a| k.eq_ignore_ascii_case(a)) {
            match v {
                serde_json::Value::String(s) => return s.clone(),
                serde_json::Value::Number(n) => return n.to_string(),
                _ => {}
            }
        }
    }
    String::new()
}

fn decode_bolt_telemetry_leaf(key_bytes: &[u8], val_bytes: &[u8]) -> Option<NewTelemetryRecord> {
    let serde_json::Value::Object(map) = serde_json::from_slice(val_bytes).ok()? else {
        return None;
    };
    let mut raw_uuid = extract_json_field_ci(&map, &["uuid", "id"]);
    if raw_uuid.trim().is_empty() {
        if let Ok(key_str) = std::str::from_utf8(key_bytes) {
            raw_uuid = key_str.trim().to_string();
        }
    }
    let trimmed_uuid = raw_uuid.trim();
    let uuid = if let Some(canon) = canonicalize_ulid(trimmed_uuid) {
        canon
    } else if (8..=64).contains(&trimmed_uuid.len())
        && trimmed_uuid
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        trimmed_uuid.to_string()
    } else {
        return None;
    };

    let dl = clamp_imported_utf8(extract_json_field_ci(&map, &["dl", "download"]).trim(), 24);
    let ul = clamp_imported_utf8(extract_json_field_ci(&map, &["ul", "upload"]).trim(), 24);
    let ping = clamp_imported_utf8(extract_json_field_ci(&map, &["ping"]).trim(), 24);
    let jitter = clamp_imported_utf8(extract_json_field_ci(&map, &["jitter"]).trim(), 24);
    if dl.is_empty() && ul.is_empty() && ping.is_empty() && jitter.is_empty() {
        return None;
    }

    let raw_ts = extract_json_field_ci(&map, &["timestamp", "created_at"]);
    let timestamp = if raw_ts.trim().is_empty() {
        "1970-01-01T00:00:00.000Z".to_string()
    } else {
        clamp_imported_utf8(raw_ts.trim(), 64)
    };

    Some(NewTelemetryRecord {
        uuid,
        timestamp,
        ip: clamp_imported_utf8(
            extract_json_field_ci(&map, &["ip", "ip_address", "ipaddress"]).trim(),
            128,
        ),
        ispinfo: clamp_imported_utf8(&extract_json_field_ci(&map, &["ispinfo", "isp_info"]), 8192),
        extra: clamp_imported_utf8(&extract_json_field_ci(&map, &["extra"]), 8192),
        ua: clamp_imported_utf8(
            &extract_json_field_ci(&map, &["ua", "user_agent", "useragent"]),
            512,
        ),
        lang: clamp_imported_utf8(&extract_json_field_ci(&map, &["lang", "language"]), 64),
        dl,
        ul,
        ping,
        jitter,
        log: clamp_imported_utf8(&extract_json_field_ci(&map, &["log", "logs"]), 65_536),
    })
}

trait BoltByteSource {
    fn byte_len(&self) -> u64;
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
}

impl BoltByteSource for &[u8] {
    fn byte_len(&self) -> u64 {
        self.len() as u64
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).context("bbolt slice offset overflow")?;
        let end = start
            .checked_add(buf.len())
            .context("bbolt slice end overflow")?;
        if end > self.len() {
            bail!("bbolt read past slice end ({end} > {})", self.len());
        }
        buf.copy_from_slice(&self[start..end]);
        Ok(())
    }
}

struct FileBoltSource {
    file: fs::File,
    len: u64,
}

impl BoltByteSource for FileBoltSource {
    fn byte_len(&self) -> u64 {
        self.len
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let end = offset
            .checked_add(buf.len() as u64)
            .context("bbolt file offset overflow")?;
        if end > self.len {
            bail!("bbolt read past file end ({end} > {})", self.len);
        }
        self.file
            .read_exact_at(buf, offset)
            .with_context(|| format!("bbolt positional pread failed at offset {offset}"))
    }
}

fn select_best_bbolt_meta_from_source<S: BoltByteSource>(src: &S) -> Option<BoltMeta> {
    let head_len = usize::try_from(src.byte_len().min(131_072)).ok()?;
    if head_len < 80 {
        return None;
    }
    let mut head = vec![0u8; head_len];
    src.read_exact_at(0, &mut head).ok()?;
    select_best_bbolt_meta(&head)
}

type BoltRankKey = (i64, String, String);

struct BoltRecordCollector {
    max_retained: usize,
    by_uuid: HashMap<String, (BoltRankKey, NewTelemetryRecord)>,
    order: BTreeSet<BoltRankKey>,
}

impl BoltRecordCollector {
    fn new(max_retained: usize) -> Self {
        Self {
            max_retained,
            by_uuid: HashMap::new(),
            order: BTreeSet::new(),
        }
    }

    fn push(&mut self, record: NewTelemetryRecord) {
        if self.max_retained == 0 {
            return;
        }
        let rank_key: BoltRankKey = (
            parse_timestamp_epoch_ms(&record.timestamp),
            record.timestamp.clone(),
            record.uuid.clone(),
        );
        if let Some((existing_key, _)) = self.by_uuid.get(&record.uuid) {
            if rank_key <= *existing_key {
                return;
            }
            let prev_key = existing_key.clone();
            self.order.remove(&prev_key);
            self.order.insert(rank_key.clone());
            self.by_uuid.insert(record.uuid.clone(), (rank_key, record));
            return;
        }

        if self.by_uuid.len() < self.max_retained {
            self.order.insert(rank_key.clone());
            self.by_uuid.insert(record.uuid.clone(), (rank_key, record));
            return;
        }

        if let Some(oldest_key) = self.order.first().cloned() {
            if rank_key > oldest_key {
                self.order.remove(&oldest_key);
                self.by_uuid.remove(&oldest_key.2);
                self.order.insert(rank_key.clone());
                self.by_uuid.insert(record.uuid.clone(), (rank_key, record));
            }
        }
    }

    fn into_chronological_vec(mut self) -> Vec<NewTelemetryRecord> {
        let mut out = Vec::with_capacity(self.order.len());
        for key in &self.order {
            if let Some((_, rec)) = self.by_uuid.remove(&key.2) {
                out.push(rec);
            }
        }
        out
    }
}

fn walk_bbolt_page_id<S: BoltByteSource>(
    src: &S,
    page_size: usize,
    pgid: u64,
    depth: usize,
    visited: &mut HashSet<u64>,
    cumulative_bytes: &mut u64,
    out: &mut BoltRecordCollector,
) -> Result<()> {
    if depth > MAX_BOLTDB_TREE_DEPTH || pgid < 2 || visited.len() >= MAX_BOLTDB_VISITED_PAGES {
        bail!("bbolt tree depth or page bound exceeded at pgid={pgid}");
    }
    if !visited.insert(pgid) {
        bail!("cyclic bbolt page reference detected at pgid={pgid}");
    }
    let start = pgid
        .checked_mul(page_size as u64)
        .context("bbolt page start overflow")?;
    if start
        .checked_add(BBOLT_PAGE_HEADER_BYTES as u64)
        .is_none_or(|hdr_end| hdr_end > src.byte_len())
    {
        bail!("bbolt page {pgid} header out of file bounds");
    }
    let mut hdr = [0u8; BBOLT_PAGE_HEADER_BYTES];
    src.read_exact_at(start, &mut hdr)?;
    let overflow =
        u32::from_le_bytes(hdr[12..16].try_into().expect("4-byte overflow slice")) as usize;
    let span_pages = 1usize
        .checked_add(overflow)
        .context("bbolt page overflow count")?;
    let span_bytes = span_pages
        .checked_mul(page_size)
        .context("bbolt page span byte overflow")?;
    if span_bytes > MAX_BOLTDB_PAGE_SPAN_BYTES {
        bail!("bbolt page {pgid} span ({span_bytes} bytes) exceeds 16 MiB bound");
    }
    *cumulative_bytes = cumulative_bytes
        .checked_add(span_bytes as u64)
        .context("bbolt cumulative read byte overflow")?;
    if *cumulative_bytes > MAX_BOLTDB_CUMULATIVE_READ_BYTES {
        bail!("bbolt cumulative page reads exceed 16 GiB bound");
    }
    let end = start
        .checked_add(span_bytes as u64)
        .context("bbolt page end overflow")?;
    if end > src.byte_len() {
        bail!("bbolt page {pgid} span exceeds file length");
    }
    let mut page_buf = vec![0u8; span_bytes];
    src.read_exact_at(start, &mut page_buf)?;
    let flags = u16::from_le_bytes(page_buf[8..10].try_into().expect("2-byte flags"));
    if flags == BBOLT_BRANCH_FLAG {
        let count = u16::from_le_bytes(page_buf[10..12].try_into().expect("2-byte count")) as usize;
        let elems_end = count
            .checked_mul(16)
            .and_then(|n| BBOLT_PAGE_HEADER_BYTES.checked_add(n))
            .context("bbolt element table overflow")?;
        if elems_end > page_buf.len() {
            bail!("bbolt element headers exceed page span");
        }
        let mut child_pgids = Vec::with_capacity(count);
        for idx in 0..count {
            let elem_off = BBOLT_PAGE_HEADER_BYTES + idx * 16;
            child_pgids.push(u64::from_le_bytes(
                page_buf[elem_off + 8..elem_off + 16]
                    .try_into()
                    .expect("8-byte child pgid"),
            ));
        }
        // Drop branch page buffer before recursing so peak page-buffer memory stays <= 16 MiB.
        drop(page_buf);
        for child_pgid in child_pgids {
            walk_bbolt_page_id(
                src,
                page_size,
                child_pgid,
                depth + 1,
                visited,
                cumulative_bytes,
                out,
            )?;
        }
        return Ok(());
    }
    walk_bbolt_page_slice(
        src,
        page_size,
        &page_buf,
        depth,
        visited,
        cumulative_bytes,
        out,
    )
}

fn walk_bbolt_page_slice<S: BoltByteSource>(
    src: &S,
    page_size: usize,
    page_span: &[u8],
    depth: usize,
    visited: &mut HashSet<u64>,
    cumulative_bytes: &mut u64,
    out: &mut BoltRecordCollector,
) -> Result<()> {
    if depth > MAX_BOLTDB_TREE_DEPTH || page_span.len() < BBOLT_PAGE_HEADER_BYTES {
        bail!("invalid bbolt page slice");
    }
    let flags = u16::from_le_bytes(page_span[8..10].try_into().expect("2-byte flags"));
    let count = u16::from_le_bytes(page_span[10..12].try_into().expect("2-byte count")) as usize;
    let elems_end = count
        .checked_mul(16)
        .and_then(|n| BBOLT_PAGE_HEADER_BYTES.checked_add(n))
        .context("bbolt element table overflow")?;
    if elems_end > page_span.len() {
        bail!("bbolt element headers exceed page span");
    }

    if flags == BBOLT_BRANCH_FLAG {
        for idx in 0..count {
            let elem_off = BBOLT_PAGE_HEADER_BYTES + idx * 16;
            let child_pgid = u64::from_le_bytes(
                page_span[elem_off + 8..elem_off + 16]
                    .try_into()
                    .expect("8-byte child pgid"),
            );
            walk_bbolt_page_id(
                src,
                page_size,
                child_pgid,
                depth + 1,
                visited,
                cumulative_bytes,
                out,
            )?;
        }
        Ok(())
    } else if flags == BBOLT_LEAF_FLAG {
        for idx in 0..count {
            let elem_off = BBOLT_PAGE_HEADER_BYTES + idx * 16;
            let eflags = u32::from_le_bytes(
                page_span[elem_off..elem_off + 4]
                    .try_into()
                    .expect("eflags"),
            );
            let pos = u32::from_le_bytes(
                page_span[elem_off + 4..elem_off + 8]
                    .try_into()
                    .expect("pos"),
            ) as usize;
            let ksize = u32::from_le_bytes(
                page_span[elem_off + 8..elem_off + 12]
                    .try_into()
                    .expect("ksize"),
            ) as usize;
            let vsize = u32::from_le_bytes(
                page_span[elem_off + 12..elem_off + 16]
                    .try_into()
                    .expect("vsize"),
            ) as usize;
            let k_start = elem_off
                .checked_add(pos)
                .context("bbolt leaf key start overflow")?;
            let v_start = k_start
                .checked_add(ksize)
                .context("bbolt leaf val start overflow")?;
            let v_end = v_start
                .checked_add(vsize)
                .context("bbolt leaf val end overflow")?;
            if v_end > page_span.len() {
                bail!("bbolt leaf key/value exceeds page span");
            }
            let key_bytes = &page_span[k_start..v_start];
            let val_bytes = &page_span[v_start..v_end];
            if (eflags & BBOLT_BUCKET_LEAF_FLAG) != 0 {
                if val_bytes.len() < 16 {
                    bail!("truncated bbolt sub-bucket header");
                }
                let sub_root =
                    u64::from_le_bytes(val_bytes[0..8].try_into().expect("8-byte sub_root"));
                if sub_root == 0 {
                    if val_bytes.len() > 16 {
                        walk_bbolt_page_slice(
                            src,
                            page_size,
                            &val_bytes[16..],
                            depth + 1,
                            visited,
                            cumulative_bytes,
                            out,
                        )?;
                    }
                } else {
                    walk_bbolt_page_id(
                        src,
                        page_size,
                        sub_root,
                        depth + 1,
                        visited,
                        cumulative_bytes,
                        out,
                    )?;
                }
            } else if let Some(record) = decode_bolt_telemetry_leaf(key_bytes, val_bytes) {
                out.push(record);
            }
        }
        Ok(())
    } else {
        bail!("unsupported bbolt tree page flags 0x{flags:04x}");
    }
}

fn parse_boltdb_telemetry_with_meta<S: BoltByteSource>(
    src: &S,
    meta: BoltMeta,
    max_retained: usize,
) -> Result<Vec<NewTelemetryRecord>> {
    if meta.root_pgid < 2 {
        return Ok(Vec::new());
    }
    let mut visited = HashSet::new();
    let mut cumulative_bytes = 0u64;
    let mut collector = BoltRecordCollector::new(max_retained);
    walk_bbolt_page_id(
        src,
        meta.page_size,
        meta.root_pgid,
        0,
        &mut visited,
        &mut cumulative_bytes,
        &mut collector,
    )?;
    Ok(collector.into_chronological_vec())
}

fn parse_boltdb_telemetry_from_source<S: BoltByteSource>(
    src: &S,
    max_retained: usize,
) -> Result<Vec<NewTelemetryRecord>> {
    let Some(meta) = select_best_bbolt_meta_from_source(src) else {
        bail!("no valid bbolt v2 meta page with matching FNV-1a checksum");
    };
    parse_boltdb_telemetry_with_meta(src, meta, max_retained)
}

pub fn parse_boltdb_telemetry_bytes(data: &[u8]) -> Result<Vec<NewTelemetryRecord>> {
    parse_boltdb_telemetry_from_source(&data, usize::MAX)
}

pub(super) fn discover_and_import_legacy_bolt_backups(
    db_path: &Path,
    primary_backup: Option<&Path>,
    sibling_backup: Option<&Path>,
    conn: &mut Connection,
    max_rows: usize,
) -> Result<()> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(p) = primary_backup {
        candidates.push(p.to_path_buf());
    }
    if let Some(s) = sibling_backup {
        if !candidates.iter().any(|c| c == s) {
            candidates.push(s.to_path_buf());
        }
    }
    if let (Some(parent), Some(db_fname)) = (
        db_path.parent(),
        db_path.file_name().and_then(|s| s.to_str()),
    ) {
        if let Ok(entries) = fs::read_dir(parent) {
            let bak_exact = format!("{db_fname}.bak");
            let bak_prefix = format!("{db_fname}.bak.");
            let bolt_bak_exact = format!("{db_fname}.bolt.bak");
            let bolt_bak_prefix = format!("{db_fname}.bolt.bak.");
            let pre_migrate_prefix = format!("{db_fname}.pre-migrate.");
            let mut extra: Vec<PathBuf> = Vec::new();
            for entry in entries.flatten() {
                let Ok(ft) = entry.file_type() else {
                    continue;
                };
                if !ft.is_file() {
                    continue;
                }
                let fname_os = entry.file_name();
                let Some(fname) = fname_os.to_str() else {
                    continue;
                };
                let is_bolt_backup = fname == bak_exact
                    || fname.starts_with(&bak_prefix)
                    || fname == bolt_bak_exact
                    || fname.starts_with(&bolt_bak_prefix)
                    || fname == "speedtest.bolt.bak"
                    || fname.starts_with("speedtest.bolt.bak.")
                    || fname == "speedtest.bolt.bolt.bak"
                    || fname.starts_with("speedtest.bolt.bolt.bak.")
                    || ((fname.starts_with(&pre_migrate_prefix)
                        || fname.starts_with("speedtest.bolt.pre-migrate."))
                        && fname.ends_with(".bak"));
                if is_bolt_backup {
                    let path = entry.path();
                    if !candidates.iter().any(|c| c == &path) {
                        extra.push(path);
                    }
                }
            }
            extra.sort();
            candidates.extend(extra);
        }
    }

    for cand in candidates {
        let Some(source_name) = cand.file_name().and_then(|s| s.to_str()).map(str::to_owned) else {
            continue;
        };
        let already_migrated: bool = conn
            .query_row(
                "SELECT 1 FROM telemetry_bolt_migrations WHERE source_name = ?1 LIMIT 1",
                params![&source_name],
                |_| Ok(true),
            )
            .optional()
            .context("failed querying telemetry_bolt_migrations")?
            .unwrap_or(false);
        if already_migrated {
            continue;
        }
        import_legacy_boltdb_if_valid(&cand, &source_name, conn, max_rows)?;
    }
    Ok(())
}

fn import_legacy_boltdb_if_valid(
    backup_path: &Path,
    source_name: &str,
    conn: &mut Connection,
    max_rows: usize,
) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(backup_path)
        .with_context(|| {
            format!(
                "failed opening legacy BoltDB backup {} for migration",
                backup_path.display()
            )
        })?;
    let meta = file.metadata().with_context(|| {
        format!(
            "failed reading metadata for legacy BoltDB backup {}",
            backup_path.display()
        )
    })?;
    if !meta.is_file() {
        warn!(
            backup = %backup_path.display(),
            "Skipping legacy BoltDB telemetry import: backup is not a regular file"
        );
        return Ok(());
    }
    if meta.len() < 80 {
        warn!(
            backup = %backup_path.display(),
            size_bytes = meta.len(),
            "Legacy non-SQLite backup is smaller than bbolt header; leaving eligible for repair"
        );
        return Ok(());
    }

    let src = FileBoltSource {
        file,
        len: meta.len(),
    };
    let Some(bolt_meta) = select_best_bbolt_meta_from_source(&src) else {
        warn!(
            backup = %backup_path.display(),
            "Legacy non-SQLite backup has no valid committed BoltDB v2 meta page; leaving unrecorded for retry after repair"
        );
        return Ok(());
    };

    // Genuine committed BoltDB v2 archive: any B+tree parse/budget failure or SQLite write failure
    // MUST propagate so startup fails closed instead of silently serving an empty vault.
    let records =
        parse_boltdb_telemetry_with_meta(&src, bolt_meta, max_rows).with_context(|| {
            format!(
                "failed migrating committed BoltDB v2 telemetry archive {}",
                backup_path.display()
            )
        })?;

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let inserted = {
        let tx = conn.transaction().with_context(|| {
            format!(
                "failed beginning SQLite migration transaction for {}",
                backup_path.display()
            )
        })?;
        let mut count = 0usize;
        if !records.is_empty() {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO speedtest_users
                 (uuid, timestamp, ts_epoch_ms, ip, ispinfo, extra, ua, lang, dl, ul, ping, jitter, log)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )?;
            let mut legacy_id_stmt = tx.prepare(
                "INSERT OR IGNORE INTO telemetry_legacy_raw_ids (uuid, ulid_suffix) VALUES (?1, ?2)",
            )?;
            for rec in &records {
                let ts_epoch_ms = parse_timestamp_epoch_ms(&rec.timestamp);
                count += stmt.execute(params![
                    rec.uuid,
                    rec.timestamp,
                    ts_epoch_ms,
                    rec.ip,
                    rec.ispinfo,
                    rec.extra,
                    rec.ua,
                    rec.lang,
                    rec.dl,
                    rec.ul,
                    rec.ping,
                    rec.jitter,
                    rec.log,
                ])?;
                let suffix_opt = ulid_suffix_blob(&rec.uuid);
                legacy_id_stmt
                    .execute(params![rec.uuid, suffix_opt.as_ref().map(|b| b.as_slice())])?;
            }
        }
        enforce_retention_on_conn(&tx, max_rows)?;
        tx.execute(
            "INSERT OR IGNORE INTO telemetry_bolt_migrations (source_name, imported_at) VALUES (?1, ?2)",
            params![source_name, now_ts],
        )?;
        tx.commit().with_context(|| {
            format!(
                "failed committing migrated BoltDB rows from {}",
                backup_path.display()
            )
        })?;
        count
    };

    info!(
        backup_path = %backup_path.display(),
        imported_rows = inserted,
        "Migrated legacy BoltDB speedtest history into SQLite WAL telemetry vault"
    );
    Ok(())
}
