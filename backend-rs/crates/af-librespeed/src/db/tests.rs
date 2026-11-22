use super::bolt_migration::{
    fnv1a_64, BBOLT_BRANCH_FLAG, BBOLT_BUCKET_LEAF_FLAG, BBOLT_LEAF_FLAG, BBOLT_MAGIC,
    BBOLT_META_FLAG, BBOLT_PAGE_HEADER_BYTES, BBOLT_VERSION,
};
use super::*;
use std::os::unix::fs::{symlink, FileExt};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(label: &str) -> Self {
        let unique = format!(
            "af-librespeed-db-{}-{}-{}",
            label,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn opens_wal_vault_with_0600_perms_and_roundtrips_records() {
    let tmp = TempDirGuard::new("roundtrip");
    let db_path = tmp.0.join("nested").join("speedtest.db");

    let vault = TelemetryVault::open(&db_path).expect("open vault");
    let mode = fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    vault
        .insert(NewTelemetryRecord {
            uuid: "01JABCDEFGHJKMNPQRSTVWXYZ0".to_string(),
            timestamp: "2026-11-15T01:02:03.004Z".to_string(),
            ip: "198.51.100.1".to_string(),
            ispinfo: r#"{"processedString":"198.51.100.1"}"#.to_string(),
            extra: "tag=alpha".to_string(),
            ua: "Mozilla/5.0".to_string(),
            lang: "en-US".to_string(),
            dl: "912.34".to_string(),
            ul: "456.78".to_string(),
            ping: "4.25".to_string(),
            jitter: "0.75".to_string(),
            log: "ok".to_string(),
        })
        .await
        .unwrap();

    let fetched = vault
        .get_by_uuid("01JABCDEFGHJKMNPQRSTVWXYZ0".to_string())
        .await
        .unwrap()
        .expect("record exists");
    assert_eq!(fetched.dl, "912.34");
    assert_eq!(fetched.extra, "tag=alpha");

    let recent = vault.list_recent(10).await.unwrap();
    assert_eq!(recent.len(), 1);

    // Verify obfuscation_key persists across reopen and pre-existing 0644 perms tighten to 0600
    let first_key = *vault.obfuscation_key();
    drop(vault);
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o644)).unwrap();
    let reopened = TelemetryVault::open(&db_path).expect("reopen vault");
    assert_eq!(reopened.obfuscation_key(), &first_key);
    let tightened = fs::metadata(&db_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(tightened, 0o600);
}

#[test]
fn backs_up_legacy_boltdb_header_before_sqlite_init() {
    let tmp = TempDirGuard::new("bolt");
    let db_path = tmp.0.join("speedtest.db");
    let mut fake_bolt = vec![0u8; 64];
    fake_bolt[12..16].copy_from_slice(&[0xED, 0xDA, 0x0C, 0xED]);
    fs::write(&db_path, &fake_bolt).unwrap();
    fs::set_permissions(&db_path, fs::Permissions::from_mode(0o644)).unwrap();

    let _vault = TelemetryVault::open(&db_path).expect("open migrated vault");
    let bak_path = tmp.0.join("speedtest.db.bolt.bak");
    assert!(bak_path.exists());
    assert_eq!(fs::read(&bak_path).unwrap(), fake_bolt);
    let bak_mode = fs::metadata(&bak_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(bak_mode, 0o600);

    let header = &fs::read(&db_path).unwrap()[..16];
    assert_eq!(header, SQLITE_MAGIC);

    // Second non-SQLite migration never overwrites existing .bolt.bak (nor a pre-existing .bolt.bak.<ts>)
    let mut second_bolt = vec![0xA5u8; 64];
    second_bolt[12..16].copy_from_slice(&[0xED, 0xDA, 0x0C, 0xED]);
    fs::write(&db_path, &second_bolt).unwrap();
    let _vault2 = TelemetryVault::open(&db_path).expect("open second migrated vault");
    assert_eq!(fs::read(&bak_path).unwrap(), fake_bolt);
    let extra_baks: Vec<_> = fs::read_dir(&tmp.0)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p != &bak_path
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("speedtest.db.bolt.bak."))
        })
        .collect();
    assert_eq!(extra_baks.len(), 1);
    assert_eq!(fs::read(&extra_baks[0]).unwrap(), second_bolt);
}

#[test]
fn rejects_world_writable_parent_dir_including_sticky() {
    let tmp = TempDirGuard::new("world-writable");
    for mode in [0o777, 0o1777] {
        let insecure_dir = tmp.0.join(format!("insecure-{mode:o}"));
        fs::create_dir_all(&insecure_dir).unwrap();
        fs::set_permissions(&insecure_dir, fs::Permissions::from_mode(mode)).unwrap();
        let res = TelemetryVault::open(&insecure_dir.join("speedtest.db"));
        fs::set_permissions(&insecure_dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            res.is_err(),
            "expected world-writable mode {mode:o} to fail"
        );
    }
}

#[test]
fn rejects_symlinked_db_sidecar_and_parent() {
    let tmp = TempDirGuard::new("symlink");
    let target = tmp.0.join("real.db");
    fs::write(&target, b"").unwrap();

    let sym_db = tmp.0.join("sym.db");
    symlink(&target, &sym_db).unwrap();
    assert!(TelemetryVault::open(&sym_db).is_err());

    let normal_db = tmp.0.join("normal.db");
    let wal_link = tmp.0.join("normal.db-wal");
    symlink(&target, &wal_link).unwrap();
    assert!(TelemetryVault::open(&normal_db).is_err());

    let journal_db = tmp.0.join("journal.db");
    let journal_link = tmp.0.join("journal.db-journal");
    symlink(&target, &journal_link).unwrap();
    assert!(TelemetryVault::open(&journal_db).is_err());

    let real_dir = tmp.0.join("real_dir");
    fs::create_dir_all(&real_dir).unwrap();
    let sym_dir = tmp.0.join("sym_dir");
    symlink(&real_dir, &sym_dir).unwrap();
    assert!(TelemetryVault::open(&sym_dir.join("sub.db")).is_err());
}

fn write_test_bbolt_meta_page(
    buf: &mut [u8],
    pgid: u64,
    page_size: u32,
    root_pgid: u64,
    txid: u64,
) {
    buf.fill(0);
    buf[0..8].copy_from_slice(&pgid.to_le_bytes());
    buf[8..10].copy_from_slice(&BBOLT_META_FLAG.to_le_bytes());
    buf[16..20].copy_from_slice(&BBOLT_MAGIC.to_le_bytes());
    buf[20..24].copy_from_slice(&BBOLT_VERSION.to_le_bytes());
    buf[24..28].copy_from_slice(&page_size.to_le_bytes());
    buf[32..40].copy_from_slice(&root_pgid.to_le_bytes());
    buf[56..64].copy_from_slice(&(pgid + 5).to_le_bytes());
    buf[64..72].copy_from_slice(&txid.to_le_bytes());
    let checksum = fnv1a_64(&buf[16..72]);
    buf[72..80].copy_from_slice(&checksum.to_le_bytes());
}

fn build_leaf_page_bytes(pgid: u64, page_len: usize, items: &[(u32, &[u8], &[u8])]) -> Vec<u8> {
    let mut page = vec![0u8; page_len];
    page[0..8].copy_from_slice(&pgid.to_le_bytes());
    page[8..10].copy_from_slice(&BBOLT_LEAF_FLAG.to_le_bytes());
    page[10..12].copy_from_slice(&(items.len() as u16).to_le_bytes());
    let mut data_cursor = BBOLT_PAGE_HEADER_BYTES + items.len() * 16;
    for (idx, (eflags, k, v)) in items.iter().enumerate() {
        let elem_off = BBOLT_PAGE_HEADER_BYTES + idx * 16;
        let pos = (data_cursor - elem_off) as u32;
        page[elem_off..elem_off + 4].copy_from_slice(&eflags.to_le_bytes());
        page[elem_off + 4..elem_off + 8].copy_from_slice(&pos.to_le_bytes());
        page[elem_off + 8..elem_off + 12].copy_from_slice(&(k.len() as u32).to_le_bytes());
        page[elem_off + 12..elem_off + 16].copy_from_slice(&(v.len() as u32).to_le_bytes());
        page[data_cursor..data_cursor + k.len()].copy_from_slice(k);
        data_cursor += k.len();
        page[data_cursor..data_cursor + v.len()].copy_from_slice(v);
        data_cursor += v.len();
    }
    page
}

#[tokio::test]
async fn migrates_legacy_bbolt_v2_records_both_paged_and_inline_buckets_and_preserves_backup() {
    let page_size = 4096usize;
    let mut archive = vec![0u8; page_size * 5];

    // Page 0: older meta (txid=1, bogus root 99); Page 1: newer committed meta (txid=2, root=2)
    write_test_bbolt_meta_page(&mut archive[0..page_size], 0, page_size as u32, 99, 1);
    write_test_bbolt_meta_page(
        &mut archive[page_size..page_size * 2],
        1,
        page_size as u32,
        2,
        2,
    );

    // Inline sub-bucket value (16-byte bucket header with root=0 + embedded leaf page)
    let inline_json = br#"{"uuid":"01JABCDEFGHJKMNPQRSTVWXYZ2","timestamp":"2026-11-15T10:02:00.000Z","ip":"198.51.100.8","dl":"888.88","ul":"444.44","ping":"2.50","jitter":"0.25","extra":"inline-bucket"}"#;
    let inline_leaf = build_leaf_page_bytes(
        0,
        320,
        &[(0, b"01JABCDEFGHJKMNPQRSTVWXYZ2", inline_json.as_slice())],
    );
    let mut inline_bucket_val = vec![0u8; 16 + inline_leaf.len()];
    inline_bucket_val[16..].copy_from_slice(&inline_leaf);

    // Normal sub-bucket value pointing to branch page 3
    let mut paged_bucket_val = [0u8; 16];
    paged_bucket_val[0..8].copy_from_slice(&3u64.to_le_bytes());

    // Page 2: root leaf page containing both buckets
    let root_page = build_leaf_page_bytes(
        2,
        page_size,
        &[
            (
                BBOLT_BUCKET_LEAF_FLAG,
                b"inline_speedtest",
                &inline_bucket_val,
            ),
            (BBOLT_BUCKET_LEAF_FLAG, b"speedtest", &paged_bucket_val),
        ],
    );
    archive[page_size * 2..page_size * 3].copy_from_slice(&root_page);

    // Page 3: branch page pointing to leaf page 4
    {
        let branch = &mut archive[page_size * 3..page_size * 4];
        branch[0..8].copy_from_slice(&3u64.to_le_bytes());
        branch[8..10].copy_from_slice(&BBOLT_BRANCH_FLAG.to_le_bytes());
        branch[10..12].copy_from_slice(&1u16.to_le_bytes());
        let elem_off = BBOLT_PAGE_HEADER_BYTES;
        let key = b"01JABCDEFGHJKMNPQRSTVWXYZ1";
        branch[elem_off..elem_off + 4].copy_from_slice(&16u32.to_le_bytes());
        branch[elem_off + 4..elem_off + 8].copy_from_slice(&(key.len() as u32).to_le_bytes());
        branch[elem_off + 8..elem_off + 16].copy_from_slice(&4u64.to_le_bytes());
        branch[elem_off + 16..elem_off + 16 + key.len()].copy_from_slice(key);
    }

    // Page 4: leaf page with Go speedtest-go PascalCase TelemetryData record
    let go_json = br#"{"UUID":"01JABCDEFGHJKMNPQRSTVWXYZ1","Timestamp":"2026-11-15T10:01:00.000Z","IPAddress":"198.51.100.7","ISPInfo":"{\"processedString\":\"198.51.100.7 - ExampleISP\"}","Extra":"paged-bucket","UserAgent":"GoSpeedtest/1.1","Language":"en-US","Download":"777.77","Upload":"333.33","Ping":"3.10","Jitter":"0.40","Log":"ok"}"#;
    let leaf_page = build_leaf_page_bytes(
        4,
        page_size,
        &[(0, b"01JABCDEFGHJKMNPQRSTVWXYZ1", go_json.as_slice())],
    );
    archive[page_size * 4..page_size * 5].copy_from_slice(&leaf_page);

    let tmp = TempDirGuard::new("bolt-v2-import");
    let db_path = tmp.0.join("speedtest.db");
    fs::write(&db_path, &archive).unwrap();

    let vault = TelemetryVault::open(&db_path).expect("open & migrate bbolt v2");
    let bak_path = tmp.0.join("speedtest.db.bolt.bak");
    assert_eq!(fs::read(&bak_path).unwrap(), archive);
    assert_eq!(
        fs::metadata(&bak_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let recent = vault.list_recent(10).await.unwrap();
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].uuid, "01JABCDEFGHJKMNPQRSTVWXYZ2");
    assert_eq!(recent[0].dl, "888.88");
    assert_eq!(recent[0].extra, "inline-bucket");
    assert_eq!(recent[1].uuid, "01JABCDEFGHJKMNPQRSTVWXYZ1");
    assert_eq!(recent[1].dl, "777.77");
    assert_eq!(recent[1].extra, "paged-bucket");

    let by_id = vault
        .get_by_uuid("01JABCDEFGHJKMNPQRSTVWXYZ1".to_string())
        .await
        .unwrap()
        .expect("migrated record retrievable by ULID");
    assert_eq!(by_id.ul, "333.33");
    assert_eq!(by_id.ip, "198.51.100.7");

    // Cyclic branch page self-reference must be rejected cleanly
    let mut cyclic = archive.clone();
    let self_off = page_size * 3 + BBOLT_PAGE_HEADER_BYTES + 8;
    cyclic[self_off..self_off + 8].copy_from_slice(&3u64.to_le_bytes());
    assert!(parse_boltdb_telemetry_bytes(&cyclic).is_err());

    // Crash-resumable migration: simulate process crash right after BoltDB was renamed to
    // `speedtest.db.bolt.bak` (before SQLite imported rows), and confirm next startup
    // discovers `.bolt.bak`, imports records once, and records legacy raw IDs.
    let crash_tmp = TempDirGuard::new("bolt-crash-resume");
    let crash_db = crash_tmp.0.join("speedtest.db");
    let crash_bak = crash_tmp.0.join("speedtest.db.bolt.bak");
    fs::write(&crash_bak, &archive).unwrap();
    let resumed = TelemetryVault::open(&crash_db).expect("resume interrupted bolt migration");
    assert_eq!(resumed.list_recent(10).await.unwrap().len(), 2);
    assert!(resumed
        .is_legacy_raw_id("01JABCDEFGHJKMNPQRSTVWXYZ1".to_string())
        .await
        .unwrap());

    // In-memory vault supports full telemetry lifecycle without touching disk
    let mem_vault = TelemetryVault::open_in_memory(10).expect("in-memory vault");
    assert_eq!(mem_vault.path(), Path::new(":memory:"));
}

fn build_single_record_bbolt_archive(uuid: &str, timestamp: &str, dl: &str) -> Vec<u8> {
    let page_size = 4096usize;
    let mut archive = vec![0u8; page_size * 4];
    write_test_bbolt_meta_page(&mut archive[0..page_size], 0, page_size as u32, 2, 1);
    write_test_bbolt_meta_page(
        &mut archive[page_size..page_size * 2],
        1,
        page_size as u32,
        2,
        2,
    );
    let mut bucket_val = [0u8; 16];
    bucket_val[0..8].copy_from_slice(&3u64.to_le_bytes());
    let root_page = build_leaf_page_bytes(
        2,
        page_size,
        &[(BBOLT_BUCKET_LEAF_FLAG, b"speedtest", &bucket_val)],
    );
    archive[page_size * 2..page_size * 3].copy_from_slice(&root_page);

    let payload = format!(
        r#"{{"uuid":"{uuid}","timestamp":"{timestamp}","ip":"198.51.100.9","dl":"{dl}","ul":"100.0","ping":"1.5","jitter":"0.2"}}"#
    );
    let leaf_page =
        build_leaf_page_bytes(3, page_size, &[(0, uuid.as_bytes(), payload.as_bytes())]);
    archive[page_size * 3..page_size * 4].copy_from_slice(&leaf_page);
    archive
}

#[tokio::test]
async fn migrates_sparse_128mib_bbolt_via_pread_and_retries_after_repair() {
    let tmp = TempDirGuard::new("sparse-128m-and-retry");
    let db_path = tmp.0.join("speedtest.db");
    let sparse_bak = tmp.0.join("speedtest.bolt.bak");

    // 1. Truncated/unreadable backup must NOT be permanently marked migrated
    fs::write(&sparse_bak, b"truncated-partial-copy").unwrap();
    {
        let v1 = TelemetryVault::open(&db_path).expect("open with truncated backup");
        assert!(v1.list_recent(10).await.unwrap().is_empty());
    }

    // 2. Repair the backup into a sparse 128 MiB BoltDB v2 file (> old 64 MiB limit)
    //    with leaf page placed at 96 MiB (pgid = 24_576 * 4096)
    let page_size = 4096usize;
    let high_leaf_pgid: u64 = 24_576;
    let f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&sparse_bak)
        .unwrap();
    f.set_len(128 * 1024 * 1024).unwrap();
    let mut meta0 = vec![0u8; page_size];
    let mut meta1 = vec![0u8; page_size];
    write_test_bbolt_meta_page(&mut meta0, 0, page_size as u32, 2, 1);
    write_test_bbolt_meta_page(&mut meta1, 1, page_size as u32, 2, 2);
    f.write_all_at(&meta0, 0).unwrap();
    f.write_all_at(&meta1, page_size as u64).unwrap();

    let mut bucket_val = [0u8; 16];
    bucket_val[0..8].copy_from_slice(&high_leaf_pgid.to_le_bytes());
    let root_page = build_leaf_page_bytes(
        2,
        page_size,
        &[(BBOLT_BUCKET_LEAF_FLAG, b"speedtest", &bucket_val)],
    );
    f.write_all_at(&root_page, (page_size * 2) as u64).unwrap();

    let rec_json = br#"{"uuid":"01JABCDEFGHJKMNPQRSTVWXYZ9","timestamp":"2026-11-15T12:00:00.000Z","dl":"950.5","ul":"450.2","ping":"1.9","jitter":"0.1"}"#;
    let high_leaf = build_leaf_page_bytes(
        high_leaf_pgid,
        page_size,
        &[(0, b"01JABCDEFGHJKMNPQRSTVWXYZ9", rec_json.as_slice())],
    );
    f.write_all_at(&high_leaf, high_leaf_pgid * page_size as u64)
        .unwrap();
    drop(f);

    let v2 = TelemetryVault::open(&db_path).expect("reopen after repairing 128 MiB boltdb");
    let rows = v2.list_recent(10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].uuid, "01JABCDEFGHJKMNPQRSTVWXYZ9");
    assert_eq!(rows[0].dl, "950.5");
}

#[tokio::test]
async fn bolt_extension_backup_naming_multi_backup_retention_and_legacy_go_share_ids() {
    use crate::ulid::encode_legacy_go_obfuscated_ulid;

    // 1. Direct `.bolt` database_file backs up to `speedtest.bolt.bak` (not `.bolt.bolt.bak`)
    let tmp_bolt = TempDirGuard::new("dot-bolt-naming");
    let dot_bolt_db = tmp_bolt.0.join("speedtest.bolt");
    let arch1 = build_single_record_bbolt_archive(
        "01JABCDEFGHJKMNPQRSTVWXYZ3",
        "2026-11-15T09:00:00.000Z",
        "500.0",
    );
    fs::write(&dot_bolt_db, &arch1).unwrap();
    let salt = [0x12, 0x34, 0x56, 0x78];
    let salt_path = tmp_bolt.0.join("idObfuscation_salt.bin");
    fs::write(&salt_path, salt).unwrap();
    fs::set_permissions(&salt_path, fs::Permissions::from_mode(0o644)).unwrap();

    let v_bolt = TelemetryVault::open(&dot_bolt_db).expect("migrate speedtest.bolt");
    assert!(tmp_bolt.0.join("speedtest.bolt.bak").is_file());
    assert!(!tmp_bolt.0.join("speedtest.bolt.bolt.bak").exists());
    assert_eq!(
        fs::metadata(&salt_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(v_bolt.legacy_go_salt(), Some(salt));

    let go_tok = encode_legacy_go_obfuscated_ulid("01JABCDEFGHJKMNPQRSTVWXYZ3", &salt).unwrap();
    assert_eq!(
        v_bolt
            .resolve_legacy_go_share_id(go_tok.clone())
            .await
            .unwrap()
            .as_deref(),
        Some("01JABCDEFGHJKMNPQRSTVWXYZ3")
    );

    // 2. Multi-backup global `max_rows = 1` cap + crash-resume of `.bolt.bolt.bak` + saltless 96-bit fallback
    let tmp_cap = TempDirGuard::new("multi-backup-cap");
    let cap_db = tmp_cap.0.join("speedtest.db");
    let older = build_single_record_bbolt_archive(
        "01JABCDEFGHJKMNPQRSTVWXYZ4",
        "2026-11-15T08:00:00.000Z",
        "300.0",
    );
    let newer = build_single_record_bbolt_archive(
        "01JABCDEFGHJKMNPQRSTVWXYZ5",
        "2026-11-15T11:00:00.000Z",
        "999.0",
    );
    fs::write(tmp_cap.0.join("speedtest.bolt.bolt.bak"), &older).unwrap();
    fs::write(tmp_cap.0.join("speedtest.db.bolt.bak"), &newer).unwrap();

    let v_cap = TelemetryVault::open_with_max_rows(&cap_db, 1).expect("open with max_rows=1");
    let kept = v_cap.list_recent(10).await.unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].uuid, "01JABCDEFGHJKMNPQRSTVWXYZ5");
    assert!(!v_cap
        .is_legacy_raw_id("01JABCDEFGHJKMNPQRSTVWXYZ4".to_string())
        .await
        .unwrap());

    // Saltless 96-bit suffix fallback resolves unique migrated ULID even without idObfuscation_salt.bin
    let unknown_salt_tok =
        encode_legacy_go_obfuscated_ulid("01JABCDEFGHJKMNPQRSTVWXYZ5", &[0xAA, 0xBB, 0xCC, 0xDD])
            .unwrap();
    assert_eq!(v_cap.legacy_go_salt(), None);
    assert_eq!(
        v_cap
            .resolve_legacy_go_share_id(unknown_salt_tok)
            .await
            .unwrap()
            .as_deref(),
        Some("01JABCDEFGHJKMNPQRSTVWXYZ5")
    );
}

#[tokio::test]
async fn reopen_enforces_lowered_max_rows_and_mixed_offset_timestamp_ordering() {
    let tmp = TempDirGuard::new("reopen-retention-offsets");
    let db_path = tmp.0.join("speedtest.db");

    // 1. Insert 3 records with mixed timezone offsets where row insertion order != UTC chronological order:
    // - r1: 2026-11-15T18:00:00+02:00 == 16:00:00Z (middle)
    // - r2: 2026-11-15T15:30:00Z       == 15:30:00Z (oldest, inserted 2nd!)
    // - r3: 2026-11-15 16:45:00.250 +0000 UTC m=+12.34 == 16:45:00.250Z (newest, Go time.Time.String())
    {
        let v = TelemetryVault::open_with_max_rows(&db_path, 10).unwrap();
        for (uuid, ts, dl) in [
            (
                "01JABCDEFGHJKMNPQRSTVWXYA1",
                "2026-11-15T18:00:00+02:00",
                "200.0",
            ),
            (
                "01JABCDEFGHJKMNPQRSTVWXYA2",
                "2026-11-15T15:30:00Z",
                "100.0",
            ),
            (
                "01JABCDEFGHJKMNPQRSTVWXYA3",
                "2026-11-15 16:45:00.250 +0000 UTC m=+12.345",
                "300.0",
            ),
        ] {
            v.insert_with_mode(
                NewTelemetryRecord {
                    uuid: uuid.to_string(),
                    timestamp: ts.to_string(),
                    ip: "0.0.0.0".to_string(),
                    ispinfo: String::new(),
                    extra: String::new(),
                    ua: String::new(),
                    lang: String::new(),
                    dl: dl.to_string(),
                    ul: "50.0".to_string(),
                    ping: "4.0".to_string(),
                    jitter: "0.5".to_string(),
                    log: String::new(),
                },
                true,
            )
            .await
            .unwrap();
        }

        let ordered = v.list_recent(10).await.unwrap();
        let uuids: Vec<&str> = ordered.iter().map(|r| r.uuid.as_str()).collect();
        assert_eq!(
            uuids,
            vec![
                "01JABCDEFGHJKMNPQRSTVWXYA3",
                "01JABCDEFGHJKMNPQRSTVWXYA1",
                "01JABCDEFGHJKMNPQRSTVWXYA2",
            ],
            "list_recent must order by parsed UTC epoch ms, not string or rowid order"
        );
    }

    // 2. Reopen the existing SQLite DB with lowered `max_rows = 2` (with NO BoltDB import);
    // the oldest UTC record (`A2`, 15:30Z) must be pruned immediately on reopen even though it had higher `id` than `A1`!
    let v_reopened = TelemetryVault::open_with_max_rows(&db_path, 2).unwrap();
    let after_reopen = v_reopened.list_recent(10).await.unwrap();
    let kept_uuids: Vec<&str> = after_reopen.iter().map(|r| r.uuid.as_str()).collect();
    assert_eq!(
        kept_uuids,
        vec!["01JABCDEFGHJKMNPQRSTVWXYA3", "01JABCDEFGHJKMNPQRSTVWXYA1"]
    );
    assert!(!v_reopened
        .is_legacy_raw_id("01JABCDEFGHJKMNPQRSTVWXYA2".to_string())
        .await
        .unwrap());
}

#[tokio::test]
async fn first_open_of_pre_obfuscation_sqlite_db_backfills_ulid_suffix_without_salt() {
    use crate::ulid::{encode_legacy_go_obfuscated_ulid, generate_ulid};

    let tmp = TempDirGuard::new("first-open-legacy-suffix");
    let db_path = tmp.0.join("legacy_go.sql");

    let legacy_uuid = generate_ulid();
    let unknown_salt = [0xDE, 0xAD, 0xBE, 0xEF];
    let legacy_share_token = encode_legacy_go_obfuscated_ulid(&legacy_uuid, &unknown_salt).unwrap();

    // Simulate pre-existing Go SQLite database (`speedtest_users` only, no `telemetry_meta` or salt file)
    {
        let raw_conn = Connection::open(&db_path).unwrap();
        raw_conn
            .execute_batch(
                "CREATE TABLE speedtest_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    ispinfo TEXT,
                    extra TEXT,
                    ua TEXT NOT NULL,
                    lang TEXT NOT NULL,
                    dl TEXT,
                    ul TEXT,
                    ping TEXT,
                    jitter TEXT,
                    log TEXT,
                    uuid TEXT UNIQUE
                );",
            )
            .unwrap();
        raw_conn
            .execute(
                "INSERT INTO speedtest_users (timestamp, ip, ispinfo, extra, ua, lang, dl, ul, ping, jitter, log, uuid)
                 VALUES ('2026-11-15T10:00:00Z', '198.51.100.12', '', '', 'TestUA', 'en', '777.0', '333.0', '3.1', '0.2', '', ?1)",
                params![&legacy_uuid],
            )
            .unwrap();
    }

    // Very FIRST open of TelemetryVault (no restart, no `idObfuscation_salt.bin` on disk)
    let vault = TelemetryVault::open(&db_path).unwrap();
    assert!(vault.legacy_go_salt.is_none());

    let resolved = vault
        .resolve_legacy_go_share_id(legacy_share_token)
        .await
        .unwrap();
    assert_eq!(
        resolved.as_deref(),
        Some(legacy_uuid.as_str()),
        "first startup must backfill ulid_suffix so saltless Go XOR share tokens resolve immediately"
    );
}

#[tokio::test]
async fn migrates_over_256mib_bbolt_in_bounded_ram_and_fails_closed_on_corrupt_committed_bolt() {
    let tmp = TempDirGuard::new("over-256mib-bbolt");
    let db_path = tmp.0.join("speedtest.db");
    let big_bak = tmp.0.join("speedtest.bolt.bak");

    // Build a synthetic 64-record, >256 MiB (268,455,936 bytes = 65,541 * 4096) BoltDB v2 archive
    // where 64 leaf overflow spans each occupy 1,025 pages (4,198,400 bytes -> 268,697,600 bytes total).
    let page_size = 4096usize;
    let span_pages = 1025usize; // > 4 MiB per leaf span; 64 * 4,198,400 = 268,697,600 bytes (> 256 MiB)
    let span_bytes = span_pages * page_size;
    let branch_pgid = 3u64;
    let first_leaf_pgid = 5u64;
    let total_pages = first_leaf_pgid + (64u64 * span_pages as u64);
    let file_bytes = total_pages * page_size as u64;
    assert!(file_bytes > 256 * 1024 * 1024);

    let f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&big_bak)
        .unwrap();
    f.set_len(file_bytes).unwrap();

    let mut meta0 = vec![0u8; page_size];
    let mut meta1 = vec![0u8; page_size];
    write_test_bbolt_meta_page(&mut meta0, 0, page_size as u32, 2, 1);
    write_test_bbolt_meta_page(&mut meta1, 1, page_size as u32, 2, 2);
    f.write_all_at(&meta0, 0).unwrap();
    f.write_all_at(&meta1, page_size as u64).unwrap();

    let mut bucket_val = [0u8; 16];
    bucket_val[0..8].copy_from_slice(&branch_pgid.to_le_bytes());
    let root_page = build_leaf_page_bytes(
        2,
        page_size,
        &[(BBOLT_BUCKET_LEAF_FLAG, b"speedtest", &bucket_val)],
    );
    f.write_all_at(&root_page, (page_size * 2) as u64).unwrap();

    // Branch page 3 with 64 children
    let mut branch = vec![0u8; page_size * 2];
    branch[0..8].copy_from_slice(&branch_pgid.to_le_bytes());
    branch[8..10].copy_from_slice(&BBOLT_BRANCH_FLAG.to_le_bytes());
    branch[10..12].copy_from_slice(&64u16.to_le_bytes());
    branch[12..16].copy_from_slice(&1u32.to_le_bytes()); // 1 overflow page for 64 branch elements + keys
    let mut key_cursor = BBOLT_PAGE_HEADER_BYTES + 64 * 16;
    for i in 0..64usize {
        let child_pgid = first_leaf_pgid + (i as u64 * span_pages as u64);
        let uuid = format!("01JABCDEFGHJKMNPQRSTVW{:04}", i);
        let elem_off = BBOLT_PAGE_HEADER_BYTES + i * 16;
        let pos = (key_cursor - elem_off) as u32;
        branch[elem_off..elem_off + 4].copy_from_slice(&pos.to_le_bytes());
        branch[elem_off + 4..elem_off + 8].copy_from_slice(&(uuid.len() as u32).to_le_bytes());
        branch[elem_off + 8..elem_off + 16].copy_from_slice(&child_pgid.to_le_bytes());
        branch[key_cursor..key_cursor + uuid.len()].copy_from_slice(uuid.as_bytes());
        key_cursor += uuid.len();

        let ts = format!("2026-11-15T12:{:02}:00.000Z", i % 60);
        let ts_adj = if i >= 60 {
            format!("2026-11-15T13:{:02}:00.000Z", i - 60)
        } else {
            ts
        };
        let payload = format!(
            r#"{{"uuid":"{uuid}","timestamp":"{ts_adj}","ip":"198.51.100.42","dl":"{}.5","ul":"100.0","ping":"2.0","jitter":"0.3"}}"#,
            500 + i
        );
        // Write only the leaf header + 1 element + payload at child_pgid; trailing sparse zeros are valid page slack
        let mut leaf_prefix = build_leaf_page_bytes(
            child_pgid,
            page_size,
            &[(0, uuid.as_bytes(), payload.as_bytes())],
        );
        let overflow_count = (span_pages - 1) as u32;
        leaf_prefix[12..16].copy_from_slice(&overflow_count.to_le_bytes());
        assert_eq!(leaf_prefix.len(), page_size);
        let _ = span_bytes;
        f.write_all_at(&leaf_prefix, child_pgid * page_size as u64)
            .unwrap();
    }
    f.write_all_at(&branch, branch_pgid * page_size as u64)
        .unwrap();
    drop(f);

    let vault = TelemetryVault::open_with_max_rows(&db_path, 100)
        .expect("migrate >256 MiB 64-record BoltDB v2 archive");
    let rows = vault.list_recent(100).await.unwrap();
    assert_eq!(rows.len(), 64, "all 64 records must be migrated");
    assert_eq!(rows[0].uuid, "01JABCDEFGHJKMNPQRSTVW0063");
    assert_eq!(rows[63].uuid, "01JABCDEFGHJKMNPQRSTVW0000");

    // Verify a committed BoltDB v2 archive with a corrupt/out-of-bounds root page fails closed
    let bad_tmp = TempDirGuard::new("corrupt-committed-bolt");
    let bad_db = bad_tmp.0.join("speedtest.db");
    let bad_bak = bad_tmp.0.join("speedtest.bolt.bak");
    let mut corrupt_committed = vec![0u8; page_size * 2];
    write_test_bbolt_meta_page(
        &mut corrupt_committed[0..page_size],
        0,
        page_size as u32,
        999,
        5,
    );
    fs::write(&bad_bak, &corrupt_committed).unwrap();
    let err = TelemetryVault::open_with_max_rows(&bad_db, 100);
    assert!(
        err.is_err(),
        "corrupt committed BoltDB v2 archive must fail closed instead of returning an empty vault"
    );
}

#[tokio::test]
async fn legacy_sqlite_rows_with_null_columns_reopen_and_query_cleanly() {
    let tmp = TempDirGuard::new("null-legacy-sqlite-cols");
    let db_path = tmp.0.join("speedtest.db");
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE speedtest_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid TEXT,
                timestamp TEXT,
                ip TEXT,
                ispinfo TEXT,
                extra TEXT,
                ua TEXT,
                lang TEXT,
                dl TEXT,
                ul TEXT,
                ping TEXT,
                jitter TEXT,
                log TEXT
            );
            INSERT INTO speedtest_users (uuid, timestamp, ip, ispinfo, extra, ua, lang, dl, ul, ping, jitter, log)
            VALUES ('01JNULLTEST000000000000001', NULL, '192.0.2.55', NULL, NULL, NULL, NULL, '250.4', NULL, '4.1', NULL, NULL);",
        )
        .unwrap();
    }

    let vault = TelemetryVault::open_with_max_rows(&db_path, 100)
        .expect("reopen pre-existing SQLite DB with NULL text columns");
    let recent = vault
        .list_recent(10)
        .await
        .expect("list_recent with NULL columns");
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].uuid, "01JNULLTEST000000000000001");
    assert_eq!(recent[0].ip, "192.0.2.55");
    assert_eq!(recent[0].dl, "250.4");
    assert_eq!(recent[0].ispinfo, "");
    assert_eq!(recent[0].extra, "");
    assert_eq!(recent[0].log, "");

    let by_id = vault
        .get_by_uuid("01JNULLTEST000000000000001".to_string())
        .await
        .expect("get_by_uuid with NULL columns")
        .expect("row must exist");
    assert_eq!(by_id.uuid, "01JNULLTEST000000000000001");
    assert_eq!(by_id.ping, "4.1");
    assert_eq!(by_id.ul, "");
}

#[tokio::test]
async fn unreadable_sibling_boltdb_fails_closed_until_permissions_repaired() {
    use std::os::unix::fs::PermissionsExt;
    // Skip chmod-000 permission denial check if running as root (UID 0 bypasses DAC read bits)
    if unsafe { libc::geteuid() == 0 } {
        return;
    }
    let tmp = TempDirGuard::new("unreadable-sibling-bolt");
    let db_path = tmp.0.join("speedtest.db");
    let sibling_bolt = tmp.0.join("speedtest.bolt");
    let bolt_bytes = build_single_record_bbolt_archive(
        "01JSIBLINGBOLT0000000000001",
        "2026-11-16 01:00:00",
        "888.8",
    );
    std::fs::write(&sibling_bolt, &bolt_bytes).unwrap();
    std::fs::set_permissions(&sibling_bolt, std::fs::Permissions::from_mode(0o000)).unwrap();

    let err = TelemetryVault::open_with_max_rows(&db_path, 100)
        .err()
        .expect(
        "unreadable sibling speedtest.bolt must fail closed rather than silently starting empty",
    );
    assert!(
        format!("{err:#}").contains("speedtest.bolt")
            || format!("{err:#}").contains("Permission denied"),
        "unexpected error for unreadable sibling bolt: {err:#}"
    );

    std::fs::set_permissions(&sibling_bolt, std::fs::Permissions::from_mode(0o600)).unwrap();
    let vault = TelemetryVault::open_with_max_rows(&db_path, 100)
        .expect("reopen after repairing sibling speedtest.bolt permissions");
    let rows = vault.list_recent(10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].uuid, "01JSIBLINGBOLT0000000000001");
}
