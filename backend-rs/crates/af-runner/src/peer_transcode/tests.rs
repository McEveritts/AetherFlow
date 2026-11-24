use super::*;
use crate::package_executor::PackageExecutorError;
use crate::sandbox_ops::{
    apply_sandbox_dropins_in_dir, is_exempt_sandbox_unit, render_systemd_sandbox_dropin,
};
use crate::{
    build_runner_router, dispatch_peer_transcode, resolve_af_transcode_binary,
    serve_runner_connections, ENV_TEST_MUTEX,
};
use std::collections::VecDeque;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::Mutex;

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedCall {
    program: String,
    args: Vec<String>,
}

type RuleHandler =
    Box<dyn Fn(&str, &[String]) -> Result<CommandOutput, PackageExecutorError> + Send + Sync>;

struct MockCommandRunner {
    calls: Mutex<Vec<RecordedCall>>,
    rules: Mutex<VecDeque<RuleHandler>>,
    default_active_worker: Mutex<bool>,
}

impl MockCommandRunner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            rules: Mutex::new(VecDeque::new()),
            default_active_worker: Mutex::new(false),
        })
    }

    fn set_worker_active(&self, active: bool) {
        *self.default_active_worker.lock().unwrap() = active;
    }

    fn push_rule<F>(&self, f: F)
    where
        F: Fn(&str, &[String]) -> Result<CommandOutput, PackageExecutorError>
            + Send
            + Sync
            + 'static,
    {
        self.rules.lock().unwrap().push_back(Box::new(f));
    }

    fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().unwrap().clone()
    }

    fn clear_calls(&self) {
        self.calls.lock().unwrap().clear();
    }
}

impl CommandRunner for MockCommandRunner {
    fn run_command<'a>(
        &'a self,
        program: &'a str,
        args: &'a [String],
        _env_vars: &'a [(String, String)],
        _cancel: &'a CancellationToken,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<CommandOutput, PackageExecutorError>>
                + Send
                + 'a,
        >,
    > {
        let program_owned = program.to_string();
        let args_owned = args.to_vec();
        Box::pin(async move {
            self.calls.lock().unwrap().push(RecordedCall {
                program: program_owned.clone(),
                args: args_owned.clone(),
            });
            let rule = self.rules.lock().unwrap().pop_front();
            if let Some(handler) = rule {
                return handler(&program_owned, &args_owned);
            }
            if program_owned == "systemctl"
                && args_owned
                    == vec![
                        "is-active".to_string(),
                        PEER_TRANSCODE_WORKER_UNIT.to_string(),
                    ]
            {
                let active = *self.default_active_worker.lock().unwrap();
                return Ok(CommandOutput {
                    exit_code: if active { 0 } else { 3 },
                    stdout: if active {
                        "active\n".to_string()
                    } else {
                        "inactive\n".to_string()
                    },
                    stderr: String::new(),
                });
            }
            if program_owned == "systemctl"
                && args_owned
                    == vec![
                        "enable".to_string(),
                        "--now".to_string(),
                        PEER_TRANSCODE_WORKER_UNIT.to_string(),
                    ]
            {
                *self.default_active_worker.lock().unwrap() = true;
            }
            if program_owned == "systemctl"
                && args_owned
                    == vec![
                        "disable".to_string(),
                        "--now".to_string(),
                        PEER_TRANSCODE_WORKER_UNIT.to_string(),
                    ]
            {
                *self.default_active_worker.lock().unwrap() = false;
            }
            Ok(CommandOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        })
    }
}

struct TranscodeFixture {
    root: PathBuf,
    source_bin: PathBuf,
    real_ffprobe: PathBuf,
    runner: Arc<MockCommandRunner>,
}

impl TranscodeFixture {
    fn new() -> Self {
        let root = env::temp_dir().join(format!("af-peer-transcode-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("create fixture root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("chmod root");

        let bin_dir = root.join("opt/AetherFlow/current/bin");
        fs::create_dir_all(&bin_dir).expect("create release bin dir");
        let source_bin = bin_dir.join("af-transcode");
        fs::write(&source_bin, b"#!/bin/sh\necho af-transcode-fixture\n")
            .expect("write source bin");
        fs::set_permissions(&source_bin, fs::Permissions::from_mode(0o755))
            .expect("chmod source bin");

        let real_ffprobe_dir = root.join("usr/lib/jellyfin-ffmpeg");
        fs::create_dir_all(&real_ffprobe_dir).expect("create real ffprobe dir");
        let real_ffprobe = real_ffprobe_dir.join("ffprobe");
        fs::write(&real_ffprobe, b"#!/bin/sh\necho ffprobe-fixture\n").expect("write ffprobe");
        fs::set_permissions(&real_ffprobe, fs::Permissions::from_mode(0o755))
            .expect("chmod ffprobe");

        Self {
            root,
            source_bin,
            real_ffprobe,
            runner: MockCommandRunner::new(),
        }
    }

    fn config(&self) -> PeerTranscodePathsConfig {
        let mut cfg = PeerTranscodePathsConfig::isolated(&self.root);
        cfg.transcode_bin_override = Some(self.source_bin.clone());
        cfg.real_ffprobe_override = Some(self.real_ffprobe.clone());
        cfg.jellyfin_identity_override = Some((108, 114));
        cfg.aetherflow_identity_override = Some((998, 998));
        cfg
    }

    fn manager(&self) -> PeerTranscodeManager {
        PeerTranscodeManager::new(self.config(), self.runner.clone()).expect("build manager")
    }

    fn create_dir(&self, canonical_abs: &str) -> PathBuf {
        let full = self.root.join(canonical_abs.trim_start_matches('/'));
        fs::create_dir_all(&full).expect("create dir");
        full
    }

    fn write_encoding_xml(&self, xml: &str) {
        let xml_path = self
            .root
            .join(DEFAULT_JELLYFIN_ENCODING_XML.trim_start_matches('/'));
        fs::create_dir_all(xml_path.parent().unwrap()).expect("create jellyfin config dir");
        fs::write(&xml_path, xml).expect("write encoding.xml");
    }
}

impl Drop for TranscodeFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn serde_shapes_match_p9_contract() {
    // Request round-trips & action tags
    let requests = vec![
        (
            PeerTranscodeRequest::InspectJellyfinPaths,
            r#"{"action":"inspect_jellyfin_paths"}"#,
        ),
        (
            PeerTranscodeRequest::EnsureDispatcherDir,
            r#"{"action":"ensure_dispatcher_dir"}"#,
        ),
        (
            PeerTranscodeRequest::InstallShim,
            r#"{"action":"install_shim"}"#,
        ),
        (
            PeerTranscodeRequest::EnableJellyfin,
            r#"{"action":"enable_jellyfin"}"#,
        ),
        (
            PeerTranscodeRequest::DisableJellyfin,
            r#"{"action":"disable_jellyfin"}"#,
        ),
        (
            PeerTranscodeRequest::InstallWorkerUnit,
            r#"{"action":"install_worker_unit"}"#,
        ),
        (
            PeerTranscodeRequest::RemoveWorkerUnit,
            r#"{"action":"remove_worker_unit"}"#,
        ),
        (
            PeerTranscodeRequest::ExportTranscodeDirs {
                link_id: "media-2".to_string(),
                tunnel_ip: "10.231.0.2".to_string(),
                uid: 108,
                gid: 114,
                paths: vec![DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string()],
            },
            r#"{"action":"export_transcode_dirs","link_id":"media-2","tunnel_ip":"10.231.0.2","uid":108,"gid":114,"paths":["/var/cache/jellyfin/transcodes"]}"#,
        ),
        (
            PeerTranscodeRequest::RemoveTranscodeExports {
                link_id: "media-2".to_string(),
            },
            r#"{"action":"remove_transcode_exports","link_id":"media-2"}"#,
        ),
        (
            PeerTranscodeRequest::MountTranscodeDirs {
                link_id: "media-2".to_string(),
                tunnel_ip: "10.231.0.2".to_string(),
                paths: vec![DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string()],
            },
            r#"{"action":"mount_transcode_dirs","link_id":"media-2","tunnel_ip":"10.231.0.2","paths":["/var/cache/jellyfin/transcodes"]}"#,
        ),
        (
            PeerTranscodeRequest::RemoveTranscodeMounts {
                link_id: "media-2".to_string(),
                paths: vec![DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string()],
            },
            r#"{"action":"remove_transcode_mounts","link_id":"media-2","paths":["/var/cache/jellyfin/transcodes"]}"#,
        ),
        (
            PeerTranscodeRequest::BindMedia {
                from: "/srv/media/movies".to_string(),
                to: "/mnt/af-peers/media-2/movies".to_string(),
                writable: false,
            },
            r#"{"action":"bind_media","from":"/srv/media/movies","to":"/mnt/af-peers/media-2/movies","writable":false}"#,
        ),
        (
            PeerTranscodeRequest::RemoveBindMedia {
                to: "/mnt/af-peers/media-2/movies".to_string(),
            },
            r#"{"action":"remove_bind_media","to":"/mnt/af-peers/media-2/movies"}"#,
        ),
    ];

    for (req, expected_json) in requests {
        let encoded = serde_json::to_string(&req).expect("serialize request");
        assert_eq!(encoded, expected_json);
        let decoded: PeerTranscodeRequest =
            serde_json::from_str(&encoded).expect("deserialize request");
        assert_eq!(decoded, req);
    }

    // BindMedia defaults writable to false and denies unknown fields.
    let bind_default: PeerTranscodeRequest =
        serde_json::from_str(r#"{"action":"bind_media","from":"/srv/a","to":"/mnt/af-peers/l/e"}"#)
            .expect("default writable");
    assert_eq!(
        bind_default,
        PeerTranscodeRequest::BindMedia {
            from: "/srv/a".to_string(),
            to: "/mnt/af-peers/l/e".to_string(),
            writable: false,
        }
    );
    assert!(serde_json::from_str::<PeerTranscodeRequest>(
        r#"{"action":"bind_media","from":"/srv/a","to":"/mnt/af-peers/l/e","unexpected":true}"#
    )
    .is_err());
    assert!(serde_json::from_str::<PeerTranscodeRequest>(
        r#"{"action":"remove_transcode_exports","link_id":"media-2","extra":1}"#
    )
    .is_err());
    assert!(
        serde_json::from_str::<PeerTranscodeRequest>(r#"{"action":"unknown_action"}"#).is_err()
    );

    // Response tagged shapes
    let mut_resp = PeerTranscodeResponse::Mutation(TranscodeMutationReport {
        changed: true,
        detail: "ok".to_string(),
        units: Vec::new(),
        paths: vec!["/a".to_string()],
        api_restart_required: false,
    });
    let mut_json = serde_json::to_string(&mut_resp).unwrap();
    assert!(mut_json.contains(r#""kind":"mutation""#));
    assert!(!mut_json.contains(r#""units""#));
    assert!(!mut_json.contains(r#""api_restart_required""#));
    assert_eq!(
        decode_peer_transcode_response(&PeerTranscodeRequest::InstallShim, &mut_json).unwrap(),
        mut_resp
    );
    assert!(
        decode_peer_transcode_response(&PeerTranscodeRequest::InspectJellyfinPaths, &mut_json)
            .is_err()
    );

    let cleanup_resp = PeerTranscodeResponse::ParityFileCleanup(ParityFileCleanupReport {
        existed: true,
        size_bytes: 128,
        removed: true,
    });
    let cleanup_json = serde_json::to_string(&cleanup_resp).unwrap();
    assert!(cleanup_json.contains(r#""kind":"parity_file_cleanup""#));
    let cleanup_req = PeerTranscodeRequest::CleanupParityFile {
        dir: DEFAULT_JELLYFIN_TRANSCODE_DIR.to_string(),
        file_name: ".af-parity-0123456789abcdef0123456789abcdef.ts".to_string(),
    };
    assert_eq!(
        decode_peer_transcode_response(&cleanup_req, &cleanup_json).unwrap(),
        cleanup_resp
    );
    assert!(
        decode_peer_transcode_response(&PeerTranscodeRequest::InstallShim, &cleanup_json).is_err()
    );
}

#[test]
fn encoding_xml_parser_extracts_valid_paths_and_rejects_traversal() {
    assert_eq!(
        parse_jellyfin_transcoding_temp_path(
            r#"<?xml version="1.0"?><EncodingOptions><TranscodingTempPath>/srv/jf/transcodes/</TranscodingTempPath></EncodingOptions>"#
        )
        .unwrap(),
        Some("/srv/jf/transcodes".to_string())
    );
    assert_eq!(
        parse_jellyfin_transcoding_temp_path(
            r#"<EncodingOptions><TranscodingTempPath /></EncodingOptions>"#
        )
        .unwrap(),
        None
    );
    assert_eq!(
        parse_jellyfin_transcoding_temp_path(
            r#"<EncodingOptions><TranscodingTempPath>   </TranscodingTempPath></EncodingOptions>"#
        )
        .unwrap(),
        None
    );
    assert_eq!(
        parse_jellyfin_transcoding_temp_path(
            r#"<EncodingOptions><!-- <TranscodingTempPath>/etc/shadow</TranscodingTempPath> --><TranscodingTempPath>/var/cache/jellyfin/custom</TranscodingTempPath></EncodingOptions>"#
        )
        .unwrap(),
        Some("/var/cache/jellyfin/custom".to_string())
    );
    assert_eq!(
        parse_jellyfin_transcoding_temp_path(r#"<EncodingOptions></EncodingOptions>"#).unwrap(),
        None
    );

    // Traversal, relative paths, and forbidden system paths must be rejected.
    for bad_xml in [
        r#"<EncodingOptions><TranscodingTempPath>/var/cache/jellyfin/../etc</TranscodingTempPath></EncodingOptions>"#,
        r#"<EncodingOptions><TranscodingTempPath>relative/transcodes</TranscodingTempPath></EncodingOptions>"#,
        r#"<EncodingOptions><TranscodingTempPath>/etc/jellyfin</TranscodingTempPath></EncodingOptions>"#,
        r#"<EncodingOptions><TranscodingTempPath>/run/aetherflow</TranscodingTempPath></EncodingOptions>"#,
        r#"<EncodingOptions><TranscodingTempPath>/var/cache/jellyfin/transcodes"#,
    ] {
        assert!(
            parse_jellyfin_transcoding_temp_path(bad_xml)
                .unwrap_err()
                .is_invalid_input(),
            "expected invalid input for {bad_xml}"
        );
    }
}

#[tokio::test]
async fn resolve_af_transcode_binary_verifies_regular_executable_non_world_writable() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let fx = TranscodeFixture::new();

    // Valid regular executable binary via AETHERFLOW_TRANSCODE_BIN
    env::set_var("AETHERFLOW_TRANSCODE_BIN", &fx.source_bin);
    assert_eq!(resolve_af_transcode_binary(), Some(fx.source_bin.clone()));

    // Reject symlink
    let sym = fx.root.join("sym-transcode");
    symlink(&fx.source_bin, &sym).unwrap();
    assert!(validate_transcode_binary_file(&sym)
        .unwrap_err()
        .is_invalid_input());
    env::set_var("AETHERFLOW_TRANSCODE_BIN", &sym);
    assert_ne!(
        resolve_af_transcode_binary().as_deref(),
        Some(sym.as_path())
    );

    // Reject non-executable file
    let non_exec = fx.root.join("non-exec-transcode");
    fs::write(&non_exec, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&non_exec, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(validate_transcode_binary_file(&non_exec)
        .unwrap_err()
        .is_invalid_input());

    // Reject world-writable executable file
    let world_writable = fx.root.join("ww-transcode");
    fs::write(&world_writable, b"#!/bin/sh\n").unwrap();
    fs::set_permissions(&world_writable, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(validate_transcode_binary_file(&world_writable)
        .unwrap_err()
        .is_invalid_input());

    env::remove_var("AETHERFLOW_TRANSCODE_BIN");
}

#[tokio::test]
async fn dormant_inspection_performs_zero_mutations_and_reads_encoding_xml() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();

    // Default fallback when encoding.xml is absent; zero directories or lock files created.
    let paths = mgr.inspect_jellyfin_paths().await.unwrap();
    assert_eq!(paths.transcoding_temp_path, DEFAULT_JELLYFIN_TRANSCODE_DIR);
    assert_eq!(paths.tmp_dir, DEFAULT_JELLYFIN_TMP_DIR);
    assert_eq!(paths.cache_dir, DEFAULT_JELLYFIN_CACHE_DIR);
    assert_eq!(paths.shim_path, DEFAULT_TRANSCODE_SHIM_PATH);
    assert!(!paths.shim_installed);
    assert!(!paths.dropin_enabled);
    assert!(!paths.worker_unit_installed);
    assert!(!paths.worker_unit_active);
    assert_eq!(paths.jellyfin_uid, Some(108));
    assert_eq!(paths.jellyfin_gid, Some(114));
    assert!(!fx.root.join("etc/aetherflow/peers").exists());
    assert!(fx.runner.calls().is_empty());

    // Custom TranscodingTempPath from encoding.xml
    fx.write_encoding_xml(
        r#"<?xml version="1.0"?><EncodingOptions><TranscodingTempPath>/srv/jellyfin-transcodes</TranscodingTempPath></EncodingOptions>"#,
    );
    let paths2 = mgr.inspect_jellyfin_paths().await.unwrap();
    assert_eq!(paths2.transcoding_temp_path, "/srv/jellyfin-transcodes");
}

#[tokio::test]
async fn install_shim_copies_atomically_creates_ffprobe_symlink_and_refuses_symlinks() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();

    let report = mgr.install_shim().await.unwrap();
    assert!(report.changed);
    let installed_ffmpeg = fx.root.join("usr/lib/aetherflow/transcode/ffmpeg");
    let installed_ffprobe = fx.root.join("usr/lib/aetherflow/transcode/ffprobe");
    assert_eq!(
        fs::read(&installed_ffmpeg).unwrap(),
        fs::read(&fx.source_bin).unwrap()
    );
    assert_eq!(
        fs::symlink_metadata(&installed_ffmpeg)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    assert!(fs::symlink_metadata(&installed_ffprobe)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_link(&installed_ffprobe).unwrap(), fx.real_ffprobe);

    // Idempotent second call reports changed=false.
    let second = mgr.install_shim().await.unwrap();
    assert!(!second.changed);

    // Inspect reports shim_installed = true.
    let inspected = mgr.inspect_jellyfin_paths().await.unwrap();
    assert!(inspected.shim_installed);

    // Refuses to replace a symlink at `<shim_dir>/ffmpeg`.
    fs::remove_file(&installed_ffmpeg).unwrap();
    symlink(&fx.real_ffprobe, &installed_ffmpeg).unwrap();
    let err = mgr.install_shim().await.unwrap_err();
    assert!(err.is_conflict(), "expected Conflict, got {err:?}");
    assert!(fs::symlink_metadata(&installed_ffmpeg)
        .unwrap()
        .file_type()
        .is_symlink());

    // Refuses to overwrite a non-symlink unmanaged file at `<shim_dir>/ffprobe`.
    fs::remove_file(&installed_ffmpeg).unwrap();
    fs::remove_file(&installed_ffprobe).unwrap();
    fs::write(&installed_ffprobe, b"unmanaged").unwrap();
    let err = mgr.install_shim().await.unwrap_err();
    assert!(
        err.is_unmanaged_file(),
        "expected UnmanagedFile, got {err:?}"
    );
    assert_eq!(fs::read(&installed_ffprobe).unwrap(), b"unmanaged");
}

#[tokio::test]
async fn ensure_dispatcher_dir_creates_0750_dir_tmpfiles_and_api_dropin_without_aetherflow_group() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();

    let report = mgr.ensure_dispatcher_dir().await.unwrap();
    assert!(report.changed);

    let run_dir = fx.root.join("run/aetherflow-transcode");
    assert!(run_dir.is_dir());
    assert_eq!(
        fs::metadata(&run_dir).unwrap().permissions().mode() & 0o777,
        0o750
    );

    let tmpfiles = fs::read_to_string(fx.root.join("etc/tmpfiles.d/aetherflow-transcode.conf"))
        .expect("read tmpfiles.d conf");
    assert!(tmpfiles.starts_with(PEER_MANAGED_HEADER));
    assert!(tmpfiles.contains("d /run/aetherflow-transcode 0750 aetherflow jellyfin -"));

    let api_dropin = fs::read_to_string(
        fx.root
            .join("etc/systemd/system/aetherflow-api.service.d/20-aetherflow-transcode.conf"),
    )
    .expect("read api drop-in");
    assert!(api_dropin.starts_with(PEER_MANAGED_HEADER));
    assert!(api_dropin.contains("SupplementaryGroups=jellyfin\n"));
    assert!(api_dropin
        .contains("ReadWritePaths=-/run/aetherflow-transcode -/run/aetherflow-transcode-worker\n"));
    assert!(!api_dropin.contains("SupplementaryGroups=aetherflow"));
    assert!(!api_dropin.contains("aetherflow "));

    assert!(fx
        .runner
        .calls()
        .iter()
        .any(|c| c.program == "systemctl" && c.args == vec!["daemon-reload".to_string()]));

    // Idempotent second call
    fx.runner.clear_calls();
    let second = mgr.ensure_dispatcher_dir().await.unwrap();
    assert!(!second.changed);
    assert!(fx.runner.calls().is_empty());

    // Refuses to overwrite unmanaged tmpfiles.d file
    fs::write(
        fx.root.join("etc/tmpfiles.d/aetherflow-transcode.conf"),
        "d /run/aetherflow-transcode 0755 root root -\n",
    )
    .unwrap();
    let err = mgr.ensure_dispatcher_dir().await.unwrap_err();
    assert!(
        err.is_unmanaged_file(),
        "expected UnmanagedFile, got {err:?}"
    );
}

#[tokio::test]
async fn enable_and_disable_jellyfin_preserves_sandbox_dropins_and_protects_unmanaged_files() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();

    // Pre-create Jellyfin sandbox drop-ins that MUST NEVER be touched.
    let dropin_dir = fx.create_dir("/etc/systemd/system/jellyfin.service.d");
    let sandbox_10 = dropin_dir.join("10-aetherflow-sandbox.conf");
    let sandbox_legacy = dropin_dir.join("aetherflow-sandbox.conf");
    let sandbox_10_content = "[Service]\nNoNewPrivileges=yes\nProtectSystem=strict\n";
    let sandbox_legacy_content = "[Service]\nPrivateTmp=yes\n";
    fs::write(&sandbox_10, sandbox_10_content).unwrap();
    fs::write(&sandbox_legacy, sandbox_legacy_content).unwrap();

    // Enable Jellyfin transcoding
    let report = mgr.enable_jellyfin().await.unwrap();
    assert!(report.changed);

    let tmp_dir = fx.root.join("var/cache/jellyfin/af-tmp");
    assert!(tmp_dir.is_dir());
    assert_eq!(
        fs::metadata(&tmp_dir).unwrap().permissions().mode() & 0o777,
        0o750
    );

    let transcode_dropin = dropin_dir.join(JELLYFIN_TRANSCODE_DROPIN_NAME);
    let dropin_text = fs::read_to_string(&transcode_dropin).unwrap();
    assert!(dropin_text.starts_with(PEER_MANAGED_HEADER));
    assert!(
        dropin_text.contains("Environment=JELLYFIN_FFMPEG=/usr/lib/aetherflow/transcode/ffmpeg\n")
    );
    assert!(dropin_text.contains("Environment=TMPDIR=/var/cache/jellyfin/af-tmp\n"));

    // Sandbox drop-ins remain byte-for-byte intact.
    assert_eq!(fs::read_to_string(&sandbox_10).unwrap(), sandbox_10_content);
    assert_eq!(
        fs::read_to_string(&sandbox_legacy).unwrap(),
        sandbox_legacy_content
    );

    let calls = fx.runner.calls();
    assert_eq!(
        calls,
        vec![
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["daemon-reload".to_string()],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["restart".to_string(), "jellyfin.service".to_string()],
            },
        ]
    );

    // Inspect reports dropin_enabled = true.
    assert!(mgr.inspect_jellyfin_paths().await.unwrap().dropin_enabled);

    // Disable removes managed drop-in, reloads, restarts, and preserves sandbox drop-ins.
    fx.runner.clear_calls();
    let disabled = mgr.disable_jellyfin().await.unwrap();
    assert!(disabled.changed);
    assert!(!transcode_dropin.exists());
    assert_eq!(fs::read_to_string(&sandbox_10).unwrap(), sandbox_10_content);
    assert_eq!(
        fs::read_to_string(&sandbox_legacy).unwrap(),
        sandbox_legacy_content
    );
    assert_eq!(
        fx.runner.calls(),
        vec![
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["daemon-reload".to_string()],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["restart".to_string(), "jellyfin.service".to_string()],
            },
        ]
    );

    // Idempotent second disable does nothing.
    fx.runner.clear_calls();
    assert!(!mgr.disable_jellyfin().await.unwrap().changed);
    assert!(fx.runner.calls().is_empty());

    // Unmanaged 20-aetherflow-transcode.conf is refused on both enable and disable.
    fs::write(
        &transcode_dropin,
        "[Service]\nEnvironment=JELLYFIN_FFMPEG=/custom/ffmpeg\n",
    )
    .unwrap();
    assert!(mgr.enable_jellyfin().await.unwrap_err().is_unmanaged_file());
    assert!(mgr
        .disable_jellyfin()
        .await
        .unwrap_err()
        .is_unmanaged_file());
    assert!(transcode_dropin.exists());
}

#[tokio::test]
async fn install_and_remove_worker_unit_verifies_security_policy_and_api_dropin() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();

    let report = mgr.install_worker_unit().await.unwrap();
    assert!(report.changed);

    let unit_path = fx
        .root
        .join("etc/systemd/system/af-transcode-worker.service");
    let unit_text = fs::read_to_string(&unit_path).unwrap();
    assert!(unit_text.starts_with(PEER_MANAGED_HEADER));
    assert!(unit_text.contains("User=jellyfin\n"));
    assert!(unit_text.contains("Group=jellyfin\n"));
    assert!(unit_text.contains("SupplementaryGroups=render video\n"));
    assert!(unit_text.contains("RuntimeDirectory=aetherflow-transcode-worker\n"));
    assert!(unit_text.contains("RuntimeDirectoryMode=0750\n"));
    assert!(unit_text.contains(
        "Environment=AF_TRANSCODE_WORKER_SOCK=/run/aetherflow-transcode-worker/worker.sock\n"
    ));
    assert!(unit_text.contains("Environment=AF_TRANSCODE_WORKER_SOCKET_MODE=0660\n"));
    assert!(unit_text.contains(&format!("ExecStart={} worker\n", fx.source_bin.display())));
    assert!(unit_text.contains("Restart=on-failure\n"));
    // INVARIANT: worker service NEVER runs with group `aetherflow`.
    assert!(!unit_text.contains("Group=aetherflow"));
    assert!(!unit_text.contains("SupplementaryGroups=aetherflow"));
    assert!(!unit_text.contains("aetherflow\n"));

    // API drop-in is also provisioned.
    let api_dropin = fs::read_to_string(
        fx.root
            .join("etc/systemd/system/aetherflow-api.service.d/20-aetherflow-transcode.conf"),
    )
    .unwrap();
    assert!(api_dropin.contains("SupplementaryGroups=jellyfin\n"));
    assert!(api_dropin
        .contains("ReadWritePaths=-/run/aetherflow-transcode -/run/aetherflow-transcode-worker\n"));

    let calls = fx.runner.calls();
    assert_eq!(
        calls,
        vec![
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["daemon-reload".to_string()],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec![
                    "enable".to_string(),
                    "--now".to_string(),
                    "af-transcode-worker.service".to_string(),
                ],
            },
        ]
    );

    // Inspect reports worker_unit_installed and worker_unit_active.
    let inspected = mgr.inspect_jellyfin_paths().await.unwrap();
    assert!(inspected.worker_unit_installed);
    assert!(inspected.worker_unit_active);

    // When systemd reports inactive, worker_unit_installed stays true and worker_unit_active is false.
    fx.runner.set_worker_active(false);
    let inspected_inactive = mgr.inspect_jellyfin_paths().await.unwrap();
    assert!(inspected_inactive.worker_unit_installed);
    assert!(!inspected_inactive.worker_unit_active);
    fx.runner.set_worker_active(true);

    // RemoveWorkerUnit disables, removes unit, and reloads daemon.
    fx.runner.clear_calls();
    let removed = mgr.remove_worker_unit().await.unwrap();
    assert!(removed.changed);
    assert!(!unit_path.exists());
    assert_eq!(
        fx.runner.calls(),
        vec![
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec![
                    "disable".to_string(),
                    "--now".to_string(),
                    "af-transcode-worker.service".to_string(),
                ],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["daemon-reload".to_string()],
            },
        ]
    );

    // Refuses to remove an unmanaged af-transcode-worker.service
    fs::write(&unit_path, "[Unit]\nDescription=User Custom Worker\n").unwrap();
    assert!(mgr
        .remove_worker_unit()
        .await
        .unwrap_err()
        .is_unmanaged_file());
    assert!(unit_path.exists());
}

#[tokio::test]
async fn transcode_exports_are_isolated_from_media_exports_and_reject_root_uid_gid() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();

    fx.create_dir("/var/cache/jellyfin/transcodes");
    fx.create_dir("/var/cache/jellyfin/af-tmp");
    let exports_dir = fx.create_dir("/etc/exports.d");
    let media_exports = exports_dir.join("aetherflow-peer-media-2.exports");
    let media_content = format!(
        "{PEER_MANAGED_HEADER}\n/srv/media/movies 10.231.0.2(ro,root_squash,secure,no_subtree_check)\n"
    );
    fs::write(&media_exports, &media_content).unwrap();

    // Reject uid == 0 or gid == 0
    assert!(mgr
        .export_transcode_dirs(
            "media-2",
            "10.231.0.2",
            0,
            114,
            &["/var/cache/jellyfin/transcodes".to_string()],
        )
        .await
        .unwrap_err()
        .is_invalid_input());
    assert!(mgr
        .export_transcode_dirs(
            "media-2",
            "10.231.0.2",
            108,
            0,
            &["/var/cache/jellyfin/transcodes".to_string()],
        )
        .await
        .unwrap_err()
        .is_invalid_input());

    // Reject tunnel_ip outside configured CIDR
    assert!(mgr
        .export_transcode_dirs(
            "media-2",
            "192.168.1.50",
            108,
            114,
            &["/var/cache/jellyfin/transcodes".to_string()],
        )
        .await
        .unwrap_err()
        .is_invalid_input());

    // Reject forbidden paths and traversal
    for bad_path in [
        "/etc/jellyfin",
        "/var/cache/jellyfin/../etc",
        "/mnt/af-peers/x/y",
        "/",
    ] {
        assert!(
            mgr.export_transcode_dirs("media-2", "10.231.0.2", 108, 114, &[bad_path.to_string()])
                .await
                .unwrap_err()
                .is_invalid_input(),
            "expected InvalidInput for {bad_path}"
        );
    }

    // Valid export writes separate `-transcode.exports` file
    let report = mgr
        .export_transcode_dirs(
            "media-2",
            "10.231.0.2",
            108,
            114,
            &[
                "/var/cache/jellyfin/transcodes".to_string(),
                "/var/cache/jellyfin/af-tmp".to_string(),
            ],
        )
        .await
        .unwrap();
    assert!(report.changed);

    let transcode_exports = exports_dir.join("aetherflow-peer-media-2-transcode.exports");
    let text = fs::read_to_string(&transcode_exports).unwrap();
    assert!(text.starts_with(PEER_MANAGED_HEADER));
    assert!(text.contains(
        "/var/cache/jellyfin/af-tmp 10.231.0.2(rw,all_squash,anonuid=108,anongid=114,secure,no_subtree_check)\n"
    ));
    assert!(text.contains(
        "/var/cache/jellyfin/transcodes 10.231.0.2(rw,all_squash,anonuid=108,anongid=114,secure,no_subtree_check)\n"
    ));
    assert_eq!(fs::read_to_string(&media_exports).unwrap(), media_content);
    assert_eq!(
        fx.runner.calls(),
        vec![RecordedCall {
            program: "exportfs".to_string(),
            args: vec!["-ra".to_string()],
        }]
    );

    // Removing transcode exports leaves P7 media exports completely untouched!
    fx.runner.clear_calls();
    let removed = mgr.remove_transcode_exports("media-2").await.unwrap();
    assert!(removed.changed);
    assert!(!transcode_exports.exists());
    assert_eq!(fs::read_to_string(&media_exports).unwrap(), media_content);
    assert_eq!(
        fx.runner.calls(),
        vec![RecordedCall {
            program: "exportfs".to_string(),
            args: vec!["-ra".to_string()],
        }]
    );

    // Rollback on exportfs failure
    fx.runner.push_rule(|prog, _| {
        assert_eq!(prog, "exportfs");
        Ok(CommandOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "exportfs simulated failure".to_string(),
        })
    });
    let err = mgr
        .export_transcode_dirs(
            "media-2",
            "10.231.0.2",
            108,
            114,
            &["/var/cache/jellyfin/transcodes".to_string()],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, PeerTranscodeError::Runtime(_)));
    assert!(
        !transcode_exports.exists(),
        "failed exportfs must roll back new file"
    );
}

#[tokio::test]
async fn mount_and_remove_transcode_dirs_orders_nested_mounts_and_protects_unmanaged_units() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();

    let paths = vec![
        "/var/cache/jellyfin/transcodes".to_string(),
        "/var/cache/jellyfin".to_string(),
        "/var/cache/jellyfin/af-tmp".to_string(),
    ];

    let report = mgr
        .mount_transcode_dirs("seedbox-1", "10.231.0.1", &paths)
        .await
        .unwrap();
    assert!(report.changed);

    // Parent path must be mounted before child paths.
    let expected_units = vec![
        "var-cache-jellyfin.mount".to_string(),
        r"var-cache-jellyfin-af\x2dtmp.mount".to_string(),
        "var-cache-jellyfin-transcodes.mount".to_string(),
    ];
    assert_eq!(report.units, expected_units);

    let af_tmp_unit = fs::read_to_string(
        fx.root
            .join("etc/systemd/system")
            .join(r"var-cache-jellyfin-af\x2dtmp.mount"),
    )
    .unwrap();
    assert!(af_tmp_unit.starts_with(PEER_MANAGED_HEADER));
    assert!(af_tmp_unit.contains("Requires=wg-quick@afpeer0.service\n"));
    assert!(af_tmp_unit.contains("After=wg-quick@afpeer0.service\n"));
    assert!(af_tmp_unit.contains("What=10.231.0.1:/var/cache/jellyfin/af-tmp\n"));
    assert!(af_tmp_unit.contains("Where=/var/cache/jellyfin/af-tmp\n"));
    assert!(af_tmp_unit.contains("Type=nfs4\n"));
    assert!(
        af_tmp_unit.contains("Options=vers=4.2,soft,timeo=100,retrans=2,rw,_netdev,nosuid,nodev")
    );

    let mount_calls = fx.runner.calls();
    assert_eq!(
        mount_calls,
        vec![
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["daemon-reload".to_string()],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["start".to_string(), "var-cache-jellyfin.mount".to_string()],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec![
                    "start".to_string(),
                    r"var-cache-jellyfin-af\x2dtmp.mount".to_string(),
                ],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec![
                    "start".to_string(),
                    "var-cache-jellyfin-transcodes.mount".to_string(),
                ],
            },
        ]
    );

    // Unmount must stop child units BEFORE parent unit.
    fx.runner.clear_calls();
    let removed = mgr
        .remove_transcode_mounts("seedbox-1", &paths)
        .await
        .unwrap();
    assert!(removed.changed);
    assert_eq!(
        fx.runner.calls(),
        vec![
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec![
                    "stop".to_string(),
                    "var-cache-jellyfin-transcodes.mount".to_string(),
                ],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec![
                    "stop".to_string(),
                    r"var-cache-jellyfin-af\x2dtmp.mount".to_string(),
                ],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["stop".to_string(), "var-cache-jellyfin.mount".to_string()],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["daemon-reload".to_string()],
            },
        ]
    );

    // Unmanaged existing unit is refused on both mount and remove.
    let unmanaged_unit = fx
        .root
        .join("etc/systemd/system/var-cache-jellyfin-transcodes.mount");
    fs::write(&unmanaged_unit, "[Unit]\nDescription=Admin Manual Mount\n").unwrap();
    assert!(mgr
        .mount_transcode_dirs(
            "seedbox-1",
            "10.231.0.1",
            &["/var/cache/jellyfin/transcodes".to_string()],
        )
        .await
        .unwrap_err()
        .is_unmanaged_file());
    assert!(mgr
        .remove_transcode_mounts("seedbox-1", &["/var/cache/jellyfin/transcodes".to_string()],)
        .await
        .unwrap_err()
        .is_unmanaged_file());
    assert!(unmanaged_unit.exists());
}

#[tokio::test]
async fn bind_media_and_remove_bind_media_enforce_validation_and_managed_headers() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();
    fx.create_dir("/srv/media/movies");

    // Reject forbidden paths, traversal, symlink source, and identical paths.
    assert!(mgr
        .bind_media("/etc/ssh", "/mnt/af-peers/media-2/movies", false)
        .await
        .unwrap_err()
        .is_invalid_input());
    assert!(mgr
        .bind_media("/srv/media/movies", "/etc/movies", false)
        .await
        .unwrap_err()
        .is_invalid_input());
    assert!(mgr
        .bind_media("/srv/media/../etc", "/mnt/af-peers/media-2/movies", false)
        .await
        .unwrap_err()
        .is_invalid_input());
    assert!(mgr
        .bind_media("/srv/media/movies", "/srv/media/movies", false)
        .await
        .unwrap_err()
        .is_invalid_input());
    assert!(mgr
        .bind_media("/srv/media/movies", "/mnt/af-peers", false)
        .await
        .unwrap_err()
        .is_invalid_input());

    let sym_src = fx.root.join("srv/media/sym");
    symlink(fx.root.join("srv/media/movies"), &sym_src).unwrap();
    assert!(mgr
        .bind_media("/srv/media/sym", "/mnt/af-peers/media-2/movies", false)
        .await
        .unwrap_err()
        .is_invalid_input());

    // Valid read-only bind mount
    let report = mgr
        .bind_media("/srv/media/movies", "/mnt/af-peers/media-2/movies", false)
        .await
        .unwrap();
    assert!(report.changed);
    let unit_name = r"mnt-af\x2dpeers-media\x2d2-movies.mount";
    assert_eq!(report.units, vec![unit_name.to_string()]);

    let unit_disk = fx.root.join("etc/systemd/system").join(unit_name);
    let unit_text = fs::read_to_string(&unit_disk).unwrap();
    assert!(unit_text.starts_with(PEER_MANAGED_HEADER));
    assert!(unit_text.contains("What=/srv/media/movies\n"));
    assert!(unit_text.contains("Where=/mnt/af-peers/media-2/movies\n"));
    assert!(unit_text.contains("Type=none\n"));
    assert!(unit_text.contains("Options=bind,ro,nosuid,nodev\n"));

    // Update to read-write
    let rw_report = mgr
        .bind_media("/srv/media/movies", "/mnt/af-peers/media-2/movies", true)
        .await
        .unwrap();
    assert!(rw_report.changed);
    let rw_text = fs::read_to_string(&unit_disk).unwrap();
    assert!(rw_text.contains("Options=bind,rw,nosuid,nodev\n"));

    // RemoveBindMedia stops, removes unit, and reloads systemd
    fx.runner.clear_calls();
    let removed = mgr
        .remove_bind_media("/mnt/af-peers/media-2/movies")
        .await
        .unwrap();
    assert!(removed.changed);
    assert!(!unit_disk.exists());
    assert_eq!(
        fx.runner.calls(),
        vec![
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["stop".to_string(), unit_name.to_string()],
            },
            RecordedCall {
                program: "systemctl".to_string(),
                args: vec!["daemon-reload".to_string()],
            },
        ]
    );

    // Unmanaged bind unit is refused
    fs::write(&unit_disk, "[Mount]\nWhat=/other\n").unwrap();
    assert!(mgr
        .bind_media("/srv/media/movies", "/mnt/af-peers/media-2/movies", false)
        .await
        .unwrap_err()
        .is_unmanaged_file());
    assert!(mgr
        .remove_bind_media("/mnt/af-peers/media-2/movies")
        .await
        .unwrap_err()
        .is_unmanaged_file());
    assert!(unit_disk.exists());
}

#[tokio::test]
async fn unix_socket_roundtrip_dispatches_requests_and_preserves_typed_errors() {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let fx = TranscodeFixture::new();
    let mgr = Arc::new(fx.manager());

    // Use a short socket path under /tmp to stay well below Linux SUN_LEN (108 bytes).
    let sock_dir = PathBuf::from(format!(
        "/tmp/af-pt-{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    ));
    fs::create_dir_all(&sock_dir).expect("create short sock dir");
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o700)).expect("chmod sock dir");
    let sock_path = sock_dir.join("r.sock");
    let listener = tokio::net::UnixListener::bind(&sock_path).expect("bind test runner socket");
    let router = build_runner_router().layer(Extension(mgr));
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let _ = serve_runner_connections(listener, router, async move {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    // Router creation alone must be completely dormant.
    assert!(fx.runner.calls().is_empty());

    let prev_sock = env::var_os("AETHERFLOW_RUNNER_SOCK");
    env::set_var("AETHERFLOW_RUNNER_SOCK", &sock_path);

    let result = std::panic::AssertUnwindSafe(async {
        // Inspect over socket
        let inspected = dispatch_peer_transcode(&PeerTranscodeRequest::InspectJellyfinPaths)
            .await
            .expect("dispatch inspect")
            .into_jellyfin_paths()
            .expect("jellyfin paths variant");
        assert_eq!(
            inspected.transcoding_temp_path,
            DEFAULT_JELLYFIN_TRANSCODE_DIR
        );
        assert_eq!(inspected.jellyfin_uid, Some(108));

        // EnsureDispatcherDir over socket
        let ensured = dispatch_peer_transcode(&PeerTranscodeRequest::EnsureDispatcherDir)
            .await
            .expect("dispatch ensure dispatcher dir")
            .into_mutation()
            .expect("mutation variant");
        assert!(ensured.changed);

        // UnmanagedFile error preserves exact typed variant across Unix socket
        let dropin_dir = fx.create_dir("/etc/systemd/system/jellyfin.service.d");
        fs::write(
            dropin_dir.join(JELLYFIN_TRANSCODE_DROPIN_NAME),
            "[Service]\nEnvironment=JELLYFIN_FFMPEG=/custom\n",
        )
        .unwrap();
        let err = dispatch_peer_transcode(&PeerTranscodeRequest::DisableJellyfin)
            .await
            .unwrap_err();
        assert!(
            err.is_unmanaged_file(),
            "expected UnmanagedFile across socket, got {err:?}"
        );
        assert_eq!(err.error_code(), "unmanaged_file");
        assert_eq!(err.http_status(), StatusCode::CONFLICT);

        // InvalidInput preserves exact typed variant across Unix socket
        let bad_uid = dispatch_peer_transcode(&PeerTranscodeRequest::ExportTranscodeDirs {
            link_id: "media-2".to_string(),
            tunnel_ip: "10.231.0.2".to_string(),
            uid: 0,
            gid: 114,
            paths: vec!["/var/cache/jellyfin/transcodes".to_string()],
        })
        .await
        .unwrap_err();
        assert!(bad_uid.is_invalid_input());
        assert_eq!(bad_uid.http_status(), StatusCode::BAD_REQUEST);
    });
    let outcome = futures::FutureExt::catch_unwind(result).await;

    if let Some(prev) = prev_sock {
        env::set_var("AETHERFLOW_RUNNER_SOCK", prev);
    } else {
        env::remove_var("AETHERFLOW_RUNNER_SOCK");
    }
    let _ = shutdown_tx.send(());
    let _ = server.await;
    let _ = fs::remove_dir_all(&sock_dir);
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

#[tokio::test]
async fn rollbacks_unmanaged_exports_api_dropin_and_lock_contention() {
    let fx = TranscodeFixture::new();
    let mut cfg = fx.config();
    cfg.lock_timeout = Duration::from_millis(120);
    let mgr = PeerTranscodeManager::new(cfg, fx.runner.clone()).unwrap();

    // 1. Unmanaged API drop-in is refused by both EnsureDispatcherDir and InstallWorkerUnit.
    let api_dropin_dir = fx.create_dir("/etc/systemd/system/aetherflow-api.service.d");
    let api_dropin = api_dropin_dir.join(API_TRANSCODE_DROPIN_NAME);
    fs::write(&api_dropin, "[Service]\nSupplementaryGroups=custom\n").unwrap();
    assert!(mgr
        .ensure_dispatcher_dir()
        .await
        .unwrap_err()
        .is_unmanaged_file());
    assert!(mgr
        .install_worker_unit()
        .await
        .unwrap_err()
        .is_unmanaged_file());
    fs::remove_file(&api_dropin).unwrap();

    // 2. Unmanaged transcode exports file is refused on export and remove.
    fx.create_dir("/var/cache/jellyfin/transcodes");
    let exports_dir = fx.create_dir("/etc/exports.d");
    let unmanaged_export = exports_dir.join("aetherflow-peer-media-3-transcode.exports");
    fs::write(&unmanaged_export, "/srv/custom 10.231.0.3(rw)\n").unwrap();
    assert!(mgr
        .export_transcode_dirs(
            "media-3",
            "10.231.0.3",
            108,
            114,
            &["/var/cache/jellyfin/transcodes".to_string()],
        )
        .await
        .unwrap_err()
        .is_unmanaged_file());
    assert!(mgr
        .remove_transcode_exports("media-3")
        .await
        .unwrap_err()
        .is_unmanaged_file());
    fs::remove_file(&unmanaged_export).unwrap();

    // 3. Rollback on EnableJellyfin restart failure restores absence of drop-in.
    fx.runner.push_rule(|_, _| {
        Ok(CommandOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    fx.runner.push_rule(|prog, args| {
        assert_eq!(prog, "systemctl");
        assert_eq!(
            args,
            &["restart".to_string(), "jellyfin.service".to_string()]
        );
        Ok(CommandOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "jellyfin restart failed".to_string(),
        })
    });
    assert!(matches!(
        mgr.enable_jellyfin().await.unwrap_err(),
        PeerTranscodeError::Runtime(_)
    ));
    assert!(!fx
        .root
        .join("etc/systemd/system/jellyfin.service.d/20-aetherflow-transcode.conf")
        .exists());

    // 4. Rollback on InstallWorkerUnit enable failure removes both worker unit and new API drop-in.
    fx.runner.push_rule(|_, _| {
        Ok(CommandOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    fx.runner.push_rule(|_, _| {
        Ok(CommandOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "worker enable failed".to_string(),
        })
    });
    assert!(matches!(
        mgr.install_worker_unit().await.unwrap_err(),
        PeerTranscodeError::Runtime(_)
    ));
    assert!(!fx
        .root
        .join("etc/systemd/system/af-transcode-worker.service")
        .exists());
    assert!(!api_dropin.exists());

    // 5. Rollback on MountTranscodeDirs stops already-started unit and removes newly written units.
    fx.runner.clear_calls();
    fx.runner.push_rule(|_, _| {
        // daemon-reload ok
        Ok(CommandOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    fx.runner.push_rule(|_, _| {
        // start 1st unit ok
        Ok(CommandOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    fx.runner.push_rule(|_, _| {
        // start 2nd unit fails
        Ok(CommandOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "mount failed".to_string(),
        })
    });
    assert!(matches!(
        mgr.mount_transcode_dirs(
            "seedbox-1",
            "10.231.0.1",
            &[
                "/var/cache/jellyfin".to_string(),
                "/var/cache/jellyfin/transcodes".to_string(),
            ],
        )
        .await
        .unwrap_err(),
        PeerTranscodeError::Runtime(_)
    ));
    assert!(fx.runner.calls().iter().any(|c| c.program == "systemctl"
        && c.args == vec!["stop".to_string(), "var-cache-jellyfin.mount".to_string()]));
    assert!(!fx
        .root
        .join("etc/systemd/system/var-cache-jellyfin.mount")
        .exists());
    assert!(!fx
        .root
        .join("etc/systemd/system/var-cache-jellyfin-transcodes.mount")
        .exists());

    // 6. Lock contention returns typed PeerTranscodeError::Busy.
    let (_mem_guard, _file_guard) = mgr.acquire_transcode_write_locks(true).await.unwrap();
    let busy = mgr.ensure_dispatcher_dir().await.unwrap_err();
    assert!(busy.is_busy(), "expected Busy, got {busy:?}");
    assert_eq!(busy.error_code(), "busy");
    assert_eq!(busy.http_status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn execute_dispatches_all_request_variants_and_client_timeouts() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();
    fx.create_dir("/var/cache/jellyfin/transcodes");
    fx.create_dir("/srv/media/movies");

    assert_eq!(
        client_timeout_for_request(&PeerTranscodeRequest::InspectJellyfinPaths),
        TRANSCODE_INSPECT_CLIENT_TIMEOUT
    );
    assert_eq!(
        client_timeout_for_request(&PeerTranscodeRequest::InstallShim),
        TRANSCODE_DEFAULT_CLIENT_TIMEOUT
    );
    assert_eq!(
        client_timeout_for_request(&PeerTranscodeRequest::MountTranscodeDirs {
            link_id: "a".to_string(),
            tunnel_ip: "10.231.0.1".to_string(),
            paths: vec![],
        }),
        TRANSCODE_MOUNT_CLIENT_TIMEOUT
    );

    let all_requests = vec![
        PeerTranscodeRequest::InspectJellyfinPaths,
        PeerTranscodeRequest::EnsureDispatcherDir,
        PeerTranscodeRequest::InstallShim,
        PeerTranscodeRequest::EnableJellyfin,
        PeerTranscodeRequest::DisableJellyfin,
        PeerTranscodeRequest::InstallWorkerUnit,
        PeerTranscodeRequest::RemoveWorkerUnit,
        PeerTranscodeRequest::ExportTranscodeDirs {
            link_id: "media-2".to_string(),
            tunnel_ip: "10.231.0.2".to_string(),
            uid: 108,
            gid: 114,
            paths: vec!["/var/cache/jellyfin/transcodes".to_string()],
        },
        PeerTranscodeRequest::RemoveTranscodeExports {
            link_id: "media-2".to_string(),
        },
        PeerTranscodeRequest::MountTranscodeDirs {
            link_id: "media-2".to_string(),
            tunnel_ip: "10.231.0.2".to_string(),
            paths: vec!["/var/cache/jellyfin/transcodes".to_string()],
        },
        PeerTranscodeRequest::RemoveTranscodeMounts {
            link_id: "media-2".to_string(),
            paths: vec!["/var/cache/jellyfin/transcodes".to_string()],
        },
        PeerTranscodeRequest::BindMedia {
            from: "/srv/media/movies".to_string(),
            to: "/mnt/af-peers/media-2/movies".to_string(),
            writable: false,
        },
        PeerTranscodeRequest::RemoveBindMedia {
            to: "/mnt/af-peers/media-2/movies".to_string(),
        },
        PeerTranscodeRequest::ScheduleApiRestart,
        PeerTranscodeRequest::CleanupParityFile {
            dir: "/var/cache/jellyfin/transcodes".to_string(),
            file_name: ".af-parity-0123456789abcdef0123456789abcdef.ts".to_string(),
        },
    ];

    for req in all_requests {
        let resp = mgr.execute(&req).await.expect("execute request");
        match req {
            PeerTranscodeRequest::InspectJellyfinPaths => {
                assert!(matches!(resp, PeerTranscodeResponse::JellyfinPaths(_)));
            }
            PeerTranscodeRequest::CleanupParityFile { .. } => {
                assert!(matches!(resp, PeerTranscodeResponse::ParityFileCleanup(_)));
            }
            _ => {
                assert!(matches!(resp, PeerTranscodeResponse::Mutation(_)));
            }
        }
    }
}

#[tokio::test]
async fn schedule_api_restart_and_api_restart_required_flag_work_and_cleanup_parity_file_enforces_bounds(
) {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();
    let tc_dir = fx.create_dir("/var/cache/jellyfin/transcodes");
    fx.create_dir("/mnt/af-peers/peer-a/movies");

    // 1. First EnsureDispatcherDir writes 20-aetherflow-transcode.conf -> api_restart_required=true;
    //    second idempotent call -> api_restart_required=false.
    let first = mgr.ensure_dispatcher_dir().await.unwrap();
    assert!(first.api_restart_required);
    let second = mgr.ensure_dispatcher_dir().await.unwrap();
    assert!(!second.api_restart_required);

    // 2. ScheduleApiRestart invokes argv-only systemd-run targeting aetherflow-api.service.
    fx.runner.clear_calls();
    let restart_rep = mgr.schedule_api_restart().await.unwrap();
    assert!(restart_rep.changed);
    let calls = fx.runner.calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].program, "systemd-run");
    assert!(calls[0]
        .args
        .iter()
        .any(|a| a.starts_with("--unit=aetherflow-api-transcode-restart-")));
    assert_eq!(
        &calls[0].args[calls[0].args.len() - 4..],
        &["--", "systemctl", "restart", API_SERVICE_UNIT]
    );

    // 3. CleanupParityFile verifies regular file readability and unlinks it via unlinkat.
    let good_name = ".af-parity-0123456789abcdef0123456789abcdef.ts";
    let parity_path = tc_dir.join(good_name);
    fs::write(&parity_path, b"mpegts-payload").unwrap();
    let rep = mgr
        .cleanup_parity_file("/var/cache/jellyfin/transcodes", good_name)
        .await
        .unwrap();
    assert_eq!(
        rep,
        ParityFileCleanupReport {
            existed: true,
            size_bytes: 14,
            removed: true,
        }
    );
    assert!(!parity_path.exists());

    // Missing file returns existed=false cleanly.
    let absent = mgr
        .cleanup_parity_file("/var/cache/jellyfin/transcodes", good_name)
        .await
        .unwrap();
    assert_eq!(
        absent,
        ParityFileCleanupReport {
            existed: false,
            size_bytes: 0,
            removed: false,
        }
    );

    // Rejects invalid filenames, symlinks, and directories outside configured Jellyfin paths.
    for bad_name in [
        "other.ts",
        ".af-parity-short.ts",
        ".af-parity-0123456789ABCDEF0123456789ABCDEF.ts",
        "../.af-parity-0123456789abcdef0123456789abcdef.ts",
    ] {
        assert!(matches!(
            mgr.cleanup_parity_file("/var/cache/jellyfin/transcodes", bad_name)
                .await,
            Err(PeerTranscodeError::InvalidInput(_))
        ));
    }
    fx.create_dir("/srv/unrelated");
    assert!(matches!(
        mgr.cleanup_parity_file("/srv/unrelated", good_name).await,
        Err(PeerTranscodeError::InvalidInput(_))
    ));
    let target = tc_dir.join("real.txt");
    fs::write(&target, b"keep").unwrap();
    symlink(&target, &parity_path).unwrap();
    assert!(matches!(
        mgr.cleanup_parity_file("/var/cache/jellyfin/transcodes", good_name)
            .await,
        Err(PeerTranscodeError::Conflict(_))
    ));
    assert!(target.exists());

    // 4. BindMedia supports A-holds-media bind-aliasing (`from` under `/mnt/af-peers/<A>/...`).
    let bind_rep = mgr
        .bind_media("/mnt/af-peers/peer-a/movies", "/srv/media/movies", false)
        .await
        .unwrap();
    assert!(bind_rep.changed);

    // 5. XML parser skips preceding prefix-matching tags like `<TranscodingTempPathFoo>`.
    let parsed = parse_jellyfin_transcoding_temp_path(
        r#"<EncodingOptions><TranscodingTempPathFoo>/ignore</TranscodingTempPathFoo><TranscodingTempPath>/srv/jf/transcodes</TranscodingTempPath></EncodingOptions>"#,
    )
    .unwrap();
    assert_eq!(parsed.as_deref(), Some("/srv/jf/transcodes"));
}

#[test]
fn sandbox_policy_exempts_transcode_worker_unit() {
    assert!(is_exempt_sandbox_unit("af-transcode-worker"));
    assert!(is_exempt_sandbox_unit("af-transcode-worker.service"));
    assert!(!is_exempt_sandbox_unit("jellyfin.service"));

    let root = env::temp_dir().join(format!("af-p9-sandbox-{}", uuid::Uuid::new_v4()));
    for unit in ["af-transcode-worker", "af-transcode-worker.service"] {
        assert!(render_systemd_sandbox_dropin("native", unit, &[]).is_empty());
        apply_sandbox_dropins_in_dir(&root, &[unit.to_string()], "native", &[]).unwrap();
    }
    assert!(!root.exists());
}
