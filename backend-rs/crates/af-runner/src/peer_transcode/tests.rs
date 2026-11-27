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
                calling_link_segment: None,
            },
            r#"{"action":"bind_media","from":"/srv/media/movies","to":"/mnt/af-peers/media-2/movies","writable":false}"#,
        ),
        (
            PeerTranscodeRequest::BindMedia {
                from: "/srv/media/movies".to_string(),
                to: "/mnt/af-peers/media-2/movies".to_string(),
                writable: true,
                calling_link_segment: Some("media-2".to_string()),
            },
            r#"{"action":"bind_media","from":"/srv/media/movies","to":"/mnt/af-peers/media-2/movies","writable":true,"calling_link_segment":"media-2"}"#,
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

    // BindMedia defaults writable to false, calling_link_segment to None, and denies unknown fields.
    let bind_default: PeerTranscodeRequest =
        serde_json::from_str(r#"{"action":"bind_media","from":"/srv/a","to":"/mnt/af-peers/l/e"}"#)
            .expect("default writable");
    assert_eq!(
        bind_default,
        PeerTranscodeRequest::BindMedia {
            from: "/srv/a".to_string(),
            to: "/mnt/af-peers/l/e".to_string(),
            writable: false,
            calling_link_segment: None,
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
            calling_link_segment: Some("media-2".to_string()),
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

    // 2. ScheduleApiRestart probes is-active and invokes argv-only systemd-run with fixed unit name.
    fx.runner.clear_calls();
    let restart_rep = mgr.schedule_api_restart().await.unwrap();
    assert!(restart_rep.changed);
    let calls = fx.runner.calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].program, "systemctl");
    assert_eq!(
        calls[0].args,
        vec![
            "is-active".to_string(),
            format!("{TRANSCODE_API_RESTART_UNIT}.timer"),
            format!("{TRANSCODE_API_RESTART_UNIT}.service"),
        ]
    );
    assert_eq!(calls[1].program, "systemd-run");
    assert!(calls[1]
        .args
        .iter()
        .any(|a| a == &format!("--unit={TRANSCODE_API_RESTART_UNIT}")));
    assert_eq!(
        &calls[1].args[calls[1].args.len() - 4..],
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

#[tokio::test]
async fn mount_and_remove_transcode_dirs_enforce_worker_jellyfin_allowlist() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();

    // Paths outside the worker Jellyfin cache/transcode allowlist MUST be rejected on both
    // MountTranscodeDirs and RemoveTranscodeMounts.
    for bad_path in [
        "/home/admin/.ssh",
        "/var/spool/cron/crontabs",
        "/srv/media/movies",
        "/var/cache/jellyfin-evil",
        "/var/cache/jellyfin/nested/deep",
        "/tmp/transcodes",
        "/var/cache/jellyfin/../etc",
    ] {
        let mount_err = mgr
            .mount_transcode_dirs("seedbox-1", "10.231.0.1", &[bad_path.to_string()])
            .await
            .unwrap_err();
        assert!(
            mount_err.is_invalid_input(),
            "expected InvalidInput on mount for '{bad_path}', got {mount_err:?}"
        );
        let remove_err = mgr
            .remove_transcode_mounts("seedbox-1", &[bad_path.to_string()])
            .await
            .unwrap_err();
        assert!(
            remove_err.is_invalid_input(),
            "expected InvalidInput on remove for '{bad_path}', got {remove_err:?}"
        );
    }

    // Symlink inside `/var/cache/jellyfin/` MUST be rejected.
    let cache_dir = fx.create_dir("/var/cache/jellyfin");
    let escape_target = fx.create_dir("/srv/escape");
    symlink(&escape_target, cache_dir.join("sym-sub")).unwrap();
    let sym_err = mgr
        .mount_transcode_dirs(
            "seedbox-1",
            "10.231.0.1",
            &["/var/cache/jellyfin/sym-sub".to_string()],
        )
        .await
        .unwrap_err();
    assert!(
        sym_err.is_invalid_input(),
        "expected InvalidInput for symlinked mountpoint, got {sym_err:?}"
    );

    // Direct subdirectory inside `/var/cache/jellyfin/` and custom inspected `<TranscodingTempPath>`
    // are allowed on both mount and remove.
    fx.write_encoding_xml(
        r#"<?xml version="1.0"?><EncodingOptions><TranscodingTempPath>/srv/jf/custom-tc</TranscodingTempPath></EncodingOptions>"#,
    );
    let allowed = vec![
        "/var/cache/jellyfin".to_string(),
        "/var/cache/jellyfin/transcodes".to_string(),
        "/var/cache/jellyfin/af-tmp".to_string(),
        "/var/cache/jellyfin/direct-sub".to_string(),
        "/srv/jf/custom-tc".to_string(),
    ];
    let mounted = mgr
        .mount_transcode_dirs("seedbox-1", "10.231.0.1", &allowed)
        .await
        .unwrap();
    assert!(mounted.changed);
    assert_eq!(mounted.paths.len(), 5);

    // Sibling path outside inspected `<TranscodingTempPath>` is still rejected.
    assert!(mgr
        .mount_transcode_dirs(
            "seedbox-1",
            "10.231.0.1",
            &["/srv/jf/other-dir".to_string()],
        )
        .await
        .unwrap_err()
        .is_invalid_input());

    let removed = mgr
        .remove_transcode_mounts("seedbox-1", &allowed)
        .await
        .unwrap();
    assert!(removed.changed);
    assert_eq!(removed.paths.len(), 5);
}

#[tokio::test]
async fn bind_media_enforces_bidirectional_allowlists_link_confinement_empty_dir_and_conditional_bindsto(
) {
    let _env_guard = ENV_TEST_MUTEX.lock().await;
    let prev_allowed = env::var_os("AF_ALLOWED_FS_ROOTS");
    env::remove_var("AF_ALLOWED_FS_ROOTS");

    let fx = TranscodeFixture::new();
    let mgr = fx.manager();
    fx.create_dir("/home/alice/movies");
    fx.create_dir("/home/admin/.ssh");
    fx.create_dir("/var/spool/cron");
    fx.create_dir("/mnt/af-peers/link1/movies/sub/4k");
    fx.create_dir("/mnt/af-peers/link10/movies");

    // 1. Worker-holds-media (`to` under `/mnt/af-peers/`):
    //    calling_link_segment enforces exact component equality (rejects link1 vs link10 prefix overlap).
    assert!(mgr
        .bind_media_with_link(
            "/home/alice/movies",
            "/mnt/af-peers/link10/movies",
            false,
            Some("link1"),
        )
        .await
        .unwrap_err()
        .is_invalid_input());
    assert!(mgr
        .bind_media_with_link(
            "/home/alice/movies",
            "/mnt/af-peers/link2/movies",
            false,
            Some("link1"),
        )
        .await
        .unwrap_err()
        .is_invalid_input());
    // Rejects `from` inside `/mnt/af-peers/` or sensitive system/user dirs.
    for bad_from in [
        "/mnt/af-peers/link10/movies",
        "/etc/ssh",
        "/root/media",
        "/var/spool/cron",
        "/home/admin/.ssh",
        "/run/aetherflow",
        "/usr/local",
    ] {
        assert!(
            mgr.bind_media_with_link(bad_from, "/mnt/af-peers/link1/movies", false, Some("link1"),)
                .await
                .unwrap_err()
                .is_invalid_input(),
            "expected InvalidInput for bad_from={bad_from}"
        );
    }

    // Valid worker-holds-media bind MUST NOT include BindsTo= or extra After= for local `from`.
    let worker_rep = mgr
        .bind_media_with_link(
            "/home/alice/movies",
            "/mnt/af-peers/link1/local-movies",
            false,
            Some("link1"),
        )
        .await
        .unwrap();
    assert!(worker_rep.changed);
    let worker_unit_text = fs::read_to_string(
        fx.root
            .join("etc/systemd/system")
            .join(&worker_rep.units[0]),
    )
    .unwrap();
    assert!(!worker_unit_text.contains("BindsTo="));
    assert_eq!(worker_unit_text.matches("After=").count(), 1);
    assert!(worker_unit_text.contains("After=local-fs.target\n"));

    // 2. Neither under `/mnt/af-peers/` is rejected.
    assert!(mgr
        .bind_media_with_link("/home/alice/movies", "/srv/media/local-only", false, None)
        .await
        .unwrap_err()
        .is_invalid_input());

    // 3. Controller-holds-media (`from` under `/mnt/af-peers/`, `to` outside `/mnt/af-peers/`):
    //    calling_link_segment enforces exact component equality on `from`.
    assert!(mgr
        .bind_media_with_link(
            "/mnt/af-peers/link10/movies",
            "/srv/media/movies",
            false,
            Some("link1"),
        )
        .await
        .unwrap_err()
        .is_invalid_input());

    // Enforce explicit allowlist on `to` (rejects `/etc`, `/home/*/.ssh`, `/home/*`, `/root`,
    // `/var/spool`, `/tmp`, `/usr`, `/var/lib/aetherflow`, exact `/var/lib/jellyfin`, prefix overlap).
    for bad_to in [
        "/etc/movies",
        "/home/admin/.ssh",
        "/home/admin/movies",
        "/root/movies",
        "/var/spool/cron",
        "/tmp/movies",
        "/usr/share/movies",
        "/var/lib/aetherflow/data",
        "/var/lib/jellyfin",
        "/var/lib/jellyfin-evil/movies",
    ] {
        assert!(
            mgr.bind_media_with_link(
                "/mnt/af-peers/link1/movies/sub/4k",
                bad_to,
                false,
                Some("link1"),
            )
            .await
            .unwrap_err()
            .is_invalid_input(),
            "expected InvalidInput for disallowed controller bind target {bad_to}"
        );
    }

    // Valid controller-holds-media bind adds conditional BindsTo=/After= on the backing 4-component
    // NFS mount unit (`/mnt/af-peers/link1/movies` -> `mnt-af\x2dpeers-link1-movies.mount`).
    let ctrl_rep = mgr
        .bind_media_with_link(
            "/mnt/af-peers/link1/movies/sub/4k",
            "/srv/media/movies_4k",
            false,
            Some("link1"),
        )
        .await
        .unwrap();
    assert!(ctrl_rep.changed);
    let ctrl_unit_text =
        fs::read_to_string(fx.root.join("etc/systemd/system").join(&ctrl_rep.units[0])).unwrap();
    let expected_backing = r"mnt-af\x2dpeers-link1-movies.mount";
    assert!(
        ctrl_unit_text.contains(&format!("BindsTo={expected_backing}\n")),
        "missing conditional BindsTo in:\n{ctrl_unit_text}"
    );
    assert!(
        ctrl_unit_text.contains(&format!("After={expected_backing}\n")),
        "missing conditional After in:\n{ctrl_unit_text}"
    );

    // Other default media roots are accepted.
    for good_to in [
        "/mnt/storage/movies",
        "/media/tv",
        "/downloads/done",
        "/data/library",
        "/var/lib/jellyfin/media",
    ] {
        let rep = mgr
            .bind_media_with_link(
                "/mnt/af-peers/link1/movies/sub/4k",
                good_to,
                false,
                Some("link1"),
            )
            .await
            .unwrap();
        assert!(rep.changed);
    }

    // 4. Empty-directory check on `to`:
    //    Non-empty existing local directory MUST be rejected with Conflict.
    let occupied = fx.create_dir("/srv/media/occupied");
    fs::write(occupied.join("existing-movie.mkv"), b"data").unwrap();
    let conflict_err = mgr
        .bind_media_with_link(
            "/mnt/af-peers/link1/movies/sub/4k",
            "/srv/media/occupied",
            false,
            Some("link1"),
        )
        .await
        .unwrap_err();
    assert!(
        conflict_err.is_conflict(),
        "expected Conflict for non-empty target dir, got {conflict_err:?}"
    );

    // Non-empty directory with an INACTIVE managed bind unit MUST still be rejected with Conflict.
    let srv_movies_dir = fx.create_dir("/srv/media/movies_4k");
    fs::write(srv_movies_dir.join("file.mkv"), b"data").unwrap();
    fx.runner.push_rule(|prog, args| {
        assert_eq!(prog, "systemctl");
        assert_eq!(args[0], "is-active");
        Ok(CommandOutput {
            exit_code: 3,
            stdout: "inactive\n".to_string(),
            stderr: String::new(),
        })
    });
    assert!(mgr
        .bind_media_with_link(
            "/mnt/af-peers/link1/movies/sub/4k",
            "/srv/media/movies_4k",
            true,
            Some("link1"),
        )
        .await
        .unwrap_err()
        .is_conflict());

    // Non-empty directory that IS an active managed bind mountpoint for the same unit IS allowed!
    fx.runner.push_rule(|prog, args| {
        assert_eq!(prog, "systemctl");
        assert_eq!(args[0], "is-active");
        Ok(CommandOutput {
            exit_code: 0,
            stdout: "active\n".to_string(),
            stderr: String::new(),
        })
    });
    let rebind_rep = mgr
        .bind_media_with_link(
            "/mnt/af-peers/link1/movies/sub/4k",
            "/srv/media/movies_4k",
            true,
            Some("link1"),
        )
        .await
        .unwrap();
    assert!(rebind_rep.changed);

    // 5. Configured `extra_bind_media_roots` and `AF_ALLOWED_FS_ROOTS` allow custom roots while
    //    still rejecting restricted system paths.
    let mut custom_cfg = fx.config();
    custom_cfg
        .extra_bind_media_roots
        .push(PathBuf::from("/custom-fixture-media"));
    let custom_mgr = PeerTranscodeManager::new(custom_cfg, fx.runner.clone()).unwrap();
    assert!(custom_mgr
        .bind_media_with_link(
            "/mnt/af-peers/link1/movies/sub/4k",
            "/custom-fixture-media/anime",
            false,
            Some("link1"),
        )
        .await
        .is_ok());

    env::set_var("AF_ALLOWED_FS_ROOTS", "/tank/library,/etc");
    assert!(mgr
        .bind_media_with_link(
            "/mnt/af-peers/link1/movies/sub/4k",
            "/tank/library/films",
            false,
            Some("link1"),
        )
        .await
        .is_ok());
    // `/etc` stays rejected even if present in AF_ALLOWED_FS_ROOTS!
    assert!(mgr
        .bind_media_with_link(
            "/mnt/af-peers/link1/movies/sub/4k",
            "/etc/films",
            false,
            Some("link1"),
        )
        .await
        .unwrap_err()
        .is_invalid_input());

    if let Some(prev) = prev_allowed {
        env::set_var("AF_ALLOWED_FS_ROOTS", prev);
    } else {
        env::remove_var("AF_ALLOWED_FS_ROOTS");
    }
}

#[tokio::test]
async fn mount_transcode_dirs_atomic_rollback_removes_units_and_empty_newly_created_dirs() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();

    // `/var/cache/jellyfin` pre-exists; child mount dirs do NOT exist beforehand.
    let preexisting_parent = fx.create_dir("/var/cache/jellyfin");
    let created_tmp = fx.root.join("var/cache/jellyfin/af-tmp");
    let created_tc = fx.root.join("var/cache/jellyfin/transcodes");
    assert!(!created_tmp.exists());
    assert!(!created_tc.exists());

    let created_tmp_c = created_tmp.clone();
    let created_tc_c = created_tc.clone();

    // 1: daemon-reload OK
    fx.runner.push_rule(|prog, args| {
        assert_eq!(prog, "systemctl");
        assert_eq!(args, &["daemon-reload".to_string()]);
        Ok(CommandOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    // 2: start var-cache-jellyfin.mount OK
    fx.runner.push_rule(|prog, args| {
        assert_eq!(prog, "systemctl");
        assert_eq!(
            args,
            &["start".to_string(), "var-cache-jellyfin.mount".to_string()]
        );
        Ok(CommandOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    // 3: start var-cache-jellyfin-af\x2dtmp.mount creates empty dir and succeeds
    fx.runner.push_rule(move |prog, args| {
        assert_eq!(prog, "systemctl");
        assert_eq!(
            args,
            &[
                "start".to_string(),
                r"var-cache-jellyfin-af\x2dtmp.mount".to_string()
            ]
        );
        fs::create_dir_all(&created_tmp_c).unwrap();
        Ok(CommandOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    // 4: start var-cache-jellyfin-transcodes.mount creates empty dir then fails
    fx.runner.push_rule(move |prog, args| {
        assert_eq!(prog, "systemctl");
        assert_eq!(
            args,
            &[
                "start".to_string(),
                "var-cache-jellyfin-transcodes.mount".to_string()
            ]
        );
        fs::create_dir_all(&created_tc_c).unwrap();
        Ok(CommandOutput {
            exit_code: 1,
            stdout: String::new(),
            stderr: "simulated nfs mount timeout".to_string(),
        })
    });

    let err = mgr
        .mount_transcode_dirs(
            "seedbox-1",
            "10.231.0.1",
            &[
                "/var/cache/jellyfin".to_string(),
                "/var/cache/jellyfin/af-tmp".to_string(),
                "/var/cache/jellyfin/transcodes".to_string(),
            ],
        )
        .await
        .unwrap_err();
    assert!(matches!(err, PeerTranscodeError::Runtime(_)));

    // Verify already-started units were stopped in reverse order and daemon-reload ran.
    let calls = fx.runner.calls();
    let stop_pos_tmp = calls
        .iter()
        .position(|c| {
            c.program == "systemctl"
                && c.args
                    == vec![
                        "stop".to_string(),
                        r"var-cache-jellyfin-af\x2dtmp.mount".to_string(),
                    ]
        })
        .expect("af-tmp unit stopped");
    let stop_pos_parent = calls
        .iter()
        .position(|c| {
            c.program == "systemctl"
                && c.args == vec!["stop".to_string(), "var-cache-jellyfin.mount".to_string()]
        })
        .expect("parent unit stopped");
    assert!(stop_pos_tmp < stop_pos_parent);
    assert_eq!(
        calls.last().unwrap(),
        &RecordedCall {
            program: "systemctl".to_string(),
            args: vec!["daemon-reload".to_string()],
        }
    );

    // All newly created units and worker paths drop-in are cleaned up.
    assert!(!fx
        .root
        .join("etc/systemd/system/var-cache-jellyfin.mount")
        .exists());
    assert!(!fx
        .root
        .join(r"etc/systemd/system/var-cache-jellyfin-af\x2dtmp.mount")
        .exists());
    assert!(!fx
        .root
        .join("etc/systemd/system/var-cache-jellyfin-transcodes.mount")
        .exists());
    assert!(!fx
        .root
        .join("etc/systemd/system/af-transcode-worker.service.d/30-aetherflow-transcode-paths.conf")
        .exists());

    // Newly created empty mount dirs were removed, while pre-existing parent dir was preserved!
    assert!(!created_tmp.exists());
    assert!(!created_tc.exists());
    assert!(preexisting_parent.exists());
}

#[tokio::test]
async fn export_transcode_dirs_prunes_same_st_dev_children_and_preserves_distinct_fs_children() {
    // 1. Unit-test pure pruning semantics including prefix overlap and nested filesystem crossings.
    let pruned_same = prune_same_device_descendant_exports(&[
        ("/var/cache/jellyfin".to_string(), 100),
        ("/var/cache/jellyfin/af-tmp".to_string(), 100),
        ("/var/cache/jellyfin/transcodes".to_string(), 100),
        ("/var/cache/jellyfin2".to_string(), 100),
    ]);
    assert_eq!(
        pruned_same,
        vec![
            "/var/cache/jellyfin".to_string(),
            "/var/cache/jellyfin2".to_string(),
        ]
    );

    let pruned_mixed = prune_same_device_descendant_exports(&[
        ("/var/cache/jellyfin".to_string(), 100),
        ("/var/cache/jellyfin/af-tmp".to_string(), 100),
        ("/var/cache/jellyfin/transcodes".to_string(), 200),
        ("/var/cache/jellyfin/transcodes/inner".to_string(), 100),
    ]);
    assert_eq!(
        pruned_mixed,
        vec![
            "/var/cache/jellyfin".to_string(),
            "/var/cache/jellyfin/transcodes".to_string(),
            "/var/cache/jellyfin/transcodes/inner".to_string(),
        ]
    );

    // 2. End-to-end ExportTranscodeDirs on same real filesystem prunes strict descendants.
    let fx = TranscodeFixture::new();
    fx.create_dir("/var/cache/jellyfin");
    fx.create_dir("/var/cache/jellyfin/af-tmp");
    fx.create_dir("/var/cache/jellyfin/transcodes");
    let mgr = fx.manager();

    let all_three = vec![
        "/var/cache/jellyfin".to_string(),
        "/var/cache/jellyfin/af-tmp".to_string(),
        "/var/cache/jellyfin/transcodes".to_string(),
    ];
    let rep_same = mgr
        .export_transcode_dirs("media-2", "10.231.0.2", 108, 114, &all_three)
        .await
        .unwrap();
    assert!(rep_same.changed);
    let export_file = fx
        .root
        .join("etc/exports.d/aetherflow-peer-media-2-transcode.exports");
    let text_same = fs::read_to_string(&export_file).unwrap();
    assert!(text_same.contains("/var/cache/jellyfin 10.231.0.2("));
    assert!(!text_same.contains("/var/cache/jellyfin/af-tmp"));
    assert!(!text_same.contains("/var/cache/jellyfin/transcodes"));

    // 3. End-to-end ExportTranscodeDirs with differing st_dev keeps separate-FS child export!
    let mut dev_map = HashMap::new();
    dev_map.insert("/var/cache/jellyfin".to_string(), 1001);
    dev_map.insert("/var/cache/jellyfin/af-tmp".to_string(), 1001);
    dev_map.insert("/var/cache/jellyfin/transcodes".to_string(), 2002);
    let mgr_diff = fx.manager().with_st_dev_overrides(dev_map);

    let rep_diff = mgr_diff
        .export_transcode_dirs("media-2", "10.231.0.2", 108, 114, &all_three)
        .await
        .unwrap();
    assert!(rep_diff.changed);
    let text_diff = fs::read_to_string(&export_file).unwrap();
    assert!(text_diff.contains("/var/cache/jellyfin 10.231.0.2("));
    assert!(text_diff.contains("/var/cache/jellyfin/transcodes 10.231.0.2("));
    assert!(!text_diff.contains("/var/cache/jellyfin/af-tmp"));
}

#[tokio::test]
async fn transcode_env_file_is_0640_idempotent_secret_free_and_wired_to_all_four_units() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();

    // 1. Direct idempotent helper creates `0640` file documenting both env vars and never overwrites.
    assert!(mgr.ensure_transcode_env_file().unwrap());
    let env_path = fx.root.join("etc/aetherflow/transcode.env");
    assert_eq!(
        fs::metadata(&env_path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    let initial = fs::read_to_string(&env_path).unwrap();
    assert!(initial.contains("AF_TRANSCODE_REAL_FFMPEG"));
    assert!(initial.contains("AF_TRANSCODE_WORKER_MAX_JOBS"));
    assert!(!initial.contains("AES_MASTER_KEY"));
    assert!(!initial.contains("JWT_SECRET"));

    // Simulate operator edit; subsequent calls MUST NOT overwrite.
    let operator_content =
        "# Operator tuned\nAF_TRANSCODE_WORKER_MAX_JOBS=12\nAF_TRANSCODE_REAL_FFMPEG=/opt/ffmpeg/bin/ffmpeg\n";
    fs::write(&env_path, operator_content).unwrap();
    assert!(!mgr.ensure_transcode_env_file().unwrap());

    // 2. Provision all 4 consuming units and verify EnvironmentFile=-/etc/aetherflow/transcode.env.
    mgr.ensure_dispatcher_dir().await.unwrap();
    mgr.enable_jellyfin().await.unwrap();
    mgr.install_worker_unit().await.unwrap();

    // Operator edits remain completely untouched.
    assert_eq!(fs::read_to_string(&env_path).unwrap(), operator_content);

    let worker_unit = fs::read_to_string(
        fx.root
            .join("etc/systemd/system/af-transcode-worker.service"),
    )
    .unwrap();
    let jellyfin_dropin = fs::read_to_string(
        fx.root
            .join("etc/systemd/system/jellyfin.service.d/20-aetherflow-transcode.conf"),
    )
    .unwrap();
    let api_dropin = fs::read_to_string(
        fx.root
            .join("etc/systemd/system/aetherflow-api.service.d/20-aetherflow-transcode.conf"),
    )
    .unwrap();
    let runner_dropin_path = fx
        .root
        .join("etc/systemd/system/aetherflow-runner.service.d/20-aetherflow-transcode.conf");
    let runner_dropin = fs::read_to_string(&runner_dropin_path).unwrap();

    let expected_env_line = format!("EnvironmentFile=-{DEFAULT_TRANSCODE_ENV_FILE}\n");
    for (label, content) in [
        ("worker", &worker_unit),
        ("jellyfin", &jellyfin_dropin),
        ("api", &api_dropin),
        ("runner", &runner_dropin),
    ] {
        assert!(
            content.starts_with(PEER_MANAGED_HEADER),
            "{label} missing managed header"
        );
        assert!(
            content.contains(&expected_env_line),
            "{label} missing EnvironmentFile=-/etc/aetherflow/transcode.env:\n{content}"
        );
    }
    // NEVER load `/etc/aetherflow/aetherflow.env` into worker or jellyfin!
    assert!(!worker_unit.contains("aetherflow.env"));
    assert!(!jellyfin_dropin.contains("aetherflow.env"));

    // 3. Because dispatcher IS installed, RemoveWorkerUnit keeps the runner drop-in.
    mgr.remove_worker_unit().await.unwrap();
    assert!(runner_dropin_path.exists());

    // 4. On a worker-only host (no dispatcher installed), RemoveWorkerUnit cleans up runner drop-in!
    let fx_worker_only = TranscodeFixture::new();
    let mgr_worker_only = fx_worker_only.manager();
    mgr_worker_only.install_worker_unit().await.unwrap();
    let worker_only_runner_dropin = fx_worker_only
        .root
        .join("etc/systemd/system/aetherflow-runner.service.d/20-aetherflow-transcode.conf");
    assert!(worker_only_runner_dropin.exists());
    mgr_worker_only.remove_worker_unit().await.unwrap();
    assert!(!worker_only_runner_dropin.exists());
}

#[tokio::test]
async fn worker_unit_hardening_and_dynamic_readwritepaths_dropin_lifecycle() {
    let fx = TranscodeFixture::new();
    let mgr = fx.manager();
    fx.create_dir("/srv/media/movies");

    mgr.install_worker_unit().await.unwrap();
    let unit_text = fs::read_to_string(
        fx.root
            .join("etc/systemd/system/af-transcode-worker.service"),
    )
    .unwrap();
    for expected in [
        "PrivateNetwork=yes\n",
        "RestrictAddressFamilies=AF_UNIX\n",
        "ProtectSystem=strict\n",
        "ProtectHome=read-only\n",
        "CacheDirectory=aetherflow-transcode-worker\n",
        "CacheDirectoryMode=0750\n",
        "WorkingDirectory=/run/aetherflow-transcode-worker\n",
        "Environment=MESA_SHADER_CACHE_DIR=/var/cache/aetherflow-transcode-worker/mesa-cache\n",
        "Environment=MESA_SHADER_CACHE_MAX_SIZE=512M\n",
        "DevicePolicy=closed\n",
        "DeviceAllow=char-drm rw\n",
        "DeviceAllow=/dev/dri rw\n",
        "DeviceAllow=/dev/kfd rw\n",
        "DeviceAllow=char-nvidia-frontend rw\n",
        "DeviceAllow=char-nvidia-uvm rw\n",
        "DeviceAllow=char-nvidia-caps rw\n",
        "DeviceAllow=/dev/nvidiactl rw\n",
        "DeviceAllow=/dev/nvidia-modeset rw\n",
        "DeviceAllow=/dev/nvidia-uvm rw\n",
        "DeviceAllow=/dev/nvidia-uvm-tools rw\n",
        "ReadWritePaths=-/run/aetherflow-transcode-worker -/var/cache/jellyfin\n",
        "EnvironmentFile=-/etc/aetherflow/transcode.env\n",
    ] {
        assert!(
            unit_text.contains(expected),
            "missing hardening directive {expected:?} in:\n{unit_text}"
        );
    }
    assert!(!unit_text.contains("aetherflow.env"));

    let paths_dropin = fx.root.join(
        "etc/systemd/system/af-transcode-worker.service.d/30-aetherflow-transcode-paths.conf",
    );
    assert!(!paths_dropin.exists());

    // MountTranscodeDirs writes 30-aetherflow-transcode-paths.conf and restarts active worker.
    fx.runner.clear_calls();
    mgr.mount_transcode_dirs(
        "seedbox-1",
        "10.231.0.1",
        &["/var/cache/jellyfin/transcodes".to_string()],
    )
    .await
    .unwrap();
    let text1 = fs::read_to_string(&paths_dropin).unwrap();
    assert!(text1.starts_with(PEER_MANAGED_HEADER));
    assert!(text1.contains("ReadWritePaths=-/var/cache/jellyfin/transcodes\n"));
    assert!(fx.runner.calls().iter().any(|c| c.program == "systemctl"
        && c.args
            == vec![
                "restart".to_string(),
                PEER_TRANSCODE_WORKER_UNIT.to_string()
            ]));

    // Read-only BindMedia does NOT add to ReadWritePaths= and does NOT restart worker.
    fx.runner.clear_calls();
    mgr.bind_media_with_link(
        "/srv/media/movies",
        "/mnt/af-peers/seedbox-1/movies",
        false,
        Some("seedbox-1"),
    )
    .await
    .unwrap();
    assert_eq!(fs::read_to_string(&paths_dropin).unwrap(), text1);
    assert!(!fx.runner.calls().iter().any(|c| c.program == "systemctl"
        && c.args
            == vec![
                "restart".to_string(),
                PEER_TRANSCODE_WORKER_UNIT.to_string()
            ]));

    // Writable BindMedia adds path to 30-aetherflow-transcode-paths.conf and restarts active worker.
    fx.runner.clear_calls();
    mgr.bind_media_with_link(
        "/srv/media/movies",
        "/mnt/af-peers/seedbox-1/movies",
        true,
        Some("seedbox-1"),
    )
    .await
    .unwrap();
    let text2 = fs::read_to_string(&paths_dropin).unwrap();
    assert!(text2.contains(
        "ReadWritePaths=-/mnt/af-peers/seedbox-1/movies -/var/cache/jellyfin/transcodes\n"
    ));
    assert!(fx.runner.calls().iter().any(|c| c.program == "systemctl"
        && c.args
            == vec![
                "restart".to_string(),
                PEER_TRANSCODE_WORKER_UNIT.to_string()
            ]));

    // RemoveBindMedia removes bind path from drop-in and restarts active worker.
    fx.runner.clear_calls();
    mgr.remove_bind_media("/mnt/af-peers/seedbox-1/movies")
        .await
        .unwrap();
    assert_eq!(fs::read_to_string(&paths_dropin).unwrap(), text1);
    assert!(fx.runner.calls().iter().any(|c| c.program == "systemctl"
        && c.args
            == vec![
                "restart".to_string(),
                PEER_TRANSCODE_WORKER_UNIT.to_string()
            ]));

    // When worker is inactive, RemoveTranscodeMounts removes drop-in WITHOUT restarting worker.
    fx.runner.set_worker_active(false);
    fx.runner.clear_calls();
    mgr.remove_transcode_mounts("seedbox-1", &["/var/cache/jellyfin/transcodes".to_string()])
        .await
        .unwrap();
    assert!(!paths_dropin.exists());
    assert!(!fx.runner.calls().iter().any(|c| c.program == "systemctl"
        && c.args
            == vec![
                "restart".to_string(),
                PEER_TRANSCODE_WORKER_UNIT.to_string()
            ]));

    // RemoveWorkerUnit deletes 30-aetherflow-transcode-paths.conf if still present.
    mgr.mount_transcode_dirs(
        "seedbox-1",
        "10.231.0.1",
        &["/var/cache/jellyfin/transcodes".to_string()],
    )
    .await
    .unwrap();
    assert!(paths_dropin.exists());
    mgr.remove_worker_unit().await.unwrap();
    assert!(!paths_dropin.exists());
}

#[tokio::test]
async fn slow_systemctl_mount_start_does_not_starve_concurrent_inspect_cleanup_or_sibling_mount() {
    struct BlockingMountRunner {
        blocked_unit: String,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    impl CommandRunner for BlockingMountRunner {
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
            let is_target = program == "systemctl"
                && args.len() == 2
                && args[0] == "start"
                && args[1] == self.blocked_unit;
            let entered = Arc::clone(&self.entered);
            let release = Arc::clone(&self.release);
            Box::pin(async move {
                if is_target {
                    entered.notify_one();
                    release.notified().await;
                }
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
        }
    }

    let fx = TranscodeFixture::new();
    let tc_dir = fx.create_dir("/var/cache/jellyfin/transcodes");
    fx.create_dir("/srv/media/movies");
    let parity_name = ".af-parity-0123456789abcdef0123456789abcdef.ts";
    fs::write(tc_dir.join(parity_name), b"mpegts").unwrap();

    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingMountRunner {
        blocked_unit: "var-cache-jellyfin-transcodes.mount".to_string(),
        entered: Arc::clone(&entered),
        release: Arc::clone(&release),
    });

    let mut cfg = fx.config();
    cfg.lock_timeout = Duration::from_millis(120);
    let mgr = Arc::new(PeerTranscodeManager::new(cfg, runner).unwrap());

    let mgr_mount = Arc::clone(&mgr);
    let mount_task = tokio::spawn(async move {
        mgr_mount
            .mount_transcode_dirs(
                "seedbox-1",
                "10.231.0.1",
                &["/var/cache/jellyfin/transcodes".to_string()],
            )
            .await
    });

    // Wait until `systemctl start var-cache-jellyfin-transcodes.mount` is actively blocked.
    entered.notified().await;

    // Concurrent InspectJellyfinPaths, CleanupParityFile, and sibling BindMedia MUST succeed
    // without hitting 503 Busy while the slow mount start is in flight!
    let inspected = mgr.inspect_jellyfin_paths().await.unwrap();
    assert_eq!(
        inspected.transcoding_temp_path,
        DEFAULT_JELLYFIN_TRANSCODE_DIR
    );

    let parity = mgr
        .cleanup_parity_file("/var/cache/jellyfin/transcodes", parity_name)
        .await
        .unwrap();
    assert!(parity.removed);

    let sibling = mgr
        .bind_media_with_link(
            "/srv/media/movies",
            "/mnt/af-peers/seedbox-1/movies",
            false,
            Some("seedbox-1"),
        )
        .await
        .unwrap();
    assert!(sibling.changed);

    // Concurrent operation targeting the SAME unit MUST serialize and return Busy on timeout.
    let same_unit_err = mgr
        .remove_transcode_mounts("seedbox-1", &["/var/cache/jellyfin/transcodes".to_string()])
        .await
        .unwrap_err();
    assert!(
        same_unit_err.is_busy(),
        "expected Busy for conflicting operation on the same mount unit, got {same_unit_err:?}"
    );

    release.notify_one();
    let mount_rep = mount_task.await.unwrap().unwrap();
    assert!(mount_rep.changed);
}

#[tokio::test]
async fn schedule_api_restart_debounces_deterministically_and_resets_failed_unit() {
    let fx = TranscodeFixture::new();
    let mgr = Arc::new(fx.manager());

    // 1. When already active/queued, ScheduleApiRestart coalesces without invoking systemd-run.
    fx.runner.clear_calls();
    fx.runner.push_rule(|prog, args| {
        assert_eq!(prog, "systemctl");
        assert_eq!(
            args,
            &[
                "is-active".to_string(),
                format!("{TRANSCODE_API_RESTART_UNIT}.timer"),
                format!("{TRANSCODE_API_RESTART_UNIT}.service"),
            ]
        );
        Ok(CommandOutput {
            exit_code: 3,
            stdout: "active\ninactive\n".to_string(),
            stderr: String::new(),
        })
    });
    let debounced = mgr.schedule_api_restart().await.unwrap();
    assert!(!debounced.changed);
    assert_eq!(debounced.units[1], TRANSCODE_API_RESTART_UNIT);
    assert_eq!(fx.runner.calls().len(), 1);

    // 2. When previously failed, ScheduleApiRestart resets failed state before scheduling.
    fx.runner.clear_calls();
    fx.runner.push_rule(|prog, args| {
        assert_eq!(prog, "systemctl");
        assert_eq!(args[0], "is-active");
        Ok(CommandOutput {
            exit_code: 3,
            stdout: "inactive\nfailed\n".to_string(),
            stderr: String::new(),
        })
    });
    fx.runner.push_rule(|prog, args| {
        assert_eq!(prog, "systemctl");
        assert_eq!(
            args,
            &[
                "reset-failed".to_string(),
                format!("{TRANSCODE_API_RESTART_UNIT}.timer"),
                format!("{TRANSCODE_API_RESTART_UNIT}.service"),
            ]
        );
        Ok(CommandOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    });
    let scheduled = mgr.schedule_api_restart().await.unwrap();
    assert!(scheduled.changed);
    let calls = fx.runner.calls();
    assert_eq!(calls.len(), 3);
    assert_eq!(calls[1].args[0], "reset-failed");
    assert_eq!(calls[2].program, "systemd-run");
    assert!(calls[2]
        .args
        .contains(&format!("--unit={TRANSCODE_API_RESTART_UNIT}")));

    // 3. Concurrent calls coalesce cleanly under the deterministic unit lock into 1 systemd-run.
    struct StatefulRestartRunner {
        active: Mutex<bool>,
        systemd_run_count: Mutex<usize>,
    }

    impl CommandRunner for StatefulRestartRunner {
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
            let program = program.to_string();
            let args = args.to_vec();
            Box::pin(async move {
                if program == "systemctl" && args.first().map(String::as_str) == Some("is-active") {
                    let is_active = *self.active.lock().unwrap();
                    return Ok(CommandOutput {
                        exit_code: if is_active { 0 } else { 3 },
                        stdout: if is_active {
                            "active\ninactive\n".to_string()
                        } else {
                            "inactive\ninactive\n".to_string()
                        },
                        stderr: String::new(),
                    });
                }
                if program == "systemd-run" {
                    // Brief yield to maximize overlap between concurrent callers.
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    *self.active.lock().unwrap() = true;
                    *self.systemd_run_count.lock().unwrap() += 1;
                }
                Ok(CommandOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                })
            })
        }
    }

    let stateful_runner = Arc::new(StatefulRestartRunner {
        active: Mutex::new(false),
        systemd_run_count: Mutex::new(0),
    });
    let mgr_conc =
        Arc::new(PeerTranscodeManager::new(fx.config(), stateful_runner.clone()).unwrap());
    let (r1, r2, r3) = tokio::join!(
        mgr_conc.schedule_api_restart(),
        mgr_conc.schedule_api_restart(),
        mgr_conc.schedule_api_restart()
    );
    let results = [r1.unwrap(), r2.unwrap(), r3.unwrap()];
    assert_eq!(results.iter().filter(|r| r.changed).count(), 1);
    assert_eq!(results.iter().filter(|r| !r.changed).count(), 2);
    assert_eq!(*stateful_runner.systemd_run_count.lock().unwrap(), 1);
}

#[tokio::test]
async fn worker_unit_sets_host_local_mesa_shader_cache_before_env_file_and_allows_kfd() {
    assert_eq!(
        crate::DEFAULT_WORKER_CACHE_DIR,
        "/var/cache/aetherflow-transcode-worker"
    );
    assert_eq!(
        crate::DEFAULT_MESA_SHADER_CACHE_DIR,
        "/var/cache/aetherflow-transcode-worker/mesa-cache"
    );
    assert_eq!(crate::DEFAULT_MESA_SHADER_CACHE_MAX_SIZE, "512M");
    assert!(
        crate::DEFAULT_MESA_SHADER_CACHE_DIR.starts_with(crate::DEFAULT_WORKER_CACHE_DIR),
        "Mesa shader cache dir must reside under the host-local worker cache dir"
    );
    assert!(
        !crate::DEFAULT_MESA_SHADER_CACHE_DIR.starts_with(DEFAULT_JELLYFIN_CACHE_DIR),
        "Mesa shader cache dir must not reside under NFS-mounted Jellyfin cache dir"
    );

    let fx = TranscodeFixture::new();
    let mgr = fx.manager();
    mgr.install_worker_unit().await.unwrap();

    let unit_text = fs::read_to_string(
        fx.root
            .join("etc/systemd/system/af-transcode-worker.service"),
    )
    .unwrap();

    // CacheDirectory directives appear immediately after RuntimeDirectoryMode=0750.
    assert!(
        unit_text.contains(
            "RuntimeDirectoryMode=0750\n\
             CacheDirectory=aetherflow-transcode-worker\n\
             CacheDirectoryMode=0750\n"
        ),
        "CacheDirectory directives missing or misplaced in:\n{unit_text}"
    );

    // Default Mesa shader cache env lines MUST precede EnvironmentFile so /etc/aetherflow/transcode.env
    // overrides take precedence, while worker socket lines MUST stay after EnvironmentFile.
    let mesa_dir_line =
        format!("Environment=MESA_SHADER_CACHE_DIR={DEFAULT_MESA_SHADER_CACHE_DIR}\n");
    let mesa_size_line =
        format!("Environment=MESA_SHADER_CACHE_MAX_SIZE={DEFAULT_MESA_SHADER_CACHE_MAX_SIZE}\n");
    let env_file_line = format!("EnvironmentFile=-{DEFAULT_TRANSCODE_ENV_FILE}\n");
    let sock_line = format!("Environment=AF_TRANSCODE_WORKER_SOCK={DEFAULT_WORKER_SOCKET_PATH}\n");
    let sock_mode_line =
        format!("Environment=AF_TRANSCODE_WORKER_SOCKET_MODE={DEFAULT_WORKER_SOCKET_MODE_STR}\n");

    let mesa_dir_pos = unit_text
        .find(&mesa_dir_line)
        .expect("missing MESA_SHADER_CACHE_DIR line");
    let mesa_size_pos = unit_text
        .find(&mesa_size_line)
        .expect("missing MESA_SHADER_CACHE_MAX_SIZE line");
    let env_file_pos = unit_text
        .find(&env_file_line)
        .expect("missing EnvironmentFile line");
    let sock_pos = unit_text
        .find(&sock_line)
        .expect("missing AF_TRANSCODE_WORKER_SOCK line");
    let sock_mode_pos = unit_text
        .find(&sock_mode_line)
        .expect("missing AF_TRANSCODE_WORKER_SOCKET_MODE line");

    assert!(
        mesa_dir_pos < env_file_pos && mesa_size_pos < env_file_pos,
        "Mesa shader cache defaults must precede EnvironmentFile in:\n{unit_text}"
    );
    assert!(
        env_file_pos < sock_pos && env_file_pos < sock_mode_pos,
        "Worker socket Environment lines must remain after EnvironmentFile in:\n{unit_text}"
    );

    // AMD ROCm/OpenCL compute device allowance and preserved security hardening invariants.
    for expected in [
        "DeviceAllow=/dev/kfd rw\n",
        "ProtectSystem=strict\n",
        "ProtectHome=read-only\n",
        "PrivateNetwork=yes\n",
        "RestrictAddressFamilies=AF_UNIX\n",
        "DevicePolicy=closed\n",
        "NoNewPrivileges=yes\n",
    ] {
        assert!(
            unit_text.contains(expected),
            "missing required directive {expected:?} in:\n{unit_text}"
        );
    }
    assert!(!unit_text.contains("aetherflow.env"));
    assert!(!unit_text.contains("Group=aetherflow"));
}

#[test]
fn default_transcode_env_file_is_secret_free_commented_out_and_documents_tuning_vars() {
    let content = render_default_transcode_env_file();

    // Every non-empty line must be commented out so defaults remain unchanged out of the box.
    for line in content.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            assert!(
                trimmed.starts_with('#'),
                "default transcode.env must keep tuning lines commented out, found: {line:?}"
            );
        }
    }

    // Secret-free invariant.
    for forbidden in [
        "AES_MASTER_KEY",
        "JWT_SECRET",
        "AETHERFLOW_TOKEN",
        "API_KEY",
        "PASSWORD",
        "PRIVATE_KEY",
        "aetherflow.env",
    ] {
        assert!(
            !content.contains(forbidden),
            "default transcode.env must not reference secret identifier {forbidden:?}"
        );
    }

    // All documented secret-free tuning variables.
    for documented in [
        "# AF_TRANSCODE_REAL_FFMPEG=/usr/lib/jellyfin-ffmpeg/ffmpeg",
        "# AF_TRANSCODE_WORKER_MAX_JOBS=8",
        "# AF_TRANSCODE_FFMPEG_THREADS=",
        "# AF_TRANSCODE_ADAPT_BACKEND=off",
        "# Enable hardware Vulkan Compute for libplacebo HDR tone-mapping and *_vulkan filters (true/false):",
        "# AF_TRANSCODE_VULKAN_COMPUTE=true",
        "# Scale via scale_vaapi before Vulkan libplacebo HDR tone-mapping (default true; set false to disable):",
        "# AF_TRANSCODE_OPTIMIZE_VULKAN_TONEMAP=true",
        "# Enable experimental Vulkan Video hardware decode/encode (-hwaccel vulkan, *_vulkan codecs; off by default):",
        "# AF_TRANSCODE_VULKAN_VIDEO=false",
        "# RUSTICL_ENABLE=radeonsi",
        "# MESA_SHADER_CACHE_DIR=/var/cache/aetherflow-transcode-worker/mesa-cache",
        "# MESA_SHADER_CACHE_MAX_SIZE=512M",
        "# AF_TRANSCODE_HANDSHAKE_TIMEOUT_MS=2000",
        "# AF_TRANSCODE_DISPATCH_POLICY=remote_first",
        "# AF_TRANSCODE_LOCAL_MAX_JOBS=2",
    ] {
        assert!(
            content.contains(documented),
            "default transcode.env missing documented variable {documented:?}:\n{content}"
        );
    }

    assert!(
        !content.contains("# AF_TRANSCODE_OPTIMIZE_VULKAN_TONEMAP=false"),
        "default transcode.env should document AF_TRANSCODE_OPTIMIZE_VULKAN_TONEMAP=true instead of false:\n{content}"
    );
}
