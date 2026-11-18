use super::*;
use serde_json::json;

#[test]
fn typed_read_contracts_accept_partial_snapshots_and_preserve_extensions() {
    for value in [
        json!([]),
        json!({}),
        json!({"users":[{"id":7,"username":"operator"}]}),
    ] {
        serde_json::from_value::<Records<UserRecord>>(value).unwrap();
    }
    serde_json::from_value::<Records<UserQuota>>(
        json!({"quotas":[{"user_id":7,"quota_bytes":"4096"}]}),
    )
    .unwrap();
    serde_json::from_value::<Records<ClusterNode>>(json!({"nodes":[{"id":3,"metrics":null}]}))
        .unwrap();
    let catalog =
        serde_json::from_value::<Records<SharedRecord<af_models::MarketplaceApp>>>(json!([
            {"id":"sonarr","name":"Sonarr","future_capability":true},
        ]))
        .unwrap();
    let catalog = serde_json::to_value(catalog).unwrap();
    assert_eq!(catalog[0]["name"], "Sonarr");
    assert_eq!(catalog[0]["future_capability"], true);
    for banks in [json!(2), json!([{"name":"DIMM 0"}, {"name":"DIMM 1"}])] {
        let report = serde_json::from_value::<HardwareEnvelope>(json!({
            "cpu":{"model":"AMD EPYC"},"memory":{"total_gb":64,"banks":banks},
            "storage":[{"model":"NVMe Array"}],"future_sensor":12,
        }))
        .unwrap();
        assert_eq!(report.cpu.as_ref().unwrap().model.model, "AMD EPYC");
        assert_eq!(report.memory.as_ref().unwrap().banks, 2);
        let report = serde_json::to_value(report).unwrap();
        assert_eq!(report["memory"]["total_gb"], 64);
        assert_eq!(report["storage"][0]["model"], "NVMe Array");
        assert_eq!(report["future_sensor"], 12);
    }
    serde_json::from_value::<TopologyEnvelope>(json!({"nodes":[],"edges":[]})).unwrap();
    assert_eq!(
        serde_json::from_value::<PendingCount>(json!({"count":3,"actions":[]}))
            .unwrap()
            .reported_total(),
        Some(3)
    );
    assert_eq!(
        serde_json::from_value::<PendingCount>(json!({}))
            .unwrap()
            .reported_total(),
        None
    );
    assert!(serde_json::from_value::<Records<UserRecord>>(json!({"users":"invalid"})).is_err());
    let counts =
        serde_json::from_value::<PendingCount>(json!({"total":120,"count":1,"actions":[{}]}))
            .unwrap();
    assert_eq!(counts.reported_total(), Some(120));
}

#[test]
fn quota_bytes_round_trip_as_integers_through_grid_rows() {
    let amount = 107_374_182_400_i64;
    for value in [
        json!(amount),
        json!(amount as f64),
        json!(amount.to_string()),
        json!("107374182400.0"),
    ] {
        let rows = grid_rows::<UserQuota>(&json!([{
            "userId": 9, "quotaBytes": value, "usedBytes": 25, "future": true
        }]));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["quota_bytes"].as_i64(), Some(amount));
        let quota = decode::<UserQuota>(&rows[0]);
        assert_eq!(quota.quota_bytes, Some(amount));
        assert_eq!(quota.used_bytes, Some(25));
        assert_eq!(quota.extra["future"], true);
    }
}

#[test]
fn integer_counters_reject_fractional_nonfinite_and_out_of_range_values() {
    for value in [
        json!(1.5),
        json!("1.5"),
        json!("NaN"),
        json!("inf"),
        json!(u64::MAX),
        json!("9223372036854775808"),
        json!("-9223372036854775809"),
        json!(9_223_372_036_854_775_808.0),
        Value::Null,
        json!(false),
    ] {
        let quota = decode::<UserQuota>(&json!({"quota_bytes": value, "username": "kept"}));
        assert_eq!(quota.quota_bytes, None);
        assert_eq!(quota.username, "kept");
    }
    for value in [i64::MIN, i64::MAX, 9_007_199_254_740_993] {
        for encoded in [json!(value), json!(value.to_string())] {
            assert_eq!(
                decode::<UserQuota>(&json!({"quota_bytes": encoded})).quota_bytes,
                Some(value)
            );
        }
    }
}

#[test]
fn live_progress_coerces_numeric_fields_and_preserves_extensions() {
    let progress: MediaFlowLiveProgress = serde_json::from_value(json!({"frame":120,"fps":48,"speed":"2.1x","time":"00:02:30","size":"412 MiB","bitrate":2048,"status":"PROCESSING"})).unwrap();
    assert_eq!(progress.frame, "120");
    assert_eq!(progress.fps, "48");
    assert_eq!(progress.bitrate, "2048");
    assert_eq!(progress.extra["status"], "PROCESSING");
    assert_eq!(
        decode::<MediaFlowLiveProgress>(&json!({"frame":null})).frame,
        ""
    );
}
#[test]
fn upload_lookup_decodes_aliases_and_retains_unknown_fields() {
    let upload: TusUploadLookup = serde_json::from_value(json!({
        "id":"abc", "offset":4, "length":9, "exists":true, "future":"retained"
    }))
    .unwrap();
    assert_eq!(upload.upload_id, "abc");
    assert_eq!(
        (upload.offset, upload.length, upload.exists),
        (Some(4), Some(9), Some(true))
    );
    assert_eq!(serde_json::to_value(&upload).unwrap()["future"], "retained");
    assert!(serde_json::from_value::<TusUploadLookup>(json!({"offset":-1})).is_err());
    assert!(decode::<TusUploadLookup>(&json!({})).offset.is_none());
    assert_eq!(
        decode::<TusUploadLookup>(&json!({"upload_id":"new"})).upload_id,
        "new"
    );
}

#[test]
fn share_creation_preserves_policy_and_envelope_extensions() {
    let created: ShareCreatedEnvelope = serde_json::from_value(json!({
        "share":{"id":12,"url":"/share?token=secret","expiresAt":"tomorrow",
            "passwordRequired":true,"allowDownload":true,"policy_version":2},
        "receipt":"created"
    }))
    .unwrap();
    assert_eq!(created.share.id, "12");
    assert_eq!(created.share.url.as_deref(), Some("/share?token=secret"));
    assert!(created.share.password_required && created.share.allow_download);
    let roundtrip = serde_json::to_value(created).unwrap();
    assert_eq!(roundtrip["share"]["policy_version"], 2);
    assert_eq!(roundtrip["receipt"], "created");
}

#[test]
fn streaming_summary_accepts_versions_and_missing_counters() {
    let summary: StreamingSummaryContract = serde_json::from_value(json!({
        "activeStreams":3,"directPlayCount":"2","directStreamCount":null,
        "transcodeCount":1,"totalBandwidthMbps":"12.5","updatedAt":"now","future":true
    }))
    .unwrap();
    assert_eq!(summary.active_sessions, Some(3.0));
    assert_eq!(summary.direct_play, Some(2.0));
    assert_eq!(summary.direct_stream, None);
    assert_eq!(summary.transcode, Some(1.0));
    assert_eq!(summary.total_bandwidth_mbps, Some(12.5));
    assert_eq!(summary.updated_at, "now");
    assert_eq!(serde_json::to_value(summary).unwrap()["future"], true);
}

#[test]
fn mediaflow_contracts_preserve_service_and_queue_extensions() {
    let service: MediaFlowServiceContract = serde_json::from_value(json!({
        "id":"sonarr","installed":true,"auto_configured":false,
        "wired":true,"webUiUrl":"/apps/sonarr","future":42
    }))
    .unwrap();
    assert_eq!(service.installed, Some(true));
    assert_eq!(service.auto_configured, Some(false));
    assert_eq!(service.wired, Some(true));
    assert_eq!(service.web_ui_url.as_deref(), Some("/apps/sonarr"));
    assert_eq!(serde_json::to_value(service).unwrap()["future"], 42);
    let jobs = vec![
        json!({"status":"PENDING_APPROVAL"}),
        json!({"status":"PROCESSING"}),
        json!({"status":"COMPLETED","originalSize":100,"newSize":40}),
        json!({"status":"COMPLETED","originalSize":20,"newSize":30}),
    ];
    let queue = MediaFlowQueueSummary::from_jobs(&jobs);
    assert_eq!((queue.queued, queue.pending, queue.processing), (4, 1, 1));
    assert_eq!(queue.saved_bytes, 60.0);
    let mut value = serde_json::to_value(queue).unwrap();
    value["future"] = json!("kept");
    let decoded: MediaFlowQueueSummary = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.extra["future"], "kept");
}

#[test]
fn partial_telemetry_adapts_to_shared_models_without_inventing_capacity() {
    let telemetry:Telemetry=serde_json::from_value(json!({"cpu_avg":12,"disks":[{"mountPoint":"/","totalGb":120,"usedGb":30}],"memory":{"total":64},"future":true})).unwrap();
    assert_eq!(telemetry.metrics().disks[0].total_gb, 120.0);
    assert_eq!(telemetry.metrics().cpu_usage, 12.0);
    assert_eq!(telemetry.extra["future"], true);
    assert!(decode::<Telemetry>(&Value::Null).disks.is_empty());
    let report = hardware(&json!({"cpu":{"model":"EPYC"},"storage":[{"model":"NVMe"}]}));
    assert_eq!(report.cpu.unwrap().model, "EPYC");
    assert_eq!(report.storage[0].model, "NVMe");
}
#[test]
fn nullable_counters_and_arbitrary_action_payloads_are_preserved() {
    let status: NetworkStatus = serde_json::from_value(
        serde_json::json!({"runner_available":true,"wireguard":null,"tailscale":null}),
    )
    .unwrap();
    assert_eq!(status.runner_available, Some(true));
    assert_eq!(status.extra["wireguard"], Value::Null);

    let node:ClusterNode=serde_json::from_value(serde_json::json!({"id":"worker","metrics":{"cpu_usage":"unavailable","mem_total_gb":64,"disk_used_gb":"12.5"}})).unwrap();
    assert_eq!(node.id, "worker");
    assert_eq!(node.metrics["cpu_usage"], None);
    assert_eq!(node.metrics["mem_total_gb"], Some(64.0));
    assert_eq!(node.metrics["disk_used_gb"], Some(12.5));
    let action:ActionApprovalRequest=serde_json::from_value(serde_json::json!({"id":7,"payload":"systemctl restart unit","parameters":["unit"],"future":{"id":42}})).unwrap();
    assert_eq!(action.payload, serde_json::json!("systemctl restart unit"));
    assert_eq!(action.parameters, serde_json::json!(["unit"]));
    assert_eq!(action.extra["future"]["id"], 42);
    let policy:McBrowserPolicy=serde_json::from_value(serde_json::json!({"scope":"media","permissions":{"read":true},"rules":[{"path":"private","allow":false}],"future":true})).unwrap();
    assert!(policy.permissions["read"]);
    assert!(!policy.rules[0].allow);
    assert_eq!(policy.extra["future"], true);
}
#[test]
fn domain_aliases_defaults_and_extensions_deserialize() {
    let user: UserRecord =
        serde_json::from_value(json!({"id":1,"totpEnabled":1,"isOauth":true,"custom":7})).unwrap();
    assert!(user.user().totp_enabled);
    assert!(user.user().is_oauth);
    assert_eq!(user.extra["custom"], 7);
    let ingress: IngressConfig = serde_json::from_value(
        json!({"app_name":"sonarr","public_domain":"media.example.com","tls_enabled":true}),
    )
    .unwrap();
    assert!(ingress.config().tls_enabled);
    assert_eq!(ingress.app_name, "sonarr");
    let quota: UserQuota =
        serde_json::from_value(json!({"userId":9,"quotaBytes":"1000","usedBytes":250})).unwrap();
    assert_eq!(quota.user_id, 9);
    assert_eq!(quota.quota_bytes, Some(1000));
    let audit: AuditLog =
        serde_json::from_value(json!({"targetId":42,"createdAt":"today","extra":true})).unwrap();
    assert_eq!(audit.target_id, "42");
    assert_eq!(audit.extra["extra"], true);
    let action: ActionApprovalRequest =
        serde_json::from_value(json!({"riskLevel":"high","parameters":{"service":"sonarr"}}))
            .unwrap();
    assert_eq!(action.risk_level, "high");
    assert_eq!(
        decode::<ActionScope>(&action.parameters).service,
        Some(json!("sonarr"))
    );
    let channel: NotificationChannel =
        serde_json::from_value(json!({"type":"telegram","config":{"chat_id":"42"}})).unwrap();
    assert_eq!(channel.kind, "telegram");
    let rule: NotificationRule =
        serde_json::from_value(json!({"conditionType":"cpu_usage","conditionValue":90})).unwrap();
    assert_eq!(rule.condition_value, "90");
    let node: ClusterNode =
        serde_json::from_value(json!({"id":7,"lastHeartbeat":"today","metrics":{"cpu_usage":12}}))
            .unwrap();
    assert_eq!(node.id, "7");
    assert_eq!(node.metrics["cpu_usage"], Some(12.0));
    let share: SharePolicyRecord =
        serde_json::from_value(json!({"id":5,"path":"a","custom":true})).unwrap();
    assert_eq!(share.id, "5");
    assert_eq!(share.extra["custom"], true);
}
