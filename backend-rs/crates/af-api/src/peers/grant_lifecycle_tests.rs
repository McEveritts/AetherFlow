use super::*;
use crate::peers::grants::{
    cleanup_pending_received_grant_credentials, committed_received_grant_credential_id,
    read_committed_received_grant_token, retry_received_grant_cleanup_slot,
};
use std::collections::VecDeque;

type RunnerAction = Box<
    dyn FnMut(
            &FakePeerRunner,
            &PeerNetworkRequest,
        ) -> Option<Result<PeerNetworkResponse, PeerNetworkError>>
        + Send,
>;

struct BarrierConfig {
    entered: Arc<Notify>,
    release: Arc<Notify>,
}

struct ScriptedGrantRunner {
    inner: Arc<FakePeerRunner>,
    write_grant_actions: StdMutex<VecDeque<RunnerAction>>,
    delete_grant_actions: StdMutex<VecDeque<RunnerAction>>,
    write_grant_barrier: StdMutex<Option<BarrierConfig>>,
    post_write_grant_barrier: StdMutex<Option<BarrierConfig>>,
    write_grant_calls: AtomicUsize,
    delete_grant_calls: AtomicUsize,
}

impl ScriptedGrantRunner {
    fn new(inner: Arc<FakePeerRunner>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            write_grant_actions: StdMutex::new(VecDeque::new()),
            delete_grant_actions: StdMutex::new(VecDeque::new()),
            write_grant_barrier: StdMutex::new(None),
            post_write_grant_barrier: StdMutex::new(None),
            write_grant_calls: AtomicUsize::new(0),
            delete_grant_calls: AtomicUsize::new(0),
        })
    }

    fn push_write_grant_action(
        &self,
        action: impl FnMut(
                &FakePeerRunner,
                &PeerNetworkRequest,
            ) -> Option<Result<PeerNetworkResponse, PeerNetworkError>>
            + Send
            + 'static,
    ) {
        self.write_grant_actions
            .lock()
            .unwrap()
            .push_back(Box::new(action));
    }

    fn push_delete_grant_action(
        &self,
        action: impl FnMut(
                &FakePeerRunner,
                &PeerNetworkRequest,
            ) -> Option<Result<PeerNetworkResponse, PeerNetworkError>>
            + Send
            + 'static,
    ) {
        self.delete_grant_actions
            .lock()
            .unwrap()
            .push_back(Box::new(action));
    }

    fn arm_next_write_grant_barrier(&self) -> (Arc<Notify>, Arc<Notify>) {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *self.write_grant_barrier.lock().unwrap() = Some(BarrierConfig {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        (entered, release)
    }

    fn arm_next_post_write_grant_barrier(&self) -> (Arc<Notify>, Arc<Notify>) {
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *self.post_write_grant_barrier.lock().unwrap() = Some(BarrierConfig {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        (entered, release)
    }

    fn write_grant_calls(&self) -> usize {
        self.write_grant_calls.load(Ordering::SeqCst)
    }

    fn delete_grant_calls(&self) -> usize {
        self.delete_grant_calls.load(Ordering::SeqCst)
    }
}

impl PeerRunner for ScriptedGrantRunner {
    fn dispatch<'a>(
        &'a self,
        req: &'a PeerNetworkRequest,
    ) -> BoxFuture<'a, Result<PeerNetworkResponse, PeerNetworkError>> {
        Box::pin(async move {
            match req {
                PeerNetworkRequest::WriteCredential {
                    slot: PeerCredentialSlot::GrantToken,
                    ..
                } => {
                    self.write_grant_calls.fetch_add(1, Ordering::SeqCst);
                    let barrier = self.write_grant_barrier.lock().unwrap().take();
                    if let Some(cfg) = barrier {
                        cfg.entered.notify_waiters();
                        cfg.release.notified().await;
                    }
                    let action = self.write_grant_actions.lock().unwrap().pop_front();
                    let res = if let Some(mut act) = action {
                        match act(&self.inner, req) {
                            Some(override_res) => override_res,
                            None => self.inner.dispatch(req).await,
                        }
                    } else {
                        self.inner.dispatch(req).await
                    };
                    let post_barrier = self.post_write_grant_barrier.lock().unwrap().take();
                    if let Some(cfg) = post_barrier {
                        cfg.entered.notify_waiters();
                        cfg.release.notified().await;
                    }
                    return res;
                }
                PeerNetworkRequest::DeleteCredential {
                    slot: PeerCredentialSlot::GrantToken,
                    ..
                } => {
                    self.delete_grant_calls.fetch_add(1, Ordering::SeqCst);
                    let action = self.delete_grant_actions.lock().unwrap().pop_front();
                    if let Some(mut act) = action {
                        if let Some(override_res) = act(&self.inner, req) {
                            return override_res;
                        }
                    }
                }
                _ => {}
            }
            self.inner.dispatch(req).await
        })
    }
}

fn stub_services_management_router() -> axum::Router {
    axum::Router::new().route(
        "/api/v1/admin/services",
        axum::routing::get(|| async { (StatusCode::OK, Json(json!({ "ok": true }))) }),
    )
}

fn build_runtime_with_mgmt_override(
    name: &str,
    db_conn: Arc<StdMutex<Connection>>,
    runner: Arc<dyn PeerRunner>,
    public_transport: Arc<dyn PublicPairingTransport>,
    clock: &Arc<FakeClock>,
    bind_listener: bool,
    mgmt_router: Option<axum::Router>,
) -> Arc<PeerRuntime> {
    let (revocation_tx, _) = broadcast::channel(64);
    Arc::new(PeerRuntime {
        db: PeerDb::Isolated(db_conn),
        runner,
        public_transport,
        revocation_tx,
        pairing_rate_limiter: crate::peers::pairing::PairingRateLimiter::new(
            crate::peers::pairing::PAIRING_RATE_LIMIT_PER_MIN,
            Duration::from_secs(60),
        ),
        attempt_locks: KeyedAsyncLockPool::new(),
        link_locks: KeyedAsyncLockPool::new(),
        link_semaphores: StdMutex::new(HashMap::new()),
        link_ws_semaphores: StdMutex::new(HashMap::new()),
        tunnel_clients: StdMutex::new(HashMap::new()),
        proxy_tunnel_clients: StdMutex::new(HashMap::new()),
        listener_state: TokioMutex::new(None),
        health_shutdown: TokioMutex::new(None),
        clock: clock.as_fn(),
        monotonic_clock: clock.as_monotonic_fn(),
        lock_wait_timeout: PEER_LOCK_WAIT_TIMEOUT,
        listen_port: 0,
        max_conn_per_link: 64,
        max_ws_per_link: 16,
        proxy_header_timeout: Duration::from_secs(30),
        rtt_warn_ms: 25.0,
        server_name_override: Some(name.to_string()),
        version_override: Some("4.0.0-p5-test".to_string()),
        tunnel_binding: TunnelTransportBinding::LoopbackFixture,
        tunnel_request_timeout: Duration::from_secs(3),
        tunnel_port_overrides: RwLock::new(HashMap::new()),
        bind_listener_in_handlers: bind_listener,
        management_router_override: mgmt_router,
    })
}

fn all_grant_token_slots(runner: &FakePeerRunner) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = runner
        .state
        .lock()
        .unwrap()
        .credentials
        .iter()
        .filter(|((slot, _), _)| *slot == PeerCredentialSlot::GrantToken)
        .map(|((_, id), val)| (id.clone(), val.clone()))
        .collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

async fn assert_grant_token_works_for_services_read(
    caller: &Arc<PeerRuntime>,
    target_ip: IpAddr,
    link_token: &str,
    grant_token: &str,
) {
    let (st, body, _) = caller
        .send_tunnel_request_with_headers(
            Method::GET,
            &target_ip.to_string(),
            "/api/v1/admin/services",
            Some(&PeerCredentialSecret::new(link_token.to_string())),
            &[(HEADER_GRANT_TOKEN.to_string(), grant_token.to_string())],
            None,
            Duration::from_secs(2),
        )
        .await
        .expect("tunnel request should complete");
    assert_eq!(
        st,
        StatusCode::OK,
        "expected committed grant token to remain accepted, got {st}: {}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn failed_rotation_keeps_committed_slot_untouched_on_sqlite_and_double_failure() {
    let (ip_a, ip_b) = next_loopback_pair();
    let clock = FakeClock::new(1_804_100_000);
    let pk_a = fixture_wg_pubkey(201);
    let pk_b = fixture_wg_pubkey(202);

    let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let base_runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let runner_b = ScriptedGrantRunner::new(Arc::clone(&base_runner_b));

    let db_a = open_isolated_peer_db();
    let db_b = open_isolated_peer_db();

    let rt_b = build_runtime_with_mgmt_override(
        "rot-sql-b",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
        None,
    );
    let rt_a = build_runtime_with_mgmt_override(
        "rot-sql-a",
        Arc::clone(&db_a),
        Arc::clone(&base_runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 41], 45200)),
        }),
        &clock,
        true,
        Some(stub_services_management_router()),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "rot-sql-b").await;

    // 1. Establish initial active grant (gen 1: services read).
    let mut read_services = af_db::peers::AccessMap::none();
    read_services.services = af_db::peers::AccessLevel::Read;
    let (st, gen1_view) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": read_services })),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "gen1_view={gen1_view}");
    let gen1_id = gen1_view["inbound"]["id"].as_str().unwrap().to_string();

    let b_link_tok = base_runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .unwrap();
    let (rec_1, secret_1) = read_committed_received_grant_token(&rt_b, &b_link_id)
        .await
        .unwrap()
        .expect("B holds committed gen 1 token");
    let slot_1 = committed_received_grant_credential_id(&rec_1).to_string();
    let token_1 = secret_1.expose_secret().to_string();
    assert_ne!(slot_1, b_link_id, "new grants stage in distinct safe slot");
    assert_eq!(all_grant_token_slots(&base_runner_b).len(), 1);
    assert_grant_token_works_for_services_read(&rt_b, ip_a, &b_link_tok, &token_1).await;

    // 2. Abort SQLite UPDATE on B during gen 2 rotation. Verify the staged write targets a brand-new
    //    slot and NEVER touches `slot_1`.
    let captured_gen2 = Arc::new(StdMutex::new(None::<(String, String)>));
    let cap_clone = Arc::clone(&captured_gen2);
    let slot_1_check = slot_1.clone();
    runner_b.push_write_grant_action(move |_inner, req| {
        if let PeerNetworkRequest::WriteCredential { id, value, .. } = req {
            assert_ne!(
                id, &slot_1_check,
                "rotation must NEVER overwrite the last committed GrantToken file before commit"
            );
            *cap_clone.lock().unwrap() = Some((id.clone(), value.clone()));
        }
        None
    });

    {
        let conn = db_b.lock().unwrap();
        conn.execute_batch(
            "CREATE TRIGGER fail_received_grant_update
             BEFORE UPDATE ON peer_received_grants
             BEGIN
                 SELECT RAISE(ABORT, 'simulated sqlite commit failure');
             END;",
        )
        .unwrap();
    }

    let mut write_services = af_db::peers::AccessMap::none();
    write_services.services = af_db::peers::AccessLevel::Write;
    let (rot_st, rot_err) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": write_services })),
    )
    .await;
    assert_eq!(
        rot_st,
        StatusCode::INTERNAL_SERVER_ERROR,
        "rot_err={rot_err}"
    );

    let (slot_2, token_2) = captured_gen2
        .lock()
        .unwrap()
        .clone()
        .expect("rotation staged token_2 into a fresh slot");
    assert_ne!(slot_2, slot_1);
    assert_ne!(token_2, token_1);

    // Uncommitted `slot_2` was cleaned immediately while committed `slot_1` was never touched!
    assert!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_2)
            .is_none(),
        "uncommitted staged slot_2 must be removed on commit failure"
    );
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_1)
            .as_deref(),
        Some(token_1.as_str()),
        "committed slot_1 must remain untouched"
    );
    assert!(
        db_peers::list_peer_received_grant_cleanups(&db_b.lock().unwrap())
            .unwrap()
            .is_empty()
    );

    // 3. Double failure: BOTH SQLite commit fails AND runner DeleteCredential returns `Busy`!
    //    Prior committed `slot_1` MUST STILL remain completely intact and working, while the
    //    orphaned `slot_3` stays durably tracked for sweep/restart cleanup.
    let captured_slot_3 = Arc::new(StdMutex::new(None::<String>));
    let cap3 = Arc::clone(&captured_slot_3);
    runner_b.push_write_grant_action(move |_inner, req| {
        if let PeerNetworkRequest::WriteCredential { id, .. } = req {
            *cap3.lock().unwrap() = Some(id.clone());
        }
        None
    });
    runner_b.push_delete_grant_action(|_, _| {
        Some(Err(PeerNetworkError::Busy(
            "runner busy cleaning uncommitted staged slot".into(),
        )))
    });

    let (rot3_st, _) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": write_services })),
    )
    .await;
    assert_eq!(rot3_st, StatusCode::INTERNAL_SERVER_ERROR);
    let slot_3 = captured_slot_3.lock().unwrap().clone().unwrap();
    assert_ne!(slot_3, slot_1);

    // Prior active grant still works immediately despite BOTH SQLite and runner delete failing!
    let (rec_still_1, secret_still_1) = read_committed_received_grant_token(&rt_b, &b_link_id)
        .await
        .unwrap()
        .expect("committed gen 1 must still resolve after double failure");
    assert_eq!(rec_still_1.grant_id, gen1_id);
    assert_eq!(rec_still_1.generation, 1);
    assert_eq!(committed_received_grant_credential_id(&rec_still_1), slot_1);
    assert_eq!(secret_still_1.expose_secret(), token_1);
    assert_grant_token_works_for_services_read(&rt_b, ip_a, &b_link_tok, &token_1).await;

    // Orphaned `slot_3` is durably recorded in `peer_received_grant_cleanups` and cleaned on sweep.
    let cleanups =
        db_peers::list_peer_received_grant_cleanups_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap();
    assert_eq!(cleanups.len(), 1);
    assert_eq!(cleanups[0].credential_id, slot_3);

    cleanup_pending_received_grant_credentials(&rt_b).await;
    assert!(base_runner_b
        .credential(PeerCredentialSlot::GrantToken, &slot_3)
        .is_none());
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_1)
            .as_deref(),
        Some(token_1.as_str()),
        "sweep removing orphaned slot_3 must NEVER touch committed slot_1"
    );
    assert!(
        db_peers::list_peer_received_grant_cleanups(&db_b.lock().unwrap())
            .unwrap()
            .is_empty()
    );

    // Secrets must never leak into SQLite, audit logs, or HTTP error responses.
    let audit_blob = format!(
        "{}{}{}{:?}",
        rot_err,
        audit_entries_text(&db_a),
        audit_entries_text(&db_b),
        rec_still_1
    );
    assert!(!audit_blob.contains(&token_1));
    assert!(!audit_blob.contains(&token_2));

    // 4. Drop trigger and verify gen 4 rotation atomically swaps pointer and retires `slot_1`.
    {
        let conn = db_b.lock().unwrap();
        conn.execute_batch("DROP TRIGGER fail_received_grant_update;")
            .unwrap();
    }
    let (st4, gen4_view) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": write_services })),
    )
    .await;
    assert_eq!(st4, StatusCode::OK, "gen4_view={gen4_view}");
    let (rec_4, secret_4) = read_committed_received_grant_token(&rt_b, &b_link_id)
        .await
        .unwrap()
        .unwrap();
    let slot_4 = committed_received_grant_credential_id(&rec_4).to_string();
    assert_ne!(slot_4, slot_1);
    assert!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_1)
            .is_none(),
        "retired slot_1 must be deleted after promotion commits"
    );
    assert_eq!(all_grant_token_slots(&base_runner_b).len(), 1);
    assert_grant_token_works_for_services_read(&rt_b, ip_a, &b_link_tok, secret_4.expose_secret())
        .await;

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

#[tokio::test]
async fn crash_between_stage_and_commit_and_post_promotion_cleanup_recover_on_restart() {
    let (ip_a, ip_b) = next_loopback_pair();
    let clock = FakeClock::new(1_804_150_000);
    let pk_a = fixture_wg_pubkey(217);
    let pk_b = fixture_wg_pubkey(218);

    let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let base_runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let runner_b = ScriptedGrantRunner::new(Arc::clone(&base_runner_b));

    let db_a = open_isolated_peer_db();
    let db_b = open_isolated_peer_db();

    let rt_b = build_runtime_with_mgmt_override(
        "crash-stage-b",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
        None,
    );
    let rt_a = build_runtime_with_mgmt_override(
        "crash-stage-a",
        Arc::clone(&db_a),
        Arc::clone(&base_runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 49], 45208)),
        }),
        &clock,
        true,
        Some(stub_services_management_router()),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "crash-stage-b").await;

    // 1. Commit initial grant gen 1 (`slot_1`, `token_1`).
    let mut read_services = af_db::peers::AccessMap::none();
    read_services.services = af_db::peers::AccessLevel::Read;
    let (st, _) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": read_services })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (rec_1, secret_1) = read_committed_received_grant_token(&rt_b, &b_link_id)
        .await
        .unwrap()
        .unwrap();
    let slot_1 = committed_received_grant_credential_id(&rec_1).to_string();
    let token_1 = secret_1.expose_secret().to_string();
    let b_link_tok = base_runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .unwrap();

    // 2. Simulate abrupt process crash AFTER Phase 2 writes staged `slot_2` and BEFORE Phase 3
    //    commits SQLite!
    let staged_slot_2 = Arc::new(StdMutex::new(None::<String>));
    let cap2 = Arc::clone(&staged_slot_2);
    runner_b.push_write_grant_action(move |_inner, req| {
        if let PeerNetworkRequest::WriteCredential { id, .. } = req {
            *cap2.lock().unwrap() = Some(id.clone());
        }
        None
    });
    let (post_write_entered, _never_released) = runner_b.arm_next_post_write_grant_barrier();

    let rt_a_rot = Arc::clone(&rt_a);
    let a_grant_path = format!("/{a_link_id}/grant");
    let mut write_services = af_db::peers::AccessMap::none();
    write_services.services = af_db::peers::AccessLevel::Write;
    let write_services_spawn = write_services.clone();
    let rot_task = tokio::spawn(async move {
        call_admin(
            &rt_a_rot,
            Method::PUT,
            &a_grant_path,
            Some(json!({ "access": write_services_spawn })),
        )
        .await
    });

    // Wait deterministically until Phase 2 has written `slot_2` to the runner and paused right
    // before Phase 3 SQLite commit.
    tokio::time::timeout(Duration::from_secs(3), post_write_entered.notified())
        .await
        .expect("rotation should reach post-stage point before SQLite commit");

    // Abruptly stop B's listener/task to simulate API crash between stage and commit!
    if let Some(handle) = rt_b.listener_state.lock().await.take() {
        handle.task.abort();
        let _ = handle.task.await;
    }
    rot_task.abort();
    let _ = rot_task.await;

    let slot_2 = staged_slot_2
        .lock()
        .unwrap()
        .clone()
        .expect("slot_2 was written before crash");
    assert_ne!(slot_2, slot_1);
    assert!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_2)
            .is_some(),
        "orphaned staged slot_2 exists on disk after mid-rotation crash"
    );
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_1)
            .as_deref(),
        Some(token_1.as_str()),
        "committed slot_1 must survive crash between stage and commit untouched"
    );

    // 3. Restart B with a fresh PeerRuntime sharing the same SQLite DB & runner!
    let rt_b_restarted = build_runtime_with_mgmt_override(
        "crash-stage-b",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
        None,
    );
    // Bind fresh listener port and register on A for subsequent requests.
    start_with_runtime(Arc::clone(&rt_b_restarted)).await;
    let restarted_port = rt_b_restarted
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    rt_a.tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_b, restarted_port);
    let a_port = rt_a
        .listener_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .bound_addr
        .port();
    rt_b_restarted
        .tunnel_port_overrides
        .write()
        .unwrap()
        .insert(ip_a, a_port);

    // Restart recovery must have deleted orphaned `slot_2` while keeping committed `slot_1` working!
    assert!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_2)
            .is_none(),
        "restart recovery must delete orphaned uncommitted staged slot_2"
    );
    assert!(
        db_peers::list_peer_received_grant_cleanups(&db_b.lock().unwrap())
            .unwrap()
            .is_empty()
    );
    let (rec_after_restart, sec_after_restart) =
        read_committed_received_grant_token(&rt_b_restarted, &b_link_id)
            .await
            .unwrap()
            .expect("committed slot_1 remains readable after restart");
    assert_eq!(
        committed_received_grant_credential_id(&rec_after_restart),
        slot_1
    );
    assert_eq!(sec_after_restart.expose_secret(), token_1);
    assert_grant_token_works_for_services_read(&rt_b_restarted, ip_a, &b_link_tok, &token_1).await;

    // 4. Post-promotion transient retired-slot deletion failure: Phase 3 commits `slot_3` and
    //    queues `slot_1`; Phase 4 delete of `slot_1` hits `Busy`; sweep later deletes ONLY `slot_1`.
    runner_b.push_delete_grant_action(|_, _| {
        Some(Err(PeerNetworkError::Busy(
            "runner busy deleting retired slot_1 after promotion".into(),
        )))
    });
    let (st3, _) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": write_services })),
    )
    .await;
    assert_eq!(st3, StatusCode::OK);

    let (rec_3, sec_3) = read_committed_received_grant_token(&rt_b_restarted, &b_link_id)
        .await
        .unwrap()
        .unwrap();
    let slot_3 = committed_received_grant_credential_id(&rec_3).to_string();
    let token_3 = sec_3.expose_secret().to_string();
    assert_ne!(slot_3, slot_1);
    assert!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_1)
            .is_some(),
        "retired slot_1 remains pending durable sweep after transient Phase 4 delete failure"
    );
    let pending_after_promo =
        db_peers::list_peer_received_grant_cleanups_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap();
    assert_eq!(pending_after_promo.len(), 1);
    assert_eq!(pending_after_promo[0].credential_id, slot_1);

    // Sweep cleans up retired `slot_1` without deleting committed `slot_3`!
    cleanup_pending_received_grant_credentials(&rt_b_restarted).await;
    assert!(base_runner_b
        .credential(PeerCredentialSlot::GrantToken, &slot_1)
        .is_none());
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_3)
            .as_deref(),
        Some(token_3.as_str())
    );
    assert!(
        db_peers::list_peer_received_grant_cleanups(&db_b.lock().unwrap())
            .unwrap()
            .is_empty()
    );
    assert_grant_token_works_for_services_read(&rt_b_restarted, ip_a, &b_link_tok, &token_3).await;

    rt_b_restarted.shutdown_all().await;
    rt_a.shutdown_all().await;
}

#[tokio::test]
async fn legacy_canonical_compat_runner_contention_ambiguous_writes_and_newer_grant_protection() {
    let (ip_a, ip_b) = next_loopback_pair();
    let clock = FakeClock::new(1_804_200_000);
    let pk_a = fixture_wg_pubkey(203);
    let pk_b = fixture_wg_pubkey(204);

    let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let base_runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let runner_b = ScriptedGrantRunner::new(Arc::clone(&base_runner_b));

    let db_a = open_isolated_peer_db();
    let db_b = open_isolated_peer_db();

    let rt_b = build_runtime_with_mgmt_override(
        "rot-cont-b",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
        None,
    );
    let rt_a = build_runtime_with_mgmt_override(
        "rot-cont-a",
        Arc::clone(&db_a),
        Arc::clone(&base_runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 42], 45201)),
        }),
        &clock,
        true,
        Some(stub_services_management_router()),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "rot-cont-b").await;

    // 1. Issue gen 1, then migrate B's row in-place to simulate a pre-existing legacy canonical
    //    link-ID credential (`credential_id = NULL`, secret stored under `b_link_id`).
    let mut read_services = af_db::peers::AccessMap::none();
    read_services.services = af_db::peers::AccessLevel::Read;
    let (st, _) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": read_services })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (rec_1, sec_1) = read_committed_received_grant_token(&rt_b, &b_link_id)
        .await
        .unwrap()
        .unwrap();
    let old_slot_1 = committed_received_grant_credential_id(&rec_1).to_string();
    let token_1 = sec_1.expose_secret().to_string();
    {
        let mut st_runner = base_runner_b.state.lock().unwrap();
        st_runner
            .credentials
            .remove(&(PeerCredentialSlot::GrantToken, old_slot_1));
        st_runner.credentials.insert(
            (PeerCredentialSlot::GrantToken, b_link_id.clone()),
            token_1.clone(),
        );
    }
    {
        let conn = db_b.lock().unwrap();
        conn.execute(
            "UPDATE peer_received_grants SET credential_id = NULL WHERE link_id = ?1",
            rusqlite::params![b_link_id],
        )
        .unwrap();
    }

    // Helper must transparently resolve legacy canonical `link_id` slot!
    let (legacy_rec, legacy_sec) = read_committed_received_grant_token(&rt_b, &b_link_id)
        .await
        .unwrap()
        .expect("legacy canonical GrantToken must resolve");
    assert_eq!(legacy_rec.credential_id, None);
    assert_eq!(
        committed_received_grant_credential_id(&legacy_rec),
        b_link_id
    );
    assert_eq!(legacy_sec.expose_secret(), token_1);

    let b_link_tok = base_runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .unwrap();
    let mut write_services = af_db::peers::AccessMap::none();
    write_services.services = af_db::peers::AccessLevel::Write;

    // A. Runner contention (`Busy`) on forward staged WriteCredential: legacy canonical file untouched!
    runner_b.push_write_grant_action(|_, _| {
        Some(Err(PeerNetworkError::Busy(
            "credential lock busy during staged write".into(),
        )))
    });
    let deletes_before = runner_b.delete_grant_calls();
    let (st, err_a) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": write_services })),
    )
    .await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE, "err_a={err_a}");
    assert_eq!(err_a["code"], "PEER_BUSY");
    assert_eq!(runner_b.delete_grant_calls(), deletes_before);
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &b_link_id)
            .as_deref(),
        Some(token_1.as_str())
    );
    assert!(
        db_peers::list_peer_received_grant_cleanups(&db_b.lock().unwrap())
            .unwrap()
            .is_empty()
    );
    assert_grant_token_works_for_services_read(&rt_b, ip_a, &b_link_tok, &token_1).await;

    // B. Ambiguous forward write (`Runtime` AFTER mutating disk in staged slot): staged slot is
    //    cleaned while legacy canonical slot remains untouched!
    let mut_staged_id = Arc::new(StdMutex::new(None::<String>));
    let mut_cap = Arc::clone(&mut_staged_id);
    runner_b.push_write_grant_action(move |inner, req| {
        if let PeerNetworkRequest::WriteCredential { slot, id, value } = req {
            *mut_cap.lock().unwrap() = Some(id.clone());
            inner
                .state
                .lock()
                .unwrap()
                .credentials
                .insert((*slot, id.clone()), value.clone());
        }
        Some(Err(PeerNetworkError::Runtime(
            "runner socket reset after write".into(),
        )))
    });
    let (st, err_b) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": write_services })),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "err_b={err_b}");
    let ambig_slot = mut_staged_id.lock().unwrap().clone().unwrap();
    assert!(base_runner_b
        .credential(PeerCredentialSlot::GrantToken, &ambig_slot)
        .is_none());
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &b_link_id)
            .as_deref(),
        Some(token_1.as_str())
    );
    assert_grant_token_works_for_services_read(&rt_b, ip_a, &b_link_tok, &token_1).await;

    // C. Unconfirmed write acknowledgement (`written: false`) after mutating staged slot: fails
    //    closed, cleans staged slot, keeps legacy canonical slot intact!
    let unconf_staged_id = Arc::new(StdMutex::new(None::<String>));
    let unconf_cap = Arc::clone(&unconf_staged_id);
    runner_b.push_write_grant_action(move |inner, req| {
        if let PeerNetworkRequest::WriteCredential { slot, id, value } = req {
            *unconf_cap.lock().unwrap() = Some(id.clone());
            inner
                .state
                .lock()
                .unwrap()
                .credentials
                .insert((*slot, id.clone()), value.clone());
            return Some(Ok(PeerNetworkResponse::CredentialWritten(
                PeerCredentialWriteResponse {
                    slot: *slot,
                    id: id.clone(),
                    written: false,
                },
            )));
        }
        None
    });
    let (st, err_c) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": write_services })),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "err_c={err_c}");
    let unconf_slot = unconf_staged_id.lock().unwrap().clone().unwrap();
    assert!(base_runner_b
        .credential(PeerCredentialSlot::GrantToken, &unconf_slot)
        .is_none());
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &b_link_id)
            .as_deref(),
        Some(token_1.as_str())
    );

    // D. Successful rotation from legacy canonical slot promotes new staged slot AND retires legacy
    //    canonical `b_link_id` file!
    let (st_ok, _) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": write_services })),
    )
    .await;
    assert_eq!(st_ok, StatusCode::OK);
    let (promoted_rec, promoted_sec) = read_committed_received_grant_token(&rt_b, &b_link_id)
        .await
        .unwrap()
        .unwrap();
    let promoted_slot = committed_received_grant_credential_id(&promoted_rec).to_string();
    assert_ne!(promoted_slot, b_link_id);
    assert!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &b_link_id)
            .is_none(),
        "retired legacy canonical GrantToken must be cleaned up after promotion"
    );
    assert_grant_token_works_for_services_read(
        &rt_b,
        ip_a,
        &b_link_tok,
        promoted_sec.expose_secret(),
    )
    .await;

    // E. Defense-in-depth committed-slot guard: even if a stale cleanup row somehow references the
    //    active committed slot at an older generation, cleanup refuses to delete the runner file!
    {
        let conn = db_b.lock().unwrap();
        db_peers::upsert_peer_received_grant_cleanup(
            &conn,
            &b_link_id,
            &promoted_slot,
            promoted_rec.generation - 1,
            "2026-11-23T12:00:00Z",
        )
        .unwrap();
    }
    let deletes_before = runner_b.delete_grant_calls();
    cleanup_pending_received_grant_credentials(&rt_b).await;
    assert_eq!(
        runner_b.delete_grant_calls(),
        deletes_before,
        "cleanup sweep must NEVER call DeleteCredential on the active committed slot"
    );
    assert!(base_runner_b
        .credential(PeerCredentialSlot::GrantToken, &promoted_slot)
        .is_some());

    // F. Newer-grant protection: if a newer generation (gen 99, `slot_99`) becomes committed in
    //    SQLite before this rotation commits, rollback cleans ONLY its own uncommitted staged slot
    //    and NEVER touches or deletes `slot_99`!
    let db_b_hook = Arc::clone(&db_b);
    let b_link_hook = b_link_id.clone();
    let newer_slot = "grant-newer-99";
    let newer_token = "9999999999999999999999999999999999999999999999999999999999999999";
    let loser_staged_slot = Arc::new(StdMutex::new(None::<String>));
    let loser_cap = Arc::clone(&loser_staged_slot);
    runner_b.push_write_grant_action(move |inner, req| {
        if let PeerNetworkRequest::WriteCredential { slot, id, value } = req {
            *loser_cap.lock().unwrap() = Some(id.clone());
            {
                let mut st_r = inner.state.lock().unwrap();
                st_r.credentials.insert((*slot, id.clone()), value.clone());
                st_r.credentials.insert(
                    (PeerCredentialSlot::GrantToken, newer_slot.to_string()),
                    newer_token.to_string(),
                );
            }
            let conn = db_b_hook.lock().unwrap();
            db_peers::upsert_peer_received_grant(
                &conn,
                &db_peers::PeerReceivedGrant {
                    link_id: b_link_hook.clone(),
                    grant_id: "newer-grant-99".to_string(),
                    run_as_user_id: 77,
                    access: af_db::peers::AccessMap::read_write_all(),
                    created_by: "alice".to_string(),
                    created_at: "2026-11-23T12:00:00Z".to_string(),
                    generation: 99,
                    revoked_at: None,
                    credential_id: Some(newer_slot.to_string()),
                    updated_at: "2026-11-23T12:00:00Z".to_string(),
                },
            )
            .unwrap();
            return Some(Ok(PeerNetworkResponse::CredentialWritten(
                PeerCredentialWriteResponse {
                    slot: *slot,
                    id: id.clone(),
                    written: true,
                },
            )));
        }
        None
    });

    let (st, err_f) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": read_services })),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT, "err_f={err_f}");
    let loser_slot = loser_staged_slot.lock().unwrap().clone().unwrap();
    assert!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &loser_slot)
            .is_none(),
        "stale rotation's own uncommitted staged slot must be cleaned up"
    );
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, newer_slot)
            .as_deref(),
        Some(newer_token),
        "newer generation's committed slot must NEVER be overwritten or deleted"
    );
    let rec = db_peers::get_peer_received_grant(&db_b.lock().unwrap(), &b_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(rec.generation, 99);
    assert_eq!(rec.effective_credential_id(), newer_slot);

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}

#[tokio::test]
async fn concurrent_grant_receipt_synchronizes_with_link_revocation_cleanup_without_deadlock() {
    // ── Sub-case 1: Grant receipt acquires `link_lock` first, concurrent admin link delete waits
    //    and deletes BOTH LinkToken and the staged GrantToken slot.
    {
        let (ip_a, ip_b) = next_loopback_pair();
        let clock = FakeClock::new(1_804_300_000);
        let pk_a = fixture_wg_pubkey(207);
        let pk_b = fixture_wg_pubkey(208);

        let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
        let base_runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
        let runner_b = ScriptedGrantRunner::new(Arc::clone(&base_runner_b));

        let db_a = open_isolated_peer_db();
        let db_b = open_isolated_peer_db();

        let rt_b = build_runtime_with_mgmt_override(
            "sync-del-b",
            Arc::clone(&db_b),
            Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
            Arc::new(UnreachablePublicTransport),
            &clock,
            true,
            None,
        );
        let rt_a = build_runtime_with_mgmt_override(
            "sync-del-a",
            Arc::clone(&db_a),
            Arc::clone(&base_runner_a) as Arc<dyn PeerRunner>,
            Arc::new(RouterPublicTransport {
                target_runtime: Arc::clone(&rt_b),
                client_ip: SocketAddr::from(([198, 51, 100, 44], 45203)),
            }),
            &clock,
            true,
            None,
        );

        let (a_link_id, b_link_id, _) =
            pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "sync-del-b").await;

        let (entered, release) = runner_b.arm_next_write_grant_barrier();

        let rt_a_put = Arc::clone(&rt_a);
        let a_put_path = format!("/{a_link_id}/grant");
        let put_task = tokio::spawn(async move {
            call_admin(
                &rt_a_put,
                Method::PUT,
                &a_put_path,
                Some(json!({ "access": af_db::peers::AccessMap::read_only_all() })),
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(3), entered.notified())
            .await
            .expect("grant receipt should reach WriteCredential under link_lock");

        let rt_b_del = Arc::clone(&rt_b);
        let b_del_path = format!("/{b_link_id}");
        let mut del_task =
            tokio::spawn(
                async move { call_admin(&rt_b_del, Method::DELETE, &b_del_path, None).await },
            );

        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !del_task.is_finished(),
            "link deletion must wait on link_lock while grant receipt performs credential I/O"
        );

        release.notify_waiters();
        let (_put_res, del_res) = tokio::time::timeout(Duration::from_secs(5), async {
            let p = put_task.await.unwrap();
            let d = (&mut del_task).await.unwrap();
            (p, d)
        })
        .await
        .expect("concurrent grant receipt vs link delete must never deadlock");

        assert_eq!(del_res.0, StatusCode::OK, "del_res={:?}", del_res.1);
        assert!(
            all_grant_token_slots(&base_runner_b).is_empty(),
            "ZERO GrantToken slots may remain after concurrent link deletion: {:?}",
            all_grant_token_slots(&base_runner_b)
        );
        assert!(base_runner_b
            .credential(PeerCredentialSlot::LinkToken, &b_link_id)
            .is_none());
        assert!(db_peers::get_peer_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .is_none());

        rt_a.shutdown_all().await;
        rt_b.shutdown_all().await;
    }

    // ── Sub-case 2: Link revocation acquires `link_lock` first while a grant delivery already
    //    passed `authenticate_active_link`; grant receipt must revalidate and refuse to write.
    {
        let (ip_a, ip_b) = next_loopback_pair();
        let clock = FakeClock::new(1_804_310_000);
        let pk_a = fixture_wg_pubkey(209);
        let pk_b = fixture_wg_pubkey(210);

        let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
        let base_runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
        let runner_b = ScriptedGrantRunner::new(Arc::clone(&base_runner_b));

        let db_a = open_isolated_peer_db();
        let db_b = open_isolated_peer_db();

        let rt_b = build_runtime_with_mgmt_override(
            "sync-rev-b",
            Arc::clone(&db_b),
            Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
            Arc::new(UnreachablePublicTransport),
            &clock,
            true,
            None,
        );
        let rt_a = build_runtime_with_mgmt_override(
            "sync-rev-a",
            Arc::clone(&db_a),
            Arc::clone(&base_runner_a) as Arc<dyn PeerRunner>,
            Arc::new(RouterPublicTransport {
                target_runtime: Arc::clone(&rt_b),
                client_ip: SocketAddr::from(([198, 51, 100, 45], 45204)),
            }),
            &clock,
            true,
            None,
        );

        let (a_link_id, b_link_id, _) =
            pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "sync-rev-b").await;
        let a_link_tok = base_runner_a
            .credential(PeerCredentialSlot::LinkToken, &a_link_id)
            .unwrap();

        let held_guard = rt_b
            .lock_link(&b_link_id, "test_hold_link_lock")
            .await
            .unwrap();

        let rt_a_send = Arc::clone(&rt_a);
        let send_task = tokio::spawn(async move {
            rt_a_send
                .send_tunnel_request(
                    Method::POST,
                    &ip_b.to_string(),
                    "/peer/v1/grant-token",
                    Some(&PeerCredentialSecret::new(a_link_tok)),
                    Some(
                        serde_json::to_vec(&json!({
                            "grant_id": "late-after-revoke",
                            "run_as_user_id": 11,
                            "access": af_db::peers::AccessMap::read_only_all(),
                            "created_by": "alice",
                            "created_at": "2026-11-23T12:00:00Z",
                            "generation": 1,
                            "token": "abababababababababababababababababababababababababababababababab"
                        }))
                        .unwrap(),
                    ),
                    Duration::from_secs(3),
                )
                .await
        });

        // Wait deterministically until `authenticate_active_link` acquires the per-link permit
        // right before `handle_tunnel_grant_token_inner` blocks on `link_lock`.
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let permit_taken = rt_b
                    .link_semaphores
                    .lock()
                    .unwrap()
                    .get(&b_link_id)
                    .and_then(std::sync::Weak::upgrade)
                    .is_some_and(|sem| sem.available_permits() < rt_b.max_conn_per_link);
                if permit_taken {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("grant-token request should pass link auth and queue behind link_lock");
        assert!(!send_task.is_finished());

        {
            let conn = db_b.lock().unwrap();
            conn.execute(
                "UPDATE peer_links SET state = 'revoking', inbound_token_hash = NULL, pending_expires_at = 0 WHERE id = ?1",
                rusqlite::params![b_link_id],
            )
            .unwrap();
        }
        drop(held_guard);

        let (resp_st, resp_body, _) = tokio::time::timeout(Duration::from_secs(3), send_task)
            .await
            .expect("queued grant-token must complete once link_lock releases")
            .unwrap()
            .unwrap();
        assert_eq!(
            resp_st,
            StatusCode::FORBIDDEN,
            "queued grant-token must reject revoked link: {}",
            String::from_utf8_lossy(&resp_body)
        );
        let parsed: Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(parsed["code"], "LINK_REVOKED");
        assert_eq!(
            runner_b.write_grant_calls(),
            0,
            "must NEVER write GrantToken after link transitions to revoking/revoked"
        );
        assert!(all_grant_token_slots(&base_runner_b).is_empty());

        rt_a.shutdown_all().await;
        rt_b.shutdown_all().await;
    }

    // ── Sub-case 3: Reciprocal simultaneous PUT /grant AND remote revoke-notice vs in-flight
    //    grant rotation remain deadlock-free with zero surviving tokens after revocation.
    {
        let (ip_a, ip_b) = next_loopback_pair();
        let clock = FakeClock::new(1_804_320_000);
        let pk_a = fixture_wg_pubkey(211);
        let pk_b = fixture_wg_pubkey(212);

        let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
        let base_runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
        let runner_b = ScriptedGrantRunner::new(Arc::clone(&base_runner_b));

        let db_a = open_isolated_peer_db();
        let db_b = open_isolated_peer_db();

        let rt_b = build_runtime_with_mgmt_override(
            "sync-recip-b",
            Arc::clone(&db_b),
            Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
            Arc::new(UnreachablePublicTransport),
            &clock,
            true,
            None,
        );
        let rt_a = build_runtime_with_mgmt_override(
            "sync-recip-a",
            Arc::clone(&db_a),
            Arc::clone(&base_runner_a) as Arc<dyn PeerRunner>,
            Arc::new(RouterPublicTransport {
                target_runtime: Arc::clone(&rt_b),
                client_ip: SocketAddr::from(([198, 51, 100, 46], 45205)),
            }),
            &clock,
            true,
            None,
        );

        let (a_link_id, b_link_id, _) =
            pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "sync-recip-b").await;

        let path_a = format!("/{a_link_id}/grant");
        let path_b = format!("/{b_link_id}/grant");
        let (res_a, res_b) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                call_admin(
                    &rt_a,
                    Method::PUT,
                    &path_a,
                    Some(json!({ "access": af_db::peers::AccessMap::read_only_all() })),
                ),
                call_admin(
                    &rt_b,
                    Method::PUT,
                    &path_b,
                    Some(json!({ "access": af_db::peers::AccessMap::read_write_all() })),
                ),
            )
        })
        .await
        .expect("reciprocal PUT /grant must remain deadlock-free under unified link_lock");
        assert_eq!(res_a.0, StatusCode::OK, "res_a={:?}", res_a.1);
        assert_eq!(res_b.0, StatusCode::OK, "res_b={:?}", res_b.1);

        let (entered, release) = runner_b.arm_next_write_grant_barrier();
        let rt_a_rot = Arc::clone(&rt_a);
        let a_grant_path = format!("/{a_link_id}/grant");
        let rot_task = tokio::spawn(async move {
            call_admin(
                &rt_a_rot,
                Method::PUT,
                &a_grant_path,
                Some(json!({ "access": af_db::peers::AccessMap::read_write_all() })),
            )
            .await
        });

        tokio::time::timeout(Duration::from_secs(3), entered.notified())
            .await
            .expect("rotation should pause inside B's WriteCredential");

        let rt_a_del = Arc::clone(&rt_a);
        let a_del_path = format!("/{a_link_id}");
        let del_task =
            tokio::spawn(
                async move { call_admin(&rt_a_del, Method::DELETE, &a_del_path, None).await },
            );

        release.notify_waiters();
        let (_rot_res, del_res) = tokio::time::timeout(Duration::from_secs(5), async {
            let r = rot_task.await.unwrap();
            let d = del_task.await.unwrap();
            (r, d)
        })
        .await
        .expect("remote revoke-notice racing with grant rotation must not deadlock");
        assert_eq!(del_res.0, StatusCode::OK, "del_res={:?}", del_res.1);

        assert!(
            all_grant_token_slots(&base_runner_b).is_empty(),
            "B must have zero surviving GrantToken slots after remote revoke-notice cleanup: {:?}",
            all_grant_token_slots(&base_runner_b)
        );
        assert!(base_runner_b
            .credential(PeerCredentialSlot::LinkToken, &b_link_id)
            .is_none());
        let b_rec = db_peers::get_peer_received_grant(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .unwrap();
        assert!(b_rec.revoked_at.is_some());
        assert!(db_peers::list_peer_received_grant_cleanups_for_link(
            &db_b.lock().unwrap(),
            &b_link_id
        )
        .unwrap()
        .is_empty());

        rt_a.shutdown_all().await;
        rt_b.shutdown_all().await;
    }
}

#[tokio::test]
async fn grant_revoke_transient_delete_and_unverified_ack_recover_across_restart_and_sweep() {
    let (ip_a, ip_b) = next_loopback_pair();
    let clock = FakeClock::new(1_804_400_000);
    let pk_a = fixture_wg_pubkey(213);
    let pk_b = fixture_wg_pubkey(214);

    let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let base_runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let runner_b = ScriptedGrantRunner::new(Arc::clone(&base_runner_b));

    let db_a = open_isolated_peer_db();
    let db_b = open_isolated_peer_db();

    let rt_b = build_runtime_with_mgmt_override(
        "rev-dur-b",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
        None,
    );
    let rt_a = build_runtime_with_mgmt_override(
        "rev-dur-a",
        Arc::clone(&db_a),
        Arc::clone(&base_runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 47], 45206)),
        }),
        &clock,
        true,
        None,
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "rev-dur-b").await;

    // Establish BOTH directions: A->B (outbound on B) AND B->A (inbound on B).
    let (st, _) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": af_db::peers::AccessMap::read_only_all() })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, b_inbound_saved) = call_admin(
        &rt_b,
        Method::PUT,
        &format!("/{b_link_id}/grant"),
        Some(json!({ "access": af_db::peers::AccessMap::read_write_all() })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let b_inbound_grant_id = b_inbound_saved["inbound"]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let (rec_1, _) = read_committed_received_grant_token(&rt_b, &b_link_id)
        .await
        .unwrap()
        .unwrap();
    let slot_1 = committed_received_grant_credential_id(&rec_1).to_string();

    let a_link_tok = base_runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link_id)
        .unwrap();
    let b_link_tok = base_runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .unwrap();
    assert!(base_runner_b
        .credential(PeerCredentialSlot::GrantToken, &slot_1)
        .is_some());

    // 1. Direct `/peer/v1/grant-revoke` with transient runner `Busy` MUST NOT swallow the error,
    //    and MUST durably queue `slot_1` in `peer_received_grant_cleanups` alongside `revoked_at`.
    runner_b.push_delete_grant_action(|_, _| {
        Some(Err(PeerNetworkError::Busy(
            "runner busy deleting GrantToken".into(),
        )))
    });
    let (rev_st, rev_body, _) = rt_a
        .send_tunnel_request(
            Method::POST,
            &ip_b.to_string(),
            "/peer/v1/grant-revoke",
            Some(&PeerCredentialSecret::new(a_link_tok.clone())),
            Some(serde_json::to_vec(&json!({ "generation": 2 })).unwrap()),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(
        rev_st,
        StatusCode::SERVICE_UNAVAILABLE,
        "transient runner delete must not be swallowed: {}",
        String::from_utf8_lossy(&rev_body)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&rev_body).unwrap()["code"],
        "PEER_BUSY"
    );

    let b_rec = db_peers::get_peer_received_grant(&db_b.lock().unwrap(), &b_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(b_rec.generation, 2);
    assert!(b_rec.revoked_at.is_some());
    assert_eq!(b_rec.credential_id, None);
    let cleanups =
        db_peers::list_peer_received_grant_cleanups_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap();
    assert_eq!(cleanups.len(), 1);
    assert_eq!(cleanups[0].credential_id, slot_1);
    assert_eq!(cleanups[0].generation, 2);

    // Outbound view is already cleared while inbound grant on B is completely untouched.
    let (_, b_view) = call_admin(&rt_b, Method::GET, &format!("/{b_link_id}/grant"), None).await;
    assert!(b_view["outbound"].is_null());
    assert_eq!(b_view["inbound"]["id"], b_inbound_grant_id);

    // 2. Unverified/mismatched deletion ack (wrong slot) during health sweep MUST retain the
    //    durable cleanup row, and MUST keep link health, notifications, LinkToken, and inbound
    //    grant completely unaffected!
    base_runner_b.set_peer_live_state(&pk_a, true, Some(5));
    let notifs_before = notification_row_count(&db_b);
    runner_b.push_delete_grant_action(|_, req| {
        if let PeerNetworkRequest::DeleteCredential { id, .. } = req {
            return Some(Ok(PeerNetworkResponse::CredentialDeleted(
                PeerCredentialDeleteResponse {
                    slot: PeerCredentialSlot::LinkToken, // mismatched slot!
                    id: id.clone(),
                    deleted: true,
                },
            )));
        }
        None
    });

    run_health_tick(&rt_b).await;

    let cleanups_after_bad_ack =
        db_peers::list_peer_received_grant_cleanups_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap();
    assert_eq!(
        cleanups_after_bad_ack.len(),
        1,
        "unverified deletion ack must retain durable cleanup row"
    );
    assert!(base_runner_b
        .credential(PeerCredentialSlot::GrantToken, &slot_1)
        .is_some());
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::LinkToken, &b_link_id)
            .as_deref(),
        Some(b_link_tok.as_str())
    );
    let b_link_after_tick = db_peers::get_peer_link(&db_b.lock().unwrap(), &b_link_id)
        .unwrap()
        .unwrap();
    assert_eq!(b_link_after_tick.state, "active");
    assert_eq!(b_link_after_tick.consecutive_failures, 0);
    assert_eq!(
        notification_row_count(&db_b),
        notifs_before,
        "outbound grant credential cleanup failure must not emit link health notifications"
    );
    let b_inbound_after_tick =
        db_peers::get_active_peer_grant_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .expect("B's inbound grant must remain untouched");
    assert_eq!(b_inbound_after_tick.id, b_inbound_grant_id);

    // 3. Simulate restart on B (fresh PeerRuntime sharing same durable DB and recovered runner):
    //    `start_with_runtime` must retry cleanup, verify typed ack, delete `slot_1`, and clear row.
    rt_b.shutdown_all().await;
    let rt_b_restarted = build_runtime_with_mgmt_override(
        "rev-dur-b",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        false,
        None,
    );
    start_with_runtime(Arc::clone(&rt_b_restarted)).await;

    assert!(
        all_grant_token_slots(&base_runner_b).is_empty(),
        "restart recovery must delete revoked GrantToken once runner returns verified ack"
    );
    assert!(db_peers::list_peer_received_grant_cleanups_for_link(
        &db_b.lock().unwrap(),
        &b_link_id
    )
    .unwrap()
    .is_empty());
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::LinkToken, &b_link_id)
            .as_deref(),
        Some(b_link_tok.as_str())
    );
    assert_eq!(
        db_peers::get_active_peer_grant_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap()
            .unwrap()
            .id,
        b_inbound_grant_id
    );

    rt_b_restarted.shutdown_all().await;
    rt_a.shutdown_all().await;
}

#[tokio::test]
async fn stale_revoke_and_stale_cleanup_retry_never_delete_newer_grant_generation() {
    let (ip_a, ip_b) = next_loopback_pair();
    let clock = FakeClock::new(1_804_500_000);
    let pk_a = fixture_wg_pubkey(215);
    let pk_b = fixture_wg_pubkey(216);

    let base_runner_a = FakePeerRunner::new(pk_a.clone(), ip_a, 51821);
    let base_runner_b = FakePeerRunner::new(pk_b.clone(), ip_b, 51821);
    let runner_b = ScriptedGrantRunner::new(Arc::clone(&base_runner_b));

    let db_a = open_isolated_peer_db();
    let db_b = open_isolated_peer_db();

    let rt_b = build_runtime_with_mgmt_override(
        "stale-gen-b",
        Arc::clone(&db_b),
        Arc::clone(&runner_b) as Arc<dyn PeerRunner>,
        Arc::new(UnreachablePublicTransport),
        &clock,
        true,
        None,
    );
    let rt_a = build_runtime_with_mgmt_override(
        "stale-gen-a",
        Arc::clone(&db_a),
        Arc::clone(&base_runner_a) as Arc<dyn PeerRunner>,
        Arc::new(RouterPublicTransport {
            target_runtime: Arc::clone(&rt_b),
            client_ip: SocketAddr::from(([198, 51, 100, 48], 45207)),
        }),
        &clock,
        true,
        Some(stub_services_management_router()),
    );

    let (a_link_id, b_link_id, _) =
        pair_two_test_runtimes(&rt_a, &rt_b, ip_a, ip_b, "stale-gen-b").await;

    // 1. Issue gen 1 from A -> B (`slot_1`, `token_1`).
    let mut read_services = af_db::peers::AccessMap::none();
    read_services.services = af_db::peers::AccessLevel::Read;
    let (st, _) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": read_services })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (rec_1, sec_1) = read_committed_received_grant_token(&rt_b, &b_link_id)
        .await
        .unwrap()
        .unwrap();
    let slot_1 = committed_received_grant_credential_id(&rec_1).to_string();
    let token_1 = sec_1.expose_secret().to_string();

    // 2. Revoke gen 1 (bumping A epoch to gen 2) while B's runner transiently fails DeleteCredential.
    runner_b.push_delete_grant_action(|_, _| {
        Some(Err(PeerNetworkError::Busy(
            "transient runner busy on revoke gen 2".into(),
        )))
    });
    let (del_st, del_view) =
        call_admin(&rt_a, Method::DELETE, &format!("/{a_link_id}/grant"), None).await;
    assert_eq!(del_st, StatusCode::OK, "del_view={del_view}");

    let pending_cleanups =
        db_peers::list_peer_received_grant_cleanups_for_link(&db_b.lock().unwrap(), &b_link_id)
            .unwrap();
    assert_eq!(pending_cleanups.len(), 1);
    assert_eq!(pending_cleanups[0].credential_id, slot_1);
    assert_eq!(pending_cleanups[0].generation, 2);
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_1)
            .as_deref(),
        Some(token_1.as_str())
    );

    // 3. Before cleanup sweep runs, A issues a NEWER grant (gen 3) -> B commits `slot_3` (`token_3`).
    let (st3, gen3_view) = call_admin(
        &rt_a,
        Method::PUT,
        &format!("/{a_link_id}/grant"),
        Some(json!({ "access": read_services })),
    )
    .await;
    assert_eq!(st3, StatusCode::OK, "gen3_view={gen3_view}");
    let (rec_3, sec_3) = read_committed_received_grant_token(&rt_b, &b_link_id)
        .await
        .unwrap()
        .unwrap();
    let slot_3 = committed_received_grant_credential_id(&rec_3).to_string();
    let token_3 = sec_3.expose_secret().to_string();
    assert_ne!(slot_3, slot_1);
    assert_ne!(token_3, token_1);
    assert_eq!(rec_3.generation, 3);
    assert!(rec_3.revoked_at.is_none());

    // 4. Stale gen-2 `/peer/v1/grant-revoke` and stale cleanup retries MUST NOT delete `slot_3`,
    //    while sweep safely cleans up ONLY retired `slot_1`!
    let a_link_tok = base_runner_a
        .credential(PeerCredentialSlot::LinkToken, &a_link_id)
        .unwrap();
    let deletes_before_stale_rev = runner_b.delete_grant_calls();
    let (stale_rev_st, stale_rev_body, _) = rt_a
        .send_tunnel_request(
            Method::POST,
            &ip_b.to_string(),
            "/peer/v1/grant-revoke",
            Some(&PeerCredentialSecret::new(a_link_tok)),
            Some(serde_json::to_vec(&json!({ "generation": 2 })).unwrap()),
            Duration::from_secs(2),
        )
        .await
        .unwrap();
    assert_eq!(stale_rev_st, StatusCode::OK);
    let stale_rev_json: Value = serde_json::from_slice(&stale_rev_body).unwrap();
    assert_eq!(stale_rev_json["revoked"], false);
    assert_eq!(runner_b.delete_grant_calls(), deletes_before_stale_rev);

    // Attempting a stale cleanup retry targeting committed `slot_3` must do nothing.
    let stale_on_new_slot = retry_received_grant_cleanup_slot(&rt_b, &b_link_id, &slot_3, Some(2))
        .await
        .unwrap();
    assert!(!stale_on_new_slot);

    // Health tick / sweep removes ONLY retired `slot_1`, leaving committed `slot_3` (`token_3`) intact!
    base_runner_b.set_peer_live_state(&pk_a, true, Some(5));
    run_health_tick(&rt_b).await;

    assert!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_1)
            .is_none(),
        "retired slot_1 must be cleaned up by sweep"
    );
    assert!(db_peers::list_peer_received_grant_cleanups_for_link(
        &db_b.lock().unwrap(),
        &b_link_id
    )
    .unwrap()
    .is_empty());
    assert_eq!(
        base_runner_b
            .credential(PeerCredentialSlot::GrantToken, &slot_3)
            .as_deref(),
        Some(token_3.as_str()),
        "newer gen-3 GrantToken slot_3 must remain intact"
    );
    let b_link_tok = base_runner_b
        .credential(PeerCredentialSlot::LinkToken, &b_link_id)
        .unwrap();
    assert_grant_token_works_for_services_read(&rt_b, ip_a, &b_link_tok, &token_3).await;

    rt_a.shutdown_all().await;
    rt_b.shutdown_all().await;
}
