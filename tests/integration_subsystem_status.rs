// SPDX-License-Identifier: AGPL-3.0-only
//! Integration tests for Unified 7-Subsystem Operational Status (`#88`),
//! Maintenance Overrides, SSE streaming, Anonymous Read Policy, and SLO Problem Suppression (`#89`).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mu_auth::{RoleLeases, HEADER_FORWARDED_USER, HEADER_PROXY_SECRET};
use mu_observable_hub::{
    build_console_api_router, build_console_api_router_with_auth, CausalProblemsFeedResponse,
    HotDuckDbStore, IngressEngine, MuAuthFolioVerifier, ObsAuthVerifier, PlatformSubsystemId,
    SubsystemHealthState, SubsystemMaintenanceRequest, SubsystemOverrideMode, SubsystemStatusDto,
    SubsystemStatusRegistry, SubsystemsStatusResponse,
};
use mu_observable_ipc::OtelSpanEntry;
use serde_json::{json, Value};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

fn seed_problem_span(store: &HotDuckDbStore, trace_id: &str, service: &str, now_ts: i64) {
    store
        .insert_spans_batch(&[OtelSpanEntry {
            trace_id: trace_id.to_string(),
            span_id: format!("span-{trace_id}"),
            parent_span_id: None,
            service_name: service.to_string(),
            node_id: "worker-riscv64.example.invalid".to_string(),
            span_name: format!("{service}.op"),
            span_kind: "SERVER".to_string(),
            start_time_unix_nano: now_ts - 900_000_000,
            end_time_unix_nano: now_ts,
            duration_ns: 900_000_000, // 900 ms > p95 SLO threshold
            status_code: "ERROR".to_string(),
            status_message: Some(format!("SLO failure simulated on {service}")),
            attributes_json: r#"{"http.status_code":503}"#.to_string(),
        }])
        .expect("insert problem span");
}

#[tokio::test]
async fn test_subsystems_status_route_mounts_and_auto_live_defaults() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let router = build_console_api_router(store);

    for path in [
        "/api/obs/v1/status/subsystems",
        "/api/v1/status/subsystems",
        "/api/observe/status/subsystems",
        "/api/status/subsystems",
        "/api/v1/console/status/subsystems",
    ] {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("GET subsystems");
        assert_eq!(resp.status(), StatusCode::OK, "path={path}");
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );

        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: SubsystemsStatusResponse = serde_json::from_slice(&body).expect("JSON DTO");
        assert_eq!(parsed.total, 7);
        assert_eq!(parsed.subsystems.len(), 7);
        assert_eq!(parsed.overall_state, SubsystemHealthState::Live);
        assert_eq!(parsed.maintenance_active_count, 0);

        let ids: Vec<&str> = parsed.subsystems.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "ci",
                "cd",
                "ab_deploy",
                "repository",
                "observability",
                "model_runner",
                "platform"
            ]
        );
        for sub in &parsed.subsystems {
            assert_eq!(sub.mode, SubsystemOverrideMode::Auto);
            assert_eq!(sub.mode_label, "Auto (Live Probe)");
            assert_eq!(sub.state, SubsystemHealthState::Live);
            // Anonymous caller with system:status.read receives redacted generic text
            assert_eq!(sub.summary, "Operational");
            assert_eq!(sub.updated_by, None);
        }
    }
}

#[tokio::test]
async fn test_subsystems_anonymous_lockdown_returns_401() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let ingress = IngressEngine::new(store.clone(), "node-a".into());
    let locked_auth: Arc<dyn ObsAuthVerifier> =
        Arc::new(MuAuthFolioVerifier::with_anonymous_policy(false, false));
    let router = build_console_api_router_with_auth(store.clone(), ingress.clone(), locked_auth);

    for path in [
        "/api/obs/v1/status/subsystems",
        "/api/obs/v1/problems",
        "/api/obs/v1/smartscape",
        "/api/obs/v1/logs",
        "/api/obs/v1/traces",
        "/api/obs/v1/metrics",
        "/api/obs/v1/store/status",
        "/api/obs/v1/ingress/routes",
    ] {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "path={path}");
    }

    let strictly_locked: Arc<dyn ObsAuthVerifier> =
        Arc::new(MuAuthFolioVerifier::locked_down(Some("edge-secret-lock")));
    let strict_router = build_console_api_router_with_auth(store, ingress, strictly_locked);
    let resp = strict_router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/status/subsystems")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_maintenance_overrides_five_states_auth_sse_redaction_and_clear() {
    let _guard = ENV_LOCK.lock().await;
    let prev = std::env::var("MUOBSERVE_INGRESS_ADMIN_TOKEN").ok();
    std::env::set_var("MUOBSERVE_INGRESS_ADMIN_TOKEN", "ops-maint-secret-token");

    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let mut sse_rx = store.subscribe_events();
    let router = build_console_api_router(store);

    // 1. Unauthenticated maintenance PUT must fail closed with 401
    let unauth_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/subsystems/ci/maintenance")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "state": "in-maintenance" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid state -> 400, unknown subsystem -> 404
    let bad_state_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/subsystems/ci/maintenance")
                .header("authorization", "Bearer ops-maint-secret-token")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "state": "bogus-state" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_state_resp.status(), StatusCode::BAD_REQUEST);

    let unknown_sub_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/subsystems/unknown-sub/maintenance")
                .header("authorization", "Bearer ops-maint-secret-token")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "state": "in-maintenance" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unknown_sub_resp.status(), StatusCode::NOT_FOUND);

    // 3. Test all 5 states with sensitive strings redacted by PrivacyRedactor
    for target_state in [
        "in-maintenance",
        "partial-maintenance",
        "offline",
        "degraded",
        "live",
    ] {
        let put_resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/obs/v1/status/subsystems/model_runner/maintenance")
                    .header("authorization", "Bearer ops-maint-secret-token")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        json!({
                            "state": target_state,
                            "summary": "Node 10.42.19.8 reboot Authorization: Bearer secret_token_999 /Users/op/key",
                            "duration_secs": 300
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put_resp.status(), StatusCode::OK, "state={target_state}");
        let body = put_resp.into_body().collect().await.unwrap().to_bytes();
        let dto: SubsystemStatusDto = serde_json::from_slice(&body).unwrap();
        assert_eq!(dto.id, PlatformSubsystemId::ModelRunner);
        assert_eq!(dto.state.as_str(), target_state);
        assert_eq!(dto.mode, SubsystemOverrideMode::Manual);
        assert_eq!(dto.mode_label, "Manual Override");
        assert!(!dto.summary.contains("10.42.19.8"));
        assert!(!dto.summary.contains("secret_token_999"));
        assert!(!dto.summary.contains("/Users/op"));
        assert!(dto.expires_at_ms.is_some());

        // Verify SSE broadcast event arrived with `subsystem_status_changed`
        let raw_ev = tokio::time::timeout(Duration::from_secs(2), sse_rx.recv())
            .await
            .expect("SSE timeout")
            .expect("SSE broadcast");
        let ev_val: Value = serde_json::from_str(&raw_ev).unwrap();
        assert_eq!(ev_val["subsystem_status_changed"], Value::Bool(true));
        assert_eq!(ev_val["subsystem"], json!("model_runner"));
        assert_eq!(ev_val["state"], json!(target_state));
    }

    // 4. Authenticated GET sees full (privacy-redacted) summary; anonymous GET sees generic summary
    let auth_get = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/status/subsystems")
                .header("authorization", "Bearer ops-maint-secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(auth_get.status(), StatusCode::OK);
    let auth_snap: SubsystemsStatusResponse =
        serde_json::from_slice(&auth_get.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let mr_auth = auth_snap
        .subsystems
        .iter()
        .find(|s| s.id == PlatformSubsystemId::ModelRunner)
        .unwrap();
    assert!(mr_auth.summary.contains("reboot"));
    assert_eq!(mr_auth.updated_by.as_deref(), Some("operator-token"));

    // 5. Clear override back to "Auto (Live Probe)" via PUT {"mode": "auto"}
    let clear_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/subsystems/model_runner/maintenance")
                .header("authorization", "Bearer ops-maint-secret-token")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "mode": "auto" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(clear_resp.status(), StatusCode::OK);
    let cleared: SubsystemStatusDto =
        serde_json::from_slice(&clear_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(cleared.mode, SubsystemOverrideMode::Auto);
    assert_eq!(cleared.mode_label, "Auto (Live Probe)");
    assert_eq!(cleared.expires_at_ms, None);

    match prev {
        Some(v) => std::env::set_var("MUOBSERVE_INGRESS_ADMIN_TOKEN", v),
        None => std::env::remove_var("MUOBSERVE_INGRESS_ADMIN_TOKEN"),
    }
}

#[tokio::test]
async fn test_maintenance_window_suppresses_and_tags_slo_problems_and_sse() {
    let _guard = ENV_LOCK.lock().await;
    let prev = std::env::var("MUOBSERVE_INGRESS_ADMIN_TOKEN").ok();
    std::env::set_var("MUOBSERVE_INGRESS_ADMIN_TOKEN", "ops-maint-secret-token");

    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("maint_slo.duckdb");
    let store = HotDuckDbStore::open(Some(&db_path), None).expect("open store");
    let now_ts = 1_700_000_500_000_000_000i64;

    seed_problem_span(&store, "trace-ci-fail", "actionrunner-controller", now_ts);
    seed_problem_span(&store, "trace-repo-fail", "muregist", now_ts);
    seed_problem_span(&store, "trace-cd-fail", "muconde-controller", now_ts);

    let router = build_console_api_router(store.clone());

    // Baseline: all 3 services show open problems
    let base_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/problems")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(base_resp.status(), StatusCode::OK);
    let base_feed: CausalProblemsFeedResponse =
        serde_json::from_slice(&base_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(base_feed.open_count, 3);
    assert_eq!(base_feed.suppressed_count, 0);

    // Put CI -> in-maintenance, Repository -> partial-maintenance
    for (sub, state) in [
        ("ci", "in-maintenance"),
        ("repository", "partial-maintenance"),
    ] {
        let r = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/obs/v1/status/subsystems/{sub}/maintenance"))
                    .header("authorization", "Bearer ops-maint-secret-token")
                    .header("content-type", "application/json")
                    .body(Body::from(json!({ "state": state }).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
    }

    // Verify GET /api/obs/v1/problems suppresses CI and tags Repository while CD remains active
    let maint_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/problems")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let maint_feed: CausalProblemsFeedResponse =
        serde_json::from_slice(&maint_resp.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(maint_feed.suppressed_count, 1);
    assert_eq!(maint_feed.open_count, 2);
    assert_eq!(maint_feed.total, 2);
    assert_eq!(
        maint_feed.suppressed_problems[0].impacted_entity,
        "actionrunner-controller"
    );
    assert_eq!(
        maint_feed.suppressed_problems[0].maintenance_suppressed,
        Some(true)
    );
    assert_eq!(
        maint_feed.suppressed_problems[0]
            .maintenance_subsystem
            .as_deref(),
        Some("ci")
    );

    let repo_card = maint_feed
        .problems
        .iter()
        .find(|p| p.impacted_entity == "muregist")
        .expect("repository problem remains visible under partial-maintenance");
    assert_eq!(
        repo_card.maintenance_state.as_deref(),
        Some("partial-maintenance")
    );
    assert_eq!(
        repo_card.maintenance_subsystem.as_deref(),
        Some("repository")
    );
    assert_eq!(repo_card.maintenance_suppressed, Some(false));

    let cd_card = maint_feed
        .problems
        .iter()
        .find(|p| p.impacted_entity == "muconde-controller")
        .expect("CD problem remains untagged");
    assert_eq!(cd_card.maintenance_state, None);

    // Verify /api/obs/v1/events initial SSE snapshot excludes suppressed CI problem_opened
    // AND classifies subsystem_status_changed broadcast events properly
    let sse_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut body = sse_resp.into_body();
    let mut frames_text = String::new();
    for _ in 0..2 {
        let frame = tokio::time::timeout(Duration::from_secs(2), body.frame())
            .await
            .expect("SSE initial frame timeout")
            .expect("SSE stream present")
            .expect("SSE chunk ok");
        if let Some(data) = frame.data_ref() {
            frames_text.push_str(&String::from_utf8_lossy(data));
        }
    }
    assert!(
        !frames_text.contains("actionrunner-controller"),
        "Suppressed in-maintenance subsystem problem must not emit initial problem_opened SSE: {frames_text}"
    );
    assert!(frames_text.contains("event: problem_opened"));

    // Clear CI via DELETE and trigger transition SSE event on an active stream
    let del_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/obs/v1/status/subsystems/ci/maintenance")
                .header("authorization", "Bearer ops-maint-secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(del_resp.status(), StatusCode::OK);

    // Read next SSE event emitted by DELETE clear -> must carry `event: subsystem_status_changed`
    let live_ev = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(Ok(frame)) = body.frame().await {
                if let Some(data) = frame.data_ref() {
                    let s = String::from_utf8_lossy(data).into_owned();
                    if s.contains("subsystem_status_changed") {
                        return s;
                    }
                }
            }
        }
    })
    .await
    .expect("SSE subsystem_status_changed timeout");
    assert!(live_ev.contains("event: subsystem_status_changed"));
    assert!(live_ev.contains("Auto (Live Probe)"));

    // Verify cleared CI problem immediately restores in GET /api/obs/v1/problems
    let restored_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/problems")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let restored_feed: CausalProblemsFeedResponse = serde_json::from_slice(
        &restored_resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(restored_feed.open_count, 3);
    assert_eq!(restored_feed.suppressed_count, 0);

    // Verify DuckDB persistence across registry re-hydration (repository is still partial-maintenance)
    drop(router);
    let rehydrated = SubsystemStatusRegistry::new(store);
    let snap = rehydrated.snapshot(&[], false, None);
    let repo_status = snap
        .subsystems
        .iter()
        .find(|s| s.id == PlatformSubsystemId::Repository)
        .unwrap();
    assert_eq!(repo_status.state, SubsystemHealthState::PartialMaintenance);
    assert_eq!(repo_status.mode, SubsystemOverrideMode::Manual);

    // Verify clean validation of SubsystemMaintenanceRequest helper usage
    let _ = SubsystemMaintenanceRequest::default();

    match prev {
        Some(v) => std::env::set_var("MUOBSERVE_INGRESS_ADMIN_TOKEN", v),
        None => std::env::remove_var("MUOBSERVE_INGRESS_ADMIN_TOKEN"),
    }
}

fn epoch_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
}

#[tokio::test]
async fn test_mu_auth_public_status_only_redacts_and_locks_down_obs_and_writes() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let ingress = IngressEngine::new(store.clone(), "node-a".into());
    let verifier = Arc::new(MuAuthFolioVerifier::public_status_only(Some(
        "edge-secret-1",
    )));
    verifier.bind_principal(
        "ops-admin",
        1,
        &["viewer", "platform-admin"],
        RoleLeases::default(),
    );
    verifier
        .activate_timed_role("ops-admin", "platform-admin", true, epoch_ms_now())
        .expect("timed lease activated");

    let auth: Arc<dyn ObsAuthVerifier> = verifier;
    let router = build_console_api_router_with_auth(store, ingress, auth);

    // Authenticated platform-admin sets an override with sensitive summary text
    let put_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/subsystems/ci/maintenance")
                .header(HEADER_PROXY_SECRET, "edge-secret-1")
                .header(HEADER_FORWARDED_USER, "ops-admin")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "state": "in-maintenance",
                        "summary": "Node 192.0.2.9 maintenance Authorization: Bearer supersecret",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    // Anonymous caller has only folio:system:status -> 200 OK with generic redacted summary
    let anon_status = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/status/subsystems")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anon_status.status(), StatusCode::OK);
    let snap: SubsystemsStatusResponse =
        serde_json::from_slice(&anon_status.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    let ci = snap
        .subsystems
        .iter()
        .find(|s| s.id == PlatformSubsystemId::Ci)
        .unwrap();
    assert_eq!(ci.state, SubsystemHealthState::InMaintenance);
    assert_eq!(ci.summary, "Scheduled maintenance in progress");
    assert_eq!(ci.updated_by, None);

    // Anonymous observability read & mutation endpoints must fail closed (401)
    for (method, path) in [
        ("GET", "/api/obs/v1/problems"),
        ("GET", "/api/obs/v1/smartscape"),
        ("GET", "/api/obs/v1/logs"),
        ("GET", "/api/obs/v1/traces"),
        ("GET", "/api/obs/v1/metrics"),
        ("GET", "/api/obs/v1/store/status"),
        ("GET", "/api/obs/v1/ingress/routes"),
        ("POST", "/api/obs/v1/ingress/routes"),
        ("POST", "/api/obs/v1/ingress/tls"),
        ("PUT", "/api/obs/v1/status/subsystems/ci/maintenance"),
    ] {
        let mut req_builder = Request::builder().method(method).uri(path);
        if method == "POST" || method == "PUT" {
            req_builder = req_builder.header("content-type", "application/json");
        }
        let body = if method == "POST" || method == "PUT" {
            Body::from("{}")
        } else {
            Body::empty()
        };
        let resp = router
            .clone()
            .oneshot(req_builder.body(body).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert!(resp.headers().contains_key("www-authenticate"));
    }
}

#[tokio::test]
async fn test_mu_auth_edge_proxy_folios_passkey_and_timed_leases() {
    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let ingress = IngressEngine::new(store.clone(), "node-a".into());
    let verifier = Arc::new(MuAuthFolioVerifier::public_status_only(Some(
        "edge-secret-2",
    )));

    verifier.bind_principal(
        "nopasskey",
        0,
        &["viewer", "ingress-admin", "platform-admin"],
        RoleLeases::default(),
    );
    verifier.bind_principal("viewer-only", 1, &["viewer"], RoleLeases::default());
    verifier.bind_principal(
        "ingress-op",
        1,
        &["viewer", "ingress-admin"],
        RoleLeases::default(),
    );
    verifier
        .enable_elective_role("ingress-op", "ingress-admin")
        .expect("elective ingress-admin enabled");

    verifier.bind_principal(
        "platform-op",
        1,
        &["viewer", "platform-admin"],
        RoleLeases::default(),
    );
    verifier
        .activate_timed_role("platform-op", "platform-admin", true, epoch_ms_now())
        .expect("timed platform-admin activated");

    let auth: Arc<dyn ObsAuthVerifier> = verifier;
    let router = build_console_api_router_with_auth(store, ingress, auth);

    // 1. Spoofed x-forwarded-user without valid edge proxy secret fails closed
    for secret_opt in [None, Some("wrong-secret")] {
        let mut builder = Request::builder()
            .method("GET")
            .uri("/api/obs/v1/problems")
            .header(HEADER_FORWARDED_USER, "viewer-only");
        if let Some(secret) = secret_opt {
            builder = builder.header(HEADER_PROXY_SECRET, secret);
        }
        let resp = router
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // 2. Authenticated account with 0 Passkeys must fail closed (even on system:status.read)
    for uri in ["/api/obs/v1/status/subsystems", "/api/obs/v1/problems"] {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(HEADER_PROXY_SECRET, "edge-secret-2")
                    .header(HEADER_FORWARDED_USER, "nopasskey")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "uri={uri}");
    }

    // 3. Viewer reads all observability feeds (200) but cannot mutate ingress or maintenance (401)
    for uri in [
        "/api/obs/v1/problems",
        "/api/obs/v1/smartscape",
        "/api/obs/v1/traces",
        "/api/obs/v1/logs",
        "/api/obs/v1/metrics",
        "/api/obs/v1/store/status",
        "/api/obs/v1/ingress/routes",
        "/api/obs/v1/status/subsystems",
    ] {
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(HEADER_PROXY_SECRET, "edge-secret-2")
                    .header(HEADER_FORWARDED_USER, "viewer-only")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "viewer uri={uri}");
    }

    let viewer_maint_put = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/subsystems/ci/maintenance")
                .header(HEADER_PROXY_SECRET, "edge-secret-2")
                .header(HEADER_FORWARDED_USER, "viewer-only")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "state": "in-maintenance" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(viewer_maint_put.status(), StatusCode::UNAUTHORIZED);

    // 4. ingress-op can create ingress routes (201) but cannot modify maintenance (401)
    let create_route = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/obs/v1/ingress/routes")
                .header(HEADER_PROXY_SECRET, "edge-secret-2")
                .header(HEADER_FORWARDED_USER, "ingress-op")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "route_id": "folio-route-1",
                        "path_prefix": "/svc",
                        "upstream_url": "https://203.0.113.10:8443",
                        "service_name": "svc-a",
                        "strip_prefix": true,
                        "auth_required": true
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_route.status(), StatusCode::CREATED);

    let ingress_maint_put = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/subsystems/ci/maintenance")
                .header(HEADER_PROXY_SECRET, "edge-secret-2")
                .header(HEADER_FORWARDED_USER, "ingress-op")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "state": "in-maintenance" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ingress_maint_put.status(), StatusCode::UNAUTHORIZED);

    // 5. platform-op with timed lease can set and clear maintenance (200) and cannot create ingress routes (401)
    let platform_maint_put = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/subsystems/ci/maintenance")
                .header(HEADER_PROXY_SECRET, "edge-secret-2")
                .header(HEADER_FORWARDED_USER, "platform-op")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "state": "degraded", "summary": "Queue backlog elevated" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(platform_maint_put.status(), StatusCode::OK);
    let dto: SubsystemStatusDto = serde_json::from_slice(
        &platform_maint_put
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes(),
    )
    .unwrap();
    assert_eq!(dto.updated_by.as_deref(), Some("platform-op"));

    let platform_maint_del = router
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/api/obs/v1/status/subsystems/ci/maintenance")
                .header(HEADER_PROXY_SECRET, "edge-secret-2")
                .header(HEADER_FORWARDED_USER, "platform-op")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(platform_maint_del.status(), StatusCode::OK);

    let platform_ingress_post = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/obs/v1/ingress/routes")
                .header(HEADER_PROXY_SECRET, "edge-secret-2")
                .header(HEADER_FORWARDED_USER, "platform-op")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "route_id": "folio-route-denied",
                        "path_prefix": "/denied",
                        "upstream_url": "https://203.0.113.10:8443"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(platform_ingress_post.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_ingress_proxy_request_mu_auth_edge_and_spoofing() {
    let _guard = ENV_LOCK.lock().await;
    let prev_proxy = std::env::var("MUOBSERVE_PROXY_SECRET").ok();
    std::env::set_var("MUOBSERVE_PROXY_SECRET", "ingress-edge-secret");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().expect("local addr");
    let server_task = tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
            let _ = stream.shutdown().await;
        }
    });

    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let engine = IngressEngine::new(store, "node-a".into());
    engine.add_route(
        "r-edge",
        "/proxy-test",
        &format!("http://127.0.0.1:{}", addr.port()),
        "test-svc",
        true,
        true,
    );

    // Unauthenticated -> 401
    let unauth = engine
        .proxy_request(
            Request::builder()
                .method("GET")
                .uri("/proxy-test/ping")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauth.status(), StatusCode::UNAUTHORIZED);

    // Spoofed x-forwarded-user without valid x-proxy-secret -> 401
    let spoofed = engine
        .proxy_request(
            Request::builder()
                .method("GET")
                .uri("/proxy-test/ping")
                .header(HEADER_FORWARDED_USER, "admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(spoofed.status(), StatusCode::UNAUTHORIZED);

    let wrong_secret = engine
        .proxy_request(
            Request::builder()
                .method("GET")
                .uri("/proxy-test/ping")
                .header(HEADER_PROXY_SECRET, "wrong-secret")
                .header(HEADER_FORWARDED_USER, "admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(wrong_secret.status(), StatusCode::UNAUTHORIZED);

    // Valid mu-auth edge headers -> proxies to upstream 200 OK
    let authed = engine
        .proxy_request(
            Request::builder()
                .method("GET")
                .uri("/proxy-test/ping")
                .header(HEADER_PROXY_SECRET, "ingress-edge-secret")
                .header(HEADER_FORWARDED_USER, "admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authed.status(), StatusCode::OK);

    let _ = server_task.await;

    match prev_proxy {
        Some(v) => std::env::set_var("MUOBSERVE_PROXY_SECRET", v),
        None => std::env::remove_var("MUOBSERVE_PROXY_SECRET"),
    }
}
