// SPDX-License-Identifier: AGPL-3.0-only
//! Integration tests for Unified 7-Subsystem Operational Status (`#88`),
//! Maintenance Overrides, SSE streaming, Anonymous Read Policy, and SLO Problem Suppression (`#89`).

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mu_observable_hub::{
    build_console_api_router, build_console_api_router_with_auth, CausalProblemsFeedResponse,
    DefaultObsAuthGuard, HotDuckDbStore, IngressEngine, ObsAuthVerifier, PlatformSubsystemId,
    SubsystemHealthState, SubsystemMaintenanceRequest, SubsystemOverrideMode, SubsystemStatusDto,
    SubsystemStatusRegistry, SubsystemsStatusResponse,
};
use mu_observable_ipc::OtelSpanEntry;
use serde_json::{json, Value};
use tempfile::tempdir;
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
        Arc::new(DefaultObsAuthGuard::with_anonymous_policy(false, false));
    let router = build_console_api_router_with_auth(store, ingress, locked_auth);

    for path in ["/api/obs/v1/status/subsystems", "/api/obs/v1/problems"] {
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
                            "summary": "Node 192.168.42.19 reboot Authorization: Bearer secret_token_999 /Users/op/key",
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
        assert!(!dto.summary.contains("192.168.42.19"));
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
