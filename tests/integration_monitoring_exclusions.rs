// SPDX-License-Identifier: AGPL-3.0-only
//! Integration tests for non-destructive monitoring exclusions (Maintainer Decision A1).
//!
//! Verifies that retired repositories (`__ar_console_registry__` & `MUOBSERVE_EXCLUDED_REPOS`),
//! retired service names (`MUOBSERVE_RETIRED_SERVICES`), pre-cutover telemetry floors
//! (`MUOBSERVE_MONITORING_SINCE_UNIX_NANO`), and persisted control state
//! (`__muobserve_monitoring_exclusions__` via `PUT /api/obs/v1/status/exclusions`) exclude
//! stale/retired items from causal problems, deterministic problems feed, and Smartscape while
//! retaining 100% of historical rows across `v_traces`, `v_logs`, `v_tests`, `v_benchmarks`, and
//! `v_jobs_history`.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mu_auth::{RoleLeases, HEADER_FORWARDED_USER, HEADER_PROXY_SECRET};
use mu_observable_hub::{
    build_console_api_router, build_console_api_router_with_auth, compute_causal_problems,
    compute_smartscape_topology, evaluate_deterministic_problems, execute_guarded_sql,
    CausalProblemsFeedResponse, HotDuckDbStore, IngressEngine, McpServer, MonitoringExclusions,
    MonitoringExclusionsStatus, MuAuthFolioVerifier, ObsAuthVerifier, SmartscapeTopology,
};
use mu_observable_ipc::{
    BenchmarkRunEntry, CentralJobRecord, CentralSubmoduleSnapshot, OtelLogEntry, OtelSpanEntry,
    QuerySubmoduleSnapshotsRequest, TestCaseRunEntry,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::const_new(());

struct EnvRestoreGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvRestoreGuard {
    fn capture(keys: &[&'static str]) -> Self {
        let saved = keys.iter().map(|&k| (k, std::env::var(k).ok())).collect();
        Self { saved }
    }
}

impl Drop for EnvRestoreGuard {
    fn drop(&mut self) {
        for (k, v) in &self.saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}

fn epoch_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
}

fn seed_bench_regression(store: &HotDuckDbStore, repo_key: &str, crate_name: &str, ts_ns: i64) {
    let mut runs = Vec::new();
    for i in 0..5 {
        runs.push(BenchmarkRunEntry {
            job_id: format!("job-base-{crate_name}-{i}"),
            repo_key: repo_key.into(),
            branch_key: "main".into(),
            commit_sha: format!("base-sha-{i}"),
            crate_name: crate_name.into(),
            bench_name: "hot_loop".into(),
            ns_per_iter: 1_000.0 + f64::from(i),
            std_dev_ns: 10.0,
            mad_ns: 5.0,
            p50_ns: 1_000.0,
            p95_ns: 1_010.0,
            p99_ns: 1_020.0,
            throughput_value: None,
            throughput_unit: None,
            arch: "riscv64gc".into(),
            cpu_cluster: "A100".into(),
            vlen_bits: 1024,
            timestamp_unix_nano: ts_ns - (10 - i64::from(i)) * 1_000_000_000,
            node_id: "worker-riscv64".into(),
        });
    }
    // Regressed candidate (+100%)
    runs.push(BenchmarkRunEntry {
        job_id: format!("job-cand-{crate_name}"),
        repo_key: repo_key.into(),
        branch_key: "feat/cand".into(),
        commit_sha: format!("cand-sha-{crate_name}"),
        crate_name: crate_name.into(),
        bench_name: "hot_loop".into(),
        ns_per_iter: 2_000.0,
        std_dev_ns: 15.0,
        mad_ns: 10.0,
        p50_ns: 2_000.0,
        p95_ns: 2_020.0,
        p99_ns: 2_030.0,
        throughput_value: None,
        throughput_unit: None,
        arch: "riscv64gc".into(),
        cpu_cluster: "A100".into(),
        vlen_bits: 1024,
        timestamp_unix_nano: ts_ns,
        node_id: "worker-riscv64".into(),
    });
    store.insert_benchmark_runs_batch(&runs).unwrap();
}

#[tokio::test]
async fn test_env_and_registry_exclusions_preserve_100pct_historical_rows() {
    let _guard = ENV_LOCK.lock().await;
    let _restore = EnvRestoreGuard::capture(&[
        "MUOBSERVE_EXCLUDED_REPOS",
        "MUOBSERVE_RETIRED_SERVICES",
        "MUOBSERVE_MONITORING_SINCE_UNIX_NANO",
    ]);
    std::env::remove_var("MUOBSERVE_EXCLUDED_REPOS");
    std::env::remove_var("MUOBSERVE_RETIRED_SERVICES");
    std::env::remove_var("MUOBSERVE_MONITORING_SINCE_UNIX_NANO");

    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let cutover_ns = 1_700_001_000_000_000_000i64;
    let pre_cutover_ns = cutover_ns - 60_000_000_000;
    let post_cutover_ns = cutover_ns + 60_000_000_000;

    // Without env vars or DB tombstones, exclusions must be empty so existing fixtures stay intact
    assert!(MonitoringExclusions::resolve(&store).is_empty());

    // Seed pre-cutover remediated mu-ingress 508/self-proxy error span + log AND retired service spans
    store
        .insert_spans_batch(&[
            OtelSpanEntry {
                trace_id: "trace-pre-ingress".into(),
                span_id: "span-pre-ingress".into(),
                parent_span_id: None,
                service_name: "mu-ingress".into(),
                node_id: "node-a".into(),
                span_name: "GET /api/obs/v1/causal-problems".into(),
                span_kind: "SERVER".into(),
                start_time_unix_nano: pre_cutover_ns - 900_000_000,
                end_time_unix_nano: pre_cutover_ns,
                duration_ns: 900_000_000,
                status_code: "ERROR".into(),
                status_message: Some("508 Loop Detected".into()),
                attributes_json: "{}".into(),
            },
            // Post-cutover healthy mu-ingress span
            OtelSpanEntry {
                trace_id: "trace-post-ingress".into(),
                span_id: "span-post-ingress".into(),
                parent_span_id: None,
                service_name: "mu-ingress".into(),
                node_id: "node-a".into(),
                span_name: "GET /api/obs/v1/status/subsystems/".into(),
                span_kind: "SERVER".into(),
                start_time_unix_nano: post_cutover_ns - 5_000_000,
                end_time_unix_nano: post_cutover_ns,
                duration_ns: 5_000_000,
                status_code: "OK".into(),
                status_message: None,
                attributes_json: "{}".into(),
            },
            // Retired service spans (both post-cutover and on an otherwise unused node)
            OtelSpanEntry {
                trace_id: "trace-retired-svc".into(),
                span_id: "span-retired-svc".into(),
                parent_span_id: None,
                service_name: "actionrunner-controller".into(),
                node_id: "retired-node".into(),
                span_name: "dispatch".into(),
                span_kind: "SERVER".into(),
                start_time_unix_nano: post_cutover_ns - 800_000_000,
                end_time_unix_nano: post_cutover_ns,
                duration_ns: 800_000_000,
                status_code: "ERROR".into(),
                status_message: Some("legacy error".into()),
                attributes_json: "{}".into(),
            },
            // Active service with error post-cutover (MUST still surface!)
            OtelSpanEntry {
                trace_id: "trace-active-err".into(),
                span_id: "span-active-err".into(),
                parent_span_id: None,
                service_name: "mu-ci-controller".into(),
                node_id: "node-b".into(),
                span_name: "webhook.handle".into(),
                span_kind: "SERVER".into(),
                start_time_unix_nano: post_cutover_ns - 700_000_000,
                end_time_unix_nano: post_cutover_ns,
                duration_ns: 700_000_000,
                status_code: "ERROR".into(),
                status_message: Some("active controller failure".into()),
                attributes_json: "{}".into(),
            },
        ])
        .unwrap();

    store
        .insert_logs_batch(&[
            OtelLogEntry {
                timestamp_unix_nano: pre_cutover_ns,
                trace_id: "trace-pre-ingress".into(),
                span_id: "span-pre-ingress".into(),
                severity_number: 21,
                severity_text: "FATAL".into(),
                service_name: "mu-ingress".into(),
                node_id: "node-a".into(),
                body: "pre-cutover self-proxy panic".into(),
                attributes_json: "{}".into(),
                job_id: None,
                stage_id: None,
            },
            OtelLogEntry {
                timestamp_unix_nano: post_cutover_ns,
                trace_id: "trace-retired-svc".into(),
                span_id: "span-retired-svc".into(),
                severity_number: 21,
                severity_text: "FATAL".into(),
                service_name: "actionrunner-rs".into(),
                node_id: "retired-node".into(),
                body: "legacy worker panic".into(),
                attributes_json: "{}".into(),
                job_id: None,
                stage_id: None,
            },
        ])
        .unwrap();

    // Benchmarks & tests for:
    // 1) retired via __ar_console_registry__ ("lma1980/k3-core")
    // 2) excluded via MUOBSERVE_EXCLUDED_REPOS ("old-crate")
    // 3) active ("lma1980/mu-ci-controller") with pre-cutover test failure + post-cutover pass, plus regressed bench
    seed_bench_regression(&store, "lma1980/k3-core", "k3-core", post_cutover_ns);
    seed_bench_regression(&store, "lma1980/old-crate", "old-crate", post_cutover_ns);
    seed_bench_regression(
        &store,
        "lma1980/mu-ci-controller",
        "mu-ci-controller",
        post_cutover_ns,
    );

    store
        .insert_test_runs_batch(&[
            TestCaseRunEntry {
                job_id: "job-ret-test".into(),
                repo_key: "lma1980/k3-core".into(),
                branch_key: "main".into(),
                commit_sha: "sha-ret".into(),
                crate_name: "k3-core".into(),
                test_binary: "k3_core".into(),
                test_name: "test_retired_fail".into(),
                status: "failed".into(),
                duration_ms: 5.0,
                failure_summary: Some("retired repo failure".into()),
                timestamp_unix_nano: post_cutover_ns,
                node_id: "worker-riscv64".into(),
                arch: "riscv64gc".into(),
            },
            // Active repo had a pre-cutover failure followed by a post-cutover pass
            TestCaseRunEntry {
                job_id: "job-pre-fail".into(),
                repo_key: "lma1980/mu-ci-controller".into(),
                branch_key: "main".into(),
                commit_sha: "sha-pre".into(),
                crate_name: "mu-ci-controller".into(),
                test_binary: "mu_ci_controller".into(),
                test_name: "test_pre_cutover_flake".into(),
                status: "failed".into(),
                duration_ms: 3.0,
                failure_summary: Some("pre-cutover flake".into()),
                timestamp_unix_nano: pre_cutover_ns,
                node_id: "node-a".into(),
                arch: "x86_64".into(),
            },
            TestCaseRunEntry {
                job_id: "job-post-ok".into(),
                repo_key: "lma1980/mu-ci-controller".into(),
                branch_key: "main".into(),
                commit_sha: "sha-post".into(),
                crate_name: "mu-ci-controller".into(),
                test_binary: "mu_ci_controller".into(),
                test_name: "test_pre_cutover_flake".into(),
                status: "ok".into(),
                duration_ms: 2.0,
                failure_summary: None,
                timestamp_unix_nano: post_cutover_ns,
                node_id: "node-a".into(),
                arch: "x86_64".into(),
            },
        ])
        .unwrap();

    // Seed historical CI jobs for retired & active repos
    store
        .upsert_ci_state_batch(
            &[
                CentralJobRecord {
                    job_id: "job-hist-retired".into(),
                    event_type: "push".into(),
                    repo_name: "LMA1980/k3-core".into(),
                    repo_key: "lma1980/k3-core".into(),
                    clone_url: "https://github.com/LMA1980/k3-core.git".into(),
                    commit_sha: "sha-ret".into(),
                    ref_name: "refs/heads/main".into(),
                    branch_key: "main".into(),
                    sender: "LMA1980".into(),
                    queued_at_us: 1_700_000_000_000_000,
                    updated_at_us: 1_700_000_010_000_000,
                    status_state: "Completed".into(),
                    exit_code: Some(0),
                    duration_secs: Some(10),
                    quality_score: Some(95),
                    letter_grade: Some("A".into()),
                    coverage_pct: Some(90.0),
                    benchmark_summary: None,
                    tests_passed: Some(10),
                    tests_total: Some(10),
                    advisories_count: Some(0),
                    clippy_warnings: Some(0),
                    record_json: "{}".into(),
                },
                CentralJobRecord {
                    job_id: "job-hist-active".into(),
                    event_type: "push".into(),
                    repo_name: "LMA1980/mu-ci-controller".into(),
                    repo_key: "lma1980/mu-ci-controller".into(),
                    clone_url: "https://github.com/LMA1980/mu-ci-controller.git".into(),
                    commit_sha: "sha-post".into(),
                    ref_name: "refs/heads/main".into(),
                    branch_key: "main".into(),
                    sender: "LMA1980".into(),
                    queued_at_us: 1_700_001_050_000_000,
                    updated_at_us: 1_700_001_060_000_000,
                    status_state: "Completed".into(),
                    exit_code: Some(0),
                    duration_secs: Some(10),
                    quality_score: Some(100),
                    letter_grade: Some("A+".into()),
                    coverage_pct: Some(95.0),
                    benchmark_summary: None,
                    tests_passed: Some(20),
                    tests_total: Some(20),
                    advisories_count: Some(0),
                    clippy_warnings: Some(0),
                    record_json: "{}".into(),
                },
            ],
            &[],
            &[CentralSubmoduleSnapshot {
                parent_repo_key: "__ar_console_registry__".into(),
                branch_key: "console".into(),
                submodule_key: "registry".into(),
                submodule_path_key: "console".into(),
                latest_active_job_id: Some("registry".into()),
                latest_active_json: Some(
                    r#"{"fabric_rev":9,"retired_repos":{"LMA1980/k3-core":"2026-11-17T00:00:00Z"}}"#
                        .into(),
                ),
                latest_active_queued_us: Some(1_700_001_000_000_000),
                latest_completed_job_id: None,
                latest_completed_json: None,
                latest_completed_queued_us: None,
            }],
        )
        .unwrap();

    // Configure env exclusions
    std::env::set_var("MUOBSERVE_EXCLUDED_REPOS", "old-crate");
    std::env::set_var(
        "MUOBSERVE_RETIRED_SERVICES",
        "action-runner-controller,actionrunner-controller,action-runner-worker,actionrunner-rs,muconde-controller,muconde-agent,muregist,musentinel",
    );
    std::env::set_var(
        "MUOBSERVE_MONITORING_SINCE_UNIX_NANO",
        cutover_ns.to_string(),
    );

    // 1. Causal problems: only active mu-ci-controller appears; pre-cutover mu-ingress & retired services excluded
    let causal = compute_causal_problems(&store, 3600, Some(post_cutover_ns)).unwrap();
    let causal_entities: Vec<&str> = causal.iter().map(|p| p.impacted_entity.as_str()).collect();
    assert_eq!(causal_entities, vec!["mu-ci-controller"]);

    // 2. Smartscape topology: retired services and retired-only hosts disappear; mu-ingress is healthy (0 errors)
    let topo = compute_smartscape_topology(&store, 3600, Some(post_cutover_ns)).unwrap();
    let svc_names: Vec<&str> = topo.services.iter().map(|s| s.name.as_str()).collect();
    assert!(svc_names.contains(&"mu-ingress"));
    assert!(svc_names.contains(&"mu-ci-controller"));
    assert!(!svc_names.contains(&"actionrunner-controller"));
    assert!(!svc_names.contains(&"actionrunner-rs"));
    let host_names: Vec<&str> = topo.hosts.iter().map(|h| h.name.as_str()).collect();
    assert!(!host_names.contains(&"retired-node"));
    let ingress_svc = topo
        .services
        .iter()
        .find(|s| s.name == "mu-ingress")
        .unwrap();
    assert_eq!(ingress_svc.error_count, 0);
    assert_eq!(ingress_svc.health_state, "healthy");

    // 3. Deterministic problems feed: excludes retired repos, retired services, pre-cutover mu-ingress & pre-cutover test flake
    let det = evaluate_deterministic_problems(&store, 3600, Some(post_cutover_ns)).unwrap();
    let det_entities: Vec<&str> = det
        .problems
        .iter()
        .map(|p| p.impacted_entity.as_str())
        .collect();
    assert!(!det_entities.contains(&"mu-ingress"));
    assert!(!det_entities.contains(&"actionrunner-controller"));
    assert!(!det_entities.contains(&"actionrunner-rs"));
    assert!(!det_entities.contains(&"lma1980/k3-core"));
    assert!(!det_entities.contains(&"lma1980/old-crate"));
    assert!(det
        .problems
        .iter()
        .any(|p| p.impacted_entity == "mu-ci-controller" && p.category == "error_rate_breach"));
    assert!(det.problems.iter().any(|p| {
        p.impacted_entity == "lma1980/mu-ci-controller" && p.category == "benchmark_regression"
    }));
    assert!(!det.problems.iter().any(|p| p.category == "test_flakiness"));

    // 4. HTTP router endpoints (/api/obs/v1/problems & /api/obs/v1/smartscape) match active exclusions
    let router = build_console_api_router(store.clone());
    let prob_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/problems?window_secs=3600")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prob_resp.status(), StatusCode::OK);
    let prob_feed: CausalProblemsFeedResponse =
        serde_json::from_slice(&prob_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(prob_feed
        .problems
        .iter()
        .all(|p| !p.impacted_entity.contains("k3-core")
            && !p.impacted_entity.contains("old-crate")
            && !p.impacted_entity.contains("actionrunner")
            && p.impacted_entity != "mu-ingress"));
    assert!(prob_feed
        .problems
        .iter()
        .any(|p| p.impacted_entity == "mu-ci-controller"));

    let sc_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/smartscape?window_secs=3600")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sc_resp.status(), StatusCode::OK);
    let sc_dto: SmartscapeTopology =
        serde_json::from_slice(&sc_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(sc_dto
        .services
        .iter()
        .all(|s| s.name != "actionrunner-controller" && s.name != "actionrunner-rs"));

    // 5. Maintainer Decision A1: 100% of historical rows MUST still exist in v_* views & guarded SQL / MCP
    assert_eq!(store.count_rows("v_traces").unwrap(), 4);
    assert_eq!(store.count_rows("v_logs").unwrap(), 2);
    assert_eq!(store.count_rows("v_tests").unwrap(), 3);
    assert_eq!(store.count_rows("v_benchmarks").unwrap(), 18);
    assert_eq!(store.count_rows("v_jobs_history").unwrap(), 2);

    let sql_res = execute_guarded_sql(
        &store,
        "SELECT COUNT(*) AS cnt FROM v_jobs_history WHERE repo_key = 'lma1980/k3-core'",
        10,
        Duration::from_secs(5),
    )
    .unwrap();
    assert_eq!(sql_res.rows[0][0], json!(1));

    let mcp = McpServer::new(store.clone());
    let mcp_sql = mcp
        .call_tool(
            "execute_analytics_sql",
            &json!({
                "sql": "SELECT COUNT(*) AS cnt FROM v_traces WHERE service_name = 'mu-ingress' AND status_code = 'ERROR'"
            }),
        )
        .unwrap();
    assert_eq!(mcp_sql["rows"][0][0], json!(1));
}

#[tokio::test]
async fn test_put_status_exclusions_auth_persistence_and_dynamic_registry_sync() {
    let _guard = ENV_LOCK.lock().await;
    let _restore = EnvRestoreGuard::capture(&[
        "MUOBSERVE_EXCLUDED_REPOS",
        "MUOBSERVE_RETIRED_SERVICES",
        "MUOBSERVE_MONITORING_SINCE_UNIX_NANO",
    ]);
    std::env::remove_var("MUOBSERVE_EXCLUDED_REPOS");
    std::env::remove_var("MUOBSERVE_RETIRED_SERVICES");
    std::env::remove_var("MUOBSERVE_MONITORING_SINCE_UNIX_NANO");

    let store = HotDuckDbStore::open_in_memory().expect("open store");
    let now_ts = 1_700_002_000_000_000_000i64;
    let pre_ts = now_ts - 30_000_000_000;

    store
        .insert_spans_batch(&[
            OtelSpanEntry {
                trace_id: "trace-dyn-pre".into(),
                span_id: "span-dyn-pre".into(),
                parent_span_id: None,
                service_name: "mu-ingress".into(),
                node_id: "node-a".into(),
                span_name: "GET /api/old".into(),
                span_kind: "SERVER".into(),
                start_time_unix_nano: pre_ts - 500_000_000,
                end_time_unix_nano: pre_ts,
                duration_ns: 500_000_000,
                status_code: "ERROR".into(),
                status_message: Some("pre-cutover".into()),
                attributes_json: "{}".into(),
            },
            OtelSpanEntry {
                trace_id: "trace-dyn-legacy".into(),
                span_id: "span-dyn-legacy".into(),
                parent_span_id: None,
                service_name: "muregist".into(),
                node_id: "node-b".into(),
                span_name: "manifest.get".into(),
                span_kind: "SERVER".into(),
                start_time_unix_nano: now_ts - 600_000_000,
                end_time_unix_nano: now_ts,
                duration_ns: 600_000_000,
                status_code: "ERROR".into(),
                status_message: Some("legacy registry error".into()),
                attributes_json: "{}".into(),
            },
        ])
        .unwrap();
    seed_bench_regression(&store, "lma1980/muregist", "muregist", now_ts);

    let ingress = IngressEngine::new(store.clone(), "node-a".into());
    let verifier = Arc::new(MuAuthFolioVerifier::public_status_only(Some(
        "edge-secret-exclusions",
    )));
    verifier.bind_principal("viewer-user", 1, &["viewer"], RoleLeases::default());
    verifier.bind_principal(
        "admin-user",
        1,
        &["viewer", "platform-admin"],
        RoleLeases::default(),
    );
    verifier
        .activate_timed_role("admin-user", "platform-admin", true, epoch_ms_now())
        .expect("timed role");

    let auth: Arc<dyn ObsAuthVerifier> = verifier;
    let router = build_console_api_router_with_auth(store.clone(), ingress, auth);

    // 1. Anonymous GET and PUT fail closed (401) under public_status_only
    let anon_get = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/status/exclusions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(anon_get.status(), StatusCode::UNAUTHORIZED);

    let viewer_put = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/exclusions")
                .header(HEADER_PROXY_SECRET, "edge-secret-exclusions")
                .header(HEADER_FORWARDED_USER, "viewer-user")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"retired_services": ["muregist"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(viewer_put.status(), StatusCode::UNAUTHORIZED);

    // 2. Negative timestamp rejected with 400 Bad Request
    let bad_put = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/exclusions")
                .header(HEADER_PROXY_SECRET, "edge-secret-exclusions")
                .header(HEADER_FORWARDED_USER, "admin-user")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"monitoring_since_unix_nano": -5}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_put.status(), StatusCode::BAD_REQUEST);

    // 3. Authenticated platform-admin persists exclusions via PUT /api/obs/v1/status/exclusions
    let ok_put = router
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/obs/v1/status/exclusions")
                .header(HEADER_PROXY_SECRET, "edge-secret-exclusions")
                .header(HEADER_FORWARDED_USER, "admin-user")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "excluded_repos": ["LMA1980/MuRegist"],
                        "retired_services": ["MuRegist"],
                        "monitoring_since_unix_nano": now_ts - 10_000_000_000i64
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_put.status(), StatusCode::OK);
    let status_dto: MonitoringExclusionsStatus =
        serde_json::from_slice(&ok_put.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(status_dto.excluded_repos.contains("lma1980/muregist"));
    assert!(status_dto.retired_services.contains("muregist"));
    assert_eq!(
        status_dto.persisted.updated_by.as_deref(),
        Some("admin-user")
    );

    // 4. Viewer can read GET /api/obs/v1/status/exclusions and sees persisted + dynamic registry exclusions
    let viewer_get = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/status/exclusions")
                .header(HEADER_PROXY_SECRET, "edge-secret-exclusions")
                .header(HEADER_FORWARDED_USER, "viewer-user")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(viewer_get.status(), StatusCode::OK);
    let body_val: Value =
        serde_json::from_slice(&viewer_get.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    assert_eq!(body_val["retired_services"], json!(["muregist"]));

    // 5. Problems feed & Smartscape reflect persisted exclusions immediately while v_* views retain all rows
    let prob_resp = router
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/obs/v1/problems?window_secs=3600")
                .header(HEADER_PROXY_SECRET, "edge-secret-exclusions")
                .header(HEADER_FORWARDED_USER, "viewer-user")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(prob_resp.status(), StatusCode::OK);
    let feed: CausalProblemsFeedResponse =
        serde_json::from_slice(&prob_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(feed.problems.is_empty());

    assert_eq!(store.count_rows("v_traces").unwrap(), 2);
    assert_eq!(store.count_rows("v_benchmarks").unwrap(), 6);

    // 6. Unfiltered query_submodule_snapshots never exposes __muobserve_monitoring_exclusions__
    let unfiltered = store
        .query_submodule_snapshots(&QuerySubmoduleSnapshotsRequest {
            request_id: "check".into(),
            parent_repo_key: None,
            submodule_key: None,
            branch_key: None,
        })
        .unwrap();
    assert!(unfiltered.is_empty());
}
