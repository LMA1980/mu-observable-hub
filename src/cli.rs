use std::path::{Path, PathBuf};
use std::time::Duration;

use duckdb::Connection;
use mu_observable_ipc::{
    CanarySloAssertionRequest, CentralBranchSnapshot, CentralJobRecord, CentralSubmoduleSnapshot,
    RegressionGateRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::analytics::{evaluate_canary_slo, evaluate_regression_gate};
use crate::config::{non_empty_env_first, resolve_parquet_root};
use crate::error::MuObserveError;
use crate::mcp::McpServer;
use crate::sql_guard::{execute_guarded_sql, DEFAULT_SQL_MAX_ROWS, DEFAULT_SQL_TIMEOUT_MS};
use crate::storage::hot_duckdb::HotDuckDbStore;
use crate::storage::parquet_compactor::{CompactorConfig, ParquetCompactor};
use crate::DEFAULT_HOT_RETENTION_DAYS;

/// Report returned by `migrate-actionrunner --from <path>` summarizing imported rows.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRunnerMigrationReport {
    pub jobs_imported: u32,
    pub branch_snapshots_imported: u32,
    pub submodule_snapshots_imported: u32,
}

/// Structured CLI subcommands supported by `mu-observable-hub-cli` (and `muobserve-cli`).
#[derive(Debug, Clone, PartialEq)]
pub enum CliCommand {
    MigrateActionRunner {
        from_path: PathBuf,
    },
    Compact {
        parquet_root: Option<PathBuf>,
        hot_retention_days: u32,
        raw_telemetry_ttl_days: u32,
        max_store_bytes: Option<u64>,
        min_free_disk_bytes: Option<u64>,
    },
    Regressions {
        repo_key: String,
        candidate_commit: String,
        baseline_branch: String,
        max_slowdown_pct: f64,
        max_flakiness_pct: f64,
    },
    Traces {
        trace_id: String,
    },
    Slo {
        service_name: String,
        candidate_digest: String,
        node_id: String,
        bake_window_secs: u64,
        max_error_logs: u32,
        max_p99_latency_ms: f64,
    },
    Sql {
        query: String,
        max_rows: usize,
    },
}

/// Losslessly imports `jobs_history`, `branch_snapshots`, and `submodule_snapshots` from a
/// legacy `actionrunner.duckdb` file into `MuObserve`'s `HotDuckDbStore`.
pub fn migrate_actionrunner_duckdb(
    store: &HotDuckDbStore,
    from_path: &Path,
) -> Result<ActionRunnerMigrationReport, MuObserveError> {
    if !from_path.exists() {
        return Err(MuObserveError::Validation(format!(
            "Source actionrunner.duckdb does not exist at '{}'",
            from_path.display()
        )));
    }

    let src_conn = Connection::open(from_path)?;

    let mut jobs = Vec::new();
    if table_exists(&src_conn, "jobs_history")? {
        let mut stmt = src_conn.prepare(
            r#"
            SELECT
                job_id, event_type, repo_name, repo_key, clone_url,
                commit_sha, ref_name, branch_key, sender, queued_at_us,
                updated_at_us, status_state, exit_code, duration_secs, quality_score,
                letter_grade, coverage_pct, benchmark_summary, tests_passed, tests_total,
                advisories_count, clippy_warnings, record_json
            FROM jobs_history
            ORDER BY queued_at_us ASC
            "#,
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(CentralJobRecord {
                job_id: r.get(0)?,
                event_type: r.get(1)?,
                repo_name: r.get(2)?,
                repo_key: r.get(3)?,
                clone_url: r.get(4)?,
                commit_sha: r.get(5)?,
                ref_name: r.get(6)?,
                branch_key: r.get(7)?,
                sender: r.get(8)?,
                queued_at_us: r.get(9)?,
                updated_at_us: r.get(10)?,
                status_state: r.get(11)?,
                exit_code: r.get(12)?,
                duration_secs: r.get(13)?,
                quality_score: r.get(14)?,
                letter_grade: r.get(15)?,
                coverage_pct: r.get(16)?,
                benchmark_summary: r.get(17)?,
                tests_passed: r.get(18)?,
                tests_total: r.get(19)?,
                advisories_count: r.get(20)?,
                clippy_warnings: r.get(21)?,
                record_json: r.get(22)?,
            })
        })?;
        for row in rows {
            jobs.push(row?);
        }
    }

    let mut branches = Vec::new();
    if table_exists(&src_conn, "branch_snapshots")? {
        let mut stmt = src_conn.prepare(
            r#"
            SELECT
                repo_key, branch_key, repo_name, ref_name,
                latest_active_job_id, latest_active_json, latest_active_queued_us,
                latest_completed_job_id, latest_completed_json, latest_completed_queued_us
            FROM branch_snapshots
            "#,
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(CentralBranchSnapshot {
                repo_key: r.get(0)?,
                branch_key: r.get(1)?,
                repo_name: r.get(2)?,
                ref_name: r.get(3)?,
                latest_active_job_id: r.get(4)?,
                latest_active_json: r.get(5)?,
                latest_active_queued_us: r.get(6)?,
                latest_completed_job_id: r.get(7)?,
                latest_completed_json: r.get(8)?,
                latest_completed_queued_us: r.get(9)?,
            })
        })?;
        for row in rows {
            branches.push(row?);
        }
    }

    let mut submodules = Vec::new();
    if table_exists(&src_conn, "submodule_snapshots")? {
        let mut stmt = src_conn.prepare(
            r#"
            SELECT
                parent_repo_key, branch_key, submodule_key, submodule_path_key,
                latest_active_job_id, latest_active_json, latest_active_queued_us,
                latest_completed_job_id, latest_completed_json, latest_completed_queued_us
            FROM submodule_snapshots
            "#,
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(CentralSubmoduleSnapshot {
                parent_repo_key: r.get(0)?,
                branch_key: r.get(1)?,
                submodule_key: r.get(2)?,
                submodule_path_key: r.get(3)?,
                latest_active_job_id: r.get(4)?,
                latest_active_json: r.get(5)?,
                latest_active_queued_us: r.get(6)?,
                latest_completed_job_id: r.get(7)?,
                latest_completed_json: r.get(8)?,
                latest_completed_queued_us: r.get(9)?,
            })
        })?;
        for row in rows {
            submodules.push(row?);
        }
    }

    store.upsert_ci_state_batch(&jobs, &branches, &submodules)?;

    Ok(ActionRunnerMigrationReport {
        jobs_imported: jobs.len() as u32,
        branch_snapshots_imported: branches.len() as u32,
        submodule_snapshots_imported: submodules.len() as u32,
    })
}

fn table_exists(conn: &Connection, table_name: &str) -> Result<bool, MuObserveError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ?1",
        duckdb::params![table_name],
        |r| r.get(0),
    )?;
    Ok(count > 0)
}

/// Parses command-line arguments (excluding `argv[0]`) into a `(Option<PathBuf>, CliCommand)` pair
/// where the first element is an optional `--db <path>` override.
pub fn parse_cli_args(args: &[String]) -> Result<(Option<PathBuf>, CliCommand), MuObserveError> {
    let mut db_path: Option<PathBuf> = None;
    let mut pre_parquet_root: Option<PathBuf> = None;
    let mut idx = 0;

    while idx < args.len() && matches!(args[idx].as_str(), "--db" | "--parquet-root") {
        let flag = args[idx].as_str();
        let Some(p) = args.get(idx + 1) else {
            return Err(MuObserveError::Validation(format!(
                "Missing path argument after {flag}"
            )));
        };
        if flag == "--db" {
            db_path = Some(PathBuf::from(p));
        } else {
            pre_parquet_root = Some(PathBuf::from(p));
        }
        idx += 2;
    }

    let Some(subcmd) = args.get(idx).map(String::as_str) else {
        return Err(MuObserveError::Validation(
            "Expected subcommand: migrate-actionrunner | compact | regressions | traces | slo | sql"
                .into(),
        ));
    };
    let extracted = extract_global_flags(&args[idx + 1..])?;
    if db_path.is_none() {
        db_path = extracted.db_path;
    }
    let parquet_root_override = extracted.parquet_root.or(pre_parquet_root);
    let rest = extracted.rest;

    let cmd = match subcmd {
        "migrate-actionrunner" => {
            let from = find_flag_value(&rest, "--from").ok_or_else(|| {
                MuObserveError::Validation("migrate-actionrunner requires --from <path>".into())
            })?;
            CliCommand::MigrateActionRunner {
                from_path: PathBuf::from(from),
            }
        }
        "compact" => {
            let hot_retention_days = find_flag_value(&rest, "--hot-retention-days")
                .and_then(|s| s.parse::<u32>().ok())
                .or_else(|| {
                    non_empty_env_first(&[
                        "MU_OBSERVABLE_HUB_HOT_RETENTION_DAYS",
                        "MU_OBSERVABLE_HOT_RETENTION_DAYS",
                        "MUOBSERVE_HOT_RETENTION_DAYS",
                    ])
                    .and_then(|s| s.parse::<u32>().ok())
                })
                .unwrap_or(DEFAULT_HOT_RETENTION_DAYS);
            let raw_telemetry_ttl_days = find_flag_value(&rest, "--raw-telemetry-ttl-days")
                .or_else(|| find_flag_value(&rest, "--ttl-days"))
                .and_then(|s| s.parse::<u32>().ok())
                .or_else(|| {
                    non_empty_env_first(&[
                        "MU_OBSERVABLE_HUB_RAW_TELEMETRY_TTL_DAYS",
                        "MU_OBSERVABLE_RAW_TELEMETRY_TTL_DAYS",
                        "MUOBSERVE_RAW_TELEMETRY_TTL_DAYS",
                    ])
                    .and_then(|s| s.parse::<u32>().ok())
                })
                .unwrap_or(60);
            let max_store_bytes = find_flag_value(&rest, "--max-store-bytes")
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| {
                    non_empty_env_first(&[
                        "MU_OBSERVABLE_HUB_MAX_STORE_BYTES",
                        "MU_OBSERVABLE_MAX_STORE_BYTES",
                        "MUOBSERVE_MAX_STORE_BYTES",
                    ])
                    .and_then(|s| s.parse::<u64>().ok())
                });
            let min_free_disk_bytes = find_flag_value(&rest, "--min-free-disk-bytes")
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| {
                    non_empty_env_first(&[
                        "MU_OBSERVABLE_HUB_MIN_FREE_DISK_BYTES",
                        "MU_OBSERVABLE_MIN_FREE_DISK_BYTES",
                        "MUOBSERVE_MIN_FREE_DISK_BYTES",
                    ])
                    .and_then(|s| s.parse::<u64>().ok())
                });
            CliCommand::Compact {
                parquet_root: parquet_root_override,
                hot_retention_days,
                raw_telemetry_ttl_days,
                max_store_bytes,
                min_free_disk_bytes,
            }
        }
        "regressions" => {
            let repo_key = find_flag_value(&rest, "--repo").ok_or_else(|| {
                MuObserveError::Validation("regressions requires --repo <repo_key>".into())
            })?;
            let candidate_commit = find_flag_value(&rest, "--commit").ok_or_else(|| {
                MuObserveError::Validation(
                    "regressions requires --commit <candidate_commit>".into(),
                )
            })?;
            let baseline_branch =
                find_flag_value(&rest, "--baseline").unwrap_or_else(|| "main".into());
            let max_slowdown_pct = find_flag_value(&rest, "--max-slowdown-pct")
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(5.0);
            let max_flakiness_pct = find_flag_value(&rest, "--max-flakiness-pct")
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(2.0);
            CliCommand::Regressions {
                repo_key,
                candidate_commit,
                baseline_branch,
                max_slowdown_pct,
                max_flakiness_pct,
            }
        }
        "traces" => {
            let trace_id = find_flag_value(&rest, "--trace-id")
                .or_else(|| rest.first().cloned())
                .ok_or_else(|| {
                    MuObserveError::Validation("traces requires --trace-id <trace_id>".into())
                })?;
            CliCommand::Traces { trace_id }
        }
        "slo" => {
            let service_name = find_flag_value(&rest, "--service").ok_or_else(|| {
                MuObserveError::Validation("slo requires --service <service_name>".into())
            })?;
            let candidate_digest =
                find_flag_value(&rest, "--digest").unwrap_or_else(|| "HEAD".into());
            let node_id = find_flag_value(&rest, "--node").unwrap_or_default();
            let bake_window_secs = find_flag_value(&rest, "--window-secs")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(300);
            let max_error_logs = find_flag_value(&rest, "--max-errors")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            let max_p99_latency_ms = find_flag_value(&rest, "--max-p99-ms")
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(250.0);
            CliCommand::Slo {
                service_name,
                candidate_digest,
                node_id,
                bake_window_secs,
                max_error_logs,
                max_p99_latency_ms,
            }
        }
        "sql" => {
            let query = find_flag_value(&rest, "--query")
                .or_else(|| rest.first().cloned())
                .ok_or_else(|| {
                    MuObserveError::Validation("sql requires --query <SELECT ...>".into())
                })?;
            let max_rows = find_flag_value(&rest, "--max-rows")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(DEFAULT_SQL_MAX_ROWS);
            CliCommand::Sql { query, max_rows }
        }
        other => {
            return Err(MuObserveError::Validation(format!(
                "Unknown subcommand '{other}'"
            )))
        }
    };

    Ok((db_path, cmd))
}

struct ExtractedGlobalFlags {
    db_path: Option<PathBuf>,
    parquet_root: Option<PathBuf>,
    rest: Vec<String>,
}

fn extract_global_flags(args: &[String]) -> Result<ExtractedGlobalFlags, MuObserveError> {
    const VALUE_FLAGS: &[&str] = &[
        "--from",
        "--repo",
        "--commit",
        "--baseline",
        "--max-slowdown-pct",
        "--max-flakiness-pct",
        "--trace-id",
        "--service",
        "--digest",
        "--node",
        "--window-secs",
        "--max-errors",
        "--max-p99-ms",
        "--query",
        "--max-rows",
        "--hot-retention-days",
        "--raw-telemetry-ttl-days",
        "--ttl-days",
        "--max-store-bytes",
        "--min-free-disk-bytes",
    ];
    let mut db_path: Option<PathBuf> = None;
    let mut parquet_root: Option<PathBuf> = None;
    let mut rest = Vec::with_capacity(args.len());
    let mut i = 0;

    while i < args.len() {
        let arg = args[i].as_str();
        if matches!(arg, "--db" | "--parquet-root") {
            let Some(val) = args.get(i + 1) else {
                return Err(MuObserveError::Validation(format!(
                    "Missing path argument after {arg}"
                )));
            };
            if arg == "--db" {
                db_path = Some(PathBuf::from(val));
            } else {
                parquet_root = Some(PathBuf::from(val));
            }
            i += 2;
            continue;
        }
        rest.push(args[i].clone());
        if VALUE_FLAGS.contains(&arg) {
            if let Some(val) = args.get(i + 1) {
                rest.push(val.clone());
                i += 2;
                continue;
            }
        }
        i += 1;
    }

    Ok(ExtractedGlobalFlags {
        db_path,
        parquet_root,
        rest,
    })
}

fn find_flag_value(args: &[String], flag: &str) -> Option<String> {
    for i in 0..args.len() {
        if args[i] == flag {
            return args.get(i + 1).cloned();
        }
    }
    None
}

/// Executes a parsed [`CliCommand`] against `store` and returns the structured JSON output.
pub fn execute_cli_command(
    store: &HotDuckDbStore,
    cmd: &CliCommand,
) -> Result<Value, MuObserveError> {
    match cmd {
        CliCommand::MigrateActionRunner { from_path } => {
            let report = migrate_actionrunner_duckdb(store, from_path)?;
            Ok(serde_json::to_value(report)?)
        }
        CliCommand::Compact {
            parquet_root,
            hot_retention_days,
            raw_telemetry_ttl_days,
            max_store_bytes,
            min_free_disk_bytes,
        } => {
            let resolved_root = parquet_root
                .clone()
                .or_else(|| store.parquet_root().map(Path::to_path_buf))
                .or_else(|| resolve_parquet_root(None, store.db_path(), false))
                .ok_or_else(|| {
                    MuObserveError::Validation(
                        "compact requires --parquet-root <path> or configured parquet root".into(),
                    )
                })?;
            let mut cfg = CompactorConfig::new(resolved_root)
                .with_hot_retention_days(*hot_retention_days)
                .with_raw_telemetry_ttl_days(*raw_telemetry_ttl_days);
            if let Some(max_bytes) = max_store_bytes {
                cfg = cfg.with_max_store_bytes(*max_bytes);
            }
            if let Some(min_free) = min_free_disk_bytes {
                cfg = cfg.with_min_free_disk_bytes(*min_free);
            }
            let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_else(|| {
                chrono::Utc::now()
                    .timestamp_millis()
                    .saturating_mul(1_000_000)
            });
            let report = ParquetCompactor::new(cfg).compact_at_now(store, now_ns)?;
            Ok(serde_json::to_value(report)?)
        }
        CliCommand::Regressions {
            repo_key,
            candidate_commit,
            baseline_branch,
            max_slowdown_pct,
            max_flakiness_pct,
        } => {
            let report = evaluate_regression_gate(
                store,
                &RegressionGateRequest {
                    request_id: "cli-regressions".into(),
                    repo_key: repo_key.clone(),
                    candidate_commit: candidate_commit.clone(),
                    baseline_branch: baseline_branch.clone(),
                    max_slowdown_pct: *max_slowdown_pct,
                    max_flakiness_pct: *max_flakiness_pct,
                },
            )?;
            Ok(serde_json::to_value(report)?)
        }
        CliCommand::Traces { trace_id } => {
            let mcp = McpServer::new(store.clone());
            let waterfall =
                mcp.call_tool("query_trace_waterfall", &json!({ "trace_id": trace_id }))?;
            let logs = mcp.call_tool(
                "correlate_logs_by_trace_id",
                &json!({ "trace_id": trace_id }),
            )?;
            Ok(json!({
                "waterfall": waterfall,
                "correlated_logs": logs
            }))
        }
        CliCommand::Slo {
            service_name,
            candidate_digest,
            node_id,
            bake_window_secs,
            max_error_logs,
            max_p99_latency_ms,
        } => {
            let resp = evaluate_canary_slo(
                store,
                &CanarySloAssertionRequest {
                    request_id: "cli-slo".into(),
                    service_name: service_name.clone(),
                    candidate_digest: candidate_digest.clone(),
                    node_id: node_id.clone(),
                    bake_window_secs: *bake_window_secs,
                    max_error_logs: *max_error_logs,
                    max_p99_latency_ms: *max_p99_latency_ms,
                },
                None,
            )?;
            Ok(serde_json::to_value(resp)?)
        }
        CliCommand::Sql { query, max_rows } => {
            let res = execute_guarded_sql(
                store,
                query,
                *max_rows,
                Duration::from_millis(DEFAULT_SQL_TIMEOUT_MS),
            )?;
            Ok(serde_json::to_value(res)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mu_observable_ipc::{
        QueryBranchSnapshotsRequest, QueryJobsHistoryRequest, QuerySubmoduleSnapshotsRequest,
    };
    use tempfile::tempdir;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_migrate_actionrunner_lossless_duckdb_import_and_cli_subcommands() {
        let dir = tempdir().expect("tempdir");
        let legacy_db_path = dir.path().join("actionrunner.duckdb");

        // Populate a fixture legacy actionrunner.duckdb
        let legacy_store =
            HotDuckDbStore::open(Some(&legacy_db_path), None).expect("open legacy db");
        let sample_job = CentralJobRecord {
            job_id: "legacy-job-42".into(),
            event_type: "push".into(),
            repo_name: "LMA1980/k3-core".into(),
            repo_key: "lma1980/k3-core".into(),
            clone_url: "https://github.com/LMA1980/k3-core.git".into(),
            commit_sha: "abcdef112233".into(),
            ref_name: "refs/heads/main".into(),
            branch_key: "main".into(),
            sender: "LMA1980".into(),
            queued_at_us: 1_700_000_000_000,
            updated_at_us: 1_700_000_030_000,
            status_state: "Completed".into(),
            exit_code: Some(0),
            duration_secs: Some(30),
            quality_score: Some(97),
            letter_grade: Some("A+".into()),
            coverage_pct: Some(92.0),
            benchmark_summary: Some("41.0 us".into()),
            tests_passed: Some(64),
            tests_total: Some(64),
            advisories_count: Some(0),
            clippy_warnings: Some(0),
            record_json: r#"{"id":"legacy-job-42"}"#.into(),
        };
        let sample_branch = CentralBranchSnapshot {
            repo_key: "lma1980/k3-core".into(),
            branch_key: "main".into(),
            repo_name: "LMA1980/k3-core".into(),
            ref_name: "refs/heads/main".into(),
            latest_active_job_id: None,
            latest_active_json: None,
            latest_active_queued_us: None,
            latest_completed_job_id: Some("legacy-job-42".into()),
            latest_completed_json: Some(r#"{"id":"legacy-job-42"}"#.into()),
            latest_completed_queued_us: Some(1_700_000_000_000),
        };
        let sample_submodule = CentralSubmoduleSnapshot {
            parent_repo_key: "lma1980/k3".into(),
            branch_key: "main".into(),
            submodule_key: "k3-core".into(),
            submodule_path_key: "core".into(),
            latest_active_job_id: None,
            latest_active_json: None,
            latest_active_queued_us: None,
            latest_completed_job_id: Some("legacy-job-42".into()),
            latest_completed_json: Some(r#"{"id":"legacy-job-42"}"#.into()),
            latest_completed_queued_us: Some(1_700_000_000_000),
        };
        legacy_store
            .upsert_ci_state_batch(
                std::slice::from_ref(&sample_job),
                std::slice::from_ref(&sample_branch),
                std::slice::from_ref(&sample_submodule),
            )
            .expect("seed legacy db");
        drop(legacy_store);

        // Now run migrate-actionrunner into a fresh MuObserve store
        let target_store = HotDuckDbStore::open_in_memory().expect("open target store");
        let args = vec![
            "migrate-actionrunner".to_string(),
            "--from".to_string(),
            legacy_db_path.to_string_lossy().to_string(),
        ];
        let (_, cmd) = parse_cli_args(&args).expect("parse cli args");
        let out = execute_cli_command(&target_store, &cmd).expect("execute migrate-actionrunner");
        let report: ActionRunnerMigrationReport = serde_json::from_value(out).unwrap();
        assert_eq!(
            report,
            ActionRunnerMigrationReport {
                jobs_imported: 1,
                branch_snapshots_imported: 1,
                submodule_snapshots_imported: 1,
            }
        );

        let imported_jobs = target_store
            .query_jobs_history(&QueryJobsHistoryRequest {
                request_id: "q1".into(),
                repo_key: Some("lma1980/k3-core".into()),
                branch_key: None,
                job_id: None,
                limit: 10,
            })
            .unwrap();
        assert_eq!(imported_jobs, vec![sample_job]);

        let imported_branches = target_store
            .query_branch_snapshots(&QueryBranchSnapshotsRequest {
                request_id: "q2".into(),
                repo_key: Some("lma1980/k3-core".into()),
                branch_key: Some("main".into()),
            })
            .unwrap();
        assert_eq!(imported_branches, vec![sample_branch]);

        let imported_submodules = target_store
            .query_submodule_snapshots(&QuerySubmoduleSnapshotsRequest {
                request_id: "q3".into(),
                parent_repo_key: Some("lma1980/k3".into()),
                submodule_key: Some("k3-core".into()),
                branch_key: Some("main".into()),
            })
            .unwrap();
        assert_eq!(imported_submodules, vec![sample_submodule]);

        // Verify sql, traces, regressions, and slo subcommands parse and execute cleanly
        let (_, sql_cmd) = parse_cli_args(&[
            "sql".into(),
            "--query".into(),
            "SELECT job_id FROM v_jobs_history".into(),
        ])
        .unwrap();
        let sql_res = execute_cli_command(&target_store, &sql_cmd).unwrap();
        assert_eq!(sql_res["row_count"], 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_compact_cli_subcommand_and_post_subcommand_flags() {
        use crate::storage::parquet_compactor::CompactionReport;
        use mu_observable_ipc::OtelLogEntry;

        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("hot.duckdb");
        let parquet_root = dir.path().join("parquet");

        let (parsed_db, parsed_cmd) = parse_cli_args(&[
            "compact".into(),
            "--db".into(),
            db_path.to_string_lossy().into_owned(),
            "--parquet-root".into(),
            parquet_root.to_string_lossy().into_owned(),
        ])
        .expect("parse compact post-subcommand flags");
        assert_eq!(parsed_db.as_deref(), Some(db_path.as_path()));
        assert!(matches!(
            parsed_cmd,
            CliCommand::Compact {
                parquet_root: Some(ref pr),
                hot_retention_days: 7,
                raw_telemetry_ttl_days: 60,
                ..
            } if pr == &parquet_root
        ));

        let store = HotDuckDbStore::open(Some(&db_path), Some(&parquet_root)).expect("open duckdb");
        let now_ns = chrono::Utc::now().timestamp_nanos_opt().unwrap_or_else(|| {
            chrono::Utc::now()
                .timestamp_millis()
                .saturating_mul(1_000_000)
        });
        let aged_within_ttl_ts = now_ns - (10 * 86_400 * 1_000_000_000i64);
        store
            .insert_logs(&[OtelLogEntry {
                timestamp_unix_nano: aged_within_ttl_ts,
                trace_id: "tr-compact-1".into(),
                span_id: "sp-compact-1".into(),
                severity_number: 9,
                severity_text: "INFO".into(),
                service_name: "mu-observable-hub".into(),
                node_id: "node-a".into(),
                body: "aged compaction line".into(),
                attributes_json: "{}".into(),
                job_id: None,
                stage_id: None,
            }])
            .expect("insert aged log");

        let out = execute_cli_command(&store, &parsed_cmd).expect("execute compact");
        let report: CompactionReport = serde_json::from_value(out).expect("parse CompactionReport");
        assert_eq!(report.exported_logs, 1);
        assert_eq!(report.ttl_pruned_files, 0);
        assert_eq!(store.count_rows("otel_logs").unwrap(), 0);
        assert_eq!(store.count_rows("v_logs").unwrap(), 1);
    }
}
