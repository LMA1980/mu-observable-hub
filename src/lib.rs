//! `mu-observable-hub`: Distributed OTEL + DuckDB/Parquet observability backend, centralized
//! `ActionRunner-controller` state catalog, hardware-aware benchmark & test regression
//! analytics engine, and Antigravity Model Context Protocol (MCP) server.

pub mod analytics;
pub mod cli;
pub mod config;
pub mod error;
pub mod ingress;
pub mod mcp;
pub mod server;
pub mod sql_guard;
pub mod storage;

pub use ingress::{
    IngressEngine, IngressOverviewDto, IngressRouteDto, IngressUpstreamDto, TlsHealthDto,
    UpstreamHealthChecker,
};

/// Default hot DuckDB retention window in days before cold Zstd Parquet compaction.
pub const DEFAULT_HOT_RETENTION_DAYS: u32 = 7;

pub use analytics::{
    compute_active_failing_tests_with_min_ts, compute_causal_problems,
    compute_causal_problems_with_exclusions, compute_purepath_waterfall,
    compute_smartscape_topology, compute_smartscape_topology_with_exclusions,
    compute_test_flakiness, compute_test_flakiness_with_min_ts, evaluate_benchmark_regressions,
    evaluate_canary_slo, evaluate_deterministic_problems,
    evaluate_deterministic_problems_with_exclusions, evaluate_regression_gate,
    generate_statistical_diagnosis, is_batch_ci_execution_span, is_child_ci_context_attributes,
    is_ci_regression_problem_category, is_user_ci_failure_span, list_trace_summaries,
    synthesize_ai_diagnosis, CausalProblemCard, CausalProblemsFeedResponse, FlakyTestItem,
    MonitoringExclusions, MonitoringExclusionsStatus, MonitoringExclusionsUpdateRequest,
    PersistedMonitoringExclusions, ProblemCard, ProblemSummary, ProblemsFeedResponse,
    PurePathLogEntry, PurePathMetricEntry, PurePathResponse, PurePathSpanNode, SmartscapeEdge,
    SmartscapeHostNode, SmartscapeProcessNode, SmartscapeServiceNode, SmartscapeTopology,
    TraceListFilter, TraceListQuery, TraceListResponse, TraceSummaryDto,
    DEFAULT_SMARTSCAPE_WINDOW_SECS,
};
pub use cli::{
    execute_cli_command, migrate_actionrunner_duckdb, parse_cli_args, ActionRunnerMigrationReport,
    CliCommand,
};
pub use config::{
    env_var_first, non_empty_env_first, parse_bool_env_first, resolve_db_path,
    resolve_parquet_root, resolve_path_with_fallback, resolve_secret_env_pairs, resolve_tls_paths,
};
pub use error::{MuObserveError, StorageError};
pub use mcp::{JsonRpcError, JsonRpcRequest, JsonRpcResponse, McpServer, MCP_TOOL_NAMES};
pub use server::{
    alias_internal_hostnames, anonymize_ipv4_rfc5737, apply_maintenance_policy_to_causal_cards,
    apply_maintenance_policy_to_deterministic_feed, authorize_http_any_read,
    authorize_http_request, build_console_api_router, build_console_api_router_with_auth,
    build_console_api_router_with_ingress, build_console_api_router_with_state,
    build_mtls_server_config, build_sandbox_execution_plan, classify_problem_subsystem,
    classify_service_subsystem, collect_storage_health_status, dispatch_frame, extract_cert_sans,
    fqdn_to_shortname, mask_ipv4_third_octet, query_sanitized_job_log, query_sanitized_logs,
    query_sanitized_logs_with_job, query_sanitized_logs_with_token, query_sanitized_metrics,
    resolve_san_identity, sanitize_console_value, scrub_host_paths, scrub_secrets_and_tokens,
    trim_path_last_two_segments, AuthContext, AuthRejection, CausalMaintenanceFilterOutcome,
    ClusterEfficiencyItem, CollectorBatchAck, ConsoleApiState, ConsoleLogItem, IngestServerConfig,
    LogsQueryResponse, MaintenanceCommand, MetricTimeseriesPoint, MetricsTimeseriesResponse,
    MtlsIngestServer, MuAuthFolioVerifier, ObsAuthVerifier, ObsPermission, PlatformSubsystemId,
    PrivacyRedactor, SanAttribution, SanEnforcementPolicy, SanitizedLogRecord, StoreStatusResponse,
    SubsystemHealthState, SubsystemMaintenanceRequest, SubsystemOverrideMode,
    SubsystemStatusChangedEvent, SubsystemStatusDto, SubsystemStatusRegistry,
    SubsystemsStatusResponse, MAX_MAINTENANCE_DURATION_SECS, MSG_TYPE_ARROW_LOGS,
    MSG_TYPE_ARROW_METRICS, MSG_TYPE_ARROW_SPANS,
};
pub use sql_guard::{
    execute_guarded_sql, validate_readonly_sql, SqlQueryResult, DEFAULT_SQL_MAX_ROWS,
    DEFAULT_SQL_TIMEOUT_MS,
};
pub use storage::{
    available_disk_bytes, compute_log_dedup_hash, register_unified_views, tokenize_log_line,
    CompactionReport, CompactorConfig, HotDuckDbStore, ParquetCompactor,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_retention_window() {
        assert_eq!(DEFAULT_HOT_RETENTION_DAYS, 7);
    }
}
