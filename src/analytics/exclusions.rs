// SPDX-License-Identifier: AGPL-3.0-only
//! Non-destructive monitoring exclusions for active observability feeds.
//!
//! Resolves retired repositories (dynamically from `__ar_console_registry__`,
//! `MUOBSERVE_EXCLUDED_REPOS`, and persisted `__muobserve_monitoring_exclusions__`),
//! retired service names (`MUOBSERVE_RETIRED_SERVICES` + persisted state), and
//! a pre-cutover timestamp floor (`MUOBSERVE_MONITORING_SINCE_UNIX_NANO` + persisted state).
//!
//! Historical rows in `HotDuckDbStore` and cold Parquet partitions are never deleted
//! or mutated; raw views (`v_logs`, `v_traces`, `v_tests`, `v_benchmarks`, `v_jobs_history`)
//! retain 100% of historical telemetry until retention expiration.

use std::collections::BTreeSet;

use mu_observable_ipc::{CentralSubmoduleSnapshot, QuerySubmoduleSnapshotsRequest};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::MuObserveError;
use crate::server::sanitize::PrivacyRedactor;
use crate::storage::HotDuckDbStore;

/// Environment variable listing comma-separated lowercase `owner/repo` or short repo names
/// excluded from active monitoring feeds.
pub const ENV_EXCLUDED_REPOS: &str = "MUOBSERVE_EXCLUDED_REPOS";

/// Environment variable listing comma-separated lowercase legacy `service_name` values
/// excluded from active monitoring feeds.
pub const ENV_RETIRED_SERVICES: &str = "MUOBSERVE_RETIRED_SERVICES";

/// Environment variable specifying an optional epoch-nanosecond floor applied as
/// `cutoff_ts = cutoff_ts.max(monitoring_since_ns)` in active monitoring queries.
pub const ENV_MONITORING_SINCE_UNIX_NANO: &str = "MUOBSERVE_MONITORING_SINCE_UNIX_NANO";

/// Returns `true` when `span_name` identifies a batch CI pipeline or stage execution span
/// (`ci.pipeline.*` or `ci.stage.*`, case-insensitive after trimming).
///
/// Batch CI spans legitimately execute over seconds or minutes and are excluded from
/// interactive RPC latency percentiles and causal latency regression baselines while still
/// retaining call counts, error counts, and 100% raw `v_traces` storage rows.
#[must_use]
pub fn is_batch_ci_execution_span(span_name: &str) -> bool {
    let s = span_name.trim().to_ascii_lowercase();
    s.starts_with("ci.pipeline.") || s.starts_with("ci.stage.")
}

/// Returns `true` when `category` identifies a CI inner-step test or benchmark regression
/// finding (`test_flakiness` or `benchmark_regression`, case-insensitive) rather than a
/// runtime service or host SLO alert.
#[must_use]
pub fn is_ci_regression_problem_category(category: &str) -> bool {
    matches!(
        category.trim().to_ascii_lowercase().as_str(),
        "test_flakiness" | "benchmark_regression"
    )
}

/// Returns `true` when an `ERROR`-tagged batch CI span reflects a non-infrastructure CI job or
/// stage exit (e.g., user test/lint failure or cancellation) rather than a runtime daemon,
/// worker, sandbox, timeout, or signal fault.
#[must_use]
pub fn is_user_ci_failure_span(span_name: &str, attributes_json: &str) -> bool {
    if !is_batch_ci_execution_span(span_name) {
        return false;
    }
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(attributes_json) else {
        return false;
    };
    if map.get("infra_error").and_then(Value::as_bool) == Some(true) {
        return false;
    }
    if map.get("infra_error").and_then(Value::as_bool) == Some(false) {
        return true;
    }
    if matches!(
        map.get("outcome").and_then(Value::as_str),
        Some("user_failure" | "cancelled" | "succeeded")
    ) {
        return true;
    }
    if let Some(code) = map.get("exit_code").and_then(Value::as_i64) {
        if (1..=123).contains(&code) || code == 125 {
            return true;
        }
    }
    span_name
        .trim()
        .to_ascii_lowercase()
        .starts_with("ci.pipeline.")
        && map.contains_key("job_id")
}

/// Internal snapshot `parent_repo_key` populated by `mu-ci-controller` containing `retired_repos`.
pub const CONSOLE_REGISTRY_REPO_KEY: &str = "__ar_console_registry__";

/// Internal snapshot `branch_key` for `mu-ci-controller`'s console registry.
pub const CONSOLE_REGISTRY_BRANCH_KEY: &str = "console";

/// Internal snapshot `submodule_key` for `mu-ci-controller`'s console registry.
pub const CONSOLE_REGISTRY_SUBMODULE_KEY: &str = "registry";

/// Internal snapshot `parent_repo_key` persisting operator monitoring exclusion state.
pub const MONITORING_EXCLUSIONS_REPO_KEY: &str = "__muobserve_monitoring_exclusions__";

/// Internal snapshot `branch_key` for persisted monitoring exclusions.
pub const MONITORING_EXCLUSIONS_BRANCH_KEY: &str = "monitoring";

/// Internal snapshot `submodule_key` for persisted monitoring exclusions.
pub const MONITORING_EXCLUSIONS_SUBMODULE_KEY: &str = "exclusions";

/// Operator-persisted monitoring exclusions stored under `__muobserve_monitoring_exclusions__`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedMonitoringExclusions {
    #[serde(default)]
    pub excluded_repos: BTreeSet<String>,
    #[serde(default)]
    pub retired_services: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring_since_unix_nano: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
}

/// Request payload for `PUT /api/obs/v1/status/exclusions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoringExclusionsUpdateRequest {
    #[serde(default)]
    pub excluded_repos: Option<Vec<String>>,
    #[serde(default)]
    pub retired_services: Option<Vec<String>>,
    #[serde(default)]
    pub monitoring_since_unix_nano: Option<i64>,
    #[serde(default)]
    pub clear_monitoring_since: bool,
    #[serde(default)]
    pub actor: Option<String>,
}

/// Detailed exclusion state returned by `GET` and `PUT /api/obs/v1/status/exclusions`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoringExclusionsStatus {
    pub excluded_repos: BTreeSet<String>,
    pub retired_services: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring_since_unix_nano: Option<i64>,
    pub registry_retired_repos: BTreeSet<String>,
    pub env_excluded_repos: BTreeSet<String>,
    pub env_retired_services: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_monitoring_since_unix_nano: Option<i64>,
    pub persisted: PersistedMonitoringExclusions,
}

/// Resolved effective exclusion rules applied to active monitoring queries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitoringExclusions {
    pub excluded_repos: BTreeSet<String>,
    pub retired_services: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitoring_since_unix_nano: Option<i64>,
}

impl MonitoringExclusions {
    /// Parses a comma-separated list into a normalized lowercase `BTreeSet<String>`.
    #[must_use]
    pub fn parse_csv_set(raw: &str) -> BTreeSet<String> {
        raw.split(',')
            .map(|item| item.trim().to_ascii_lowercase())
            .filter(|item| !item.is_empty())
            .collect()
    }

    /// Parses exclusions directly from optional environment variable string values.
    #[must_use]
    pub fn parse_from_env_values(
        excluded_repos_raw: Option<&str>,
        retired_services_raw: Option<&str>,
        monitoring_since_raw: Option<&str>,
    ) -> Self {
        let excluded_repos = excluded_repos_raw
            .map(Self::parse_csv_set)
            .unwrap_or_default();
        let retired_services = retired_services_raw
            .map(Self::parse_csv_set)
            .unwrap_or_default();
        let monitoring_since_unix_nano = monitoring_since_raw.and_then(|raw| {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return None;
            }
            match trimmed.parse::<i64>() {
                Ok(ts) if ts >= 0 => Some(ts),
                _ => {
                    tracing::warn!(
                        env = ENV_MONITORING_SINCE_UNIX_NANO,
                        "Ignoring invalid non-negative i64 timestamp"
                    );
                    None
                }
            }
        });
        Self {
            excluded_repos,
            retired_services,
            monitoring_since_unix_nano,
        }
    }

    /// Loads exclusions configured via environment variables (`MU_OBSERVABLE_HUB_EXCLUDED_REPOS` /
    /// `MUOBSERVE_EXCLUDED_REPOS`, `MU_OBSERVABLE_HUB_RETIRED_SERVICES` / `MUOBSERVE_RETIRED_SERVICES`,
    /// `MU_OBSERVABLE_HUB_MONITORING_SINCE_UNIX_NANO` / `MUOBSERVE_MONITORING_SINCE_UNIX_NANO`).
    #[must_use]
    pub fn from_env() -> Self {
        let repos = crate::config::env_var_first(&[
            "MU_OBSERVABLE_HUB_EXCLUDED_REPOS",
            "MU_OBSERVABLE_EXCLUDED_REPOS",
            ENV_EXCLUDED_REPOS,
        ]);
        let services = crate::config::env_var_first(&[
            "MU_OBSERVABLE_HUB_RETIRED_SERVICES",
            "MU_OBSERVABLE_RETIRED_SERVICES",
            ENV_RETIRED_SERVICES,
        ]);
        let since = crate::config::env_var_first(&[
            "MU_OBSERVABLE_HUB_MONITORING_SINCE_UNIX_NANO",
            "MU_OBSERVABLE_MONITORING_SINCE_UNIX_NANO",
            ENV_MONITORING_SINCE_UNIX_NANO,
        ]);
        Self::parse_from_env_values(repos.as_deref(), services.as_deref(), since.as_deref())
    }

    /// Extracts normalized `retired_repos` keys from a serialized `__ar_console_registry__` payload.
    #[must_use]
    pub fn parse_registry_retired_repos_json(raw_json: &str) -> BTreeSet<String> {
        let Ok(val) = serde_json::from_str::<Value>(raw_json) else {
            return BTreeSet::new();
        };
        let Some(retired) = val.get("retired_repos") else {
            return BTreeSet::new();
        };
        match retired {
            Value::Object(map) => map
                .keys()
                .map(|k| k.trim().to_ascii_lowercase())
                .filter(|k| !k.is_empty())
                .collect(),
            Value::Array(items) => items
                .iter()
                .filter_map(Value::as_str)
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            _ => BTreeSet::new(),
        }
    }

    /// Dynamically reads `retired_repos` keys persisted in `__ar_console_registry__`.
    #[must_use]
    pub fn load_registry_retired_repos(store: &HotDuckDbStore) -> BTreeSet<String> {
        let req = QuerySubmoduleSnapshotsRequest {
            request_id: "monitoring-exclusions-registry".to_string(),
            parent_repo_key: Some(CONSOLE_REGISTRY_REPO_KEY.to_string()),
            submodule_key: Some(CONSOLE_REGISTRY_SUBMODULE_KEY.to_string()),
            branch_key: Some(CONSOLE_REGISTRY_BRANCH_KEY.to_string()),
        };
        let Ok(rows) = store.query_submodule_snapshots(&req) else {
            return BTreeSet::new();
        };
        let mut out = BTreeSet::new();
        for snap in rows {
            if let Some(json_str) = snap
                .latest_active_json
                .as_deref()
                .or(snap.latest_completed_json.as_deref())
            {
                out.extend(Self::parse_registry_retired_repos_json(json_str));
            }
        }
        out
    }

    /// Loads operator-persisted exclusions from `__muobserve_monitoring_exclusions__`.
    #[must_use]
    pub fn load_persisted(store: &HotDuckDbStore) -> PersistedMonitoringExclusions {
        let req = QuerySubmoduleSnapshotsRequest {
            request_id: "monitoring-exclusions-persisted".to_string(),
            parent_repo_key: Some(MONITORING_EXCLUSIONS_REPO_KEY.to_string()),
            submodule_key: Some(MONITORING_EXCLUSIONS_SUBMODULE_KEY.to_string()),
            branch_key: Some(MONITORING_EXCLUSIONS_BRANCH_KEY.to_string()),
        };
        let Ok(rows) = store.query_submodule_snapshots(&req) else {
            return PersistedMonitoringExclusions::default();
        };
        for snap in rows {
            if let Some(raw_json) = snap
                .latest_active_json
                .as_deref()
                .or(snap.latest_completed_json.as_deref())
            {
                if let Ok(mut parsed) =
                    serde_json::from_str::<PersistedMonitoringExclusions>(raw_json)
                {
                    parsed.excluded_repos = normalize_set(parsed.excluded_repos);
                    parsed.retired_services = normalize_set(parsed.retired_services);
                    parsed.monitoring_since_unix_nano =
                        parsed.monitoring_since_unix_nano.filter(|&ts| ts >= 0);
                    return parsed;
                }
            }
        }
        PersistedMonitoringExclusions::default()
    }

    /// Persists operator monitoring exclusions under `__muobserve_monitoring_exclusions__`.
    pub fn save_persisted(
        store: &HotDuckDbStore,
        persisted: &PersistedMonitoringExclusions,
    ) -> Result<(), MuObserveError> {
        let normalized = PersistedMonitoringExclusions {
            excluded_repos: normalize_set(persisted.excluded_repos.clone()),
            retired_services: normalize_set(persisted.retired_services.clone()),
            monitoring_since_unix_nano: persisted.monitoring_since_unix_nano.filter(|&ts| ts >= 0),
            updated_at_ms: persisted.updated_at_ms,
            updated_by: persisted.updated_by.clone(),
        };
        let json_str = serde_json::to_string(&normalized)?;
        let now_us = chrono::Utc::now().timestamp_micros();
        store.upsert_submodule_snapshots(&[CentralSubmoduleSnapshot {
            parent_repo_key: MONITORING_EXCLUSIONS_REPO_KEY.to_string(),
            branch_key: MONITORING_EXCLUSIONS_BRANCH_KEY.to_string(),
            submodule_key: MONITORING_EXCLUSIONS_SUBMODULE_KEY.to_string(),
            submodule_path_key: MONITORING_EXCLUSIONS_BRANCH_KEY.to_string(),
            latest_active_job_id: Some("exclusions".to_string()),
            latest_active_json: Some(json_str),
            latest_active_queued_us: Some(now_us),
            latest_completed_job_id: None,
            latest_completed_json: None,
            latest_completed_queued_us: None,
        }])?;
        Ok(())
    }

    /// Validates, merges, and persists a [`MonitoringExclusionsUpdateRequest`], returning the
    /// refreshed [`MonitoringExclusionsStatus`].
    pub fn apply_update(
        store: &HotDuckDbStore,
        req: &MonitoringExclusionsUpdateRequest,
        actor_fallback: Option<&str>,
    ) -> Result<MonitoringExclusionsStatus, MuObserveError> {
        if let Some(ts) = req.monitoring_since_unix_nano {
            if ts < 0 {
                return Err(MuObserveError::Validation(
                    "monitoring_since_unix_nano must be non-negative".to_string(),
                ));
            }
        }
        if let Some(ref repos) = req.excluded_repos {
            validate_identifier_list(repos, "excluded_repos")?;
        }
        if let Some(ref services) = req.retired_services {
            validate_identifier_list(services, "retired_services")?;
        }

        let mut persisted = Self::load_persisted(store);
        if let Some(ref repos) = req.excluded_repos {
            persisted.excluded_repos = repos
                .iter()
                .map(|r| r.trim().to_ascii_lowercase())
                .filter(|r| !r.is_empty())
                .collect();
        }
        if let Some(ref services) = req.retired_services {
            persisted.retired_services = services
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
        }
        if req.clear_monitoring_since {
            persisted.monitoring_since_unix_nano = None;
        } else if let Some(ts) = req.monitoring_since_unix_nano {
            persisted.monitoring_since_unix_nano = Some(ts);
        }

        let redactor = PrivacyRedactor::new();
        persisted.updated_at_ms = Some(chrono::Utc::now().timestamp_millis());
        persisted.updated_by = req
            .actor
            .as_deref()
            .or(actor_fallback)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|a| redactor.redact_str(a));

        Self::save_persisted(store, &persisted)?;
        Ok(Self::resolve_status(store))
    }

    /// Resolves the full exclusion status including per-source breakdowns.
    #[must_use]
    pub fn resolve_status(store: &HotDuckDbStore) -> MonitoringExclusionsStatus {
        let env = Self::from_env();
        let registry_retired_repos = Self::load_registry_retired_repos(store);
        let persisted = Self::load_persisted(store);

        let mut excluded_repos = env.excluded_repos.clone();
        excluded_repos.extend(registry_retired_repos.iter().cloned());
        excluded_repos.extend(persisted.excluded_repos.iter().cloned());

        let mut retired_services = env.retired_services.clone();
        retired_services.extend(persisted.retired_services.iter().cloned());

        let monitoring_since_unix_nano = match (
            env.monitoring_since_unix_nano,
            persisted.monitoring_since_unix_nano,
        ) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        };

        MonitoringExclusionsStatus {
            excluded_repos,
            retired_services,
            monitoring_since_unix_nano,
            registry_retired_repos,
            env_excluded_repos: env.excluded_repos,
            env_retired_services: env.retired_services,
            env_monitoring_since_unix_nano: env.monitoring_since_unix_nano,
            persisted,
        }
    }

    /// Resolves the effective [`MonitoringExclusions`] from environment variables,
    /// `__ar_console_registry__` `retired_repos`, and `__muobserve_monitoring_exclusions__`.
    #[must_use]
    pub fn resolve(store: &HotDuckDbStore) -> Self {
        let status = Self::resolve_status(store);
        Self {
            excluded_repos: status.excluded_repos,
            retired_services: status.retired_services,
            monitoring_since_unix_nano: status.monitoring_since_unix_nano,
        }
    }

    /// Returns `true` when no repository, service, or cutover exclusions are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.excluded_repos.is_empty()
            && self.retired_services.is_empty()
            && self.monitoring_since_unix_nano.is_none()
    }

    /// Returns `true` when `repo_key` (case-insensitive `owner/repo` or short repo name)
    /// matches an excluded repository.
    #[must_use]
    pub fn is_repo_excluded(&self, repo_key: &str) -> bool {
        let norm = repo_key.trim().to_ascii_lowercase();
        if norm.is_empty() || self.excluded_repos.is_empty() {
            return false;
        }
        if self.excluded_repos.contains(&norm) {
            return true;
        }
        if let Some((_, short_name)) = norm.rsplit_once('/') {
            return !short_name.is_empty() && self.excluded_repos.contains(short_name);
        }
        self.excluded_repos
            .iter()
            .any(|entry| entry.rsplit_once('/').is_some_and(|(_, s)| s == norm))
    }

    /// Returns `true` when `service_name` (case-insensitive) is in `retired_services`.
    #[must_use]
    pub fn is_service_excluded(&self, service_name: &str) -> bool {
        let norm = service_name.trim().to_ascii_lowercase();
        !norm.is_empty() && self.retired_services.contains(&norm)
    }

    /// Applies `monitoring_since_unix_nano` as a floor: `cutoff_ts.max(monitoring_since_ns)`.
    #[must_use]
    pub fn apply_cutoff_floor(&self, cutoff_ts: i64) -> i64 {
        match self.monitoring_since_unix_nano {
            Some(since) => cutoff_ts.max(since),
            None => cutoff_ts,
        }
    }

    /// Returns `true` when `ts_ns` precedes `monitoring_since_unix_nano`.
    #[must_use]
    pub fn is_before_monitoring_floor(&self, ts_ns: i64) -> bool {
        self.monitoring_since_unix_nano
            .is_some_and(|since| ts_ns < since)
    }
}

fn normalize_set(items: BTreeSet<String>) -> BTreeSet<String> {
    items
        .into_iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn validate_identifier_list(items: &[String], field_name: &str) -> Result<(), MuObserveError> {
    for item in items {
        if item.bytes().any(|b| b < 32 || b == 127) {
            return Err(MuObserveError::Validation(format!(
                "Control characters are forbidden in {field_name}"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_values_and_matching_rules() {
        let empty = MonitoringExclusions::parse_from_env_values(None, None, None);
        assert!(empty.is_empty());
        assert!(!empty.is_repo_excluded("lma1980/k3-core"));
        assert!(!empty.is_service_excluded("action-runner-controller"));
        assert_eq!(empty.apply_cutoff_floor(1_000), 1_000);

        let parsed = MonitoringExclusions::parse_from_env_values(
            Some(" LMA1980/ActionRunner-Controller , k3-core ,, "),
            Some(" ActionRunner-RS, muconde-controller , muregist "),
            Some("1700000500000000000"),
        );
        assert!(parsed.is_repo_excluded("lma1980/actionrunner-controller"));
        assert!(parsed.is_repo_excluded("LMA1980/k3-core"));
        assert!(parsed.is_repo_excluded("k3-core"));
        assert!(!parsed.is_repo_excluded("lma1980/mu-observable-hub"));

        assert!(parsed.is_service_excluded("actionrunner-rs"));
        assert!(parsed.is_service_excluded("MuConde-Controller"));
        assert!(parsed.is_service_excluded("muregist"));
        assert!(!parsed.is_service_excluded("mu-ci-controller"));

        assert_eq!(
            parsed.apply_cutoff_floor(1_700_000_000_000_000_000),
            1_700_000_500_000_000_000
        );
        assert_eq!(
            parsed.apply_cutoff_floor(1_700_000_900_000_000_000),
            1_700_000_900_000_000_000
        );
        assert!(parsed.is_before_monitoring_floor(1_700_000_499_999_999_999));
        assert!(!parsed.is_before_monitoring_floor(1_700_000_500_000_000_000));
    }

    #[test]
    fn test_parse_registry_retired_repos_json_variants() {
        let obj_json = r#"{
            "fabric_rev": 12,
            "repos": {"lma1980/mu-ci-controller": {}},
            "retired_repos": {
                "LMA1980/ActionRunner-Controller": "2026-11-17T00:00:00Z",
                "lma1980/k3-core": "2026-11-17T00:01:00Z"
            }
        }"#;
        let repos = MonitoringExclusions::parse_registry_retired_repos_json(obj_json);
        assert_eq!(repos.len(), 2);
        assert!(repos.contains("lma1980/actionrunner-controller"));
        assert!(repos.contains("lma1980/k3-core"));

        let arr_json = r#"{"retired_repos": ["LMA1980/MuRegist", " "]}"#;
        let arr_repos = MonitoringExclusions::parse_registry_retired_repos_json(arr_json);
        assert_eq!(arr_repos.len(), 1);
        assert!(arr_repos.contains("lma1980/muregist"));

        assert!(MonitoringExclusions::parse_registry_retired_repos_json("not-json").is_empty());
        assert!(MonitoringExclusions::parse_registry_retired_repos_json("{}").is_empty());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_resolve_combines_registry_and_persisted_exclusions_dynamically() {
        let store = HotDuckDbStore::open_in_memory().expect("open store");
        assert!(MonitoringExclusions::load_registry_retired_repos(&store).is_empty());

        store
            .upsert_submodule_snapshots(&[CentralSubmoduleSnapshot {
                parent_repo_key: CONSOLE_REGISTRY_REPO_KEY.into(),
                branch_key: CONSOLE_REGISTRY_BRANCH_KEY.into(),
                submodule_key: CONSOLE_REGISTRY_SUBMODULE_KEY.into(),
                submodule_path_key: CONSOLE_REGISTRY_BRANCH_KEY.into(),
                latest_active_job_id: Some("registry".into()),
                latest_active_json: Some(
                    r#"{"fabric_rev":7,"retired_repos":{"LMA1980/K3-Core":"2026-11-17T00:00:00Z"}}"#
                        .into(),
                ),
                latest_active_queued_us: Some(1_700_000_000_000_000),
                latest_completed_job_id: None,
                latest_completed_json: None,
                latest_completed_queued_us: None,
            }])
            .expect("upsert console registry snapshot");

        let status = MonitoringExclusions::apply_update(
            &store,
            &MonitoringExclusionsUpdateRequest {
                excluded_repos: Some(vec!["lma1980/muregist".into()]),
                retired_services: Some(vec!["muregist".into(), "actionrunner-rs".into()]),
                monitoring_since_unix_nano: Some(1_700_000_123_000_000_000),
                clear_monitoring_since: false,
                actor: Some("operator-1".into()),
            },
            None,
        )
        .expect("apply exclusion update");

        assert!(status.excluded_repos.contains("lma1980/k3-core"));
        assert!(status.excluded_repos.contains("lma1980/muregist"));
        assert!(status.retired_services.contains("muregist"));
        assert!(status.retired_services.contains("actionrunner-rs"));
        assert_eq!(
            status.monitoring_since_unix_nano,
            Some(1_700_000_123_000_000_000)
        );
        assert_eq!(status.persisted.updated_by.as_deref(), Some("operator-1"));

        // Unfiltered submodule snapshot queries must never return __muobserve_* internal rows
        let unfiltered = store
            .query_submodule_snapshots(&QuerySubmoduleSnapshotsRequest {
                request_id: "unfiltered".into(),
                parent_repo_key: None,
                submodule_key: None,
                branch_key: None,
            })
            .expect("unfiltered query");
        assert!(unfiltered.is_empty());
    }

    #[test]
    fn test_is_batch_ci_execution_span() {
        assert!(is_batch_ci_execution_span(
            "ci.pipeline.run:LMA1980/mu-console"
        ));
        assert!(is_batch_ci_execution_span("  CI.Pipeline.Deploy  "));
        assert!(is_batch_ci_execution_span("ci.stage.dispatch:fmt-check"));
        assert!(is_batch_ci_execution_span(" CI.STAGE.test-check "));

        // Bare prefixes without trailing dot and interactive RPC spans must not match.
        assert!(!is_batch_ci_execution_span("ci.pipeline"));
        assert!(!is_batch_ci_execution_span("ci.stage"));
        assert!(!is_batch_ci_execution_span("GET /api/obs/v1/problems"));
        assert!(!is_batch_ci_execution_span(""));
    }

    #[test]
    fn test_ci_regression_problem_category_and_user_ci_failure_span() {
        assert!(is_ci_regression_problem_category("test_flakiness"));
        assert!(is_ci_regression_problem_category(" BENCHMARK_REGRESSION "));
        assert!(!is_ci_regression_problem_category("error_rate_breach"));
        assert!(!is_ci_regression_problem_category("latency_p95_breach"));

        // Non-batch spans never match, even with exit_code or infra_error=false.
        assert!(!is_user_ci_failure_span(
            "GET /api/jobs",
            r#"{"infra_error":false,"exit_code":1}"#
        ));
        // Explicit infra_error=true stays visible as a runtime fault.
        assert!(!is_user_ci_failure_span(
            "ci.stage.test-check",
            r#"{"infra_error":true,"exit_code":127}"#
        ));
        // Unannotated fixture spans (e.g., {"domain":"ci"}) remain runtime faults.
        assert!(!is_user_ci_failure_span(
            "ci.stage.dispatch:test-check",
            r#"{"domain":"ci"}"#
        ));
        // User test/lint failures and pre-#227 controller pipeline spans are classified as user CI exits.
        assert!(is_user_ci_failure_span(
            "ci.stage.test-check",
            r#"{"infra_error":false,"outcome":"user_failure","exit_code":101}"#
        ));
        assert!(is_user_ci_failure_span(
            "ci.stage.dispatch:clippy-check",
            r#"{"job_id":"j1","stage_id":"clippy-check","exit_code":1}"#
        ));
        assert!(is_user_ci_failure_span(
            "ci.pipeline.run:LMA1980/jero-core",
            r#"{"job_id":"j1","repo":"LMA1980/jero-core"}"#
        ));
    }
}
