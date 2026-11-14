// SPDX-License-Identifier: AGPL-3.0-only
//! Unified 7-subsystem operational status registry, manual maintenance overrides,
//! live probe aggregation, privacy redaction, and maintenance-window SLO suppression.

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;
use std::time::Duration;

use duckdb::params;
use serde::{Deserialize, Serialize};

use crate::analytics::causal::CausalProblemCard;
use crate::analytics::smartscape::{ProblemCard, ProblemsFeedResponse};
use crate::ingress::IngressUpstreamDto;
use crate::server::sanitize::PrivacyRedactor;
use crate::storage::HotDuckDbStore;

/// Maximum bounded maintenance override duration (7 days, aligned with retention/query bounds).
pub const MAX_MAINTENANCE_DURATION_SECS: u64 = 604_800;

/// Canonical 7 platform subsystems monitored by the console operational status bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformSubsystemId {
    Ci,
    Cd,
    AbDeploy,
    Repository,
    Observability,
    ModelRunner,
    Platform,
}

impl PlatformSubsystemId {
    /// Complete ordered list of all 7 canonical subsystems.
    pub const ALL: [Self; 7] = [
        Self::Ci,
        Self::Cd,
        Self::AbDeploy,
        Self::Repository,
        Self::Observability,
        Self::ModelRunner,
        Self::Platform,
    ];

    /// Canonical snake_case identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ci => "ci",
            Self::Cd => "cd",
            Self::AbDeploy => "ab_deploy",
            Self::Repository => "repository",
            Self::Observability => "observability",
            Self::ModelRunner => "model_runner",
            Self::Platform => "platform",
        }
    }

    /// Human-facing engineering label.
    #[must_use]
    pub const fn display_label(self) -> &'static str {
        match self {
            Self::Ci => "CI Runner",
            Self::Cd => "Continuous Delivery",
            Self::AbDeploy => "A/B Deployments",
            Self::Repository => "Artifact Repository",
            Self::Observability => "Observability",
            Self::ModelRunner => "Model Runner",
            Self::Platform => "Platform",
        }
    }

    /// Parses a subsystem path identifier (`snake_case` or hyphenated alias).
    #[must_use]
    pub fn from_str_id(raw: &str) -> Option<Self> {
        let norm = raw.trim().to_ascii_lowercase().replace('-', "_");
        match norm.as_str() {
            "ci" => Some(Self::Ci),
            "cd" => Some(Self::Cd),
            "ab_deploy" | "abdeploy" => Some(Self::AbDeploy),
            "repository" => Some(Self::Repository),
            "observability" => Some(Self::Observability),
            "model_runner" | "modelrunner" => Some(Self::ModelRunner),
            "platform" => Some(Self::Platform),
            _ => None,
        }
    }
}

/// Canonical 5-state subsystem operational health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubsystemHealthState {
    Live,
    InMaintenance,
    PartialMaintenance,
    Offline,
    Degraded,
}

impl SubsystemHealthState {
    /// Canonical kebab-case wire representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::InMaintenance => "in-maintenance",
            Self::PartialMaintenance => "partial-maintenance",
            Self::Offline => "offline",
            Self::Degraded => "degraded",
        }
    }

    /// Returns `true` when the state represents an active planned maintenance window.
    #[must_use]
    pub const fn is_maintenance(self) -> bool {
        matches!(self, Self::InMaintenance | Self::PartialMaintenance)
    }

    /// Parses a health state string case-insensitively (`kebab-case` or `snake_case`).
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let norm = raw.trim().to_ascii_lowercase().replace('_', "-");
        match norm.as_str() {
            "live" | "healthy" | "operational" => Some(Self::Live),
            "in-maintenance" | "maintenance" => Some(Self::InMaintenance),
            "partial-maintenance" | "partial" => Some(Self::PartialMaintenance),
            "offline" | "down" | "unhealthy" => Some(Self::Offline),
            "degraded" => Some(Self::Degraded),
            _ => None,
        }
    }

    /// Generic public-safe summary text used when anonymous access exposes redacted status.
    #[must_use]
    pub const fn anonymous_generic_summary(self) -> &'static str {
        match self {
            Self::Live => "Operational",
            Self::InMaintenance => "Scheduled maintenance in progress",
            Self::PartialMaintenance => "Partial maintenance in progress",
            Self::Offline => "Subsystem unavailable",
            Self::Degraded => "Degraded operation",
        }
    }

    const fn severity_rank(self) -> u8 {
        match self {
            Self::Live => 0,
            Self::PartialMaintenance => 1,
            Self::Degraded => 2,
            Self::InMaintenance => 3,
            Self::Offline => 4,
        }
    }
}

/// Resolution source mode for a subsystem's operational status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsystemOverrideMode {
    Auto,
    Manual,
}

impl SubsystemOverrideMode {
    /// Canonical human-readable mode badge text (`"Auto (Live Probe)"` vs `"Manual Override"`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto (Live Probe)",
            Self::Manual => "Manual Override",
        }
    }
}

/// Operational status snapshot for a single subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsystemStatusDto {
    pub id: PlatformSubsystemId,
    pub label: String,
    pub state: SubsystemHealthState,
    pub mode: SubsystemOverrideMode,
    pub mode_label: String,
    pub maintenance_active: bool,
    pub summary: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_health: Option<String>,
    pub updated_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
}

/// Unified operational status feed across all 7 platform subsystems (`GET /api/obs/v1/status/subsystems`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsystemsStatusResponse {
    pub generated_at_ms: i64,
    pub total: usize,
    pub maintenance_active_count: usize,
    pub degraded_or_offline_count: usize,
    pub overall_state: SubsystemHealthState,
    pub subsystems: Vec<SubsystemStatusDto>,
}

impl SubsystemsStatusResponse {
    /// Returns a redacted copy suitable for anonymous callers granted only `system:status.read`.
    #[must_use]
    pub fn redacted_for_anonymous(mut self) -> Self {
        for sub in &mut self.subsystems {
            sub.summary = sub.state.anonymous_generic_summary().to_string();
            sub.updated_by = None;
            sub.upstream_health = None;
        }
        self
    }
}

/// Request payload for `PUT /api/obs/v1/status/subsystems/{id}/maintenance`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct SubsystemMaintenanceRequest {
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub clear: bool,
    #[serde(default, alias = "reason")]
    pub summary: Option<String>,
    #[serde(default)]
    pub duration_secs: Option<u64>,
    #[serde(default)]
    pub actor: Option<String>,
}

/// Validated maintenance action parsed from [`SubsystemMaintenanceRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaintenanceCommand {
    ClearToAuto {
        actor: Option<String>,
        reason: Option<String>,
    },
    SetManual {
        state: SubsystemHealthState,
        summary: Option<String>,
        duration_secs: Option<u64>,
        actor: Option<String>,
    },
}

impl SubsystemMaintenanceRequest {
    /// Validates and normalizes the maintenance update payload.
    pub fn validate(&self) -> Result<MaintenanceCommand, &'static str> {
        if let Some(secs) = self.duration_secs {
            if secs == 0 || secs > MAX_MAINTENANCE_DURATION_SECS {
                return Err("duration_secs must be between 1 and 604800");
            }
        }

        let mode_norm = self
            .mode
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_ascii_lowercase);

        if let Some(ref m) = mode_norm {
            if !matches!(
                m.as_str(),
                "auto" | "auto (live probe)" | "manual" | "manual override"
            ) {
                return Err("Unsupported mode: expected 'auto' or 'manual'");
            }
        }

        let state_trimmed = self
            .state
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let state_is_auto = state_trimmed.is_some_and(|s| {
            matches!(
                s.to_ascii_lowercase().as_str(),
                "auto" | "auto (live probe)" | "auto-live-probe"
            )
        });

        let wants_clear = self.clear
            || matches!(mode_norm.as_deref(), Some("auto" | "auto (live probe)"))
            || state_is_auto;

        if wants_clear {
            return Ok(MaintenanceCommand::ClearToAuto {
                actor: self.actor.clone(),
                reason: self.summary.clone(),
            });
        }

        let Some(raw_state) = state_trimmed else {
            return Err("Missing required maintenance state or auto clear instruction");
        };

        let Some(parsed_state) = SubsystemHealthState::parse(raw_state) else {
            return Err(
                "Invalid subsystem state: expected live, in-maintenance, partial-maintenance, offline, degraded, or auto",
            );
        };

        Ok(MaintenanceCommand::SetManual {
            state: parsed_state,
            summary: self.summary.clone(),
            duration_secs: self.duration_secs,
            actor: self.actor.clone(),
        })
    }
}

/// SSE change event payload broadcast when a subsystem transitions state or mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsystemStatusChangedEvent {
    pub subsystem_status_changed: bool,
    pub subsystem: PlatformSubsystemId,
    pub id: PlatformSubsystemId,
    pub label: String,
    pub state: SubsystemHealthState,
    pub previous_state: SubsystemHealthState,
    pub mode: SubsystemOverrideMode,
    pub mode_label: String,
    pub maintenance_active: bool,
    pub summary: String,
    pub updated_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone)]
struct ManualOverrideRecord {
    state: SubsystemHealthState,
    summary: String,
    updated_at_ms: i64,
    expires_at_ms: Option<i64>,
    updated_by: Option<String>,
}

/// Thread-safe registry tracking live probe state and manual overrides for all 7 subsystems.
pub struct SubsystemStatusRegistry {
    overrides: RwLock<HashMap<PlatformSubsystemId, ManualOverrideRecord>>,
    store: Option<HotDuckDbStore>,
    redactor: PrivacyRedactor,
}

impl std::fmt::Debug for SubsystemStatusRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubsystemStatusRegistry")
            .field("has_store", &self.store.is_some())
            .finish()
    }
}

impl SubsystemStatusRegistry {
    /// Creates an in-memory registry without DuckDB persistence (useful for unit tests and Miri).
    #[must_use]
    pub fn in_memory() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            overrides: RwLock::new(HashMap::new()),
            store: None,
            redactor: PrivacyRedactor::new(),
        })
    }

    /// Creates a registry backed by `HotDuckDbStore` for durable maintenance override state and SSE events.
    #[must_use]
    pub fn new(store: HotDuckDbStore) -> std::sync::Arc<Self> {
        let registry = std::sync::Arc::new(Self {
            overrides: RwLock::new(HashMap::new()),
            store: Some(store),
            redactor: PrivacyRedactor::new(),
        });
        registry.init_persistence_and_hydrate();
        registry
    }

    /// Spawns a background reaper clearing expired timed maintenance overrides and emitting SSE events.
    pub fn spawn_expiry_reaper(
        self: &std::sync::Arc<Self>,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        let reg = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let _ = reg.tick_expirations(None);
            }
        })
    }

    fn init_persistence_and_hydrate(&self) {
        let Some(ref store) = self.store else {
            return;
        };
        let Ok(conn) = store.lock_conn() else {
            return;
        };
        let _ = conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS subsystem_maintenance_overrides (
                subsystem_id VARCHAR PRIMARY KEY,
                state VARCHAR NOT NULL,
                summary VARCHAR NOT NULL,
                updated_by VARCHAR,
                updated_at_ms BIGINT NOT NULL,
                expires_at_ms BIGINT
            );
            "#,
        );
        let now_ms = current_epoch_ms();
        let Ok(mut stmt) = conn.prepare(
            "SELECT subsystem_id, state, summary, updated_by, updated_at_ms, expires_at_ms FROM subsystem_maintenance_overrides",
        ) else {
            return;
        };
        let Ok(rows) = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Option<i64>>(5)?,
            ))
        }) else {
            return;
        };

        let mut hydrated = HashMap::new();
        let mut expired_keys = Vec::new();
        for row in rows.flatten() {
            let (raw_id, raw_state, summary, updated_by, updated_at_ms, expires_at_ms) = row;
            let Some(sub_id) = PlatformSubsystemId::from_str_id(&raw_id) else {
                continue;
            };
            if expires_at_ms.is_some_and(|exp| exp <= now_ms) {
                expired_keys.push(raw_id);
                continue;
            }
            let Some(state) = SubsystemHealthState::parse(&raw_state) else {
                continue;
            };
            hydrated.insert(
                sub_id,
                ManualOverrideRecord {
                    state,
                    summary: self.redactor.redact_str(&summary),
                    updated_at_ms,
                    expires_at_ms,
                    updated_by: updated_by.map(|a| self.redactor.redact_str(&a)),
                },
            );
        }
        drop(stmt);
        for key in expired_keys {
            let _ = conn.execute(
                "DELETE FROM subsystem_maintenance_overrides WHERE subsystem_id = ?1",
                params![key],
            );
        }
        if let Ok(mut guard) = self.overrides.write() {
            *guard = hydrated;
        }
    }

    /// Expires any manual maintenance override whose `expires_at_ms <= now`, reverting it to `"Auto (Live Probe)"`
    /// and returning emitted [`SubsystemStatusChangedEvent`] entries (and broadcasting them if a store is attached).
    pub fn tick_expirations(&self, now_ms: Option<i64>) -> Vec<SubsystemStatusChangedEvent> {
        let now = now_ms.unwrap_or_else(current_epoch_ms);
        let expired: Vec<(PlatformSubsystemId, SubsystemHealthState)> = {
            let Ok(mut guard) = self.overrides.write() else {
                return Vec::new();
            };
            let due: Vec<(PlatformSubsystemId, SubsystemHealthState)> = guard
                .iter()
                .filter_map(|(&id, rec)| {
                    if rec.expires_at_ms.is_some_and(|exp| exp <= now) {
                        Some((id, rec.state))
                    } else {
                        None
                    }
                })
                .collect();
            for (id, _) in &due {
                guard.remove(id);
            }
            due
        };

        let mut events = Vec::with_capacity(expired.len());
        for (id, prev_state) in expired {
            self.delete_persisted_override(id);
            let mut dto = self.resolve_single_dto(id, &[], now);
            dto.summary = "Maintenance window expired; reverted to Auto (Live Probe)".to_string();
            let event = self.build_change_event(&dto, prev_state);
            self.broadcast_change_event(&event);
            events.push(event);
        }
        events
    }

    /// Applies a validated [`MaintenanceCommand`] to `subsystem`, returning the updated [`SubsystemStatusDto`],
    /// the emitted [`SubsystemStatusChangedEvent`], and persisting + broadcasting when a store is configured.
    pub fn apply_maintenance_command(
        &self,
        subsystem: PlatformSubsystemId,
        cmd: MaintenanceCommand,
        upstreams: &[IngressUpstreamDto],
        now_ms: Option<i64>,
    ) -> (SubsystemStatusDto, SubsystemStatusChangedEvent) {
        let now = now_ms.unwrap_or_else(current_epoch_ms);
        let _ = self.tick_expirations(Some(now));
        let prev_dto = self.resolve_single_dto(subsystem, upstreams, now);

        match cmd {
            MaintenanceCommand::ClearToAuto { actor: _, reason } => {
                if let Ok(mut guard) = self.overrides.write() {
                    guard.remove(&subsystem);
                }
                self.delete_persisted_override(subsystem);
                let mut dto = self.resolve_single_dto(subsystem, upstreams, now);
                if let Some(custom_reason) = reason {
                    let trimmed = custom_reason.trim();
                    if !trimmed.is_empty() {
                        dto.summary = self.redactor.redact_str(trimmed);
                    }
                }
                let event = self.build_change_event(&dto, prev_dto.state);
                self.broadcast_change_event(&event);
                (dto, event)
            }
            MaintenanceCommand::SetManual {
                state,
                summary,
                duration_secs,
                actor,
            } => {
                let raw_summary = summary
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| default_manual_summary(subsystem, state));
                let redacted_summary = self.redactor.redact_str(&raw_summary);
                let redacted_actor = actor
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(|a| self.redactor.redact_str(a));
                let expires_at_ms = duration_secs.map(|secs| {
                    let delta_ms = i64::try_from(secs).unwrap_or(i64::MAX).saturating_mul(1000);
                    now.saturating_add(delta_ms)
                });

                let rec = ManualOverrideRecord {
                    state,
                    summary: redacted_summary.clone(),
                    updated_at_ms: now,
                    expires_at_ms,
                    updated_by: redacted_actor.clone(),
                };

                if let Ok(mut guard) = self.overrides.write() {
                    guard.insert(subsystem, rec.clone());
                }
                self.upsert_persisted_override(subsystem, &rec);

                let dto = self.resolve_single_dto(subsystem, upstreams, now);
                let event = self.build_change_event(&dto, prev_dto.state);
                self.broadcast_change_event(&event);
                (dto, event)
            }
        }
    }

    /// Returns the unified snapshot of all 7 subsystems, optionally redacted for anonymous viewers.
    #[must_use]
    pub fn snapshot(
        &self,
        upstreams: &[IngressUpstreamDto],
        anonymous_redacted: bool,
        now_ms: Option<i64>,
    ) -> SubsystemsStatusResponse {
        let now = now_ms.unwrap_or_else(current_epoch_ms);
        let _ = self.tick_expirations(Some(now));

        let overrides_copy: HashMap<PlatformSubsystemId, ManualOverrideRecord> =
            self.overrides.read().map(|g| g.clone()).unwrap_or_default();

        let store_healthy = self
            .store
            .as_ref()
            .map(|s| s.lock_conn().is_ok())
            .unwrap_or(true);

        // Pass 1: resolve direct live probes & manual overrides for non-platform subsystems first.
        let mut dtos_by_id: BTreeMap<PlatformSubsystemId, SubsystemStatusDto> = BTreeMap::new();
        for &id in &PlatformSubsystemId::ALL {
            if id == PlatformSubsystemId::Platform {
                continue;
            }
            let dto = self.build_non_platform_dto(
                id,
                overrides_copy.get(&id),
                upstreams,
                store_healthy,
                now,
            );
            dtos_by_id.insert(id, dto);
        }

        // Pass 2: resolve `Platform` (either manual override or aggregated platform probe).
        let platform_dto = if let Some(ov) = overrides_copy.get(&PlatformSubsystemId::Platform) {
            Self::dto_from_override(PlatformSubsystemId::Platform, ov, None)
        } else {
            self.aggregate_platform_dto(&dtos_by_id, upstreams, now)
        };
        dtos_by_id.insert(PlatformSubsystemId::Platform, platform_dto);

        let subsystems: Vec<SubsystemStatusDto> = PlatformSubsystemId::ALL
            .iter()
            .filter_map(|id| dtos_by_id.get(id).cloned())
            .collect();

        let maintenance_active_count = subsystems.iter().filter(|s| s.maintenance_active).count();
        let degraded_or_offline_count = subsystems
            .iter()
            .filter(|s| {
                matches!(
                    s.state,
                    SubsystemHealthState::Degraded | SubsystemHealthState::Offline
                )
            })
            .count();

        let overall_state = subsystems
            .iter()
            .map(|s| s.state)
            .max_by_key(|s| s.severity_rank())
            .unwrap_or(SubsystemHealthState::Live);

        let resp = SubsystemsStatusResponse {
            generated_at_ms: now,
            total: subsystems.len(),
            maintenance_active_count,
            degraded_or_offline_count,
            overall_state,
            subsystems,
        };

        if anonymous_redacted {
            resp.redacted_for_anonymous()
        } else {
            resp
        }
    }

    /// Returns subsystems currently in an active maintenance state (`in-maintenance` or `partial-maintenance`).
    #[must_use]
    pub fn active_maintenance_windows(
        &self,
        now_ms: Option<i64>,
    ) -> Vec<(PlatformSubsystemId, SubsystemHealthState)> {
        let now = now_ms.unwrap_or_else(current_epoch_ms);
        let _ = self.tick_expirations(Some(now));
        let Ok(guard) = self.overrides.read() else {
            return Vec::new();
        };
        PlatformSubsystemId::ALL
            .iter()
            .filter_map(|&id| {
                guard
                    .get(&id)
                    .filter(|ov| ov.state.is_maintenance())
                    .map(|ov| (id, ov.state))
            })
            .collect()
    }

    fn resolve_single_dto(
        &self,
        subsystem: PlatformSubsystemId,
        upstreams: &[IngressUpstreamDto],
        now: i64,
    ) -> SubsystemStatusDto {
        let snap = self.snapshot(upstreams, false, Some(now));
        snap.subsystems
            .into_iter()
            .find(|s| s.id == subsystem)
            .unwrap_or_else(|| SubsystemStatusDto {
                id: subsystem,
                label: subsystem.display_label().to_string(),
                state: SubsystemHealthState::Live,
                mode: SubsystemOverrideMode::Auto,
                mode_label: SubsystemOverrideMode::Auto.label().to_string(),
                maintenance_active: false,
                summary: "Live probe nominal".to_string(),
                source: "live_probe".to_string(),
                upstream_health: None,
                updated_at_ms: now,
                expires_at_ms: None,
                updated_by: None,
            })
    }

    fn build_non_platform_dto(
        &self,
        id: PlatformSubsystemId,
        manual: Option<&ManualOverrideRecord>,
        upstreams: &[IngressUpstreamDto],
        store_healthy: bool,
        now: i64,
    ) -> SubsystemStatusDto {
        let matched_upstream = find_matching_upstream(id, upstreams);
        let upstream_health = matched_upstream.map(|u| u.health_state.clone());

        if let Some(ov) = manual {
            return Self::dto_from_override(id, ov, upstream_health);
        }

        let (state, summary) = match id {
            PlatformSubsystemId::Observability => {
                if store_healthy {
                    (
                        SubsystemHealthState::Live,
                        "Hot DuckDB storage and OTEL ingestion pipelines nominal".to_string(),
                    )
                } else {
                    (
                        SubsystemHealthState::Degraded,
                        "Observability storage lock contention detected".to_string(),
                    )
                }
            }
            PlatformSubsystemId::AbDeploy => {
                if let Some(up) = matched_upstream {
                    map_upstream_probe(up)
                } else if let Some(cd_up) =
                    find_matching_upstream(PlatformSubsystemId::Cd, upstreams)
                {
                    match cd_up.health_state.to_ascii_uppercase().as_str() {
                        "UNHEALTHY" | "OFFLINE" => (
                            SubsystemHealthState::Degraded,
                            "A/B deployment controller dependency unavailable".to_string(),
                        ),
                        "DEGRADED" => (
                            SubsystemHealthState::Degraded,
                            "A/B deployment controller reporting degraded latency".to_string(),
                        ),
                        _ => (
                            SubsystemHealthState::Live,
                            "Auto-detected live canary and A/B rollout pipeline".to_string(),
                        ),
                    }
                } else {
                    (
                        SubsystemHealthState::Live,
                        "Auto-detected live canary and A/B rollout pipeline".to_string(),
                    )
                }
            }
            _ => {
                if let Some(up) = matched_upstream {
                    map_upstream_probe(up)
                } else {
                    (
                        SubsystemHealthState::Live,
                        format!("{} auto probe nominal", id.display_label()),
                    )
                }
            }
        };

        SubsystemStatusDto {
            id,
            label: id.display_label().to_string(),
            state,
            mode: SubsystemOverrideMode::Auto,
            mode_label: SubsystemOverrideMode::Auto.label().to_string(),
            maintenance_active: state.is_maintenance(),
            summary: self.redactor.redact_str(&summary),
            source: "live_probe".to_string(),
            upstream_health,
            updated_at_ms: matched_upstream
                .map(|u| u.last_check_ms)
                .filter(|&ts| ts > 0)
                .unwrap_or(now),
            expires_at_ms: None,
            updated_by: None,
        }
    }

    fn aggregate_platform_dto(
        &self,
        siblings: &BTreeMap<PlatformSubsystemId, SubsystemStatusDto>,
        upstreams: &[IngressUpstreamDto],
        now: i64,
    ) -> SubsystemStatusDto {
        let matched = find_matching_upstream(PlatformSubsystemId::Platform, upstreams);
        let upstream_health = matched.map(|u| u.health_state.clone());

        let (state, summary) = if let Some(up) = matched {
            map_upstream_probe(up)
        } else {
            let any_offline = siblings
                .values()
                .any(|s| s.state == SubsystemHealthState::Offline);
            let any_degraded = siblings
                .values()
                .any(|s| s.state == SubsystemHealthState::Degraded);
            let any_maint = siblings.values().any(|s| s.maintenance_active);

            if any_offline {
                (
                    SubsystemHealthState::Degraded,
                    "Platform control plane degraded: one or more subsystems offline".to_string(),
                )
            } else if any_degraded {
                (
                    SubsystemHealthState::Degraded,
                    "Platform control plane degraded: upstream probe latency/errors elevated"
                        .to_string(),
                )
            } else if any_maint {
                (
                    SubsystemHealthState::PartialMaintenance,
                    "Platform partially in maintenance across scheduled subsystems".to_string(),
                )
            } else {
                (
                    SubsystemHealthState::Live,
                    "All platform subsystems operational".to_string(),
                )
            }
        };

        SubsystemStatusDto {
            id: PlatformSubsystemId::Platform,
            label: PlatformSubsystemId::Platform.display_label().to_string(),
            state,
            mode: SubsystemOverrideMode::Auto,
            mode_label: SubsystemOverrideMode::Auto.label().to_string(),
            maintenance_active: state.is_maintenance(),
            summary: self.redactor.redact_str(&summary),
            source: "live_probe".to_string(),
            upstream_health,
            updated_at_ms: now,
            expires_at_ms: None,
            updated_by: None,
        }
    }

    fn dto_from_override(
        id: PlatformSubsystemId,
        ov: &ManualOverrideRecord,
        upstream_health: Option<String>,
    ) -> SubsystemStatusDto {
        SubsystemStatusDto {
            id,
            label: id.display_label().to_string(),
            state: ov.state,
            mode: SubsystemOverrideMode::Manual,
            mode_label: SubsystemOverrideMode::Manual.label().to_string(),
            maintenance_active: ov.state.is_maintenance(),
            summary: ov.summary.clone(),
            source: "manual_override".to_string(),
            upstream_health,
            updated_at_ms: ov.updated_at_ms,
            expires_at_ms: ov.expires_at_ms,
            updated_by: ov.updated_by.clone(),
        }
    }

    fn build_change_event(
        &self,
        dto: &SubsystemStatusDto,
        previous_state: SubsystemHealthState,
    ) -> SubsystemStatusChangedEvent {
        SubsystemStatusChangedEvent {
            subsystem_status_changed: true,
            subsystem: dto.id,
            id: dto.id,
            label: dto.label.clone(),
            state: dto.state,
            previous_state,
            mode: dto.mode,
            mode_label: dto.mode_label.clone(),
            maintenance_active: dto.maintenance_active,
            summary: self.redactor.redact_str(&dto.summary),
            updated_at_ms: dto.updated_at_ms,
            expires_at_ms: dto.expires_at_ms,
        }
    }

    fn broadcast_change_event(&self, event: &SubsystemStatusChangedEvent) {
        let Some(ref store) = self.store else {
            return;
        };
        if let Ok(json_line) = serde_json::to_string(event) {
            store.broadcast_event(&json_line);
        }
    }

    fn upsert_persisted_override(
        &self,
        subsystem: PlatformSubsystemId,
        rec: &ManualOverrideRecord,
    ) {
        let Some(ref store) = self.store else {
            return;
        };
        let Ok(conn) = store.lock_conn() else {
            return;
        };
        let _ = conn.execute(
            r#"
            INSERT INTO subsystem_maintenance_overrides (
                subsystem_id, state, summary, updated_by, updated_at_ms, expires_at_ms
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT (subsystem_id) DO UPDATE SET
                state = excluded.state,
                summary = excluded.summary,
                updated_by = excluded.updated_by,
                updated_at_ms = excluded.updated_at_ms,
                expires_at_ms = excluded.expires_at_ms
            "#,
            params![
                subsystem.as_str(),
                rec.state.as_str(),
                rec.summary,
                rec.updated_by,
                rec.updated_at_ms,
                rec.expires_at_ms,
            ],
        );
    }

    fn delete_persisted_override(&self, subsystem: PlatformSubsystemId) {
        let Some(ref store) = self.store else {
            return;
        };
        let Ok(conn) = store.lock_conn() else {
            return;
        };
        let _ = conn.execute(
            "DELETE FROM subsystem_maintenance_overrides WHERE subsystem_id = ?1",
            params![subsystem.as_str()],
        );
    }
}

/// Result of applying maintenance-window suppression/tagging to [`CausalProblemCard`] items.
#[derive(Debug, Clone, PartialEq)]
pub struct CausalMaintenanceFilterOutcome {
    pub active_problems: Vec<CausalProblemCard>,
    pub suppressed_problems: Vec<CausalProblemCard>,
    pub active_maintenance_subsystems: Vec<String>,
}

/// Maps a telemetry service name to its corresponding [`PlatformSubsystemId`], if recognized.
#[must_use]
pub fn classify_service_subsystem(service_name: &str) -> Option<PlatformSubsystemId> {
    let lower = service_name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return None;
    }

    if lower == "ci"
        || lower.contains("actionrunner")
        || lower.contains("action-runner")
        || lower.contains("muci")
        || lower.contains("mu-ci")
        || lower.contains("ci-runner")
    {
        return Some(PlatformSubsystemId::Ci);
    }
    if lower == "cd"
        || lower.contains("muconde")
        || lower.contains("mu-conde")
        || lower.contains("deploy-agent")
    {
        return Some(PlatformSubsystemId::Cd);
    }
    if lower == "ab_deploy"
        || lower == "ab-deploy"
        || lower.contains("canary")
        || lower.contains("abdeploy")
    {
        return Some(PlatformSubsystemId::AbDeploy);
    }
    if lower == "repository"
        || lower.contains("muregist")
        || lower.contains("mu-regist")
        || lower.contains("registry")
        || lower.contains("artifact")
    {
        return Some(PlatformSubsystemId::Repository);
    }
    if lower == "observability"
        || lower.contains("muobserve")
        || lower.contains("mu-observe")
        || lower.contains("mu-observable")
        || lower.contains("otel")
        || lower.contains("duckdb")
    {
        return Some(PlatformSubsystemId::Observability);
    }
    if lower == "model_runner"
        || lower == "model-runner"
        || lower.contains("model_runner")
        || lower.contains("model-runner")
        || lower.contains("modelrunner")
        || lower.contains("k3-engine")
        || lower.contains("k3-server")
        || lower.contains("k3-diag")
        || lower.contains("inference")
    {
        return Some(PlatformSubsystemId::ModelRunner);
    }
    if lower == "platform"
        || lower.contains("mu-console")
        || lower.contains("muconsole")
        || lower.contains("mu-auth")
        || lower.contains("control-plane")
    {
        return Some(PlatformSubsystemId::Platform);
    }

    None
}

/// Attributes a problem card to one of the 7 subsystems using entity, root-cause service,
/// affected services list, and telemetry category.
#[must_use]
pub fn classify_problem_subsystem(
    impacted_entity: &str,
    root_cause_service: &str,
    affected_services: &[String],
    category: &str,
) -> Option<PlatformSubsystemId> {
    if let Some(sub) = classify_service_subsystem(impacted_entity) {
        return Some(sub);
    }
    if let Some(sub) = classify_service_subsystem(root_cause_service) {
        return Some(sub);
    }
    for svc in affected_services {
        if let Some(sub) = classify_service_subsystem(svc) {
            return Some(sub);
        }
    }

    match category.trim().to_ascii_lowercase().as_str() {
        "benchmark_regression" | "test_flakiness" => Some(PlatformSubsystemId::Ci),
        "canary_taint" => Some(PlatformSubsystemId::AbDeploy),
        "heartbeat_staleness" => Some(PlatformSubsystemId::Platform),
        _ => None,
    }
}

/// Filters and tags [`CausalProblemCard`] alerts according to active subsystem maintenance windows.
#[must_use]
pub fn apply_maintenance_policy_to_causal_cards(
    cards: Vec<CausalProblemCard>,
    active_maintenance: &[(PlatformSubsystemId, SubsystemHealthState)],
) -> CausalMaintenanceFilterOutcome {
    let active_maintenance_subsystems: Vec<String> = active_maintenance
        .iter()
        .map(|(id, _)| id.as_str().to_string())
        .collect();

    if active_maintenance.is_empty() {
        return CausalMaintenanceFilterOutcome {
            active_problems: cards,
            suppressed_problems: Vec::new(),
            active_maintenance_subsystems,
        };
    }

    let mut active_problems = Vec::with_capacity(cards.len());
    let mut suppressed_problems = Vec::new();

    for mut card in cards {
        let attributed = classify_problem_subsystem(
            &card.impacted_entity,
            &card.root_cause_service,
            &card.affected_services,
            &card.category,
        );
        if let Some((sub_id, maint_state)) = attributed.and_then(|sub| {
            active_maintenance
                .iter()
                .find(|(id, _)| *id == sub)
                .copied()
        }) {
            card.maintenance_subsystem = Some(sub_id.as_str().to_string());
            card.maintenance_state = Some(maint_state.as_str().to_string());
            if maint_state == SubsystemHealthState::InMaintenance {
                card.maintenance_suppressed = Some(true);
                card.status = "SUPPRESSED_MAINTENANCE".to_string();
                suppressed_problems.push(card);
                continue;
            }
            card.maintenance_suppressed = Some(false);
        }
        active_problems.push(card);
    }

    CausalMaintenanceFilterOutcome {
        active_problems,
        suppressed_problems,
        active_maintenance_subsystems,
    }
}

/// Applies maintenance-window tagging and false-positive SLO suppression to [`ProblemsFeedResponse`].
#[must_use]
pub fn apply_maintenance_policy_to_deterministic_feed(
    mut feed: ProblemsFeedResponse,
    active_maintenance: &[(PlatformSubsystemId, SubsystemHealthState)],
) -> ProblemsFeedResponse {
    let active_subsystems: Vec<String> = active_maintenance
        .iter()
        .map(|(id, _)| id.as_str().to_string())
        .collect();

    if active_maintenance.is_empty() {
        return feed;
    }

    let mut remaining: Vec<ProblemCard> = Vec::with_capacity(feed.problems.len());
    let mut suppressed: Vec<ProblemCard> = Vec::new();

    for mut card in feed.problems.drain(..) {
        let attributed = classify_problem_subsystem(
            &card.impacted_entity,
            &card.impacted_entity,
            &[],
            &card.category,
        );
        if let Some((sub_id, maint_state)) = attributed.and_then(|sub| {
            active_maintenance
                .iter()
                .find(|(id, _)| *id == sub)
                .copied()
        }) {
            card.maintenance_subsystem = Some(sub_id.as_str().to_string());
            card.maintenance_state = Some(maint_state.as_str().to_string());
            if maint_state == SubsystemHealthState::InMaintenance {
                card.maintenance_suppressed = Some(true);
                card.status = "SUPPRESSED_MAINTENANCE".to_string();
                suppressed.push(card);
                continue;
            }
            card.maintenance_suppressed = Some(false);
        }
        remaining.push(card);
    }

    feed.open_count = remaining.len();
    feed.total = remaining.len();
    feed.suppressed_count = suppressed.len();
    feed.active_maintenance_subsystems = active_subsystems;
    feed.suppressed_problems = suppressed;
    feed.problems = remaining;
    feed
}

fn find_matching_upstream(
    id: PlatformSubsystemId,
    upstreams: &[IngressUpstreamDto],
) -> Option<&IngressUpstreamDto> {
    upstreams.iter().find(|u| {
        let svc = u.service_name.to_ascii_lowercase();
        match id {
            PlatformSubsystemId::Ci => {
                svc.contains("actionrunner")
                    || svc.contains("action-runner")
                    || svc.contains("muci")
                    || svc == "ci"
            }
            PlatformSubsystemId::Cd => svc.contains("muconde") || svc == "cd",
            PlatformSubsystemId::AbDeploy => {
                svc.contains("canary") || svc.contains("ab_deploy") || svc.contains("ab-deploy")
            }
            PlatformSubsystemId::Repository => {
                svc.contains("muregist") || svc.contains("registry") || svc == "repository"
            }
            PlatformSubsystemId::Observability => {
                svc.contains("muobserve") || svc == "observability"
            }
            PlatformSubsystemId::ModelRunner => {
                svc.contains("model-runner")
                    || svc.contains("model_runner")
                    || svc.contains("k3-engine")
                    || svc.contains("k3-server")
            }
            PlatformSubsystemId::Platform => {
                svc.contains("mu-console") || svc == "platform" || svc.contains("control-plane")
            }
        }
    })
}

fn map_upstream_probe(up: &IngressUpstreamDto) -> (SubsystemHealthState, String) {
    match up.health_state.to_ascii_uppercase().as_str() {
        "HEALTHY" => (
            SubsystemHealthState::Live,
            format!(
                "Live probe nominal ({:.1}% success, {:.1} ms)",
                up.success_rate_pct, up.latency_ms
            ),
        ),
        "DEGRADED" => (
            SubsystemHealthState::Degraded,
            format!(
                "Upstream {} degraded ({:.1}% success, {:.1} ms)",
                up.service_name, up.success_rate_pct, up.latency_ms
            ),
        ),
        _ => (
            SubsystemHealthState::Offline,
            format!("Upstream {} offline / unreachable", up.service_name),
        ),
    }
}

fn default_manual_summary(id: PlatformSubsystemId, state: SubsystemHealthState) -> String {
    match state {
        SubsystemHealthState::Live => {
            format!("{} manually marked live", id.display_label())
        }
        SubsystemHealthState::InMaintenance => {
            format!("{} in scheduled maintenance window", id.display_label())
        }
        SubsystemHealthState::PartialMaintenance => {
            format!("{} in partial maintenance window", id.display_label())
        }
        SubsystemHealthState::Offline => {
            format!("{} marked offline by operator", id.display_label())
        }
        SubsystemHealthState::Degraded => {
            format!("{} marked degraded by operator", id.display_label())
        }
    }
}

fn current_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_upstreams() -> Vec<IngressUpstreamDto> {
        vec![
            IngressUpstreamDto {
                upstream_id: "upstream-actionrunner-controller".into(),
                target_url: "http://127.0.0.1:8000/api/".into(),
                service_name: "actionrunner-controller".into(),
                health_state: "HEALTHY".into(),
                latency_ms: 4.2,
                success_rate_pct: 100.0,
                active_connections: 1,
                last_check_ms: 1_700_000_000_000,
            },
            IngressUpstreamDto {
                upstream_id: "upstream-muconde-controller".into(),
                target_url: "http://127.0.0.1:8444/api/cd/".into(),
                service_name: "muconde-controller".into(),
                health_state: "HEALTHY".into(),
                latency_ms: 3.1,
                success_rate_pct: 100.0,
                active_connections: 0,
                last_check_ms: 1_700_000_000_000,
            },
            IngressUpstreamDto {
                upstream_id: "upstream-muregist".into(),
                target_url: "http://127.0.0.1:8443/api/".into(),
                service_name: "muregist".into(),
                health_state: "HEALTHY".into(),
                latency_ms: 2.0,
                success_rate_pct: 100.0,
                active_connections: 0,
                last_check_ms: 1_700_000_000_000,
            },
        ]
    }

    #[test]
    fn test_all_seven_subsystems_default_to_auto_live_probe() {
        let reg = SubsystemStatusRegistry::in_memory();
        let snap = reg.snapshot(&sample_upstreams(), false, Some(1_700_000_000_000));

        assert_eq!(snap.total, 7);
        assert_eq!(snap.subsystems.len(), 7);
        assert_eq!(snap.overall_state, SubsystemHealthState::Live);
        assert_eq!(snap.maintenance_active_count, 0);
        for (expected, actual) in PlatformSubsystemId::ALL.iter().zip(snap.subsystems.iter()) {
            assert_eq!(actual.id, *expected);
            assert_eq!(actual.mode, SubsystemOverrideMode::Auto);
            assert_eq!(actual.mode_label, "Auto (Live Probe)");
            assert_eq!(actual.state, SubsystemHealthState::Live);
            assert!(!actual.maintenance_active);
        }
    }

    #[test]
    fn test_manual_five_state_overrides_clear_and_ttl_expiry() {
        let reg = SubsystemStatusRegistry::in_memory();
        let ups = sample_upstreams();
        let t0 = 1_700_000_000_000i64;

        for state_str in [
            "in-maintenance",
            "partial-maintenance",
            "offline",
            "degraded",
            "live",
        ] {
            let req = SubsystemMaintenanceRequest {
                state: Some(state_str.to_string()),
                summary: Some(
                    "Upgrade on https://10.20.30.40:8443 bearer=sk-testsecret999".to_string(),
                ),
                duration_secs: Some(60),
                actor: Some("operator-1".into()),
                ..Default::default()
            };
            let cmd = req.validate().expect("valid maintenance request");
            let (dto, ev) =
                reg.apply_maintenance_command(PlatformSubsystemId::Ci, cmd, &ups, Some(t0));
            assert_eq!(dto.state.as_str(), state_str);
            assert_eq!(dto.mode, SubsystemOverrideMode::Manual);
            assert_eq!(dto.mode_label, "Manual Override");
            assert_eq!(dto.expires_at_ms, Some(t0 + 60_000));
            assert!(!dto.summary.contains("10.20.30.40"));
            assert!(!dto.summary.contains("sk-testsecret999"));
            assert!(ev.subsystem_status_changed);
        }

        // Advance past expiration -> auto-clears back to Auto (Live Probe)
        let expired_events = reg.tick_expirations(Some(t0 + 60_001));
        assert_eq!(expired_events.len(), 1);
        assert_eq!(expired_events[0].mode, SubsystemOverrideMode::Auto);
        assert_eq!(expired_events[0].mode_label, "Auto (Live Probe)");

        let snap = reg.snapshot(&ups, false, Some(t0 + 60_002));
        let ci = snap
            .subsystems
            .iter()
            .find(|s| s.id == PlatformSubsystemId::Ci)
            .unwrap();
        assert_eq!(ci.mode, SubsystemOverrideMode::Auto);
        assert_eq!(ci.mode_label, "Auto (Live Probe)");
        assert_eq!(ci.expires_at_ms, None);
    }

    #[test]
    fn test_anonymous_redaction_strips_operator_details() {
        let reg = SubsystemStatusRegistry::in_memory();
        let ups = sample_upstreams();
        let req = SubsystemMaintenanceRequest {
            state: Some("in-maintenance".into()),
            summary: Some("Internal rolling kernel reboot for cluster-node".into()),
            actor: Some("alice@example.org".into()),
            ..Default::default()
        };
        let cmd = req.validate().unwrap();
        reg.apply_maintenance_command(
            PlatformSubsystemId::ModelRunner,
            cmd,
            &ups,
            Some(1_700_000_000_000),
        );

        let anon_snap = reg.snapshot(&ups, true, Some(1_700_000_000_100));
        let mr = anon_snap
            .subsystems
            .iter()
            .find(|s| s.id == PlatformSubsystemId::ModelRunner)
            .unwrap();
        assert_eq!(mr.state, SubsystemHealthState::InMaintenance);
        assert_eq!(mr.summary, "Scheduled maintenance in progress");
        assert_eq!(mr.updated_by, None);
        assert_eq!(mr.upstream_health, None);
    }

    #[test]
    fn test_causal_problem_suppression_in_maintenance_vs_partial_tag() {
        let make_card = |id: &str, svc: &str, cat: &str| CausalProblemCard {
            problem_id: id.into(),
            title: id.into(),
            severity: "critical".into(),
            status: "OPEN".into(),
            category: cat.into(),
            impacted_entity: svc.into(),
            slo_metric: "error_rate_pct=25.00%".into(),
            root_cause_service: svc.into(),
            root_cause_trace_id: None,
            root_cause_span_id: None,
            causal_chain: vec![svc.into()],
            confidence_score: 0.9,
            root_cause_error_message: None,
            artifact_digest: None,
            detected_at_ms: 1_700_000_000_000,
            summary: "test".into(),
            burn_rate_bp: 200,
            affected_services: vec![svc.into()],
            ai_diagnosis: None,
            maintenance_suppressed: None,
            maintenance_subsystem: None,
            maintenance_state: None,
        };

        let cards = vec![
            make_card("P1", "actionrunner-controller", "error_rate_spike"),
            make_card("P2", "muregist", "latency_regression"),
            make_card("P3", "muconde-controller", "error_rate_spike"),
        ];

        let outcome = apply_maintenance_policy_to_causal_cards(
            cards,
            &[
                (PlatformSubsystemId::Ci, SubsystemHealthState::InMaintenance),
                (
                    PlatformSubsystemId::Repository,
                    SubsystemHealthState::PartialMaintenance,
                ),
            ],
        );

        // CI in-maintenance suppresses P1; Repository partial-maintenance tags P2; CD active open P3
        assert_eq!(outcome.suppressed_problems.len(), 1);
        assert_eq!(outcome.suppressed_problems[0].problem_id, "P1");
        assert_eq!(
            outcome.suppressed_problems[0].maintenance_suppressed,
            Some(true)
        );
        assert_eq!(
            outcome.suppressed_problems[0]
                .maintenance_subsystem
                .as_deref(),
            Some("ci")
        );

        assert_eq!(outcome.active_problems.len(), 2);
        let p2 = outcome
            .active_problems
            .iter()
            .find(|c| c.problem_id == "P2")
            .unwrap();
        assert_eq!(p2.maintenance_suppressed, Some(false));
        assert_eq!(p2.maintenance_state.as_deref(), Some("partial-maintenance"));
        assert_eq!(p2.maintenance_subsystem.as_deref(), Some("repository"));

        let p3 = outcome
            .active_problems
            .iter()
            .find(|c| c.problem_id == "P3")
            .unwrap();
        assert_eq!(p3.maintenance_suppressed, None);
    }
}
