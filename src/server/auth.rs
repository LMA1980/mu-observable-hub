// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization gate and fail-closed `mu-auth` folio policy enforcement for observability
//! and platform control endpoints.

use std::collections::{BTreeSet, HashMap};
use std::sync::RwLock;

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use mu_auth::{
    canonical_super_operator_folios, constant_time_str_eq, evaluate_session, resolve_secret_value,
    EdgeAuthConfig, FolioCatalog, FolioError, FolioId, GithubEdgeAuthAdapter, Principal,
    RoleCatalog, RoleFolioIndex, RoleId, RoleLease, RoleLeases, RoleSpec, StepUpRequirement,
    SUPER_OPERATOR_ROLE_ID,
};
use serde_json::json;

/// Granular `mu-auth` policy permission required by an observability or platform control endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObsPermission {
    /// Read overall 7-subsystem operational status (`system:status.read`).
    SystemStatusRead,
    /// Read Smartscape dependency topology (`obs:smartscape.read`).
    SmartscapeRead,
    /// Read active SLO degradation and causal problem feeds (`obs:problems.read`).
    ProblemsRead,
    /// Query distributed W3C traces and PurePath waterfalls (`obs:traces.read`).
    TracesRead,
    /// Query sanitized OpenTelemetry log records and CI job logs (`obs:logs.read`).
    LogsRead,
    /// Read hardware and service benchmark telemetry (`obs:metrics.read`).
    MetricsRead,
    /// Inspect DuckDB/Parquet analytics store status (`obs:store.read`).
    StoreRead,
    /// Inspect telemetry collector ingress routes and upstreams (`obs:ingress.read`).
    IngressRead,
    /// Mutate ingress routing or TLS configuration (`obs:ingress.write`).
    IngressWrite,
    /// Read detailed operator maintenance records (`platform:maintenance.read`).
    PlatformMaintenanceRead,
    /// Manage subsystem maintenance overrides (`platform:maintenance.write`).
    PlatformMaintenanceWrite,
}

impl ObsPermission {
    /// Returns the canonical `mu-auth` [`mu_auth::PolicyId`] string for this permission.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemStatusRead => "system:status.read",
            Self::SmartscapeRead => "obs:smartscape.read",
            Self::ProblemsRead => "obs:problems.read",
            Self::TracesRead => "obs:traces.read",
            Self::LogsRead => "obs:logs.read",
            Self::MetricsRead => "obs:metrics.read",
            Self::StoreRead => "obs:store.read",
            Self::IngressRead => "obs:ingress.read",
            Self::IngressWrite => "obs:ingress.write",
            Self::PlatformMaintenanceRead => "platform:maintenance.read",
            Self::PlatformMaintenanceWrite => "platform:maintenance.write",
        }
    }

    /// Returns `true` when this permission mutates ingress or platform maintenance state.
    #[must_use]
    pub const fn is_write_permission(self) -> bool {
        matches!(self, Self::IngressWrite | Self::PlatformMaintenanceWrite)
    }
}

/// Verified caller identity and resolved `mu-auth` policy grants returned by [`ObsAuthVerifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub authenticated: bool,
    pub is_anonymous: bool,
    pub subject: Option<String>,
    pub folios: Vec<String>,
    pub granted_policies: Vec<String>,
}

impl AuthContext {
    /// Returns `true` when `policy` was granted by the evaluated session.
    #[must_use]
    pub fn has_policy(&self, policy: &str) -> bool {
        self.granted_policies.iter().any(|p| p == policy)
    }

    /// Returns `true` when an authenticated caller may view full non-anonymous observability/status details.
    #[must_use]
    pub fn can_read_full_observability(&self) -> bool {
        self.authenticated
            && !self.is_anonymous
            && (self.has_policy("platform:maintenance.read") || self.has_policy("obs:ingress.read"))
    }
}

/// Fail-closed authorization error returned when a caller lacks a required `mu-auth` policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRejection {
    pub message: &'static str,
    pub realm: &'static str,
}

/// Authorization policy verifier trait implemented by [`MuAuthFolioVerifier`].
pub trait ObsAuthVerifier: Send + Sync {
    /// Evaluates `headers` against `permission`, failing closed when access is denied.
    fn authorize(
        &self,
        headers: &HeaderMap,
        permission: ObsPermission,
    ) -> Result<AuthContext, AuthRejection>;
}

#[derive(Debug, Clone)]
struct PrincipalBinding {
    passkey_count: usize,
    bound_roles: BTreeSet<RoleId>,
    leases: RoleLeases,
}

#[derive(Debug)]
struct PolicyEngineState {
    folio_catalog: FolioCatalog,
    role_catalog: RoleCatalog,
    role_folio_index: RoleFolioIndex,
    edge_adapter: Option<GithubEdgeAuthAdapter>,
    principals: HashMap<String, PrincipalBinding>,
    service_token_override: Option<String>,
}

/// Fail-closed authorization verifier powered by `mu-auth` [`FolioCatalog`], [`RoleCatalog`],
/// [`RoleFolioIndex`], [`GithubEdgeAuthAdapter`], and [`evaluate_session`].
#[derive(Debug)]
pub struct MuAuthFolioVerifier {
    state: RwLock<PolicyEngineState>,
}

impl Default for MuAuthFolioVerifier {
    fn default() -> Self {
        Self::from_env()
    }
}

impl MuAuthFolioVerifier {
    /// Constructs a verifier from environment configuration.
    ///
    /// - When `MU_OBSERVABLE_HUB_PROXY_SECRET` / `MU_OBSERVABLE_HUB_PROXY_SECRET_FILE` (or legacy
    ///   `MU_OBSERVABLE_PROXY_SECRET*` / `MUOBSERVE_PROXY_SECRET*`) is configured, edge proxy
    ///   authentication is strictly enforced via [`GithubEdgeAuthAdapter`], and anonymous visitors
    ///   receive only `folio:system:status` unless overridden by
    ///   `MU_OBSERVABLE_HUB_ANONYMOUS_FOLIOS` / `MUOBSERVE_ANONYMOUS_FOLIOS` or
    ///   `MU_OBSERVABLE_HUB_ANONYMOUS_LOCKDOWN=true`.
    /// - When `MU_OBSERVABLE_HUB_ANONYMOUS_LOCKDOWN=true`, anonymous visitors receive `[]`
    ///   (returning `401` on all endpoints).
    #[must_use]
    pub fn from_env() -> Self {
        let proxy_secret = crate::config::resolve_secret_env_pairs(&[
            (
                "MU_OBSERVABLE_HUB_PROXY_SECRET",
                "MU_OBSERVABLE_HUB_PROXY_SECRET_FILE",
            ),
            (
                "MU_OBSERVABLE_PROXY_SECRET",
                "MU_OBSERVABLE_PROXY_SECRET_FILE",
            ),
            ("MUOBSERVE_PROXY_SECRET", "MUOBSERVE_PROXY_SECRET_FILE"),
        ]);
        let edge_adapter = EdgeAuthConfig::with_secret_and_loopback(proxy_secret.as_deref(), false)
            .ok()
            .map(GithubEdgeAuthAdapter::new);

        let lockdown = crate::config::parse_bool_env_first(
            &[
                "MU_OBSERVABLE_HUB_ANONYMOUS_LOCKDOWN",
                "MU_OBSERVABLE_ANONYMOUS_LOCKDOWN",
                "MUOBSERVE_ANONYMOUS_LOCKDOWN",
            ],
            false,
        );
        let explicit_folios = crate::config::env_var_first(&[
            "MU_OBSERVABLE_HUB_ANONYMOUS_FOLIOS",
            "MU_OBSERVABLE_ANONYMOUS_FOLIOS",
            "MUOBSERVE_ANONYMOUS_FOLIOS",
        ]);
        let status_flag = crate::config::parse_bool_env_first(
            &[
                "MU_OBSERVABLE_HUB_ANONYMOUS_STATUS_READ",
                "MU_OBSERVABLE_ANONYMOUS_STATUS_READ",
                "MUOBSERVE_ANONYMOUS_STATUS_READ",
            ],
            true,
        );
        let default_obs = edge_adapter.is_none();
        let obs_flag = crate::config::parse_bool_env_first(
            &[
                "MU_OBSERVABLE_HUB_ANONYMOUS_OBS_READ",
                "MU_OBSERVABLE_ANONYMOUS_OBS_READ",
                "MUOBSERVE_ANONYMOUS_OBS_READ",
            ],
            default_obs,
        );

        let anon_folio_ids: Vec<String> = if lockdown {
            Vec::new()
        } else if let Some(raw_list) = explicit_folios {
            parse_anonymous_folio_list(&raw_list)
        } else {
            let mut list = Vec::new();
            if status_flag {
                list.push("folio:system:status".to_string());
            }
            if obs_flag {
                list.push("folio:obs:read".to_string());
            }
            list
        };

        let anon_refs: Vec<&str> = anon_folio_ids.iter().map(String::as_str).collect();
        let verifier = Self::build_internal(edge_adapter, &anon_refs, None);

        if let Some(op_users) = crate::config::non_empty_env_first(&[
            "MU_OBSERVABLE_HUB_OPERATOR_USERS",
            "MU_OBSERVABLE_OPERATOR_USERS",
            "MUOBSERVE_OPERATOR_USERS",
        ]) {
            let role_catalog = verifier.state.read().expect("lock").role_catalog.clone();
            let now_ms = current_epoch_ms();
            for login in op_users.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let (_, leases) = full_operator_principal_and_leases(&role_catalog, login, now_ms);
                verifier.bind_principal(
                    login,
                    1,
                    &[
                        "viewer",
                        "ingress-admin",
                        "platform-admin",
                        SUPER_OPERATOR_ROLE_ID,
                    ],
                    leases,
                );
            }
        }

        verifier
    }

    /// Builds a strict locked-down verifier where anonymous visitors have zero folios (`401` on all routes).
    #[must_use]
    pub fn locked_down(edge_secret: Option<&str>) -> Self {
        let edge_adapter = edge_secret
            .and_then(|s| EdgeAuthConfig::with_proxy_secret(s).ok())
            .map(GithubEdgeAuthAdapter::new);
        Self::build_internal(edge_adapter, &[], None)
    }

    /// Builds a verifier granting anonymous visitors only `folio:system:status` (redacted status reads)
    /// while locking down all observability reads and control writes (`401`).
    #[must_use]
    pub fn public_status_only(edge_secret: Option<&str>) -> Self {
        let edge_adapter = edge_secret
            .and_then(|s| EdgeAuthConfig::with_proxy_secret(s).ok())
            .map(GithubEdgeAuthAdapter::new);
        Self::build_internal(edge_adapter, &["folio:system:status"], None)
    }

    /// Builds a verifier with custom anonymous toggle compatibility and optional edge proxy secret.
    #[must_use]
    pub fn with_anonymous_policy(status_read_enabled: bool, obs_read_enabled: bool) -> Self {
        let mut folios = Vec::new();
        if status_read_enabled {
            folios.push("folio:system:status");
        }
        if obs_read_enabled {
            folios.push("folio:obs:read");
        }
        Self::build_internal(None, &folios, None)
    }

    /// Configures an explicit in-memory operator Bearer token (for isolated tests without global env mutation).
    pub fn set_service_token_for_test(&self, token: Option<&str>) {
        if let Ok(mut guard) = self.state.write() {
            guard.service_token_override = token.and_then(resolve_secret_value);
        }
    }

    /// Updates anonymous read folios dynamically (`folio:system:status`, `folio:obs:read`).
    pub fn set_anonymous_policy(&self, status_read_enabled: bool, obs_read_enabled: bool) {
        let mut wanted = BTreeSet::new();
        if status_read_enabled {
            wanted.insert(FolioId::new("folio:system:status").expect("valid folio"));
        }
        if obs_read_enabled {
            wanted.insert(FolioId::new("folio:obs:read").expect("valid folio"));
        }
        if let Ok(mut guard) = self.state.write() {
            let catalog = guard.folio_catalog.clone();
            let _ = guard
                .role_folio_index
                .set_anonymous_folios(wanted, &catalog);
        }
    }

    /// Registers an authenticated GitHub principal, enrolled Passkey count, bound roles, and active leases.
    pub fn bind_principal(
        &self,
        login: &str,
        passkey_count: usize,
        bound_roles: &[&str],
        leases: RoleLeases,
    ) {
        let role_set: BTreeSet<RoleId> = bound_roles
            .iter()
            .filter_map(|r| RoleId::new(*r).ok())
            .collect();
        if let Ok(mut guard) = self.state.write() {
            guard.principals.insert(
                login.trim().to_ascii_lowercase(),
                PrincipalBinding {
                    passkey_count,
                    bound_roles: role_set,
                    leases,
                },
            );
        }
    }

    /// Activates an elective role (such as `ingress-admin`) for an already bound principal.
    pub fn enable_elective_role(&self, login: &str, role_id: &str) -> Result<(), FolioError> {
        let role = RoleId::new(role_id)?;
        let mut guard = self.state.write().expect("auth lock");
        let role_catalog = guard.role_catalog.clone();
        let entry = guard
            .principals
            .get_mut(&login.trim().to_ascii_lowercase())
            .ok_or_else(|| FolioError::UnauthorizedActivation {
                role: role_id.to_string(),
            })?;
        let principal = Principal::Authenticated {
            login: login.trim().to_string(),
            passkey_count: entry.passkey_count,
            bound_roles: entry.bound_roles.clone(),
        };
        entry
            .leases
            .enable_elective(&role_catalog, &principal, &role, true)?;
        Ok(())
    }

    /// Activates a short-lived `Timed` role (such as `platform-admin`) enforcing `mu-auth` Passkey & TTL rules.
    pub fn activate_timed_role(
        &self,
        login: &str,
        role_id: &str,
        step_up_verified: bool,
        now_ms: u64,
    ) -> Result<RoleLease, FolioError> {
        let role = RoleId::new(role_id)?;
        let mut guard = self.state.write().expect("auth lock");
        let role_catalog = guard.role_catalog.clone();
        let entry = guard
            .principals
            .get_mut(&login.trim().to_ascii_lowercase())
            .ok_or_else(|| FolioError::UnauthorizedActivation {
                role: role_id.to_string(),
            })?;
        let principal = Principal::Authenticated {
            login: login.trim().to_string(),
            passkey_count: entry.passkey_count,
            bound_roles: entry.bound_roles.clone(),
        };
        let lease = entry.leases.activate_timed(
            &role_catalog,
            &principal,
            &role,
            now_ms,
            step_up_verified,
        )?;
        Ok(lease.clone())
    }

    /// Extends an active renewable `Timed` role lease (such as `super-operator`) within its final
    /// renewal window after fresh Passkey step-up verification.
    pub fn renew_timed_role(
        &self,
        login: &str,
        role_id: &str,
        step_up_verified: bool,
        now_ms: u64,
    ) -> Result<RoleLease, FolioError> {
        let role = RoleId::new(role_id)?;
        let mut guard = self.state.write().expect("auth lock");
        let role_catalog = guard.role_catalog.clone();
        let entry = guard
            .principals
            .get_mut(&login.trim().to_ascii_lowercase())
            .ok_or_else(|| FolioError::UnauthorizedActivation {
                role: role_id.to_string(),
            })?;
        let principal = Principal::Authenticated {
            login: login.trim().to_string(),
            passkey_count: entry.passkey_count,
            bound_roles: entry.bound_roles.clone(),
        };
        let lease =
            entry
                .leases
                .renew_timed(&role_catalog, &principal, &role, now_ms, step_up_verified)?;
        Ok(lease.clone())
    }

    /// Records explicit user activity to extend active idle timers up to each lease's hard deadline.
    pub fn record_activity(&self, login: &str, now_ms: u64) {
        if let Ok(mut guard) = self.state.write() {
            if let Some(entry) = guard.principals.get_mut(&login.trim().to_ascii_lowercase()) {
                let _ = entry.leases.record_activity(now_ms);
            }
        }
    }

    fn build_internal(
        edge_adapter: Option<GithubEdgeAuthAdapter>,
        anonymous_folios: &[&str],
        service_token_override: Option<String>,
    ) -> Self {
        let folio_catalog = FolioCatalog::with_canonical_manifests();

        let viewer_id = RoleId::new("viewer").expect("valid role");
        let ingress_admin_id = RoleId::new("ingress-admin").expect("valid role");
        let platform_admin_id = RoleId::new("platform-admin").expect("valid role");
        let super_operator_id = RoleId::new(SUPER_OPERATOR_ROLE_ID).expect("valid role");

        let role_catalog = RoleCatalog::from_roles([
            RoleSpec::pinned_baseline(
                viewer_id.clone(),
                Some("Baseline Viewer"),
                "Read-only access to operational status, observability views, and maintenance banners",
            )
            .expect("valid viewer role"),
            RoleSpec::elective(
                ingress_admin_id.clone(),
                Some("Ingress Admin"),
                "Manage dynamic ingress reverse-proxy routes and TLS health",
                StepUpRequirement::Passkey,
            )
            .expect("valid ingress admin role"),
            RoleSpec::timed(
                platform_admin_id.clone(),
                Some("Platform Admin"),
                "Time-bounded Passkey-gated platform maintenance & administrative control",
                1800,
                600,
            )
            .expect("valid platform admin role"),
            RoleSpec::super_operator(),
        ])
        .expect("valid role catalog");

        let mut role_folio_index = RoleFolioIndex::new();
        let safe_anon_folios: BTreeSet<FolioId> = anonymous_folios
            .iter()
            .filter(|id| !matches!(**id, "folio:obs:ingress-admin" | "folio:platform:admin"))
            .filter_map(|id| FolioId::new(*id).ok())
            .collect();
        role_folio_index
            .set_anonymous_folios(safe_anon_folios, &folio_catalog)
            .expect("valid anonymous folios");

        role_folio_index
            .set_role_folios(
                viewer_id,
                BTreeSet::from([
                    FolioId::new("folio:system:status").expect("folio"),
                    FolioId::new("folio:obs:read").expect("folio"),
                    FolioId::new("folio:platform:read").expect("folio"),
                ]),
                &folio_catalog,
                &role_catalog,
            )
            .expect("valid viewer folios");
        role_folio_index
            .set_role_folios(
                ingress_admin_id,
                BTreeSet::from([
                    FolioId::new("folio:obs:ingress-admin").expect("folio"),
                    FolioId::new("folio:obs:read").expect("folio"),
                ]),
                &folio_catalog,
                &role_catalog,
            )
            .expect("valid ingress admin folios");
        role_folio_index
            .set_role_folios(
                platform_admin_id,
                BTreeSet::from([
                    FolioId::new("folio:platform:admin").expect("folio"),
                    FolioId::new("folio:system:status").expect("folio"),
                ]),
                &folio_catalog,
                &role_catalog,
            )
            .expect("valid platform admin folios");
        role_folio_index
            .set_role_folios(
                super_operator_id,
                BTreeSet::from(canonical_super_operator_folios()),
                &folio_catalog,
                &role_catalog,
            )
            .expect("valid super-operator folios");

        Self {
            state: RwLock::new(PolicyEngineState {
                folio_catalog,
                role_catalog,
                role_folio_index,
                edge_adapter,
                principals: HashMap::new(),
                service_token_override,
            }),
        }
    }

    fn evaluate_at(
        &self,
        headers: &HeaderMap,
        permission: ObsPermission,
        now_ms: u64,
    ) -> Result<AuthContext, AuthRejection> {
        let state = self.state.read().map_err(|_| AuthRejection {
            message: "Unauthorized: auth state lock unavailable",
            realm: "mu-observe",
        })?;

        // 1. Service/Operator Bearer credential path (strict constant-time match, fail closed when unset)
        if headers.contains_key(header::AUTHORIZATION) {
            let presented = extract_bearer_token(headers).ok_or(AuthRejection {
                message: "Unauthorized: valid Bearer token required",
                realm: "mu-observe",
            })?;
            let expected = state
                .service_token_override
                .clone()
                .or_else(expected_service_token);

            let Some(exp) = expected else {
                return Err(AuthRejection {
                    message: "Unauthorized: service operator token not configured",
                    realm: "mu-observe",
                });
            };
            if presented.is_empty() || !constant_time_str_eq(presented, &exp) {
                return Err(AuthRejection {
                    message: "Unauthorized: invalid Bearer token",
                    realm: "mu-observe",
                });
            }

            let (principal, leases) =
                full_operator_principal_and_leases(&state.role_catalog, "operator-token", now_ms);

            return evaluate_policy_result(
                &state,
                &principal,
                &leases,
                permission,
                now_ms,
                Some("operator-token".to_string()),
            );
        }

        // 2. Trusted Edge Proxy (`X-Proxy-Secret` + `X-Forwarded-User`) verification via `mu-auth`
        let has_edge_headers = headers.contains_key(mu_auth::HEADER_FORWARDED_USER)
            || headers.contains_key(mu_auth::HEADER_PROXY_SECRET)
            || headers.contains_key(mu_auth::HEADER_FORWARDED_EMAIL);

        if has_edge_headers {
            let Some(ref edge_adapter) = state.edge_adapter else {
                return Err(AuthRejection {
                    message: "Unauthorized: proxy trust boundary not configured",
                    realm: "mu-observe",
                });
            };

            let mut header_pairs = Vec::with_capacity(headers.len());
            for (name, val) in headers {
                let s = val.to_str().map_err(|_| AuthRejection {
                    message: "Unauthorized: malformed proxy header encoding",
                    realm: "mu-observe",
                })?;
                header_pairs.push((name.as_str(), s));
            }

            let identity_opt = edge_adapter
                .authenticate_header_iter(header_pairs, None)
                .map_err(|_| AuthRejection {
                    message: "Unauthorized: invalid edge proxy authentication headers",
                    realm: "mu-observe",
                })?;

            if let Some(identity) = identity_opt {
                let login_lower = identity.login.to_lowercase();
                let (principal, leases) = match state.principals.get(&login_lower) {
                    Some(binding) => (
                        Principal::Authenticated {
                            login: identity.login.as_str().to_string(),
                            passkey_count: binding.passkey_count,
                            bound_roles: binding.bound_roles.clone(),
                        },
                        binding.leases.clone(),
                    ),
                    None => (
                        Principal::Authenticated {
                            login: identity.login.as_str().to_string(),
                            passkey_count: 0,
                            bound_roles: BTreeSet::new(),
                        },
                        RoleLeases::default(),
                    ),
                };

                return evaluate_policy_result(
                    &state,
                    &principal,
                    &leases,
                    permission,
                    now_ms,
                    Some(identity.login.as_str().to_string()),
                );
            }
        }

        // 3. Anonymous visitor evaluated strictly against `RoleFolioIndex::anonymous_folios()`
        if permission.is_write_permission() {
            return Err(AuthRejection {
                message: "Unauthorized: authenticated folio required for control mutations",
                realm: "mu-observe",
            });
        }

        evaluate_policy_result(
            &state,
            &Principal::Anonymous,
            &RoleLeases::default(),
            permission,
            now_ms,
            None,
        )
    }
}

impl ObsAuthVerifier for MuAuthFolioVerifier {
    fn authorize(
        &self,
        headers: &HeaderMap,
        permission: ObsPermission,
    ) -> Result<AuthContext, AuthRejection> {
        self.evaluate_at(headers, permission, current_epoch_ms())
    }
}

fn evaluate_policy_result(
    state: &PolicyEngineState,
    principal: &Principal,
    leases: &RoleLeases,
    permission: ObsPermission,
    now_ms: u64,
    subject: Option<String>,
) -> Result<AuthContext, AuthRejection> {
    let eval = evaluate_session(
        &state.folio_catalog,
        &state.role_catalog,
        &state.role_folio_index,
        principal,
        leases,
        now_ms,
    )
    .map_err(|_| AuthRejection {
        message: "Unauthorized: folio session evaluation failed",
        realm: "mu-observe",
    })?;

    if eval.passkey_enrollment_required {
        return Err(AuthRejection {
            message: "Unauthorized: Passkey enrollment required before accessing subsystem folios",
            realm: "mu-observe",
        });
    }

    if permission.is_write_permission() && eval.is_anonymous {
        return Err(AuthRejection {
            message: "Unauthorized: anonymous principals cannot perform write operations",
            realm: "mu-observe",
        });
    }

    if !eval.has_policy_str(permission.as_str()) {
        return Err(AuthRejection {
            message: if permission.is_write_permission() {
                "Unauthorized: missing required administrative mu-auth folio"
            } else {
                "Unauthorized: missing required read mu-auth folio"
            },
            realm: if permission == ObsPermission::IngressWrite {
                "mu-ingress"
            } else {
                "mu-observe"
            },
        });
    }

    let folios = eval
        .active_folios
        .iter()
        .map(|f| f.as_str().to_string())
        .collect();
    let granted_policies = eval
        .policies
        .iter()
        .map(|p| p.as_str().to_string())
        .collect();

    Ok(AuthContext {
        authenticated: !eval.is_anonymous,
        is_anonymous: eval.is_anonymous,
        subject,
        folios,
        granted_policies,
    })
}

/// Evaluates an HTTP request against `verifier` for `permission`, returning a boxed `401` JSON
/// response with `Cache-Control: no-store` and `WWW-Authenticate` on failure.
pub fn authorize_http_request(
    verifier: &dyn ObsAuthVerifier,
    headers: &HeaderMap,
    permission: ObsPermission,
) -> Result<AuthContext, Box<Response>> {
    verifier.authorize(headers, permission).map_err(|rej| {
        let challenge = format!("Bearer realm=\"{}\"", rej.realm);
        Box::new(
            (
                StatusCode::UNAUTHORIZED,
                [
                    (header::CACHE_CONTROL, "no-store".to_string()),
                    (header::WWW_AUTHENTICATE, challenge),
                ],
                Json(json!({
                    "error": rej.message,
                    "status": 401,
                    "required_permission": permission.as_str(),
                })),
            )
                .into_response(),
        )
    })
}

/// Evaluates an HTTP request against `verifier` across a set of read `permissions`,
/// returning the first matching [`AuthContext`] or a fail-closed `401` response.
pub fn authorize_http_any_read(
    verifier: &dyn ObsAuthVerifier,
    headers: &HeaderMap,
    permissions: &[ObsPermission],
) -> Result<AuthContext, Box<Response>> {
    let mut last_err: Option<Box<Response>> = None;
    for &perm in permissions {
        if perm.is_write_permission() {
            continue;
        }
        match authorize_http_request(verifier, headers, perm) {
            Ok(ctx) => return Ok(ctx),
            Err(resp) => last_err = Some(resp),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        authorize_http_request(verifier, headers, ObsPermission::ProblemsRead)
            .err()
            .unwrap_or_else(|| {
                Box::new(
                    (
                        StatusCode::UNAUTHORIZED,
                        [(header::CACHE_CONTROL, "no-store".to_string())],
                        Json(json!({
                            "error": "Unauthorized: missing required read mu-auth folio",
                            "status": 401,
                        })),
                    )
                        .into_response(),
                )
            })
    }))
}

/// Extracts a trimmed `Bearer <token>` credential from an HTTP header map.
pub(crate) fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|val| {
            val.strip_prefix("Bearer ")
                .or_else(|| val.strip_prefix("bearer "))
        })
        .map(str::trim)
}

fn expected_service_token() -> Option<String> {
    crate::config::resolve_secret_env_pairs(&[
        (
            "MU_OBSERVABLE_HUB_INGRESS_ADMIN_TOKEN",
            "MU_OBSERVABLE_HUB_INGRESS_ADMIN_TOKEN_FILE",
        ),
        (
            "MU_OBSERVABLE_INGRESS_ADMIN_TOKEN",
            "MU_OBSERVABLE_INGRESS_ADMIN_TOKEN_FILE",
        ),
        (
            "MUOBSERVE_INGRESS_ADMIN_TOKEN",
            "MUOBSERVE_INGRESS_ADMIN_TOKEN_FILE",
        ),
    ])
    .or_else(|| {
        crate::config::resolve_secret_env_pairs(&[
            (
                "MU_OBSERVABLE_HUB_OPERATOR_TOKEN",
                "MU_OBSERVABLE_HUB_OPERATOR_TOKEN_FILE",
            ),
            (
                "MU_OBSERVABLE_OPERATOR_TOKEN",
                "MU_OBSERVABLE_OPERATOR_TOKEN_FILE",
            ),
            ("MUOBSERVE_OPERATOR_TOKEN", "MUOBSERVE_OPERATOR_TOKEN_FILE"),
        ])
    })
    .or_else(|| {
        crate::config::resolve_secret_env_pairs(&[
            (
                "MU_OBSERVABLE_HUB_BEARER_TOKEN",
                "MU_OBSERVABLE_HUB_BEARER_TOKEN_FILE",
            ),
            (
                "MU_OBSERVABLE_BEARER_TOKEN",
                "MU_OBSERVABLE_BEARER_TOKEN_FILE",
            ),
            ("MUOBSERVE_BEARER_TOKEN", "MUOBSERVE_BEARER_TOKEN_FILE"),
        ])
    })
}

fn parse_anonymous_folio_list(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        return Vec::new();
    }
    trimmed
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn current_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn full_operator_principal_and_leases(
    role_catalog: &RoleCatalog,
    login: &str,
    now_ms: u64,
) -> (Principal, RoleLeases) {
    let viewer = RoleId::new("viewer").expect("role");
    let ingress_admin = RoleId::new("ingress-admin").expect("role");
    let platform_admin = RoleId::new("platform-admin").expect("role");
    let bound_roles = BTreeSet::from([viewer, ingress_admin.clone(), platform_admin.clone()]);
    let principal = Principal::Authenticated {
        login: login.to_string(),
        passkey_count: 1,
        bound_roles,
    };
    let mut leases = RoleLeases::default();
    let _ = leases.enable_elective(role_catalog, &principal, &ingress_admin, true);
    let _ = leases.activate_timed(role_catalog, &principal, &platform_admin, now_ms, true);
    (principal, leases)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_locked_down_verifier_denies_all_anonymous_and_writes() {
        let verifier = MuAuthFolioVerifier::locked_down(Some("proxy-secret-val"));
        let empty = HeaderMap::new();

        for perm in [
            ObsPermission::SystemStatusRead,
            ObsPermission::SmartscapeRead,
            ObsPermission::ProblemsRead,
            ObsPermission::LogsRead,
            ObsPermission::IngressWrite,
            ObsPermission::PlatformMaintenanceWrite,
        ] {
            assert!(
                verifier.authorize(&empty, perm).is_err(),
                "locked-down verifier must reject anonymous {perm:?}"
            );
        }
    }

    #[test]
    fn test_public_status_only_exposes_redacted_status_and_blocks_obs_and_writes() {
        let verifier = MuAuthFolioVerifier::public_status_only(Some("proxy-secret-val"));
        let empty = HeaderMap::new();

        let status_ctx = verifier
            .authorize(&empty, ObsPermission::SystemStatusRead)
            .expect("anonymous system:status.read permitted");
        assert!(status_ctx.is_anonymous);
        assert!(!status_ctx.can_read_full_observability());

        assert!(verifier
            .authorize(&empty, ObsPermission::ProblemsRead)
            .is_err());
        assert!(verifier.authorize(&empty, ObsPermission::LogsRead).is_err());
        assert!(verifier
            .authorize(&empty, ObsPermission::IngressWrite)
            .is_err());
        assert!(verifier
            .authorize(&empty, ObsPermission::PlatformMaintenanceWrite)
            .is_err());
    }

    #[test]
    fn test_edge_proxy_folios_passkey_gate_and_timed_lease_expiry() {
        let verifier = MuAuthFolioVerifier::locked_down(Some("edge-secret-123"));
        let t0 = 1_700_000_000_000u64;

        // Unenrolled Passkey user (`passkey_count == 0`) fails closed even with valid proxy secret
        verifier.bind_principal(
            "alice",
            0,
            &["viewer", "platform-admin"],
            RoleLeases::default(),
        );
        let mut alice_headers = HeaderMap::new();
        alice_headers.insert(
            "x-proxy-secret",
            HeaderValue::from_static("edge-secret-123"),
        );
        alice_headers.insert("x-forwarded-user", HeaderValue::from_static("alice"));
        assert!(verifier
            .evaluate_at(&alice_headers, ObsPermission::SystemStatusRead, t0)
            .is_err());

        // Spoofed header without valid proxy secret is rejected
        verifier.bind_principal(
            "bob",
            1,
            &["viewer", "ingress-admin", "platform-admin"],
            RoleLeases::default(),
        );
        let mut spoofed = HeaderMap::new();
        spoofed.insert("x-proxy-secret", HeaderValue::from_static("wrong-secret"));
        spoofed.insert("x-forwarded-user", HeaderValue::from_static("bob"));
        assert!(verifier
            .evaluate_at(&spoofed, ObsPermission::ProblemsRead, t0)
            .is_err());

        // Valid Passkey user `bob` gets baseline `viewer` (`obs:*.read`, `system:status.read`),
        // NOT `ingress.write` / `maintenance.write` until roles are explicitly activated
        let mut bob_headers = HeaderMap::new();
        bob_headers.insert(
            "x-proxy-secret",
            HeaderValue::from_static("edge-secret-123"),
        );
        bob_headers.insert("x-forwarded-user", HeaderValue::from_static("bob"));
        let read_ctx = verifier
            .evaluate_at(&bob_headers, ObsPermission::ProblemsRead, t0)
            .expect("baseline viewer reads problems");
        assert!(read_ctx.can_read_full_observability());
        assert!(verifier
            .evaluate_at(&bob_headers, ObsPermission::IngressWrite, t0)
            .is_err());
        assert!(verifier
            .evaluate_at(&bob_headers, ObsPermission::PlatformMaintenanceWrite, t0)
            .is_err());

        // Enable elective `ingress-admin` and timed Passkey `platform-admin` at t0
        verifier
            .enable_elective_role("bob", "ingress-admin")
            .expect("enable elective ingress-admin");
        verifier
            .activate_timed_role("bob", "platform-admin", true, t0)
            .expect("activate timed platform-admin");

        assert!(verifier
            .evaluate_at(&bob_headers, ObsPermission::IngressWrite, t0 + 10_000)
            .is_ok());
        assert!(verifier
            .evaluate_at(
                &bob_headers,
                ObsPermission::PlatformMaintenanceWrite,
                t0 + 10_000,
            )
            .is_ok());

        // After idle TTL (600s) expires without activity, timed `platform:maintenance.write` fails closed!
        assert!(verifier
            .evaluate_at(
                &bob_headers,
                ObsPermission::PlatformMaintenanceWrite,
                t0 + 601_000,
            )
            .is_err());
    }

    #[test]
    fn test_malformed_bearer_token_fails_closed() {
        let verifier = MuAuthFolioVerifier::with_anonymous_policy(true, true);
        verifier.set_service_token_for_test(Some("valid-service-secret"));

        let mut bad_headers = HeaderMap::new();
        bad_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer wrong"),
        );
        assert!(verifier
            .authorize(&bad_headers, ObsPermission::SystemStatusRead)
            .is_err());

        let mut empty_bearer = HeaderMap::new();
        empty_bearer.insert(header::AUTHORIZATION, HeaderValue::from_static("Bearer "));
        assert!(verifier
            .authorize(&empty_bearer, ObsPermission::SystemStatusRead)
            .is_err());

        let mut ok_headers = HeaderMap::new();
        ok_headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer valid-service-secret"),
        );
        assert!(verifier
            .authorize(&ok_headers, ObsPermission::PlatformMaintenanceWrite)
            .is_ok());
        assert!(verifier
            .authorize(&ok_headers, ObsPermission::IngressWrite)
            .is_ok());
    }

    #[test]
    fn test_super_operator_grants_all_obs_permissions_and_supports_single_last_2m_renewal() {
        let verifier = MuAuthFolioVerifier::locked_down(Some("edge-secret-123"));
        let t0 = 1_000_000_u64;
        verifier.bind_principal(
            "alice",
            1,
            &["viewer", SUPER_OPERATOR_ROLE_ID],
            RoleLeases::default(),
        );
        let mut alice_headers = HeaderMap::new();
        alice_headers.insert(
            "x-proxy-secret",
            HeaderValue::from_static("edge-secret-123"),
        );
        alice_headers.insert("x-forwarded-user", HeaderValue::from_static("alice"));

        // Activation requires Passkey step-up confirmation.
        assert!(matches!(
            verifier.activate_timed_role("alice", SUPER_OPERATOR_ROLE_ID, false, t0),
            Err(FolioError::StepUpRequired { .. })
        ));
        let initial = verifier
            .activate_timed_role("alice", SUPER_OPERATOR_ROLE_ID, true, t0)
            .expect("passkey activates super-operator");
        assert_eq!(initial.hard_expires_at_ms, t0 + 900_000);
        assert_eq!(initial.idle_expires_at_ms, t0 + 120_000);

        assert!(verifier
            .evaluate_at(&alice_headers, ObsPermission::IngressWrite, t0 + 1_000)
            .is_ok());
        assert!(verifier
            .evaluate_at(
                &alice_headers,
                ObsPermission::PlatformMaintenanceWrite,
                t0 + 1_000,
            )
            .is_ok());

        for offset in [
            90_000, 180_000, 270_000, 360_000, 450_000, 540_000, 630_000, 720_000, 779_000,
        ] {
            verifier.record_activity("alice", t0 + offset);
        }
        assert!(matches!(
            verifier.renew_timed_role("alice", SUPER_OPERATOR_ROLE_ID, true, t0 + 779_000),
            Err(FolioError::RenewalWindowNotReached { .. })
        ));
        assert!(matches!(
            verifier.renew_timed_role("alice", SUPER_OPERATOR_ROLE_ID, false, t0 + 780_000),
            Err(FolioError::StepUpRequired { .. })
        ));
        let renewed = verifier
            .renew_timed_role("alice", SUPER_OPERATOR_ROLE_ID, true, t0 + 780_000)
            .expect("single last-2m Passkey renewal succeeds");
        assert_eq!(renewed.hard_expires_at_ms, t0 + 1_800_000);
        verifier.record_activity("alice", t0 + 880_000);
        verifier.record_activity("alice", t0 + 920_000);
        assert!(verifier
            .evaluate_at(
                &alice_headers,
                ObsPermission::PlatformMaintenanceWrite,
                t0 + 920_000,
            )
            .is_ok());
        assert!(matches!(
            verifier.renew_timed_role("alice", SUPER_OPERATOR_ROLE_ID, true, t0 + 920_000),
            Err(FolioError::RenewalLimitReached { .. })
        ));
        assert!(verifier
            .evaluate_at(
                &alice_headers,
                ObsPermission::PlatformMaintenanceWrite,
                t0 + 1_040_000,
            )
            .is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_canonical_hub_auth_env_precedence() {
        static AUTH_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _lock = AUTH_ENV_LOCK.lock().expect("auth env lock");
        let keys = [
            "MU_OBSERVABLE_HUB_PROXY_SECRET",
            "MU_OBSERVABLE_HUB_PROXY_SECRET_FILE",
            "MU_OBSERVABLE_PROXY_SECRET",
            "MU_OBSERVABLE_PROXY_SECRET_FILE",
            "MUOBSERVE_PROXY_SECRET",
            "MUOBSERVE_PROXY_SECRET_FILE",
            "MU_OBSERVABLE_HUB_ANONYMOUS_FOLIOS",
            "MU_OBSERVABLE_ANONYMOUS_FOLIOS",
            "MUOBSERVE_ANONYMOUS_FOLIOS",
            "MU_OBSERVABLE_HUB_INGRESS_ADMIN_TOKEN",
            "MU_OBSERVABLE_HUB_INGRESS_ADMIN_TOKEN_FILE",
            "MUOBSERVE_INGRESS_ADMIN_TOKEN",
            "MUOBSERVE_INGRESS_ADMIN_TOKEN_FILE",
        ];
        let saved: Vec<(&str, Option<String>)> =
            keys.iter().map(|&k| (k, std::env::var(k).ok())).collect();
        for k in keys {
            std::env::remove_var(k);
        }

        std::env::set_var("MUOBSERVE_PROXY_SECRET", "legacy-edge-secret");
        std::env::set_var("MU_OBSERVABLE_HUB_PROXY_SECRET", "hub-edge-secret");
        std::env::set_var("MUOBSERVE_ANONYMOUS_FOLIOS", "folio:obs:read");
        std::env::set_var("MU_OBSERVABLE_HUB_ANONYMOUS_FOLIOS", "folio:system:status");
        std::env::set_var("MUOBSERVE_INGRESS_ADMIN_TOKEN", "legacy-admin");
        std::env::set_var("MU_OBSERVABLE_HUB_INGRESS_ADMIN_TOKEN", "hub-admin");

        let verifier = MuAuthFolioVerifier::from_env();
        let empty = HeaderMap::new();
        assert!(verifier
            .authorize(&empty, ObsPermission::SystemStatusRead)
            .is_ok());
        assert!(verifier
            .authorize(&empty, ObsPermission::ProblemsRead)
            .is_err());

        let mut bearer = HeaderMap::new();
        bearer.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer hub-admin"),
        );
        assert!(verifier
            .authorize(&bearer, ObsPermission::IngressWrite)
            .is_ok());

        let mut legacy_bearer = HeaderMap::new();
        legacy_bearer.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer legacy-admin"),
        );
        assert!(verifier
            .authorize(&legacy_bearer, ObsPermission::IngressWrite)
            .is_err());

        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
}
