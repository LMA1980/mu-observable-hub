// SPDX-License-Identifier: AGPL-3.0-only
//! Authorization gate and `mu-auth` folio interface seam for observability & platform routes.

use std::sync::atomic::{AtomicBool, Ordering};

use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// Logical permission required by an observability or platform control endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObsPermission {
    /// Read observability data (`obs:*.read`: Smartscape, problems, traces, logs, metrics, ingress overview).
    ObservabilityRead,
    /// Mutate ingress routing or TLS configuration (`obs:ingress.write`).
    IngressWrite,
    /// Manage subsystem maintenance windows (`platform:maintenance.write` / `folio:platform:admin`).
    PlatformMaintenanceWrite,
    /// Read overall 7-subsystem operational status (`system:status.read`).
    SystemStatusRead,
}

impl ObsPermission {
    /// Returns the canonical permission scope string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservabilityRead => "obs:*.read",
            Self::IngressWrite => "obs:ingress.write",
            Self::PlatformMaintenanceWrite => "platform:maintenance.write",
            Self::SystemStatusRead => "system:status.read",
        }
    }
}

/// Verified caller identity and folio grants returned by [`ObsAuthVerifier`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthContext {
    pub authenticated: bool,
    pub is_anonymous: bool,
    pub subject: Option<String>,
    pub folios: Vec<String>,
}

impl AuthContext {
    /// Returns `true` when the caller may view unredacted full observability telemetry.
    #[must_use]
    pub fn can_read_full_observability(&self) -> bool {
        self.authenticated && !self.is_anonymous
    }
}

/// Fail-closed authorization error returned when a caller lacks a required permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRejection {
    pub message: &'static str,
    pub realm: &'static str,
}

/// Authorization policy verifier seam allowing clean drop-in `mu-auth` folio integration.
pub trait ObsAuthVerifier: Send + Sync {
    /// Evaluates `headers` against `permission`, failing closed when access is denied.
    fn authorize(
        &self,
        headers: &HeaderMap,
        permission: ObsPermission,
    ) -> Result<AuthContext, AuthRejection>;
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

/// Default authorization policy guard supporting Bearer tokens and configurable anonymous policy.
///
/// Write permissions (`IngressWrite`, `PlatformMaintenanceWrite`) always fail closed unless valid
/// credentials are supplied. Anonymous `SystemStatusRead` visibility can be locked down independently
/// via `MUOBSERVE_ANONYMOUS_STATUS_READ` or runtime toggle so status endpoints emit `401` when locked down.
#[derive(Debug)]
pub struct DefaultObsAuthGuard {
    anonymous_status_read_enabled: AtomicBool,
    anonymous_obs_read_enabled: AtomicBool,
}

impl Default for DefaultObsAuthGuard {
    fn default() -> Self {
        Self::from_env()
    }
}

impl DefaultObsAuthGuard {
    /// Constructs a guard reading initial anonymous read toggles from environment variables.
    #[must_use]
    pub fn from_env() -> Self {
        let anon_status = parse_bool_env("MUOBSERVE_ANONYMOUS_STATUS_READ", true);
        let anon_obs = parse_bool_env("MUOBSERVE_ANONYMOUS_OBS_READ", true);
        Self {
            anonymous_status_read_enabled: AtomicBool::new(anon_status),
            anonymous_obs_read_enabled: AtomicBool::new(anon_obs),
        }
    }

    /// Creates a guard with explicit anonymous read policy flags (primarily for deterministic tests).
    #[must_use]
    pub fn with_anonymous_policy(status_read_enabled: bool, obs_read_enabled: bool) -> Self {
        Self {
            anonymous_status_read_enabled: AtomicBool::new(status_read_enabled),
            anonymous_obs_read_enabled: AtomicBool::new(obs_read_enabled),
        }
    }

    /// Sets whether anonymous callers are granted `system:status.read` (redacted status visibility).
    pub fn set_anonymous_status_read(&self, enabled: bool) {
        self.anonymous_status_read_enabled
            .store(enabled, Ordering::Relaxed);
    }

    /// Sets whether anonymous callers are granted `obs:*.read`.
    pub fn set_anonymous_obs_read(&self, enabled: bool) {
        self.anonymous_obs_read_enabled
            .store(enabled, Ordering::Relaxed);
    }

    /// Returns whether anonymous `system:status.read` is currently enabled.
    #[must_use]
    pub fn is_anonymous_status_read_enabled(&self) -> bool {
        self.anonymous_status_read_enabled.load(Ordering::Relaxed)
    }

    /// Returns whether anonymous `obs:*.read` is currently enabled.
    #[must_use]
    pub fn is_anonymous_obs_read_enabled(&self) -> bool {
        self.anonymous_obs_read_enabled.load(Ordering::Relaxed)
    }
}

impl ObsAuthVerifier for DefaultObsAuthGuard {
    fn authorize(
        &self,
        headers: &HeaderMap,
        permission: ObsPermission,
    ) -> Result<AuthContext, AuthRejection> {
        if let Some(presented) = extract_bearer_token(headers) {
            let expected = expected_admin_token();
            return match expected {
                Some(exp)
                    if !presented.is_empty()
                        && crate::ingress::constant_time_eq(
                            presented.as_bytes(),
                            exp.as_bytes(),
                        ) =>
                {
                    Ok(AuthContext {
                        authenticated: true,
                        is_anonymous: false,
                        subject: Some("operator-token".to_string()),
                        folios: vec![
                            "obs:*.read".to_string(),
                            "obs:ingress.write".to_string(),
                            "platform:maintenance.write".to_string(),
                            "system:status.read".to_string(),
                        ],
                    })
                }
                _ => Err(AuthRejection {
                    message: "Unauthorized: invalid Bearer token",
                    realm: "mu-observe",
                }),
            };
        }

        match permission {
            ObsPermission::SystemStatusRead => {
                if self.is_anonymous_status_read_enabled() {
                    Ok(AuthContext {
                        authenticated: false,
                        is_anonymous: true,
                        subject: None,
                        folios: vec!["system:status.read".to_string()],
                    })
                } else {
                    Err(AuthRejection {
                        message: "Unauthorized: anonymous status access disabled",
                        realm: "mu-observe",
                    })
                }
            }
            ObsPermission::ObservabilityRead => {
                if self.is_anonymous_obs_read_enabled() {
                    Ok(AuthContext {
                        authenticated: false,
                        is_anonymous: true,
                        subject: None,
                        folios: vec!["obs:*.read".to_string()],
                    })
                } else {
                    Err(AuthRejection {
                        message: "Unauthorized: observability read authentication required",
                        realm: "mu-observe",
                    })
                }
            }
            ObsPermission::IngressWrite => Err(AuthRejection {
                message: "Unauthorized: Ingress admin Bearer token required",
                realm: "mu-ingress",
            }),
            ObsPermission::PlatformMaintenanceWrite => Err(AuthRejection {
                message: "Unauthorized: maintenance write authorization required",
                realm: "mu-observe",
            }),
        }
    }
}

/// Extracts a trimmed `Bearer <token>` credential from an HTTP header map.
pub(crate) fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|val| {
            val.strip_prefix("Bearer ")
                .or_else(|| val.strip_prefix("bearer "))
        })
        .map(str::trim)
}

fn expected_admin_token() -> Option<String> {
    crate::ingress::non_empty_env("MUOBSERVE_INGRESS_ADMIN_TOKEN")
        .or_else(|| crate::ingress::non_empty_env("MUOBSERVE_OPERATOR_TOKEN"))
        .or_else(|| crate::ingress::non_empty_env("MUOBSERVE_BEARER_TOKEN"))
}

fn parse_bool_env(key: &str, default: bool) -> bool {
    match crate::ingress::non_empty_env(key) {
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        None => default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn test_auth_guard_fails_closed_for_write_permissions() {
        let guard = DefaultObsAuthGuard::with_anonymous_policy(true, true);
        let empty = HeaderMap::new();

        assert!(guard
            .authorize(&empty, ObsPermission::IngressWrite)
            .is_err());
        assert!(guard
            .authorize(&empty, ObsPermission::PlatformMaintenanceWrite)
            .is_err());

        let status_ctx = guard
            .authorize(&empty, ObsPermission::SystemStatusRead)
            .expect("anonymous system:status.read allowed when enabled");
        assert!(status_ctx.is_anonymous);
        assert!(!status_ctx.can_read_full_observability());
    }

    #[test]
    fn test_auth_guard_anonymous_lockdown_returns_rejection() {
        let guard = DefaultObsAuthGuard::with_anonymous_policy(false, false);
        let empty = HeaderMap::new();

        assert!(guard
            .authorize(&empty, ObsPermission::SystemStatusRead)
            .is_err());
        assert!(guard
            .authorize(&empty, ObsPermission::ObservabilityRead)
            .is_err());
    }

    #[test]
    fn test_auth_guard_rejects_malformed_bearer_token() {
        let guard = DefaultObsAuthGuard::with_anonymous_policy(true, true);
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer "),
        );
        assert!(guard
            .authorize(&headers, ObsPermission::SystemStatusRead)
            .is_err());
    }
}
