// SPDX-License-Identifier: AGPL-3.0-only
//! Canonical environment variable and default filesystem path resolution for `mu-observable-hub`,
//! preferring `MU_OBSERVABLE_HUB_*` variables and `/var/lib/mu-observable-hub` /
//! `/etc/mu-observable-hub` paths with backwards-compatible fallback to `MU_OBSERVABLE_*`,
//! `MUOBSERVE_*`, `/var/lib/muobserve`, and `/etc/muobserve`.

use std::path::{Path, PathBuf};

/// Canonical default DuckDB database paths checked in priority order when no override is configured.
pub const CANONICAL_DB_PATHS: &[&str] = &[
    "/var/lib/mu-observable-hub/hot.duckdb",
    "/var/lib/mu-observable-hub/db/mu-observable-hub.duckdb",
];

/// Legacy Phase 1 DuckDB database paths checked on disk when canonical paths do not exist.
pub const LEGACY_DB_PATHS: &[&str] = &[
    "/var/lib/muobserve/db/muobserve.duckdb",
    "/var/lib/muobserve/hot.duckdb",
];

/// Canonical default cold Zstd Parquet root directory.
pub const CANONICAL_PARQUET_ROOT: &str = "/var/lib/mu-observable-hub/parquet";

/// Legacy Phase 1 cold Parquet root directory.
pub const LEGACY_PARQUET_ROOT: &str = "/var/lib/muobserve/parquet";

/// Canonical and legacy TLS certificate paths.
pub const CANONICAL_CA_CERT_PATH: &str = "/etc/mu-observable-hub/tls/ca.crt";
pub const LEGACY_CA_CERT_PATH: &str = "/etc/muobserve/tls/ca.crt";
pub const CANONICAL_SERVER_CERT_PATH: &str = "/etc/mu-observable-hub/tls/server.crt";
pub const LEGACY_SERVER_CERT_PATH: &str = "/etc/muobserve/tls/server.crt";
pub const CANONICAL_SERVER_KEY_PATH: &str = "/etc/mu-observable-hub/tls/server.key";
pub const LEGACY_SERVER_KEY_PATH: &str = "/etc/muobserve/tls/server.key";

/// Environment variable names for database path override in priority order.
pub const ENV_DB_PATH_KEYS: &[&str] = &[
    "MU_OBSERVABLE_HUB_DB_PATH",
    "MU_OBSERVABLE_DB_PATH",
    "MUOBSERVE_DB_PATH",
];

/// Environment variable names for cold Parquet root override in priority order.
pub const ENV_PARQUET_ROOT_KEYS: &[&str] = &[
    "MU_OBSERVABLE_HUB_PARQUET_ROOT",
    "MU_OBSERVABLE_PARQUET_ROOT",
    "MUOBSERVE_PARQUET_ROOT",
];

/// Returns the first set environment variable value in `keys` (including empty strings).
#[must_use]
pub fn env_var_first(keys: &[&str]) -> Option<String> {
    env_var_first_with_lookup(keys, |k| std::env::var(k).ok())
}

/// Pure lookup variant of [`env_var_first`] for deterministic unit testing.
#[must_use]
pub fn env_var_first_with_lookup(
    keys: &[&str],
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Option<String> {
    for &key in keys {
        if let Some(val) = lookup(key) {
            return Some(val);
        }
    }
    None
}

/// Returns the first trimmed non-empty environment variable value across `keys`.
#[must_use]
pub fn non_empty_env_first(keys: &[&str]) -> Option<String> {
    non_empty_env_first_with_lookup(keys, |k| std::env::var(k).ok())
}

/// Pure lookup variant of [`non_empty_env_first`] for deterministic unit testing.
#[must_use]
pub fn non_empty_env_first_with_lookup(
    keys: &[&str],
    mut lookup: impl FnMut(&str) -> Option<String>,
) -> Option<String> {
    for &key in keys {
        if let Some(val) = lookup(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

/// Parses a boolean environment variable across `keys` in priority order.
#[must_use]
pub fn parse_bool_env_first(keys: &[&str], default: bool) -> bool {
    match non_empty_env_first(keys) {
        Some(v) => match v.to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => default,
        },
        None => default,
    }
}

/// Resolves a secret from `(value_env, file_env)` pairs in priority order.
///
/// Once a pair has either `file_env` or `value_env` configured as non-empty, resolution fails
/// closed (`None`) via [`mu_auth::resolve_secret_with_file_var`] if that source is unreadable or
/// empty rather than silently falling back to lower-priority legacy variables.
#[must_use]
pub fn resolve_secret_env_pairs(pairs: &[(&str, &str)]) -> Option<String> {
    for &(val_key, file_key) in pairs {
        let has_file = std::env::var(file_key).is_ok_and(|v| !v.trim().is_empty());
        let has_val = std::env::var(val_key).is_ok_and(|v| !v.trim().is_empty());
        if has_file || has_val {
            return mu_auth::resolve_secret_with_file_var(val_key, file_key);
        }
    }
    None
}

/// Resolves the first existing path from `canonical_candidates`, falling back to the first
/// existing path in `legacy_candidates`, or returning `None` if no candidate exists.
#[must_use]
pub fn resolve_existing_path_with_exists(
    canonical_candidates: &[&Path],
    legacy_candidates: &[&Path],
    mut exists: impl FnMut(&Path) -> bool,
) -> Option<PathBuf> {
    for &cand in canonical_candidates {
        if exists(cand) {
            return Some(cand.to_path_buf());
        }
    }
    for &legacy in legacy_candidates {
        if exists(legacy) {
            return Some(legacy.to_path_buf());
        }
    }
    None
}

/// Resolves a filesystem path preferring existing `canonical_candidates`, falling back to existing
/// `legacy_candidates`, and otherwise defaulting to `canonical_candidates[0]`.
#[must_use]
pub fn resolve_path_with_exists(
    canonical_candidates: &[&Path],
    legacy_candidates: &[&Path],
    exists: impl FnMut(&Path) -> bool,
) -> PathBuf {
    resolve_existing_path_with_exists(canonical_candidates, legacy_candidates, exists)
        .unwrap_or_else(|| {
            canonical_candidates
                .first()
                .map(|p| (*p).to_path_buf())
                .unwrap_or_default()
        })
}

/// Resolves the first existing path on disk across `canonical_candidates` then `legacy_candidates`.
#[must_use]
pub fn resolve_existing_path_with_fallback(
    canonical_candidates: &[&Path],
    legacy_candidates: &[&Path],
) -> Option<PathBuf> {
    resolve_existing_path_with_exists(canonical_candidates, legacy_candidates, |p| p.exists())
}

/// Resolves a path on disk across `canonical_candidates` then `legacy_candidates`, defaulting to
/// `canonical_candidates[0]` when neither exists yet.
#[must_use]
pub fn resolve_path_with_fallback(
    canonical_candidates: &[&Path],
    legacy_candidates: &[&Path],
) -> PathBuf {
    resolve_path_with_exists(canonical_candidates, legacy_candidates, |p| p.exists())
}

/// Resolves the DuckDB database path from CLI override, environment variables, or on-disk defaults.
///
/// When `require_path` is `true` (server `--serve` mode) and no env var or existing file is found,
/// returns the primary canonical path `/var/lib/mu-observable-hub/hot.duckdb`. When `require_path`
/// is `false` (CLI / stdio MCP), returns `None` if neither env var nor an existing file is found
/// so in-memory stores still work in unprivileged environments.
#[must_use]
pub fn resolve_db_path(cli_override: Option<&Path>, require_path: bool) -> Option<PathBuf> {
    if let Some(p) = cli_override {
        return Some(p.to_path_buf());
    }
    if let Some(env_val) = non_empty_env_first(ENV_DB_PATH_KEYS) {
        return Some(PathBuf::from(env_val));
    }
    let canonical: Vec<&Path> = CANONICAL_DB_PATHS.iter().map(Path::new).collect();
    let legacy: Vec<&Path> = LEGACY_DB_PATHS.iter().map(Path::new).collect();
    if require_path {
        Some(resolve_path_with_fallback(&canonical, &legacy))
    } else {
        resolve_existing_path_with_fallback(&canonical, &legacy)
    }
}

/// Resolves the cold Parquet root directory from CLI override, environment variables, sibling
/// database layout, or on-disk defaults.
#[must_use]
pub fn resolve_parquet_root(
    cli_override: Option<&Path>,
    db_path: Option<&Path>,
    require_path: bool,
) -> Option<PathBuf> {
    if let Some(p) = cli_override {
        return Some(p.to_path_buf());
    }
    if let Some(env_val) = non_empty_env_first(ENV_PARQUET_ROOT_KEYS) {
        return Some(PathBuf::from(env_val));
    }
    let canonical = [Path::new(CANONICAL_PARQUET_ROOT)];
    let legacy = [Path::new(LEGACY_PARQUET_ROOT)];
    if require_path {
        return Some(resolve_path_with_fallback(&canonical, &legacy));
    }
    if let Some(db) = db_path {
        if let Some(parent) = db.parent().filter(|p| !p.as_os_str().is_empty()) {
            if parent.file_name().and_then(|n| n.to_str()) == Some("db") {
                if let Some(grandparent) = parent.parent() {
                    let sibling = grandparent.join("parquet");
                    if sibling.exists() {
                        return Some(sibling);
                    }
                }
            }
            return Some(parent.join("parquet"));
        }
    }
    resolve_existing_path_with_fallback(&canonical, &legacy)
}

/// Resolves `(ca_cert_path, server_cert_path, server_key_path)` from `MU_OBSERVABLE_HUB_*` /
/// `MU_OBSERVABLE_*` / `MUOBSERVE_*` env vars, falling back on disk to `/etc/mu-observable-hub/tls/*`
/// and then `/etc/muobserve/tls/*`.
#[must_use]
pub fn resolve_tls_paths() -> (PathBuf, PathBuf, PathBuf) {
    let ca_path = non_empty_env_first(&[
        "MU_OBSERVABLE_HUB_CA_CERT",
        "MU_OBSERVABLE_CA_CERT",
        "MUOBSERVE_CA_CERT",
    ])
    .map(PathBuf::from)
    .unwrap_or_else(|| {
        resolve_path_with_fallback(
            &[Path::new(CANONICAL_CA_CERT_PATH)],
            &[Path::new(LEGACY_CA_CERT_PATH)],
        )
    });

    let cert_path = non_empty_env_first(&[
        "MU_OBSERVABLE_HUB_SERVER_CERT",
        "MU_OBSERVABLE_SERVER_CERT",
        "MUOBSERVE_SERVER_CERT",
    ])
    .map(PathBuf::from)
    .unwrap_or_else(|| {
        resolve_path_with_fallback(
            &[Path::new(CANONICAL_SERVER_CERT_PATH)],
            &[Path::new(LEGACY_SERVER_CERT_PATH)],
        )
    });

    let key_path = non_empty_env_first(&[
        "MU_OBSERVABLE_HUB_SERVER_KEY",
        "MU_OBSERVABLE_SERVER_KEY",
        "MUOBSERVE_SERVER_KEY",
    ])
    .map(PathBuf::from)
    .unwrap_or_else(|| {
        resolve_path_with_fallback(
            &[Path::new(CANONICAL_SERVER_KEY_PATH)],
            &[Path::new(LEGACY_SERVER_KEY_PATH)],
        )
    });

    (ca_path, cert_path, key_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    static CONFIG_ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn capture(keys: &[&'static str]) -> Self {
            let saved = keys.iter().map(|&k| (k, std::env::var(k).ok())).collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.saved {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn test_env_precedence_and_blank_skipping() {
        let mut map = HashMap::new();
        map.insert("MU_OBSERVABLE_HUB_DB_PATH", "   ");
        map.insert("MU_OBSERVABLE_DB_PATH", "/mid/db.duckdb");
        map.insert("MUOBSERVE_DB_PATH", "/legacy/db.duckdb");

        let chosen = non_empty_env_first_with_lookup(ENV_DB_PATH_KEYS, |k| {
            map.get(k).map(|s| (*s).to_string())
        });
        assert_eq!(chosen.as_deref(), Some("/mid/db.duckdb"));

        map.insert("MU_OBSERVABLE_HUB_DB_PATH", "/canonical/hot.duckdb");
        let chosen = non_empty_env_first_with_lookup(ENV_DB_PATH_KEYS, |k| {
            map.get(k).map(|s| (*s).to_string())
        });
        assert_eq!(chosen.as_deref(), Some("/canonical/hot.duckdb"));

        // env_var_first preserves explicit empty string (needed for ANONYMOUS_FOLIOS="")
        let mut anon_map = HashMap::new();
        anon_map.insert("MU_OBSERVABLE_HUB_ANONYMOUS_FOLIOS", "");
        anon_map.insert("MUOBSERVE_ANONYMOUS_FOLIOS", "folio:system:status");
        let anon = env_var_first_with_lookup(
            &[
                "MU_OBSERVABLE_HUB_ANONYMOUS_FOLIOS",
                "MU_OBSERVABLE_ANONYMOUS_FOLIOS",
                "MUOBSERVE_ANONYMOUS_FOLIOS",
            ],
            |k| anon_map.get(k).map(|s| (*s).to_string()),
        );
        assert_eq!(anon.as_deref(), Some(""));
    }

    #[test]
    fn test_canonical_and_legacy_path_fallback_logic() {
        let can = [
            Path::new("/var/lib/mu-observable-hub/hot.duckdb"),
            Path::new("/var/lib/mu-observable-hub/db/mu-observable-hub.duckdb"),
        ];
        let leg = [
            Path::new("/var/lib/muobserve/db/muobserve.duckdb"),
            Path::new("/var/lib/muobserve/hot.duckdb"),
        ];

        // 1. Neither exists -> defaults to primary canonical path
        assert_eq!(
            resolve_path_with_exists(&can, &leg, |_| false),
            PathBuf::from("/var/lib/mu-observable-hub/hot.duckdb")
        );
        assert_eq!(
            resolve_existing_path_with_exists(&can, &leg, |_| false),
            None
        );

        // 2. Only legacy exists -> falls back to legacy
        assert_eq!(
            resolve_path_with_exists(&can, &leg, |p| {
                p == Path::new("/var/lib/muobserve/db/muobserve.duckdb")
            }),
            PathBuf::from("/var/lib/muobserve/db/muobserve.duckdb")
        );

        // 3. Both canonical and legacy exist -> canonical wins
        assert_eq!(
            resolve_path_with_exists(&can, &leg, |p| {
                p == Path::new("/var/lib/mu-observable-hub/db/mu-observable-hub.duckdb")
                    || p == Path::new("/var/lib/muobserve/db/muobserve.duckdb")
            }),
            PathBuf::from("/var/lib/mu-observable-hub/db/mu-observable-hub.duckdb")
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_real_env_and_filesystem_fallback_resolution() {
        let _lock = CONFIG_ENV_LOCK.lock().expect("env lock");
        let _guard = EnvGuard::capture(&[
            "MU_OBSERVABLE_HUB_DB_PATH",
            "MU_OBSERVABLE_DB_PATH",
            "MUOBSERVE_DB_PATH",
            "MU_OBSERVABLE_HUB_PARQUET_ROOT",
            "MU_OBSERVABLE_PARQUET_ROOT",
            "MUOBSERVE_PARQUET_ROOT",
            "MU_OBSERVABLE_HUB_CA_CERT",
            "MU_OBSERVABLE_CA_CERT",
            "MUOBSERVE_CA_CERT",
            "MU_OBSERVABLE_HUB_SERVER_CERT",
            "MU_OBSERVABLE_SERVER_CERT",
            "MUOBSERVE_SERVER_CERT",
            "MU_OBSERVABLE_HUB_SERVER_KEY",
            "MU_OBSERVABLE_SERVER_KEY",
            "MUOBSERVE_SERVER_KEY",
            "MU_OBSERVABLE_HUB_SERVE",
            "MU_OBSERVABLE_SERVE",
            "MUOBSERVE_SERVE",
            "MU_OBSERVABLE_HUB_PROXY_SECRET",
            "MU_OBSERVABLE_HUB_PROXY_SECRET_FILE",
            "MUOBSERVE_PROXY_SECRET",
            "MUOBSERVE_PROXY_SECRET_FILE",
        ]);

        for &k in &[
            "MU_OBSERVABLE_HUB_DB_PATH",
            "MU_OBSERVABLE_DB_PATH",
            "MUOBSERVE_DB_PATH",
            "MU_OBSERVABLE_HUB_PARQUET_ROOT",
            "MU_OBSERVABLE_PARQUET_ROOT",
            "MUOBSERVE_PARQUET_ROOT",
            "MU_OBSERVABLE_HUB_CA_CERT",
            "MU_OBSERVABLE_CA_CERT",
            "MUOBSERVE_CA_CERT",
            "MU_OBSERVABLE_HUB_SERVER_CERT",
            "MU_OBSERVABLE_SERVER_CERT",
            "MUOBSERVE_SERVER_CERT",
            "MU_OBSERVABLE_HUB_SERVER_KEY",
            "MU_OBSERVABLE_SERVER_KEY",
            "MUOBSERVE_SERVER_KEY",
            "MU_OBSERVABLE_HUB_SERVE",
            "MU_OBSERVABLE_SERVE",
            "MUOBSERVE_SERVE",
            "MU_OBSERVABLE_HUB_PROXY_SECRET",
            "MU_OBSERVABLE_HUB_PROXY_SECRET_FILE",
            "MUOBSERVE_PROXY_SECRET",
            "MUOBSERVE_PROXY_SECRET_FILE",
        ] {
            std::env::remove_var(k);
        }

        // Legacy fallback when canonical env unset
        std::env::set_var("MUOBSERVE_DB_PATH", "/tmp/legacy.duckdb");
        std::env::set_var("MUOBSERVE_PARQUET_ROOT", "/tmp/legacy-parquet");
        assert_eq!(
            resolve_db_path(None, true),
            Some(PathBuf::from("/tmp/legacy.duckdb"))
        );
        assert_eq!(
            resolve_parquet_root(None, None, true),
            Some(PathBuf::from("/tmp/legacy-parquet"))
        );

        // Canonical env overrides legacy env
        std::env::set_var("MU_OBSERVABLE_HUB_DB_PATH", "/tmp/hub.duckdb");
        std::env::set_var("MU_OBSERVABLE_HUB_PARQUET_ROOT", "/tmp/hub-parquet");
        assert_eq!(
            resolve_db_path(None, true),
            Some(PathBuf::from("/tmp/hub.duckdb"))
        );
        assert_eq!(
            resolve_parquet_root(None, None, true),
            Some(PathBuf::from("/tmp/hub-parquet"))
        );

        // CLI flag overrides canonical env
        assert_eq!(
            resolve_db_path(Some(Path::new("/tmp/cli.duckdb")), true),
            Some(PathBuf::from("/tmp/cli.duckdb"))
        );

        // Bool env precedence
        std::env::set_var("MUOBSERVE_SERVE", "true");
        std::env::set_var("MU_OBSERVABLE_HUB_SERVE", "false");
        assert!(!parse_bool_env_first(
            &[
                "MU_OBSERVABLE_HUB_SERVE",
                "MU_OBSERVABLE_SERVE",
                "MUOBSERVE_SERVE"
            ],
            false
        ));

        // Secret file resolution + fail-closed when canonical file path is unreadable
        let dir = tempfile::tempdir().expect("tempdir");
        let secret_file = dir.path().join("proxy.secret");
        std::fs::write(&secret_file, "hub-proxy-secret-val\n").unwrap();
        std::env::set_var("MUOBSERVE_PROXY_SECRET", "legacy-secret");
        std::env::set_var("MU_OBSERVABLE_HUB_PROXY_SECRET_FILE", &secret_file);
        assert_eq!(
            resolve_secret_env_pairs(&[
                (
                    "MU_OBSERVABLE_HUB_PROXY_SECRET",
                    "MU_OBSERVABLE_HUB_PROXY_SECRET_FILE"
                ),
                ("MUOBSERVE_PROXY_SECRET", "MUOBSERVE_PROXY_SECRET_FILE"),
            ]),
            Some("hub-proxy-secret-val".to_string())
        );

        let missing_file = dir.path().join("missing.secret");
        std::env::set_var("MU_OBSERVABLE_HUB_PROXY_SECRET_FILE", &missing_file);
        assert_eq!(
            resolve_secret_env_pairs(&[
                (
                    "MU_OBSERVABLE_HUB_PROXY_SECRET",
                    "MU_OBSERVABLE_HUB_PROXY_SECRET_FILE"
                ),
                ("MUOBSERVE_PROXY_SECRET", "MUOBSERVE_PROXY_SECRET_FILE"),
            ]),
            None
        );

        // On-disk fallback using real temp files
        let can_tls = dir.path().join("etc-hub/tls/ca.crt");
        let leg_tls = dir.path().join("etc-legacy/tls/ca.crt");
        std::fs::create_dir_all(leg_tls.parent().unwrap()).unwrap();
        std::fs::write(&leg_tls, "legacy-ca").unwrap();
        assert_eq!(
            resolve_path_with_fallback(&[can_tls.as_path()], &[leg_tls.as_path()]),
            leg_tls
        );
        std::fs::create_dir_all(can_tls.parent().unwrap()).unwrap();
        std::fs::write(&can_tls, "canonical-ca").unwrap();
        assert_eq!(
            resolve_path_with_fallback(&[can_tls.as_path()], &[leg_tls.as_path()]),
            can_tls
        );
    }
}
