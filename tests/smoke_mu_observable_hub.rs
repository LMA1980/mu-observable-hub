#![deny(unsafe_code)]

use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use mu_observable_hub::{
    build_console_api_router_with_auth, build_mtls_server_config, collect_storage_health_status,
    HotDuckDbStore, IngestServerConfig, IngressEngine, MtlsIngestServer, MuAuthFolioVerifier,
    ObsAuthVerifier, StoreStatusResponse, SubsystemsStatusResponse,
};
use mu_observable_ipc::{
    decode_control_envelope, encode_control_envelope, read_frame, write_frame, ControlRpcEnvelope,
    IpcHeader, QueryJobsHistoryRequest, MSG_TYPE_FORY_CONTROL,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

const DEFAULT_SMOKE_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone)]
struct SmokeConfig {
    target_url: Option<String>,
    target_addr: Option<String>,
    tls_ca_file: Option<PathBuf>,
    tls_cert_file: Option<PathBuf>,
    tls_key_file: Option<PathBuf>,
    server_name: Option<String>,
    bearer_token: Option<String>,
    timeout: Duration,
}

impl SmokeConfig {
    fn from_env() -> Result<Self, String> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup<F>(lookup: F) -> Result<Self, String>
    where
        F: Fn(&str) -> Option<String>,
    {
        let tls_ca_file = non_empty_path(&lookup, "MU_SMOKE_TLS_CA_FILE")?;
        let tls_cert_file = non_empty_path(&lookup, "MU_SMOKE_TLS_CERT_FILE")?;
        let tls_key_file = non_empty_path(&lookup, "MU_SMOKE_TLS_KEY_FILE")?;

        if tls_cert_file.is_some() != tls_key_file.is_some() {
            return Err(
                "MU_SMOKE_TLS_CERT_FILE and MU_SMOKE_TLS_KEY_FILE must both be set when configuring client mTLS"
                    .to_string(),
            );
        }

        if let Some(ref ca_path) = tls_ca_file {
            load_certs(ca_path, "MU_SMOKE_TLS_CA_FILE")?;
        }
        if let (Some(ref cert_path), Some(ref key_path)) = (&tls_cert_file, &tls_key_file) {
            load_certs(cert_path, "MU_SMOKE_TLS_CERT_FILE")?;
            load_key(key_path, "MU_SMOKE_TLS_KEY_FILE")?;
        }

        let bearer_token = match non_empty_path(&lookup, "MU_SMOKE_BEARER_TOKEN_FILE")? {
            Some(path) => Some(read_trimmed_secret(&path, "MU_SMOKE_BEARER_TOKEN_FILE")?),
            None => None,
        };

        let timeout_secs = match non_empty_var(&lookup, "MU_SMOKE_TIMEOUT_SECS") {
            Some(raw) => {
                let parsed = raw
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid MU_SMOKE_TIMEOUT_SECS '{raw}': {e}"))?;
                if parsed == 0 {
                    return Err("MU_SMOKE_TIMEOUT_SECS must be greater than 0".to_string());
                }
                parsed
            }
            None => DEFAULT_SMOKE_TIMEOUT_SECS,
        };

        let target_url = non_empty_var(&lookup, "MU_SMOKE_TARGET_URL")
            .map(|u| u.trim_end_matches('/').to_string());
        let target_addr =
            non_empty_var(&lookup, "MU_SMOKE_TARGET_ADDR").map(|a| normalize_host_port(&a));
        let server_name = non_empty_var(&lookup, "MU_SMOKE_TLS_SERVER_NAME");

        Ok(Self {
            target_url,
            target_addr,
            tls_ca_file,
            tls_cert_file,
            tls_key_file,
            server_name,
            bearer_token,
            timeout: Duration::from_secs(timeout_secs),
        })
    }
}

fn normalize_host_port(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    let stripped = trimmed
        .strip_prefix("tls://")
        .or_else(|| trimmed.strip_prefix("https://"))
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    stripped.split('/').next().unwrap_or(stripped).to_string()
}

fn non_empty_var<F>(lookup: &F, key: &str) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    lookup(key)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn non_empty_path<F>(lookup: &F, key: &str) -> Result<Option<PathBuf>, String>
where
    F: Fn(&str) -> Option<String>,
{
    match lookup(key) {
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                Err(format!("{key} was set but empty"))
            } else {
                Ok(Some(PathBuf::from(trimmed)))
            }
        }
        None => Ok(None),
    }
}

fn read_trimmed_secret(path: &Path, var_name: &str) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Failed to read {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "{var_name} at '{}' is empty after trimming (fail closed)",
            path.display()
        ));
    }
    Ok(trimmed.to_string())
}

fn load_certs(path: &Path, var_name: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let file = File::open(path).map_err(|e| {
        format!(
            "Failed to open {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            format!(
                "Invalid PEM certificate in {var_name} at '{}': {e}",
                path.display()
            )
        })?;
    if certs.is_empty() {
        return Err(format!(
            "{var_name} at '{}' contains zero certificates",
            path.display()
        ));
    }
    Ok(certs)
}

fn load_key(path: &Path, var_name: &str) -> Result<PrivateKeyDer<'static>, String> {
    let file = File::open(path).map_err(|e| {
        format!(
            "Failed to open {var_name} at '{}': {e} (fail closed)",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    PrivateKeyDer::from_pem_reader(&mut reader).map_err(|e| {
        format!(
            "Invalid PEM private key in {var_name} at '{}': {e}",
            path.display()
        )
    })
}

fn build_tls_connector(
    ca_path: Option<&Path>,
    client_identity: Option<(&Path, &Path)>,
) -> Result<TlsConnector, String> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let mut root_store = rustls::RootCertStore::empty();
    if let Some(ca) = ca_path {
        for cert in load_certs(ca, "MU_SMOKE_TLS_CA_FILE")? {
            root_store
                .add(cert)
                .map_err(|e| format!("Failed adding CA cert: {e}"))?;
        }
    } else {
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);
    let client_cfg = match client_identity {
        Some((cert_path, key_path)) => {
            let certs = load_certs(cert_path, "MU_SMOKE_TLS_CERT_FILE")?;
            let key = load_key(key_path, "MU_SMOKE_TLS_KEY_FILE")?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("Invalid client mTLS cert/key pair: {e}"))?
        }
        None => builder.with_no_client_auth(),
    };

    Ok(TlsConnector::from(Arc::new(client_cfg)))
}

fn server_name_from_host(host: &str, override_name: Option<&str>) -> ServerName<'static> {
    if let Some(name) = override_name {
        return ServerName::try_from(name.to_string()).expect("valid server name override");
    }
    let clean = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().unwrap_or(host)
    } else {
        host.split(':').next().unwrap_or(host)
    };
    ServerName::try_from(clean.to_string()).expect("valid host server name")
}

async fn http_get(
    base_url: &str,
    path: &str,
    bearer_token: Option<&str>,
    cfg: &SmokeConfig,
) -> Result<(StatusCode, Vec<u8>), String> {
    let is_https = base_url.starts_with("https://");
    let authority_and_prefix = base_url
        .strip_prefix("https://")
        .or_else(|| base_url.strip_prefix("http://"))
        .ok_or_else(|| format!("Unsupported URL scheme in '{base_url}'"))?;
    let (authority, base_path) = match authority_and_prefix.find('/') {
        Some(idx) => (&authority_and_prefix[..idx], &authority_and_prefix[idx..]),
        None => (authority_and_prefix, ""),
    };
    let connect_addr = if authority.contains(':') {
        authority.to_string()
    } else if is_https {
        format!("{authority}:443")
    } else {
        format!("{authority}:80")
    };
    let full_path = format!("{}{}", base_path.trim_end_matches('/'), path);

    let mut req_builder = Request::builder()
        .method(Method::GET)
        .uri(&full_path)
        .header(hyper::header::HOST, authority);
    if let Some(tok) = bearer_token {
        req_builder = req_builder.header(hyper::header::AUTHORIZATION, format!("Bearer {tok}"));
    }
    let req = req_builder
        .body(Empty::<hyper::body::Bytes>::new())
        .map_err(|e| format!("Failed building HTTP request: {e}"))?;

    let tcp = tokio::time::timeout(cfg.timeout, TcpStream::connect(&connect_addr))
        .await
        .map_err(|_| format!("Timed out connecting to {connect_addr}"))?
        .map_err(|e| format!("TCP connect to {connect_addr} failed: {e}"))?;

    if is_https {
        let client_id = cfg
            .tls_cert_file
            .as_deref()
            .zip(cfg.tls_key_file.as_deref());
        let connector = build_tls_connector(cfg.tls_ca_file.as_deref(), client_id)?;
        let sni = server_name_from_host(authority, cfg.server_name.as_deref());
        let tls = tokio::time::timeout(cfg.timeout, connector.connect(sni, tcp))
            .await
            .map_err(|_| format!("TLS handshake timeout for {connect_addr}"))?
            .map_err(|e| format!("TLS handshake failed for {connect_addr}: {e}"))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| format!("HTTP/1.1 TLS handshake failed: {e}"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = tokio::time::timeout(cfg.timeout, sender.send_request(req))
            .await
            .map_err(|_| format!("HTTP request timeout on {full_path}"))?
            .map_err(|e| format!("HTTP request failed on {full_path}: {e}"))?;
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("Body read failed: {e}"))?
            .to_bytes()
            .to_vec();
        Ok((status, body))
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| format!("HTTP/1.1 handshake failed: {e}"))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let resp = tokio::time::timeout(cfg.timeout, sender.send_request(req))
            .await
            .map_err(|_| format!("HTTP request timeout on {full_path}"))?
            .map_err(|e| format!("HTTP request failed on {full_path}: {e}"))?;
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| format!("Body read failed: {e}"))?
            .to_bytes()
            .to_vec();
        Ok((status, body))
    }
}

struct EphemeralPki {
    ca_pem: String,
    srv_cert_pem: String,
    srv_key_pem: String,
    ca_path: PathBuf,
    cli_cert_path: PathBuf,
    cli_key_path: PathBuf,
    rogue_cert_path: PathBuf,
    rogue_key_path: PathBuf,
}

fn generate_ephemeral_pki(dir: &Path) -> EphemeralPki {
    let mut ca_params =
        CertificateParams::new(vec!["step-ca.cluster.internal".to_string()]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "MuObserve Smoke CA");
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    let srv_params =
        CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    let srv_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &ca_issuer).unwrap();

    let mut cli_params =
        CertificateParams::new(vec!["mu-cd-controller.node-a.cluster.internal".to_string()])
            .unwrap();
    cli_params.subject_alt_names.push(SanType::URI(
        "spiffe://cluster.internal/node/node-a/service/mu-cd-controller"
            .try_into()
            .unwrap(),
    ));
    let cli_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let cli_cert = cli_params.signed_by(&cli_key, &ca_issuer).unwrap();

    let mut rogue_ca_params = CertificateParams::new(vec!["rogue-ca".to_string()]).unwrap();
    rogue_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let rogue_ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let rogue_issuer = Issuer::from_params(&rogue_ca_params, &rogue_ca_key);
    let rogue_cli_params =
        CertificateParams::new(vec!["rogue.node-a.cluster.internal".to_string()]).unwrap();
    let rogue_cli_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let rogue_cli_cert = rogue_cli_params
        .signed_by(&rogue_cli_key, &rogue_issuer)
        .unwrap();

    let ca_path = dir.join("ca.crt");
    let cli_cert_path = dir.join("client.crt");
    let cli_key_path = dir.join("client.key");
    let rogue_cert_path = dir.join("rogue.crt");
    let rogue_key_path = dir.join("rogue.key");

    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    std::fs::write(&cli_cert_path, cli_cert.pem()).unwrap();
    std::fs::write(&cli_key_path, cli_key.serialize_pem()).unwrap();
    std::fs::write(&rogue_cert_path, rogue_cli_cert.pem()).unwrap();
    std::fs::write(&rogue_key_path, rogue_cli_key.serialize_pem()).unwrap();

    EphemeralPki {
        ca_pem: ca_cert.pem(),
        srv_cert_pem: srv_cert.pem(),
        srv_key_pem: srv_key.serialize_pem(),
        ca_path,
        cli_cert_path,
        cli_key_path,
        rogue_cert_path,
        rogue_key_path,
    }
}

async fn run_http_hub_smoke(base_url: &str, bearer_token: Option<&str>, cfg: &SmokeConfig) {
    // 1. Read-only /health endpoint
    let (status, health_body) = http_get(base_url, "/health", None, cfg)
        .await
        .expect("GET /health");
    assert_eq!(status, StatusCode::OK, "GET /health must return 200 OK");
    let health_json: serde_json::Value =
        serde_json::from_slice(&health_body).expect("GET /health JSON");
    assert_eq!(health_json["status"], "ok");
    assert_eq!(health_json["healthy"], true);

    // 2. Unauthenticated access to protected observability endpoints MUST fail closed (401/403)
    for protected in ["/api/v1/store/status", "/api/v1/ingress/overview"] {
        let (unauth_status, _) = http_get(base_url, protected, None, cfg)
            .await
            .expect("unauthenticated protected probe");
        assert!(
            matches!(
                unauth_status,
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            ),
            "{protected} without credentials must fail closed with 401/403, got {unauth_status}"
        );
    }

    // Wrong bearer token must fail closed (401/403)
    let (bad_status, _) = http_get(
        base_url,
        "/api/obs/v1/status/subsystems",
        Some("wrong-hub-token"),
        cfg,
    )
    .await
    .expect("wrong bearer token probe");
    assert!(
        matches!(bad_status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN),
        "wrong bearer token must fail closed with 401/403, got {bad_status}"
    );

    // 3. Authenticated read-only probes when bearer token is available
    if let Some(token) = bearer_token {
        let (sub_status, sub_body) =
            http_get(base_url, "/api/obs/v1/status/subsystems", Some(token), cfg)
                .await
                .expect("authenticated GET /api/obs/v1/status/subsystems");
        assert_eq!(sub_status, StatusCode::OK);
        let subs: SubsystemsStatusResponse =
            serde_json::from_slice(&sub_body).expect("deserialize SubsystemsStatusResponse");
        assert_eq!(subs.total, 7);
        assert_eq!(subs.subsystems.len(), 7);

        let (store_status, store_body) =
            http_get(base_url, "/api/v1/store/status", Some(token), cfg)
                .await
                .expect("authenticated GET /api/v1/store/status");
        assert_eq!(store_status, StatusCode::OK);
        let store_dto: StoreStatusResponse =
            serde_json::from_slice(&store_body).expect("deserialize StoreStatusResponse");
        assert!(store_dto.healthy);
    }
}

async fn assert_muob_unauthenticated_rejected(
    target_addr: &str,
    server_name: ServerName<'static>,
    ca_path: &Path,
    rogue_identity: Option<(&Path, &Path)>,
    timeout: Duration,
) {
    let req_env = ControlRpcEnvelope::Noop;
    let req_bytes = encode_control_envelope(&req_env).unwrap();
    let hdr = IpcHeader::new(MSG_TYPE_FORY_CONTROL, req_bytes.len() as u32, 0, 77);

    // 1. Missing client cert over TLS must fail closed
    let no_cert_conn = build_tls_connector(Some(ca_path), None).unwrap();
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(target_addr))
        .await
        .expect("tcp connect timeout")
        .expect("tcp connect");
    if let Ok(Ok(mut tls_stream)) =
        tokio::time::timeout(timeout, no_cert_conn.connect(server_name.clone(), tcp)).await
    {
        let _ = write_frame(&mut tls_stream, &hdr, &req_bytes).await;
        let read_res =
            tokio::time::timeout(Duration::from_secs(2), read_frame(&mut tls_stream)).await;
        assert!(
            !matches!(read_res, Ok(Ok(_))),
            "MUOB mTLS listener must reject connection without client certificate"
        );
    }

    // 2. Untrusted rogue client cert must fail closed
    if let Some((rogue_cert, rogue_key)) = rogue_identity {
        let rogue_conn = build_tls_connector(Some(ca_path), Some((rogue_cert, rogue_key))).unwrap();
        let tcp = tokio::time::timeout(timeout, TcpStream::connect(target_addr))
            .await
            .expect("tcp connect timeout")
            .expect("tcp connect");
        if let Ok(Ok(mut tls_stream)) =
            tokio::time::timeout(timeout, rogue_conn.connect(server_name, tcp)).await
        {
            let _ = write_frame(&mut tls_stream, &hdr, &req_bytes).await;
            let read_res =
                tokio::time::timeout(Duration::from_secs(2), read_frame(&mut tls_stream)).await;
            assert!(
                !matches!(read_res, Ok(Ok(_))),
                "MUOB mTLS listener must reject untrusted client certificate"
            );
        }
    }
}

async fn run_muob_readonly_query_probe(
    target_addr: &str,
    server_name: ServerName<'static>,
    ca_path: &Path,
    cert_path: &Path,
    key_path: &Path,
    timeout: Duration,
) {
    let connector = build_tls_connector(Some(ca_path), Some((cert_path, key_path)))
        .expect("build mTLS connector");
    let tcp = tokio::time::timeout(timeout, TcpStream::connect(target_addr))
        .await
        .expect("tcp connect timeout")
        .expect("tcp connect to MUOB listener");
    let mut tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp))
        .await
        .expect("mTLS handshake timeout")
        .expect("mTLS handshake with MUOB listener");

    // 1. Read-only QueryJobsHistoryReq
    let q_env = ControlRpcEnvelope::QueryJobsHistoryReq(QueryJobsHistoryRequest {
        request_id: "smoke-readonly-query".to_string(),
        repo_key: None,
        branch_key: None,
        job_id: None,
        limit: 1,
    });
    let q_bytes = encode_control_envelope(&q_env).expect("encode QueryJobsHistoryReq");
    let q_hdr = IpcHeader::new(MSG_TYPE_FORY_CONTROL, q_bytes.len() as u32, 0, 101);
    tokio::time::timeout(timeout, write_frame(&mut tls_stream, &q_hdr, &q_bytes))
        .await
        .expect("write timeout")
        .expect("write MUOB QueryJobsHistoryReq");

    let (resp_hdr, resp_bytes) = tokio::time::timeout(timeout, read_frame(&mut tls_stream))
        .await
        .expect("read timeout")
        .expect("read MUOB QueryJobsHistoryResp");
    assert_eq!(resp_hdr.msg_type, MSG_TYPE_FORY_CONTROL);
    assert_eq!(resp_hdr.sequence, 101);
    match decode_control_envelope(&resp_bytes).expect("decode QueryJobsHistoryResp") {
        ControlRpcEnvelope::QueryJobsHistoryResp(resp) => {
            assert_eq!(resp.request_id, "smoke-readonly-query");
            assert!(resp.records.len() <= 1);
        }
        other => panic!("expected QueryJobsHistoryResp, got {other:?}"),
    }

    // 2. Read-only Noop frame
    let noop_bytes = encode_control_envelope(&ControlRpcEnvelope::Noop).unwrap();
    let noop_hdr = IpcHeader::new(MSG_TYPE_FORY_CONTROL, noop_bytes.len() as u32, 0, 102);
    tokio::time::timeout(
        timeout,
        write_frame(&mut tls_stream, &noop_hdr, &noop_bytes),
    )
    .await
    .expect("write timeout")
    .expect("write MUOB Noop");

    let (noop_resp_hdr, noop_resp_bytes) =
        tokio::time::timeout(timeout, read_frame(&mut tls_stream))
            .await
            .expect("read timeout")
            .expect("read MUOB Noop response");
    assert_eq!(noop_resp_hdr.msg_type, MSG_TYPE_FORY_CONTROL);
    assert_eq!(noop_resp_hdr.sequence, 102);
    assert!(matches!(
        decode_control_envelope(&noop_resp_bytes).unwrap(),
        ControlRpcEnvelope::Noop
    ));
}

#[test]
#[cfg_attr(miri, ignore)]
fn smoke_config_enforces_fail_closed_credentials_and_tls() {
    let temp = tempfile::tempdir().unwrap();
    let pki = generate_ephemeral_pki(temp.path());
    let token_path = temp.path().join("hub.token");
    std::fs::write(&token_path, "\thub-smoke-token\n").unwrap();

    let ok_env = HashMap::from([
        ("MU_SMOKE_TARGET_URL", "http://127.0.0.1:9480/".to_string()),
        ("MU_SMOKE_TARGET_ADDR", "127.0.0.1:9443".to_string()),
        (
            "MU_SMOKE_BEARER_TOKEN_FILE",
            token_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_CA_FILE",
            pki.ca_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_CERT_FILE",
            pki.cli_cert_path.to_string_lossy().into_owned(),
        ),
        (
            "MU_SMOKE_TLS_KEY_FILE",
            pki.cli_key_path.to_string_lossy().into_owned(),
        ),
    ]);
    let cfg = SmokeConfig::from_lookup(|k| ok_env.get(k).cloned()).unwrap();
    assert_eq!(cfg.target_url.as_deref(), Some("http://127.0.0.1:9480"));
    assert_eq!(cfg.target_addr.as_deref(), Some("127.0.0.1:9443"));
    assert_eq!(cfg.bearer_token.as_deref(), Some("hub-smoke-token"));
    assert_eq!(cfg.timeout, Duration::from_secs(10));

    // Unreadable bearer token file fails closed
    let missing_tok = HashMap::from([(
        "MU_SMOKE_BEARER_TOKEN_FILE",
        temp.path()
            .join("missing.tok")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| missing_tok.get(k).cloned()).is_err());

    // Unreadable CA cert fails closed
    let missing_ca = HashMap::from([(
        "MU_SMOKE_TLS_CA_FILE",
        temp.path()
            .join("missing.ca")
            .to_string_lossy()
            .into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| missing_ca.get(k).cloned()).is_err());

    // Half-configured cert/key fails closed
    let partial = HashMap::from([(
        "MU_SMOKE_TLS_CERT_FILE",
        pki.cli_cert_path.to_string_lossy().into_owned(),
    )]);
    assert!(SmokeConfig::from_lookup(|k| partial.get(k).cloned()).is_err());
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn smoke_mu_observable_hub_http_and_muob_readonly() {
    let cfg = SmokeConfig::from_env().expect("valid MU_SMOKE_* environment configuration");

    if cfg.target_url.is_some() || cfg.target_addr.is_some() {
        if let Some(ref url) = cfg.target_url {
            run_http_hub_smoke(url, cfg.bearer_token.as_deref(), &cfg).await;
        }
        if let Some(ref addr) = cfg.target_addr {
            let ca = cfg
                .tls_ca_file
                .as_deref()
                .expect("MU_SMOKE_TLS_CA_FILE required for MUOB mTLS probe");
            let cert = cfg
                .tls_cert_file
                .as_deref()
                .expect("MU_SMOKE_TLS_CERT_FILE required for MUOB mTLS probe");
            let key = cfg
                .tls_key_file
                .as_deref()
                .expect("MU_SMOKE_TLS_KEY_FILE required for MUOB mTLS probe");
            let server_name = server_name_from_host(addr, cfg.server_name.as_deref());
            assert_muob_unauthenticated_rejected(addr, server_name.clone(), ca, None, cfg.timeout)
                .await;
            run_muob_readonly_query_probe(addr, server_name, ca, cert, key, cfg.timeout).await;
        }
        return;
    }

    // Ephemeral mode: spin up local HTTP Console API and mTLS MUOB server
    let temp = tempfile::tempdir().unwrap();
    let pki = generate_ephemeral_pki(temp.path());
    let store = HotDuckDbStore::open_in_memory().expect("open in-memory HotDuckDbStore");
    let before = collect_storage_health_status(&store).expect("initial storage status");

    let verifier = MuAuthFolioVerifier::locked_down(None);
    let ephemeral_token = "ephemeral-hub-smoke-token";
    verifier.set_service_token_for_test(Some(ephemeral_token));
    let auth: Arc<dyn ObsAuthVerifier> = Arc::new(verifier);
    let ingress = IngressEngine::new(store.clone(), "node-a".into());
    let router = build_console_api_router_with_auth(store.clone(), ingress, auth);

    let http_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let http_handle = tokio::spawn(async move {
        let _ = axum::serve(http_listener, router).await;
    });

    let http_url = format!("http://{http_addr}");
    // Protected /api/obs/v1/status/subsystems also rejects 401 when locked down
    let (sub_unauth, _) = http_get(&http_url, "/api/obs/v1/status/subsystems", None, &cfg)
        .await
        .unwrap();
    assert_eq!(sub_unauth, StatusCode::UNAUTHORIZED);
    run_http_hub_smoke(&http_url, Some(ephemeral_token), &cfg).await;

    let tls_cfg = build_mtls_server_config(&pki.ca_pem, &pki.srv_cert_pem, &pki.srv_key_pem)
        .expect("build mTLS server config");
    let ingest_server = Arc::new(MtlsIngestServer::new(
        store.clone(),
        IngestServerConfig {
            allowed_dns_suffix: Some("cluster.internal".to_string()),
            ..Default::default()
        },
        Arc::new(tls_cfg),
    ));
    let muob_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let muob_addr = muob_listener.local_addr().unwrap().to_string();
    let muob_server = ingest_server.clone();
    let muob_handle = tokio::spawn(async move {
        let _ = muob_server.serve(muob_listener).await;
    });

    let server_name = server_name_from_host(&muob_addr, Some("localhost"));
    assert_muob_unauthenticated_rejected(
        &muob_addr,
        server_name.clone(),
        &pki.ca_path,
        Some((&pki.rogue_cert_path, &pki.rogue_key_path)),
        cfg.timeout,
    )
    .await;
    run_muob_readonly_query_probe(
        &muob_addr,
        server_name,
        &pki.ca_path,
        &pki.cli_cert_path,
        &pki.cli_key_path,
        cfg.timeout,
    )
    .await;

    let after = collect_storage_health_status(&store).expect("final storage status");
    assert_eq!(before.total_spans, after.total_spans);
    assert_eq!(before.total_logs, after.total_logs);
    assert_eq!(before.total_metric_points, after.total_metric_points);
    assert_eq!(before.total_test_runs, after.total_test_runs);
    assert_eq!(before.total_benchmark_runs, after.total_benchmark_runs);

    muob_handle.abort();
    http_handle.abort();
}
