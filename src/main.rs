use std::path::PathBuf;
use std::sync::Arc;

use mu_observable_hub::{
    build_mtls_server_config, execute_cli_command, non_empty_env_first, parse_bool_env_first,
    parse_cli_args, resolve_db_path, resolve_parquet_root, resolve_tls_paths, CliCommand,
    HotDuckDbStore, IngestServerConfig, McpServer, MtlsIngestServer, SanEnforcementPolicy,
};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("mcp-stdio") {
        let mut cli_db: Option<PathBuf> = None;
        let mut cli_parquet: Option<PathBuf> = None;
        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--db" => {
                    if let Some(p) = args.get(i + 1) {
                        cli_db = Some(PathBuf::from(p));
                    }
                    i += 2;
                }
                "--parquet-root" => {
                    if let Some(p) = args.get(i + 1) {
                        cli_parquet = Some(PathBuf::from(p));
                    }
                    i += 2;
                }
                _ => i += 1,
            }
        }
        let db_path = resolve_db_path(cli_db.as_deref(), false);
        let parquet_root = resolve_parquet_root(cli_parquet.as_deref(), db_path.as_deref(), false);
        let store = HotDuckDbStore::open(db_path.as_deref(), parquet_root.as_deref())
            .expect("failed to initialize HotDuckDbStore");
        let mcp = McpServer::new(store);
        let stdin = std::io::stdin();
        let stdout = std::io::stdout();
        if let Err(e) = mcp.serve_stdio(stdin.lock(), stdout.lock()) {
            eprintln!("mu-observable-hub mcp-stdio error: {e}");
            std::process::exit(1);
        }
        return;
    }

    let serve_flag = matches!(args.first().map(String::as_str), Some("serve" | "--serve"))
        || parse_bool_env_first(
            &[
                "MU_OBSERVABLE_HUB_SERVE",
                "MU_OBSERVABLE_SERVE",
                "MUOBSERVE_SERVE",
            ],
            false,
        );

    if serve_flag {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
            )
            .init();

        let db_path = resolve_db_path(None, true).expect("resolved database path");
        let parquet_root =
            resolve_parquet_root(None, Some(&db_path), true).expect("resolved parquet root");

        let store = HotDuckDbStore::open(Some(&db_path), Some(&parquet_root))
            .expect("failed to open HotDuckDbStore");

        let mcp_http_addr = non_empty_env_first(&[
            "MU_OBSERVABLE_HUB_MCP_HTTP_ADDR",
            "MU_OBSERVABLE_MCP_HTTP_ADDR",
            "MUOBSERVE_MCP_HTTP_ADDR",
        ])
        .unwrap_or_else(|| "127.0.0.1:9480".to_string());
        let mcp_store = store.clone();
        let node_id = non_empty_env_first(&[
            "MU_OBSERVABLE_HUB_NODE_ID",
            "MU_OBSERVABLE_NODE_ID",
            "MUOBSERVE_NODE_ID",
        ])
        .unwrap_or_else(|| "node-a".to_string());
        let ingress_engine = mu_observable_hub::IngressEngine::new_with_listen_addr(
            store.clone(),
            node_id,
            &mcp_http_addr,
        );
        mu_observable_hub::UpstreamHealthChecker::spawn(
            ingress_engine.clone(),
            std::time::Duration::from_secs(10),
        );
        let ingress_for_server = ingress_engine.clone();

        tokio::spawn(async move {
            if let Ok(listener) = tokio::net::TcpListener::bind(&mcp_http_addr).await {
                tracing::info!(%mcp_http_addr, "mu-observable-hub MCP HTTP/SSE & Ingress server listening");
                let router = McpServer::new(mcp_store).router_with_ingress(ingress_for_server);
                let _ = axum::serve(listener, router).await;
            }
        });

        let listen_addr = non_empty_env_first(&[
            "MU_OBSERVABLE_HUB_LISTEN_ADDR",
            "MU_OBSERVABLE_LISTEN_ADDR",
            "MUOBSERVE_LISTEN_ADDR",
        ])
        .unwrap_or_else(|| "0.0.0.0:9443".to_string());
        let (ca_path, cert_path, key_path) = resolve_tls_paths();

        let ca_pem = std::fs::read_to_string(&ca_path)
            .unwrap_or_else(|e| panic!("failed to read CA cert '{}': {e}", ca_path.display()));
        let cert_pem = std::fs::read_to_string(&cert_path).unwrap_or_else(|e| {
            panic!("failed to read server cert '{}': {e}", cert_path.display())
        });
        let key_pem = std::fs::read_to_string(&key_path)
            .unwrap_or_else(|e| panic!("failed to read server key '{}': {e}", key_path.display()));

        let tls_cfg =
            build_mtls_server_config(&ca_pem, &cert_pem, &key_pem).expect("failed to build mTLS");
        let san_policy = match non_empty_env_first(&[
            "MU_OBSERVABLE_HUB_SAN_POLICY",
            "MU_OBSERVABLE_SAN_POLICY",
            "MUOBSERVE_SAN_POLICY",
        ])
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
        {
            "reject" | "reject_mismatch" => SanEnforcementPolicy::RejectMismatch,
            _ => SanEnforcementPolicy::OverrideWithCertSan,
        };
        let ingest_cfg = IngestServerConfig {
            san_policy,
            redact_on_ingest: true,
            allowed_dns_suffix: non_empty_env_first(&[
                "MU_OBSERVABLE_HUB_ALLOWED_DNS_SUFFIX",
                "MU_OBSERVABLE_ALLOWED_DNS_SUFFIX",
                "MUOBSERVE_ALLOWED_DNS_SUFFIX",
            ]),
        };

        let server = MtlsIngestServer::new(store, ingest_cfg, Arc::new(tls_cfg));
        let listener = tokio::net::TcpListener::bind(&listen_addr)
            .await
            .unwrap_or_else(|e| panic!("failed to bind listen address '{listen_addr}': {e}"));
        tracing::info!(
            %listen_addr,
            db = %db_path.display(),
            parquet = %parquet_root.display(),
            "mu-observable-hub v{} mTLS ingestion & Fory RPC server listening",
            env!("CARGO_PKG_VERSION")
        );
        if let Err(e) = server.serve(listener).await {
            eprintln!("mu-observable-hub server error: {e}");
            std::process::exit(1);
        }
        return;
    }

    if !args.is_empty() {
        match parse_cli_args(&args) {
            Ok((cli_db_path, cmd)) => {
                let cli_parquet_root: Option<PathBuf> = match &cmd {
                    CliCommand::Compact { parquet_root, .. } => parquet_root.clone(),
                    _ => None,
                };
                let db_path = resolve_db_path(cli_db_path.as_deref(), false);
                let parquet_root =
                    resolve_parquet_root(cli_parquet_root.as_deref(), db_path.as_deref(), false);
                let store = HotDuckDbStore::open(db_path.as_deref(), parquet_root.as_deref())
                    .expect("failed to open HotDuckDbStore");
                match execute_cli_command(&store, &cmd) {
                    Ok(out) => {
                        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
                        return;
                    }
                    Err(e) => {
                        eprintln!("mu-observable-hub error: {e}");
                        std::process::exit(1);
                    }
                }
            }
            Err(_) => {
                let _ = PathBuf::new();
            }
        }
    }

    println!(
        "mu-observable-hub v{} initialized (hot retention window: {} days)",
        env!("CARGO_PKG_VERSION"),
        mu_observable_hub::DEFAULT_HOT_RETENTION_DAYS
    );
}
