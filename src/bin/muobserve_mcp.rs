use std::path::PathBuf;

use mu_observable_hub::{resolve_db_path, resolve_parquet_root, HotDuckDbStore, McpServer};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cli_db_path: Option<PathBuf> = None;
    let mut cli_parquet_root: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--db" => {
                if let Some(p) = args.get(i + 1) {
                    cli_db_path = Some(PathBuf::from(p));
                }
                i += 2;
            }
            "--parquet-root" => {
                if let Some(p) = args.get(i + 1) {
                    cli_parquet_root = Some(PathBuf::from(p));
                }
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }

    let db_path = resolve_db_path(cli_db_path.as_deref(), false);
    let parquet_root = resolve_parquet_root(cli_parquet_root.as_deref(), db_path.as_deref(), false);
    let store = match HotDuckDbStore::open(db_path.as_deref(), parquet_root.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mu-observable-hub-mcp failed to open store: {e}");
            std::process::exit(1);
        }
    };

    let mcp = McpServer::new(store);
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    if let Err(e) = mcp.serve_stdio(stdin.lock(), stdout.lock()) {
        eprintln!("mu-observable-hub-mcp stdio error: {e}");
        std::process::exit(1);
    }
}
