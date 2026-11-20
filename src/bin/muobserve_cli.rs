use std::path::PathBuf;

use mu_observable_hub::{
    execute_cli_command, parse_cli_args, resolve_db_path, resolve_parquet_root, CliCommand,
    HotDuckDbStore,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cli_db_path, cmd) = match parse_cli_args(&args) {
        Ok(parsed) => parsed,
        Err(e) => {
            eprintln!("mu-observable-hub-cli error: {e}");
            std::process::exit(2);
        }
    };

    let cli_parquet_root: Option<PathBuf> = match &cmd {
        CliCommand::Compact { parquet_root, .. } => parquet_root.clone(),
        _ => None,
    };
    let db_path = resolve_db_path(cli_db_path.as_deref(), false);
    let parquet_root = resolve_parquet_root(cli_parquet_root.as_deref(), db_path.as_deref(), false);
    let store = match HotDuckDbStore::open(db_path.as_deref(), parquet_root.as_deref()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("mu-observable-hub-cli failed to open HotDuckDbStore: {e}");
            std::process::exit(1);
        }
    };

    match execute_cli_command(&store, &cmd) {
        Ok(val) => {
            println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
        }
        Err(e) => {
            eprintln!("mu-observable-hub-cli execution error: {e}");
            std::process::exit(1);
        }
    }
}
