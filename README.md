# mu-observable-hub

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs">
    <img src="https://hook.lma1980.duckdns.org/cards/LMA1980/mu-observable-hub/card.svg" alt="mu-observable-hub Factory Scorecard" width="520"/>
  </a>
</p>

<p align="center">
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-hub/status.svg" alt="CI Status"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-hub/score.svg" alt="Quality Score"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-hub/coverage.svg" alt="Coverage"/></a>
  <a href="https://hook.lma1980.duckdns.org/jobs"><img src="https://hook.lma1980.duckdns.org/badges/LMA1980/mu-observable-hub/benchmark.svg" alt="Benchmark"/></a>
</p>

______________________________________________________________________

Distributed **OpenTelemetry (OTEL) + DuckDB/Parquet** observability backend for [`mu-observable`](https://github.com/LMA1980/mu-observable), centralized [`mu-ci-controller`](https://github.com/LMA1980/mu-ci-controller) state store, hardware-aware benchmark & test regression analytics engine, and **Antigravity Model Context Protocol (MCP) server**.

## Architectural Scope

- **Binaries & Listeners**:
  - `mu-observable-hub` (`--serve` / `MUOBSERVE_SERVE=true`): Runs the `step-ca` mTLS telemetry ingest server (`0.0.0.0:9443` default) and the HTTP MCP + Console API server (`127.0.0.1:9480` default) under [`mu-ci-isolation`](https://github.com/LMA1980/mu-ci-isolation) confinement.
  - `mu-observable-mcp`: Antigravity-native MCP server speaking JSON-RPC over `stdio`.
  - `mu-observable-cli`: Local administration, regression evaluation, canary SLO assertion, trace inspection, and SQL query CLI.
- **Zero-Trust `step-ca` mTLS Ingestion & Centralized State**:
  - Verifies client certificate DNS/URI SANs on batches from [`mu-observable-collector`](https://github.com/LMA1980/mu-observable-collector) and [`mu-observable-sentinel`](https://github.com/LMA1980/mu-observable-sentinel) using [`mu-observable-ipc`](https://github.com/LMA1980/mu-observable-ipc) framing.
  - Hosts the centralized [`mu-ci-controller`](https://github.com/LMA1980/mu-ci-controller) operational catalog (`jobs_history`, `branch_snapshots`, `submodule_snapshots`) alongside unified `otel_spans`, `otel_logs`, `otel_metrics`, `test_case_runs`, and `benchmark_runs`.
- **Console API, [`mu-auth`](https://github.com/LMA1980/mu-auth) RBAC & `IngressEngine` (`/api/obs/v1/*`)**:
  - Enforces [`mu-auth`](https://github.com/LMA1980/mu-auth) policy folios (`MuAuthFolioVerifier`, including `super-operator`) for [`mu-console`](https://github.com/LMA1980/mu-console) queries across Smartscape (`/api/obs/v1/smartscape`), causal SLO problems (`/api/obs/v1/problems`, `/api/obs/v1/events` SSE), PurePath traces (`/api/obs/v1/traces*`), sanitized logs (`/api/obs/v1/logs*`, `/api/obs/v1/jobs/{job_id}/log`), golden-signal metrics (`/api/obs/v1/metrics/timeseries`), 7-subsystem operational status and maintenance overrides (`/api/obs/v1/status/subsystems*`), non-destructive monitoring exclusions (`/api/obs/v1/status/exclusions`), and `IngressEngine` routing/upstream telemetry (`/api/obs/v1/ingress/{overview,routes,upstreams,tls}`).
- **3-Tier Hybrid DuckDB + Zstd Parquet Storage Lifecycle & OpenSearch-Style Line Index**:
  - **Single-Line Deduplicated Log Store (`otel_logs`)**: Stores every CI and daemon log line once (`1 line = 1 record`) with `line_no`, `stream`, and a deterministic 64-bit FNV-1a `dedup_hash` (bounded 65,536-entry FIFO ring + SQL `WHERE NOT EXISTS` guard), retiring full-file `job_logs_store` (`__ar_job_logs__`) blob rewrites.
  - **Inverted Token Index & Shard Catalog (`log_inverted_index`, `log_shards_catalog`)**: Indexes up to 32 normalized lowercase tokens per log line in local DuckDB and tracks hot and cold Zstd Parquet / Garage S3 (`cold_parquet` / `cold_s3`) segments for sub-millisecond keyword search and ordered line-by-line `/api/v1/jobs/{job_id}/log` reconstruction.
  - **Strict FIFO Time & Disk-Space Eviction**: Evicts oldest cold shards and hot records strictly in FIFO timestamp order whenever retention TTL expires or available physical disk space (`libc::statvfs` vs `MUOBSERVE_MIN_FREE_DISK_BYTES`) / store byte ceiling (`MUOBSERVE_MAX_STORE_BYTES`) is exceeded. See [`specs/line-indexed-log-store-and-fifo-eviction.md`](specs/line-indexed-log-store-and-fifo-eviction.md).
- **Hardware-Aware Benchmark & Test Regression Engine**:
  - Compares `feat/**` candidate runs against rolling `main` baselines stratified by hardware profile (`arch`, `cpu_cluster` e.g. `X100` `VLEN=256` vs `A100` `VLEN=1024` vs `x86_64`), computing relative deltas and MAD modified $z$-scores, plus rolling 30-day test flakiness indices and [`mu-cd-controller`](https://github.com/LMA1980/mu-cd-controller) canary SLO assertions.
- **12 Structured MCP Tools (`mu-observable-mcp` / HTTP `/mcp`)**:
  - `check_benchmark_regressions`, `get_test_flakiness`, `compare_branches`, `query_trace_waterfall`, `correlate_logs_by_trace_id`, `search_error_anomalies`, `assert_service_slo`, `inspect_node_utilization`, `compare_cluster_efficiency`, `execute_analytics_sql`, `analyze_causal_root_cause`, and `diagnose_anomaly_ai`.

## Ecosystem Integration

- **Parent & Sibling Crates**: [`mu-observable`](https://github.com/LMA1980/mu-observable), [`mu-observable-ipc`](https://github.com/LMA1980/mu-observable-ipc), [`mu-observable-collector`](https://github.com/LMA1980/mu-observable-collector), [`mu-observable-sentinel`](https://github.com/LMA1980/mu-observable-sentinel)
- **Platform Controllers & Console**: [`mu-console`](https://github.com/LMA1980/mu-console), [`mu-auth`](https://github.com/LMA1980/mu-auth), [`mu-ci-controller`](https://github.com/LMA1980/mu-ci-controller), [`mu-cd-controller`](https://github.com/LMA1980/mu-cd-controller), [`mu-ci-isolation`](https://github.com/LMA1980/mu-ci-isolation)

## Testing & Verification

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo audit
cargo build --workspace --all-targets
cargo test --workspace
cargo llvm-cov --workspace --summary-only
MIRIFLAGS="-Zmiri-disable-isolation" cargo +nightly miri test --workspace --lib
```

## License

Licensed under `AGPL-3.0-only`. See [`LICENSE`](LICENSE) for details.
