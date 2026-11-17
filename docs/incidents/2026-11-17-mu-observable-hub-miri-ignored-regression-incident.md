# Incident Report: Ecosystem-Wide `RegressionDetected` CI Failures Caused by `cargo-miri` `ignored` Test Runs

- **Date**: 2026-11-17
- **Status**: Remediated in PR (pending merge and `MuConDe` deployment)
- **Affected Repositories**:
  - `main` branch failures: `LMA1980/mu-console` (`job-1794899287-80224f90`), `LMA1980/jero-runner` (`job-1794898850-1f9a1294`)
  - Open PR failures: `LMA1980/mu-console-theme#41`, `LMA1980/mu-console#380`, `LMA1980/mu-ci-tools#40`, `LMA1980/mu-ci#20`, `LMA1980/jero-manager#92`
  - Quality score degradation (`RegressionVerdict::Warn`): `LMA1980/mu-observable-hub@main` (`job-1794916513-5078ef6f`), `LMA1980/mu-registry@main` (`job-1794902977-187e9d2f`)
- **Root-Cause Component**: `LMA1980/mu-observable-hub` (`src/analytics/regression.rs`, `src/analytics/smartscape.rs`)

______________________________________________________________________

## 1. Incident Summary & Impact

On 2026-11-17, multiple `main` branch and Pull Request CI pipelines across the `LMA1980` ecosystem passed 100% of their declarative `ActionRunner` stages (`fmt-check`, `clippy-check`, `audit-check`, `build-check`, `test-check`, `coverage-check`, `miri-check`, `wasm32-build`, `dist-freshness-check`) with `exit_code = 0`, yet were transitioned to `JobStatus::Failed` by `ActionRunner-controller` with errors such as:

```text
RegressionDetected: verdict=Fail: 0 regressed benchmarks, 4 flaky/failed tests
```

Querying `v_tests` in `MuObserve` (`mu-observable-hub`) across all 48 repositories confirmed zero actual failing test runs (`status != 'ok' AND status != 'ignored'` returned `0` rows). Every flagged test row was a `cargo-miri` execution of a `#[cfg_attr(miri, ignore)]` test (`status = 'ignored'`).

______________________________________________________________________

## 2. Root Cause Analysis

1. **`ignored` Treated as Hard Test Failure**:
   `is_pass_status()` in `src/analytics/regression.rs` only accepted `"ok"`, `"pass"`, `"passed"`, and `"success"`. When `ActionRunner-worker` (`mu-ci-worker`) ingested `TestCaseStatus::Ignored` as `"ignored"` for `#[cfg_attr(miri, ignore)]` tests (such as `#[tokio::test]` or shared-memory/socket tests excluded under Miri), `evaluate_regression_gate()` evaluated `!is_pass_status(&t.status)` as `true`, marking the test as a hard failure (`RegressionVerdict::Fail`) and capping the job quality score to `<= 65` (`D`/`F`).

1. **Cross-Runner History Collisions (`test_binary` Omitted from Grouping Key)**:
   `compute_test_flakiness_with_min_ts()` grouped `v_tests` rows solely by `(crate_name, test_name)` instead of `(crate_name, test_binary, test_name)`. Consequently, `cargo-test` (`"ok"`), `cargo-llvm-cov` (`"ok"`), and `cargo-miri` (`"ignored"`) observations for the same test were merged into a single time series:

   - Whenever `miri-check` finished after `test-check`, the candidate commit's representative status became `"ignored"` (`RegressionVerdict::Fail`).
   - Whenever `test-check`/`coverage-check` finished after `miri-check`, the `"ok" -> "ignored" -> "ok"` transition incremented `flip_flop_count` (`RegressionVerdict::Warn`, `40`-point quality score penalty).
   - Conversely, a genuine UB failure in `cargo-miri` (`status = "failed"`) could have been masked if a `cargo-test` (`"ok"`) stage finished later.

1. **Unscoped Candidate Failure Attribution & Smartscape Filter**:

   - When `candidate_commit` did not execute a test (e.g., a test present only on an older feature branch), `latest_for_candidate.unwrap_or_else(|| history.last().unwrap())` could attribute that older commit's failure to `candidate_commit`.
   - `smartscape.rs` filtered problem cards using `!t.status.eq_ignore_ascii_case("ok")`, also surfacing `"ignored"` Miri tests as `"error"` `ProblemCard` entries.

1. **How the Regression Reached `main`**:
   Unit tests in `regression.rs` only exercised `"ok"` and `"failed"` statuses under a single `test_binary`, without testing `"ignored"` `cargo-miri` runs alongside `"ok"` `cargo-test` runs for the same test name. Once `mu-ci-worker` began emitting granular `cargo-miri` `TestCaseRunEntry` rows into `v_tests`, existing `main` builds and documentation PRs immediately tripped the regression gate.

______________________________________________________________________

## 3. Remediation & Preventive Controls

### Immediate Remediation

1. **Partition Flakiness History by `test_binary`**:
   Updated `compute_test_flakiness_internal()` in `src/analytics/regression.rs` to group by `(crate_name, test_binary, test_name)` so `cargo-test`, `cargo-llvm-cov`, and `cargo-miri` histories never cross-contaminate and a `cargo-miri` UB failure can never be masked by a passing `cargo-test` run.

1. **Treat `ignored`/`skip`/`skipped` as Non-Executed Skips**:
   Added `is_ignored_status()` in `src/analytics/regression.rs` and excluded ignored observations from `flip_flops` transition counting, `evaluate_regression_gate()` failure/warning verdicts, and `smartscape.rs` `ProblemCard` emission.

1. **Candidate-Scoped Hard Failure Attribution**:
   Scoped `hard_test_failure` in `evaluate_regression_gate()` to tests that actually executed and failed on `candidate_commit`, and wired `monitoring_since_unix_nano` exclusions into `evaluate_regression_gate()`.

### Preventive Controls

1. **Multi-Runner Regression Gate Test Coverage**:
   Added unit and integration tests covering mixed `cargo-test` (`"ok"`) + `cargo-miri` (`"ignored"`) runs, real `cargo-miri` (`"failed"`) UB isolation against passing `cargo-test`, and abandoned-branch test non-contamination.
1. **Pre-PR Verification**:
   Executed the full local CI gate (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `cargo +nightly miri test --workspace --lib`) before opening the remediation Pull Request.
