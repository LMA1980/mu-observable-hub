# Incident Report: `LMA1980/mu-observable-hub` `main` CI Failure in `test-check` (`job-1794732014-08bf87bc`)

- **Date**: 2026-11-15
- **Status**: Resolved
- **Affected Repository**: `LMA1980/mu-observable-hub` (`main` branch, commit `08bf87bc420aaddba18d9c849b423bbee75fd125`)
- **Failed Job ID**: `job-1794732014-08bf87bc` (`test-check` stage)

______________________________________________________________________

## 1. Incident Summary & Impact

On 2026-11-15 at 09:06:40 UTC, the `main` branch CI pipeline for `LMA1980/mu-observable-hub` (`job-1794732014-08bf87bc`, commit `08bf87bc`) failed during the `test-check` stage (`cargo test --workspace`) dispatched to an ARM64 worker node (`worker-aarch64`) with linker error:

```text
error: linking with `cc` failed: exit status: 1
  = note: /usr/bin/ld: cannot find -lduckdb: No such file or directory
          collect2: error: ld returned 1 exit status
error: could not compile `mu-observable-hub` (lib test) due to 1 previous error
```

### Impact

- Automated Continuous Integration on `mu-observable-hub`'s `main` branch entered a `failure` state following the merge of PR #99 (`fix(cd): align service identifier and deployment block in MuConDe manifests`).
- Downstream verification stages (`coverage-check` and `miri-check`) remained `Pending` and could not execute on `main`.
- Pull request status checks referencing the `main` branch baseline encountered an upstream failure status.

______________________________________________________________________

## 2. Root Cause Analysis

1. **Heterogeneous Worker Node Topology & Dynamic Linker Dependencies**:
   `mu-observable-hub` depends on DuckDB (`duckdb = { version = "=1.2.2", default-features = false }`) via dynamic linking (`-lduckdb`). The `build.rs` script searches native library paths (`/opt/homebrew/lib`, `/usr/local/lib`) and adds `-Wl,-rpath,/usr/local/lib`.

1. **Heterogeneous Shared Library Provisioning Discrepancy**:
   While primary x86_64 and RISC-V compute nodes (`node-a`, `worker-x86_64`, `worker-riscv64`) had `libduckdb.so` installed under `/usr/local/lib/`, the ARM64 compute node (`worker-aarch64`) had joined the distributed runner cluster without having `libduckdb.so` (v1.2.2 for Linux `aarch64`) provisioned in `/usr/local/lib`.

1. **Multi-Stage Task Dispatching Across Nodes**:
   In `job-1794732014-08bf87bc`, `build-check` (`cargo build --workspace --all-targets`) was assigned to an x86_64 node (`worker-x86_64`), where compilation and linking succeeded cleanly in 24 seconds. Subsequently, `test-check` (`cargo test --workspace`) was scheduled on `worker-aarch64`. Because cargo compiled test binaries afresh in the target workspace on `worker-aarch64`, the linker attempted to resolve `-lduckdb` and failed immediately due to the missing shared library.

1. **How the Regression Reached `main`**:
   PR #99 only touched declarative deployment manifests (`.mucd/mu-cd.yml` and `.muconde/MuConDe.yml`). The PR's own test stage had been scheduled on an x86_64 worker node where `libduckdb.so` was present, passing all stages. Upon merge to `main`, the distributed scheduler dynamically assigned the `test-check` stage of the merge event to `worker-aarch64`, exposing the environment provisioning gap on `main`.

______________________________________________________________________

## 3. Remediation & Preventive Controls

### Immediate Remediation

1. **Worker Shared Library Provisioning**:

   - Downloaded and verified the official DuckDB v1.2.2 aarch64 Linux release archive.
   - Installed `libduckdb.so` (`0755`) to `/usr/local/lib/libduckdb.so` and C headers to `/usr/local/include/` on `worker-aarch64`.
   - Updated the dynamic linker cache via `ldconfig`, verifying that `ldconfig -p` resolves `libduckdb.so => /usr/local/lib/libduckdb.so`.
   - Verified direct C linkage and execution against `libduckdb.so` on `worker-aarch64`.

1. **Incident Documentation & CI Validation**:

   - Created this incident postmortem under `docs/incidents/2026-11-15-mu-observable-hub-main-ci-incident.md`.
   - Executed the full pre-PR local CI gate sequence (`fmt`, `clippy`, `test`, `miri`) to ensure repository integrity.
   - Submitted a remediation Pull Request (`feat/m2-hub-incident-ingress-san-log-fixes`) to re-trigger and validate the pipeline across all nodes.

### Preventive Controls

1. **Cluster Node Provisioning Validation**:
   - Ensure all worker node onboarding checklists enforce verification of platform shared libraries (`libduckdb.so`, `libssl`, `libcrypto`) before marking nodes available for job dispatch.
1. **ActionRunner Capability Matching**:
   - Where tasks depend on node-local system dynamic libraries, declare explicit node capability requirements or bundle static fallbacks so schedulers never dispatch un-provisioned stages to heterogeneous hardware targets.
