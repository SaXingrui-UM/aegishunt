# Phase 13 Requirement Traceability

## Frozen core definition

Before Phase 13 coverage results were examined, the core boundary was frozen in
`configs/hardening/phase-13-core-coverage.yaml`. It includes shared
configuration/artifact I/O and the API, ingestion, flows, datasets, ML,
detection, explainability, correlation, hunting, cases, feedback, runtime,
schemas, storage, and demo packages. CLI and Streamlit are excluded only from
the 80% core subset; they remain in the unchanged repository-wide 85%
branch-aware gate.

## Roadmap tasks

| ID | Phase 13 Roadmap task | Implementation/evidence | Result |
| --- | --- | --- | --- |
| P13-01 | Complete unit tests | Existing suite plus bounded-input, integrity, benchmark, robustness, core-coverage, and reason-catalog regressions | Implemented |
| P13-02 | Complete integration tests | SQLite concurrency/rollback, ingestion/flow atomicity, model/policy loading, runtime and service integrations | Implemented |
| P13-03 | Complete E2E tests | Offline Phase 0–12 suite plus real Sample Demo and Phase 13 robustness selection | Implemented |
| P13-04 | Core coverage at least 80% | Frozen config and `check_phase13_core_coverage.py`; 85.72% combined statement/branch core coverage across 219 source files; repository 85% gate unchanged | Passed |
| P13-05 | Corrupt PCAP tests | Truncated, forged length, malformed packet, unsupported frame, bounded PCAPNG metadata | Passed |
| P13-06 | Wrong CSV schema tests | Missing/extra fields, invalid IP/type, non-finite values, record bounds | Passed |
| P13-07 | Oversized upload tests | Raw ASGI pre-parser 413; exact/over staging boundary; no job or residue | Passed |
| P13-08 | Model schema mismatch | Feature schema/order/dtype/non-finite checks and verified identity gates | Passed |
| P13-09 | Path traversal tests | Upload names, archive members, artifact roots, downloads, and local origins | Passed |
| P13-10 | Database concurrency | Five concurrent jobs, WAL/restart, transaction rollback and atomic claim tests | Passed |
| P13-11 | Corrupt model tests | Missing/extra/corrupt/unsafe files, checksums, version collision, no arbitrary pickle/joblib | Passed |
| P13-12 | Performance measurement | Versioned offline tool measures six required components | Completed |
| P13-13 | Memory measurement | 2 ms process peak-RSS sampler and artifact sizes | Completed |
| P13-14 | p50/p95/p99 reporting | Linear-interpolated iteration latency plus throughput and CPU | Completed |
| P13-15 | Robustness experiments | Versioned 21-scenario matrix; final 21 PASS / 0 FAIL | Passed |
| P13-16 | Secret scan | Baseline referenced; independent tracked-pattern and artifact-hygiene checks found no secret | Passed within documented scope |
| P13-17 | Dependency review | `pip check` pass; `pip inspect` 92 distributions; CVE audit not executed because no installed/offline audit database | Partial; limitation recorded |

## Acceptance criteria

| Acceptance criterion | Evidence | Status |
| --- | --- | --- |
| `pytest`, `ruff`, and `mypy` pass | Final repository commands: 488 tests passed at 85.29% branch-aware coverage; strict mypy covered 237 source files | Satisfied |
| E2E is offline and non-admin | Existing E2E contracts, temporary roots, robustness runner | Satisfied |
| Bad input does not crash unrelated work | Security and atomicity regressions | Satisfied |
| User model uploads are never deserialized | Strict bundle inventory/root/type checks and regressions | Satisfied |
| Upload paths remain safe | filename/root/archive/download regressions | Satisfied |
| No Phase 14 scope creep | Diff review; no deployment/auth/RBAC/broker/live-capture implementation | Satisfied |

## NFR mapping

- Reliability: ROB-001–ROB-021 and transaction/restart tests.
- Testability: frozen core plus repository-wide branch-aware coverage.
- Security: Phase 13 security baseline map and targeted regression suite.
- Performance: versioned benchmark JSON/CSV/Markdown and method.
- Reproducibility: checksums, versions, random seeds, host/dependency metadata,
  deterministic test nodes, and reviewable results.
- Portability: offline/rootless local Python; macOS development-host result;
  Linux CI must pass on the pull request before merge.
- Data/model integrity: exact dataset provenance, leakage, model/policy
  inventory, schema, checksum, and collision gates.
