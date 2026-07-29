# Phase 13 Release Notes

## Objective and status

Harden the completed Phase 0–12 local research prototype, validate malformed
input and artifact boundaries, establish reproducible performance/robustness
evidence, and preserve the scientific and audit contracts of earlier phases.

Status: **Implementation complete — awaiting PR review**.

- Branch: `phase/13-hardening`
- Pull request: pending
- Merge commit: pending
- Completion tag: pending; `phase-13-complete` must not be created before merge
- Phase 14: Not started

## Completed scope

- Added raw streaming request-body enforcement before multipart parsing.
- Replaced whole-file JSON/JSONL telemetry loading with incremental bounded
  parsing, per-record byte ceilings, logical record limits, finite-value
  validation, and nesting-depth limits.
- Added a configured PCAPNG interface-inventory bound.
- Replaced per-packet active-flow scans with a deadline heap and bounded stale
  entry compaction while preserving active-before-idle timeout semantics.
- Replaced rounded near-duplicate fingerprints with exact tolerance components
  for dataset quality and cross-split leakage.
- Bound controlled-generator provenance to exact deterministic regeneration.
- Required verified supervised/anomaly identities and feature schema before
  fusion refitting.
- Enforced disabled reason-code catalog entries at generation time.
- Added a frozen core coverage definition and machine-readable gate.
- Added a versioned 21-scenario robustness matrix and isolated runner.
- Added a versioned six-component benchmark with throughput, p50/p95/p99, CPU,
  peak RSS, artifact sizes, checksums, identities, and environment metadata.
- Referenced the immutable Security baseline, mapped all Medium findings, and
  recorded residual Low findings and dependency-audit limitations.

## Architecture decisions

ADR 0022 records earliest-boundary streaming limits, incremental JSON parsing,
deadline-indexed flow timeout processing, exact near-duplicate components,
controlled-generator equivalence, fusion identity binding, catalog enforcement,
and isolated performance/robustness evidence.

No distributed broker, public service, live capture, production authentication,
deployment wrapper, automatic response, automatic training/activation, new
public dataset, or Phase 14 functionality was added.

## Commits

- `71fc9c0` — `fix: bound untrusted telemetry and flow state`
- `3638353` — `fix: strengthen dataset and fusion integrity`
- `93290cc` — `test: cover phase 13 security regressions`
- `f1cf2b8` — `perf: add reproducible phase 13 benchmark`
- `a34a541` — `test: add phase 13 robustness matrix`
- `3292edc` — `fix: correct robustness provenance test node`
- `db29f9c` — `test: enforce phase 13 core coverage gate`
- `bc4c531` — `test: expand phase 13 boundary regressions`
- `05d67f6` — `fix: honor disabled explanation reason codes`

Later documentation, final-verification, and review commits will be listed in
the pull request.

## Tests and coverage

### Startup baseline

- Ruff: passed.
- Strict mypy: passed for 237 source files.
- Repository pytest: 465 passed, 0 failed, 0 skipped, 0 xfailed in 1,563.08
  seconds at 85.34% branch-aware coverage.
- Corrected Phase 12 API/frontend/demo/security/status gate: 63 passed in 81.69
  seconds.
- One earlier focused command used a nonexistent test path and a zsh readonly
  variable. It failed before collection, was corrected, and was not counted as
  a product pass.

### Phase 13 focused evidence

- Input/integrity/benchmark/robustness/core-coverage focused selections passed.
- Reason-code focused suite: 10 passed; strict mypy remained clean.
- Final robustness matrix v1.1.0: 21 scenarios, 27 represented test instances,
  21 PASS and 0 FAIL.
- Initial robustness v1.0.0 run: 16 PASS / 1 FAIL because ROB-011 named an old
  test function. The matrix was corrected and fully rerun; the failure was not
  hidden or converted to skip.
- Final repository-wide Ruff, mypy, pytest, core coverage, and benchmark smoke
  are required before the PR and will be recorded in the final checkpoint.

The repository-wide 85% branch-aware threshold was not lowered. CLI and
Streamlit are excluded only from the separately frozen 80% core subset and
remain in repository coverage.

## Performance baseline

The controlled development-host run used the reviewed
`phase12-presentation-demo.pcap` (32 packets, 9 flows), seed `4204`, two
warm-ups, and ten repetitions. It measured PCAP reading, flow/feature
aggregation, supervised inference, anomaly inference, fusion, and the complete
flow-to-alert pipeline.

The actual JSON/CSV/Markdown reports are under
`reports/hardening/phase-13/performance/`. The full pipeline p50 was
6,138.5708 ms and its throughput was 1.4590 persisted flows/s on this host.
These values are development-host observations only—not an SLA, public
benchmark, production capacity, or real-world detection result.

## Robustness result

All 21 versioned scenarios passed in isolated processes. They cover corrupted
PCAP, invalid CSV, pre-parser upload limits, exact/over upload boundaries,
schema drift, path traversal, SQLite concurrency/rollback, corrupt and colliding
model artifacts, fusion-policy integrity, duplicate ingestion, controlled
provenance, bounded JSON/PCAPNG parsing, cross-split near duplicates, idempotent
Demo execution, and atomic flow persistence.

No formal frozen test was reopened. All model/evidence work used pytest
temporary directories or the ignored isolated Demo namespace.

## Security baseline

The user-confirmed repository baseline at
`75c73bc86a40a78a22edde5fb175359a7b755c05` covered all 448 tracked files and
reported 7 Medium, 73 Low, 0 High, and 0 Critical findings. It was not rerun.

- All seven Medium findings have regression-backed Phase 13 remediations.
- Two Low findings have direct Phase 13 fixes (excessive JSON nesting and
  disabled reason-code enforcement).
- The other 71 Low findings remain explicit residual/deferred risks in the
  immutable baseline ledger.
- Independent secret/artifact hygiene checks found no tracked secret or unsafe
  model/database artifact.
- `pip check` passed; `pip inspect` recorded 92 distributions.
- Dependency CVE scanning was not executed because `pip-audit` and an offline
  vulnerability database were unavailable.

## Generated artifacts

Committed, small, reviewed evidence:

- performance JSON/CSV/Markdown summaries;
- robustness JSON/CSV/Markdown summaries;
- Phase 13 method, traceability, security, ADR, and release documentation.

Not committed:

- temporary SQLite databases;
- isolated demo model binaries and policy artifacts;
- coverage machine output;
- raw subprocess logs;
- the environment-owned Codex Security scan directory;
- any runtime upload or staging file.

## Known limitations

- Performance uses a small controlled synthetic PCAP on one Darwin arm64
  development host; it cannot establish production capacity.
- No noisy latency threshold is used in CI.
- The baseline Security scan's 71 unremediated Low findings remain residual
  risks; many require stronger deployment custody or Phase 14 controls.
- No offline CVE database was available for dependency vulnerability scanning.
- SQLite remains a single-node store. DEF-004 remains: total database
  unavailability cannot persist a failure record into that same database.
- The desktop runtime can hide editable-install `.pth`; recorded manual
  commands use `PYTHONPATH=src`, while pytest and normal CI use the declared
  source layout.
- Controlled synthetic evidence is pipeline verification only, not a public
  benchmark, production validation, real-world performance, or zero-day proof.
- Phase 6 LOF remains validation-qualified without an untouched independent
  holdout; Phase 7 fusion remains inconclusive and is not superior to every
  single-engine result.

## Next phase

Phase 14 — Final Integration and Delivery — is **Not started**.

Before Phase 14, the Phase 13 PR must pass CI, be reviewed and merged by the
user, synchronized to `main`, and receive a separately authorized annotated
`phase-13-complete` checkpoint tag.
