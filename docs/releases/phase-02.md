# Phase 02 Release Notes

## Objective

Implement a safe, observable telemetry-ingestion boundary for offline PCAP,
canonical flow CSV, structured JSON events, and reviewed sample inputs without
starting packet-to-flow processing or any ML workflow.

## Status

Phase complete. PR #5 was squash-merged into `main` on 2026-07-16 00:00:35
(UTC+8), and annotated checkpoint tag `phase-02-complete` was pushed and
verified against the merge commit.

## Completed scope

- Configurable controlled roots, upload byte/chunk limits, and record limits.
- Typed registry for PCAP, flow CSV, and JSON event adapters.
- Bounded PCAP/PCAPNG framing inspection and record counting.
- Canonical flow-CSV and structured JSON validation with finite numeric values.
- Safe names/media types, bounded staging, SHA-256, integrity-checked deduplication,
  atomic storage, and cleanup after validation failures.
- Durable audited `TelemetrySource` job lifecycles with progress and safe errors.
- Manifest/checksum-controlled deterministic synthetic PCAP and CSV samples.
- Structured JSON/JSONL ingestion validated with controlled temporary test fixtures.
- FastAPI upload/sample/job endpoints and Typer ingestion commands.
- Unit, integration, target-free E2E, CLI, API, and frontend status tests.

## Architecture decisions

- ADR 0010 uses `TelemetrySource` as the ingestion job to preserve one provenance record.
- Adapters stop at file/container/schema validation; Phase 3 owns flow creation.
- Stored filenames derive from SHA-256 rather than untrusted client names.
- Samples are local, allowlisted, synthetic, and checksum-verified before use.
- The synchronous lifecycle contract is designed for later Phase 11 worker execution.

## Major files

- `src/aegishunt/ingestion/`
- `src/aegishunt/api/routes/ingestion.py`, `src/aegishunt/api/dependencies.py`
- `data/sample/`, `scripts/generate_phase2_samples.py`
- `tests/unit/test_ingestion_adapters.py`, `tests/unit/test_file_storage.py`
- `tests/integration/test_ingestion_service.py`, `tests/e2e/test_ingestion_api.py`
- `docs/ingestion.md`, `docs/adr/0010-durable-safe-ingestion-boundary.md`

## Commits

- `b92b829` - `build: configure Phase 2 telemetry ingestion`
- `72ccb03` - `feat: add secure telemetry ingestion adapters`
- `3ff92d5` - `feat: persist audited ingestion job lifecycles`
- `3acad60` - `feat: expose telemetry ingestion API and CLI`
- `853bb2b` - `feat: add controlled Phase 2 sample telemetry`
- `abb6c8d` - `test: cover Phase 2 telemetry ingestion`
- `881851e` - `docs: document Phase 2 telemetry ingestion`
- `20c1fd7` - `fix: bound PCAP declared-length reads`
- `af7c2e0` - `docs: record Phase 2 review outcome`
- `e9516f2` - `docs: record Phase 2 pull request checkpoint`
- `40405df` - `docs: record Phase 2 CI result`
- `d5e1ba6` - squash merge, `[Phase 02] Telemetry ingestion framework (#5)`

## Tests

- Ruff: passed.
- Strict mypy: passed for 46 source files.
- Pytest: 45 passed.
- Branch-aware coverage: 90.34% (minimum 85%).
- Deterministic sample regeneration: byte-identical, checksum verified.
- Live loopback API: health/sample/upload returned HTTP 200/200/201.
- Live loopback Streamlit: health `ok`, root HTTP 200.
- Manual CLI: PCAP, CSV, and sample jobs completed; invalid suffix exited 1 safely.
- GitHub Actions: both PR #5 `quality` checks passed with zero failures or pending checks.

## Generated artifacts

Committed artifacts are limited to the reviewed 114-byte synthetic PCAP, a
two-row synthetic flow CSV, their manifest, and generator. Temporary SQLite
databases and stored uploads were removed. No model, evaluation result, runtime
database, captured traffic, or fabricated metric is committed.

JSON and JSONL ingestion uses controlled temporary fixtures in the test suite;
the committed sample manifest contains the PCAP and CSV fixtures only.

## Review findings

The first read-only review found one high-severity memory-exhaustion risk from
passing forged PCAP/PCAPNG lengths to one-shot reads. Commit `20c1fd7` replaces
those reads with bounded consumption and adds a forged-length regression test.
The second review found no remaining blocking or high-severity issue. Secret,
oversized-file, generated-artifact, scope-creep, and Phase 3 checks were clean.
The local Codex CLI review command itself was unavailable because its packaged
native executable is missing; the same review criteria were applied manually.

## Known limitations

- No packet decoding, flow persistence, feature extraction, replay, live capture,
  model work, detection, alert, correlation, hypothesis, case, or feedback workflow.
- Jobs are synchronous; worker scheduling and replay belong to Phase 11.
- API authentication/authorization and concurrency hardening remain later work.
- PCAPNG validation supports one section and rejects multiple sections explicitly.
- The packaged sample catalog has no manifest-controlled JSON sample; JSON and
  JSONL contracts are instead exercised by controlled temporary test fixtures.
- No performance result is claimed.
- Bare editable CLI execution is affected by the already-recorded Codex/macOS
  hidden-`.pth` behavior; explicit `PYTHONPATH=src` manual validation passed.

## Migration notes

Database schema version remains `1`; Phase 2 reuses existing `TelemetrySource`
columns and validated JSON metadata, so no schema migration is required. Existing
databases are initialized and compatibility-checked as in Phase 1.

## Version-control checkpoint

- Branch: `phase/02-telemetry-ingestion`
- Pull request: [#5](https://github.com/SaXingrui-UM/aegishunt/pull/5)
- PR title: `[Phase 02] Telemetry ingestion framework`
- PR status: `MERGED`
- Base/head: `main` <- `phase/02-telemetry-ingestion`
- Merge date: 2026-07-16 00:00:35 (UTC+8)
- Merge commit: `d5e1ba6b4df7614977a0330a4c38a56cec051241`
- Completion date: 2026-07-16 (Asia/Shanghai)
- Tag: annotated `phase-02-complete`, remotely verified at the merge commit
- Post-merge metadata branch: `docs/phase-02-post-merge-metadata`

## Next phase

Phase 3 - Packet-to-Flow and Behavioral Feature Extraction is `Not started`.
Its planned branch is `phase/03-flow-feature-engineering`, which has not been
created. Starting Phase 3 still requires explicit user authorization after the
post-merge metadata PR is reviewed and merged.
