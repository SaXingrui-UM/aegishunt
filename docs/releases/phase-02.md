# Phase 02 Release Notes

## Objective

Implement a safe, observable telemetry-ingestion boundary for offline PCAP,
canonical flow CSV, structured JSON events, and reviewed sample inputs without
starting packet-to-flow processing or any ML workflow.

## Status

Implementation complete - preparing pull request review. This phase is not
`Phase complete` until its PR is merged and its annotated checkpoint tag is
explicitly requested and created.

## Completed scope

- Configurable controlled roots, upload byte/chunk limits, and record limits.
- Typed registry for PCAP, flow CSV, and JSON event adapters.
- Bounded PCAP/PCAPNG framing inspection and record counting.
- Canonical flow-CSV and structured JSON validation with finite numeric values.
- Safe names/media types, bounded staging, SHA-256, integrity-checked deduplication,
  atomic storage, and cleanup after validation failures.
- Durable audited `TelemetrySource` job lifecycles with progress and safe errors.
- Manifest/checksum-controlled deterministic synthetic PCAP and CSV samples.
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
- Documentation checkpoint - this release-note commit.

## Tests

- Ruff: passed.
- Strict mypy: passed for 46 source files.
- Pytest: 45 passed.
- Branch-aware coverage: 90.38% (minimum 85%).
- Deterministic sample regeneration: byte-identical, checksum verified.
- Live loopback API: health/sample/upload returned HTTP 200/200/201.
- Live loopback Streamlit: health `ok`, root HTTP 200.
- Manual CLI: PCAP, CSV, and sample jobs completed; invalid suffix exited 1 safely.

## Generated artifacts

Committed artifacts are limited to the reviewed 114-byte synthetic PCAP, a
two-row synthetic flow CSV, their manifest, and generator. Temporary SQLite
databases and stored uploads were removed. No model, evaluation result, runtime
database, captured traffic, or fabricated metric is committed.

## Known limitations

- No packet decoding, flow persistence, feature extraction, replay, live capture,
  model work, detection, alert, correlation, hypothesis, case, or feedback workflow.
- Jobs are synchronous; worker scheduling and replay belong to Phase 11.
- API authentication/authorization and concurrency hardening remain later work.
- PCAPNG validation supports one section and rejects multiple sections explicitly.
- No performance result is claimed.
- Bare editable CLI execution is affected by the already-recorded Codex/macOS
  hidden-`.pth` behavior; explicit `PYTHONPATH=src` manual validation passed.

## Migration notes

Database schema version remains `1`; Phase 2 reuses existing `TelemetrySource`
columns and validated JSON metadata, so no schema migration is required. Existing
databases are initialized and compatibility-checked as in Phase 1.

## Version-control checkpoint

- Branch: `phase/02-telemetry-ingestion`
- Pull request: pending
- Merge commit: pending
- Tag: pending; must not be created before merge

## Next phase

Phase 3 remains unstarted. After the Phase 2 PR is reviewed and merged, a user may
explicitly authorize `phase/03-flow-feature-engineering`; this release does not do so.
