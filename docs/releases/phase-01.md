# Phase 01 Release Notes

## Objective

Establish the validated configuration, entity-contract, and persistence foundation
shared by later AegisHunt phases without implementing telemetry or ML workflows.

## Status

Implementation complete — awaiting PR review.

## Completed scope

- YAML defaults with environment-variable overrides and explicit validation failures.
- Pydantic schemas for all Project Plan core entities.
- SQLAlchemy records, SQLite initialization, WAL, foreign keys, and busy timeout.
- Explicit schema version `1` with incompatible-version rejection.
- Typed add/get/list repositories and same-transaction append-only audit events.
- Repeatable `aegishunt init-db` with safe structured output.
- FastAPI empty-database startup and truthful Phase 1 Streamlit status.
- Unit and integration coverage for configuration, schemas, storage, repositories, CLI, API, and frontend.

## Architecture decisions

- Configuration precedence is defaults, YAML, then `AEGISHUNT_*` environment values.
- Domain schemas are independent of ORM records.
- Business modules use typed repositories rather than SQL.
- SQLite connection integrity settings are installed at the engine boundary.
- ADR 0009 records the initial explicit version table and deferred migration framework.

## Major files

- `configs/application.yaml`
- `src/aegishunt/config.py`, `src/aegishunt/errors.py`
- `src/aegishunt/schemas/`
- `src/aegishunt/storage/`
- `tests/unit/test_config.py`, `tests/unit/test_schemas.py`, `tests/unit/test_database.py`
- `tests/integration/test_repositories.py`
- `docs/data_model.md`, `docs/adr/0009-explicit-schema-versioning.md`

## Tests

- Ruff: passed.
- Mypy: passed for 32 source files.
- Pytest: 26 passed.
- Branch-aware coverage: 94.92%.
- Repeat initialization: two successful runs; WAL, schema version `1`, and 11 tables verified.
- FastAPI: live `/health` and `/docs` returned HTTP 200 on loopback.
- Streamlit: live health returned `ok` and root returned HTTP 200 on loopback.
- GitHub Actions: both `quality` checks passed at PR checkpoint `2acd246`.

The Codex macOS runtime repeatedly reapplied the hidden flag to the editable
installation `.pth`. Manual CLI/server checks therefore used `PYTHONPATH=src`;
this runtime-specific issue does not change the package layout or CI commands.

## Known limitations

- No ingestion, PCAP parsing, flow construction, feature engineering, dataset, model, detection, correlation, hypothesis-generation, or case service exists.
- The initial schema-version mechanism detects mismatch but does not migrate it.
- SQLite remains the only exercised database; PostgreSQL portability is architectural, not yet demonstrated.
- JSON evidence/reference fields require later service-level referential validation.

## Version-control checkpoint

- Branch: `phase/01-data-foundation`
- Pull request: [#3](https://github.com/SaXingrui-UM/aegishunt/pull/3), Draft, base `main`, head `phase/01-data-foundation`
- Merge commit: pending
- Tag: not created; prohibited before merge and explicit user instruction

## Migration notes

Run `aegishunt init-db` with the selected YAML/environment configuration. This is
the first application database schema, so there is no earlier AegisHunt database
to migrate.

## Generated artifacts

Manual verification created temporary ignored SQLite files and removed them.
No dataset, PCAP, model, metric result, database, or other generated artifact is committed.

## Next phase

Phase 2 will implement controlled telemetry adapters and ingestion jobs. It has
not started and must not start automatically.
