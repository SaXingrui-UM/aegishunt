# ADR 0004: Use SQLite as the default storage

## Status

Accepted

## Context

AegisHunt must run locally and in a self-contained demonstration without an
external database service. It needs durable metadata and investigation state,
transactional updates, auditability, and a path to stronger concurrency if the
prototype grows.

## Decision

Use SQLite through SQLAlchemy as the default database beginning in Phase 1,
enable WAL mode, and isolate access behind repository interfaces and explicit
transactions. Keep schema and query design portable enough for a future
PostgreSQL adapter. Generated datasets and model binaries remain filesystem
artifacts with database metadata and hashes rather than opaque database blobs.

## Alternatives considered

- PostgreSQL as a mandatory local service.
- Embedded analytical stores such as DuckDB for all operational state.
- Flat JSON/CSV files as the primary persistence mechanism.
- In-memory state only.

## Consequences

Installation and sample demonstrations remain simple, while SQLAlchemy supplies
schema and repository structure. SQLite limits and transaction semantics must be
tested, especially for worker/API concurrency. Storage migration remains a
designed option, not a promised zero-effort switch.

## Risks

Write contention, large flow tables, or long transactions may exceed SQLite's
comfortable operating envelope. WAL files require correct lifecycle handling.
SQLite-specific assumptions could undermine portability if repository and
migration boundaries are not maintained.
