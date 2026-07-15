# ADR 0009: Use explicit schema versions before adopting a migration framework

## Status

Accepted

## Context

Phase 1 needs repeatable SQLite initialization and a detectable database contract.
There is only one schema version and no deployed historical database yet. Adding
a full migration framework now would add machinery without a migration to perform,
but silently accepting mismatched schemas would risk corrupt or misleading reads.

## Decision

Create an append-only `schema_versions` table with current version `1`. Database
initialization creates missing tables and registers version `1` idempotently. It
rejects any different highest version with an explicit `SchemaVersionError`.
SQLAlchemy metadata defines the initial schema; repository and schema-version
modules remain separate so an ordered migration framework can replace this step
before the first schema-changing release.

## Alternatives considered

- Add Alembic immediately despite having no prior schema to migrate.
- Infer compatibility from table or column presence.
- Run destructive drop-and-recreate initialization.
- Ignore schema versions until deployment work.

## Consequences

Empty databases initialize repeatedly, compatibility is explicit, and Phase 1
stays lightweight. Future schema changes cannot be shipped by editing metadata
alone: they require a migration decision, tests, and an incremented version.

## Risks

The initial mechanism cannot upgrade an older database. A later phase could add
columns without introducing migrations, leaving version `1` ambiguous. Reviewers
must treat any ORM schema change as requiring a new ADR or migration record.
