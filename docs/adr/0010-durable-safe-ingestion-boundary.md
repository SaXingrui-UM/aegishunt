# ADR 0010: Use a durable safe-ingestion boundary over TelemetrySource

## Status

Accepted

## Context

Phase 2 must accept untrusted PCAP, flow CSV, and JSON files; expose progress and
errors; retain checksum provenance; and avoid implementing Phase 3 packet-to-flow
logic. Phase 1 already defines `TelemetrySource` with lifecycle, timestamps,
record count, checksum, metadata, repository, and audit support. A separate job
table would duplicate those fields before asynchronous workers exist.

## Decision

Use `TelemetrySource` as the durable ingestion-job record and store Phase 2
progress, safe storage metadata, inspection metadata, and typed error details in
its validated JSON metadata. A service exclusively owns lifecycle transitions
and audits every transition. Stream uploads into a controlled temporary file,
enforce configurable byte/type/name limits, hash with SHA-256, inspect through a
source-type adapter with a configurable record limit, then atomically store under
the checksum name. Failed validation retains the job but removes staged bytes.

PCAP adapters validate only container framing and packet-block counts. Flow CSV
rows are checked against the canonical schema but are not persisted as flows.
Sample files require an allowlisted manifest and checksum. Phase 11 may execute
the same service contract asynchronously without changing job semantics.

## Alternatives considered

- Add a separate ingestion-job table duplicating source provenance.
- Store uploads under client filenames.
- Parse packets and derive flows during Phase 2.
- Accept arbitrary server filesystem paths through the API.
- Keep failures only in process logs without durable state.

## Consequences

Phase 2 has one source of truth for provenance, avoids a schema migration, and
provides queryable success/failure states. Storage names cannot traverse paths or
collide by client naming. Later processing can reference the source ID and stored
checksum. Synchronous requests perform bounded local I/O and validation; they do
not yet benefit from worker scheduling or resumability.

## Risks

JSON metadata has weaker database-level constraints than dedicated columns, so
all writes must remain behind validated schemas and the service. Large allowed
uploads can occupy an API worker until Phase 11. SHA-256 deduplicates bytes, not
semantic records. Container validation does not establish that packet contents
are useful or benign, and sample ingestion must never be presented as a detection
result.
