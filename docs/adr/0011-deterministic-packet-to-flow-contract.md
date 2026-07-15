# ADR 0011: Use a deterministic bounded packet-to-flow contract

## Status

Accepted

## Context

Phase 3 must convert validated offline PCAP data into reproducible bidirectional
flows without weakening the Phase 2 untrusted-file boundary. Direction, timeout,
out-of-order timestamps, division by zero, feature ordering, and the transaction
that makes flows visible all require explicit semantics. The existing Phase 1
schema already has `NetworkFlow` and a typed repository, so adding another flow
table or bypassing repositories would duplicate contracts.

## Decision

Use a pure `flows` domain boundary between capture bytes and persistence:

1. A bounded streaming reader handles classic PCAP and supported PCAPNG packet
   blocks. The packet parser uses IP and transport headers only; it never derives
   model features from application payload. Ethernet and raw-IP link types are
   supported. Non-IP frames, fragments, unknown transports, and unsupported link
   layers are counted as explicit skips. Malformed supported packets fail the job.
2. Canonical keys contain IP version, protocol number, normalized endpoint pair,
   and an ICMP discriminator. TCP/UDP endpoints include ports. ICMP echo traffic
   uses its identifier so request/reply types share a key; non-echo ICMP uses
   type/code and is intentionally not paired with an inferred response type.
3. The first decoded packet in a segment defines forward. Its reverse endpoint
   order defines backward regardless of canonical-key sorting.
4. On every capture packet, active timeout is evaluated before idle timeout for
   all active states. Both boundaries use `>=`. A timed-out or capacity-bounded
   state is removed before a new segment begins. Capture-end and manual flush are
   idempotent because finalized states leave the active map.
5. Packet arrival order remains the direction and TCP-handshake evidence order.
   Earliest/latest and IAT calculations use sorted captured timestamps, so clock
   disorder is visible in provenance but cannot create negative duration or IAT.
   Python `datetime` limits timestamp resolution to microseconds.
6. Zero-duration rates, zero backward denominators, empty directions, and missing
   IATs return `0.0`. This avoids undefined or infinite values without pretending
   an unobserved reverse rate exists.
7. Feature schema `1.0.0` is an explicit tuple of 43 definitions. Registry order
   is the only training/inference order. A deterministic JSON export and human
   dictionary define types, calculations, ranges, and empty behavior.
8. PCAP parsing and finalization finish before the source file is committed. A
   parsing failure therefore removes the staged file and writes no flow. On
   success, all `NetworkFlow` creates and the ingestion completion transition
   share one database transaction through existing repositories and audit logic.
   The source metadata records the feature-schema version and packet/flow counts.

No database column changes are required: `NetworkFlow.behavioral_features`
contains only flat finite numeric values, and its `source_id` links to the
`TelemetrySource` metadata that carries `feature_schema_version`.

## Alternatives considered

- Treat each direction as a separate flow.
- Sort endpoints and also use that order as forward, losing first-observed meaning.
- Apply timeouts only when another packet for the same key arrives.
- Clamp negative deltas in capture order without documenting timestamp disorder.
- Use NaN, infinity, or an arbitrary epsilon for empty and zero-duration cases.
- Depend on dictionary insertion as an undocumented model feature order.
- Persist flows incrementally while parsing, leaving partial capture results.
- Add a Phase 3 flow table or write SQL directly from packet code.

## Consequences

The same supported capture and configuration produce equivalent flow boundaries,
feature order, and numeric values. Direction is investigation-friendly and does
not depend on endpoint lexical order. Parsing is unit-testable without a database,
and restart persistence is testable independently. A failed packet cannot leave a
partially completed flow set. Existing flow CSV and JSON ingestion remain at their
Phase 2 validation-only boundary.

## Risks

Per-flow packet size/timestamp observations are bounded but still consume memory
up to configured limits; a later streaming performance phase must measure this.
Unsupported link layers, fragments, PCAPNG simple packet blocks, and multi-section
PCAPNG files produce a skip or explicit failure rather than guessed evidence.
Timeout choices affect segmentation and must be preserved with experiment
configuration. ICMP non-echo pairing is conservative. Single-flow behavioral
features do not replace cross-flow entity/window features, which remain deferred.
