# ADR 0020: Durable single-node runtime replay

- Status: Accepted

## Context

Phases 2–10 provide safe PCAP storage, deterministic flow extraction, verified
model/policy artifacts, detections, optional alerts, correlation, and hypotheses,
but they do not provide a durable runtime that joins those stages. Phase 11 must
support slow replay, operator pause/resume, graceful shutdown, explicit recovery,
worker health, and restart-safe persistence without requiring root, live capture,
an external broker, or a distributed database.

## Decision

Use an additive SQLite-backed queue with `RuntimeJob`, `RuntimeAttempt`,
`RuntimeWorker`, `RuntimeResourceSample`, and `RuntimeOutputLedger` records. A
worker atomically claims one queued job with a bounded lease, persists attempts,
heartbeats without audit spam, and reconciles an expired lease to
`recovery_pending`. Recovery is deliberately operator-initiated and restarts the
capture from packet zero. It is not exact packet-cursor resume.

Before job creation and again before the first packet, load every configured
bundle/policy through its existing secure loader. Pin source checksum, logical
stored filename, model/policy IDs, versions, checksums, feature/runtime/schema
versions, capture session, and Git commit. Identity or byte drift fails closed.

Replay uses packet event-time deltas divided by configured speed. The first
packet is immediate, negative deltas sleep zero and increment an out-of-order
counter, long gaps are capped and counted, and sleep occurs in short
interruptible quanta. Existing Phase 3 parsing, aggregation, finalization, and
EOF flush are reused.

Persist each finalized-flow batch, detection, optional alert, output ledger, and
durable output-counter update in one transaction. Separately persist
`non_durable_live_observation` packet telemetry for the current worker attempt.
Observed telemetry may lead committed evidence, is never a checkpoint, and
resets to zero on a new origin-recovery attempt. The principal job/attempt
progress remains `durable_committed_evidence`; its packet position stays at the
conservative proven lower bound (zero in this implementation) until final
completion. It reaches 100% only in the transaction that follows EOF flow flush,
final correlation, and final hypothesis generation.

The ledger lets explicit recovery replay from origin while reusing
byte-equivalent committed outputs and rejecting conflicting evidence. Phase 11
does not persist an exact packet cursor or complete open-flow state and therefore
does not claim exact resume or distributed exactly-once processing.

Live capture and automatic recovery remain disabled. The execution mode is one
local worker process family over SQLite; resource samples are bounded and an
unavailable sampler records null measurements rather than fabricated zeros.

## Alternatives considered

- Exact packet-cursor resume: rejected because flow-aggregator state and timeout
  ordering would also need a complete atomic checkpoint.
- In-memory task queue: rejected because process termination would lose work and
  audit state.
- Celery, Redis, Kafka, or an external database: rejected as unnecessary
  operational weight for the Phase 11 single-node prototype.
- Automatic stale-job requeue: rejected because repeated work must remain an
  explicit operator decision.
- Live interface capture as the primary runtime: rejected because it commonly
  requires privileges, creates target/environment coupling, and is not needed
  for the primary offline demonstration.
- Per-packet audit events: rejected because they create unbounded noise; observed
  progress, heartbeats, and resource samples have dedicated bounded records.

## Consequences

The runtime survives ordinary process restart, exposes explicit state, and can
replay deterministically without overwriting prior evidence. SQLite transactions
protect each durable output batch, but there is no distributed exactly-once
guarantee. A stopped job may redo packet parsing and scoring from origin; the
ledger prevents duplicate committed evidence. Only one runtime job is allowed
per telemetry source; later work uses explicit recovery. Live observed progress
can disappear with a worker and must never be interpreted as committed evidence.

## Risks

SQLite supports only bounded single-node concurrency. Very large captures may
require further memory and throughput profiling. Resource metrics are
development-host observations, not production SLAs. A complete database outage
still cannot persist failure evidence into that same database (DEF-004). Abrupt
host termination between external file I/O and database work can require
operator verification, although source and artifact checksums fail closed.
