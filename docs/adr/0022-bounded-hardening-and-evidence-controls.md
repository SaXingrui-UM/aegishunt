# ADR 0022: Bounded Hardening and Evidence Controls

## Status

Accepted

## Context

The completed Phase 0–12 modular monolith accepts untrusted telemetry, consumes
replaceable local artifacts, maintains SQLite state, and issues research
evidence. The immutable Phase 13 Codex Security baseline found no Critical or
High findings, but it identified seven Medium findings involving resource
bounds, model/policy identity, dataset provenance, duplicate detection, and
flow-expiration complexity. Phase 13 also requires repeatable performance and
robustness evidence without changing frozen model selection or test evidence.

Controls must preserve the existing local, offline, single-user research
boundary. They must not introduce a broker, production authentication, live
capture, Phase 14 deployment packaging, or latency-dependent correctness.

## Decision

Use complementary bounded controls at the earliest practical trust boundary:

1. Install a raw ASGI request-body limit before Starlette multipart parsing.
   Endpoint limits are derived from existing upload limits plus a separately
   bounded multipart overhead allowance.
2. Parse JSON arrays and JSONL incrementally. Bound logical records, bytes per
   record, and nesting depth before constructing a complete object inventory.
3. Bound PCAPNG interface metadata independently of packet and upload limits.
4. Replace per-packet scans of every active flow with a deadline heap. Stale
   entries are checked against the authoritative flow state and compacted when
   required; active timeout retains priority over idle timeout.
5. Detect near duplicates using exact tolerance components rather than rounded
   bins, including across frozen dataset partitions.
6. Permit controlled-generator evidence reissuance only when canonical rows
   exactly match deterministic regeneration under the recorded seed.
7. Require the Phase 5 supervised identity, Phase 6 anomaly identity, and Phase
   3 feature schema before fusion refitting.
8. Treat the reason-code catalog's enabled flag as an enforcement decision, not
   display metadata.
9. Keep performance and robustness harnesses separate from production
   orchestration. They use isolated temporary databases/artifacts, versioned
   methods, no network or root privilege, and no noisy latency pass/fail target.

The repository-wide branch-aware coverage gate remains 85%. A separately
versioned Phase 13 core boundary enforces at least 80% combined statement and
branch coverage; excluding CLI/Streamlit from that subset does not exclude them
from the repository-wide gate.

## Alternatives considered

- **Rely only on final file-size validation:** rejected because multipart and
  JSON object amplification occurs before the existing late checks.
- **Scan all active flows for every packet:** rejected because configured flow
  capacity makes quadratic work reachable even with bounded input.
- **Use rounded near-duplicate fingerprints:** rejected because points inside
  the declared tolerance can fall on different quantization sides.
- **Trust self-issued checksums for controlled data and fusion evidence:**
  rejected because mutually generated metadata does not establish the upstream
  producer identity.
- **Set hard latency thresholds in CI:** rejected because shared-runner noise
  would make correctness non-deterministic. CI uses smoke execution only.
- **Introduce Redis, Kafka, Celery, distributed workers, or public services:**
  rejected as out of scope for the single-node Phase 13 prototype.

## Consequences

- Malformed and oversized requests fail earlier and use less parser memory.
- Flow expiration is deadline-driven while final state remains authoritative.
- Controlled-demo and fusion evidence have stronger provenance/identity gates.
- Performance results remain reproducible observations rather than product
  claims or model-selection inputs.
- New configuration fields require validation and documented defaults.
- Deadline heaps contain stale entries by design and therefore need bounded
  compaction and regression coverage.
- Exact tolerance components cost more than rounded hashing but preserve the
  declared leakage invariant for the current bounded dataset workflow.

## Risks

- ASGI clients without a trustworthy `Content-Length` still require streaming
  byte counting; middleware must enforce both paths.
- A small synthetic workload cannot establish production capacity or
  real-network robustness.
- Artifact checksums stored beside artifacts do not provide a hardware or
  external trust anchor; residual local-filesystem risks remain documented.
- SQLite outage evidence cannot be persisted into that same unavailable
  database (DEF-004).
- Phase 14 must separately decide deployment, authentication, reverse proxy,
  TLS, and dependency-vulnerability operational controls.
