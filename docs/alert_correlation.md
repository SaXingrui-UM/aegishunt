# Phase 9 Alert Correlation Contract

## Purpose and claim boundary

The Phase 9 engine groups related `SecurityAlert` evidence to support analyst triage.
It does not confirm an attack, infer an actor, perform external enrichment, or execute a
response. The correlation score is a bounded evidence-strength score, not probability.

## Input and eligibility

- Input is immutable persisted `SecurityAlert` data.
- Event time comes only from `evidence.observed_facts.first_seen/last_seen`; database
  creation time is not used for behavioral windows.
- Unreviewed, true-positive, and needs-more-information alerts are eligible by default.
- False-positive and benign-expected verdicts are excluded by configured policy.
- Unknown verdict policy, missing event facts, invalid IPs, duplicate alert IDs, and
  configured size-limit violations fail closed.

## Canonical entities and windows

Entity types include source/destination IP or host, user, protocol, service, flow,
capture session, and the directional source/destination pair. IPs use canonical
compressed notation; host/user/protocol/service values are trimmed and case-folded.
Weak protocol-only relationships never create groups.

Candidate alerts are sorted by observed event start and alert ID. Each entity uses a
non-overlapping window anchored to the earliest unconsumed event. The boundary is
inclusive only when the candidate's observed end time remains within it; this keeps the
complete group span bounded. Per-run, per-alert, per-entity, and per-group limits are configuration
controlled; the implementation does not perform an unbounded all-pairs scan.

## Versioned rules

The `1.0.0` policy declares versions for source-centered reconnaissance, repeated
source/destination failures, source fan-out, destination fan-in, periodic beacon-like
timing, multi-engine evidence, and multi-alert accumulation. Every match retains its
rule/version, alert IDs, required entity, evidence, and limitation. A match describes a
pattern only; benign scanning, shared services, scheduled traffic, retries, and model
dependency remain explicit limitations.

## Score and group identity

The retained components are mean/maximum member risk (as configured), bounded alert
count, reason/rule diversity, and temporal density. Configured weights sum to one.
Severity is an operational triage mapping. Stable UUIDv5 group identity binds the
policy ID/version and sorted alert IDs. Duplicate group evidence is returned
idempotently; an identity collision with different evidence fails closed.

An `AlertGroup` retains members, canonical entities, matched rules, components, event
window, count, severity, summary, evidence snapshots, policy checksum, schema version,
and an explicit lifecycle creation time. `first_seen` and `last_seen` remain the
observed event window. `created_at` is the time the group record is generated, comes
from an injectable UTC clock, and is also retained as `evidence.generated_at`.
Lifecycle time is excluded from the stable UUID identity. An idempotent rerun returns
the existing group and preserves its original `created_at`; a conflicting evidence
payload fails closed. Phase 8 source alerts are never mutated.

One alert may belong to multiple groups only when it participates in distinct canonical
relationships (for example, one source-centered and one destination-centered pattern).
The same sorted alert set is aggregated into one group even if several shared entity
keys produce it; exact duplicates are not created.
