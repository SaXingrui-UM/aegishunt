# ADR 0019: Audited cases and review-only analyst feedback

- Status: Accepted

## Context

Phase 9 produces cautious hypotheses but provides no analyst investigation lifecycle.
Phase 10 must close that human-review loop without turning hypotheses into facts,
feedback into trusted ground truth, or candidate data into automatic online learning.
It must preserve immutable Phase 5–9 evidence and exclude historical evaluation rows.

## Decision

Reuse and extend the existing `InvestigationCase` and `AnalystFeedback` entities. Bind
one deterministic primary Case UUID to one primary hypothesis plus Case/policy schema
identity. Store append-only notes and typed immutable evidence snapshots in dedicated
tables. Configure all state transitions, priority mapping, limits, provenance gates,
and exact artifact inventories in a checksummed YAML policy. Use injectable UTC clocks
for lifecycle timestamps and retain source event time separately.

Keep the existing alert verdict as the current alert-level value and update it together
with alert feedback in one transaction. Treat all feedback as human-supplied and
potentially noisy. Permit only explicit, uniquely mapped alert→detection→flow feedback
to produce review-only retraining candidates. Exclude case-level propagation,
conflicts, evaluation/test/holdout, unknown provenance, and non-finite/schema-mismatched
features. Write feedback exports, candidate data, and case reports as atomic,
non-overwriting, exact-inventory, checksummed data-only artifacts.

## Alternatives considered

- Separate replacement Case/Feedback entities: rejected because they would duplicate
  Phase 1 contracts and create inconsistent sources.
- Mutable JSON notes/evidence: rejected because author/time and audit history would be
  lost.
- Case-verdict propagation to every flow: rejected because a multi-alert Case does not
  establish row-level truth.
- Latest/highest-confidence conflict resolution: rejected because it hides disagreement.
- Automatic retraining/activation: rejected by research integrity and analyst control.
- Arbitrary file attachments: rejected because Phase 10 needs structured evidence, not
  a new untrusted file boundary.

## Consequences

Case and feedback mutations remain transactional and auditable; duplicate creation is
idempotent; source evidence remains unchanged. Candidate artifacts are traceable but
require a later explicit quality/split/training workflow. Schema v4 is an additive
SQLite migration. Full Cases HTTP/UI workflows remain Phase 12, while replay/workers
remain Phase 11.

## Risks

Human labels can be wrong or inconsistent. Strict provenance gates may yield an empty
candidate artifact. SQLite cannot persist an outage record into itself when completely
unavailable (DEF-004). Data-only filesystem writes and database audit commits cannot be
made one atomic transaction across both resources, so failed audit commits may require
manual cleanup of an otherwise valid non-overwriting artifact.
