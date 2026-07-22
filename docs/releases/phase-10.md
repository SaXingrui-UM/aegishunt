# Phase 10 Release Notes

## Objective and status

Create an analyst-controlled Investigation Case and feedback loop while preserving
hypothesis uncertainty, immutable evidence, evaluation isolation, and explicit model
control. A Case is a review work item, not a confirmed attack.

Status: **Implementation complete — awaiting PR review**.

- Branch: `phase/10-case-feedback`
- Base main: `92bd2f5833778d82e5b815b8c3764478f5e3b1ab`
- Pull request: pending
- Merge commit: pending
- Completion tag: pending; no `phase-10-complete` Tag exists before merge
- Phase 11: Not started

## Completed scope

- Reused and extended existing Case/Feedback schema, ORM, and repositories.
- Deterministic one-hypothesis/one-primary-Case identity and idempotent creation.
- Configured lifecycle transitions, priority mapping, assignment, append-only notes,
  close gate, analyst verdict, injected UTC clocks, and complete audit events.
- Typed immutable hypothesis/group/alert/detection/flow evidence snapshots and SHA-256.
- Transactionally consistent alert verdict/feedback and Case verdict/feedback.
- Bounded feedback query/filter/pagination and explicit correction policy.
- Versioned exact-inventory feedback export and deterministic JSON/Markdown Case report.
- Explicit review-only `retraining_candidate` artifacts with fixed features, conflict
  exclusion, consistent deduplication, and fail-closed frozen-test, evaluation, and
  unknown-provenance gates. Candidate construction does not train or activate a model.
- Additive SQLite schema v3→v4 migration with new note/reference tables.
- Typed Case/Feedback CLI, offline E2E, integration/restart, migration, artifact, and
  security coverage.

## Architecture decisions

ADR 0019 records the stable Case identity, lifecycle/event-time separation, append-only
notes/evidence, feedback trust boundary, alert-verdict consistency, row-level candidate
eligibility, evaluation isolation, exact-inventory artifacts, and no-auto-training
boundary. Phase 11 replay/worker orchestration and Phase 12 complete Cases API/UI are
explicitly absent.

## Tests

- Ruff passed for the complete repository.
- Strict mypy passed for all 185 source files.
- Focused Phase 10 unit, integration, artifact, frontend/status, and offline E2E
  selection passed all 27 tests in 4.93 seconds.
- The final complete pytest suite passed all 388 tests in 1,092.33 seconds; failures,
  skips, and xfails were all zero.
- Branch-aware coverage was 86.01%, above the unchanged 85% project gate.
- Tests use only temporary SQLite databases and controlled local fixtures; no network,
  root, real PCAP, formal experiment evidence, model training, or activation.

## Review outcome

- The implementation review corrected an empty-candidate CLI transaction that could
  leave a valid artifact without its audit commit; empty and below-minimum outcomes
  now return explicit persisted states.
- Native `codex review --base main` was attempted but could not start because the local
  arm64 executable is missing (`ENOENT`). The equivalent read-only branch review found
  one correctness-related Medium audit-contract gap. Commit `c6a10ee` added uniform
  before/after, reason, and source summaries plus regression assertions.
- The post-fix equivalent review found zero Blocking, zero High, and zero unresolved
  correctness-related Medium findings. No Phase 11 scope creep was found.

## Known limitations

- Analyst judgments may be noisy and are not benchmark ground truth.
- Case verdicts are not row-level labels; candidate data requires manual review.
- Strict provenance and conflict gates can legitimately produce an empty candidate set.
- Phase 10 has CLI/services, not the complete Phase 12 API/Streamlit workflow.
- Arbitrary attachments are unsupported; only persisted typed evidence is accepted.
- DEF-004 remains: a completely unavailable database cannot audit into itself.
- Runtime replay, workers, progress/recovery, and resource monitoring remain Phase 11.

## Next phase

Phase 11 — Runtime Pipeline and PCAP Replay, planned branch
`phase/11-runtime-replay`. It is **Not started** and must not begin before Phase 10 PR
review/merge, checkpoint closure, and explicit user authorization.
