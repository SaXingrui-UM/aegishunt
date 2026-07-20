# Phase 08 Release Notes

## Objective and status

Convert verified supervised, anomaly, and fusion outputs into persisted,
analyst-reviewable detection evidence, configured operational risk/severity,
threshold-gated alerts, non-causal explanations, and an audited alert verdict.

Status: **Implementation complete — awaiting PR review**. Development branch:
`phase/08-alert-explainability`. Pull request, merge commit, and completion Tag
are pending. Phase 9 has not started.

## Completed scope

- Reused and extended existing `DetectionResult` and `SecurityAlert` schemas,
  ORM records, repositories, and foreign-key relationships.
- Added complete finite supervised/anomaly/fusion scores, thresholds, model and
  policy versions/checksums, feature schema, configured risk source, severity,
  reasons, explanation, and timestamps.
- Added the versioned `aegishunt-risk-controlled` policy with identity mapping
  from Phase 7 fusion score, explicit alternative sources, no fallback, an
  inclusive alert boundary, and complete monotonic severity bands.
- Created every completed score as a detection and created an alert only when
  risk meets the configured threshold.
- Added deterministic cautious alert types/templates, non-empty evidence and
  reasons, flow-derived involved entities, and no ground-truth trigger.
- Added benign train-only q05–q95 reference profiles, supported native tree
  importance, fixed-validation permutation importance, bounded local median-
  replacement sensitivity, and versioned reason evidence.
- Added an exact seven-file checksummed JSON/Markdown explanation artifact with
  path, inventory, corruption, identity, and version-collision protection.
- Added mutable nullable analyst verdict with immutable alert evidence and an
  actor-attributed audit event; no retraining or downstream workflow is invoked.
- Added schema version 2 and a repeatable additive v1→v2 SQLite migration that
  preserves existing rows and rejects unknown versions.
- Added `detection`, `alerts`, and `explainability` CLI command groups, unit,
  migration, integration, restart-persistence, offline E2E, and regression tests.
- Updated architecture, data model, ADR 0017, README, status shell, protocol
  documentation, progress, and release notes.

## Architecture decisions

ADR 0017 records the explicit single-score risk mapping, Phase 7 inconclusive
recommendation, inclusive severity/alert boundaries, non-causal explanation
methods, data-only artifact, transactional persistence, duplicate rejection,
and verdict-only mutation boundary.

## Test and Review status

The synchronized Phase 7 baseline passed Ruff, strict mypy for 134 source files,
and 316 tests with zero failures/skips/xfails and 87.37% branch-aware coverage.
After Phase 8 implementation, Ruff passed, strict mypy passed for 152 source
files, and all 334 tests passed in 1,088.56 seconds with zero failures, skips, or
xfails and 86.63% branch-aware coverage. The focused Phase 8 risk/explanation,
migration, CLI, persistence/restart/verdict, artifact-integrity, and offline E2E
selection passed all 21 tests. Review and GitHub Actions status remain pending;
no unexecuted check is claimed as passed here.

Native `codex review --base main` could not start because the installed arm64
executable is missing (`ENOENT`). Equivalent review found an explanation-
artifact identity binding gap, root-symlink acceptance, and incomplete self-
contained alert evidence. The implementation now fails closed on model/policy
identity mismatch, rejects a symlinked artifact root, and records the required
flow, scoring, severity, identity, reason, contribution, fact/inference, and
generation-time evidence in each alert. Regressions and the complete suite pass;
the final equivalent review found zero Blocking, zero High, and zero unhandled
Medium findings. GitHub Actions remains pending.

## Generated artifacts

Tests generate explanation artifacts and SQLite databases only below isolated
temporary roots. They are not committed. No trained model binary, dataset,
runtime database, upload, PCAP, secret, or full experiment evidence is added.

## Known limitations

- Controlled synthetic evidence is pipeline verification only, not a public
  benchmark, production validation, or real-world performance evidence.
- Phase 7 did not establish fusion superiority; its recommendation remains
  inconclusive. Risk mapping from fusion score is an operational policy choice.
- Phase 6 LOF remains validation-qualified without an untouched independent
  holdout.
- Benign reference ranges may not generalize; local feature replacement ignores
  interactions and is not additive or causal.
- Historical schema-v1 detection/alert rows are preserved but are not assigned
  fabricated Phase 8 model/policy identities.
- DEF-004 remains the non-blocking limitation that a completely unavailable
  database cannot record its own failure in that same database.
- Full alert API/frontend, correlation, hypotheses, cases, feedback export,
  replay orchestration, and later model lifecycle work remain Phase 9–14 scope.

## Next phase

Phase 9 — Hypothesis Engine. Status: **Not started**. Planned branch:
`phase/09-hypothesis-engine`. Do not create it before Phase 8 is merged,
checkpointed under explicit instruction, and the user authorizes Phase 9.
