# Phase 07 Release Notes

## Objective and status

Implement auditable supervised/anomaly fusion and compare supervised-only,
anomaly-only, and true dual-engine fusion across known behavior, held-out attack
families, a strict controlled timeline, and preregistered parameter shifts.

Status: **Implementation complete — awaiting PR review**. Development branch:
`phase/07-fusion-evaluation`. Pull request, merge commit, and completion Tag are
pending. Phase 8 has not started.

All reported evidence is controlled synthetic pipeline verification only, not a
public benchmark, deployment result, or real-world performance claim.

## Completed scope

- Added strict bounded score, weight, candidate, selection, comparison,
  confidence-interval, policy, checksum, and scoring contracts.
- Implemented the configured fusion formula and explicit supervised-only and
  anomaly-only baseline modes with no silent fallback.
- Added validation-only weight/threshold selection under an FPR ceiling,
  deterministic tie-breaks, positive attack utility, and three truthful
  recommendation states.
- Generated a Phase 7-only controlled dataset with new identities, five attack
  families, 72 groups, strict early/middle/late ordering, quality evidence, and
  no reuse of historical frozen tests.
- Refit the fixed Phase 5 Random Forest/isotonic and Phase 6 novelty-mode LOF
  configurations within each isolated research split without overwriting active
  bundles or registering temporary models.
- Added known, five-fold LOAO, temporal, and four fixed parameter-shift
  experiments with score distributions, per-partition isolation evidence,
  baseline deltas, family-macro summaries, and actual base/shift ranges.
- Added deterministic 1,000-draw whole-group metric and paired-delta bootstrap
  intervals plus measured latency, throughput, temporary component sizes, and
  policy size.
- Added exclusive experiment evidence, a three-file JSON/Markdown policy with
  exact inventory and SHA-256 verification, independent load/score, and
  missing/extra/corrupt/path/version rejection.
- Added `aegishunt fusion evaluate|verify|describe|score` and an offline E2E.
- Updated architecture, protocol, policy card, README, progress, release notes,
  ADR 0016, and the truthful Streamlit phase shell.
- Did not add detection persistence, alerts, risk/severity, reason codes,
  explanations, correlation, hypotheses, cases, replay, or automated response.

## Architecture decisions

ADR 0016 records the Phase 7-specific controlled dataset, validation-only
selection boundary, experimental refits, explicit baselines, positive dual
weights, group bootstrap, JSON-only policy, recommendation states, and Phase 8
boundary. The Phase 5/6 consumed tests and bundles remain immutable.

## Controlled evidence

- Dataset: `aegishunt-phase-07-controlled` `1.0.0`.
- Dataset checksum:
  `4d3319d0a66ff204c9b9cd3720caf83fe66d9bb17d32140edda898f33e2acb40`.
- Rows/groups: `144/72`; early, middle, late each `48/24`.
- Families: benign plus brute force, command-and-control, denial-of-service,
  exfiltration, and reconnaissance.
- Exact, feature, conflicting-label, and near-duplicate counts: all `0`.
- Group/source/session/scenario overlap: none.
- Historical Phase 5/6 frozen test reused: no.
- Selected candidate: `supervised-75-anomaly-25-t0.700`.
- Policy: `aegishunt-fusion-controlled` `1.0.0`; FPR ceiling `0.25`.
- Recommendation: `inconclusive`; validation did not establish an advantage.

Known late-group fusion matched supervised-only at Recall/F1/Macro F1/PR-AUC
`1.0` and FPR `0.0`; anomaly-only Recall was `0.9333`, Macro F1 `0.8125`,
PR-AUC `0.8103`, and FPR `0.3333`. Fusion-minus-supervised primary deltas and
their 1,000-draw group-bootstrap intervals were exactly zero in this controlled
sample.

LOAO family-macro recall was supervised `0.6000`, anomaly `0.9333`, fusion
`0.3333`; mean FPR was `0.0000`, `0.3333`, `0.0000`. Fusion missed all held-out
exfiltration and reconnaissance rows. Negative evidence is retained and no new
grid points were added. The temporal controlled result matched known behavior;
four bounded shifts produced fusion Recall `1.0`/FPR `0.0`, without a real-world
robustness claim.

One development-host latency run measured total batch p50/p95/p99
`1.8157/2.1595/2.3857 ms`, fusion arithmetic p50 `0.0381 ms`, and throughput
`25,834.5 samples/s`. The temporary policy size was `3,621 bytes`. These values
are executed development evidence, not an SLA.

## Commits

- `8edf315` — configurable fusion contracts.
- `04629a6` — isolated research dataset and fixed engine refits.
- `c911aae` — controlled evaluation, artifacts, CLI, and E2E.
- `f75291d` — clarified validation-selection and quality audit fields.
- `cd4c29e` — enriched experiment isolation, distribution, shift, and aggregate evidence.
- `af2d712` — hardened positive-utility selection and policy provenance.
- Documentation/test commits: pending final commit list.

## Tests

Final Ruff passes. Strict mypy passes for 134 source files. All 316 tests pass in
1,147.27 seconds with zero failures, skips, or xfails and 87.37% branch-aware
coverage. The focused Phase 7/frontend/status unit, integration, and offline E2E
selection passes all 32 tests in 26.34 seconds.

## Generated artifacts

The final manual run generated 18 experiment JSON/CSV/Markdown files and one
three-file policy directory under a repository-external temporary root. It also
generated temporary fitted estimators only for measurement. All machine evidence
is ignored/not committed; reviewed configuration, contracts, protocols, result
summary, ADR, and tests are committed. No model binary, database, PCAP, upload,
secret, or large dataset is added.

## Known limitations

- Evidence is a small controlled synthetic pipeline experiment, not a public
  benchmark or independent real-world dataset.
- The LOF configuration remains validation-qualified; this phase does not claim
  final production validation.
- Family-specific experimental refits can use different validation-selected
  thresholds; the LOAO aggregate describes a procedure, not one deployed binary.
- The temporal experiment is a controlled timestamp simulation and parameter
  shifts operate on bounded feature-space clones.
- Confidence intervals reflect only 24 or 12 evaluation groups and can be wide
  or degenerate; class-conditional metrics exclude resamples lacking the
  required class and record the actual successful-draw count.
- DEF-004 remains an existing non-blocking database-outage audit limitation.
- Detection results, alerts, explanations, correlation, hypotheses, cases, and
  runtime replay remain Phase 8–12 work.

## Next phase

Phase 8 — Alert Generation and Explainability. Planned branch:
`phase/08-alert-explainability`. It must not begin before this Phase 7 PR is
reviewed and merged, `main` is synchronized, the user authorizes the next phase,
and an annotated `phase-07-complete` checkpoint is created under the project
policy.
