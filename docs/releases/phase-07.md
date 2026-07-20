# Phase 07 Release Notes

## Objective and status

Implement auditable supervised/anomaly fusion and compare supervised-only,
anomaly-only, and true dual-engine fusion across known behavior, held-out attack
families, a strict controlled timeline, and preregistered parameter shifts.

Status: **Phase complete**. Development branch:
`phase/07-fusion-evaluation`. PR
[#21](https://github.com/SaXingrui-UM/aegishunt/pull/21), titled
`[Phase 07] Dual-engine fusion and unknown-behavior evaluation`, was
squash-merged from `phase/07-fusion-evaluation` into `main` on 2026-07-20 as
`2465f8de67be7638670f9d30c1198ff76a60d17c`. Annotated checkpoint Tag
`phase-07-complete` is pushed and remotely verified at that commit. Phase 8 has
not started. Post-merge metadata PR
[#22](https://github.com/SaXingrui-UM/aegishunt/pull/22) was merged as
`59e1cd05b36fd3718db10e1cb7f0662b11efc08a`; final visible-status closure PR
[#23](https://github.com/SaXingrui-UM/aegishunt/pull/23) was merged as
`3c2950f7d9c5e3b0ffd385cf2d44cd7c96a03fde`. Required CI passed for all three
Phase 7 PRs, and the final read-only verification confirmed synchronized `main`,
an unchanged completion Tag, truthful README/Streamlit status, and no Phase 8
branch or implementation.

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
- `720cc61` — aligned scoring fixtures with policy provenance.
- `7551625`, `b70cd2d`, `ebda328` — feature contract, status, and initial final verification.
- `bce107b` — hardened statistical and policy evidence integrity after Review.
- Final evidence and checkpoint documentation are retained in the PR history.

## Review outcome

Native `codex review --base main` could not start because the installed arm64
Codex executable was missing (`ENOENT`); it is not reported as successful. An
equivalent read-only Review found three correctness-related Medium issues:
single-class Bootstrap resamples were contributing undefined metrics as zero,
selection/policy cross-field consistency and frozen rows-per-group were not
fully enforced, and policy-internal symlinks were not explicitly rejected.
Commit `bce107b` fixed all three with regression coverage. The second equivalent
Review found zero Blocking, High, or remaining correctness-related Medium
findings. Known synthetic-evidence and external-validity limitations remain
documented rather than hidden.

Post-merge native Review failed with the same missing arm64 executable
(`ENOENT`) and is not claimed as successful. The equivalent read-only review of
the merged change, current evidence contracts, tests, tracked artifacts, and
Phase 8 boundary found zero Blocking, zero High, and zero correctness-related
Medium findings.

## Tests

Final metadata-closure Ruff passes. Strict mypy passes for 134 source files. All
316 tests pass in 1,039.30 seconds with zero failures, skips, or xfails and
87.37% branch-aware coverage; all 3 status-document tests pass. The earlier
focused Phase 7/frontend/status unit, integration, and offline E2E selection
passed all 32 tests. The CLI help and fresh repository-external `fusion
evaluate`, `verify`, and `describe` workflow passed. Required GitHub Actions
checks passed for PRs #21, #22, and #23.

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

Phase 8 — Alerts, Risk Scoring and Explainability. Status: **Not started**.
Planned branch: `phase/08-alert-explainability`. It may begin only after `main`
is synchronized and the user explicitly authorizes the next phase.
