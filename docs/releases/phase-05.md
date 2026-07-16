# Phase 05 Release Notes

## Objective and status

Implement the supervised detection research engine with strict Phase 4 evidence
gates, group-aware training, validation-only selection, a one-time frozen test,
secure versioned bundles, and deterministic prediction interfaces.

Status: **Implementation complete — awaiting PR review**. Phase 5 is not Phase
complete until its PR is merged and the user later authorizes a checkpoint tag.
Phase 6 has not started.

## Completed scope

- Exact Phase 4 dataset/split/checksum/schema/label/quality/leakage/frozen-test gate.
- Fixed feature/metadata separation and finite float64 matrices.
- Dummy, Logistic Regression, Decision Tree, Random Forest, and
  HistGradientBoosting pipelines from finite configured search spaces.
- Train-only deterministic group CV with fold identity/class evidence and no fallback.
- Sigmoid/isotonic validation calibration and validation threshold curves.
- Full classification, fold stability, Brier, latency, throughput, size, memory,
  and deterministic-prediction metrics.
- Versioned validation-only selection policy that excludes Accuracy and test results as keys.
- Immutable pre-test selection record and explicit one-time frozen-test gate.
- Fixed-seed 1,000-draw group-bootstrap confidence intervals.
- Checksummed skops bundle containing preprocessing, estimator, calibrator,
  threshold, schema, provenance, metrics, environment, and model card.
- Strict batch prediction plus Typer train/test/list/describe/predict/verify commands.
- Machine JSON/CSV artifacts and committed protocol, ADR, and controlled model card.

## Architecture decisions

ADR 0013 records the train/validation/test boundary and safe bundle design. The
final estimator remains train-only; validation fits calibration and chooses the
threshold. This avoids an ambiguous train-plus-validation refit. Configured files
serve as the Phase 5 model registry, avoiding a premature database migration.

## Controlled verification result

The public benchmark remains unavailable/provisional. The actual run therefore
uses `aegishunt-controlled-demo` `1.0.0` and is **pipeline verification only**.
It selected HistGradientBoosting from validation results, with sigmoid
calibration and threshold 0.5. Validation Macro F1 was 1.0; frozen-test Macro F1
was 0.7619 with TN/FP/FN/TP = 2/2/0/6. These are not research conclusions.
See `docs/model_card.md` for the complete metrics, operational evidence, and limits.

## Tests

- Ruff: pass.
- Strict mypy: pass across 95 source files.
- Pytest: 194 passed, 0 failed, 0 skipped, 0 xfailed.
- Branch-aware coverage: 86.97% (required minimum 85%).
- Unit, integration, offline E2E, group isolation, five-model comparison,
  selection/test separation, bootstrap determinism, independent-process reload,
  checksum corruption, arbitrary pickle, path containment, schema rejection,
  duplicate test, and Phase 0–4 regressions pass.

## Generated artifacts

The actual temporary run generated all required training/CV/tuning/validation/
calibration/threshold/comparison/latency/selection/frozen-test/classification
reports, `selection.skops`, the final bundle, manifest, and model card under
`/tmp`. Machine reports and model binaries are ignored and not committed. Only
the reviewed human protocol, ADR, release notes, and model card are committed.

## Known limitations

- Public benchmark acquisition/conversion remains provisional, so no research
  main-model or real-world performance claim is made.
- Five validation and five test groups yield unstable calibration/threshold and
  wide confidence intervals; the observed frozen-test FPR is 0.5.
- In-memory Phase 4 loading and finite grid search have not been benchmarked on a full corpus.
- Skops loading is integrity/type/version checked but still depends on compatible
  recorded Python/scikit-learn versions.
- Multi-file experiment writes are exclusive but not a transactional filesystem;
  a partial directory fails closed and requires an explicit new version.
- DEF-004 remains open and non-blocking: a total database outage cannot write to itself.
- Anomaly detection, fusion, alerts, explanations, correlation, hypotheses, and
  cases remain Phase 6+ and are absent.

## Version-control checkpoint

- Branch: `phase/05-supervised-detection`
- Baseline main: `ab73ffd7cdb3c749cc3b4ee4ed93ab4d30c44160`
- Pull request: pending
- Merge commit: pending
- Tag: pending; `phase-05-complete` must not be created before merge

## Next phase

Phase 6 — Anomaly Detection is not started. Its planned branch is
`phase/06-anomaly-detection`; it must not start before user review and merge of
the Phase 5 PR.
