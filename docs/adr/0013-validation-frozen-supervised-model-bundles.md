# ADR 0013: Validation-Frozen Supervised Model Bundles

- Status: Accepted
- Date: 2026-07-16

## Context

Phase 5 must compare heterogeneous classifiers without leaking frozen-test
evidence into feature handling, tuning, calibration, thresholding, or model
selection. The selected inference path must preserve preprocessing and reject
untrusted serialized Python objects or incompatible feature vectors.

## Decision

Training consumes only the Phase 4 train partition and uses deterministic
`GroupKFold` over its declared groups. Every preprocessing step is inside the
candidate pipeline and is fit inside each training fold. Validation alone
selects probability calibration, the classification threshold, operational
trade-offs, and the main candidate under selection-policy version `1.0.0`.

The service writes an immutable, checksummed `model_selection.json` and a fixed
`selection.skops` artifact before test rows can be loaded. A separate explicit
command performs one frozen-test evaluation. It cannot change the selected
algorithm, hyperparameters, calibration, or threshold, and a second official
evaluation is refused.

Final bundles use a version directory containing exactly `model.skops`,
`manifest.json`, `model_card.md`, and `checksums.json`. The loader accepts only
paths under the configured model root, verifies outer SHA-256 values for every
content file and the exact skops type inventory, permits only required
scikit-learn internal types, and rejects pickle/joblib or extra files. The
manifest binds
feature names/order/schema, float64 dtype, preprocessing version, dataset and
split checksums, label mapping, threshold, software versions, and metrics.

## Alternatives considered

- Select the highest test score: rejected because it contaminates the frozen test.
- Fit preprocessing on all rows before CV: rejected because it leaks fold statistics.
- Use Accuracy alone: rejected because imbalance and operational false positives matter.
- Save estimator-only pickle/joblib files: rejected because preprocessing and integrity are lost.
- Add a database model registry now: rejected because configured immutable files meet Phase 5
  requirements without a premature schema migration.
- Refit estimator on train plus validation: deferred; validation is retained for calibration and
  threshold evidence under the current protocol.

## Consequences

Research boundaries are machine-enforced and independently testable. The same
pipeline is used for training-time validation and inference. Artifact creation
is non-overwriting, so failed or partial experiments require an explicit new
version rather than silent replacement. A small controlled demo can validate
the machinery but cannot establish a research or production model conclusion.

## Risks

Validation is small and serves model comparison, calibration, and thresholding,
so estimates can be unstable. Skops compatibility still depends on recorded
Python/scikit-learn versions. A write failure after a multi-file experiment
starts may leave a deliberately unusable partial directory. Public benchmark
acquisition and conversion remain provisional, and DEF-004 remains unchanged.

## Corrective evidence amendment

PM-DEF-001 showed that truthiness-based optional-number fallbacks can corrupt a
legitimate Brier score of `0.0`. Selection policy `1.0.1` retains the documented
ordering while using explicit missing-value handling and finite-value validation.
Defect-authorized corrective runs use configuration schema `1.1.0`, a new
experiment ID, and a new model version. Their immutable selection and bundle
metadata record the defect ID, superseded experiment/model, reason, and exact Git
commit. Existing frozen evidence remains unchanged, and the normal one-evaluation
guard continues to apply independently to the new corrective experiment.
