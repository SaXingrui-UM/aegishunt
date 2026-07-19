# Phase 6 LOF Production-Candidate Protocol 001

## Registration status

This protocol implements the user-authorized direction B and was fixed before
executing the LOF production-candidate workflow.

- Experiment: `phase-06-controlled-demo-lof-production-candidate-001`
- Candidate model version: `1.1.0-candidate`
- Configuration schema: `2.0.0`
- Selection policy: `2.0.0`
- Normalization policy: `1.0.1`
- Decision record: ADR 0015
- Candidate algorithms: registered Isolation Forest matrix and novelty-mode LOF
- Original immutable experiment/model: `phase-06-controlled-demo` / `1.0.0`
- Prior corrective experiment: `phase-06-controlled-demo-validation-corrective-001`
  / `1.0.1-candidate`

The LOF validation evidence and the corrective Isolation Forest smoke failure
were known before direction B was authorized. This is a post-hoc algorithm
eligibility decision and an auditable candidate-packaging exercise, not a new
blind comparison or independent performance evaluation.

## Fixed evidence boundary

- Estimator fit: 10 benign training rows from 5 groups only.
- Excluded from fit: all 18 malicious training rows.
- Normalizer fit: canonical scores from those benign training rows only.
- Threshold and algorithm eligibility: 10 validation rows from 5 groups only.
- Original test: no row, label, score, metric, or aggregate may be read.
- Fixed SYN-burst smoke fixture: runs only after selection is frozen and cannot
  affect candidate ranking, normalization, or threshold selection.
- No untouched independent holdout is available in the registered dataset.

Dataset identity is `aegishunt-controlled-demo` version `1.0.0`. The registered
dataset-manifest checksum is
`badf8c045c29fa02299eb55f8a1cd7deb15d92aec40c0e80cd6ea4a133d98d0d` and
the split-manifest checksum is
`a2949d3ef88381119616c5c352e39c30c7c98371edc0101614c230e0c7b8a1e0`.

## Fixed LOF candidate

LOF is fixed to:

- `n_neighbors=5`
- `metric=minkowski`
- `algorithm=auto`
- `leaf_size=30`
- `n_jobs=1`
- `novelty=True`
- `StandardScaler`
- canonical score `-score_samples`
- `benign_training_quantile_cdf` normalization fitted on benign training only

No LOF hyperparameter search is authorized. `fit_predict` is prohibited.

## Deterministic eligibility and ranking

Policy `2.0.0` requires a validation threshold that satisfies benign FPR at
most `0.25`, positive anomaly recall, and positive anomaly F1. Eligible
candidates rank by:

1. validation anomaly F1;
2. validation anomaly recall;
3. validation PR-AUC;
4. validation balanced accuracy;
5. lower validation benign FPR;
6. stable ascending algorithm/candidate identity.

Latency and serialized size are reported but do not affect ranking. Test data
cannot enter the key. The selection result is frozen before the smoke fixture
is evaluated.

## Bundle gate and claims

The selected candidate must classify the unchanged registered SYN-burst sample
as anomalous, then produce the identical result after an integrity-checked
independent bundle reload. A failure produces evidence but no bundle.

A passing artifact is only a `validation-qualified candidate`. It is not
final-tested or production-validated. It requires a new independently sourced,
never-viewed, group-isolated holdout before any final evaluation.

This controlled synthetic workflow is pipeline verification only. A normalized
anomaly score is not a probability, anomaly is not proof of malicious activity,
and these results are not a public benchmark or evidence of real-world or
zero-day performance.
