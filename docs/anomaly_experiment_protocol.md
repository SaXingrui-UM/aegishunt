# Phase 6 Anomaly Experiment Protocol

## Purpose and scope

This protocol defines the auditable Phase 6 workflow for learning a benign
flow-feature baseline and scoring deviation from it. It implements Isolation
Forest, an offline novelty-mode LOF comparison, deterministic normalization,
validation-only threshold selection, one frozen evaluation, and a safe bundle.
It does not implement Phase 7 fusion, alerts, reason codes, explanations,
correlation, hypotheses, or cases.

## Evidence partitions

| Evidence | Permitted use | Forbidden use |
| --- | --- | --- |
| Train benign rows | Fit StandardScaler, Isolation Forest, LOF, and score normalizer | No malicious rows may enter fit |
| Train malicious rows | Counted as excluded audit evidence only | Fit, normalization, candidate or threshold selection |
| Validation rows | Candidate comparison, score checks, threshold selection, FPR/recall/latency evidence | Estimator/preprocessing/normalizer fit |
| Frozen test rows | One final evaluation after immutable selection | Any tuning, normalization, threshold/FPR/algorithm choice |

The Phase 4 manifests, checksums, quality/leakage reports, fixed 43-feature order,
label mapping, frozen-test flag, group inventories, and source/session/scenario
isolation must validate before any fit. Metadata and labels never enter the
feature matrix.

## Controlled-demo evidence boundary

The repository has no downloaded public benchmark. The executable fixture is
AegisHunt-generated controlled synthetic data: 48 rows/24 groups, split into
28/10/10 train/validation/test rows and 14/5/5 groups. Phase 6 extracts 10 benign
training rows from 5 groups and excludes 18 malicious training rows. Validation
and test each retain 4 benign and 6 malicious rows. Results are **controlled
synthetic pipeline verification only**, not public-benchmark, research,
production, real-world, or zero-day performance evidence.

## Model and score contract

1. Each configured Isolation Forest candidate is constructed with a fixed seed,
   bounded estimators/samples/features, `n_jobs=1`, and `contamination="auto"`.
   Contamination does not set the external Phase 6 decision threshold.
2. StandardScaler and the estimator fit only the benign training matrix.
3. Sklearn `score_samples` is the raw auditable score; higher is more normal.
4. Canonical anomaly score is `-raw_score`; higher is more anomalous.
5. The benign-training quantile CDF maps canonical scores to `[0,1]` with tail
   clipping and explicit constant-score behavior. The normalized score is not a
   probability.
6. LOF uses StandardScaler and `novelty=True`, fits the same benign training
   rows, and scores unseen validation rows. It remains offline-only.
7. One-Class SVM is not implemented because the controlled benign sample is
   small and the bounded Phase 6 scope avoids quadratic scaling risk. No
   Autoencoder is implemented.

## Candidate and threshold selection

All candidates come from `configs/models/anomaly.yaml`. Validation selection is
deterministic and never receives test metrics. The production algorithm remains
Isolation Forest even when LOF comparison metrics are higher.

Threshold candidates operate on normalized validation scores. Eligible
thresholds must satisfy the configured validation benign-FPR limit (`0.25` for
the controlled run). Tie-break order is anomaly F1, recall, PR-AUC, balanced
accuracy, lower FPR, lower group-FPR variation, then the stable threshold order.
Candidate ordering additionally considers PR-AUC, F1/recall, group stability,
p95 latency, serialized size, and stable candidate ID.

## Metrics and operational evidence

Anomaly/malicious is positive. Reports include Accuracy, precision, recall, F1,
Macro/Weighted F1, Balanced Accuracy, MCC, ROC-AUC and PR-AUC when defined,
specificity, benign FPR, anomaly FNR, confusion matrix, support, unavailable
metrics, raw/normalized class distributions, threshold sensitivity, and group
stability. The frozen report uses at least 1,000 fixed-seed group-bootstrap draws.

Operational evidence uses a warmed validation batch and repeated scoring in one
process. It records training duration, p50/p95/p99 batch latency, per-sample p50,
throughput, serialized estimator size, traced peak scoring memory, and score
determinism. These values are development-host observations, not an SLA.

## Freeze and bundle protocol

`aegishunt anomaly train` writes training configuration, benign manifest, every
candidate, validation metrics, normalizer, threshold curves, comparator evidence,
score distributions, latency evidence, `selection.skops`, and an immutable
selection record with `test_data_accessed: false`. The separate
`anomaly_model_selection.sha256` companion is verified before frozen-test access;
selection threshold/normalizer tampering fails closed.

`aegishunt anomaly test` is a separate explicit command. It verifies the
selection/config/dataset/split checksums, opens frozen test once, writes final
metrics/confidence intervals, and creates a four-file model bundle. A repeated
test or existing model version is rejected before new frozen evidence is written.
The bundle contains exactly:

- `model.skops`
- `manifest.json`
- `checksums.json`
- `model_card.md`

Loading verifies configured-root containment, exact file inventory, outer and
inner checksums, an empty skops untrusted-type inventory, StandardScaler plus
IsolationForest component types, feature schema/order/dtype, score direction,
normalizer, and threshold. Pickle/joblib, missing/extra/corrupt files, path
escape, and version collision fail closed.

## Reproduction commands

After building an approved Phase 4 dataset under configured roots:

```bash
aegishunt anomaly train \
  --data-dir <processed-dataset-dir> \
  --dataset-report-dir <dataset-report-dir> \
  --allow-controlled-demo

aegishunt anomaly test \
  --data-dir <processed-dataset-dir> \
  --dataset-report-dir <dataset-report-dir> \
  --allow-controlled-demo

aegishunt anomaly verify 1.0.0
```

The train command generates real `score_distribution.csv` and
`threshold_sensitivity.csv` evidence under the ignored experiment report root.
Optional plots are not generated because the project has no plotting dependency;
the two CSV files are the executable, source-backed plot inputs and no plot is
claimed in Phase 6.
