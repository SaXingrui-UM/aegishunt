# AegisHunt Phase 6 Anomaly Model Card

**CONTROLLED SYNTHETIC PIPELINE VERIFICATION ONLY — not a public benchmark,
production result, real-world performance claim, or proof of zero-day detection.**

## Model details and intended use

- Model ID/version: `aegishunt-anomaly-1.0.0` / `1.0.0`
- Production algorithm/candidate: Isolation Forest / `iforest-64-full`
- Feature schema: Phase 3 `1.0.0`, 43 ordered finite `float64` features
- Preprocessing: StandardScaler fitted on benign training only
- Status: Phase 6 controlled research-prototype verification

The model scores flow-feature deviation from the observed benign training
baseline. `is_anomaly` is a thresholded model judgment, not confirmation of an
attack. The normalized anomaly score is not a probability. Legitimate rare
behavior can score highly, and familiar malicious behavior can score normally.

Do not use this model as a sole production blocking control. Phase 6 does not
create alerts, severity, supervised/anomaly fusion, reason codes, explanations,
correlation, hypotheses, cases, or automated response. Phase 7 owns fusion.

## Data provenance and split

The AegisHunt project generated this controlled synthetic fixture offline for
pipeline verification. It is not an externally licensed or public benchmark.
The complete dataset has 48 rows/24 groups with fixed 28/10/10 rows and 14/5/5
groups for train/validation/test.

- Benign fit evidence: 10 train rows / 5 groups
- Excluded malicious train rows: 18
- Validation evidence: 10 rows / 5 groups (4 benign, 6 malicious)
- Frozen test evidence: 10 rows / 5 groups (4 benign, 6 malicious)
- Dataset manifest SHA-256 for the verified run:
  `badf8c045c29fa02299eb55f8a1cd7deb15d92aec40c0e80cd6ea4a133d98d0d`
- Split manifest SHA-256:
  `a2949d3ef88381119616c5c352e39c30c7c98371edc0101614c230e0c7b8a1e0`
- Training config SHA-256:
  `0caa294c9dd823c8954d0e1cda23c66611fef7c3e0be32f24b9127966e582dd5`

Metadata, labels, attack family, group/source/session/scenario IDs, addresses,
ports, filenames, and local paths never enter the estimator.

## Score and threshold policy

- Raw score: sklearn `score_samples`; larger means more normal
- Canonical score: negative raw score; larger means more anomalous
- Normalizer: benign-training quantile CDF `1.0.0`, clipped to `[0,1]`
- Normalized score meaning: relative deviation only, not probability
- Threshold policy: validation benign-FPR constrained
- FPR ceiling: `0.25`
- Selected threshold: `0.9`

The threshold and candidate were frozen before test access. Neither test labels
nor test scores selected hyperparameters, normalization, threshold, FPR target,
or algorithm.

## Actual controlled validation result

| Metric | Value |
| --- | ---: |
| Accuracy | 0.4 |
| Precision | 0.0 (undefined because no positive prediction; recorded) |
| Recall / anomaly detection rate | 0.0 |
| F1 | 0.0 |
| Macro F1 | 0.2857143 |
| Balanced Accuracy | 0.5 |
| MCC | 0.0 |
| ROC-AUC | 0.5 |
| PR-AUC | 0.6388889 |
| Specificity | 1.0 |
| Benign FPR | 0.0 |
| Anomaly FNR | 1.0 |
| Confusion matrix TN/FP/FN/TP | 4 / 0 / 6 / 0 |

## Actual frozen-test result

| Metric | Value |
| --- | ---: |
| Accuracy | 0.4 |
| Precision | 0.0 (undefined because no positive prediction; recorded) |
| Recall / anomaly detection rate | 0.0 |
| F1 | 0.0 |
| Macro F1 | 0.2857143 |
| Balanced Accuracy | 0.5 |
| MCC | 0.0 |
| ROC-AUC | 0.0833333 |
| PR-AUC | 0.4703704 |
| Specificity | 1.0 |
| Benign FPR | 0.0 |
| Anomaly FNR | 1.0 |
| Confusion matrix TN/FP/FN/TP | 4 / 0 / 6 / 0 |

The poor anomaly recall is retained as evidence of the controlled baseline's
limited generalization. It was not used to retune or replace Isolation Forest.
Fixed-seed group bootstrap used 1,000 draws; AUC intervals had 907 valid draws
when resampling included both classes. The 95% F1 interval was `[0.0, 0.0]`,
ROC-AUC `[0.0, 0.375]`, and PR-AUC approximately `[0.1556, 0.7597]`.

## Comparator and operational evidence

LOF ran in novelty mode as an offline comparator only. Its validation result was
PR-AUC `0.8083333`, recall `0.3333333`, F1 `0.5`, and benign FPR `0.0` at
threshold `0.9`. It did not replace the roadmap-defined Isolation Forest.

One-Class SVM was not implemented due to bounded Phase 6 scope, quadratic
scaling risk, and the limited benign controlled sample. Autoencoder was not
implemented.

On the recorded development run, selected-model training took about `0.0279 s`;
10-row batch latency p50/p95/p99 was approximately
`3.0847/3.4076/3.4627 ms`, per-sample p50 `0.3085 ms`, and throughput
`3201 samples/s`. Serialized preprocessing + estimator size was `1,672,484`
bytes and traced peak scoring memory was `239,312` bytes. These measurements
vary with host load and are not a production SLA.

## Bundle and reproducibility

The verified temporary model payload SHA-256 was
`d6ab14b4a6566c14be394d50c4cb424d2a766f09c468d72ff47a8ee708e37718`.
The model binary and machine experiment reports are ignored and not committed.
Skops bytes are integrity evidence for one artifact, not a reproducible-build
identifier; reproducibility is asserted for selection and numeric scoring under
the recorded code/config/data/dependency environment.

The exact four-file bundle verifies inventory, root containment, SHA-256,
component types, feature schema/order/dtype, normalizer, and threshold. It rejects
pickle/joblib, path escape, missing/extra/corrupt files, and version collisions.
Independent-process reload produced identical raw, canonical, normalized, and
decision output for the same input.

## Limitations and retraining conditions

- The benign sample is very small and lacks operational diversity.
- Current controlled Isolation Forest evidence missed all labeled anomalies.
- Domain/concept drift can create false positives or false negatives.
- Quantile normalization saturates outside the benign-training reference tails.
- Anomaly score is associative evidence, not causality or attack probability.
- Public benchmark acquisition/conversion remains provisional.
- DEF-004 remains non-blocking: an unavailable database cannot persist its own
  failure into that same database.

Retraining requires a new immutable version after approved dataset, split,
feature schema, data distribution, or dependency changes. The frozen test must
not be reused for iterative optimization.
