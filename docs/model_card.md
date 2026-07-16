# AegisHunt Supervised Model Card

**PIPELINE VERIFICATION ONLY — controlled synthetic demo metrics are not
research, production, or real-world performance evidence.**

## Model details and intended use

- Model: `aegishunt-supervised-1.0.0`
- Algorithm: HistGradientBoosting, selected from actual validation evidence
- Feature contract: 43 ordered float64 flow features, schema `1.0.0`
- Preprocessing contract: `1.0.0`; no scaling for this tree-based candidate
- Dataset: `aegishunt-controlled-demo` `1.0.0`
- Label mapping: `1.0.0`
- Purpose: offline research verification of known-pattern binary classification

Do not use this model as a sole production control or as proof of zero-day
detection. It does not create alerts or confirm attacks. Its calibrated score is
not the real-world probability that an attack occurred, and model importance
would not establish causality.

## Data and split

The synthetic generator produced 48 rows and 24 whole groups: 28/14 train
rows/groups, 10/5 validation rows/groups, and 10/5 frozen-test rows/groups.
Quality and leakage reports passed with no group, source, capture-session,
scenario, exact-duplicate, or near-duplicate overlap. The public benchmark was
not downloaded or used.

- Dataset manifest SHA-256: `0a92ef8308493fdf95e20469c3917f48412bef4007c9fcb1fd0fb77ff9d4c0f1`
- Split manifest SHA-256: `a2949d3ef88381119616c5c352e39c30c7c98371edc0101614c230e0c7b8a1e0`

Train-only three-fold GroupKFold tuned five required candidates. Validation only
selected sigmoid calibration, threshold `0.5`, and the final candidate. Test was
read once after the immutable selection record was written and did not affect selection.

## Selected configuration

```text
early_stopping=false
l2_regularization=1.0
learning_rate=0.1
max_iter=100
max_leaf_nodes=7
min_samples_leaf=2
calibration=sigmoid
threshold=0.5
```

No resampling or imputation was used. The final estimator was fit on train;
validation fit calibration and selected the threshold. Test entered none of those steps.

## Metrics

| Metric | Validation | Frozen test |
| --- | ---: | ---: |
| Accuracy | 1.0000 | 0.8000 |
| Precision | 1.0000 | 0.7500 |
| Recall | 1.0000 | 1.0000 |
| F1 | 1.0000 | 0.8571 |
| Macro F1 | 1.0000 | 0.7619 |
| Weighted F1 | 1.0000 | 0.7810 |
| Balanced Accuracy | 1.0000 | 0.7500 |
| MCC | 1.0000 | 0.6124 |
| ROC-AUC | 1.0000 | 0.6667 |
| PR-AUC | 1.0000 | 0.8333 |
| Specificity | 1.0000 | 0.5000 |
| FPR | 0.0000 | 0.5000 |
| FNR | 0.0000 | 0.0000 |
| Brier score | 0.1152 | 0.1918 |

Frozen confusion matrix: TN 2, FP 2, FN 0, TP 6. Fixed-seed group-bootstrap
95% intervals are broad because the test has only five groups; Macro F1 is
`[0.2857, 1.0000]`, and PR-AUC is `[0.3333, 1.0000]` across 910 valid AUC draws.
This instability is a limitation, not evidence to revisit the frozen selection.

Train-CV Macro F1 was `0.8317 ± 0.1195`. On the recorded development host, the
selected model measured 0.9262 ms p50 per sample, 9.2620/10.8713/11.3069 ms
p50/p95/p99 for a batch of 10 over 50 repetitions, and a 639,387-byte serialized
preprocessing/model/calibration artifact. These values are not production SLAs.

## Limitations, security, and retraining

The demo is tiny, synthetic, imbalanced, and cannot measure domain shift,
unseen protocols, enterprise traffic, or novel attacks. Validation is reused for
comparison, calibration, and thresholding, so overfitting is possible. The high
test FPR and wide confidence intervals must be reported as observed.

The bundle is loaded only below its configured root after its exact four-file
inventory, model/manifest/model-card SHA-256 values, and exact skops type
inventory are verified; arbitrary pickle/joblib, extra files, corruption, and
schema drift are rejected. The selected model artifact SHA-256 for this checked
run is `adc950ef954b25906107547799397a15760135b6ccffc9bd012b27541a691618`.
The artifact records Python and scikit-learn versions. Retraining needs
an approved new version after feature-schema, label, dependency, or material
distribution changes. The existing DEF-004 database-outage limitation remains
open and non-blocking; Phase 5 adds no alternate broker.
