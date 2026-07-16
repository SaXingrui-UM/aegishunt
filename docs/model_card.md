# AegisHunt Supervised Model Card

**PIPELINE VERIFICATION ONLY — controlled synthetic demo metrics are not
research, production, or real-world performance evidence.**

## Model details and intended use

- Model: `aegishunt-supervised-1.0.1`
- Algorithm: Random Forest, selected from corrected validation evidence
- Feature contract: 43 ordered float64 flow features, schema `1.0.0`
- Preprocessing contract: `1.0.0`; no scaling for this tree-based candidate
- Dataset: `aegishunt-controlled-demo` `1.0.0`
- Label mapping: `1.0.0`
- Purpose: offline research verification of known-pattern binary classification

This model corrects PM-DEF-001. Its immutable metadata supersedes experiment
`phase-05-controlled-demo` / model `1.0.0` without overwriting the original
selection record, frozen-test report, or bundle.

Do not use this model as a sole production control or as proof of zero-day
detection. It does not create alerts or confirm attacks. Its calibrated score is
not the real-world probability that an attack occurred, and model importance
would not establish causality.

## Data and split

The AegisHunt project generated these 48 controlled synthetic rows and 24 whole
groups solely for pipeline verification: 28/14 train
rows/groups, 10/5 validation rows/groups, and 10/5 frozen-test rows/groups.
Quality and leakage reports passed with no group, source, capture-session,
scenario, exact-duplicate, or near-duplicate overlap. The public benchmark was
not downloaded or used. The registry records the license/provenance status as
`Project-internal synthetic research fixture`; no public benchmark or external
dataset license is claimed or implied.

- Dataset manifest SHA-256: `523026c44c0c1d42473a34df3f3504aa8d03066e5082456d986c872856040294`
- Split manifest SHA-256: `a2949d3ef88381119616c5c352e39c30c7c98371edc0101614c230e0c7b8a1e0`
- Canonical dataset SHA-256: `75c584dbee56cf985864fabeb3d01a0975122276a31c2acbb45b0323c4f885ad`

Train-only three-fold GroupKFold tuned five required candidates. Validation only
selected isotonic calibration, threshold `0.5`, and the final candidate. Test was
read once after the immutable selection record was written and did not affect selection.

## Selected configuration

```text
class_weight=none
max_depth=8
max_features=sqrt
min_samples_leaf=1
min_samples_split=2
n_estimators=64
n_jobs=1
calibration=isotonic
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
| ROC-AUC | 1.0000 | 0.9583 |
| PR-AUC | 1.0000 | 0.9524 |
| Specificity | 1.0000 | 0.5000 |
| FPR | 0.0000 | 0.5000 |
| FNR | 0.0000 | 0.0000 |
| Brier score | 0.0000 | 0.1091 |

Frozen confusion matrix: TN 2, FP 2, FN 0, TP 6. Fixed-seed group-bootstrap
95% intervals are broad because the test has only five groups; Macro F1 is
`[0.2857, 1.0000]`, and PR-AUC is `[0.6667, 1.0000]` across 910 valid AUC draws.
This instability is a limitation, not evidence to revisit the frozen selection.

Train-CV Macro F1 was `0.8317 ± 0.1195`. On the recorded development host, the
selected model measured 0.3086 ms p50 per sample, 3.0855/3.3506/3.3909 ms
p50/p95/p99 for a batch of 10 over 50 repetitions, and a 1,606,438-byte serialized
preprocessing/model/calibration artifact. These values are not production SLAs.

Before correction, the affected evidence selected HistGradientBoosting with
sigmoid calibration and reported validation Brier `0.1152`, frozen-test Brier
`0.1918`, ROC-AUC `0.6667`, and PR-AUC `0.8333`. The corrected run changed the
candidate, calibration, rank-sensitive probability metrics, model artifact, and
bundle checksum. Threshold `0.5`, frozen Accuracy `0.8`, Macro F1 `0.7619`, and
TN/FP/FN/TP `2/2/0/6` remained unchanged. Neither run is benchmark evidence.

## Limitations, security, and retraining

The demo is tiny, synthetic, imbalanced, and cannot measure domain shift,
unseen protocols, enterprise traffic, or novel attacks. Validation is reused for
comparison, calibration, and thresholding, so overfitting is possible. The high
test FPR and wide confidence intervals must be reported as observed.

The bundle is loaded only below its configured root after its exact four-file
inventory, model/manifest/model-card SHA-256 values, and exact skops type
inventory are verified; arbitrary pickle/joblib, extra files, corruption, and
schema drift are rejected. The selected model artifact SHA-256 for this corrected
run is `9b403dd20ca77322983a175980081399414219f3cc6a2ceac7acff0bec3d17a5`.
The corrected selection record SHA-256 is
`31c1421eb3d37b6fd5e204a12483243f91d6c20cdba97b28189e0806da599d91`.
The artifact records Python and scikit-learn versions. Retraining needs
an approved new version after feature-schema, label, dependency, or material
distribution changes. The existing DEF-004 database-outage limitation remains
open and non-blocking; Phase 5 adds no alternate broker.
