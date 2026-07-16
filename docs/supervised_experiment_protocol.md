# Supervised Experiment Protocol

## Purpose and boundary

This protocol defines Phase 5 binary known-pattern classification. It does not
implement anomaly detection, signal fusion, alerts, severity, MITRE mapping, or
threat hypotheses. The current checked experiment uses the synthetic controlled
demo solely for pipeline verification; its metrics are not academic benchmark
or deployment evidence.

## Evidence gate

Before fitting, the loader verifies all Phase 4 data and report files, exact
partition/checksum inventories, dataset/split identity, quality and leakage pass
states, supported conversion, frozen-test state, schema and label versions,
group sets, fixed feature order, finite float64 values, binary labels, and
group/source/session/scenario isolation. Metadata and labels never enter the
feature matrix.

## Data use

| Partition | Permitted use | Prohibited use |
| --- | --- | --- |
| Train | Estimator/preprocessing fit, class weight, group CV, hyperparameter search | Validation/test substitution |
| Validation | Candidate comparison, calibration, threshold, operational trade-offs, selection | Estimator/preprocessing fit, frozen-test claims |
| Test | One final evaluation after immutable selection | Any tuning, calibration, threshold, feature, or model choice |

The final estimator is fit on train only. Sigmoid or sufficiently supported
isotonic calibration is fit on validation only. The classification threshold is
selected from the configured validation curve. Test never enters these steps.

## Candidates and preprocessing

- DummyClassifier (`most_frequent`, `prior`) establishes no-information baselines.
- Logistic Regression uses `StandardScaler` inside its sklearn pipeline.
- Decision Tree, Random Forest, and HistGradientBoosting use no unjustified scaling.
- Candidate class weights are configured; no resampling or imputation is performed.
- All finite search grids, folds, seeds, calibration methods, thresholds, latency
  repetitions, and bootstrap iterations come from `configs/models/supervised.yaml`.

Train-only deterministic GroupKFold refuses insufficient groups, overlap, or a
single-class fold. All candidate/fold results and failures are retained. The
primary search metric is Macro F1, followed by PR-AUC, recall, FPR, and a stable
parameter tie-break.

## Validation selection policy

Policy `1.0.0` ranks candidates by validation Macro F1, PR-AUC, recall, lower
FPR, lower Brier score, lower CV Macro-F1 variance, lower latency, smaller size,
then stable algorithm name. Accuracy is reported but is not a selection key.
Calibration is selected by validation Brier score. Thresholds maximize
validation Macro F1, then recall, lower FPR, proximity to 0.5, and stable value.

Corrective policy `1.0.1` preserves this order but fixes PM-DEF-001: optional
numeric metrics use explicit `None` handling, valid zero values remain zero, and
non-finite values are rejected. Missing lower-is-better evidence ranks after every
finite value. A defect-authorized corrective run must use a new experiment ID and
model version and record its defect, superseded experiment/model, reason, and Git
commit. It cannot overwrite the original selection, frozen-test report, or bundle.

`model_selection.json` freezes the algorithm, hyperparameters, pipeline,
calibration, threshold, schema, dataset/split/config checksums, seed, validation
evidence, and selected artifact hash before `test.jsonl` is loaded.

## Evaluation and uncertainty

Fold, validation, and frozen-test reports include Accuracy, Precision, Recall,
F1, Macro/Weighted F1, Balanced Accuracy, MCC, ROC-AUC and PR-AUC when available,
Specificity, FPR, FNR, confusion matrix, class metrics, support, and Brier score.
Unavailable AUCs are explicit. Zero divisions use finite documented values.

Frozen-test 95% confidence intervals use 1,000 fixed-seed whole-group bootstrap
draws. Draws lacking both classes remain usable for defined metrics but are not
used for unavailable ROC/PR AUC, so successful AUC iteration counts are recorded.

## Operational measurement

Each fitted validation candidate receives one warm-up and 50 timed batch
predictions on identical validation input. Reports include p50/p95/p99 batch
latency, per-sample p50, throughput, training duration, complete serialized
pipeline size, traced peak inference memory, and repeated-prediction determinism.
These development-host measurements are not production SLAs.

## Bundle and inference

The final versioned bundle contains the fitted preprocessing/estimator,
validation calibrator, threshold, strict manifest, model card, and outer checksum
inventory. Exact bundle-file inventory, SHA-256 for the model/manifest/model
card, configured-root containment, exact skops type inventory, version-directory
identity, and schema checks run before loading. Arbitrary pickle/joblib input is
never accepted.

Prediction requires a non-empty finite float64 matrix plus the exact feature
schema version, names, and order. It returns only label, raw classifier score,
calibrated probability, selected threshold, model identity/schema, and timestamp.
The probability is distribution-dependent and is not a real-world attack probability.

## Reproduction

```bash
aegishunt dataset build-demo --data-dir <data> --report-dir <dataset-reports>
aegishunt model train --data-dir <data> --dataset-report-dir <dataset-reports> \
  --allow-controlled-demo --config <config>
aegishunt model test --data-dir <data> --dataset-report-dir <dataset-reports> \
  --allow-controlled-demo --config <config>
aegishunt model verify <model-version> --config <config>
```

The `--allow-controlled-demo` gate is mandatory for synthetic pipeline metrics.
Commands are offline, require no root, do not redownload or resplit data, and do
not overwrite an experiment or model version.

The controlled demo is generated by AegisHunt solely for pipeline verification.
Its registry status is `Project-internal synthetic research fixture`; no public
benchmark or external dataset license is claimed or implied.
