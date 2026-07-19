# Phase 6 Validation-Only Corrective Protocol 001

## Registration status

This protocol was fixed before executing the corrective candidate matrix. It
must not be expanded after results are observed.

- Experiment: `phase-06-controlled-demo-validation-corrective-001`
- Candidate model version: `1.0.1-candidate`
- Configuration schema: `1.1.0`
- Selection policy: `1.0.1`
- Normalization policy: `1.0.1`
- Research status: validation-only algorithm/configuration corrective research
- Original immutable experiment/model: `phase-06-controlled-demo` / `1.0.0`

The original frozen-test result has already been viewed. It is historical
evidence only and is prohibited from every candidate, normalization, threshold,
or selection decision in this corrective protocol.

## Fixed evidence boundary

- Fit estimator: 10 benign training rows from 5 groups only.
- Excluded from fit: all 18 malicious training rows.
- Fit normalizer: canonical scores from those benign training rows only.
- Candidate and threshold selection: 10 validation rows from 5 groups only.
- Original test: no row, label, score, metric, or aggregate may be read.
- Fixed SYN-burst smoke fixture: run only after selection is frozen; it cannot
  affect ranking, normalization, threshold, or the candidate matrix.
- LOF: benign-fit, validation-only, offline comparator; production eligibility
  remains false.

Dataset identity is `aegishunt-controlled-demo` version `1.0.0`. The registered
dataset-manifest checksum is
`badf8c045c29fa02299eb55f8a1cd7deb15d92aec40c0e80cd6ea4a133d98d0d` and
the split-manifest checksum is
`a2949d3ef88381119616c5c352e39c30c7c98371edc0101614c230e0c7b8a1e0`.
The dataset manifest's audit commit is
`352205f92e81f82a7878f2cb8799c6e6e3b7b002`. Reproducing the registered
fixture must restore that audit field and byte-verify the manifest checksum;
it may not change any processed-file checksum or dataset row.

## Closed Isolation Forest matrix

Every configuration uses `contamination="auto"`, `n_jobs=1`, fixed seed `6106`,
StandardScaler, and external validation thresholding.

| Candidate | Estimators | Samples | Features | Bootstrap |
| --- | ---: | ---: | ---: | --- |
| corrective-iforest-64-full | 64 | 1.0 | 1.0 | false |
| corrective-iforest-128-full | 128 | 1.0 | 1.0 | false |
| corrective-iforest-256-full | 256 | 1.0 | 1.0 | false |
| corrective-iforest-128-sample-80 | 128 | 0.8 | 1.0 | false |
| corrective-iforest-128-feature-75 | 128 | 1.0 | 0.75 | false |
| corrective-iforest-128-feature-50 | 128 | 1.0 | 0.5 | false |
| corrective-iforest-128-sample-80-feature-75 | 128 | 0.8 | 0.75 | false |
| corrective-iforest-128-bootstrap | 128 | 1.0 | 1.0 | true |

No additional estimator configuration or random seed may be added after the
first matrix execution.

## Closed normalization matrix

Each normalizer is deterministic, fitted only on benign-training canonical
scores, higher-is-more-anomalous, bounded to `[0,1]`, explicitly handles ties
and constant references, rejects non-finite values, and is persisted in the
selection evidence.

1. `benign_training_quantile_cdf`: existing linear empirical quantile mapping.
2. `smoothed_empirical_cdf`: unique benign scores mapped to mid-rank empirical
   probabilities, with explicit zero/one tail bounds.
3. `robust_percentile_scaling`: linear scaling between fixed benign q05 and q95,
   clipped to zero/one with explicit constant-reference behavior.

The matrix is exactly 8 estimator configurations × 3 normalizers = 24 candidate
evaluations. Validation labels may evaluate them but never fit a normalizer.

## Fixed thresholds and selection objective

Thresholds are `0.40, 0.50, 0.60, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95`.
The benign FPR ceiling remains `0.25`.

Policy `1.0.1` first removes thresholds that exceed the FPR ceiling. Eligible
thresholds rank by:

1. positive anomaly F1;
2. higher anomaly F1;
3. higher anomaly recall;
4. higher validation PR-AUC;
5. higher balanced accuracy;
6. lower benign FPR;
7. lower group-FPR variation;
8. lower deterministic threshold.

Eligible estimator/normalizer candidates rank by positive F1, F1, recall,
PR-AUC, balanced accuracy, and lower benign FPR. Exact utility ties use lower
configured estimator complexity (`n_estimators`, sample fraction, feature
fraction, bootstrap), followed by stable ascending candidate ID. Runtime
latency and serialized size are reported but cannot influence selection.
Accuracy cannot dominate and the original test cannot enter the key.

If no Isolation Forest configuration has FPR at most `0.25`, Recall above zero,
and F1 above zero, selection fails closed and no passing candidate bundle is
created.

## Candidate and holdout status

A successful result may be described only as `validation-qualified candidate`.
It must independently reload, preserve exact schema and checksum contracts, and
pass the unchanged SYN-burst smoke test after selection freeze.

No untouched independent holdout is assumed. The existing 48 rows are already
assigned to train, validation, or the viewed original test. The corrective run
must report whether an independently sourced, never-viewed group-isolated pool
exists without opening labels or scoring it. Without such a pool, no corrective
candidate can be described as final-tested or production-validated.

This controlled synthetic workflow is pipeline verification only. A normalized
score is not a probability, anomaly is not proof of malicious activity, and the
protocol does not provide evidence of real-world or zero-day performance.
