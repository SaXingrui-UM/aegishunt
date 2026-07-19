# Phase 7 Fusion Experiment Protocol

## Purpose and claim boundary

This protocol compares supervised-only, anomaly-only, and true dual-engine
fusion under a new, controlled, group-isolated Phase 7 experiment. It asks
whether fusion improves known behavior, held-out-family detection, temporal
robustness, or bounded parameter-shift robustness. It does not assume the answer
is positive.

All executable evidence is **controlled synthetic pipeline verification only**.
It is not a public benchmark, production evaluation, real-world performance
claim, independent zero-day proof, or retroactive validation of Phase 5/6. A
fusion score is experimental suspiciousness, not probability, risk, severity,
or attack confirmation.

## Preregistration

Configuration `configs/models/fusion.yaml` is schema `1.0.0`. Protocol identity
`phase-07-controlled-fusion-001` was frozen in commit `8edf315` at
`2026-07-19T22:31:34Z`, before the first candidate run. The executable config
fixes:

- dataset `aegishunt-phase-07-controlled` version `1.0.0`;
- feature schema `1.0.0` and the unchanged 43-value feature order;
- data/model/bootstrap seeds `7207`, `7307`, and `7407`;
- 1,000 group-bootstrap draws;
- supervised Random Forest parameters, isotonic calibration, and threshold grid;
- novelty-mode LOF, StandardScaler, benign-training quantile CDF, and threshold grid;
- weight candidates `0.25/0.75`, `0.50/0.50`, and `0.75/0.25`;
- fusion thresholds `0.20` through `0.80` in steps of `0.10`;
- validation benign-FPR ceiling `0.25`;
- Macro-F1-under-FPR selection and deterministic tie-break order;
- four bounded parameter shifts and 25 latency repetitions;
- no historical test access and mandatory negative-result retention.

No weight, threshold, family, time boundary, shift magnitude, FPR limit, metric,
or seed is added after observing the result. A protocol change requires a new
identity and version and cannot overwrite this evidence.

## Engine boundary

The supervised research engine refits the fixed Phase 5 corrective Random
Forest configuration (`1.0.1`) on experiment training groups, then fits isotonic
calibration and selects its threshold on experiment validation groups. The
historical Phase 5 binary is neither required nor overwritten.

The anomaly research engine refits the fixed Phase 6 validation-qualified LOF
configuration (`1.1.0-candidate`, `novelty=True`) and StandardScaler on benign
training rows only. Its normalizer is fitted to benign-training canonical scores
and its threshold is selected on validation only. This does not convert the LOF
candidate into public-benchmark or production-validated evidence.

Operational adapters separately accept only aligned, verified prediction
records with exact supervised/anomaly model IDs, versions, and feature schema.
Missing, non-finite, out-of-range, or mismatched scores fail closed; there is no
single-engine fallback called fusion.

## Dataset and isolation

The safe existing flow generator creates 144 rows in 72 two-row groups across
benign, brute-force, command-and-control, denial-of-service, exfiltration, and
reconnaissance patterns. Each timeline stage has 48 rows and 24 groups. New
source files, checksums, capture sessions, scenarios, group IDs, record IDs, and
timestamps are generated for Phase 7.

The manifest checks schema, finite features, missing values, exact and feature
duplicates, conflicting-label fingerprints, near duplicates, and class/family
distribution. Early, middle, and late stages have no group, source, session, or
scenario overlap. Their timestamps are strictly ordered. Metadata and labels
never enter the feature matrix.

## Selection and recommendation

For each configured weight and threshold, validation metrics are computed from:

```text
fusion_score = supervised_weight * supervised_probability
             + anomaly_weight * normalized_anomaly_score
```

Weights are finite, positive for both engines, and sum to one. Inputs and output
are finite and in `[0,1]`. Candidates must meet the benign-FPR ceiling and have
positive attack recall and F1. Ranking is deterministic and does not use
Accuracy as the primary metric. Evaluation groups and held-out families are not
accepted by the selection function.

Recommendation requires the preregistered validation improvement and FPR rule.
Otherwise the policy records `fusion_not_recommended` or `inconclusive` and
retains every candidate result.

## Experiments

- **Known behavior:** early groups fit, middle groups select, and late groups
  evaluate all three modes on identical rows.
- **Leave-One-Attack-Family-Out:** one family is absent from supervised training,
  calibration, engine thresholds, fusion weights, and fusion threshold. Late
  evaluation contains only independent benign groups and the held-out family.
  At least two eligible families are required; this dataset provides five.
- **Temporal holdout:** early timestamps fit, middle timestamps select, and late
  timestamps evaluate. There is no shuffle or future-statistic fallback.
- **Parameter shifts:** late groups are cloned to new identities and transformed
  by the fixed factors: duration `1.25`, packet rate `1.25`, packet-size pattern
  `1.25`, and bounded connection-frequency proxy `1.50`. These are controlled
  feature-space simulations, not packet replay, traffic generation, flooding, or
  external targeting. Base and shifted ranges are recorded.

## Metrics and uncertainty

Each mode records classification metrics, FPR/FNR, confusion matrix, score
distributions, row/group/family counts, isolation evidence, and fusion-minus-
baseline deltas. Whole groups are resampled with replacement for 1,000 fixed-seed
draws. Recall, F1, Macro F1, PR-AUC, FPR, and paired deltas receive 95% intervals.
Undefined metrics remain null with a reason rather than becoming zero.

Latency uses a warmed 48-row batch and 25 repetitions in one process. It records
engine, fusion, total p50/p95/p99, per-sample p50, throughput, temporary research
component sizes, policy size, and deterministic-score status. Host measurements
are not an SLA.

## Artifact and persistence boundary

The experiment writer uses an exclusive experiment identity and writes reviewed
JSON/CSV/Markdown evidence beneath a caller-provided root. Existing identities
fail closed. The policy directory contains exactly:

- `fusion_policy_manifest.json`
- `fusion_policy_checksums.json`
- `fusion_policy_card.md`

The loader verifies root containment, the exact inventory, file checksums,
contract schema, directory/version agreement, and engine/schema identities.
Missing, extra, corrupt, escaped, or colliding artifacts are rejected. Fusion
uses no pickle, joblib, skops, or other model binary. Generated experiments and
policies are ignored/temporary and do not overwrite Phase 5/6 bundles.

## Reproduction

```bash
aegishunt fusion evaluate \
  --fusion-config configs/models/fusion.yaml \
  --supervised-config configs/models/supervised-corrective-pm-def-001.yaml \
  --anomaly-config configs/models/anomaly-lof-production-candidate.yaml \
  --label-mapping configs/label_mappings/aegishunt-controlled-demo-v1.yaml \
  --experiment-root <new-experiment-root> \
  --policy-root <new-policy-root> \
  --allow-controlled-demo

aegishunt fusion verify 1.0.0 --policy-root <policy-root>
aegishunt fusion describe 1.0.0 --policy-root <policy-root>
aegishunt fusion score 1.0.0 --input <score-input.json> --policy-root <policy-root>
```

Every evaluation requires fresh roots or a new version. Historical evidence is
never deleted to make a repeat succeed.
