# Consolidated experiment protocol

## Objective and evidence classes

AegisHunt evaluates whether a deterministic network-telemetry pipeline can
produce reviewable supervised, anomaly, fused, and hunting evidence. It does
not claim external validity. Four evidence classes are kept separate:

1. **Validation** selects candidates, calibration, thresholds, and policies.
2. **Frozen test** is a one-time, identity-protected controlled evaluation that
   never participates in selection.
3. **Controlled demo** proves execution and integration only.
4. **Development-host performance** measures one bounded workload and is not an
   SLA or capacity claim.

Historical details remain in the [supervised](supervised_experiment_protocol.md),
[anomaly](anomaly_experiment_protocol.md), and
[fusion](fusion_experiment_protocol.md) protocols.

## Data and feature contract

The implemented research evidence uses controlled synthetic data grouped by
source/session/scenario. The public benchmark registry and mappings are
provisional workflows; no public dataset result is claimed. The canonical
feature schema is `1.0.0` with 43 ordered finite flow features. Metadata, IDs,
labels, family, timestamps, actor/verdict, and provenance are not model
features. Group-exclusive train/validation/test splitting fails closed on
cross-split source/session/scenario identity, exact or near duplicates, label
leakage, missing data, non-finite values, and schema mismatch.

## Supervised procedure

Fixed-seed candidates use train-only preprocessing and group cross-validation.
The primary selection metric is validation Macro F1; the declared tie-breaks
include PR-AUC, recall, lower FPR/Brier/variance/latency/size, then stable
identity. Calibration is selected on validation Brier with `None` distinct from
valid zero. Threshold selection uses validation only and freezes before test.
The PM-DEF-001 corrective experiment has a new experiment/model/policy/config
identity and does not overwrite the original evidence.

## Anomaly procedure

Only benign training rows fit the scaler and anomaly estimators. Score
orientation/normalization is explicit. Thresholds and candidates are selected
using validation only. Isolation Forest has the original frozen controlled
result. The later LOF candidate is validation-qualified and has no untouched
independent holdout, so it must not be described as frozen-test or production
validated.

## Fusion and unknown-behavior procedure

Phase 7 used 144 new controlled rows in 72 groups and did not reopen Phase 5/6
frozen evidence. A fixed grid selected weights and threshold using validation.
Known late groups, five leave-one-attack-family-out folds, one temporal split,
and four fixed parameter shifts were then evaluated. Negative LOAO and held-out
family results are retained; no late result retuned the policy.

## Downstream and operational evaluation

Phase 8 validates identity-bound risk, severity, alerts, reasons, and non-causal
explanations. Phase 9 validates bounded event-time correlation and deterministic
hypotheses, including benign alternatives and non-executed query suggestions.
Phase 10 validates audited cases, notes, evidence, verdicts, feedback, exports,
and review-only retraining candidates. Phase 11–12 validate offline replay,
worker leases, observed versus durable progress, restart-from-origin recovery,
API-only frontend access, and the full sample chain.

Phase 13 uses fixed seeds for 21 robustness scenarios and a separate performance
protocol with warmups, repetitions, p50/p95/p99 availability, throughput,
CPU/RSS, exact environment, and source-backed JSON/CSV. Missing p99 is reported
as unavailable, not zero. The current benchmark source is
[`benchmark-results.json`](../reports/hardening/phase-13/performance-v1.1/benchmark-results.json).

## Reproducibility and contamination policy

- Configuration, feature, dataset, model, policy, evidence, and application
  versions remain independent.
- Random seeds, groups, source checksums, environment, exact inventory, and
  SHA-256 checksums are recorded where available.
- Frozen-test repeat identity is rejected. No formal frozen evidence is
  regenerated during final delivery.
- Test, holdout, LOAO, evaluation, benchmark, unknown, or ambiguous provenance
  cannot enter retraining candidates.
- Negative and inconclusive results are never rewritten to improve the thesis.
- The two uploaded final-delivery PCAPs are used only to derive payload-free
  aggregate-profile demo samples and local integration evidence; they are not
  training, tuning, benchmark, or ground truth.
