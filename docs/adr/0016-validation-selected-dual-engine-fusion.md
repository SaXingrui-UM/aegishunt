# ADR 0016: Validation-selected dual-engine fusion research policy

## Status

Accepted

## Context

Phase 5 provides a corrected Random Forest supervised configuration with
isotonic calibration. Phase 6 provides a validation-qualified novelty-mode LOF
configuration whose normalized score is bounded but is not probability. Their
historical frozen tests have already been consumed, so they cannot select a
Phase 7 fusion policy or serve as a renamed holdout.

The project needs an auditable comparison of supervised-only, anomaly-only, and
true dual-engine fusion on known behavior, held-out attack families, a strict
timeline, and bounded parameter changes. It must allow a negative result and
must stop before Phase 8 detection-result, alert, risk, severity, or explanation
semantics.

## Decision

- Use a Phase 7-specific, versioned controlled dataset with new group, source,
  capture-session, scenario, and record identities. It is pipeline verification,
  not a public benchmark or retroactive Phase 5/6 holdout.
- Refit the fixed Phase 5 Random Forest/isotonic configuration and fixed Phase 6
  novelty-mode LOF/StandardScaler/benign-quantile configuration inside each
  isolated experiment. Temporary estimators are not registered as active models.
- Fit estimators and preprocessing on early groups only. Fit anomaly components
  on benign early rows only. Select engine thresholds and the fusion policy on
  middle groups only. Evaluation and held-out-family evidence cannot enter
  selection.
- Define fusion as `supervised_weight * supervised_probability +
  anomaly_weight * normalized_anomaly_score`. Both weights are positive for a
  dual-engine candidate, finite, configured, and sum to one.
- Keep supervised-only and anomaly-only as explicit baseline modes rather than
  representing them as endpoint fusion weights.
- Select from the finite preregistered weight and threshold grid under the
  validation benign-FPR ceiling. A candidate must have positive attack recall
  and F1. Deterministic ranking uses Macro F1, recall, PR-AUC, balanced accuracy,
  FNR, FPR, and stable identity.
- Freeze one of `fusion_recommended`, `fusion_not_recommended`, or
  `inconclusive`; implementation alone does not imply recommendation.
- Use at least 1,000 fixed-seed whole-group bootstrap draws, including paired
  fusion-minus-baseline intervals.
- Persist no ML binary for fusion. Save an exact-inventory JSON/Markdown policy
  with SHA-256 checksums, evidence checksums, identities, schema, and semantics.
- Define fusion output as an experimental suspiciousness score. It is not attack
  probability, malicious probability, production risk, severity, or attack
  confirmation, and it creates no `SecurityAlert`.

## Alternatives considered

- **Reuse Phase 5/6 frozen tests:** rejected because they have already been
  viewed and cannot provide selection-independent Phase 7 evidence.
- **Load only the locally available active bundles:** rejected as the only
  research path because the supervised binary is intentionally not committed
  and LOAO requires family-specific refits. Verified operational output adapters
  remain supported separately.
- **Use an unbounded weight/threshold search:** rejected because result-driven
  refinement would overfit validation evidence and weaken reproducibility.
- **Select the best policy on LOAO or late results:** rejected because held-out
  and future evidence must remain evaluation-only.
- **Force-enable fusion because two engines exist:** rejected because the
  research question explicitly permits an inconclusive or adverse result.
- **Create alerts or a final risk score now:** rejected as Phase 8 scope.

## Consequences

- Phase 7 results are comparable within the controlled protocol and retain
  negative family-level outcomes.
- A policy can be loaded and scored independently without deserializing Python
  model objects, but it still depends on separately verified engine outputs.
- The controlled generator supplies reproducible behavioral variation while
  providing no public-benchmark, deployment, or zero-day claim.
- Phase 8 may later consume the score contract, but must add its own persistence,
  alert, explanation, severity, and human-review boundaries.

## Risks

- The small synthetic groups can make confidence intervals degenerate or wide
  and cannot represent enterprise traffic diversity.
- Reusing the same generator family with new identities limits external validity
  even though the Phase 7 groups and timestamps are isolated.
- LOF is validation-qualified and sensitive to scaling, neighborhood size, and
  density; Phase 7 does not promote it to benchmark-validated status.
- Family-specific refits may select different internal thresholds, so LOAO
  results describe the preregistered procedure rather than one deployed binary.
- Future independent data can reverse engine and fusion rankings.
