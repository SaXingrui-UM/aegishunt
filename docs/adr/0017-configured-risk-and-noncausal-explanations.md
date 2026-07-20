# ADR 0017: Configured Risk and Non-Causal Alert Explanations

## Status

Accepted for Phase 8 implementation review.

## Context

Phase 5, 6, and 7 expose distinct verified score contracts. Phase 7 retained an
inconclusive recommendation, so Phase 8 must make analyst-facing risk auditable
without claiming fusion superiority or reselecting weights. Alerts require
useful evidence while protecting against causal or attack-confirmation claims.

## Decision

Use a checksummed YAML risk policy with an explicit single score source. The
default is identity mapping from the verified Phase 7 fusion score, whose full
upstream identities and inconclusive recommendation must match. Use configured
inclusive severity bands and alert threshold. Persist every successful score in
the existing `DetectionResult`; create an existing `SecurityAlert` only at the
threshold.

Use benign-training q05–q95 profiles, supported native tree importance,
fixed-validation permutation importance, and deterministic single-feature
median-replacement local sensitivity. Persist versioned reason evidence and
mandatory non-causal limitations. Store explanation artifacts as exact-inventory
checksummed JSON/Markdown only. Update only the nullable alert verdict and audit
metadata after creation.

## Alternatives considered

- Reoptimize fusion/risk weights in Phase 8: rejected because it changes Phase 7
  research selection and risks leakage.
- Select the maximum available score: rejected as a hidden dynamic fallback.
- SHAP as a core dependency: rejected as unnecessary weight and because its
  values still require careful non-causal interpretation.
- LLM-generated explanations: rejected for nondeterminism and because the core
  must not depend on an LLM.
- Correlation/context-adjusted risk: deferred to Phase 9.

## Consequences

Risk and severity are reproducible, score identity is traceable, low-risk
detections remain available, alerts always carry reason evidence, and analyst
verdicts cannot mutate evidence. Explanations are bounded sensitivity evidence,
not causal findings. Full correlation and analyst UI/API workflows remain later
work.

## Risks

Controlled reference ranges may not generalize to public or operational data.
Single-feature replacement ignores interactions and contributions need not add
to risk. The Phase 7 fusion recommendation remains inconclusive and Phase 6 LOF
still lacks an untouched independent holdout. These limitations are explicit in
every explanation.
