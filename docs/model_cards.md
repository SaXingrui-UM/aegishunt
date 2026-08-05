# Model, policy, and demo artifact index

This is a reader-facing index; the linked cards and machine manifests remain
authoritative. Application version `1.0.0` does not change any model, policy,
feature-schema, or evidence version.

| Artifact | Identity / role | Evidence boundary | Source |
| --- | --- | --- | --- |
| Supervised original | model `1.0.0`, HistGradientBoosting, sigmoid, threshold 0.5 | Historical pre-corrective controlled evidence affected by PM-DEF-001; preserved, not active corrective evidence | [Phase 5 release](releases/phase-05.md) |
| Supervised corrective | model `1.0.1`, Random Forest, isotonic, threshold 0.5, feature schema `1.0.0` | Validation-selected; one frozen controlled test; synthetic pipeline verification only | [Supervised model card](model_card.md) |
| Anomaly selected | Isolation Forest `1.0.0` | Original validation/frozen controlled path; not a public benchmark | [Anomaly card](anomaly_model_card.md) |
| LOF candidate | LOF `1.1.0-candidate` | Validation-qualified only; there is no untouched independent holdout | [LOF protocol](anomaly_lof_candidate_protocol.md) |
| Fusion policy | policy `1.0.0`, supervised/anomaly weights `0.75/0.25`, threshold `0.7` | Recommendation **inconclusive**; not superior to supervised-only; family-macro LOAO below anomaly-only | [Fusion policy card](fusion_policy_card.md) |
| Risk policy | configured Phase 8 deterministic mapping | Operational suspiciousness score and severity, not attack probability | [Detection and alerts](detection_alerts.md) |
| Explanation artifact | schema `1.0.0`, benign reference, global and local non-causal evidence | Reference-replacement contributions and importance do not establish causality | [Explainability](explainability.md) |
| Demo-only artifacts | namespace `phase14-controlled-demo`, operation `1.0.0` | Created only after explicit confirmation; checksum-verified; release-bundle class `controlled_demo_only` | [Demo Guide](demo_guide.md) |

## Corrective supervised evidence

PM-DEF-001 incorrectly treated valid Brier `0.0` as missing. PR #14 corrected
explicit `None` handling without changing the primary metric or test isolation.
Corrective controlled validation selected Random Forest/isotonic with Macro F1
`1.0` and Brier `0.0`; the frozen controlled test reported Accuracy `0.8`,
Macro F1 `0.7619`, ROC-AUC `0.9583`, PR-AUC `0.9524`, Brier `0.1091`, and
confusion TN/FP/FN/TP `2/2/0/6`. The confidence intervals are wide because the
test is small. The original `1.0.0` artifact remains an immutable historical
checkpoint. See the detailed card for bundle checksum, size, latency, inventory,
and provenance.

## Anomaly and fusion caveats

The LOF candidate is not production- or frozen-test validated. Its qualification
uses validation evidence with no untouched independent holdout. Phase 7 used a
new controlled dataset and selected fusion before late/LOAO analysis. Fusion
matched supervised-only on known late controlled groups but did not improve it.
Family-macro LOAO recall was supervised `0.6000`, anomaly `0.9333`, fusion
`0.3333`; held-out exfiltration and reconnaissance misses remain visible.

## Intended use and exclusions

These artifacts support an offline master's-project demonstration, reproducible
pipeline research, and analyst review. They are not intended for autonomous
response, public-network exposure, real-world attribution, legal conclusions,
enterprise deployment, or safety-critical decisions. No card guarantees
zero-day detection. Probabilities, anomaly scores, fusion values, risk,
correlation, and confidence have different semantics and are not interchangeable
attack probabilities.

Formal model binaries are ignored and are never committed. The release builder
may include separately generated, checksummed demo-only artifacts. Loaders
reject missing/extra/corrupt inventory, unsupported types, identity or feature
schema mismatch, path escape, and version collision.
