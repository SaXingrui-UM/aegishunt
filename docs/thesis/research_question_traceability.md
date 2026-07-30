# Research-question traceability

| Research question | Evidence | Result boundary |
| --- | --- | --- |
| RQ1: Can flow features support known-behavior classification? | Phase 5 corrected validation/frozen controlled evidence | Pipeline-qualified on small synthetic data; no public benchmark |
| RQ2: Can benign-only anomaly scoring surface unknown-like behavior? | Phase 6 Isolation Forest and LOF evidence | Original controlled frozen result; LOF validation-qualified without independent holdout |
| RQ3: Does fusion improve the two engines? | Phase 7 known, LOAO, temporal, parameter shift | Inconclusive; no superiority; LOAO below anomaly-only with misses |
| RQ4: Can detections become reviewable hunting work? | Phases 8–12 full-chain E2E | Implemented deterministic alerts/groups/hypotheses/cases/feedback; no causal or attack-confirmation claim |
| RQ5: Is the prototype reproducible and bounded? | Phase 13–14 coverage, robustness, security, package, Docker, release manifest | Local research delivery; not production assurance |

Machine evidence and tests are mapped in
[final requirement traceability](../final_requirement_traceability.md).
