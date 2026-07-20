# AegisHunt Phase 7 Fusion Policy Card

## Intended use

Policy `aegishunt-fusion-controlled` version `1.0.0` combines an independently
validated supervised probability contract and a bounded normalized anomaly
score contract for controlled research comparison. It supports deterministic
offline scoring and Phase 7 pipeline verification.

It is not approved as production risk, severity, attack confirmation, automated
response, or a `SecurityAlert`. Its score is not attack probability, malicious
probability, compromise probability, or proof of zero-day detection.

## Inputs and formula

- Supervised identity: `aegishunt-supervised-1.0.1`, version `1.0.1`.
- Anomaly identity: `aegishunt-anomaly-1.1.0-candidate`, version
  `1.1.0-candidate`; this LOF configuration remains validation-qualified.
- Feature schema: `1.0.0`.
- Formula: `0.75 * supervised_probability + 0.25 * normalized_anomaly_score`.
- Selected threshold: `0.7`.
- Validation benign-FPR ceiling: `0.25`.

Missing scores, non-finite values, values outside `[0,1]`, model/version mismatch,
feature-schema mismatch, and artifact-integrity failure are rejected. There is
no automatic single-engine fallback.

## Selection evidence

Three preregistered weight pairs and seven thresholds were evaluated on the
middle 24 groups only. The selected validation candidate matched the supervised
baseline (Macro F1 `1.0`, recall `1.0`, PR-AUC `1.0`, FPR `0.0`) and did not
exceed it. Therefore the recommendation is **`inconclusive`**, not
`fusion_recommended`. No further weight or threshold search was performed.

## Controlled evaluation result

The final manual evidence run used dataset checksum
`4d3319d0a66ff204c9b9cd3720caf83fe66d9bb17d32140edda898f33e2acb40`.
It contained 144 rows and 72 isolated groups. This is controlled synthetic
pipeline verification only, not a public benchmark.

On identical known late groups:

| Mode | Recall | F1 | Macro F1 | PR-AUC | FPR | TN/FP/FN/TP |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Supervised only | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 18/0/0/30 |
| Anomaly only | 0.9333 | 0.8750 | 0.8125 | 0.8103 | 0.3333 | 12/6/2/28 |
| Fusion | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 18/0/0/30 |

The fusion-minus-supervised Recall, Macro F1, PR-AUC, and FPR deltas were all
`0.0`; their 1,000-draw group-bootstrap 95% intervals were `[0.0, 0.0]` in this
small controlled scenario. This does not imply population certainty.

Across five LOAO folds, family-macro recall was `0.6000` supervised,
`0.9333` anomaly, and `0.3333` fusion. Mean FPR was `0.0000`, `0.3333`, and
`0.0000`, respectively. Fusion recall was `0.3333` for brute force, `0.6667`
for command-and-control, `0.6667` for denial-of-service, and `0.0` for both
exfiltration and reconnaissance. These adverse results are retained.

The controlled temporal result matched the known comparison. Under all four
fixed parameter shifts, fusion recall was `1.0` and FPR `0.0`; the scenarios are
bounded feature-space simulations and do not establish real temporal or attack
robustness.

## Operational evidence

One development-host run over a 48-row batch and 25 repetitions measured:

- supervised p50 `1.0952 ms`;
- anomaly p50 `0.6729 ms`;
- fusion arithmetic p50 `0.0381 ms`;
- total p50/p95/p99 `1.8157/2.1595/2.3857 ms`;
- per-sample p50 `0.0378 ms`;
- throughput `25,834.5 samples/s`;
- temporary supervised/anomaly component sizes `1,506,433/33,755 bytes`;
- policy artifact size `3,621 bytes`;
- deterministic repeated scores: passed.

These measurements are not a production SLA and can vary by host and load.

## Integrity and limitations

The final temporary policy manifest checksum was
`808bd05e2e5a648324fe6052e65a6602f04c15f24e39f2a043a72b73ca3b29c7`;
its three-file exact inventory loaded independently. Missing, extra, corrupt,
escaped, and version-colliding artifacts are rejected. The machine artifact is
temporary/ignored and is not committed.

Limitations include the small synthetic sample, a generator shared conceptually
with earlier controlled data, wide or degenerate group intervals, LOF's
validation-qualified status, family-specific experimental refits, and no public
or enterprise capture. Future independent evidence can reverse every ranking.
