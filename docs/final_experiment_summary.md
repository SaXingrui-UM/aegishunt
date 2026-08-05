# Final experiment and implementation summary

## Evidence boundary

AegisHunt implements the complete local chain from offline PCAP ingestion to
analyst feedback. Current research metrics come from controlled synthetic data,
not a public benchmark, enterprise capture, or production deployment. Validation,
one-time frozen test, controlled demo, and development-host performance are
different evidence classes and are not pooled.

## Data and features

The canonical contract has 43 explicitly ordered finite flow features under
schema `1.0.0`. Group-exclusive dataset splitting and quality/leakage checks
protect source/session/scenario identity. Public dataset acquisition remains a
manual, license- and checksum-gated workflow, so no public benchmark result is
reported.

## Supervised result and correction

The original Phase 5 evidence selected HistGradientBoosting/sigmoid because
PM-DEF-001 treated valid Brier `0.0` as missing. The independently versioned
corrective experiment selected Random Forest/isotonic at threshold `0.5` using
validation only. Corrective validation Macro F1 was `1.0`, Brier `0.0`; the
frozen controlled test reported Accuracy `0.8`, Macro F1 `0.7619`, ROC-AUC
`0.9583`, PR-AUC `0.9524`, Brier `0.1091`, and confusion `2/2/0/6`. Intervals
are broad because the frozen sample is small. Historical and corrective
evidence remain separately auditable.

## Anomaly and fusion

The original selected anomaly model's controlled frozen result reported recall
`0.3333`, F1 `0.5`, Macro F1 `0.5833`, ROC-AUC `0.6667`, PR-AUC `0.8083`, and
benign FPR `0.0`. The later LOF candidate is validation-qualified only and has
no untouched independent holdout.

Fusion selected supervised/anomaly weights `0.75/0.25` and threshold `0.7`.
Known late controlled groups matched supervised-only, so fusion was not shown
superior. Across five LOAO folds, family-macro recall was supervised `0.6000`,
anomaly `0.9333`, fusion `0.3333`; held-out exfiltration and reconnaissance
misses remain. The recommendation is **inconclusive**.

## Alerting, hunting, and analyst workflow

Identity-bound supervised probability, anomaly score, fusion value, configured
risk/severity, reasons, and non-causal explanations are persisted separately.
Alerts prompt review rather than confirming attack. Event-time bounded
correlation produces deterministic groups and proposed hypotheses with facts,
inferences, assumptions, benign alternatives, possible mappings, and
non-executed queries. Cases, append-only notes/evidence, verdicts, feedback,
reports, and review-only retraining candidates preserve audit/provenance.

## Runtime and frontend

One leased worker replays offline PCAPs without root or a target. Observed
progress is live and non-durable; durable progress is committed evidence.
Explicit recovery restarts from packet zero. FastAPI is the only frontend
business boundary; Streamlit reads and mutates through typed API calls. The
final controlled sample chain is explicit and idempotent.

## Performance, robustness, security, and coverage

Phase 13's controlled Darwin arm64 measurements include parser, feature,
inference, fusion, full-pipeline, API, export, artifact-size, CPU/RSS, and
latency evidence. The source-backed table/figure is generated from
[`benchmark-results.json`](../reports/hardening/phase-13/performance-v1.1/benchmark-results.json).
These measurements are not an SLA, capacity statement, or guaranteed real-time
performance.

The 21-scenario robustness matrix passed its final recorded execution.
Repository branch-aware coverage was `85.75%` at the Phase 14 startup baseline,
with each Phase 13 core package at least `80%`. Final Phase 14 values are
recorded in the acceptance report after execution.

Phase 13 recorded dependency, secret-history, Bandit, and 80-finding ledger
evidence. The formal final Codex Security rescan was explicitly waived and was
not executed; no pass is claimed. One bounded oversized historical blob was
excluded from the secret-history scanner.

## Final interpretation

The contribution is a modular, reproducible, offline research prototype with
explicit evidence semantics and a complete analyst-facing lifecycle. It is not
state of the art, production ready, enterprise scale, proven zero-day
detection, guaranteed real-time, or a substitute for analyst judgment. The
negative and inconclusive results, no-independent-holdout limitation, wide
intervals, DEF-004, security residual risk, and local-only boundary are part of
the final result.
