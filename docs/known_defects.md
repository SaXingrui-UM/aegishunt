# Known Defects

Last updated: 2026-07-23 (Asia/Shanghai)

## PM-DEF-001 — Zero Brier score treated as missing

- Severity: High
- Status: Resolved
- Component: Phase 5 calibration and candidate selection
- Root cause: optional numeric evidence used truthiness fallbacks, so valid
  Brier `0.0` was replaced by a worse fallback value.
- Before fix: sigmoid Brier `0.19178394648427863` was selected over isotonic
  Brier `0.0` in the reproduced calibration case.
- Correction: explicit `None` handling preserves zero, ranks missing evidence
  last, and rejects non-finite metrics. The same rule covers the candidate Brier
  tie-break and equivalent Phase 5 CV optional-metric ranking.
- Audit strategy: the original experiment `phase-05-controlled-demo` and model
  `1.0.0` remain immutable. Corrective experiment
  `phase-05-controlled-demo-pm-def-001` and model `1.0.1` explicitly supersede
  them and bind the correction to its Git commit.
- Corrective result: Random Forest, isotonic calibration, threshold `0.5`.
  These controlled synthetic results verify the pipeline only and are not public
  benchmark or real-world performance evidence.
- Corrective PR: [#14](https://github.com/SaXingrui-UM/aegishunt/pull/14),
  merged as `76f79972dff778f5d30d550bc6da78583e338fa1`.
- Checkpoints: original annotated `phase-05-complete` remains unchanged as the
  affected historical checkpoint; annotated `phase-05-pm-def-001-complete`
  identifies the merged correction.
- Metadata closure: PR
  [#15](https://github.com/SaXingrui-UM/aegishunt/pull/15) merged the corrective
  post-merge record into `main`.
- Regression evidence: zero-Brier calibration, candidate tie-break, `None`
  ordering, non-finite rejection, determinism, non-overwrite, one-time frozen
  test, secure bundle, and independent reload tests.

## DEF-004 — Database outage cannot persist to the unavailable database

- Severity: Medium
- Status: Open; non-blocking for Phase 11
- Component: database failure auditability
- Behavior: total database unavailability fails closed, rolls back, returns a
  sanitized error, and logs safely, but cannot persist a failed record into that
  same unavailable database.
- Constraint: Phase 11 adds a durable SQLite queue and explicit recovery but does
  not add Redis, Kafka, Celery, another database, or an alternate broker. Total
  loss of that same SQLite store still requires a later approved out-of-band
  design for durable outage evidence.
