# Detection Results, Risk, Alerts, and Verdicts

## Scope and truthfulness boundary

Phase 8 converts already verified Phase 5–7 scores into persisted detection
evidence and optional analyst-review alerts. It does not correlate alerts,
generate hypotheses, create cases, map MITRE techniques, or retrain models.

Risk is configured operational suspiciousness for triage. It is not attack
probability. Severity is configured triage priority, not certainty or business
impact. A security alert means evidence warrants analyst review; it is not a
confirmed attack.

## Score and risk contract

`configs/models/detection.yaml` is the versioned risk policy. The default source
is the verified Phase 7 `fusion_score`, mapped identically into `[0,1]`. The
policy binds the exact supervised model, anomaly model, fusion policy,
feature-schema, and fusion-policy checksum, and requires Phase 7's
`inconclusive` recommendation. Missing or mismatched identities fail closed.
There is no maximum-score fallback, implicit zero, dynamic source selection, or
Phase 8 weight/threshold optimization.

The configured alert rule is inclusive:

```text
risk_score >= alert_threshold
```

Every successful score is a `DetectionResult`. A below-threshold result remains
queryable but does not create a `SecurityAlert`. Severity bands use inclusive
lower bounds and cover informational, low, medium, high, and critical.

## Persistence and migration

The existing Phase 1 entities and repositories are reused. Schema version 2
adds score thresholds, fusion/risk identity fields, explanation fields, and
alert verdict metadata. The ordered v1→v2 migration is additive, records version
2, preserves old rows, and rejects unknown versions. Historical v1 rows are not
silently given invented model evidence.

Detection and optional alert creation share the caller transaction. Stable UUID5
identities make duplicate semantics explicit: the same score identity is
rejected instead of overwritten. Core alert evidence, risk, severity, reason
codes, model identities, and policy identities are immutable through the verdict
workflow.

## Alert type and template

Alert types are deterministic and limited to:

- `multi_engine_suspicion`;
- `supervised_suspicion`;
- `anomalous_behavior`;
- `behavioral_pattern`.

Templates use cautious analyst-review language. Ground-truth labels, attack
families, IP values, filenames, and user identities do not choose alert types or
severity.

## Analyst verdict

The nullable verdict accepts `true_positive`, `false_positive`,
`benign_expected`, or `needs_more_information`. An update changes only verdict
and `updated_at` and appends an actor-attributed audit event. Repeating the same
verdict is idempotent. Verdict changes do not trigger training, feedback export,
case creation, hypotheses, model replacement, or correlation.

## CLI

The `detection`, `alerts`, and `explainability` Typer groups provide integrity-
checked evaluation/query/verdict/artifact commands. Model and explanation
artifacts must be within explicitly configured roots. Operator failures are
sanitized and do not emit raw tracebacks.

Full alert APIs and frontend analyst workflows remain Phase 12 scope.
