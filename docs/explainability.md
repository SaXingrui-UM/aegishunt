# Phase 8 Explainability Contract

## Evidence boundary

Explanations deliberately separate observed facts from model inferences.
Observed facts are captured flow identifiers, endpoints, protocol, and time
bounds. Model inferences are supervised probability, normalized anomaly score,
fusion score, operational risk, reason triggers, and feature sensitivities.
Ground-truth labels and attack-family fields never enter alert construction or
reason generation.

No feature importance, local contribution, or reason code establishes causation.
No explanation claims an attack is confirmed, fusion is superior, the Phase 6
LOF has an untouched independent holdout, or the controlled evidence is a public
benchmark or production validation.

## Benign reference profile

The versioned reference profile is built only from finite benign rows in the
training partition. It binds dataset and split checksums, feature schema/order,
group count, generation configuration, and q05/q25/median/q75/q95 plus minimum
and maximum for every feature. q05–q95 is an observed reference range, not a
safety boundary.

## Global importance

- Native tree importance is emitted only when the verified estimator exposes a
  finite, non-negative vector matching the feature order; otherwise its status is
  `not_applicable` rather than an invented zero vector.
- Permutation importance uses a fixed validation partition, fixed seed, one
  process, configured repeats/scoring, and never test data. Negative values are
  retained because they are valid sensitivity evidence.

Both reports use explicit non-causal semantics.

## Local contributions

For one flow, each bounded feature is replaced independently with its benign
training median. The system rescoring delta is:

```text
observed risk - reference-replacement risk
```

The largest absolute deltas are returned in stable feature-order tie breaks.
Each record includes observed value, q05–q95 range, reference median, both risk
values, delta, and `increases_suspicion`, `decreases_suspicion`, or `neutral`.
These are not SHAP values, are not additive, and are not causal.

## Reason-code catalog

Catalog `aegishunt-phase-08-reason-codes` version `1.0.0` stores category,
trigger source/condition, evidence type, fact/inference classification,
limitations, and Phase 8 enablement. Reasons are emitted only from a measured
feature/reference comparison or a configured score threshold.

`REPEATED_DESTINATION_ACTIVITY` and `MULTIPLE_CORRELATED_ALERTS` are reserved and
disabled because they require Phase 9 cross-flow/correlation state. They are
never fabricated as Phase 8 evidence.

## Artifact integrity

An explanation artifact contains exactly seven JSON/Markdown files: manifest,
checksums, benign reference profile, native importance, permutation importance,
reason catalog, and protocol. SHA-256 covers every non-checksum file. Loading
rejects path escape, symlinks, missing/extra/corrupt files, identity mismatch,
version-directory mismatch, unsafe serialized model extensions, and version
collision. Artifacts are data-only and contain no pickle/joblib/skops model.
