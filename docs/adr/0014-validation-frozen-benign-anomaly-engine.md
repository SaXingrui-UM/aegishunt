# ADR 0014: Validation-Frozen Benign-Baseline Anomaly Engine

## Status

Accepted

## Context

Phase 6 must learn deviation from benign behavior without allowing malicious,
validation, or frozen-test rows to fit the estimator, preprocessing, or score
normalizer. Scikit-learn anomaly estimators expose model-specific score directions
and internal contamination decisions that are unsuitable as a shared external
decision contract. The project also requires audit-preserving evidence, a single
frozen-test evaluation, safe persistence, and future compatibility with Phase 7
fusion without implementing fusion now.

## Decision

- Isolation Forest is the production Phase 6 anomaly algorithm. Every candidate
  is fit only on ground-truth benign rows from the Phase 4 training partition.
- StandardScaler is fit on those same benign rows and persisted with the estimator.
- Raw `score_samples` is retained for audit. Canonical score is its negation, so
  higher always means more anomalous for Isolation Forest and novelty-mode LOF.
- A versioned quantile-CDF normalizer is fit only on canonical benign-training
  scores. It clips to `[0,1]`; the result is explicitly not a probability.
- Candidate and threshold selection use validation evidence only. The threshold
  policy first enforces the configured benign-FPR ceiling, then uses anomaly F1,
  recall, PR-AUC, balanced accuracy, group stability, latency, and size under a
  deterministic tie-break.
- LOF runs in `novelty=True` mode as an offline comparator and cannot replace the
  production algorithm. One-Class SVM is not implemented in the bounded Phase 6
  scope; Autoencoder is excluded.
- An immutable checksummed selection record is written before an explicit,
  one-time frozen-test command. Test evidence cannot alter estimator,
  normalization, threshold, FPR target, or production algorithm.
- The four-file bundle contains a skops pipeline, manifest, outer checksums, and
  model card. Exact inventory, root containment, checksums, component types,
  schema, normalizer, and threshold are verified before scoring.

## Alternatives considered

- Use estimator `predict()` or contamination as the final decision threshold:
  rejected because it bypasses the declared validation FPR policy.
- Fit on benign and malicious rows: rejected because it violates the one-class
  research question and would turn Phase 6 into another supervised learner.
- Select LOF when its controlled validation result is higher: rejected because
  the roadmap defines Isolation Forest as production and comparison evidence is
  not authorization to change architecture.
- Fit min-max normalization on validation or test: rejected due to leakage and
  unstable tail behavior.
- Refit with validation-benign rows after selection: rejected for Phase 6 so the
  fitted baseline and saved threshold evidence retain a simple auditable boundary.
- Persist pickle/joblib: rejected because arbitrary object loading is unsafe.

## Consequences

- Training, normalization, validation, and test evidence remain distinguishable.
- Score semantics are portable across future anomaly estimators and Phase 7 can
  consume a bounded signal without treating it as probability.
- Strict FPR control can yield low anomaly recall on small or shifted validation
  data; this must be reported rather than optimized against frozen test.
- Bundle loading is more verbose but reproducible at the inference-contract level.
- Repeated frozen evaluation and model-version collisions fail closed.

## Risks

- A small benign baseline may poorly represent legitimate operational diversity.
- Quantile normalization saturates beyond observed benign-training tails.
- Isolation Forest scores and skops bytes can vary across dependency versions;
  environment metadata and per-bundle integrity checks remain mandatory.
- LOF is sensitive to dimensionality and sample size; its comparison is not a
  production recommendation.
- Domain/concept drift may increase false positives or hide anomalous behavior.
