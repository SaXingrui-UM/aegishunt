# ADR 0015: Permit LOF as a validation-qualified production candidate

## Status

Accepted

## Context

ADR 0014 made Isolation Forest the only production-eligible Phase 6 algorithm
and limited novelty-mode Local Outlier Factor (LOF) to an offline comparator.
The bounded validation-only corrective experiment then produced two important
results on the registered controlled-demo split:

- the best eligible Isolation Forest candidate had positive but weak validation
  utility and failed the fixed post-selection SYN-burst smoke decision; and
- the already-registered LOF comparator, fitted only on benign training rows,
  satisfied the benign false-positive-rate constraint and had stronger
  validation F1 and PR-AUC than the selected Isolation Forest candidate.

The original frozen test has already been viewed and cannot be reused for
selection. No untouched independent holdout is available in the registered
48-row controlled dataset. The user therefore authorized direction B: change
the algorithm-eligibility boundary, without changing the dataset, threshold
evidence, fixed smoke fixture, or fail-closed bundle gate.

This decision is made after the LOF validation evidence and the Isolation
Forest smoke failure were observed. It is a transparent post-hoc governance
decision, not a blinded model-selection result and not new independent
performance evidence.

## Decision

- Permit novelty-mode LOF as a production-candidate algorithm in the new,
  versioned selection policy `2.0.0`.
- Keep Isolation Forest eligible and compare both algorithms using only their
  registered benign-training and validation evidence. The test partition must
  not be opened or used.
- Require LOF to use `novelty=True`, `score_samples`, StandardScaler, the fixed
  registered hyperparameters, and a normalizer fitted only on benign-training
  canonical scores.
- Use a new immutable experiment identity,
  `phase-06-controlled-demo-lof-production-candidate-001`, and candidate model
  version `1.1.0-candidate`. Existing experiment evidence and model versions
  remain untouched.
- Retain the validation benign-FPR constraint and positive F1/recall gate.
  Rank eligible algorithms deterministically by validation F1, recall, PR-AUC,
  balanced accuracy, lower benign FPR, and a stable algorithm/candidate ID.
  Runtime measurements and the previously viewed test cannot affect ranking.
- Freeze selection before running the unchanged SYN-burst smoke fixture. The
  fixture cannot affect fitting, normalization, thresholding, or ranking.
- Create a safe model bundle only when the selected candidate passes the fixed
  smoke decision before and after an independent bundle reload. Otherwise fail
  closed and create no bundle.
- Describe a passing bundle only as `validation-qualified`. It remains awaiting
  a new, independently sourced, group-isolated holdout before final evaluation
  or any production-performance claim.

## Alternatives considered

- **Continue searching Isolation Forest configurations:** rejected because the
  registered 24-candidate matrix was complete and expanding it after observing
  results would increase validation overfitting risk.
- **Create a new controlled dataset immediately:** valid future work, but not
  selected by the user for this corrective direction.
- **Treat the original test as a new holdout:** rejected because it has already
  been viewed and is immutable historical evidence.
- **Lower the smoke threshold or change the smoke fixture:** rejected because
  this would weaken a pre-existing fail-closed acceptance gate after failure.
- **Promote LOF directly to validated/production status:** rejected because no
  untouched independent holdout exists.
- **Introduce another anomaly library or algorithm:** rejected as unnecessary
  scope and dependency expansion.

## Consequences

- Phase 6 bundle and selection contracts must support both Isolation Forest and
  novelty-mode LOF while retaining exact type and checksum validation.
- ADR 0014 remains the historical initial decision; this ADR supersedes only
  its prohibition on LOF production-candidate eligibility.
- The selection policy, configuration schema, experiment identity, evidence,
  and candidate model version must all be versioned independently.
- A successful outcome improves pipeline readiness but does not establish
  benchmark, real-world, zero-day, or calibrated-probability performance.
- Phase 7 remains out of scope.

## Risks

- The controlled dataset is very small, and LOF is sensitive to dimensionality,
  neighborhood size, scaling, and dataset density.
- Because the eligibility decision follows observed validation evidence, its
  apparent advantage may be optimistic and must not be treated as independent
  confirmation.
- A validation-qualified LOF candidate may still fail the unchanged smoke gate;
  fail-closed behavior is intentional.
- Future independent data may reverse the algorithm ranking or require a new
  threshold and normalization policy.
