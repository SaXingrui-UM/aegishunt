# Phase 06 Release Notes

## Objective and status

Build a benign-training-only anomaly engine over the frozen Phase 4 feature and
split contracts, preserving validation/test isolation and producing auditable,
safe, deterministic scoring artifacts.

Status: **Implementation complete — awaiting PR review** on
`phase/06-anomaly-detection`. Phase 7 has not started. PR, merge commit, and
completion Tag are `pending`; no `phase-06-complete` Tag may exist before merge.

## Completed scope

- Reused the Phase 4 quality/leakage/checksum/frozen-split gate and Phase 3
  schema `1.0.0`/43-feature order.
- Enforced benign-only train extraction: 10 rows/5 groups fit; 18 malicious
  training rows excluded. Metadata and labels remain outside the matrix.
- Added configured, deterministic Isolation Forest candidates with StandardScaler,
  external thresholding, and no estimator-contamination decision leakage.
- Added novelty-mode LOF as an offline comparator. It cannot become the
  production bundle. One-Class SVM is explicitly not implemented; Autoencoder
  is absent.
- Defined raw, canonical higher-is-more-anomalous, and benign-training quantile
  normalized `[0,1]` scores. Normalized score is not probability.
- Added validation-only FPR-constrained candidate/threshold selection, complete
  threshold curves, class score distributions, group stability, full anomaly
  metrics, 1,000-draw group bootstrap intervals, and operational evidence.
- Added immutable selection evidence before explicit one-time frozen test.
- Added an independently verified SHA-256 companion for the frozen selection;
  tampered threshold/normalizer evidence is rejected before test access.
- Added exact-inventory safe skops bundle, model card, strict prediction batch,
  deterministic independent-process reload, CLI, and machine reports.
- Added unit, integration, security-oriented bundle, CLI, and offline E2E tests.
- Updated architecture, README, ADR, frontend status, experiment protocol, and
  source-backed model card without implementing a dashboard or invented metrics.

## Architecture decisions

ADR 0014 records the following boundaries:

- Isolation Forest remains the production algorithm even when an offline
  comparator scores better on the controlled validation fixture.
- StandardScaler, estimator, and quantile normalizer fit benign train only.
- Canonical anomaly score is `-score_samples`; external validation thresholding
  is independent of sklearn contamination/predict behavior.
- Selection evidence is immutable before one frozen test.
- The safe bundle includes preprocessing, score semantics, normalizer, threshold,
  feature contract, provenance, and integrity metadata.

## Controlled pipeline evidence

The AegisHunt-generated synthetic demo is pipeline verification only. It is not a public benchmark,
real-world/production claim, or zero-day evidence.

- Dataset/split: 48 rows/24 groups; 28/10/10 rows and 14/5/5 groups.
- Benign fit: 10 rows/5 groups; 18 malicious train rows excluded.
- Selected: `iforest-64-full`, threshold `0.9`, validation FPR ceiling `0.25`.
- Validation: Accuracy `0.4`, F1 `0.0`, recall `0.0`, Macro F1 `0.2857143`,
  Balanced Accuracy `0.5`, MCC `0.0`, ROC-AUC `0.5`, PR-AUC `0.6388889`,
  specificity `1.0`, benign FPR `0.0`, anomaly FNR `1.0`, TN/FP/FN/TP `4/0/6/0`.
- Frozen test: Accuracy `0.4`, F1 `0.0`, recall `0.0`, Macro F1 `0.2857143`,
  Balanced Accuracy `0.5`, MCC `0.0`, ROC-AUC `0.0833333`, PR-AUC `0.4703704`,
  specificity `1.0`, benign FPR `0.0`, anomaly FNR `1.0`, TN/FP/FN/TP `4/0/6/0`.
- LOF validation-only comparison: recall `0.3333333`, F1 `0.5`, PR-AUC
  `0.8083333`, ROC-AUC `0.6666667`, FPR `0.0`; production eligibility false.
- Fixed-seed group bootstrap: 1,000 draws; frozen F1 interval `[0,0]`, ROC-AUC
  `[0,0.375]`, PR-AUC approximately `[0.1556,0.7597]` with 907 valid AUC draws.

The selected Isolation Forest missed all controlled validation/test anomalies.
That weakness is a recorded generalization limitation; no test-driven retuning,
algorithm switching, threshold change, or evidence deletion occurred.

## Operational and integrity evidence

One recorded development-host run measured selected training at approximately
`0.0279 s`, 10-row batch p50/p95/p99 at `3.0847/3.4076/3.4627 ms`, per-sample
p50 `0.3085 ms`, throughput `3201 samples/s`, serialized pipeline size
`1,672,484` bytes, and traced peak scoring memory `239,312` bytes. These values
are not an SLA and vary with host load.

- Training config SHA-256:
  `0caa294c9dd823c8954d0e1cda23c66611fef7c3e0be32f24b9127966e582dd5`.
- Dataset manifest SHA-256 for the controlled run:
  `badf8c045c29fa02299eb55f8a1cd7deb15d92aec40c0e80cd6ea4a133d98d0d`.
- Split manifest SHA-256:
  `a2949d3ef88381119616c5c352e39c30c7c98371edc0101614c230e0c7b8a1e0`.
- Temporary selected model SHA-256:
  `d6ab14b4a6566c14be394d50c4cb424d2a766f09c468d72ff47a8ee708e37718`.

The binary is intentionally ignored and not committed. Skops hashes identify
one artifact and are not claimed as reproducible-build hashes; each bundle must
match its own exact inventory/checksums and reproduce numeric scoring.

## Tests

- Phase 6 focused suite: 41 tests passed after one test-only assertion was fixed;
  no implementation failure was hidden or skipped.
- Ruff: pass.
- Strict mypy: pass for 118 source files.
- Full Pytest/coverage: 249 passed, 0 failed, 0 skipped, and 0 xfailed in
  408.16 seconds; branch-aware coverage was 87.15% (85% required).
- Offline controlled E2E: pass, including benign-only fit, validation freeze,
  frozen test, bundle, independent-process reload, and identical numeric scoring.
- Bundle checks reject path escape, arbitrary joblib, extra/missing/corrupt files,
  checksum mismatch, version collision, and schema/order/dtype drift.

## Review outcome

Native `codex review --base main` could not start because the installed arm64
binary is missing (`ENOENT`); no native-review success is claimed. The equivalent
first read-only review found one High selection-integrity gap and two Medium
issues: an impossible FPR limit could select a non-compliant threshold, and a
model-version collision could be discovered after frozen evidence was written.
Commit `0ad6fb6` added the independent selection checksum, fail-closed FPR
selection, pre-test version-collision check, and three regression tests. Fifteen
focused tests and the complete suite then passed. The second equivalent review
found zero remaining Blocking, High, or unhandled Medium findings.

## Generated artifacts

Actual controlled evidence generated under an isolated `/tmp` root includes all
configured JSON/CSV reports, selection skops, frozen metrics, model card, and the
four-file bundle. Generated datasets, reports, model binaries, coverage output,
and temporary input batches are ignored and not committed. No database, PCAP,
secret, credential, external download, or public dataset was generated.

Optional score/threshold plots were not generated because no plotting dependency
is part of Phase 6. The explicit `anomaly train` command generates real
`score_distribution.csv` and `threshold_sensitivity.csv` plot inputs.

## Known limitations and risks

- The controlled benign baseline is very small and not operationally diverse.
- Isolation Forest controlled anomaly recall is zero in validation and test.
- Domain/concept drift can materially change score distribution and FPR.
- Quantile mapping clips outside its observed benign-training tails.
- Public benchmark acquisition/conversion remains provisional.
- LOF comparison is sensitive to dimensionality/sample size and is not deployable.
- One-Class SVM and Autoencoder are not implemented.
- DEF-004 remains open and non-blocking: total database failure cannot persist a
  failure event into that same unavailable database.

## Commit, PR, and checkpoint

- Branch: `phase/06-anomaly-detection`
- Core implementation: `d710b09` (`feat: add benign-baseline anomaly engine`)
- Regression tests: `352205f` (`test: cover anomaly selection and bundle integrity`)
- Frontend status: `63cedb6` (`feat: update phase 6 frontend status`)
- Documentation: `3363788` (`docs: document phase 6 anomaly contract`)
- Review fix: `0ad6fb6` (`fix: harden anomaly selection freeze`)
- Final checkpoint documentation commit: pending
- Pull request: pending
- Merge commit: pending
- Annotated Tag: pending; do not create before user merge authorization

## Next phase

Phase 7 — Fusion and Evaluation (`phase/07-fusion-evaluation`) is **Not started**.
It may begin only after Phase 6 PR review/merge, a user-directed checkpoint Tag,
clean synchronized `main`, and explicit user authorization.
