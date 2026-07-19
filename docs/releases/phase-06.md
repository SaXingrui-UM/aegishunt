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
- Added novelty-mode LOF first as an offline comparator, then—under user-authorized
  ADR 0015—as a fixed validation-qualified production candidate. One-Class SVM
  is explicitly not implemented; Autoencoder is absent.
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

ADR 0014 records the original boundaries:

- Isolation Forest remains the production algorithm even when an offline
  comparator scores better on the controlled validation fixture.
- StandardScaler, estimator, and quantile normalizer fit benign train only.
- Canonical anomaly score is `-score_samples`; external validation thresholding
  is independent of sklearn contamination/predict behavior.
- Selection evidence is immutable before one frozen test.
- The safe bundle includes preprocessing, score semantics, normalizer, threshold,
  feature contract, provenance, and integrity metadata.

ADR 0015 supersedes only the Isolation Forest-only candidate boundary. It
permits the already-evaluated fixed novelty-mode LOF under policy `2.0.0`, while
keeping test access prohibited, the unchanged smoke gate fail-closed, and final
validation dependent on a new independent holdout. The eligibility decision was
made after validation results were known and is documented as post-hoc.

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
- Direction-B LOF candidate: Accuracy `0.6`, Precision `1.0`, Recall
  `0.3333333`, F1 `0.5`, Macro F1 `0.5833333`, Balanced Accuracy `0.6666667`,
  MCC `0.4082483`, PR-AUC `0.8083333`, ROC-AUC `0.6666667`, FPR `0.0`,
  TN/FP/FN/TP `4/0/4/2`; validation-qualified only.
- Fixed-seed group bootstrap: 1,000 draws; frozen F1 interval `[0,0]`, ROC-AUC
  `[0,0.375]`, PR-AUC approximately `[0.1556,0.7597]` with 907 valid AUC draws.

The selected Isolation Forest missed all controlled validation/test anomalies.
That weakness is a recorded generalization limitation; no test-driven retuning,
algorithm switching, threshold change, or evidence deletion occurred.

The subsequent validation-only Isolation Forest corrective matrix selected
`corrective-iforest-128-bootstrap--benign_training_quantile_cdf` with threshold
`0.85`, F1 `0.4444`, recall `0.3333`, and benign FPR `0.25`, but failed the
unchanged fixed SYN-burst smoke decision. It produced no candidate bundle. ADR
0015 then allowed the already-evaluated LOF path to become candidate-eligible.
Policy `2.0.0` selected it at threshold `0.9`; the fixed smoke produced normalized
score `1.0` and passed before/after reload. The original viewed test was not
opened, and no final-test metric is claimed for this candidate.

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
- Direction-B candidate model SHA-256:
  `4e2c7e6cb905875285c56d2df820655f386a7cf950ac3fcffdabae47ff8e4bb0`.
- Direction-B configuration SHA-256:
  `0e3afd1ba98c129bfed20a8ec2dd9be923a63e3caf2e4d3d3f64016cf737d6b1`.

The binary is intentionally ignored and not committed. Skops hashes identify
one artifact and are not claimed as reproducible-build hashes; each bundle must
match its own exact inventory/checksums and reproduce numeric scoring.

## Tests

- The full suite includes 83 Phase 6-focused tests, including the validation-only
  Isolation Forest correction, direction-B LOF selection/smoke, exact bundle
  algorithm and eligibility-state checks, fixed-matrix validation, no-test-access
  tracking, repeat rejection, and independent-process reload.
- Ruff: pass.
- Strict mypy: pass for 120 source files.
- Full Pytest/coverage: 288 passed, 0 failed, 0 skipped, and 0 xfailed in
  999.93 seconds; branch-aware coverage was 87.34% (85% required).
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
found zero remaining Blocking, High, or unhandled Medium findings. A final
direction-B equivalent review found one Medium audit-contract gap: metadata could
overstate LOF eligibility or substitute a different Isolation Forest comparison
matrix while remaining structurally valid. Commit `0c83a2d` added cross-field
fail-closed evidence contracts and exact-matrix regressions. Ruff, mypy, and all
288 tests passed afterward; zero Blocking, zero High, and zero unhandled Medium
findings remain.

The first direction-B Linux CI run passed 287 tests and failed one E2E reference
constant by one ULP (`...6717` versus `...6718`). Commit `d85689b` retains exact
same-platform local/independent-process comparisons and applies only a strict
`1e-12` relative/`1e-15` absolute tolerance to the fixed cross-platform reference
values. The targeted E2E passed after this portability correction.

The next PR-triggered Linux workflow passed in 9m44s. Its duplicate push workflow
was canceled at the previous 15-minute job limit while pytest was still running
on a slower worker; no test failure was reported. Commit `f03f75f` raises only
the bounded job timeout to 30 minutes while retaining Ruff, mypy, full pytest,
and the 85% branch-coverage requirement unchanged.
Both updated GitHub Actions `quality` runs then passed in 15m26s and 15m57s.

## Generated artifacts

Actual controlled evidence generated under an isolated `/tmp` root includes all
configured JSON/CSV reports, selection skops, frozen metrics, model card, and the
four-file bundle. Generated datasets, reports, model binaries, coverage output,
and temporary input batches are ignored and not committed. No database, PCAP,
secret, credential, external download, or public dataset was generated.

The direction-B formal run used a temporary reconstructed registered dataset and
the configured ignored report/model roots. It opened only train and validation,
wrote the independent experiment/model identities, and rejected a repeat. A
standalone Python command first failed before application execution because the
local editable `.pth` was not visible; `PYTHONPATH=src` was the documented local
workaround and is not claimed as a standard installation pass.

The explicit `anomaly train` command generates source-backed raw/normalized score
distributions, threshold sensitivity, benign-FPR, and anomaly-utility plots plus
a checksum manifest. These machine artifacts are ignored and are not benchmark
figures.

## Known limitations and risks

- The controlled benign baseline is very small and not operationally diverse.
- Historical Isolation Forest controlled anomaly recall is zero in validation and test.
- Domain/concept drift can materially change score distribution and FPR.
- Quantile mapping clips outside its observed benign-training tails.
- Public benchmark acquisition/conversion remains provisional.
- LOF is sensitive to dimensionality/sample size. The candidate has no untouched
  independent holdout and is not final-tested, production-validated, or deployable.
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
- Final checkpoint documentation: `c64ef32` (`docs: record phase 6 review outcome`)
- Direction-B decision registration: `265df40`
- Candidate implementation: `32e24ee`
- Candidate regression/E2E coverage: `ca830fd`
- Direction-B evidence documentation: `d6552fa`
- Candidate evidence-contract hardening: `0c83a2d`
- Cross-platform score-reference test: `d85689b`
- Bounded CI timeout correction: `f03f75f`
- Pull request: [#18](https://github.com/SaXingrui-UM/aegishunt/pull/18), open and ready for review
- Merge commit: pending
- Annotated Tag: pending; do not create before user merge authorization

## Next phase

Phase 7 — Fusion and Evaluation (`phase/07-fusion-evaluation`) is **Not started**.
It may begin only after Phase 6 PR review/merge, a user-directed checkpoint Tag,
clean synchronized `main`, and explicit user authorization.
