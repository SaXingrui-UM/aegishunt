# Phase 05 Release Notes

## Objective and status

Deliver the validation-frozen supervised detection engine, then correct
PM-DEF-001 without erasing its historical evidence or weakening frozen-test
protection.

Status: **Phase 5 corrective implementation complete — awaiting PR review**.
PR #13 was merged into `main`; the corrective PR has not yet been merged. Phase
6 has not started.

## Original completed scope

- Exact Phase 4 dataset, checksum, schema, label, quality, leakage, group, and
  frozen-test evidence gates.
- Dummy, Logistic Regression, Decision Tree, Random Forest, and
  HistGradientBoosting candidates with train-only deterministic GroupKFold.
- Validation-only sigmoid/isotonic calibration, threshold curves, full metrics,
  operational evidence, and a selection policy excluding Accuracy/test metrics.
- Immutable pre-test selection record and one-time frozen-test evaluation with
  1,000-draw group bootstrap intervals.
- Exact-inventory skops bundles with outer checksums, type allowlists, provenance,
  fixed feature schema/order/dtype, model card, CLI, and prediction interfaces.

## PM-DEF-001 root cause and correction

`select_calibration()` and candidate ranking used truthiness fallbacks for
optional numeric metrics. Python treated a valid Brier score of `0.0` as false,
so the calibration reproduction selected sigmoid Brier
`0.19178394648427863` instead of isotonic Brier `0.0`.

Selection policy `1.0.1` keeps the existing ordering but uses typed explicit
missing-value handling:

- finite zero remains zero;
- `None` ranks after all finite evidence;
- NaN and positive/negative Infinity are rejected;
- candidate Brier and equivalent CV optional metrics follow the same rule;
- validation remains the only source for calibration, threshold, and model
  selection; test metrics remain excluded.

## Corrective evidence strategy

- Original experiment/model: `phase-05-controlled-demo` / `1.0.0`.
- Corrective experiment/model: `phase-05-controlled-demo-pm-def-001` / `1.0.1`.
- Corrective configuration schema: `1.1.0`.
- Corrective selection policy: `1.0.1`.
- Selection and bundle metadata record PM-DEF-001, superseded IDs, correction
  reason, and the exact code commit.
- Experiment and bundle directories are non-overwriting. Existing selection,
  frozen report, and bundle remain unchanged.
- The corrective experiment independently permits exactly one frozen-test
  evaluation; a second attempt was rejected with exit code 1.

## Controlled corrective result

The dataset remains the project-generated controlled synthetic demo. It is a
pipeline fixture, not a public benchmark or research/production performance
claim. Quality and leakage gates passed for 48 rows/24 groups with 28/10/10
train/validation/test rows and 14/5/5 groups.

| Evidence | Affected run | Corrective run |
| --- | --- | --- |
| Candidate | HistGradientBoosting | Random Forest |
| Calibration | sigmoid | isotonic |
| Threshold | 0.5 | 0.5 |
| Validation Macro F1 | 1.0 | 1.0 |
| Validation Brier | 0.1151926 | 0.0 |
| Frozen Accuracy | 0.8 | 0.8 |
| Frozen Macro F1 | 0.7619048 | 0.7619048 |
| Frozen ROC-AUC | 0.6666667 | 0.9583333 |
| Frozen PR-AUC | 0.8333333 | 0.9523810 |
| Frozen Brier | 0.1917839 | 0.1090712 |
| Confusion matrix TN/FP/FN/TP | 2/2/0/6 | 2/2/0/6 |
| Model SHA-256 | `adc950ef…` | `9b403dd2…` |

The selected candidate, calibration, probability-ranking evidence, serialized
model, and checksum changed. The threshold and label-derived frozen metrics did
not. These comparisons must not be used to retune against the test set.

Corrective model artifact SHA-256:
`9b403dd20ca77322983a175980081399414219f3cc6a2ceac7acff0bec3d17a5`.
Corrective selection-record SHA-256:
`31c1421eb3d37b6fd5e204a12483243f91d6c20cdba97b28189e0806da599d91`.

## Data integrity and provenance

- Canonical data SHA-256 remained
  `75c584dbee56cf985864fabeb3d01a0975122276a31c2acbb45b0323c4f885ad`.
- Split manifest SHA-256 remained
  `a2949d3ef88381119616c5c352e39c30c7c98371edc0101614c230e0c7b8a1e0`.
- Corrective dataset-manifest SHA-256 is
  `523026c44c0c1d42473a34df3f3504aa8d03066e5082456d986c872856040294`;
  the manifest changed because it records the corrective Git commit, not because
  canonical rows or split membership changed.
- Provenance states AegisHunt-generated controlled synthetic demo data,
  `Project-internal synthetic research fixture`, no downloaded public benchmark,
  and no implied external dataset license.

## Tests

- Ruff: pass.
- Strict mypy: pass across 96 source files.
- Pytest: 202 passed, 0 failed, 0 skipped, 0 xfailed.
- Branch-aware coverage: 86.90% (minimum 85%).
- Focused Phase 5 suite: 33 passed.
- Phase 4 dataset-integrity suite: 61 passed.
- Zero-Brier calibration/candidate, missing-value, non-finite, deterministic
  selection, original/non-corrective E2E, corrective non-overwrite, one-time
  frozen test, GroupKFold, threshold, bootstrap, independent reload, checksum,
  extra-file, pickle/joblib, path, schema, and corruption checks pass.

## Review outcome

The native `codex review --base main` command could not start because the local
Codex arm64 executable is missing (`ENOENT`). An equivalent first read-only
review found one Medium test-regression issue: the corrective E2E had replaced
the original Phase 5 E2E path. Commit `f93a5b4` restored the original full path
and added a separate corrective audit E2E. Low documentation/test-strength gaps
were addressed in `c152679`. No Blocking or High finding remains.

## Generated artifacts

The corrective run created dataset reports, selection evidence, frozen metrics,
confidence intervals, `selection.skops`, and a four-file model bundle under a
temporary `/tmp` root. No model binary, generated dataset, database, or temporary
report is committed. Independent-process reload produced identical numeric
predictions.

## Known limitations

- The demo is small, synthetic, and not a public benchmark; calibration and
  threshold evidence are unstable and not a final research claim.
- Runtime latency is a late tie-break and may vary by development host load.
- Full-corpus memory/runtime behavior remains unbenchmarked.
- The public benchmark acquisition/conversion remains provisional.
- DEF-004 remains open and non-blocking: total database unavailability cannot
  persist a failure record into that same unavailable database.
- Anomaly detection, fusion, alerts, explanations, correlation, hypotheses, and
  cases are Phase 6+ and absent.

## Version-control checkpoint

- Original Phase 5 branch: `phase/05-supervised-detection`.
- Original PR: [#13](https://github.com/SaXingrui-UM/aegishunt/pull/13), merged
  into `main` as `2510c295f9bf82d90e8c82a072187808651980dc` on 2026-07-16.
- Existing tag: annotated `phase-05-complete`, unchanged at the PR #13 merge
  commit. It was not moved, deleted, overwritten, or recreated.
- Corrective branch: `fix/phase-05-zero-brier-selection`.
- Corrective PR: pending creation; must not be auto-merged.
- Corrective checkpoint/tag: pending user instruction after corrective merge.

## Next phase

Phase 6 — Anomaly Detection is **Not started**. Do not create
`phase/06-anomaly-detection` or implement anomaly/fusion work before the
corrective PR is reviewed and merged and the user authorizes the next step.
