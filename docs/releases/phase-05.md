# Phase 05 Release Notes

## Objective and status

Deliver the validation-frozen supervised detection engine, then correct
PM-DEF-001 without erasing its historical evidence or weakening frozen-test
protection.

Status: **Phase complete — corrected by PR #14**. Original PR #13 and corrective
PR #14 are merged into `main`. The separately named corrective checkpoint Tag is
pushed. Phase 6 has not started.

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

Severity: **High**. The issue was discovered after original PR #13 and its
historical checkpoint. It affected calibration and candidate-ranking evidence:
the implementation confused a valid zero-valued probability metric with missing
evidence. It did not justify changing the primary metric, tie-break order, or
train/validation/test boundary.

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
- Corrective PR #14 merged as
  `76f79972dff778f5d30d550bc6da78583e338fa1`; isolated post-merge evidence binds
  its correction metadata to that exact merged commit.

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

The historical model checksum identifies the formal temporary corrective
artifact generated before PR merge. Its binary was correctly not committed and
is no longer present locally, so this checkpoint did not claim a direct re-hash
of that specific payload. Two isolated post-merge rebuilds produced different
skops payload hashes, but each matched its own manifest, loaded in an independent
process, and produced deterministic predictions and identical selection/evaluation
evidence. Bundle SHA-256 is therefore an integrity value for one generated
artifact, not a reproducible-build identifier.

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
- Post-merge isolated checks also rejected missing bundle files, model-version
  collision, and a repeated corrective frozen evaluation without modifying any
  formal experiment record.
- GitHub Actions PR #14 required `quality` check passed in 3m21s; no pending or
  failing required check remained.

## Review outcome

Before PR #14, the native `codex review --base main` command could not start
because the local Codex arm64 executable was missing (`ENOENT`). Equivalent
review found one Medium regression gap; commit `f93a5b4` restored the original
E2E and retained a separate corrective audit E2E. Post-merge native review
against `2510c295...` failed with the same `ENOENT`; the equivalent read-only
review found zero Blocking, zero High, and zero blocking Medium findings. One
Low truthfulness finding remains because README, Streamlit, and
`docs/known_defects.md` still carry pre-merge status wording; those files were
outside this task's explicitly limited two-file metadata branch.

## Generated artifacts

The corrective run created dataset reports, selection evidence, frozen metrics,
confidence intervals, `selection.skops`, and a four-file model bundle under a
temporary `/tmp` root. No model binary, generated dataset, database, or temporary
report is committed. Independent-process reload produced identical numeric
predictions.

Post-merge verification created only isolated `/tmp` evidence and bundles and
removed them automatically. No formal frozen-test record was rerun or overwritten.

## Known limitations

- The demo is small, synthetic, and not a public benchmark; calibration and
  threshold evidence are unstable and not a final research claim.
- Runtime latency is a late tie-break and may vary by development host load.
- Full-corpus memory/runtime behavior remains unbenchmarked.
- The public benchmark acquisition/conversion remains provisional.
- DEF-004 remains open and non-blocking: total database unavailability cannot
  persist a failure record into that same unavailable database.
- The historical formal corrective bundle binary is not retained in Git; its
  recorded `9b403dd2...` checksum cannot be re-verified without the original
  external/temporary artifact. Current isolated bundles pass their own complete
  checksum inventories.
- README, Streamlit, and `docs/known_defects.md` retain stale pre-merge status
  text. This is a Low documentation issue and not a model, evidence, or bundle
  integrity failure; no out-of-scope file was changed during this metadata task.
- Anomaly detection, fusion, alerts, explanations, correlation, hypotheses, and
  cases are Phase 6+ and absent.

## Version-control checkpoint

- Original Phase 5 branch: `phase/05-supervised-detection`.
- Original PR: [#13](https://github.com/SaXingrui-UM/aegishunt/pull/13), merged
  into `main` as `2510c295f9bf82d90e8c82a072187808651980dc` on 2026-07-16.
- Existing tag: annotated `phase-05-complete`, unchanged at the PR #13 merge
  commit `2510c295f9bf82d90e8c82a072187808651980dc`; Tag object
  `ff3f9710d9447884c50b8c1488ee90820eb4b964`. Local and remote references match.
- Corrective branch: `fix/phase-05-zero-brier-selection`.
- Corrective PR: [#14](https://github.com/SaXingrui-UM/aegishunt/pull/14),
  `[Phase 05] Fix zero-Brier model selection`, merged from
  `fix/phase-05-zero-brier-selection` into `main` on 2026-07-16 19:43:20 +08:00
  as `76f79972dff778f5d30d550bc6da78583e338fa1`; required CI passed.
- Corrective checkpoint: annotated `phase-05-pm-def-001-complete`, Tag object
  `8ce8e8ad91a72a945bed3d71569ba42c28e1891b`, locally and remotely verified at
  the PR #14 merged `main` commit `76f79972dff778f5d30d550bc6da78583e338fa1`.
- `phase-05-complete` remains an immutable historical pre-corrective checkpoint.

## Next phase

Phase 6 — Anomaly Detection is **Not started**. Do not create
`phase/06-anomaly-detection` or implement anomaly/fusion work. First review and
merge the post-merge metadata PR, resynchronize clean `main`, and then wait for
explicit user authorization in a separate task.
