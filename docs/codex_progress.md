# Codex Progress

Last updated: 2026-07-19 (Asia/Shanghai)

## Current state

| Field | Value |
| --- | --- |
| Current phase | Phase 6 - Unsupervised Anomaly Detection Engine |
| Status | Implementation complete — awaiting PR review |
| Phase 6 implementation | Benign-only Isolation Forest and novelty-mode LOF, bounded normalization, validation thresholding, legacy frozen test, ADR 0015 validation-qualified LOF candidate, safe bundles, prediction, CLI, evidence, and tests |
| Current activity | Direction B is implemented on Phase 6 PR [#18](https://github.com/SaXingrui-UM/aegishunt/pull/18); the LOF candidate passed its unchanged smoke gate, and Phase 7 has not started |
| Verification status | Ruff passes; strict mypy passes for 120 source files; all 288 tests pass with 87.34% branch-aware coverage and no skipped/xfailed tests; the full suite includes 83 focused Phase 6 tests |
| Stable branch checkpoint | Phase 6 branch started from synchronized `main` `030e4e2f2bfeb05dc8ca8288afd642c7b8d8f14b`; latest direction-B commits are `265df40`, `32e24ee`, `ca830fd`, `d6552fa`, `0c83a2d`, `d85689b`, and `f03f75f` |
| PM-DEF-001 | Resolved by PR #14; original and corrective evidence remain separately versioned |
| Original Phase 5 merge | `2510c295f9bf82d90e8c82a072187808651980dc` (PR #13) |
| Corrective Phase 5 merge | `76f79972dff778f5d30d550bc6da78583e338fa1` (PR #14) |
| Phase 2 merge commit | `d5e1ba6b4df7614977a0330a4c38a56cec051241` |
| Phase 3 merge commit | `5df43bc6b994f846fd11e2e7221ef55f9b5610aa` |
| Phase 4 implementation merge | `2ecaaae794684fd51aefbcd5f27f9c1eb70eadf0` |
| GitHub remote | `origin` -> `git@github.com:SaXingrui-UM/aegishunt.git` (private) |
| Pull requests | Phase 5 PRs #13–#17 are merged; Phase 6 PR [#18](https://github.com/SaXingrui-UM/aegishunt/pull/18) is open from `phase/06-anomaly-detection` to `main` |
| Metadata PR | [#15](https://github.com/SaXingrui-UM/aegishunt/pull/15) merged into `main` as `a8d2a3ad324b89e3d8b8d703d00e73e82a2e6574` |
| Final status PR | [#16](https://github.com/SaXingrui-UM/aegishunt/pull/16) merged into `main` as `cc3b1ac52d93d786ab5552c4f9be4b08b3408696` |
| CI status | After `d85689b`, the first PR-triggered Linux `quality` run passed while its duplicate push run hit the old 15-minute job limit. With bounded timeout fix `f03f75f`, both updated `quality` checks passed in 15m26s and 15m57s without changing checks or coverage |
| Phase 0 tag | Annotated `phase-00-complete`, unchanged at `097c01a` |
| Phase 1 tag | Annotated `phase-01-complete`, pushed and remotely verified at `a240805` |
| Phase 2 tag | Annotated `phase-02-complete`, pushed and remotely verified at merge commit `d5e1ba6` |
| Phase 3 tag | Annotated `phase-03-complete`, locally and remotely verified at merge commit `5df43bc` |
| Phase 4 tag | Annotated `phase-04-complete`, locally and remotely verified at merge commit `2ecaaae` |
| Phase 5 tags | Historical annotated `phase-05-complete` remains unchanged at `2510c295`; corrective annotated `phase-05-pm-def-001-complete` is remotely verified at `76f79972` |
| Phase 6 tag | `phase-06-complete` is pending user review, PR merge, and an explicit post-merge checkpoint instruction; it has not been created |
| Current branch | `phase/06-anomaly-detection` |
| Working tree | Clean after the direction-B documentation checkpoint commit |
| Phase 7 status | Not started |
| Next planned branch | `phase/07-fusion-evaluation` (must not be created before Phase 6 merge/checkpoint and explicit authorization) |
| Next action | Complete full checks and Review, push the existing Phase 6 branch, update PR #18, then wait for CI and user review; do not begin Phase 7 |

Phase 0 through Phase 5 remain complete. Phase 5's original and corrective Tags
remain unchanged. Phase 6 implementation is isolated on its declared branch and
has not modified frozen Phase 4 splits or Phase 5 model/evidence contracts. Phase
7 fusion, combined risk, alerts, explanations, correlation, and hunting logic
have not started.

## Phase 6 implementation checkpoint

- Phase 4 quality, leakage, checksum, feature-order, label-mapping, frozen-test,
  and group/source/session/scenario isolation remain mandatory before training.
- Only 10 benign rows from 5 Phase 4 training groups fit StandardScaler,
  Isolation Forest, novelty-mode LOF, and each registered normalizer. Eighteen malicious
  training rows are explicitly excluded; validation and test are never fit data.
- The original `1.0.0` experiment selected `iforest-64-full` under policy
  `1.0.0`; its frozen evidence remains immutable. The validation-only corrective
  matrix evaluated 8 fixed Isolation Forest configurations across 3 fixed
  normalizers. Its best eligible candidate had positive validation utility but
  failed the unchanged post-selection SYN-burst smoke decision, so no
  `1.0.1-candidate` bundle was created.
- User-authorized direction B is recorded in ADR 0015 and experiment
  `phase-06-controlled-demo-lof-production-candidate-001`. Policy `2.0.0`
  permits the already-evaluated fixed novelty-mode LOF to compete as a
  production candidate. Because this follows observed validation evidence, it
  is explicitly post-hoc and does not count as independent confirmation.
- Raw sklearn scores are retained, canonical scores reverse direction so higher
  means more anomalous, and normalizer `1.0.0` maps benign-training quantiles to
  `[0,1]`. The normalized score is not probability.
- Direction B selected `lof-novelty-5--benign_training_quantile_cdf`, threshold
  `0.9`, under FPR ceiling `0.25`. Validation Accuracy is `0.6`, Precision
  `1.0`, Recall `0.3333`, F1 `0.5`, Macro F1 `0.5833`, ROC-AUC `0.6667`,
  PR-AUC `0.8083`, benign FPR `0.0`, and confusion `4/0/4/2`.
- The fixed smoke fixture ran only after selection freeze, produced normalized
  score `1.0`, and passed before/after bundle reload. Independent-process reload
  reproduced the same result. The candidate remains `validation_qualified`:
  all 48 registered rows are already assigned and no untouched holdout exists.
- The original viewed test was not opened by either corrective candidate run.
  Formal partition tracking recorded only `train.jsonl` and `validation.jsonl`;
  a repeat of the direction-B experiment identity is rejected.
- Actual controlled validation: Accuracy `0.4`, F1/recall `0.0`, Macro F1
  `0.2857`, ROC-AUC `0.5`, PR-AUC `0.6389`, benign FPR `0.0`, confusion
  `4/0/6/0`. Frozen test: Accuracy `0.4`, F1/recall `0.0`, Macro F1 `0.2857`,
  ROC-AUC `0.0833`, PR-AUC `0.4704`, benign FPR `0.0`, confusion `4/0/6/0`.
  Poor anomaly recall is retained, not used for retuning.
- The direction-B candidate skops checksum is
  `4e2c7e6cb905875285c56d2df820655f386a7cf950ac3fcffdabae47ff8e4bb0`;
  bundle/evidence bytes are ignored and not committed. Exact type validation
  requires LOF `novelty=True` and rejects algorithm/manifest mismatch.
- The four-file skops bundle preserves scaler/estimator, score direction,
  normalizer, threshold, schema, provenance, metrics, environment, and model
  card. It rejects path escape, pickle/joblib, missing/extra/corrupt files,
  unsafe types, schema drift, and version collision. Independent-process scoring
  reproduced raw, canonical, normalized, and decision output exactly.
- The historical `d6ab14b4...` Isolation Forest checksum remains unchanged.
  Neither old experiment evidence nor the old bundle was overwritten.
- The controlled synthetic demo verifies pipeline mechanics only. It is not a
  public benchmark, research/production conclusion, real-world evidence, or
  proof of zero-day detection.
- Five source-backed validation plots and their SHA-256 inventory are generated
  from actual scores/thresholds; they are ignored machine evidence, not invented
  metrics or public-benchmark figures.
- The first equivalent read-only Review found one High selection-integrity gap
  and two Medium threshold/version-collision gaps. Commit `0ad6fb6` added a
  persisted selection checksum, FPR fail-closed behavior, pre-test version
  collision rejection, and three regressions. Native `codex review --base main`
  could not start because its arm64 executable is missing (`ENOENT`); the second
  equivalent review found no remaining Blocking, High, or unhandled Medium issue.
- Final direction-B verification passed Ruff, strict mypy for 120 source files,
  and all 288 tests in 999.93 seconds with 87.34% branch-aware coverage. There
  were no failures, skips, or xfails; 83 Phase 6-focused tests are included.
- The final equivalent read-only review found one Medium audit-contract gap:
  structurally valid metadata could overstate LOF eligibility or alter the fixed
  Isolation Forest comparison matrix. Commit `0c83a2d` added cross-field
  fail-closed contracts and exact-matrix regressions. The complete suite passed
  afterward; zero Blocking, zero High, and zero unhandled Medium findings remain.
- The first Linux CI run passed 287 tests but exposed a one-ULP difference in a
  hard-coded Isolation Forest reference score. Commit `d85689b` retains exact
  local-versus-independent-process comparisons and applies only a strict
  `1e-12` relative/`1e-15` absolute tolerance to the cross-platform reference
  constants. The targeted E2E passed after the test portability correction.
- On the next SHA, the PR-triggered Linux workflow passed fully in 9m44s. The
  duplicate push workflow ran on a slower worker and was canceled at the old
  15-minute job limit while pytest was still running, not because a test failed.
  Commit `f03f75f` raises only that bounded CI timeout to 30 minutes; Ruff, mypy,
  pytest, and the 85% coverage gate remain unchanged.
- Both post-timeout-fix GitHub Actions `quality` runs completed successfully in
  15m26s and 15m57s. The longer successful run confirms that the previous
  cancellation was a timeout configuration problem rather than a test failure.
- The local `.venv` editable `.pth` was not visible to a standalone Python
  process, so the first formal command stopped at import with no artifact writes.
  The recorded `PYTHONPATH=src` workaround then ran successfully; this is not a
  standard-install success claim.
- DEF-004 remains open and non-blocking; Phase 6 adds no alternate database or
  broker merely to record total database unavailability.

## Phase 5 implementation checkpoint

- PM-DEF-001 was reproduced before correction: sigmoid Brier
  `0.19178394648427863` was selected over valid isotonic Brier `0.0` because
  optional numeric evidence used truthiness fallbacks.
- Selection policy `1.0.1` now preserves zero, ranks `None` after every finite
  value, and rejects NaN/Infinity without changing the documented tie-break order.
- Candidate Brier and equivalent CV optional-metric fallbacks use the same typed
  handling; regression tests cover zero, missing, non-finite, and deterministic
  repeated selection.
- The original experiment/model `phase-05-controlled-demo` / `1.0.0` remain
  immutable. Corrective experiment `phase-05-controlled-demo-pm-def-001` and
  model `1.0.1` record PM-DEF-001, the superseded IDs, reason, and code commit.
  New artifact directories refuse overwrite, and a second frozen test still fails.
- Actual corrected controlled run: Random Forest, isotonic calibration, threshold
  `0.5`; validation Macro F1 `1.0`, Brier `0.0`; frozen Macro F1 `0.7619`,
  ROC-AUC `0.9583`, PR-AUC `0.9524`, Brier `0.1091`, confusion matrix 2/2/0/6.
  This is pipeline verification only, not public-benchmark or real-world evidence.
- Compared with the affected run, candidate, calibration, probability metrics,
  model payload, and checksum changed. Threshold, frozen Accuracy/Macro F1, and
  confusion matrix did not. Bundle SHA-256 is
  `9b403dd20ca77322983a175980081399414219f3cc6a2ceac7acff0bec3d17a5`.
- Post-merge verification used isolated temporary roots and did not touch the
  formal frozen-test identity. It reproduced the same candidate, calibration,
  threshold, validation metrics, frozen metrics, confidence intervals, and
  confusion matrix. Independent process reload and deterministic predictions
  passed; repeat frozen evaluation, missing/extra/corrupt files, arbitrary
  joblib, and version collision were rejected.
- The historical `9b403dd2...` model binary was intentionally not committed and
  is no longer present locally, so that particular payload could not be
  re-hashed. Two new isolated skops serializations had different per-artifact
  checksums while each matched its own manifest. The historical checksum remains
  an audit record, not a claimed reproducible-build checksum.
- Controlled-demo provenance explicitly states project-generated synthetic data,
  project-internal fixture status, and no claimed external/public license.
- Post-merge checks on synchronized `main`: Ruff pass; strict mypy pass for 96 source files; 202
  tests pass, zero failures/skips/xfails, 86.90% branch-aware coverage; 33 focused
  Phase 5 tests and 61 Phase 4 dataset-integrity tests pass.
- Final status-closure verification: Ruff pass; strict mypy pass for 96 source
  files; 205 tests pass with zero failures/skips/xfails and 86.90% branch-aware
  coverage; the focused status, frontend, PM-DEF-001 regression, original E2E,
  and corrective E2E selection passed 20 tests.
- Final status PR #16 merged into `main` as
  `cc3b1ac52d93d786ab5552c4f9be4b08b3408696` after its required `quality`
  check passed. It corrected README, Streamlit, and known-defect current-state
  text. The subsequent read-only check identified the remaining stale
  progress/release wording and stale test expectation; this metadata correction
  removes both.
- Native post-merge `codex review --base 2510c295...` remained unavailable
  because the installed arm64 binary is missing (`ENOENT`). Equivalent read-only
  review found zero Blocking, zero High, and zero blocking Medium findings. It
  identified one Low status-truthfulness cluster in README, Streamlit,
  `docs/known_defects.md`, and the PR #15 metadata state; the dedicated final
  status-closure change corrects those current-status representations without
  rewriting historical evidence.
- `phase-05-complete` remains unchanged: annotated Tag object `ff3f9710...`
  dereferences to `2510c295...`. Corrective annotated Tag
  `phase-05-pm-def-001-complete` (object `8ce8e8ad...`) dereferences to the PR #14
  merge `76f79972...`; both local and remote references were verified.
- Phase 6 anomaly detection, fusion, alerts, and related functionality are absent.

### Original merged implementation record

The following records the scope and checks that entered PR #13. Its selection
and frozen-test values are retained for audit but are affected by PM-DEF-001 and
must not be presented as final evidence.

- Enforced Phase 4 file, checksum, schema, label, quality, leakage, conversion,
  frozen-test, group, metadata, and finite-feature gates before fitting.
- Added configured Dummy, Logistic Regression, Decision Tree, Random Forest,
  and HistGradientBoosting candidates with model-specific sklearn pipelines.
- Added train-only deterministic GroupKFold, bounded exhaustive tuning, complete
  candidate/fold/failure evidence, and fixed seeds.
- Added validation-only sigmoid/isotonic calibration, Brier evidence, complete
  threshold curves, full classification metrics, operational timing/size/memory,
  and a versioned selection policy that does not use Accuracy or test metrics as keys.
- Froze an immutable model selection and checksummed selected artifact before an
  explicit one-time frozen test; generated 1,000-draw group-bootstrap intervals.
- Added configured-root skops bundles with exact four-file inventories, outer
  model/manifest/model-card checksums, exact type allowlists, fixed
  schema/order/dtype, preprocessing, calibration, threshold, provenance,
  metrics, environment, and model card. Pickle/joblib, path escape, extra files,
  corruption, schema drift, empty/non-finite input, and version collisions fail closed.
- Added Typer model train/test/list/describe/predict/verify commands and a
  truthful Phase 5 Streamlit shell without invented metrics.
- The affected PR #13 run used the controlled demo only: 48 rows/24 groups,
  train/validation/test 28/10/10 rows and 14/5/5 groups, quality/leakage pass.
  It selected HistGradientBoosting from validation evidence with sigmoid
  calibration and threshold 0.5. This is pipeline verification only.
- Controlled validation Macro F1 was 1.0; frozen-test Macro F1 was 0.7619 with
  confusion matrix 2/2/0/6 and wide group-bootstrap intervals. These values are
  not public-benchmark, research, production, or real-world conclusions.
- PR #13 pre-merge checks: Ruff pass; strict mypy pass for 95 source files; 197
  pytest tests passed, zero failures/skips/xfails, 86.88% branch-aware coverage;
  the 44-test focused Phase 5 suite also passed.
- Independent-process reload, repeated numeric predictions, checksum/type/path
  rejection, one-time test refusal, no-root/no-network operation, and absence of
  Phase 6 anomaly/fusion/alert functionality are tested.
- The affected machine reports and 639,387-byte controlled model bundle were
  generated under temporary ignored storage and are not committed. The reviewed
  protocol, ADR, release notes, and model card are committed.
- First read-only review found one High bundle-integrity gap, two Medium
  evidence/test gaps, and one Low inventory gap. Commit `d4cd57f` fixed them;
  the targeted post-fix run passed Ruff, mypy for 21 supervised source files,
  and 15 tests. The final full suite passed, and the second review found no
  remaining Blocking, High, or unhandled Medium issue.
- DEF-004 remains open and non-blocking: a total database outage cannot write a
  failure record into that same unavailable database. Phase 5 adds no broker.

## Phase 4 implementation checkpoint

- Added strict public/controlled dataset definitions, versioned label mappings,
  safe acquisition/manual verification, SHA-256, and bounded archive extraction.
- Selected CSE-CIC-IDS2018 as the conditional primary benchmark from official
  evidence; no public dataset was downloaded, mirrored, or fabricated.
- Added canonical metadata/ordered-feature/label contracts bound to unchanged
  Phase 3 feature schema `1.0.0`, deterministic JSONL, and exact CSV conversion.
- Added a fixed-seed offline controlled demo with eight documented behavior
  patterns produced through the real Phase 3 feature engine.
- Added missingness, duplicate/near-duplicate, class, range, constant-feature,
  and formal leakage analysis plus group-exclusive frozen splits.
- Added deterministic dataset/split manifests, quality/leakage JSON,
  class-distribution and feature-statistics CSV, Typer commands, and EDA notebook.
- Manual demo verification: 48 rows, 24 groups, quality pass, leakage pass,
  zero exact/feature/near duplicates, and 28/10/10 train/validation/test rows.
- Post-fix checks: Ruff pass; strict mypy pass for 73 source files; 169 pytest
  tests passed with 0 failures/skips/xfails and 88.06% branch-aware coverage.
- Focused Phase 4 suite: 61 passed; two fixed-seed offline rebuilds were
  byte-identical. Controlled split counts are 28/10/10 rows and 14/5/5 groups.
- The current Codex/macOS runtime skips virtual-environment `.pth` files marked
  hidden, so standalone editable console verification required `PYTHONPATH=src`;
  this workaround is not recorded as a standard-install pass.
- First read-only review identified provenance, registry conversion/version,
  label mapping, strict-type, duplicate-ID, checksum, non-overwrite, and output
  preflight gaps. Commit `9b0bdef` fixed them with regression coverage.
- Second review identified manifest date/checksum validation and provisional
  status evidence gaps; commit `4d63cd7` fixed them. The third read-only review
  found no remaining Blocking, High, or unhandled Medium findings.
- No public network, root, live capture, external target, database migration,
  Phase 3 schema change, model, model metric, anomaly detector, fusion, alert, or
  hypothesis functionality was introduced.
- DEF-004 remains open and non-blocking; Phase 4 does not add an alternate queue
  or database merely to record a total database outage.
- Post-merge verification on synchronized `main` repeated Ruff, strict mypy,
  all 169 tests, the 61-test Phase 4 suite, and two independent offline demo
  builds. The builds were byte-identical, quality/leakage passed, all split
  overlap counts were zero, and the canonical checksum remained
  `75c584dbee56cf985864fabeb3d01a0975122276a31c2acbb45b0323c4f885ad`.
- PR #11 was merged on 2026-07-16 with both GitHub Actions `quality` checks
  successful. Annotated tag `phase-04-complete` points to the merged `main`
  commit `2ecaaae794684fd51aefbcd5f27f9c1eb70eadf0`.

## Phase 3 implementation checkpoint

- Added bounded classic PCAP/supported PCAPNG reading and payload-independent
  IPv4/IPv6 TCP, UDP, ICMP, and ICMPv6 packet parsing.
- Added canonical bidirectional keys, first-packet forward direction, bounded
  directional state, active/idle/capacity segmentation, and idempotent flush.
- Added deterministic finite volume, size, timing, TCP evidence, and basic
  single-flow behavioral features in fixed schema `1.0.0` (43 features).
- Added deterministic `artifacts/feature_schema.json`, feature dictionary, and
  ADR 0011 for direction, timeout, time-order, division, schema, and transaction semantics.
- Integrated complete PCAP flow sets with existing repositories/audit records in
  the same transaction as ingestion completion; malformed packets leave no partial flows.
- Final local checks: Ruff pass; strict mypy pass for 57 source files; 108 pytest
  tests passed with 0 failures/skips/xfails and 87.83% branch-aware coverage.
- Focused Phase 3 runs: 25 parser/aggregation/feature tests and 7 integration/E2E tests passed.
- Deterministic schema export matched the committed artifact byte-for-byte; SHA-256
  is `11e6deb54239408157accc5e94858cbb06d072148cd553a3f4951ea6d538cbfa`.
- Native `codex review --base main` could not launch because its packaged arm64
  executable is missing (`ENOENT`). The equivalent read-only manual review found
  no Blocking/High issue. One Medium UDP-test gap and one Low report-count error
  were fixed in `242e1f3`, then all checks were rerun.
- DEF-004 remains open and non-blocking: a complete database outage cannot write
  its own failure record into that same unavailable database. Phase 3 introduces
  no alternate queue/database dependency.
- Cross-flow history/window features are deferred explicitly; Phase 4 datasets,
  model training/inference, detections, alerts, correlation, and hypotheses are absent.
- Post-merge verification repeated Ruff, strict mypy, and all 108 tests on
  synchronized `main`; results and coverage remained unchanged.

## Phase 0–2 integration verification

- Verified annotated tags `phase-00-complete`, `phase-01-complete`, and
  `phase-02-complete` at their merged `main` commits without modifying them.
- Verified a fresh Python 3.11 editable installation with `PYTHONPATH` unset.
- Re-ran the 72-test integration baseline in both the project environment and a
  second clean clone, then passed the final 75-test pre-Phase 3 suite at 91.97%
  branch-aware coverage in the project environment.
- Added durable configuration/database/repository, cross-phase E2E, ingestion
  security, persistence/restart, and five-job concurrency verification.
- Found and fixed two High defects: JSONL staging lost its suffix, and database
  credentials appeared in settings representations. Both have regression tests.
- Resolved DEF-003 by adding non-initializing, sanitized configuration/database
  diagnostics to `doctor`, including safe unavailable-database behavior.
- Resolved DEF-005 by recording Phase 2 as complete on `main` and Phase 3 as not started.
- Kept DEF-004 Medium/Open: a complete database outage returns fixed HTTP 503,
  rolls back, and emits a sanitized log, but cannot write a failure record into
  that same unavailable database. It is explicitly non-blocking for Phase 3.
- Produced the report, test matrix, requirement traceability, environment record,
  and defect register under `reports/integration/phase-00-02/`.
- Final verdict: `CONDITIONALLY READY`; no Blocking or open High defect remains.
- Confirmed ingestion still creates zero `NetworkFlow` rows and implements no
  packet-to-flow conversion, feature extraction, or other Phase 3 functionality.

## Phase 2 completed work

- Added validated ingestion roots, upload byte/chunk limits, and record limits.
- Added a common typed ingestor interface and explicit source-type registry.
- Added PCAP/PCAPNG container inspection without packet decoding or flow derivation.
- Added canonical flow-CSV validation without persisting `NetworkFlow` records.
- Added structured JSON/JSON Lines event validation with non-finite-value rejection.
- Added traversal-resistant bounded staging, SHA-256 addressing, integrity-checked
  deduplication, atomic storage, and deterministic cleanup.
- Reused `TelemetrySource` for audited pending/running/completed/failed jobs with
  progress, records, checksum, storage metadata, format metadata, and safe errors.
- Added checksum-verified sample registry plus deterministic synthetic PCAP and CSV inputs.
- Added Typer ingestion commands and FastAPI upload, sample, list, and status endpoints.
- Added unit, integration, E2E, CLI, API, repository, frontend, and reproducibility checks.
- Confirmed no packet-to-flow processing, features, replay, ML, detections, or Phase 3 work.

## Phase 2 commands executed

| Command or check | Result |
| --- | --- |
| Read progress, AGENTS rules, relevant Roadmap/Project Plan pages, and existing Phase 1 code/tests | Completed |
| Baseline `ruff check .`, `mypy src`, and `pytest` on synchronized `main` | Exit 0; 26 passed, 94.92% coverage |
| `git checkout -b phase/02-telemetry-ingestion` | Exit 0 from clean `main` at `b501189` |
| `.venv/bin/python -m pip install -e ".[dev]"` | Exit 0; installed `python-multipart` and editable package |
| Iterative Ruff, strict mypy, targeted pytest, and full pytest runs | Failures were corrected and rerun; none hidden |
| Final `.venv/bin/ruff check .` | Exit 0 |
| Final `.venv/bin/mypy src` | Exit 0; 46 source files |
| Final `.venv/bin/pytest` | Exit 0; 45 passed, 90.34% branch-aware coverage |
| Generate PCAP twice, `cmp`, and SHA-256 verification | Exit 0; deterministic digest `84aa8524...f2e9a` |
| Bare `.venv/bin/aegishunt --help` | Exit 1 due to the previously recorded hidden editable `.pth` runtime issue |
| CLI help, doctor, PCAP, CSV, sample, and expected-failure checks with `PYTHONPATH=src` | Passed; invalid suffix returned exit 1 safely |
| SQLite inspection after manual ingestion | 3 completed jobs, 12 audit events, 0 flows, 2 deduplicated stored files |
| Live FastAPI `/health`, sample list, and PCAP upload on loopback | HTTP 200, 200, and 201; server stopped cleanly |
| Live Streamlit health and root on loopback | `ok` and HTTP 200; server stopped cleanly |
| Temporary databases, uploads, and regenerated PCAP | Removed after verification |
| `gh pr view 5` and `gh pr checks 5` after merge | PR #5 confirmed `MERGED`; two `quality` checks passed |
| `git checkout main` and `git pull --ff-only origin main` | Exit 0; fast-forwarded to merge commit `d5e1ba6` with a clean tree |
| Phase 2 code, tests, samples, documentation, and Phase 3 scope audit on merged `main` | Completed; Phase 2 ingestion boundary present and no Phase 3 implementation found |
| Local and remote `phase-02-complete` absence checks | Confirmed absent before creation |
| Create, push, and verify annotated `phase-02-complete` | Exit 0; local and remote peeled target equals `d5e1ba6` |

## Phase 2 tests

- 45 tests passed with 90.34% branch-aware coverage; configured minimum is 85%.
- Ruff passes and strict mypy passes for 46 source files.
- Tests cover traversal, type/size limits, checksum integrity and deduplication,
  PCAP and PCAPNG framing, CSV schema/non-finite values, JSON structure, sample
  checksum failures, durable success/failure jobs, audit events, zero flow writes,
  API upload/status/failure/sample behavior, CLI failures, and configuration.

## Phase 2 architecture decisions

- ADR 0010 reuses `TelemetrySource` as the durable job record instead of adding
  duplicate provenance columns and a premature migration.
- Adapters validate container/contract boundaries only; Phase 3 owns packet-to-flow work.
- Client names are metadata only; committed storage names derive from SHA-256.
- Controlled samples require manifest allowlisting and checksum verification.
- Synchronous service semantics are stable for a later Phase 11 worker implementation.

## Phase 2 generated artifacts

The branch intentionally contains a reviewed 114-byte synthetic PCAP, a two-row
synthetic flow CSV, their manifest/checksums, and the deterministic PCAP generator.
No runtime database, uploaded telemetry, model, evaluation, metric, or captured
operational traffic is committed.

The structured JSON adapter is covered with controlled temporary JSON and JSONL
test fixtures. The packaged sample manifest itself intentionally contains only
the reviewed PCAP and CSV fixtures; it does not contain a third JSON sample file.

## Phase 2 known limitations and risks

- PCAP inspection validates framing and counts only; it does not decode packets.
- CSV validation does not persist canonical flows; Phase 3 owns that transaction.
- Jobs execute synchronously; worker scheduling, replay, pause/resume, and recovery are later phases.
- API authentication/authorization is not yet implemented; default listeners remain loopback.
- The committed PCAPNG support accepts one section; multi-section files fail explicitly.
- The packaged sample catalog contains PCAP and CSV fixtures; JSON ingestion is
  validated by controlled tests but has no committed manifest sample.
- Large uploads within configured limits occupy one request worker until runtime orchestration.
- The Codex macOS runtime still hides editable-install `.pth` files; manual commands
  used `PYTHONPATH=src`, while pytest and standard CI use the declared source layout.
- No performance, detection, or model-quality result is claimed.

## Phase 2 review status

The first read-only review against `main` covered correctness, security, roadmap
scope, tests, typing, errors, data integrity, API/filesystem safety, secrets, and
oversized artifacts. It found one high-severity denial-of-service risk: forged
PCAP/PCAPNG length fields were passed to one-shot reads. Commit `20c1fd7` consumes
declared payload lengths in bounded chunks and adds a forged 4 GiB-length
regression fixture. Ruff, strict mypy, and all 45 tests pass after the fix at
90.34% coverage. The second read-only review found no remaining blocking or
high-severity finding.

The installed Codex CLI review command could not start because its packaged
native executable is missing (`ENOENT`); the full diff review and repository
safety scans were completed manually under the same required criteria. PR #5 was
squash-merged as `d5e1ba6`, and annotated tag `phase-02-complete` points to that
merged `main` commit. No Phase 3 branch or Phase 3 implementation exists.

## Phase 0 checkpoint

- PR #1 delivered the foundation and was squash-merged as `097c01a`.
- Annotated tag `phase-00-complete` was pushed and verified at that merge commit.
- PR #2 recorded post-merge metadata and was merged as `b3d6b19`.
- Final Phase 0 tests were 11 passed with 97.06% branch-aware coverage.

## Phase 1 completed work

- Implemented safe YAML loading with `AEGISHUNT_*` environment-variable overrides.
- Added strict immutable Pydantic schemas for all Project Plan core entities.
- Added SQLAlchemy 2.x records with explicit UUIDs, UTC timestamps, enums, JSON evidence, indexes, and foreign keys.
- Added repeatable SQLite initialization with WAL, foreign keys, bounded busy timeout, and explicit schema version `1`.
- Refused incompatible or non-empty unversioned databases without destructive mutation.
- Added typed add/get/list repositories and same-transaction append-only audit events.
- Added `aegishunt init-db --config ...` with safe structured output and non-zero expected failure handling.
- Initialized empty databases during FastAPI lifespan and exposed ready/schema state through `/health`.
- Updated the Streamlit shell to report only truthful Phase 1 foundation status.
- Added schema, database, repository, CLI, API, frontend, and configuration tests.
- Confirmed no ingestion, PCAP parsing, flow construction, features, datasets, ML, detection workflow, correlation, hypothesis generation, or case service was implemented.

## Phase 1 files created

- Configuration: `configs/application.yaml`.
- Errors and schemas: `src/aegishunt/errors.py`, `src/aegishunt/schemas/`.
- Storage: `src/aegishunt/storage/` and typed repositories.
- Tests: `tests/unit/test_schemas.py`, `tests/unit/test_database.py`, and `tests/integration/test_repositories.py`.
- Documentation: `docs/data_model.md`, ADR 0009, and `docs/releases/phase-01.md`.

## Phase 1 files modified

- `pyproject.toml`, `.env.example`, `Makefile`, and configuration documentation.
- CLI, FastAPI application, Streamlit shell, README, and architecture documentation.
- Existing configuration, CLI, API, and frontend tests.

## Phase 1 commands executed

| Command or check | Result |
| --- | --- |
| Read `docs/codex_progress.md`, `AGENTS.md`, Phase 1 PDF pages, architecture, requirements, and existing code | Completed |
| Verify PR #2 and CI | Merged; remote `quality` check passed |
| `git checkout main` and `git pull --ff-only origin main` | Exit 0; updated to `b3d6b19` |
| Baseline Ruff and mypy | Exit 0 |
| Baseline pytest | Initial desktop-runtime import failure; `PYTHONPATH=src` rerun exit 0, 11 passed, 97.06% coverage |
| `git checkout -b phase/01-data-foundation` | Exit 0 |
| `python -m pip install -e ".[dev]"` | Exit 0; installed SQLAlchemy and PyYAML typing support |
| Initial Phase 1 Ruff/mypy/test cycles | Found and fixed formatting, typing, and local environment issues; no failures hidden |
| Final `.venv/bin/ruff check .` | Exit 0 |
| Final `.venv/bin/mypy src` | Exit 0; 32 source files |
| Final `.venv/bin/pytest` | Exit 0; 26 passed, 94.92% branch-aware coverage |
| Repeat `init-db` twice on a temporary SQLite database | Both exit 0; WAL, schema version `1`, and 11 tables verified |
| Live FastAPI `/health` and `/docs` on loopback | Both HTTP 200; database ready and schema version `1` |
| Live Streamlit health and root on loopback | Health `ok`; root HTTP 200; process stopped manually |
| Bare CLI after editable reinstall in the Codex macOS runtime | Failed when the runtime repeatedly restored the hidden flag on the editable `.pth`; failure was not treated as a product success |
| CLI/API/Streamlit manual rerun with explicit `PYTHONPATH=src` | Passed; this bypassed only the runtime-specific hidden-file behavior |
| `gh pr checks 3 --watch --interval 10` at `2acd246` | Exit 0; two `quality` checks passed, zero failed or pending |
| `git checkout main` and `git pull --ff-only origin main` after PR #3 | Exit 0; fast-forwarded to merge commit `a240805` |
| Phase 1 deliverable and PR #3 verification | Required configuration, schemas, storage, CLI, and tests present; PR state `MERGED` with two successful checks |
| Local and remote `phase-01-complete` absence checks | Confirmed absent before creation |
| `git tag -a phase-01-complete -m "AegisHunt Phase 1 complete: configuration, schemas, and database foundation"` | Exit 0; annotated Tag targets `a240805` |
| `git push origin phase-01-complete` and local/remote verification | Exit 0; remote peeled Tag target equals current `main` at `a240805` |
| Temporary PDF renders and SQLite databases | Removed after verification |

## Phase 1 tests

- 26 tests passed: 25 unit/smoke tests and one repository integration test.
- Branch-aware coverage: 94.92% (required minimum 85%).
- Ruff passes.
- Strict mypy passes for 32 source files.
- Tests cover configuration precedence/failures, schema validation, repeatable initialization, WAL, version mismatch, unversioned-database refusal, all core repository round trips, audit events, CLI, API startup, and frontend truthfulness.

## Phase 1 architecture decisions

- Configuration precedence is defaults, YAML, then environment overrides.
- Pydantic domain contracts remain separate from SQLAlchemy records.
- Repositories own persistence operations; business modules do not construct SQL.
- Audit events share the entity-write transaction so rollback preserves truthfulness.
- SQLite integrity pragmas are configured at connection creation.
- ADR 0009 uses explicit version `1` now and requires a migration decision before any schema-changing release.
- Pytest declares the `src` path so tests do not depend on platform-specific editable `.pth` handling.

## Phase 1 generated artifacts

No database, dataset, PCAP, model, evaluation result, or fabricated record was
committed. Manual verification used temporary SQLite files under ignored `tmp/`
and removed them after inspection. Coverage output remains ignored.

## Phase 1 known limitations and risks

- Phase 1 provides contracts and storage only; later services must enforce workflow-specific references and transitions.
- Schema versioning detects incompatibility but does not yet perform upgrades.
- SQLite is tested; PostgreSQL portability is not demonstrated.
- JSON evidence/reference fields trade relational constraints for planned schema evolution.
- Concurrent SQLite load and migration behavior require later hardening tests.
- This Codex macOS runtime repeatedly hides editable-install `.pth` files; local
  manual commands required `PYTHONPATH=src`, while pytest's declared `pythonpath`
  and standard GitHub runners do not depend on that hidden-file state.
- No performance result is claimed.

## Phase 1 review outcome

The first read-only review covered correctness, security, requirements, tests,
typing, error handling, data integrity, API/filesystem safety, secrets, oversized
files, scope creep, and documentation accuracy. It found one acceptance-level
test gap: repository reads occurred in the writing Session and could use its
identity map. The fix verifies every entity and audit record after commit in a
new Session. Two low-risk findings also clarified ORM registration and recorded
the local editable-install limitation. Dedicated fix commit `e04234d` passes
Ruff, strict mypy, and all 26 tests at 94.92% coverage. The second review found
no remaining blocking or high-severity issue.

## Phase 1 next-phase record

At the Phase 1 checkpoint, Phase 2 had not started. The user subsequently
authorized it, and the work is tracked above. This historical section does not
authorize Phase 3.
