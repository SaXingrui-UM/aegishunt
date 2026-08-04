# Codex Progress

Last updated: 2026-08-04 (Asia/Shanghai)

## Current state

| Field | Value |
| --- | --- |
| Current phase | Phase 14 - Final Delivery, Deployment, Documentation, and Thesis Materials |
| Status | Phase complete |
| Phase 8 implementation | Existing DetectionResult/SecurityAlert entities extended with complete score and identity evidence; configured risk/severity; threshold alerts; benign references; native/permutation importance; local reference replacement; reason catalog; immutable evidence; audited alert verdict; schema v2 migration; CLI; integration/E2E; truthful status shell |
| Phase 9 implementation | Checksummed correlation policy; canonical entity/event-time index; separate injectable-clock lifecycle time; seven versioned rules; bounded scoring and stable groups; deterministic cautious templates; possible ATT&CK mappings; non-executed queries; schema v3 migration; repositories/audit; CLI; tests and documentation |
| Phase 10 implementation | Deterministic hypothesis-to-case conversion; audited lifecycle, priority, assignment, notes, typed evidence, verdicts and alert feedback; versioned feedback export; explicit provenance-gated retraining candidates; deterministic reports; schema v4 migration; CLI; tests and documentation |
| Phase 11 implementation | Strict runtime policy; source/artifact preflight and pinning; schema v5 durable job/attempt/worker/resource/ledger records; atomic claims and leases; explicit origin recovery; interruptible event-time replay; separate non-durable observed replay telemetry and durable committed evidence progress; Phase 3 flow reuse; transactional detection/alert ledgers; bounded resource status; CLI; Streamlit status shell; tests and documentation |
| Phase 12 implementation | Complete typed FastAPI boundary; bounded pagination/filtering; request IDs and sanitized errors; streamed secure uploads; explicit audited mutations; API-only typed Streamlit client; nine modular pages; isolated controlled sample artifacts; real PCAP-to-case demo; tests and documentation |
| Phase 13 implementation | Raw pre-multipart body limits; incremental bounded JSON/JSONL; bounded PCAPNG interfaces; deadline-indexed flow expiry; exact near-duplicate components; controlled-generator equivalence; verified fusion identities; reason-catalog enforcement; repository 85% and per-package 80% coverage gates; performance protocol 1.1; 21-scenario robustness matrix; real dependency/secret/Bandit gates; complete 80-finding disposition ledger |
| Phase 14 implementation | Application version `1.0.0`; wheel/sdist; verified external Python 3.11/3.12 clean installs; non-root local Docker/Compose contract; payload-free final PCAP derivatives; exact release manifest/builder; full persisted demo/restart verification; source-backed figures/tables; install/deployment/demo/thesis/traceability/acceptance materials; final delivery tests and CI Gates |
| Current activity | The canonical Phase 14 merge and annotated `phase-14-complete` Tag remain unchanged. One authorized bounded mentor-demo corrective is implemented on `codex/frontend-demo-polish`; it is not Phase 15 and does not alter model, threshold, fusion/risk policy, or historical evidence semantics. The formal final Codex Security rescan remains explicitly waived and was not executed |
| Corrective status | Implementation complete — awaiting PR review |
| Verification status | Merged-main Ruff passed; strict mypy passed 239 source files; all 550 pytest tests passed with 0 failed/skipped/xfailed at 85.83% branch-aware coverage; every one of the 17 declared core packages exceeds 80%. External Python 3.11 and 3.12 wheel installs passed without editable mode or `PYTHONPATH`. Wheel/sdist, Twine metadata, exact distribution inventory, documentation delivery, and release-bundle verification passed. Security, robustness, and performance gates passed; they are complementary controls rather than a formal Codex Security rescan. A fresh local arm64 no-cache Docker build passed after an initial historical Docker Hub metadata timeout. The final non-root/read-only Compose run passed health/OpenAPI/Streamlit, `doctor`, a 1,017-packet/42-flow controlled demo, 42 alerts, one group, one hypothesis, case/note/verdict/feedback, restart persistence, schema v5/WAL, and SQLite integrity `ok`. Matplotlib now uses explicit writable `/tmp/matplotlib`; no read-only-home warning remains. Corrective verification passed Ruff, strict mypy for 239 source files, and all 554 pytest tests with 0 failures at 85.87% branch-aware coverage. Base-Compose no-cache build and final-image rebuild passed; API/frontend health, Streamlit production controls, writable bounded HOME, non-root/read-only hardening, and clean logs were verified. The real Browser sequence Overview → Model Lab → Evaluation → Overview → Model Lab passed without stale page content, duplicate disclaimer, fresh console errors, or 1280 px horizontal overflow; evidence screenshots are 1280×720. Larger desktop layouts remain covered by the same responsive grid rules but were not separately screenshot-emulated |
| Phase 13 canonical implementation merge commit | `38e5b8b905aba50ff9acfc7f84f850f03eb3f2f3`; PR #39 final source-branch Head is separately recorded as `5b183a53d76aaa72807200e6d54793e9c0a4fcda` |
| PM-DEF-001 | Resolved by PR #14; original and corrective evidence remain separately versioned |
| Original Phase 5 merge | `2510c295f9bf82d90e8c82a072187808651980dc` (PR #13) |
| Corrective Phase 5 merge | `76f79972dff778f5d30d550bc6da78583e338fa1` (PR #14) |
| Phase 2 merge commit | `d5e1ba6b4df7614977a0330a4c38a56cec051241` |
| Phase 3 merge commit | `5df43bc6b994f846fd11e2e7221ef55f9b5610aa` |
| Phase 4 implementation merge | `2ecaaae794684fd51aefbcd5f27f9c1eb70eadf0` |
| GitHub remote | `origin` -> `git@github.com:SaXingrui-UM/aegishunt.git` (private) |
| Pull requests | Phase 5 PRs #13–#17, Phase 6 PRs #18–#20, Phase 7 PRs #21–#24, Phase 8 PRs #25–#27, Phase 9 PRs #28–#29, Phase 10 PR #31, Phase 11 PR #33, Phase 12 PR #35, validation PR #37, corrective PR #38, Phase 13 PR #39, and Phase 14 PR [#41](https://github.com/SaXingrui-UM/aegishunt/pull/41) are merged |
| Phase 9 closure PR | [#29](https://github.com/SaXingrui-UM/aegishunt/pull/29), `[Docs] Record Phase 9 post-merge checkpoint`, merged into `main` as `8e18ae97d9710813a782182eebcfc55d0edcfed8` |
| Metadata PR | [#15](https://github.com/SaXingrui-UM/aegishunt/pull/15) merged into `main` as `a8d2a3ad324b89e3d8b8d703d00e73e82a2e6574` |
| Final status PR | [#16](https://github.com/SaXingrui-UM/aegishunt/pull/16) merged into `main` as `cc3b1ac52d93d786ab5552c4f9be4b08b3408696` |
| CI status | All 18 PR #41 implementation-Head checks passed: `quality`, `security`, `robustness`, `performance-smoke`, `package`, Python 3.11/3.12 `clean-install`, `docker`, and `docs-delivery`, each on both push and pull-request runs. The sole checkpoint PR must pass the same required workflow on its own exact final Head before review |
| Phase 0 tag | Annotated `phase-00-complete`, unchanged at `097c01a` |
| Phase 1 tag | Annotated `phase-01-complete`, pushed and remotely verified at `a240805` |
| Phase 2 tag | Annotated `phase-02-complete`, pushed and remotely verified at merge commit `d5e1ba6` |
| Phase 3 tag | Annotated `phase-03-complete`, locally and remotely verified at merge commit `5df43bc` |
| Phase 4 tag | Annotated `phase-04-complete`, locally and remotely verified at merge commit `2ecaaae` |
| Phase 5 tags | Historical annotated `phase-05-complete` remains unchanged at `2510c295`; corrective annotated `phase-05-pm-def-001-complete` is remotely verified at `76f79972` |
| Phase 6 tag | Annotated `phase-06-complete` (`908095a1e62d02f55eecb28034f5a26a2cd303e2`) is pushed and remotely verified at merged `main` `40692d0f576b70fd57719ca2f74d869e27891e13` |
| Phase 7 tag | Annotated `phase-07-complete` (`b3e7059250562b140d4c119e7cee5460e3c8e7d9`) is pushed and remotely verified at merged `main` `2465f8de67be7638670f9d30c1198ff76a60d17c` |
| Phase 8 tag | Annotated `phase-08-complete` (`239463ce855327d9896cda7640b6eda2895be4bf`) is pushed and locally/remotely verified at merged `main` `f622faec6513a9fadcba11b73d2fbe1239779217` |
| Phase 9 tag | Annotated `phase-09-complete` (`e5b39861c23e15f887cf9d4a586d0dcda5d93d1e`) is pushed and locally/remotely verified at merged `main` `ffdd7639b60d944b19d70096e1ff38de0d8761f8` |
| Phase 10 tag | Annotated `phase-10-complete` peels to the PR #31 merge commit `ba40211a374aa8e4efa62702a83d063f9eb88039` and is pushed for remote verification |
| Phase 11 tag | Annotated `phase-11-complete` peels to the PR #33 merge commit `8f85949406e3db7d2fa2b3c48d04e832e84f3559` and is pushed for remote verification |
| Phase 12 tag | Annotated `phase-12-complete` peels to the PR #35 merge commit `baac8e5ecf9f8a2ac66afe2873269bebcbbcbf17` and is pushed for remote verification |
| Phase 13 tag | Annotated `phase-13-complete` peels to the PR #39 canonical merge commit `38e5b8b905aba50ff9acfc7f84f850f03eb3f2f3`; later documentation-only descendants must not move this Tag |
| Phase 14 tag | Annotated `phase-14-complete` object `06e393c77918ef13ba66c0cdf253800074bdd71a` peels to PR #41 canonical merge `c342260162c3c3895120720559d73d33b172a7ef` and is locally/remotely verified |
| Stable branch | The canonical Phase 14 checkpoint is an ancestor of later documentation-only descendants; those descendants must not move its stable target |
| Working tree | Merged-main verification used temporary output directories outside the repository; generated databases, uploads, demo model binaries, coverage machine output, secrets, and formal evidence remain untracked |
| Phase 7 status | Phase complete; implementation, checkpoint, metadata, and visible-status closures are merged and verified |
| Phase 8 status | Phase complete |
| Phase 9 status | Phase complete |
| Phase 10 status | Phase complete |
| Phase 11 status | Phase complete |
| Phase 12 status | Phase complete |
| Phase 13 status | Phase complete |
| Phase 14 status | Phase complete |
| Phase 13 source branch | `phase/13-hardening` was merged through PR #39 |
| Next planned phase | None |
| Next action | Review the single mentor-demo corrective PR. Do not merge automatically. No additional Phase 14 status-closure PR is required |

Phase 0 through Phase 14 are checkpointed and their Tags remain unchanged. Phase
11 joins the immutable offline evidence pipeline through deterministic replay
without changing its scientific claims: a risk or fusion score is not attack
probability, an alert is not confirmation, and a hypothesis is not fact.
Recovery restarts from capture origin and verifies committed evidence; it is not
exact packet-cursor resume. Phase 12 exposes complete explicit local API and
frontend workflows without enabling live capture, automatic recovery, automatic
training/activation, or response actions.

## Phase 14 final implementation checkpoint

- PR #41 was Squash and merge merged into `main` at
  `c342260162c3c3895120720559d73d33b172a7ef`. The final source-branch Head was
  `168a91caecd59fff7d66e9237a97653831cf024e`; both objects resolve to tree
  `0749ac9b055341f7c792673ba0561bce42da9aa0`.
- All 18 implementation-Head checks passed. Merged-main verification passed
  Ruff, strict mypy for 239 source files, 550 tests with no failures, skips, or
  xfails at 85.83% branch-aware coverage, and every declared core package
  remained above 80%.
- Annotated `phase-14-complete` object
  `06e393c77918ef13ba66c0cdf253800074bdd71a` peels to the canonical merge and
  was verified against the remote. It does not point to the source Head or a
  later documentation descendant.
- Wheel/sdist, Twine, exact distribution inventory, documentation delivery,
  ignored release-bundle verification, and clean Python 3.11/3.12 wheel
  installations passed. No GitHub Release, `v1.0.0` release Tag, registry
  upload, PyPI publication, or Docker publication was authorized or executed.
- The first local Docker base-image metadata request timed out. A later
  independent pull/build succeeded; a fresh merged-main arm64 no-cache build
  then passed the complete local Compose workflow. The image remained
  UID/GID 10001, read-only, `ALL` capabilities dropped, and
  `no-new-privileges:true`, with loopback-only published ports and no host,
  home, Git, SSH, or Docker-socket mount.
- The final controlled Docker run processed the 1,017-packet attack-like
  derivative into 42 bidirectional flows and 42 alerts, one alert group, one
  hypothesis, one completed runtime job, and an analyst case with note,
  bounded verdict, and feedback. All evidence survived API/worker/frontend
  restart; schema version 5, WAL, application-level foreign keys, and SQLite
  integrity `ok` were verified.
- Docker `doctor` is healthy after runtime artifact/report paths were made
  visible through the existing named volumes. Matplotlib uses the explicit
  writable `/tmp/matplotlib` cache under the existing bounded tmpfs; no
  root-user or writable-root relaxation was introduced.
- The formal exact-final-head Codex Security rescan was explicitly waived,
  was not executed, and no result is claimed. Dependency audit, secret scan,
  Bandit, ledger validation, and regression tests are complementary controls,
  not a formal-rescan substitute.
- No further implementation phase is planned. The single checkpoint PR is a
  documentation/verification descendant of the immutable canonical
  implementation checkpoint; it does not need its own future merge SHA in
  durable status and must not trigger another status-closure PR.

## Phase 13 implementation checkpoint

- PR #39 was squash-merged into `main` as the canonical implementation commit
  `38e5b8b905aba50ff9acfc7f84f850f03eb3f2f3`. Its final source-branch Head was
  `5b183a53d76aaa72807200e6d54793e9c0a4fcda`; all eight final-head GitHub
  checks passed. Annotated `phase-13-complete` peels to the canonical merge,
  not the source-branch Head or a later documentation-only commit.
- The immutable Security baseline at
  `75c73bc86a40a78a22edde5fb175359a7b755c05` covered 448 tracked files and
  reported 7 Medium, 73 Low, 0 High, and 0 Critical findings. It was read, not
  rerun. All 80 rows are now represented in a validated ledger: 9 Fixed,
  39 Accepted risk, 19 Deferred to Phase 14, 13 Needs further validation, and
  0 Untriaged.
- Untrusted multipart, JSON/JSONL, and PCAPNG metadata now encounter configured
  work/memory bounds before costly framework or object materialization.
- Flow timeout processing uses an authoritative deadline heap rather than
  scanning every active flow per packet.
- Dataset near-duplicate leakage uses exact tolerance components; controlled
  generator provenance requires deterministic row equivalence; fusion
  refitting requires registered Phase 5/6 identities and the Phase 3 schema.
- Performance protocol 1.1 uses 100 measured samples for micro/API scenarios,
  records p99 only at that sample count, keeps bounded 10-sample scenarios'
  p99 unavailable, covers seven read-only API routes with a no-mutation check,
  and records seven explicit RSS scenarios. Results are development-host
  observations only.
- Robustness matrix `1.1.0` passed all 21 scenarios/27 represented tests after
  one initial test-node naming defect was corrected and the full matrix rerun.
- Passing refreshed runs observed 85.74–85.78% repository combined
  statement/branch coverage. Each of the 17 declared core packages separately
  exceeds 80%; `flows` is lowest at 81.58%.
- Final dependency-installed repository verification passed 527 tests with no
  failures, skips, or xfails in 1,555.14 seconds at 85.73% branch-aware
  coverage; strict mypy passed 237 source files and Ruff passed. The complete
  standalone offline E2E passed 22/22 in 131.46
  seconds after its Phase 6 assertion was made candidate-aware without changing
  any model, threshold, selection policy, or historical evidence.
- Final Phase 13-focused tests passed 29/29 in 3.73 seconds, and the complete
  offline E2E selection passed 22/22 in 139.74 seconds. Deterministic benchmark
  and robustness smoke commands completed using temporary output directories.
- Native `codex review --base main` failed to start with `ENOENT` for the local
  arm64 vendor executable. Equivalent read-only review found one Medium
  extreme-JSON-depth boundary defect; `f8d424e` fixed it and added streaming
  body/depth regressions. Final findings: 0 Blocking, 0 High, 0 unresolved
  Medium.
- `pip check` passed. `pip-audit` 2.10.1 audited 114 Python 3.12
  distributions and 110 clean Python 3.11 distributions with zero advisories
  in either environment. The reachable-history `detect-secrets` gate scanned
  1,264 historical text blobs subject to one documented bounded oversized-blob
  exclusion, skipped 18 binary blobs and one oversized historical blob, and
  reported zero confirmed secrets, zero unreviewed candidates, and zero stale
  allowlist entries. Current tracked files remain subject to the normal scan;
  passing does not mean every reachable blob was scanned. Bandit reported 45
  Low and zero Medium/High findings without suppression.
- The first refreshed GitHub Actions run correctly failed three new gates:
  Python 3.11 retained vulnerable bundled `setuptools 65.5.0`; the robustness
  console entry point could not import `tests.fixtures`; and the optional
  official Dependency Review Action was unavailable because the repository
  lacks Dependency Graph plus GitHub Advanced Security. The build/development
  dependency now requires reviewed setuptools 83.x, every CI pytest step uses
  `python -m pytest`, and the unsupported optional job is removed rather than
  mislabeled as passing. A clean Python 3.11 reproduction audited 110
  distributions with zero advisories, passed the full local security gate, and
  passed 53 robustness/security boundary tests.
- A formal Codex Security workspace was opened for the previous exact Head and
  its capability preflight returned ready, but the scan was canceled before
  discovery when those CI failures made that Head non-final. The user later
  explicitly waived the final exact-head Codex Security rescan. It was not
  executed, no final-rescan result is claimed, and the completed Bandit,
  secret-history, dependency, and ledger evidence is not presented as a
  replacement scan.
- Merged-main verification passed Ruff, strict mypy for 237 source files, all
  527 pytest tests with zero failures/skips/xfails at 85.79% branch-aware
  coverage, all 17 per-package coverage gates, 17 security regressions plus the
  80-row ledger validator, 53 robustness regressions plus smoke, and 7
  performance-tool regressions plus smoke. The first bare shell attempt used
  neither the project virtual environment nor its dependencies; that
  environment error was retained and all required commands were rerun
  successfully with `.venv`.
- After adding the durable checkpoint state and its direct status regressions,
  the final checkpoint-branch suite passed all 528 tests with 0 failures,
  0 skips, 0 xfails, and 18 warnings in 1,552.44 seconds at 85.73%
  branch-aware coverage. Ruff and strict mypy for 237 source files remained
  clean.
- Phase 14 deployment/authentication/packaging is not implemented. No model,
  selection, frozen evidence, fusion conclusion, or active pointer was changed.

## Phase 12 implementation checkpoint

- Added modular typed FastAPI routes for system/runtime, ingestion,
  flows/detections, alerts, groups/hypotheses, cases/feedback, models,
  evaluation, and controlled demonstration. List reads are bounded and
  deterministic; mutations require explicit attribution and confirmation where
  applicable.
- Added request IDs, one sanitized error envelope, documented status mappings,
  loopback-only CORS, streaming upload limits, Phase 2 secure-storage reuse,
  verified identity-based downloads, and unique OpenAPI operation regression
  coverage.
- Added a typed HTTP frontend client and nine modular Streamlit pages. No
  production frontend module imports storage, repositories, SQLAlchemy, or
  artifact readers. Empty, unavailable, error, and controlled-evidence states
  remain explicit.
- Added shared session-state pagination with bounded previous/next navigation
  for every primary list workflow. Traffic Explorer now links selected flow
  detail to ordered behavioral features, directional distributions,
  DetectionResult thresholds/reasons, and its related SecurityAlert.
- Completed Overview with server-derived flow, alert, hypothesis, case, model,
  fusion-policy, ingestion, queue, worker, and recent-activity state. Missing
  P95 latency remains explicitly Unavailable rather than inferred.
- Completed Alerts with score-versus-threshold evidence, structured reasons,
  involved entities, related groups/hypotheses, limitations, and analyst
  action. Data Ingestion now exposes one confirmed, audited, bounded worker
  cycle that claims at most one queued job and stops.
- Added `phase12-demo-pcap`, a deterministic 350-byte controlled capture with
  UDP and TCP exchanges over documentation addresses, plus a reproducible
  generator and manifest checksum.
- Added an isolated versioned demo artifact manager that invokes existing
  production dataset, model, anomaly, fusion, explanation, detection, runtime,
  correlation, hypothesis, and case services. Explicit preparation is atomic;
  reuse verifies checksums and inventory; formal Phase 5–11 roots and active
  model pointers are not overwritten.
- Added a Phase 12-only supervised model identity (`12.0.0`) and portable
  validation tie-break policy. Host-dependent latency and serialized size remain
  measured evidence but cannot change the demo winner; the derived fusion,
  risk, runtime, and explanation identities are bound to the actual isolated
  bundle rather than impersonating formal Phase 5 corrective evidence.
- Added a fresh-database full E2E that produces actual flows, detections, alerts,
  a group, a hypothesis, and an optional case, verifies typed client retrieval,
  repeats idempotently, and confirms formal artifact roots remain untouched.
- ADR 0021 and `docs/api_frontend.md` define the API-only frontend boundary,
  sample isolation, upload/download safety, research truthfulness, and Phase 13
  exclusion.

## Phase 12 verification checkpoint

- Initial post-merge verification on synchronized `main`
  `baac8e5ecf9f8a2ac66afe2873269bebcbbcbf17` passed all 458 repository tests
  with zero failures, skips, or xfails in 1,580.01 seconds at 85.46%
  branch-aware coverage; the required Phase 12/API/security selection passed
  58 tests in 77.82 seconds.
- After the metadata and status regressions were updated, Ruff passed; strict
  mypy passed for 234 source files; all 460 tests passed with zero failures,
  skips, or xfails in 1,594.52 seconds at 85.40% branch-aware coverage; and the
  expanded Phase 12/API/security/status selection passed 60 tests in 77.98
  seconds.
- Final corrective-head Ruff passed. Strict mypy passed for 234 source files.
  The final complete pytest run passed all 458 tests with zero failures, skips,
  or xfails in 1,641.38 seconds at 85.40% branch-aware coverage, above the
  unchanged 85% gate.
- The final Phase 12 E2E/API/client/frontend selection passed all 22 tests in
  76.70 seconds without collecting global coverage. The portable-selection and
  Sample Demo selection passed all 4 tests in 54.09 seconds. These cover
  pagination state transitions, server totals, KPI truthfulness, flow-to-alert
  drill-down, related investigation context, and the explicit bounded worker
  operation, plus host-independent model selection and derived policy identity
  alignment.
- The first full run exposed one stale exact-set sample-registry assertion (449
  passed, 1 failed) and 82.55% coverage for the newly exposed paths. The sample
  assertion was corrected and a populated nine-page API/frontend regression
  now exercises real reads and explicit mutations. No test was removed,
  skipped, weakened, or excluded, and the coverage threshold remains 85%.
- The first GitHub Actions run at `4226ccb` then exposed a clean-Linux evidence
  binding defect: two Sample Demo tests received sanitized HTTP 422 responses
  because the demo anomaly config still referenced a historical dataset
  manifest checksum. The demo now derives its isolated anomaly config from the
  freshly generated demo dataset and split manifests, preserving validation-only
  model policy and evidence identities. A clean Python 3.11 environment and the
  final full suite both execute the real Sample Demo successfully.
- Refreshed GitHub Actions at `f8a464d` exposed a second cross-platform
  correctness issue: both Linux jobs passed Ruff and mypy but the demo rejected
  the legal validation winner because the orchestrator hard-coded Random Forest
  and isotonic while the registered Phase 5 ranking includes host-dependent
  operational ties. The Phase 12 demo now uses a separately versioned portable
  selection policy that excludes host-dependent latency and size from selection
  while retaining them as evidence, applies a stable algorithm-ID final tie,
  and derives all downstream policy identities from its isolated `12.0.0`
  bundle. It does not change Phase 5 selection or historical evidence.
- Both required GitHub Actions `quality` jobs at corrective head `f98a593`
  passed Ruff, mypy, and all 458 tests. They reported 85.46% branch-aware
  coverage and completed the test step in 1,378.48 and 1,223.66 seconds,
  respectively. The clean-Linux Sample Demo therefore verifies the portable
  selection and isolated downstream identity bindings.
- Post-merge live FastAPI verification returned HTTP 200 for health, docs, and
  OpenAPI; the schema contained 58 paths and 62 unique operations. Headless
  Streamlit health and root both returned HTTP 200, and both processes stopped
  cleanly.
- A clean local clone outside the repository ran the CLI controlled Demo twice
  against an isolated database. Both runs completed with the same source and
  runtime-job IDs, two flows, two alerts, one group, and one hypothesis. The
  second run reused verified artifacts and persisted identities; no formal
  evidence root or model bundle was modified.
- Headless Streamlit health and root returned HTTP 200. Browser verification
  covered all nine populated pages, explicit forms, empty/error semantics, and
  truthful research limitations. The API's missing-object response was
  sanitized and contained no traceback or local path.
- Bare `.venv/bin/aegishunt demo` failed because this desktop runtime did not
  expose the editable-install `.pth` (`ModuleNotFoundError`). The documented
  `PYTHONPATH=src` workaround ran the same real demo successfully; it is not
  claimed as clean-install success.
- Native `codex review --base main` could not start because the installed arm64
  executable is missing (`ENOENT`). Equivalent read-only review covered API and
  frontend boundaries, pagination, GET/mutation semantics, streaming uploads,
  artifact paths, auditing, model safety, demo isolation, research truthfulness,
  generated files, and Phase 13 scope.
- That review found one correctness-related Medium: runtime-worker pagination
  counted only the first 100 records. Exact repository counting plus a
  101-worker regression corrected it; local origins also reject path-bearing
  values. The acceptance-correction review found one additional Medium:
  Overview counted only `open` alerts as active and omitted `acknowledged`
  alerts. The active set now includes both states with direct regression
  coverage. Final retesting passed with zero Blocking, zero High, and zero
  unresolved correctness-related Medium findings.
- The final native review attempt after the portable-demo correction failed
  with the same arm64 executable `ENOENT`. Its equivalent read-only review
  compared `f8a464d...HEAD`, confirmed the isolated model and downstream policy
  identities, portable selection/test boundary, formal-evidence preservation,
  generated-artifact exclusion, secret hygiene, and Phase 13 absence, and found
  zero Blocking, zero High, and zero unresolved correctness-related Medium
  findings.

## Phase 11 implementation checkpoint

- Added strict configured runtime policy and complete source/model/policy/schema
  preflight. Jobs accept only a persisted completed PCAP source ID; pinned
  snapshots contain logical filenames and checksums rather than absolute paths.
- Added additive schema v4→v5 with durable runtime jobs, attempts, workers,
  bounded resource samples, and transactional output ledgers.
- Added atomic oldest-job claims, bounded leases/heartbeats, stale reconciliation,
  pause/resume, graceful shutdown, explicit origin recovery, and no automatic
  requeue. Interrupted partial flow state is never flushed.
- Added interruptible event-time replay with configured speed and gap cap,
  explicit out-of-order/gap counters, existing Phase 3 aggregation/finalization,
  and EOF flush.
- Added one transaction per finalized output batch: flow reuse/create,
  supervised/anomaly/fusion scoring, DetectionResult, optional SecurityAlert,
  ledger, and durable output counters. Observed packet telemetry is persisted
  separately and is explicitly non-durable; the conservative durable packet
  position remains zero until final completion. Recovery verifies/reuses only
  matching committed evidence and never uses observed progress as a cursor.
- Added post-EOF idempotent Phase 9 correlation/hypothesis generation, psutil
  process observations with explicit unavailable/null semantics, runtime CLI
  operations, and a truthful Streamlit status shell.
- Scoped downstream runtime counters to output-ledger evidence owned by the
  current job, reconciled stale active worker status with the configured
  threshold, and completed lifecycle audit timestamps and structured context.
- Added unit, migration, race, rollback, shutdown, resource, CLI, frontend,
  integration/restart, drift, malformed-PCAP, and real temporary-bundle E2E
  coverage. No external network, root, live capture, Phase 12 workflow, training,
  formal frozen-test evidence, or model binary is used.
- Corrected periodic control updates that previously could persist in-memory
  packet progress ahead of an open flow or pending output batch. Jobs and
  attempts now retain explicit observed/durable semantics, recovery creates a
  zeroed origin-restart attempt while preserving history, pause/resume keeps the
  live attempt, and completion reaches 100% only after EOF plus final
  correlation/hypothesis commit.

## Phase 11 verification checkpoint

- Pre-branch baseline: Ruff passed; strict mypy passed for 185 source files; the
  full suite passed 389 tests with 86.01% branch-aware coverage.
- The pre-corrective focused Phase 11 selection passed 44 tests in 38.70 seconds, including
  durable queue lifecycle/race/rollback, live-worker pause/heartbeat/resume,
  replay timing, preflight drift, malformed PCAP, schema migration, Streamlit
  status, and real temporary verified-bundle E2E.
- The first full Phase 11 run exposed three stale schema-v4 expectations;
  `595f79d` updated them to the additive schema-v5 contract. The final Ruff
  check passed, strict mypy passed for 205 source files, and all 427 tests
  passed with zero failures, skips, or xfails in 1,248.47 seconds at 86.07%
  branch-aware coverage.
- The real Phase 11 E2E now requires complete flow, detection, alert,
  correlation-group, and hypothesis evidence from a controlled temporary PCAP,
  then verifies restart persistence and deterministic reuse. No downstream
  service is stubbed and no formal model evidence is regenerated.
- The durable-progress corrective focused selection passed 53 tests in 37.78
  seconds. It covers a long open flow before commit, interruption before the
  first durable flow, mixed committed/open evidence, atomic rollback,
  pause/resume, zeroed origin recovery with historical attempt preservation,
  output reuse without duplication, completion gating, truthful CLI/frontend
  labels, and repeatable v4→v5/fresh schema initialization.
- Final corrective Ruff passed; strict mypy passed for 205 source files; all 437
  tests passed with zero failures, skips, or xfails in 1,253.12 seconds at
  86.20% branch-aware coverage, above the unchanged 85% gate.
- Native `codex review --base main` could not start because the installed arm64
  executable is missing (`ENOENT`). Equivalent read-only review findings for
  job-scoped downstream counters, resume audit time, E2E completeness, signal
  registration coverage, stale worker reconciliation, and audit context were
  closed by commits `5789356`, `1056ad9`, `7d8eb22`, `fcdd2ca`, `ce70330`, and
  `720f4c3`. The final equivalent review found zero Blocking, zero High, and
  zero unresolved correctness-related Medium findings.
- The native corrective review attempt failed with the same arm64 executable
  `ENOENT`. Its equivalent read-only review confirmed the observed/durable
  split, output transaction boundaries, rollback, completion gate, origin
  recovery, attempt history, counter monotonicity, UI/CLI wording, schema-v5
  contract, and Phase 12 exclusion. It found zero Blocking, zero High, and zero
  unresolved correctness-related Medium findings.
- Manual runtime CLI verification used a temporary database outside the
  repository. The desktop environment did not expose the editable-install
  `.pth`; bare console invocation failed with `ModuleNotFoundError`, while the
  recorded `PYTHONPATH=src` workaround passed. It is not claimed as a standard
  installation success.

## Phase 11 startup invariant (satisfied)

The canonical Phase 10 checkpoint is PR #31 merge commit
`ba40211a374aa8e4efa62702a83d063f9eb88039` plus the annotated
`phase-10-complete` Tag whose peeled target is that commit. Later documentation
commits may be descendants of the checkpoint and must not move the Tag.

Before the Phase 11 branch was created, live Git and GitHub checks confirmed the
working tree was clean; local `main` was synchronized with `origin/main` by
`git pull --ff-only`; PR #31 was merged with successful required checks; local
and remote `phase-10-complete` were annotated and peeled to the canonical merge
commit; and
`git merge-base --is-ancestor ba40211a374aa8e4efa62702a83d063f9eb88039 main`
succeeded. The Phase 11 branch did not exist locally or remotely at that point.
The full baseline then passed before `phase/11-runtime-replay` was created.

This gate intentionally uses ancestor containment rather than requiring the Tag
to equal a future documentation-only `main` HEAD. It does not require documents
to hard-code the live `main` HEAD or any later status-only PR merge SHA. Once the
invariant passes, no additional final-status or closure PR is required.

## Phase 12 startup invariant (satisfied)

The canonical Phase 11 checkpoint is PR #33 merge commit
`8f85949406e3db7d2fa2b3c48d04e832e84f3559` plus the annotated
`phase-11-complete` Tag whose local and remote peeled targets are that commit.
Later documentation-only commits may be descendants of this checkpoint and
must not move the Tag.

Before Phase 12 starts, live Git and GitHub state must confirm a clean working
tree; a local `main` synchronized with `origin/main` by
`git pull --ff-only`; merged PR #33 with successful required checks; annotated
local and remote `phase-11-complete` Tags peeled to the canonical commit; and
successful ancestor containment through
`git merge-base --is-ancestor 8f85949406e3db7d2fa2b3c48d04e832e84f3559 main`.
The status documents must show Phase 11 complete and Phase 12 not started, the
`phase/12-api-frontend` branch must not already exist locally or remotely, and
the required baseline tests must pass. Phase 12 also requires explicit user
authorization.

This invariant does not require the Tag to equal a later documentation-only
`main` HEAD, does not require permanent documents to hard-code the live
`main` HEAD, and does not require another final-status or closure PR after this
checkpoint is recorded. Once the live invariant passes, Phase 12 may start on
its declared branch without a self-referential status-update loop.

## Phase 13 startup invariant (satisfied)

The canonical Phase 12 checkpoint is PR #35 merge commit
`baac8e5ecf9f8a2ac66afe2873269bebcbbcbf17` plus the annotated
`phase-12-complete` Tag whose local and remote peeled targets are that commit.
Later documentation-only commits may be descendants of this checkpoint and
must not move the Tag.

Before Phase 13 starts, live Git and GitHub state must confirm a clean working
tree; a local `main` synchronized with `origin/main` by
`git pull --ff-only`; merged PR #35 with successful required checks; annotated
local and remote `phase-12-complete` Tags peeled to the canonical commit; and
successful ancestor containment through
`git merge-base --is-ancestor baac8e5ecf9f8a2ac66afe2873269bebcbbcbf17 main`.
The status documents must show Phase 12 complete and Phase 13 not started, the
`phase/13-hardening` branch must not already exist locally or remotely, and the
required baseline Ruff, mypy, pytest, and Phase 12 smoke tests must pass. Phase
13 also requires explicit user authorization.

This invariant does not require the Tag to equal a later documentation-only
`main` HEAD, does not require permanent documents to hard-code the live
`main` HEAD, and does not require another final-status or closure PR after this
checkpoint is recorded. Once the live invariant passes, Phase 13 may start on
its declared branch without a self-referential status-update loop.

## Phase 14 startup invariant

The canonical Phase 13 checkpoint is PR #39 merge commit
`38e5b8b905aba50ff9acfc7f84f850f03eb3f2f3` plus the annotated
`phase-13-complete` Tag whose peeled target is exactly that commit. The PR's
final source-branch Head is separately recorded as
`5b183a53d76aaa72807200e6d54793e9c0a4fcda`. Later documentation-only commits
may be descendants of the checkpoint and must not move the Tag.

Before creating `phase/14-final-delivery`, the Phase 14 startup task must
verify all of the following live conditions:

1. the working tree is clean;
2. the task checks out `main`;
3. `git pull --ff-only origin main` succeeds;
4. local `main` and `origin/main` are identical;
5. PR #39 is merged;
6. all required checks for final Head
   `5b183a53d76aaa72807200e6d54793e9c0a4fcda` passed;
7. `phase-13-complete` is an annotated Tag;
8. its peeled target is exactly
   `38e5b8b905aba50ff9acfc7f84f850f03eb3f2f3`;
9. the following ancestor check succeeds:

   ```bash
   git merge-base --is-ancestor \
     38e5b8b905aba50ff9acfc7f84f850f03eb3f2f3 \
     main
   ```

10. README, release notes, progress, and Streamlit display Phase 13 complete
    and Phase 14 not started;
11. `phase/14-final-delivery` does not exist locally or remotely;
12. the merged-main baseline checks pass and the user explicitly authorizes
    Phase 14.

The invariant deliberately checks ancestry instead of requiring the live
`main` HEAD to remain equal to the Phase 13 canonical merge. It does not need
the number or future merge commit of any documentation-only descendant, does
not require another Phase 13 status-closure PR, and does not require the final
Codex Security rescan that the user explicitly waived. Once these live gates
pass, the authorized Phase 14 task may create `phase/14-final-delivery`
directly.

## Phase 10 implementation checkpoint

- Added deterministic, idempotent creation of one primary case from an eligible
  Phase 9 hypothesis while retaining facts, inference, assumptions, benign
  alternatives, possible mappings, and underlying typed evidence snapshots.
- Added configured status transitions and priority mapping, assignment, append-only
  notes/references, case verdicts, closure requirements, explicit correction
  semantics, injectable lifecycle clocks, and same-transaction audit records.
- Added human-supplied alert/case feedback with actor, confidence, provenance,
  query filters, exact duplicate idempotency, and explicit conflict handling.
  Feedback remains noisy/revisable analyst evidence and never rewrites source data.
- Added exact-inventory, checksummed feedback export and deterministic JSON/Markdown
  case reports. Artifact roots are configured, contained, non-overwriting, and
  separate from database evidence.
- Added an explicit retraining-candidate builder limited to unambiguous
  alert-to-detection-to-flow mappings. It rejects unknown or frozen/evaluation
  provenance, reports conflicts/exclusions, preserves Phase 3 feature order, and
  never invokes training or activation.
- Added additive schema v3→v4 migration, typed repositories/services, CLI groups,
  unit/integration/restart/offline E2E tests, ADR 0019, and Phase 10 contracts.
- Full Phase 10 APIs/frontend pages remain Phase 12 scope; Phase 11 runtime replay,
  workers, progress/recovery, and resource monitoring remain unimplemented.

## Phase 10 verification checkpoint

- Ruff passed for the complete repository; strict mypy passed for all 185 source files.
- The merged-main focused Phase 10 selection passed all 27 tests in 6.00 seconds,
  and the migration selection passed all 4 tests in 0.31 seconds.
- The merged-main complete pytest suite passed all 388 tests in 1,102.37 seconds with zero
  failures, skips, or xfails and 86.01% branch-aware coverage, above the unchanged
  85% gate.
- After adding the permanent ancestor-invariant regression, the updated Phase 10
  focused selection passed all 28 tests in 5.49 seconds and the final complete
  suite passed all 389 tests in 1,094.54 seconds with the same 86.01% coverage
  and no failures, skips, or xfails.
- The first implementation review found that an empty candidate artifact caused a
  CLI exit inside the database transaction, rolling back its audit while leaving the
  valid data-only artifact. The command now returns an explicit `empty` state and
  commits the audit; a separate `insufficient_records` state applies below the
  configured minimum. Offline E2E regression coverage verifies the empty audit.
- Native `codex review --base main` could not start because the installed arm64
  executable is missing (`ENOENT`). The equivalent read-only branch review found one
  correctness-related Medium gap: several Phase 10 audit events did not uniformly
  include the required before/after, reason, and source summaries. Commit `c6a10ee`
  completed those structured summaries and added regression assertions. The post-fix
  equivalent review found zero Blocking, zero High, and zero unresolved
  correctness-related Medium findings.
- Tests created only isolated temporary databases and ignored data-only artifacts.
  They did not regenerate formal model evidence, load arbitrary pickle/joblib, train
  or activate a model, access a network, require root, or implement Phase 11.

## Phase 9 implementation checkpoint

- Added a strict checksummed YAML policy with all thresholds, limits, verdict
  eligibility, rule versions, weights, severity mapping, and score semantics.
- Added canonical typed local entities and observed event-time indexing. Earliest-event
  anchored inclusive windows and configured bounds avoid processing-time drift and
  unbounded pairwise work.
- Added seven explainable rules, retained rule limitations, transparent bounded score
  components, stable alert-group IDs, deterministic ordering, deduplication, and
  immutable member evidence snapshots.
- Added eight deterministic hypothesis templates with one primary choice, retained
  candidates, separated facts/inferences/assumptions/benign alternatives, cautious
  possible ATT&CK mappings, and structured query suggestions marked `not_executed`.
- Added confidence components with explicit non-probability semantics and a fail-closed
  generation gate. Hypotheses default to `proposed`; direct/automatic confirmation is
  prohibited and safe analyst transitions are audited.
- Extended existing schemas/ORM/repositories and added ordered additive schema v2→v3
  migration while preserving legacy Phase 1 records. Writes are transactional and
  stable reruns are idempotent; identity/evidence conflicts fail closed.
- Added the `aegishunt hunt` CLI tree. Full hunting APIs/frontend pages remain Phase 12,
  and Phase 10 case/feedback workflows remain unimplemented.
- Added unit, migration, integration/restart, CLI, status, and offline E2E coverage. The
  focused Phase 9 selection passed all 39 tests in 7.01 seconds.

## Phase 9 verification checkpoint

- Ruff passed for the complete repository.
- Strict mypy passed for all 168 source files.
- The complete final closure pytest suite passed all 365 collected tests in 1,062.84 seconds;
  failures, skips, and xfails were all zero.
- Branch-aware coverage was 86.74%, above the unchanged 85% project gate.
- The focused Phase 9 unit, migration, CLI, integration/restart, lifecycle, offline
  E2E, frontend, and status selection passed all 39 tests in 7.58 seconds.
- Manual CLI verification used `PYTHONPATH=src` because the desktop environment's
  editable-install `.pth` was not visible. The workaround exposed and helped fix an
  actual circular schema import; it is not represented as a standard-install success.
- Native post-merge `codex review` against the pre-merge base could not start because
  the installed arm64 executable is missing (`ENOENT`). The equivalent first read-only review found one
  Medium issue: normal hypothesis-gate rejection used a silently caught exception.
  Commit `8c80e8e` replaced it with an explicit, tested eligibility result. The
  post-fix equivalent review found no remaining issue in that path.
- A subsequent user review found a second correctness-related Medium: group and
  hypothesis `created_at`/`updated_at` values were copied from historical event
  `last_seen` rather than actual record generation time. Commit `864ef66` added
  injectable clocks, separate lifecycle evidence, idempotent timestamp preservation,
  strictly later status-update time, and unit/integration/restart/E2E regression
  coverage. The final equivalent review found zero Blocking, zero High, and zero
  unresolved correctness-related Medium findings.
- Tests generated only isolated temporary SQLite databases and fixtures. No model,
  formal experiment evidence, external enrichment, network access, or Phase 10 case
  artifact was created.

## Phase 8 implementation checkpoint

- Added a checksummed YAML risk policy that explicitly maps the verified Phase 7
  fusion score by identity, retains the `inconclusive` recommendation, and
  forbids hidden fallback or weight/threshold reselection.
- Added finite bounded score contracts, inclusive configured severity bands,
  exact alert-threshold behavior, and deterministic detection/alert identities.
- Extended existing schemas, ORM records, and repositories; schema version 2
  uses an additive tested v1→v2 SQLite migration. Detection and optional alert
  writes share one transaction and duplicates never overwrite evidence.
- Added benign-training q05–q95 references, supported native tree importance,
  fixed-validation permutation importance, single-feature median-replacement
  local sensitivity, and a versioned reason-code catalog. Importance and
  contributions explicitly remain non-causal.
- Added exact-inventory checksummed data-only explanation artifacts with
  root/path/symlink/missing/extra/corruption/version protections and no pickle,
  joblib, or model binary.
- Added threshold-gated analyst alerts with non-empty reason/evidence records;
  below-threshold detections persist without a fabricated alert.
- Added audited, idempotent alert-level verdict updates that cannot mutate alert
  evidence or trigger training, correlation, cases, feedback export, or
  hypotheses.
- Added typed `detection`, `alerts`, and `explainability` CLI groups. Full alert
  API/frontend workflows remain Phase 12 scope.
- Controlled synthetic evidence remains pipeline verification only. The Phase 6
  LOF remains validation-qualified without an untouched independent holdout,
  and the Phase 7 fusion recommendation remains inconclusive.

## Phase 8 verification checkpoint

- Ruff passed for the complete repository.
- Strict mypy passed for all 152 source files.
- The complete pytest suite on merged `main` passed all 334 collected tests in
  1,095.95 seconds;
  failures, skips, and xfails were all zero.
- Branch-aware coverage was 86.63%, above the unchanged 85% project gate.
- The focused Phase 8 unit, migration, CLI, integration, persistence/restart,
  verdict, artifact-integrity, offline E2E, frontend, and status selection
  passed all 25 tests.
- Both GitHub Actions `quality` checks for PR #25 passed before merge.
- Tests generated only isolated temporary SQLite databases and explanation
  artifacts; none are tracked. No Phase 5–7 experiment evidence or bundle was
  regenerated or overwritten.
- Native `codex review --base main` could not start because the installed arm64
  executable is missing (`ENOENT`). Equivalent review found and closed an
  explanation-artifact identity binding gap, a root-symlink acceptance gap, and
  incomplete self-contained alert evidence. Final review found zero Blocking,
  zero High, and zero unhandled correctness-related Medium findings. The merged
  diff received the same equivalent read-only conclusion before Tag creation.

## Phase 7 implementation checkpoint

- Config schema, experiment identity, candidate weights/thresholds, FPR limits,
  fixed engine configurations, eligible families, temporal order, four shift
  axes, seeds, and 1,000 bootstrap draws were committed before the first run.
- Phase 7 dataset `aegishunt-phase-07-controlled` `1.0.0` contains 144 rows and
  72 new groups across benign plus five attack families. Early/middle/late each
  contain 48 rows and 24 groups. Exact, feature, conflicting-label, and near
  duplicates are zero; group/source/session/scenario overlaps are empty.
- Dataset checksum is
  `4d3319d0a66ff204c9b9cd3720caf83fe66d9bb17d32140edda898f33e2acb40`.
  Historical Phase 5/6 frozen tests were not reused and no old bundle/evidence
  was overwritten.
- The fixed corrected Phase 5 Random Forest/isotonic and fixed Phase 6
  novelty-mode LOF/StandardScaler/benign-quantile configurations are refitted
  only inside isolated early/middle groups. LOF remains validation-qualified;
  temporary research estimators are not registered as active bundles.
- Fusion formula is `sw * supervised_probability + aw * normalized_anomaly_score`.
  Inputs and true dual weights are finite/bounded; weights sum to one and both
  are positive. Missing or mismatched engine/schema evidence fails closed.
- Validation selected candidate `supervised-75-anomaly-25-t0.700`, policy
  `1.0.0`, under FPR ceiling `0.25`. Its recommendation is `inconclusive`
  because it did not improve over the perfect controlled supervised baseline.
- Known/controlled-temporal supervised and fusion Recall/F1/Macro F1/PR-AUC are
  `1.0` with FPR `0.0`; anomaly Recall is `0.9333`, Macro F1 `0.8125`, PR-AUC
  `0.8103`, FPR `0.3333`. Fusion-minus-supervised primary deltas are zero.
- Across five LOAO folds, family-macro Recall is supervised `0.6000`, anomaly
  `0.9333`, fusion `0.3333`; mean FPR is `0.0000`, `0.3333`, `0.0000`.
  Fusion missed held-out exfiltration and reconnaissance. Negative evidence was
  retained without expanding the grid.
- Four fixed feature-space shifts produce separate groups and record base versus
  shifted ranges. Fusion Recall/FPR is `1.0/0.0` on each controlled shift; this
  is not a real-world robustness or zero-day claim.
- Every comparison includes score distributions, identical evaluation rows per
  mode, isolation counts, full metrics, absolute deltas, and fixed-seed 95%
  whole-group/paired-delta intervals with 1,000 requested draws.
- A 48-row/25-repeat development-host measurement observed supervised/anomaly/
  fusion p50 `1.0952/0.6729/0.0381 ms`, total p50/p95/p99
  `1.8157/2.1595/2.3857 ms`, per-sample p50 `0.0378 ms`, and throughput
  `25,834.5/s`. These measurements are not an SLA.
- The three-file JSON/Markdown policy has an exact inventory, evidence hashes,
  selected contract, environment, and SHA-256 checks. Manifest checksum
  `808bd05e2e5a648324fe6052e65a6602f04c15f24e39f2a043a72b73ca3b29c7`
  verified independently. Missing/extra/corrupt/outside/colliding artifacts fail
  closed; no pickle or model binary is used.
- The first focused integration run exposed a protocol timestamp later than the
  UTC execution time. It was corrected to the actual preregistration commit time
  before the final evidence run. A separate selection review exposed that
  Macro F1 alone could admit an all-negative candidate; positive attack Recall
  and F1 are now mandatory, with regression coverage.
- Final equivalent Review also made class-conditional Bootstrap metrics
  unavailable for one-class resamples, enforced selection/policy cross-field
  consistency and frozen rows-per-group, and rejected policy-internal symlinks.
- Generated machine evidence is repository-external/ignored and is not
  committed. Reviewed config, contracts, protocol, card, ADR, release notes,
  CLI, and tests are committed.
- Post-merge quality gate: Ruff passed; strict mypy passed for 134 source files;
  all 316 tests passed in 1,050.77 seconds with 87.37% branch-aware coverage and
  no failures, skips, or xfails. The focused Phase 7/frontend/status selection
  passed all 32 tests in 24.74 seconds. Both PR #21 `quality` checks passed.
- Native post-merge `codex review` could not start because the installed arm64
  executable is missing (`ENOENT`). The equivalent read-only review found zero
  Blocking, zero High, and zero correctness-related Medium findings.
- The fusion score is experimental suspiciousness, not probability, final risk,
  severity, or confirmation. `DetectionResult`, `SecurityAlert`, reason codes,
  explanations, correlation, hypotheses, cases, and automated response are not
  implemented.

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
  all 48 registered rows are already assigned and no untouched independent
  holdout exists.
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
- Post-merge verification on merged `main` passed Ruff, strict mypy for 120
  source files, and all 288 tests in 991.05 seconds with 87.34% branch-aware
  coverage. There were no failures, skips, or xfails. A selected 87-test
  anomaly/frontend/status run passed every assertion; its subset-only command
  returned nonzero solely because the unchanged whole-project coverage gate was
  evaluated against that subset, while the required full suite passed the gate.
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
- Post-merge native `codex review` again failed to start because the installed
  arm64 executable is missing (`ENOENT`). The equivalent read-only review found
  zero Blocking, zero High, and zero correctness-related Medium findings. One
  Low limitation remains: preserved historical `1.0.0` temporary bundle bytes
  predate the strengthened identity field and therefore fail closed under the
  current strict loader; their original checksum/evidence remain unchanged, and
  the active `1.1.0-candidate` bundle verifies and scores deterministically.
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
