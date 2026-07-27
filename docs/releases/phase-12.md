# Phase 12 Release Notes

## Objective and status

Expose the completed Phase 0–11 local research workflows through a complete
FastAPI contract, typed API-only Streamlit interface, and controlled offline
sample demonstration.

Status: **Phase complete**.

- Historical implementation branch: `phase/12-api-frontend`
- Pull request: [#35](https://github.com/SaXingrui-UM/aegishunt/pull/35),
  `[Phase 12] FastAPI and Streamlit demonstration`, merged
- Merge commit: `baac8e5ecf9f8a2ac66afe2873269bebcbbcbf17`
- Completion tag: annotated `phase-12-complete`, peeled to the merge commit
- Phase 13: Not started

## Completed scope

- Modular FastAPI routers for system/runtime, ingestion, flows/detections,
  alerts, alert groups, hypotheses, cases/feedback, models, evaluation, and
  controlled demonstration.
- Typed request/response contracts, bounded pagination/filtering, unique
  OpenAPI operation IDs, request IDs, and sanitized error envelopes.
- Chunked bounded PCAP/CSV/JSON upload through the existing secure ingestion
  service and identity-based verified report downloads.
- Explicit audited runtime, verdict, hypothesis, case, feedback, training, and
  activation mutations. GET and auto-refresh paths remain read-only.
- Typed HTTP frontend client and nine modular Streamlit pages with truthful
  empty/error/unavailable states, shared previous/next pagination, and bounded
  GET-only refresh.
- Complete analyst-facing Overview KPIs and activity state; Traffic Explorer
  flow/detail/feature/detection/alert linkage; Alert score/threshold, reason,
  entity, group, hypothesis, and limitation context; and a confirmed audited
  worker run-once action that claims at most one queued job.
- Allowlisted deterministic `phase12-demo-pcap`, isolated versioned demo
  artifacts, actual Phase 2–11 service execution, stable persisted outputs, and
  optional explicit case creation.
- Phase 12-only supervised model `12.0.0` with a portable validation tie-break
  that excludes host-dependent latency/size from selection while retaining both
  as measured evidence, plus derived fusion/risk/runtime identities bound to
  that isolated bundle. Formal Phase 5 model/evidence identities remain
  untouched.
- API, upload-security, client, frontend-boundary, regression, and full
  fresh-database sample E2E coverage.

## Architecture decisions

ADR 0021 records the API-only frontend boundary and isolated demonstration
namespace. Streamlit never reaches storage or artifacts directly. The demo uses
production writers/services and verifies its isolated evidence before reuse;
it does not overwrite formal experiments or move active model pointers.

## Historical implementation commits

- `268b2db` — `build: configure phase 12 web surface`
- `d52e7a6` — `feat: add complete phase 12 API and controlled demo`
- `f01cdcf` — `feat: add API-only Streamlit demonstration interface`
- `4e846be` — `test: verify phase 12 API frontend and demo workflows`
- `78c5b8b` — `docs: document phase 12 API and frontend contract`
- `4226ccb` — `docs: record phase 12 pull request checkpoint`
- `549a424` — `fix: bind sample demo to generated evidence`
- `84c7cb9` — `feat: complete phase 12 analyst workflows`
- `42f28ef` — `test: cover phase 12 acceptance gaps`
- `45b4ac8` — `docs: record phase 12 acceptance corrections`
- `6b23e3a` — `fix: count acknowledged alerts as active`
- `f8a464d` — `docs: record phase 12 corrective review`
- `dd8c448` — `fix: make phase 12 demo selection portable`
- `17cf065` — `test: cover portable demo evidence binding`
- `3797b1a` — `docs: record portable demo correction`
- `f98a593` — `docs: record portable demo review`
- `47e0ccb` — `docs: record phase 12 refreshed CI result`

These commits are the historical Phase 12 branch record. The canonical stable
checkpoint is the separate Squash and merge commit
`baac8e5ecf9f8a2ac66afe2873269bebcbbcbf17`.

## Tests

- Initial synchronized-main repository-wide `pytest`: 458 passed, 0 failed, 0
  skipped, 0 xfailed in 1,580.01 seconds at 85.46% branch-aware coverage; the
  initial Phase 12/API/security selection passed 58 tests in 77.82 seconds.
- Final post-merge-checkpoint `ruff check .`: passed.
- Final post-merge-checkpoint `mypy src`: passed for 234 source files.
- Final post-merge-checkpoint repository-wide `pytest`: 460 passed, 0 failed,
  0 skipped, 0 xfailed in 1,594.52 seconds.
- Final post-merge-checkpoint branch-aware coverage: 85.40%, above the unchanged
  85% gate.
- Expanded Phase 12/API/security/status selection: 60 passed in 77.98 seconds
  without collecting global coverage.
- `ruff check .`: passed.
- `mypy src`: passed for 234 source files.
- Final corrective-head repository-wide `pytest`: 458 passed, 0 failed,
  0 skipped, 0 xfailed in 1,641.38 seconds.
- Branch-aware coverage: 85.40%, above the unchanged 85% gate.
- Phase 12 E2E/API/client/frontend selection: 22 passed in 76.70 seconds
  without collecting global coverage.
- Portable selection plus full Sample Demo E2E: 4 passed in 54.09 seconds
  without collecting global coverage.
- The first complete run exposed one stale exact-set assertion after adding the
  Phase 12 sample (449 passed, 1 failed) and insufficient new-path coverage
  (82.55%). The assertion was corrected and a real populated nine-page
  API/frontend interaction regression was added; no test was deleted, skipped,
  weakened, or excluded and the coverage gate was not changed.
- The first GitHub Actions execution at head `4226ccb` failed two Sample Demo
  tests with sanitized HTTP 422 responses and consequently reported only 82%
  coverage. The clean environment exposed an anomaly-config checksum still
  bound to a historical Phase 6 dataset manifest. The demo now writes its
  isolated anomaly config from the newly generated demo dataset and split
  checksums. Clean Python 3.11 verification and the final full suite execute
  the actual Sample Demo path successfully.
- Both refreshed GitHub Actions jobs at head `f8a464d` passed Ruff and mypy,
  then failed two Sample Demo assertions because host-dependent operational
  tie-breaks produced a legal supervised validation winner different from the
  hard-coded demo expectation (455 tests passed before the two failures).
  Phase 12 now has a separately versioned portable selection policy, stable
  algorithm-ID final tie-break, isolated `12.0.0` model identity, and derived
  fusion/risk/runtime policy identities. Phase 5 ranking and historical
  corrective evidence are unchanged. The final 458-test local run verifies the
  corrected path.
- At corrective head `f98a593`, both required GitHub Actions `quality` jobs
  passed Ruff, mypy, and all 458 tests. They reported 85.46% branch-aware
  coverage and completed the test step in 1,378.48 and 1,223.66 seconds,
  respectively.

## Manual verification

- FastAPI `/health`, `/docs`, and `/openapi.json` returned HTTP 200. The
  post-merge generated schema contained 58 paths and 62 unique operations.
- The controlled sample completed against a temporary database and produced two
  real flows, two alerts, one alert group, one hypothesis, and an explicitly
  created case. Repetition reused the same persisted evidence without
  duplicating it.
- The API returned sanitized 404 errors without a traceback or local path.
- Streamlit started headlessly on loopback; both its root and health endpoint
  returned HTTP 200. Browser navigation verified all nine pages with populated
  API state, explicit mutation forms, truthful evidence limitations, and no
  unsafe dataframe rendering.
- Bare `.venv/bin/aegishunt demo` could not see the editable-install `.pth` in
  this desktop runtime and failed with `ModuleNotFoundError`. The recorded
  `PYTHONPATH=src` workaround completed the same real demo successfully; this
  workaround is not claimed as clean-install success.
- Post-merge verification used a clean local clone outside the repository.
  Two CLI Demo runs completed with the same source/job IDs, two flows, two
  alerts, one group, and one hypothesis. The second run reused verified
  artifacts and persisted identities; its expected reuse limitation text was
  the only result difference.

## Review

`codex review --base main` could not start because the installed arm64
executable is missing (`ENOENT`). The equivalent read-only review checked
router/service separation, API-only frontend access, bounded queries, upload
streaming, path containment, sanitized errors, explicit actor/audit semantics,
GET side effects, rerun safety, model operations, demo evidence isolation,
research claims, generated files, and Phase 13 scope.

The earlier review found one correctness-related Medium issue:
runtime-worker pagination reported at most 100 total records. The repository
now performs an exact count, and a 101-worker regression test verifies the
response. It also tightened the local-origin validator so path-bearing values
are rejected.

The acceptance review additionally identified failed required CI, missing
frontend pagination, incomplete Traffic Explorer and Overview workflows, and
partial Alerts/worker controls. The corrections described above now have
page-level and E2E coverage. The final equivalent review found one additional
Medium: acknowledged alerts were omitted from the Overview active-alert count.
It now counts both open and acknowledged states with a direct regression.
Final findings are zero Blocking, zero High, and zero unresolved
correctness-related Medium.

The final native review attempt after the portable-demo correction failed with
the same arm64 executable `ENOENT`. Equivalent read-only review of
`f8a464d...HEAD` verified the isolated model and downstream policy identities,
portable selection/test boundary, preservation of formal Phase 5 evidence,
absence of generated binaries/secrets, and no Phase 13 scope creep. It found
zero Blocking, zero High, and zero unresolved correctness-related Medium
findings.

## Known limitations

- Local single-user prototype; no production authentication or RBAC.
- SQLite/single-process worker boundary; no distributed broker or worker pool.
- Controlled synthetic sample evidence is pipeline verification only.
- Controlled training and demo artifact preparation are synchronous.
- No comprehensive Phase 13 performance, capacity, robustness, dependency, or
  secret-scanning program has been implemented.
- No Docker, deployment, reverse proxy, TLS termination, or final Phase 14 demo
  script has been implemented.
- Phase 6 retains validation-qualified LOF with no untouched independent
  holdout; Phase 7 fusion remains inconclusive and does not outperform the
  strongest single engine in all reported settings.
- DEF-004 remains: a fully unavailable database cannot persist an outage record
  into that same database.

## Next phase

Phase 13 — Hardening, performance, robustness, and security validation, planned
branch `phase/13-hardening`. It is **Not started** and requires the Phase 13
startup invariant plus explicit user authorization.
