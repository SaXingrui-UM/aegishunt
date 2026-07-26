# Phase 12 Release Notes

## Objective and status

Expose the completed Phase 0–11 local research workflows through a complete
FastAPI contract, typed API-only Streamlit interface, and controlled offline
sample demonstration.

Status: **Implementation complete — awaiting PR review**.

- Branch: `phase/12-api-frontend`
- Pull request: [#35](https://github.com/SaXingrui-UM/aegishunt/pull/35),
  `[Phase 12] FastAPI and Streamlit demonstration`, open and ready for review
- Merge commit: pending
- Completion tag: pending; do not create before merge
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
  empty/error/unavailable states and bounded GET-only refresh.
- Allowlisted deterministic `phase12-demo-pcap`, isolated versioned demo
  artifacts, actual Phase 2–11 service execution, stable persisted outputs, and
  optional explicit case creation.
- API, upload-security, client, frontend-boundary, regression, and full
  fresh-database sample E2E coverage.

## Architecture decisions

ADR 0021 records the API-only frontend boundary and isolated demonstration
namespace. Streamlit never reaches storage or artifacts directly. The demo uses
production writers/services and verifies its isolated evidence before reuse;
it does not overwrite formal experiments or move active model pointers.

## Tests

- `ruff check .`: passed.
- `mypy src`: passed for 234 source files.
- Final repository-wide `pytest`: 452 passed, 0 failed, 0 skipped, 0 xfailed
  in 1,466.61 seconds.
- Branch-aware coverage: 85.28%, above the unchanged 85% gate.
- Phase 12 API/client/frontend/demo and CLI selection: 31 passed in 7.64
  seconds without collecting global coverage.
- Configuration and ingestion regression selection: 35 passed in 6.79 seconds
  without collecting global coverage.
- Final OpenAPI/config/pagination selection: 7 passed in 3.97 seconds,
  including exact worker totals beyond 100 records.
- The first complete run exposed one stale exact-set assertion after adding the
  Phase 12 sample (449 passed, 1 failed) and insufficient new-path coverage
  (82.55%). The assertion was corrected and a real populated nine-page
  API/frontend interaction regression was added; no test was deleted, skipped,
  weakened, or excluded and the coverage gate was not changed.

## Manual verification

- FastAPI `/health`, `/docs`, and `/openapi.json` returned HTTP 200. The
  generated schema contained 57 paths and 61 unique operations.
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

## Review

`codex review --base main` could not start because the installed arm64
executable is missing (`ENOENT`). The equivalent read-only review checked
router/service separation, API-only frontend access, bounded queries, upload
streaming, path containment, sanitized errors, explicit actor/audit semantics,
GET side effects, rerun safety, model operations, demo evidence isolation,
research claims, generated files, and Phase 13 scope.

The review found one correctness-related Medium issue: runtime-worker
pagination reported at most 100 total records. The repository now performs an
exact count, and a 101-worker regression test verifies the response. It also
tightened the local-origin validator so path-bearing values are rejected.
Retesting passed. Final findings are zero Blocking, zero High, and zero
unresolved correctness-related Medium.

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
branch `phase/13-hardening`. It is **Not started** and requires Phase 12 merge,
checkpoint closure, and explicit user authorization.
