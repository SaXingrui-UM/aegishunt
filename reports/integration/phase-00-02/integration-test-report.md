# AegisHunt Phase 0–2 Integration Test Report

## 1. Executive Summary

- Overall result: **PASS WITH LIMITATIONS**
- Phase 3 recommendation: **CONDITIONALLY READY**
- Open defects: Blocking 0, High 0, Medium 1, Low 0
- Resolved during verification and pre-Phase 3 cleanup: High 2, Medium 1, Low 1
- Automated result: 75 passed, 0 failed, 0 skipped, 0 xfailed
- Branch-aware coverage: 91.97% (configured minimum 85%)
- Manual/traceable matrix: 77 cases — 73 PASS, 1 FAIL, 2 NOT_APPLICABLE,
  1 NOT_EXECUTED, 0 BLOCKED

The install/configuration/database/repository/API/CLI/Streamlit/ingestion chain is
operational in a fresh Python 3.11 environment. PCAP, CSV, JSON, JSONL, and
allowlisted sample ingestion persist jobs and audit records, survive application
restart, and remain safe under the tested malformed-file and path attacks. Two
High defects found in the first pass were fixed with regression coverage. The
remaining Medium finding does not block Phase 3's packet-to-flow implementation,
but must stay visible: a total database outage cannot persist its own failure
record in the unavailable database. `doctor` and README findings are resolved.

## 2. Scope

Included:

- Phase 0 packaging, CLI, API, OpenAPI, Streamlit, project hygiene, and quality gates.
- Phase 1 configuration, schemas, SQLite initialization/pragmas/version, repositories,
  transactions, audit, and empty-database startup.
- Phase 2 typed ingestion adapters, durable job lifecycle, safe file boundary,
  checksums, API/CLI, success/failure paths, restart, and lightweight concurrency.
- Cross-phase operation from clean installation through durable retrieval after restart.

Explicitly excluded:

- Packet-to-flow conversion, bidirectional flow keys, packet direction, idle/active
  timeouts, flow finalization, behavioral/size/timing/TCP features, feature schemas,
  throughput claims, model work, detections, alerts, and hypotheses.

No test or report claims that an accepted PCAP produces ML-ready `NetworkFlow`
features. The E2E test affirmatively verifies that ingestion writes zero flows.

## 3. Baseline

| Item | SHA / value |
| --- | --- |
| Latest synchronized `main` | `45056b6c0b61ec78c39fca82ad8fea6da006577f` |
| `phase-00-complete` target | `097c01a40d3e153c3eaa6cfbea09f0ff981059fc` |
| `phase-01-complete` target | `a240805f53d7213bd4b0f074fa35964d5dfecc5b` |
| `phase-02-complete` target | `d5e1ba6b4df7614977a0330a4c38a56cec051241` |
| Verification branch | `test/phase-00-02-integration-verification` |
| Verification test-code commit | `23719785e8d7a0b6af4eca8e54b57c8b9042a55d` |
| Test date | 2026-07-16 (Asia/Shanghai) |

All three checkpoint tags were inspected with `git show --no-patch`; each is an
annotated tag and was neither moved nor rewritten.

## 4. Environment

- macOS 26.5.2 / Darwin 25.5.0, Apple arm64.
- Final clean clone: `/tmp/aegishunt-phase-00-02-final-20260716-rPYJ6Z`.
- Clean verification: Python 3.11.5, pip 23.2.1, SQLite 3.42.0.
- Project verification: Python 3.12.13, SQLite 3.50.4.
- Git 2.51.2; effective UID 501; no root or administrator privilege.
- Final clean install used `pip install -e ".[dev]"`; `PYTHONPATH` was unset.
- Dependency installation used PyPI. Runtime/test traffic used loopback only and
  made no external-network, live-capture, interface, scan, or fixed-target request.
- The optional wheel check was not executed because `build` is not declared or installed.

Dependency versions and isolation details are in [environment.md](environment.md).

## 5. Test Strategy

- Unit: existing schema, adapter, storage, API, CLI, config, and database contracts.
- Integration: defaults/YAML/environment, pragmas, transaction boundaries,
  pagination/update/missing-object semantics, audit, and empty startup.
- E2E: API and CLI ingest PCAP/CSV/JSON/JSONL/sample; close/recreate application
  and database objects; retrieve identical durable records.
- Negative/security: malformed/truncated/forged inputs, extension/media mismatch,
  size limits, traversal/absolute names, dedup/overwrite, unavailable storage,
  database outage, response hygiene, and valid-after-failure recovery.
- Concurrency: five small allowlisted jobs in parallel against SQLite WAL, then restart.
- Packaging: two independent fresh local clones and Python 3.11 virtual environments;
  no repository `PYTHONPATH` workaround.
- Review: initial failure recording before production changes, regression tests for
  confirmed defects, full diff/scope/secret/oversize scans, then assertion hardening.

## 6. Automated Test Results

| Check | Result |
| --- | --- |
| `ruff check .` | PASS |
| `mypy src` | PASS; 46 source files |
| `pytest` | PASS; 75 passed in 2.93 s on the clean preflight branch |
| Failed / skipped / xfailed | 0 / 0 / 0 |
| Branch-aware coverage | 91.97% |
| Coverage threshold | 85%; met |
| JUnit | Generated under `artifacts/test-reports/phase-00-02/junit.xml` |

Key module coverage from the final run:

| Module | Coverage |
| --- | ---: |
| `api/app.py` | 100% |
| `api/routes/ingestion.py` | 83% |
| `cli.py` | 94% |
| `config.py` | 89% |
| `ingestion/file_storage.py` | 90% |
| `ingestion/pcap.py` | 82% |
| `ingestion/flow_csv.py` | 82% |
| `ingestion/json_events.py` | 82% |
| `ingestion/service.py` | 94% |
| `storage/database.py` | 92% |
| `storage/repositories/core.py` | 95% |

The 72-test integration baseline passed in both the working environment and a
clean Python 3.11 clone. The final pre-Phase 3 cleanup adds two doctor cases and
passes all 75 tests in the project environment. Machine reports remain ignored by Git.

## 7. Phase 0 Results

| IDs | Result | Evidence |
| --- | --- | --- |
| P0-001–002 | PASS | Installed import and CLI help work with no `PYTHONPATH`. |
| P0-003 | PASS | Doctor reports sanitized configuration/database states and fails safely when unavailable. |
| P0-004–006 | PASS | API import, `/health`, `/docs`, and `/openapi.json` succeeded. |
| P0-007–008 | PASS | Frontend import and live headless health/root succeeded. |
| P0-009 | PASS | README records Phase 2 complete on `main` and Phase 3 not started. |
| P0-010 | PASS | No prohibited secret, database, upload, model, or large capture is tracked. |
| P0-WHEEL-001 | NOT_EXECUTED | `build` is not a declared dependency; no ad-hoc install was performed. |

The first clean-clone installation command was interrupted by the execution
harness before completion. The same unchanged command succeeded on retry, and a
second new clone then completed installation and all checks on its first attempt.
This is recorded as an initial environmental interruption, not a product pass or defect.

## 8. Phase 1 Results

### Configuration

- Defaults, YAML, environment precedence, relative paths, and invalid database URL
  rejection pass (P1-CONFIG-001–003, 005, 007).
- Database URL redaction initially failed and now passes after `b20a467` (P1-CONFIG-008).
- Field-level CLI overrides and a formal log-level setting do not exist in Phase 0–2;
  P1-CONFIG-004 and 006 are `NOT_APPLICABLE`. The unknown log-level environment
  value is still rejected as forbidden configuration rather than silently accepted.

### Database and repositories

P1-DB-001–015 pass. `init-db` is repeatable; schema version is `1`; all 11
expected tables exist; application connections return `journal_mode=wal`,
`foreign_keys=1`, and configured `busy_timeout=7000`. Commit persistence and
rollback were queried from new Sessions. Pagination is complete/ordered with no
duplicate, update persists, missing IDs return `None`, and five expected audit
events survive restart. Empty API and Streamlit startup are healthy.

`PRAGMA foreign_keys` is connection-scoped: a raw third-party SQLite connection
starts with its own default, while every application-created SQLAlchemy connection
was verified at `1`. This is expected SQLite behavior, not a failed application setting.

## 9. Phase 2 Results

- P2-SUCCESS-001–020: all PASS after the JSONL staging fix.
- PCAP: safe container framing only; one controlled packet record counted.
- Flow CSV: two rows validated; no canonical `NetworkFlow` persisted.
- JSON/JSONL: two structured records validated in API and CLI paths.
- Sample adapter: manifest/checksum-controlled PCAP and CSV paths pass.
- Every successful payload has a UUID, completed status, progress 1.0, byte size,
  independently matched SHA-256, safe stored name, legal timestamps, and empty error.
- Four mixed jobs produced 16 audit events; list/detail and a newly created Session
  returned the same objects; application restart returned byte-for-byte-equivalent JSON.
- P2-NEG-001–018 and 020 pass. P2-NEG-019 remains a documented partial fail:
  it now returns fixed HTTP 503, logs a sanitized fixed message, rolls back, and
  creates no false completed job, but cannot write a durable record to the failed database.

Independent SHA-256 evidence from the clean run:

- PCAP: `84aa852419452b33020b08aa329e54dd37ea454589318fd8ba437c3b3a9f2e9a`
- CSV: `b941140c30f4d7f823626d9861498998089bb5c993d12e6490350d9d6dcfd08a`
- JSON: `31c3b9ba346a791708f7cf4802ff762f8b43ff7dff4904d1310675970651c645`

## 10. Cross-Phase E2E Result

`CROSS-001` passes this chain:

1. Construct isolated configuration, upload root, and SQLite database.
2. Initialize schema and verify WAL/schema version.
3. Create the FastAPI application.
4. Upload PCAP, flow CSV, and structured JSON; ingest an allowlisted sample.
5. Validate exact stored bytes, sizes, independent checksums, IDs, timestamps,
   job states, TelemetrySource records, and audit events.
6. Close the API and database object.
7. Recreate application/engine/Sessions against the same temporary database.
8. Retrieve all four identical records by API and repository.
9. Verify zero `NetworkFlow` records, proving no Phase 3 behavior slipped in.

The path requires neither root, a live interface, an external service, nor a fixed target.

## 11. Security Validation

- Traversal and absolute multipart filenames: HTTP 422; exact outside targets absent.
- Unsupported extension and media mismatch: rejected before staging; no external write.
- Oversize: bounded at the configured 512-byte limit; durable failed job.
- Forged PCAP declared length: 36-byte input declaring nearly 4 GiB returned quickly
  with HTTP 422; no unbounded read or memory exception.
- Malformed PCAP/CSV/JSON: safe HTTP 422; staged objects cleaned; durable failed jobs
  where a lifecycle had already begun.
- Duplicate names/content: three unique jobs, one checksum-addressed object, no overwrite.
- Unavailable storage: safe `file_storage_error`, failed job, no local path leakage.
- Response hygiene: no tested credential, SQLite URL, SQL statement, traceback, or
  complete temporary path appears in negative API responses.
- Valid ingestion remained functional after the negative sequence.

## 12. Persistence Validation

- Repository commit was read through a new Session; rollback was absent in a new Session.
- Successful and failed ingestion jobs and audits were queried after Session closure.
- Four E2E jobs remained identical after application/engine recreation.
- Five concurrent jobs and 20 audit records remained after database restart.
- Runtime databases/uploads lived only in temporary directories and are not tracked.

## 13. Defects

| ID | Severity | Status | Summary | Fix / evidence |
| --- | --- | --- | --- | --- |
| DEF-001 | High | Resolved | JSONL lost suffix during staging | `6042097`; final regression PASS |
| DEF-002 | High | Resolved | Database URL credentials leaked in repr | `b20a467`; final regression PASS |
| DEF-003 | Medium | Resolved | Doctor now reports safe config/database status | `45d29c4`; P0-003 PASS |
| DEF-004 | Medium | Open | DB outage cannot persist its own failed job | Safe 503/log in `495e795`; P2-NEG-019 |
| DEF-005 | Low | Resolved | README records merged Phase 2 status | `2a33b82`; P0-009 PASS |

Detailed reproduction, expected/actual, root cause, and retest evidence are in
[known-defects.md](known-defects.md). No failing test was removed, skipped, or weakened.

## 14. Limitations

- Jobs execute synchronously; the concurrency check is functional, not a benchmark.
- Total database loss is fail-closed with a fixed HTTP 503 and sanitized log but
  cannot be durably recorded in that same unavailable database.
- The manifest-controlled sample catalog includes PCAP and CSV; JSON/JSONL use
  controlled temporary fixtures.
- PCAPNG is limited to one section as documented by Phase 2.
- Wheel build/install was not run because `build` is not a declared dependency.
- External network was not physically disabled at OS level, but tests made no external calls.
- No Phase 3 behavior or performance measurement was attempted.

## 15. Requirements Traceability

The machine-readable mapping is in
[requirement-traceability.csv](requirement-traceability.csv). It covers the
Phase 0 install/CLI/API/frontend/quality gates, Phase 1 config/schema/storage/audit
foundation, Phase 2 PCAP/CSV/JSON/sample/lifecycle/security/API contracts, the
cross-phase restart chain, concurrency, and the Phase 3 exclusion boundary.

## 16. Phase 3 Readiness

Verdict: **CONDITIONALLY READY**.

No Blocking or open High defect remains. DEF-003 and DEF-005 are resolved.
DEF-004 limits outage observability but does not prevent Phase 3 from consuming
completed, validated telemetry in an isolated transaction.

Phase 3 will depend on these verified contracts:

- `TelemetrySource` completed/failed states and source type metadata.
- Checksum-addressed stored objects confined to the configured ingestion root.
- PCAP framing validation and bounded reads; Phase 3 must not bypass them.
- Database/session/repository transaction boundaries, WAL, foreign keys, and audits.
- Stable API/CLI job IDs and durable retrieval after restart.
- The strict boundary that Phase 2 does not create `NetworkFlow` rows.

Risks for Phase 3: a packet parser must preserve the bounded-read guarantees,
must keep file validation separate from flow transactions, must define restart-safe
finalization, and must not treat the synchronous Phase 2 call as a throughput result.

## 17. Reproduction Commands

```bash
git clone --branch test/phase-00-02-integration-verification --single-branch \
  <local-or-github-aegishunt-repository> aegishunt-verification
cd aegishunt-verification
python3.11 -m venv .venv
source .venv/bin/activate
unset PYTHONPATH
python -m pip install -e ".[dev]"
aegishunt --help
aegishunt doctor
python -c "import aegishunt; print(aegishunt.__file__)"
ruff check .
mypy src
pytest
mkdir -p artifacts/test-reports/phase-00-02
pytest --cov=src/aegishunt \
  --cov-report=term-missing \
  --cov-report=xml:artifacts/test-reports/phase-00-02/coverage.xml \
  --cov-report=json:artifacts/test-reports/phase-00-02/coverage.json \
  --junitxml=artifacts/test-reports/phase-00-02/junit.xml
```

The automated tests allocate their own databases, storage roots, and loopback
clients. They require no root, target address, live network capture, or external service.

## 18. Final Verdict

**CONDITIONALLY READY**

Phase 0–2 form a reproducible integration baseline suitable for starting Phase 3
after this PR is reviewed. The open Medium/Low findings must remain tracked, but
none blocks isolated packet-to-flow work. Phase 3 has not started in this branch.
