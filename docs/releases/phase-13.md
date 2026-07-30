# Phase 13 Release Notes

## Objective and status

Harden the completed Phase 0–12 local research prototype, validate malformed
input and artifact boundaries, establish reproducible performance/robustness
evidence, and preserve the scientific and audit contracts of earlier phases.

Status: **Phase complete**.

- Source branch: `phase/13-hardening`
- Pull request: [#39](https://github.com/SaXingrui-UM/aegishunt/pull/39),
  `[Phase 13] Hardening, performance, robustness, and security validation`
  (Merged)
- Final source-branch Head:
  `5b183a53d76aaa72807200e6d54793e9c0a4fcda`
- Canonical squash merge:
  `38e5b8b905aba50ff9acfc7f84f850f03eb3f2f3`
- Completion tag: annotated `phase-13-complete`
- Tag target: `38e5b8b905aba50ff9acfc7f84f850f03eb3f2f3`
- Phase 14: Not started

## Completed scope

- Added raw streaming request-body enforcement before multipart parsing.
- Replaced whole-file JSON/JSONL telemetry loading with incremental bounded
  parsing, per-record byte ceilings, logical record limits, finite-value
  validation, and nesting-depth limits.
- Added a configured PCAPNG interface-inventory bound.
- Replaced per-packet active-flow scans with a deadline heap and bounded stale
  entry compaction while preserving active-before-idle timeout semantics.
- Replaced rounded near-duplicate fingerprints with exact tolerance components
  for dataset quality and cross-split leakage.
- Bound controlled-generator provenance to exact deterministic regeneration.
- Required verified supervised/anomaly identities and feature schema before
  fusion refitting.
- Enforced disabled reason-code catalog entries at generation time.
- Added a stable per-package core coverage definition and machine-readable
  gate: repository combined statement/branch coverage remains at least 85%,
  and every declared core package must independently reach at least 80%.
- Added a versioned 21-scenario robustness matrix and isolated runner.
- Added performance protocol 1.1 with 100-sample micro/API measurements,
  truthful unavailable p99 for bounded runs below 100 samples, seven read-only
  API scenarios, cold/warm separation, and seven explicit RSS scenarios.
- Ran real `pip-audit`, bounded reachable-history `detect-secrets`, and Bandit
  gates; added independent fail-closed CI jobs for security, robustness,
  performance smoke, and quality. The history scan covered 1,264 text blobs,
  skipped 18 binary blobs and one explicitly documented bounded oversized
  historical blob, and reported zero confirmed secrets, zero unreviewed
  candidates, and zero stale allowlist entries. Current tracked files remain
  subject to the normal secret scan; passing the gate does not mean every
  reachable blob was scanned. GitHub's optional dependency-diff Action is not
  retained because this repository does not have the required Dependency Graph
  plus GitHub Advanced Security capability; that unsupported run is recorded as
  a failure rather than a pass, while the required security job retains
  `pip check` and online `pip-audit`.
- Represented all 80 immutable Codex Security baseline findings, including all
  73 Low findings, in a validated per-finding disposition ledger.

## Architecture decisions

ADR 0022 records earliest-boundary streaming limits, incremental JSON parsing,
deadline-indexed flow timeout processing, exact near-duplicate components,
controlled-generator equivalence, fusion identity binding, catalog enforcement,
and isolated performance/robustness evidence.

No distributed broker, public service, live capture, production authentication,
deployment wrapper, automatic response, automatic training/activation, new
public dataset, or Phase 14 functionality was added.

## Commits

- `71fc9c0` — `fix: bound untrusted telemetry and flow state`
- `3638353` — `fix: strengthen dataset and fusion integrity`
- `93290cc` — `test: cover phase 13 security regressions`
- `f1cf2b8` — `perf: add reproducible phase 13 benchmark`
- `a34a541` — `test: add phase 13 robustness matrix`
- `3292edc` — `fix: correct robustness provenance test node`
- `db29f9c` — `test: enforce phase 13 core coverage gate`
- `bc4c531` — `test: expand phase 13 boundary regressions`
- `05d67f6` — `fix: honor disabled explanation reason codes`
- `9322652` — `fix: emit reviewable phase 13 csv`
- `a4c0cf9` — `docs: document phase 13 hardening evidence`
- `11c0d4d` — `docs: record phase 13 implementation checkpoint`
- `a29d657` — `ci: add phase 13 deterministic smoke gates`
- `7e9e785` — `docs: record phase 13 final coverage evidence`
- `f8d424e` — `fix: reject extreme json depth before decoding`
- `dbff140` — `docs: record phase 13 review outcome`
- `f44b71f` — `security: add auditable dependency secret and static gates`
- `fcb5a2b` — `docs: disposition phase 13 security findings`
- `d7ce725` — `test: preserve cli diagnostics across dependency upgrades`
- `970471e` — `test: enforce per-package core coverage`
- `3e8cda0` — `perf: correct percentile api and memory evidence`
- `588de65` — `ci: add phase 13 security and audit gates`
- `718c3b8` — `test: remove host-dependent anomaly score literals`
- `7ebd844` — `docs: record phase 13 final remediation evidence`
- `76af316` — `test: correct phase 13 status assertion`
- `354baf2` — `docs: record phase 13 final local checks`
- `6fcb415` — `ci: fix clean-linux phase 13 gates`
- `3b130a2` — `docs: record phase 13 clean-linux remediation`
- `5b183a53d76aaa72807200e6d54793e9c0a4fcda` —
  `docs: align phase 13 security waiver evidence`

These are the source-branch commits retained by PR #39. GitHub squash-merged
their content into the distinct canonical commit
`38e5b8b905aba50ff9acfc7f84f850f03eb3f2f3`.

## Tests and coverage

### Startup baseline

- Ruff: passed.
- Strict mypy: passed for 237 source files.
- Repository pytest: 465 passed, 0 failed, 0 skipped, 0 xfailed in 1,563.08
  seconds at 85.34% branch-aware coverage.
- Corrected Phase 12 API/frontend/demo/security/status gate: 63 passed in 81.69
  seconds.
- One earlier focused command used a nonexistent test path and a zsh readonly
  variable. It failed before collection, was corrected, and was not counted as
  a product pass.

### Phase 13 focused evidence

- Input/integrity/benchmark/robustness/core-coverage focused selections passed.
- Reason-code focused suite: 10 passed; strict mypy remained clean.
- Final robustness matrix v1.1.0: 21 scenarios, 27 represented test instances,
  21 PASS and 0 FAIL.
- Initial robustness v1.0.0 run: 16 PASS / 1 FAIL because ROB-011 named an old
  test function. The matrix was corrected and fully rerun; the failure was not
  hidden or converted to skip.
- The first complete run after the necessary dependency updates collected 518
  tests and reported 515 passed / 3 failed. All three failures were stale
  Click/Typer assertions that looked only at stdout after the upgraded CLI
  correctly placed sanitized diagnostics in stderr; production behavior and
  security handling were unchanged. The corrected focused run passed 3/3.
- A final complete rerun after the status-assertion correction passed 522 tests
  with 0 failures, 0 skips, and 0 xfails in 1,650.90 seconds at 85.74%
  branch-aware coverage.
- Passing complete runs observed 85.74–85.78% repository combined
  statement/branch coverage. All 17 declared core packages pass their separate
  80% gates; the lowest is `flows` at 81.58%. Strict mypy passes all 237 source
  files and Ruff passes the complete repository.
- A first standalone offline E2E rerun reported 21 passed / 1 failed because
  two historical tests hard-coded the score of one Phase 6 candidate even
  though the registered 1.0.0 policy intentionally uses host timing as its last
  tie-break. The tests now verify the selected bundle identity, hyperparameters,
  frozen threshold, finite score contract, decision rule, and exact
  independent-process equality without changing the Phase 6 policy or model.
  The corrected focused suite passed 8/8 and the complete offline E2E passed
  22/22 in 131.46 seconds.
- The next exact-Head full run reported 521 passed / 1 failed because the newly
  added status regression expected lowercase `all` while the truthful progress
  text begins the sentence with `All`. The assertion was corrected exactly;
  no product behavior, evidence, threshold, coverage rule, skip, or xfail was
  changed.
- Final Ruff passed; strict mypy passed for 237 source files.
- The final Phase 13 focused selection passed 29 tests in 3.73 seconds; the
  complete offline E2E selection passed 22 tests in 139.74 seconds.
- Benchmark smoke and robustness smoke both completed with reviewed output
  contracts. CI runs those deterministic smoke modes, not the formal full
  development-host benchmark or robustness experiment.
- The first refreshed CI execution of the hardened workflow exposed three
  environment contracts before any merge claim. The optional official
  Dependency Review Action was unsupported by the repository's GitHub feature
  set. The required security job found the Python 3.11 virtual environment's
  bundled `setuptools 65.5.0`; the build and development contracts now require
  the audited 83.x line, and a clean Python 3.11 reproduction audits 110
  distributions with zero advisories. The robustness job also exposed that the
  `pytest` console entry point did not put the repository root on `sys.path`;
  all CI pytest steps now use the portable `python -m pytest` form. The same
  clean environment passed the 53-test robustness/security selection. Three
  dedicated CI-contract regressions preserve these corrections.
- After installing the declared setuptools 83.x dependency into the primary
  development environment, the final full regression passed all 527 tests with
  0 failures, 0 skips, and 0 xfails in 1,555.14 seconds. Branch-aware repository
  coverage was 85.73%, and all 17 core packages retained their separate 80%
  pass status.
- Final Head `5b183a53d76aaa72807200e6d54793e9c0a4fcda` passed eight GitHub
  checks: two successful `quality`, two `security`, two `robustness`, and two
  `performance-smoke` results. PR #39 was then squash-merged by the user.

### Merged-main checkpoint verification

- The initial bare-shell command attempt did not activate the project virtual
  environment: `ruff` was absent from PATH and the system Python 3.13 mypy
  lacked project dependencies. This environment failure was retained, and all
  required checks were rerun with the declared `.venv`.
- Ruff passed. Strict mypy passed all 237 source files.
- The complete merged-main suite passed 527 tests with 0 failures, 0 skips,
  and 0 xfails in 1,555.35 seconds. Branch-aware coverage was 85.79%.
- The core coverage gate passed all 17 packages at or above 80%; `flows`
  remained the lowest at 81.58%.
- The focused security selection passed 17 tests; the 80-row ledger validator
  passed. Bandit reported 45 Low and 0 blocking findings. `pip-audit` checked
  114 Python 3.12 distributions with 0 advisories and `pip check` passed. The
  longer merged history produced 1,293 unique scanned text blobs while still
  disclosing one bounded oversized historical-blob exclusion; it reported 0
  confirmed secrets, 0 unreviewed candidates, and 0 stale allowlist entries.
  The committed PR-head evidence remains the earlier 1,264-historical-text-blob
  snapshot and is not retroactively rewritten.
- Robustness-focused tests passed 53/53. Its bounded smoke matrix passed 1/1
  without network, root, or frozen-evidence regeneration.
- Performance-tool tests passed 7/7, and the controlled offline performance
  smoke completed. Its one-sample observations are execution evidence, not a
  latency target, SLA, production-capacity result, or public benchmark.
- After adding the durable checkpoint state and its direct status regressions,
  the final checkpoint-branch suite passed all 528 tests with 0 failures,
  0 skips, 0 xfails, and 18 warnings in 1,552.44 seconds at 85.73%
  branch-aware coverage. Ruff and strict mypy for 237 source files remained
  clean.

## Review outcome

Native `codex review --base main` could not start because the local arm64 vendor
executable was missing (`ENOENT`). The equivalent read-only diff review found
one correctness-related Medium: extreme JSON nesting could reach decoder
recursion before the post-decode depth check. Commit `f8d424e` added a
pre-decode structural-depth gate plus extreme-depth and underreported streaming
body regressions. Final review has 0 Blocking, 0 High, and 0 unresolved Medium
findings.

The repository-wide 85% branch-aware threshold was not lowered. CLI and
Streamlit are excluded only from the separately frozen 80% core subset and
remain in repository coverage.

The formal repository-wide Codex Security rescan was prepared against the
then-current exact Head and passed capability preflight, but it was canceled
before discovery when refreshed CI exposed defects that required a new commit.
The final exact-head Codex Security rescan was explicitly waived by the user,
was not executed, and no final-rescan result is claimed. Bandit, the
secret-history gate, the dependency audit, and the baseline ledger are
complementary controls and are not represented as a substitute result.

## Performance baseline

Protocol 1.1 uses the reviewed `phase12-presentation-demo.pcap` (32 packets, 9
flows), seed `4204`, 5 warm-ups and 100 measured samples for micro/API
scenarios. Cold artifact load and full-pipeline runs remain bounded at 10
samples, so their p99 is null with `insufficient_samples`. Seven TestClient GET
routes each returned HTTP 200 for 100 measured requests and passed an ORM
no-mutation check. Seven memory scenarios record baseline, peak, delta,
sampling interval, status, and limitations.

The current reports are under
`reports/hardening/phase-13/performance-v1.1/`. Full-pipeline p50 was
6,223.5294 ms and throughput was 1.4484 persisted flows/s on this host. These
values are development-host observations only—not an SLA, public benchmark,
production capacity, or real-world detection result.

## Robustness result

All 21 versioned scenarios passed in isolated processes. They cover corrupted
PCAP, invalid CSV, pre-parser upload limits, exact/over upload boundaries,
schema drift, path traversal, SQLite concurrency/rollback, corrupt and colliding
model artifacts, fusion-policy integrity, duplicate ingestion, controlled
provenance, bounded JSON/PCAPNG parsing, cross-split near duplicates, idempotent
Demo execution, and atomic flow persistence.

No formal frozen test was reopened. All model/evidence work used pytest
temporary directories or the ignored isolated Demo namespace.

## Security baseline

The user-confirmed repository baseline at
`75c73bc86a40a78a22edde5fb175359a7b755c05` covered all 448 tracked files and
reported 7 Medium, 73 Low, 0 High, and 0 Critical findings. It was not rerun.

- All seven Medium findings have regression-backed Phase 13 remediations.
- Two Low findings have direct Phase 13 fixes (excessive JSON nesting and
  disabled reason-code enforcement).
- All 80 findings and all 73 Low findings are individually represented:
  9 Fixed, 39 Accepted risk, 19 Deferred to Phase 14, 13 Needs further
  validation, and 0 Untriaged.
- `pip-audit` 2.10.1 audited 114 Python 3.12 distributions and 110 clean
  Python 3.11 distributions and found zero advisories in either environment;
  `pip check` passed.
- `detect-secrets` 1.5.0 scanned the current tree and generated PR body, plus
  1,264 reachable historical text blobs subject to one explicitly documented
  bounded oversized-blob exclusion. It skipped 18 binary blobs and one
  oversized historical blob, with zero confirmed secrets, zero unreviewed
  candidates, and zero stale allowlist entries. Current tracked files remain
  under the normal scan; passing does not mean every reachable blob was scanned.
- Bandit 1.9.4 reported 45 Low and 0 Medium/High findings, with no scanner
  errors and no suppression.
- These complementary tools are not represented as a formal Codex Security
  full-repository rescan. The user explicitly removed that final rescan from
  this task, and no rescan result is claimed.

## Generated artifacts

Committed, small, reviewed evidence:

- performance JSON/CSV/Markdown summaries;
- robustness JSON/CSV/Markdown summaries;
- Phase 13 method, traceability, security, ADR, and release documentation.

Not committed:

- temporary SQLite databases;
- isolated demo model binaries and policy artifacts;
- coverage machine output;
- raw subprocess logs;
- the environment-owned Codex Security scan directory;
- any runtime upload or staging file.

## Known limitations

- Performance uses a small controlled synthetic PCAP on one Darwin arm64
  development host; it cannot establish production capacity.
- No noisy latency threshold is used in CI.
- The baseline ledger retains 39 accepted, 19 Phase 14-deferred, and 13
  further-validation findings; stronger deployment custody remains a Phase 14
  concern.
- Dependency findings are point-in-time; Phase 14 must preserve recurring audit
  execution.
- SQLite remains a single-node store. DEF-004 remains: total database
  unavailability cannot persist a failure record into that same database.
- The desktop runtime can hide editable-install `.pth`; recorded manual
  commands use `PYTHONPATH=src`, while pytest and normal CI use the declared
  source layout.
- Controlled synthetic evidence is pipeline verification only, not a public
  benchmark, production validation, real-world performance, or zero-day proof.
- Phase 6 LOF remains validation-qualified without an untouched independent
  holdout; Phase 7 fusion remains inconclusive and is not superior to every
  single-engine result.

## Next phase

Phase 14 — Final Integration and Delivery — is **Not started**.

Phase 14 startup must verify that the working tree is clean, `main` is
fast-forward synchronized with `origin/main`, PR #39 and its eight final-head
checks remain successful, annotated `phase-13-complete` still peels to
`38e5b8b905aba50ff9acfc7f84f850f03eb3f2f3`, that commit is an ancestor of
then-current `main`, the Phase 14 branch remains absent, merged-main baselines
pass, and the user explicitly authorizes Phase 14. A later documentation-only
`main` descendant does not invalidate the checkpoint and does not require
another Phase 13 status-closure PR.
