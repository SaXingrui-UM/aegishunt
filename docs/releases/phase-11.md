# Phase 11 Release Notes

## Objective and status

Join the completed offline PCAP, flow, scoring, alert, correlation, and
hypothesis components with a durable, observable, interruptible single-node
runtime.

Status: **Implementation complete — awaiting PR review**.

- Branch: `phase/11-runtime-replay`
- Pull request: [#33](https://github.com/SaXingrui-UM/aegishunt/pull/33) —
  Open, ready for review
- CI: GitHub reports required checks against the current pushed PR Head; all
  required checks must pass before merge
- Merge commit: pending
- Completion tag: pending; do not create before merge
- Phase 12: Not started

## Completed scope

- Strict checksummed runtime policy and configured replay/worker/resource bounds.
- Additive schema v4→v5 with durable jobs, attempts, workers, resource samples,
  and output ledgers.
- Atomic oldest-job claim, bounded lease/heartbeat, stale reconciliation,
  pause/resume, graceful interruption, explicit origin recovery, and no
  automatic requeue.
- Source-ID-only job creation and complete model/policy/source preflight before
  job persistence and again before the first packet.
- Interruptible event-time PCAP replay with speed, gap cap, out-of-order/gap
  counters, existing Phase 3 packet/flow semantics, and EOF flush.
- Transactional flow/detection/optional-alert/ledger/progress batches.
- Separate `non_durable_live_observation` packet telemetry from
  `durable_committed_evidence` counters/progress. Open flows and uncommitted
  batches never advance the durable packet position; recovery resets the new
  attempt and retains both layers on the historical attempt.
- Existing idempotent Phase 9 correlation and hypothesis generation after EOF.
- Job-scoped downstream counters derived only from the current job's output
  ledger, so unrelated historical groups or hypotheses are never counted as
  runtime outputs.
- Bounded process/resource monitoring with explicit unavailable semantics.
- Startup reconciliation of stale active worker status using the configured
  threshold without implicitly requeuing or recovering interrupted jobs.
- Typer runtime operations and truthful Streamlit runtime status shell.
- Unit, migration, claim-race, transaction, integration, restart, drift,
  malformed-PCAP, CLI, frontend, and real temporary-bundle E2E coverage.

## Architecture decisions

ADR 0020 records deterministic origin replay, single-node SQLite queue/leases,
verified artifact snapshots, transactional output ledgers, explicit recovery,
disabled live capture, bounded resource observations, and the separate observed
versus durable progress contracts. Phase 11 intentionally uses a conservative
zero-until-final-completion durable packet position instead of inventing an
exact cursor without persisted open-flow state.

## Tests

- Baseline before branch creation: Ruff passed; strict mypy passed for 185
  source files; 389 tests passed with 86.01% branch-aware coverage.
- Phase 11 focused implementation selection: 44 tests passed in 38.70 seconds.
- The first Phase 11 full-suite run exposed three stale schema-v4 test
  expectations; commit `595f79d` updated those tests to the additive v5 schema
  contract without weakening their assertions.
- Final Ruff passed; strict mypy passed for 205 source files; all 427 tests
  passed with zero failures, skips, or xfails in 1,248.47 seconds. Branch-aware
  coverage was 86.07%, above the unchanged 85% gate.
- Durable-progress corrective focused verification passed 53 tests in 37.78
  seconds. The final corrective full suite passed 437 tests with zero failures,
  skips, or xfails in 1,253.12 seconds. Branch-aware coverage was 86.20%, above
  the unchanged 85% gate; Ruff and strict mypy for 205 source files also passed.
- The strengthened PCAP-to-runtime E2E used a controlled temporary capture and
  verified real flow, detection, alert, correlation-group, and hypothesis
  evidence plus restart persistence. The corrective E2E also verifies a
  committed flow beside an in-memory open flow, pause/resume on one attempt,
  interruption before durable evidence, origin recovery, output reuse, and the
  final downstream completion gate. It did not stub downstream services or
  create formal experiment evidence.

## Review outcome

Native `codex review --base main` could not start because the installed arm64
Codex executable is missing (`ENOENT`). An equivalent read-only review found:

- current-job counters could include unrelated historical correlation and
  hypothesis evidence;
- a resume audit event used the prior lifecycle timestamp;
- the original E2E did not require alerts, groups, and hypotheses;
- cooperative signal-handler registration lacked direct regression coverage;
- the configured stale-worker threshold was not applied to persisted worker
  status during startup;
- some runtime lifecycle audit records lacked complete structured context.

Commits `5789356`, `1056ad9`, `7d8eb22`, `fcdd2ca`, `ce70330`, and `720f4c3`
closed those findings with regression coverage. The final equivalent review
found zero Blocking, zero High, and zero unresolved correctness-related Medium
findings. No Phase 12 functionality was introduced.

A later PR review identified that periodic control updates persisted live packet
counters before an open flow or pending batch had durable evidence. The
corrective implementation splits observed telemetry from durable evidence,
keeps the latter in domain-output transactions, resets recovery from origin,
and reaches 100% only after final correlation/hypothesis completion. Its
pre-fix regression reproduced observed packet progress with zero Flow,
DetectionResult, SecurityAlert, and ledger rows. Corrective review and new-Head
CI results are recorded in the PR checkpoint before merge.

## Manual verification

The runtime CLI help, policy verification, disabled live-capture status, and
empty runtime status were exercised against a temporary database outside the
repository. The desktop environment did not expose the editable-install
`.pth`, so the bare console command failed with `ModuleNotFoundError`; the
recorded `PYTHONPATH=src` workaround passed. This workaround is not represented
as a standard editable-install success.

## Commits

- `288c39d` — `feat: add persistent runtime job foundation`
- `896ee77` — `feat: orchestrate verified pcap replay pipeline`
- `4c18e89` — `feat: add runtime worker and operator controls`
- `c5866f9` — `test: cover phase 11 runtime and recovery boundaries`
- `4dcbcaf` — `docs: document phase 11 runtime and recovery`
- `595f79d` — `test: update schema version five expectations`
- `5789356` — `fix: scope downstream runtime counters to job evidence`
- `1056ad9` — `fix: timestamp runtime resume audit events`
- `7d8eb22` — `test: require complete replay downstream evidence`
- `fcdd2ca` — `test: cover cooperative runtime signal handlers`
- `ce70330` — `fix: reconcile stale runtime worker status`
- `720f4c3` — `fix: complete runtime lifecycle audit context`
- `17ca582` — `fix: separate observed and durable runtime progress`
- `2a6ba1c` — `test: cover pre-commit runtime interruption`

## Known limitations

- Runtime execution is single-node SQLite, not distributed processing.
- Recovery restarts from packet zero; it is not exact packet-cursor resume.
- Open-flow state is in memory only. Observed progress is live telemetry, not a
  checkpoint; pause/resume retention applies only to the same living worker.
- Only offline PCAP replay is enabled; live capture is safely disabled.
- Source/artifact bundles must already exist under configured roots.
- Resource observations are not production SLAs.
- Complete runtime HTTP endpoints and frontend workflows remain Phase 12.
- DEF-004 remains: a fully unavailable database cannot persist an outage record
  into that same database.

## Next phase

Phase 12 — Complete API and Frontend, planned branch
`phase/12-api-frontend`. It is **Not started** and requires PR merge, checkpoint
instructions, and explicit user authorization.
