# Phase 11 Release Notes

## Objective and status

Join the completed offline PCAP, flow, scoring, alert, correlation, and
hypothesis components with a durable, observable, interruptible single-node
runtime.

Status: **Implementation complete — awaiting PR review**.

- Branch: `phase/11-runtime-replay`
- Pull request: pending
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
- Existing idempotent Phase 9 correlation and hypothesis generation after EOF.
- Bounded process/resource monitoring with explicit unavailable semantics.
- Typer runtime operations and truthful Streamlit runtime status shell.
- Unit, migration, claim-race, transaction, integration, restart, drift,
  malformed-PCAP, CLI, frontend, and real temporary-bundle E2E coverage.

## Architecture decisions

ADR 0020 records deterministic origin replay, single-node SQLite queue/leases,
verified artifact snapshots, transactional output ledgers, explicit recovery,
disabled live capture, and bounded resource observations.

## Tests

- Baseline before branch creation: Ruff passed; strict mypy passed for 185
  source files; 389 tests passed with 86.01% branch-aware coverage.
- Phase 11 focused implementation selection: 44 tests passed in 38.70 seconds.
- Final full quality and coverage results: pending final execution.

## Known limitations

- Runtime execution is single-node SQLite, not distributed processing.
- Recovery restarts from packet zero; it is not exact packet-cursor resume.
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
