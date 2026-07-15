# Phase 03 Release Notes

## Objective

Convert safely staged PCAP telemetry into deterministic bidirectional
`NetworkFlow` records and a versioned, fixed-order, finite behavioral feature
vector without starting dataset or model work.

## Status

Implementation complete — awaiting PR review on
`phase/03-flow-feature-engineering` in PR
[#9](https://github.com/SaXingrui-UM/aegishunt/pull/9). It is not Phase complete
until a later user-reviewed merge and explicitly authorized checkpoint tag.

## Completed scope

- Streaming classic PCAP and supported PCAPNG packet reading with allocation and record bounds.
- Payload-independent Ethernet/raw-IP parsing for IPv4/IPv6 TCP, UDP, ICMP, and ICMPv6.
- Explicit skip policy for non-IP, fragments, unknown transports, and unsupported link types.
- Canonical comparable/serializable keys and first-packet forward direction.
- Bounded flow state with directional counts, sizes, timestamps, and TCP flags.
- Active/idle/capacity segmentation plus idempotent capture-end/manual flush.
- Stable volume, size, timing, TCP evidence, and basic single-flow behavior features.
- Feature registry/schema `1.0.0`, deterministic JSON export, and feature dictionary.
- Repository/audit integration with atomic flow-set and completed-job persistence.
- Unit, integration, API E2E, deterministic replay, restart, and malformed-input coverage.

## Architecture decisions

ADR 0011 records parser and transaction boundaries, canonical key and direction,
active-before-idle `>=` timeout semantics, sorted timestamp calculations,
zero-division behavior, schema versioning, and atomic persistence.

The database schema remains version `1`. Feature vectors use the existing flat
JSON field and contain finite numeric values only. The source metadata records
feature schema version, flow count, and decoded/skipped packet counts.

## Major files

- `src/aegishunt/flows/`
- `src/aegishunt/ingestion/service.py`
- `artifacts/feature_schema.json`
- `docs/feature_dictionary.md`
- `docs/adr/0011-deterministic-packet-to-flow-contract.md`
- Phase 3 unit, integration, and E2E tests under `tests/`

## Tests

Pre-review validation on 2026-07-16 passed:

- `ruff check .`: pass.
- `mypy src`: pass across 57 source files.
- `pytest`: 108 passed, 0 failed, 0 skipped, 0 xfailed after review fixes.
- Branch-aware coverage: 87.83% (project threshold: 85%).
- Focused packet/parser/aggregation/feature tests: 25 passed.
- PCAP-to-flow integration and E2E tests: 7 passed.
- Deterministic replay, restart persistence, schema export, timeout boundaries,
  malformed/truncated captures, and no-partial-flow rollback are covered and pass.

The post-review run passed. At this checkpoint the initial branch `quality` check
passed and the latest PR `quality` check is in progress; no pending result is
reported as successful.

## Review outcome

Native `codex review --base main` could not launch because its packaged arm64
executable is missing (`ENOENT`). The equivalent read-only manual review found no
Blocking or High issue. One Medium gap (no explicit bidirectional UDP aggregation
test) and one Low documentation-count mismatch were fixed in `242e1f3`; all local
checks then passed again. The second manual pass found no remaining blocking,
high, or unhandled medium finding.

## Generated artifacts

`artifacts/feature_schema.json` is a reviewed deterministic 43-feature schema and
is committed. Tests create only temporary synthetic PCAPs and SQLite databases;
they are removed by `tmp_path` and are not committed.

## Known limitations

- Packet decoding supports Ethernet and raw IPv4/IPv6 link types; unsupported link layers are skipped.
- Fragmented IP packets are skipped rather than reassembled.
- PCAPNG simple packet blocks lack timestamps and fail explicitly; multi-section PCAPNG remains unsupported.
- Nanosecond capture timestamps are represented at Python `datetime` microsecond precision.
- In-memory packet observations and active flows are bounded but not yet performance-benchmarked.
- Cross-flow repeated destination/port and short-connection-window features are not fabricated.
- Flow list/detail HTTP/UI surfaces and timed replay belong to later interface/runtime phases.
- DEF-004 remains open and non-blocking: a total database outage cannot record its own failure in that database.
- On the current Codex macOS host, the editable console script still requires
  the known `PYTHONPATH=src` workaround despite successful editable installation;
  automated package imports and tests pass, but this host-specific manual CLI
  limitation remains recorded rather than reported as a standard-install pass.

## Migration notes

No database migration is required. Existing Phase 1/2 databases keep schema
version `1`; the pre-existing `network_flows` table is now populated through its
repository contract.

## Version-control checkpoint

- Branch: `phase/03-flow-feature-engineering`
- Baseline main: `5d4b26f91e9bdae118de26ddb71c11b6fda08ccb`
- Latest reviewed implementation commit: `242e1f35dabfe936c36dce485d0403fcf5e10249`
- Pull request: [#9](https://github.com/SaXingrui-UM/aegishunt/pull/9), open and ready for review
- Merge commit: pending
- Tag: pending; `phase-03-complete` must not be created before merge

## Next phase

Phase 4 — Dataset Quality, Registry, Splitting, and Leakage Control is not started.
It must not begin before this Phase 3 PR is reviewed and merged and the user
explicitly authorizes the next phase.
