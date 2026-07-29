# Phase 13 Performance Baseline

## Purpose and evidence versions

This document records the reproducible development-host baseline produced by
`scripts/run_phase13_benchmark.py`. It is not an SLA, public benchmark,
production-capacity claim, or detection-performance result.

- Current benchmark schema/protocol: `1.1.0`
- Superseded evidence: `reports/hardening/phase-13/performance/`
- Current evidence: `reports/hardening/phase-13/performance-v1.1/`
- Controlled input: `phase12-presentation-demo.pcap`
- Input SHA-256:
  `0d272ac98660eb119cded8be194a513c2db82b475d4cce982a120eb210a8ab51`
- Per iteration: 32 packets and 9 finalized flows
- Random seed: `4204`
- Environment: CPython 3.12.13, Darwin 25.5.0, arm64, 10 logical CPUs

Protocol 1.0 used ten samples and over-reported exact p99 values. It remains
available as historical evidence but is superseded. Protocol 1.1 requires at
least 100 measured samples before reporting p99, excludes warm-ups from the
sample count, and writes `null` plus `insufficient_samples` otherwise.
Percentiles use deterministic linear interpolation.

## Sample design

- Micro and API scenarios: 5 warm-ups, 100 measured samples
- Cold artifact load: 0 warm-ups, 10 measured samples
- Full pipeline: 0 warm-ups, 10 measured samples
- Case report/export: 0 warm-ups, 10 measured samples
- RSS sampling interval: 2 ms
- Execution: one offline sequential process, no root, live capture, browser,
  external target, or public network workflow

## Component results

| Component | Samples | p50 ms | p95 ms | p99 ms | p99 status |
| --- | ---: | ---: | ---: | ---: | --- |
| PCAP packet parsing | 100 | 0.0687 | 0.1841 | 0.2801 | available |
| Flow aggregation/features | 100 | 2.1424 | 6.1036 | 6.5766 | available |
| Supervised warm inference | 100 | 1.1143 | 1.3847 | 1.4251 | available |
| Anomaly warm inference | 100 | 0.5157 | 0.6636 | 0.7511 | available |
| Fusion | 100 | 0.0365 | 0.0380 | 0.0480 | available |
| Supervised/anomaly artifact load | 10 | 38.3746 | 41.3764 | unavailable | insufficient samples |
| Full flow-to-alert pipeline | 10 | 6,223.5294 | 6,250.6534 | unavailable | insufficient samples |

The full-pipeline throughput was 1.4484 persisted flows/second on this host.
That path includes isolated verified artifact reuse, SQLite initialization,
ingestion/replay, detection, alert persistence, correlation, and hypothesis
processing; it is not model inference latency.

## Read-only API results

All API measurements use FastAPI `TestClient`, so the semantics are
`in_process_testclient_latency`, not network latency. Each route was measured
100 times against fixed temporary data. Every response was HTTP 200, and ORM
row counts before and after the run proved that GET requests did not mutate
state.

| Route | p50 ms | p95 ms | p99 ms |
| --- | ---: | ---: | ---: |
| `GET /health` | 0.7497 | 0.9407 | 1.0707 |
| `GET /system/status` | 2.5920 | 3.0309 | 3.1901 |
| paginated `GET /flows` | 1.9251 | 2.3222 | 2.4307 |
| paginated `GET /alerts` | 2.4597 | 2.8489 | 3.0931 |
| `GET /runtime/status` | 3.2311 | 4.0419 | 4.3591 |
| `GET /demo/status` | 49.0853 | 55.7117 | 120.1481 |
| one flow-detail GET | 0.9986 | 1.3254 | 1.3867 |

## Memory evidence

| Scenario | Samples | Baseline RSS | Peak RSS | Delta RSS | Status |
| --- | ---: | ---: | ---: | ---: | --- |
| Process baseline | 1 | 309,755,904 | 309,755,904 | 0 | available |
| Supervised/anomaly artifact load | 10 | 331,022,336 | 331,022,336 | 0 | available |
| Warm inference | 100 | 331,022,336 | 331,055,104 | 32,768 | available |
| Full sample replay | 100 | 331,022,336 | 331,055,104 | 32,768 | available |
| Controlled demo | 10 | 314,474,496 | 318,111,744 | 3,637,248 | available |
| Bounded API list | 100 | 294,617,088 | 294,699,008 | 81,920 | available |
| Case report export | 10 | 309,739,520 | 309,837,824 | 98,304 | available |

Units are bytes. A zero observed load delta means allocator reuse masked an
incremental RSS change; it is not a claim of zero memory use. When the sampler
is unavailable the contract records `null` values and status `unavailable`
rather than fabricating zero.

## Limitations and reproduction

The synthetic sample is intentionally small; host scheduling, allocator reuse,
thermal state, and a 2 ms RSS interval affect measurements. No latency number
is a CI pass/fail target, and no result was used to tune a model, threshold, or
policy. The TestClient timing excludes actual networking and browser overhead.

```bash
PYTHONPATH=src .venv/bin/python -m scripts.run_phase13_benchmark \
  --output-dir reports/hardening/phase-13/performance-v1.1

PYTHONPATH=src .venv/bin/python -m scripts.run_phase13_benchmark \
  --smoke \
  --output-dir /tmp/aegishunt-phase13-benchmark-smoke
```
