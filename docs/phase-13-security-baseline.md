# Phase 13 Security Baseline and Remediation Map

## Immutable baseline

The user-confirmed Codex Security repository baseline was read, not rerun.

- Scan ID: `182ceaf4-8d4a-4a23-983a-ffa0a4b0610a`
- Target revision: `75c73bc86a40a78a22edde5fb175359a7b755c05`
- Scope: all 448 tracked files, no excluded path
- Coverage: complete static repository review plus two bounded local validations
- Findings: 80 total — 7 Medium, 73 Low, 0 High, 0 Critical
- Main categories: resource exhaustion (26), filesystem boundary (19),
  race condition (17), artifact/audit/dataset/model/state integrity, supply
  chain, cross-origin request, and policy enforcement
- Baseline limitations: local prototype assumptions; no public target, exploit
  execution, live capture, model retuning, frozen-evidence regeneration, or
  external deployment validation

The canonical external scan directory contains `scan-manifest.json`,
`findings.json`, `coverage.json`, and `report.md`. It is not copied into the
repository because those artifacts are large, environment-owned scan evidence.

## Medium finding remediation

| Finding | Phase 13 control | Regression evidence | Status |
| --- | --- | --- | --- |
| JSON record limits apply after complete materialization | Incremental JSON-array/JSONL parser; byte-per-record and nesting limits | `test_json_array_and_jsonl_enforce_limits_during_incremental_parsing`; nesting test | Remediated |
| Fusion can freeze unverified engine/schema identities | Require registered supervised/anomaly IDs, versions, algorithms, and Phase 3 schema before fit | `test_fusion_refit_rejects_unverified_model_and_schema_identities` | Remediated |
| Rounded near-duplicate boundary misses | Exact Chebyshev-tolerance connected components for quality and cross-split leakage | quality and cross-split quantization-boundary tests | Remediated |
| Per-packet full-table flow expiration | Deadline heap with authoritative stale-entry checks and bounded compaction | 500-active-flow no-full-scan regression plus existing timeout suite | Remediated |
| Unbounded PCAPNG interface inventory | Configured `max_pcapng_interfaces` bound in the packet reader | interface-inventory security regression | Remediated |
| Multipart limit applies after spooling | Raw ASGI streaming body limit installed before multipart parsing | 413/no-ingestion-job/no-staging regression | Remediated |
| Arbitrary rows can be reissued as controlled evidence | Exact deterministic generator-equivalence gate before split publication | substituted-canonical-row rejection regression | Remediated |

## Low finding disposition

The immutable ledger retains all 73 original Low findings. Phase 13 provides
direct regression-backed remediation for two additional Low findings:

- excessive JSON nesting no longer escapes the ingestion error boundary; and
- a disabled reason-code catalog entry can no longer be emitted by a matching
  feature or threshold trigger.

The other 71 baseline Low findings remain explicit residual/deferred risks.
They are mostly local-filesystem substitution races, artifact trust-anchor
limitations, post-verification reopen races, or bounded-resource improvements
whose exploitability depends on a lower-trust principal being able to modify
the process owner's configured roots. They are not silently reclassified: no
new full Security scan was run. Phase 14 must use the baseline ledger when
deciding deployment permissions, authentication, reverse proxy/TLS, immutable
artifact custody, and operational dependency scanning.

## Independent checks completed

- Secret-pattern checks found no tracked AWS access key, private-key header,
  GitHub token, or OpenAI-style key.
- `.env` is not tracked; `.env.example` is the only tracked environment file.
- No database, SQLite, PCAPNG, pickle, joblib, or model binary is tracked.
- Three reviewed controlled sample PCAPs are tracked, totaling 4,044 bytes.
- No tracked file exceeds 5 MiB.
- `pip check` reports no broken requirements.
- `pip inspect` recorded 92 installed distributions under CPython 3.12.13 on
  Darwin arm64.
- `pip-audit` is not installed and no offline vulnerability database is
  available. A dependency-CVE result was therefore **not executed** and is not
  claimed as passing.

## Security boundary retained

The prototype remains loopback-first, offline-capable, rootless, and
non-destructive. It performs no live capture, scan, exploit, blocking, account
change, automatic response, or arbitrary model deserialization. Controlled
synthetic results remain pipeline verification only—not a public benchmark,
production validation, zero-day proof, or real-world performance claim.
