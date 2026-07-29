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

## Finding disposition

The canonical machine-readable ledger is
`configs/hardening/phase-13-security-findings.json`; its reader-facing summary
is `docs/security_findings.md`. It retains all 80 original findings and all 73
Low findings individually:

- Fixed: 9 (all 7 Medium plus Low 35 and Low 61)
- Accepted risk: 39
- Deferred to Phase 14: 19
- Needs further validation: 13
- Duplicate / False positive / Not reachable: 0
- Untriaged: 0

Every risk row records its own reachability, required attacker capability,
mitigation, residual impact, and Phase 14 action. The ledger validator rejects
missing, duplicate, unsupported, or untriaged rows. The immutable baseline is
not presented as the final scan. The exact-final-HEAD formal Codex Security
rescan was explicitly waived by the user and was not executed. No final rescan
result is claimed. The immutable baseline ledger, regression evidence, Bandit,
dependency audit, and secret scan are complementary controls and are not
represented as a formal rescan or substitute result.

## Independent checks completed

- `detect-secrets` 1.5.0 scanned the tracked tree and generated PR body, plus
  reachable Git history subject to one explicitly documented, bounded
  oversized-blob exclusion. It scanned 1,264 historical text blobs, skipped 18
  binary blobs and one oversized historical blob, and reported zero confirmed
  secrets, zero unreviewed candidates, and zero stale allowlist entries.
  Current tracked files remain subject to the normal secret scan. Passing this
  gate does not mean every reachable blob was scanned.
- Bandit 1.9.4 scanned `src/aegishunt` and `scripts`: 45 Low, 0 Medium/High,
  0 scanner errors, and no suppression.
- `.env` is not tracked; `.env.example` is the only tracked environment file.
- No database, SQLite, PCAPNG, pickle, joblib, or model binary is tracked.
- Three reviewed controlled sample PCAPs are tracked, totaling 4,044 bytes.
- No tracked file exceeds 5 MiB.
- `pip check` reports no broken requirements.
- `pip-audit` 2.10.1 audited 114 installed distributions under CPython 3.12.13
  and 110 installed distributions in a clean CPython 3.11 environment, with
  network access available, and reported zero advisories in both environments.

Sanitized method and result details are in `docs/dependency_review.md` and
`docs/security_review.md`.

## Security boundary retained

The prototype remains loopback-first, offline-capable, rootless, and
non-destructive. It performs no live capture, scan, exploit, blocking, account
change, automatic response, or arbitrary model deserialization. Controlled
synthetic results remain pipeline verification only—not a public benchmark,
production validation, zero-day proof, or real-world performance claim.
