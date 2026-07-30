# Phase 14 — Final delivery, deployment, and thesis materials

## Objective and current status

- Branch: `phase/14-final-delivery`
- Status: Implementation complete — awaiting PR review
- Base: Phase 13 post-merge `main`
- Pull request: [#41](https://github.com/SaXingrui-UM/aegishunt/pull/41), open
- Merge commit: pending
- Completion Tag: not created
- Release/GitHub Release: not created

## Declared scope

Application versioning, wheel/sdist, clean install, non-root local Docker
Compose, safe final samples, reproducible ignored release bundle, final
documentation, source-backed figures/tables, experiment summary, demo guide and
script, thesis evidence, requirement traceability, final acceptance, and CI
delivery Gates.

The original uploaded `traffic_attack.pcap` and `traffic_benign.pcap` remain
ignored and unmodified. The tracked Phase 14 derivatives contain no copied
payload or original address, use documentation addresses, and retain only
reviewed aggregate profiles. Their names are not ground truth.

## Non-scope

No model, calibration, threshold, fusion/risk policy, frozen evidence, Phase
0–13 Tag, or historical metric is changed. No production authentication,
distributed runtime, live capture, response action, public benchmark, release
Tag, or GitHub Release is introduced.

## Tests and acceptance

Local verification is complete: Ruff passed; strict mypy passed 239 source
files; the final local full run passed 549 pytest tests with no failures, skips,
or xfails at 85.83% branch-aware coverage; all 17 core packages remain above
80%. GitHub quality on implementation Head
`305b479f523d745fa92d889c9d4134509754a3d7` passed 550 tests at 85.81%; the
additional test protects Docker restart readiness. Python 3.11 and 3.12
external clean-wheel environments passed without editable installation or
`PYTHONPATH`. Both Phase 14 sample derivatives completed the full persisted
demo/restart path. The exact-inventory ignored release bundle, sample database,
and copied controlled demo models verified. Security reported 128 audited
dependencies with no advisories, zero unreviewed secret candidates, 54 Low and
zero blocking Bandit findings; robustness smoke passed 1/1 and performance
smoke completed.

Docker Compose validates, but the local image build could not retrieve pinned
base-image metadata because the workstation Docker Hub credential/network path
failed. No local Docker runtime pass is claimed. Exact-Head Linux CI independently
built and exercised the non-root image twice, including health/OpenAPI,
Streamlit, the 42-flow controlled demo, case/note/verdict/feedback, restart
persistence, SQLite integrity, and cleanup. All 18 implementation-Head checks
passed; every later docs-only PR Head must pass the same required workflow
before merge.

## Known limitations

See [Consolidated limitations](../limitations.md). Final formal Codex Security
rescan was explicitly waived and is not claimed. Phase 14 remains a local
single-user SQLite research delivery.
