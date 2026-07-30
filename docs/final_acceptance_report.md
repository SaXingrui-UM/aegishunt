# Final delivery acceptance report

## Status

Local final execution is complete on branch `phase/14-final-delivery`.

**Current verdict: NOT ACCEPTED pending required new-Head CI and user review.**
The local Docker Compose contract validates, but the local image build could
not obtain the pinned base-image metadata because the workstation's Docker Hub
credential/network path failed. This is not recorded as a successful Docker
run. The PR's Docker job must build and exercise the image before the delivery
can become `ACCEPTED WITH LIMITATIONS`.

## Baseline

- Base main: `69cf7ec87734f036a7201ea563d0759965a4d2db`
- Application version: `1.0.0`
- Phase 13 checkpoint: annotated `phase-13-complete`, unchanged
- Phase 14 completion/release Tags: not created
- Formal final Codex Security rescan: explicitly waived; not executed; no pass
  claimed

## Executed evidence

| Gate | Result | Evidence |
| --- | --- | --- |
| Build wheel/sdist and metadata | PASS | Wheel and sdist built; Twine metadata and distribution inventory passed |
| Clean wheel install Python 3.11 | PASS | External venv, non-editable wheel, no `PYTHONPATH`; pip/CLI/doctor/demo/API/restart passed |
| Clean wheel install Python 3.12 | PASS | External venv, non-editable wheel, no `PYTHONPATH`; pip/CLI/doctor/DB/demo/worker/API/Streamlit/restart passed |
| Docker build/Compose/full demo/restart | PARTIAL | Compose validates; local base-image retrieval failed externally, so runtime proof is pending the new-Head Docker CI |
| Local full-chain/API/frontend/restart | PASS | Both Phase 14 derivative samples completed through persisted flows, dual detection, fusion, alerts, correlation, hypothesis, case, note, verdict, feedback, report, API, frontend, audit, and restart |
| Release bundle/database/demo artifacts | PASS | Exact-inventory bundle verified; generated database integrity/schema/rows and copied model identities were independently checked; collision rerun rejected |
| Figures/tables manifest | PASS | `docs/assets/final-evidence-manifest.json` generated and checksum-bound |
| Ruff/mypy/full pytest/coverage | PASS | Ruff passed; strict mypy passed 239 source files; 545 tests passed with no failures/skips/xfails; branch-aware coverage 85.78% |
| Core-package coverage | PASS | Repository 85.78%; all 17 declared core packages exceed 80% |
| Security/robustness/performance gates | PASS | 128 dependencies/0 advisories; 0 secret candidates; 54 Low and 0 blocking Bandit findings; robustness smoke 1/1; performance smoke completed |
| Requirement traceability | PARTIAL | Matrix is evidence-backed; Docker remains partial until the required new-Head CI passes |

Local release-bundle output, databases, copied demo model binaries, machine
coverage, and scanner output remain ignored and uncommitted. The exact bundle
manifest binds the clean committed source revision used to build it; the final
PR Head will be rebuilt and verified after status metadata is committed.

The controlled demo is not a benchmark, real-world validation, or production
evidence. Any Blocking/High finding, required CI failure, full-chain failure,
Docker failure, or clean-install failure requires `NOT ACCEPTED`. The formal
final Codex Security rescan was explicitly waived, was not executed, and no
result is claimed; dependency, secret, Bandit, regression, and ledger checks are
complementary controls rather than a substitute rescan.
