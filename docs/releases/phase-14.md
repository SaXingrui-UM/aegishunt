# Phase 14 — Final delivery, deployment, and thesis materials

## Objective and current status

- Implementation branch: `phase/14-final-delivery`
- Status: Phase complete
- Pull request: [#41](https://github.com/SaXingrui-UM/aegishunt/pull/41),
  merged on 2026-07-30
- Final source-branch Head:
  `168a91caecd59fff7d66e9237a97653831cf024e`
- Canonical Squash merge:
  `c342260162c3c3895120720559d73d33b172a7ef`
- Shared source/merge tree:
  `0749ac9b055341f7c792673ba0561bce42da9aa0`
- Completion Tag: annotated `phase-14-complete`; object
  `06e393c77918ef13ba66c0cdf253800074bdd71a`; locally and remotely verified
  at the canonical Squash merge
- Release/GitHub Release: not created; no `v1.0.0` release Tag, package
  publication, registry publication, or release publication was authorized

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

The first local Docker Hub authentication/base-image metadata request timed
out. A subsequent independent pull succeeded; the merged canonical source then
completed a fresh local arm64 no-cache build. The local non-root/read-only
Compose deployment passed API health, OpenAPI/docs, Streamlit health/root,
worker execution, and a 1,017-packet controlled demo producing 42 flows,
42 alerts, one group, one hypothesis, one completed runtime job, and one case
with analyst note, bounded verdict, and feedback. Restart preserved the job,
case, note, feedback, and flows; schema v5, WAL, application-level foreign
keys, and SQLite integrity `ok` were verified. API/frontend remained bound to
loopback, UID/GID remained `10001:10001`, all capabilities were dropped,
`no-new-privileges:true` remained set, and no host/home/Git/SSH/Docker-socket
mount was introduced. Docker `doctor` is healthy after the existing runtime
artifact/report volumes were exposed at the foundation paths. Matplotlib now
uses `/tmp/matplotlib` under the bounded tmpfs instead of attempting to write
the read-only home. All 18 PR #41 implementation-Head checks passed; the single
checkpoint PR must independently pass its own exact-Head workflow before
review.

## Post-merge verification

- Merged-main Ruff passed; strict mypy passed 239 source files; all 550 tests
  passed with no failures, skips, or xfails at 85.83% branch-aware coverage.
  Every one of the 17 declared core packages remained above 80%.
- Phase 14 unit/release/E2E tests passed, including deterministic final
  samples, exact feature ordering, distribution inventory, full persisted
  chain, and restart.
- Wheel/sdist, Twine metadata, distribution inventory, documentation delivery,
  and the collision-safe exact-inventory release bundle passed. Fresh Python
  3.11 and 3.12 wheel installations passed without editable installation or
  `PYTHONPATH`.
- Dependency audit, current/history secret controls, Bandit, security ledger,
  robustness smoke, and performance smoke passed. The final formal Codex
  Security rescan was explicitly waived, was not executed, and no result is
  claimed; those independent gates are not represented as a substitute.
- Generated wheels, sdists, release bundles, databases, model copies, upload
  data, logs, and machine reports remain ignored and uncommitted.

## Known limitations

See [Consolidated limitations](../limitations.md). Final formal Codex Security
rescan was explicitly waived and is not claimed. Phase 14 remains a local
single-user SQLite research delivery.

## Mentor-demo corrective delivery

The bounded `codex/frontend-demo-polish` correction keeps the Phase 14
checkpoint and annotated `phase-14-complete` Tag unchanged. It removes the
implicit Streamlit `pages/` navigation, presents effective runtime models
instead of an empty global registry, adds a read-only typed demo evaluation
summary, aligns family-macro fusion LOAO Recall to the verified `0.3333`, fixes
telemetry upload submission, gives the explicit synchronous worker operation a
separate 600-second timeout, isolates correlation to the current replay job,
and permits in-flight durable progress to settle at a pause-request boundary.
The controlled demo artifact operation advances to `1.0.1` for its
capacity-only correlation setting. The final corrective suite passes all 564
tests at 85.91% branch-aware coverage. A real 42,888,106-byte PCAP worker call
remained connected for 96.13 seconds and completed with 449 flows, 449
detections, 449 alerts, 94 groups, and 94 hypotheses.
The base Compose deployment retains UID/GID 10001, read-only root,
`cap_drop: ALL`, `no-new-privileges`, loopback ports, and all named volumes.
No model, threshold, fusion weight, risk policy, historical Tag, or automatic
activation changes in this corrective PR.

## Docker case-artifact path corrective

After PR #43 was merged, mentor-demo report generation exposed a deployment
path conflict: the final Docker image retains `artifacts` and `reports` as
compatibility symlinks, while the case artifact safety boundary intentionally
rejects every configured root that traverses a symlink. The Docker settings now
select a dedicated case/feedback policy whose three writable roots point
directly to `runtime/artifacts/...` and `runtime/reports/...`. The base policy
and the symlink-rejection control remain unchanged.

Ruff and strict mypy passed. All 28 relevant test assertions passed, and the
direct report/configuration subset passed 26 tests with a zero exit status.
Using an isolated backup of the manual-recording database, the API generated
and downloaded a versioned Markdown report with the exact four-file inventory;
no production case, report version, or recording evidence was mutated.

The same corrective now offers an allowlisted, checksum-verified ZIP download
for reviewed feedback exports and review-only retraining-candidate proposals.
The frontend shows the generated manifest and download button immediately, and
also provides a separate existing-version form so retained artifacts can be
downloaded after a refresh or restart. The preserved `demo-v2` feedback export
downloaded with its exact four-file inventory. Ruff, strict mypy, and 48
relevant unit, integration, API-client, and rendered frontend tests passed.
Existing case-report versions also have a separate reverification/download form,
so a retained report remains accessible without attempting to recreate its
immutable version.

## Next phase

None. No further implementation phase is planned. Optional archival, thesis
submission, GitHub Release/version publication, or deployment beyond the local
research boundary requires separate user authorization. No additional Phase 14
status-closure PR is required after the single checkpoint PR is merged.
