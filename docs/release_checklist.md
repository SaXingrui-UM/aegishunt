# Phase 14 release checklist

This checklist records the Phase 14 implementation and post-merge checkpoint
evidence. It does not authorize a GitHub Release or publication.

## Git

- [x] PR #41 source branch was `phase/14-final-delivery`; final source Head and
  canonical Squash merge have the same tree.
- [x] Phase 0–13 annotated Tags were read-only verified and remain unchanged.
- [x] Working tree is clean after every logical local commit.
- [x] Phase 14 PR #41 is merged into `main` as
  `c342260162c3c3895120720559d73d33b172a7ef`; no force push or direct main
  push was used.
- [x] Annotated `phase-14-complete` is locally/remotely verified at the
  canonical merge, not at the source Head or checkpoint documentation branch.

## Code and tests

- [x] Ruff, strict mypy, full pytest, branch coverage >=85%.
- [x] All 17 Phase 13 core packages remain >=80%.
- [x] Offline E2E, full final demo, persistence/restart, security, robustness,
  and performance smoke pass.
- [x] No test is deleted, skipped, xfailed, or weakened to hide a defect.

## Packaging

- [x] Wheel and sdist build; Twine metadata check passes.
- [x] Python 3.11 and 3.12 fresh wheel installs use no editable mode or
  `PYTHONPATH`; `pip check`, CLI, doctor, DB, API, frontend, worker, demo pass.
- [x] Package inventory has no secret, DB, formal model, cache, or local
  path.

## Docker

- [x] Image builds from wheel and runs as non-root UID 10001. The first local
  base-image metadata request timed out; a later pull and fresh local arm64
  no-cache build succeeded.
- [x] Compose validates; `init/api/worker/frontend` work and are healthy.
- [x] Ports publish on loopback, root filesystem is read-only, capabilities are
  dropped, network/volumes are explicit, no Docker socket/host network exists.
- [x] Explicit demo, restart persistence, graceful shutdown, SQLite integrity,
  and test-volume cleanup pass.
- [x] Docker `doctor` is healthy and Matplotlib uses the bounded writable
  `/tmp/matplotlib` cache without relaxing read-only-root or privilege controls.

## Documentation and evidence

- [x] README, install/macOS/Linux/Docker/troubleshooting guides exist.
- [x] Architecture, data model, 43-feature dictionary, model cards, protocol,
  limitations, threat model, final summary, demo/script, thesis materials,
  traceability, and acceptance report exist.
- [x] Figures/tables are generated from declared source JSON/CSV with exact
  checksums; missing evidence is not fabricated.
- [x] Negative/inconclusive results, no holdout, DEF-004, local boundary,
  performance limits, and final security-rescan waiver remain visible.

## Repository hygiene

- [x] No DB, generated release bundle, formal model binary, upload, raw scan,
  coverage output, secret, `.env`, cache, user absolute path, or unreviewed
  large PCAP is staged.
- [x] Raw uploaded PCAPs remain ignored and unchanged; only payload-free,
  documentation-address derivatives plus provenance are tracked.

## Release identity

- [x] Application version `1.0.0` has one source and remains independent of
  model/policy/schema/artifact versions.
- [x] Ignored release bundle builds without overwrite and its exact manifest
  verifies corruption/missing/extra rejection.
- [x] Phase 14 PR implementation-Head CI jobs `quality`, `security`, `robustness`,
  `performance-smoke`, `package`, `clean-install`, `docker`, and
  `docs-delivery` passed twice; the checkpoint PR Head remains subject to the
  same Gates.
- [x] Annotated `phase-14-complete` was created only after merge and peels to
  the canonical PR #41 commit.
- [x] No GitHub Release, `v1.0.0` release Tag, package publication, or Docker
  registry publication was performed.
- [x] No further implementation phase is planned and no additional Phase 14
  status-closure PR is required after this single checkpoint PR is merged.
