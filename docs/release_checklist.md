# Phase 14 release checklist

This checklist records evidence for the Phase 14 PR. It does not authorize a
merge, completion Tag, GitHub Release, or publication.

## Git

- [x] Branch is `phase/14-final-delivery` from synchronized Phase 13 `main`.
- [x] Phase 0–13 annotated Tags were read-only verified and remain unchanged.
- [x] Working tree is clean after every logical local commit.
- [ ] Phase 14 PR is open against `main`; no force push or direct main push.

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

- [ ] Image builds from wheel and runs as non-root UID 10001. Local base-image
  retrieval was blocked by the workstation's Docker Hub credential/network
  path; the new-Head Docker CI must provide this runtime evidence.
- [ ] Compose validates; `init/api/worker/frontend` work and are healthy.
- [ ] Ports publish on loopback, root filesystem is read-only, capabilities are
  dropped, network/volumes are explicit, no Docker socket/host network exists.
- [ ] Explicit demo, restart persistence, graceful shutdown, SQLite integrity,
  and test-volume cleanup pass.

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
- [ ] Phase 14 PR CI jobs `quality`, `security`, `robustness`,
  `performance-smoke`, `package`, `clean-install`, `docker`, and
  `docs-delivery` pass.
- [x] No `phase-14-complete`, release Tag, or GitHub Release is created before
  separate post-merge authorization.
