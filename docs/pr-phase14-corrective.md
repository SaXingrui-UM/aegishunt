## Phase

Phase 14 corrective — mentor-demo frontend and evidence presentation only.

## Summary

This bounded corrective makes the existing local research frontend suitable for
a supervisor demonstration without changing any trained model, threshold,
fusion weight, risk policy, active pointer, historical evidence, merge, or Tag.

The original problems were duplicate implicit Streamlit navigation, developer
chrome in the demo shell, an empty global model registry presented as the main
model state, a raw/incomplete evaluation view, and a documented family-macro
LOAO Recall of `0.8000` that did not match the verified experiment artifact.

## Requirements Completed

- Moved the nine frontend modules from Streamlit's implicit `pages/` discovery
  directory to explicit `views/` routing and reduced the sidebar to one concise
  page selector plus one research disclaimer.
- Reworked Overview, Model Lab, and Evaluation for a compact mentor narrative.
  Effective runtime models and policy are shown before provenance details.
- Added read-only model-operation readiness so unavailable training/activation
  actions are omitted based on server-side prerequisites rather than UI guesses.
- Added `GET /evaluation/summary`, a typed, read-only projection of the latest
  completed demo run and the exact verified controlled fusion artifact.
- Corrected family-macro LOAO Recall from `0.8000` to `0.3333` in the source
  experiment summary and model cards, with a cross-document regression test.
- Preserved the base-Compose named volumes and all existing model, threshold,
  fusion, and risk settings.

## Architecture Decisions

- Evaluation evidence fails closed. The reader requires the exact artifact
  inventory, non-symlink files, checksums, experiment identities, and effective
  runtime policy identity before returning a summary.
- The summary endpoint never prepares demo artifacts and is regression-tested
  not to change demo file timestamps or database row counts across repeated
  reads.
- Missing or invalid evidence returns a bounded unavailable state with no local
  filesystem path disclosure.
- Streamlit remains an API-only client. It does not import storage,
  repositories, SQLAlchemy, or artifact readers.
- The container keeps UID/GID 10001, read-only root, `cap_drop: ALL`,
  `no-new-privileges:true`, loopback-only ports, and existing named volumes.
  Writable Streamlit state is constrained to the existing `/tmp` tmpfs.

## Tests

- `ruff check .` — passed.
- `mypy src` — passed for 239 source files.
- `pytest` — 554 passed, 0 failed, 18 warnings, 85.87% branch-aware coverage.
- Focused API, evidence-integrity, status-document, CLI, and Streamlit AppTest
  suites — passed.
- Evaluation regressions cover missing, extra, corrupt, symlinked,
  checksum-mismatched, and identity-mismatched evidence plus no-mutation reads.
- Base-Compose final image — built and healthy; API summary and Streamlit
  production settings verified.
- Real Browser flow — Overview → Model Lab → Evaluation → Overview → Model Lab,
  with no stale cross-page content, duplicate disclaimer, fresh console errors,
  or horizontal overflow at the captured 1280 px desktop viewport.

## Commands Executed

```text
docker compose build --no-cache
docker compose build
docker compose up -d --force-recreate
ruff check .
mypy src
pytest
```

The no-cache build validated the required base deployment; the later normal
build recreated the exact final source image after presentation-only tweaks.
Named volumes were never removed and `docker compose down -v` was not run.

## Generated Artifacts

Only review evidence screenshots are added:

- [Baseline Overview](screenshots/frontend-demo/before-overview.png)
- [Corrected Overview](screenshots/frontend-demo/after-overview.png)
- [Corrected Model Lab](screenshots/frontend-demo/after-model-lab.png)
- [Corrected Evaluation](screenshots/frontend-demo/after-evaluation.png)
- [Corrected LOAO detail](screenshots/frontend-demo/after-evaluation-loao.png)

No datasets, PCAPs, databases, model binaries, secrets, `.env` files, coverage
machine output, or other generated runtime artifacts are included.

## Security Considerations

The new endpoint is read-only and rejects artifact substitution, inventory
drift, symlinks, checksum mismatch, experiment/policy identity mismatch, and
unsafe error detail. Container hardening and volume topology are unchanged
apart from providing Streamlit a bounded writable HOME under `/tmp`.

The formal final Codex Security rescan remains explicitly waived. This PR does
not claim that the completed regression checks are a substitute for that scan.

## Known Limitations

- The product remains a local, single-user research demonstration; it is not a
  multi-user SOC deployment and does not perform live capture or response.
- Training and activation remain unavailable in the standard demo environment
  unless all backend-declared prerequisites are present.
- Screenshots document the in-app Browser's actual 1280×720 viewport. Wider
  desktop behavior follows the same bounded responsive grid but was not
  separately screenshot-emulated in that Browser session.
- A fusion recommendation of `Inconclusive` and zero Recall for Exfiltration
  and Reconnaissance are intentionally displayed as verified negative results.

## Checklist

- [x] Changes are limited to the declared Phase 14 corrective
- [x] Ruff passes
- [x] Mypy passes
- [x] Pytest passes
- [x] No secrets are committed
- [x] No large generated artifacts are committed
- [x] Documentation is updated
- [x] `codex_progress.md` is updated
- [x] No later-phase functionality was implemented prematurely
- [x] No model, threshold, fusion/risk policy, historical merge, or Tag changed
- [x] No named Docker volume was deleted
