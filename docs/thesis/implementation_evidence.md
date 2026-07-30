# Implementation evidence

Evidence level: **implemented and tested**.

| Layer | Repository evidence | Verification |
| --- | --- | --- |
| Telemetry and flows | `src/aegishunt/ingestion`, `src/aegishunt/flows` | ingestion, parser, timeout, determinism, security tests |
| Dataset and ML | `src/aegishunt/datasets`, `src/aegishunt/ml` | group/leakage, selection, frozen identity, bundle tests |
| Detection and hunting | `src/aegishunt/detection`, `correlation`, `hunting` | identity, explanation, lifecycle, E2E tests |
| Cases and runtime | `src/aegishunt/cases`, `feedback`, `runtime` | audit, export, lease/recovery/restart tests |
| Interfaces | `src/aegishunt/api`, `frontend`, `cli.py` | OpenAPI/client/frontend/full-demo tests |
| Delivery | Docker/Compose, release manifest, install guides | Phase 14 package/container/delivery tests |

The repository is the implementation source; generated databases, demo models,
and release bundles remain ignored.
