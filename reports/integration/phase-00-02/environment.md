# Phase 0–2 Integration Verification Environment

Verification date: 2026-07-16 (Asia/Shanghai)

## Baseline

- Repository: `git@github.com:SaXingrui-UM/aegishunt.git`
- Baseline `main`: `45056b6c0b61ec78c39fca82ad8fea6da006577f`
- Verification branch: `test/phase-00-02-integration-verification`
- Verification test-code commit: `23719785e8d7a0b6af4eca8e54b57c8b9042a55d`
- Clean-clone path: `/tmp/aegishunt-phase-00-02-final-20260716-rPYJ6Z`
- Clean clone commit: `23719785e8d7a0b6af4eca8e54b57c8b9042a55d`

The temporary path is evidence metadata, not a required project path. Every
automated test uses `tmp_path` and does not depend on this literal location.

## Host

- OS: macOS 26.5.2 (build 25F84), Darwin 25.5.0
- Architecture: Apple arm64
- Host Python: 3.13.5
- Project virtual environment Python: 3.12.13
- Clean-clone virtual environment Python: 3.11.5
- Host pip: 25.1
- Clean-clone pip: 23.2.1
- Git: 2.51.2
- SQLite: 3.50.4 in the project environment; 3.42.0 in the Python 3.11 clean clone
- Effective user ID: 501; root privileges were not used

## Key Installed Dependencies

| Package | Version |
| --- | --- |
| AegisHunt | 0.1.0 editable |
| FastAPI | 0.115.14 |
| HTTPX | 0.27.2 |
| Pydantic | 2.13.4 |
| PyYAML | 6.0.3 |
| SQLAlchemy | 2.0.51 |
| Streamlit | 1.45.1 |
| Typer | 0.15.4 |
| Uvicorn | 0.34.3 |
| Pytest | 8.4.2 |
| Ruff | 0.15.21 |
| Mypy | 1.14.1 |

## Isolation and Network

- The final verification used a fresh local clone and a new Python 3.11 virtual environment.
- `PYTHONPATH` was unset; package import and console entry points came from editable installation.
- Dependency installation contacted PyPI because dependencies were not vendored. Test execution,
  ingestion, API, Streamlit, persistence, restart, and concurrency checks made no external-network calls.
- API and Streamlit manual checks bound only to loopback.
- No live capture, real interface, fixed target, scanning, or administrator privilege was used.
- Runtime SQLite databases and uploads were created only below temporary directories and were not committed.

## Packaging Note

`python -m build` and wheel installation were `NOT_EXECUTED`: the `build`
module is not declared in the development dependencies and was not installed
from the network solely for this optional check. Standard editable installation
is verified successfully without `PYTHONPATH`.
