# Troubleshooting

| Symptom | Safe check | Resolution |
| --- | --- | --- |
| `aegishunt` cannot import the package | `python -m pip show aegishunt` | Install the wheel in the active venv; do not rely on a stale editable `.pth` or `PYTHONPATH`. |
| `doctor` reports database unavailable | `aegishunt init-db` | Initialize the configured workspace database, then rerun `doctor`. |
| API unavailable | `aegishunt doctor` and `GET /health` | Confirm API process and loopback port 8000. Do not expose another interface. |
| Streamlit shows API unavailable | Check `http://127.0.0.1:8000/health` | Start API first; in Compose inspect `docker compose ps`. |
| Replay remains queued | `aegishunt runtime workers list` | Start exactly one local worker. |
| SQLite `-wal`/`-shm` remains | Stop API/worker and inspect open processes | Let SQLite close/checkpoint normally. Never delete sidecars while a process has the DB open. |
| `database locked` | Check for extra writers | Stop duplicate workers; single-node SQLite supports one configured worker. |
| Compose volume is stale | `docker compose down` | Use `down --volumes` only after reviewing that demo data may be destroyed. |
| Port conflict | Inspect local listeners | Stop the other process or change the loopback host port only. |
| Sample checksum failure | Run generator and inspect manifest diff | Do not bypass checks or force-add unreviewed PCAPs. |
| Release verification fails | `python scripts/build_release_bundle.py verify <path>` | Treat missing, extra, linked, or corrupt files as failure; rebuild into a new empty version directory. |

DEF-004 remains: when the only database is completely unavailable, failure
cannot be recorded in that same database. The service fails closed and emits a
sanitized local error. This is non-blocking for the local research deployment
but requires an independent durable control plane in future production work.
