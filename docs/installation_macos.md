# macOS installation

## Scope

The verified local delivery environment is macOS on Apple Silicon with CPython
3.12. CI covers CPython 3.11/3.12 on Linux. Intel macOS is expected to use the
same universal Python wheel, but is not separately guaranteed by this project.

Install Python 3.11 or 3.12 using python.org or, optionally, Homebrew:

```bash
brew install python@3.12
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install dist/aegishunt-1.0.0-py3-none-any.whl
python -m pip check
```

This wheel installation replaces the stale editable `.pth` failure mode. Do
not use `PYTHONPATH=src` as the standard installation.

From the release workspace, initialize and start:

```bash
aegishunt init-db
aegishunt doctor
aegishunt api
# second terminal
aegishunt runtime worker run --forever --worker-id macos-worker
# third terminal
aegishunt frontend --headless
```

The default SQLite database is `data/aegishunt.db` relative to the workspace.
The user running AegisHunt must own the workspace. Do not use `sudo`.

For Docker Desktop:

```bash
docker compose build
docker compose run --rm init
docker compose up -d api worker frontend
```

Both Apple Silicon and Intel Docker Desktop may build the explicit
`python:3.11.13-slim-bookworm` image for their active architecture. This is not
multi-architecture release-image certification.

If ports 8000 or 8501 are occupied, stop the conflicting local process or
change only the host-side Compose port while retaining `127.0.0.1`. Do not
publish the prototype on a LAN interface.

Run the sample commands in [the Demo Guide](demo_guide.md). For clean uninstall,
stop processes, `docker compose down` (add `--volumes` only after reviewing
data), uninstall the wheel, and remove the venv. See
[Troubleshooting](troubleshooting.md) for SQLite WAL files, stale volumes, and
broken editable launchers.
