# Linux installation

## Scope

CI verifies Ubuntu-hosted CPython 3.11 and 3.12. Other contemporary
glibc-based distributions may work but are not all certified. AegisHunt does
not ship a systemd unit and the application itself must not run as root.

Create a user-owned virtual environment and install the wheel:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install dist/aegishunt-1.0.0-py3-none-any.whl
python -m pip check
aegishunt init-db
aegishunt doctor
```

Start the API, one worker, and Streamlit as the same unprivileged user:

```bash
aegishunt api
aegishunt runtime worker run --forever --worker-id linux-worker
aegishunt frontend --headless
```

The API and frontend bind loopback by default. Firewall rules must not expose
ports 8000 or 8501. The SQLite database and artifact roots must be writable by
the application user and must not be shared over an unsafe network filesystem.

Docker requires Engine plus the Compose plugin. Membership in the `docker`
group is effectively root-equivalent access to the host daemon; evaluate that
risk rather than using it as an application requirement:

```bash
docker compose build
docker compose run --rm init
docker compose up -d api worker frontend
```

Containers themselves run as UID/GID 10001, drop all capabilities, use a
read-only root filesystem, and receive named writable volumes only. The Docker
socket is not mounted.

Use [the Demo Guide](demo_guide.md) for the sample workflow. For clean
uninstall, stop processes, uninstall the wheel, remove the venv, and use
`docker compose down`. Add `--volumes` only if the demo database and artifacts
are no longer needed. See [Troubleshooting](troubleshooting.md).
