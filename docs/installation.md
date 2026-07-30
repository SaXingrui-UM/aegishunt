# Installation and local operation

## Supported boundary

AegisHunt `1.0.0` supports CPython 3.11 and 3.12 as a local, single-user
research prototype. Runtime operation is offline: installation may contact a
configured Python package index, but replay, inference, the sample demo, API,
worker, and frontend do not require an external target or service.

The application does not require root. It provides no production
authentication, authorization, TLS termination, distributed database, service
manager, or live capture.

## Build distributions

From a clean repository checkout:

```bash
python3.12 -m venv .build-venv
source .build-venv/bin/activate
python -m pip install "build>=1.3,<2.0" "twine>=6.1,<7.0"
python -m build
python -m twine check dist/*
```

The supported delivery installation is the resulting wheel:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install dist/aegishunt-1.0.0-py3-none-any.whl
python -m pip check
```

Do not set `PYTHONPATH`. From the release bundle's `project/` directory:

```bash
export AEGISHUNT_CONFIG=configs/final-delivery.yaml
aegishunt --help
aegishunt init-db
aegishunt doctor
```

`doctor` returns non-zero until the database has been initialized. Its output
is sanitized and never includes the database URL or credentials.

## Start each process

Use separate terminals from the release workspace:

```bash
aegishunt api
aegishunt runtime worker run --forever --worker-id local-worker
aegishunt frontend --headless
```

Open `http://127.0.0.1:8501`; API documentation is
`http://127.0.0.1:8000/docs`. Ports bind to loopback by default.

## Explicit sample demo

The final delivery uses payload-free, documentation-address derivatives of the
two user-supplied PCAP aggregate profiles:

```bash
export AEGISHUNT_CONFIG=configs/final-delivery.yaml
aegishunt demo status
aegishunt demo run \
  --sample-id phase14-attack-like-pcap \
  --actor local-analyst \
  --reason "explicit controlled final-delivery demonstration" \
  --confirm
```

Repeat with `phase14-benign-like-pcap` if desired. These names are not verified
labels. The data are not used for model, threshold, calibration, or policy
selection, and results are not benchmark evidence.

## Tests and uninstall

Repository checks:

```bash
ruff check .
mypy src
pytest
```

Uninstall the wheel and remove only the workspace you created:

```bash
python -m pip uninstall aegishunt
rm -rf .venv
```

Do not delete databases, artifact roots, or evidence directories unless their
contents have been reviewed. See [Troubleshooting](troubleshooting.md),
[macOS](installation_macos.md), [Linux](installation_linux.md), and
[Docker](docker_deployment.md).
