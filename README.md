# AegisHunt

**Design and Implementation of an Autonomous Threat Hunting System Using Machine Learning**

AegisHunt is a defensive research prototype that will turn network-flow and
structured security telemetry into explainable detections, correlated alerts,
investigation hypotheses, and analyst-managed cases. It is intended to
demonstrate a complete threat-hunting lifecycle rather than only a classifier.

## Project goals

- Detect known malicious behavior with supervised learning.
- Identify behavior that departs from a benign baseline with anomaly detection.
- Fuse independent signals without presenting risk scores as attack probabilities.
- Correlate evidence and generate deterministic, reviewable hunt hypotheses.
- Preserve analyst control over verdicts, retraining, and model activation.
- Produce a runnable, testable, reproducible master's-project prototype.

## Current status

Phase 2 telemetry ingestion is implemented on `phase/02-telemetry-ingestion`.
The repository now provides bounded PCAP/PCAPNG container inspection, canonical
flow-CSV validation, structured JSON validation, checksum-addressed safe storage,
durable ingestion jobs, controlled samples, API endpoints, and CLI commands on
top of the Phase 1 data foundation. Packet-to-flow processing, feature extraction,
detection, model training, correlation, hypotheses, replay, and case workflows
are **not implemented**.

## Planned architecture

The system is a modular monolith with a FastAPI backend, Streamlit frontend,
Typer CLI, lightweight background processing, SQLite default storage, and a
scikit-learn dual detection engine. The core remains usable without an LLM,
live capture, root privileges, or a fixed network target. See
[`docs/architecture.md`](docs/architecture.md) and the ADRs in
[`docs/adr/`](docs/adr/).

## Local development installation

Python 3.11 or newer is required.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

`pyproject.toml` is the dependency source of truth; no compatibility
`requirements.txt` is maintained.

## Current commands

```bash
aegishunt --help
aegishunt doctor
aegishunt init-db
aegishunt ingest --help
aegishunt ingest pcap data/sample/phase2-benign.pcap
aegishunt ingest csv data/sample/phase2-flows.csv
aegishunt ingest sample phase2-benign-pcap
aegishunt api
aegishunt frontend
```

`doctor` checks Python compatibility, the operating system, and required local
directories. `init-db` validates configuration and idempotently initializes the
configured database without printing its URL. `ingest` validates and stores
explicit local files; it does not replay traffic, capture an interface, or
derive flows from packets.

## Telemetry ingestion

The Phase 2 API exposes `/ingestion/pcap`, `/ingestion/flow-csv`,
`/ingestion/json-events`, `/ingestion/jobs`, and `/ingestion/samples`. Uploads
are streamed through configured byte and record limits, stored under a
SHA-256-derived filename, and represented by durable status/error records.
Reviewed samples are declared in `data/sample/manifest.yaml` and verified before
use. See [`docs/ingestion.md`](docs/ingestion.md) for contracts and boundaries.

## Configuration and database initialization

Version-controlled defaults live in `configs/application.yaml`. Environment
variables override YAML values with `AEGISHUNT_` and a double underscore for
nested keys:

```bash
export AEGISHUNT_DATABASE__URL="sqlite:///data/aegishunt.db"
aegishunt init-db --config configs/application.yaml
```

The default SQLite database uses WAL, foreign-key enforcement, a bounded busy
timeout, and schema version `1`. Database files and WAL sidecars are ignored by Git.

## Start the API

```bash
aegishunt api --host 127.0.0.1 --port 8000
curl http://127.0.0.1:8000/health
```

Interactive OpenAPI documentation is available at
`http://127.0.0.1:8000/docs` while the API is running.

## Start Streamlit

```bash
aegishunt frontend --address 127.0.0.1 --port 8501
```

The Phase 2 page reports ingestion-foundation status and planned modules only.
It does not display invented flows, alerts, hypotheses, or model metrics.

## Quality checks

```bash
ruff check .
mypy src
pytest
```

The test command produces terminal coverage output and `coverage.xml`.

## Roadmap overview

| Phases | Planned outcome |
| --- | --- |
| 0 | Requirements, ADRs, engineering foundation, CLI/API/frontend shells |
| 1-4 | Configuration, storage, telemetry, flows, features, and dataset quality |
| 5-7 | Supervised, anomaly, and fusion experiments |
| 8-10 | Explainable alerts, correlation, hypotheses, cases, and feedback |
| 11-12 | Runtime replay, API, and complete frontend demonstration |
| 13-14 | Hardening, performance, deployment, documentation, and final delivery |

Only one declared phase is developed at a time. Progress is tracked in
[`docs/codex_progress.md`](docs/codex_progress.md).

## Research-prototype disclaimer

AegisHunt is not a production security product and must not be treated as an
authoritative attack-confirmation or automated-response system. It does not
perform unauthorized scanning, exploitation, credential attacks, unrestricted
flooding, arbitrary command execution, firewall changes, or account disabling.
Future detections and hypotheses will remain evidence-backed suggestions for
human investigation.
