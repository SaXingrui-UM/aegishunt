# Architecture

## Status and scope

This document defines the target architecture and its phased realization. Phase
3 provides bounded packet decoding, canonical bidirectional aggregation,
deterministic feature schema `1.0.0`, and transactional `NetworkFlow`
persistence. Phase 4 adds file-based dataset registry, canonical transformation,
quality/leakage gates, and group-exclusive frozen splits. ML, detection,
correlation, hunting workflows, cases, PCAP replay orchestration, and runtime
workers remain planned.

## System context

```mermaid
flowchart LR
    Operator["Operator / demonstrator"] --> CLI["Typer CLI"]
    Analyst["Security analyst / threat hunter"] --> UI["Streamlit frontend"]
    Researcher["ML researcher"] --> CLI
    UI --> API["FastAPI backend"]
    CLI --> Core["AegisHunt application core"]
    API --> Core
    Sources["PCAP, flow CSV, JSON, sample data"] --> Core
    Core --> Store["SQLite and controlled artifact registry"]
    Core --> Evidence["Flows, detections, alerts, groups, hypotheses, cases"]
```

Users interact through the CLI, HTTP API, or frontend. Offline inputs are the
default operational boundary. The system does not require a live target or an
external model service.

## Modular-monolith structure

One deployable Python application is divided by responsibility:

| Module boundary | Planned responsibility | First owning phase |
| --- | --- | --- |
| `config`, schemas, storage | Implemented settings, entity contracts, repositories, audit | 1 |
| ingestion | Implemented safe adapters, storage, samples, and ingestion jobs | 2 |
| flows, features | Implemented packet state, timeouts, finalization, and feature registry | 3 |
| datasets | Implemented registry, conversion, split, manifests, leakage and quality | 4 |
| ML supervised/anomaly/fusion/evaluation | Training, inference, thresholds, comparison | 5-7 |
| detection and explainability | Results, risk, alerts, reasons, explanations | 8 |
| correlation and hunting | Entity/time groups and deterministic hypotheses | 9 |
| cases and feedback | Investigation workflow and retraining candidates | 10 |
| runtime | Pipeline, worker, replay, health, graceful shutdown | 11 |
| API and frontend | Complete external workflows and sample demonstration | 12 |

Domain modules must not depend on Streamlit. FastAPI routes and the CLI call
application services; repositories isolate persistence; adapters isolate file,
packet, model, and UI concerns. This keeps unit testing possible without running
the whole application.

## Planned data flow

```mermaid
flowchart TD
    Input["Untrusted telemetry file"] --> Boundary["Phase 2 safety + format validation"]
    Boundary --> Job["Durable ingestion job + checksum"]
    Job --> Packet["Phase 3 packet/event processing"]
    Packet --> Flow["Canonical bidirectional flow"]
    Flow --> Feature["Versioned behavioral feature vector"]
    Feature --> Dataset["Phase 4 canonical dataset + provenance"]
    Dataset --> Quality["Quality + leakage gates"]
    Quality --> Split["Group-exclusive frozen splits"]
    Split --> Supervised["Supervised detector"]
    Feature --> Anomaly["Anomaly detector"]
    Supervised --> Fusion["Configured signal fusion"]
    Anomaly --> Fusion
    Fusion --> Detection["Detection result + explanation"]
    Detection --> Alert["Security alert"]
    Alert --> Correlation["Entity/time correlation"]
    Correlation --> Hypothesis["Structured threat hypothesis"]
    Hypothesis --> Case["Investigation case"]
    Case --> Feedback["Analyst feedback export"]
```

The boundary through `Split` is implemented for supported PCAP-derived features
and the controlled demo. Public benchmark acquisition and label joining remain
manual/provisional gates. The remaining nodes are planned. IDs and provenance
are preserved across transitions; raw evidence, labels, model inference, fusion,
correlation, and analyst judgment remain distinguishable.

## Dataset lifecycle

```mermaid
flowchart LR
    Registry["Static dataset + license registry"] --> Acquire["Manual/explicit acquisition"]
    Acquire --> Raw["Configured raw root + SHA-256"]
    Raw --> Convert["Versioned exact-schema converter"]
    Convert --> Canonical["Metadata | ordered features | labels"]
    Canonical --> Quality["Schema, missing, duplicate, range, class checks"]
    Quality --> GroupSplit["Seeded whole-group split"]
    GroupSplit --> Leakage["Cross-split and label leakage gate"]
    Leakage --> Manifests["Frozen manifests + CSV/JSON reports"]
```

Static provider facts are separate from machine-local state. Raw files are never
overwritten. The canonical feature section exactly matches the Phase 3 43-field
tuple; source, capture, scenario, group, timestamp, IDs, labels, and checksums
remain metadata. Missing or semantically unmatched public features are rejected,
not imputed or fabricated. CSE-CIC-IDS2018 is the conditional primary candidate,
while the offline controlled demo validates the machinery without representing
real traffic.

The splitter refuses fewer than three groups and any source/session/scenario
identity shared by multiple groups. It never falls back to random rows. Quality
and leakage reports must pass before a final dataset manifest is written. Test
is marked frozen and prohibited for future model/threshold/feature selection.

## Planned ML lifecycle

```mermaid
flowchart LR
    Sources["Versioned source data"] --> Quality["Schema + quality + leakage checks"]
    Quality --> Split["Group/time-aware split manifests"]
    Split --> Train["Candidate training with fixed seeds"]
    Train --> Validate["Validation selection and thresholds"]
    Validate --> Freeze["Frozen bundle + hashes + model card"]
    Freeze --> Test["One-time final test evaluation"]
    Test --> Registry["Validated model registry entry"]
    Registry --> Activate["Explicit human activation"]
    Feedback["Exported analyst feedback"] --> Sources
```

Supervised candidates include baseline and tree/linear models; the selected
algorithm follows evidence. Isolation Forest learns a benign baseline. Fusion
weights and thresholds come from validation experiments. Model bundles reject
feature-schema or integrity mismatch. No online self-modification occurs.

## Planned threat-hunting lifecycle

1. **Observe:** safely ingest or replay telemetry.
2. **Detect:** run supervised, anomaly, and optional deterministic signals.
3. **Explain:** retain observed values, references, contributions, and reason codes.
4. **Correlate:** group alerts by time and shared entities under configured rules.
5. **Hypothesize:** select deterministic templates and attach supporting and
   alternative evidence without marking an attack confirmed.
6. **Investigate:** create cases, notes, evidence references, status, and verdict.
7. **Learn under control:** export feedback, explicitly retrain, validate a new
   immutable version, and explicitly activate it.

## Backend and frontend relationship

FastAPI is the authoritative programmatic boundary. Streamlit will consume API
contracts rather than access the database or model artifacts directly. This
supports independent API tests, explicit validation, and future replacement of
the demonstration UI. The CLI can launch each shell and will later call the same
application services for batch workflows. In Phase 3, Streamlit remains a
truthful static status shell rather than a flow explorer. FastAPI exposes
`/health` plus typed ingestion, sample, and job endpoints; API lifespan startup
initializes and verifies the empty or existing configured database. PCAP upload
uses the same service as the CLI and produces persistent flows synchronously.

## Planned storage approach

SQLite with SQLAlchemy and WAL mode is the implemented default local store.
Foreign keys and a bounded busy timeout are enabled for SQLite connections.
Typed repositories prevent SQL from leaking into business logic and preserve a
future PostgreSQL migration path. Schema version `1` is registered explicitly;
an incompatible database is rejected rather than silently mutated. Core entity
tables exist now. Phase 2 persists ingestion lifecycle state in
`telemetry_sources` and writes an audit event in the same transaction as every
create or transition. Phase 3 parses a complete staged PCAP before committing its
file, then creates all `network_flows` and the completed source transition in one
database transaction. A packet failure therefore leaves no partial flow set.

Each flow retains the first-observed direction, source provenance, capture-session
reference, stable timestamps/counts, and a flat finite feature vector. The source
metadata carries feature schema version `1.0.0`; the canonical schema export is
`artifacts/feature_schema.json`.

Untrusted uploads are written to private temporary files below the configured
root in bounded chunks, hashed with SHA-256, format-validated, and atomically
moved to checksum-derived names. Client paths are never used as destinations.
Failures remove staging files and remain observable as safe failed jobs.

Large or generated material stays outside source control:

- original and derived telemetry under `data/` with manifests and checksums;
- immutable model and evaluation bundles under `artifacts/`;
- human-readable experiment output under `reports/`.

Phase 4 generated canonical/split JSONL and machine reports use configured
`data/processed/datasets` and `reports/datasets` roots, both ignored except for
directory placeholders. Registry YAML, versioned label mappings, schema docs,
and tests are reviewed source files.

The controlled model registry will verify schema and hashes before loading; user
uploads can never be treated as arbitrary serialized Python models.

## Deployment and trust boundaries

Local Python is the current execution mode. Docker and Docker Compose are Phase
14 deliverables. Default listeners bind to loopback. Inputs cross an untrusted
file/API boundary and require validation before persistence or parsing. The
system performs observation and recommendation only: it does not scan targets,
execute attacks, modify firewalls, disable accounts, or run arbitrary commands.
