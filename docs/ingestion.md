# Telemetry Ingestion

## Implemented Phase 2 scope

Phase 2 accepts three offline file contracts and reviewed local samples:

| Input | Accepted suffixes | Phase 2 validation | Explicitly deferred |
| --- | --- | --- | --- |
| PCAP | `.pcap`, `.pcapng` | container magic, framing, lengths, bounded packet-block count | packet decoding, bidirectional flows, replay |
| Flow CSV | `.csv` | UTF-8, unique canonical headers, every row through `NetworkFlow` validation, bounded row count | flow persistence and feature calculation |
| JSON events | `.json`, `.jsonl`, `.ndjson` | finite JSON values, object records, bounded record count | vendor semantics and feature mapping |
| Sample | manifest allowlist | manifest schema, safe relative path, SHA-256 before ingestion | end-to-end detection claims |

The adapters report inspected record counts and format metadata. They do not
create flows, features, detections, alerts, hypotheses, model metrics, or replay
traffic.

## Safety boundary

The upload filename must be a single safe basename with a supported suffix.
The declared media type, when supplied, must be allowlisted for the selected
adapter. Data is copied below the configured storage root in bounded chunks;
the service enforces byte and record limits, computes SHA-256, validates content,
and atomically commits a checksum-derived filename. Empty, oversized, malformed,
or unsupported inputs fail with typed errors. Temporary data is removed even if
validation stops unexpectedly.

No endpoint accepts an arbitrary server-side path. CLI paths are read only when
the local operator explicitly supplies them. The ingestion commands require no
root privilege, do not open a capture interface, do not scan a host, and do not
transmit packet contents.

## Durable job lifecycle

Phase 2 reuses the Phase 1 `TelemetrySource` record as the durable ingestion job
instead of adding a second table with duplicate provenance. Safe metadata records
progress, content type, byte size, stored filename, format inspection, and an
error code/message. The service owns these transitions:

```text
pending -> running -> completed
                   -> failed
```

Each create and transition is audited in the same database transaction. Failed
format validation remains queryable, but the untrusted staged file is discarded.
The synchronous implementation exposes intermediate progress through audited
transitions and the final job; Phase 11 may move the same state machine to a
worker without changing the public contract.

## CLI

```bash
aegishunt ingest pcap PATH [--config FILE]
aegishunt ingest csv PATH [--config FILE]
aegishunt ingest json PATH [--config FILE]
aegishunt ingest sample SAMPLE_ID [--config FILE]
```

Successful commands print the validated job as JSON. Expected configuration,
file-policy, format, storage, or sample errors exit non-zero without a traceback.

## API

- `POST /ingestion/pcap`
- `POST /ingestion/flow-csv`
- `POST /ingestion/json-events`
- `GET /ingestion/jobs?limit=...&offset=...`
- `GET /ingestion/jobs/{job_id}`
- `GET /ingestion/samples`
- `POST /ingestion/samples/{sample_id}`

Upload success returns HTTP 201 and an `IngestionJob`. Invalid content returns
HTTP 422 with a safe code/message and, when a job was created, its identifier.
Unknown job identifiers return HTTP 404. Authentication and authorization are
planned hardening work; listeners remain loopback by default.

## Controlled samples

`data/sample/manifest.yaml` declares the two committed Phase 2 fixtures. Both
use documentation-only IP/name ranges, contain no captured user traffic, and
make no detection or performance claim. The PCAP generator is deterministic:

```bash
python scripts/generate_phase2_samples.py --output data/sample/phase2-benign.pcap
```

Changing either sample requires deliberate checksum review and a manifest update.
