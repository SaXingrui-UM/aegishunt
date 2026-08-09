# Phase 12 API and Frontend Contract

## Purpose and boundary

Phase 12 exposes the completed Phase 0–11 local services through FastAPI and a
typed Streamlit client. FastAPI is the only external business boundary.
Streamlit never creates a database session, imports a repository, reads a model
file, resolves an artifact path, or duplicates mutation rules.

This is a loopback-only, single-user research prototype. The `actor` field
attributes audit events; it is not authentication. Authentication/RBAC,
performance hardening, security automation, distributed workers, Docker, and
deployment are not implemented.

## API conventions

- Lists use `items`, `total`, `limit`, `offset`, `has_more`, and a deterministic
  `next_offset`. Limits are validated and bounded.
- Validation uses typed filters and timezone-aware UTC timestamps.
- Every request has a bounded `X-Request-ID`, generated when omitted.
- Errors contain `error_code`, safe `message`, `request_id`, optional structured
  `details`, `retryable`, and `status_code`.
- Errors never return a traceback, raw SQL error, credential-bearing URL,
  packet payload, model bytes, or local artifact path.
- Mutations require explicit forms. Consequential operations also require
  confirmation, actor, and a reason/notes field.
- GET requests are read-only. Auto-refresh uses GET requests only.

HTTP errors distinguish malformed requests (400), missing identities (404),
state/version conflicts (409), oversized uploads (413), validation failures
(422), unavailable local dependencies (503), and sanitized internal failures
(500).

## Route inventory

| Area | Routes and capabilities |
| --- | --- |
| System/runtime | `/health`, `/system/status`, runtime status/jobs/workers, source-scoped `/runtime/replay-statistics/{source_id}`, measured job latency/throughput, process resource snapshot, pause/resume/recover, bounded run-once |
| Ingestion | streamed PCAP/CSV/JSON upload, allowlisted samples, sources/jobs, source-ID replay |
| Traffic | bounded flow list/detail/summary and detection list/detail |
| Alerts | list/detail with immutable evidence and explicit analyst-verdict update |
| Hunts | alert-group and hypothesis list/detail, safe hypothesis transition, idempotent case creation |
| Cases/feedback | case lifecycle, notes, evidence references, feedback, report/export/candidate artifacts, bounded read-only audit history |
| Models | verified list/detail/global-active, native and stored permutation importance, runtime-job effective models and policy, controlled explicit train, verified explicit activate |
| Evaluation | verified read-only run list/latest/detail, strict Phase 7 fusion discovery, and `/evaluation/summary`, a typed projection of the latest runtime-pinned controlled demo evidence; unavailable/invalid evidence fails closed |
| Demo | read-only status and explicit allowlisted sample execution |

The generated `/openapi.json`, `/docs`, and `/redoc` describe the same typed
contracts. Operation IDs are regression-tested for uniqueness.

## Upload and download safety

Uploads are read from `UploadFile` in configured chunks. Size is checked before
and during streaming. The existing Phase 2 service validates extension, content,
format/schema, checksum, empty/truncated input, storage containment, and atomic
commit. Client filenames are metadata only. Traversal, absolute filenames,
unsupported types, malformed inputs, and partial oversized uploads fail safely.

Downloads are identity-based, not path-based. Case reports and controlled
artifacts must pass configured-root containment, exact inventory/checksum,
regular-file, and symlink checks before a sanitized download response is
returned.

## Typed frontend

`aegishunt.frontend.client.ApiClient` validates response contracts and parses
API error envelopes. It applies bounded timeouts and does not silently turn
errors into empty results, retry mutations, or fall back to direct storage.

The nine pages are:

1. **Overview** — four mentor-facing KPIs, real packet-to-case pipeline counts,
   runtime-job effective models/fusion, a collapsed controlled-demo action, and
   one concise research boundary.
2. **Data Ingestion** — uploads, sample selection, replay creation and controls,
   worker run-once, and separate observed versus durable progress.
3. **Traffic Explorer** — server-paginated flow filters, bounded summaries,
   detections, and associated alerts.
4. **Alerts** — scores, reason codes, facts/inferences/limitations,
   non-causal explanations, related hunts, and verdict form.
5. **Threat Hunts** — groups, hypotheses, facts/inferences/assumptions,
   benign alternatives, possible mappings, non-executed queries, transitions,
   and explicit case creation.
6. **Cases** — lifecycle, priority/assignment/verdict, an additional explicit
   confirmation before an existing verdict can be replaced, append-only notes
   and typed evidence, feedback, bounded read-only Audit History, closure, and
   verified report export.
7. **Model Lab** — the two effective runtime-pinned models and evaluated fusion
   policy first; native feature importance reports standard deviation as not
   applicable, while a Native/Permutation selector exposes the persisted
   repeated-permutation means and deviations. Hashes, schema, snapshot, and
   global-pointer semantics are collapsed as provenance. Training and
   activation controls appear only when their API-reported prerequisites are
   actually ready.
8. **Evaluation** — source-selectable operational Replay Statistics first,
   followed by the unchanged typed controlled model evaluation. Replay counts,
   score distributions, duration, and throughput are joined through the
   selected source's runtime job and output ledger, so they cannot mix another
   PCAP's outputs. The controlled section remains a presentation-oriented view
   of evidence scope, known-group metrics, five-family LOAO Recall,
   confidence-interval summary, provenance, and limitations. It never parses
   arbitrary JSON in Streamlit and never prepares evidence on GET.
9. **System Health** — API/database/schema, queue/workers, observed/durable
   replay state, measured process CPU/RSS/thread/PID snapshot, observed Demo
   job latency, policies, and disabled live capture.

Pages provide explicit empty, success, warning, and API-error states. A single
radio navigation renders one page per rerun; the view modules live under
`frontend/views/` so Streamlit cannot discover a second implicit multipage
navigation. No page uses untrusted unsafe HTML.

`GET /evaluation/summary` first resolves the latest completed runtime job and
its immutable effective fusion policy, then calls `DemoArtifactManager.read()`
only. It requires exact experiment inventory, regular non-symlink files,
verified policy/checksums, matching experiment/dataset/split identities, and a
policy manifest hash equal to the runtime snapshot. It returns only a typed
available, unavailable, or invalid projection and never exposes absolute paths.

`GET /runtime/replay-statistics/{source_id}` resolves the stored source's
unique replay job, then counts distinct flow, detection, and alert identities
from that job's immutable output ledger. Supervised, anomaly, fusion, and risk
score summaries and ten fixed buckets are calculated only from detections
referenced by the same ledger. A stored source without a replay job returns a
typed unavailable state rather than falling back to global statistics.

## Controlled sample demonstration

`POST /demo/sample` and `aegishunt demo run` require explicit confirmation and
accept only allowlisted samples. `phase12-demo-pcap` remains the deterministic
350-byte, five-packet complete-lifecycle regression fixture. The separate
`phase12-presentation-demo-pcap` is a deterministic 3,580-byte, 32-packet
presentation sample with IPv4, IPv6, TCP, UDP, ICMPv4, ICMPv6, bidirectional
exchanges, repeated short connections, periodic small flows, and an asymmetric
transfer-like flow. Both use only documentation addresses, neither contacts or
targets a network, and neither contains an exploit payload or credential.

In a fresh environment the demo:

1. initializes the configured SQLite database;
2. verifies or atomically prepares isolated demo-only datasets, bundles,
   evaluation evidence, explanation data, and policies;
3. ingests the allowlisted PCAP through the Phase 2 service;
4. creates a Phase 11 runtime job and explicitly runs one existing worker;
5. persists real flows, detections, alerts, groups, and hypotheses;
6. optionally creates a case only when separately requested; and
7. exposes the resulting identities through the same API/client used by all
   pages.

Repeated execution verifies and reuses matching identities. It does not reset
the database, duplicate outputs, overwrite historical evidence, activate a
model, access the network, require root, use live capture, or perform response
actions. Generated artifacts live under the configured ignored demo root.

The sample uses controlled synthetic evidence solely to verify the pipeline.
It is not a public benchmark, production validation, real-world performance,
proof of zero-day detection, or attack probability.

## Research truthfulness

- Phase 6 LOF is `validation_qualified`; no untouched independent holdout exists.
- Phase 7 fusion is `inconclusive`, was not shown superior to the strongest
  single engine, and underperformed anomaly-only in family-macro LOAO Recall.
- Risk, fusion, correlation, and hypothesis-confidence scores are not attack
  probabilities.
- Severity is triage, alerts are not confirmed attacks, hypotheses are not
  facts, possible MITRE mappings are not attribution, and feature contributions
  are non-causal.
- Analyst feedback can be noisy and retraining candidates are not approved
  training data.
- Observed replay progress is non-durable. Recovery restarts from origin rather
  than an exact packet cursor.

## Verification

Phase 12 tests cover API contracts/OpenAPI, errors, pagination/filtering,
uploads, runtime controls, traffic, alerts/hunts/cases, model/evaluation access,
the typed client, frontend source boundaries, and a fresh-database full sample
E2E. The E2E verifies idempotent real outputs and confirms that formal artifact
roots remain unchanged.
