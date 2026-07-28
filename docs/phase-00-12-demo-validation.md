# Phase 0–12 Full Demo Validation

## 1. Validation Scope

Status: **Verified with limitations**.

This validation exercised the implemented Phase 0–12 system from the repository's
packaged PCAP through packet parsing, canonical bidirectional flows, 43 behavioral
features, supervised and anomaly inference, score fusion, alerts, correlation,
deterministic hypothesis generation, case management, analyst feedback, FastAPI,
the runtime worker, SQLite persistence, and all nine Streamlit pages.

The validation target was commit
`75c73bc86a40a78a22edde5fb175359a7b755c05`
(`docs: record phase 12 post-merge checkpoint (#36)`). The implementation was
checked in source, routes, repositories, CLI entries, tests, sample artifacts,
model bundles, and rendered frontend pages; status documentation alone was not
treated as proof.

Phase 13 was not started. No live capture, real target, exploitation, automated
response, dependency upgrade, performance hardening, or new research feature was
introduced. `docs/demo_guide.md` was not present; the existing README,
architecture, release documents, source, tests, Project Plan, and Implementation
Roadmap were used.

The expected validation-only changes were:

- `.gitignore`, to keep the isolated `.tmp/` run out of Git;
- `tests/e2e/test_phase_12_api_frontend.py`, to connect the existing demo E2E to
  case verdict and analyst feedback;
- this report.

## 2. Git and Environment

Status: **Verified**.

- Initial branch: `main`
- Validation branch: `fix/phase-00-12-demo-validation`
- Target SHA: `75c73bc86a40a78a22edde5fb175359a7b755c05`
- Remote: `origin git@github.com:SaXingrui-UM/aegishunt.git`
- Initial working tree: clean
- Python: `3.12.13`
- OS: Darwin 25.5.0, arm64
- SQLite schema version: `5`
- Time zone: `Asia/Shanghai`
- Run start: `2026-07-28T06:23:27Z`
- Run end: `2026-07-28T08:01:12Z`
- Isolated run root:
  `.tmp/demo-validation/20260728T062327Z`
- Primary database:
  `.tmp/demo-validation/20260728T062327Z/demo-primary.db`
- Independent reproducibility database:
  `.tmp/demo-validation/20260728T062327Z/demo-reproducibility.db`
- Pause/resume database:
  `.tmp/demo-validation/20260728T062327Z/demo-pause-resume-api.db`
- Failure-recovery database:
  `.tmp/demo-validation/20260728T062327Z/demo-failure.db`
- Dependency inventory:
  `.tmp/demo-validation/20260728T062327Z/reports/dependencies.txt`
- Environment inventory:
  `.tmp/demo-validation/20260728T062327Z/reports/environment.txt`

The virtual environment requires `PYTHONPATH=src` for direct module execution;
this was used consistently and is included in every reproduction command.

## 3. Startup Commands

Status: **Verified**.

The existing official CLI entries were used:

```bash
cd /Users/yuxiaoxing/Desktop/AegisHunt
source .tmp/demo-validation/20260728T062327Z/demo.env
PYTHONPATH=src .venv/bin/python -m aegishunt.cli doctor
PYTHONPATH=src .venv/bin/python -m aegishunt.cli init-db
PYTHONPATH=src .venv/bin/python -m aegishunt.cli api \
  --host 127.0.0.1 --port 18080 --no-reload
PYTHONPATH=src .venv/bin/python -m aegishunt.cli frontend \
  --address 127.0.0.1 --port 18501 --headless
```

The controlled run was invoked through the implemented API:

```bash
curl -fsS -X POST http://127.0.0.1:18080/demo/sample \
  -H 'Content-Type: application/json' \
  -d '{
    "actor":"demo-validation-analyst",
    "reason":"Phase 0-12 full controlled demo validation",
    "confirm":true,
    "sample_id":"phase12-demo-pcap",
    "create_case":true
  }'
```

The demo endpoint used the existing ingestion service, pinned runtime job, and
bounded worker. It did not insert flows, detections, alerts, groups, hypotheses,
or cases directly.

## 4. Demo Configuration

Status: **Verified**.

The run used only isolated environment overrides documented in
`.tmp/demo-validation/20260728T062327Z/demo.env`. Generated demo artifacts were
then exposed read-only to the restarted services by
`.tmp/demo-validation/20260728T062327Z/prepared-demo.env`.

Relevant repository or generated configuration:

- `configs/application.yaml`
- `configs/models/detection.yaml`
- `configs/models/fusion.yaml`
- `configs/correlation.yaml`
- `configs/runtime.yaml`
- `src/aegishunt/hunting/templates.py`
- generated `configs/supervised.yaml`
- generated `configs/anomaly.yaml`
- generated `configs/detection.yaml`
- generated `configs/correlation.yaml`
- generated `configs/runtime.yaml`

Random seeds were dataset `4204`, supervised `5105`, anomaly `6106`, fusion data
`7207`, fusion model `7307`, and fusion bootstrap `7407`. Live capture remained
disabled. Recovery semantics were deterministic restart from origin, not packet
cursor resume. Automated response remained disabled.

SQLite was initialized successfully with WAL enabled. The application connection
reported `foreign_keys=1`, and `PRAGMA integrity_check` returned `ok` before and
after failures, service restart, browser mutation, and final shutdown.

## 5. Sample Input

Status: **Verified**.

- Registered sample: `data/sample/phase12-demo.pcap`
- Evidence copy:
  `.tmp/demo-validation/20260728T062327Z/input/phase12-demo.pcap`
- Size: `350` bytes
- SHA-256:
  `5275d1cd350072883d046cf5b4fe4a438d8ded69375241bbd94b90a21e8c4226`
- Packets: `5`
- Decoded packets: `5`
- IP versions observed: IPv4 `5`; IPv6 was not present in this sample
- Transport distribution: TCP `3`, UDP `2`
- Scenario: one bidirectional UDP exchange and one TCP SYN/SYN-ACK/ACK exchange
  from the same controlled documentation-range source
- Expected semantics: controlled synthetic suspiciousness evidence, not attack
  ground truth or a public benchmark

Packet-level evidence is in
`.tmp/demo-validation/20260728T062327Z/reports/sample-packet-inventory.json`.

## 6. Model Versions

Status: **Verified for runtime loading; partially verified in generic active-model UI**.

The replay job's immutable snapshot proves the exact artifacts loaded during
inference:

| Engine | Algorithm | Version | Model artifact SHA-256 |
| --- | --- | --- | --- |
| Supervised | Random Forest with packaged preprocessing | `12.0.0` | `c7ef652540fe0fe306b31fb20e682d94b4ed989fef0ad7af7c07b65e2e08d9cf` |
| Anomaly | Local Outlier Factor | `1.1.0-candidate` | `353f75ddcfd7e56dbbe1a114c4fd0a14c62582beabc80a681211baf745dfdc95` |
| Fusion | selected 0.75 supervised / 0.25 anomaly policy | `1.0.0` | `868645d37780d9fe401faf545e2059a081fad35e36d180dee56600785218c7e8` |

The feature schema was `1.0.0` with 43 ordered features for both model bundles and
runtime data. Model, schema, checksum, and pinned-source mismatches are rejected by
preflight; this was also covered by the full automated suite.

The generic `/models/active` response was an empty list because the controlled
demo does not mutate global active pointers. This is intentionally distinct from
the verified per-job artifact snapshot. Model Lab showed the supervised and
anomaly bundles as available, but the generic configured fusion row as
unavailable.

Full artifact hashes are in
`.tmp/demo-validation/20260728T062327Z/reports/model-artifact-sha256.txt`.

## 7. End-to-End Pipeline

Status: **Verified**.

The following chain completed through official services:

```text
phase12-demo.pcap
  -> 5 decoded packets
  -> 2 canonical bidirectional flows
  -> 2 deterministic 43-feature vectors
  -> 2 supervised + anomaly inference results
  -> 2 fused detection results
  -> 2 security alerts
  -> 1 alert group
  -> 1 proposed threat hypothesis
  -> 1 investigation case
  -> 2 analyst feedback records
  -> FastAPI and Streamlit read views
```

Primary runtime job `93cf551a-e374-4c93-90a3-dd38cfa05ead` completed at
`2026-07-28T06:55:49.158823Z`, with durable progress `5/5`, no skipped packets,
no out-of-order packets, no error, and one completed worker attempt. The job
reused the two flows committed by official Phase 2 ingestion, then created two
detections, two alerts, one group, and one hypothesis.

## 8. PCAP and Flow Results

Status: **Verified**.

Two canonical flows were generated:

1. UDP flow `f4614f5c-e225-5401-9f86-25cf3091db5e`:
   `192.0.2.10:53000 -> 198.51.100.53:53`, 2 packets, 56 network bytes,
   forward/backward packets `1/1`, duration `0.1s`.
2. TCP flow `797edc9d-0882-54ef-9960-0adb93a3f805`:
   `192.0.2.10:49152 -> 198.51.100.80:443`, 3 packets, 120 network bytes,
   forward/backward packets `2/1`, duration `0.2s`, SYN count `2`, ACK count `2`,
   completed-handshake indicator `1`.

All feature values were finite; there were no NaN or Infinity values. Volume,
packet-size, timing, direction, TCP flags, asymmetry, burst, periodicity, and
failed-connection features were present.

The same sample was processed in a completely separate database. Its two
canonical flow records and all 43 feature values were identical to the primary
run. No primary database record was reused. Evidence:
`.tmp/demo-validation/20260728T062327Z/reports/reproducibility-comparison.json`.

## 9. Detection Results

Status: **Verified**.

Two detection results were created, and both included supervised and anomaly
fields. Representative TCP result
`25e91925-680a-5f2d-a649-c44c5aa2844b`:

- flow: `797edc9d-0882-54ef-9960-0adb93a3f805`
- supervised label: `"1"`
- supervised probability: `1.0`
- supervised threshold: `0.5`
- anomaly raw score: `-1.0083856423145203`
- normalized anomaly score: `0.8230462611167106`
- anomaly threshold: `0.9`
- fusion score: `0.9557615652791777`
- fusion threshold: `0.7`
- operational risk: `0.9557615652791777`
- severity: `critical`

The result came from the pinned model bundles and packaged preprocessing pipeline;
no inference failure or fallback occurred.

## 10. Anomaly Results

Status: **Verified**.

The LOF bundle produced raw and normalized scores for both flows:

- below-threshold representative: TCP normalized score
  `0.8230462611167106` versus threshold `0.9`;
- above-threshold representative: UDP normalized score `1.0` versus threshold
  `0.9`.

Both normalized scores were in `[0, 1]`. The UI and API explicitly state that an
anomaly score is not attack probability. The bundle remains
`validation_qualified`; no untouched independent holdout is claimed.

## 11. Fusion Results

Status: **Verified**.

The selected policy uses `0.75 * supervised_probability + 0.25 *
normalized_anomaly_score` and a fusion threshold of `0.7`.

For UDP detection `bd636d9d-29c3-5184-8dad-71119e1a7ea7`:

```text
0.75 * 0.9166666666666666 + 0.25 * 1.0 = 0.9375
```

The persisted fusion score and operational risk were both `0.9375`. Severity was
derived from the isolated demo risk policy; it was not hard-coded in the sample.
The UI identifies fusion and risk as suspiciousness/triage evidence, not attack
probability. The underlying Phase 7 fusion recommendation remains inconclusive.

## 12. Alert Results

Status: **Verified**.

- Total alerts: `2`
- By severity: `critical=2`
- By generated alert title/type: `Suspicious network behavior detected=2`
- Status: both `open`

Representative alert `adf0ef94-0150-53fc-8e01-a73c0797da7c` links to detection
`bd636d9d-29c3-5184-8dad-71119e1a7ea7`, flow
`f4614f5c-e225-5401-9f86-25cf3091db5e`, source `192.0.2.10`, destination
`198.51.100.53`, severity `critical`, and risk `0.9375`.

Reason codes were:

- `SUPERVISED_HIGH_CONFIDENCE`
- `ANOMALY_HIGH_SCORE`
- `MULTI_ENGINE_SUPPORT`
- `RISK_SCORE_ABOVE_ALERT_THRESHOLD`

The detail response and Alerts UI exposed observed facts, thresholds, entities,
reference ranges, single-feature reference-replacement contributions, and
limitations. Explanations state that the evidence is non-causal and does not
confirm an attack.

## 13. Correlation Results

Status: **Verified**.

Alert group `09d0e5ea-1f88-59ad-a551-629d235cc2a2` contains both alerts. It spans
`2026-01-01T00:00:00Z` to `2026-01-01T00:00:01.200000Z`, uses entity key
`source_ip:192.0.2.10`, and has correlation score `0.8605207739238561`.

Matched deterministic reasons were:

- `multi_alert_accumulation`
- `multi_engine_evidence`
- `source_centered_reconnaissance`
- `source_fan_out`

The score is presented as non-probabilistic triage evidence. The group was
readable through both `/alert-groups/{id}` and the Threat Hunts frontend.

## 14. Threat Hypothesis

Status: **Verified**.

Hypothesis `a2d32506-cf6f-59c8-af7c-05058be76a97`:

- title: `Possible network reconnaissance`
- template: `possible_network_reconnaissance`
- confidence: `0.9442083095695425`
- severity: `high`
- status: `proposed`
- supporting alerts: `2`
- involved entity: `source_ip:192.0.2.10`
- possible mapping: MITRE ATT&CK `T1046`, confidence `low`
- assumptions: `2`
- alternative benign explanations: authorized vulnerability scanning; asset
  discovery or monitoring
- recommended query: present and explicitly `not_executed`
- recommended investigation steps: `3`

The engine was deterministic and offline. The mapping is labeled as a possible
behavioral analogy, not attribution. The hypothesis was not marked confirmed.

## 15. Investigation Case

Status: **Verified**.

Case `3fdacb15-cef9-5d92-b856-b138b4c09147` was created from the real hypothesis,
links both generated alerts, and remained open for investigation:

- initial status: `open`
- updated status: `investigating`
- priority: `high`
- verdict: `needs_more_information`
- evidence reference added for detection
  `25e91925-680a-5f2d-a649-c44c5aa2844b`
- API note:
  `Reviewed the replay-generated flow, dual-engine detection, fused risk,
  correlated alerts, and hypothesis. More information is required before any
  conclusion.`
- browser-added note:
  `Browser validation confirmed the persisted case, linked evidence, analyst
  verdict, and append-only workflow.`

The browser-added note persisted after rerender, and the final case response had
two notes. Audit event `add_case_note` recorded actor
`demo-validation-analyst`, case ID, before/after note counts, timestamp, and
service-level reason. A versioned case report was also generated.

## 16. Analyst Feedback

Status: **Verified**.

Two case feedback records were persisted: one created by the case-verdict workflow
and one explicit API submission.

Representative feedback:

- feedback ID: `f4c2a56b-9730-5247-b0d3-b529205e1b49`
- object type: `case`
- object ID: `3fdacb15-cef9-5d92-b856-b138b4c09147`
- verdict: `needs_more_information`
- confidence: `0.6`
- notes: `Controlled synthetic pipeline evidence; do not treat as attack
  confirmation or training truth.`
- created at: `2026-07-28T06:57:27.004259Z`

Export `demo-validation-v1` contained both records with checksums and limitations.
Retraining-candidate generation returned `eligibility_status=empty`,
`candidate_count=0`, and `exclusion_count=2`, as expected for
`needs_more_information` synthetic evidence. Audit data explicitly recorded
`training_invoked=false` and `model_activation_invoked=false`; feedback did not
replace any model.

## 17. API Verification

Status: **Verified**.

Service URLs during validation:

- FastAPI: `http://127.0.0.1:18080`
- OpenAPI: `http://127.0.0.1:18080/openapi.json`
- Swagger UI: `http://127.0.0.1:18080/docs`
- Streamlit: `http://127.0.0.1:18501`

Observed service processes after the prepared-artifact restart:

- API PID `96867`
- frontend launcher PID `96868`
- Streamlit PID `96871`
- bounded demo worker record `phase12-demo-worker`, completed and stopped

The following real routes returned HTTP 200 with validated response models and
pagination where applicable:

- `/health`
- `/system/status`
- `/ingestion/jobs`
- `/ingestion/sources`
- `/runtime/status`
- `/runtime/jobs`
- `/runtime/workers`
- `/flows` and `/flows/summary`
- `/detections`
- `/alerts`
- `/alert-groups`
- `/hypotheses`
- `/cases`
- `/feedback`
- `/models` and `/models/active`
- `/evaluation` and `/evaluation/latest`
- `/demo/status`

Empty list states returned 200 with zero totals before the demo. Valid missing
UUIDs returned 404. Unsupported and malformed uploads returned structured 422
errors. All object-detail routes and case/feedback mutations returned 200. Full
status evidence:

- `.tmp/demo-validation/20260728T062327Z/reports/api-empty-and-error-status.tsv`
- `.tmp/demo-validation/20260728T062327Z/reports/api-post-demo-status.tsv`
- `.tmp/demo-validation/20260728T062327Z/reports/api-detail-status.tsv`
- `.tmp/demo-validation/20260728T062327Z/reports/api-mutation-status.tsv`

## 18. Frontend Verification

Status: **Verified with limitations**.

The Codex in-app browser was used to open the actual Streamlit service, navigate
and interact with all nine pages, inspect rendered values, click tabs and
controls, and append a real case note. Browser console warning/error count was
zero.

Verified pages:

1. Overview: database ready; 2 flows, 2 active/critical alerts, 1 open hypothesis,
   1 open case, ingestion state, recent activity, and controlled demo action.
2. Data Ingestion: upload, packaged sample, replay, and jobs tabs; completed
   5-record ingestion and runtime job; understandable malformed-file error.
3. Traffic Explorer: two-flow table, filters, protocol distribution, endpoints,
   packet/byte counts, detail, all 43 behavioral features, detection and alert
   tabs.
4. Alerts: supervised/anomaly/fusion/risk values, thresholds, reason codes,
   entities, explanations, reference ranges, limitations, and analyst verdict.
5. Threat Hunts: alert group, correlation score, hypothesis evidence,
   assumptions, alternatives, possible MITRE mapping, query, and steps.
6. Cases: case detail, two notes, evidence, verdict, two feedback records, and
   report controls; one note was submitted through the UI.
7. Model Lab: supervised/anomaly bundles, states, versions, artifact availability,
   global importance, and explicit non-auto-activation training controls.
8. Evaluation: real anomaly and supervised results, confusion matrix and
   classification metrics, plus explicit fusion-unavailable/inconclusive evidence.
9. System Health: database/schema, worker record, queue, runtime job, model load
   state, recovery semantics, and latest error field.

Screenshots:

- `.tmp/demo-validation/20260728T062327Z/screenshots/01-overview.png`
- `.tmp/demo-validation/20260728T062327Z/screenshots/02-data-ingestion-upload.png`
- `.tmp/demo-validation/20260728T062327Z/screenshots/03-data-ingestion-jobs.png`
- `.tmp/demo-validation/20260728T062327Z/screenshots/04-traffic-explorer-features.png`
- `.tmp/demo-validation/20260728T062327Z/screenshots/05-alerts-reasons.png`
- `.tmp/demo-validation/20260728T062327Z/screenshots/06-threat-hunts-hypotheses.png`
- `.tmp/demo-validation/20260728T062327Z/screenshots/07-cases-browser-note.png`
- `.tmp/demo-validation/20260728T062327Z/screenshots/08-model-lab.png`
- `.tmp/demo-validation/20260728T062327Z/screenshots/09-evaluation.png`
- `.tmp/demo-validation/20260728T062327Z/screenshots/10-system-health.png`

Limitations are recorded in Section 23: global active pointers, dedicated audit
history, p95 latency, CPU/RSS, and some fusion evaluation fields were unavailable
and were not inferred or fabricated.

## 19. Failure and Recovery Checks

Status: **Verified**.

- Unsupported `.txt` upload: structured 422 rejection.
- Malformed `.pcap`: structured 422, failed ingestion job recorded, API remained
  healthy.
- Missing ingestion job, flow, alert, group, hypothesis, and case: structured 404.
- Runtime preflight mismatch: job
  `d267731e-51ec-4105-a369-9f2deba8079c` failed safely at `preflight` with
  `runtimepreflight`; the worker remained alive to poll and then stopped
  gracefully.
- Pause/resume: job `e236cda7-23db-4787-8958-c0b8edf9e5d7` paused at observed
  `3/5`, resumed the same attempt
  `a4f8b095-af5d-4cf8-a76a-9a149284c547`, and completed `5/5`.
- Graceful idle-worker interruption: worker state was persisted as `stopped`.
- Service restart: case data remained readable with HTTP 200.
- Database integrity after malformed input, runtime failure, pause/resume, browser
  mutation, and shutdown: `ok`.
- Primary database after final shutdown: 2 flows, 2 feedback records, 2 case
  notes; ports 18080 and 18501 were closed.

No path traversal, oversized-file stress, vulnerability scan, secret scan, or
adversarial experiment was performed.

## 20. Automated Tests

Status: **Verified**.

Baseline before live demo:

- `ruff check .`: passed
- `mypy src`: passed, 234 source files
- `pytest`: 460 passed in 1559.79s; coverage 85.46%

After the regression update:

- focused full-demo feedback E2E: 1 passed in 36.26s
- `ruff check .`: passed
- `mypy src`: passed, 234 source files
- `pytest`: 460 passed in 1536.31s; coverage 85.42%

The final suite included Phase 0–12 E2E plus ingestion, packet parsing,
bidirectional flow, features, supervised inference, anomaly inference, fusion,
alerts, correlation, hypothesis, case, feedback, API, frontend client, replay,
integration, unit, and existing security regression tests.

Logs:

- `.tmp/demo-validation/20260728T062327Z/logs/baseline-pytest.log`
- `.tmp/demo-validation/20260728T062327Z/logs/focused-phase12-feedback-test.log`
- `.tmp/demo-validation/20260728T062327Z/logs/final-ruff.log`
- `.tmp/demo-validation/20260728T062327Z/logs/final-mypy.log`
- `.tmp/demo-validation/20260728T062327Z/logs/final-pytest.log`

`codex review --base main` was attempted but could not start because the locally
installed Codex package was missing its native executable (`ENOENT`). A complete
manual `main...HEAD` diff review was therefore performed for correctness,
requirement scope, tests, secrets, generated/oversized files, data leakage, and
model-evaluation integrity. It found no blocking issue: the diff contains only
`.gitignore`, the connected E2E regression, and this report; no run database,
logs, model binary, PCAP, secret, deleted test, or Phase 13 work is included.

## 21. Defects Found

Status: **Verified**.

No application-runtime defect blocked the complete Phase 0–12 demonstration.

Two validation hygiene gaps were found:

1. The existing Phase 12 sample-demo E2E stopped after case retrieval. Case
   feedback was tested elsewhere, so no single automated scenario proved
   `sample PCAP -> ... -> case -> feedback -> frontend API client`.
2. `.tmp/` was not explicitly ignored, so the required isolated run root could
   pollute Git status if generated.

The generic read views also exposed truthful product limitations rather than
runtime defects: empty global active pointers, unavailable generic fusion
artifact/evaluation rows, and no dedicated audit-history UI.

## 22. Defects Fixed

Status: **Verified**.

- Extended
  `test_sample_demo_runs_full_existing_pipeline_idempotently` to set a case
  verdict, submit explicit case feedback, re-query the case, assert two related
  feedback records, and verify the same objects through `AegisHuntApiClient`.
- Added `.tmp/` to `.gitignore`.
- Added this auditable report.

No production business logic was changed. No test was deleted, skipped, weakened,
or hard-coded to bypass services.

## 23. Remaining Limitations

Status: **Partially verified where stated**.

1. The controlled demo pins and verifies models per runtime job, but does not
   mutate global active-model pointers. Consequently Overview shows active
   supervised/anomaly as unavailable and `/models/active` is empty.
2. Model Lab's generic fusion row is unavailable even though the runtime snapshot
   proves the exact fusion policy used.
3. The Evaluation page displays real supervised and anomaly evidence, but the
   generic Phase 7 fusion row is unavailable; the existing recommendation is
   inconclusive.
4. P95 pipeline latency, CPU, RSS, and thread metrics are not persisted for this
   local run and are shown as unavailable.
5. Audit events are persisted and were queried from the database, but the Cases
   page has no dedicated audit-history tab.
6. The sample is deliberately tiny and synthetic: IPv4 TCP/UDP only. It does not
   validate IPv6, ICMP, public-benchmark quality, production scale, zero-day
   detection, or real-world attack attribution.
7. Recovery restarts deterministically from origin and reuses committed evidence;
   it is not exact packet-cursor resume.
8. LOF is validation-qualified without an untouched independent holdout; fusion
   superiority over supervised-only is not claimed.

## 24. Demo Readiness Decision

Decision: **READY WITH LIMITATIONS**.

All critical readiness conditions were actually executed and evidenced: real
sample replay, flows, supervised inference, anomaly inference, fusion, alerts,
correlation, hypothesis, case, feedback, FastAPI, Streamlit, Ruff, mypy, full
pytest, and the connected Phase 0–12 E2E.

The decision is not plain READY because several requested generic frontend
observability fields remain truthfully unavailable: global active pointers,
fusion evaluation/artifact views, audit history UI, and local resource/latency
metrics. None of these prevented the real controlled pipeline.

## 25. Exact Reproduction Steps

### Clean deterministic automated reproduction

This command uses pytest's fresh temporary directory and exercises the controlled
sample through case verdict, feedback, API, and frontend API client:

```bash
cd /Users/yuxiaoxing/Desktop/AegisHunt
PYTHONPATH=src .venv/bin/pytest \
  tests/e2e/test_phase_12_api_frontend.py::test_sample_demo_runs_full_existing_pipeline_idempotently \
  -q --no-cov
```

### Reopen the preserved live validation run

```bash
cd /Users/yuxiaoxing/Desktop/AegisHunt
source .tmp/demo-validation/20260728T062327Z/prepared-demo.env
PYTHONPATH=src .venv/bin/python -m aegishunt.cli doctor
PYTHONPATH=src .venv/bin/python -m aegishunt.cli api \
  --host 127.0.0.1 --port 18080 --no-reload
```

In a second terminal:

```bash
cd /Users/yuxiaoxing/Desktop/AegisHunt
source .tmp/demo-validation/20260728T062327Z/prepared-demo.env
PYTHONPATH=src .venv/bin/python -m aegishunt.cli frontend \
  --address 127.0.0.1 --port 18501 --headless
```

Then open `http://127.0.0.1:18501`. Stop both processes with Ctrl-C after review.
The preserved run is for local evidence review only; do not commit its `.tmp`
contents.

### 5–8 minute manual demonstration script

Preparation: source `prepared-demo.env`, start API and Streamlit as above, and
confirm both URLs return 200. The run already contains the validated objects.

| Step | Click | Expected content | Suggested narration | Fallback |
| --- | --- | --- | --- | --- |
| 1 | Sidebar → Overview | database ready; 2 flows, 2 alerts, 1 hypothesis, 1 case | This is an isolated synthetic run, not production validation. | Show `/system/status`. |
| 2 | Overview → Controlled sample demonstration | sample `phase12-demo-pcap` and explicit confirmation controls | The action is local, allowlisted, and audited. | Show `/demo/status`. |
| 3 | Sidebar → Data Ingestion → Packaged sample | allowlisted sample selector | No real target or live capture is used. | Show sample manifest and SHA-256. |
| 4 | Data Ingestion → Replay | stored sources and replay-speed control | Replay uses the official durable runtime path. | Show `/runtime/jobs/{id}`. |
| 5 | Data Ingestion → Jobs | completed ingestion and runtime jobs, progress `1.0`, records `5` | Durable and observed progress are distinct. | Show runtime-job JSON. |
| 6 | Sidebar → Traffic Explorer | two canonical flows and protocol distribution | Five packets became one UDP and one TCP bidirectional flow. | Show `/flows`. |
| 7 | Traffic Explorer → Behavioral features | 43 finite values, forward/backward counts and TCP/timing features | Features are observations, not attack labels. | Show flow-detail JSON. |
| 8 | Sidebar → Alerts | two detections and two critical review prompts | Alerts are analyst prompts, not confirmed attacks. | Show `/alerts`. |
| 9 | Alerts → Scores and thresholds | supervised, anomaly, fusion, risk, thresholds | The TCP example is 1.0 supervised, 0.823 anomaly, 0.956 fused risk. | Show detection-detail JSON. |
| 10 | Alerts → Reasons and entities, then Explanation | reason codes, observed values, reference ranges, contributions | Contributions are model sensitivity evidence, not causation. | Show alert-detail JSON. |
| 11 | Sidebar → Threat Hunts → Alert groups | one two-alert group, score 0.861, source entity | Correlation uses time and shared source evidence. | Show group-detail JSON. |
| 12 | Threat Hunts → Hypotheses | Possible network reconnaissance, confidence, proposed status | The hypothesis is a deterministic lead, not a fact. | Show hypothesis-detail JSON. |
| 13 | Scroll hypothesis detail | evidence, assumptions, two alternatives, possible T1046, unexecuted query | MITRE is a possible analogy, not attribution. | Use saved screenshot 06. |
| 14 | Sidebar → Cases | case linked to the hypothesis and both alerts | The case remains analyst-controlled. | Show `/cases/{id}`. |
| 15 | Cases → Notes | two append-only notes | One note was added through the live browser during validation. | Show case-after-browser JSON. |
| 16 | Cases → Feedback | two `needs_more_information` records | Synthetic evidence was deliberately not labeled true positive. | Show `/feedback`. |
| 17 | Sidebar → Model Lab | supervised/anomaly artifacts and global importance; no active pointers | Runtime loading is pinned per job; global activation is intentionally unchanged. | Show job snapshot and hashes. |
| 18 | Sidebar → Evaluation | real anomaly/supervised metrics and explicit fusion limitation | Missing results are shown as unavailable, never fabricated. | Show `/evaluation/latest`. |
| 19 | Sidebar → System Health | DB/schema, stopped bounded worker, queue 0, completed job | The worker completed and stopped cleanly; recovery is restart from origin. | Show `/runtime/status`. |
| 20 | Return to Overview | complete object counts | Summarize PCAP → feedback → frontend, then stop the services. | Use this report and screenshot 01. |
