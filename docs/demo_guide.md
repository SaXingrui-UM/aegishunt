# Final controlled demonstration guide

## Preconditions and safety

Allow 8–15 minutes on first use because demo-only models are created after
explicit confirmation. Later runs reuse verified artifacts. Use Python
3.11/3.12 wheel installation or Docker Compose. No root, internet, live
interface, or external target is required after installation. The sample is a
payload-free documentation-address derivative and its profile name is not
ground truth.

## Start

Wheel:

```bash
aegishunt init-db
aegishunt api
# terminal 2
aegishunt runtime worker run --forever --worker-id demo-worker
# terminal 3
aegishunt frontend --headless
```

Docker:

```bash
docker compose build
docker compose run --rm init
docker compose up -d api worker frontend
```

Open `http://127.0.0.1:8501`. System Health should show a reachable API,
initialized schema, one worker, and real process/resource status.

## Demonstration sequence

1. **Overview:** explain the real packet → flow → detection → alert → group →
   hypothesis → case counts and the two effective runtime-pinned models. If the
   environment is empty, open **Run or reset controlled demo**; execution still
   requires actor, reason, and explicit confirmation.
2. **Data Ingestion:** inspect the available samples, then choose
   `phase14-attack-like-pcap` or `phase14-benign-like-pcap`. Alternatively use
   the explicit Demo form/command. Confirm the mutation and record the returned
   source/job IDs; UUIDs are runtime values and must not be hard-coded.
3. **Runtime:** create replay for the completed source. Observe live packet
   progress separately from durable committed progress. Wait for `completed`.
4. **Traffic Explorer:** inspect at least one bidirectional flow and its ordered
   43-feature vector.
5. **Alerts:** inspect supervised probability, anomaly score, fusion/risk,
   severity, reason codes, and non-causal explanation. Scores are not attack
   probabilities and an alert is not confirmation.
6. **Threat Hunts:** inspect an AlertGroup and the proposed ThreatHypothesis.
   Review facts, inferences, assumptions, benign alternatives, possible
   mappings, and query suggestions marked not executed.
7. **Cases:** create a case from an eligible hypothesis. Add an analyst note,
   set a supported verdict with confidence/reason, and review audit history.
8. **Feedback:** inspect persisted feedback and export/build a retraining
   candidate only with a new version and explicit confirmation. No training or
   activation occurs.
9. **Cases:** export the case report with a new version.
10. **Model Lab:** show Random Forest v12.0.0, validation-qualified LOF
    v1.1.0-candidate, and the 75%/25% fusion policy pinned by the completed job.
    The empty global pointer is valid and does not trigger activation.
11. **Evaluation:** show the verified known comparison and the five-family LOAO
    result. Family-macro Recall is supervised `0.6000`, anomaly `0.9333`, and
    fusion `0.3333`; fusion Recall is `0.0000` for held-out exfiltration and
    reconnaissance. The negative result is evidence, not a UI failure.
12. **System Health:** review durable jobs, worker/resource state, and measured
    observations. Performance is not an SLA.

The exact number of flows/alerts depends on the selected profile and current
policy; use the API response rather than a scripted count. Repeating the same
sample uses checksum/source and runtime idempotency contracts and must not
silently duplicate committed outputs.

## Explicit CLI demo

```bash
export AEGISHUNT_CONFIG=configs/final-delivery.yaml
aegishunt demo status
aegishunt demo run \
  --sample-id phase14-attack-like-pcap \
  --actor demo-analyst \
  --reason "explicit controlled final demonstration" \
  --confirm
```

Expected final state is `completed` with source, runtime job, flow, alert,
group, hypothesis, and optional case identifiers. Demo-only artifacts are
checksum-verified in `artifacts/demo/phase14/` or the Compose artifact volume.

## Screenshot checklist

- Overview and real API status
- Sample inventory and source checksum
- Runtime observed/durable progress
- Flow protocol and 43-feature view
- Detection/alert reasons and explanation
- Group and hypothesis evidence/alternatives
- Case note, verdict, evidence, and audit
- Model Lab effective identity
- Evaluation known comparison and negative LOAO evidence
- System Health worker/resource state

## Failure paths

- **API unavailable:** verify `/health`; start API before Streamlit.
- **Worker not running:** start one worker; queued jobs are not evidence of
  completion.
- **Empty state:** run explicit sample ingestion/demo; opening a page never
  creates data.
- **Port conflict:** stop the conflicting process or change only the loopback
  host port.
- **Stale Compose volume:** inspect the named-volume evidence and configuration;
  do not delete volumes as a troubleshooting shortcut.
- **Corrupt sample/artifact:** do not bypass checksum or inventory validation;
  regenerate the reviewed sample or create a fresh demo namespace.
- **No internet:** use the already built image/wheel. Runtime demo is offline.

Stop with Ctrl-C for local processes or `docker compose down`. Delete Compose
volumes only after reviewing evidence. Never delete SQLite WAL/SHM sidecars
while API/worker processes are open.

## Claim boundary

Say “controlled offline pipeline verification.” Do not claim public benchmark,
production validation, zero-day proof, autonomous response, attack
confirmation, fusion superiority, complete TCP truth, threat-actor attribution,
or enterprise scalability.
