# Core Use Cases

All use cases below describe target behavior derived from the Project Plan.
They are acceptance inputs, not blanket implementation claims. Phase 2 implements
the safe storage, container/schema validation, durable job, sample, API, and CLI
portions of UC-01 and UC-02. Packet-to-flow conversion and canonical flow
persistence remain Phase 3 work; PCAP replay in UC-03 remains Phase 11 work.

## UC-01: Import a PCAP file

- **Actor:** System operator or security analyst.
- **Preconditions:** The API and storage are available; the actor has a PCAP or
  PCAPNG within configured type and size limits.
- **Normal flow:** The actor selects the file; the system validates extension,
  content, size, and safe name; computes a checksum; stores it in a controlled
  location; creates an ingestion job; and returns the job identifier and status.
- **Alternative flow:** If the checksum already exists, policy may reference the
  existing source and create an explicit reprocessing job rather than duplicate bytes.
- **Expected output:** A `TelemetrySource` and observable ingestion job with no
  flow or detection result fabricated before processing.
- **Failure cases:** Unsupported or malformed capture, oversize file, path
  traversal name, storage failure, duplicate-policy conflict, or checksum failure
  yields a safe structured error and no partial trusted source.

## UC-02: Import a flow CSV

- **Actor:** System operator, security analyst, or ML researcher.
- **Preconditions:** A CSV is available; its intended schema or mapping is known;
  storage and ingestion services are available.
- **Normal flow:** The actor uploads the CSV; the system validates file safety,
  headers, types, required fields, row limits, and numerical values; records the
  checksum and schema mapping; then processes valid rows under an ingestion job.
- **Alternative flow:** A supported source-specific mapping converts columns to
  the canonical flow schema while retaining the original field manifest.
- **Expected output:** Canonical flow records, source provenance, validation
  counts, and an ingestion summary.
- **Failure cases:** Missing or ambiguous fields, invalid timestamps, NaN or
  infinity, mixed incompatible schemas, oversize input, unsafe name, or row
  conversion failure is reported without silently coercing untrusted values.

## UC-03: Replay a PCAP

- **Actor:** System operator or demonstrator.
- **Preconditions:** A validated PCAP source exists; required runtime components
  and compatible active model bundles are available for the requested pipeline stage.
- **Normal flow:** The actor chooses replay speed and starts a replay; the system
  processes packet timing through the offline pipeline; reports progress; and
  persists each completed stage atomically.
- **Alternative flow:** The actor pauses, resumes, or uses a deterministic
  fastest-possible mode; the primary demonstration may use reviewed sample data.
- **Expected output:** A completed replay job and, when later phases exist,
  reproducible flows, features, detections, alerts, groups, and hypotheses.
- **Failure cases:** Corrupt capture, unsupported link type, incompatible model
  schema, resource exhaustion, interruption, or worker failure produces a failed
  or resumable job while keeping stored state consistent.

## UC-04: Inspect extracted flows

- **Actor:** Security analyst or threat hunter.
- **Preconditions:** A completed ingestion/replay has produced canonical flow records.
- **Normal flow:** The actor opens Traffic Explorer; filters by time, protocol,
  entity, label, or anomaly state; pages through flows; and opens one record to
  inspect direction, volume, timing, flags, features, and provenance.
- **Alternative flow:** The actor navigates from an alert to its originating flow
  or exports a bounded, authorized result set.
- **Expected output:** Paginated flow summaries and a detailed flow view tied to
  source, session, feature schema, and any related detections.
- **Failure cases:** No matching flow returns a clear empty state; invalid filters,
  missing/deleted source references, or access/storage errors return structured errors.

## UC-05: Review supervised detection

- **Actor:** Security analyst, threat hunter, or ML researcher.
- **Preconditions:** A validated supervised model is active; a compatible feature
  vector has been generated; inference completed successfully.
- **Normal flow:** The actor views predicted class and probability, threshold,
  model version, reason codes, top contributing features, observed values,
  reference ranges, and related flow evidence.
- **Alternative flow:** The actor compares the result with another validated
  model version or records an analyst verdict.
- **Expected output:** An auditable supervised result explicitly labeled as model
  inference rather than confirmed malicious activity.
- **Failure cases:** Missing model, schema mismatch, corrupt bundle, invalid
  features, inference error, or unavailable explanation blocks trusted output
  and records a diagnosable failure.

## UC-06: Review anomaly detection

- **Actor:** Security analyst, threat hunter, or ML researcher.
- **Preconditions:** A validated anomaly model trained on benign data is active;
  compatible features and a recorded threshold exist.
- **Normal flow:** The actor reviews raw and normalized anomaly score, threshold,
  baseline/reference context, contributing behavioral deviations, model version,
  and uncertainty statement.
- **Alternative flow:** The actor compares the score with validation distributions
  or marks the behavior benign expected for future controlled feedback use.
- **Expected output:** An explainable deviation assessment that does not claim an attack.
- **Failure cases:** Missing baseline, schema mismatch, non-finite score, corrupt
  model, missing threshold provenance, or inference failure prevents result publication.

## UC-07: Review combined risk

- **Actor:** Security analyst or threat hunter.
- **Preconditions:** At least one valid detection signal exists; fusion
  configuration and applicable model versions are recorded.
- **Normal flow:** The system normalizes available inputs and applies configured
  weights and thresholds; the actor reviews component contributions, correlation
  and contextual inputs, combined score, severity mapping, and configuration version.
- **Alternative flow:** A documented missing-signal policy computes a partial
  score or withholds fusion; a researcher compares supervised-only,
  anomaly-only, and fusion results.
- **Expected output:** A reproducible combined risk assessment with a component
  breakdown and no claim that the score is an attack probability.
- **Failure cases:** Invalid weights, out-of-range scores, absent required signal,
  unversioned configuration, or calculation error fails closed and records diagnostics.

## UC-08: Review security alerts

- **Actor:** Security analyst or threat hunter.
- **Preconditions:** A detection has crossed a configured alert policy and a
  `SecurityAlert` exists.
- **Normal flow:** The actor filters alerts; opens one; reviews severity, title,
  description, engines, risk, involved entities, evidence, reason codes, local
  explanation, status, model versions, and related objects; then records a verdict if known.
- **Alternative flow:** The actor changes workflow status, follows links to flow
  or group context, or leaves the alert unresolved with a note.
- **Expected output:** A persistent, explainable alert and audited analyst update.
- **Failure cases:** Stale references, invalid transition, concurrent update,
  missing evidence, or storage failure leaves the prior state intact and reports the conflict.

## UC-09: Review correlated alert groups

- **Actor:** Threat hunter or security analyst.
- **Preconditions:** Multiple alerts are eligible for configured entity/time correlation.
- **Normal flow:** The actor opens a group and reviews member alerts, shared
  entities, first/last time, matched rules, decay/window parameters, correlation
  score, evidence sources, and group summary.
- **Alternative flow:** The actor expands an entity timeline, compares an alert
  outside the window, or determines that the grouping is a benign coincidence.
- **Expected output:** A deterministic, reproducible group whose membership and
  score can be explained from configuration and evidence.
- **Failure cases:** Missing alert, invalid time ordering, configuration error,
  duplicate membership, or concurrent modification is rejected or repaired by
  explicit policy rather than hidden.

## UC-10: Review generated threat hypotheses

- **Actor:** Threat hunter or security analyst.
- **Preconditions:** A qualifying alert or correlated group exists and a
  deterministic hypothesis template matches its evidence.
- **Normal flow:** The actor reviews title, description, confidence, severity,
  entities, supporting alerts/features, time window, possible category/MITRE
  mapping, observed facts, inference, assumptions, benign alternatives,
  recommended queries, validation steps, and status.
- **Alternative flow:** Evidence is insufficient and no hypothesis is generated;
  the actor marks a generated hypothesis rejected or under investigation.
- **Expected output:** A structured, traceable hypothesis that is never automatically confirmed.
- **Failure cases:** Missing evidence, unsupported template, contradictory entity
  references, invalid score, or template/configuration error prevents generation
  and preserves the underlying alerts.

## UC-11: Create an investigation case

- **Actor:** Security analyst or threat hunter.
- **Preconditions:** A hypothesis exists and the actor has reviewed its evidence.
- **Normal flow:** The actor chooses create case; supplies or confirms title,
  priority, assignment, and initial note; the system links hypotheses, alerts,
  and evidence and records creation/audit timestamps.
- **Alternative flow:** The actor creates a standalone case with explicit alert
  references or links the hypothesis to an existing compatible open case.
- **Expected output:** A unique open case with stable related-object references and audit history.
- **Failure cases:** Invalid priority/status, missing related object, duplicate
  request, authorization conflict, or transaction failure creates no partial case.

## UC-12: Add analyst feedback

- **Actor:** Security analyst or threat hunter.
- **Preconditions:** A reviewable alert, hypothesis, or case exists; the actor has
  sufficient evidence to select a verdict or request more information.
- **Normal flow:** The actor selects `true_positive`, `false_positive`,
  `benign_expected`, or `needs_more_information`; optionally adds confidence and
  notes; the system validates and stores the immutable feedback event and audit data.
- **Alternative flow:** A later feedback event supersedes an earlier judgment
  without erasing history; authorized feedback can be exported as a retraining candidate.
- **Expected output:** Queryable, attributable feedback that does not alter an active model.
- **Failure cases:** Unsupported verdict, invalid object, conflicting update,
  untrusted attachment, or storage failure is rejected without changing model state.

## UC-13: Train a new model version

- **Actor:** ML researcher or authorized system operator.
- **Preconditions:** The dataset and split manifests pass schema, quality, and
  leakage checks; test data remains sealed; configuration and random seeds are recorded.
- **Normal flow:** The actor explicitly starts training; the system runs candidate
  preprocessing/training and validation; calculates metrics and confidence
  intervals; selects thresholds from validation evidence; writes a hashed,
  immutable model bundle and model card; and registers it as non-active.
- **Alternative flow:** The actor trains only supervised or anomaly candidates,
  resumes a safely resumable job, or rejects a candidate after comparison.
- **Expected output:** A versioned candidate with full data, schema, configuration,
  metric, environment, and artifact provenance, not an automatically active model.
- **Failure cases:** Leakage, group overlap, schema mismatch, invalid data,
  unavailable algorithm, failed evaluation, hash failure, or resource limit marks
  the job failed and does not publish a valid candidate.

## UC-14: Activate a validated model

- **Actor:** Authorized ML researcher or system operator.
- **Preconditions:** A registered model version has passed validation, schema and
  artifact integrity checks, and any required approval; current active version is known.
- **Normal flow:** The actor reviews comparison and limitations, explicitly
  requests activation, confirms the target version, and the system atomically
  changes registry status while retaining rollback provenance.
- **Alternative flow:** The actor activates a prior validated version as a
  controlled rollback or cancels before the state change.
- **Expected output:** Exactly one intended active version per model role and an audit event.
- **Failure cases:** Unvalidated status, incompatible schema, corrupt or missing
  artifact, concurrent activation, or load failure leaves the existing model active.

## UC-15: View evaluation results

- **Actor:** ML researcher, security analyst, project reviewer, or demonstrator.
- **Preconditions:** A completed evaluation run has stored metrics, definitions,
  plots/tables, split manifest, model versions, and provenance.
- **Normal flow:** The actor selects a run and reviews classification, anomaly,
  fusion, operational, correlation, and hunting metrics; confidence intervals;
  confusion matrix and ROC/PR views; known-versus-unseen experiments; latency,
  memory, and size; and documented limitations.
- **Alternative flow:** The actor compares compatible runs or downloads
  machine-readable measured results with their provenance.
- **Expected output:** Traceable results clearly labeled by split, threshold,
  averaging, positive class, versions, hardware, and evaluation time.
- **Failure cases:** Incomplete run, incompatible comparison, missing manifest,
  stale artifact, undefined metric, or failed plot generation displays a clear
  unavailable/partial state and never substitutes a hard-coded number.

## UC-16: Run the sample demonstration

- **Actor:** System operator, demonstrator, or project reviewer.
- **Preconditions:** The documented environment is installed; sample telemetry
  and validated demo model bundles exist; no live capture or external network is required.
- **Normal flow:** The actor starts local services; selects and replays sample
  PCAP; observes flows and features; reviews supervised, anomaly, and fusion
  results; inspects alerts and correlation; reviews a hypothesis; creates a case;
  adds a note and verdict; and views evaluation and health information.
- **Alternative flow:** A scripted CLI path runs the same bounded pipeline, or
  an empty-state demonstration is used in an earlier phase and clearly identified.
- **Expected output:** A reproducible end-to-end evidence chain from sample PCAP
  to frontend visualization, with all generated behavior labeled synthetic or sample.
- **Failure cases:** Missing sample, service failure, incompatible model bundle,
  corrupt PCAP, port conflict, or resource limit produces actionable diagnostics,
  no real attack traffic, and no claim of a successful complete demo.
