# System Requirements

## Requirement sources and interpretation

This document converts the two source PDFs into implementation and acceptance
requirements. `AegisHunt Project Plan.pdf` controls system goals, technical and
safety boundaries, research design, and final delivery. `AegisHunt
Implementation Roadmap.pdf` controls phase order and the scope allowed in each
phase. A requirement is not implemented merely because it is documented here;
implementation claims require code and tests.

Normative terms use **must** for required behavior, **should** for a justified
default, and **may** for an optional extension. Phase 0 establishes the
foundation only.

## Project vision

AegisHunt will be a runnable, testable, reproducible, and demonstrable defensive
research prototype for autonomous threat hunting. It will observe security
telemetry, extract behavioral evidence, detect known and anomalous behavior,
correlate alerts, generate structured investigation hypotheses, support case
management and analyst feedback, and evaluate controlled model retraining.

The system must communicate uncertainty. A detection or hypothesis is a
decision-support artifact, not confirmation that an attack occurred.

## Project scope

The final system scope includes:

1. Offline ingestion of PCAP, flow CSV, and structured JSON security events.
2. Stable PCAP replay as the primary demonstration path; live capture is optional.
3. Deterministic bidirectional flow aggregation and payload-independent behavioral features.
4. Supervised classification for behavior represented by labeled training data.
5. Benign-baseline anomaly detection for behavior outside learned norms.
6. Configurable fusion of model, correlation, and contextual signals.
7. Explainable security alerts and entity/time-based alert correlation.
8. Deterministic, evidence-based threat hypotheses with benign alternatives.
9. Investigation cases, analyst verdicts, notes, and feedback export.
10. Versioned training, validation, evaluation, activation, and artifact provenance.
11. FastAPI, Streamlit, Typer, local Python, and containerized demonstration paths.

## Primary users

- **Security analyst:** reviews flows, detections, alerts, hypotheses, evidence,
  explanations, and cases; records verdicts and notes.
- **Threat hunter:** explores related entities and activity, validates hypotheses,
  and determines next investigation steps.
- **ML researcher:** builds leakage-resistant datasets, trains candidates,
  evaluates known and unseen behavior, and compares model versions.
- **System operator or demonstrator:** imports or replays sample telemetry,
  monitors jobs and health, and runs the end-to-end demonstration.
- **Project reviewer:** verifies architecture, methodology, safety, metrics,
  reproducibility, limitations, tests, and final deliverables.

## Functional requirements

### Telemetry and flow processing

- **FR-001:** The system must accept PCAP files, flow CSV files, and structured
  JSON security events through controlled ingestion interfaces.
- **FR-002:** The system must provide deterministic PCAP replay that requires no
  live target, public network, root privilege, or administrator privilege.
- **FR-003:** Each ingestion job must expose status, progress, errors, record
  count, source checksum, and safe source metadata.
- **FR-004:** File ingestion must enforce type and size policy, sanitize names,
  prevent arbitrary path reads, and fail safely on malformed input.
- **FR-005:** Packet processing must create canonical bidirectional flows for
  supported IPv4, IPv6, TCP, UDP, and ICMP traffic with explicit direction and
  timeout semantics.
- **FR-006:** Feature extraction must be deterministic, documented, versioned,
  ordered consistently between training and inference, and free of NaN and
  infinity values.
- **FR-007:** Raw IP addresses and ports may support investigation and
  correlation but must not be default supervised-model features.

### Detection, fusion, and explanations

- **FR-008:** The supervised engine must provide baselines and candidate models;
  the selected model must be determined by measured validation evidence rather
  than a hard-coded algorithm choice.
- **FR-009:** The anomaly engine must use Isolation Forest as the primary
  candidate and a benign-only training strategy; offline comparison models are
  optional and resource-dependent.
- **FR-010:** Fusion must combine separately versioned supervised probability,
  normalized anomaly score, correlation score, and optional contextual risk
  using configuration-controlled weights and thresholds.
- **FR-011:** A combined risk score must not be described as the probability that
  an attack occurred.
- **FR-012:** Each alert must retain source detections, involved entities,
  reason codes, observed evidence, local explanation, severity, status, model
  versions, and creation time.
- **FR-013:** Explanations must distinguish observed facts, model inference,
  assumptions, alternative explanations, and validation steps; feature
  importance must not be represented as causality.

### Correlation and threat hunting

- **FR-014:** Alert correlation must be deterministic, configurable, testable,
  explainable, bounded by time windows, and based on declared entity keys.
- **FR-015:** Correlation must support source-centered, destination-centered,
  source-destination, multi-entity, concurrent-signal, and low-severity
  accumulation patterns.
- **FR-016:** The hypothesis engine must use deterministic templates and
  structured evidence and must operate without an LLM or API key.
- **FR-017:** Each hypothesis must contain an ID, title, description, confidence,
  severity, involved entities, supporting alerts and features, time window,
  possible attack category, possible MITRE ATT&CK mapping, assumptions,
  alternative explanations, recommended queries and investigation steps, and status.
- **FR-018:** A hypothesis must never be automatically marked `confirmed`, and a
  possible MITRE mapping must not be represented as verified attribution.

### Cases, feedback, and model control

- **FR-019:** Analysts must be able to create an investigation case from a
  hypothesis and manage priority, status, assignment, evidence references,
  notes, related objects, verdict, and timestamps.
- **FR-020:** Feedback verdicts must include `true_positive`, `false_positive`,
  `benign_expected`, and `needs_more_information`, with confidence, notes,
  object reference, and audit time.
- **FR-021:** Feedback must be queryable and exportable as a candidate future
  retraining dataset without triggering automatic online learning.
- **FR-022:** Training must be an explicit user action that creates a new,
  immutable model version and complete provenance bundle.
- **FR-023:** Activating a model must be a separate explicit action limited to a
  validated model whose feature schema and artifact integrity are verified.
- **FR-024:** The system must never deserialize an arbitrary user-submitted
  pickle; model loading must be constrained to the controlled registry.

### Interfaces and operations

- **FR-025:** The final API must provide the health, system, ingestion, flow,
  alert, alert-group, hypothesis, case, model, and evaluation resources listed
  in the Project Plan, with Pydantic validation, pagination, OpenAPI, and
  structured error handling.
- **FR-026:** The CLI must provide help, validation, clear logging, non-zero
  failure codes, configuration support, and non-hard-coded paths and results.
- **FR-027:** The frontend must provide explicit empty, loading, progress,
  success, and error states and must not invent data when no records exist.
- **FR-028:** The sample demonstration must complete without live capture,
  public-network access, a fixed target, root privileges, or real attack activity.

## Non-functional requirements

The detailed, testable quality requirements are in
[`non_functional_requirements.md`](non_functional_requirements.md). The system
must be reliable, maintainable, testable, usable, secure, measurable for
performance, reproducible, portable, observable, and protective of data and
model integrity. Performance values must be reported only from executed,
documented experiments; targets may be declared in advance but never presented
as achieved results without evidence.

## Research requirements

- **RR-001:** Document selection criteria, license, provenance, fields, mapping,
  and limitations for the public benchmark dataset.
- **RR-002:** Provide a controlled, reproducible demonstration dataset whose
  simulated behaviors are safe and clearly distinguished from real observations.
- **RR-003:** Prevent leakage using capture/session/scenario/source-file groups
  or time ordering rather than naive random splits of related flows.
- **RR-004:** Detect and report exact duplicates, near duplicates, group overlap,
  label leakage, source leakage, family leakage, timestamp leakage, and features
  that encode labels.
- **RR-005:** Freeze models and thresholds before the one-time final test-set evaluation.
- **RR-006:** Simulate unseen behavior through leave-one-attack-family-out,
  temporal holdout, and controlled parameter-shift experiments.
- **RR-007:** Never claim guaranteed zero-day detection; report the defined
  experiment and its limits.
- **RR-008:** Use fixed seeds and calculate 95% bootstrap confidence intervals
  with at least 1,000 resamples for primary metrics.
- **RR-009:** Compare predictive quality, latency, size, explainability, and
  split stability when selecting a primary model.
- **RR-010:** Preserve raw observations, transformations, configuration,
  manifests, and hashes needed to audit every reported result.

## Machine-learning evaluation requirements

All metrics are computed artifacts, never constants embedded in application
code. Multi-class and binary averaging, positive-class definitions, thresholds,
data split, and confidence-interval method must accompany each result.

### Classification metrics

- Accuracy
- Precision
- Recall
- F1-score
- Macro F1
- Weighted F1
- Balanced Accuracy
- Matthews Correlation Coefficient (MCC)
- ROC-AUC
- PR-AUC
- Specificity
- False Positive Rate
- False Negative Rate
- Confusion Matrix

### Anomaly-detection metrics

- Anomaly precision, recall, and F1
- PR-AUC
- Normal and anomalous score distributions
- Threshold sensitivity
- False-positive rate on benign data
- Detection performance on held-out families, temporal holdout, and parameter shift

### Fusion-engine metrics

- Supervised-only, anomaly-only, and fusion metric comparison on the same split
- Known-attack and unseen-family recall
- Precision, F1, PR-AUC, False Positive Rate, and False Negative Rate
- Recall change and false-positive change relative to each component engine
- Fusion-weight and threshold sensitivity
- 95% bootstrap confidence intervals for primary comparisons

### Operational metrics

- PCAP parsing and feature-extraction throughput
- Supervised, anomaly, fusion, and end-to-end flow-to-alert latency
- p50, p95, and p99 latency
- Peak memory, CPU usage, and model artifact size

### Alert-correlation metrics

- Alerts entering and leaving correlation
- Correlated groups generated and alerts per group
- Multi-entity and multi-signal group rate
- False-positive reduction after correlation
- Group precision where ground truth is available
- Correlation latency and sensitivity to window, minimum-alert, decay, and threshold settings

### Threat-hunting metrics

- Alerts per 1,000 flows
- Hypotheses generated and alerts per hypothesis
- Hypotheses containing multiple evidence sources
- Hypothesis precision where ground truth is available
- Case conversion rate
- False-positive reduction after correlation

## Frontend demonstration requirements

The final Streamlit application must provide:

1. **Overview:** flow, alert, hypothesis, case, model, latency, ingestion, and activity status.
2. **Data Ingestion:** safe PCAP/CSV upload, sample selection, replay, progress, records, and errors.
3. **Traffic Explorer:** filters, flow table and detail, distributions, and entity relationships.
4. **Alerts:** severity, engines, combined risk, reasons, explanations, entities, related alerts, and verdict.
5. **Threat Hunts:** hypothesis evidence, confidence, assumptions, alternatives, mappings, steps, and case creation.
6. **Cases:** list, detail, notes, evidence, status, verdict, and report export.
7. **Model Lab:** active versions, schema, controlled training/activation, comparison, and global explanations.
8. **Evaluation:** confusion matrix, ROC/PR curves, known/unseen and fusion comparisons, latency, size, and robustness.
9. **System Health:** API, storage, worker, resources, queue, errors, and model loading state.

The sample mode must demonstrate the complete planned lifecycle without live
capture or external data. Until those phases are implemented, the frontend must
show truthful foundation or empty-state content only.

## Security and safety boundaries

AegisHunt is defensive and observational. It must not implement or perform:

- unauthorized scanning or vulnerability exploitation;
- credential attacks against real systems, malware, or persistence;
- destructive response, unrestricted flooding, or attack automation;
- firewall modification, account disabling, or arbitrary command execution;
- automatic attack confirmation, autonomous blocking, or unreviewed model replacement.

Safe demonstrations are limited to PCAP replay, synthetic flow generation,
container-contained benign services, rate-limited behavioral simulation, and
dry-run response recommendations. Recommendations are recorded for human review
and are not executed by default.

## Reproducibility requirements

Every experiment must record the Git commit, Python and dependency versions,
operating system, dataset identity/version/checksum, feature schema version,
split manifest, model configuration, random seeds, threshold, model artifact
hash, and evaluation timestamp. A model bundle must contain controlled model and
preprocessing artifacts, schemas, thresholds, fusion and training configuration,
metrics, model card, dataset manifest, and artifact hashes. Generated binaries
and datasets are not committed to Git.

## Definition of Done

The final project is done only when all of the following are evidenced by code,
tests, documentation, and a reproducible demonstration:

- Sample PCAP replay runs without a fixed target or elevated privilege.
- PCAP data becomes deterministic bidirectional flows and versioned valid features.
- Supervised and anomaly models train and infer together under schema control.
- Fusion is configurable and produces explainable alerts without probability misrepresentation.
- Alerts correlate into evidence-backed groups and structured hypotheses.
- Hypotheses can become cases; notes, verdicts, and analyst feedback persist.
- Models and experiments are versioned, leakage-resistant, reproducible, and measured honestly.
- The complete API and frontend demonstrate the lifecycle on sample data.
- Automated tests, linting, typing, local or Docker startup, and user documentation pass acceptance.
- The system remains explicitly labeled a research prototype, not a production security product.

Phase completion is narrower: each roadmap phase must meet its own acceptance
criteria, pass required checks, be reviewed against `main`, and reach a PR
checkpoint before the next phase begins.

## Out-of-scope items

- Production SOC scale, high availability, multi-tenancy, and regulated-data certification.
- Mandatory microservices, Kafka, Redis, Celery, or distributed stream processing.
- Guaranteed zero-day detection or automated attribution.
- Payload inspection as a prerequisite for core behavioral features.
- Mandatory live packet capture or operation requiring root privileges.
- Offensive security activity, real attack execution, and autonomous response.
- LLM-dependent core detection or unrestricted generated hunt decisions.
- Automatic online learning or automatic activation of a newly trained model.
- Implementing a later roadmap phase before the current phase is accepted.
