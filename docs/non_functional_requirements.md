# Non-Functional Requirements

These requirements define quality attributes and verification methods. Numeric
performance values are experimental targets or measurements only; this document
does not claim any unexecuted result.

## Reliability

- **NFR-REL-01:** Malformed or unsupported input must produce a bounded,
  diagnosable failure without crashing unrelated jobs or corrupting stored state.
- **NFR-REL-02:** Reprocessing the same input with the same configuration and
  versions must produce equivalent deterministic flow and feature outputs.
- **NFR-REL-03:** Background work must expose lifecycle state and support graceful
  shutdown; interrupted durable work must remain internally consistent.
- **NFR-REL-04:** Optional facilities, including live capture and any LLM summary,
  must fail independently without disabling PCAP replay or core hunting behavior.
- **Verification:** fault-injection, repeatability, shutdown, and degraded-mode tests.

## Maintainability

- **NFR-MNT-01:** Use a modular monolith with explicit module boundaries and no
  circular dependency on frontend or infrastructure code from domain modules.
- **NFR-MNT-02:** Keep configuration, thresholds, schemas, and mappings versioned
  and separate from orchestration logic.
- **NFR-MNT-03:** Use clear type annotations, small focused modules, ADRs for
  consequential changes, and Conventional Commits.
- **NFR-MNT-04:** Never hide exceptions with empty or catch-all suppression.
- **Verification:** `ruff`, `mypy`, architecture review, and change review.

## Testability

- **NFR-TST-01:** Deterministic computation, I/O adapters, storage, API, and UI
  clients must have separable interfaces that permit fixture-based tests.
- **NFR-TST-02:** Unit, integration, and end-to-end tests must run without public
  network access, root privilege, a real target, or real attack activity.
- **NFR-TST-03:** The final core-module line coverage target is at least 80%; each
  phase must add tests appropriate to its delivered behavior.
- **NFR-TST-04:** Failing tests may not be deleted or bypassed to satisfy CI.
- **Verification:** `pytest`, coverage reports, CI, and test review.

## Usability

- **NFR-USA-01:** CLI commands must provide help, validated options, clear output,
  and non-zero exit status for failures.
- **NFR-USA-02:** API errors must be structured and actionable; collection
  endpoints must support pagination once introduced.
- **NFR-USA-03:** The frontend must distinguish empty, loading, running, failed,
  and completed states and must never substitute invented results.
- **NFR-USA-04:** Risk, anomaly, hypothesis, and mapping labels must explain their
  uncertainty and offer evidence and benign alternatives.
- **Verification:** command tests, API schema tests, UI smoke tests, and manual demo review.

## Security

- **NFR-SEC-01:** Validate file type, declared and actual size, name, destination,
  and checksum before processing uploaded telemetry.
- **NFR-SEC-02:** Prevent path traversal, arbitrary filesystem reads, arbitrary
  command execution, and uncontrolled model deserialization.
- **NFR-SEC-03:** Secrets belong in environment-specific secret storage and may
  not be committed; `.env.example` contains names and non-secret defaults only.
- **NFR-SEC-04:** Basic tests and demonstrations must not require secrets or
  public-network access.
- **NFR-SEC-05:** No automated destructive or access-control response is permitted.
- **Verification:** adversarial input tests, secret scan, dependency review,
  permissions review, and source review.

## Performance

- **NFR-PERF-01:** Measure PCAP parsing, feature extraction, supervised inference,
  anomaly inference, fusion, and end-to-end flow-to-alert performance.
- **NFR-PERF-02:** Report throughput, p50/p95/p99 latency, peak memory, CPU usage,
  and model size with workload, hardware, versions, and method.
- **NFR-PERF-03:** Establish acceptance targets only after a reproducible baseline;
  target values must be labeled as targets until an experiment demonstrates them.
- **NFR-PERF-04:** Performance optimization must not weaken validation, safety,
  leakage controls, or explanation provenance.
- **Verification:** versioned benchmark scripts and experiment reports in the declared phase.

## Reproducibility

- **NFR-REP-01:** Record code commit, runtime and dependency versions, OS,
  configuration, random seeds, dataset and artifact hashes, schema, split,
  thresholds, and timestamps.
- **NFR-REP-02:** Repeat runs with identical inputs must retain stable ordering and
  deterministic transformations; model nondeterminism must be seeded and documented.
- **NFR-REP-03:** Dataset, split, leakage, feature, training, and evaluation
  manifests must be machine-readable and human-reviewable.
- **NFR-REP-04:** Generated reports must link to provenance rather than embed
  unexplained copied numbers.
- **Verification:** clean-run reproduction and manifest/hash comparison.

## Portability

- **NFR-PORT-01:** Support Python 3.11 or newer on documented macOS and Linux environments.
- **NFR-PORT-02:** Support local Python operation; Docker and Docker Compose are
  final-delivery requirements, not Phase 0 deliverables.
- **NFR-PORT-03:** Offline replay and sample mode must not depend on a particular
  interface, target address, root privilege, shell, or absolute user path.
- **NFR-PORT-04:** SQLite is the default while storage boundaries preserve a
  future PostgreSQL migration path.
- **Verification:** clean installation and demo on documented platforms and container CI.

## Observability

- **NFR-OBS-01:** Use structured, severity-aware logs without secrets or raw
  sensitive payloads by default.
- **NFR-OBS-02:** Health and status surfaces must report API, storage, worker,
  queue, model-loading, resource, and latest-error state as those modules appear.
- **NFR-OBS-03:** Long-running jobs must expose IDs, timestamps, progress, counts,
  terminal status, and safe error details.
- **NFR-OBS-04:** Evaluation and operational metrics must include definitions and provenance.
- **Verification:** schema tests, log review, health tests, and failure-path integration tests.

## Data integrity

- **NFR-DATA-01:** Source files, derived datasets, manifests, and artifacts must
  retain checksums and immutable provenance references.
- **NFR-DATA-02:** Database transactions and WAL configuration must protect
  consistent state across interruption and expected concurrent access.
- **NFR-DATA-03:** Schema and feature order must be explicit and versioned; invalid
  numerical values or incompatible records must be rejected or safely normalized
  by documented rules.
- **NFR-DATA-04:** Dataset splits must prevent group overlap, duplicates, and
  known leakage paths; the test set remains sealed until final evaluation.
- **Verification:** checksum, transaction, schema, leakage, and split-manifest tests.

## Model integrity

- **NFR-MODEL-01:** A model version must be immutable and include algorithm,
  features, data provenance, configuration, metrics, thresholds, hashes, and status.
- **NFR-MODEL-02:** Training and activation are separate explicit user actions;
  neither analyst feedback nor retraining automatically replaces an active model.
- **NFR-MODEL-03:** Reject inference when feature schema, preprocessing,
  thresholds, model metadata, or artifact hash is incompatible.
- **NFR-MODEL-04:** Load artifacts only from the controlled registry and never
  deserialize a user upload as a model.
- **NFR-MODEL-05:** Do not hard-code model results, tune on the final test set, or
  overstate anomaly detection, importance, or MITRE mappings.
- **Verification:** registry, corruption, mismatch, activation, and evaluation-protocol tests.
