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

Phases 0–12 are complete and their annotated checkpoints remain immutable.
Phase 12 PR [#35](https://github.com/SaXingrui-UM/aegishunt/pull/35) is merged as
`baac8e5ecf9f8a2ac66afe2873269bebcbbcbf17`; annotated
`phase-12-complete` peels to that canonical merge commit. Phase 13 is **Not
started** and branch `phase/13-hardening` has not been created. Validation PR
[#37](https://github.com/SaXingrui-UM/aegishunt/pull/37) is merged. The
subsequent Phase 12 demo-readiness corrective keeps global model pointers
separate from immutable runtime-job effective models, exposes the effective
Fusion Policy, reports typed Phase 7 artifact availability, adds measured
Demo-run observations and Case Audit History, and adds a separate controlled
IPv4/IPv6/ICMP presentation sample. See
[`docs/phase-12-demo-readiness-corrective-validation.md`](docs/phase-12-demo-readiness-corrective-validation.md).
Phase 11
provides offline, rootless PCAP replay on a single
SQLite node with durable jobs, leases, explicit recovery, verified artifact
pinning, transactional output ledgers, separate non-durable observed replay
telemetry and durable committed evidence progress, and bounded worker/resource
observations. It does not enable live capture or automatic recovery.

The Phase 9 checkpoint remains immutable. Its implementation adds a checksummed
correlation policy, bounded event-time entity indexing, deterministic alert
groups, evidence-backed proposed hunting hypotheses, audited analyst status
transitions, and an additive schema v2→v3 migration. The lifecycle correction
keeps observed event time separate from injectable-clock creation/update time;
stable IDs remain independent of wall-clock time and idempotent reruns preserve
the first persisted `created_at`.

The Phase 7 run uses 144 newly identified controlled synthetic rows in 72 groups
and does not reuse Phase 5/6 frozen-test evidence. It selected supervised/anomaly
weights `0.75/0.25` and threshold `0.7`, but the recommendation is
**inconclusive**: fusion matched supervised-only on known controlled groups and
was not shown to be superior. Its family-macro LOAO Recall was lower than
anomaly-only, and it missed held-out exfiltration and reconnaissance rows.
These Phase 7 negative results are retained. This is **pipeline verification only**,
not a public benchmark, production validation, real-world performance claim,
or proof of zero-day detection. Phase 8 maps the recorded fusion score to an
operational suspiciousness risk by explicit identity policy; this does not imply
fusion superiority and is not attack probability. An alert is a prompt for
analyst review, not attack confirmation. Phase 9 adds bounded event-time correlation,
stable alert groups, and deterministic proposed hunting hypotheses with explicit
facts, inferences, assumptions, benign alternatives, possible ATT&CK mappings, and
investigation-query suggestions that are never executed by the core. Correlation/confidence scores are not
attack probabilities, hypotheses are not facts, and no hypothesis is automatically
confirmed. Phase 10 reuses the existing Case and Feedback entities for deterministic
hypothesis-to-case creation, audited lifecycle/notes/evidence/verdict workflows,
checksummed feedback/report exports, and explicit review-only retraining candidates.
A Case remains a review work item, priority is triage rather than certainty, and
analyst feedback may be noisy. Case verdicts are not propagated to every related
Flow; candidate artifacts use status `retraining_candidate`, and
evaluation/test/holdout or unknown provenance is excluded. No operation trains,
activates, or replaces a model. Phase 11 reuses the existing verified models and
policies; it does not train, select, activate, or replace them.

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
aegishunt dataset --help
aegishunt dataset list
aegishunt dataset describe cse-cic-ids2018
aegishunt dataset build-demo
aegishunt dataset validate data/processed/datasets/aegishunt-controlled-demo/1.0.0/canonical.jsonl
aegishunt model --help
aegishunt model train --data-dir <data> --dataset-report-dir <reports> --allow-controlled-demo
aegishunt model test --data-dir <data> --dataset-report-dir <reports> --allow-controlled-demo
aegishunt model list
aegishunt model verify 1.0.1
aegishunt anomaly --help
aegishunt anomaly train --data-dir <data> --dataset-report-dir <reports> --allow-controlled-demo
aegishunt anomaly test --data-dir <data> --dataset-report-dir <reports> --allow-controlled-demo
aegishunt anomaly list
aegishunt anomaly verify 1.0.0
aegishunt fusion --help
aegishunt fusion evaluate --fusion-config <fusion-yaml> --supervised-config <supervised-yaml> --anomaly-config <anomaly-yaml> --label-mapping <label-yaml> --experiment-root <new-root> --policy-root <new-root> --allow-controlled-demo
aegishunt fusion verify 1.0.0 --policy-root <policy-root>
aegishunt fusion describe 1.0.0 --policy-root <policy-root>
aegishunt fusion score 1.0.0 --input <score-input.json> --policy-root <policy-root>
aegishunt detection --help
aegishunt detection evaluate --help
aegishunt detection list
aegishunt detection describe <detection-id>
aegishunt alerts list
aegishunt alerts describe <alert-id>
aegishunt alerts verdict <alert-id> false_positive --actor <analyst-id>
aegishunt explainability verify <artifact-directory>
aegishunt explainability describe <artifact-directory>
aegishunt hunt config verify
aegishunt hunt correlate
aegishunt hunt alert-groups list
aegishunt hunt alert-groups describe <group-id>
aegishunt hunt generate-hypotheses
aegishunt hunt hypotheses list
aegishunt hunt hypotheses describe <hypothesis-id>
aegishunt hunt hypotheses update-status <hypothesis-id> under_review --actor <analyst-id>
aegishunt cases --help
aegishunt cases create-from-hypothesis <hypothesis-id> --actor <analyst-id>
aegishunt cases list
aegishunt cases describe <case-id>
aegishunt cases add-note <case-id> --body <text> --actor <analyst-id>
aegishunt cases set-verdict <case-id> true_positive --confidence 0.8 --reason <text> --actor <analyst-id>
aegishunt cases close <case-id> --closure-note <text> --actor <analyst-id> --confirm
aegishunt cases report <case-id> --version <new-version> --actor <analyst-id> --confirm
aegishunt feedback --help
aegishunt feedback record-alert <alert-id> false_positive --confidence 0.8 --notes <text> --actor <analyst-id>
aegishunt feedback list
aegishunt feedback export --version <new-version> --actor <analyst-id>
aegishunt feedback build-retraining-candidates --version <new-version> --actor <analyst-id> --confirm
aegishunt runtime config verify
aegishunt runtime replay create <telemetry-source-id>
aegishunt runtime jobs list
aegishunt runtime jobs describe <runtime-job-id>
aegishunt runtime worker run --once
aegishunt runtime workers list
aegishunt runtime status
aegishunt demo --help
aegishunt demo run --sample-id phase12-demo-pcap --actor analyst --reason "controlled demonstration" --confirm
aegishunt demo run --sample-id phase12-presentation-demo-pcap --actor analyst --reason "controlled presentation demonstration" --confirm
aegishunt api
aegishunt frontend
```

`doctor` checks Python compatibility, the operating system, required local
directories, configuration loading, and configured database availability. It
returns a non-zero exit code with fixed, sanitized diagnostics when configuration
or database checks fail; it does not print the database URL, credentials, project
path, or traceback. `init-db` validates configuration and idempotently initializes
the configured database without printing its URL. `ingest pcap` validates,
decodes supported packets, and persists deterministic flows; it does not capture
an interface, open an external connection, or require root.

`runtime replay create` accepts only a completed persisted PCAP source ID. It
pins source and verified artifact identities before durable queue creation.
Workers repeat that preflight before the first packet, replay event-time gaps
with configured speed/caps, and persist each output batch transactionally.
Pause/resume uses the live worker; interruption becomes `recovery_pending`, and
only an explicit operator recovery restarts deterministic replay from packet
zero. Observed packet progress is non-durable live telemetry, is not a
checkpoint, and resets for the new attempt. Durable progress represents
committed evidence and reaches 100% only after EOF flush and final downstream
completion. Open-flow state remains in memory. This is not exact packet-cursor
resume or a distributed exactly-once guarantee. See
[`docs/runtime_pipeline.md`](docs/runtime_pipeline.md),
[`docs/pcap_replay.md`](docs/pcap_replay.md), and
[`docs/runtime_recovery.md`](docs/runtime_recovery.md).

`dataset build-demo` runs entirely offline and creates ignored processed data and
machine reports under configured roots. The demo is controlled synthetic data,
not a benchmark or real enterprise capture. `dataset download` never accepts a
license for the operator and the selected CSE-CIC-IDS2018 benchmark remains a
manual, checksum-recorded workflow. See
[`docs/dataset_selection.md`](docs/dataset_selection.md) and
[`docs/dataset_schema.md`](docs/dataset_schema.md).

## Supervised model workflow

The model workflow does not automatically read the test split. `model train`
uses train/group-CV and validation evidence, then writes an immutable selection
record with `test_data_accessed: false`. The separate `model test` command
performs the one permitted frozen evaluation and refuses a repeat. Controlled
demo use requires the explicit flag shown above.

Bundles include preprocessing, estimator, calibration, threshold, fixed feature
order/schema, provenance checksums, metrics, and environment metadata. Loading
is restricted to the configured model root and verifies SHA-256 plus an exact
skops type inventory; arbitrary pickle/joblib is rejected. Prediction returns
only supervised label/score/probability metadata and does not create alerts or
risk. See [`docs/supervised_experiment_protocol.md`](docs/supervised_experiment_protocol.md)
and [`docs/model_card.md`](docs/model_card.md).

## Anomaly model workflow

`anomaly train` validates the same Phase 4 evidence, excludes malicious training
rows from every fit, compares configured Isolation Forest candidates, and runs
LOF in novelty mode. Legacy policy `1.0.0` keeps LOF offline-only. The separately
registered ADR 0015 policy `2.0.0` permits fixed LOF as a validation-qualified
candidate and still forbids test access. `anomaly test` performs the legacy
one-time frozen evaluation and refuses a repeat; validation-qualified corrective
candidates require a new independent holdout and cannot reuse that command.

Anomaly bundles persist the exact StandardScaler/estimator pipeline, raw score
direction, canonical transform, normalizer, threshold, fixed feature schema,
provenance, metrics, and environment. Prediction returns raw, canonical, and
normalized anomaly scores plus `is_anomaly`; it creates no alert or combined risk.
See [`docs/anomaly_experiment_protocol.md`](docs/anomaly_experiment_protocol.md),
[`docs/anomaly_lof_candidate_protocol.md`](docs/anomaly_lof_candidate_protocol.md),
[`docs/anomaly_model_card.md`](docs/anomaly_model_card.md),
[`docs/adr/0014-validation-frozen-benign-anomaly-engine.md`](docs/adr/0014-validation-frozen-benign-anomaly-engine.md),
and [`docs/adr/0015-lof-validation-qualified-production-candidate.md`](docs/adr/0015-lof-validation-qualified-production-candidate.md).

## Fusion experiment workflow

`fusion evaluate` creates a new exclusive experiment and policy version; it
never overwrites Phase 5/6 artifacts or silently falls back to one engine. The
fixed Phase 5 Random Forest/isotonic and Phase 6 novelty-mode LOF configurations
are refitted only within isolated Phase 7 early/middle groups. Late, held-out
family, temporal, and shifted groups do not select weights or thresholds.

The policy contains no model binary. Its exact JSON/Markdown inventory and
SHA-256 checksums are verified before describe or score. Missing, extra,
corrupt, escaped, mismatched, or colliding artifacts fail closed. See
[`docs/fusion_experiment_protocol.md`](docs/fusion_experiment_protocol.md),
[`docs/fusion_policy_card.md`](docs/fusion_policy_card.md), and
[`docs/adr/0016-validation-selected-dual-engine-fusion.md`](docs/adr/0016-validation-selected-dual-engine-fusion.md).

## Detection, alert, and explanation workflow

The Phase 8 risk policy uses an explicit identity mapping from the verified
Phase 7 `fusion_score` by default. It records all required model and policy
versions/checksums, keeps the Phase 7 recommendation `inconclusive`, and has no
hidden weights or score fallback. Risk is operational suspiciousness for triage,
not attack probability; severity is configured priority, not certainty.

Every completed score creates a `DetectionResult`. Only a result at or above the
configured threshold creates a `SecurityAlert`. Alert evidence contains stable
reason codes, observed flow facts, configured/reference boundaries, model
inferences, and top single-feature reference-replacement sensitivities. Global
native/permutation importance and local contributions are non-causal. Verdicts
change only the alert verdict/timestamp and append an audit event; they do not
train models, create cases, or create hypotheses. See
[`docs/detection_alerts.md`](docs/detection_alerts.md) and
[`docs/explainability.md`](docs/explainability.md).

## Investigation cases and analyst feedback

`cases create-from-hypothesis` creates one deterministic primary Case per eligible
reviewable hypothesis. It snapshots the hypothesis, source alert group, and supporting
alerts as typed SHA-256 references without mutating any source evidence. Status,
triage priority, assignment, append-only notes, evidence additions, verdict, and close
operations require explicit actors and are audited. Closure requires a final analyst
verdict and closure note. Arbitrary files, paths, URLs, and evidence downloads are not
accepted.

Alert feedback is transactionally consistent with the existing alert verdict. Feedback
is human-supplied and potentially noisy—not ground truth. Data-only feedback exports,
case reports, and retraining-candidate artifacts are versioned, exact-inventory,
checksummed, non-overwriting, and restricted to configured roots. Candidates use only
uniquely mapped alert→detection→flow evidence with fixed Phase 3 feature order and
explicit non-evaluation provenance. Conflicts are excluded; consistent duplicates are
deduplicated; Case verdicts never label all member Flows. Candidate status is
`retraining_candidate` and requires manual review plus a new group-aware quality/split
workflow. See [`docs/investigation_cases.md`](docs/investigation_cases.md),
[`docs/analyst_feedback.md`](docs/analyst_feedback.md), and
[`docs/retraining_candidates.md`](docs/retraining_candidates.md).

## Telemetry ingestion

The ingestion API exposes `/ingestion/pcap`, `/ingestion/flow-csv`,
`/ingestion/json-events`, `/ingestion/jobs`, and `/ingestion/samples`. Uploads
are streamed through configured byte and record limits, stored under a
SHA-256-derived filename, and represented by durable status/error records.
Reviewed samples are declared in `data/sample/manifest.yaml` and verified before
use. PCAP job metadata records flow count and feature schema version. See
[`docs/ingestion.md`](docs/ingestion.md) and
[`docs/feature_dictionary.md`](docs/feature_dictionary.md).

## Configuration and database initialization

Version-controlled defaults live in `configs/application.yaml`. Environment
variables override YAML values with `AEGISHUNT_` and a double underscore for
nested keys:

```bash
export AEGISHUNT_DATABASE__URL="sqlite:///data/aegishunt.db"
aegishunt init-db --config configs/application.yaml
```

The default SQLite database uses WAL, foreign-key enforcement, a bounded busy
timeout, and schema version `5`. Ordered additive v1→v2→v3→v4→v5 migrations preserve
existing rows and record new schema-version events. Database files and WAL sidecars are
ignored by Git.

Flow segmentation is configuration-controlled. Defaults are 60-second idle and
300-second active timeouts, with explicit per-flow packet, active-flow, and
captured-packet byte bounds under the `flows` YAML section. Environment overrides
use names such as `AEGISHUNT_FLOWS__IDLE_TIMEOUT_SECONDS`.

Dataset registry, label mapping, raw/interim/processed/report roots, download and
archive limits, near-duplicate tolerance, demo seed, and split ratios are under
the `datasets` YAML section. Raw and generated dataset files remain Git-ignored.

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

The Phase 12 Streamlit application exposes nine API-backed pages: Overview,
Data Ingestion, Traffic Explorer, Alerts, Threat Hunts, Cases, Model Lab,
Evaluation, and System Health. It uses a typed HTTP client and never opens the
database, repository, or model files directly. Empty and unavailable values are
shown explicitly rather than replaced with fabricated zeros. Mutations require
an explicit form, actor/reason attribution, and confirmation where applicable.

With the API running, the packaged `phase12-demo-pcap` asset can be launched
explicitly from Data Ingestion or the CLI. It uses isolated, checksummed
demo-only artifacts, existing production services, no external network, no
root privileges, and no live capture. Its synthetic results verify the local
pipeline only; they are not a public benchmark, production validation, or an
attack-probability claim. See
[`docs/api_frontend.md`](docs/api_frontend.md).

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
| 11 | Durable offline runtime replay, workers, recovery, and resource status |
| 12 | Complete API, Streamlit, and controlled demonstration workflows |
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
