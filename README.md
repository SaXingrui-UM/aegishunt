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

Phases 0–7 are closed and their annotated checkpoints remain immutable. Phase 7
is complete: implementation PR
[#21](https://github.com/SaXingrui-UM/aegishunt/pull/21) and post-merge metadata
PR [#22](https://github.com/SaXingrui-UM/aegishunt/pull/22) are merged, and
annotated Tag `phase-07-complete` records the merged implementation checkpoint.
The phase adds bounded score contracts, validation-only weight/threshold
selection, explicit single-engine baselines, known and
Leave-One-Attack-Family-Out comparisons, a strict controlled timeline, four
preregistered parameter shifts, 1,000-draw group-bootstrap intervals, and a
checksummed JSON-only policy. Phase 8 is **Not started**.

The Phase 7 run uses 144 newly identified controlled synthetic rows in 72 groups
and does not reuse Phase 5/6 frozen-test evidence. It selected supervised/anomaly
weights `0.75/0.25` and threshold `0.7`, but the recommendation is
**inconclusive**: fusion matched supervised-only on known controlled groups and
was not shown to be superior. Its family-macro LOAO Recall was lower than
anomaly-only, and it missed held-out exfiltration and reconnaissance rows.
These negative results are retained. This is **pipeline verification only**,
not a public benchmark, production validation, real-world performance claim,
or proof of zero-day detection. Fusion score is not probability, risk,
severity, or attack confirmation. Phase 8 detection results, alerts,
explanations, correlation, hypotheses, replay orchestration, and cases are
**not implemented**.

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
aegishunt api
aegishunt frontend
```

`doctor` checks Python compatibility, the operating system, required local
directories, configuration loading, and configured database availability. It
returns a non-zero exit code with fixed, sanitized diagnostics when configuration
or database checks fail; it does not print the database URL, credentials, project
path, or traceback. `init-db` validates configuration and idempotently initializes
the configured database without printing its URL. `ingest pcap` validates,
decodes supported packets, and persists deterministic flows; it does not replay
traffic, capture an interface, open an external connection, or require root.

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
timeout, and schema version `1`. Database files and WAL sidecars are ignored by Git.

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

The Phase 7 page reports the implemented experiment boundary and planned modules
only. It does not display invented metrics, flows, alerts, explanations,
hypotheses, or model results.

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
