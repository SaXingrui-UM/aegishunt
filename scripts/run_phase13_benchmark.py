"""Run the controlled offline Phase 13 performance baseline."""

from __future__ import annotations

import argparse
import hashlib
import tempfile
import time
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from uuid import UUID

import yaml
from fastapi.testclient import TestClient
from sqlalchemy import func, inspect, select

from aegishunt.api.app import create_app
from aegishunt.api.contracts import DemoRequest
from aegishunt.api.demo_service import SampleDemoService
from aegishunt.cases.config import load_case_feedback_policy
from aegishunt.cases.reports import CaseReportService
from aegishunt.config import (
    ApplicationSettings,
    CaseFeedbackSettings,
    DatabaseSettings,
    IngestionSettings,
    WebSettings,
)
from aegishunt.demo import DemoArtifactManager
from aegishunt.explainability.artifacts import load_explanation_artifact
from aegishunt.flows.pcap_reader import PcapPacketReader
from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION
from aegishunt.flows.service import PcapFlowProcessor
from aegishunt.ml.anomaly.bundle import load_bundle as load_anomaly_bundle
from aegishunt.ml.anomaly.prediction import AnomalyPredictionBatch, score_batch
from aegishunt.ml.fusion.artifacts import (
    POLICY_MANIFEST_FILENAME,
    load_policy,
    sha256_file,
)
from aegishunt.ml.fusion.contracts import FusionScoreInput
from aegishunt.ml.fusion.scoring import fuse_score
from aegishunt.ml.supervised.bundle import load_bundle as load_supervised_bundle
from aegishunt.ml.supervised.prediction import PredictionBatch, predict_batch
from aegishunt.runtime.config import load_runtime_policy
from aegishunt.storage import Database
from aegishunt.storage.base import Base
from scripts.phase13_benchmark_support import (
    BENCHMARK_SCHEMA_VERSION,
    RSS_SAMPLING_INTERVAL_SECONDS,
    current_rss_bytes,
    directory_size,
    environment,
    measure,
    write_results,
)

API_READ_COMPONENTS = (
    "api_health",
    "api_system_status",
    "api_flows_page",
    "api_alerts_page",
    "api_runtime_status",
    "api_demo_status",
    "api_flow_detail",
)


def _settings(
    project_root: Path,
    runtime_root: Path,
    *,
    artifact_root: Path,
    database_name: str,
    case_policy_path: Path,
) -> ApplicationSettings:
    return ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{runtime_root / database_name}"),
        ingestion=IngestionSettings(
            storage_root=runtime_root / f"{database_name}-raw",
            sample_root=project_root / "data" / "sample",
        ),
        web=WebSettings(
            demo_sample_ids=("phase12-presentation-demo-pcap",),
            demo_artifact_root=artifact_root,
            demo_namespace="phase13-benchmark",
            demo_operation_version="1.0.0",
            demo_worker_id="phase13-benchmark-worker",
            web_worker_id_prefix="phase13-benchmark-web",
        ),
        case_feedback=CaseFeedbackSettings(policy_path=case_policy_path),
    )


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/hardening/phase-13/performance-v1.1"),
    )
    parser.add_argument("--micro-warmups", type=int, default=5)
    parser.add_argument("--micro-repetitions", type=int, default=100)
    parser.add_argument("--full-pipeline-repetitions", type=int, default=10)
    parser.add_argument("--smoke", action="store_true")
    return parser.parse_args()


def _table_counts(database: Database) -> dict[str, int]:
    """Count ORM-managed rows without constructing SQL identifiers from strings."""

    table_names = tuple(sorted(inspect(database.engine).get_table_names()))
    unknown = set(table_names) - set(Base.metadata.tables)
    if unknown:
        raise ValueError(f"API benchmark database has unknown tables: {sorted(unknown)}")
    with database.engine.connect() as connection:
        return {
            name: int(
                connection.scalar(
                    select(func.count()).select_from(Base.metadata.tables[name])
                )
                or 0
            )
            for name in table_names
        }


def _memory_result(
    scenario: str,
    measured: dict[str, int | float | str | None],
    *,
    limitation: str,
) -> dict[str, int | float | str | None]:
    return {
        "scenario": scenario,
        "sample_count": measured["sample_count"],
        "baseline_rss_bytes": measured["baseline_rss_bytes"],
        "peak_rss_bytes": measured["peak_rss_bytes"],
        "rss_delta_bytes": measured["rss_delta_bytes"],
        "sampling_interval_seconds": measured["rss_sampling_interval_seconds"],
        "status": measured["memory_status"],
        "unit": "bytes",
        "limitation": limitation,
    }


def _require_successful_api_read(path: str, status_code: int) -> None:
    if status_code != 200:
        raise ValueError(f"in-process API read {path} returned {status_code}")


def _require_unchanged_get_counts(
    before: dict[str, int],
    after: dict[str, int],
) -> None:
    if before != after:
        raise ValueError("GET benchmark mutated persistent table row counts")


def _rss_sort_value(result: dict[str, int | float | str | None]) -> int:
    value = result["peak_rss_bytes"]
    return int(value) if isinstance(value, (int, float)) else -1


def _numeric_feature(value: object, *, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"benchmark feature {name} is not numeric")
    return float(value)


def main() -> int:
    arguments = _parse_arguments()
    project_root = Path(__file__).resolve().parents[1]
    micro_repetitions = 1 if arguments.smoke else arguments.micro_repetitions
    full_repetitions = 1 if arguments.smoke else arguments.full_pipeline_repetitions
    micro_warmups = 0 if arguments.smoke else arguments.micro_warmups
    sample = project_root / "data" / "sample" / "phase12-presentation-demo.pcap"
    sample_checksum = hashlib.sha256(sample.read_bytes()).hexdigest()
    output_dir = (
        arguments.output_dir
        if arguments.output_dir.is_absolute()
        else project_root / arguments.output_dir
    )

    with tempfile.TemporaryDirectory(prefix="aegishunt-phase13-benchmark-") as temp_name:
        runtime_root = Path(temp_name)
        with tempfile.TemporaryDirectory(
            prefix=".phase13-benchmark-",
            dir=project_root / "artifacts",
        ) as artifact_name:
            artifact_relative = Path(artifact_name).relative_to(project_root)
            case_policy_path = runtime_root / "case-feedback.yaml"
            case_policy = yaml.safe_load(
                (project_root / "configs/case_feedback.yaml").read_text(encoding="utf-8")
            )
            if not isinstance(case_policy, dict):
                raise ValueError("case feedback policy root must be a mapping")
            case_policy.update(
                {
                    "export_root": (artifact_relative / "feedback").as_posix(),
                    "report_root": (artifact_relative / "case-reports").as_posix(),
                    "candidate_root": (artifact_relative / "candidates").as_posix(),
                }
            )
            case_policy_path.write_text(
                yaml.safe_dump(case_policy, sort_keys=False),
                encoding="utf-8",
            )
            base_settings = _settings(
                project_root,
                runtime_root,
                artifact_root=artifact_relative,
                database_name="setup.db",
                case_policy_path=case_policy_path,
            )
            preparation_started = time.perf_counter()
            environment_settings = DemoArtifactManager(
                base_settings,
                project_root=project_root,
            ).prepare().settings
            preparation_seconds = time.perf_counter() - preparation_started
            runtime_policy = load_runtime_policy(environment_settings.runtime.policy_path).policy
            supervised = load_supervised_bundle(
                environment_settings.supervised.artifact_root
                / runtime_policy.supervised_model_version,
                artifact_root=environment_settings.supervised.artifact_root,
            )
            anomaly = load_anomaly_bundle(
                environment_settings.anomaly.artifact_root
                / runtime_policy.anomaly_model_version,
                artifact_root=environment_settings.anomaly.artifact_root,
            )
            fusion_dir = (
                environment_settings.runtime.fusion_policy_root
                / runtime_policy.fusion_policy_version
            )
            fusion = load_policy(
                fusion_dir,
                root=environment_settings.runtime.fusion_policy_root,
            )
            explanation_dir = (
                environment_settings.detection.explanation_artifact_root
                / runtime_policy.explanation_artifact_version
            )
            load_explanation_artifact(
                explanation_dir,
                root=environment_settings.detection.explanation_artifact_root,
            )

            processor = PcapFlowProcessor(
                base_settings.flows,
                max_records=base_settings.ingestion.max_records,
            )
            packet_reader = PcapPacketReader(
                max_records=base_settings.ingestion.max_records,
                max_packet_bytes=base_settings.flows.max_packet_bytes,
                max_interfaces=base_settings.flows.max_pcapng_interfaces,
            )

            def parse_packets() -> int:
                return sum(1 for _packet in packet_reader.packets(sample))

            def aggregate_flows() -> int:
                return processor.process(
                    sample,
                    source_id=UUID("00000000-0000-0000-0000-000000000013"),
                    capture_session_id="phase13-benchmark",
                ).captured_packets

            flow_result = processor.process(
                sample,
                source_id=UUID("00000000-0000-0000-0000-000000000013"),
                capture_session_id="phase13-benchmark",
            )
            feature_rows = tuple(
                tuple(
                    _numeric_feature(flow.behavioral_features[name], name=name)
                    for name in supervised.manifest.feature_names
                )
                for flow in flow_result.flows
            )
            supervised_batch = PredictionBatch(
                feature_schema_version=supervised.manifest.feature_schema_version,
                feature_names=supervised.manifest.feature_names,
                dtype="float64",
                rows=feature_rows,
            )
            anomaly_batch = AnomalyPredictionBatch(
                feature_schema_version=anomaly.manifest.feature_schema_version,
                feature_names=anomaly.manifest.feature_names,
                dtype="float64",
                rows=feature_rows,
            )
            supervised_results = predict_batch(supervised, supervised_batch)
            anomaly_results = score_batch(anomaly, anomaly_batch)

            def supervised_inference() -> int:
                return len(predict_batch(supervised, supervised_batch))

            def anomaly_inference() -> int:
                return len(score_batch(anomaly, anomaly_batch))

            def fusion_inference() -> int:
                for supervised_item, anomaly_item in zip(
                    supervised_results,
                    anomaly_results,
                    strict=True,
                ):
                    fuse_score(
                        FusionScoreInput(
                            supervised_probability=supervised_item.calibrated_probability,
                            normalized_anomaly_score=(
                                anomaly_item.normalized_anomaly_score
                            ),
                            supervised_model_id=supervised_item.model_id,
                            supervised_model_version=supervised_item.model_version,
                            anomaly_model_id=anomaly_item.model_id,
                            anomaly_model_version=anomaly_item.model_version,
                            feature_schema_version=supervised_item.feature_schema_version,
                        ),
                        fusion,
                        scored_at=datetime(2026, 7, 29, tzinfo=UTC),
                    )
                return len(supervised_results)

            pipeline_index = 0

            def full_pipeline() -> int:
                nonlocal pipeline_index
                pipeline_index += 1
                settings = _settings(
                    project_root,
                    runtime_root,
                    artifact_root=artifact_relative,
                    database_name=f"pipeline-{pipeline_index}.db",
                    case_policy_path=case_policy_path,
                )
                service = SampleDemoService(
                    database=Database(settings.database),
                    settings=settings,
                )
                result = service.run(
                    DemoRequest(
                        sample_id="phase12-presentation-demo-pcap",
                        create_case=False,
                        actor="phase13-benchmark",
                        reason="controlled performance baseline",
                        confirm=True,
                    )
                )
                return len(result.flow_ids)

            packet_result = measure(
                "pcap_packet_parsing",
                parse_packets,
                warmups=micro_warmups,
                repetitions=micro_repetitions,
                operation_unit="captured_packets",
            )
            aggregation_result = measure(
                "flow_aggregation_feature_extraction",
                aggregate_flows,
                warmups=micro_warmups,
                repetitions=micro_repetitions,
                operation_unit="captured_packets",
            )
            supervised_result = measure(
                "supervised_warm_inference",
                supervised_inference,
                warmups=micro_warmups,
                repetitions=micro_repetitions,
                operation_unit="flow_rows",
            )
            anomaly_result = measure(
                "anomaly_warm_inference",
                anomaly_inference,
                warmups=micro_warmups,
                repetitions=micro_repetitions,
                operation_unit="flow_rows",
            )
            fusion_result = measure(
                "fusion",
                fusion_inference,
                warmups=micro_warmups,
                repetitions=micro_repetitions,
                operation_unit="score_pairs",
            )

            def load_model_artifacts() -> int:
                load_supervised_bundle(
                    environment_settings.supervised.artifact_root
                    / runtime_policy.supervised_model_version,
                    artifact_root=environment_settings.supervised.artifact_root,
                )
                load_anomaly_bundle(
                    environment_settings.anomaly.artifact_root
                    / runtime_policy.anomaly_model_version,
                    artifact_root=environment_settings.anomaly.artifact_root,
                )
                return 2

            model_load_result = measure(
                "supervised_anomaly_artifact_load",
                load_model_artifacts,
                warmups=0,
                repetitions=full_repetitions,
                operation_unit="verified_artifacts",
            )
            full_pipeline_result = measure(
                "full_flow_to_alert_pipeline",
                full_pipeline,
                warmups=0,
                repetitions=full_repetitions,
                operation_unit="persisted_flows",
            )

            api_settings = _settings(
                project_root,
                runtime_root,
                artifact_root=artifact_relative,
                database_name="api-read.db",
                case_policy_path=case_policy_path,
            )
            api_database = Database(api_settings.database)
            api_database.initialize()
            api_demo = SampleDemoService(api_database, api_settings).run(
                DemoRequest(
                    sample_id="phase12-presentation-demo-pcap",
                    create_case=True,
                    actor="phase13-api-benchmark",
                    reason="controlled in-process API read baseline",
                    confirm=True,
                )
            )
            if not api_demo.flow_ids or api_demo.case_id is None:
                raise ValueError("API benchmark setup did not create required evidence")
            api_case_id = api_demo.case_id
            before_api_counts = _table_counts(api_database)
            api_results: list[dict[str, int | float | str | None]] = []
            with TestClient(create_app(api_settings, api_database)) as client:

                def api_read(path: str) -> int:
                    response = client.get(path)
                    _require_successful_api_read(path, response.status_code)
                    return 1

                for component, path, route in (
                    ("api_health", "/health", "/health"),
                    ("api_system_status", "/system/status", "/system/status"),
                    ("api_flows_page", "/flows?limit=10&offset=0", "/flows"),
                    ("api_alerts_page", "/alerts?limit=10&offset=0", "/alerts"),
                    ("api_runtime_status", "/runtime/status", "/runtime/status"),
                    ("api_demo_status", "/demo/status", "/demo/status"),
                    (
                        "api_flow_detail",
                        f"/flows/{api_demo.flow_ids[0]}",
                        "/flows/{flow_id}",
                    ),
                ):
                    result = measure(
                        component,
                        partial(api_read, path),
                        warmups=micro_warmups,
                        repetitions=micro_repetitions,
                        operation_unit="http_200_responses",
                    )
                    result.update(
                        {
                            "request_method": "GET",
                            "route": route,
                            "http_status": 200,
                            "latency_semantics": "in_process_testclient_latency",
                        }
                    )
                    api_results.append(result)
            after_api_counts = _table_counts(api_database)
            _require_unchanged_get_counts(before_api_counts, after_api_counts)

            report_index = 0
            loaded_case_policy = load_case_feedback_policy(case_policy_path)

            def export_case_report() -> int:
                nonlocal report_index
                report_index += 1
                with api_database.session() as session, session.begin():
                    CaseReportService(
                        session,
                        loaded_case_policy,
                        project_root=project_root,
                    ).generate(
                        api_case_id,
                        f"performance-{report_index}",
                        actor="phase13-benchmark",
                    )
                return 1

            report_result = measure(
                "case_report_export",
                export_case_report,
                warmups=0,
                repetitions=full_repetitions,
                operation_unit="versioned_reports",
            )
            api_database.dispose()

            results = [
                packet_result,
                aggregation_result,
                supervised_result,
                anomaly_result,
                fusion_result,
                model_load_result,
                full_pipeline_result,
                *api_results,
                report_result,
            ]
            baseline_rss = current_rss_bytes()
            memory_results = [
                {
                    "scenario": "baseline_process_rss",
                    "sample_count": 1,
                    "baseline_rss_bytes": baseline_rss,
                    "peak_rss_bytes": baseline_rss,
                    "rss_delta_bytes": 0 if baseline_rss is not None else None,
                    "sampling_interval_seconds": RSS_SAMPLING_INTERVAL_SECONDS,
                    "status": "available" if baseline_rss is not None else "unavailable",
                    "unit": "bytes",
                    "limitation": (
                        "single point-in-time RSS observation"
                        if baseline_rss is not None
                        else "process RSS sampler unavailable on this platform"
                    ),
                },
                _memory_result(
                    "supervised_anomaly_artifact_load_delta",
                    model_load_result,
                    limitation="allocator reuse can reduce the observed incremental RSS",
                ),
                _memory_result(
                    "warm_inference_peak",
                    max(
                        (supervised_result, anomaly_result),
                        key=_rss_sort_value,
                    ),
                    limitation="small controlled feature batch",
                ),
                _memory_result(
                    "full_sample_replay_peak",
                    aggregation_result,
                    limitation="controlled sample PCAP; not a large-capture capacity claim",
                ),
                _memory_result(
                    "sample_demo_peak",
                    full_pipeline_result,
                    limitation="isolated controlled demo with bounded synthetic input",
                ),
                _memory_result(
                    "bounded_api_list_peak",
                    next(
                        item for item in api_results if item["component"] == "api_flows_page"
                    ),
                    limitation="in-process TestClient; excludes network and browser memory",
                ),
                _memory_result(
                    "case_report_export_peak",
                    report_result,
                    limitation="bounded controlled case evidence only",
                ),
            ]
            payload: dict[str, object] = {
                "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
                "recorded_at": datetime.now(UTC).isoformat(),
                "environment": environment(project_root),
                "method": {
                    "micro_warmups": micro_warmups,
                    "micro_repetitions": micro_repetitions,
                    "full_pipeline_repetitions": full_repetitions,
                    "percentile_method": "linear_interpolation",
                    "p99_minimum_samples": 100,
                    "rss_sampling_interval_seconds": 0.002,
                    "concurrency": "single_process_sequential",
                    "api_latency_semantics": "in_process_testclient_latency",
                    "api_read_components": list(API_READ_COMPONENTS),
                    "api_get_mutation_check": "PASS",
                    "artifact_preparation_seconds": preparation_seconds,
                },
                "workload": {
                    "sample_name": sample.name,
                    "sample_sha256": sample_checksum,
                    "captured_packets_per_iteration": flow_result.captured_packets,
                    "flows_per_iteration": len(flow_result.flows),
                    "feature_schema_version": FEATURE_SCHEMA_VERSION,
                    "supervised_model_id": supervised.manifest.model_id,
                    "supervised_model_version": supervised.manifest.model_version,
                    "anomaly_model_id": anomaly.manifest.model_id,
                    "anomaly_model_version": anomaly.manifest.model_version,
                    "fusion_policy_id": fusion.policy_id,
                    "fusion_policy_version": fusion.policy_version,
                    "fusion_policy_checksum": sha256_file(
                        fusion_dir / POLICY_MANIFEST_FILENAME
                    ),
                    "random_seed": base_settings.datasets.demo_seed,
                },
                "artifact_sizes_bytes": {
                    "supervised_bundle": directory_size(
                        environment_settings.supervised.artifact_root
                        / runtime_policy.supervised_model_version
                    ),
                    "anomaly_bundle": directory_size(
                        environment_settings.anomaly.artifact_root
                        / runtime_policy.anomaly_model_version
                    ),
                    "fusion_policy": directory_size(fusion_dir),
                    "explanation_artifact": directory_size(explanation_dir),
                },
                "results": results,
                "memory_results": memory_results,
                "limitations": [
                    "development-host research baseline only",
                    "controlled synthetic sample; not a public benchmark",
                    "not an SLA or production capacity claim",
                    "RSS sampled at two-millisecond intervals",
                    "API latency is in-process TestClient latency, not network latency",
                    "full-pipeline and report samples below 100 intentionally omit p99",
                    "no frozen evaluation evidence was reopened",
                ],
            }
            written = write_results(output_dir, payload)
            print("\n".join(path.as_posix() for path in written))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
