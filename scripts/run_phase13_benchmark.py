"""Run the controlled offline Phase 13 performance baseline."""

from __future__ import annotations

import argparse
import hashlib
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from aegishunt.api.contracts import DemoRequest
from aegishunt.api.demo_service import SampleDemoService
from aegishunt.config import (
    ApplicationSettings,
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
from scripts.phase13_benchmark_support import (
    BENCHMARK_SCHEMA_VERSION,
    directory_size,
    environment,
    measure,
    write_results,
)


def _settings(
    project_root: Path,
    runtime_root: Path,
    *,
    artifact_root: Path,
    database_name: str,
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
    )


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/hardening/phase-13/performance"),
    )
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--smoke", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    project_root = Path(__file__).resolve().parents[1]
    repetitions = 1 if arguments.smoke else arguments.repetitions
    warmups = 0 if arguments.smoke else arguments.warmups
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
            base_settings = _settings(
                project_root,
                runtime_root,
                artifact_root=artifact_relative,
                database_name="setup.db",
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
                    float(flow.behavioral_features[name])
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

            results = [
                measure(
                    "pcap_packet_parsing",
                    parse_packets,
                    warmups=warmups,
                    repetitions=repetitions,
                    operation_unit="captured_packets",
                ),
                measure(
                    "flow_aggregation_feature_extraction",
                    aggregate_flows,
                    warmups=warmups,
                    repetitions=repetitions,
                    operation_unit="captured_packets",
                ),
                measure(
                    "supervised_inference",
                    supervised_inference,
                    warmups=warmups,
                    repetitions=repetitions,
                    operation_unit="flow_rows",
                ),
                measure(
                    "anomaly_inference",
                    anomaly_inference,
                    warmups=warmups,
                    repetitions=repetitions,
                    operation_unit="flow_rows",
                ),
                measure(
                    "fusion",
                    fusion_inference,
                    warmups=warmups,
                    repetitions=repetitions,
                    operation_unit="score_pairs",
                ),
                measure(
                    "full_flow_to_alert_pipeline",
                    full_pipeline,
                    warmups=warmups,
                    repetitions=repetitions,
                    operation_unit="persisted_flows",
                ),
            ]
            payload: dict[str, object] = {
                "benchmark_schema_version": BENCHMARK_SCHEMA_VERSION,
                "recorded_at": datetime.now(UTC).isoformat(),
                "environment": environment(project_root),
                "method": {
                    "warmups": warmups,
                    "repetitions": repetitions,
                    "percentile_method": "linear_interpolation",
                    "rss_sampling_interval_seconds": 0.002,
                    "concurrency": "single_process_sequential",
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
                "limitations": [
                    "development-host research baseline only",
                    "controlled synthetic sample; not a public benchmark",
                    "not an SLA or production capacity claim",
                    "RSS sampled at two-millisecond intervals",
                    "no frozen evaluation evidence was reopened",
                ],
            }
            written = write_results(output_dir, payload)
            print("\n".join(path.as_posix() for path in written))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
