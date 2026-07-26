"""Small deterministic Phase 11 runtime fixtures."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import yaml

from aegishunt.config import (
    AnomalySettings,
    ApplicationSettings,
    CorrelationSettings,
    DatabaseSettings,
    DetectionSettings,
    IngestionSettings,
    RuntimeSettings,
    SupervisedSettings,
)
from aegishunt.explainability.artifacts import save_explanation_artifact
from aegishunt.ml.fusion.artifacts import POLICY_MANIFEST_FILENAME, sha256_file
from aegishunt.ml.fusion.service import FusionEvaluationService
from aegishunt.ml.supervised.service import SupervisedTrainingService
from aegishunt.runtime.config import LoadedRuntimePolicy, load_runtime_policy
from aegishunt.runtime.contracts import (
    RuntimeArtifactIdentity,
    RuntimeJob,
    RuntimePipelineSnapshot,
)
from aegishunt.schemas.enums import SourceType
from tests.fixtures.anomaly import (
    LOF_CANDIDATE_CONFIG_PATH,
    anomaly_lof_candidate_service,
)
from tests.fixtures.datasets import LABEL_ROOT
from tests.fixtures.detection import explanation_artifact
from tests.fixtures.fusion import FUSION_CONFIG_PATH
from tests.fixtures.supervised import CORRECTIVE_CONFIG_PATH, build_phase4_bundle

NOW = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
CHECKSUM = "a" * 64
SOURCE_ID = UUID(int=1_101)
PROJECT_ROOT = Path(__file__).parents[2]


def build_verified_runtime_environment(
    root: Path,
) -> tuple[ApplicationSettings, LoadedRuntimePolicy]:
    """Create real temporary Phase 5–9 artifacts aligned for runtime preflight."""

    data_root, dataset_report_root = build_phase4_bundle(root / "phase4")
    supervised_root = root / "models" / "supervised"
    supervised_service = SupervisedTrainingService(
        data_root=data_root,
        dataset_report_root=dataset_report_root,
        training_config_path=CORRECTIVE_CONFIG_PATH,
        artifact_root=supervised_root,
        reports_root=root / "reports" / "supervised",
    )
    supervised = supervised_service.train(allow_controlled_demo=True)
    assert supervised.model_version == "1.0.1"
    supervised_service.evaluate_test(allow_controlled_demo=True)

    anomaly_service, _, _, anomaly_root, _ = anomaly_lof_candidate_service(
        root / "anomaly-run"
    )
    anomaly = anomaly_service.train(allow_controlled_demo=True)
    assert anomaly.model_version == "1.1.0-candidate"

    fusion_root = root / "models" / "fusion"
    fusion = FusionEvaluationService(
        fusion_config_path=FUSION_CONFIG_PATH,
        supervised_config_path=CORRECTIVE_CONFIG_PATH,
        anomaly_config_path=LOF_CANDIDATE_CONFIG_PATH,
        label_mapping_path=LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml",
        experiment_root=root / "reports" / "fusion",
        policy_root=fusion_root,
    ).evaluate(allow_controlled_demo=True)
    fusion_checksum = sha256_file(
        fusion.policy_directory / POLICY_MANIFEST_FILENAME
    )

    risk_payload = yaml.safe_load(
        (PROJECT_ROOT / "configs" / "models" / "detection.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert isinstance(risk_payload, dict)
    risk_payload["required_fusion_policy_checksum"] = fusion_checksum
    risk_path = root / "configs" / "detection.yaml"
    risk_path.parent.mkdir(parents=True)
    risk_path.write_text(yaml.safe_dump(risk_payload), encoding="utf-8")

    expected_explanation = explanation_artifact()
    explanation_root = root / "models" / "explainability"
    save_explanation_artifact(
        root=explanation_root,
        manifest=expected_explanation.manifest,
        reference_profile=expected_explanation.reference_profile,
        native_importance=expected_explanation.native_importance,
        permutation_importance=expected_explanation.permutation_importance,
        reason_catalog=expected_explanation.reason_catalog,
        protocol=expected_explanation.protocol,
    )

    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{root / 'runtime.sqlite3'}"),
        ingestion=IngestionSettings(
            storage_root=root / "raw",
            sample_root=PROJECT_ROOT / "data" / "sample",
            max_upload_bytes=2_048,
            chunk_size_bytes=16,
            max_records=100,
        ),
        supervised=SupervisedSettings(
            training_config_path=CORRECTIVE_CONFIG_PATH,
            artifact_root=supervised_root,
            reports_root=root / "reports" / "supervised",
        ),
        anomaly=AnomalySettings(
            training_config_path=LOF_CANDIDATE_CONFIG_PATH,
            artifact_root=anomaly_root,
            reports_root=root / "reports" / "anomaly",
        ),
        detection=DetectionSettings(
            risk_policy_path=risk_path,
            explanation_artifact_root=explanation_root,
        ),
        correlation=CorrelationSettings(
            policy_path=PROJECT_ROOT / "configs" / "correlation.yaml"
        ),
        runtime=RuntimeSettings(
            policy_path=PROJECT_ROOT / "configs" / "runtime.yaml",
            fusion_policy_root=fusion_root,
        ),
    )
    return settings, load_runtime_policy(settings.runtime.policy_path)


def runtime_snapshot(
    *,
    source_id: UUID = SOURCE_ID,
    stored_filename: str = "stored-phase-11.pcap",
) -> RuntimePipelineSnapshot:
    """Return a complete seven-component pinned snapshot."""

    kinds = (
        "supervised_model",
        "anomaly_model",
        "fusion_policy",
        "risk_policy",
        "explanation_artifact",
        "correlation_policy",
        "flow_configuration",
    )
    return RuntimePipelineSnapshot(
        source_id=source_id,
        source_checksum=CHECKSUM,
        source_type=SourceType.PCAP,
        stored_filename=stored_filename,
        source_size_bytes=128,
        verified_packet_count=2,
        capture_session_id=f"pcap:{source_id}",
        feature_schema_version="1.0.0",
        artifacts=tuple(
            RuntimeArtifactIdentity(
                artifact_type=kind,  # type: ignore[arg-type]
                artifact_id=f"fixture-{kind}",
                version="1.0.0",
                checksum=f"{index + 1:x}" * 64,
            )
            for index, kind in enumerate(kinds)
        ),
        runtime_policy_id="fixture-runtime",
        runtime_policy_version="1.0.0",
        runtime_policy_checksum="f" * 64,
        git_commit_sha="1" * 40,
        database_schema_version=5,
    )


def runtime_job(
    *,
    source_id: UUID = SOURCE_ID,
    created_at: datetime = NOW,
) -> RuntimeJob:
    return RuntimeJob(
        source_id=source_id,
        replay_speed=1.0,
        snapshot=runtime_snapshot(source_id=source_id),
        created_at=created_at,
        updated_at=created_at,
    )
