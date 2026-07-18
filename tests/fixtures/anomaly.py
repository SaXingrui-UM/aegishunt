"""Small isolated Phase 6 fixture builders."""

from __future__ import annotations

from pathlib import Path

from aegishunt.ml.anomaly.service import AnomalyTrainingService
from tests.fixtures.supervised import build_phase4_bundle

ANOMALY_CONFIG_PATH = Path(__file__).parents[2] / "configs" / "models" / "anomaly.yaml"


def anomaly_service(
    root: Path,
) -> tuple[AnomalyTrainingService, Path, Path, Path, Path]:
    data_root, dataset_report_root = build_phase4_bundle(root)
    model_root = root / "models"
    experiment_root = root / "experiments"
    service = AnomalyTrainingService(
        data_root=data_root,
        dataset_report_root=dataset_report_root,
        training_config_path=ANOMALY_CONFIG_PATH,
        artifact_root=model_root,
        reports_root=experiment_root,
    )
    return service, data_root, dataset_report_root, model_root, experiment_root
