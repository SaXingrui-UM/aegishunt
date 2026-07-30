"""Small isolated Phase 6 fixture builders."""

from __future__ import annotations

import json
from pathlib import Path

from aegishunt.datasets.io import sha256_file
from aegishunt.ml.anomaly.service import AnomalyTrainingService
from aegishunt.ml.anomaly.smoke import predefined_sample_anomaly as _sample_anomaly
from tests.fixtures.supervised import build_phase4_bundle

ANOMALY_CONFIG_PATH = Path(__file__).parents[2] / "configs" / "models" / "anomaly.yaml"
CORRECTIVE_CONFIG_PATH = (
    Path(__file__).parents[2]
    / "configs"
    / "models"
    / "anomaly-validation-corrective.yaml"
)
LOF_CANDIDATE_CONFIG_PATH = (
    Path(__file__).parents[2]
    / "configs"
    / "models"
    / "anomaly-lof-production-candidate.yaml"
)
REGISTERED_DATASET_MANIFEST_SHA = (
    "badf8c045c29fa02299eb55f8a1cd7deb15d92aec40c0e80cd6ea4a133d98d0d"
)
REGISTERED_DATASET_GIT_COMMIT = "352205f92e81f82a7878f2cb8799c6e6e3b7b002"
REGISTERED_DATASET_TOOL_VERSION = "0.1.0"


def predefined_sample_anomaly() -> tuple[float, ...]:
    return _sample_anomaly()


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


def anomaly_corrective_service(
    root: Path,
) -> tuple[AnomalyTrainingService, Path, Path, Path, Path]:
    """Build the byte-verified dataset evidence registered by the corrective protocol."""

    data_root, dataset_report_root = build_phase4_bundle(root)
    manifest_path = dataset_report_root / "dataset_manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["git_commit_sha"] = REGISTERED_DATASET_GIT_COMMIT
    payload["tool_version"] = REGISTERED_DATASET_TOOL_VERSION
    manifest_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if sha256_file(manifest_path) != REGISTERED_DATASET_MANIFEST_SHA:
        raise RuntimeError("reconstructed corrective dataset manifest differs from registration")
    model_root = root / "models"
    experiment_root = root / "experiments"
    service = AnomalyTrainingService(
        data_root=data_root,
        dataset_report_root=dataset_report_root,
        training_config_path=CORRECTIVE_CONFIG_PATH,
        artifact_root=model_root,
        reports_root=experiment_root,
    )
    return service, data_root, dataset_report_root, model_root, experiment_root


def anomaly_lof_candidate_service(
    root: Path,
) -> tuple[AnomalyTrainingService, Path, Path, Path, Path]:
    """Build the registered direction-B dataset evidence and isolated service."""

    data_root, dataset_report_root = build_phase4_bundle(root)
    manifest_path = dataset_report_root / "dataset_manifest.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["git_commit_sha"] = REGISTERED_DATASET_GIT_COMMIT
    payload["tool_version"] = REGISTERED_DATASET_TOOL_VERSION
    manifest_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if sha256_file(manifest_path) != REGISTERED_DATASET_MANIFEST_SHA:
        raise RuntimeError("reconstructed LOF-candidate manifest differs from registration")
    model_root = root / "models"
    experiment_root = root / "experiments"
    service = AnomalyTrainingService(
        data_root=data_root,
        dataset_report_root=dataset_report_root,
        training_config_path=LOF_CANDIDATE_CONFIG_PATH,
        artifact_root=model_root,
        reports_root=experiment_root,
    )
    return service, data_root, dataset_report_root, model_root, experiment_root
