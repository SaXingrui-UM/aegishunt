"""Small Phase 4 bundle builder for isolated Phase 5 tests."""

from __future__ import annotations

from pathlib import Path

from aegishunt.config import DatasetSettings
from aegishunt.datasets.service import DatasetService
from tests.fixtures.datasets import LABEL_ROOT, REGISTRY_PATH

TRAINING_CONFIG_PATH = Path(__file__).parents[2] / "configs" / "models" / "supervised.yaml"
CORRECTIVE_CONFIG_PATH = (
    Path(__file__).parents[2]
    / "configs"
    / "models"
    / "supervised-corrective-pm-def-001.yaml"
)


def build_phase4_bundle(root: Path) -> tuple[Path, Path]:
    data_root = root / "data"
    report_root = root / "reports"
    service = DatasetService(
        DatasetSettings(
            registry_path=REGISTRY_PATH,
            label_mapping_root=LABEL_ROOT,
            raw_root=root / "raw",
            interim_root=root / "interim",
            processed_root=root / "processed",
            reports_root=root / "dataset-reports",
        )
    )
    service.build_demo(data_root=data_root, report_root=report_root, seed=4_204)
    return data_root, report_root
