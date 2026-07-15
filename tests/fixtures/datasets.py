"""Small controlled dataset helpers shared by Phase 4 tests."""

from __future__ import annotations

from pathlib import Path

from aegishunt.datasets.demo import build_controlled_demo
from aegishunt.datasets.labels import LabelMapper
from aegishunt.datasets.schemas import CanonicalDatasetRow

PROJECT_ROOT = Path(__file__).parents[2]
REGISTRY_PATH = PROJECT_ROOT / "configs" / "datasets" / "registry.yaml"
LABEL_ROOT = PROJECT_ROOT / "configs" / "label_mappings"


def demo_rows(seed: int = 4_204) -> tuple[CanonicalDatasetRow, ...]:
    mapper = LabelMapper.load(LABEL_ROOT / "aegishunt-controlled-demo-v1.yaml")
    return build_controlled_demo(seed=seed, label_mapper=mapper)
