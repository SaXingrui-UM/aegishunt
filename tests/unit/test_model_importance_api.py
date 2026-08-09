"""Verified native/permutation importance API projections."""

from __future__ import annotations

from pathlib import Path

from aegishunt.api.contracts import ModelDescriptor
from aegishunt.api.model_service import ModelRegistryService
from aegishunt.config import ApplicationSettings, DatabaseSettings
from aegishunt.explainability.contracts import GlobalImportanceReport
from aegishunt.storage import Database
from tests.fixtures.detection import NOW, explanation_artifact


def test_importance_distinguishes_native_na_from_permutation_deviation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'importance.sqlite3'}")
    )
    database = Database(settings.database)
    artifact = explanation_artifact()
    native = GlobalImportanceReport(
        report_schema_version="1.0.0",
        report_id="native-available",
        method="native_tree_importance",
        status="available",
        model_id="aegishunt-supervised-1.0.1",
        model_version="1.0.1",
        feature_schema_version=artifact.native_importance.feature_schema_version,
        feature_names=artifact.permutation_importance.feature_names,
        entries=artifact.permutation_importance.entries,
        semantics="model association or sensitivity; not causation",
        created_at=NOW,
    )
    loaded = artifact.model_copy(update={"native_importance": native})
    descriptor = ModelDescriptor(
        model_id="fixture-model",
        engine="supervised",
        version="1.0.1",
        state="verified",
        active=False,
        checksum="a" * 64,
        artifact_available=True,
        activation_eligible=True,
    )
    monkeypatch.setattr(
        ModelRegistryService,
        "get",
        lambda self, model_id: descriptor,
    )
    monkeypatch.setattr(
        "aegishunt.api.model_service.load_explanation_artifact",
        lambda *args, **kwargs: loaded,
    )
    service = ModelRegistryService(database, settings)

    native_result = service.importance(descriptor.model_id, kind="native")
    permutation = service.importance(descriptor.model_id, kind="permutation")

    assert native_result.method == "native_tree_importance"
    assert native_result.importance is not None
    assert all(item.standard_deviation is None for item in native_result.importance)
    assert native_result.repeats is None
    assert permutation.method == "permutation_importance"
    assert permutation.importance is not None
    assert all(item.standard_deviation == 0.0 for item in permutation.importance)
    assert permutation.source_partition == "validation"
    assert permutation.scoring_metric == "balanced_accuracy"
    assert permutation.repeats == 5
