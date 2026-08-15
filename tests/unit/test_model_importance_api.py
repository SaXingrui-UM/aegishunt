"""Verified native/permutation importance API projections."""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

from aegishunt.api.contracts import ModelDescriptor
from aegishunt.api.model_service import ModelRegistryService
from aegishunt.config import ApplicationSettings, DatabaseSettings, DetectionSettings
from aegishunt.explainability.contracts import GlobalImportanceReport
from aegishunt.runtime.contracts import RuntimeArtifactIdentity, RuntimeJobStatus
from aegishunt.runtime.repositories import RuntimeJobRepository
from aegishunt.storage import Database
from tests.fixtures.detection import NOW, explanation_artifact
from tests.fixtures.runtime import runtime_job


def _available_artifact():
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
    return artifact.model_copy(update={"native_importance": native})


def test_importance_distinguishes_native_na_from_permutation_deviation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'importance.sqlite3'}")
    )
    database = Database(settings.database)
    loaded = _available_artifact()
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
        RuntimeJobRepository,
        "latest_with_status",
        lambda self, status: None,
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


def test_importance_reads_exact_latest_runtime_snapshot_without_registry_entry(
    tmp_path: Path,
    monkeypatch,
) -> None:
    explanation_root = tmp_path / "explanations"
    checksums = explanation_root / "1.0.0" / "checksums.json"
    checksums.parent.mkdir(parents=True)
    checksums.write_bytes(b'{"verified": true}\n')
    checksum = hashlib.sha256(checksums.read_bytes()).hexdigest()
    settings = ApplicationSettings(
        database=DatabaseSettings(url=f"sqlite:///{tmp_path / 'runtime.sqlite3'}"),
        detection=DetectionSettings(explanation_artifact_root=explanation_root),
    )
    database = Database(settings.database)
    loaded = _available_artifact()
    job = runtime_job()
    identities = []
    for identity in job.snapshot.artifacts:
        if identity.artifact_type == "supervised_model":
            identity = RuntimeArtifactIdentity(
                artifact_type="supervised_model",
                artifact_id=loaded.manifest.supervised_model_id,
                version=loaded.manifest.supervised_model_version,
                checksum=identity.checksum,
            )
        elif identity.artifact_type == "explanation_artifact":
            identity = RuntimeArtifactIdentity(
                artifact_type="explanation_artifact",
                artifact_id=loaded.manifest.artifact_id,
                version=loaded.manifest.artifact_version,
                checksum=checksum,
            )
        identities.append(identity)
    completed = job.model_copy(
        update={
            "status": RuntimeJobStatus.COMPLETED,
            "snapshot": job.snapshot.model_copy(update={"artifacts": tuple(identities)}),
        }
    )
    monkeypatch.setattr(
        RuntimeJobRepository,
        "latest_with_status",
        lambda self, status: completed,
    )
    monkeypatch.setattr(
        "aegishunt.api.model_service.resolve_job_execution_environment",
        lambda *args, **kwargs: SimpleNamespace(settings=settings),
    )
    monkeypatch.setattr(
        "aegishunt.api.model_service.load_explanation_artifact",
        lambda *args, **kwargs: loaded,
    )
    monkeypatch.setattr(
        ModelRegistryService,
        "get",
        lambda self, model_id: (_ for _ in ()).throw(
            AssertionError("runtime-pinned importance must not require registry lookup")
        ),
    )
    service = ModelRegistryService(database, settings)

    native = service.importance(loaded.manifest.supervised_model_id, kind="native")
    permutation = service.importance(
        loaded.manifest.supervised_model_id,
        kind="permutation",
    )

    assert native.available is True
    assert native.importance is not None
    assert all(item.standard_deviation is None for item in native.importance)
    assert permutation.available is True
    assert permutation.source_partition == "validation"
    assert permutation.scoring_metric == "balanced_accuracy"
    assert permutation.repeats == 5
