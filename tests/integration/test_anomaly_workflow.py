"""Phase 4-to-Phase 6 integration boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.ml.anomaly.bundle import (
    estimator_bytes,
    load_bundle,
    save_bundle,
    sha256_bytes,
    trusted_types,
)
from aegishunt.ml.anomaly.contracts import (
    AnomalyBundleManifest,
    AnomalySelectionRecord,
    ComparatorResult,
)
from aegishunt.ml.anomaly.errors import AnomalyArtifactError, AnomalyDatasetError
from aegishunt.ml.anomaly.prediction import AnomalyPredictionBatch, score_batch
from tests.fixtures.anomaly import (
    anomaly_corrective_service,
    anomaly_lof_candidate_service,
    anomaly_service,
    predefined_sample_anomaly,
)


def test_training_freezes_selection_without_reading_frozen_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, _, experiment_root = anomaly_service(tmp_path)
    from aegishunt.ml.supervised import data as supervised_data

    original = supervised_data.read_canonical_jsonl
    opened: list[str] = []

    def tracked(path: Path) -> tuple[object, ...]:
        opened.append(path.name)
        return original(path)  # type: ignore[return-value]

    monkeypatch.setattr(supervised_data, "read_canonical_jsonl", tracked)
    result = service.train(allow_controlled_demo=True)

    assert result.selection.test_data_accessed is False
    assert "test.jsonl" not in opened
    assert set(opened) == {"train.jsonl", "validation.jsonl"}
    frozen_report = experiment_root / result.experiment_id / "anomaly_frozen_test_metrics.json"
    assert not frozen_report.exists()
    assert result.selection.benign_training_rows == 10
    assert len(result.selection.benign_training_groups) == 5


def test_controlled_demo_requires_explicit_permission(tmp_path: Path) -> None:
    service, _, _, _, _ = anomaly_service(tmp_path)

    with pytest.raises(AnomalyDatasetError, match="explicit"):
        service.train()


def test_frozen_test_requires_selection_and_rejects_repeat(tmp_path: Path) -> None:
    service, _, _, _, _ = anomaly_service(tmp_path)

    with pytest.raises(AnomalyArtifactError, match="does not exist"):
        service.evaluate_test(allow_controlled_demo=True)
    training = service.train(allow_controlled_demo=True)
    frozen = service.evaluate_test(allow_controlled_demo=True)

    assert frozen.report.evaluation_count == 1
    assert frozen.report.test_affected_selection is False
    assert frozen.report.model_version == training.model_version
    with pytest.raises(AnomalyArtifactError, match="already exists"):
        service.evaluate_test(allow_controlled_demo=True)


def test_frozen_test_rejects_selection_tampering(tmp_path: Path) -> None:
    service, _, _, _, experiment_root = anomaly_service(tmp_path)
    training = service.train(allow_controlled_demo=True)
    selection_path = experiment_root / training.experiment_id / "anomaly_model_selection.json"
    payload = json.loads(selection_path.read_text(encoding="utf-8"))
    payload["threshold"] = 0.1
    selection_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    with pytest.raises(AnomalyArtifactError, match="selection checksum"):
        service.evaluate_test(allow_controlled_demo=True)
    assert not (
        experiment_root / training.experiment_id / "anomaly_frozen_test_metrics.json"
    ).exists()


def test_model_version_collision_is_rejected_before_frozen_evidence(
    tmp_path: Path,
) -> None:
    service, _, _, model_root, experiment_root = anomaly_service(tmp_path)
    training = service.train(allow_controlled_demo=True)
    (model_root / training.model_version).mkdir(parents=True)

    with pytest.raises(AnomalyArtifactError, match="version already exists"):
        service.evaluate_test(allow_controlled_demo=True)
    assert not (
        experiment_root / training.experiment_id / "anomaly_frozen_test_metrics.json"
    ).exists()


def test_training_artifact_inventory_is_complete_and_has_no_test_metrics(tmp_path: Path) -> None:
    service, _, _, _, experiment_root = anomaly_service(tmp_path)
    training = service.train(allow_controlled_demo=True)
    directory = experiment_root / training.experiment_id

    expected = {
        "anomaly_training_config.json",
        "benign_training_manifest.json",
        "isolation_forest_candidates.json",
        "anomaly_hyperparameter_results.csv",
        "validation_anomaly_metrics.json",
        "score_normalization.json",
        "threshold_results.csv",
        "threshold_sensitivity.csv",
        "anomaly_model_comparison.csv",
        "lof_comparison.json",
        "one_class_svm_comparison.json",
        "score_distribution.csv",
        "latency_results.csv",
        "raw_score_distribution.png",
        "normalized_score_distribution.png",
        "threshold_sensitivity.png",
        "benign_fpr_vs_threshold.png",
        "anomaly_utility_vs_threshold.png",
        "validation_plot_manifest.json",
        "selection.skops",
        "anomaly_model_selection.json",
        "anomaly_model_selection.sha256",
    }
    assert {path.name for path in directory.iterdir()} == expected
    assert not (directory / "anomaly_frozen_test_metrics.json").exists()
    manifest = json.loads((directory / "validation_plot_manifest.json").read_text())
    assert manifest["selected_threshold"] == training.selection.threshold
    assert manifest["frozen_test_accessed"] is False
    assert {item["filename"] for item in manifest["artifacts"]} == {
        "raw_score_distribution.png",
        "normalized_score_distribution.png",
        "threshold_sensitivity.png",
        "benign_fpr_vs_threshold.png",
        "anomaly_utility_vs_threshold.png",
    }


def test_corrective_selection_fails_closed_on_unchanged_smoke_without_test_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, model_root, experiment_root = anomaly_corrective_service(tmp_path)
    from aegishunt.ml.supervised import data as supervised_data

    original = supervised_data.read_canonical_jsonl
    opened: list[str] = []

    def tracked(path: Path) -> tuple[object, ...]:
        opened.append(path.name)
        return original(path)  # type: ignore[return-value]

    monkeypatch.setattr(supervised_data, "read_canonical_jsonl", tracked)
    with pytest.raises(AnomalyArtifactError, match="failed the fixed smoke"):
        service.train(allow_controlled_demo=True)

    experiment = experiment_root / "phase-06-controlled-demo-validation-corrective-001"
    smoke = json.loads((experiment / "candidate_smoke_test.json").read_text())
    assert sorted(opened) == ["train.jsonl", "validation.jsonl"]
    assert smoke["affected_selection"] is False
    assert smoke["ran_after_selection_freeze"] is True
    assert smoke["passed"] is False
    assert smoke["prediction"]["is_anomaly"] is False
    assert not (model_root / "1.0.1-candidate").exists()
    assert not (experiment / "anomaly_frozen_test_metrics.json").exists()


def test_corrective_test_command_rejects_old_test_before_opening(tmp_path: Path) -> None:
    service, _, _, _, _ = anomaly_corrective_service(tmp_path)

    with pytest.raises(AnomalyArtifactError, match="new independent holdout"):
        service.evaluate_test(allow_controlled_demo=True)


def test_direction_b_creates_only_a_smoke_qualified_lof_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, _, _, model_root, experiment_root = anomaly_lof_candidate_service(tmp_path)
    from aegishunt.ml.supervised import data as supervised_data

    original = supervised_data.read_canonical_jsonl
    opened: list[str] = []

    def tracked(path: Path) -> tuple[object, ...]:
        opened.append(path.name)
        return original(path)  # type: ignore[return-value]

    monkeypatch.setattr(supervised_data, "read_canonical_jsonl", tracked)
    result = service.train(allow_controlled_demo=True)

    assert sorted(opened) == ["train.jsonl", "validation.jsonl"]
    assert result.selected_algorithm == "local_outlier_factor"
    assert result.status == "validation_qualified"
    assert result.candidate_smoke_passed is True
    assert result.selection.test_data_accessed is False
    bundle = model_root / "1.1.0-candidate"
    loaded = load_bundle(bundle, artifact_root=model_root)
    assert loaded.manifest.algorithm == "local_outlier_factor"
    assert loaded.estimator.named_steps["model"].novelty is True
    invalid_comparator = result.selection.lof_comparison.model_dump()
    invalid_comparator["status"] = "failed"
    with pytest.raises(ValidationError, match="complete and passed"):
        ComparatorResult.model_validate(invalid_comparator)

    invalid_selection = result.selection.model_dump()
    invalid_selection["status"] = "frozen"
    with pytest.raises(ValidationError, match="validation-qualified"):
        AnomalySelectionRecord.model_validate(invalid_selection)

    invalid_manifest = loaded.manifest.model_dump()
    invalid_manifest["status"] = "validated"
    with pytest.raises(ValidationError, match="frozen-test metrics"):
        AnomalyBundleManifest.model_validate(invalid_manifest)

    invalid_manifest = loaded.manifest.model_dump()
    invalid_manifest["untouched_independent_holdout_available"] = True
    with pytest.raises(ValidationError, match="evidence is incomplete"):
        AnomalyBundleManifest.model_validate(invalid_manifest)
    batch = AnomalyPredictionBatch(
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=feature_names(),
        dtype="float64",
        rows=(predefined_sample_anomaly(),),
    )
    first = score_batch(loaded, batch)[0]
    second = score_batch(loaded, batch)[0]
    assert first.is_anomaly is True
    assert first.model_dump(exclude={"scored_at"}) == second.model_dump(exclude={"scored_at"})
    experiment = experiment_root / result.experiment_id
    assert not (experiment / "anomaly_frozen_test_metrics.json").exists()
    smoke = json.loads((experiment / "candidate_smoke_test.json").read_text())
    assert smoke["passed"] is True
    assert smoke["independently_reloaded"] is True
    with pytest.raises(AnomalyArtifactError, match="new independent holdout"):
        service.evaluate_test(allow_controlled_demo=True)
    with pytest.raises(AnomalyArtifactError, match="already exists"):
        service.train(allow_controlled_demo=True)

    model_payload = (bundle / "model.skops").read_bytes()
    model_card = (bundle / "model_card.md").read_text(encoding="utf-8")
    wrong_algorithm = loaded.manifest.model_copy(
        update={"model_version": "wrong-algorithm", "algorithm": "isolation_forest"}
    )
    with pytest.raises(AnomalyArtifactError, match="component types"):
        save_bundle(model_root, wrong_algorithm, model_payload, model_card)
    assert not (model_root / "wrong-algorithm").exists()

    non_novelty = Pipeline(
        (("scale", StandardScaler()), ("model", LocalOutlierFactor(novelty=False)))
    )
    non_novelty_payload = estimator_bytes(non_novelty)
    non_novelty_manifest = loaded.manifest.model_copy(
        update={
            "model_version": "non-novelty",
            "artifact_checksum": sha256_bytes(non_novelty_payload),
            "trusted_types": trusted_types(non_novelty_payload),
        }
    )
    with pytest.raises(AnomalyArtifactError, match="novelty mode"):
        save_bundle(
            model_root,
            non_novelty_manifest,
            non_novelty_payload,
            model_card,
        )
    assert not (model_root / "non-novelty").exists()
