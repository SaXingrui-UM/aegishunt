"""Safe anomaly bundle and strict prediction contract tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegishunt.flows.registry import FEATURE_SCHEMA_VERSION, feature_names
from aegishunt.ml.anomaly.bundle import load_bundle, save_bundle
from aegishunt.ml.anomaly.errors import AnomalyArtifactError, AnomalyPredictionError
from aegishunt.ml.anomaly.prediction import AnomalyPredictionBatch, score_batch
from tests.fixtures.anomaly import anomaly_service


def _validated(tmp_path: Path) -> tuple[object, Path, Path]:
    service, data_root, _, model_root, _ = anomaly_service(tmp_path)
    service.train(allow_controlled_demo=True)
    service.evaluate_test(allow_controlled_demo=True)
    return service, data_root, model_root


def _batch(row: tuple[float, ...]) -> AnomalyPredictionBatch:
    return AnomalyPredictionBatch(
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        feature_names=feature_names(),
        dtype="float64",
        rows=(row,),
    )


def test_bundle_round_trip_preserves_raw_normalized_and_decision(tmp_path: Path) -> None:
    service, data_root, model_root = _validated(tmp_path)
    from aegishunt.datasets.io import read_canonical_jsonl

    row = read_canonical_jsonl(data_root / "validation.jsonl")[0]
    model = load_bundle(model_root / "1.0.0", artifact_root=model_root)
    first = score_batch(model, _batch(row.features.values))[0]
    second = service.predict("1.0.0", _batch(row.features.values))[0]  # type: ignore[attr-defined]

    assert first.raw_model_score == second.raw_model_score
    assert first.canonical_anomaly_score == second.canonical_anomaly_score
    assert first.normalized_anomaly_score == second.normalized_anomaly_score
    assert first.is_anomaly == second.is_anomaly
    assert first.canonical_anomaly_score == -first.raw_model_score
    assert 0.0 <= first.normalized_anomaly_score <= 1.0
    assert first.model_version == "1.0.0"


def test_prediction_rejects_schema_order_dtype_nonfinite_and_empty(tmp_path: Path) -> None:
    _, data_root, model_root = _validated(tmp_path)
    from aegishunt.datasets.io import read_canonical_jsonl

    row = read_canonical_jsonl(data_root / "validation.jsonl")[0]
    model = load_bundle(model_root / "1.0.0", artifact_root=model_root)
    with pytest.raises(AnomalyPredictionError, match="schema version"):
        score_batch(
            model,
            _batch(row.features.values).model_copy(
                update={"feature_schema_version": "99.0.0"}
            ),
        )
    with pytest.raises(AnomalyPredictionError, match="names or order"):
        score_batch(
            model,
            _batch(row.features.values).model_copy(
                update={"feature_names": tuple(reversed(feature_names()))}
            ),
        )
    with pytest.raises(AnomalyPredictionError, match="dtype"):
        score_batch(
            model,
            _batch(row.features.values).model_copy(update={"dtype": "float32"}),  # type: ignore[dict-item]
        )
    with pytest.raises(ValueError, match="finite"):
        AnomalyPredictionBatch(
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_names=feature_names(),
            dtype="float64",
            rows=(tuple(float("nan") for _ in feature_names()),),
        )
    with pytest.raises(ValueError, match="empty"):
        AnomalyPredictionBatch(
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            feature_names=feature_names(),
            dtype="float64",
            rows=(),
        )


def test_prediction_contract_rejects_metadata_and_has_no_phase7_fields() -> None:
    payload = {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": feature_names(),
        "dtype": "float64",
        "rows": [tuple(0.0 for _ in feature_names())],
        "group_id": "must-not-enter-model",
    }
    with pytest.raises(ValueError, match="Extra inputs"):
        AnomalyPredictionBatch.model_validate(payload)


def test_bundle_rejects_extra_missing_corrupt_and_unsafe_artifacts(tmp_path: Path) -> None:
    _, _, model_root = _validated(tmp_path)
    bundle = model_root / "1.0.0"

    extra = bundle / "unexpected.txt"
    extra.write_text("unexpected", encoding="utf-8")
    with pytest.raises(AnomalyArtifactError, match="inventory"):
        load_bundle(bundle, artifact_root=model_root)
    extra.unlink()

    checksums = bundle / "checksums.json"
    original_checksums = checksums.read_bytes()
    checksums.unlink()
    with pytest.raises(AnomalyArtifactError, match="inventory"):
        load_bundle(bundle, artifact_root=model_root)
    checksums.write_bytes(original_checksums)

    model_path = bundle / "model.skops"
    original_model = model_path.read_bytes()
    model_path.write_bytes(original_model + b"corrupt")
    with pytest.raises(AnomalyArtifactError, match="checksum"):
        load_bundle(bundle, artifact_root=model_root)
    model_path.write_bytes(original_model)

    unsafe = model_root / "arbitrary.joblib"
    unsafe.write_bytes(b"not trusted")
    with pytest.raises(AnomalyArtifactError, match="system-generated"):
        load_bundle(unsafe, artifact_root=model_root)
    with pytest.raises(AnomalyArtifactError, match="outside configured"):
        load_bundle(tmp_path / "outside", artifact_root=model_root)


def test_bundle_refuses_model_version_collision(tmp_path: Path) -> None:
    _, _, model_root = _validated(tmp_path)
    loaded = load_bundle(model_root / "1.0.0", artifact_root=model_root)
    bundle = model_root / "1.0.0"

    with pytest.raises(AnomalyArtifactError, match="version already exists"):
        save_bundle(
            model_root,
            loaded.manifest,
            (bundle / "model.skops").read_bytes(),
            (bundle / "model_card.md").read_text(encoding="utf-8"),
        )
