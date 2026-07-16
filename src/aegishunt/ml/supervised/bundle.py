"""Integrity-checked skops persistence for selected supervised pipelines."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import skops.io as sio
from pydantic import ValidationError
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from aegishunt.ml.supervised.calibration import ProbabilityCalibrator
from aegishunt.ml.supervised.contracts import (
    BundleChecksums,
    BundleManifest,
    ModelSelectionRecord,
)
from aegishunt.ml.supervised.errors import ArtifactError
from aegishunt.ml.supervised.selection import FittedCandidate

MODEL_FILENAME = "model.skops"
MANIFEST_FILENAME = "manifest.json"
BUNDLE_CHECKSUMS_FILENAME = "checksums.json"
SELECTION_FILENAME = "selection.skops"
_ALLOWED_UNTRUSTED_TYPES = frozenset(
    {
        "sklearn._loss.link.Interval",
        "sklearn._loss.link.LogitLink",
        "sklearn._loss.loss.HalfBinomialLoss",
        "sklearn.ensemble._hist_gradient_boosting.binning._BinMapper",
        "sklearn.ensemble._hist_gradient_boosting.predictor.TreePredictor",
    }
)
_BUNDLE_FILES = frozenset(
    {MODEL_FILENAME, MANIFEST_FILENAME, BUNDLE_CHECKSUMS_FILENAME, "model_card.md"}
)


@dataclass(frozen=True, slots=True)
class LoadedModel:
    """Validated inference components and immutable bundle metadata."""

    estimator: Pipeline
    calibrator: ProbabilityCalibrator
    manifest: BundleManifest


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def candidate_bytes(candidate: FittedCandidate) -> bytes:
    """Serialize the fitted estimator and validation-fitted calibrator together."""

    payload = {
        "estimator": candidate.estimator,
        "calibration_method": candidate.calibrator.method,
        "calibration_estimator": candidate.calibrator.estimator,
    }
    try:
        serialized = sio.dumps(payload)
    except (OSError, TypeError, ValueError) as exc:
        raise ArtifactError("selected model serialization failed") from exc
    if not isinstance(serialized, bytes):
        raise ArtifactError("selected model serialization did not produce bytes")
    return serialized


def trusted_types(payload: bytes) -> tuple[str, ...]:
    """Return a stable allowlist discovered from one system-generated skops artifact."""

    try:
        names = tuple(sorted(sio.get_untrusted_types(data=payload)))
    except (OSError, TypeError, ValueError) as exc:
        raise ArtifactError("unable to inspect selected model types") from exc
    if any(name not in _ALLOWED_UNTRUSTED_TYPES for name in names):
        raise ArtifactError("selected model contains a non-allowlisted type")
    return names


def _load_components(
    payload: bytes,
    *,
    expected_checksum: str,
    expected_trusted_types: tuple[str, ...],
    calibration_method: Literal["sigmoid", "isotonic"],
) -> tuple[Pipeline, ProbabilityCalibrator]:
    if sha256_bytes(payload) != expected_checksum:
        raise ArtifactError("model artifact checksum verification failed")
    actual_types = trusted_types(payload)
    if actual_types != expected_trusted_types:
        raise ArtifactError("model artifact type inventory verification failed")
    try:
        loaded: Any = sio.loads(payload, trusted=list(actual_types))
    except (OSError, TypeError, ValueError) as exc:
        raise ArtifactError("model artifact cannot be safely loaded") from exc
    if not isinstance(loaded, dict) or set(loaded) != {
        "estimator",
        "calibration_method",
        "calibration_estimator",
    }:
        raise ArtifactError("model artifact structure is invalid")
    estimator = loaded["estimator"]
    stored_method = loaded["calibration_method"]
    calibration_estimator = loaded["calibration_estimator"]
    if not isinstance(estimator, Pipeline) or stored_method != calibration_method:
        raise ArtifactError("model artifact inference contract is invalid")
    if calibration_method == "sigmoid" and not isinstance(
        calibration_estimator, LogisticRegression
    ):
        raise ArtifactError("model artifact sigmoid calibrator is invalid")
    if calibration_method == "isotonic" and not isinstance(
        calibration_estimator, IsotonicRegression
    ):
        raise ArtifactError("model artifact isotonic calibrator is invalid")
    return estimator, ProbabilityCalibrator(calibration_method, calibration_estimator)


def load_selection_artifact(
    experiment_dir: Path,
    selection: ModelSelectionRecord,
) -> tuple[Pipeline, ProbabilityCalibrator]:
    """Load only the fixed, checksummed system selection artifact."""

    artifact = experiment_dir / SELECTION_FILENAME
    try:
        payload = artifact.read_bytes()
    except OSError as exc:
        raise ArtifactError("selection artifact is unavailable") from exc
    return _load_components(
        payload,
        expected_checksum=selection.selection_artifact_checksum,
        expected_trusted_types=selection.trusted_types,
        calibration_method=selection.calibration_method,
    )


def _within(path: Path, root: Path) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise ArtifactError("model bundle path is outside configured storage")
    return resolved


def save_bundle(
    artifact_root: Path,
    manifest: BundleManifest,
    model_payload: bytes,
    model_card: str,
) -> Path:
    """Create one version directory atomically and refuse collisions."""

    artifact_root.mkdir(parents=True, exist_ok=True)
    destination = artifact_root / manifest.model_version
    if destination.exists():
        raise ArtifactError("model version already exists")
    temporary = artifact_root / f".{manifest.model_version}.tmp-{os.getpid()}"
    if temporary.exists():
        raise ArtifactError("model bundle staging path already exists")
    temporary.mkdir(mode=0o750)
    try:
        if sha256_bytes(model_payload) != manifest.artifact_checksum:
            raise ArtifactError("model bundle payload does not match its manifest")
        manifest_payload = (manifest.model_dump_json(indent=2) + "\n").encode("utf-8")
        model_card_payload = model_card.encode("utf-8")
        checksums = BundleChecksums(
            checksum_schema_version="1.0.0",
            model_checksum=sha256_bytes(model_payload),
            manifest_checksum=sha256_bytes(manifest_payload),
            model_card_checksum=sha256_bytes(model_card_payload),
        )
        (temporary / MODEL_FILENAME).write_bytes(model_payload)
        (temporary / MANIFEST_FILENAME).write_bytes(manifest_payload)
        (temporary / "model_card.md").write_bytes(model_card_payload)
        (temporary / BUNDLE_CHECKSUMS_FILENAME).write_text(
            checksums.model_dump_json(indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.rename(destination)
    except (OSError, ArtifactError) as exc:
        for child in temporary.iterdir() if temporary.exists() else ():
            child.unlink(missing_ok=True)
        temporary.rmdir() if temporary.exists() else None
        if isinstance(exc, ArtifactError):
            raise
        raise ArtifactError("unable to save model bundle") from exc
    return destination


def _read_verified_bundle(
    bundle_dir: Path,
    *,
    artifact_root: Path,
) -> tuple[BundleManifest, bytes]:
    resolved = _within(bundle_dir, artifact_root)
    if resolved.suffix in {".pkl", ".pickle", ".joblib"} or not resolved.is_dir():
        raise ArtifactError("model bundle must be a system-generated directory")
    if {path.name for path in resolved.iterdir()} != _BUNDLE_FILES:
        raise ArtifactError("model bundle file inventory is invalid")
    try:
        manifest_payload = (resolved / MANIFEST_FILENAME).read_bytes()
        model_card_payload = (resolved / "model_card.md").read_bytes()
        checksums = BundleChecksums.model_validate_json(
            (resolved / BUNDLE_CHECKSUMS_FILENAME).read_text(encoding="utf-8")
        )
        if checksums.manifest_checksum != sha256_bytes(manifest_payload):
            raise ArtifactError("model bundle manifest checksum verification failed")
        if checksums.model_card_checksum != sha256_bytes(model_card_payload):
            raise ArtifactError("model card checksum verification failed")
        manifest = BundleManifest.model_validate_json(
            manifest_payload
        )
        payload = (resolved / MODEL_FILENAME).read_bytes()
    except ArtifactError:
        raise
    except (OSError, ValidationError) as exc:
        raise ArtifactError("model bundle manifest or artifact is invalid") from exc
    if checksums.model_checksum != sha256_bytes(payload):
        raise ArtifactError("model artifact checksum verification failed")
    if manifest.artifact_checksum != checksums.model_checksum:
        raise ArtifactError("model manifest and outer checksum inventory differ")
    if resolved.name != manifest.model_version:
        raise ArtifactError("model bundle directory does not match its version")
    return manifest, payload


def load_bundle(bundle_dir: Path, *, artifact_root: Path) -> LoadedModel:
    """Load a configured bundle only after path, manifest, checksum, and type checks."""

    manifest, payload = _read_verified_bundle(bundle_dir, artifact_root=artifact_root)
    estimator, calibrator = _load_components(
        payload,
        expected_checksum=manifest.artifact_checksum,
        expected_trusted_types=manifest.trusted_types,
        calibration_method=manifest.calibration_method,
    )
    return LoadedModel(estimator=estimator, calibrator=calibrator, manifest=manifest)


def load_manifest(bundle_dir: Path, *, artifact_root: Path) -> BundleManifest:
    """Read metadata after verifying the complete bundle without loading model state."""

    manifest, _ = _read_verified_bundle(bundle_dir, artifact_root=artifact_root)
    return manifest


def manifest_as_safe_json(manifest: BundleManifest) -> str:
    """Provide stable CLI metadata without filesystem locations."""

    return json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True)
