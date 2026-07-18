"""Exact-inventory, integrity-checked skops bundles for anomaly scoring."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import skops.io as sio
from pydantic import ValidationError
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from aegishunt.ml.anomaly.contracts import (
    AnomalyBundleChecksums,
    AnomalyBundleManifest,
    AnomalySelectionRecord,
)
from aegishunt.ml.anomaly.errors import AnomalyArtifactError

MODEL_FILENAME = "model.skops"
MANIFEST_FILENAME = "manifest.json"
CHECKSUMS_FILENAME = "checksums.json"
SELECTION_FILENAME = "selection.skops"
_BUNDLE_FILES = frozenset(
    {MODEL_FILENAME, MANIFEST_FILENAME, CHECKSUMS_FILENAME, "model_card.md"}
)
_ALLOWED_UNTRUSTED_TYPES: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class LoadedAnomalyModel:
    estimator: Pipeline
    manifest: AnomalyBundleManifest


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def estimator_bytes(estimator: Pipeline) -> bytes:
    try:
        payload = sio.dumps({"estimator": estimator})
    except (OSError, TypeError, ValueError) as exc:
        raise AnomalyArtifactError("anomaly estimator serialization failed") from exc
    if not isinstance(payload, bytes):
        raise AnomalyArtifactError("anomaly estimator serialization did not produce bytes")
    return payload


def trusted_types(payload: bytes) -> tuple[str, ...]:
    try:
        names = tuple(sorted(sio.get_untrusted_types(data=payload)))
    except (OSError, TypeError, ValueError) as exc:
        raise AnomalyArtifactError("unable to inspect anomaly estimator types") from exc
    if any(name not in _ALLOWED_UNTRUSTED_TYPES for name in names):
        raise AnomalyArtifactError("anomaly estimator contains a non-allowlisted type")
    return names


def _load_estimator(
    payload: bytes,
    *,
    expected_checksum: str,
    expected_trusted_types: tuple[str, ...],
) -> Pipeline:
    if sha256_bytes(payload) != expected_checksum:
        raise AnomalyArtifactError("anomaly model checksum verification failed")
    actual_types = trusted_types(payload)
    if actual_types != expected_trusted_types:
        raise AnomalyArtifactError("anomaly model type inventory verification failed")
    try:
        loaded: Any = sio.loads(payload, trusted=list(actual_types))
    except (OSError, TypeError, ValueError) as exc:
        raise AnomalyArtifactError("anomaly model cannot be safely loaded") from exc
    if not isinstance(loaded, dict) or set(loaded) != {"estimator"}:
        raise AnomalyArtifactError("anomaly model structure is invalid")
    estimator = loaded["estimator"]
    if not isinstance(estimator, Pipeline) or tuple(estimator.named_steps) != (
        "scale",
        "model",
    ):
        raise AnomalyArtifactError("anomaly model inference pipeline is invalid")
    if not isinstance(estimator.named_steps["scale"], StandardScaler) or not isinstance(
        estimator.named_steps["model"], IsolationForest
    ):
        raise AnomalyArtifactError("anomaly model component types are invalid")
    return estimator


def load_selection_artifact(
    experiment_dir: Path,
    selection: AnomalySelectionRecord,
) -> Pipeline:
    try:
        payload = (experiment_dir / SELECTION_FILENAME).read_bytes()
    except OSError as exc:
        raise AnomalyArtifactError("anomaly selection artifact is unavailable") from exc
    return _load_estimator(
        payload,
        expected_checksum=selection.selection_artifact_checksum,
        expected_trusted_types=selection.trusted_types,
    )


def _within(path: Path, root: Path) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise AnomalyArtifactError("anomaly bundle path is outside configured storage")
    return resolved


def save_bundle(
    artifact_root: Path,
    manifest: AnomalyBundleManifest,
    model_payload: bytes,
    model_card: str,
) -> Path:
    """Create a model-version directory atomically and reject every collision."""

    artifact_root.mkdir(parents=True, exist_ok=True)
    destination = artifact_root / manifest.model_version
    if destination.exists():
        raise AnomalyArtifactError("anomaly model version already exists")
    temporary = artifact_root / f".{manifest.model_version}.tmp-{os.getpid()}"
    if temporary.exists():
        raise AnomalyArtifactError("anomaly bundle staging path already exists")
    temporary.mkdir(mode=0o750)
    try:
        if sha256_bytes(model_payload) != manifest.artifact_checksum:
            raise AnomalyArtifactError("anomaly model payload differs from its manifest")
        manifest_payload = (manifest.model_dump_json(indent=2) + "\n").encode()
        card_payload = model_card.encode()
        checksums = AnomalyBundleChecksums(
            checksum_schema_version="1.0.0",
            model_checksum=sha256_bytes(model_payload),
            manifest_checksum=sha256_bytes(manifest_payload),
            model_card_checksum=sha256_bytes(card_payload),
        )
        (temporary / MODEL_FILENAME).write_bytes(model_payload)
        (temporary / MANIFEST_FILENAME).write_bytes(manifest_payload)
        (temporary / "model_card.md").write_bytes(card_payload)
        (temporary / CHECKSUMS_FILENAME).write_text(
            checksums.model_dump_json(indent=2) + "\n", encoding="utf-8"
        )
        temporary.rename(destination)
    except (OSError, AnomalyArtifactError) as exc:
        for child in temporary.iterdir() if temporary.exists() else ():
            child.unlink(missing_ok=True)
        temporary.rmdir() if temporary.exists() else None
        if isinstance(exc, AnomalyArtifactError):
            raise
        raise AnomalyArtifactError("unable to save anomaly model bundle") from exc
    return destination


def _read_verified_bundle(
    bundle_dir: Path,
    *,
    artifact_root: Path,
) -> tuple[AnomalyBundleManifest, bytes]:
    resolved = _within(bundle_dir, artifact_root)
    if resolved.suffix in {".pkl", ".pickle", ".joblib"} or not resolved.is_dir():
        raise AnomalyArtifactError("anomaly bundle must be a system-generated directory")
    if {path.name for path in resolved.iterdir()} != _BUNDLE_FILES:
        raise AnomalyArtifactError("anomaly bundle file inventory is invalid")
    try:
        manifest_payload = (resolved / MANIFEST_FILENAME).read_bytes()
        card_payload = (resolved / "model_card.md").read_bytes()
        checksums = AnomalyBundleChecksums.model_validate_json(
            (resolved / CHECKSUMS_FILENAME).read_text(encoding="utf-8")
        )
        if checksums.manifest_checksum != sha256_bytes(manifest_payload):
            raise AnomalyArtifactError("anomaly manifest checksum verification failed")
        if checksums.model_card_checksum != sha256_bytes(card_payload):
            raise AnomalyArtifactError("anomaly model-card checksum verification failed")
        manifest = AnomalyBundleManifest.model_validate_json(manifest_payload)
        payload = (resolved / MODEL_FILENAME).read_bytes()
    except AnomalyArtifactError:
        raise
    except (OSError, ValidationError) as exc:
        raise AnomalyArtifactError("anomaly bundle manifest or artifact is invalid") from exc
    if checksums.model_checksum != sha256_bytes(payload):
        raise AnomalyArtifactError("anomaly model checksum verification failed")
    if manifest.artifact_checksum != checksums.model_checksum:
        raise AnomalyArtifactError("anomaly manifest and checksum inventory differ")
    if resolved.name != manifest.model_version:
        raise AnomalyArtifactError("anomaly bundle directory differs from its version")
    return manifest, payload


def load_bundle(bundle_dir: Path, *, artifact_root: Path) -> LoadedAnomalyModel:
    manifest, payload = _read_verified_bundle(bundle_dir, artifact_root=artifact_root)
    estimator = _load_estimator(
        payload,
        expected_checksum=manifest.artifact_checksum,
        expected_trusted_types=manifest.trusted_types,
    )
    return LoadedAnomalyModel(estimator=estimator, manifest=manifest)


def load_manifest(bundle_dir: Path, *, artifact_root: Path) -> AnomalyBundleManifest:
    manifest, _ = _read_verified_bundle(bundle_dir, artifact_root=artifact_root)
    return manifest


def manifest_as_safe_json(manifest: AnomalyBundleManifest) -> str:
    return json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True)
