"""Exact-inventory, non-overwriting JSON explanation artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from pydantic import BaseModel, ValidationError

from aegishunt.detection.errors import DetectionArtifactError
from aegishunt.explainability.contracts import (
    ExplanationArtifactChecksums,
    ExplanationArtifactManifest,
    GlobalImportanceReport,
    LoadedExplanationArtifact,
    PermutationImportanceReport,
    ReasonCodeCatalog,
    ReferenceProfile,
)

REFERENCE_FILENAME = "reference_profile.json"
NATIVE_IMPORTANCE_FILENAME = "global_importance.json"
PERMUTATION_IMPORTANCE_FILENAME = "permutation_importance.json"
CATALOG_FILENAME = "reason_code_catalog.json"
MANIFEST_FILENAME = "manifest.json"
CHECKSUMS_FILENAME = "checksums.json"
PROTOCOL_FILENAME = "explanation_protocol.md"
ARTIFACT_FILES = frozenset(
    {
        REFERENCE_FILENAME,
        NATIVE_IMPORTANCE_FILENAME,
        PERMUTATION_IMPORTANCE_FILENAME,
        CATALOG_FILENAME,
        MANIFEST_FILENAME,
        CHECKSUMS_FILENAME,
        PROTOCOL_FILENAME,
    }
)
CHECKSUMMED_FILES = ARTIFACT_FILES - {CHECKSUMS_FILENAME}


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _json_bytes(value: object) -> bytes:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def save_explanation_artifact(
    *,
    root: Path,
    manifest: ExplanationArtifactManifest,
    reference_profile: ReferenceProfile,
    native_importance: GlobalImportanceReport,
    permutation_importance: PermutationImportanceReport,
    reason_catalog: ReasonCodeCatalog,
    protocol: str,
) -> Path:
    """Write one new artifact version atomically; never replace an existing one."""

    if root.is_symlink():
        raise DetectionArtifactError("explanation artifact root cannot be a symlink")
    if manifest.file_inventory != tuple(sorted(ARTIFACT_FILES)):
        raise DetectionArtifactError("explanation artifact inventory declaration is invalid")
    _validate_cross_fields(
        manifest,
        reference_profile,
        native_importance,
        permutation_importance,
        reason_catalog,
    )
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DetectionArtifactError("explanation artifact root is unavailable") from exc
    destination = root / manifest.artifact_version
    if destination.exists() or destination.is_symlink():
        raise DetectionArtifactError("explanation artifact version already exists")
    staging = root / f".{manifest.artifact_version}.tmp-{os.getpid()}"
    if staging.exists():
        raise DetectionArtifactError("explanation artifact staging path already exists")
    payloads = {
        REFERENCE_FILENAME: _json_bytes(reference_profile),
        NATIVE_IMPORTANCE_FILENAME: _json_bytes(native_importance),
        PERMUTATION_IMPORTANCE_FILENAME: _json_bytes(permutation_importance),
        CATALOG_FILENAME: _json_bytes(reason_catalog),
        MANIFEST_FILENAME: _json_bytes(manifest),
        PROTOCOL_FILENAME: protocol.encode(),
    }
    checksums = ExplanationArtifactChecksums(
        checksum_schema_version="1.0.0",
        checksums={name: sha256_bytes(payload) for name, payload in payloads.items()},
    )
    payloads[CHECKSUMS_FILENAME] = _json_bytes(checksums)
    try:
        staging.mkdir(mode=0o750)
        for name, payload in payloads.items():
            (staging / name).write_bytes(payload)
        staging.rename(destination)
    except OSError as exc:
        if staging.exists():
            for path in staging.iterdir():
                path.unlink(missing_ok=True)
            staging.rmdir()
        raise DetectionArtifactError("unable to save explanation artifact") from exc
    return destination


def load_explanation_artifact(path: Path, *, root: Path) -> LoadedExplanationArtifact:
    """Reject escaped, symlinked, missing, extra, corrupt, or mismatched artifacts."""

    if root.is_symlink():
        raise DetectionArtifactError("explanation artifact root cannot be a symlink")
    resolved_root = root.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(resolved_root):
        raise DetectionArtifactError("explanation artifact is outside configured storage")
    if resolved.suffix in {".pkl", ".pickle", ".joblib", ".skops"} or not resolved.is_dir():
        raise DetectionArtifactError("explanation artifact must be a data-only directory")
    try:
        entries = tuple(resolved.iterdir())
    except OSError as exc:
        raise DetectionArtifactError("unable to read explanation artifact") from exc
    if {item.name for item in entries} != ARTIFACT_FILES:
        raise DetectionArtifactError("explanation artifact inventory is invalid")
    if any(item.is_symlink() or not item.is_file() for item in entries):
        raise DetectionArtifactError("explanation artifact must contain regular files")
    try:
        payloads = {name: (resolved / name).read_bytes() for name in CHECKSUMMED_FILES}
        checksums = ExplanationArtifactChecksums.model_validate_json(
            (resolved / CHECKSUMS_FILENAME).read_bytes()
        )
        if set(checksums.checksums) != CHECKSUMMED_FILES:
            raise DetectionArtifactError("explanation checksum inventory is invalid")
        for name, payload in payloads.items():
            if checksums.checksums[name] != sha256_bytes(payload):
                raise DetectionArtifactError("explanation artifact checksum failed")
        manifest = ExplanationArtifactManifest.model_validate_json(payloads[MANIFEST_FILENAME])
        reference = ReferenceProfile.model_validate_json(payloads[REFERENCE_FILENAME])
        native = GlobalImportanceReport.model_validate_json(
            payloads[NATIVE_IMPORTANCE_FILENAME]
        )
        permutation = PermutationImportanceReport.model_validate_json(
            payloads[PERMUTATION_IMPORTANCE_FILENAME]
        )
        catalog = ReasonCodeCatalog.model_validate_json(payloads[CATALOG_FILENAME])
        protocol = payloads[PROTOCOL_FILENAME].decode()
    except DetectionArtifactError:
        raise
    except (OSError, UnicodeDecodeError, ValidationError) as exc:
        raise DetectionArtifactError("explanation artifact content is invalid") from exc
    if resolved.name != manifest.artifact_version:
        raise DetectionArtifactError("explanation artifact directory/version mismatch")
    _validate_cross_fields(manifest, reference, native, permutation, catalog)
    return LoadedExplanationArtifact(
        manifest=manifest,
        reference_profile=reference,
        native_importance=native,
        permutation_importance=permutation,
        reason_catalog=catalog,
        protocol=protocol,
    )


def _validate_cross_fields(
    manifest: ExplanationArtifactManifest,
    reference: ReferenceProfile,
    native: GlobalImportanceReport,
    permutation: PermutationImportanceReport,
    catalog: ReasonCodeCatalog,
) -> None:
    actual = (
        reference.profile_id,
        reference.profile_version,
        native.report_id,
        permutation.report_id,
        catalog.catalog_id,
        catalog.catalog_version,
        reference.feature_schema_version,
        native.feature_schema_version,
        permutation.feature_schema_version,
        reference.feature_names,
        native.feature_names,
        permutation.feature_names,
    )
    expected = (
        manifest.reference_profile_id,
        manifest.reference_profile_version,
        manifest.native_importance_report_id,
        manifest.permutation_importance_report_id,
        manifest.reason_catalog_id,
        manifest.reason_catalog_version,
        manifest.feature_schema_version,
        manifest.feature_schema_version,
        manifest.feature_schema_version,
        reference.feature_names,
        reference.feature_names,
        reference.feature_names,
    )
    if actual != expected:
        raise DetectionArtifactError("explanation artifact identities are inconsistent")
    if native.model_id != manifest.supervised_model_id or native.model_version != (
        manifest.supervised_model_version
    ):
        raise DetectionArtifactError("native importance model identity is inconsistent")
    if permutation.model_id != manifest.supervised_model_id or permutation.model_version != (
        manifest.supervised_model_version
    ):
        raise DetectionArtifactError("permutation importance model identity is inconsistent")
