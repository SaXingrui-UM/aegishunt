"""Exact-inventory, checksummed, atomic data-only artifact I/O."""

from __future__ import annotations

import hashlib
import json
import os
import re
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from aegishunt.errors import DataArtifactError

CHECKSUMS_FILENAME = "checksums.json"
_VERSION_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")


def json_bytes(value: object) -> bytes:
    """Return canonical human-readable JSON bytes with stable key ordering."""

    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def configured_artifact_root(project_root: Path, configured_root: Path) -> Path:
    """Resolve one project-relative root without permitting symlink escape."""

    if configured_root.is_absolute() or ".." in configured_root.parts:
        raise DataArtifactError("artifact root must be project-relative")
    resolved_project = project_root.resolve()
    resolved_root = (resolved_project / configured_root).resolve()
    if not resolved_root.is_relative_to(resolved_project):
        raise DataArtifactError("artifact root escapes the project boundary")
    candidate = resolved_project
    for part in configured_root.parts:
        candidate /= part
        if candidate.is_symlink():
            raise DataArtifactError("artifact root cannot traverse a symlink")
    return resolved_root


def _validate_version(version: str) -> None:
    if not _VERSION_PATTERN.fullmatch(version):
        raise DataArtifactError("artifact version must be a safe identifier")


def write_data_artifact(
    *,
    root: Path,
    version: str,
    payloads: dict[str, bytes],
    exact_inventory: tuple[str, ...],
) -> Path:
    """Atomically create one non-overwriting data-only artifact directory."""

    _validate_version(version)
    expected = set(exact_inventory)
    if expected != set(payloads) | {CHECKSUMS_FILENAME} or len(expected) != len(
        exact_inventory
    ):
        raise DataArtifactError("artifact inventory declaration is inconsistent")
    if root.is_symlink():
        raise DataArtifactError("artifact root cannot be a symlink")
    try:
        root.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise DataArtifactError("artifact root is unavailable") from exc
    destination = root / version
    if destination.exists() or destination.is_symlink():
        raise DataArtifactError("artifact version already exists")
    staging = root / f".{version}.tmp-{os.getpid()}"
    if staging.exists() or staging.is_symlink():
        raise DataArtifactError("artifact staging path already exists")
    checksums = {
        "checksum_schema_version": "1.0.0",
        "checksums": {
            name: sha256_bytes(payload) for name, payload in sorted(payloads.items())
        },
    }
    complete = {**payloads, CHECKSUMS_FILENAME: json_bytes(checksums)}
    try:
        staging.mkdir(mode=0o750)
        for name, payload in complete.items():
            path = staging / name
            if path.name != name or path.parent != staging:
                raise DataArtifactError("artifact filename is unsafe")
            path.write_bytes(payload)
        staging.rename(destination)
    except DataArtifactError:
        _remove_staging(staging)
        raise
    except OSError as exc:
        _remove_staging(staging)
        raise DataArtifactError("artifact could not be written atomically") from exc
    return destination


def _remove_staging(staging: Path) -> None:
    if not staging.is_dir() or staging.is_symlink():
        return
    for path in staging.iterdir():
        if path.is_file() and not path.is_symlink():
            path.unlink(missing_ok=True)
    try:
        staging.rmdir()
    except OSError:
        return


def verify_data_artifact(
    path: Path,
    *,
    root: Path,
    exact_inventory: tuple[str, ...],
) -> dict[str, bytes]:
    """Load an exact regular-file inventory and reject corruption or escape."""

    if root.is_symlink():
        raise DataArtifactError("artifact root cannot be a symlink")
    resolved_root = root.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(resolved_root) or not resolved.is_dir():
        raise DataArtifactError("artifact is outside configured storage")
    try:
        entries = tuple(resolved.iterdir())
    except OSError as exc:
        raise DataArtifactError("artifact cannot be read") from exc
    if {entry.name for entry in entries} != set(exact_inventory):
        raise DataArtifactError("artifact inventory is invalid")
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise DataArtifactError("artifact inventory must contain regular files")
    try:
        payloads = {
            entry.name: entry.read_bytes()
            for entry in entries
            if entry.name != CHECKSUMS_FILENAME
        }
        checksums_raw = json.loads((resolved / CHECKSUMS_FILENAME).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DataArtifactError("artifact content is invalid") from exc
    if not isinstance(checksums_raw, dict) or checksums_raw.get(
        "checksum_schema_version"
    ) != "1.0.0":
        raise DataArtifactError("artifact checksum schema is invalid")
    checksums = checksums_raw.get("checksums")
    if not isinstance(checksums, dict) or set(checksums) != set(payloads):
        raise DataArtifactError("artifact checksum inventory is invalid")
    if any(checksums[name] != sha256_bytes(payload) for name, payload in payloads.items()):
        raise DataArtifactError("artifact checksum verification failed")
    return payloads


def verified_data_artifact_zip(
    path: Path,
    *,
    root: Path,
    exact_inventory: tuple[str, ...],
) -> bytes:
    """Return a deterministic ZIP only after the complete artifact verifies."""

    payloads = verify_data_artifact(
        path,
        root=root,
        exact_inventory=exact_inventory,
    )
    checksums = {
        "checksum_schema_version": "1.0.0",
        "checksums": {
            name: sha256_bytes(payload) for name, payload in sorted(payloads.items())
        },
    }
    complete = {**payloads, CHECKSUMS_FILENAME: json_bytes(checksums)}
    archive_buffer = BytesIO()
    with ZipFile(
        archive_buffer,
        mode="w",
        compression=ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        for name in sorted(exact_inventory):
            member = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.compress_type = ZIP_DEFLATED
            member.external_attr = 0o640 << 16
            archive.writestr(member, complete[name])
    return archive_buffer.getvalue()
