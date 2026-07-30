"""Exact-inventory manifest for a reproducible AegisHunt release directory."""

from __future__ import annotations

import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Any

from aegishunt.metadata import __version__

RELEASE_MANIFEST_FILENAME = "release-manifest.json"
RELEASE_SCHEMA_VERSION = "1.0.0"


class ReleaseManifestError(ValueError):
    """Raised when a final-delivery bundle violates its trust contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(65_536):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_files(root: Path) -> tuple[Path, ...]:
    if root.is_symlink() or not root.is_dir():
        raise ReleaseManifestError("release bundle root must be a regular directory")
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ReleaseManifestError("release bundle cannot contain symlinks")
        if path.is_file():
            files.append(path)
        elif not path.is_dir():
            raise ReleaseManifestError("release bundle contains an unsupported entry")
    return tuple(files)


def build_release_manifest(
    root: Path,
    *,
    git_commit: str,
    generated_at: str,
    database_schema: int,
    demo_models: tuple[dict[str, str], ...],
) -> dict[str, Any]:
    """Build deterministic metadata for all pre-existing bundle files."""

    resolved = root.resolve()
    inventory = []
    for path in _regular_files(resolved):
        relative = path.relative_to(resolved).as_posix()
        if relative == RELEASE_MANIFEST_FILENAME:
            continue
        content_type = mimetypes.guess_type(relative)[0] or "application/octet-stream"
        inventory.append(
            {
                "path": relative,
                "size_bytes": path.stat().st_size,
                "sha256": _sha256(path),
                "content_type": content_type,
                "source": "committed" if relative.startswith("project/") else "generated",
            }
        )
    return {
        "release_schema_version": RELEASE_SCHEMA_VERSION,
        "application_version": __version__,
        "git_commit": git_commit,
        "generated_at": generated_at,
        "python_compatibility": ["3.11", "3.12"],
        "database_schema": database_schema,
        "demo_models": list(demo_models),
        "artifact_inventory": inventory,
        "known_limitations": [
            "local single-node SQLite research prototype",
            "no authentication, authorization, TLS termination, or live capture",
            "controlled demo artifacts only; not a benchmark or production validation",
            "final formal Codex Security rescan was explicitly waived and not executed",
        ],
        "verification_commands": [
            "python scripts/build_release_bundle.py verify <bundle>",
            "python -m pip install wheel/*.whl",
            "aegishunt doctor",
        ],
    }


def write_release_manifest(root: Path, manifest: dict[str, Any]) -> Path:
    """Write the canonical manifest after the inventory is complete."""

    destination = root / RELEASE_MANIFEST_FILENAME
    if destination.exists() or destination.is_symlink():
        raise ReleaseManifestError("release manifest already exists")
    destination.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def verify_release_bundle(root: Path) -> dict[str, Any]:
    """Reject missing, additional, corrupt, linked, or version-mismatched files."""

    resolved = root.resolve()
    files = _regular_files(resolved)
    manifest_path = resolved / RELEASE_MANIFEST_FILENAME
    if manifest_path not in files:
        raise ReleaseManifestError("release manifest is missing")
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseManifestError("release manifest is invalid") from exc
    if not isinstance(payload, dict):
        raise ReleaseManifestError("release manifest root must be an object")
    if payload.get("release_schema_version") != RELEASE_SCHEMA_VERSION:
        raise ReleaseManifestError("release manifest schema is unsupported")
    if payload.get("application_version") != __version__:
        raise ReleaseManifestError("release application version does not match runtime")
    inventory = payload.get("artifact_inventory")
    if not isinstance(inventory, list) or not inventory:
        raise ReleaseManifestError("release artifact inventory is invalid")
    records: dict[str, dict[str, Any]] = {}
    for item in inventory:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ReleaseManifestError("release artifact record is invalid")
        declared_path = Path(item["path"])
        if (
            declared_path.is_absolute()
            or ".." in declared_path.parts
            or declared_path.as_posix() == RELEASE_MANIFEST_FILENAME
            or declared_path.as_posix() in records
        ):
            raise ReleaseManifestError("release artifact path is unsafe or duplicated")
        records[declared_path.as_posix()] = item
    actual = {
        path.relative_to(resolved).as_posix()
        for path in files
        if path != manifest_path
    }
    if actual != set(records):
        raise ReleaseManifestError("release artifact inventory is not exact")
    for relative, record in records.items():
        path = resolved / relative
        if path.stat().st_size != record.get("size_bytes"):
            raise ReleaseManifestError("release artifact size verification failed")
        if _sha256(path) != record.get("sha256"):
            raise ReleaseManifestError("release artifact checksum verification failed")
    return payload
