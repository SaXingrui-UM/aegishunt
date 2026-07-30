"""Build or verify one non-overwriting AegisHunt final-delivery directory."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, func, select

from aegishunt.delivery.release_manifest import (
    ReleaseManifestError,
    build_release_manifest,
    verify_release_bundle,
    write_release_manifest,
)
from aegishunt.detection.config import load_risk_policy
from aegishunt.metadata import __version__
from aegishunt.storage import models as storage_models
from aegishunt.storage.base import Base
from aegishunt.storage.schema_version import CURRENT_SCHEMA_VERSION

_STORAGE_MODELS_REGISTERED = storage_models

PROJECT_FILES = (
    "README.md",
    "Dockerfile",
    ".dockerignore",
    "compose.yaml",
    "pyproject.toml",
    "Makefile",
)
PROJECT_TREES = (
    "configs",
    "data/sample",
    "docs",
)
EXCLUDED_NAMES = {".DS_Store", "__pycache__"}
EXCLUDED_SUFFIXES = {
    ".db",
    ".joblib",
    ".pcap",
    ".pcapng",
    ".pkl",
    ".pyc",
    ".skops",
    ".sqlite",
    ".sqlite3",
}
ALLOWED_SAMPLE_PCAPS = {
    "phase2-benign.pcap",
    "phase12-demo.pcap",
    "phase12-presentation-demo.pcap",
    "phase14-attack-like.pcap",
    "phase14-benign-like.pcap",
}
RELEASE_EXCLUDED_DOCUMENTS = {
    "phase-00-12-demo-validation.md",
    "phase-12-demo-readiness-corrective-validation.md",
}


def _git(project: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=project,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _copy_file(
    source: Path,
    destination: Path,
    *,
    allow_demo_model: bool = False,
) -> None:
    if source.is_symlink() or not source.is_file():
        raise ReleaseManifestError("release source must be a regular file")
    allowed_exception = (
        allow_demo_model and source.suffix.lower() == ".skops"
    ) or (
        source.suffix.lower() == ".pcap" and source.name in ALLOWED_SAMPLE_PCAPS
    )
    if (
        source.name in EXCLUDED_NAMES
        or source.suffix.lower() in EXCLUDED_SUFFIXES
    ) and not allowed_exception:
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)


def _copy_tree(
    source: Path,
    destination: Path,
    *,
    excluded_relative: set[str] | None = None,
) -> None:
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source).as_posix()
        if excluded_relative is not None and relative in excluded_relative:
            continue
        if path.is_symlink():
            raise ReleaseManifestError("release source tree cannot contain symlinks")
        if path.is_file():
            _copy_file(path, destination / relative)


def _copy_demo_tree(source: Path, destination: Path) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ReleaseManifestError("demo artifact tree cannot contain symlinks")
        if path.is_file():
            _copy_file(
                path,
                destination / path.relative_to(source),
                allow_demo_model=True,
            )


def _find_distribution(project: Path, suffix: str) -> Path:
    candidates = tuple(sorted((project / "dist").glob(f"aegishunt-*{suffix}")))
    if len(candidates) != 1:
        raise ReleaseManifestError(f"exactly one {suffix} distribution is required")
    return candidates[0]


def _sqlite_metadata(database: Path) -> dict[str, Any]:
    connection = sqlite3.connect(database)
    try:
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
    finally:
        connection.close()
    engine = create_engine(f"sqlite:///{database}")
    try:
        with engine.connect() as typed_connection:
            counts = {
                table.name: int(
                    typed_connection.execute(
                        select(func.count()).select_from(table)
                    ).scalar_one()
                )
                for table in Base.metadata.sorted_tables
            }
    finally:
        engine.dispose()
    if integrity != ("ok",):
        raise ReleaseManifestError("sample database integrity check failed")
    return {
        "synthetic": True,
        "controlled_demo_only": True,
        "schema_version": CURRENT_SCHEMA_VERSION,
        "wal_checkpoint": list(checkpoint or ()),
        "row_counts": counts,
        "limitations": [
            "not user data",
            "not a benchmark or production validation",
            "contains only controlled sample-demo records",
        ],
    }


def _demo_identities(root: Path) -> tuple[dict[str, str], ...]:
    """Read versioned identities from the copied, verified demo workspace."""

    records = []
    for kind, relative in (
        ("supervised", "models/supervised/12.0.0/manifest.json"),
        ("anomaly", "models/anomaly/1.1.0-candidate/manifest.json"),
        ("fusion", "models/fusion/1.0.0/fusion_policy_manifest.json"),
        ("explainability", "models/explainability/1.0.0/manifest.json"),
    ):
        path = root / relative
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReleaseManifestError("demo artifact manifest is unavailable") from exc
        if not isinstance(payload, dict):
            raise ReleaseManifestError("demo artifact manifest is invalid")
        identifier = payload.get("model_id") or payload.get("policy_id") or payload.get(
            "artifact_id"
        )
        version = payload.get("model_version") or payload.get("policy_version") or payload.get(
            "artifact_version"
        )
        if not isinstance(identifier, str) or not isinstance(version, str):
            raise ReleaseManifestError("demo artifact identity is incomplete")
        records.append(
            {
                "kind": kind,
                "id": identifier,
                "version": version,
                "classification": "controlled_demo_only",
                "manifest_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    risk_path = root / "configs/detection.yaml"
    risk = load_risk_policy(risk_path)
    records.append(
        {
            "kind": "risk",
            "id": risk.policy.policy_id,
            "version": risk.policy.policy_version,
            "classification": "controlled_demo_only",
            "manifest_sha256": risk.configuration_checksum,
        }
    )
    return tuple(records)


def _verify_demo_models(root: Path) -> None:
    """Load both copied model binaries in a new process through safe loaders."""

    code = """
from pathlib import Path
import sys
from aegishunt.ml.supervised.bundle import load_bundle as load_supervised
from aegishunt.ml.anomaly.bundle import load_bundle as load_anomaly
from aegishunt.ml.fusion.artifacts import load_policy
from aegishunt.detection.config import load_risk_policy
from aegishunt.explainability.artifacts import load_explanation_artifact
root = Path(sys.argv[1])
supervised_root = root / "models/supervised"
anomaly_root = root / "models/anomaly"
fusion_root = root / "models/fusion"
explanation_root = root / "models/explainability"
assert load_supervised(
    supervised_root / "12.0.0", artifact_root=supervised_root
).manifest.pipeline_verification_only is True
anomaly = load_anomaly(
    anomaly_root / "1.1.0-candidate", artifact_root=anomaly_root
)
assert anomaly.manifest.pipeline_verification_only is True
assert anomaly.manifest.status == "validation_qualified"
assert load_policy(
    fusion_root / "1.0.0", root=fusion_root
).recommendation == "inconclusive"
assert load_risk_policy(
    root / "configs/detection.yaml"
).policy.controlled_pipeline_only is True
assert load_explanation_artifact(
    explanation_root / "1.0.0", root=explanation_root
).manifest.pipeline_verification_only is True
"""
    subprocess.run(
        [sys.executable, "-c", code, str(root)],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def _build_sample_database(
    project: Path,
    destination: Path,
    demo_destination: Path,
) -> tuple[dict[str, str], ...]:
    """Run the explicit controlled demo and export its DB and isolated models."""

    temporary_parent = project / "tmp"
    temporary_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="aegishunt-release-db-",
        dir=temporary_parent,
    ) as temporary:
        temporary_root = Path(temporary)
        database = Path(temporary) / "sample.sqlite3"
        relative_root = temporary_root.relative_to(project) / "demo-artifacts"
        environment = {
            "AEGISHUNT_CONFIG": str(project / "configs/final-delivery.yaml"),
            "AEGISHUNT_DATABASE_URL": f"sqlite:///{database}",
            "AEGISHUNT_WEB__DEMO_ARTIFACT_ROOT": relative_root.as_posix(),
            "AEGISHUNT_WEB__DEMO_NAMESPACE": "phase14-controlled-demo",
            "AEGISHUNT_WEB__DEMO_OPERATION_VERSION": "1.0.0",
        }
        process_environment = {**os.environ, **environment}
        for sample_id in (
            "phase14-attack-like-pcap",
            "phase14-benign-like-pcap",
        ):
            subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "aegishunt.cli",
                    "demo",
                    "run",
                    "--sample-id",
                    sample_id,
                    "--actor",
                    "phase14-release-builder",
                    "--reason",
                    "explicit controlled final-delivery demonstration",
                    "--confirm",
                ],
                cwd=project,
                env=process_environment,
                check=True,
                capture_output=True,
                text=True,
            )
        metadata = _sqlite_metadata(database)
        metadata["generator_commit"] = _git(project, "rev-parse", "HEAD")
        metadata["sample_asset_ids"] = [
            "phase14-attack-like-pcap",
            "phase14-benign-like-pcap",
        ]
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(database, destination)
        destination.with_suffix(".manifest.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        built_demo = (
            project
            / relative_root
            / "phase14-controlled-demo-1.0.0"
        )
        if not built_demo.is_dir():
            raise ReleaseManifestError("controlled demo artifacts were not generated")
        _copy_demo_tree(built_demo, demo_destination)
        _verify_demo_models(demo_destination)
        return _demo_identities(demo_destination)


def _validate_no_local_identity(root: Path, project: Path) -> None:
    """Reject release files that expose this workstation or build workspace."""

    forbidden = {
        project.resolve().as_posix().encode(),
        Path.home().resolve().as_posix().encode(),
    }
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        payload = path.read_bytes()
        if any(value and value in payload for value in forbidden):
            raise ReleaseManifestError("release artifact contains a local absolute path")


def build(project: Path, output_root: Path) -> Path:
    """Create one immutable release directory from a clean committed tree."""

    project = project.resolve()
    output_root = output_root.resolve()
    if _git(project, "status", "--porcelain", "--untracked-files=all"):
        raise ReleaseManifestError("release bundle requires a clean committed worktree")
    destination = output_root / __version__
    if destination.exists() or destination.is_symlink():
        raise ReleaseManifestError("release version already exists")
    if output_root.is_symlink():
        raise ReleaseManifestError("release output root cannot be a symlink")
    output_root.mkdir(parents=True, exist_ok=True)
    staging = output_root / f".{__version__}.building"
    if staging.exists() or staging.is_symlink():
        raise ReleaseManifestError("release staging directory already exists")
    try:
        staging.mkdir()
        project_destination = staging / "project"
        for name in PROJECT_FILES:
            _copy_file(project / name, project_destination / name)
        for name in PROJECT_TREES:
            _copy_tree(
                project / name,
                project_destination / name,
                excluded_relative=(
                    RELEASE_EXCLUDED_DOCUMENTS if name == "docs" else None
                ),
            )
        wheel = _find_distribution(project, ".whl")
        sdist = _find_distribution(project, ".tar.gz")
        _copy_file(wheel, staging / "wheel" / wheel.name)
        _copy_file(sdist, staging / "sdist" / sdist.name)
        demo_models = _build_sample_database(
            project,
            staging / "demo" / "sample.sqlite3",
            staging / "demo" / "artifacts",
        )
        _validate_no_local_identity(staging, project)
        git_commit = _git(project, "rev-parse", "HEAD")
        generated_at = _git(project, "show", "-s", "--format=%cI", git_commit)
        manifest = build_release_manifest(
            staging,
            git_commit=git_commit,
            generated_at=generated_at,
            database_schema=CURRENT_SCHEMA_VERSION,
            demo_models=demo_models,
        )
        write_release_manifest(staging, manifest)
        verify_release_bundle(staging)
        staging.rename(destination)
    except Exception:
        if staging.is_dir() and not staging.is_symlink():
            shutil.rmtree(staging)
        raise
    return destination


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--project-root", type=Path, default=Path.cwd())
    build_parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("dist/release"),
    )
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("bundle", type=Path)
    arguments = parser.parse_args()
    try:
        if arguments.action == "build":
            built = build(arguments.project_root, arguments.output_root)
            print(built)
        else:
            payload = verify_release_bundle(arguments.bundle)
            print(
                json.dumps(
                    {
                        "status": "verified",
                        "application_version": payload["application_version"],
                        "artifact_count": len(payload["artifact_inventory"]),
                    },
                    sort_keys=True,
                )
            )
    except (OSError, ReleaseManifestError, subprocess.CalledProcessError) as exc:
        print(f"release bundle operation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
