"""Inspect final Python distributions without installing or extracting them."""

from __future__ import annotations

import argparse
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from aegishunt.metadata import __version__

FORBIDDEN_SUFFIXES = {
    ".db",
    ".joblib",
    ".pcap",
    ".pcapng",
    ".pkl",
    ".skops",
    ".sqlite",
    ".sqlite3",
}
FORBIDDEN_PARTS = {
    ".env",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "artifacts",
    "htmlcov",
    "reports",
}
REQUIRED_WHEEL_SUFFIXES = (
    "aegishunt/cli.py",
    "aegishunt/frontend/app.py",
    "aegishunt/metadata.py",
    ".dist-info/METADATA",
    ".dist-info/entry_points.txt",
)


class DistributionValidationError(ValueError):
    """Raised when a built distribution exceeds the final package boundary."""


def _safe_names(names: list[str]) -> None:
    for name in names:
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts:
            raise DistributionValidationError("distribution contains an unsafe path")
        if set(path.parts) & FORBIDDEN_PARTS or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise DistributionValidationError(f"distribution contains forbidden content: {name}")


def validate(wheel: Path, sdist: Path) -> dict[str, object]:
    """Validate wheel identity, entry point, and safe source inventory."""

    if not wheel.is_file() or not sdist.is_file():
        raise DistributionValidationError("wheel and sdist must both exist")
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
        _safe_names(wheel_names)
        for required in REQUIRED_WHEEL_SUFFIXES:
            if not any(name.endswith(required) for name in wheel_names):
                raise DistributionValidationError(f"wheel is missing {required}")
        metadata_name = next(name for name in wheel_names if name.endswith(".dist-info/METADATA"))
        entry_name = next(
            name for name in wheel_names if name.endswith(".dist-info/entry_points.txt")
        )
        metadata = archive.read(metadata_name).decode("utf-8")
        entry_points = archive.read(entry_name).decode("utf-8")
    if not re.search(rf"^Version: {re.escape(__version__)}$", metadata, flags=re.MULTILINE):
        raise DistributionValidationError("wheel metadata version is inconsistent")
    if "aegishunt = aegishunt.cli:app" not in entry_points:
        raise DistributionValidationError("wheel CLI entry point is missing")
    with tarfile.open(sdist, mode="r:gz") as archive:
        source_names = archive.getnames()
        _safe_names(source_names)
        if not any(name.endswith("/pyproject.toml") for name in source_names):
            raise DistributionValidationError("sdist is missing pyproject.toml")
    return {
        "status": "PASS",
        "application_version": __version__,
        "wheel": wheel.name,
        "wheel_entries": len(wheel_names),
        "sdist": sdist.name,
        "sdist_entries": len(source_names),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--sdist", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = validate(arguments.wheel, arguments.sdist)
    except (OSError, DistributionValidationError, tarfile.TarError, zipfile.BadZipFile) as exc:
        print(f"distribution validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
