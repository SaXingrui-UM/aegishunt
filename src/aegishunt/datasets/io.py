"""Deterministic canonical JSON Lines persistence helpers."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path

from pydantic import ValidationError

from aegishunt.datasets.errors import DatasetConversionError
from aegishunt.datasets.schemas import CanonicalDatasetRow


def sha256_file(path: Path, *, chunk_size: int = 65_536) -> str:
    """Compute a bounded-memory SHA-256 digest for one regular file."""

    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(chunk_size):
                digest.update(chunk)
    except OSError as exc:
        raise DatasetConversionError("unable to read dataset file for checksum") from exc
    return digest.hexdigest()


def canonical_row_json(row: CanonicalDatasetRow) -> str:
    """Serialize one row with stable bytes independent of incidental dict order."""

    payload = row.model_dump(mode="json")
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def write_canonical_jsonl(rows: Iterable[CanonicalDatasetRow], path: Path) -> str:
    """Write canonical rows atomically and return the resulting SHA-256."""

    temporary = path.with_name(f".{path.name}.tmp")
    if path.exists() or temporary.exists():
        raise DatasetConversionError("canonical output already exists")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with temporary.open("x", encoding="utf-8", newline="\n") as destination:
            for row in rows:
                destination.write(canonical_row_json(row))
                destination.write("\n")
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise DatasetConversionError("canonical output already exists") from exc
    except OSError as exc:
        raise DatasetConversionError("unable to write canonical dataset") from exc
    finally:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)
    return sha256_file(path)


def read_canonical_jsonl(path: Path) -> tuple[CanonicalDatasetRow, ...]:
    """Read a canonical dataset with explicit line-local validation failures."""

    rows: list[CanonicalDatasetRow] = []
    try:
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, start=1):
                if not line.strip():
                    continue
                try:
                    payload = json.loads(line)
                    rows.append(CanonicalDatasetRow.model_validate(payload))
                except (json.JSONDecodeError, ValidationError) as exc:
                    raise DatasetConversionError(
                        f"canonical dataset row is invalid at line {line_number}"
                    ) from exc
    except OSError as exc:
        raise DatasetConversionError("unable to read canonical dataset") from exc
    if not rows:
        raise DatasetConversionError("canonical dataset is empty")
    return tuple(rows)
