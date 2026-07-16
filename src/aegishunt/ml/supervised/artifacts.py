"""Exclusive, auditable experiment artifact persistence."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from aegishunt.ml.supervised.contracts import ModelSelectionRecord
from aegishunt.ml.supervised.errors import ArtifactError


@dataclass(frozen=True, slots=True)
class ExperimentStore:
    """One immutable experiment directory created outside tracked source paths."""

    directory: Path

    @classmethod
    def create(cls, reports_root: Path, experiment_id: str) -> ExperimentStore:
        directory = reports_root / experiment_id
        try:
            directory.mkdir(parents=True, exist_ok=False, mode=0o750)
        except FileExistsError as exc:
            raise ArtifactError("supervised experiment already exists") from exc
        except OSError as exc:
            raise ArtifactError("unable to create supervised experiment directory") from exc
        return cls(directory)

    @classmethod
    def open(cls, reports_root: Path, experiment_id: str) -> ExperimentStore:
        directory = reports_root / experiment_id
        if not directory.is_dir():
            raise ArtifactError("supervised experiment does not exist")
        return cls(directory)

    def path(self, filename: str) -> Path:
        path = Path(filename)
        if path.is_absolute() or len(path.parts) != 1 or ".." in path.parts:
            raise ArtifactError("experiment artifact name is unsafe")
        return self.directory / path

    def exists(self, filename: str) -> bool:
        return self.path(filename).exists()

    def write_bytes(self, filename: str, payload: bytes) -> Path:
        path = self.path(filename)
        try:
            with path.open("xb") as destination:
                destination.write(payload)
        except FileExistsError as exc:
            raise ArtifactError("experiment artifact already exists") from exc
        except OSError as exc:
            raise ArtifactError("unable to write experiment artifact") from exc
        return path

    def write_text(self, filename: str, payload: str) -> Path:
        return self.write_bytes(filename, payload.encode("utf-8"))

    def write_json(self, filename: str, payload: BaseModel | dict[str, Any] | list[Any]) -> Path:
        if isinstance(payload, BaseModel):
            encoded = payload.model_dump_json(indent=2) + "\n"
        else:
            encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        return self.write_text(filename, encoded)

    def write_csv(self, filename: str, rows: list[dict[str, object]]) -> Path:
        if not rows:
            raise ArtifactError("CSV experiment artifact cannot be empty")
        fieldnames = tuple(rows[0])
        if any(tuple(row) != fieldnames for row in rows):
            raise ArtifactError("CSV experiment rows have inconsistent columns")
        buffer = io.StringIO(newline="")
        writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        return self.write_text(filename, buffer.getvalue())

    def read_selection(self) -> ModelSelectionRecord:
        try:
            return ModelSelectionRecord.model_validate_json(
                self.path("model_selection.json").read_text(encoding="utf-8")
            )
        except (OSError, ValidationError) as exc:
            raise ArtifactError("model selection record is invalid") from exc
