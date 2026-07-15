"""Load and query the versioned static dataset registry."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from aegishunt.datasets.errors import DatasetNotFoundError, DatasetRegistryError
from aegishunt.datasets.schemas import DatasetDefinition, DatasetRegistryDocument


class DatasetRegistry:
    """Validated in-memory lookup over stable dataset identifiers."""

    def __init__(self, document: DatasetRegistryDocument) -> None:
        self._document = document
        self._entries = {entry.dataset_id: entry for entry in document.datasets}

    @classmethod
    def load(cls, path: Path) -> DatasetRegistry:
        try:
            payload = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise DatasetRegistryError("unable to read the dataset registry") from exc
        except yaml.YAMLError as exc:
            raise DatasetRegistryError("dataset registry YAML is invalid") from exc
        try:
            document = DatasetRegistryDocument.model_validate(payload)
        except ValidationError as exc:
            errors = exc.errors(include_input=False, include_url=False)
            raise DatasetRegistryError(f"dataset registry validation failed: {errors}") from exc
        return cls(document)

    def list(self) -> tuple[DatasetDefinition, ...]:
        """Return definitions in deterministic stable-ID order."""

        return tuple(self._entries[dataset_id] for dataset_id in sorted(self._entries))

    def describe(self, dataset_id: str) -> DatasetDefinition:
        """Return one definition or a typed not-found failure."""

        try:
            return self._entries[dataset_id.strip().lower()]
        except KeyError as exc:
            raise DatasetNotFoundError("dataset ID is not registered") from exc

    def to_json(self) -> str:
        """Serialize without introducing local runtime state."""

        return self._document.model_dump_json(indent=2) + "\n"
